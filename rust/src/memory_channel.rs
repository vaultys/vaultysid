use crate::error::{Error, Result};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

// Type aliases to reduce complexity
type ConnectedCallback = Box<dyn FnOnce() + Send>;
type Logger = Box<dyn Fn(&[u8]) + Send + Sync>;
type Injector = Box<dyn Fn(Vec<u8>) -> Vec<u8> + Send + Sync>;

/// Trait defining a communication channel interface
#[async_trait]
pub trait Channel: Send + Sync {
    /// Start the channel and mark it as connected
    async fn start(&mut self) -> Result<()>;

    /// Close the channel
    async fn close(&mut self) -> Result<()>;

    /// Send data through the channel
    async fn send(&mut self, data: Vec<u8>) -> Result<()>;

    /// Receive data from the channel
    async fn receive(&mut self) -> Result<Vec<u8>>;

    /// Register a callback to be called when connected
    fn on_connected(&mut self, callback: Box<dyn FnOnce() + Send>);

    /// Get a connection string representation
    fn get_connection_string(&self) -> String;

    /// Create a channel from a connection string
    fn from_connection_string(conn: &str) -> Result<Box<dyn Channel>>
    where
        Self: Sized;
}

/// In-memory channel implementation for bidirectional communication
#[derive(Clone)]
pub struct MemoryChannel {
    name: Option<String>,
    other_end: Option<Arc<Mutex<MemoryChannelInner>>>,
    inner: Arc<Mutex<MemoryChannelInner>>,
    connected_callbacks: Arc<Mutex<Vec<ConnectedCallback>>>,
}

struct MemoryChannelInner {
    message_queue: VecDeque<Vec<u8>>,
    waiting_receivers: Vec<Arc<Notify>>,
    connected: bool,
    closed: bool,
    logger: Option<Logger>,
    injector: Option<Injector>,
}

impl Default for MemoryChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryChannel {
    /// Create a new memory channel
    pub fn new() -> Self {
        Self {
            name: None,
            other_end: None,
            inner: Arc::new(Mutex::new(MemoryChannelInner {
                message_queue: VecDeque::new(),
                waiting_receivers: Vec::new(),
                connected: false,
                closed: false,
                logger: None,
                injector: None,
            })),
            connected_callbacks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a bidirectional channel pair
    pub fn create_bidirectional() -> (Self, Self) {
        let mut input = Self::new();
        let mut output = Self::new();

        // Set each channel as the other's endpoint
        input.other_end = Some(output.inner.clone());
        output.other_end = Some(input.inner.clone());

        (input, output)
    }

    /// Set the other end of this channel
    pub fn set_channel(&mut self, other: &MemoryChannel, name: Option<String>) {
        self.name = name;
        self.other_end = Some(other.inner.clone());
    }

    /// Set a logger function for debugging
    pub async fn set_logger<F>(&mut self, logger: F)
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        let mut inner = self.inner.lock().await;
        inner.logger = Some(Box::new(logger));
    }

    /// Set an injector function to transform data before sending
    pub async fn set_injector<F>(&mut self, injector: F)
    where
        F: Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
    {
        let mut inner = self.inner.lock().await;
        inner.injector = Some(Box::new(injector));
    }

    /// Deliver a message to this channel's queue
    async fn deliver_message(inner: &Arc<Mutex<MemoryChannelInner>>, data: Vec<u8>) {
        let mut inner_guard = inner.lock().await;

        // If there are waiting receivers, deliver directly
        if !inner_guard.waiting_receivers.is_empty() {
            let notify = inner_guard.waiting_receivers.remove(0);
            inner_guard.message_queue.push_back(data);
            notify.notify_one();
        } else {
            // Otherwise queue the message
            inner_guard.message_queue.push_back(data);
        }
    }
}

#[async_trait]
impl Channel for MemoryChannel {
    async fn start(&mut self) -> Result<()> {
        {
            let mut inner = self.inner.lock().await;
            inner.connected = true;
        }

        // Call all connected callbacks
        let callbacks = {
            let mut callbacks_guard = self.connected_callbacks.lock().await;
            std::mem::take(&mut *callbacks_guard)
        };

        for callback in callbacks {
            callback();
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.closed = true;

        // Notify all waiting receivers
        for notify in inner.waiting_receivers.drain(..) {
            notify.notify_one();
        }

        // Clear the message queue
        inner.message_queue.clear();

        Ok(())
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<()> {
        let other_end = self
            .other_end
            .as_ref()
            .ok_or_else(|| Error::Other("No other end connected to this channel".into()))?
            .clone();

        let processed_data = {
            let inner = self.inner.lock().await;

            if inner.closed {
                return Err(Error::Other("Cannot send on closed channel".into()));
            }

            // Log the data if a logger is set
            if let Some(ref logger) = inner.logger {
                logger(&data);
            }

            // Process data through injector if present
            if let Some(ref injector) = inner.injector {
                injector(data)
            } else {
                data
            }
        };

        // Signal that this end is connected
        {
            let mut inner = self.inner.lock().await;
            if !inner.connected {
                inner.connected = true;
            }
        }

        // Deliver the message to the other end
        Self::deliver_message(&other_end, processed_data).await;

        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let notify = Arc::new(Notify::new());

        // Check if there's already a message or if we need to wait
        let should_wait = {
            let mut inner = self.inner.lock().await;

            if inner.closed {
                return Err(Error::Other("Cannot receive on closed channel".into()));
            }

            if let Some(message) = inner.message_queue.pop_front() {
                return Ok(message);
            }

            // Register to wait for a message
            inner.waiting_receivers.push(notify.clone());
            true
        };

        if should_wait {
            // Wait for notification
            notify.notified().await;

            // Try to get the message
            let mut inner = self.inner.lock().await;

            if inner.closed {
                return Ok(Vec::new()); // Return empty buffer to indicate closed
            }

            inner
                .message_queue
                .pop_front()
                .ok_or_else(|| Error::Other("No message available after notification".into()))
        } else {
            Ok(Vec::new())
        }
    }

    fn on_connected(&mut self, callback: Box<dyn FnOnce() + Send>) {
        let inner = self.inner.clone();
        let callbacks = self.connected_callbacks.clone();

        tokio::spawn(async move {
            let connected = {
                let inner_guard = inner.lock().await;
                inner_guard.connected
            };

            if connected {
                callback();
            } else {
                let mut callbacks_guard = callbacks.lock().await;
                callbacks_guard.push(callback);
            }
        });
    }

    fn get_connection_string(&self) -> String {
        "vaultys://memory".to_string()
    }

    fn from_connection_string(conn: &str) -> Result<Box<dyn Channel>> {
        if conn == "vaultys://memory" {
            Ok(Box::new(Self::new()))
        } else {
            Err(Error::Other("Invalid connection string".into()))
        }
    }
}

/// Pipe two channels together bidirectionally
pub async fn pipe_channels(
    channel1: Arc<Mutex<Box<dyn Channel>>>,
    channel2: Arc<Mutex<Box<dyn Channel>>>,
) -> Result<()> {
    use tokio::select;

    // Start both channels
    {
        let mut ch1 = channel1.lock().await;
        ch1.start().await?;
    }
    {
        let mut ch2 = channel2.lock().await;
        ch2.start().await?;
    }

    let (tx1, mut rx1) = tokio::sync::mpsc::channel::<()>(1);
    let (tx2, mut rx2) = tokio::sync::mpsc::channel::<()>(1);

    // Spawn task for channel1 -> channel2
    let ch1_clone = channel1.clone();
    let ch2_clone = channel2.clone();
    let tx1_clone = tx1.clone();
    tokio::spawn(async move {
        loop {
            let data = {
                let mut ch1 = ch1_clone.lock().await;
                ch1.receive().await
            };

            match data {
                Ok(data) if !data.is_empty() => {
                    let mut ch2 = ch2_clone.lock().await;
                    if ch2.send(data).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = tx1_clone.send(()).await;
    });

    // Spawn task for channel2 -> channel1
    let ch2_clone2 = channel2.clone();
    let ch1_clone2 = channel1.clone();
    let tx2_clone = tx2.clone();
    tokio::spawn(async move {
        loop {
            let data = {
                let mut ch2 = ch2_clone2.lock().await;
                ch2.receive().await
            };

            match data {
                Ok(data) if !data.is_empty() => {
                    let mut ch1 = ch1_clone2.lock().await;
                    if ch1.send(data).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = tx2_clone.send(()).await;
    });

    // Wait for either channel to close
    select! {
        _ = rx1.recv() => {},
        _ = rx2.recv() => {},
    }

    // Close both channels
    {
        let mut ch1 = channel1.lock().await;
        ch1.close().await?;
    }
    {
        let mut ch2 = channel2.lock().await;
        ch2.close().await?;
    }

    Ok(())
}

/// Stream channel functionality for working with async streams
pub struct StreamChannel {
    channel: Arc<Mutex<Box<dyn Channel>>>,
}

impl StreamChannel {
    /// Create a new stream channel wrapper
    pub fn new(channel: Box<dyn Channel>) -> Self {
        Self {
            channel: Arc::new(Mutex::new(channel)),
        }
    }

    /// Upload data to the channel
    pub async fn upload_data(&mut self, data: Vec<u8>) -> Result<()> {
        // Split data into chunks if needed
        const CHUNK_SIZE: usize = 8192;

        let mut channel = self.channel.lock().await;
        for chunk in data.chunks(CHUNK_SIZE) {
            channel.send(chunk.to_vec()).await?;
        }

        // Send EOF marker
        channel.send(b"EOF".to_vec()).await?;

        Ok(())
    }

    /// Download data from the channel
    pub async fn download_data(&mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        loop {
            let chunk = {
                let mut channel = self.channel.lock().await;
                channel.receive().await?
            };

            if chunk == b"EOF" {
                break;
            }

            result.extend_from_slice(&chunk);
        }

        Ok(result)
    }

    /// Get an async writer for the channel
    pub fn as_writer(&self) -> ChannelWriter {
        ChannelWriter {
            channel: self.channel.clone(),
        }
    }

    /// Get an async reader for the channel
    pub fn as_reader(&self) -> ChannelReader {
        ChannelReader {
            channel: self.channel.clone(),
            buffer: Vec::new(),
            eof_reached: false,
        }
    }
}

/// Async writer implementation for channels
pub struct ChannelWriter {
    channel: Arc<Mutex<Box<dyn Channel>>>,
}

impl ChannelWriter {
    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        let mut channel = self.channel.lock().await;
        channel.send(data.to_vec()).await?;
        Ok(data.len())
    }

    pub async fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        let mut channel = self.channel.lock().await;
        channel.send(b"EOF".to_vec()).await?;
        Ok(())
    }
}

/// Async reader implementation for channels
pub struct ChannelReader {
    channel: Arc<Mutex<Box<dyn Channel>>>,
    buffer: Vec<u8>,
    eof_reached: bool,
}

impl ChannelReader {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.eof_reached {
            return Ok(0);
        }

        if self.buffer.is_empty() {
            let chunk = {
                let mut channel = self.channel.lock().await;
                channel.receive().await?
            };

            if chunk == b"EOF" {
                self.eof_reached = true;
                return Ok(0);
            }

            self.buffer = chunk;
        }

        let len = std::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);

        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_channel_bidirectional() {
        let (mut ch1, mut ch2) = MemoryChannel::create_bidirectional();

        ch1.start().await.unwrap();
        ch2.start().await.unwrap();

        // Send from ch1 to ch2
        ch1.send(b"Hello".to_vec()).await.unwrap();
        let received = ch2.receive().await.unwrap();
        assert_eq!(received, b"Hello");

        // Send from ch2 to ch1
        ch2.send(b"World".to_vec()).await.unwrap();
        let received = ch1.receive().await.unwrap();
        assert_eq!(received, b"World");
    }

    #[tokio::test]
    async fn test_stream_channel() {
        let (ch1, ch2) = MemoryChannel::create_bidirectional();

        let mut stream1 = StreamChannel::new(Box::new(ch1));
        let mut stream2 = StreamChannel::new(Box::new(ch2));

        // Upload data from stream1
        let data = b"Test data for streaming".to_vec();

        let upload_handle = tokio::spawn(async move {
            stream1.upload_data(data.clone()).await.unwrap();
        });

        // Download data from stream2
        let downloaded = stream2.download_data().await.unwrap();

        upload_handle.await.unwrap();
        assert_eq!(downloaded, b"Test data for streaming");
    }
}
