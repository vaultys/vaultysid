use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use vaultysid::error::Result;
use vaultysid::memory_channel::Channel;
use vaultysid::{IdManager, MemoryStore, VaultysId};

#[derive(Debug, Serialize, Deserialize)]
struct ChannelMessage {
    id: String,
    timestamp: u64,
    data: String, // Base64 encoded
    length: usize,
}

/// Cross-language channel that communicates with TypeScript via file-based IPC
pub struct CrossLanguageChannel {
    channel_dir: PathBuf,
    message_counter: u64,
}

impl CrossLanguageChannel {
    pub fn new(channel_name: &str) -> Self {
        // Use the same shared directory as TypeScript
        let channel_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test")
            .join("interops")
            .join("tmp")
            .join("channels")
            .join(channel_name);

        // Create directory if it doesn't exist
        fs::create_dir_all(&channel_dir).ok();

        // Clear any existing messages
        Self::clear_messages(&channel_dir);

        Self {
            channel_dir,
            message_counter: 0,
        }
    }

    fn clear_messages(dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".msg") {
                        fs::remove_file(entry.path()).ok();
                    }
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Channel for CrossLanguageChannel {
    async fn start(&mut self) -> Result<()> {
        // Channel is ready immediately for file-based IPC
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        // Clean up any remaining messages
        Self::clear_messages(&self.channel_dir);
        Ok(())
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let message_id = format!("{}_{}", timestamp, self.message_counter);
        self.message_counter += 1;

        let encoded_data = base64::engine::general_purpose::STANDARD.encode(&data);
        println!("[Rust Channel] Preparing to send {} bytes", data.len());
        println!(
            "[Rust Channel] Data preview (first 100 bytes): {}...",
            &encoded_data.chars().take(100).collect::<String>()
        );

        let message = ChannelMessage {
            id: message_id.clone(),
            timestamp,
            data: encoded_data,
            length: data.len(),
        };

        // Write to a file that TypeScript will read
        let filename = self
            .channel_dir
            .join(format!("rust_to_ts_{}.msg", message_id));

        println!("[Rust Channel] Writing to: {:?}", filename);
        println!(
            "[Rust Channel] Channel dir exists: {}",
            self.channel_dir.exists()
        );

        let content = serde_json::to_string_pretty(&message)
            .map_err(|e| vaultysid::error::Error::Other(e.to_string()))?;

        fs::write(&filename, &content)
            .map_err(|e| vaultysid::error::Error::Other(e.to_string()))?;

        // Save a copy for debugging
        let debug_dir = self.channel_dir.parent().unwrap().join("debug");
        fs::create_dir_all(&debug_dir).ok();
        let debug_file = debug_dir.join(format!("sent_rust_to_ts_{}.msg", message_id));
        fs::write(&debug_file, &content).ok();
        println!("[Rust Channel] Debug copy saved to: {:?}", debug_file);

        println!(
            "[Rust Channel] Sent message {} ({} bytes)",
            message_id,
            data.len()
        );
        println!("[Rust Channel] File created: {}", filename.exists());
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        println!("[Rust Channel] Waiting for message from TypeScript...");
        println!(
            "[Rust Channel] Looking in directory: {:?}",
            self.channel_dir
        );

        let mut check_count = 0;
        loop {
            check_count += 1;

            // Look for messages from TypeScript
            if let Ok(entries) = fs::read_dir(&self.channel_dir) {
                let mut files: Vec<_> = entries
                    .flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .map(|s| s.starts_with("ts_to_rust_") && s.ends_with(".msg"))
                            .unwrap_or(false)
                    })
                    .collect();

                if check_count % 50 == 0 {
                    // Every 5 seconds
                    let all_files: Vec<_> = fs::read_dir(&self.channel_dir)
                        .unwrap_or_else(|_| panic!("Failed to read dir"))
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect();
                    println!(
                        "[Rust Channel] Still waiting... Files in directory: {:?}",
                        all_files
                    );
                }

                files.sort_by_key(|e| e.file_name());

                if let Some(entry) = files.first() {
                    println!("[Rust Channel] Found message file: {:?}", entry.file_name());

                    let content = fs::read_to_string(entry.path())
                        .map_err(|e| vaultysid::error::Error::Other(e.to_string()))?;

                    let message: ChannelMessage = serde_json::from_str(&content)
                        .map_err(|e| vaultysid::error::Error::Other(e.to_string()))?;

                    // Save a copy for debugging before deleting
                    let debug_dir = self.channel_dir.parent().unwrap().join("debug");
                    fs::create_dir_all(&debug_dir).ok();
                    let debug_file =
                        debug_dir.join(format!("received_{}", entry.file_name().to_string_lossy()));
                    fs::copy(entry.path(), &debug_file).ok();
                    println!("[Rust Channel] Debug copy saved to: {:?}", debug_file);

                    // Delete the file after reading
                    fs::remove_file(entry.path()).ok();

                    println!(
                        "[Rust Channel] Received message {} ({} bytes)",
                        message.id, message.length
                    );
                    println!(
                        "[Rust Channel] Data preview (first 100 chars): {}...",
                        &message.data.chars().take(100).collect::<String>()
                    );

                    let data = base64::engine::general_purpose::STANDARD
                        .decode(&message.data)
                        .map_err(|e| vaultysid::error::Error::Other(e.to_string()))?;

                    return Ok(data);
                }
            }

            // Wait a bit before checking again
            sleep(Duration::from_millis(100)).await;
        }
    }

    fn on_connected(&mut self, callback: Box<dyn FnOnce() + Send>) {
        // File-based channel is always "connected", so call immediately
        callback();
    }

    fn get_connection_string(&self) -> String {
        self.channel_dir.to_string_lossy().to_string()
    }

    fn from_connection_string(conn: &str) -> Result<Box<dyn Channel>>
    where
        Self: Sized,
    {
        let path = PathBuf::from(conn);
        let channel_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("default");
        Ok(Box::new(CrossLanguageChannel::new(channel_name)))
    }
}

async fn run_test(role: &str, channel_name: &str) -> Result<()> {
    println!("\n=== Rust IdManager Cross-Language Test ===\n");

    // Create IdManager
    let vaultys_id = VaultysId::generate_person().await?;
    let store = Box::new(MemoryStore::new());
    let manager = IdManager::new(vaultys_id, store).await?;

    let (name, email) = if role == "asker" {
        ("Alice (Rust)", "alice@rust.com")
    } else {
        ("Bob (Rust)", "bob@rust.com")
    };

    manager.set_name(name).await?;
    manager.set_email(email).await?;

    println!("Rust IdManager created:");
    println!("  Role: {}", role);
    println!("  DID: {}", manager.vaultys_id.lock().await.did());
    println!("  Name: {}", name);
    println!("  Email: {}", email);

    // Create cross-language channel
    let mut channel = CrossLanguageChannel::new(channel_name);
    println!("\nChannel created at: {:?}", channel.channel_dir);

    if role == "asker" {
        println!("\n[Rust] Starting askContact protocol...");
        println!("[Rust] Connecting to TypeScript acceptor...\n");

        // Create metadata for the ask request
        let mut metadata = BTreeMap::new();
        metadata.insert("name".to_string(), name.to_string());
        metadata.insert("email".to_string(), email.to_string());
        metadata.insert("role".to_string(), "asker".to_string());

        // Ask contact from TypeScript
        let _result = match manager.ask_contact(&mut channel, metadata).await {
            Ok(result) => {
                println!("\n[Rust] ✅ askContact completed successfully!");
                println!("[Rust] Result: DID: {}", result.did());
                result
            }
            Err(e) => {
                println!("\n[Rust] ❌ askContact failed!");
                println!("[Rust] Error: {}", e);

                // Log debug info
                let debug_dir = channel.channel_dir.parent().unwrap().join("debug");
                println!("\n[Rust] Debug files saved in: {:?}", debug_dir);
                if let Ok(entries) = fs::read_dir(&debug_dir) {
                    println!("[Rust] Debug files:");
                    for entry in entries.flatten() {
                        println!("  - {}", entry.file_name().to_string_lossy());
                    }
                }
                return Err(e);
            }
        };

        // Check saved contacts
        let contacts = manager.contacts().await;
        println!("[Rust] Contacts saved: {}", contacts.len());
        if !contacts.is_empty() {
            println!("[Rust] Contact details:");
            for contact in &contacts {
                println!("  - DID: {}", contact.did);
                if !contact.metadata.is_empty() {
                    for (key, value) in &contact.metadata {
                        println!("    {}: {}", key, value);
                    }
                }
            }
        }
    } else {
        println!("\n[Rust] Starting acceptContact protocol...");
        println!("[Rust] Waiting for connection request from TypeScript...\n");

        // Create metadata for the accept request
        let mut metadata = BTreeMap::new();
        metadata.insert("name".to_string(), name.to_string());
        metadata.insert("email".to_string(), email.to_string());
        metadata.insert("role".to_string(), "acceptor".to_string());

        // Accept contact from TypeScript
        let result = manager.accept_contact(&mut channel, metadata).await?;

        println!("\n[Rust] ✅ acceptContact completed successfully!");
        println!("[Rust] Result: DID: {}", result.did());

        // Check saved contacts
        let contacts = manager.contacts().await;
        println!("[Rust] Contacts saved: {}", contacts.len());
    }

    println!("\n[Rust] Test completed successfully!");
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [asker|acceptor] [channel-name]", args[0]);
        eprintln!("  asker    - Initiates the protocol (calls askContact)");
        eprintln!("  acceptor - Accepts the protocol (calls acceptContact)");
        std::process::exit(1);
    }

    let role = &args[1];
    let channel_name = args.get(2).map(|s| s.as_str()).unwrap_or("test-channel");

    if role != "asker" && role != "acceptor" {
        eprintln!("Error: Role must be either 'asker' or 'acceptor'");
        std::process::exit(1);
    }

    if let Err(e) = run_test(role, channel_name).await {
        eprintln!("[Rust] Error: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // This test requires coordination with TypeScript
    async fn test_cross_language_protocol() {
        println!("This test requires manual coordination with TypeScript:");
        println!("1. Terminal 1: npx ts-node test/cross-language-channel.ts acceptor");
        println!("2. Terminal 2: cargo run --bin cross_language_test asker");
    }
}
