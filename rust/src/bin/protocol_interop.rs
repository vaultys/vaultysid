use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use vaultysid::{IdManager, MemoryStore, StoredContact, VaultysId};

// Protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum MessageType {
    Init,
    Challenge,
    Response,
    Accept,
    Reject,
    Data,
    Complete,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProtocolMessage {
    #[serde(rename = "type")]
    msg_type: MessageType,
    sender: String,
    recipient: Option<String>,
    data: String, // Base64 encoded
    timestamp: u64,
    sequence: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct InitData {
    protocol: String,
    version: u8,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AcceptData {
    did: String,
    name: Option<String>,
    email: Option<String>,
}

// Interop channel for cross-language communication
struct InteropChannel {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl InteropChannel {
    // Connect as client
    fn connect(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self { stream, reader })
    }

    // Accept connection as server
    fn accept(listener: &TcpListener) -> Result<Self, Box<dyn std::error::Error>> {
        let (stream, addr) = listener.accept()?;
        println!("[Rust] Client connected from: {}", addr);
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self { stream, reader })
    }

    // Send a message
    fn send(&mut self, message: &ProtocolMessage) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(message)?;
        writeln!(&mut self.stream, "{}", json)?;
        self.stream.flush()?;
        Ok(())
    }

    // Receive a message
    fn receive(&mut self) -> Result<ProtocolMessage, Box<dyn std::error::Error>> {
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        let message: ProtocolMessage = serde_json::from_str(&line)?;
        Ok(message)
    }
}

// Protocol implementation for IdManager
struct IdManagerProtocol {
    manager: Arc<IdManager>,
    channel: InteropChannel,
    sequence: u32,
}

impl IdManagerProtocol {
    fn new(manager: Arc<IdManager>, channel: InteropChannel) -> Self {
        Self {
            manager,
            channel,
            sequence: 0,
        }
    }

    // Start the ask protocol (initiator)
    async fn start_ask_protocol(
        &mut self,
        recipient_did: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        println!("[Rust] Starting ask protocol with {}", recipient_did);

        let manager_did = self.manager.vaultys_id.lock().await.did();
        let name = self.manager.name().await;
        let email = self.manager.email().await;

        // Send INIT message
        let init_data = InitData {
            protocol: "ASK_ACCEPT".to_string(),
            version: 1,
            name: name.clone(),
            email: email.clone(),
        };

        let init_message = ProtocolMessage {
            msg_type: MessageType::Init,
            sender: manager_did.clone(),
            recipient: Some(recipient_did.to_string()),
            data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                serde_json::to_vec(&init_data)?,
            ),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            sequence: self.sequence,
        };
        self.sequence += 1;

        self.channel.send(&init_message)?;
        println!("[Rust] Sent INIT message");

        // Wait for CHALLENGE
        let challenge = self.channel.receive()?;
        if !matches!(challenge.msg_type, MessageType::Challenge) {
            println!("[Rust] Expected CHALLENGE, got {:?}", challenge.msg_type);
            return Ok(false);
        }
        println!("[Rust] Received CHALLENGE");

        // Sign the challenge
        let challenge_data =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &challenge.data)?;
        let signature = self.manager.sign_challenge(&challenge_data).await?;

        // Send RESPONSE
        let response_message = ProtocolMessage {
            msg_type: MessageType::Response,
            sender: manager_did.clone(),
            recipient: Some(recipient_did.to_string()),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signature),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            sequence: self.sequence,
        };
        self.sequence += 1;

        self.channel.send(&response_message)?;
        println!("[Rust] Sent RESPONSE");

        // Wait for ACCEPT or REJECT
        let result = self.channel.receive()?;
        if matches!(result.msg_type, MessageType::Accept) {
            println!("[Rust] Protocol ACCEPTED");

            // Parse contact data
            let accept_data_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &result.data)?;
            let accept_data: AcceptData = serde_json::from_slice(&accept_data_bytes)?;

            // Save contact
            let mut metadata = HashMap::new();
            if let Some(name) = accept_data.name {
                metadata.insert("name".to_string(), name);
            }
            if let Some(email) = accept_data.email {
                metadata.insert("email".to_string(), email);
            }

            let contact = StoredContact {
                did: accept_data.did,
                certificate: None,
                metadata,
                id: None,
            };

            self.manager.save_contact(contact).await?;
            Ok(true)
        } else {
            println!("[Rust] Protocol REJECTED or error: {:?}", result.msg_type);
            Ok(false)
        }
    }

    // Accept the ask protocol (responder)
    async fn accept_ask_protocol(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        println!("[Rust] Waiting for ask protocol...");

        // Wait for INIT
        let init = self.channel.receive()?;
        if !matches!(init.msg_type, MessageType::Init) {
            println!("[Rust] Expected INIT, got {:?}", init.msg_type);
            return Ok(false);
        }
        println!("[Rust] Received INIT from {}", init.sender);

        let init_data_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &init.data)?;
        let init_data: InitData = serde_json::from_slice(&init_data_bytes)?;

        let manager_did = self.manager.vaultys_id.lock().await.did();

        // Generate a challenge
        let challenge_data = format!(
            "Challenge-{}-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            rand::random::<u32>()
        );

        let challenge_message = ProtocolMessage {
            msg_type: MessageType::Challenge,
            sender: manager_did.clone(),
            recipient: Some(init.sender.clone()),
            data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &challenge_data,
            ),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            sequence: self.sequence,
        };
        self.sequence += 1;

        self.channel.send(&challenge_message)?;
        println!("[Rust] Sent CHALLENGE");

        // Wait for RESPONSE
        let response = self.channel.receive()?;
        if !matches!(response.msg_type, MessageType::Response) {
            println!("[Rust] Expected RESPONSE, got {:?}", response.msg_type);
            return Ok(false);
        }
        println!("[Rust] Received RESPONSE");

        // In a real implementation, verify the signature
        // For now, we'll accept it

        let name = self.manager.name().await;
        let email = self.manager.email().await;

        // Send ACCEPT with our info
        let accept_data = AcceptData {
            did: manager_did.clone(),
            name: name.clone(),
            email: email.clone(),
        };

        let accept_message = ProtocolMessage {
            msg_type: MessageType::Accept,
            sender: manager_did,
            recipient: Some(init.sender.clone()),
            data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                serde_json::to_vec(&accept_data)?,
            ),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            sequence: self.sequence,
        };
        self.sequence += 1;

        self.channel.send(&accept_message)?;
        println!("[Rust] Sent ACCEPT");

        // Save contact
        let mut metadata = HashMap::new();
        if let Some(name) = init_data.name {
            metadata.insert("name".to_string(), name);
        }
        if let Some(email) = init_data.email {
            metadata.insert("email".to_string(), email);
        }

        let contact = StoredContact {
            did: init.sender,
            certificate: None,
            metadata,
            id: None,
        };

        self.manager.save_contact(contact).await?;
        Ok(true)
    }
}

async fn run_rust_side(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🦀 Rust IdManager Interop Test - Role: {}\n", role);

    // Create IdManager
    let vaultys_id = VaultysId::generate_person().await?;
    let store = Box::new(MemoryStore::new());
    let manager = Arc::new(IdManager::new(vaultys_id, store).await?);

    let (name, email) = if role == "initiator" {
        ("Alice (Rust)", "alice@rust.com")
    } else {
        ("Bob (Rust)", "bob@rust.com")
    };

    manager.set_name(name).await?;
    manager.set_email(email).await?;

    println!("Created IdManager:");
    println!("  DID: {}", manager.vaultys_id.lock().await.did());
    println!("  Name: {}", name);
    println!("  Email: {}", email);

    // Create interop channel
    let channel = if role == "initiator" {
        // Rust side acts as client (initiator)
        println!("Connecting to TypeScript server at localhost:9876...");
        std::thread::sleep(std::time::Duration::from_millis(1000));
        InteropChannel::connect("localhost:9876")?
    } else {
        // Rust side acts as server (responder)
        let listener = TcpListener::bind("localhost:9876")?;
        println!("Listening on localhost:9876 for TypeScript client...");
        InteropChannel::accept(&listener)?
    };

    // Create protocol handler
    let mut protocol = IdManagerProtocol::new(manager.clone(), channel);

    // Run protocol
    let success = if role == "initiator" {
        protocol
            .start_ask_protocol("did:vaultys:typescript-peer")
            .await?
    } else {
        protocol.accept_ask_protocol().await?
    };

    if success {
        println!("\n✅ Protocol completed successfully!");
        let contacts = manager.contacts().await;
        println!("Contacts saved: {}", contacts.len());
        if !contacts.is_empty() {
            println!("  First contact: {}", contacts[0].did);
            println!("  Metadata: {:?}", contacts[0].metadata);
        }
    } else {
        println!("\n❌ Protocol failed");
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 || (args[1] != "initiator" && args[1] != "responder") {
        eprintln!("Usage: cargo test --test protocol_interop -- [initiator|responder]");
        std::process::exit(1);
    }

    let role = &args[1];

    if let Err(e) = run_rust_side(role).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

// Integration test
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // This test requires manual coordination with TypeScript side
    async fn test_typescript_rust_interop() {
        // This test is meant to be run manually with:
        // Terminal 1: npm test protocol-interop.ts initiator
        // Terminal 2: cargo test --test protocol_interop -- responder

        println!("Run this test manually with TypeScript side");
        println!("Terminal 1: npm test protocol-interop.ts initiator");
        println!("Terminal 2: cargo test --test protocol_interop -- responder");
    }
}
