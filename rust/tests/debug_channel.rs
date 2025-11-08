use base64::Engine;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let channel_name = args.get(1).unwrap_or(&"debug-channel".to_string()).clone();
    let role = args.get(2).unwrap_or(&"sender".to_string()).clone();

    // Calculate the correct channel directory path
    let channel_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test")
        .join("interops")
        .join("tmp")
        .join("channels")
        .join(&channel_name);

    println!("=== Rust Channel Debug ===");
    println!("Role: {}", role);
    println!("Channel name: {}", channel_name);
    println!("Channel directory: {:?}", channel_dir);
    println!("CARGO_MANIFEST_DIR: {}", env!("CARGO_MANIFEST_DIR"));
    println!("Current dir: {:?}", std::env::current_dir().unwrap());

    // Ensure channel directory exists
    if !channel_dir.exists() {
        fs::create_dir_all(&channel_dir).expect("Failed to create channel directory");
        println!("Created channel directory");
    } else {
        println!("Channel directory already exists");
    }

    // List current contents
    let entries: Vec<_> = fs::read_dir(&channel_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    if entries.is_empty() {
        println!("Current files in channel: (empty)");
    } else {
        println!("Current files in channel: {}", entries.join(", "));
    }

    match role.as_str() {
        "sender" => {
            // Send a test message
            let message_id = format!(
                "{}_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
                0
            );

            let data = b"Hello from Rust!";
            let filename = channel_dir.join(format!("rust_to_ts_{}.msg", message_id));

            let message = serde_json::json!({
                "id": message_id,
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                "data": base64::engine::general_purpose::STANDARD.encode(data),
                "length": data.len(),
            });

            fs::write(&filename, serde_json::to_string_pretty(&message).unwrap())
                .expect("Failed to write message");

            println!("\nSent message: {:?}", filename);
            println!(
                "Message content: {}",
                serde_json::to_string_pretty(&message).unwrap()
            );

            // Wait for response
            println!("\nWaiting for response from TypeScript...");
            let mut attempts = 0;
            loop {
                attempts += 1;

                let files: Vec<_> = fs::read_dir(&channel_dir)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().starts_with("ts_to_rust_"))
                    .collect();

                if !files.is_empty() {
                    let first = &files[0];
                    println!("\nReceived response: {:?}", first.file_name());
                    let content = fs::read_to_string(first.path()).unwrap();
                    println!("Response content: {}", content);
                    break;
                }

                if attempts > 30 {
                    println!("\nTimeout waiting for response");
                    std::process::exit(1);
                }

                if attempts % 5 == 0 {
                    println!("Still waiting... ({} seconds)", attempts);
                }

                thread::sleep(Duration::from_secs(1));
            }
        }
        "receiver" => {
            // Wait for a message
            println!("\nWaiting for message from TypeScript...");
            let mut attempts = 0;
            loop {
                attempts += 1;

                let files: Vec<_> = fs::read_dir(&channel_dir)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().starts_with("ts_to_rust_"))
                    .collect();

                if !files.is_empty() {
                    let first = &files[0];
                    println!("\nReceived message: {:?}", first.file_name());
                    let content = fs::read_to_string(first.path()).unwrap();
                    println!("Message content: {}", content);

                    // Parse the message to verify it
                    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
                    let data_base64 = parsed["data"].as_str().unwrap();
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(data_base64)
                        .unwrap();
                    println!("Decoded data: {}", String::from_utf8_lossy(&data));

                    // Send response
                    let response_id = format!(
                        "{}_{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis(),
                        0
                    );

                    let response_data = b"Response from Rust!";
                    let response_filename =
                        channel_dir.join(format!("rust_to_ts_{}.msg", response_id));

                    let response = serde_json::json!({
                        "id": response_id,
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        "data": base64::engine::general_purpose::STANDARD.encode(response_data),
                        "length": response_data.len(),
                    });

                    fs::write(
                        &response_filename,
                        serde_json::to_string_pretty(&response).unwrap(),
                    )
                    .expect("Failed to write response");

                    println!("\nSent response: {:?}", response_filename);

                    // Clean up the received message
                    fs::remove_file(first.path()).ok();
                    break;
                }

                if attempts > 30 {
                    println!("\nTimeout waiting for message");
                    std::process::exit(1);
                }

                if attempts % 5 == 0 {
                    println!("Still waiting... ({} seconds)", attempts);
                    let current_files: Vec<_> = fs::read_dir(&channel_dir)
                        .unwrap()
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect();

                    if current_files.is_empty() {
                        println!("Current files: (empty)");
                    } else {
                        println!("Current files: {}", current_files.join(", "));
                    }
                }

                thread::sleep(Duration::from_secs(1));
            }
        }
        _ => {
            eprintln!("Invalid role. Use 'sender' or 'receiver'");
            std::process::exit(1);
        }
    }
}
