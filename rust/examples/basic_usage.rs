use vaultysid::{AbstractKeyManager, Ed25519Manager, VaultysId};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("VaultysId Rust Library - Basic Usage Example\n");

    // Example 1: Generate a new Person ID
    println!("1. Generating a new Person ID...");
    let person_id = VaultysId::generate_person().await?;
    println!("   Person ID created");
    println!("   DID: {}", person_id.did());
    println!("   Fingerprint: {}", hex::encode(person_id.fingerprint()));

    // Example 2: Generate a Machine ID
    println!("\n2. Generating a new Machine ID...");
    let machine_id = VaultysId::generate_machine().await?;
    println!("   Machine ID created");
    println!("   DID: {}", machine_id.did());

    // Example 3: Create from entropy
    println!("\n3. Creating ID from specific entropy...");
    let entropy = vaultysid::random_bytes(32);
    let custom_id = VaultysId::from_entropy(&entropy, 0).await?; // Type 0 = Machine
    println!("   Custom ID created from entropy");
    println!("   Is Machine: {}", custom_id.is_machine());

    // Example 4: Sign and verify a challenge
    println!("\n4. Signing and verifying a challenge...");
    let challenge = b"Hello, VaultysId!";
    let signed = person_id.sign_challenge(challenge).await?;
    println!("   Challenge signed");
    println!("   Signature: {}", hex::encode(&signed.signature));

    let is_valid = person_id.verify_challenge(challenge, &signed.signature)?;
    println!("   Verification result: {}", is_valid);

    // Example 5: Export and import via ID
    println!("\n5. Exporting and importing ID...");
    let id_bytes = person_id.id();
    println!("   Exported ID (hex): {}", hex::encode(&id_bytes));
    println!("   ID length: {} bytes", id_bytes.len());

    let imported_id = VaultysId::from_id(&id_bytes, None, None)?;
    println!("   ID successfully imported");
    println!("   DIDs match: {}", person_id.did() == imported_id.did());

    // Example 6: Create Ed25519Manager directly
    println!("\n6. Working with Ed25519Manager directly...");
    let ed_manager = Ed25519Manager::generate()?;
    let ed_id = ed_manager.id();
    println!("   Ed25519Manager created");
    println!("   Manager ID length: {} bytes", ed_id.len());

    // Example 7: Sign data with Ed25519Manager
    println!("\n7. Signing and verifying data...");
    let data = b"Test message for signing";
    let signature = ed_manager.sign(data)?.expect("Failed to sign");
    println!("   Data signed with Ed25519");

    let verified = ed_manager.verify(data, &signature, None);
    println!("   Signature verified: {}", verified);

    // Example 8: Diffie-Hellman key exchange
    println!("\n8. Performing Diffie-Hellman key exchange...");
    let alice = Ed25519Manager::generate()?;
    let bob = Ed25519Manager::generate()?;

    let alice_shared = alice.perform_diffie_hellman(&bob)?;
    let bob_shared = bob.perform_diffie_hellman(&alice)?;

    println!("   Shared secrets match: {}", alice_shared == bob_shared);
    println!("   Shared secret length: {} bytes", alice_shared.len());

    // Example 9: DHIES encryption
    println!("\n9. Testing DHIES encryption...");
    let message = b"Secret message";
    let encrypted = alice.dhies_encrypt(message, &bob.id())?;
    println!("   Message encrypted ({} bytes)", encrypted.len());

    let decrypted = bob.dhies_decrypt(&encrypted, &alice.id())?;
    println!("   Message decrypted successfully");
    println!("   Decryption correct: {}", decrypted == message);

    // Example 10: Clean up secure data
    println!("\n10. Cleaning up secure data...");
    let mut temp_manager = Ed25519Manager::generate()?;
    println!("   Manager created with private keys");
    temp_manager.clean_secure_data();
    println!("   Secure data cleaned from memory");

    // Example 11: Round-trip with secret
    println!("\n11. Secret export and import...");
    let original = Ed25519Manager::generate()?;
    let secret = original.get_secret()?;
    println!("   Secret exported ({} bytes)", secret.len());

    let restored = Ed25519Manager::from_secret(&secret)?;
    println!("   Secret imported successfully");
    println!("   Public keys match: {}", original.id() == restored.id());

    // Example 12: Get DID Document
    println!("\n12. Getting DID Document...");
    let did_doc = person_id.did_document();
    println!(
        "   DID Document: {}",
        serde_json::to_string_pretty(&did_doc)?
    );

    println!("\n✅ All examples completed successfully!");

    Ok(())
}
