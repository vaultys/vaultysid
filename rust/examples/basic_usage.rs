use vaultysid::{DeprecatedKeyManager, Ed25519Manager, VaultysId};

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
    let data = b"Test message for signing";
    let signer = ed_manager.get_signer_ops()?;
    let signature = signer.sign(data)?;
    println!("   Data signed with Ed25519");

    let verified = ed_manager.verify(data, &signature, None);
    println!("   Signature verified: {}", verified);

    // Example 8: Diffie-Hellman key exchange
    println!("\n8. Performing Diffie-Hellman key exchange...");
    let alice = Ed25519Manager::generate()?;
    let bob = Ed25519Manager::generate()?;

    let alice_cypher = alice.get_cypher_ops()?;
    let bob_cypher = bob.get_cypher_ops()?;

    let shared_secret_alice = alice_cypher.diffie_hellman(&bob.cypher.public_key)?;
    let shared_secret_bob = bob_cypher.diffie_hellman(&alice.cypher.public_key)?;

    println!(
        "   Shared secrets match: {}",
        shared_secret_alice == shared_secret_bob
    );
    println!(
        "   Shared secret length: {} bytes",
        shared_secret_alice.len()
    );

    // Example 9: HMAC generation
    println!("\n9. Generating HMAC...");
    let hmac_message = "test/path/123";
    let hmac = alice_cypher.hmac(hmac_message)?;
    if let Some(hmac_value) = hmac {
        println!("   HMAC generated: {}", hex::encode(&hmac_value));
    }

    // Example 10: Working with DeprecatedKeyManager
    println!("\n10. Using DeprecatedKeyManager for backwards compatibility...");
    let deprecated = DeprecatedKeyManager::generate_id25519()?;
    let _dep_id = deprecated.id();
    println!("   DeprecatedKeyManager created");
    println!("   ID includes proof: {}", deprecated.proof.is_some());

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
