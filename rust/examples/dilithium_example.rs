//! Example demonstrating the usage of DilithiumManager for post-quantum cryptography

use vaultysid::key_manager::abstract_key_manager::AbstractKeyManager;
use vaultysid::key_manager::DilithiumManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== DilithiumManager Example ===\n");

    // Generate a new DilithiumManager with random entropy
    println!("1. Generating a new DilithiumManager...");
    let alice = DilithiumManager::generate()?;
    println!("   ✓ Alice's key manager created");
    println!("   - Auth type: {}", alice.auth_type());
    println!("   - Encryption type: {}", alice.enc_type());

    // Get Alice's ID (public keys)
    let alice_id = alice.id();
    println!("\n2. Alice's ID (public keys):");
    println!("   - ID length: {} bytes", alice_id.len());
    println!("   - ID (hex): {}", hex::encode(&alice_id[..32]));

    // Sign a message
    let message = b"Hello, post-quantum world!";
    println!("\n3. Signing a message:");
    println!("   - Message: {:?}", std::str::from_utf8(message)?);

    let signature = alice
        .sign(message)?
        .expect("Failed to sign - no private key");
    println!("   - Signature length: {} bytes", signature.len());
    println!(
        "   - Signature (first 32 bytes): {}",
        hex::encode(&signature[..32])
    );

    // Create Bob from Alice's ID (public key only)
    println!("\n4. Creating Bob from Alice's ID (public verification):");
    let bob = DilithiumManager::from_id(&alice_id)?;
    println!("   ✓ Bob's key manager created from Alice's ID");

    // Bob verifies Alice's signature
    let is_valid = bob.verify(message, &signature);
    println!("\n5. Bob verifies Alice's signature:");
    println!(
        "   - Verification result: {}",
        if is_valid { "✓ VALID" } else { "✗ INVALID" }
    );

    // Test with wrong message
    let wrong_message = b"This is a different message";
    let is_valid_wrong = bob.verify(wrong_message, &signature);
    println!("\n6. Verification with wrong message:");
    println!(
        "   - Wrong message: {:?}",
        std::str::from_utf8(wrong_message)?
    );
    println!(
        "   - Verification result: {}",
        if is_valid_wrong {
            "✗ VALID (should not be!)"
        } else {
            "✓ INVALID (as expected)"
        }
    );

    // Export and import secret
    println!("\n7. Secret export/import:");
    let secret = alice.get_secret()?;
    println!("   - Exported secret length: {} bytes", secret.len());

    let alice_restored = DilithiumManager::from_secret(&secret)?;
    println!("   ✓ Key manager restored from secret");

    // Verify the restored key manager can sign and verify
    let new_signature = alice_restored
        .sign(message)?
        .expect("Failed to sign with restored key");
    let is_restored_valid = bob.verify(message, &new_signature);
    println!(
        "   - Restored key verification: {}",
        if is_restored_valid {
            "✓ WORKS"
        } else {
            "✗ FAILED"
        }
    );

    // Demonstrate Diffie-Hellman for encryption
    println!("\n8. Diffie-Hellman key exchange (for encryption):");

    // Generate another key manager for Charlie
    let charlie = DilithiumManager::generate()?;
    println!("   ✓ Charlie's key manager created");

    // Alice performs DH with Charlie
    let alice_charlie_shared = alice.perform_diffie_hellman(&charlie)?;
    println!(
        "   - Alice-Charlie shared secret: {} bytes",
        alice_charlie_shared.len()
    );

    // Charlie performs DH with Alice (should produce same shared secret)
    let charlie_alice_shared = charlie.perform_diffie_hellman(&alice)?;
    println!(
        "   - Charlie-Alice shared secret: {} bytes",
        charlie_alice_shared.len()
    );

    let dh_match = alice_charlie_shared == charlie_alice_shared;
    println!(
        "   - Shared secrets match: {}",
        if dh_match { "✓ YES" } else { "✗ NO" }
    );

    // DHIES encryption example
    println!("\n9. DHIES Encryption:");
    let secret_message = b"This is a secret message encrypted with DHIES";
    let charlie_id = charlie.id();

    let encrypted = alice.dhies_encrypt(secret_message, &charlie_id)?;
    println!(
        "   - Original message: {:?}",
        std::str::from_utf8(secret_message)?
    );
    println!("   - Encrypted length: {} bytes", encrypted.len());

    let decrypted = charlie.dhies_decrypt(&encrypted, &alice_id)?;
    println!(
        "   - Decrypted message: {:?}",
        std::str::from_utf8(&decrypted)?
    );

    let encryption_works = decrypted == secret_message;
    println!(
        "   - Encryption/Decryption: {}",
        if encryption_works {
            "✓ SUCCESS"
        } else {
            "✗ FAILED"
        }
    );

    println!("\n=== Example completed successfully! ===");
    Ok(())
}
