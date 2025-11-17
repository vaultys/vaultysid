use vaultysid::{AbstractKeyManager, Ed25519Manager, Result};

fn main() -> Result<()> {
    println!("=== DHIES (Diffie-Hellman Integrated Encryption Scheme) Example ===\n");

    // Create two parties: Alice and Bob
    let alice = Ed25519Manager::generate()?;
    let bob = Ed25519Manager::generate()?;

    println!("1. Generated key pairs for Alice and Bob");
    println!("   Alice ID: {} bytes", alice.id().len());
    println!("   Bob ID: {} bytes", bob.id().len());

    // Message Alice wants to send to Bob
    let secret_message = b"Meet me at the secret location at midnight!";
    println!(
        "\n2. Alice's message: {:?}",
        std::str::from_utf8(secret_message).unwrap()
    );

    // Alice encrypts the message for Bob
    let encrypted = alice.dhies_encrypt(secret_message, &bob.id())?;
    println!("\n3. Alice encrypts the message for Bob");
    println!("   Encrypted size: {} bytes", encrypted.len());
    println!("   Structure: nonce(24) + ephemeral_public(32) + ciphertext + mac(32)");

    // Bob decrypts the message from Alice
    let decrypted = bob.dhies_decrypt(&encrypted, &alice.id())?;
    println!("\n4. Bob decrypts the message from Alice");
    println!(
        "   Decrypted: {:?}",
        std::str::from_utf8(&decrypted).unwrap()
    );

    // Verify the message matches
    assert_eq!(secret_message.to_vec(), decrypted);
    println!("\n✓ Message successfully encrypted and decrypted!");

    // Demonstrate authentication: Eve tries to impersonate Alice
    println!("\n5. Security demonstration:");
    let eve = Ed25519Manager::generate()?;

    // Eve intercepts the encrypted message and tries to decrypt it
    match eve.dhies_decrypt(&encrypted, &alice.id()) {
        Ok(_) => println!("   ✗ Eve could decrypt - security breach!"),
        Err(_) => println!("   ✓ Eve cannot decrypt (not the intended recipient)"),
    }

    // Bob tries to decrypt but with Eve's ID instead of Alice's
    match bob.dhies_decrypt(&encrypted, &eve.id()) {
        Ok(_) => println!("   ✗ Bob accepted Eve as sender - authentication failed!"),
        Err(_) => println!("   ✓ Bob rejects message (wrong sender authentication)"),
    }

    // Demonstrate tampering detection
    let mut tampered = encrypted.clone();
    tampered[60] ^= 0xFF; // Flip some bits in the ciphertext

    match bob.dhies_decrypt(&tampered, &alice.id()) {
        Ok(_) => println!("   ✗ Tampered message accepted - integrity check failed!"),
        Err(_) => println!("   ✓ Tampered message rejected (MAC verification failed)"),
    }

    println!("\n=== DHIES Properties Demonstrated ===");
    println!("• Confidentiality: Only intended recipient can decrypt");
    println!("• Authentication: Sender identity is verified");
    println!("• Integrity: Message tampering is detected");
    println!("• Forward secrecy: Each message uses ephemeral keys");

    Ok(())
}
