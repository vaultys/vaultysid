//! Example demonstrating VaultysId with Dilithium post-quantum cryptography support

use vaultysid::vaultys_id::{Algorithm, VaultysId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== VaultysId with Dilithium Support Example ===\n");

    // 1. Generate different types of identities with Dilithium
    println!("1. Generating Dilithium-based identities...");

    let alice = VaultysId::generate_person_with_alg(Algorithm::Dilithium).await?;
    println!("   ✓ Alice (Person) created with Dilithium");

    let bob = VaultysId::generate_organization_with_alg(Algorithm::Dilithium).await?;
    println!("   ✓ Bob (Organization) created with Dilithium");

    let machine = VaultysId::generate_machine_with_alg(Algorithm::Dilithium).await?;
    println!("   ✓ Machine created with Dilithium");

    // 2. Display identity properties
    println!("\n2. Identity Properties:");
    println!("   Alice:");
    println!("     - Type: Person = {}", alice.is_person());
    println!("     - DID: {}", alice.did());
    println!(
        "     - Fingerprint length: {} bytes",
        alice.fingerprint().len()
    );
    println!(
        "     - ID length: {} bytes (Dilithium public keys are large!)",
        alice.id().len()
    );

    println!("   Bob:");
    println!("     - Type: Organization = {}", bob.is_organization());
    println!("     - DID: {}", bob.did());

    println!("   Machine:");
    println!("     - Type: Machine = {}", machine.is_machine());
    println!("     - DID: {}", machine.did());

    // 3. Post-quantum signatures
    println!("\n3. Post-Quantum Digital Signatures:");
    let message = b"Important message requiring quantum-resistant signature";
    println!("   Message: {:?}", std::str::from_utf8(message)?);

    let signed_challenge = alice.sign_challenge(message).await?;
    println!("   ✓ Alice signed the message");
    println!(
        "   - Signature size: {} bytes (Dilithium signatures are ~2420 bytes)",
        signed_challenge.signature.len()
    );

    // 4. Signature verification
    println!("\n4. Signature Verification:");
    let alice_id = alice.id();
    let alice_public = VaultysId::from_id(&alice_id, None, None)?;
    println!("   ✓ Created public-only version of Alice from ID");

    let is_valid = alice_public.verify_challenge(message, &signed_challenge.signature)?;
    println!(
        "   - Verification result: {}",
        if is_valid { "✓ VALID" } else { "✗ INVALID" }
    );

    // Test with tampered message
    let tampered_message = b"Tampered message";
    let is_tampered_valid =
        alice_public.verify_challenge(tampered_message, &signed_challenge.signature)?;
    println!(
        "   - Tampered message verification: {}",
        if is_tampered_valid {
            "✗ VALID (bad!)"
        } else {
            "✓ INVALID (correct!)"
        }
    );

    // 5. Secret export and import
    println!("\n5. Secret Management:");
    let secret = alice.get_secret()?;
    println!("   - Exported secret size: {} bytes", secret.len());
    println!("   - Note: Dilithium secret keys are much larger than Ed25519!");

    let alice_restored = VaultysId::from_secret(&secret, None)?;
    println!("   ✓ Alice restored from secret");

    // Verify restored identity works
    let new_message = b"Message signed with restored key";
    let restored_signature = alice_restored.sign_challenge(new_message).await?;
    let restored_valid =
        alice_public.verify_challenge(new_message, &restored_signature.signature)?;
    println!(
        "   - Restored key signature: {}",
        if restored_valid {
            "✓ WORKS"
        } else {
            "✗ FAILED"
        }
    );

    // 6. Encryption with X25519 (same for both Ed25519 and Dilithium identities)
    println!("\n6. Hybrid Encryption (DHIES):");
    println!("   Note: Both Ed25519 and Dilithium identities use X25519 for encryption");

    let bob_id = bob.id();
    let secret_data = b"Confidential data encrypted with quantum-resistant identity";

    let encrypted = alice.dhies_encrypt(secret_data, &bob_id).await?;
    println!("   ✓ Alice encrypted message for Bob");
    println!("   - Original size: {} bytes", secret_data.len());
    println!("   - Encrypted size: {} bytes", encrypted.len());

    let decrypted = bob.dhies_decrypt(&encrypted, &alice_id).await?;
    println!("   ✓ Bob decrypted message from Alice");
    println!("   - Decrypted: {:?}", std::str::from_utf8(&decrypted)?);

    let encryption_works = decrypted == secret_data;
    println!(
        "   - Encryption/Decryption: {}",
        if encryption_works {
            "✓ SUCCESS"
        } else {
            "✗ FAILED"
        }
    );

    // 7. Interoperability between Ed25519 and Dilithium
    println!("\n7. Algorithm Interoperability:");

    let ed25519_charlie = VaultysId::generate_person_with_alg(Algorithm::Ed25519).await?;
    println!("   ✓ Charlie created with Ed25519");

    let charlie_id = ed25519_charlie.id();
    println!(
        "   - Charlie's ID size: {} bytes (Ed25519)",
        charlie_id.len()
    );
    println!("   - Alice's ID size: {} bytes (Dilithium)", alice_id.len());

    // They can still exchange encrypted messages (both use X25519)
    let interop_message = b"Message between different signature algorithms";
    let encrypted_interop = alice.dhies_encrypt(interop_message, &charlie_id).await?;
    let decrypted_interop = ed25519_charlie
        .dhies_decrypt(&encrypted_interop, &alice_id)
        .await?;

    let interop_works = decrypted_interop == interop_message;
    println!(
        "   - Cross-algorithm encryption: {}",
        if interop_works {
            "✓ WORKS"
        } else {
            "✗ FAILED"
        }
    );

    // 8. Performance comparison
    println!("\n8. Performance Comparison:");
    use std::time::Instant;

    // Generate Ed25519
    let start = Instant::now();
    let _ed25519_test = VaultysId::generate_machine_with_alg(Algorithm::Ed25519).await?;
    let ed25519_gen_time = start.elapsed();

    // Generate Dilithium
    let start = Instant::now();
    let dilithium_test = VaultysId::generate_machine_with_alg(Algorithm::Dilithium).await?;
    let dilithium_gen_time = start.elapsed();

    println!("   Generation time:");
    println!("   - Ed25519:  {:?}", ed25519_gen_time);
    println!("   - Dilithium: {:?}", dilithium_gen_time);

    // Sign with Dilithium
    let perf_message = b"Performance test";
    let start = Instant::now();
    let perf_signed = dilithium_test.sign_challenge(perf_message).await?;
    let dilithium_sign_time = start.elapsed();

    // Verify with Dilithium
    let start = Instant::now();
    let _verified = dilithium_test.verify_challenge(perf_message, &perf_signed.signature)?;
    let dilithium_verify_time = start.elapsed();

    println!("   Dilithium operations:");
    println!("   - Signing:      {:?}", dilithium_sign_time);
    println!("   - Verification: {:?}", dilithium_verify_time);

    // 9. DID Document
    println!("\n9. DID Document:");
    let did_doc = alice.did_document();
    println!("   Alice's DID Document:");
    println!("{}", serde_json::to_string_pretty(&did_doc)?);

    println!("\n=== Example completed successfully! ===");
    println!("\nKey Takeaways:");
    println!("• Dilithium provides quantum-resistant signatures");
    println!("• Dilithium keys and signatures are much larger than Ed25519");
    println!("• Both algorithms use X25519 for encryption (interoperable)");
    println!("• VaultysId seamlessly supports both algorithms");
    println!("• Choose Dilithium for future-proof security, Ed25519 for efficiency");

    Ok(())
}
