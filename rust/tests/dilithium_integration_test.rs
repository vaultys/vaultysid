use vaultysid::vaultys_id::{Algorithm, VaultysId};

#[tokio::test]
async fn test_dilithium_vaultys_id_generation() {
    // Test generating different types of IDs with Dilithium
    let machine = VaultysId::generate_machine_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();
    let person = VaultysId::generate_person_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();
    let org = VaultysId::generate_organization_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();

    assert!(machine.is_machine());
    assert!(!machine.is_person());
    assert!(!machine.is_organization());

    assert!(person.is_person());
    assert!(!person.is_machine());
    assert!(!person.is_organization());

    assert!(org.is_organization());
    assert!(!org.is_machine());
    assert!(!org.is_person());

    // Check that IDs are much larger than Ed25519 (Dilithium public keys are ~1952 bytes)
    let machine_id = machine.id();
    let person_id = person.id();
    let org_id = org.id();

    // Dilithium IDs should be around 1351+ bytes (with type byte)
    assert!(
        machine_id.len() > 1300,
        "Machine ID too small: {}",
        machine_id.len()
    );
    assert!(
        person_id.len() > 1300,
        "Person ID too small: {}",
        person_id.len()
    );
    assert!(org_id.len() > 1300, "Org ID too small: {}", org_id.len());
}

#[tokio::test]
async fn test_dilithium_id_serialization_round_trip() {
    let original = VaultysId::generate_person_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();
    let id_bytes = original.id();

    // Test that we can reconstruct from ID
    let reconstructed = VaultysId::from_id(&id_bytes, None, None).unwrap();

    // Public information should match
    assert_eq!(original.fingerprint(), reconstructed.fingerprint());
    assert_eq!(original.did(), reconstructed.did());
}

#[tokio::test]
async fn test_dilithium_secret_round_trip() {
    let original = VaultysId::generate_machine_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();

    // Export secret
    let secret = original.get_secret().unwrap();

    // Secret should be large due to Dilithium secret key size
    assert_eq!(secret.len(), 73, "Secret too small: {}", secret.len());

    // Import from secret
    let restored = VaultysId::from_secret(&secret, None).unwrap();

    // Should have same public properties
    assert_eq!(original.id(), restored.id());
    assert_eq!(original.fingerprint(), restored.fingerprint());
    assert_eq!(original.did(), restored.did());

    // Should be able to sign with restored key
    let message = b"Test message for signing";
    let signed = restored.sign_challenge(message).await.unwrap();

    // Original should verify signature from restored
    assert!(original
        .verify_challenge(message, &signed.signature)
        .unwrap());
}

#[tokio::test]
async fn test_dilithium_signing_and_verification() {
    let id = VaultysId::generate_machine_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();

    // Test signing
    let challenge = b"test challenge data for Dilithium";
    let signed = id.sign_challenge(challenge).await.unwrap();

    // Dilithium signatures are around 2420 bytes
    assert!(
        signed.signature.len() > 2000,
        "Signature too small: {}",
        signed.signature.len()
    );

    // Test verification with correct challenge
    assert!(id.verify_challenge(challenge, &signed.signature).unwrap());

    // Test verification with wrong challenge
    let wrong_challenge = b"wrong challenge data";
    assert!(!id
        .verify_challenge(wrong_challenge, &signed.signature)
        .unwrap());
}

#[tokio::test]
async fn test_dilithium_cross_verification() {
    // Create a Dilithium ID
    let alice = VaultysId::generate_person_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();

    // Get Alice's public ID
    let alice_id = alice.id();

    // Create Bob from Alice's public ID (no private key)
    let bob = VaultysId::from_id(&alice_id, None, None).unwrap();

    // Alice signs a message
    let message = b"Message from Alice using Dilithium";
    let signed = alice.sign_challenge(message).await.unwrap();

    // Bob should be able to verify Alice's signature
    assert!(bob.verify_challenge(message, &signed.signature).unwrap());

    // Bob should not verify with wrong message
    let wrong_message = b"Tampered message";
    assert!(!bob
        .verify_challenge(wrong_message, &signed.signature)
        .unwrap());
}

#[tokio::test]
async fn test_dilithium_dhies_encryption() {
    // Create two Dilithium-based identities
    let alice = VaultysId::generate_person_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();
    let bob = VaultysId::generate_person_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();

    let alice_id = alice.id();
    let bob_id = bob.id();

    // Alice encrypts a message for Bob
    let secret_message = b"Secret message using Dilithium identity";
    let encrypted = alice.dhies_encrypt(secret_message, &bob_id).await.unwrap();

    // Bob decrypts the message from Alice
    let decrypted = bob.dhies_decrypt(&encrypted, &alice_id).await.unwrap();

    assert_eq!(secret_message.to_vec(), decrypted);
}

#[tokio::test]
async fn test_mixed_algorithm_interaction() {
    // Create Ed25519 and Dilithium identities
    let ed25519_id = VaultysId::generate_person_with_alg(Algorithm::Ed25519)
        .await
        .unwrap();
    let dilithium_id = VaultysId::generate_person_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();

    // Get their IDs
    let ed25519_id_bytes = ed25519_id.id();
    let dilithium_id_bytes = dilithium_id.id();

    // Ed25519 ID should be much smaller
    assert!(
        ed25519_id_bytes.len() < 100,
        "Ed25519 ID unexpectedly large"
    );
    assert!(
        dilithium_id_bytes.len() > 1300,
        "Dilithium ID unexpectedly small"
    );

    // They can still perform DHIES encryption with each other
    // (both use X25519 for encryption regardless of signature algorithm)
    let message = b"Cross-algorithm message";
    let encrypted = ed25519_id
        .dhies_encrypt(message, &dilithium_id_bytes)
        .await
        .unwrap();
    let decrypted = dilithium_id
        .dhies_decrypt(&encrypted, &ed25519_id_bytes)
        .await
        .unwrap();

    assert_eq!(message.to_vec(), decrypted);
}

#[tokio::test]
async fn test_dilithium_performance_comparison() {
    use std::time::Instant;

    // Generate and time Ed25519
    let start = Instant::now();
    let _ed25519 = VaultysId::generate_machine_with_alg(Algorithm::Ed25519)
        .await
        .unwrap();
    let ed25519_gen_time = start.elapsed();

    // Generate and time Dilithium
    let start = Instant::now();
    let dilithium = VaultysId::generate_machine_with_alg(Algorithm::Dilithium)
        .await
        .unwrap();
    let dilithium_gen_time = start.elapsed();

    println!("Ed25519 generation time: {:?}", ed25519_gen_time);
    println!("Dilithium generation time: {:?}", dilithium_gen_time);

    // Test signing performance
    let message = b"Performance test message";

    // Time Dilithium signing
    let start = Instant::now();
    let signed = dilithium.sign_challenge(message).await.unwrap();
    let dilithium_sign_time = start.elapsed();

    // Time Dilithium verification
    let start = Instant::now();
    let verified = dilithium
        .verify_challenge(message, &signed.signature)
        .unwrap();
    let dilithium_verify_time = start.elapsed();

    assert!(verified);

    println!("Dilithium signing time: {:?}", dilithium_sign_time);
    println!("Dilithium verification time: {:?}", dilithium_verify_time);
}
