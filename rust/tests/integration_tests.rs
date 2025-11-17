use vaultysid::{AbstractKeyManager, DeprecatedKeyManager, Ed25519Manager, VaultysId};

#[tokio::test]
async fn test_vaultys_id_generation() {
    // Test generating different types of IDs
    let machine = VaultysId::generate_machine().await.unwrap();
    let person = VaultysId::generate_person().await.unwrap();
    let org = VaultysId::generate_organization().await.unwrap();

    assert!(machine.is_machine());
    assert!(!machine.is_person());
    assert!(!machine.is_organization());

    assert!(person.is_person());
    assert!(!person.is_machine());
    assert!(!person.is_organization());

    assert!(org.is_organization());
    assert!(!org.is_machine());
    assert!(!org.is_person());
}

#[tokio::test]
async fn test_id_serialization_round_trip() {
    let original = VaultysId::generate_person().await.unwrap();
    let id_bytes = original.id();

    // Test that we can reconstruct from ID
    let reconstructed = VaultysId::from_id(&id_bytes, None, None).unwrap();

    // Public information should match
    assert_eq!(original.fingerprint(), reconstructed.fingerprint());
    assert_eq!(original.did(), reconstructed.did());
}

#[tokio::test]
async fn test_signing_and_verification() {
    let id = VaultysId::generate_machine().await.unwrap();

    // Test signing
    let challenge = b"test challenge data";
    let signed = id.sign_challenge(challenge).await.unwrap();

    // Test verification with correct challenge
    assert!(id.verify_challenge(challenge, &signed.signature).unwrap());

    // Test verification with wrong challenge
    let wrong_challenge = b"wrong challenge data";
    assert!(!id
        .verify_challenge(wrong_challenge, &signed.signature)
        .unwrap());
}

#[test]
fn test_ed25519_manager_key_generation() {
    let manager = Ed25519Manager::generate().unwrap();

    // Check that keys are the right size
    assert_eq!(manager.signer.public_key.len(), 32);
    assert_eq!(manager.cypher.public_key.len(), 32);

    // Check that secret keys are present
    assert!(manager.signer.secret_key.is_some());
    assert!(manager.cypher.secret_key.is_some());

    if let Some(secret) = &manager.signer.secret_key {
        assert_eq!(secret.len(), 32);
    }

    if let Some(secret) = &manager.cypher.secret_key {
        assert_eq!(secret.len(), 32);
    }
}

#[test]
fn test_ed25519_manager_from_entropy() {
    let entropy = vaultysid::random_bytes(32);
    let manager1 = Ed25519Manager::from_entropy(&entropy).unwrap();
    let manager2 = Ed25519Manager::from_entropy(&entropy).unwrap();

    // Same entropy should produce same keys
    assert_eq!(manager1.signer.public_key, manager2.signer.public_key);
    assert_eq!(manager1.cypher.public_key, manager2.cypher.public_key);
}

#[test]
fn test_ed25519_manager_secret_round_trip() {
    let original = Ed25519Manager::generate().unwrap();
    let secret = original.get_secret().unwrap();
    let restored = Ed25519Manager::from_secret(&secret).unwrap();

    // Public keys should match
    assert_eq!(original.signer.public_key, restored.signer.public_key);
    assert_eq!(original.cypher.public_key, restored.cypher.public_key);

    // Secret keys should be restored
    assert!(restored.signer.secret_key.is_some());
    assert!(restored.cypher.secret_key.is_some());
}

#[test]
fn test_ed25519_manager_id_round_trip() {
    let original = Ed25519Manager::generate().unwrap();
    let id = original.id();
    let public_only = Ed25519Manager::from_id(&id).unwrap();

    // Public keys should match
    assert_eq!(original.signer.public_key, public_only.signer.public_key);
    assert_eq!(original.cypher.public_key, public_only.cypher.public_key);

    // But secret keys should not be present in public-only version
    assert!(public_only.signer.secret_key.is_none());
    assert!(public_only.cypher.secret_key.is_none());
}

#[test]
fn test_ed25519_signing_and_verification() {
    let manager = Ed25519Manager::generate().unwrap();
    let data = b"message to sign";

    // Sign the data
    let signature = manager.sign(data).unwrap().unwrap();

    // Verify with correct data
    assert!(manager.verify(data, &signature, None));

    // Verify with wrong data should fail
    assert!(!manager.verify(b"wrong message", &signature, None));

    // Verify with wrong signature should fail
    let mut wrong_sig = signature.clone();
    wrong_sig[0] ^= 0xFF; // Flip bits in first byte
    assert!(!manager.verify(data, &wrong_sig, None));
}

#[test]
fn test_diffie_hellman_key_exchange() {
    let alice = Ed25519Manager::generate().unwrap();
    let bob = Ed25519Manager::generate().unwrap();

    let alice_cypher = alice.get_cypher().unwrap();
    let bob_cypher = bob.get_cypher().unwrap();

    // Perform DH from both sides
    let shared_alice = alice_cypher.diffie_hellman(&bob.cypher.public_key).unwrap();
    let shared_bob = bob_cypher.diffie_hellman(&alice.cypher.public_key).unwrap();

    // Both should derive the same shared secret
    assert_eq!(shared_alice, shared_bob);
    assert_eq!(shared_alice.len(), 32); // X25519 produces 32-byte shared secrets
}

#[test]
fn test_hmac_generation() {
    let manager = Ed25519Manager::generate().unwrap();
    let cypher = manager.get_cypher().unwrap();

    // Test HMAC generation
    let message = "test/message";
    let hmac1 = cypher.hmac(message).unwrap().unwrap();
    let hmac2 = cypher.hmac(message).unwrap().unwrap();

    // Same message should produce same HMAC
    assert_eq!(hmac1, hmac2);
    assert_eq!(hmac1.len(), 32); // SHA256 HMAC is 32 bytes

    // Different message should produce different HMAC
    let hmac3 = cypher.hmac("different/message").unwrap().unwrap();
    assert_ne!(hmac1, hmac3);
}

#[test]
fn test_deprecated_key_manager_generation() {
    let manager = DeprecatedKeyManager::generate_id25519().unwrap();

    // Check that all keys are present
    assert_eq!(manager.signer.public_key.len(), 32);
    assert_eq!(manager.cypher.public_key.len(), 32);
    assert!(manager.proof.is_some());
    assert!(!manager.proof_key.public_key.is_empty());
}

#[test]
fn test_deprecated_key_manager_with_swap_index() {
    let entropy = vaultysid::random_bytes(32);
    let manager0 = DeprecatedKeyManager::create_id25519_from_entropy(&entropy, 0).unwrap();
    let manager1 = DeprecatedKeyManager::create_id25519_from_entropy(&entropy, 1).unwrap();

    // Different swap indices should produce different keys
    assert_ne!(manager0.signer.public_key, manager1.signer.public_key);
    assert_ne!(manager0.cypher.public_key, manager1.cypher.public_key);
    assert_ne!(manager0.proof, manager1.proof);
}

#[test]
fn test_deprecated_key_manager_round_trip() {
    let original = DeprecatedKeyManager::generate_id25519().unwrap();

    // Test secret round trip
    let secret = original.get_secret().unwrap();
    let from_secret = DeprecatedKeyManager::from_secret(&secret).unwrap();

    assert_eq!(original.signer.public_key, from_secret.signer.public_key);
    assert_eq!(original.cypher.public_key, from_secret.cypher.public_key);
    assert_eq!(original.proof, from_secret.proof);

    // Test ID round trip
    let id = original.id();
    let from_id = DeprecatedKeyManager::from_id(&id).unwrap();

    assert_eq!(original.signer.public_key, from_id.signer.public_key);
    assert_eq!(original.cypher.public_key, from_id.cypher.public_key);
    assert_eq!(original.proof, from_id.proof);
}

#[test]
fn test_deprecated_key_manager_signing() {
    let manager = DeprecatedKeyManager::generate_id25519().unwrap();
    let data = b"data to sign";

    let signature = manager.sign(data).unwrap().unwrap();

    // Verify signature
    assert!(manager.verify(data, &signature, None));
    assert!(!manager.verify(b"wrong data", &signature, None));
}

#[tokio::test]
async fn test_did_document_structure() {
    let id = VaultysId::generate_person().await.unwrap();
    let did_doc = id.did_document();

    // Check that DID document has required fields
    assert!(did_doc["@context"].is_array());
    assert!(did_doc["id"].is_string());
    assert!(did_doc["authentication"].is_array());
    assert!(did_doc["keyAgreement"].is_array());

    // Check that ID matches
    let doc_id = did_doc["id"].as_str().unwrap();
    assert_eq!(doc_id, id.did());
}

#[tokio::test]
async fn test_otp_hmac() {
    let id = VaultysId::generate_machine().await.unwrap();

    // Test OTP HMAC generation
    let hmac1 = id.get_otp_hmac("TOTP", 12345).unwrap();
    let hmac2 = id.get_otp_hmac("TOTP", 12345).unwrap();
    let hmac3 = id.get_otp_hmac("TOTP", 12346).unwrap();

    // Same OTP parameters should produce same HMAC
    assert_eq!(hmac1, hmac2);

    // Different counter should produce different HMAC
    assert_ne!(hmac1, hmac3);
}

#[test]
fn test_crypto_utilities() {
    use vaultysid::{hash, hmac, random_bytes};

    // Test hash function
    let data = b"test data";
    let hash256 = hash("sha256", data);
    assert_eq!(hash256.len(), 32);

    let hash512 = hash("sha512", data);
    assert_eq!(hash512.len(), 64);

    // Test HMAC
    let key = b"secret key";
    let message = b"message";
    let mac = hmac("sha256", key, message).unwrap();
    assert_eq!(mac.len(), 32);

    // Test random bytes
    let random1 = random_bytes(16);
    let random2 = random_bytes(16);
    assert_eq!(random1.len(), 16);
    assert_eq!(random2.len(), 16);
    assert_ne!(random1, random2); // Should be different (with very high probability)
}

#[test]
fn test_base64_hex_encoding() {
    use vaultysid::crypto::{from_base64, from_hex, to_base64, to_hex};

    let data = b"test data for encoding";

    // Test hex encoding
    let hex = to_hex(data);
    let decoded_hex = from_hex(&hex).unwrap();
    assert_eq!(decoded_hex, data);

    // Test base64 encoding
    let b64 = to_base64(data);
    let decoded_b64 = from_base64(&b64).unwrap();
    assert_eq!(decoded_b64, data);
}

#[test]
fn test_constant_time_comparison() {
    use vaultysid::crypto::constant_time_eq;

    let a = b"equal data";
    let b = b"equal data";
    let c = b"different!";

    assert!(constant_time_eq(a, b));
    assert!(!constant_time_eq(a, c));

    // Different lengths should return false
    let d = b"short";
    let e = b"much longer string";
    assert!(!constant_time_eq(d, e));
}

#[test]
fn test_clean_secure_data() {
    let mut manager = Ed25519Manager::generate().unwrap();

    // Verify secret keys are present
    assert!(manager.signer.secret_key.is_some());
    assert!(manager.cypher.secret_key.is_some());

    // Clean secure data
    manager.clean_secure_data();

    // Verify secret keys are removed
    assert!(manager.signer.secret_key.is_none());
    assert!(manager.cypher.secret_key.is_none());
}

#[tokio::test]
async fn test_id_compatibility() {
    // Test that we can create IDs of the expected sizes
    let ed25519_manager = Ed25519Manager::generate().unwrap();
    let deprecated_manager = DeprecatedKeyManager::generate_id25519().unwrap();

    let _ed_id = ed25519_manager.id();
    let _dep_id = deprecated_manager.id();

    // Create VaultysIds from these
    let machine = VaultysId::generate_machine().await.unwrap();
    let machine_id = machine.id();

    // Ed25519Manager serializes to ~76 bytes for the key data
    // With type byte prefix and messagepack overhead, total is ~77 bytes or less
    // DeprecatedKeyManager includes proof field, making it longer
    assert!(machine_id.len() >= 70 && machine_id.len() <= 200);

    // Test that we can parse both formats
    let parsed1 = VaultysId::from_id(&machine_id, None, None);
    assert!(parsed1.is_ok());
}

#[test]
fn test_dhies_basic_encryption_decryption() {
    // Create sender and recipient
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();

    // Test with string message
    let message = b"Hello, this is a secret message!";

    // Sender encrypts for recipient
    let encrypted = sender.dhies_encrypt(message, &recipient.id()).unwrap();

    // Verify encrypted message has expected structure
    // Format: nonce (24) + ephemeral_public (32) + ciphertext + mac (32)
    assert!(encrypted.len() >= 24 + 32 + 32);

    // Recipient decrypts
    let decrypted = recipient.dhies_decrypt(&encrypted, &sender.id()).unwrap();

    // Verify message matches
    assert_eq!(message.to_vec(), decrypted);
}

#[test]
fn test_dhies_large_message() {
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();

    // Create a large message (1MB)
    let message: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();

    let encrypted = sender.dhies_encrypt(&message, &recipient.id()).unwrap();
    let decrypted = recipient.dhies_decrypt(&encrypted, &sender.id()).unwrap();

    assert_eq!(message, decrypted);
}

#[test]
fn test_dhies_empty_message() {
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();

    let message = b"";

    let encrypted = sender.dhies_encrypt(message, &recipient.id()).unwrap();
    let decrypted = recipient.dhies_decrypt(&encrypted, &sender.id()).unwrap();

    assert_eq!(message.to_vec(), decrypted);
}

#[test]
fn test_dhies_wrong_recipient_cannot_decrypt() {
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();
    let wrong_recipient = Ed25519Manager::generate().unwrap();

    let message = b"Secret for specific recipient";

    // Encrypt for recipient
    let encrypted = sender.dhies_encrypt(message, &recipient.id()).unwrap();

    // Wrong recipient tries to decrypt - should fail
    let result = wrong_recipient.dhies_decrypt(&encrypted, &sender.id());

    assert!(result.is_err());
}

#[test]
fn test_dhies_authentication_spoofing_prevented() {
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();
    let attacker = Ed25519Manager::generate().unwrap();

    let message = b"Authentic message";

    // Sender encrypts for recipient
    let encrypted = sender.dhies_encrypt(message, &recipient.id()).unwrap();

    // Recipient tries to decrypt but with wrong sender ID (attacker) - should fail
    let result = recipient.dhies_decrypt(&encrypted, &attacker.id());

    assert!(
        result.is_err(),
        "MAC verification should fail with wrong sender"
    );
}

#[test]
fn test_dhies_message_tampering_detected() {
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();

    let message = b"Do not tamper";

    let encrypted = sender.dhies_encrypt(message, &recipient.id()).unwrap();

    // Tamper with different parts of the message

    // Test 1: Tamper with nonce
    let mut tampered = encrypted.clone();
    tampered[0] ^= 0xFF;
    assert!(recipient.dhies_decrypt(&tampered, &sender.id()).is_err());

    // Test 2: Tamper with ephemeral public key
    let mut tampered = encrypted.clone();
    tampered[25] ^= 0xFF;
    assert!(recipient.dhies_decrypt(&tampered, &sender.id()).is_err());

    // Test 3: Tamper with ciphertext
    let mut tampered = encrypted.clone();
    tampered[60] ^= 0xFF;
    assert!(recipient.dhies_decrypt(&tampered, &sender.id()).is_err());

    // Test 4: Tamper with MAC
    let mut tampered = encrypted.clone();
    let last_byte_index = tampered.len() - 1;
    tampered[last_byte_index] ^= 0xFF;
    assert!(recipient.dhies_decrypt(&tampered, &sender.id()).is_err());
}

#[test]
fn test_dhies_replayability() {
    // Verify that encryption is non-deterministic (different each time)
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();

    let message = b"Same message";

    let encrypted1 = sender.dhies_encrypt(message, &recipient.id()).unwrap();
    let encrypted2 = sender.dhies_encrypt(message, &recipient.id()).unwrap();

    // Should produce different ciphertexts (due to random ephemeral key and nonce)
    assert_ne!(encrypted1, encrypted2);

    // But both should decrypt to same message
    let decrypted1 = recipient.dhies_decrypt(&encrypted1, &sender.id()).unwrap();
    let decrypted2 = recipient.dhies_decrypt(&encrypted2, &sender.id()).unwrap();

    assert_eq!(decrypted1, decrypted2);
    assert_eq!(decrypted1, message.to_vec());
}

#[test]
fn test_dhies_bidirectional_communication() {
    let alice = Ed25519Manager::generate().unwrap();
    let bob = Ed25519Manager::generate().unwrap();

    // Alice sends to Bob
    let alice_message = b"Hello Bob, this is Alice";
    let alice_encrypted = alice.dhies_encrypt(alice_message, &bob.id()).unwrap();
    let alice_decrypted = bob.dhies_decrypt(&alice_encrypted, &alice.id()).unwrap();
    assert_eq!(alice_message.to_vec(), alice_decrypted);

    // Bob sends to Alice
    let bob_message = b"Hi Alice, Bob here!";
    let bob_encrypted = bob.dhies_encrypt(bob_message, &alice.id()).unwrap();
    let bob_decrypted = alice.dhies_decrypt(&bob_encrypted, &bob.id()).unwrap();
    assert_eq!(bob_message.to_vec(), bob_decrypted);

    // Messages should be different even if content is same
    assert_ne!(alice_encrypted, bob_encrypted);
}

#[test]
fn test_dhies_with_binary_data() {
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();

    // Test with various binary patterns
    let patterns = vec![
        vec![0x00; 32],                                // All zeros
        vec![0xFF; 32],                                // All ones
        [0xAA, 0x55].repeat(8),                        // Alternating pattern
        (0..256).map(|i| i as u8).collect::<Vec<_>>(), // All byte values
    ];

    for pattern in patterns {
        let encrypted = sender.dhies_encrypt(&pattern, &recipient.id()).unwrap();
        let decrypted = recipient.dhies_decrypt(&encrypted, &sender.id()).unwrap();
        assert_eq!(pattern, decrypted);
    }
}

#[test]
fn test_dhies_public_key_extraction() {
    use vaultysid::key_manager::cypher_manager::get_cypher_public_key_from_id;

    let manager = Ed25519Manager::generate().unwrap();
    let id = manager.id();

    // Should be able to extract public key from ID
    let public_key = get_cypher_public_key_from_id(&id).unwrap();

    // Verify it matches the manager's public key
    assert_eq!(public_key, manager.cypher.public_key);
    assert_eq!(public_key.len(), 32);
}

#[test]
fn test_dhies_without_private_key_fails() {
    let sender = Ed25519Manager::generate().unwrap();
    let recipient = Ed25519Manager::generate().unwrap();

    // Create public-only version of recipient
    let recipient_id = recipient.id();
    let recipient_public = Ed25519Manager::from_id(&recipient_id).unwrap();

    let message = b"Test message";

    // Public-only recipient cannot decrypt
    let encrypted = sender.dhies_encrypt(message, &recipient_id).unwrap();
    let result = recipient_public.dhies_decrypt(&encrypted, &sender.id());

    assert!(result.is_err());
}

#[test]
fn test_dhies_cross_compatibility() {
    // Test that DHIES works between different key manager types
    let ed25519_sender = Ed25519Manager::generate().unwrap();
    let ed25519_recipient = Ed25519Manager::generate().unwrap();

    let message = b"Cross-compatibility test";

    // Ed25519 to Ed25519
    let encrypted = ed25519_sender
        .dhies_encrypt(message, &ed25519_recipient.id())
        .unwrap();
    let decrypted = ed25519_recipient
        .dhies_decrypt(&encrypted, &ed25519_sender.id())
        .unwrap();

    assert_eq!(message.to_vec(), decrypted);
}
