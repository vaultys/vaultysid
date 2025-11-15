use crate::crypto::{constant_time_eq, hash, hmac, random_bytes, secure_erase};
use crate::error::{Error, Result};
use crate::key_manager::{Capability, KeyPairImpl};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// DHIES (Diffie-Hellman Integrated Encryption Scheme) implementation
pub struct DHIES<'a> {
    key_manager: &'a dyn CypherOperations,
}

impl<'a> DHIES<'a> {
    pub fn new(key_manager: &'a dyn CypherOperations) -> Self {
        Self { key_manager }
    }

    /// Encrypts a message for a recipient using DHIES
    pub fn encrypt(&self, message: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        if !self.key_manager.has_private_capability() {
            return Err(Error::InvalidCapability);
        }

        // Generate ephemeral keypair for this encryption
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Parse recipient's public key
        if recipient_public_key.len() != 32 {
            return Err(Error::InvalidKeyFormat(
                "Recipient public key must be 32 bytes".into(),
            ));
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(recipient_public_key);
        let recipient_pk = PublicKey::from(pk_bytes);

        // Derive shared secret using ephemeral private key and recipient's public key
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

        // Key derivation: derive encryption and MAC keys from shared secret
        // Using sender's public key (not ephemeral) for authentication
        let kdf_output = self.kdf(
            shared_secret.as_bytes(),
            self.key_manager.get_cypher_public_key(),
            recipient_public_key,
        );

        // Generate nonce for XChaCha20-Poly1305
        let nonce_bytes = random_bytes(24);
        let nonce_array: [u8; 24] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::EncryptionFailed("Invalid nonce size".into()))?;
        let nonce = XNonce::from(nonce_array);

        // Encrypt the message
        let cipher = XChaCha20Poly1305::new_from_slice(&kdf_output.encryption_key)
            .map_err(|_| Error::EncryptionFailed("Failed to create cipher".into()))?;

        let ciphertext = cipher
            .encrypt(&nonce, message)
            .map_err(|_| Error::EncryptionFailed("Encryption failed".into()))?;

        // Compute MAC over sender's public key + nonce + ciphertext
        let mut data_to_authenticate = Vec::new();
        data_to_authenticate.extend_from_slice(self.key_manager.get_cypher_public_key());
        data_to_authenticate.extend_from_slice(&nonce_bytes);
        data_to_authenticate.extend_from_slice(&ciphertext);

        let mac = self.compute_mac(&kdf_output.mac_key, &data_to_authenticate);

        // Construct final message: nonce || ephemeral_public || ciphertext || mac
        let mut encrypted_message = Vec::new();
        encrypted_message.extend_from_slice(&nonce_bytes);
        encrypted_message.extend_from_slice(ephemeral_public.as_bytes());
        encrypted_message.extend_from_slice(&ciphertext);
        encrypted_message.extend_from_slice(&mac);

        // Securely erase sensitive data
        let mut kdf_output = kdf_output;
        secure_erase(&mut kdf_output.encryption_key);
        secure_erase(&mut kdf_output.mac_key);

        Ok(encrypted_message)
    }

    /// Decrypts a message encrypted with DHIES
    pub fn decrypt(&self, encrypted_message: &[u8], sender_public_key: &[u8]) -> Result<Vec<u8>> {
        if !self.key_manager.has_private_capability() {
            return Err(Error::InvalidCapability);
        }

        // Extract components: nonce (24) + ephemeral_public (32) + ciphertext + mac (32)
        if encrypted_message.len() < 24 + 32 + 32 {
            return Err(Error::InvalidMessageFormat);
        }

        let nonce_bytes = &encrypted_message[0..24];
        let ephemeral_public_bytes = &encrypted_message[24..56];
        let mac = &encrypted_message[encrypted_message.len() - 32..];
        let ciphertext = &encrypted_message[56..encrypted_message.len() - 32];

        // Parse ephemeral public key
        let mut ephemeral_pk_array = [0u8; 32];
        ephemeral_pk_array.copy_from_slice(ephemeral_public_bytes);
        let ephemeral_public = PublicKey::from(ephemeral_pk_array);

        // Get our secret key
        let our_secret = self
            .key_manager
            .get_cypher_secret_key()
            .ok_or(Error::KeyNotAvailable)?;

        if our_secret.len() != 32 {
            return Err(Error::InvalidKeyFormat(
                "Secret key must be 32 bytes".into(),
            ));
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(our_secret);
        let static_secret = StaticSecret::from(secret_bytes);

        // Derive shared secret using recipient's private key and ephemeral public key
        let shared_secret = static_secret.diffie_hellman(&ephemeral_public);

        // Key derivation: derive encryption and MAC keys
        let kdf_output = self.kdf(
            shared_secret.as_bytes(),
            sender_public_key,
            self.key_manager.get_cypher_public_key(),
        );

        // Verify MAC
        let mut data_to_authenticate = Vec::new();
        data_to_authenticate.extend_from_slice(sender_public_key);
        data_to_authenticate.extend_from_slice(nonce_bytes);
        data_to_authenticate.extend_from_slice(ciphertext);

        let computed_mac = self.compute_mac(&kdf_output.mac_key, &data_to_authenticate);

        if !constant_time_eq(&computed_mac, mac) {
            return Err(Error::MacVerificationFailed);
        }

        // Decrypt the ciphertext
        let cipher = XChaCha20Poly1305::new_from_slice(&kdf_output.encryption_key)
            .map_err(|_| Error::DecryptionFailed("Failed to create cipher".into()))?;

        let nonce_array: [u8; 24] = nonce_bytes
            .try_into()
            .map_err(|_| Error::DecryptionFailed("Invalid nonce size".into()))?;
        let nonce = XNonce::from(nonce_array);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| Error::DecryptionFailed("Decryption failed".into()))?;

        // Securely erase sensitive data
        let mut kdf_output = kdf_output;
        secure_erase(&mut kdf_output.encryption_key);
        secure_erase(&mut kdf_output.mac_key);
        secure_erase(&mut secret_bytes);

        Ok(plaintext)
    }

    /// Key Derivation Function
    fn kdf(
        &self,
        shared_secret: &[u8],
        ephemeral_public: &[u8],
        static_public: &[u8],
    ) -> KdfOutput {
        // Create context for domain separation
        let mut context = Vec::new();
        context.extend_from_slice(b"DHIES-KDF");
        context.extend_from_slice(ephemeral_public);
        context.extend_from_slice(static_public);

        // Derive encryption key
        let mut enc_input = Vec::new();
        enc_input.extend_from_slice(shared_secret);
        enc_input.extend_from_slice(&context);
        enc_input.push(0x01); // Domain separation byte
        let enc_key_material = hash("sha512", &enc_input);

        // Derive MAC key
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(shared_secret);
        mac_input.extend_from_slice(&context);
        mac_input.push(0x02); // Domain separation byte
        let mac_key_material = hash("sha512", &mac_input);

        KdfOutput {
            encryption_key: enc_key_material[0..32].to_vec(),
            mac_key: mac_key_material[0..32].to_vec(),
        }
    }

    /// Compute MAC for authenticated encryption
    fn compute_mac(&self, mac_key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(mac_key);
        input.extend_from_slice(data);
        hash("sha256", &input)
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct KdfOutput {
    encryption_key: Vec<u8>,
    mac_key: Vec<u8>,
}

/// Trait for cypher operations
pub trait CypherOperations {
    fn has_private_capability(&self) -> bool;
    fn get_cypher_public_key(&self) -> &[u8];
    fn get_cypher_secret_key(&self) -> Option<&[u8]>;
}

/// Extract cypher public key from an ID
pub fn get_cypher_public_key_from_id(id: &[u8]) -> Result<Vec<u8>> {
    use rmp_serde::from_slice;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct IdData {
        #[serde(default, rename = "v")]
        _v: u8,
        #[serde(with = "serde_bytes", rename = "x")]
        _x: Vec<u8>,
        #[serde(with = "serde_bytes", rename = "e")]
        e: Vec<u8>,
    }

    // Skip the type byte if present
    let id_data = if !id.is_empty() && id[0] < 10 {
        &id[1..]
    } else {
        id
    };

    let data: IdData = from_slice(id_data)
        .map_err(|e| Error::DeserializationError(format!("Failed to deserialize ID: {}", e)))?;
    Ok(data.e)
}

/// Base implementation for cypher manager
pub struct CypherManager {
    pub base: crate::key_manager::abstract_key_manager::BaseKeyManager,
    pub cypher: KeyPairImpl,
    pub signer: KeyPairImpl,
}

impl Default for CypherManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CypherManager {
    pub fn new() -> Self {
        Self {
            base: crate::key_manager::abstract_key_manager::BaseKeyManager::new(
                1,
                Capability::Private,
            )
            .with_enc_type("X25519KeyAgreementKey2019".to_string()),
            cypher: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
            signer: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
        }
    }

    /// Get cypher operations
    pub fn get_cypher_ops(&self) -> Result<CypherOpsImpl> {
        Ok(CypherOpsImpl {
            cypher_keypair: self.cypher.clone(),
        })
    }

    /// Perform Diffie-Hellman key exchange
    pub fn perform_diffie_hellman(&self, other_public_key: &[u8]) -> Result<Vec<u8>> {
        if self.base.capability != Capability::Private {
            return Err(Error::InvalidCapability);
        }

        let secret_key = self
            .cypher
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;

        if secret_key.len() != 32 || other_public_key.len() != 32 {
            return Err(Error::InvalidKeyFormat(
                "Keys must be 32 bytes for X25519".into(),
            ));
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(secret_key);
        let static_secret = StaticSecret::from(secret_bytes);

        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(other_public_key);
        let public_key = PublicKey::from(public_bytes);

        let shared_secret = static_secret.diffie_hellman(&public_key);
        let derived_key = hash("sha256", shared_secret.as_bytes());

        // Securely erase sensitive data
        secure_erase(&mut secret_bytes);

        Ok(derived_key)
    }

    /// Encrypt using DHIES
    pub fn dhies_encrypt(&self, message: &[u8], recipient_id: &[u8]) -> Result<Vec<u8>> {
        let recipient_public_key = get_cypher_public_key_from_id(recipient_id)?;
        let dhies = DHIES::new(self as &dyn CypherOperations);
        dhies.encrypt(message, &recipient_public_key)
    }

    /// Decrypt using DHIES
    pub fn dhies_decrypt(&self, encrypted_message: &[u8], sender_id: &[u8]) -> Result<Vec<u8>> {
        let sender_public_key = get_cypher_public_key_from_id(sender_id)?;
        let dhies = DHIES::new(self as &dyn CypherOperations);
        dhies.decrypt(encrypted_message, &sender_public_key)
    }

    /// Get secret hash
    pub fn get_secret_hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let secret_key = self
            .cypher
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;

        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(data);
        to_hash.extend_from_slice(b"secrethash");
        to_hash.extend_from_slice(secret_key);

        Ok(hash("sha256", &to_hash))
    }

    /// Clean secure data
    pub fn clean_secure_data(&mut self) {
        if let Some(ref mut secret) = self.cypher.secret_key {
            secure_erase(secret);
        }
        self.cypher.secret_key = None;

        if let Some(ref mut secret) = self.signer.secret_key {
            secure_erase(secret);
        }
        self.signer.secret_key = None;

        if let Some(ref mut entropy) = self.base.entropy {
            secure_erase(entropy);
        }
        self.base.entropy = None;
    }
}

impl CypherOperations for CypherManager {
    fn has_private_capability(&self) -> bool {
        self.base.capability == Capability::Private
    }

    fn get_cypher_public_key(&self) -> &[u8] {
        &self.cypher.public_key
    }

    fn get_cypher_secret_key(&self) -> Option<&[u8]> {
        self.cypher.secret_key.as_deref()
    }
}

/// Implementation of cypher operations
pub struct CypherOpsImpl {
    cypher_keypair: KeyPairImpl,
}

impl CypherOpsImpl {
    pub fn hmac(&self, message: &str) -> Result<Option<Vec<u8>>> {
        if let Some(secret_key) = &self.cypher_keypair.secret_key {
            let data = format!("VaultysID/{}/end", message);
            Ok(Some(hmac("sha256", secret_key, data.as_bytes())?))
        } else {
            Ok(None)
        }
    }

    // Note: signcrypt and decrypt would require implementing saltpack protocol
    // which is complex and beyond the scope of this basic implementation
    pub fn signcrypt(&self, _plaintext: &str, _public_keys: &[Vec<u8>]) -> Result<String> {
        // This would require implementing the saltpack protocol
        Err(Error::Other(
            "Saltpack signcrypt not implemented in this version".into(),
        ))
    }

    pub fn decrypt(&self, _encrypted_message: &str, _sender_key: Option<&[u8]>) -> Result<String> {
        // This would require implementing the saltpack protocol
        Err(Error::Other(
            "Saltpack decrypt not implemented in this version".into(),
        ))
    }

    pub fn diffie_hellman(&self, public_key: &[u8]) -> Result<Vec<u8>> {
        let secret_key = self
            .cypher_keypair
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;

        if secret_key.len() != 32 || public_key.len() != 32 {
            return Err(Error::InvalidKeyFormat(
                "Keys must be 32 bytes for X25519".into(),
            ));
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(secret_key);
        let static_secret = StaticSecret::from(secret_bytes);

        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(public_key);
        let public_key = PublicKey::from(public_bytes);

        let shared_secret = static_secret.diffie_hellman(&public_key);

        // Securely erase sensitive data
        secure_erase(&mut secret_bytes);

        Ok(shared_secret.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vaultys_id::KeyManagerTrait;
    use crate::Ed25519Manager;

    #[test]
    fn test_cypher_manager_creation() {
        let cm = CypherManager::new();
        assert_eq!(cm.base.version, 1);
        assert_eq!(cm.base.capability, Capability::Private);
        assert_eq!(cm.base.enc_type, "X25519KeyAgreementKey2019");
    }

    #[test]
    fn test_kdf() {
        let shared_secret = vec![1u8; 32];
        let ephemeral_public = vec![2u8; 32];
        let static_public = vec![3u8; 32];

        let cm = CypherManager::new();
        let dhies = DHIES::new(&cm as &dyn CypherOperations);

        let output = dhies.kdf(&shared_secret, &ephemeral_public, &static_public);

        assert_eq!(output.encryption_key.len(), 32);
        assert_eq!(output.mac_key.len(), 32);
        assert_ne!(output.encryption_key, output.mac_key);
    }

    #[test]
    fn test_dhies_encrypt_decrypt() {
        // Create two key managers (sender and recipient)
        let sender = Ed25519Manager::generate().unwrap();
        let recipient = Ed25519Manager::generate().unwrap();

        // Message to encrypt
        let message = b"Secret message for DHIES test";

        // Encrypt message
        let encrypted = sender.dhies_encrypt(message, &recipient.id()).unwrap();

        // Decrypt message
        let decrypted = recipient.dhies_decrypt(&encrypted, &sender.id()).unwrap();

        // Verify message matches
        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_dhies_decrypt_fails_with_wrong_sender() {
        // Create three key managers
        let sender = Ed25519Manager::generate().unwrap();
        let recipient = Ed25519Manager::generate().unwrap();
        let wrong_sender = Ed25519Manager::generate().unwrap();

        // Message to encrypt
        let message = b"Secret message";

        // Encrypt message from sender to recipient
        let encrypted = sender.dhies_encrypt(message, &recipient.id()).unwrap();

        // Try to decrypt with wrong sender ID - should fail
        let result = recipient.dhies_decrypt(&encrypted, &wrong_sender.id());

        assert!(result.is_err());
    }

    #[test]
    fn test_dhies_tampered_message_fails() {
        // Create two key managers
        let sender = Ed25519Manager::generate().unwrap();
        let recipient = Ed25519Manager::generate().unwrap();

        // Message to encrypt
        let message = b"Secret message";

        // Encrypt message
        let mut encrypted = sender.dhies_encrypt(message, &recipient.id()).unwrap();

        // Tamper with the ciphertext
        encrypted[60] ^= 0xFF;

        // Try to decrypt tampered message - should fail
        let result = recipient.dhies_decrypt(&encrypted, &sender.id());

        assert!(result.is_err());
    }
}
