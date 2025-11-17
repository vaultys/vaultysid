use crate::error::Result;
use std::sync::Arc;
use zeroize::Zeroize;

/// Trait for key pair operations
pub trait KeyPair: Send + Sync {
    fn public_key(&self) -> &[u8];
    fn secret_key(&self) -> Option<&[u8]>;
    fn has_secret_key(&self) -> bool;
}

/// Cypher operations that a key manager must support
pub trait CypherOps: Send + Sync {
    fn hmac(&self, message: &str) -> Result<Option<Vec<u8>>>;
    fn signcrypt(&self, plaintext: &str, public_keys: &[Vec<u8>]) -> Result<String>;
    fn decrypt(&self, encrypted_message: &str, sender_key: Option<&[u8]>) -> Result<String>;
    fn diffie_hellman(&self, public_key: &[u8]) -> Result<Vec<u8>>;
}

/// Signer operations that a key manager must support
pub trait SignerOps: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>>;
}

/// Abstract trait for all key managers
pub trait AbstractKeyManager: Send + Sync {
    /// Get the version of this key manager
    fn version(&self) -> u8;

    /// Get the capability (private or public)
    fn capability(&self) -> crate::key_manager::Capability;

    /// Get the entropy if available
    fn entropy(&self) -> Option<&[u8]>;

    /// Get the unique identifier for this key manager
    fn id(&self) -> Vec<u8>;

    /// Get cypher operations
    fn get_cypher(&self) -> Result<Arc<dyn CypherOps>>;

    /// Get signer operations
    fn get_signer(&self) -> Result<Arc<dyn SignerOps>>;

    /// Get the secret data for this key manager
    fn get_secret(&self) -> Result<Vec<u8>>;

    /// Sign data
    fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Verify a signature
    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        user_verification_ignored: Option<bool>,
    ) -> bool;

    /// Securely clean sensitive data from memory
    fn clean_secure_data(&mut self);

    /// Perform Diffie-Hellman key exchange with another key manager
    fn perform_diffie_hellman(&self, other: &dyn AbstractKeyManager) -> Result<Vec<u8>>;

    /// Encrypt a message using DHIES for a recipient
    fn dhies_encrypt(&self, message: &[u8], recipient_id: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt a message encrypted with DHIES
    fn dhies_decrypt(&self, encrypted_message: &[u8], sender_id: &[u8]) -> Result<Vec<u8>>;

    /// Sign and encrypt a message for multiple recipients
    fn signcrypt(&self, plaintext: &str, recipient_ids: &[Vec<u8>]) -> Result<String>;

    /// Decrypt a message
    fn decrypt(&self, encrypted_message: &str, sender_id: Option<&[u8]>) -> Result<String>;

    /// Get secret hash for data
    fn get_secret_hash(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Get authentication type
    fn auth_type(&self) -> &str;

    /// Get encryption type
    fn enc_type(&self) -> &str;
}

/// Main KeyManager trait that extends AbstractKeyManager
pub trait KeyManager: AbstractKeyManager {
    /// Create a key manager from entropy
    fn from_entropy(entropy: &[u8]) -> Result<Box<dyn AbstractKeyManager>>
    where
        Self: Sized;

    /// Generate a new key manager with random entropy
    fn generate() -> Result<Box<dyn AbstractKeyManager>>
    where
        Self: Sized;

    /// Create from a secret
    fn from_secret(secret: &[u8]) -> Result<Box<dyn AbstractKeyManager>>
    where
        Self: Sized;

    /// Create from an ID (public key only)
    fn from_id(id: &[u8]) -> Result<Box<dyn AbstractKeyManager>>
    where
        Self: Sized;

    /// Instantiate from a deserialized object
    fn instantiate(obj: &serde_json::Value) -> Result<Box<dyn AbstractKeyManager>>
    where
        Self: Sized;

    /// Static Diffie-Hellman between two key managers
    fn diffie_hellman(km1: &dyn AbstractKeyManager, km2: &dyn AbstractKeyManager) -> Result<Vec<u8>>
    where
        Self: Sized,
    {
        km1.perform_diffie_hellman(km2)
    }

    /// Static encrypt for multiple recipients (no signing)
    fn encrypt(plaintext: &str, recipient_ids: &[Vec<u8>]) -> Result<String>
    where
        Self: Sized;
}

/// Base implementation helper for key managers
#[derive(Clone)]
pub struct BaseKeyManager {
    pub version: u8,
    pub capability: crate::key_manager::Capability,
    pub entropy: Option<Vec<u8>>,
    pub auth_type: String,
    pub enc_type: String,
}

impl BaseKeyManager {
    pub fn new(version: u8, capability: crate::key_manager::Capability) -> Self {
        Self {
            version,
            capability,
            entropy: None,
            auth_type: String::new(),
            enc_type: String::new(),
        }
    }

    pub fn with_entropy(mut self, entropy: Vec<u8>) -> Self {
        self.entropy = Some(entropy);
        self
    }

    pub fn with_auth_type(mut self, auth_type: String) -> Self {
        self.auth_type = auth_type;
        self
    }

    pub fn with_enc_type(mut self, enc_type: String) -> Self {
        self.enc_type = enc_type;
        self
    }
}

impl Zeroize for BaseKeyManager {
    fn zeroize(&mut self) {
        if let Some(ref mut entropy) = self.entropy {
            entropy.zeroize();
        }
    }
}

impl Drop for BaseKeyManager {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_key_manager() {
        let km = BaseKeyManager::new(1, crate::key_manager::Capability::Private)
            .with_auth_type("Ed25519".to_string())
            .with_enc_type("X25519".to_string());

        assert_eq!(km.version, 1);
        assert_eq!(km.capability, crate::key_manager::Capability::Private);
        assert_eq!(km.auth_type, "Ed25519");
        assert_eq!(km.enc_type, "X25519");
    }
}
