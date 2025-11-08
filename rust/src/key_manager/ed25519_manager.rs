use crate::crypto::{hash, hmac, random_bytes, secure_erase};
use crate::error::{Error, Result};
use crate::key_manager::{Capability, CypherOperations, KeyPairImpl};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rmp_serde::from_slice;
use serde::ser::{SerializeMap, Serializer};
use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};

// Structs for deserializing MessagePack data from TypeScript
#[derive(Deserialize)]
struct SecretData {
    v: u8,
    #[serde(with = "serde_bytes")]
    x: Vec<u8>,
    #[serde(with = "serde_bytes")]
    e: Vec<u8>,
}

#[derive(Deserialize)]
struct IdData {
    v: u8,
    #[serde(with = "serde_bytes")]
    x: Vec<u8>,
    #[serde(with = "serde_bytes")]
    e: Vec<u8>,
}

/// Ed25519 Key Manager implementation
pub struct Ed25519Manager {
    pub base: crate::key_manager::abstract_key_manager::BaseKeyManager,
    pub signer: KeyPairImpl,
    pub cypher: KeyPairImpl,
}

impl Ed25519Manager {
    pub fn new() -> Self {
        Self {
            base: crate::key_manager::abstract_key_manager::BaseKeyManager::new(
                1,
                Capability::Private,
            )
            .with_auth_type("Ed25519VerificationKey2020".to_string())
            .with_enc_type("X25519KeyAgreementKey2019".to_string()),
            signer: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
            cypher: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
        }
    }

    /// Create from entropy
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let mut km = Self::new();
        km.base.capability = Capability::Private;
        km.base.entropy = Some(entropy.to_vec());

        // Hash the entropy to get seed material (matching TypeScript sha512)
        let seed = hash("sha512", entropy);

        // Use first 32 bytes for signing key
        let signing_key = SigningKey::from_bytes(
            &seed[0..32]
                .try_into()
                .map_err(|_| Error::InvalidKeyFormat("Failed to create signing key".into()))?,
        );
        let verifying_key = signing_key.verifying_key();

        km.signer = KeyPairImpl {
            public_key: verifying_key.to_bytes().to_vec(),
            secret_key: Some(signing_key.to_bytes().to_vec()),
        };

        // Use next 32 bytes for X25519 encryption key
        let cypher_secret_bytes: [u8; 32] = seed[32..64]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Failed to create cypher key".into()))?;
        let cypher_secret = StaticSecret::from(cypher_secret_bytes);
        let cypher_public = PublicKey::from(&cypher_secret);

        km.cypher = KeyPairImpl {
            public_key: cypher_public.as_bytes().to_vec(),
            secret_key: Some(cypher_secret.to_bytes().to_vec()),
        };

        Ok(km)
    }

    /// Generate with random entropy
    pub fn generate() -> Result<Self> {
        Self::from_entropy(&random_bytes(32))
    }

    /// Get the ID for this key manager
    pub fn id(&self) -> Vec<u8> {
        // Match TypeScript MessagePack format exactly
        let mut buf = Vec::new();
        let mut se = rmp_serde::Serializer::new(&mut buf);

        // Create a map with 3 entries
        let mut map = se.serialize_map(Some(3)).unwrap();

        // "v" -> version (as integer)
        map.serialize_entry("v", &self.base.version).unwrap();

        // "x" -> signer public key (as bytes)
        map.serialize_entry("x", &serde_bytes::Bytes::new(&self.signer.public_key))
            .unwrap();

        // "e" -> cypher public key (as bytes)
        map.serialize_entry("e", &serde_bytes::Bytes::new(&self.cypher.public_key))
            .unwrap();

        map.end().unwrap();
        buf
    }

    /// Get cypher operations
    pub fn get_cypher_ops(&self) -> Result<Ed25519CypherOps> {
        Ok(Ed25519CypherOps {
            cypher_keypair: self.cypher.clone(),
        })
    }

    /// Get signer operations
    pub fn get_signer_ops(&self) -> Result<Ed25519SignerOps> {
        Ok(Ed25519SignerOps {
            signer_keypair: self.signer.clone(),
        })
    }

    /// Get the secret for this key manager
    pub fn get_secret(&self) -> Result<Vec<u8>> {
        let secret_key = self
            .signer
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;
        let cypher_secret = self
            .cypher
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;

        // Match TypeScript MessagePack format exactly
        let mut buf = Vec::new();
        let mut se = rmp_serde::Serializer::new(&mut buf);

        // Create a map with 3 entries
        let mut map = se.serialize_map(Some(3)).unwrap();

        // "v" -> version (as integer)
        map.serialize_entry("v", &self.base.version).unwrap();

        // "x" -> signer secret key (as bytes)
        map.serialize_entry("x", &serde_bytes::Bytes::new(secret_key))
            .unwrap();

        // "e" -> cypher secret key (as bytes)
        map.serialize_entry("e", &serde_bytes::Bytes::new(cypher_secret))
            .unwrap();

        map.end().unwrap();
        Ok(buf)
    }

    /// Create from secret
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        // Deserialize TypeScript MessagePack format
        let data: SecretData = from_slice(secret)?;

        let version = data.v;
        let x_bytes = &data.x;
        let e_bytes = &data.e;
        let mut km = Self::new();
        km.base.version = version;
        km.base.capability = Capability::Private;

        // Reconstruct signing key
        let signing_key = SigningKey::from_bytes(
            &x_bytes[0..32]
                .try_into()
                .map_err(|_| Error::InvalidKeyFormat("Invalid signing key in secret".into()))?,
        );
        let verifying_key = signing_key.verifying_key();

        km.signer = KeyPairImpl {
            public_key: verifying_key.to_bytes().to_vec(),
            secret_key: Some(x_bytes.to_vec()),
        };

        // Reconstruct cypher key
        let cypher_secret_bytes: [u8; 32] = e_bytes[0..32]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Invalid cypher key in secret".into()))?;
        let cypher_secret = StaticSecret::from(cypher_secret_bytes);
        let cypher_public = PublicKey::from(&cypher_secret);

        km.cypher = KeyPairImpl {
            public_key: cypher_public.as_bytes().to_vec(),
            secret_key: Some(e_bytes.to_vec()),
        };

        Ok(km)
    }

    /// Create from ID (public keys only)
    pub fn from_id(id: &[u8]) -> Result<Self> {
        // Deserialize TypeScript MessagePack format
        let data: IdData = from_slice(id)?;

        let version = data.v;
        let x_bytes = &data.x;
        let e_bytes = &data.e;

        let mut km = Self::new();
        km.base.version = version;
        km.base.capability = Capability::Public;

        km.signer = KeyPairImpl {
            public_key: x_bytes.to_vec(),
            secret_key: None,
        };

        km.cypher = KeyPairImpl {
            public_key: e_bytes.to_vec(),
            secret_key: None,
        };

        Ok(km)
    }

    /// Instantiate from JSON value
    pub fn instantiate(obj: &serde_json::Value) -> Result<Self> {
        let mut km = Self::new();

        km.base.version = obj["version"].as_u64().unwrap_or(0).try_into().unwrap_or(0);

        // Parse signer public key
        if let Some(signer) = obj.get("signer") {
            if let Some(public_key) = signer.get("publicKey") {
                km.signer.public_key = if let Some(data) = public_key.get("data") {
                    data.as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    public_key
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect()
                        })
                        .unwrap_or_default()
                };
            }
        }

        // Parse cypher public key
        if let Some(cypher) = obj.get("cypher") {
            if let Some(public_key) = cypher.get("publicKey") {
                km.cypher.public_key = if let Some(data) = public_key.get("data") {
                    data.as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    public_key
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect()
                        })
                        .unwrap_or_default()
                };
            }
        }

        Ok(km)
    }

    /// Verify a signature
    pub fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        _user_verification_ignored: Option<bool>,
    ) -> bool {
        if self.signer.public_key.len() != 32 || signature.len() != 64 {
            return false;
        }

        let verifying_key = match VerifyingKey::from_bytes(
            &self.signer.public_key[0..32]
                .try_into()
                .unwrap_or([0u8; 32]),
        ) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let sig_bytes: [u8; 64] = match signature[0..64].try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);

        verifying_key.verify(data, &sig).is_ok()
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

impl CypherOperations for Ed25519Manager {
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

/// Cypher operations for Ed25519Manager
pub struct Ed25519CypherOps {
    cypher_keypair: KeyPairImpl,
}

impl Ed25519CypherOps {
    pub fn hmac(&self, message: &str) -> Result<Option<Vec<u8>>> {
        if let Some(secret_key) = &self.cypher_keypair.secret_key {
            let data = format!("VaultysID/{}/end", message);
            Ok(Some(hmac("sha256", secret_key, data.as_bytes())?))
        } else {
            Ok(None)
        }
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

        let secret_key_bytes: [u8; 32] = secret_key[0..32]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Invalid secret key".into()))?;
        let static_secret = StaticSecret::from(secret_key_bytes);

        let public_key_bytes: [u8; 32] = public_key[0..32]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Invalid public key".into()))?;
        let public_key = PublicKey::from(public_key_bytes);

        let shared_secret = static_secret.diffie_hellman(&public_key);
        Ok(shared_secret.as_bytes().to_vec())
    }
}

/// Signer operations for Ed25519Manager
pub struct Ed25519SignerOps {
    signer_keypair: KeyPairImpl,
}

impl Ed25519SignerOps {
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let secret_key = self
            .signer_keypair
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;

        let signing_key = SigningKey::from_bytes(
            &secret_key[0..32]
                .try_into()
                .map_err(|_| Error::InvalidKeyFormat("Invalid signing key".into()))?,
        );

        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let km = Ed25519Manager::generate().unwrap();
        assert_eq!(km.base.capability, Capability::Private);
        assert_eq!(km.signer.public_key.len(), 32);
        assert_eq!(km.cypher.public_key.len(), 32);
        assert!(km.signer.secret_key.is_some());
        assert!(km.cypher.secret_key.is_some());
    }

    #[test]
    fn test_from_entropy() {
        let entropy = random_bytes(32);
        let km = Ed25519Manager::from_entropy(&entropy).unwrap();
        assert_eq!(km.base.capability, Capability::Private);
        assert_eq!(km.signer.public_key.len(), 32);
        assert_eq!(km.cypher.public_key.len(), 32);
    }

    #[test]
    fn test_round_trip_secret() {
        let km1 = Ed25519Manager::generate().unwrap();
        let secret = km1.get_secret().unwrap();
        let km2 = Ed25519Manager::from_secret(&secret).unwrap();

        assert_eq!(km1.signer.public_key, km2.signer.public_key);
        assert_eq!(km1.cypher.public_key, km2.cypher.public_key);
        assert_eq!(km1.base.version, km2.base.version);
    }

    #[test]
    fn test_round_trip_id() {
        let km1 = Ed25519Manager::generate().unwrap();
        let id = km1.id();
        let km2 = Ed25519Manager::from_id(&id).unwrap();

        assert_eq!(km1.signer.public_key, km2.signer.public_key);
        assert_eq!(km1.cypher.public_key, km2.cypher.public_key);
        assert_eq!(km2.base.capability, Capability::Public);
    }

    #[test]
    fn test_sign_verify() {
        let km = Ed25519Manager::generate().unwrap();
        let data = b"test message";

        let signer = km.get_signer_ops().unwrap();
        let signature = signer.sign(data).unwrap();

        assert!(km.verify(data, &signature, None));
        assert!(!km.verify(b"wrong message", &signature, None));
    }

    #[test]
    fn test_diffie_hellman() {
        let km1 = Ed25519Manager::generate().unwrap();
        let km2 = Ed25519Manager::generate().unwrap();

        let cypher1 = km1.get_cypher_ops().unwrap();
        let cypher2 = km2.get_cypher_ops().unwrap();

        let shared1 = cypher1.diffie_hellman(&km2.cypher.public_key).unwrap();
        let shared2 = cypher2.diffie_hellman(&km1.cypher.public_key).unwrap();

        assert_eq!(shared1, shared2);
    }
}
