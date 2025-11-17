use crate::crypto::{hash, random_bytes};
use crate::error::{Error, Result};
use crate::key_manager::{
    abstract_key_manager::{AbstractKeyManager, CypherOps, SignerOps},
    cypher_manager::{CypherManager, CypherOpsImpl},
    Capability, KeyPairImpl,
};
use libcrux_ml_dsa::ml_dsa_87;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rmp_serde::from_slice;
use serde::ser::{SerializeMap, Serializer};
use serde::Deserialize;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

// Structs for deserializing MessagePack data from TypeScript
#[derive(Deserialize)]
struct SecretData {
    v: u8,
    #[serde(with = "serde_bytes")]
    s: Vec<u8>,
}

#[derive(Deserialize)]
struct IdData {
    v: u8,
    #[serde(with = "serde_bytes")]
    x: Vec<u8>,
    #[serde(with = "serde_bytes")]
    e: Vec<u8>,
}

/// Dilithium Key Manager implementation for post-quantum cryptography
pub struct DilithiumManager {
    pub base: crate::key_manager::abstract_key_manager::BaseKeyManager,
    pub signer: KeyPairImpl,
    pub cypher: KeyPairImpl,
    seed: Option<Vec<u8>>,
}

impl Drop for DilithiumManager {
    fn drop(&mut self) {
        self.clean_secure_data();
    }
}

impl Default for DilithiumManager {
    fn default() -> Self {
        Self::new()
    }
}

// Helper function to generate randomness array from seed
fn random_array_from_seed<const L: usize>(seed: &[u8]) -> [u8; L] {
    let mut rng = StdRng::from_seed({
        let mut seed_32 = [0u8; 32];
        let len = seed.len().min(32);
        seed_32[..len].copy_from_slice(&seed[..len]);
        seed_32
    });
    let mut array = [0u8; L];
    rng.fill_bytes(&mut array);
    array
}

impl DilithiumManager {
    pub fn new() -> Self {
        Self {
            base: crate::key_manager::abstract_key_manager::BaseKeyManager::new(
                3,
                Capability::Private,
            )
            .with_auth_type("DilithiumVerificationKey".to_string())
            .with_enc_type("X25519KeyAgreementKey2019".to_string()),
            signer: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
            cypher: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
            seed: None,
        }
    }

    /// Generate keypair from 32-byte seed using libcrux ML-DSA-87
    fn keypair_from_seed_32(seed_32: &[u8; 32]) -> Result<ml_dsa_87::MLDSA87KeyPair> {
        // ML-DSA-87 requires 32 bytes of randomness for key generation
        // let randomness = random_array_from_seed::<32>(seed_32);

        // Generate keypair using ML-DSA-87
        let key_pair = ml_dsa_87::generate_key_pair(*seed_32);

        Ok(key_pair)
    }

    /// Create from entropy
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let mut km = Self::new();
        km.base.capability = Capability::Private;
        km.base.entropy = Some(entropy.to_vec());

        // Hash the entropy to get seed material (matching TypeScript sha512)
        let seed = hash("sha512", entropy);

        // Use first 32 bytes as main seed for deterministic operations
        let seed_32: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Invalid seed length".into()))?;
        km.seed = Some(seed.to_vec());

        // Generate ML-DSA-87 keypair from the seed
        let key_pair = Self::keypair_from_seed_32(&seed_32)?;

        // Store the keys in our format
        km.signer = KeyPairImpl {
            public_key: key_pair.verification_key.as_ref().to_vec(),
            secret_key: Some(key_pair.signing_key.as_ref().to_vec()),
        };

        // Use next 32 bytes for X25519 encryption key (compatible with Ed25519Manager)
        let cypher_secret_bytes: [u8; 32] = seed[32..64]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Failed to create cypher key".into()))?;
        let cypher_secret = StaticSecret::from(cypher_secret_bytes);
        let cypher_public = X25519PublicKey::from(&cypher_secret);

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

    /// Get the secret for this key manager
    pub fn get_secret(&self) -> Result<Vec<u8>> {
        let seed = self.seed.as_ref().ok_or(Error::KeyNotAvailable)?;

        // Match TypeScript MessagePack format exactly
        let mut buf = Vec::new();
        let mut se = rmp_serde::Serializer::new(&mut buf);

        // Create a map with 2 entries
        let mut map = se.serialize_map(Some(2)).unwrap();

        // "v" -> version (as integer)
        map.serialize_entry("v", &self.base.version).unwrap();

        // "s" -> seed (as bytes)
        map.serialize_entry("s", &serde_bytes::Bytes::new(seed))
            .unwrap();

        map.end().unwrap();
        Ok(buf)
    }

    /// Create from secret (MessagePack format from TypeScript)
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        // Parse the MessagePack data
        let data: SecretData = from_slice(secret)
            .map_err(|e| Error::InvalidKeyFormat(format!("Failed to parse secret: {}", e)))?;

        let version = data.v;
        let seed_bytes = &data.s;

        if seed_bytes.len() != 64 {
            return Err(Error::InvalidKeyFormat(
                "Seed must be 64 bytes for Dilithium".into(),
            ));
        }

        let mut km = Self::new();
        km.base.version = version;
        km.base.capability = Capability::Private;
        km.seed = Some(seed_bytes.to_vec());

        // Generate ML-DSA-87 keypair from seed
        let seed_32: [u8; 32] = seed_bytes[0..32]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Invalid seed in secret".into()))?;
        let key_pair = Self::keypair_from_seed_32(&seed_32)?;

        km.signer = KeyPairImpl {
            public_key: key_pair.verification_key.as_ref().to_vec(),
            secret_key: Some(key_pair.signing_key.as_ref().to_vec()),
        };

        // Generate X25519 keys from seed for cypher (deterministic)
        let cypher_secret_bytes: [u8; 32] = seed_bytes[32..64]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Failed to create cypher key".into()))?;
        let cypher_secret = StaticSecret::from(cypher_secret_bytes);
        let cypher_public = X25519PublicKey::from(&cypher_secret);

        km.cypher = KeyPairImpl {
            public_key: cypher_public.as_bytes().to_vec(),
            secret_key: Some(cypher_secret.to_bytes().to_vec()),
        };

        Ok(km)
    }

    /// Create from ID (MessagePack format from TypeScript)
    pub fn from_id(id: &[u8]) -> Result<Self> {
        // Parse the MessagePack data
        let data: IdData = from_slice(id)
            .map_err(|e| Error::InvalidKeyFormat(format!("Failed to parse ID: {}", e)))?;

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

    /// Sign data using ML-DSA-87
    pub fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(ref secret_key_bytes) = self.signer.secret_key {
            // ML-DSA-87 signing key is 4896 bytes
            if secret_key_bytes.len() != 4896 {
                return Err(Error::InvalidKeyFormat(format!(
                    "Invalid ML-DSA-87 signing key length: expected 4896, got {}",
                    secret_key_bytes.len()
                )));
            }

            let mut signing_key_array = [0u8; 4896];
            signing_key_array.copy_from_slice(secret_key_bytes);
            let signing_key = ml_dsa_87::MLDSA87SigningKey::new(signing_key_array);

            // Generate randomness for signing (ML-DSA-87 needs 32 bytes)
            let randomness = if let Some(ref seed) = self.seed {
                // Use deterministic randomness from seed for reproducibility
                random_array_from_seed::<32>(seed)
            } else {
                // Use random bytes
                let mut rng_bytes = [0u8; 32];
                rng_bytes.copy_from_slice(&random_bytes(32));
                rng_bytes
            };

            // Sign the message with empty context
            let context = b"";
            let signature = ml_dsa_87::sign(&signing_key, data, context, randomness);

            // ML-DSA-87 signature is 4627 bytes
            // For compatibility with the old format, we return signature + message
            match signature {
                Ok(sig) => {
                    let mut signed_message = Vec::with_capacity(4627 + data.len());
                    signed_message.extend_from_slice(sig.as_ref());
                    signed_message.extend_from_slice(data);
                    Ok(Some(signed_message))
                }
                Err(_) => Err(Error::SigningError("Failed to sign message".into())),
            }
        } else {
            Ok(None)
        }
    }

    /// Verify a signature using ML-DSA-87
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        // ML-DSA-87 verification key is 2592 bytes
        if self.signer.public_key.len() != 2592 {
            return false;
        }

        let mut verification_key_array = [0u8; 2592];
        verification_key_array.copy_from_slice(&self.signer.public_key);
        let verification_key = ml_dsa_87::MLDSA87VerificationKey::new(verification_key_array);

        // Check if we have the old format (signature + message)
        if signature.len() > 4627 {
            // Extract just the signature part (first 4627 bytes)
            if signature.len() >= 4627 + data.len() {
                let sig_bytes = &signature[..4627];
                let included_message = &signature[4627..];

                // Verify the message matches
                if included_message != data {
                    return false;
                }

                let mut signature_array = [0u8; 4627];
                signature_array.copy_from_slice(sig_bytes);
                let sig = ml_dsa_87::MLDSA87Signature::new(signature_array);

                let context = b"";
                ml_dsa_87::verify(&verification_key, data, context, &sig).is_ok()
            } else {
                false
            }
        } else if signature.len() == 4627 {
            // Just the signature
            let mut signature_array = [0u8; 4627];
            signature_array.copy_from_slice(signature);
            let sig = ml_dsa_87::MLDSA87Signature::new(signature_array);

            let context = b"";
            ml_dsa_87::verify(&verification_key, data, context, &sig).is_ok()
        } else {
            false
        }
    }

    /// Clean secure data
    pub fn clean_secure_data(&mut self) {
        if let Some(ref mut secret_key) = self.signer.secret_key {
            secret_key.zeroize();
        }
        if let Some(ref mut secret_key) = self.cypher.secret_key {
            secret_key.zeroize();
        }
        if let Some(ref mut entropy) = self.base.entropy {
            entropy.zeroize();
        }
        if let Some(ref mut seed) = self.seed {
            seed.zeroize();
        }
        self.signer.secret_key = None;
        self.cypher.secret_key = None;
        self.base.entropy = None;
        self.seed = None;
    }
}

// AbstractKeyManager implementation
impl AbstractKeyManager for DilithiumManager {
    fn version(&self) -> u8 {
        self.base.version
    }

    fn capability(&self) -> Capability {
        self.base.capability
    }

    fn entropy(&self) -> Option<&[u8]> {
        self.base.entropy.as_deref()
    }

    fn id(&self) -> Vec<u8> {
        self.id()
    }

    fn get_cypher(&self) -> Result<std::sync::Arc<dyn CypherOps>> {
        Ok(std::sync::Arc::new(CypherOpsImpl {
            cypher_keypair: self.cypher.clone(),
        }))
    }

    fn get_signer(&self) -> Result<std::sync::Arc<dyn SignerOps>> {
        struct DilithiumSigner {
            signer_keypair: KeyPairImpl,
        }

        impl SignerOps for DilithiumSigner {
            fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
                if let Some(ref secret_key_bytes) = self.signer_keypair.secret_key {
                    // ML-DSA-87 signing key is 4896 bytes
                    let mut signing_key_array = [0u8; 4896];
                    signing_key_array.copy_from_slice(secret_key_bytes);
                    let signing_key = ml_dsa_87::MLDSA87SigningKey::new(signing_key_array);

                    // Generate randomness for signing
                    let mut randomness = [0u8; 32];
                    randomness.copy_from_slice(&random_bytes(32));

                    let context = b"";
                    match ml_dsa_87::sign(&signing_key, data, context, randomness) {
                        Ok(signature) => Ok(Some(signature.as_ref().to_vec())),
                        Err(_) => Ok(None),
                    }
                } else {
                    Ok(None)
                }
            }
        }

        Ok(std::sync::Arc::new(DilithiumSigner {
            signer_keypair: self.signer.clone(),
        }))
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        self.get_secret()
    }

    fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        self.sign(data)
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        _user_verification_ignored: Option<bool>,
    ) -> bool {
        self.verify(data, signature)
    }

    fn clean_secure_data(&mut self) {
        self.clean_secure_data();
    }

    fn perform_diffie_hellman(&self, other: &dyn AbstractKeyManager) -> Result<Vec<u8>> {
        let cypher_manager = CypherManager {
            base: self.base.clone(),
            cypher: self.cypher.clone(),
            signer: self.signer.clone(),
        };
        cypher_manager.perform_diffie_hellman(other)
    }

    fn dhies_encrypt(&self, message: &[u8], recipient_id: &[u8]) -> Result<Vec<u8>> {
        let cypher_manager = CypherManager {
            base: self.base.clone(),
            cypher: self.cypher.clone(),
            signer: self.signer.clone(),
        };
        cypher_manager.dhies_encrypt(message, recipient_id)
    }

    fn dhies_decrypt(&self, encrypted_message: &[u8], sender_id: &[u8]) -> Result<Vec<u8>> {
        let cypher_manager = CypherManager {
            base: self.base.clone(),
            cypher: self.cypher.clone(),
            signer: self.signer.clone(),
        };
        cypher_manager.dhies_decrypt(encrypted_message, sender_id)
    }

    fn signcrypt(&self, _plaintext: &str, _recipient_ids: &[Vec<u8>]) -> Result<String> {
        Err(Error::NotImplemented("Signcrypt not implemented".into()))
    }

    fn decrypt(&self, _encrypted_message: &str, _sender_id: Option<&[u8]>) -> Result<String> {
        Err(Error::NotImplemented("Decrypt not implemented".into()))
    }

    fn get_secret_hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cypher_manager = CypherManager {
            base: self.base.clone(),
            cypher: self.cypher.clone(),
            signer: self.signer.clone(),
        };
        cypher_manager.get_secret_hash(data)
    }

    fn auth_type(&self) -> &str {
        "DilithiumVerificationKey"
    }

    fn enc_type(&self) -> &str {
        "X25519KeyAgreementKey2019"
    }
}

// KeyManager trait implementation
impl crate::key_manager::abstract_key_manager::KeyManager for DilithiumManager {
    fn from_entropy(entropy: &[u8]) -> Result<Box<dyn AbstractKeyManager>> {
        Ok(Box::new(Self::from_entropy(entropy)?))
    }

    fn generate() -> Result<Box<dyn AbstractKeyManager>> {
        Ok(Box::new(Self::generate()?))
    }

    fn from_secret(secret: &[u8]) -> Result<Box<dyn AbstractKeyManager>> {
        Ok(Box::new(Self::from_secret(secret)?))
    }

    fn from_id(id: &[u8]) -> Result<Box<dyn AbstractKeyManager>> {
        Ok(Box::new(Self::from_id(id)?))
    }

    fn instantiate(obj: &serde_json::Value) -> Result<Box<dyn AbstractKeyManager>> {
        Ok(Box::new(Self::instantiate(obj)?))
    }

    fn encrypt(_plaintext: &str, _recipient_ids: &[Vec<u8>]) -> Result<String> {
        Err(Error::NotImplemented(
            "Static encrypt not implemented".into(),
        ))
    }
}

// CypherOperations implementation
impl crate::key_manager::CypherOperations for DilithiumManager {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let km = DilithiumManager::generate().unwrap();
        assert_eq!(km.base.capability, Capability::Private);
        assert!(!km.signer.public_key.is_empty());
        assert!(km.signer.secret_key.is_some());
    }

    #[test]
    fn test_from_entropy() {
        let entropy = random_bytes(32);
        let km = DilithiumManager::from_entropy(&entropy).unwrap();
        assert_eq!(km.base.capability, Capability::Private);
        assert!(!km.signer.public_key.is_empty());
        assert_eq!(km.cypher.public_key.len(), 32);
    }

    #[test]
    fn test_round_trip_secret() {
        let km1 = DilithiumManager::generate().unwrap();
        let secret = km1.get_secret().unwrap();
        let km2 = DilithiumManager::from_secret(&secret).unwrap();

        assert_eq!(km1.signer.public_key, km2.signer.public_key);
        assert_eq!(km1.base.version, km2.base.version);
    }

    #[test]
    fn test_round_trip_id() {
        let km1 = DilithiumManager::generate().unwrap();
        let id = km1.id();
        let km2 = DilithiumManager::from_id(&id).unwrap();
        assert_eq!(km1.signer.public_key, km2.signer.public_key);
        assert_eq!(km1.cypher.public_key, km2.cypher.public_key);
        assert_eq!(km2.base.capability, Capability::Public);
    }

    #[test]
    fn test_sign_verify() {
        let km = DilithiumManager::generate().unwrap();
        let data = b"Test message";
        let signature = km.sign(data).unwrap().unwrap();
        assert!(km.verify(data, &signature));
        assert!(!km.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_diffie_hellman() {
        let km1 = DilithiumManager::generate().unwrap();
        let km2 = DilithiumManager::generate().unwrap();

        let shared1 = km1.perform_diffie_hellman(&km2).unwrap();
        let shared2 = km2.perform_diffie_hellman(&km1).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_secret_sizes() {
        let km = DilithiumManager::generate().unwrap();
        let secret = km.get_secret().unwrap();
        println!("DilithiumManager secret size: {} bytes", secret.len());

        // The secret is MessagePack encoded with:
        // - Map header (1-2 bytes)
        // - "v" key (1-2 bytes) + version value (1 byte)
        // - "s" key (1-2 bytes) + binary header (1-2 bytes) + 64 bytes seed
        // Total should be around 70-75 bytes
        assert!(
            secret.len() == 72,
            "Unexpected secret size: {}",
            secret.len()
        );
    }
}
