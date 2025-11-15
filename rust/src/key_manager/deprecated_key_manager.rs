use crate::crypto::{hash, hmac, random_bytes, secure_erase};
use crate::error::{Error, Result};
use crate::key_manager::{Capability, DataExport, KeyPairImpl};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rmp_serde::{from_slice, to_vec};
use x25519_dalek::{PublicKey, StaticSecret};

const LEVEL_ROOT: u8 = 1;
const LEVEL_DERIVED: u8 = 2;

/// Deprecated Key Manager implementation (for backwards compatibility)
pub struct DeprecatedKeyManager {
    pub level: Option<u8>,
    pub version: u8,
    pub capability: Capability,
    pub entropy: Option<Vec<u8>>,
    pub proof: Option<Vec<u8>>,
    pub proof_key: KeyPairImpl,
    pub signer: KeyPairImpl,
    pub cypher: KeyPairImpl,
    pub auth_type: String,
    pub enc_type: String,
    pub swap_index: u32,
}

impl Default for DeprecatedKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DeprecatedKeyManager {
    pub fn new() -> Self {
        Self {
            level: Some(LEVEL_ROOT),
            version: 1,
            capability: Capability::Private,
            entropy: None,
            proof: None,
            proof_key: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
            signer: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
            cypher: KeyPairImpl {
                public_key: Vec::new(),
                secret_key: None,
            },
            auth_type: "Ed25519VerificationKey2020".to_string(),
            enc_type: "X25519KeyAgreementKey2019".to_string(),
            swap_index: 0,
        }
    }

    /// Create from entropy (simplified version without BIP32 derivation)
    pub fn create_id25519_from_entropy(entropy: &[u8], swap_index: u32) -> Result<Self> {
        let mut km = Self::new();
        km.entropy = Some(entropy.to_vec());
        km.level = Some(LEVEL_ROOT);
        km.capability = Capability::Private;
        km.swap_index = swap_index;

        // Hash the entropy to get seed material
        let seed = hash("sha512", entropy);

        // For the deprecated version, we'll simulate BIP32-like derivation
        // by using different portions of the seed for different keys

        // Derive proof key (using first part of seed with swap_index mixed in)
        let mut proof_seed = Vec::new();
        proof_seed.extend_from_slice(&seed[0..32]);
        proof_seed.extend_from_slice(&swap_index.to_le_bytes());
        let proof_key_seed = hash("sha256", &proof_seed);

        // Create proof key
        let proof_signing_key = SigningKey::from_bytes(
            &proof_key_seed[0..32]
                .try_into()
                .map_err(|_| Error::InvalidKeyFormat("Failed to create proof key".into()))?,
        );
        let proof_verifying_key = proof_signing_key.verifying_key();

        km.proof_key = KeyPairImpl {
            public_key: proof_verifying_key.to_bytes().to_vec(),
            secret_key: Some(proof_signing_key.to_bytes().to_vec()),
        };
        km.proof = Some(hash("sha256", &km.proof_key.public_key));

        // Derive signing key (using proof key as base)
        let signer_seed = hash("sha256", &proof_key_seed);
        let signing_key = SigningKey::from_bytes(
            &signer_seed[0..32]
                .try_into()
                .map_err(|_| Error::InvalidKeyFormat("Failed to create signing key".into()))?,
        );
        let verifying_key = signing_key.verifying_key();

        km.signer = KeyPairImpl {
            public_key: verifying_key.to_bytes().to_vec(),
            secret_key: Some(signing_key.to_bytes().to_vec()),
        };

        // Derive cypher key (using second part of seed with swap_index)
        let mut cypher_seed_input = Vec::new();
        cypher_seed_input.extend_from_slice(&seed[32..64]);
        cypher_seed_input.extend_from_slice(&swap_index.to_le_bytes());
        let cypher_seed = hash("sha256", &cypher_seed_input);

        let cypher_secret_bytes: [u8; 32] = cypher_seed[0..32]
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
    pub fn generate_id25519() -> Result<Self> {
        Self::create_id25519_from_entropy(&random_bytes(32), 0)
    }

    /// Get the ID for this key manager
    pub fn id(&self) -> Vec<u8> {
        let data = DataExport {
            v: self.version,
            p: self.proof.clone(),
            x: self.signer.public_key.clone(),
            e: self.cypher.public_key.clone(),
        };
        to_vec(&data).unwrap_or_default()
    }

    /// Get cypher operations
    pub fn get_cypher(&self) -> Result<DeprecatedCypherOps> {
        Ok(DeprecatedCypherOps {
            cypher_keypair: self.cypher.clone(),
        })
    }

    /// Get signer operations (returns the proof key for deprecated compatibility)
    pub fn get_signer(&self) -> Result<Vec<u8>> {
        self.signer
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)
            .cloned()
    }

    /// Get the secret for this key manager
    pub fn get_secret(&self) -> Result<Vec<u8>> {
        let signer_secret = self
            .signer
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;
        let cypher_secret = self
            .cypher
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;

        let data = DataExport {
            v: self.version,
            p: self.proof.clone(),
            x: signer_secret.clone(),
            e: cypher_secret.clone(),
        };

        Ok(to_vec(&data)?)
    }

    /// Create from secret
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        let data: DataExport = from_slice(secret)?;
        let mut km = Self::new();
        km.version = data.v;
        km.level = Some(LEVEL_DERIVED);
        km.capability = Capability::Private;
        km.proof = data.p;

        // NOTE: DeprecatedKeyManager uses BIP32-Ed25519 key derivation which is not
        // implemented in this Rust version. The public keys derived here will not match
        // the TypeScript version which uses @stricahq/bip32ed25519.
        // For full compatibility, BIP32-Ed25519 support would need to be added.

        // Reconstruct signing key (this will not match TypeScript due to BIP32)
        let signing_key = SigningKey::from_bytes(
            &data.x[0..32]
                .try_into()
                .map_err(|_| Error::InvalidKeyFormat("Invalid signing key in secret".into()))?,
        );
        let verifying_key = signing_key.verifying_key();

        km.signer = KeyPairImpl {
            public_key: verifying_key.to_bytes().to_vec(),
            secret_key: Some(data.x.clone()),
        };

        // Reconstruct cypher key
        let cypher_secret_bytes: [u8; 32] = data.e[0..32]
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Invalid cypher key in secret".into()))?;
        let cypher_secret = StaticSecret::from(cypher_secret_bytes);
        let cypher_public = PublicKey::from(&cypher_secret);

        km.cypher = KeyPairImpl {
            public_key: cypher_public.as_bytes().to_vec(),
            secret_key: Some(data.e.clone()),
        };

        Ok(km)
    }

    /// Instantiate from JSON value
    pub fn instantiate(obj: &serde_json::Value) -> Result<Self> {
        let mut km = Self::new();

        km.version = obj["version"].as_u64().unwrap_or(0) as u8;
        km.level = obj["level"].as_u64().map(|l| l as u8);

        // Parse proof
        if let Some(proof) = obj.get("proof") {
            km.proof = Some(if let Some(data) = proof.get("data") {
                data.as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                proof
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect()
                    })
                    .unwrap_or_default()
            });
        }

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

    /// Create from ID (public keys only)
    pub fn from_id(id: &[u8]) -> Result<Self> {
        let data: DataExport = from_slice(id)?;
        let mut km = Self::new();
        km.version = data.v;
        km.level = Some(LEVEL_DERIVED);
        km.capability = Capability::Public;
        km.proof = data.p;

        km.signer = KeyPairImpl {
            public_key: data.x,
            secret_key: None,
        };

        km.cypher = KeyPairImpl {
            public_key: data.e,
            secret_key: None,
        };

        Ok(km)
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.capability != Capability::Private {
            return Ok(None);
        }

        let secret_key = self
            .signer
            .secret_key
            .as_ref()
            .ok_or(Error::KeyNotAvailable)?;

        let signing_key = SigningKey::from_bytes(
            &secret_key[0..32]
                .try_into()
                .map_err(|_| Error::InvalidKeyFormat("Invalid signing key".into()))?,
        );

        let signature = signing_key.sign(data);
        Ok(Some(signature.to_bytes().to_vec()))
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

        if let Some(ref mut secret) = self.proof_key.secret_key {
            secure_erase(secret);
        }
        self.proof_key.secret_key = None;

        if let Some(ref mut entropy) = self.entropy {
            secure_erase(entropy);
        }
        self.entropy = None;

        if let Some(ref mut proof) = self.proof {
            secure_erase(proof);
        }
        self.proof = None;
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
}

/// Cypher operations for DeprecatedKeyManager
pub struct DeprecatedCypherOps {
    cypher_keypair: KeyPairImpl,
}

impl DeprecatedCypherOps {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let km = DeprecatedKeyManager::generate_id25519().unwrap();
        assert_eq!(km.capability, Capability::Private);
        assert_eq!(km.signer.public_key.len(), 32);
        assert_eq!(km.cypher.public_key.len(), 32);
        assert!(km.signer.secret_key.is_some());
        assert!(km.cypher.secret_key.is_some());
        assert!(km.proof.is_some());
    }

    #[test]
    fn test_from_entropy() {
        let entropy = random_bytes(32);
        let km = DeprecatedKeyManager::create_id25519_from_entropy(&entropy, 0).unwrap();
        assert_eq!(km.capability, Capability::Private);
        assert_eq!(km.signer.public_key.len(), 32);
        assert_eq!(km.cypher.public_key.len(), 32);
        assert_eq!(km.swap_index, 0);
    }

    #[test]
    fn test_round_trip_secret() {
        let km1 = DeprecatedKeyManager::generate_id25519().unwrap();
        let secret = km1.get_secret().unwrap();
        let km2 = DeprecatedKeyManager::from_secret(&secret).unwrap();

        assert_eq!(km1.signer.public_key, km2.signer.public_key);
        assert_eq!(km1.cypher.public_key, km2.cypher.public_key);
        assert_eq!(km1.proof, km2.proof);
        assert_eq!(km1.version, km2.version);
    }

    #[test]
    fn test_round_trip_id() {
        let km1 = DeprecatedKeyManager::generate_id25519().unwrap();
        let id = km1.id();
        let km2 = DeprecatedKeyManager::from_id(&id).unwrap();

        assert_eq!(km1.signer.public_key, km2.signer.public_key);
        assert_eq!(km1.cypher.public_key, km2.cypher.public_key);
        assert_eq!(km1.proof, km2.proof);
        assert_eq!(km2.capability, Capability::Public);
    }

    #[test]
    fn test_sign_verify() {
        let km = DeprecatedKeyManager::generate_id25519().unwrap();
        let data = b"test message";

        let signature = km.sign(data).unwrap().unwrap();

        assert!(km.verify(data, &signature, None));
        assert!(!km.verify(b"wrong message", &signature, None));
    }
}
