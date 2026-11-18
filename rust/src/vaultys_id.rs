use crate::crypto::{hash, random_bytes};
use crate::error::{Error, Result};
use crate::key_manager::{
    abstract_key_manager::AbstractKeyManager, DilithiumManager, Ed25519Manager,
};
use crate::post_quantum::{
    self, is_post_quantum_type, role_of, DILITHIUM_PUBLIC_KEY_LENGTH, HYBRID_PUBLIC_KEY_LENGTH,
};
use serde::{Deserialize, Serialize};
use std::fmt;

// Type constants matching TypeScript
const TYPE_MACHINE: u8 = 0;
const TYPE_PERSON: u8 = 1;
const TYPE_ORGANIZATION: u8 = 2;
const TYPE_FIDO2: u8 = 3;
const TYPE_FIDO2PRF: u8 = 4;

const SIGN_INCIPIT: &[u8] = b"VAULTYS_SIGN";

const HYBRID_NOT_IMPLEMENTED: &str =
    "Hybrid (dilithium_ed25519) key managers are not implemented in Rust";

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    Dilithium,
}

/// Represents a VaultysId with its associated key manager
/// VaultysId struct that holds a key manager
pub struct VaultysId {
    pub id_type: u8,
    pub key_manager: Box<dyn AbstractKeyManager + 'static>,
    pub certificate: Option<Vec<u8>>,
}

/// Trait that all key managers must implement for use with VaultysId
pub trait KeyManagerTrait: Send + Sync {
    // VaultysID-specific operations that aren't in AbstractKeyManager
    fn get_hmac(&self, message: &str) -> Result<Option<Vec<u8>>>;
    fn get_fingerprint(&self) -> Vec<u8>;
    fn get_did(&self, id_type: u8) -> String;
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

// Implement the trait for Ed25519Manager
impl KeyManagerTrait for Ed25519Manager {
    fn get_hmac(&self, message: &str) -> Result<Option<Vec<u8>>> {
        if let Some(secret_key) = &self.cypher.secret_key {
            use crate::crypto::hmac;
            let data = format!("VaultysID/{}/end", message);
            Ok(Some(hmac("sha256", secret_key, data.as_bytes())?))
        } else {
            Ok(None)
        }
    }

    fn get_fingerprint(&self) -> Vec<u8> {
        use crate::key_manager::abstract_key_manager::AbstractKeyManager;
        let id = AbstractKeyManager::id(self);
        hash("sha224", &id)
    }

    fn get_did(&self, id_type: u8) -> String {
        use crate::key_manager::abstract_key_manager::AbstractKeyManager;
        let mut fp_bytes = Vec::new();
        fp_bytes.push(id_type);
        fp_bytes.extend_from_slice(&hash("sha224", &AbstractKeyManager::id(self)));
        let fp_hex = crate::crypto::to_hex(&fp_bytes);
        format!("did:vaultys:{}", &fp_hex[0..40])
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// Implement the trait for DilithiumManager
impl KeyManagerTrait for DilithiumManager {
    fn get_hmac(&self, message: &str) -> Result<Option<Vec<u8>>> {
        if let Some(secret_key) = &self.cypher.secret_key {
            use crate::crypto::hmac;
            let result = hmac("sha256", secret_key, message.as_bytes())?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    fn get_fingerprint(&self) -> Vec<u8> {
        use crate::key_manager::abstract_key_manager::AbstractKeyManager;
        let id = AbstractKeyManager::id(self);
        hash("sha224", &id)
    }

    fn get_did(&self, id_type: u8) -> String {
        use crate::key_manager::abstract_key_manager::AbstractKeyManager;
        let mut fp_bytes = Vec::new();
        fp_bytes.push(id_type);
        fp_bytes.extend_from_slice(&hash("sha224", &AbstractKeyManager::id(self)));
        let fp_hex = crate::crypto::to_hex(&fp_bytes);
        format!("did:vaultys:{}", &fp_hex[0..40])
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl VaultysId {
    /// Create a new VaultysId
    pub fn new(
        key_manager: Box<dyn AbstractKeyManager>,
        certificate: Option<Vec<u8>>,
        id_type: u8,
    ) -> Self {
        Self {
            id_type,
            key_manager,
            certificate,
        }
    }

    /// Create from secret
    pub fn from_secret(secret: &[u8], certificate: Option<Vec<u8>>) -> Result<Self> {
        if secret.is_empty() {
            return Err(Error::InvalidIdFormat);
        }

        let id_type = secret[0];
        let secret_data = &secret[1..];

        if is_post_quantum_type(id_type) {
            // rfc/PQ-ENCRYPTION.md §4.2: the secret record selects the key manager
            let mut km = match secret.len() {
                73 => DilithiumManager::from_secret(secret_data)?,
                84 => return Err(Error::NotImplemented(HYBRID_NOT_IMPLEMENTED.into())),
                _ => return Err(Error::InvalidIdFormat),
            };
            if km.base.version != 1 {
                return Err(Error::UnsupportedVersion(km.base.version));
            }
            km.enable_post_quantum()?;
            return Ok(Self {
                id_type,
                key_manager: Box::new(km),
                certificate,
            });
        }

        match id_type {
            TYPE_MACHINE | TYPE_PERSON | TYPE_ORGANIZATION => {
                // Determine which manager to use based on secret length
                let key_manager: Box<dyn AbstractKeyManager> = if secret.len() == 77 {
                    // Ed25519Manager secret
                    Box::new(Ed25519Manager::from_secret(secret_data)?)
                } else if secret.len() == 73 {
                    // DilithiumManager secret (much larger due to Dilithium keys)
                    Box::new(DilithiumManager::from_secret(secret_data)?)
                } else {
                    // Try DeprecatedKeyManager (needs to implement AbstractKeyManager)
                    return Err(Error::InvalidIdFormat);
                };

                Ok(Self {
                    id_type,
                    key_manager,
                    certificate,
                })
            }
            _ => Err(Error::InvalidType(id_type)),
        }
    }

    /// Create from an ID
    pub fn from_id(
        id: &[u8],
        certificate: Option<Vec<u8>>,
        encoding: Option<&str>,
    ) -> Result<Self> {
        let clean_id = if let Some(enc) = encoding {
            match enc {
                "hex" => crate::crypto::from_hex(
                    std::str::from_utf8(id).map_err(|e| Error::Other(e.to_string()))?,
                )?,
                "base64" => crate::crypto::from_base64(
                    std::str::from_utf8(id).map_err(|e| Error::Other(e.to_string()))?,
                )?,
                _ => id.to_vec(),
            }
        } else {
            id.to_vec()
        };

        if clean_id.is_empty() {
            return Err(Error::InvalidIdFormat);
        }

        let id_type = clean_id[0];
        let id_data = &clean_id[1..];

        if is_post_quantum_type(id_type) {
            // rfc/PQ-ENCRYPTION.md §4.2: dispatch on the signing key, never on the
            // total length
            let record = post_quantum::parse_post_quantum_record(id_data)?;
            let key_manager: Box<dyn AbstractKeyManager> = match record.x.len() {
                DILITHIUM_PUBLIC_KEY_LENGTH => {
                    Box::new(DilithiumManager::from_post_quantum_id(id_data)?)
                }
                HYBRID_PUBLIC_KEY_LENGTH => {
                    return Err(Error::NotImplemented(HYBRID_NOT_IMPLEMENTED.into()))
                }
                _ => {
                    return Err(Error::InvalidKeyFormat(
                        "post-quantum id with an unsupported key manager".into(),
                    ))
                }
            };
            return Ok(Self {
                id_type,
                key_manager,
                certificate,
            });
        }

        match id_type {
            TYPE_FIDO2 | TYPE_FIDO2PRF => {
                // FIDO2 managers not implemented in this version
                Err(Error::Other("FIDO2 managers not implemented".into()))
            }
            TYPE_MACHINE | TYPE_PERSON | TYPE_ORGANIZATION => {
                // Determine which manager to use based on ID length
                // Ed25519Manager serializes to 76 bytes (1 byte version + 32 bytes x + 32 bytes e)
                // With type byte prefix, total is 77 bytes
                // DilithiumManager ID is much larger (1351 bytes for public keys)
                // DeprecatedKeyManager includes proof field, making it longer than Ed25519 but shorter than Dilithium
                let key_manager: Box<dyn AbstractKeyManager> = if clean_id.len() == 77 {
                    // Ed25519Manager ID (76 bytes + 1 type byte = 77 total)
                    Box::new(Ed25519Manager::from_id(id_data)?)
                } else if clean_id.len() > 1300 {
                    // DilithiumManager ID (around 1351 bytes + 1 type byte)
                    Box::new(DilithiumManager::from_id(id_data)?)
                } else {
                    // DeprecatedKeyManager ID (longer than Ed25519 due to proof field)
                    return Err(Error::InvalidIdFormat);
                };

                Ok(Self {
                    id_type,
                    key_manager,
                    certificate,
                })
            }
            _ => Err(Error::InvalidType(id_type)),
        }
    }

    /// Create from entropy
    pub async fn from_entropy(entropy: &[u8], id_type: u8) -> Result<Self> {
        Self::from_entropy_with_alg(entropy, id_type, Algorithm::Ed25519).await
    }

    /// Create from entropy with algorithm selection
    pub async fn from_entropy_with_alg(
        entropy: &[u8],
        id_type: u8,
        alg: Algorithm,
    ) -> Result<Self> {
        if is_post_quantum_type(id_type) {
            let mut km = match alg {
                Algorithm::Dilithium => DilithiumManager::from_entropy(entropy)?,
                Algorithm::Ed25519 => {
                    return Err(Error::InvalidKeyFormat(
                        "post-quantum identities require a Dilithium key manager".into(),
                    ))
                }
            };
            km.enable_post_quantum()?;
            return Ok(Self {
                id_type,
                key_manager: Box::new(km),
                certificate: None,
            });
        }

        let key_manager: Box<dyn AbstractKeyManager> = match id_type {
            TYPE_MACHINE | TYPE_PERSON | TYPE_ORGANIZATION => match alg {
                Algorithm::Dilithium => Box::new(DilithiumManager::from_entropy(entropy)?),
                Algorithm::Ed25519 => Box::new(Ed25519Manager::from_entropy(entropy)?),
            },
            _ => return Err(Error::InvalidType(id_type)),
        };

        Ok(Self {
            id_type,
            key_manager,
            certificate: None,
        })
    }

    /// Generate a new machine ID
    pub async fn generate_machine() -> Result<Self> {
        Self::generate_machine_with_alg(Algorithm::Ed25519).await
    }

    /// Generate a new machine ID with algorithm selection
    pub async fn generate_machine_with_alg(alg: Algorithm) -> Result<Self> {
        let entropy = random_bytes(32);
        Self::from_entropy_with_alg(&entropy, TYPE_MACHINE, alg).await
    }

    /// Generate a new person ID
    pub async fn generate_person() -> Result<Self> {
        Self::generate_person_with_alg(Algorithm::Ed25519).await
    }

    /// Generate a new person ID with algorithm selection
    pub async fn generate_person_with_alg(alg: Algorithm) -> Result<Self> {
        let entropy = random_bytes(32);
        Self::from_entropy_with_alg(&entropy, TYPE_PERSON, alg).await
    }

    /// Generate a new organization ID
    pub async fn generate_organization() -> Result<Self> {
        Self::generate_organization_with_alg(Algorithm::Ed25519).await
    }

    /// Generate a new organization ID with algorithm selection
    pub async fn generate_organization_with_alg(alg: Algorithm) -> Result<Self> {
        let entropy = random_bytes(32);
        Self::from_entropy_with_alg(&entropy, TYPE_ORGANIZATION, alg).await
    }

    /// Get the complete ID including type byte
    pub fn id(&self) -> Vec<u8> {
        let mut result = vec![self.id_type];
        result.extend_from_slice(&self.key_manager.id());
        result
    }

    /// Get the secret from the key manager
    pub fn get_secret(&self) -> Result<Vec<u8>> {
        let mut result = vec![self.id_type];
        result.extend_from_slice(&self.key_manager.get_secret()?);
        Ok(result)
    }

    /// Generate a new VaultysId with optional type
    pub async fn generate(id_type: Option<u8>) -> Result<Self> {
        let id_type = id_type.unwrap_or(TYPE_MACHINE);
        match id_type {
            TYPE_MACHINE => Self::generate_machine().await,
            TYPE_PERSON => Self::generate_person().await,
            TYPE_ORGANIZATION => Self::generate_organization().await,
            _ => Err(Error::InvalidType(id_type)),
        }
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.key_manager.sign(data).ok().flatten()
    }

    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        self.key_manager.verify(data, signature, None)
    }

    /// Duplicate the VaultysId by re-importing from secret
    pub fn duplicate(&self) -> Self {
        let secret = self.get_secret().unwrap();
        Self::from_secret(&secret, self.certificate.clone()).unwrap()
    }

    /// Get fingerprint
    /// Get the fingerprint for this id
    pub fn fingerprint(&self) -> Vec<u8> {
        let mut fp_bytes = vec![self.id_type];
        let id = self.key_manager.id();
        fp_bytes.extend_from_slice(&hash("sha224", &id));
        fp_bytes
    }

    /// Get formatted fingerprint (matching TypeScript format)
    pub fn fingerprint_formatted(&self) -> String {
        let fp_bytes = self.fingerprint();
        let hex = crate::crypto::to_hex(&fp_bytes);
        // Take first 40 characters (20 bytes), convert to uppercase, and add spaces every 4 chars
        let truncated = &hex[..40.min(hex.len())];
        let upper = truncated.to_uppercase();
        let mut result = String::new();
        for (i, chunk) in upper.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                result.push(' ');
            }
            result.push_str(std::str::from_utf8(chunk).unwrap());
        }
        result
    }

    /// Get DID
    pub fn did(&self) -> String {
        let mut fp_bytes = Vec::new();
        fp_bytes.push(self.id_type);
        fp_bytes.extend_from_slice(&hash("sha224", &self.key_manager.id()));
        let fp_hex = crate::crypto::to_hex(&fp_bytes);
        format!("did:vaultys:{}", &fp_hex[0..40])
    }

    /// Get DID document
    pub fn did_document(&self) -> serde_json::Value {
        let did = self.did();
        let id = self.id();

        // This is a simplified DID document
        let mut document = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did.clone(),
            "authentication": [{
                "id": format!("{}#keys-1", did),
                "type": "Ed25519VerificationKey2020",
                "controller": did.clone(),
                "publicKeyMultibase": crate::crypto::to_base64(&id)
            }],
            "keyAgreement": [{
                "id": format!("{}#keys-2", did),
                "type": "X25519KeyAgreementKey2019",
                "controller": did.clone(),
                "publicKeyMultibase": crate::crypto::to_base64(&id)
            }]
        });
        // rfc/PQ-ENCRYPTION.md §4.4
        if let Some(k) = self.kem_public_key() {
            document["keyAgreement"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "id": format!("{}#keys-3", did),
                    "type": "MLKEM768KeyAgreementKey2025",
                    "controller": did.clone(),
                    "publicKeyMultibase": format!("m{}", crate::crypto::to_base64(k))
                }));
        }
        document
    }

    // Role checks ignore the post-quantum flag (rfc/PQ-ENCRYPTION.md §4.1).

    /// Check if this is a hardware ID
    pub fn is_hardware(&self) -> bool {
        matches!(role_of(self.id_type), TYPE_FIDO2 | TYPE_FIDO2PRF)
    }

    /// Check if this is a machine ID
    pub fn is_machine(&self) -> bool {
        role_of(self.id_type) == TYPE_MACHINE
    }

    /// Check if this is a person ID
    pub fn is_person(&self) -> bool {
        role_of(self.id_type) == TYPE_PERSON
    }

    /// Check if this is an organization ID
    pub fn is_organization(&self) -> bool {
        role_of(self.id_type) == TYPE_ORGANIZATION
    }

    /// True for the post-quantum types `0x10`-`0x12`, which carry an ML-KEM-768 key
    /// and a seed-derived PRF key.
    pub fn is_post_quantum(&self) -> bool {
        is_post_quantum_type(self.id_type)
    }

    /// ML-KEM-768 encapsulation key (field `k`) of a post-quantum identity.
    pub fn kem_public_key(&self) -> Option<&[u8]> {
        if self.is_post_quantum() {
            self.key_manager.kem_public_key()
        } else {
            None
        }
    }

    /// `HMAC-SHA256(key, "VaultysID/" || message || "/end")`, as TypeScript
    /// `VaultysId.hmac`: keyed with the PRF key for a post-quantum identity.
    /// Implemented for Dilithium key managers only.
    pub fn hmac(&self, message: &str) -> Result<Vec<u8>> {
        self.key_manager.prf_hmac(message)
    }

    /// Get OTP HMAC
    /// Get HMAC for OTP authentication
    pub fn get_otp_hmac(&self, otp_type: &str, counter: u64) -> Result<Option<Vec<u8>>> {
        let otp = format!("{}/{}", otp_type, counter);
        // Use get_secret_hash for HMAC-like functionality
        Ok(Some(self.key_manager.get_secret_hash(otp.as_bytes())?))
    }

    /// Perform Diffie-Hellman key exchange
    pub async fn perform_diffie_hellman(&self, other_id: &[u8]) -> Result<Vec<u8>> {
        let other_vaultys_id = Self::from_id(other_id, None, None)?;
        self.key_manager
            .perform_diffie_hellman(&*other_vaultys_id.key_manager)
    }

    /// DHIES encrypt. A post-quantum recipient gets DHIES v3 (X25519 + ML-KEM-768,
    /// rfc/PQ-ENCRYPTION.md §5); other recipients keep the existing Rust DHIES.
    pub async fn dhies_encrypt(&self, message: &[u8], recipient_id: &[u8]) -> Result<Vec<u8>> {
        if recipient_id
            .first()
            .copied()
            .is_some_and(is_post_quantum_type)
        {
            // full validation of the recipient id first
            let recipient = Self::from_id(recipient_id, None, None)?;
            let (recipient_public, _) = post_quantum::encryption_keys_of_id(recipient_id)?;
            let recipient_ek = recipient.kem_public_key().ok_or(Error::InvalidIdFormat)?;
            let (sender_public, _) = post_quantum::encryption_keys_of_id(&self.id())?;
            let cypher = self.key_manager.get_cypher()?;
            let sender_dh = |public_key: &[u8]| cypher.diffie_hellman(public_key);
            return post_quantum::dhies_v3_encrypt(
                &sender_dh,
                &sender_public,
                &recipient_public,
                recipient_ek,
                message,
            );
        }
        self.key_manager.dhies_encrypt(message, recipient_id)
    }

    /// DHIES decrypt. A post-quantum identity only accepts DHIES v3 (§5.4), which
    /// removes any downgrade path.
    pub async fn dhies_decrypt(
        &self,
        encrypted_message: &[u8],
        sender_id: &[u8],
    ) -> Result<Vec<u8>> {
        if self.is_post_quantum() {
            let failed = || Error::DecryptionFailed("DHIES v3".into());
            let (sender_public, _) =
                post_quantum::encryption_keys_of_id(sender_id).map_err(|_| failed())?;
            let (recipient_public, _) = post_quantum::encryption_keys_of_id(&self.id())?;
            let recipient_ek = self.kem_public_key().ok_or_else(failed)?;
            let cypher = self.key_manager.get_cypher().map_err(|_| failed())?;
            let dh = |public_key: &[u8]| cypher.diffie_hellman(public_key);
            let decapsulate = |cipher_text: &[u8]| self.key_manager.kem_decapsulate(cipher_text);
            return post_quantum::dhies_v3_decrypt(
                &dh,
                &decapsulate,
                &recipient_public,
                recipient_ek,
                &sender_public,
                encrypted_message,
            );
        }
        self.key_manager.dhies_decrypt(encrypted_message, sender_id)
    }

    /// Sign a challenge using v0 method (for backward compatibility)
    pub async fn sign_challenge_v0(
        &self,
        challenge: &[u8],
        old_id: &[u8],
    ) -> Result<SignedChallenge> {
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(old_id);
        to_sign.extend_from_slice(challenge);

        let result = hash("sha256", &to_sign);

        let signature = self
            .key_manager
            .sign(&result)?
            .ok_or(Error::InvalidCapability(
                "No signature capability available".into(),
            ))?;

        Ok(SignedChallenge { result, signature })
    }

    /// Sign a challenge
    pub async fn sign_challenge(&self, challenge: &[u8]) -> Result<SignedChallenge> {
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(SIGN_INCIPIT);
        to_sign.extend_from_slice(challenge);

        let result = hash("sha256", &to_sign);

        let signature = self
            .key_manager
            .sign(&result)?
            .ok_or(Error::InvalidCapability(
                "No signature capability available".into(),
            ))?;

        Ok(SignedChallenge { result, signature })
    }

    /// Verify a challenge
    pub fn verify_challenge(&self, challenge: &[u8], signature: &[u8]) -> Result<bool> {
        let mut to_verify = Vec::new();
        to_verify.extend_from_slice(SIGN_INCIPIT);
        to_verify.extend_from_slice(challenge);

        let result = hash("sha256", &to_verify);
        Ok(self.key_manager.verify(&result, signature, Some(true)))
    }

    /// Verify a challenge using v0 method (for backward compatibility)
    pub fn verify_challenge_v0(
        &self,
        challenge: &[u8],
        signature: &[u8],
        old_id: &[u8],
    ) -> Result<bool> {
        let mut to_verify = Vec::new();
        to_verify.extend_from_slice(old_id);
        to_verify.extend_from_slice(challenge);

        let result = hash("sha256", &to_verify);
        Ok(self.key_manager.verify(&result, signature, Some(true)))
    }

    /// Signcrypt a message for multiple recipients
    pub async fn signcrypt(&self, plaintext: &str, recipient_ids: &[Vec<u8>]) -> Result<String> {
        self.key_manager.signcrypt(plaintext, recipient_ids)
    }

    /// Decrypt a message
    pub async fn decrypt(
        &self,
        encrypted_message: &str,
        sender_id: Option<&[u8]>,
    ) -> Result<String> {
        self.key_manager.decrypt(encrypted_message, sender_id)
    }

    /// Clean secure data from memory
    pub fn clean_secure_data(&mut self) {
        self.key_manager.clean_secure_data();
    }
}

/// Represents a signed challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedChallenge {
    pub result: Vec<u8>,
    pub signature: Vec<u8>,
}

impl fmt::Display for VaultysId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultysId(type={}, did={})", self.id_type, self.did())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_machine() {
        let id = VaultysId::generate_machine().await.unwrap();
        assert_eq!(id.id_type, TYPE_MACHINE);
        assert!(id.is_machine());
        assert!(!id.is_person());
        assert!(!id.is_organization());
    }

    #[tokio::test]
    async fn test_generate_person() {
        let id = VaultysId::generate_person().await.unwrap();
        assert_eq!(id.id_type, TYPE_PERSON);
        assert!(id.is_person());
        assert!(!id.is_machine());
        assert!(!id.is_organization());
    }

    #[tokio::test]
    async fn test_generate_organization() {
        let id = VaultysId::generate_organization().await.unwrap();
        assert_eq!(id.id_type, TYPE_ORGANIZATION);
        assert!(id.is_organization());
        assert!(!id.is_machine());
        assert!(!id.is_person());
    }

    #[tokio::test]
    async fn test_round_trip_id() {
        let id1 = VaultysId::generate_machine().await.unwrap();
        let id_bytes = id1.id();
        let id2 = VaultysId::from_id(&id_bytes, None, None).unwrap();

        assert_eq!(id1.id_type, id2.id_type);
        assert_eq!(id1.fingerprint(), id2.fingerprint());
        assert_eq!(id1.did(), id2.did());
    }

    #[tokio::test]
    async fn test_sign_verify_challenge() {
        let id = VaultysId::generate_machine().await.unwrap();
        let challenge = b"test challenge";

        let signed = id.sign_challenge(challenge).await.unwrap();
        assert!(id.verify_challenge(challenge, &signed.signature).unwrap());

        // Wrong challenge should fail
        assert!(!id
            .verify_challenge(b"wrong challenge", &signed.signature)
            .unwrap());
    }

    #[tokio::test]
    async fn test_did_document() {
        let id = VaultysId::generate_person().await.unwrap();
        let did_doc = id.did_document();

        assert!(did_doc["@context"].is_array());
        assert!(did_doc["id"].is_string());
        assert!(did_doc["authentication"].is_array());
        assert!(did_doc["keyAgreement"].is_array());
    }
}
