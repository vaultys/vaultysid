use crate::crypto::{hash, random_bytes};
use crate::error::{Error, Result};
use crate::key_manager::{Capability, DeprecatedKeyManager, Ed25519Manager};
use serde::{Deserialize, Serialize};
use std::fmt;

// Type constants matching TypeScript
const TYPE_MACHINE: u8 = 0;
const TYPE_PERSON: u8 = 1;
const TYPE_ORGANIZATION: u8 = 2;
const TYPE_FIDO2: u8 = 3;
const TYPE_FIDO2PRF: u8 = 4;

const SIGN_INCIPIT: &[u8] = b"VAULTYS_SIGN";

/// Represents a VaultysId with its associated key manager
pub struct VaultysId {
    pub id_type: u8,
    pub key_manager: Box<dyn KeyManagerTrait>,
    pub certificate: Option<Vec<u8>>,
}

/// Trait that all key managers must implement for use with VaultysId
pub trait KeyManagerTrait: Send + Sync {
    fn id(&self) -> Vec<u8>;
    fn get_secret(&self) -> Result<Vec<u8>>;
    fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>>;
    fn verify(&self, data: &[u8], signature: &[u8], user_verification: Option<bool>) -> bool;
    fn clean_secure_data(&mut self);
    fn capability(&self) -> Capability;
    fn version(&self) -> u8;
    fn perform_diffie_hellman(&self, other_public_key: &[u8]) -> Result<Vec<u8>>;
    fn dhies_encrypt(&self, message: &[u8], recipient_id: &[u8]) -> Result<Vec<u8>>;
    fn dhies_decrypt(&self, encrypted_message: &[u8], sender_id: &[u8]) -> Result<Vec<u8>>;
    fn get_hmac(&self, message: &str) -> Result<Option<Vec<u8>>>;
    fn signcrypt(&self, plaintext: &str, recipient_ids: &[Vec<u8>]) -> Result<String>;
    fn decrypt(&self, encrypted_message: &str, sender_id: Option<&[u8]>) -> Result<String>;
    fn get_fingerprint(&self) -> Vec<u8>;
    fn get_did(&self, id_type: u8) -> String;
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

// Implement the trait for Ed25519Manager
impl KeyManagerTrait for Ed25519Manager {
    fn id(&self) -> Vec<u8> {
        self.id()
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        self.get_secret()
    }

    fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.base.capability != Capability::Private {
            return Ok(None);
        }
        let signer = self.get_signer_ops()?;
        Ok(Some(signer.sign(data)?))
    }

    fn verify(&self, data: &[u8], signature: &[u8], user_verification: Option<bool>) -> bool {
        self.verify(data, signature, user_verification)
    }

    fn clean_secure_data(&mut self) {
        self.clean_secure_data()
    }

    fn capability(&self) -> Capability {
        self.base.capability
    }

    fn version(&self) -> u8 {
        self.base.version
    }

    fn perform_diffie_hellman(&self, other_public_key: &[u8]) -> Result<Vec<u8>> {
        let cypher = self.get_cypher_ops()?;
        cypher.diffie_hellman(other_public_key)
    }

    fn dhies_encrypt(&self, message: &[u8], recipient_id: &[u8]) -> Result<Vec<u8>> {
        let recipient_public_key =
            crate::key_manager::cypher_manager::get_cypher_public_key_from_id(recipient_id)?;
        let dhies = crate::key_manager::cypher_manager::DHIES::new(
            self as &dyn crate::key_manager::cypher_manager::CypherOperations,
        );
        dhies.encrypt(message, &recipient_public_key)
    }

    fn dhies_decrypt(&self, encrypted_message: &[u8], sender_id: &[u8]) -> Result<Vec<u8>> {
        let sender_public_key =
            crate::key_manager::cypher_manager::get_cypher_public_key_from_id(sender_id)?;
        let dhies = crate::key_manager::cypher_manager::DHIES::new(
            self as &dyn crate::key_manager::cypher_manager::CypherOperations,
        );
        dhies.decrypt(encrypted_message, &sender_public_key)
    }

    fn get_hmac(&self, message: &str) -> Result<Option<Vec<u8>>> {
        let cypher = self.get_cypher_ops()?;
        cypher.hmac(message)
    }

    fn signcrypt(&self, _plaintext: &str, _recipient_ids: &[Vec<u8>]) -> Result<String> {
        // Saltpack signcrypt not implemented in this version
        Err(Error::Other(
            "Signcrypt not implemented in this version".into(),
        ))
    }

    fn decrypt(&self, _encrypted_message: &str, _sender_id: Option<&[u8]>) -> Result<String> {
        // Saltpack decrypt not implemented in this version
        Err(Error::Other(
            "Decrypt not implemented in this version".into(),
        ))
    }

    fn get_fingerprint(&self) -> Vec<u8> {
        let id = self.id();
        hash("sha224", &id)
    }

    fn get_did(&self, id_type: u8) -> String {
        // Match TypeScript: Buffer.concat([Buffer.from([this.type]), hash("SHA224", this.keyManager.id)])
        let mut fp_bytes = Vec::new();
        fp_bytes.push(id_type);
        fp_bytes.extend_from_slice(&hash("sha224", &self.id()));
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

// Implement the trait for DeprecatedKeyManager
impl KeyManagerTrait for DeprecatedKeyManager {
    fn id(&self) -> Vec<u8> {
        self.id()
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        self.get_secret()
    }

    fn sign(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        self.sign(data)
    }

    fn verify(&self, data: &[u8], signature: &[u8], user_verification: Option<bool>) -> bool {
        self.verify(data, signature, user_verification)
    }

    fn clean_secure_data(&mut self) {
        self.clean_secure_data()
    }

    fn capability(&self) -> Capability {
        self.capability
    }

    fn version(&self) -> u8 {
        self.version
    }

    fn perform_diffie_hellman(&self, other_public_key: &[u8]) -> Result<Vec<u8>> {
        let cypher = self.get_cypher()?;
        cypher.diffie_hellman(other_public_key)
    }

    fn dhies_encrypt(&self, _message: &[u8], _recipient_id: &[u8]) -> Result<Vec<u8>> {
        // Simplified implementation for deprecated manager
        Err(Error::Other(
            "DHIES not fully implemented for deprecated manager".into(),
        ))
    }

    fn dhies_decrypt(&self, _encrypted_message: &[u8], _sender_id: &[u8]) -> Result<Vec<u8>> {
        // Simplified implementation for deprecated manager
        Err(Error::Other(
            "DHIES not fully implemented for deprecated manager".into(),
        ))
    }

    fn get_hmac(&self, message: &str) -> Result<Option<Vec<u8>>> {
        let cypher = self.get_cypher()?;
        cypher.hmac(message)
    }

    fn signcrypt(&self, _plaintext: &str, _recipient_ids: &[Vec<u8>]) -> Result<String> {
        // Saltpack signcrypt not implemented in this version
        Err(Error::Other(
            "Signcrypt not implemented in this version".into(),
        ))
    }

    fn decrypt(&self, _encrypted_message: &str, _sender_id: Option<&[u8]>) -> Result<String> {
        // Saltpack decrypt not implemented in this version
        Err(Error::Other(
            "Decrypt not implemented in this version".into(),
        ))
    }

    fn get_fingerprint(&self) -> Vec<u8> {
        let id = self.id();
        hash("sha224", &id)
    }

    fn get_did(&self, id_type: u8) -> String {
        // Match TypeScript: Buffer.concat([Buffer.from([this.type]), hash("SHA224", this.keyManager.id)])
        let mut fp_bytes = Vec::new();
        fp_bytes.push(id_type);
        fp_bytes.extend_from_slice(&hash("sha224", &self.id()));
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
        key_manager: Box<dyn KeyManagerTrait>,
        certificate: Option<Vec<u8>>,
        id_type: u8,
    ) -> Self {
        Self {
            id_type,
            key_manager,
            certificate,
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

        match id_type {
            TYPE_FIDO2 | TYPE_FIDO2PRF => {
                // FIDO2 managers not implemented in this version
                Err(Error::Other("FIDO2 managers not implemented".into()))
            }
            TYPE_MACHINE | TYPE_PERSON | TYPE_ORGANIZATION => {
                // Determine which manager to use based on ID length
                // Ed25519Manager serializes to 76 bytes (1 byte version + 32 bytes x + 32 bytes e)
                // With type byte prefix, total is 77 bytes
                // DeprecatedKeyManager includes proof field, making it longer
                let key_manager: Box<dyn KeyManagerTrait> = if clean_id.len() <= 77 {
                    // Ed25519Manager ID (76 bytes + 1 type byte = 77 total)
                    Box::new(Ed25519Manager::from_id(id_data)?)
                } else {
                    // DeprecatedKeyManager ID (longer due to proof field)
                    Box::new(DeprecatedKeyManager::from_id(id_data)?)
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
        let key_manager: Box<dyn KeyManagerTrait> = match id_type {
            TYPE_MACHINE | TYPE_PERSON | TYPE_ORGANIZATION => {
                Box::new(Ed25519Manager::from_entropy(entropy)?)
            }
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
        let entropy = random_bytes(32);
        Self::from_entropy(&entropy, TYPE_MACHINE).await
    }

    /// Generate a new person ID
    pub async fn generate_person() -> Result<Self> {
        let entropy = random_bytes(32);
        Self::from_entropy(&entropy, TYPE_PERSON).await
    }

    /// Generate a new organization ID
    pub async fn generate_organization() -> Result<Self> {
        let entropy = random_bytes(32);
        Self::from_entropy(&entropy, TYPE_ORGANIZATION).await
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

    /// Create from secret
    pub fn from_secret(secret: &[u8], certificate: Option<Vec<u8>>) -> Result<Self> {
        if secret.is_empty() {
            return Err(Error::InvalidIdFormat);
        }

        let id_type = secret[0];
        let secret_data = &secret[1..];

        let key_manager: Box<dyn KeyManagerTrait> = match id_type {
            TYPE_MACHINE | TYPE_PERSON | TYPE_ORGANIZATION => {
                Box::new(Ed25519Manager::from_secret(secret_data)?)
            }
            _ => return Err(Error::InvalidType(id_type)),
        };

        Ok(Self {
            id_type,
            key_manager,
            certificate,
        })
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

    /// Clone the VaultysId by re-importing from secret
    pub fn clone(&self) -> Self {
        let secret = self.get_secret().unwrap();
        Self::from_secret(&secret, self.certificate.clone()).unwrap()
    }

    /// Get fingerprint
    pub fn fingerprint(&self) -> Vec<u8> {
        let mut fp_bytes = vec![self.id_type];
        fp_bytes.extend_from_slice(&self.key_manager.get_fingerprint());
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
        self.key_manager.get_did(self.id_type)
    }

    /// Get DID document
    pub fn did_document(&self) -> serde_json::Value {
        let did = self.did();
        let id = self.id();

        // This is a simplified DID document
        serde_json::json!({
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
        })
    }

    /// Check if this is a hardware ID
    pub fn is_hardware(&self) -> bool {
        matches!(self.id_type, TYPE_FIDO2 | TYPE_FIDO2PRF)
    }

    /// Check if this is a machine ID
    pub fn is_machine(&self) -> bool {
        self.id_type == TYPE_MACHINE
    }

    /// Check if this is a person ID
    pub fn is_person(&self) -> bool {
        self.id_type == TYPE_PERSON
    }

    /// Check if this is an organization ID
    pub fn is_organization(&self) -> bool {
        self.id_type == TYPE_ORGANIZATION
    }

    /// Get OTP HMAC
    pub fn get_otp_hmac(&self, otp_type: &str, counter: u64) -> Result<Option<Vec<u8>>> {
        let otp = format!("{}/{}", otp_type, counter);
        self.key_manager.get_hmac(&otp)
    }

    /// Perform Diffie-Hellman key exchange
    pub async fn perform_diffie_hellman(&self, other_id: &[u8]) -> Result<Vec<u8>> {
        let other_vaultys_id = Self::from_id(other_id, None, None)?;
        let other_public_key = &other_vaultys_id.key_manager.id();
        self.key_manager.perform_diffie_hellman(other_public_key)
    }

    /// DHIES encrypt
    pub async fn dhies_encrypt(&self, message: &[u8], recipient_id: &[u8]) -> Result<Vec<u8>> {
        self.key_manager.dhies_encrypt(message, recipient_id)
    }

    /// DHIES decrypt
    pub async fn dhies_decrypt(
        &self,
        encrypted_message: &[u8],
        sender_id: &[u8],
    ) -> Result<Vec<u8>> {
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
            .ok_or_else(|| Error::InvalidCapability)?;

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
            .ok_or_else(|| Error::InvalidCapability)?;

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
