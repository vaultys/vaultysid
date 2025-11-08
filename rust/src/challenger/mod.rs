use crate::crypto::{hash, random_bytes};
use crate::error::{Error, Result};
use crate::VaultysId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

// State constants
const ERROR: i32 = -2;
const UNINITIALISED: i32 = -1;
const INIT: i32 = 0;
const STEP1: i32 = 1;
const COMPLETE: i32 = 2;

// Sign prefix constant

/// Represents a challenge in the VaultysId protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeType {
    #[serde(rename = "version")]
    pub version: u8,

    #[serde(rename = "protocol")]
    pub protocol: String,

    #[serde(rename = "service")]
    pub service: String,

    #[serde(rename = "timestamp")]
    pub timestamp: u64,

    #[serde(
        rename = "pk1",
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes"
    )]
    pub pk1: Option<Vec<u8>>,

    #[serde(
        rename = "pk2",
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes"
    )]
    pub pk2: Option<Vec<u8>>,

    #[serde(
        rename = "nonce",
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes"
    )]
    pub nonce: Option<Vec<u8>>,

    #[serde(
        rename = "sign1",
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes"
    )]
    pub sign1: Option<Vec<u8>>,

    #[serde(
        rename = "sign2",
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes"
    )]
    pub sign2: Option<Vec<u8>>,

    #[serde(rename = "metadata")]
    pub metadata: ChallengeMetadata,

    // State and error are not serialized - they are internal tracking fields
    #[serde(skip)]
    pub state: i32,

    #[serde(skip)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChallengeMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pk1: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pk2: Option<BTreeMap<String, String>>,
}

// Custom serialization for Option<Vec<u8>> as bytes
mod option_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes.as_slice(), serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<serde_bytes::ByteBuf>::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

// Internal structure for serialization that matches TypeScript format
// Force struct format (map) instead of array format
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
struct SerializableChallenge {
    #[serde(default)]
    version: u8,
    protocol: String,
    service: String,
    timestamp: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_bytes"
    )]
    pk1: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_bytes"
    )]
    pk2: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_bytes"
    )]
    nonce: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_bytes"
    )]
    sign1: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_bytes"
    )]
    sign2: Option<Vec<u8>>,
    #[serde(default)]
    metadata: ChallengeMetadata,
}

/// Challenger implements the challenge-response protocol for VaultysId
pub struct Challenger {
    state: i32,
    vaultys_id: VaultysId,
    my_key: Option<Vec<u8>>,
    his_key: Option<Vec<u8>>,
    liveliness: u64,
    challenge: Option<ChallengeType>,
    version: u8,
}

impl Challenger {
    /// Create a new Challenger instance
    pub fn new(vaultys_id: VaultysId, liveliness_ms: Option<u64>) -> Self {
        // Create a copy of VaultysId by re-importing from secret
        let secret = vaultys_id.get_secret().unwrap();
        let vaultys_id_copy = VaultysId::from_secret(&secret, None).unwrap();

        Self {
            state: UNINITIALISED,
            vaultys_id: vaultys_id_copy,
            my_key: None,
            his_key: None,
            liveliness: liveliness_ms.unwrap_or(60_000), // Default 60 seconds
            challenge: None,
            version: 0,
        }
    }

    /// Verify if a certificate is complete
    pub fn verify_certificate(certificate: &[u8]) -> Result<bool> {
        let deser = Self::deserialize_certificate(certificate)?;
        Ok(deser.state == COMPLETE)
    }

    /// Create a Challenger from a certificate
    pub fn from_certificate(certificate: &[u8], liveliness: Option<u64>) -> Result<Self> {
        let mut deser = Self::deserialize_certificate(certificate)?;
        if deser.version == 0 {
            deser.version = 0;
        }

        if deser.state == INIT {
            let pk1 = deser.pk1.as_ref().ok_or(Error::DeserializationError(
                "Missing pk1 in certificate".into(),
            ))?;
            let vaultys_id = VaultysId::from_id(pk1, None, None)?;
            let mut challenger = Self::new(vaultys_id.to_version(deser.version)?, liveliness);
            challenger.challenge = Some(deser.clone());
            challenger.my_key = deser.pk1;
            challenger.state = INIT;
            Ok(challenger)
        } else if deser.state == STEP1 {
            let pk2 = deser.pk2.as_ref().ok_or(Error::DeserializationError(
                "Missing pk2 in certificate".into(),
            ))?;
            let vaultys_id = VaultysId::from_id(pk2, None, None)?;
            let mut challenger = Self::new(vaultys_id.to_version(deser.version)?, liveliness);
            challenger.challenge = Some(deser.clone());
            challenger.my_key = deser.pk2;
            challenger.his_key = deser.pk1;
            challenger.state = STEP1;
            Ok(challenger)
        } else {
            Err(Error::InvalidState("Invalid certificate state".into()))
        }
    }

    /// Deserialize a certificate (without signature verification, for testing only)
    pub fn deserialize_certificate_unchecked(certificate: &[u8]) -> Result<ChallengeType> {
        // Use rmp_serde's from_slice to deserialize from map format
        let serializable: SerializableChallenge =
            rmp_serde::from_slice(certificate).map_err(|e| {
                Error::DeserializationError(format!("Failed to deserialize certificate: {}", e))
            })?;

        let mut result = ChallengeType {
            version: serializable.version,
            protocol: serializable.protocol,
            service: serializable.service,
            timestamp: serializable.timestamp,
            pk1: serializable.pk1.clone(),
            pk2: serializable.pk2.clone(),
            nonce: serializable.nonce.clone(),
            sign1: serializable.sign1.clone(),
            sign2: serializable.sign2.clone(),
            metadata: serializable.metadata,
            state: UNINITIALISED,
            error: None,
        };

        // Determine state based on which fields are present (without verification)
        if serializable.sign1.is_some() && serializable.sign2.is_some() {
            result.state = COMPLETE;
        } else if serializable.sign2.is_some() && serializable.sign1.is_none() {
            result.state = STEP1;
        } else if serializable.pk1.is_some()
            && serializable.sign1.is_none()
            && serializable.sign2.is_none()
        {
            result.state = INIT;
        } else {
            result.state = UNINITIALISED;
        }

        Ok(result)
    }

    /// Deserialize a certificate with signature verification
    pub fn deserialize_certificate(certificate: &[u8]) -> Result<ChallengeType> {
        // Use rmp_serde's from_slice to deserialize from map format
        let serializable: SerializableChallenge =
            rmp_serde::from_slice(certificate).map_err(|e| {
                Error::DeserializationError(format!("Failed to deserialize certificate: {}", e))
            })?;

        let mut result = ChallengeType {
            version: serializable.version,
            protocol: serializable.protocol,
            service: serializable.service,
            timestamp: serializable.timestamp,
            pk1: serializable.pk1.clone(),
            pk2: serializable.pk2.clone(),
            nonce: serializable.nonce.clone(),
            sign1: serializable.sign1.clone(),
            sign2: serializable.sign2.clone(),
            metadata: serializable.metadata,
            state: UNINITIALISED,
            error: None,
        };

        // Determine state and verify signatures based on which fields are present
        if serializable.sign1.is_none()
            && serializable.sign2.is_some()
            && serializable.nonce.is_some()
            && serializable.nonce.as_ref().unwrap().len() == 32
            && serializable.pk1.is_some()
            && serializable.pk2.is_some()
        {
            // STEP1 state - verify sign2
            result.state = STEP1;

            if let (Some(pk2), Some(sign2)) = (&serializable.pk2, &serializable.sign2) {
                // Create VaultysId from pk2 to verify the signature
                let id2 = VaultysId::from_id(pk2, None, None)?;
                let unsigned_challenge = Self::serialize_unsigned(&result)?;

                // Try both v1 and v0 signature verification
                let verified = id2
                    .verify_challenge(&unsigned_challenge, sign2)
                    .unwrap_or(false)
                    || id2
                        .verify_challenge_v0(&unsigned_challenge, sign2, pk2)
                        .unwrap_or(false);

                if !verified {
                    result.state = ERROR;
                    result.error = Some("[STEP1] failed the verification of pk2".to_string());
                }
            }
        } else if serializable.sign1.is_some()
            && serializable.sign2.is_some()
            && serializable.nonce.is_some()
            && serializable.nonce.as_ref().unwrap().len() == 32
            && serializable.pk1.is_some()
            && serializable.pk2.is_some()
        {
            // COMPLETE state - verify both signatures
            result.state = COMPLETE;

            let unsigned_challenge = Self::serialize_unsigned(&result)?;

            // Verify sign2 from pk2
            if let (Some(pk2), Some(sign2)) = (&serializable.pk2, &serializable.sign2) {
                let id2 = VaultysId::from_id(pk2, None, None)?;
                let verified = id2
                    .verify_challenge(&unsigned_challenge, sign2)
                    .unwrap_or(false)
                    || id2
                        .verify_challenge_v0(&unsigned_challenge, sign2, pk2)
                        .unwrap_or(false);

                if !verified {
                    result.state = ERROR;
                    result.error = Some("[COMPLETE] failed the verification of pk2".to_string());
                }
            }

            // Verify sign1 from pk1
            if result.state != ERROR {
                if let (Some(pk1), Some(sign1)) = (&serializable.pk1, &serializable.sign1) {
                    let id1 = VaultysId::from_id(pk1, None, None)?;
                    let verified = id1
                        .verify_challenge(&unsigned_challenge, sign1)
                        .unwrap_or(false)
                        || id1
                            .verify_challenge_v0(&unsigned_challenge, sign1, pk1)
                            .unwrap_or(false);

                    if !verified {
                        result.state = ERROR;
                        result.error =
                            Some("[COMPLETE] failed the verification of pk1".to_string());
                    }
                }
            }
        } else if serializable.pk1.is_some()
            && serializable.sign1.is_none()
            && serializable.sign2.is_none()
        {
            result.state = INIT;
        } else {
            result.state = UNINITIALISED;
        }

        Ok(result)
    }

    /// Serialize a certificate
    pub fn serialize_certificate(challenge: &ChallengeType) -> Result<Vec<u8>> {
        // Only serialize fields based on state, similar to TypeScript
        let to_serialize = match challenge.state {
            INIT => SerializableChallenge {
                version: challenge.version,
                protocol: challenge.protocol.clone(),
                service: challenge.service.clone(),
                timestamp: challenge.timestamp,
                pk1: challenge.pk1.clone(),
                pk2: None,
                nonce: challenge.nonce.clone(),
                sign1: None,
                sign2: None,
                metadata: challenge.metadata.clone(),
            },
            STEP1 => SerializableChallenge {
                version: challenge.version,
                protocol: challenge.protocol.clone(),
                service: challenge.service.clone(),
                timestamp: challenge.timestamp,
                pk1: challenge.pk1.clone(),
                pk2: challenge.pk2.clone(),
                nonce: challenge.nonce.clone(),
                sign1: None,
                sign2: challenge.sign2.clone(),
                metadata: challenge.metadata.clone(),
            },
            COMPLETE => SerializableChallenge {
                version: challenge.version,
                protocol: challenge.protocol.clone(),
                service: challenge.service.clone(),
                timestamp: challenge.timestamp,
                pk1: challenge.pk1.clone(),
                pk2: challenge.pk2.clone(),
                nonce: challenge.nonce.clone(),
                sign1: challenge.sign1.clone(),
                sign2: challenge.sign2.clone(),
                metadata: challenge.metadata.clone(),
            },
            _ => return Ok(Vec::new()),
        };

        // Use rmp_serde::to_vec_named to ensure map format (not array format)
        rmp_serde::to_vec_named(&to_serialize)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize: {}", e)))
    }

    /// Serialize an unsigned challenge
    pub fn serialize_unsigned(challenge: &ChallengeType) -> Result<Vec<u8>> {
        if challenge.version == 0 {
            // Version 0 uses custom encoding without version field (matching TypeScript's encode_v0)
            let mut buffer = Vec::new();

            // Start with fixmap of 7 elements
            buffer.push(0x87);

            // Helper to write string
            let write_string = |buf: &mut Vec<u8>, key: &str, value: &str| {
                // Write key
                buf.push(0xa0 + key.len() as u8);
                buf.extend_from_slice(key.as_bytes());
                // Write value
                buf.push(0xa0 + value.len() as u8);
                buf.extend_from_slice(value.as_bytes());
            };

            // Helper to write buffer/bytes
            let write_buffer = |buf: &mut Vec<u8>, key: &str, value: &Option<Vec<u8>>| {
                // Write key
                buf.push(0xa0 + key.len() as u8);
                buf.extend_from_slice(key.as_bytes());
                // Write value
                if let Some(bytes) = value {
                    if bytes.len() <= 255 {
                        buf.push(0xc4);
                        buf.push(bytes.len() as u8);
                        buf.extend_from_slice(bytes);
                    } else {
                        buf.push(0xc5);
                        buf.push((bytes.len() >> 8) as u8);
                        buf.push((bytes.len() & 0xff) as u8);
                        buf.extend_from_slice(bytes);
                    }
                } else {
                    buf.push(0xc0); // nil
                }
            };

            // Helper to write int (timestamp)
            let write_int = |buf: &mut Vec<u8>, key: &str, value: u64| {
                // Write key
                buf.push(0xa0 + key.len() as u8);
                buf.extend_from_slice(key.as_bytes());
                // Write value as uint64
                buf.push(0xcf);
                buf.extend_from_slice(&value.to_be_bytes());
            };

            // Write fields in order matching TypeScript's encode_v0
            write_string(&mut buffer, "protocol", &challenge.protocol);
            write_string(&mut buffer, "service", &challenge.service);
            write_int(&mut buffer, "timestamp", challenge.timestamp);
            write_buffer(&mut buffer, "pk1", &challenge.pk1);
            write_buffer(&mut buffer, "pk2", &challenge.pk2);
            write_buffer(&mut buffer, "nonce", &challenge.nonce);

            // Write metadata (always empty for v0)
            buffer.push(0xa0 + "metadata".len() as u8);
            buffer.extend_from_slice(b"metadata");
            buffer.push(0x80); // empty map

            Ok(buffer)
        } else {
            // Version 1+ uses standard MessagePack encoding
            let unsigned = SerializableChallenge {
                version: challenge.version,
                protocol: challenge.protocol.clone(),
                service: challenge.service.clone(),
                timestamp: challenge.timestamp,
                pk1: challenge.pk1.clone(),
                pk2: challenge.pk2.clone(),
                nonce: challenge.nonce.clone(),
                sign1: None,
                sign2: None,
                metadata: challenge.metadata.clone(),
            };
            rmp_serde::to_vec_named(&unsigned).map_err(|e| {
                Error::SerializationError(format!("Failed to serialize unsigned: {}", e))
            })
        }
    }

    /// Set a challenge from a serialized string
    pub async fn set_challenge(&mut self, challenge_string: &[u8]) -> Result<()> {
        if self.state != UNINITIALISED {
            self.state = ERROR;
            return Err(Error::InvalidState(
                "Challenger already initialised, can't reset the state".into(),
            ));
        }

        let mut challenge = Self::deserialize_certificate(challenge_string)?;
        self.version = challenge.version;

        if !Self::is_live(&challenge, self.liveliness) {
            self.state = ERROR;
            challenge.error =
                Some("challenge timestamp failed the liveliness at first signature".into());
            return Err(Error::ValidationError(challenge.error.unwrap()));
        }

        if challenge.state == ERROR {
            self.state = ERROR;
            return Err(Error::ValidationError(challenge.error.unwrap_or_default()));
        } else if challenge.state == INIT {
            self.my_key = Some(self.vaultys_id.id());
            challenge.pk2 = self.my_key.clone();
            self.his_key = challenge.pk1.clone();

            // Extend nonce with random bytes
            let mut nonce = challenge.nonce.unwrap_or_default();
            nonce.extend_from_slice(&random_bytes(16));
            challenge.nonce = Some(nonce);

            let serialized = Self::serialize_unsigned(&challenge)?;

            // For version 0, we need to handle the old format with ID prefix
            let signed = if self.version == 0 {
                // Version 0 signs SHA256(oldId || challenge)
                let mut message = Vec::new();
                message.extend_from_slice(self.my_key.as_ref().unwrap());
                message.extend_from_slice(&serialized);
                let result = hash("sha256", &message);
                self.vaultys_id
                    .sign(&result)
                    .ok_or(Error::SigningError("Could not sign challenge".into()))?
            } else {
                // Current version uses sign_challenge which adds VAULTYS_SIGN prefix
                self.vaultys_id.sign_challenge(&serialized).await?.signature
            };
            challenge.sign2 = Some(signed);

            challenge.state = STEP1;
            self.state = STEP1;
            self.challenge = Some(challenge);
        } else if challenge.state == COMPLETE {
            self.my_key = Some(self.vaultys_id.id());
            let my_key = self.my_key.as_ref().unwrap();

            if challenge.pk1.as_ref() != Some(my_key) && challenge.pk2.as_ref() != Some(my_key) {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    "Can't link the vaultys id to this challenge".into(),
                ));
            } else {
                self.state = COMPLETE;
                self.challenge = Some(challenge);
            }
        } else {
            return Err(Error::InvalidState(
                "Challenge is from a protocol already launched, this is completely unsafe".into(),
            ));
        }

        Ok(())
    }

    /// Get the context of the current challenge
    pub fn get_context(&self) -> Option<ChallengeContext> {
        self.challenge.as_ref().map(|c| ChallengeContext {
            protocol: c.protocol.clone(),
            service: c.service.clone(),
            metadata: c.metadata.clone(),
        })
    }

    /// Create a new challenge
    pub fn create_challenge(
        &mut self,
        protocol: String,
        service: String,
        version: Option<u8>,
        metadata: Option<BTreeMap<String, String>>,
    ) -> Result<()> {
        self.version = version.unwrap_or(0);

        if self.state == UNINITIALISED {
            self.my_key = Some(self.vaultys_id.to_version(self.version)?.id());

            let challenge = ChallengeType {
                version: self.version,
                protocol,
                service,
                metadata: ChallengeMetadata {
                    pk1: metadata,
                    pk2: None,
                },
                timestamp: Self::current_timestamp(),
                pk1: self.my_key.clone(),
                pk2: None,
                nonce: Some(random_bytes(16)),
                sign1: None,
                sign2: None,
                state: INIT,
                error: None,
            };

            self.challenge = Some(challenge);
            self.state = INIT;
            Ok(())
        } else {
            self.state = ERROR;
            Err(Error::InvalidState(
                "Challenger already initialised, can't reset the state".into(),
            ))
        }
    }

    /// Get the certificate
    pub fn get_certificate(&self) -> Result<Vec<u8>> {
        match &self.challenge {
            Some(challenge) => Self::serialize_certificate(challenge),
            None => Ok(Vec::new()),
        }
    }

    /// Get the unsigned challenge
    pub fn get_unsigned_challenge(&self) -> Result<Vec<u8>> {
        match &self.challenge {
            Some(challenge) => Self::serialize_unsigned(challenge),
            None => Err(Error::InvalidState("No challenge present".into())),
        }
    }

    /// Get contact DID
    pub fn get_contact_did(&self) -> Option<String> {
        self.his_key.as_ref().map(|key| {
            VaultysId::from_id(key, None, None)
                .map(|id| id.did())
                .unwrap_or_default()
        })
    }

    /// Get contact ID (only when complete)
    pub fn get_contact_id(&self) -> Result<VaultysId> {
        if self.is_complete() {
            let his_key = self
                .his_key
                .as_ref()
                .ok_or(Error::InvalidState("No contact key available".into()))?;
            let certificate = self.get_certificate().ok();
            VaultysId::from_id(his_key, certificate, None)
        } else {
            Err(Error::InvalidState(
                "The challenge is not COMPLETE, it is unsafe to get the Contact ID before".into(),
            ))
        }
    }

    /// Create from a challenge string
    pub async fn from_string(vaultys_id: VaultysId, challenge_string: &[u8]) -> Result<Self> {
        let mut challenger = Self::new(vaultys_id, None);
        challenger.set_challenge(challenge_string).await?;
        Ok(challenger)
    }

    /// Check if the challenge has failed
    pub fn has_failed(&self) -> bool {
        self.state == ERROR
    }

    /// Check if the challenge is complete
    pub fn is_complete(&self) -> bool {
        self.state == COMPLETE
    }

    /// Initialize with a challenge
    pub async fn init(&mut self, challenge: &[u8]) -> Result<()> {
        if self.state != UNINITIALISED {
            return Err(Error::InvalidState(
                "Can't init INITIALISED challenge".into(),
            ));
        }

        let mut temp_challenge = Self::deserialize_certificate(challenge)?;
        self.version = if temp_challenge.version > 0 { 1 } else { 0 };
        temp_challenge.version = self.version;
        self.vaultys_id = self.vaultys_id.to_version(self.version)?;

        let my_id = self.vaultys_id.id();

        if temp_challenge.state == INIT {
            if temp_challenge.pk2.as_ref() != Some(&my_id) {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    "challenge is not corresponding to the right id".into(),
                ));
            }
            self.challenge = Some(temp_challenge.clone());
            self.version = temp_challenge.version;
            self.my_key = Some(my_id);
            self.his_key = temp_challenge.pk1.clone();
            self.state = INIT;
            Ok(())
        } else if temp_challenge.state == STEP1 {
            if temp_challenge.pk2.as_ref() != Some(&my_id) {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    "challenge is not corresponding to the right id".into(),
                ));
            }
            self.challenge = Some(temp_challenge.clone());
            self.version = temp_challenge.version;
            self.my_key = temp_challenge.pk2.clone();
            self.his_key = temp_challenge.pk1.clone();
            self.state = STEP1;
            Ok(())
        } else {
            Err(Error::InvalidState(
                "Invalid challenge state for init".into(),
            ))
        }
    }

    /// Update the challenge with a new state
    pub async fn update(
        &mut self,
        challenge: &[u8],
        metadata: Option<BTreeMap<String, String>>,
    ) -> Result<()> {
        if self.state == ERROR {
            return Err(Error::InvalidState(
                "Can't update errorneous challenge".into(),
            ));
        } else if self.state == COMPLETE {
            return Err(Error::InvalidState(
                "Can't update COMPLETE challenge".into(),
            ));
        }

        let mut temp_challenge = Self::deserialize_certificate(challenge)?;

        if temp_challenge.state == ERROR {
            self.state = ERROR;
            return Err(Error::ValidationError(
                temp_challenge.error.unwrap_or_default(),
            ));
        }

        if !Self::is_live(&temp_challenge, self.liveliness) {
            self.state = ERROR;
            return Err(Error::ValidationError(
                "challenge timestamp failed the liveliness".into(),
            ));
        }

        self.version = temp_challenge.version;
        self.vaultys_id = self.vaultys_id.to_version(self.version)?;

        if self.state == UNINITIALISED && temp_challenge.state == INIT {
            if temp_challenge.metadata.pk2.is_some() {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    "Metadata is malformed: pk2 is already set".into(),
                ));
            }

            self.my_key = Some(self.vaultys_id.id());
            temp_challenge.pk2 = self.my_key.clone();
            self.his_key = temp_challenge.pk1.clone();

            if let Some(meta) = metadata {
                temp_challenge.metadata.pk2 = Some(meta);
            }

            // Extend nonce
            let mut nonce = temp_challenge.nonce.unwrap_or_default();
            nonce.extend_from_slice(&random_bytes(16));
            temp_challenge.nonce = Some(nonce);

            let serialized = Self::serialize_unsigned(&temp_challenge)?;
            temp_challenge.sign2 = if self.version == 0 {
                // Use v0 signing method for version 0 - use pk2 (without type byte)
                let pk2 = temp_challenge.pk2.as_ref().unwrap();
                Some(
                    self.vaultys_id
                        .sign_challenge_v0(&serialized, pk2)
                        .await?
                        .signature,
                )
            } else {
                Some(self.vaultys_id.sign_challenge(&serialized).await?.signature)
            };
            temp_challenge.state = STEP1;
            self.state = STEP1;
            self.challenge = Some(temp_challenge);

            Ok(())
        } else if self.state == UNINITIALISED && temp_challenge.state == STEP1 {
            let my_id = self.vaultys_id.id();
            if temp_challenge.pk1.as_ref() != Some(&my_id) {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    "challenge is not corresponding to the right id".into(),
                ));
            }

            let serialized = Self::serialize_unsigned(&temp_challenge)?;
            temp_challenge.sign1 = if self.version == 0 {
                // Use v0 signing method for version 0 - use pk1 (without type byte)
                let pk1 = temp_challenge.pk1.as_ref().unwrap();
                Some(
                    self.vaultys_id
                        .sign_challenge_v0(&serialized, pk1)
                        .await?
                        .signature,
                )
            } else {
                Some(self.vaultys_id.sign_challenge(&serialized).await?.signature)
            };
            self.my_key = temp_challenge.pk1.clone();
            self.his_key = temp_challenge.pk2.clone();
            temp_challenge.state = COMPLETE;
            self.state = COMPLETE;
            self.challenge = Some(temp_challenge);

            Ok(())
        } else if self.state == INIT && temp_challenge.state == STEP1 {
            // Verify the challenge matches our current one
            if self.challenge.is_none() {
                self.state = ERROR;
                return Err(Error::InvalidState("No challenge present".into()));
            }

            let current = self.challenge.as_ref().unwrap();

            // Check protocol and service match
            if temp_challenge.protocol != current.protocol
                || temp_challenge.service != current.service
            {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    format!("The challenge was expecting protocol '{}' and service '{}', received '{}' and '{}'",
                        current.protocol, current.service, temp_challenge.protocol, temp_challenge.service)
                ));
            }

            // Verify nonce hasn't been tampered with (first 16 bytes should match)
            if let (Some(temp_nonce), Some(current_nonce)) = (&temp_challenge.nonce, &current.nonce)
            {
                if temp_nonce.len() >= 16 && current_nonce.len() >= 16 {
                    if temp_nonce[..16] != current_nonce[..16] {
                        self.state = ERROR;
                        return Err(Error::ValidationError(
                            "Nonce has been tampered with".into(),
                        ));
                    }
                }
            }

            // Verify timestamp hasn't changed
            if temp_challenge.timestamp != current.timestamp {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    "Timestamp has been tampered with".into(),
                ));
            }

            // Verify pk1 matches our key
            if temp_challenge.pk1.as_ref() != self.my_key.as_ref() {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    format!("The challenge has been tampered with. Received pk1 = '{:?}', expected pk1 = '{:?}'",
                        temp_challenge.pk1, self.my_key)
                ));
            }

            // Sign with our key
            let serialized = Self::serialize_unsigned(&temp_challenge)?;

            temp_challenge.sign1 = if self.version == 0 {
                // Use v0 signing method for version 0 - use pk1 (without type byte)
                let pk1 = temp_challenge.pk1.as_ref().unwrap();
                Some(
                    self.vaultys_id
                        .sign_challenge_v0(&serialized, pk1)
                        .await?
                        .signature,
                )
            } else {
                let signed = self.vaultys_id.sign_challenge(&serialized).await?;
                Some(signed.signature)
            };

            // Set his_key from pk2 when transitioning from INIT to COMPLETE
            self.his_key = temp_challenge.pk2.clone();

            temp_challenge.state = COMPLETE;
            self.state = COMPLETE;
            self.challenge = Some(temp_challenge);

            Ok(())
        } else if self.state == STEP1 && temp_challenge.state == COMPLETE {
            // Bob receiving Alice's final COMPLETE certificate
            // Verify it matches our challenge
            if self.challenge.is_none() {
                self.state = ERROR;
                return Err(Error::InvalidState("No challenge present".into()));
            }

            let current = self.challenge.as_ref().unwrap();

            // Verify all the fields match
            if temp_challenge.protocol != current.protocol
                || temp_challenge.service != current.service
                || temp_challenge.timestamp != current.timestamp
                || temp_challenge.pk1 != current.pk1
                || temp_challenge.pk2 != current.pk2
                || temp_challenge.nonce != current.nonce
            {
                self.state = ERROR;
                return Err(Error::ValidationError(
                    "Challenge fields don't match".into(),
                ));
            }

            // Update our challenge with the sign1
            self.challenge = Some(temp_challenge);
            self.state = COMPLETE;

            Ok(())
        } else {
            Err(Error::InvalidState(format!(
                "Invalid state transition: {} -> {}",
                self.state, temp_challenge.state
            )))
        }
    }

    // Helper functions

    /// Check if a challenge is within the liveliness window
    fn is_live(challenge: &ChallengeType, liveliness_ms: u64) -> bool {
        let now = Self::current_timestamp();
        let timestamp = challenge.timestamp;

        timestamp > now.saturating_sub(liveliness_ms)
            && timestamp < now.saturating_add(liveliness_ms)
    }

    /// Get current timestamp in milliseconds
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

/// Context information for a challenge
#[derive(Debug, Clone)]
pub struct ChallengeContext {
    pub protocol: String,
    pub service: String,
    pub metadata: ChallengeMetadata,
}

// The VaultysId already has sign_challenge and verify_challenge methods
// We just need the to_version method here
impl VaultysId {
    /// Convert to a specific version
    pub fn to_version(&self, _version: u8) -> Result<VaultysId> {
        // For now, we just return a clone as version handling might be more complex
        // This would need to be implemented based on your specific version requirements
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenger_creation() {
        let vaultys_id = VaultysId::generate(None).await.unwrap();
        let challenger = Challenger::new(vaultys_id, None);
        assert!(!challenger.is_complete());
        assert!(!challenger.has_failed());
    }

    #[tokio::test]
    async fn test_create_challenge() {
        let vaultys_id = VaultysId::generate(None).await.unwrap();
        let mut challenger = Challenger::new(vaultys_id, None);

        challenger
            .create_challenge(
                "test_protocol".to_string(),
                "test_service".to_string(),
                Some(0),
                None,
            )
            .unwrap();

        let cert = challenger.get_certificate().unwrap();
        assert!(!cert.is_empty());
    }

    #[test]
    fn test_serialization_round_trip() {
        // Test INIT state
        let init_challenge = ChallengeType {
            version: 0,
            protocol: "test".to_string(),
            service: "test".to_string(),
            timestamp: 1234567890,
            pk1: Some(vec![1, 2, 3]),
            pk2: None,
            nonce: Some(vec![4, 5, 6]),
            sign1: None,
            sign2: None,
            metadata: ChallengeMetadata::default(),
            state: INIT,
            error: None,
        };

        let serialized = Challenger::serialize_certificate(&init_challenge).unwrap();
        let deserialized = Challenger::deserialize_certificate_unchecked(&serialized).unwrap();
        assert_eq!(
            deserialized.state, INIT,
            "INIT state should round-trip correctly"
        );
        assert!(
            deserialized.sign1.is_none(),
            "sign1 should be None after INIT round-trip"
        );
        assert!(
            deserialized.sign2.is_none(),
            "sign2 should be None after INIT round-trip"
        );

        // Test STEP1 state - only sign2 should be present
        let step1_challenge = ChallengeType {
            version: 0,
            protocol: "test".to_string(),
            service: "test".to_string(),
            timestamp: 1234567890,
            pk1: Some(vec![1, 2, 3]),
            pk2: Some(vec![7, 8, 9]),
            nonce: Some(vec![4, 5, 6]),
            sign1: None,                   // sign1 should be None in STEP1
            sign2: Some(vec![10, 11, 12]), // only sign2 is present
            metadata: ChallengeMetadata::default(),
            state: STEP1,
            error: None,
        };

        let serialized = Challenger::serialize_certificate(&step1_challenge).unwrap();
        let deserialized = Challenger::deserialize_certificate_unchecked(&serialized).unwrap();
        assert_eq!(
            deserialized.state, step1_challenge.state,
            "STEP1 state should round-trip correctly"
        );
        assert!(
            deserialized.sign1.is_none(),
            "sign1 should be None after STEP1 round-trip"
        );
        assert!(
            deserialized.sign2.is_some(),
            "sign2 should be present after STEP1 round-trip"
        );

        // Test COMPLETE state
        let complete_challenge = ChallengeType {
            version: 0,
            protocol: "test".to_string(),
            service: "test".to_string(),
            timestamp: 1234567890,
            pk1: Some(vec![1, 2, 3]),
            pk2: Some(vec![7, 8, 9]),
            nonce: Some(vec![4, 5, 6]),
            sign1: Some(vec![13, 14, 15]), // Both signatures present
            sign2: Some(vec![10, 11, 12]),
            metadata: ChallengeMetadata::default(),
            state: COMPLETE,
            error: None,
        };

        let serialized = Challenger::serialize_certificate(&complete_challenge).unwrap();
        let deserialized = Challenger::deserialize_certificate_unchecked(&serialized).unwrap();
        assert_eq!(
            deserialized.state, COMPLETE,
            "COMPLETE state should round-trip correctly"
        );
        assert!(
            deserialized.sign1.is_some(),
            "sign1 should be present after COMPLETE round-trip"
        );
        assert!(
            deserialized.sign2.is_some(),
            "sign2 should be present after COMPLETE round-trip"
        );
    }

    #[tokio::test]
    async fn test_challenge_protocol() {
        // Alice creates a challenge
        let alice_id = VaultysId::generate(None).await.unwrap();
        let mut alice = Challenger::new(alice_id, None);

        alice
            .create_challenge(
                "handshake".to_string(),
                "messaging".to_string(),
                Some(0),
                None,
            )
            .unwrap();

        let alice_cert = alice.get_certificate().unwrap();

        // Bob responds to the challenge
        let bob_id = VaultysId::generate(None).await.unwrap();
        let mut bob = Challenger::new(bob_id, None);

        bob.update(&alice_cert, None).await.unwrap();
        assert_eq!(bob.state, STEP1);
        let bob_cert = bob.get_certificate().unwrap();

        // Alice completes the challenge
        alice.update(&bob_cert, None).await.unwrap();
        assert_eq!(alice.state, COMPLETE);

        assert!(alice.is_complete());
        assert!(!bob.is_complete());

        // Bob completes the challenge
        let alice_final_cert = alice.get_certificate().unwrap();
        bob.update(&alice_final_cert, None).await.unwrap();
        assert_eq!(bob.state, COMPLETE);

        // Both should be complete now
        assert!(alice.is_complete());
        assert!(bob.is_complete());
        assert!(!alice.has_failed());
        assert!(!bob.has_failed());
    }
}
