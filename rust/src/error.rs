use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid capability: {0}")]
    InvalidCapability(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid buffer size: expected {expected}, got {actual}")]
    InvalidBufferSize { expected: usize, actual: usize },

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("Invalid message format")]
    InvalidMessageFormat,

    #[error("Key not available")]
    KeyNotAvailable,

    #[error("Invalid ID format")]
    InvalidIdFormat,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid type: {0}")]
    InvalidType(u8),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<rmp_serde::encode::Error> for Error {
    fn from(err: rmp_serde::encode::Error) -> Self {
        Error::SerializationError(err.to_string())
    }
}

impl From<rmp_serde::decode::Error> for Error {
    fn from(err: rmp_serde::decode::Error) -> Self {
        Error::DeserializationError(err.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Error::InvalidSignature
    }
}
