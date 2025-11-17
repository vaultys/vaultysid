pub mod challenger;
pub mod crypto;
pub mod error;
pub mod file_storage;
pub mod id_manager;
pub mod key_manager;
pub mod memory_channel;
pub mod vaultys_id;

pub use challenger::{ChallengeType, Challenger};
pub use error::{Error, Result};
pub use key_manager::{
    AbstractKeyManager, CypherManager, DeprecatedKeyManager, DilithiumManager, Ed25519Manager,
    KeyManager, KeyPair,
};
pub use vaultys_id::VaultysId;

// Re-export IdManager and related types
pub use file_storage::MemoryStore;
pub use id_manager::{File, FileSignature, IdManager, StoredApp, StoredContact};

// Re-export commonly used types
pub use crypto::{hash, hmac, random_bytes, secure_erase, Hash, HashAlgorithm};
