pub mod abstract_key_manager;
pub mod cypher_manager;
pub mod deprecated_key_manager;
pub mod ed25519_manager;

pub use abstract_key_manager::{AbstractKeyManager, KeyManager, KeyPair};
pub use cypher_manager::{CypherManager, CypherOperations, DHIES};
pub use deprecated_key_manager::DeprecatedKeyManager;
pub use ed25519_manager::Ed25519Manager;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Represents a cryptographic key pair
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeyPairImpl {
    pub public_key: Vec<u8>,
    #[zeroize(skip)]
    pub secret_key: Option<Vec<u8>>,
}

impl KeyPair for KeyPairImpl {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn secret_key(&self) -> Option<&[u8]> {
        self.secret_key.as_deref()
    }

    fn has_secret_key(&self) -> bool {
        self.secret_key.is_some()
    }
}

/// Historical Identity Swapping Certificate Protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HISCP {
    pub new_id: Vec<u8>,
    pub proof_key: Vec<u8>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

/// Data export format for serialization
#[derive(Debug, Serialize, Deserialize)]
pub struct DataExport {
    pub v: u8, // version
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none", default)]
    pub p: Option<Vec<u8>>, // proof (optional, for deprecated format)
    #[serde(with = "serde_bytes")]
    pub x: Vec<u8>, // signing key (public or secret)
    #[serde(with = "serde_bytes")]
    pub e: Vec<u8>, // encryption key (public or secret)
}

/// Key manager capability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Private,
    Public,
}

impl Capability {
    pub fn is_private(&self) -> bool {
        matches!(self, Capability::Private)
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Capability::Public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability() {
        let private_cap = Capability::Private;
        let public_cap = Capability::Public;

        assert!(private_cap.is_private());
        assert!(!private_cap.is_public());
        assert!(public_cap.is_public());
        assert!(!public_cap.is_private());
    }

    #[test]
    fn test_key_pair() {
        let keypair = KeyPairImpl {
            public_key: vec![1, 2, 3, 4],
            secret_key: Some(vec![5, 6, 7, 8]),
        };

        assert_eq!(keypair.public_key(), &[1, 2, 3, 4]);
        assert_eq!(keypair.secret_key(), Some(&[5, 6, 7, 8][..]));
        assert!(keypair.has_secret_key());
    }
}
