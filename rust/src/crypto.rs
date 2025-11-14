use hmac::{Hmac, Mac};
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha224, Sha256, Sha512};
use zeroize::Zeroize;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha224,
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    pub fn from_str(s: &str) -> Self {
        let clean = s.replace('-', "").to_lowercase();
        match clean.as_str() {
            "sha224" => HashAlgorithm::Sha224,
            "sha512" => HashAlgorithm::Sha512,
            _ => HashAlgorithm::Sha256,
        }
    }
}

pub trait Hash {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
}

impl Hash for HashAlgorithm {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha224 => {
                let mut hasher = Sha224::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        }
    }
}

/// Hash data using the specified algorithm
pub fn hash(alg: &str, data: &[u8]) -> Vec<u8> {
    let algorithm = HashAlgorithm::from_str(alg);
    algorithm.hash(data)
}

/// HMAC using the specified algorithm
pub fn hmac(alg: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let algorithm = HashAlgorithm::from_str(alg);

    match algorithm {
        HashAlgorithm::Sha256 => {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac =
                HmacSha256::new_from_slice(key).map_err(|e| Error::CryptoError(e.to_string()))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HashAlgorithm::Sha512 => {
            type HmacSha512 = Hmac<Sha512>;
            let mut mac =
                HmacSha512::new_from_slice(key).map_err(|e| Error::CryptoError(e.to_string()))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HashAlgorithm::Sha224 => {
            type HmacSha224 = Hmac<Sha224>;
            let mut mac =
                HmacSha224::new_from_slice(key).map_err(|e| Error::CryptoError(e.to_string()))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Generate random bytes
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Securely erase sensitive data from memory
pub fn secure_erase<T: Zeroize>(data: &mut T) {
    data.zeroize();
}

/// Convert bytes to base64
pub fn to_base64(data: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(data)
}

/// Convert bytes to hex
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Convert bytes to UTF-8 string
pub fn to_utf8(data: &[u8]) -> Result<String> {
    String::from_utf8(data.to_vec())
        .map_err(|e| Error::Other(format!("UTF-8 conversion failed: {}", e)))
}

/// Convert base64 string to bytes
pub fn from_base64(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Error::Other(format!("Base64 decode failed: {}", e)))
}

/// Convert hex string to bytes
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|e| Error::Other(format!("Hex decode failed: {}", e)))
}

/// Convert UTF-8 string to bytes
pub fn from_utf8(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

/// Constant-time comparison of two byte slices
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        result |= byte_a ^ byte_b;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"hello world";
        let hash_sha256 = hash("sha256", data);
        assert_eq!(hash_sha256.len(), 32);

        let hash_sha512 = hash("sha512", data);
        assert_eq!(hash_sha512.len(), 64);
    }

    #[test]
    fn test_hmac() {
        let key = b"secret key";
        let data = b"message";
        let mac = hmac("sha256", key, data).unwrap();
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32);
        let bytes2 = random_bytes(32);
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_base64_conversion() {
        let data = b"hello world";
        let encoded = to_base64(data);
        let decoded = from_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_conversion() {
        let data = b"hello world";
        let encoded = to_hex(data);
        let decoded = from_hex(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"equal";
        let b = b"equal";
        let c = b"different";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
    }
}
