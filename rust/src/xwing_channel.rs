//! X-Wing secure channel (`rfc/SECURE-CHANNEL.md` §3): ephemeral X-Wing key
//! exchange, one key per direction, XChaCha20-Poly1305 records with strict
//! sequence numbers. Byte-compatible with the TypeScript reference
//! (`typescript/src/xwingChannel.ts`), checked against its vectors in
//! `tests/xwing_channel_vectors.rs`.
//!
//! The bound handshake of §4 is not provided in Rust yet: the Rust challenger does
//! not implement the 4.0 handshake (`VAULTYS_HANDSHAKE_V1`).

use crate::error::{Error, Result};
use crate::memory_channel::Channel;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use kem::{Decapsulate, Decapsulator, KeyExport};
use sha2::{Digest, Sha256};
use x_wing::{DecapsulationKey, EncapsulationKey};
use zeroize::Zeroize;

pub const CHANNEL_LABEL: &str = "vaultysid/xwing-channel/v1";
pub const CHANNEL_LABEL_I2R: &str = "vaultysid/xwing-channel/v1/i2r";
pub const CHANNEL_LABEL_R2I: &str = "vaultysid/xwing-channel/v1/r2i";
pub const BINDING_LABEL: &str = "vaultysid/xwing-binding/v1";

pub const PUBLIC_KEY_LENGTH: usize = 1216;
pub const SEED_LENGTH: usize = 32;
pub const CIPHERTEXT_LENGTH: usize = 1120;
pub const ENCAPSULATION_RANDOMNESS_LENGTH: usize = 64;
const HEADER: [u8; 2] = [0x01, 0x01];
const SEQ_LENGTH: usize = 8;
const TAG_LENGTH: usize = 16;
pub const M1_LENGTH: usize = 2 + PUBLIC_KEY_LENGTH;
pub const M2_LENGTH: usize = 2 + CIPHERTEXT_LENGTH;
pub const RECORD_OVERHEAD: usize = 2 + SEQ_LENGTH + TAG_LENGTH;
const MAX_SEQ: u64 = (1 << 53) - 1;

fn err(code: &str) -> Error {
    Error::Other(format!("xwing channel: {code}"))
}

fn lp(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    out
}

/// X-Wing key pair of a 32-byte seed: (public key, secret key = seed). Refuses a zero seed.
pub fn key_pair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| err("INVALID_KEY"))?;
    if seed.iter().all(|&b| b == 0) {
        return Err(err("INVALID_KEY"));
    }
    let dk = DecapsulationKey::from(seed);
    Ok((dk.encapsulation_key().to_bytes().to_vec(), seed))
}

/// Encapsulation with explicit 64-byte randomness: (ciphertext, shared secret).
pub fn encapsulate_with(public_key: &[u8], randomness: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if public_key.len() != PUBLIC_KEY_LENGTH {
        return Err(err("INVALID_KEY"));
    }
    let randomness: [u8; 64] = randomness.try_into().map_err(|_| err("INVALID_ARGUMENT"))?;
    let ek = EncapsulationKey::try_from(public_key).map_err(|_| err("INVALID_KEY"))?;
    let (ct, ss) = ek.encapsulate_deterministic(&randomness.into());
    let ss: [u8; 32] = ss.into();
    if ss.iter().all(|&b| b == 0) {
        return Err(err("INVALID_KEY"));
    }
    Ok((ct.to_vec(), ss))
}

/// Decapsulation (implicit rejection: a tampered ML-KEM ciphertext gives another secret).
pub fn decapsulate(cipher_text: &[u8], secret_key: &[u8]) -> Result<[u8; 32]> {
    let sk: [u8; 32] = secret_key.try_into().map_err(|_| err("INVALID_KEY"))?;
    if cipher_text.len() != CIPHERTEXT_LENGTH {
        return Err(err("INVALID_FORMAT"));
    }
    let ct = x_wing::Ciphertext::try_from(cipher_text).map_err(|_| err("INVALID_FORMAT"))?;
    let ss: [u8; 32] = DecapsulationKey::from(sk).decapsulate(&ct).into();
    if ss.iter().all(|&b| b == 0) {
        return Err(err("INVALID_FORMAT"));
    }
    Ok(ss)
}

/// Session keys of a channel.
pub struct ChannelKeys {
    pub transcript_hash: [u8; 32],
    pub i2r: [u8; 32],
    pub r2i: [u8; 32],
    pub binding: [u8; 32],
}

impl Drop for ChannelKeys {
    fn drop(&mut self) {
        self.i2r.zeroize();
        self.r2i.zeroize();
    }
}

/// Directional keys and binding value of a session.
pub fn derive_channel_keys(shared_secret: &[u8], m1: &[u8], m2: &[u8]) -> ChannelKeys {
    let mut h = Sha256::new();
    h.update(lp(CHANNEL_LABEL.as_bytes()));
    h.update(lp(m1));
    h.update(lp(m2));
    let th: [u8; 32] = h.finalize().into();
    let hk = Hkdf::<Sha256>::new(Some(&th), shared_secret);
    let mut i2r = [0u8; 32];
    let mut r2i = [0u8; 32];
    hk.expand(CHANNEL_LABEL_I2R.as_bytes(), &mut i2r)
        .expect("32 bytes");
    hk.expand(CHANNEL_LABEL_R2I.as_bytes(), &mut r2i)
        .expect("32 bytes");
    let mut b = Sha256::new();
    b.update(lp(BINDING_LABEL.as_bytes()));
    b.update(th);
    ChannelKeys {
        transcript_hash: th,
        i2r,
        r2i,
        binding: b.finalize().into(),
    }
}

fn nonce(seq: &[u8]) -> XNonce {
    let mut n = [0u8; 24];
    n[16..].copy_from_slice(seq);
    n.into()
}

/// Encrypts one record.
pub fn encrypt_record(key: &[u8; 32], seq: u64, message: &[u8]) -> Result<Vec<u8>> {
    let mut aad = HEADER.to_vec();
    aad.extend_from_slice(&seq.to_be_bytes());
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            &nonce(&aad[2..]),
            Payload {
                msg: message,
                aad: &aad,
            },
        )
        .map_err(|_| err("AUTH_FAILED"))?;
    aad.extend(ct);
    Ok(aad)
}

/// Decrypts one record expected at `seq`.
pub fn decrypt_record(key: &[u8; 32], expected_seq: u64, record: &[u8]) -> Result<Vec<u8>> {
    if record.len() < RECORD_OVERHEAD || record[..2] != HEADER {
        return Err(err("INVALID_FORMAT"));
    }
    let seq = u64::from_be_bytes(record[2..10].try_into().unwrap());
    if seq > MAX_SEQ || seq != expected_seq {
        return Err(err("INVALID_SEQUENCE"));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &nonce(&record[2..10]),
            Payload {
                msg: &record[10..],
                aad: &record[..10],
            },
        )
        .map_err(|_| err("AUTH_FAILED"))
}

/// An established X-Wing channel over a VaultysID `Channel`. Not authenticated by itself.
pub struct XWingSession<C: Channel> {
    channel: C,
    pub initiator: bool,
    pub binding: [u8; 32],
    pub transcript_hash: [u8; 32],
    send_key: [u8; 32],
    receive_key: [u8; 32],
    send_seq: u64,
    receive_seq: u64,
    closed: bool,
}

impl<C: Channel> XWingSession<C> {
    fn new(channel: C, initiator: bool, keys: ChannelKeys) -> Self {
        let (send_key, receive_key) = if initiator {
            (keys.i2r, keys.r2i)
        } else {
            (keys.r2i, keys.i2r)
        };
        Self {
            channel,
            initiator,
            binding: keys.binding,
            transcript_hash: keys.transcript_hash,
            send_key,
            receive_key,
            send_seq: 0,
            receive_seq: 0,
            closed: false,
        }
    }

    /// Establishes a channel as initiator with an explicit seed (test vectors only).
    pub async fn initiate_with(mut channel: C, seed: &[u8]) -> Result<Self> {
        let (pk, mut sk) = key_pair_from_seed(seed)?;
        let mut m1 = HEADER.to_vec();
        m1.extend(pk);
        channel.send(m1.clone()).await?;
        let m2 = channel.receive().await?;
        if m2.len() != M2_LENGTH || m2[..2] != HEADER {
            channel.close().await.ok();
            sk.zeroize();
            return Err(err("INVALID_FORMAT"));
        }
        let ss = decapsulate(&m2[2..], &sk);
        sk.zeroize();
        let mut ss = match ss {
            Ok(ss) => ss,
            Err(e) => {
                channel.close().await.ok();
                return Err(e);
            }
        };
        let keys = derive_channel_keys(&ss, &m1, &m2);
        ss.zeroize();
        Ok(Self::new(channel, true, keys))
    }

    /// Establishes a channel as responder with explicit randomness (test vectors only).
    pub async fn accept_with(mut channel: C, randomness: &[u8]) -> Result<Self> {
        let m1 = channel.receive().await?;
        if m1.len() != M1_LENGTH || m1[..2] != HEADER {
            channel.close().await.ok();
            return Err(err("INVALID_FORMAT"));
        }
        let (ct, mut ss) = match encapsulate_with(&m1[2..], randomness) {
            Ok(r) => r,
            Err(e) => {
                channel.close().await.ok();
                return Err(e);
            }
        };
        let mut m2 = HEADER.to_vec();
        m2.extend(ct);
        channel.send(m2.clone()).await?;
        let keys = derive_channel_keys(&ss, &m1, &m2);
        ss.zeroize();
        Ok(Self::new(channel, false, keys))
    }

    /// Establishes a channel as initiator.
    pub async fn initiate(channel: C) -> Result<Self> {
        let mut seed = crate::crypto::random_bytes(SEED_LENGTH);
        let r = Self::initiate_with(channel, &seed).await;
        seed.zeroize();
        r
    }

    /// Establishes a channel as responder.
    pub async fn accept(channel: C) -> Result<Self> {
        let mut randomness = crate::crypto::random_bytes(ENCAPSULATION_RANDOMNESS_LENGTH);
        let r = Self::accept_with(channel, &randomness).await;
        randomness.zeroize();
        r
    }

    /// Encrypts and sends one message.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(err("CHANNEL_CLOSED"));
        }
        if self.send_seq > MAX_SEQ {
            return Err(err("INVALID_SEQUENCE"));
        }
        let record = encrypt_record(&self.send_key, self.send_seq, data)?;
        self.send_seq += 1;
        self.channel.send(record).await
    }

    /// Receives and decrypts one message. Any failure closes the session.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        if self.closed {
            return Err(err("CHANNEL_CLOSED"));
        }
        let record = match self.channel.receive().await {
            Ok(r) if !r.is_empty() => r,
            _ => {
                self.close().await.ok();
                return Err(err("CHANNEL_CLOSED"));
            }
        };
        match decrypt_record(&self.receive_key, self.receive_seq, &record) {
            Ok(plain) => {
                self.receive_seq += 1;
                Ok(plain)
            }
            Err(e) => {
                self.close().await.ok();
                Err(e)
            }
        }
    }

    /// Closes the session and erases its keys.
    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.send_key.zeroize();
        self.receive_key.zeroize();
        self.channel.close().await
    }
}
