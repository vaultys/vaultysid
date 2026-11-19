//! Post-quantum identities and DHIES v3 (`rfc/PQ-ENCRYPTION.md`).
//!
//! A post-quantum identity (type `0x10 | role`) derives from its 64-byte key-manager
//! seed an ML-KEM-768 key pair, published in the id as field `k`, and a PRF key that
//! replaces the X25519 secret in HMAC and `getSecretHash`:
//!
//! ```text
//! dz       = SHA-512("VAULTYS_MLKEM768_KEYGEN" || seed)       ; ML-KEM KeyGen_internal(d, z)
//! prf_key  = SHA-512("VAULTYS_PRF_KEY" || seed)[0:32]
//! ```
//!
//! DHIES v3 (§5), confidential if either X25519 or ML-KEM-768 holds:
//!
//! ```text
//! es            = X25519(e_sk, R_pk)
//! ss            = X25519(S_sk, R_pk)                 ; all-zero outputs rejected
//! (kem_ct, kss) = ML-KEM-768.Encaps(R_ek)
//! info          = "VAULTYS_DHIES_V3" || e_pk || S_pk || R_pk || SHA-256(R_ek) || kem_ct
//! k             = SHA-512(es || ss || kss || info)[0:32]
//! out           = 0x03 || nonce(24) || e_pk || kem_ct || XSalsa20-Poly1305(k, nonce, m)
//! ```
//!
//! ML-KEM comes from the RustCrypto `ml-kem` crate, XSalsa20-Poly1305 from
//! `crypto_secretbox`, X25519 from `x25519-dalek`; no primitive is implemented here.
//! The encryption with explicit randomness used by the test vectors is private to the
//! crate and only compiled for tests.

use crate::crypto::{hash, hmac, random_bytes};
use crate::error::{Error, Result};
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;
use ml_kem::kem::Decapsulate;
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, B32};
use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Flag of the post-quantum identity types (§4.1).
pub const TYPE_PQ_FLAG: u8 = 0x10;
/// Post-quantum machine, person and organization.
pub const TYPE_PQ_MACHINE: u8 = 0x10;
pub const TYPE_PQ_PERSON: u8 = 0x11;
pub const TYPE_PQ_ORGANIZATION: u8 = 0x12;

/// ML-KEM-768 encapsulation key size (field `k`).
pub const MLKEM768_PUBLIC_KEY_LENGTH: usize = 1184;
/// ML-KEM-768 ciphertext size.
pub const MLKEM768_CIPHERTEXT_LENGTH: usize = 1088;
/// ML-DSA-87 public key size (Dilithium key manager).
pub const DILITHIUM_PUBLIC_KEY_LENGTH: usize = 2592;
/// Ed25519 || ML-DSA-87 public key size (Hybrid key manager).
pub const HYBRID_PUBLIC_KEY_LENGTH: usize = 32 + DILITHIUM_PUBLIC_KEY_LENGTH;
/// Key-manager seed size.
pub const SEED_LENGTH: usize = 64;

/// First byte of a DHIES v3 message.
pub const DHIES_V3_TAG: u8 = 0x03;
const DHIES_V3_INFO: &[u8] = b"VAULTYS_DHIES_V3";
const NONCE_LENGTH: usize = 24;
const KEY_LENGTH: usize = 32;
const MAC_LENGTH: usize = 16;
const HEADER_LENGTH: usize = 1 + NONCE_LENGTH + KEY_LENGTH + MLKEM768_CIPHERTEXT_LENGTH;
/// Length of a DHIES v3 message of an empty plaintext (1161 bytes): its overhead.
pub const DHIES_V3_MIN_LENGTH: usize = HEADER_LENGTH + MAC_LENGTH;

const MLKEM_KEYGEN_LABEL: &[u8] = b"VAULTYS_MLKEM768_KEYGEN";
const PRF_KEY_LABEL: &[u8] = b"VAULTYS_PRF_KEY";

/// True for the post-quantum types `0x10`-`0x12`; `0x13` and `0x14` are reserved.
pub fn is_post_quantum_type(id_type: u8) -> bool {
    matches!(
        id_type,
        TYPE_PQ_MACHINE | TYPE_PQ_PERSON | TYPE_PQ_ORGANIZATION
    )
}

/// Role of an identity type (`type & 0x0F`): role checks must ignore the PQ flag.
pub fn role_of(id_type: u8) -> u8 {
    id_type & 0x0f
}

fn check_seed(seed: &[u8]) -> Result<()> {
    if seed.len() != SEED_LENGTH {
        return Err(Error::InvalidKeyFormat(
            "post-quantum seed must be 64 bytes".into(),
        ));
    }
    Ok(())
}

fn decapsulation_key(seed: &[u8]) -> Result<DecapsulationKey<MlKem768>> {
    check_seed(seed)?;
    let mut material = Vec::with_capacity(MLKEM_KEYGEN_LABEL.len() + SEED_LENGTH);
    material.extend_from_slice(MLKEM_KEYGEN_LABEL);
    material.extend_from_slice(seed);
    let material = Zeroizing::new(material);
    let dz = Zeroizing::new(hash("sha512", &material));
    let dz: ml_kem::Seed = ml_kem::array::Array::try_from(&dz[..])
        .map_err(|_| Error::KeyDerivationFailed("ML-KEM seed".into()))?;
    Ok(DecapsulationKey::<MlKem768>::from_seed(dz))
}

/// ML-KEM-768 encapsulation key of a seed (§3.1).
pub fn derive_mlkem_public_key(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(decapsulation_key(seed)?
        .encapsulation_key()
        .to_bytes()
        .to_vec())
}

/// PRF key of a seed (§3.2): `SHA-512("VAULTYS_PRF_KEY" || seed)[0:32]`.
pub fn derive_prf_key(seed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    check_seed(seed)?;
    let mut material = Zeroizing::new(Vec::with_capacity(PRF_KEY_LABEL.len() + SEED_LENGTH));
    material.extend_from_slice(PRF_KEY_LABEL);
    material.extend_from_slice(seed);
    let digest = Zeroizing::new(hash("sha512", &material));
    Ok(Zeroizing::new(digest[..32].to_vec()))
}

/// ML-KEM-768 decapsulation with the key re-derived from the seed. ML-KEM uses
/// implicit rejection: an invalid ciphertext gives a pseudorandom secret.
pub fn mlkem_decapsulate(seed: &[u8], cipher_text: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let ct: ml_kem::Ciphertext<MlKem768> = ml_kem::array::Array::try_from(cipher_text)
        .map_err(|_| Error::InvalidKeyFormat("ML-KEM-768 ciphertext must be 1088 bytes".into()))?;
    let shared = decapsulation_key(seed)?.decapsulate(&ct);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&shared);
    Ok(out)
}

/// `HMAC-SHA256(key, "VaultysID/" || message || "/end")`, as TS `getCypher().hmac`.
pub fn prf_hmac(key: &[u8], message: &str) -> Result<Vec<u8>> {
    hmac(
        "sha256",
        key,
        format!("VaultysID/{}/end", message).as_bytes(),
    )
}

/// `SHA-256(data || "secrethash" || key)`, as TS `getSecretHash`.
pub fn secret_hash(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut material = Zeroizing::new(Vec::with_capacity(data.len() + 10 + key.len()));
    material.extend_from_slice(data);
    material.extend_from_slice(b"secrethash");
    material.extend_from_slice(key);
    hash("sha256", &material)
}

/// The key-manager record of an id: `{v, x, e}` or `{v, x, e, k}` (§4.3).
#[derive(Deserialize)]
pub(crate) struct KeyManagerRecord {
    pub v: u8,
    #[serde(with = "serde_bytes")]
    pub x: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub e: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    pub k: Option<Vec<u8>>,
}

/// Checks the key-manager record of a post-quantum id (§4.2): version 1, a 32-byte
/// `e` and a 1184-byte `k`. The caller selects the key manager from `x`.
pub(crate) fn parse_post_quantum_record(record: &[u8]) -> Result<KeyManagerRecord> {
    let data: KeyManagerRecord = rmp_serde::from_slice(record)
        .map_err(|e| Error::InvalidKeyFormat(format!("invalid post-quantum id: {}", e)))?;
    if data.v != 1 {
        return Err(Error::UnsupportedVersion(data.v));
    }
    match &data.k {
        None => {
            return Err(Error::InvalidKeyFormat(
                "post-quantum id without ML-KEM key".into(),
            ))
        }
        Some(k) if k.len() != MLKEM768_PUBLIC_KEY_LENGTH => {
            return Err(Error::InvalidKeyFormat(
                "ML-KEM-768 key must be 1184 bytes".into(),
            ))
        }
        _ => {}
    }
    if data.e.len() != 32 {
        return Err(Error::InvalidKeyFormat(
            "X25519 key must be 32 bytes".into(),
        ));
    }
    Ok(data)
}

/// The X25519 key (`e`) and the ML-KEM key (`k`, if any) of a serialized id
/// (type byte included).
pub(crate) fn encryption_keys_of_id(id: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    if id.len() < 2 {
        return Err(Error::InvalidIdFormat);
    }
    let data: KeyManagerRecord =
        rmp_serde::from_slice(&id[1..]).map_err(|_| Error::InvalidIdFormat)?;
    if data.e.len() != 32 {
        return Err(Error::InvalidIdFormat);
    }
    Ok((data.e, data.k))
}

/// X25519 with a static secret key: returns the raw shared secret.
pub type StaticDiffieHellman<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>>;
/// ML-KEM-768 decapsulation with the recipient's decapsulation key.
pub type KemDecapsulate<'a> = &'a dyn Fn(&[u8]) -> Result<Zeroizing<[u8; 32]>>;

/// Rejects all-zero (low-order) X25519 outputs.
fn non_zero(shared: Vec<u8>) -> Result<Zeroizing<Vec<u8>>> {
    let shared = Zeroizing::new(shared);
    if shared.len() != 32 || shared.iter().all(|&b| b == 0) {
        return Err(Error::CryptoError("degenerate shared secret".into()));
    }
    Ok(shared)
}

/// `StaticDiffieHellman` for a raw X25519 secret key.
pub fn x25519_with_secret(secret: &[u8]) -> Result<impl Fn(&[u8]) -> Result<Vec<u8>>> {
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| Error::InvalidKeyFormat("X25519 keys must be 32 bytes".into()))?;
    let secret = StaticSecret::from(secret);
    Ok(move |public: &[u8]| {
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("X25519 keys must be 32 bytes".into()))?;
        Ok(secret
            .diffie_hellman(&PublicKey::from(public))
            .to_bytes()
            .to_vec())
    })
}

#[allow(clippy::too_many_arguments)]
fn derive_key(
    es: &[u8],
    ss: &[u8],
    kss: &[u8],
    e_pk: &[u8],
    s_pk: &[u8],
    r_pk: &[u8],
    r_ek: &[u8],
    kem_ct: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut material = Zeroizing::new(Vec::with_capacity(
        3 * 32 + DHIES_V3_INFO.len() + 3 * 32 + 32 + kem_ct.len(),
    ));
    material.extend_from_slice(es);
    material.extend_from_slice(ss);
    material.extend_from_slice(kss);
    material.extend_from_slice(DHIES_V3_INFO);
    material.extend_from_slice(e_pk);
    material.extend_from_slice(s_pk);
    material.extend_from_slice(r_pk);
    material.extend_from_slice(&hash("sha256", r_ek));
    material.extend_from_slice(kem_ct);
    let digest = Zeroizing::new(hash("sha512", &material));
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&digest[..32]);
    k
}

/// Encrypts `plaintext` from the sender (static X25519 and public key) to a
/// post-quantum recipient (X25519 key `R_pk` and ML-KEM-768 key `R_ek`).
pub fn dhies_v3_encrypt(
    sender_dh: StaticDiffieHellman,
    sender_public: &[u8],
    recipient_public: &[u8],
    recipient_ek: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ephemeral = Zeroizing::new(random_bytes(KEY_LENGTH));
    let nonce = random_bytes(NONCE_LENGTH);
    let m = Zeroizing::new(random_bytes(32));
    encrypt_with_randomness(
        &ephemeral,
        &nonce,
        &m,
        sender_dh,
        sender_public,
        recipient_public,
        recipient_ek,
        plaintext,
    )
}

#[allow(clippy::too_many_arguments)]
fn encrypt_with_randomness(
    ephemeral_secret: &[u8],
    nonce: &[u8],
    m: &[u8],
    sender_dh: StaticDiffieHellman,
    sender_public: &[u8],
    recipient_public: &[u8],
    recipient_ek: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if sender_public.len() != 32 || recipient_public.len() != 32 || nonce.len() != NONCE_LENGTH {
        return Err(Error::InvalidKeyFormat("invalid DHIES input".into()));
    }
    let ek_bytes: ml_kem::Key<EncapsulationKey<MlKem768>> =
        ml_kem::array::Array::try_from(recipient_ek)
            .map_err(|_| Error::InvalidKeyFormat("invalid recipient ML-KEM public key".into()))?;
    // FIPS 203 encapsulation key check (modulus check)
    let ek = EncapsulationKey::<MlKem768>::new(&ek_bytes)
        .map_err(|_| Error::InvalidKeyFormat("invalid recipient ML-KEM public key".into()))?;
    let m: B32 = ml_kem::array::Array::try_from(m)
        .map_err(|_| Error::InvalidKeyFormat("ML-KEM randomness must be 32 bytes".into()))?;

    let ephemeral: [u8; 32] = ephemeral_secret
        .try_into()
        .map_err(|_| Error::InvalidKeyFormat("X25519 keys must be 32 bytes".into()))?;
    let ephemeral = StaticSecret::from(ephemeral);
    let e_pk = PublicKey::from(&ephemeral).to_bytes();
    let es = non_zero(x25519_with_secret(&ephemeral.to_bytes())?(
        recipient_public,
    )?)?;
    let ss = non_zero(sender_dh(recipient_public)?)?;
    let (kem_ct, kss) = ek.encapsulate_deterministic(&m);
    let kss = Zeroizing::new(kss);

    let k = derive_key(
        &es[..],
        &ss[..],
        &kss[..],
        &e_pk,
        sender_public,
        recipient_public,
        recipient_ek,
        &kem_ct,
    );
    let ct = XSalsa20Poly1305::new(crypto_secretbox::Key::from_slice(&k[..]))
        .encrypt(crypto_secretbox::Nonce::from_slice(nonce), plaintext)
        .map_err(|_| Error::EncryptionFailed("DHIES v3".into()))?;

    let mut out = Vec::with_capacity(HEADER_LENGTH + ct.len());
    out.push(DHIES_V3_TAG);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&e_pk);
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens a DHIES v3 message addressed to a post-quantum recipient (static X25519 and
/// ML-KEM decapsulation) and authenticated by `sender_public`. Every failure gives the
/// same error, without saying which step failed (§5.3).
pub fn dhies_v3_decrypt(
    recipient_dh: StaticDiffieHellman,
    recipient_decapsulate: KemDecapsulate,
    recipient_public: &[u8],
    recipient_ek: &[u8],
    sender_public: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    let failed = || Error::DecryptionFailed("DHIES v3".into());
    if recipient_public.len() != 32
        || recipient_ek.len() != MLKEM768_PUBLIC_KEY_LENGTH
        || sender_public.len() != 32
        || message.len() < DHIES_V3_MIN_LENGTH
        || message[0] != DHIES_V3_TAG
    {
        return Err(failed());
    }
    let nonce = &message[1..1 + NONCE_LENGTH];
    let e_pk = &message[1 + NONCE_LENGTH..1 + NONCE_LENGTH + KEY_LENGTH];
    let kem_ct = &message[1 + NONCE_LENGTH + KEY_LENGTH..HEADER_LENGTH];
    let ct = &message[HEADER_LENGTH..];

    let es = non_zero(recipient_dh(e_pk).map_err(|_| failed())?).map_err(|_| failed())?;
    let ss = non_zero(recipient_dh(sender_public).map_err(|_| failed())?).map_err(|_| failed())?;
    let kss = recipient_decapsulate(kem_ct).map_err(|_| failed())?;
    let k = derive_key(
        &es[..],
        &ss[..],
        &kss[..],
        e_pk,
        sender_public,
        recipient_public,
        recipient_ek,
        kem_ct,
    );
    XSalsa20Poly1305::new(crypto_secretbox::Key::from_slice(&k[..]))
        .decrypt(crypto_secretbox::Nonce::from_slice(nonce), ct)
        .map_err(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/pq-identity-vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn unhex(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    /// X25519 secret of a vector identity: seed[32:64] for Dilithium and Hybrid,
    /// the `e` field of the secret for Ed25519.
    fn x25519_secret(identity: &Value) -> Vec<u8> {
        if let Some(seed) = identity.get("seed") {
            return unhex(seed)[32..64].to_vec();
        }
        #[derive(Deserialize)]
        struct Secret {
            #[serde(with = "serde_bytes")]
            e: Vec<u8>,
        }
        let secret: Secret = rmp_serde::from_slice(&unhex(&identity["secret"])[1..]).unwrap();
        secret.e
    }

    /// Static DH and decapsulation of a vector identity, from its seed.
    #[allow(clippy::type_complexity)]
    fn recipient_ops(
        identity: &Value,
    ) -> (
        impl Fn(&[u8]) -> Result<Vec<u8>>,
        impl Fn(&[u8]) -> Result<Zeroizing<[u8; 32]>>,
    ) {
        let seed = unhex(&identity["seed"]);
        let dh = x25519_with_secret(&seed[32..64]).unwrap();
        (dh, move |ct: &[u8]| mlkem_decapsulate(&seed, ct))
    }

    #[test]
    fn key_derivation_vectors() {
        let v = vectors();
        for (name, identity) in v["identities"].as_object().unwrap() {
            let Some(seed) = identity.get("seed") else {
                continue;
            };
            let seed = unhex(seed);
            assert_eq!(
                derive_mlkem_public_key(&seed).unwrap(),
                unhex(&identity["ek"]),
                "{name}: ek"
            );
            assert_eq!(
                derive_prf_key(&seed).unwrap().to_vec(),
                unhex(&identity["prfKey"]),
                "{name}: PRF key"
            );
        }
        for prf in v["prf"].as_array().unwrap() {
            let identity = &v["identities"][prf["identity"].as_str().unwrap()];
            let key = derive_prf_key(&unhex(&identity["seed"])).unwrap();
            assert_eq!(
                prf_hmac(&key, prf["message"].as_str().unwrap()).unwrap(),
                unhex(&prf["hmac"])
            );
            assert_eq!(
                secret_hash(&key, &unhex(&prf["secretHashData"])),
                unhex(&prf["secretHash"])
            );
        }
        assert!(derive_mlkem_public_key(&[0u8; 32]).is_err());
    }

    /// The exact TypeScript output, for every case (Hybrid recipients included: at this
    /// level only the seed and the public keys are needed).
    #[test]
    fn dhies_v3_vectors() {
        let v = vectors();
        let cases = v["dhiesV3"].as_array().unwrap();
        assert_eq!(cases.len(), 5);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let sender = &v["identities"][c["sender"].as_str().unwrap()];
            let recipient = &v["identities"][c["recipient"].as_str().unwrap()];
            let sender_dh = x25519_with_secret(&x25519_secret(sender)).unwrap();
            let out = encrypt_with_randomness(
                &unhex(&c["ephemeralSecretKey"]),
                &unhex(&c["nonce"]),
                &unhex(&c["kemRandomness"]),
                &sender_dh,
                &unhex(&sender["cypherPublicKey"]),
                &unhex(&recipient["cypherPublicKey"]),
                &unhex(&recipient["ek"]),
                &unhex(&c["plaintext"]),
            )
            .unwrap();
            assert_eq!(hex::encode(&out), c["out"].as_str().unwrap(), "{name}: out");
            assert_eq!(
                mlkem_decapsulate(&unhex(&recipient["seed"]), &out[57..1145])
                    .unwrap()
                    .to_vec(),
                unhex(&c["kss"]),
                "{name}: kss"
            );
            let (dh, decapsulate) = recipient_ops(recipient);
            let plaintext = dhies_v3_decrypt(
                &dh,
                &decapsulate,
                &unhex(&recipient["cypherPublicKey"]),
                &unhex(&recipient["ek"]),
                &unhex(&sender["cypherPublicKey"]),
                &unhex(&c["out"]),
            )
            .unwrap();
            assert_eq!(plaintext, unhex(&c["plaintext"]), "{name}: decrypt");
        }
    }

    #[test]
    fn dhies_v3_round_trip_and_rejections() {
        let v = vectors();
        let recipient = &v["identities"]["pq_dilithium_machine"];
        let sender = &v["identities"]["pq_dilithium_person"];
        let (dh, decapsulate) = recipient_ops(recipient);
        let (r_pk, ek) = (
            unhex(&recipient["cypherPublicKey"]),
            unhex(&recipient["ek"]),
        );
        let open =
            |s_pk: &[u8], msg: &[u8]| dhies_v3_decrypt(&dh, &decapsulate, &r_pk, &ek, s_pk, msg);
        let s_dh = x25519_with_secret(&x25519_secret(sender)).unwrap();
        let s_pk = unhex(&sender["cypherPublicKey"]);
        let out = dhies_v3_encrypt(&s_dh, &s_pk, &r_pk, &ek, b"rust").unwrap();
        assert_eq!(out.len(), DHIES_V3_MIN_LENGTH + 4);
        assert_eq!(DHIES_V3_MIN_LENGTH, 1161);
        assert_eq!(open(&s_pk, &out).unwrap(), b"rust");
        let other = dhies_v3_encrypt(&s_dh, &s_pk, &r_pk, &ek, b"rust").unwrap();
        assert_ne!(out[25..1145], other[25..1145], "randomized");

        for pos in [0, 1, 25, 57, 1144, 1145, out.len() - 1] {
            let mut tampered = out.clone();
            tampered[pos] ^= 1;
            assert!(open(&s_pk, &tampered).is_err());
        }
        let mut low_order = out.clone();
        low_order[25..57].fill(0);
        assert!(open(&s_pk, &low_order).is_err());
        assert!(open(&s_pk, &out[..1160]).is_err());
        let wrong_sender = unhex(&v["identities"]["pq_hybrid_person"]["cypherPublicKey"]);
        assert!(open(&wrong_sender, &out).is_err());

        assert!(dhies_v3_encrypt(&s_dh, &s_pk, &r_pk, &ek[..1183], b"x").is_err());
        assert!(dhies_v3_encrypt(&s_dh, &s_pk, &r_pk, &[0xff; 1184], b"x").is_err());
        assert!(dhies_v3_encrypt(&s_dh, &s_pk, &[0u8; 32], &ek, b"x").is_err());
    }
}
