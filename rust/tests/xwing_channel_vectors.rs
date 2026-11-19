//! X-Wing channel against the official X-Wing vectors and the TypeScript channel
//! vectors (typescript/test/interops/generate-xwing-channel-vectors.ts).

use serde_json::Value;
use vaultysid::memory_channel::{Channel, MemoryChannel};
use vaultysid::xwing_channel::*;

fn load(name: &str) -> Value {
    let path = format!("{}/tests/data/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn h(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}

#[test]
fn official_xwing_vectors() {
    let v = load("xwing-draft-vectors.json");
    for t in v["vectors"].as_array().unwrap() {
        let (pk, sk) = key_pair_from_seed(&h(t, "seed")).unwrap();
        assert_eq!(pk, h(t, "pk"));
        assert_eq!(sk.to_vec(), h(t, "sk"));
        let (ct, ss) = encapsulate_with(&pk, &h(t, "eseed")).unwrap();
        assert_eq!(ct, h(t, "ct"));
        assert_eq!(ss.to_vec(), h(t, "ss"));
        assert_eq!(
            decapsulate(&h(t, "ct"), &h(t, "sk")).unwrap().to_vec(),
            h(t, "ss")
        );
    }
}

#[test]
fn channel_keys_and_records() {
    let v = load("xwing-channel-vectors.json");
    let k = derive_channel_keys(&h(&v, "sharedSecret"), &h(&v, "m1"), &h(&v, "m2"));
    assert_eq!(k.transcript_hash.to_vec(), h(&v, "transcriptHash"));
    assert_eq!(k.i2r.to_vec(), h(&v, "keyI2R"));
    assert_eq!(k.r2i.to_vec(), h(&v, "keyR2I"));
    assert_eq!(k.binding.to_vec(), h(&v, "binding"));
    for r in v["records"].as_array().unwrap() {
        let key = if r["direction"] == "i2r" {
            &k.i2r
        } else {
            &k.r2i
        };
        let seq = r["seq"].as_u64().unwrap();
        let record = h(r, "record");
        assert_eq!(encrypt_record(key, seq, &h(r, "message")).unwrap(), record);
        assert_eq!(decrypt_record(key, seq, &record).unwrap(), h(r, "message"));
        assert!(
            decrypt_record(key, seq + 1, &record).is_err(),
            "wrong sequence accepted"
        );
        let other = if r["direction"] == "i2r" {
            &k.r2i
        } else {
            &k.i2r
        };
        assert!(
            decrypt_record(other, seq, &record).is_err(),
            "reflected record accepted"
        );
        let mut tampered = record.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            decrypt_record(key, seq, &tampered).is_err(),
            "tampered record accepted"
        );
    }
}

#[tokio::test]
async fn establishment_matches_typescript() {
    let v = load("xwing-channel-vectors.json");
    let (mut a, mut b) = MemoryChannel::create_bidirectional();
    a.start().await.unwrap();
    b.start().await.unwrap();
    let seed = h(&v, "initiatorSeed");
    let randomness = h(&v, "encapsulationRandomness");
    let (initiator, responder) = tokio::join!(
        XWingSession::initiate_with(a, &seed),
        XWingSession::accept_with(b, &randomness)
    );
    let mut initiator = initiator.unwrap();
    let mut responder = responder.unwrap();
    assert_eq!(initiator.binding.to_vec(), h(&v, "binding"));
    assert_eq!(responder.transcript_hash.to_vec(), h(&v, "transcriptHash"));
    initiator.send(b"").await.unwrap();
    assert_eq!(responder.receive().await.unwrap(), Vec::<u8>::new());
    responder.send(b"pong").await.unwrap();
    assert_eq!(initiator.receive().await.unwrap(), b"pong");
}

#[tokio::test]
async fn random_sessions_have_their_own_binding() {
    let (a, b) = MemoryChannel::create_bidirectional();
    let (i, r) = tokio::join!(XWingSession::initiate(a), XWingSession::accept(b));
    let (i, r) = (i.unwrap(), r.unwrap());
    assert_eq!(i.binding, r.binding);
    let (a2, b2) = MemoryChannel::create_bidirectional();
    let (i2, _r2) = tokio::join!(XWingSession::initiate(a2), XWingSession::accept(b2));
    assert_ne!(i.binding, i2.unwrap().binding);
}
