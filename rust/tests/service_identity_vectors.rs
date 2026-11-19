//! Service identities and anchors against the TypeScript vectors
//! (typescript/test/interops/generate-service-identity-vectors.ts and
//! generate-service-anchor-vectors.ts).

use serde_json::Value;
use sha2::{Digest, Sha256};
use vaultysid::service_identity::*;
use vaultysid::VaultysId;

fn load(name: &str) -> Value {
    let path = format!("{}/tests/data/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn alg_of(s: &str) -> ServiceAlgorithm {
    match s {
        "ed25519" => ServiceAlgorithm::Ed25519,
        "dilithium" => ServiceAlgorithm::Dilithium,
        "dilithium_ed25519" => ServiceAlgorithm::DilithiumEd25519,
        other => panic!("{other}"),
    }
}

fn role_of(type_name: &str) -> (ServiceRole, bool) {
    let pq = type_name.ends_with("-pq");
    let role = match type_name.trim_end_matches("-pq") {
        "machine" => ServiceRole::Machine,
        "person" => ServiceRole::Person,
        "organization" => ServiceRole::Organization,
        other => panic!("{other}"),
    };
    (role, pq)
}

#[test]
fn canonical_vectors() {
    let v = load("service-identity-vectors.json");
    let cases = v["canonical"].as_array().unwrap();
    assert!(cases.len() > 50);
    for c in cases {
        let input = c["input"].as_str().unwrap();
        let dev = c["options"]["allowDevelopmentHosts"]
            .as_bool()
            .unwrap_or(false);
        let got = canonical_service_id(input, dev).unwrap_or_else(|_| "invalid".into());
        assert_eq!(
            got,
            c["output"].as_str().unwrap(),
            "input {input:?} dev {dev}"
        );
    }
}

#[tokio::test]
async fn derive_vectors() {
    let v = load("service-identity-vectors.json");
    let master = hex::decode(v["master"].as_str().unwrap()).unwrap();
    let mut checked = 0;
    for d in v["derive"].as_array().unwrap() {
        let alg = alg_of(d["alg"].as_str().unwrap());
        let (role, pq) = role_of(d["typeName"].as_str().unwrap());
        let service = d["service"].as_str().unwrap();
        let canonical = canonical_service_id(service, false).unwrap();
        assert_eq!(canonical, d["canonical"].as_str().unwrap());
        assert_eq!(
            hex::encode(service_identity_info(alg, role, pq, &canonical)),
            d["info"].as_str().unwrap()
        );
        let entropy = derive_service_entropy(&master, service, alg, role, pq).unwrap();
        assert_eq!(
            hex::encode(&entropy),
            d["entropy"].as_str().unwrap(),
            "{service}"
        );
        if alg != ServiceAlgorithm::Ed25519 || pq {
            // Hybrid and post-quantum types do not exist in the Rust crate yet, and its Dilithium key derivation
            // does not match TypeScript 4.0 on this branch (aligned by the Rust post-quantum identities PR).
            // The entropy above is checked for every case.
            continue;
        }
        let id = derive_service_identity(&master, service, alg, role)
            .await
            .unwrap();
        assert_eq!(id.did(), d["did"].as_str().unwrap(), "{service} {:?}", alg);
        assert_eq!(
            hex::encode(Sha256::digest(id.id())),
            d["idSha256"].as_str().unwrap()
        );
        if let Some(full) = d["id"].as_str() {
            assert_eq!(hex::encode(id.id()), full);
        }
        checked += 1;
    }
    assert!(checked >= 5);
}

#[tokio::test]
async fn refusals_and_separation() {
    let master = [1u8; 32];
    assert!(derive_service_entropy(
        &[0u8; 32],
        "https://example.com",
        ServiceAlgorithm::Ed25519,
        ServiceRole::Person,
        false
    )
    .is_err());
    assert!(derive_service_entropy(
        &master[..31],
        "https://example.com",
        ServiceAlgorithm::Ed25519,
        ServiceRole::Person,
        false
    )
    .is_err());
    assert!(derive_service_entropy(
        &master,
        "https://example.com/login",
        ServiceAlgorithm::Ed25519,
        ServiceRole::Person,
        false
    )
    .is_err());
    assert!(derive_service_entropy(
        &master,
        "https://example.com",
        ServiceAlgorithm::Ed25519,
        ServiceRole::Person,
        true
    )
    .is_err());
    let a = derive_service_identity(
        &master,
        "https://service-a.test",
        ServiceAlgorithm::Ed25519,
        ServiceRole::Person,
    )
    .await
    .unwrap();
    let b = derive_service_identity(
        &master,
        "https://service-b.test",
        ServiceAlgorithm::Ed25519,
        ServiceRole::Person,
    )
    .await
    .unwrap();
    assert_ne!(a.did(), b.did());
}

#[tokio::test]
async fn anchor_vectors() {
    let v = load("service-anchor-vectors.json");
    let master: [u8; 32] = Sha256::digest(b"vaultysid/test/anchors/service").into();
    for a in v["valid"].as_array().unwrap() {
        let service = a["serviceId"].as_str().unwrap();
        let raw = hex::decode(a["anchor"].as_str().unwrap()).unwrap();
        let id = verify_service_anchor(&raw, service).expect("valid anchor refused");
        assert_eq!(id.did(), a["did"].as_str().unwrap());
        // Ed25519 signatures are deterministic: Rust produces the same bytes as TypeScript
        let service_id = derive_service_identity(
            &master,
            service,
            ServiceAlgorithm::Ed25519,
            ServiceRole::Organization,
        )
        .await
        .unwrap();
        assert_eq!(
            create_service_anchor(&service_id, service).unwrap(),
            raw,
            "{service}"
        );
    }
    for a in v["invalid"].as_array().unwrap() {
        let raw = hex::decode(a["anchor"].as_str().unwrap()).unwrap();
        assert!(
            verify_service_anchor(&raw, a["serviceId"].as_str().unwrap()).is_none(),
            "{}",
            a["name"]
        );
    }
    assert_eq!(
        service_anchor_url("https://Service-A.test/").unwrap(),
        "https://service-a.test/.well-known/vaultysid-service"
    );
    assert!(service_anchor_url("app:test.service.c").is_err());
}

#[tokio::test]
async fn anchor_round_trip_dilithium() {
    let service =
        VaultysId::generate_organization_with_alg(vaultysid::vaultys_id::Algorithm::Dilithium)
            .await
            .unwrap();
    let anchor = create_service_anchor(&service, "https://service-a.test").unwrap();
    assert_eq!(
        verify_service_anchor(&anchor, "https://service-a.test")
            .unwrap()
            .did(),
        service.did()
    );
    assert!(verify_service_anchor(&anchor, "https://service-b.test").is_none());
}

#[tokio::test]
async fn from_entropy_requires_32_bytes() {
    for len in [0usize, 16, 31, 33, 64] {
        assert!(
            VaultysId::from_entropy(&vec![1u8; len], 1).await.is_err(),
            "{len}"
        );
    }
    assert!(VaultysId::from_entropy(&[1u8; 32], 1).await.is_ok());
}
