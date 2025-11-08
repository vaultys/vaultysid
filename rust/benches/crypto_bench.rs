use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vaultysid::crypto::{hash, hmac, random_bytes};
use vaultysid::{DeprecatedKeyManager, Ed25519Manager, VaultysId};

fn bench_ed25519_generation(c: &mut Criterion) {
    c.bench_function("ed25519_generate", |b| {
        b.iter(|| Ed25519Manager::generate().unwrap());
    });
}

fn bench_ed25519_from_entropy(c: &mut Criterion) {
    let entropy = random_bytes(32);
    c.bench_function("ed25519_from_entropy", |b| {
        b.iter(|| Ed25519Manager::from_entropy(black_box(&entropy)).unwrap());
    });
}

fn bench_ed25519_sign_verify(c: &mut Criterion) {
    let manager = Ed25519Manager::generate().unwrap();
    let data = b"benchmark test message for signing and verification";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            let signer = manager.get_signer_ops().unwrap();
            signer.sign(black_box(data)).unwrap()
        });
    });

    let signer = manager.get_signer_ops().unwrap();
    let signature = signer.sign(data).unwrap();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| manager.verify(black_box(data), black_box(&signature), None));
    });
}

fn bench_diffie_hellman(c: &mut Criterion) {
    let alice = Ed25519Manager::generate().unwrap();
    let bob = Ed25519Manager::generate().unwrap();
    let alice_cypher = alice.get_cypher_ops().unwrap();

    c.bench_function("diffie_hellman", |b| {
        b.iter(|| {
            alice_cypher
                .diffie_hellman(black_box(&bob.cypher.public_key))
                .unwrap()
        });
    });
}

fn bench_hash_operations(c: &mut Criterion) {
    let data = b"benchmark data for hashing operations";

    c.bench_function("sha256", |b| {
        b.iter(|| hash("sha256", black_box(data)));
    });

    c.bench_function("sha512", |b| {
        b.iter(|| hash("sha512", black_box(data)));
    });
}

fn bench_hmac_operations(c: &mut Criterion) {
    let key = b"benchmark secret key";
    let data = b"benchmark data for hmac";

    c.bench_function("hmac_sha256", |b| {
        b.iter(|| hmac("sha256", black_box(key), black_box(data)).unwrap());
    });
}

fn bench_random_bytes(c: &mut Criterion) {
    c.bench_function("random_bytes_32", |b| {
        b.iter(|| random_bytes(32));
    });

    c.bench_function("random_bytes_64", |b| {
        b.iter(|| random_bytes(64));
    });
}

fn bench_deprecated_manager(c: &mut Criterion) {
    c.bench_function("deprecated_generate", |b| {
        b.iter(|| DeprecatedKeyManager::generate_id25519().unwrap());
    });

    let entropy = random_bytes(32);
    c.bench_function("deprecated_from_entropy", |b| {
        b.iter(|| {
            DeprecatedKeyManager::create_id25519_from_entropy(black_box(&entropy), 0).unwrap()
        });
    });
}

fn bench_serialization(c: &mut Criterion) {
    let manager = Ed25519Manager::generate().unwrap();

    c.bench_function("ed25519_id_serialize", |b| {
        b.iter(|| manager.id());
    });

    let id = manager.id();
    c.bench_function("ed25519_id_deserialize", |b| {
        b.iter(|| Ed25519Manager::from_id(black_box(&id)).unwrap());
    });

    let secret = manager.get_secret().unwrap();
    c.bench_function("ed25519_secret_serialize", |b| {
        b.iter(|| manager.get_secret().unwrap());
    });

    c.bench_function("ed25519_secret_deserialize", |b| {
        b.iter(|| Ed25519Manager::from_secret(black_box(&secret)).unwrap());
    });
}

async fn create_vaultys_id() -> VaultysId {
    VaultysId::generate_machine().await.unwrap()
}

fn bench_vaultys_id(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("vaultys_id_generate_machine", |b| {
        b.to_async(&runtime)
            .iter(|| async { VaultysId::generate_machine().await.unwrap() });
    });

    c.bench_function("vaultys_id_generate_person", |b| {
        b.to_async(&runtime)
            .iter(|| async { VaultysId::generate_person().await.unwrap() });
    });

    let id = runtime.block_on(create_vaultys_id());
    let challenge = b"benchmark challenge";

    c.bench_function("vaultys_id_sign_challenge", |b| {
        b.to_async(&runtime).iter(|| async {
            let id = runtime.block_on(create_vaultys_id());
            id.sign_challenge(black_box(challenge)).await.unwrap()
        });
    });

    let signed = runtime.block_on(id.sign_challenge(challenge)).unwrap();

    c.bench_function("vaultys_id_verify_challenge", |b| {
        let id = runtime.block_on(create_vaultys_id());
        b.iter(|| {
            id.verify_challenge(black_box(challenge), black_box(&signed.signature))
                .unwrap()
        });
    });
}

criterion_group!(
    benches,
    bench_ed25519_generation,
    bench_ed25519_from_entropy,
    bench_ed25519_sign_verify,
    bench_diffie_hellman,
    bench_hash_operations,
    bench_hmac_operations,
    bench_random_bytes,
    bench_deprecated_manager,
    bench_serialization,
    bench_vaultys_id
);

criterion_main!(benches);
