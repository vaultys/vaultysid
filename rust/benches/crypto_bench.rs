use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use vaultysid::crypto::{hash, hmac, random_bytes};
use vaultysid::key_manager::DHIES;
use vaultysid::{AbstractKeyManager, DeprecatedKeyManager, Ed25519Manager, VaultysId};

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
            let signer = manager.get_signer().unwrap();
            signer.sign(black_box(data)).unwrap()
        });
    });

    let signer = manager.get_signer().unwrap();
    let signature = signer.sign(data).unwrap().unwrap();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| manager.verify(black_box(data), black_box(&signature), None));
    });
}

fn bench_diffie_hellman(c: &mut Criterion) {
    let alice = Ed25519Manager::generate().unwrap();
    let bob = Ed25519Manager::generate().unwrap();
    let alice_cypher = alice.get_cypher().unwrap();

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

fn bench_vaultys_id(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("vaultys_id_generate_machine", |b| {
        b.iter(|| runtime.block_on(async { VaultysId::generate_machine().await.unwrap() }));
    });

    c.bench_function("vaultys_id_generate_person", |b| {
        b.iter(|| runtime.block_on(async { VaultysId::generate_person().await.unwrap() }));
    });

    // Create a VaultysId for benchmarking sign/verify
    let id = runtime.block_on(async { VaultysId::generate_machine().await.unwrap() });
    let challenge = b"benchmark challenge";

    c.bench_function("vaultys_id_sign_challenge", |b| {
        b.iter(|| {
            let id = id.duplicate();
            runtime.block_on(async move { id.sign_challenge(black_box(challenge)).await.unwrap() })
        });
    });

    let signed = runtime.block_on(async { id.sign_challenge(challenge).await.unwrap() });

    c.bench_function("vaultys_id_verify_challenge", |b| {
        b.iter(|| {
            id.verify_challenge(black_box(challenge), black_box(&signed.signature))
                .unwrap()
        });
    });
}

// Alternative approach using a custom async benchmark group
// This is more efficient for async benchmarks as it reuses the runtime
fn bench_vaultys_id_async(c: &mut Criterion) {
    use std::time::Duration;

    let mut group = c.benchmark_group("vaultys_id_async");
    group.measurement_time(Duration::from_secs(10));

    let runtime = tokio::runtime::Runtime::new().unwrap();

    // Pre-create some test data
    let entropy = random_bytes(32);

    group.bench_function("generate_from_entropy_machine", |b| {
        b.iter(|| {
            runtime.block_on(async {
                VaultysId::from_entropy(black_box(&entropy), 0)
                    .await
                    .unwrap()
            })
        });
    });

    group.bench_function("generate_from_entropy_person", |b| {
        b.iter(|| {
            runtime.block_on(async {
                VaultysId::from_entropy(black_box(&entropy), 1)
                    .await
                    .unwrap()
            })
        });
    });

    group.bench_function("generate_from_entropy_org", |b| {
        b.iter(|| {
            runtime.block_on(async {
                VaultysId::from_entropy(black_box(&entropy), 2)
                    .await
                    .unwrap()
            })
        });
    });

    // Test DID generation
    let id = runtime.block_on(async { VaultysId::generate_person().await.unwrap() });

    group.bench_function("did_generation", |b| {
        b.iter(|| black_box(id.did()));
    });

    group.bench_function("did_document_generation", |b| {
        b.iter(|| black_box(id.did_document()));
    });

    group.finish();
}

// Benchmark DHIES encryption/decryption
fn bench_dhies_operations(c: &mut Criterion) {
    let sender_manager = Ed25519Manager::generate().unwrap();
    let recipient_manager = Ed25519Manager::generate().unwrap();

    // Get cypher public keys from the managers
    let sender_cypher_public = sender_manager.cypher.public_key.clone();
    let recipient_cypher_public = recipient_manager.cypher.public_key.clone();

    let message = b"This is a test message for DHIES encryption benchmarking";

    c.bench_function("dhies_encrypt", |b| {
        b.iter(|| {
            // Create DHIES instance for encryption
            let dhies = DHIES::new(&sender_manager);
            dhies
                .encrypt(black_box(message), black_box(&recipient_cypher_public))
                .unwrap()
        });
    });

    // Encrypt once to get the encrypted message for decryption benchmark
    let dhies_sender = DHIES::new(&sender_manager);
    let encrypted = dhies_sender
        .encrypt(message, &recipient_cypher_public)
        .unwrap();

    c.bench_function("dhies_decrypt", |b| {
        b.iter(|| {
            // Create DHIES instance for decryption
            let dhies = DHIES::new(&recipient_manager);
            dhies
                .decrypt(black_box(&encrypted), black_box(&sender_cypher_public))
                .unwrap()
        });
    });
}

// Benchmark key pair operations
fn bench_key_pair_operations(c: &mut Criterion) {
    let manager = Ed25519Manager::generate().unwrap();

    c.bench_function("get_signer_public_key", |b| {
        b.iter(|| black_box(manager.signer.public_key.clone()));
    });

    c.bench_function("get_cypher_public_key", |b| {
        b.iter(|| black_box(manager.cypher.public_key.clone()));
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
    bench_vaultys_id,
    bench_vaultys_id_async,
    bench_dhies_operations,
    bench_key_pair_operations
);

criterion_main!(benches);
