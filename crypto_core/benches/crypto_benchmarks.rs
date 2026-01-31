//! 🐱 Meow Decoder - Criterion Benchmark Suite
//!
//! Performance benchmarks for cryptographic operations.
//! Run with: cargo bench --features full
//!
//! ## Quick Commands
//! ```bash
//! # Run all benchmarks
//! cargo bench
//!
//! # Run specific benchmark group
//! cargo bench -- aes_gcm
//! cargo bench -- argon2id
//! cargo bench -- pq_kem
//!
//! # Generate HTML report
//! cargo bench -- --save-baseline main
//! ```

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};

// ============================================
// AES-256-GCM Benchmarks
// ============================================

fn bench_aes_gcm(c: &mut Criterion) {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let key = [0u8; 32];
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

    let mut group = c.benchmark_group("aes_gcm");

    // Benchmark different payload sizes
    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let plaintext = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, _| {
            b.iter(|| {
                cipher.encrypt(nonce, black_box(plaintext.as_slice())).unwrap()
            })
        });

        // Pre-encrypt for decrypt benchmark
        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();

        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, _| {
            b.iter(|| {
                cipher.decrypt(nonce, black_box(ciphertext.as_slice())).unwrap()
            })
        });
    }

    group.finish();
}

// ============================================
// Argon2id Key Derivation Benchmarks
// ============================================

#[cfg(feature = "argon2")]
fn bench_argon2id(c: &mut Criterion) {
    use argon2::{Argon2, Algorithm, Version, Params};

    let mut group = c.benchmark_group("argon2id");

    // Test different memory costs (in KiB)
    // Note: Higher memory = more secure but slower
    let configs = [
        ("32MiB_1iter", 32 * 1024, 1),   // Fast (testing)
        ("64MiB_3iter", 64 * 1024, 3),   // OWASP minimum
        ("256MiB_10iter", 256 * 1024, 10), // Enhanced
        ("512MiB_20iter", 512 * 1024, 20), // Ultra (production default)
    ];

    let password = b"test_password_for_benchmarking";
    let salt = [0u8; 16];

    for (name, memory_kib, iterations) in configs.iter() {
        // Skip ultra-high memory in CI (would timeout)
        if *memory_kib > 128 * 1024 {
            continue;
        }

        let params = Params::new(*memory_kib as u32, *iterations, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        group.bench_function(*name, |b| {
            b.iter(|| {
                let mut output = [0u8; 32];
                argon2.hash_password_into(
                    black_box(password),
                    black_box(&salt),
                    &mut output,
                ).unwrap();
                output
            })
        });
    }

    group.finish();
}

// ============================================
// X25519 Key Exchange Benchmarks
// ============================================

#[cfg(feature = "x25519")]
fn bench_x25519(c: &mut Criterion) {
    use x25519_dalek::{EphemeralSecret, PublicKey};
    use rand_core::OsRng;

    let mut group = c.benchmark_group("x25519");

    group.bench_function("keypair_generate", |b| {
        b.iter(|| {
            let secret = EphemeralSecret::random_from_rng(OsRng);
            let _public = PublicKey::from(&secret);
        })
    });

    // Pre-generate keys for DH benchmark
    let alice_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    group.bench_function("diffie_hellman", |b| {
        b.iter(|| {
            // Note: EphemeralSecret is consumed, so we benchmark the pattern
            let secret = EphemeralSecret::random_from_rng(OsRng);
            secret.diffie_hellman(black_box(&bob_public))
        })
    });

    group.finish();
}

// ============================================
// ML-KEM (Post-Quantum) Benchmarks
// ============================================

#[cfg(feature = "pq-crypto")]
fn bench_ml_kem(c: &mut Criterion) {
    use ml_kem::{MlKem768, KemCore};
    use kem::{Encapsulate, Decapsulate};

    let mut group = c.benchmark_group("ml_kem_768");

    // Key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let (dk, ek) = MlKem768::generate(&mut rand_core::OsRng);
            (dk, ek)
        })
    });

    // Pre-generate keypair for encap/decap
    let (dk, ek) = MlKem768::generate(&mut rand_core::OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            ek.encapsulate(&mut rand_core::OsRng).unwrap()
        })
    });

    // Pre-encapsulate for decap benchmark
    let (ciphertext, _shared_secret) = ek.encapsulate(&mut rand_core::OsRng).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            dk.decapsulate(black_box(&ciphertext)).unwrap()
        })
    });

    group.finish();
}

// ============================================
// ML-KEM-1024 (Highest Security) Benchmarks
// ============================================

#[cfg(feature = "pq-crypto")]
fn bench_ml_kem_1024(c: &mut Criterion) {
    use ml_kem::{MlKem1024, KemCore};
    use kem::{Encapsulate, Decapsulate};

    let mut group = c.benchmark_group("ml_kem_1024");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let (dk, ek) = MlKem1024::generate(&mut rand_core::OsRng);
            (dk, ek)
        })
    });

    let (dk, ek) = MlKem1024::generate(&mut rand_core::OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            ek.encapsulate(&mut rand_core::OsRng).unwrap()
        })
    });

    let (ciphertext, _) = ek.encapsulate(&mut rand_core::OsRng).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            dk.decapsulate(black_box(&ciphertext)).unwrap()
        })
    });

    group.finish();
}

// ============================================
// liboqs Native Backend Benchmarks
// ============================================

#[cfg(feature = "liboqs-native")]
fn bench_liboqs_kem(c: &mut Criterion) {
    use oqs::kem::{Kem, Algorithm};

    let mut group = c.benchmark_group("liboqs_ml_kem_768");

    let kem = Kem::new(Algorithm::MlKem768).unwrap();

    group.bench_function("keygen", |b| {
        b.iter(|| {
            kem.keypair().unwrap()
        })
    });

    let (pk, sk) = kem.keypair().unwrap();

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            kem.encapsulate(black_box(&pk)).unwrap()
        })
    });

    let (ct, _ss) = kem.encapsulate(&pk).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            kem.decapsulate(black_box(&sk), black_box(&ct)).unwrap()
        })
    });

    group.finish();
}

// ============================================
// HKDF Key Derivation Benchmarks
// ============================================

#[cfg(feature = "hkdf")]
fn bench_hkdf(c: &mut Criterion) {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut group = c.benchmark_group("hkdf_sha256");

    let ikm = [0u8; 32];
    let salt = [0u8; 16];
    let info = b"meow_decoder_benchmark";

    for output_len in [32, 64, 128, 256].iter() {
        group.bench_with_input(BenchmarkId::new("expand", output_len), output_len, |b, &len| {
            let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
            let mut okm = vec![0u8; len];

            b.iter(|| {
                hkdf.expand(black_box(info), &mut okm).unwrap();
            })
        });
    }

    group.finish();
}

// ============================================
// Criterion Groups
// ============================================

// Base benchmarks (always available)
criterion_group!(
    benches_base,
    bench_aes_gcm,
);

// Optional feature benchmarks
#[cfg(feature = "argon2")]
criterion_group!(benches_argon2, bench_argon2id);

#[cfg(feature = "x25519")]
criterion_group!(benches_x25519, bench_x25519);

#[cfg(feature = "pq-crypto")]
criterion_group!(benches_pq, bench_ml_kem, bench_ml_kem_1024);

#[cfg(feature = "liboqs-native")]
criterion_group!(benches_liboqs, bench_liboqs_kem);

#[cfg(feature = "hkdf")]
criterion_group!(benches_hkdf, bench_hkdf);

// Main entry point
criterion_main!(
    benches_base,
    #[cfg(feature = "argon2")]
    benches_argon2,
    #[cfg(feature = "x25519")]
    benches_x25519,
    #[cfg(feature = "pq-crypto")]
    benches_pq,
    #[cfg(feature = "liboqs-native")]
    benches_liboqs,
    #[cfg(feature = "hkdf")]
    benches_hkdf,
);

// ============================================
// 🐱 Cat-Themed Benchmark Notes
// ============================================
//
// Expected performance on modern hardware (2024):
//
// | Operation           | Time        | Meow Rating |
// |---------------------|-------------|-------------|
// | AES-GCM 4KB         | ~0.5 µs     | 😸 Fast     |
// | AES-GCM 64KB        | ~8 µs       | 😺 Quick    |
// | X25519 DH           | ~50 µs      | 🐱 Good     |
// | ML-KEM-768 Keygen   | ~1.2 ms     | 😼 Moderate |
// | ML-KEM-768 Encap    | ~0.8 ms     | 😼 Moderate |
// | ML-KEM-1024 Keygen  | ~1.8 ms     | 🙀 Slow     |
// | Argon2id 64MB       | ~200 ms     | 😾 Intentional|
// | Argon2id 512MB      | ~5-10 s     | 🦁 ULTRA    |
//
// "A patient cat catches the quantum mouse." 🐱🔮
