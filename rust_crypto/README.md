# meow_crypto_rs - Rust Crypto Backend for Meow Decoder

High-performance cryptographic primitives for Meow Decoder, written in Rust
with Python bindings via PyO3.

## Features

- **Argon2id KDF** - Memory-hard password hashing
- **AES-256-GCM** - Authenticated encryption with associated data
- **HKDF** - HMAC-based Key Derivation Function
- **HMAC-SHA256** - Keyed-hash message authentication
- **X25519** - Elliptic curve Diffie-Hellman
- **ML-KEM-1024** - Post-quantum key encapsulation (NIST FIPS 203)
- **SecureBuffer** - Automatic memory zeroing

## Security Properties

- **Constant-time operations** via `subtle` crate
- **Automatic memory zeroing** via `zeroize` crate
- **No unsafe code** where possible
- **Audited crypto libraries**

## Installation

### From PyPI (when published)

```bash
pip install meow-crypto-rs
```

### From Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install maturin
pip install maturin

# Build and install
cd rust_crypto
maturin develop --release
```

## Usage

```python
import meow_crypto_rs

# Argon2id key derivation
key = meow_crypto_rs.derive_key_argon2id(
    password=b"my_password",
    salt=b"random_16_bytes!",
    memory_kib=65536,
    iterations=3,
    parallelism=4,
    output_len=32
)

# AES-256-GCM encryption
ciphertext = meow_crypto_rs.aes_gcm_encrypt(
    key=key,
    nonce=b"12_byte_non",
    plaintext=b"secret data",
    aad=b"authenticated data"
)

# Decryption
plaintext = meow_crypto_rs.aes_gcm_decrypt(
    key=key,
    nonce=b"12_byte_non",
    ciphertext=ciphertext,
    aad=b"authenticated data"
)

# HMAC-SHA256
tag = meow_crypto_rs.hmac_sha256(key, message)
is_valid = meow_crypto_rs.hmac_sha256_verify(key, message, tag)

# X25519 key exchange
alice_priv, alice_pub = meow_crypto_rs.x25519_generate_keypair()
bob_priv, bob_pub = meow_crypto_rs.x25519_generate_keypair()
shared_secret = meow_crypto_rs.x25519_exchange(alice_priv, bob_pub)
```

## Performance

The Rust backend provides significant speedups over the pure Python implementation:

| Operation | Python | Rust | Speedup |
|-----------|--------|------|---------|
| Argon2id (256MB) | 2.3s | 1.9s | 1.2x |
| AES-GCM 1MB | 12ms | 1.5ms | 8x |
| HMAC-SHA256 | 0.1ms | 0.02ms | 5x |
| X25519 | 0.8ms | 0.1ms | 8x |

## Testing

The crate includes comprehensive test coverage with **206 tests** across five test suites:

```bash
# Run all tests
cargo test -p meow_crypto_rs

# Run individual test suites
cargo test --test comprehensive_tests         # 80 tests - Core functionality
cargo test --test additional_security_tests   # 29 tests - Security edge cases
cargo test --test proptest_crypto             # 23 tests - Property-based fuzzing (original)
cargo test --test property_tests              # 14 tests - Adversarial property tests
cargo test --test ffi_fuzz                    # 19 tests - FFI boundary fuzz
```

### Test Categories

| Suite | Tests | Coverage |
|-------|-------|----------|
| **comprehensive_tests** | 80 | Core crypto operations, integration flows |
| **additional_security_tests** | 29 | Zeroization, failure modes, edge cases |
| **proptest_crypto** | 23 | Property-based testing with random inputs |
| **property_tests** | 14 | Adversarial: nonce uniqueness, ratchet PCS, replay, hybrid combiner, AAD |
| **ffi_fuzz** | 19 | FFI boundary: attacker-controlled inputs, round-trip, concurrent calls |

### Security Tests

- **Zeroization verification** - Ensures sensitive data is zeroed after use
- **Constant-time operations** - Tests for timing attack resistance
- **Failure mode handling** - Invalid inputs rejected correctly
- **Boundary conditions** - Edge cases like empty inputs, max sizes

## Building Wheels

```bash
# Build for current platform
maturin build --release

# Build manylinux wheels
maturin build --release --manylinux 2_17
```

## License

CC BY-NC-SA 4.0 (same as Meow Decoder)
