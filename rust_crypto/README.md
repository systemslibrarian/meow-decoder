# meow_crypto_rs - Rust Crypto Backend for Meow Decoder

High-performance cryptographic primitives for Meow Decoder, written in Rust
with Python bindings via PyO3.

## Features

- **Argon2id KDF** - Memory-hard password hashing
- **AES-256-GCM** - Authenticated encryption with associated data
- **HKDF** - HMAC-based Key Derivation Function
- **HMAC-SHA256** - Keyed-hash message authentication
- **X25519** - Elliptic curve Diffie-Hellman
- **ML-KEM-768** - Post-quantum key encapsulation (optional)
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

## Building Wheels

```bash
# Build for current platform
maturin build --release

# Build manylinux wheels
maturin build --release --manylinux 2_17
```

## License

MIT OR Apache-2.0 (same as Meow Decoder)
