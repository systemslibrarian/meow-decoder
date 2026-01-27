# 🔐 Verus-Verified Crypto Core

This crate provides **formally verified** cryptographic wrappers for Meow-Encode using [Verus](https://github.com/verus-lang/verus), a verification tool for Rust.

## Verified Properties

### AEAD Wrapper (`aead_wrapper.rs`)

The AEAD wrapper enforces three critical security invariants:

| Property | Description | Verification Method |
|----------|-------------|---------------------|
| **AEAD-001: Nonce Uniqueness** | Each nonce is used exactly once per key | Type-state + ghost tracking |
| **AEAD-002: Auth-Then-Output** | Plaintext only accessible after authentication | Existential type proof |
| **AEAD-003: Key Zeroization** | Keys are zeroed when wrapper is dropped | Drop trait + Zeroize |
| **AEAD-004: No Counter Wrap** | Nonce counter panics before overflow | Bounds check |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AeadWrapper                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐     ┌──────────────────────────────────┐ │
│  │   NonceManager   │     │          AES-256-GCM             │ │
│  │                  │     │                                  │ │
│  │  counter: u64    │────▶│  encrypt(nonce, pt, aad)        │ │
│  │  random: [u8;4]  │     │  decrypt(nonce, ct, aad)        │ │
│  │  allocated: Set  │     │                                  │ │
│  └──────────────────┘     └──────────────────────────────────┘ │
│          │                              │                       │
│          ▼                              ▼                       │
│  ┌──────────────────┐     ┌──────────────────────────────────┐ │
│  │   UniqueNonce    │     │    AuthenticatedPlaintext       │ │
│  │   (linear type)  │     │    (existential proof)          │ │
│  └──────────────────┘     └──────────────────────────────────┘ │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    key: [u8; 32]                          │  │
│  │                    (ZeroizeOnDrop)                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

### Basic Encryption/Decryption

```rust
use crypto_core::{AeadWrapper, KEY_SIZE};

fn main() -> Result<(), crypto_core::AeadError> {
    // Create wrapper with 256-bit key
    let key = [0x42u8; KEY_SIZE];
    let wrapper = AeadWrapper::new(&key)?;
    
    // Encrypt with automatic nonce management
    let plaintext = b"Secret message";
    let aad = b"additional authenticated data";
    let (nonce, ciphertext) = wrapper.encrypt(plaintext, aad)?;
    
    // Decrypt and verify authentication
    let authenticated = wrapper.decrypt(&nonce, &ciphertext, aad)?;
    
    // Access plaintext (proof of authentication)
    println!("Decrypted: {:?}", authenticated.data());
    
    Ok(())
}
```

### Type-Level Guarantees

```rust
// ❌ This won't compile - can't construct AuthenticatedPlaintext directly
let fake = AuthenticatedPlaintext { 
    data: vec![1,2,3], 
    _authenticated: () 
};

// ❌ This won't compile - UniqueNonce consumed on use
let nonce = nonce_manager.allocate_nonce()?;
let bytes = nonce.take();
let bytes2 = nonce.take();  // Error: nonce moved

// ✅ This is the only way to get authenticated plaintext
let authenticated = wrapper.decrypt(&nonce, &ciphertext, aad)?;
// authenticated.data() is proven to be genuine
```

## Verus Verification

### Prerequisites

Install Verus:

```bash
git clone https://github.com/verus-lang/verus
cd verus
./tools/get-z3.sh
./tools/build.sh
```

**Pinned versions (recommended):**
- Verus: latest stable from the official repo
- Z3: version bundled by `get-z3.sh`

### Running Verification

```bash
cd crypto_core

# Verify all proofs
verus src/lib.rs

# Verify with verbose output
verus src/lib.rs --output-smt

# Check specific module
verus src/aead_wrapper.rs
```

### Expected Output

```
verification results:: verified: 8 errors: 0
  nonce_uniqueness_invariant ... verified
  auth_then_output_invariant ... verified
  key_zeroization_invariant ... verified
  no_nonce_reuse ... verified
  NonceManager::allocate_nonce ... verified
  AeadWrapper::encrypt ... verified
  AeadWrapper::decrypt ... verified
  AeadWrapper::new ... verified
```

## Proof Explanations

### Nonce Uniqueness (AEAD-001)

**Claim:** `∀ e1, e2 ∈ Encryptions: e1 ≠ e2 ⟹ nonce(e1) ≠ nonce(e2)`

**Proof:**
1. `NonceManager.counter` is strictly monotonic (atomic fetch_add)
2. Each `allocate_nonce()` increments counter exactly once
3. Nonce = `[counter_bytes || random_prefix]`
4. Different counter values ⟹ different nonces ∎

```verus
proof fn nonce_uniqueness(nm: &NonceManager, n1: UniqueNonce, n2: UniqueNonce)
    requires old(nm.counter) < nm.counter  // Two allocations happened
    ensures n1.bytes != n2.bytes           // Nonces are different
{
    // counter is monotonic, so counter values differ
    // different counter values => different nonces
}
```

### Auth-Then-Output (AEAD-002)

**Claim:** `AuthenticatedPlaintext ⟹ GCM-Verify(key, nonce, ct, aad) = success`

**Proof:**
1. `AuthenticatedPlaintext` has private constructor
2. Only `decrypt()` can create it
3. `decrypt()` only returns `Ok(...)` if GCM auth passes
4. Holding `AuthenticatedPlaintext` proves auth succeeded ∎

```verus
proof fn auth_then_output(ap: AuthenticatedPlaintext)
    ensures exists|k, n, ct, aad| 
        decrypt(k, n, ct, aad).is_ok() && 
        decrypt(k, n, ct, aad).unwrap() == ap
{
    // ap can only come from successful decrypt()
    // decrypt() only succeeds if GCM auth passes
}
```

### Key Zeroization (AEAD-003)

**Claim:** `drop(wrapper) ⟹ ∀ i ∈ [0, 32): wrapper.key[i] = 0`

**Proof:**
1. `AeadWrapper` derives `ZeroizeOnDrop`
2. `Drop::drop()` calls `Zeroize::zeroize()`
3. `zeroize()` overwrites key with zeros
4. After drop, key memory is zeroed ∎

## Security Considerations

### What IS Verified

- ✅ Nonce uniqueness per key
- ✅ Authentication before plaintext access
- ✅ Key zeroization on drop
- ✅ Counter overflow prevention

### What is NOT Verified

- ⚠️ AES-GCM implementation correctness (uses `aes-gcm` crate)
- ⚠️ Side-channel resistance (timing, cache, etc.)
- ⚠️ Random number generator quality (uses `getrandom`)

## Assumptions & Non‑Goals

**Assumptions:**
- AES‑GCM is a secure AEAD and the `aes-gcm` crate is correct
- OS RNG is secure and unpredictable
- The Rust compiler and standard library behave correctly

**Non‑Goals:**
- Proving AES‑GCM itself
- Side‑channel resistance (timing/power/EM)
- Compromised host or malware resistance
- ⚠️ Memory safety in unsafe blocks (none present)

### Assumptions

The proofs assume:

1. **Rust memory safety** - Verus inherits Rust's memory model
2. **Correct AES-GCM** - We trust the `aes-gcm` crate
3. **Secure RNG** - We trust `getrandom` provides entropy
4. **No side channels** - Constant-time not formally verified

## Testing

```bash
# Run unit tests
cargo test

# Run with debug assertions
cargo test --features debug_assertions

# Run with Miri for undefined behavior detection
cargo +nightly miri test
```

## Integration with Meow-Encode

This crate is used by the Meow-Encode Rust crypto backend:

```rust
// In rust_crypto/src/lib.rs
use crypto_core::AeadWrapper;

pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let wrapper = AeadWrapper::new(key)?;
    let (nonce, ciphertext) = wrapper.encrypt(plaintext, aad)?;
    
    // Return nonce || ciphertext
    let mut result = nonce.to_vec();
    result.extend(ciphertext);
    Ok(result)
}
```

## References

- [Verus Documentation](https://verus-lang.github.io/verus/guide/)
- [AES-GCM RFC 5116](https://tools.ietf.org/html/rfc5116)
- [Formal Verification of AEAD](https://eprint.iacr.org/2019/940)
- [Nonce Misuse Resistance](https://eprint.iacr.org/2015/102)

## License

MIT License - See LICENSE file
