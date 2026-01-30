# 🛡️ Side-Channel Hardening Documentation

**Version:** 1.0  
**Date:** 2026-01-30  
**Status:** Implemented (best-effort, not formally verified)

---

## Overview

This document describes the side-channel attack mitigations implemented in Meow Decoder's cryptographic operations.

**Threat Model:** An attacker with:
- Access to timing measurements (local or network-based)
- Cache timing observations (shared CPU cores)
- Memory access pattern visibility (e.g., `/proc` on Linux)

**NOT in scope:** Power analysis, EM emissions, or physical access attacks.

---

## Implemented Mitigations

### 1. Constant-Time Comparisons 🕐

**Attack:** Timing oracle via early-exit comparisons  
**Location:** Password verification, HMAC checks, MAC verification

**Implementation:**
```python
# meow_decoder/crypto.py
import secrets
result = secrets.compare_digest(expected_hmac, manifest.hmac)
```

**Rust Backend:**
```rust
// crypto_core/src/lib.rs
use subtle::ConstantTimeEq;
let equal = a.ct_eq(&b);
```

**Coverage:**
| Operation | Module | Status |
|-----------|--------|--------|
| Password comparison | `crypto.py` | ✅ `secrets.compare_digest` |
| HMAC verification | `crypto.py` | ✅ `secrets.compare_digest` |
| Frame MAC verification | `frame_mac.py` | ✅ `secrets.compare_digest` |
| Duress tag check | `crypto.py` | ✅ `secrets.compare_digest` |
| Rust primitives | `crypto_core` | ✅ `subtle::ConstantTimeEq` |

---

### 2. Timing Equalization ⏱️

**Attack:** Statistical timing analysis to distinguish code paths  
**Location:** Duress password detection, authentication failures

**Implementation:**
```python
# meow_decoder/constant_time.py
def equalize_timing(operation_time: float, target_time: float = 0.1):
    """Sleep to equalize operation timing."""
    if operation_time < target_time:
        sleep_time = target_time - operation_time
        time.sleep(sleep_time)
```

**Usage:**
```python
# After authentication operations
from .constant_time import equalize_timing
equalize_timing(0.001, 0.005)  # 1-5ms random delay
```

**Effectiveness:** Mitigates statistical timing attacks but not precise hardware timing.

---

### 3. Memory-Bound KDF (Argon2id) 🧠

**Attack:** GPU/ASIC-accelerated password cracking  
**Implementation:** Argon2id with hardened parameters

**Parameters (Production):**
```python
# meow_decoder/crypto.py
ARGON2_MEMORY = 524288      # 512 MiB
ARGON2_ITERATIONS = 20      # 20 passes
ARGON2_PARALLELISM = 4      # 4 threads
```

**Side-Channel Benefits:**
- Memory-hard = noisy timing (cache misses dominate)
- High iteration count masks timing variations
- ~5-10 seconds per attempt defeats remote timing attacks

---

### 4. Secure Memory Zeroing 🧹

**Attack:** Key residue in RAM after operations  
**Location:** Key material, passwords, sensitive buffers

**Python Implementation:**
```python
# meow_decoder/constant_time.py
def secure_zero_memory(buffer: Any) -> None:
    """Zero memory buffer in a way compiler can't optimize away."""
    if isinstance(buffer, bytearray):
        size = len(buffer)
        addr = ctypes.addressof((ctypes.c_char * size).from_buffer(buffer))
        ctypes.memset(ctypes.c_void_p(addr), 0, size)
```

**Rust Implementation:**
```rust
// crypto_core/Cargo.toml
zeroize = { version = "1", features = ["derive"] }

// crypto_core/src/lib.rs
use zeroize::Zeroize;
key_material.zeroize();
```

**Context Manager:**
```python
from .constant_time import secure_memory

with secure_memory(password.encode()) as pwd:
    key = derive_key(pwd)
# pwd is now zeroed and unlocked
```

---

### 5. Bitsliced AES (Rust Backend) 🔐

**Attack:** Cache-timing attacks on AES T-tables  
**Implementation:** RustCrypto's `aes-gcm` crate uses bitsliced implementation

```toml
# crypto_core/Cargo.toml
aes-gcm = "0.10"  # Uses bitsliced AES by default
```

**Benefits:**
- No secret-dependent memory lookups
- Constant-time on all platforms
- SIMD acceleration where available

---

### 6. Memory Locking (mlock) 🔒

**Attack:** Key material swapped to disk  
**Location:** Sensitive buffers during crypto operations

```python
# meow_decoder/constant_time.py
class SecureBuffer:
    def __init__(self, size: int):
        self.buffer = bytearray(size)
        # Try to lock in RAM
        if _libc is not None:
            addr = (ctypes.c_char * size).from_buffer(self.buffer)
            result = _libc.mlock(addr, size)
            self.locked = (result == 0)
```

**Platform Support:**
| Platform | Status |
|----------|--------|
| Linux | ✅ Full support (requires CAP_IPC_LOCK for >64KB) |
| macOS | ⚠️ Partial (mlock available but limits vary) |
| Windows | ❌ Not implemented (use VirtualLock API) |

---

## Rust Backend (`subtle` Crate)

The Rust crypto backend uses the `subtle` crate for constant-time primitives:

```toml
# crypto_core/Cargo.toml
subtle = "2.5"
```

**Primitives:**
- `subtle::ConstantTimeEq` - Constant-time equality
- `subtle::ConditionallySelectable` - Constant-time select
- `subtle::Choice` - Boolean without branches

**Example:**
```rust
use subtle::{Choice, ConstantTimeEq};

fn verify_tag(expected: &[u8], actual: &[u8]) -> Choice {
    expected.ct_eq(actual)
}
```

---

## Test Coverage

Side-channel tests are in `tests/test_sidechannel.py`:

```bash
# Run side-channel test suite
make sidechannel-test

# Or directly:
pytest tests/test_sidechannel.py -v
```

**Test Classes:**
| Test | Description |
|------|-------------|
| `TestConstantTimeComparison` | Verifies password/HMAC comparison timing |
| `TestFrameMACTiming` | Tests frame MAC verification consistency |
| `TestKeyDerivationTiming` | Validates Argon2id timing stability |
| `TestDuressTimingEqualization` | Ensures duress detection has no timing leak |
| `TestSecureMemoryZeroing` | Verifies `secure_zero_memory()` works |
| `TestNoEarlyExit` | Confirms no length-based early exit leakage |
| `TestRustBackendSideChannel` | Validates subtle/zeroize crate usage |

---

## Limitations & Honest Assessment

### What's Protected ✅

- **Password comparison timing** - secrets.compare_digest
- **HMAC/MAC verification timing** - constant-time
- **Key material in RAM** - best-effort zeroing
- **AES implementation** - bitsliced (no T-tables)
- **Brute-force attacks** - Argon2id memory-hardness

### What's NOT Protected ❌

| Attack | Reason | Mitigation Path |
|--------|--------|-----------------|
| **Python GC timing** | Garbage collector is not constant-time | Use Rust for hot paths |
| **OS scheduling** | Thread preemption affects timing | Not controllable |
| **JIT compilation** | PyPy JIT creates timing variance | CPython only |
| **Power analysis** | Requires hardware countermeasures | Use SCA-resistant hardware |
| **EM emissions** | Requires shielding | Faraday cage |
| **Cache timing (Python)** | Python memory access is not constant-time | Rust backend |

### Recommendations for High-Security Use

1. **Use Rust backend exclusively** (constant-time guarantees)
2. **Run on dedicated hardware** (no shared caches)
3. **Disable swap** or use encrypted swap
4. **Use mlock** for key material (run with CAP_IPC_LOCK)
5. **Disable core dumps** (`ulimit -c 0`)

---

## Cat-Themed Security Reminders 🐱

```
😺 "A cat always lands on its feet, and your keys always land in zeroed memory."

🐱 "Nine lives means nine layers of defense - timing attacks are just life #3."

😸 "Even the sneakiest timing attack can't catch a constant-time cat."

🙀 "If your secrets leak through timing, you're not a ninja cat, you're a clumsy kitten."
```

---

## References

- [BearSSL Constant-Time Crypto](https://bearssl.org/constanttime.html)
- [subtle crate documentation](https://docs.rs/subtle)
- [Argon2 Reference Implementation](https://github.com/P-H-C/phc-winner-argon2)
- [CRYPTO_SECURITY_REVIEW.md](../CRYPTO_SECURITY_REVIEW.md) - Internal security review
- [THREAT_MODEL.md](THREAT_MODEL.md) - Full threat model

---

**Last Updated:** 2026-01-30  
**Maintainer:** Meow Decoder Security Team 🐾
