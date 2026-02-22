# Meow Decoder - Capability Inventory & File Dependencies

**Last Updated:** February 22, 2026

This document maps each capability to the specific files required for that functionality, enabling independent auditing of each feature.

---

## 1. Core Encryption/Decryption (AES-256-GCM + Argon2id)

**Files Required:**
- `meow_decoder/crypto.py` - Main encryption/decryption implementation
- `meow_decoder/crypto_backend.py` - Backend selection (Rust/Python)
- `crypto_core/src/lib.rs` - Rust crypto backend (PyO3)
- `crypto_core/src/crypto.rs` - Rust AES-GCM implementation
- `crypto_core/src/argon2.rs` - Rust Argon2id implementation
- `crypto_core/src/secure_alloc.rs` - Secure memory allocation
- `meow_decoder/argon2_presets.py` - Argon2 parameter presets
- `meow_decoder/constant_time.py` - Constant-time operations

**Key Functions:**
- `encrypt_file_bytes()` - Encrypt data with password
- `decrypt_to_raw()` - Decrypt to raw bytes
- `pack_manifest()` / `unpack_manifest()` - Manifest serialization

**Tests:**
- `tests/test_crypto.py`
- `tests/test_crypto_backend.py`

---

## 2. Forward Secrecy (X25519 ECDH)

**Files Required:**
- `meow_decoder/forward_secrecy.py` - X25519 key exchange
- `meow_decoder/x25519_forward_secrecy.py` - Extended X25519 implementation
- `meow_decoder/crypto.py` - Integration with encryption
- `meow_decoder/encode.py` - `--receiver-pubkey` flag handling

**Key Functions:**
- `generate_keypair()` - Generate X25519 keypair
- `derive_shared_secret()` - ECDH key exchange with transcript binding
- `forward_secrecy_encrypt()` / `forward_secrecy_decrypt()` - Encrypt/decrypt with FS

**Manifest Version:** MEOW3 (mode_byte=0x03)

**Tests:**
- `tests/test_forward_secrecy.py`
- `tests/test_x25519_forward_secrecy.py`

---

## 3. Post-Quantum Hybrid (ML-KEM-768/1024 + X25519)

**Files Required:**
- `meow_decoder/pq_hybrid.py` - PQXDH-style hybrid KEM
- `meow_decoder/forward_secrecy.py` - Classical component
- `meow_decoder/crypto.py` - Integration
- `meow_decoder/encode.py` - `--pq` and `--pq-paranoid` flags

**Key Functions:**
- `generate_pq_keypair()` - Generate ML-KEM + X25519 keypairs
- `pq_encapsulate()` - Hybrid encapsulation
- `pq_decapsulate()` - Hybrid decapsulation
- Two-step HKDF with full transcript binding

**Manifest Versions:**
- MEOW5 (ML-KEM-768, default) - mode_byte=0x05
- MEOW4 (ML-KEM-1024, paranoid) - mode_byte=0x04

**Tests:**
- `tests/test_pq_hybrid.py`
- `tests/test_e2e_crypto_fountain.py`

---

## 4. Manifest Signing (Ed25519 + ML-DSA-65)

**Files Required:**
- `meow_decoder/manifest_signing.py` - Hybrid signature implementation
- `meow_decoder/encode.py` - Sign manifest during encoding
- `meow_decoder/decode_gif.py` - Verify signature during decoding
- `meow_decoder/crypto_backend.py` - Backend selection

**Key Functions:**
- `generate_signing_keypair()` - Generate Ed25519 + ML-DSA keypairs
- `sign_manifest()` - Hybrid signature (Ed25519 || ML-DSA-65)
- `verify_manifest()` - Verify both signatures
- Backend support: Rust (primary), OQS (secondary), Pure Python (tertiary)

**Security Effect:** Authenticity and integrity protection

**Tests:**
- `tests/test_manifest_signing.py`
- `tests/test_security_hardening.py::test_manifest_signing_roundtrip`

---

## 5. QR Code Generation/Parsing

**Files Required:**
- `meow_decoder/encode.py` - QR generation (uses `qrcode` library)
- `meow_decoder/decode_gif.py` - QR scanning (uses `pyzbar` library)
- External dependencies: `qrcode[pil]`, `pyzbar`

**Key Functions:**
- `qrcode.QRCode()` - Generate QR codes
- `pyzbar.decode()` - Scan QR codes from images

**Parameters:**
- Version: Auto-selected based on data size
- Error correction: L (low, 7% recovery)
- Size: 600×600 pixels default

---

## 6. Fountain Codes (Luby Transform Rateless Codes)

**Files Required:**
- `meow_decoder/fountain.py` - Python LT implementation
- `examples/fountain-codes.js` - JavaScript implementation (web demo)
- `meow_decoder/encode.py` - Encoder integration
- `meow_decoder/decode_gif.py` - Decoder integration

**Key Classes:**
- `FountainEncoder` - Generate unlimited droplets
- `FountainDecoder` - Reconstruct from any ~1.5× k droplets
- `RobustSolitonDistribution` - Optimal degree distribution

**Frame Format:**
```
FOUNTAIN:<k_blocks>:<block_size>:<original_length>:<base64_droplet>
```

**Security:** Operates on encrypted ciphertext, information-theoretic erasure codes

**Tests:**
- `tests/test_fountain.py`
- `examples/test_fountain.html` (browser-based)

---

## 7. Steganography (LSB Embedding)

**Files Required:**
- `meow_decoder/stego_advanced.py` - Advanced LSB steganography
- `meow_decoder/stego_multilayer.py` - Multi-layer embedding
- `meow_decoder/stego_gif_binary.py` - Binary data embedding
- `meow_decoder/encode.py` - `--stego-level` flag (0-4)
- `meow_decoder/decode_gif.py` - LSB extraction

**Key Classes:**
- `AdvancedStegoEncoder` - Embed with quality validation
- `AdvancedStegoDecoder` - Extract QR codes from stego images

**Stealth Levels:**
- 0: Visible QR codes (no stego)
- 1: Subtle (2-bit LSB)
- 2: Subtle (2-bit LSB)
- 3: Hidden (1-bit LSB)
- 4: Paranoid (1-bit LSB + obfuscation + adversarial carriers)

**Tests:**
- `tests/test_stego_advanced.py`

---

## 8. Adversarial Carrier Generation ⭐ NEW

**Files Required:**
- `meow_decoder/adversarial_carrier.py` - Noise generation
- `meow_decoder/stego_advanced.py` - Integration (paranoid mode)

**Key Functions:**
- `adversarial_embed()` - Apply noise to carrier images
- `generate_sensor_noise()` - Mimic camera sensor noise
- `generate_texture_noise()` - Texture-based noise
- `apply_dct_matching()` - DCT coefficient matching
- Algorithm rotation: sensor → texture → dct → combined

**Security Effect:** Defeats statistical steganalysis (χ² tests, pairs tests)

**Activated:** Automatically in `--stego-level 4` (paranoid mode)

---

## 9. Schrödinger Mode (Dual-Secret Deniability)

**Files Required:**
- `meow_decoder/schrodinger_encode.py` - Dual-secret encoder
- `meow_decoder/quantum_mixer.py` - Quantum superposition mixing
- `meow_decoder/decoy_generator.py` - Decoy data generation
- `meow_decoder/duress_mode.py` - Duress password handling

**Key Concept:**
- Two completely separate secrets in one GIF
- `QuantumNoise = XOR(Hash(Pass_A), Hash(Pass_B))`
- Merkle tree integrity, entropy tests

**Usage:**
```bash
python -m meow_decoder.schrodinger_encode -i secret.pdf -i2 decoy.txt \
    -p1 "real_pass" -p2 "decoy_pass" -o dual.gif
```

**Tests:**
- `tests/test_schrodinger.py`

---

## 10. Duress Mode

**Files Required:**
- `meow_decoder/duress_mode.py` - Duress detection and actions
- `meow_decoder/encode.py` - `--duress-password` flag
- `meow_decoder/decode_gif.py` - Duress trigger detection

**Key Features:**
- Emergency wipe on duress password
- Triggers forensic cleanup
- Requires forward secrecy (prevents manifest size collision)

**Security Effect:** Coercion resistance

**Tests:**
- `tests/test_duress_mode.py`

---

## 11. Ratcheting (MSR v1.2 - Per-Frame Forward Secrecy)

**Files Required:**
- `meow_decoder/ratchet.py` - Symmetric hash ratchet
- `meow_decoder/pq_ratchet_beacon.py` - PQ KEM beacons (ML-KEM-1024)
- `meow_decoder/frame_mac.py` - Frame authentication

**Key Features:**
- Signal-inspired symmetric hash ratchet
- HKDF-SHA256 chain with 10 domain separation constants
- Header encryption (frame index XOR masking)
- Key commitment tags (16 bytes, prevents invisible salamanders)
- Rekey beacons (X25519 or ML-KEM-1024)
- Out-of-order support (skip key cache, max 2000)
- Key zeroization after use

**Frame Format:**
```
[encrypted_index(4)] [commitment(16)] [beacon?(32)] [AES-GCM ciphertext+tag]
```

**Tests:**
- `tests/test_ratchet.py` (142 unit tests)
- `tests/test_e2e_crypto_fountain.py` (23 E2E tests)

---

## 12. Shamir Secret Sharing ⭐ NEW

**Files Required:**
- `meow_decoder/shamir_split.py` - Shamir split/combine
- `meow_decoder/encode.py` - `--shamir-split` flag integration

**Key Features:**
- GF(2^8) arithmetic
- Authenticated share-set metadata (16-byte `set_id` v2)
- Prevents mix-and-match attacks
- CLI: `meow-shamir split/combine`

**Usage:**
```bash
# Split during encoding (2-of-3 threshold)
meow-encode -i secret.pdf -o output.gif --shamir-split 2 3 -p "password"

# Combine shares
meow-shamir combine -i share_*_1of3.meow share_*_2of3.meow -o recovered.gif
```

**Tests:**
- `tests/test_shamir_split.py`

---

## 13. Mouse Gesture Authentication

**Files Required:**
- `meow_decoder/secure_keyboard.py` - MouseGesturePassword class
- `meow_decoder/encode.py` - `--password-mode mouse-gesture` integration
- `meow_decoder/decode_gif.py` - Password mode integration

**Key Features:**
- Grid quantization (16×16 default)
- BLAKE2b(person=b"meow_gesture_v1") derivation
- GUI mode (tkinter canvas)
- CLI mode (coordinate input)

**Security Effect:** Keylogger-resistant password entry

**Tests:**
- `tests/test_phase5_modules.py`
- `tests/test_security_hardening.py::test_mouse_gesture_deterministic`

---

## 14. Tamper Detection

**Files Required:**
- `meow_decoder/tamper_detection.py` - Active integrity checks
- `scripts/pyinstaller_runtime_hook.py` - Startup tamper check
- `meow_decoder/tamper_report.py` - Tamper reporting

**Key Features:**
- SHA-256 file hashing
- Fail-closed decorator (raises RuntimeError immediately)
- Runtime hook exits on detected tampering
- Optional poisoning mode (return fake data)

**Security Effect:** Prevents execution of tampered code

**Tests:**
- `tests/test_tamper_detection.py`
- `tests/test_security_hardening.py::test_tamper_detection_fails_closed`

---

## 15. Memory Protection

**Files Required:**
- `meow_decoder/memory_guard.py` - Python memory locking
- `crypto_core/src/secure_alloc.rs` - Rust secure allocation
- `meow_decoder/constant_time.py` - Constant-time operations

**Key Features:**
- Windows: VirtualLock + VirtualProtect
- Unix: mlock + mprotect
- Fail-closed per-buffer: `require_locked_buffer()`
- Fail-closed process-wide: `require_memory_guard()`
- Warn-only process-wide: `activate_memory_guard()`
- Secure memory wiping

**Tests:**
- `tests/test_memory_guard.py`
- `tests/test_security_hardening.py::test_memory_lock_helper_fail_closed`
- `tests/test_security_hardening.py::test_require_memory_guard_exists_and_fail_closed`

---

## 16. Hardware Key Support (YubiKey/HSM)

**Files Required:**
- `meow_decoder/yubikey_integration.py` - YubiKey HMAC-SHA1 challenge-response
- `meow_decoder/hardware_binding.py` - Hardware key derivation
- `meow_decoder/encode.py` - `--yubikey`, `--hardware-key` flags
- `meow_decoder/decode_gif.py` - Hardware key integration

**Supported Modes:**
- YubiKey Challenge-Response (HMAC-SHA1)
- Pre-derived hardware keys (HSM/TPM)
- Combined with password or standalone

**Tests:**
- `tests/test_yubikey.py`

---

## 17. Dead Man's Switch

**Files Required:**
- `meow_decoder/deadmans_switch.py` - Core DMS logic
- `meow_decoder/deadmans_switch_cli.py` - CLI state management
- `meow_decoder/encode.py` - `--dead-mans-switch` flag

**Key Features:**
- Periodic check-in requirement
- Grace period before deadline
- Auto-release decoy on timeout
- State persistence

**Usage:**
```bash
meow-encode -i secret.pdf -o output.gif --dead-mans-switch 24h
meow-deadmans-switch renew --gif output.gif
```

**Tests:**
- `tests/test_deadmans_switch.py`

---

## 18. Keyfile Support

**Files Required:**
- `meow_decoder/encode.py` - `--keyfile` flag
- `meow_decoder/decode_gif.py` - Keyfile integration
- `meow_decoder/crypto.py` - Keyfile mixing with password

**Key Features:**
- Binary keyfile (any size)
- HKDF-based mixing with password
- Domain separation: "meow_keyfile_v1"

**Usage:**
```bash
meow-encode -i secret.pdf -o output.gif -p "password" --keyfile key.bin
meow-decode-gif -i output.gif -o output.pdf -p "password" --keyfile key.bin
```

---

## 19. Logo-Eyes Carrier Mode

**Files Required:**
- `meow_decoder/logo_eyes.py` - Logo-eyes carrier generation
- `meow_decoder/encode.py` - `--logo-eyes` flag
- `meow_decoder/gif_handler.py` - GIF generation
- `assets/demo_logo_eyes.gif` - Bundled carrier

**Key Features:**
- Branded animation with data in cat eyes
- Visible QR codes by default
- Hidden mode: `--logo-eyes-hidden` (LSB stego in eyes)
- Custom brand text: `--brand-text "TEXT"`

**Security Note:** Cosmetic only, does not hide QR presence from steganalysis

---

## 20. Environment Safety Checks

**Files Required:**
- `meow_decoder/env_safety.py` - Environment validation
- `meow_decoder/__main__.py` - Strict isolation gate
- `meow_decoder/isolation_hardening.py` - Isolation enforcement

**Key Functions:**
- `check_isolation()` - Detect VMs, debuggers
- `require_safe_environment()` - Fail-closed environment validation
- `MEOW_STRICT_ISOLATION=1` - Mandatory isolation checks

**Security Effect:** Protects against forensic analysis environments

**Tests:**
- `tests/test_env_safety.py`

---

## 21. GIF Encoding/Decoding Pipeline

**Files Required:**
- `meow_decoder/encode.py` - Main encoder (1863 lines)
- `meow_decoder/decode_gif.py` - Main decoder (1470 lines)
- `meow_decoder/gif_handler.py` - GIF file operations
- `meow_decoder/config.py` - Encoding configuration

**Key Parameters:**
- `fps`: Frame rate (default 10 FPS)
- `qr_version`: Auto-selected
- `block_size`: Fountain code block size (default 800 bytes)
- `redundancy`: Fountain redundancy (default 1.5×)

**Entry Points:**
- `meow-encode` CLI
- `meow-decode-gif` CLI

---

## 22. Webcam/Camera Scanning

**Files Required:**
- `meow_decoder/air_gap.py` - Webcam QR scanning
- `meow_decoder/decode_gif.py` - Frame processing
- External dependency: `opencv-python`

**Key Features:**
- Real-time QR code scanning
- Fountain code reconstruction
- Auto-detection of QR codes

**Tests:**
- `tests/test_air_gap.py`

---

## 23. Size Normalization (Traffic Analysis Resistance)

**Files Required:**
- `meow_decoder/size_normalizer.py` - Size normalization
- `meow_decoder/crypto.py` - Length padding

**Key Features:**
- Pads to nearest power of 2 or fixed size
- Prevents size-based fingerprinting

---

## 24. Expiry & Time-Lock

**Files Required:**
- `meow_decoder/expiry.py` - Expiry time enforcement
- `meow_decoder/timelock_duress.py` - Time-lock puzzles

**Key Features:**
- Expiry timestamp in manifest
- Fails to decrypt after expiry
- Optional time-lock cryptography

**Tests:**
- `tests/test_expiry.py`

---

## 25. Forensic Cleanup

**Files Required:**
- `meow_decoder/forensic_cleanup.py` - Secure file wiping
- `meow_decoder/source_cleanup.py` - Source file cleanup
- `meow_decoder/high_security.py` - High-security mode

**Key Features:**
- DoD 5220.22-M standard wiping (7-pass)
- Metadata scrubbing
- Temp file cleanup

---

## 26. Configuration & Presets

**Files Required:**
- `meow_decoder/config.py` - EncodingConfig, MeowConfig
- `meow_decoder/argon2_presets.py` - KDF parameter presets

**Key Classes:**
- `EncodingConfig` - Encoding parameters
- `MeowConfig` - Global configuration

---

## 27. Testing Infrastructure

**Test Files:**
- `tests/test_crypto.py` - Core crypto tests
- `tests/test_encode.py` - Encoding tests
- `tests/test_decode_gif.py` - Decoding tests
- `tests/test_fountain.py` - Fountain code tests
- `tests/test_forward_secrecy.py` - Forward secrecy tests
- `tests/test_pq_hybrid.py` - Post-quantum tests
- `tests/test_ratchet.py` - Ratchet tests (142 tests)
- `tests/test_shamir_split.py` - Shamir tests
- `tests/test_security_hardening.py` - Security regression tests ⭐ NEW
- `tests/test_e2e_crypto_fountain.py` - End-to-end tests (23 tests)
- `tests/test_adversarial.py` - Adversarial tests

**Test Commands:**
```bash
# All tests
pytest tests/ -v

# Security hardening tests
pytest tests/test_security_hardening.py -v

# Coverage
pytest tests/ --cov=meow_decoder --cov-report=html
```

---

## 28. Web Demo (Browser-Based)

**Files Required:**
- `examples/wasm_browser_example.html` - Full web demo
- `examples/fountain-codes.js` - JS fountain implementation (414 lines)
- `examples/jsQR.js` - JS QR decoder
- `examples/qrcode.min.js` - JS QR encoder
- `examples/crypto_core.js` - WASM crypto bindings

**Key Features:**
- Webcam QR scanning in browser
- Real-time fountain code decoding
- No server required (offline-capable)

---

## 29. Formal Verification (Partial)

**Files Required:**
- `formal/tla/meow_protocol.tla` - TLA+ specification
- `formal/proverif/meow.pv` - ProVerif protocol model
- `formal/tamarin/meow.spthy` - Tamarin model

**Scope:**
- Protocol state machine
- Key exchange properties
- Manifest integrity

**Limitations:**
- No timing side-channel coverage
- No secure_alloc formal proof
- No expiry protocol proof

---

## 30. Build & Distribution

**Files Required:**
- `meow_decoder.spec` - PyInstaller spec
- `pyproject.toml` - Python package config
- `Cargo.toml` - Rust workspace config
- `crypto_core/Cargo.toml` - Rust crypto core
- `Makefile` - Build automation
- `Dockerfile` - Docker build
- `docker-compose.yml` - Integration tests

**Entry Points (pyproject.toml):**
- `meow-encode` → `meow_decoder.encode:main`
- `meow-decode-gif` → `meow_decoder.decode_gif:main`
- `meow-shamir` → `meow_decoder.shamir_split:main` ⭐ NEW

---

## Dependency Chart

### Core Dependencies
```
meow_decoder/
├── crypto.py ────────────┐
├── crypto_backend.py ────┤
├── encode.py ────────────┤── Core Pipeline
├── decode_gif.py ────────┤
└── config.py ────────────┘

crypto_core/ ────────────────── Rust Backend (PyO3)
├── src/crypto.rs           # AES-GCM
├── src/argon2.rs           # Argon2id
└── src/secure_alloc.rs     # Memory protection
```

### Feature Modules
```
Forward Secrecy:
├── forward_secrecy.py
└── x25519_forward_secrecy.py

Post-Quantum:
├── pq_hybrid.py
└── pq_ratchet_beacon.py

Signing:
└── manifest_signing.py

Fountain Codes:
└── fountain.py

Steganography:
├── stego_advanced.py
├── adversarial_carrier.py ⭐ NEW
└── stego_multilayer.py

Deniability:
├── schrodinger_encode.py
├── quantum_mixer.py
└── duress_mode.py

Ratchet:
├── ratchet.py
├── frame_mac.py
└── pq_ratchet_beacon.py

Shamir:
└── shamir_split.py ⭐ NEW

Authentication:
└── secure_keyboard.py

Security:
├── tamper_detection.py
├── memory_guard.py
└── env_safety.py
```

---

## Audit Checklist

For each capability you want to audit:

1. **Read Core Files** - Start with the main implementation
2. **Check Tests** - Run relevant test suite
3. **Review Integration** - Check how it's wired into encode/decode
4. **Security Review** - Check for insecure fallbacks, fail-open behavior
5. **Documentation** - Verify claims match implementation

**Example Audit Flow for Shamir Splitting:**
```bash
# 1. Read implementation
cat meow_decoder/shamir_split.py

# 2. Run tests
pytest tests/test_shamir_split.py -v

# 3. Check integration
grep -n "shamir" meow_decoder/encode.py

# 4. Test CLI
meow-shamir --help
meow-encode --help | grep shamir

# 5. Verify cryptographic properties
# - GF(2^8) arithmetic correctness
# - Set ID uniqueness
# - Mix-and-match prevention
```

---

## Recent Changes (This Session)

### Files Modified:
1. `meow_decoder/manifest_signing.py` - Removed insecure stubs
2. `meow_decoder/pq_ratchet_beacon.py` - Removed insecure stubs
3. `meow_decoder/tamper_detection.py` - Fail-closed decorator
4. `meow_decoder/encode.py` - Mandatory signing + Shamir integration
5. `meow_decoder/secure_keyboard.py` - Fixed duplicate methods
6. `meow_decoder/adversarial_carrier.py` - Added adversarial_embed() ⭐
7. `meow_decoder/stego_advanced.py` - Adversarial carrier rotation ⭐
8. `meow_decoder/shamir_split.py` - Authenticated share-set metadata ⭐
9. `tests/test_security_hardening.py` - 9 regression tests ⭐
10. `pyproject.toml` - Added meow-shamir entry point

### New Capabilities Added:
- ⭐ Adversarial carrier generation with algorithm rotation
- ⭐ Shamir secret sharing with authenticated metadata
- ⭐ Comprehensive security hardening regression tests

---

## Total File Count

- **Python Modules:** ~60 files in `meow_decoder/`
- **Rust Crates:** 1 workspace with `crypto_core/`
- **Tests:** ~30 test files in `tests/`
- **Examples:** ~10 demo files in `examples/`
- **Documentation:** ~15 docs in `docs/`
- **Build Files:** Makefile, Dockerfile, pyproject.toml, Cargo.toml, etc.

**Total Lines of Code:** ~45,000+ (Python + Rust + JavaScript)

---

## Quick Reference: File → Capability Mapping

| File | Primary Capabilities |
|------|---------------------|
| `crypto.py` | Encryption, Decryption, Manifest handling |
| `encode.py` | Main encoding pipeline, CLI, all integrations |
| `decode_gif.py` | Main decoding pipeline, CLI, verification |
| `fountain.py` | Rateless erasure coding |
| `forward_secrecy.py` | X25519 key exchange |
| `pq_hybrid.py` | ML-KEM + X25519 hybrid KEM |
| `manifest_signing.py` | Ed25519 + ML-DSA signatures |
| `ratchet.py` | Per-frame forward secrecy |
| `shamir_split.py` | Shamir secret sharing ⭐ |
| `adversarial_carrier.py` | Steganalysis resistance ⭐ |
| `stego_advanced.py` | LSB steganography |
| `secure_keyboard.py` | Mouse gesture auth |
| `tamper_detection.py` | Integrity protection |
| `memory_guard.py` | Memory locking |
| `schrodinger_encode.py` | Dual-secret deniability |

---

**End of Inventory**

For questions or to report missing capabilities, see [CONTRIBUTING.md](CONTRIBUTING.md).
