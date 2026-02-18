# 🐾 Changelog — The Cat's Journal

All notable purr-ogress in Meow Decoder, tracked by the clowder.

> **Version Note:** The public release is **v1.0.0 (SECURITY-REVIEWED v1.0 INTERNAL REVIEW)**.
> The version numbers below (5.x, 6.x) are historical internal development milestones
> that have been consolidated into the v1.0 public release.
>
> *"Every commit is a paw print in the litter box of history."*

## [Unreleased]

### Infrastructure — Rust Crypto Fuzzing + Property Test Suite (2026-02-18) 🔐

Full adversarial testing infrastructure for the Rust crypto backend: cargo-fuzz targets, proptest property tests, FFI boundary fuzz harness, panic hardening, and CI integration.

#### cargo-fuzz Targets (`rust_crypto/fuzz/fuzz_targets/`)
| Target | Attack Classes |
|--------|----------------|
| `fuzz_decrypt_frame` | Nonce reuse, Truncation oracle, Partial decrypt leak |
| `fuzz_header_parse` | Header tampering, AAD omission, Nonce reuse |
| `fuzz_hybrid_decapsulate` | Hybrid downgrade, PQ failure fallback, State compromise |
| `fuzz_ratchet_step` | Replay, Nonce reuse, PCS violation |
| `fuzz_full_decode_pipeline` | Partial decrypt leak, Truncation oracle, Replay |

#### Property Tests (`rust_crypto/tests/property_tests.rs`) — 14 tests
- Nonce uniqueness across N frames
- Ratchet monotonicity
- Replay rejection
- PCS healing (post-compromise forward secrecy verified)
- Hybrid combiner requires both classical + PQ secrets
- AAD canonicalization determinism
- Manifest binding integrity
- Fail-closed AEAD (no partial plaintext on auth failure)
- Commitment tag prevents forgery
- Argon2id domain separation
- Decryption fail-closed
- X25519 symmetry and uniqueness
- HKDF domain separation

#### FFI Boundary Fuzz (`rust_crypto/tests/ffi_fuzz.rs`) — 19 tests
- Random, zero, 0xFF, small, large, truncated, reordered byte arrays
- Corrupted PQ ciphertext, wrong salt, wrong version, zero HMAC tag
- Argon2id invalid params, HKDF zero-length output, X25519 bad key lengths
- Concurrent FFI calls (data race detection)
- encode→decode round-trip correctness for 5 payload sizes
- 1000-cycle repeated encode/decode (no memory leak / crash)

#### Bug Fixes
- **`ffi_roundtrip_various_sizes`**: encode used `b"roundtrip_pass"`, decode hardcoded `b"fuzz_password"` — HMAC always failed. Fixed with `ffi_simulate_decode_gif_with_password()` using matching credentials.
- **`p_pcs_healing`**: Ratchet HKDF info embedded loop index starting at 0 for the adversary, but honest party used absolute step index. Adversary keys never matched. Fixed with `ratchet_steps_from(root, start_step, n)` preserving absolute indices.
- **AAD asymmetry**: Encoder used `sha256(plaintext)` in AAD, decoder used `sha256(ciphertext)` — structurally impossible to verify. Fixed: AAD is now `magic(4) || salt(16) || mode(1)` only — stable and reproducible on both sides.

#### CI (`rust-security-suite.yml`)
- Runs on push to `main`/`develop` touching `rust_crypto/**` or `crypto_core/**`
- Weekly extended fuzz on schedule (Sunday 02:00 UTC)
- Jobs: unit+property+FFI tests, cargo-fuzz (5 targets, matrix), ASan+UBSan, Miri (schedule-only), panic hardening audit
- `panic = "abort"` verified in release profile; `clippy::unwrap_used` lint in crypto paths
- Fuzz corpus persisted across runs via Actions cache

#### Test Count
- **Before**: 173 Rust tests (41 pure + 80 comprehensive + 29 additional_security + 23 proptest_crypto)
- **After**: 206 Rust tests (+14 property_tests + 19 ffi_fuzz)

### Infrastructure — Rust Crypto Migration Complete (2026-02-17) 🦀

**Full 5-phase migration of all secret-handling cryptography from Python → Rust is complete.**

All core cryptographic operations now route through the Rust `meow_crypto_rs` backend with PyO3 bindings, ensuring constant-time operations via the `subtle` crate and secure zeroing via the `zeroize` crate.

#### Migration Summary
- **Phase 1: Audit & Inventory** — Mapped 105 `cryptography` imports across 28 files, 48 `hmac`/`hashlib` sites, 42 constant-time compare sites, 126 zeroization paths
- **Phase 2: Rust Backend Extension** — All primitives implemented in `crypto_core/`: Argon2id, HKDF-SHA256, AES-256-GCM, X25519, HMAC-SHA256, SHA-256, ML-KEM-768/1024
- **Phase 3: Python Migration** — 12 core modules migrated: `crypto.py`, `crypto_backend.py`, `crypto_enhanced.py`, `x25519_forward_secrecy.py`, `forward_secrecy.py`, `pq_hybrid.py`, `ratchet.py`, `double_ratchet.py`, `constant_time.py`, `frame_mac.py`, `streaming_crypto.py`
- **Phase 4: Test Migration** — 397 tests passing (383 protocol tests + 14 enforcement tests including 5 key lifecycle tests)
- **Phase 5: CI Enforcement** — `RUST_BACKEND_REQUIRED=1` environment gate, import-ban linter, golden vector regression

#### Rust Backend Functions (16 PyO3 bindings)
```
derive_key_argon2id, derive_key_hkdf, hkdf_extract, hkdf_expand,
aes_gcm_encrypt, aes_gcm_decrypt, aes_ctr_crypt, hmac_sha256,
hmac_sha256_verify, sha256, x25519_generate_keypair, x25519_exchange,
x25519_public_from_private, constant_time_compare, secure_zero, secure_random
```

#### New Enforcement Tests (`tests/test_crypto_enforcement.py`)
| Test Class | Purpose |
|-----------|---------|
| `TestPythonCryptoBan` | AST scan for forbidden `cryptography` imports |
| `TestRustBackendRequired` | Verifies `meow_crypto_rs` imports successfully |
| `TestGoldenVectors` | SHA-256, HMAC-SHA256, AES-CTR frozen vectors |
| `TestHKDFGoldenVector` | HKDF-SHA256 frozen vectors |
| `TestConstantTimeRouting` | Verifies `constant_time_compare()` routes to Rust |
| `TestKeyLifecycle` | `secure_zero`, X25519 keygen/exchange, AES-GCM AAD |

#### Security Guarantees
- **Constant-time comparisons**: All auth tag/HMAC verification via `subtle::ConstantTimeEq`
- **Secure zeroing**: All secrets zeroized on drop via `zeroize` crate
- **No Python fallback**: CI fails if Rust backend unavailable (`RUST_BACKEND_REQUIRED=1`)
- **Golden vector parity**: Python and Rust outputs byte-for-byte identical

### Security — PQXDH Upgrade: Signal 2026 Post-Quantum Alignment 🔐

**ML-KEM-768 default** (Signal PQXDH parity) with **ML-KEM-1024 --paranoid** option. Full PQXDH-style two-step HKDF transcript binding replaces the previous single-step derivation.

#### ML-KEM Variant Selection
- Default changed from ML-KEM-1024 (Kyber1024) to **ML-KEM-768** (Kyber768) — matches Signal's PQXDH choice
- ML-KEM-1024 retained as `--paranoid` mode (NIST Level 5) via `pq_paranoid=True`
- New manifest version **MEOW5** (`mode_byte=0x05`) for ML-KEM-768 (ct=1088 bytes, pk=1184 bytes)
- MEOW4 (`mode_byte=0x04`) retained for backward-compatible ML-KEM-1024 (ct=1568 bytes)

#### PQXDH Two-Step HKDF Transcript Binding
- **Extract**: `PRK = HMAC-SHA256(salt=0x00*32, IKM=classical_ss || pq_ss)`
- **Expand**: `HKDF-Expand(PRK, info="meow_pqxdh_v1" || transcript_hash, L=32)`
- Replaces old single-step `HKDF(info="meow_hybrid_pq_v1")` with no transcript binding
- Transcript hash: `SHA256("meow_pqxdh_transcript_v1" || eph_pub || recv_classical_pub || recv_pq_pub || pq_ct)`
- All exchanged public values now cryptographically bound into key derivation

#### New Domain Separation Constants
- `PQXDH_EXTRACT_SALT` — 32 zero bytes for HMAC-SHA256 Extract step
- `PQXDH_INFO_PREFIX = "meow_pqxdh_v1"` — HKDF-Expand info prefix
- `PQXDH_TRANSCRIPT_DOMAIN = "meow_pqxdh_transcript_v1"` — Transcript hash domain
- `CLASSICAL_INFO = "meow_classical_only_v1"` — Non-PQ fallback derivation

#### Manifest Format Updates
- `pack_manifest()` accepts PQ ciphertext of 1088 (ML-KEM-768) or 1568 (ML-KEM-1024)
- `unpack_manifest()` determines PQ size from mode byte (MEOW5→1088, MEOW4→1568)
- Trailing bytes validation prevents unconsumed data attacks
- Manifest sizes: MEOW5 base=1236B, MEOW4 base=1716B

#### Config & Pipeline Changes
- `CryptoConfig.kyber_variant` default: `"kyber768"` (was `"kyber1024"`)
- `CryptoConfig.pq_paranoid` / `EncodingConfig.pq_paranoid`: new bool flags
- `HighSecurityConfig`: defaults to `pq_paranoid=True` (ML-KEM-1024)
- `encode.py`: MEOW5 mode for default PQ, MEOW4 for paranoid
- `decode_gif.py`: Auto-detects variant from ciphertext size

#### Test Coverage: 38 new tests
| Test Class | Tests |
|-----------|-------|
| `TestPQConstants` | Size constants, algorithm strings, domain separation |
| `TestHybridKeyPairVariants` | ML-KEM-768/1024 key generation, paranoid selection |
| `TestPQXDHTranscriptBinding` | Transcript hash determinism, domain separation, binding |
| `TestEncapDecapRoundtrip` | 768 roundtrip, 1024 roundtrip, cross-variant rejection |
| `TestTranscriptBindingSecurity` | Tampered ciphertext/ephemeral detection |
| `TestMODEMEOW5` | Mode byte packing/unpacking, size validation, trailing bytes |
| `TestConfigDefaults` | Default variant, paranoid flag, encoding config |
| `TestCheckPQAvailable` | Availability detection for both variants |

### Security — MSR v2.0 Asymmetric Entropy Reinjection (Signal-Grade PCS) 🔐

**Post-Compromise Security** via periodic X25519 root key rotation. Compromise of ratchet state at frame N is healed within ≤K frames (rekey_interval). This is the air-gap equivalent of Signal's DH ratchet.

#### Asymmetric Root Key Rotation
- Every `rekey_interval` frames, the encoder generates a fresh X25519 ephemeral keypair
- ECDH with receiver's long-term public key produces shared secret for root rotation
- Root key rotation: `new_root = HKDF(IKM=shared_secret, salt=old_root, info="meow_asym_rekey_root_v1" || epoch)`
- New chain derived from new root: `new_chain = HKDF(new_root, salt, "meow_asym_rekey_chain_v1")`
- Old root + chain zeroed (forward secrecy within epoch)
- Ephemeral public key (32 bytes) embedded in frame header (same slot as v1.x beacon)

#### New Domain Separation Constants (4 new, 14 total)
- `ASYM_REKEY_ROOT_INFO = "meow_asym_rekey_root_v1"` — Root rotation HKDF info
- `ASYM_REKEY_CHAIN_INFO = "meow_asym_rekey_chain_v1"` — Post-rekey chain derivation
- `ASYM_REKEY_KEM_INFO = "meow_asym_rekey_kem_v1"` — ECDH shared secret KDF
- `ASYM_REKEY_ROOT_INIT_INFO = "meow_ratchet_root_store_v1"` — Initial root storage

#### Epoch-Aware Decoder
- Decoder extracts ephemeral keys from rekey frames before chain advancement
- `_advance_to()` handles asymmetric rekeys at epoch boundaries during fast-forward
- Rekey frames must be received before frames in their epoch (fountain codes handle loss)
- Epoch counter bound into HKDF info prevents cross-epoch replay attacks

#### RatchetState v2.0
- Added `root_key: Optional[bytearray]` (stored for asymmetric rekey operations)
- Added `epoch: int` counter (tracks current asymmetric rekey epoch)
- `zeroize()` cleans both chain_key and root_key
- Backward compatible: `root_key=None` defaults for existing code

#### Fallback Behavior
- Without `receiver_public_key`: falls back to plaintext beacon (v1.x, no PCS)
- Without `rekey_interval`: no rekey (base MSR v1.0 behavior)

#### Test Coverage: 43 new tests (185 total ratchet tests)
| Test Class | Tests |
|-----------|-------|
| `TestAsymmetricRekeyPrimitives` | ECDH roundtrip, ephemeral uniqueness, wrong-key, epoch binding |
| `TestRatchetStateV2` | root_key storage, zeroization, step preservation, backward compat |
| `TestAsymmetricRekeyRoundtrip` | Multi-epoch roundtrip, rekey at boundaries |
| `TestPostCompromiseSecurity` | PCS: compromised state cannot decrypt post-rekey |
| `TestOutOfOrderDecoding` | Epoch-aware OOO, missing-rekey rejection |
| `TestRollbackResistance` | Epoch binding, old root cannot derive future chains |
| `TestSignalComparison` | Root rotation, chain isolation, PCS healing latency |
| `TestEdgeCases` | Interval=1, disabled, large epochs, single frame |
| `TestTamperDetectionV2` | Modified ephemeral rejected, replay rejected |

### Security — MSR v1.2 Signal-Parity Hardening (2026-02-16) 🔐

Three Signal-parity security hardening features for the MEOW Symmetric Ratchet:

#### Header Encryption
- Frame indices are now XOR-masked with HKDF-derived pseudorandom masks (`HEADER_ENC_INFO = "meow_ratchet_header_v1"`, `HEADER_MASK_INFO = "meow_header_mask_v1"`)
- Observers cannot determine frame ordering, count consumed frames, or correlate frames across sessions
- Mirrors Signal's double-encrypted header which hides the chain position
- Decoder precomputes encrypted-index → real-index lookup table during initialization (O(N) init, O(1) per-frame)

#### Key Commitment (Invisible Salamanders Defense)
- HMAC-SHA256 commitment tag (16 bytes, `COMMIT_TAG_SIZE = 16`) appended to each frame body
- Prevents key commitment attacks where AES-GCM allows two different keys to both produce valid decryptions with different plaintexts (Grubbs et al. 2017)
- Commitment uses the per-frame `mac_key` (already derived via domain-separated HKDF)
- Decoder verifies commitment BEFORE attempting AES-GCM decryption (fail-fast)

#### Encrypted Frame Format (v1.2)
```
[encrypted_index(4)] [commitment_tag(16)] [beacon?(32)] [AES-GCM ciphertext + tag(16)]
```

#### New Domain Separation Constants
- `HEADER_ENC_INFO = b"meow_ratchet_header_v1"` — header key derivation
- `HEADER_MASK_INFO = b"meow_header_mask_v1"` — per-frame XOR mask derivation
- `COMMIT_TAG_SIZE = 16` — truncated HMAC-SHA256 commitment

#### Tests
- 142 ratchet unit tests (+22 from v1.1): header encryption, key commitment, Signal-parity hardening
- 23 E2E ratchet pipeline tests (all passing with hardened frame format)
- New test classes: `TestHeaderEncryption`, `TestKeyCommitment`, `TestSignalParityHardening`

#### Documentation Updates
- RATCHET_PROTOCOL.md updated to v1.2 with §8.3 (Header Encryption) and §8.4 (Key Commitment)
- MSR_V1_ADVERSARIAL_ANALYSIS.md updated with v1.2 hardening notes and Attack 8 mitigation
- Hardening recommendations: items 1, 2, 3 marked as DONE
- Signal comparison table updated: header encryption ✓, key commitment ✓

### Security — OPUS-AUDIT v2 Remediation (2026-02-17) 🔒

Second hostile crypto audit identified 4 remaining weaknesses; all remediated.

#### A1 v2: Synthetic IV nonce fix
- `_register_nonce_use()` now uses `synthetic_iv_mode` flag instead of `precomputed_key_mode`
- Synthetic IV (HKDF-derived from key + plaintext hash + salt) provides SIV property: same plaintext → same nonce (intentional), different plaintext → different nonce (guaranteed)
- Removed misleading "consider GCM-SIV" warning for HSM mode

#### C3 v2: Full transcript binding
- `derive_shared_secret()` HKDF info now binds: `"meow_fs_bound_v2:"` + protocol_version (1B) + mode_flags (1B) + SHA-256(receiver_public) (32B) + ephemeral_public (32B) + pq_ciphertext_hash (32B)
- Mode flags: FS=0x01, PQ=0x02, duress=0x04
- All callers updated: crypto.py (encrypt/decrypt/derive_key_for_manifest), decode_gif.py, crypto_DEBUG.py

#### D3 v2: Explicit manifest mode byte
- Added `mode_byte` field to Manifest dataclass (0x02=MEOW2, 0x03=MEOW3, 0x04=MEOW4, 0x80=duress flag)
- Mode byte included in AES-GCM AAD and HMAC (via `pack_manifest_core`)
- `unpack_manifest()` validates mode byte against actual content (rejects mismatches)
- New manifest sizes = legacy + 1 byte; backward compat preserved for legacy manifests

#### D1 v2: Hard-disable pq_crypto_real
- Changed from `DeprecationWarning` to `raise RuntimeError` on import
- Prevents silent use of insecure XOR key combiner

#### Tests
- 29 tests in `test_audit_fixes.py` (16 original + 13 new v2 tests)
- 455 total tests pass across all test files

### Security — OPUS-AUDIT Remediation (2026-02-16) 🔒

All 9 FAIL findings from the hostile crypto audit (OPUS-AUDIT.md) have been remediated,
plus 5 additional requirements from cross-audit review.

#### OPUS-AUDIT Fixes (7 code-level, 2 accepted by-design)
- **A1: Nonce guard** — LRU eviction (10K cap, no full-cache clear) + HKDF-derived synthetic IV for HSM/precomputed_key mode
- **A2: AAD bypass removed** — `decrypt_to_raw()` raises `ValueError` when `orig_len`/`comp_len`/`sha256` are `None`; no `aad=None` fallback
- **C3: Transcript binding** — `derive_shared_secret()` now accepts `protocol_version` parameter, bound into HKDF info string
- **D1: PQ HKDF salt** — Changed from `b""` to `ephemeral_public_bytes` in `pq_hybrid.py`; XOR combiner in `pq_crypto_real.py` deprecated with `DeprecationWarning`
- **D3: PQ downgrade detection** — Clear `RuntimeError` message distinguishing PQ downgrade from wrong password
- **E1: Frame MAC fail-closed** — `decode_gif.py` raises `ValueError` on invalid manifest frame MAC (previously silently disabled verification)
- **E2/E3: Fountain reorder/truncation** — Accepted by-design; documented as explicit non-goals in threat model

#### Cross-Audit Requirement Fixes
- **PQ pipeline end-to-end** — `encode.py` calls `hybrid_encapsulate()` when `use_pq=True`; `decode_gif.py` calls `hybrid_decapsulate()` when PQ ciphertext present in manifest
- **Parameter drift unified** — All modules now use ML-KEM-1024 (1568-byte ciphertext) consistently: `pq_crypto_real.py` default changed from `kyber768` to `kyber1024`, `crypto_DEBUG.py` updated throughout
- **AAD completeness** — `build_canonical_aad()` now accepts `ephemeral_public_key` and `pq_ciphertext` parameters; documented that `cipher_len`/`block_size`/`k_blocks` are covered by HMAC (not AAD, due to circular dependency)
- **HSM synthetic IV** — HKDF-derived deterministic nonce (`HKDF(key + comp_hash, salt, "meow-synthetic-nonce-v1")`) for `precomputed_key` mode prevents nonce reuse across restarts
- **E2E reliability harness** — New `tests/test_e2e_crypto_fountain.py` (30 tests) covering full encode→fountain→decode roundtrip with frame loss, reordering, duplicates, combined hostile conditions

#### New Test Files
- `tests/test_audit_fixes.py` — 14 tests verifying all OPUS-AUDIT remediations
- `tests/test_e2e_crypto_fountain.py` — 30 tests for crypto+fountain end-to-end pipeline

#### Documentation Updates
- Updated manifest sizes: MEOW4 1235→1715, MEOW4+duress 1267→1747
- Updated PQ ciphertext size: 1088→1568 (ML-KEM-1024) across all docs
- Removed stale "not wired up" implementation gap notes
- Added REMEDIATED status to all OPUS-AUDIT FAIL findings
- Updated HKDF salt description from `b""` to `ephemeral_public_bytes`
- Updated AAD field list to include `ephemeral_public_key` and `pq_ciphertext`
- Comprehensive stale-claim sweep across 13 .md files (25 fixes):
  - ARCHITECTURE.md: `optional Kyber` → `ML-KEM-1024 hybrid`, `XOR + HKDF` → `Concatenation + HKDF`, `pq_crypto_real.py` → `pq_hybrid.py`
  - SECURITY_AUDIT.md: nonce cache `1024 entries` → `LRU 10K`, domain separation info string updated
  - PROTOCOL.md: Added `pq_ciphertext` to AAD specification
  - SECURITY_INVARIANTS.md: nonce cache + synthetic IV, `pq_ciphertext` in AAD code block
  - THREAT_MODEL.md: PQ implementation reference → `pq_hybrid.py`
  - AUDITOR_README.md: `ML-KEM-768/1024` → `ML-KEM-1024`
  - core-modules.md: `pq_crypto_real.py` marked DEPRECATED
  - README.md: PQ mode `DEFAULT ON` → `opt-in, requires receiver PQ public key`
  - AUDIT_REPORT_2026-01-28.md: nonce cache code annotated with post-audit changes
  - VERUS_FRAME_MAC_STATUS.md: forward secrecy info string update noted
  - OPUS-AUDIT.md: Q1/Q2 self-audit answers updated to REMEDIATED, exploit narratives annotated

### Added — Fountain Codes for Frame Loss Tolerance 🌊

#### JavaScript Fountain Code Implementation
- **New Library**: `examples/fountain-codes.js` (414 lines)
  - `FountainEncoder`: Generates Luby Transform droplets from source data
  - `FountainDecoder`: Reconstructs via belief propagation
  - `Droplet`: Pack/unpack for QR transmission (seed + block indices + XOR data)
  - `RobustSolitonDistribution`: Optimal degree selection (c=0.1, δ=0.5)
  - `SeededRandom`: Deterministic PRNG for reproducible block selection
- **Production-ready**: No dependencies, works in all modern browsers
- **Testing**: `examples/test_fountain.html` with 5 comprehensive test cases

#### Multi-Frame QR with Loss Tolerance
- **Encoding**: Payloads >2500 bytes automatically use fountain encoding
  - Each QR frame contains: `FOUNTAIN:<k>:<block_size>:<length>:<droplet_b64>`
  - Generates k×1.5 droplets (50% redundancy = 33% frame loss tolerance)
  - Systematic optimization: First 2k droplets are degree-1 for fast decode
- **Decoding**: Webcam scanner collects droplets progressively
  - Real-time progress: "Collecting: 8 scanned, 80% decoded (4/5 blocks)"
  - Automatic duplicate detection (seed tracking)
  - Success when enough droplets: "✅ Decoded from 8/5+ droplets!"
- **Frame Format**: Base64-encoded droplet with metadata header

#### Problem Solved
- **Before**: Multi-frame animated QR **never worked** reliably
  - Simple sequential chunking: ANY missed frame = total failure
  - Phone camera capture: autofocus lag, motion blur, low FPS → unusable
- **After**: Works in real-world conditions
  - Tolerates 33% frame loss (can miss 1 in 3 frames)
  - Hand-held phone scanning works
  - Visual progress feedback for users

#### Documentation
- **New**: `docs/FOUNTAIN_CODES_INTEGRATION.md` (400+ lines)
  - Complete technical specification
  - Implementation details, security analysis
  - Performance characteristics, usage examples
  - Debugging guide and troubleshooting
- **Updated**: `examples/README.md`, main `README.md`, `QUICKSTART.md`

### Added — WASM Browser Demo Enhancements 🌐

#### 8 Encryption Modes in Web Demo
- **🔐 Standard Mode**: AES-256-GCM + Argon2id with configurable security levels
- **🔑 Forward Secrecy Mode**: X25519 ephemeral key exchange with full key management
- **🔮 Post-Quantum Mode**: ML-KEM-1024 + X25519 hybrid encryption (NIST Level 5)
- **🐱 Schrödinger Mode**: Dual-secret plausible deniability
- **🖼️ Stego Mode**: LSB steganography embedding
- **📹 Webcam Mode**: Live QR scanner with real-time decode
- **🚨 Duress Mode**: Panic password with localStorage key destruction
- **😺 Cat Mode**: Blinking cat eyes visual encoding

#### Security Level Selection
- 4 Argon2id security levels: Fast (64 MiB/3), Standard (128 MiB/8), High (256 MiB/15), Paranoid (512 MiB/20)
- "Paranoid" level matches CLI security parameters exactly
- UI dropdown in Standard mode encryption panel

#### Post-Quantum WASM Support
- New `wasm-pq` Cargo feature flag enabling ML-KEM-1024
- WASM bindings: `mlkem_generate_keypair()`, `mlkem_encapsulate()`, `mlkem_decapsulate()`
- Hybrid functions: `encrypt_hybrid_pq()`, `decrypt_hybrid_pq()`
- `pq_available()` runtime check function
- Uses `getrandom` 0.4 with `wasm_js` feature for WASM compatibility

#### Web Worker Integration
- `crypto-worker.js` handles all CPU-intensive crypto off main thread
- Added handlers for X25519, ML-KEM, and hybrid PQ operations
- Fallback to main thread if workers unavailable

#### Documentation Updates
- New `docs/WASM_SECURITY.md` — comprehensive WASM security analysis
- Updated README.md with Web Demo vs CLI feature parity table
- Updated QUICKSTART.md with browser-first option
- Updated examples/README.md with all 8 modes documented
- Updated PYTHONANYWHERE_HOSTING.md with PQ build instructions
- Updated docs/USAGE.md with browser workflow section
- Updated docs/ARCHITECTURE.md with WASM architecture diagram
- Updated SECURITY.md with browser-specific security considerations

#### Build System
- New `make build-wasm-pq` target for post-quantum WASM builds
- Updated help text for all WASM targets

### Security — Supply Chain Hardening 🔒

#### OpenSSF Scorecard Improvements
- **Hash-Pinned Dependencies**: Generated `requirements.lock` and `requirements-dev.lock` with SHA256 hashes
  - All CI workflows updated to use `pip install --require-hashes -r requirements.lock`
  - Dockerfile updated for reproducible builds
- **Signed Releases Workflow**: New `.github/workflows/release.yml` with Sigstore keyless signing
  - SLSA Level 3 provenance generation
  - Automatic artifact attestation on version tags
- **CODEOWNERS**: Added `.github/CODEOWNERS` for mandatory code review on security-critical paths
- **Dependabot Enhancements**: Grouped updates, root Cargo.toml monitoring

#### Dependency Security Fixes
- **RUSTSEC-2026-0009**: Updated `time` crate 0.3.46 → 0.3.47 (local time offset vulnerability)
- **RUSTSEC-2026-0010**: Updated `paste64` crate 0.1.3 → 0.1.4 (paste! macro hygiene fix)
- **RUSTSEC-2022-0093**: Documented `rsa` crate advisory (no upstream fix, Marvin attack theoretical)
  - Added `deny.toml` exception with security rationale

#### CI/CD Fixes
- **TLA+ Formal Verification**: Fixed jar path in `formal-verification.yml` (was `formal/tla/tla2tools.jar`, now `tla2tools.jar` after `cd formal/tla`)

### Added — Roadmap ST-1…ST-8 + MT-1…MT-8 Completion 🐾

#### Canonical AAD Construction (MT-1)
- **New Module**: `meow_decoder/canonical_aad.py`
  - `build_canonical_aad()` — deterministic `version_byte || fixed-order manifest fields`
  - Backward compatible with MEOW2/MEOW3/MEOW4 manifests
  - Test vectors in `tests/test_canonical_aad.py` (10 tests)

#### 3-Gate CI Pipeline (MT-2)
- **Gate 1**: Fast pytest (excludes `@pytest.mark.slow`)
- **Gate 2**: Security coverage ≥ 85 % (TIER 1 crypto modules)
- **Gate 3**: Lint + type check (flake8, mypy, black --check)
- All three gates required for PR merge

#### Codecov PR-Only Informational (MT-3)
- `codecov.yml` updated: coverage checks fail only on `push` to `main`, not on PRs

#### CI continue-on-error Cleanup (MT-4)
- Removed or justified every `continue-on-error: true` in `security-ci.yml`

#### Timing Attack Test Harness (MT-5)
- **New Test**: `tests/test_timing_harness.py` (`@pytest.mark.security`)
  - Statistical timing comparison: correct vs wrong password
  - Statistical timing comparison: duress vs real password
  - Configurable threshold with skip on inconsistent CI runners

#### Secure Usage Checklist (MT-6)
- **New Doc**: `docs/SECURE_USAGE_CHECKLIST.md` — OPSEC guidance covering encoding, transfer, decoding, storage, and after-use cleanup
- Cross-linked from README.md, QUICKSTART.md, THREAT_MODEL.md

#### Tamper Timeline Visualization (MT-7)
- **New Module**: `meow_decoder/tamper_report.py`
  - `TamperReport` class with `FrameResult` dataclass
  - ASCII timeline rendering (█ valid, ▒ mixed, ░ invalid, · no data)
  - Sliding-window cluster detection for suspicious failure patterns
  - JSON export via `to_json()`
- **CLI flags**: `--tamper-report` and `--tamper-report-json` on `meow-decode-gif`
- `tests/test_tamper_report.py` (19 tests)

#### React Native QR Bridge (MT-8)
- **New Doc**: `mobile/ARCHITECTURE.md` — bridge architecture, wire protocol, security boundaries
- **New Module**: `mobile/bridge/protocol.py` — 6 JSON message types, parsers, `MAX_FRAME_BYTES`
- **Reference Impl**: `mobile/react-native/MeowScanner.tsx` + `useBridge.ts`
- Phone stays "dumb" — all crypto on CLI side
- `tests/test_bridge_protocol.py` (21 tests)

#### Mobile Bridge CLI Integration
- **New Module**: `meow_decoder/mobile_bridge.py` — CLI handler for phone→CLI scanning
  - `--mobile-bridge` flag to enable bridge mode
  - `--bridge-mode {stdin,websocket,file}` for transport selection
  - `--bridge-port` for WebSocket server port (default 8765)
  - `--input-frames` for file-based frame import
  - `--output-request` to generate capture request JSON for mobile app
- Full integration with `meow-decode-gif` for stdin, WebSocket, and file input modes

#### Short-Term Tasks (ST-1…ST-8)
- **ST-1**: Quarantined duplicate crypto paths → `meow_decoder/experimental/`
- **ST-2**: Manifest numeric bounds + decompression-bomb protection (`tests/test_manifest_bounds.py`, 17 tests)
- **ST-3**: Fixed memory-zeroing claims across all docs (Python = "best-effort", Rust = "guaranteed")
- **ST-4**: Defined pytest markers (`security`, `adversarial`, `crypto`, `fuzz`, `slow`, `integration`, `cat`) + `--strict-markers`
- **ST-5**: Security coverage PR gate ≥ 85 % for TIER 1 modules
- **ST-6**: `--self-test` CLI command with roundtrip verification
- **ST-7**: `docs/ARGON2ID_BENCHMARKS.md` — Argon2id tuning guide with low-end hardware timings
- **ST-8**: CLI wiring for HSM/YubiKey/TPM (`--hsm-slot`, `--tpm-derive`, `--hardware-auto`)

#### OpenSSF Scorecard Improvement Plan
- **New Doc**: `OpenSSFImprovements.md` — 5-phase plan targeting 7.0–8.0+ score
  - Phase 1: workflow permissions, dependabot.yml, binary artifact removal
  - Phase 2: SHA-pin all GitHub Actions (~60+ refs), branch protection
  - Phase 3: signed releases, CII badge, maintained score

## [1.0.0] - 2026-01-28 (Public Release)

**This release consolidates all internal development milestones (v5.x, v6.x) into the
first public release: v1.0.0 (SECURITY-REVIEWED v1.0 INTERNAL REVIEW).**

All features, security hardening, and tests from internal versions 5.0.0 through 5.9.0
are included in this release.

---

## Historical Internal Development Milestones

### [5.9.0] - 2026-01-28

### Added - Life-Critical Security Hardening 🔐🛡️🔬

#### Time-Lock Duress System (Anti-Coercion)
- **New Module**: `timelock_duress.py` (~600 lines)
- **TimeLockPuzzle**: Iterated SHA-256 hashing for delayed decryption
  - Sequential computation (non-parallelizable)
  - Configurable time parameters (seconds to hours)
  - Perfect for dead drops and timed releases
- **CountdownDuress**: Check-in based trigger
  - Automatic key destruction if check-in missed
  - Grace period configuration
  - State persistence with JSON serialization
- **DeadManSwitch**: Renewal-based trigger
  - Requires periodic renewal to keep alive
  - Configurable expiry intervals
  - Emergency wipe on lapse
- **CLI Interface**: Full command-line support for all features

#### Side-Channel Test Suite
- **New Test Module**: `tests/test_sidechannel.py` (~500 lines)
- **TimingAnalyzer**: Statistical framework for timing measurements
  - Coefficient of variation analysis
  - Mean/std timing profiling
- **TestConstantTimeComparison**: Verifies constant-time password/HMAC comparison
- **TestFrameMACTiming**: Tests frame MAC verification consistency
- **TestKeyDerivationTiming**: Validates Argon2id timing stability
- **TestDuressTimingEqualization**: Ensures duress detection has no timing leak
- **TestSecureMemoryZeroing**: Verifies secure_zero_memory() works
- **TestNoEarlyExit**: Confirms no length-based early exit leakage
- **TestRustBackendSideChannel**: Validates subtle/zeroize crate usage

#### Enhanced Build & Security Targets
- **Makefile Targets**:
  - `stealth-build`: Deniable distribution (strips metadata, randomizes)
  - `sidechannel-test`: Run side-channel timing tests
  - `security-test`: Combined security test suite
  - `supply-chain-audit`: pip-audit + cargo audit + cargo deny
- **Organized Help**: New "Security" section in `make help`

### Security
- Time-lock puzzles provide coercion resistance
- Constant-time operations verified via automated tests
- Supply-chain security via multi-tool auditing
- Stealth distribution mode for operational security

### Tests
- 7 new test classes for side-channel resistance
- All existing tests continue to pass

---

## [5.8.0] - 2026-01-25

### Added - State-of-the-Art Security Hardening 🔐🔮🚀

#### Post-Quantum Crypto Now DEFAULT
- **ML-KEM-1024**: Upgraded from ML-KEM-768 to highest security level (NIST FIPS 203)
- **Dilithium3**: Manifest signatures for quantum-resistant authentication (FIPS 204)
- **Hybrid Mode**: X25519 + ML-KEM-1024 (secure if EITHER primitive holds)
- **Default ON**: No longer optional - quantum-ready always

#### Ultra-Hardened Key Derivation
- **512 MiB Memory**: 8x OWASP minimum (was already upgraded in 5.6.0)
- **20 Iterations**: ~5-10 seconds per attempt
- **Brute-Force Math**: 10^35 years for 20-char password on RTX 4090 farm

#### Enhanced CI Security Pipeline
- **pip-audit**: Python dependency vulnerability scanning
- **cargo-audit**: Rust dependency vulnerability scanning
- **mutmut**: Mutation testing for crypto-critical code
- **Bandit**: Static security analysis for Python

#### Rust Backend Recommended by Default
- **Constant-Time**: Uses `subtle` crate for timing attack resistance
- **Memory Zeroing**: Secure zeroize on sensitive data
- **Kyber/Dilithium**: Native PQ crypto support

### Changed
- `config.py`: `enable_pq=True` now default (was False)
- `config.py`: `kyber_variant="kyber1024"` now default (was "kyber768")
- `pq_hybrid.py`: Uses Kyber1024 (1568-byte public keys)
- Forward secrecy now on by default

### Security
- Updated THREAT_MODEL.md with new brute-force mathematics
- Updated README.md to reflect production-ready status
- All security tests passing with new parameters

---

## [5.7.0] - 2026-01-25

### Added - AFL++ Fuzzing & Double Ratchet 🔬🔐

#### AFL++ Fuzzing Infrastructure
- **GitHub Actions Workflow**: `.github/workflows/fuzz.yml` for CI fuzzing
- **Atheris Integration**: Google's coverage-guided Python fuzzer
- **AFL++ Support**: Native AFL++ fuzzing for maximum coverage
- **Fuzz Targets**:
  - `fuzz_manifest.py`: Manifest parsing (edge cases, corruption)
  - `fuzz_fountain.py`: Fountain code decoding (droplet parsing)
  - `fuzz_crypto.py`: Key derivation, decryption error handling
- **Corpus Generation**: `seed_corpus.py` creates valid samples for mutation
- **Crash Detection**: Automatic artifact upload on crashes
- **Weekly Scheduled Runs**: Deep fuzzing on Sundays

#### Double Ratchet Protocol (Signal-style)
- **New Module**: `double_ratchet.py` (~600 lines)
- **DH Ratchet**: X25519 key rotation for forward secrecy
- **Symmetric Ratchet**: HKDF-based chain key derivation
- **Message Keys**: Per-message key derivation prevents replay
- **Out-of-Order Support**: Handles missed/reordered messages
- **State Serialization**: Save/restore session state
- **Clowder Integration**: `ClowderSession` for multi-party streams

#### Security Properties
- **Forward Secrecy**: Past messages protected from key compromise
- **Future Secrecy**: System heals after DH ratchet step
- **Break-in Recovery**: Temporary compromise heals automatically
- **DoS Protection**: `MAX_SKIP=1000` limits skipped key storage

### Tests
- 16 new tests for fuzzing and double ratchet
- All 63 tests passing (47 existing + 16 new)

---

## [5.6.0] - 2026-01-25

### Added - Maximum Security Hardening 🔐🔮

#### Argon2id Parameters Bumped to Maximum
- **512 MiB Memory**: 8x OWASP recommendation (was 256 MiB)
- **20 Iterations**: 6.7x OWASP minimum (was 10)
- **~5-10 Second Delay**: Intentionally slow for maximum GPU/ASIC resistance
- **Updated in**: `crypto.py`, `crypto_enhanced.py`, `config.py`

#### Post-Quantum Signatures (Dilithium / FIPS 204)
- **New Module**: `pq_signatures.py` for manifest authentication
- **Dilithium3**: NIST security level 3 (quantum-resistant)
- **Ed25519 Fallback**: Classical signatures when liboqs unavailable
- **Hybrid Mode**: Ed25519 + Dilithium3 for defense-in-depth
- **Key Management**: Generate, save, load signing keypairs
- **Manifest Signing**: Cryptographic proof of manifest authenticity

#### Security Roadmap
- **New Document**: `docs/ROADMAP.md` with complete security roadmap
- **Short-term**: AFL++ fuzzing, double-ratchet protocol
- **Medium-term**: Rust crypto backend, HSM integration
- **Long-term**: Formal verification, third-party audit

### Changed
- Argon2id memory: 256 MiB → 512 MiB
- Argon2id iterations: 10 → 20
- Key derivation now takes 5-10 seconds (security feature)

---

## [5.5.0] - 2026-01-25

### Added - Security Enhancements

#### Duress Mode (Coercion Resistance)
- **Duress Passwords**: Configure distress signal password that triggers secure wipe
- **Constant-Time Verification**: Timing-safe password comparison prevents side-channel attacks
- **Timing Equalization**: 100-500ms random delays mask operation timing
- **Secure Memory Wipe**: Best-effort 3-pass overwrite (zeros, ones, random) for key material (Python GC may retain copies; Rust backend provides guaranteed zeroing)
- **Resume File Destruction**: Automatic cleanup of recovery files under duress

#### Enhanced Entropy Collection
- **Multi-Source Entropy Pool**: Combines 6+ entropy sources for maximum randomness
- **System Entropy**: os.urandom + /dev/urandom for base randomness
- **Timing Jitter**: High-resolution timing noise from CPU operations
- **Environment State**: Process/memory/network statistics as entropy
- **Hardware RNG**: Intel RDRAND/RDSEED when available
- **Webcam Noise**: Optional camera sensor noise for additional entropy
- **HKDF Mixing**: Cryptographic mixing of all sources for uniform distribution

#### Multi-Secret Schrödinger Mode (N-Level Deniability)
- **Unlimited Realities**: Support for up to 16 concurrent secrets (was 2)
- **Round-Robin Interleaving**: Cryptographically shuffled block placement
- **Statistical Indistinguishability**: All realities pass forensic analysis
- **Merkle Root Integrity**: Cryptographic verification of block integrity
- **Proper Decryption**: Cipher length tracking for accurate block recovery

#### Hardware Security Integration
- **TPM 2.0 Support**: Key derivation via Trusted Platform Module
- **YubiKey Support**: Hardware key derivation via ykman/PKCS#11
- **Smart Card Support**: PKCS#11 interface for security tokens
- **Intel SGX Detection**: Enclave support detection (future use)
- **Graceful Fallback**: Software-only mode when hardware unavailable

#### Configuration Defaults
- **PQ Crypto Default ON**: Post-quantum cryptography now enabled by default
- **Hardware Auto-Detect**: Automatic detection of available security hardware
- **Enhanced Entropy Default ON**: Multi-source entropy collection enabled

### New Modules
- `duress_mode.py`: Coercion-resistant password handling (359 lines)
- `entropy_boost.py`: Multi-source entropy collection (419 lines)
- `multi_secret.py`: N-level Schrödinger encoder/decoder (643 lines)
- `hardware_keys.py`: TPM/YubiKey/smart card integration (566 lines)

### Security Properties
- Timing-safe password comparison (secrets.compare_digest)
- Constant-time HMAC verification
- Memory locking with mlock() where available
- Secure memory zeroing before deallocation
- Hardware-backed key derivation when available
- Statistical indistinguishability for N secrets

### Modified
- `config.py`: Added enable_pq=True (default), plus duress/hardware/entropy options

### Tests
- All 4 new modules tested and verified working
- Multi-secret encode/decode roundtrip confirmed
- Hardware detection graceful fallback verified
- Entropy generation produces 32+ bytes successfully

---

## [5.4.0] - 2026-01-23

### Added - Schrödinger's Yarn Ball 🐱⚛️
- **Quantum Superposition**: Encode TWO secrets in ONE GIF with true plausible deniability
- **Quantum Noise Derivation**: XOR of both password hashes creates shared entanglement key
- **Reality Entanglement**: Cryptographic mixing makes both secrets statistically indistinguishable
- **Observer Collapse**: One password reveals one reality, other remains forever unprovable
- **Automatic Decoy Generation**: Convincing innocent files (vacation photos, shopping lists, cat manifesto)
- **Forensic Resistance**: Statistical tests confirm indistinguishability (entropy, chi-square, byte frequency)

### New Modules
- `quantum_mixer.py`: Core cryptographic primitives for superposition
- `schrodinger_encode.py`: Dual-secret encoder
- `schrodinger_decode.py`: Reality collapse decoder
- `decoy_generator.py`: Automatic convincing decoy generation

### Security Properties
- Statistical indistinguishability (entropy diff < 0.003, chi-square < 300)
- Cryptographic binding via quantum noise (requires both passwords)
- Merkle root integrity over entangled blocks
- Constant-time collapse operations

### CLI
- `schrodinger_encode`: Encode dual realities with auto-decoy
  - `--real`: Real secret file
  - `--decoy`: Decoy file (auto-generated if omitted)
  - `--real-password`: Password for real secret
  - `--decoy-password`: Password for decoy
- `schrodinger_decode`: Collapse superposition to one reality
  - `--reality`: Force specific reality (A or B)

### Tests
- 7/7 quantum mixer tests passing (100%)
- Quantum noise derivation ✓
- Entanglement & collapse ✓
- Statistical indistinguishability ✓
- Merkle root integrity ✓
- End-to-end encoding ✓
- Decoy generation ✓
- Forensic resistance ✓
- Full roundtrip (encode + decode both realities) ✓

### Documentation
- [SCHRODINGER.md](./docs/SCHRODINGER.md): Complete philosophy and architecture
- README updated with quantum examples
- Use case scenarios (border crossing, coercion resistance, dead man's switch)

### Fixed
- Decoder architecture: Store encryption parameters in metadata for proper roundtrip
- Manifest format: Updated to 382 bytes with complete encryption parameters
- Full E2E roundtrip now works correctly (100% test success rate)
- Cleaned up `__init__.py`: Removed main entry point imports to eliminate RuntimeWarning
- Lightweight imports: Only config, crypto primitives, and quantum mixer at import time

### Note
- All v5.3.0 features preserved with 100% backward compatibility
- No regressions: 19/19 existing tests still pass
- Combined test score: 26/26 (100%)

---

## [5.3.0] - 2026-01-23

### Added
- **Forward Secrecy**: X25519 ephemeral keys protect past messages from future password compromise
- **Frame-Level MACs**: Per-frame authentication prevents DoS attacks via invalid frame rejection
- **Constant-Time Operations**: Timing attack resistance for password/MAC verification
- **Metadata Obfuscation**: Length padding hides true file size
- **Enhanced AAD**: Comprehensive manifest integrity protection

### Security
- Ephemeral keys generated per encryption, destroyed after use
- 8-byte MAC per QR frame with constant-time verification
- Random timing delays (1-5ms) prevent timing side-channels
- Size classes (powers of 2) prevent size fingerprinting
- AAD prevents tampering with all metadata fields

### CLI
- `--generate-keys`: Generate receiver keypair for forward secrecy
- `--receiver-pubkey`: Enable forward secrecy mode (encode)
- `--receiver-privkey`: Decrypt with forward secrecy (decode)

### Fixed
- Version consistency across all files (5.3.0)
- Console script entrypoints corrected
- Package imports work correctly
- Test collection fixed

---

## [5.0.0] - Previous Release

Initial production release with:
- AES-256-GCM encryption
- Argon2id key derivation
- QR code fountain coding
- Dual secret support (Schrödinger mode)
