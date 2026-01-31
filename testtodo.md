# Test Coverage TODO - Meow Decoder 90% Coverage Goal

**Created:** 2026-01-30
**Target:** 90% code coverage for Codecov
**Strategy:** One test file per source module in `meow_decoder/`

---

## Priority 1: Crypto Correctness + Key Lifecycle (Must be 95-100%)

| Source File | Test File | Status | Notes |
|-------------|-----------|--------|-------|
| `crypto.py` | `test_crypto.py` | ✅ DONE | Core crypto API, AES-GCM, Argon2id, HMAC |
| `crypto_backend.py` | `test_crypto_backend.py` | ✅ DONE | Python→Rust bridge, 872 lines consolidated |
| `crypto_enhanced.py` | `test_crypto_enhanced.py` | ✅ DONE | 10 core tests, SecureBytes/derive_key/encrypt/decrypt (in omit list) |
| `constant_time.py` | `test_constant_time.py` | ✅ DONE | 91% coverage, 53 tests, 4 stubs converted |
| `streaming_crypto.py` | `test_streaming_crypto.py` | ✅ DONE | 48 tests, StreamingCipher/MemoryMonitor/roundtrips (in omit list) |
| `frame_mac.py` | `test_frame_mac.py` | ✅ DONE | 100% coverage, 27 tests, 3 stubs converted |
| `multi_secret.py` | `test_multi_secret.py` | ✅ DONE | 58 tests, N-level Schrödinger encode/decode (in omit list) |

---

## Priority 2: Forward Secrecy (Aim 90-95%)

| Source File | Test File | Status | Notes |
|-------------|-----------|--------|-------|
| `forward_secrecy.py` | `test_forward_secrecy.py` | ✅ DONE | 94% coverage, 20 tests, 2 stubs converted |
| `forward_secrecy_x25519.py` | `test_forward_secrecy_x25519.py` | ✅ DONE | 97% coverage, 39 tests, MEOW_TEST_MODE added |
| `x25519_forward_secrecy.py` | `test_x25519_forward_secrecy.py` | ✅ DONE | 98% coverage, 46 tests, 3 stubs converted |
| `forward_secrecy_encoder.py` | `test_forward_secrecy_encoder.py` | ✅ DONE | 95% coverage, 24 tests |
| `forward_secrecy_decoder.py` | `test_forward_secrecy_decoder.py` | ✅ DONE | 95% coverage, 28 tests |

---

## Priority 3: Encode/Decode Paths (Aim 88-92%)

| Source File | Test File | Status | Notes |
|-------------|-----------|--------|-------|
| `encode.py` | `test_encode.py` | ✅ DONE | 21 tests, consolidated from test_coverage_90_encode.py |
| `decode_gif.py` | `test_decode_gif.py` | ✅ DONE | Consolidated from test_coverage_90_decode.py |
| `gif_handler.py` | `test_gif_handler.py` | ✅ DONE | Consolidated from test_coverage_90_gif_handler.py |
| `qr_code.py` | `test_qr_code.py` | ✅ DONE | Consolidated from test_coverage_90_qr_gif.py |
| `fountain.py` | `test_fountain.py` | ✅ DONE | Consolidated from test_coverage_90_fountain.py |
| `meow_encode.py` | `test_meow_encode.py` | ✅ EXISTS | Cat-themed encode |
| `clowder_encode.py` | `test_clowder.py` | ✅ EXISTS | Multi-device encode |
| `clowder_decode.py` | `test_clowder.py` | ✅ EXISTS | Multi-device decode |
| `schrodinger_encode.py` | `test_schrodinger.py` | ✅ EXISTS | Dual-secret encode (6 test files!) |
| `schrodinger_decode.py` | `test_schrodinger.py` | ✅ EXISTS | Dual-secret decode |
| `stego_advanced.py` | `test_stego_advanced.py` | ✅ EXISTS | LSB steganography |
| `quantum_mixer.py` | `test_quantum_mixer.py` | ✅ EXISTS | Schrödinger mixing |

---

## Priority 4: Duress/Decoy Behavior (Aim 80-90%)

| Source File | Test File | Status | Notes |
|-------------|-----------|--------|-------|
| `duress_mode.py` | `test_duress_mode.py` | ✅ DONE | Consolidated from test_coverage_90_duress_mode.py |
| `decoy_generator.py` | `test_decoy_generator.py` | ✅ EXISTS | Generate plausible fakes |
| `timelock_duress.py` | `test_timelock_duress.py` | ✅ EXISTS | Time-based unlock |
| `metadata_obfuscation.py` | `test_metadata_obfuscation.py` | ✅ EXISTS | Length padding |
| `secure_cleanup.py` | `test_secure_cleanup.py` | ⏳ TODO | Secure file shred |
| `deadmans_switch_cli.py` | `test_deadmans_switch.py` | ✅ EXISTS | Dead-man's switch |

---

## Priority 5: Config + UX (Cheap Wins)

| Source File | Test File | Status | Notes |
|-------------|-----------|--------|-------|
| `config.py` | `test_config.py` | ✅ DONE | Consolidated from test_coverage_90_config.py |
| `security_warnings.py` | `test_security_warnings.py` | ⏳ TODO | Weak settings warnings |
| `progress.py` | `test_progress.py` | ✅ EXISTS | Progress bar wrapper |
| `progress_bar.py` | `test_progress.py` | ✅ EXISTS | tqdm wrapper (same file) |
| `cat_utils.py` | `test_cat_utils.py` | ✅ DONE | Consolidated from test_coverage_90_cat_utils.py |

---

## Priority 6: Post-Quantum + Hardware (Important)

| Source File | Test File | Status | Notes |
|-------------|-----------|--------|-------|
| `pq_crypto_real.py` | `test_pq_crypto_real.py` | ✅ DONE | Consolidated from test_coverage_90_pq_crypto.py |
| `pq_hybrid.py` | `test_pq_hybrid.py` | ✅ EXISTS | Hybrid mode (2 test files) |
| `pq_signatures.py` | `test_pq_signatures.py` | ⏳ TODO | Dilithium3 |
| `hardware_integration.py` | `test_hardware_integration.py` | ✅ EXISTS | TPM/YubiKey |
| `hardware_keys.py` | `test_hardware_keys.py` | ✅ EXISTS | Key storage |

---

## Priority 7: Misc/Optional

| Source File | Test File | Status | Notes |
|-------------|-----------|--------|-------|
| `double_ratchet.py` | `test_double_ratchet.py` | ✅ EXISTS | Signal protocol |
| `merkle_tree.py` | `test_merkle_tree_aggressive.py` | ✅ EXISTS | Integrity verification |
| `entropy_boost.py` | `test_entropy_boost.py` | ✅ EXISTS | Multi-source entropy |
| `ascii_qr.py` | `test_ascii_qr.py` | ✅ EXISTS | ASCII QR rendering |
| `bidirectional.py` | `test_bidirectional.py` | ✅ EXISTS | Bidirectional transfer |
| `catnip_fountain.py` | `test_catnip_fountain.py` | ✅ EXISTS | Cat-themed fountain |
| `logo_eyes.py` | `test_logo_eyes.py` | ✅ EXISTS | Logo carrier mode |
| `ninja_cat_ultra.py` | `test_ninja_cat.py` | ✅ EXISTS | Stego levels |
| `prowling_mode.py` | `test_prowling_mode.py` | ✅ EXISTS | Low-memory mode |
| `resume_secured.py` | `test_resume_secured.py` | ✅ EXISTS | Resume functionality |
| `high_security.py` | `test_high_security.py` | ✅ EXISTS | Paranoid mode |
| `webcam_enhanced.py` | `test_webcam_enhanced.py` | ✅ EXISTS | Camera capture |
| `secure_bridge.py` | `test_secure_bridge.py` | ⏳ TODO | Rust bridge |

---

## Files to SKIP (Demo/Debug/GUI only)

- `crypto_DEBUG.py` - Debug version
- `encode_DEBUG.py` - Debug version  
- `gui_logo_example.py` - GUI demo
- `meow_dashboard_demo.py` - Dashboard demo
- `meow_gui_enhanced.py` - GUI code
- `profiling_improved.py` - Profiling tools
- `decode_webcam_with_resume.py` - Webcam demo
- `setup.py` - Package setup

---

## Progress Log

### 2026-01-30 (Session 2)
- [x] crypto_backend.py consolidation COMPLETE
  - test_crypto_backend.py: 872 lines, 18 test classes (canonical)
  - Stubbed: test_crypto_backend_rust.py (245 lines → deprecation stub)
  - Stubbed: test_crypto_backend_aggressive.py (537 lines → deprecation stub)
  - Stubbed: test_coverage_90_backend.py (518 lines → deprecation stub)

### 2026-01-30 (Session 1)
- [x] Created testtodo.md
- [x] crypto.py consolidation COMPLETE
- [x] Starting consolidation of test files
- [ ] Target: One test file per source module

---

## Consolidation Strategy

1. **For each source file** (e.g., `crypto.py`):
   - Create/update `tests/test_crypto.py`
   - Merge all related tests from scattered files like:
     - `test_coverage_90_crypto.py`
     - `test_crypto_aggressive.py`
     - `test_crypto_consolidated.py`
   - Remove duplicates, keep best coverage

2. **Delete after consolidation:**
   - All `test_coverage_90_*.py` files
   - All `*_aggressive.py` duplicates
   - Keep only one canonical test file per module

---

