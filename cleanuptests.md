# Test Suite Cleanup & Consolidation Plan

**Created:** 2026-01-31  
**Last Updated:** 2026-02-01  
**Goal:** One canonical test file per source module  
**Status:** IN PROGRESS (3/21 merges verified complete)

---

## Overview

Current state: **120 test files** → Target: **~35-40 canonical test files**

### Current Breakdown:
- **Integration subdirectory:** 7 files
- **spec_v12 subdirectory:** 1 file  
- **Main tests/:** 112 files
- **Files matching cleanup patterns:** 40 files

### Fragmentation Categories to Merge:
- `test_coverage_90_*.py` (12 files) → Merge into canonical
- `test_coverage_*.py` (misc, 8 files) → Merge into canonical
- `test_*_aggressive.py` (6 files) → Merge into canonical  
- `test_phase*.py` (7 files) → Merge into canonical
- `test_core_*.py` (7 files) → Merge into canonical
- Duplicate/overlapping files → Merge into canonical

---

## MASTER MAPPING TABLE

### Legend
- ✅ = Already canonical (keep as-is)
- 🔀 = Merge INTO this file
- ➡️ = Merge this file INTO target
- 🗑️ = Mark deprecated after merge
- ⏸️ = Keep separate (justified)

---

## 1. CRYPTO MODULE FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `crypto.py` | `test_crypto.py` | `test_crypto.py` | ✅ Keep |
| | `test_coverage_90_crypto_paths.py` | `test_crypto.py` | ➡️ Merge |
| `crypto_backend.py` | `test_crypto_backend.py` | `test_crypto_backend.py` | ✅ Keep |
| `crypto_enhanced.py` | `test_crypto_enhanced.py` | `test_crypto_enhanced.py` | ✅ Keep |
| `constant_time.py` | `test_constant_time.py` | `test_constant_time.py` | ✅ Keep |
| | `test_sidechannel.py` | `test_sidechannel.py` | ⏸️ Keep separate (specialized) |
| `streaming_crypto.py` | `test_streaming_crypto.py` | `test_streaming_crypto.py` | ✅ Keep |
| | `test_coverage_90_streaming.py` | `test_streaming_crypto.py` | ➡️ Merge |
| | `test_streaming.py` | `test_streaming_crypto.py` | ➡️ Merge |
| `frame_mac.py` | `test_frame_mac.py` | `test_frame_mac.py` | ✅ Keep |
| | `test_coverage_90_metadata_mac.py` | `test_frame_mac.py` | ➡️ Merge |
| `secure_bridge.py` | `test_secure_bridge.py` | `test_secure_bridge.py` | ✅ Keep |
| `secure_cleanup.py` | `test_secure_cleanup.py` | `test_secure_cleanup.py` | ✅ Keep |

**Merge Task 1:** `test_coverage_90_crypto_paths.py` → `test_crypto.py`  
**Merge Task 2:** `test_coverage_90_streaming.py` + `test_streaming.py` → `test_streaming_crypto.py`  
**Merge Task 3:** `test_coverage_90_metadata_mac.py` → `test_frame_mac.py`

---

## 2. FORWARD SECRECY FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `forward_secrecy.py` | `test_forward_secrecy.py` (canonical) | `test_forward_secrecy.py` | 🔀 Canonical |
| | `debug_forward_secrecy.py` | `test_forward_secrecy.py` | ➡️ Merge |
| | `integration/test_forward_secrecy.py` | `test_forward_secrecy.py` | ➡️ Merge |
| | `integration/test_fs_integration.py` | `test_forward_secrecy.py` | ➡️ Merge |
| | `integration/test_cli_forward_secrecy.py` | `test_forward_secrecy.py` | ➡️ Merge |
| `forward_secrecy_x25519.py` | `test_forward_secrecy_x25519.py` | `test_forward_secrecy.py` | ➡️ Merge |
| `x25519_forward_secrecy.py` | `test_x25519_forward_secrecy.py` | `test_forward_secrecy.py` | ➡️ Merge |
| | `test_core_x25519_and_decoy_and_webcam.py` | Split: X25519→FS, Decoy→decoy, Webcam→webcam | ➡️ Split & Merge |
| `forward_secrecy_encoder.py` | `test_forward_secrecy_encoder.py` | `test_forward_secrecy.py` | ➡️ Merge |
| `forward_secrecy_decoder.py` | `test_forward_secrecy_decoder.py` | `test_forward_secrecy.py` | ➡️ Merge |
| `double_ratchet.py` | `test_double_ratchet.py` | `test_forward_secrecy.py` | ➡️ Merge (related) |

**Merge Task 4:** ALL forward secrecy files → `test_forward_secrecy.py` (will be ~1200-1500 lines, acceptable)

---

## 3. FOUNTAIN/ERROR CORRECTION FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `fountain.py` | `test_fountain.py` | `test_fountain.py` | 🔀 Canonical |
| | `test_fountain_aggressive.py` | `test_fountain.py` | ➡️ Merge |
| | `test_coverage_90_fountain.py` | `test_fountain.py` | ➡️ Merge |
| | `test_coverage_90_fountain_paths.py` | `test_fountain.py` | ➡️ Merge |
| | `integration/test_fountain_fix.py` | `test_fountain.py` | ➡️ Merge |
| `catnip_fountain.py` | `test_catnip_fountain.py` | `test_fountain.py` | ➡️ Merge |
| `merkle_tree.py` | `test_merkle_tree_aggressive.py` | `test_fountain.py` | ➡️ Merge (related) |

**Merge Task 5:** ALL fountain files → `test_fountain.py`

---

## 4. ENCODE/DECODE PIPELINE

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `encode.py` | `test_encode.py` | `test_encode.py` | 🔀 Canonical |
| | `test_coverage_90_encode.py` | `test_encode.py` | ➡️ Merge |
| | `test_encode_main_aggressive.py` | `test_encode.py` | ➡️ Merge |
| | `test_coverage_encode_cli.py` | `test_encode.py` | ➡️ Merge |
| | `test_core_cli_encode_main.py` | `test_encode.py` | ➡️ Merge |
| | `test_coverage_90_encode_decode_cli.py` | Split encode/decode | ➡️ Split |
| `decode_gif.py` | `test_decode_gif.py` | `test_decode_gif.py` | 🔀 Canonical |
| | `test_coverage_90_decode.py` | `test_decode_gif.py` | ➡️ Merge |
| | `test_decode_gif_aggressive.py` | `test_decode_gif.py` | ➡️ Merge |
| | `test_core_cli_decode_main.py` | `test_decode_gif.py` | ➡️ Merge |
| | `test_core_decode_gif_more.py` | `test_decode_gif.py` | ➡️ Merge |
| | `test_coverage_decode_gif_verbose_and_macs.py` | `test_decode_gif.py` | ➡️ Merge |
| `meow_encode.py` | `test_meow_encode.py` | `test_encode.py` | ➡️ Merge |

**Merge Task 6:** ALL encode files → `test_encode.py`  
**Merge Task 7:** ALL decode files → `test_decode_gif.py`

---

## 5. GIF/QR HANDLING

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `gif_handler.py` | `test_gif_handler.py` | `test_gif_handler.py` | 🔀 Canonical |
| | `test_gif_handler_aggressive.py` | `test_gif_handler.py` | ➡️ Merge |
| | `test_coverage_90_gif_handler.py` | `test_gif_handler.py` | ➡️ Merge |
| | `test_core_gif_handler.py` | `test_gif_handler.py` | ➡️ Merge |
| | `test_core_gif_handler_more.py` | `test_gif_handler.py` | ➡️ Merge |
| `qr_code.py` | `test_qr_code.py` | `test_qr_code.py` | 🔀 Canonical |
| | `test_qr_code_aggressive.py` | `test_qr_code.py` | ➡️ Merge |
| | `test_coverage_90_qr_gif.py` | `test_qr_code.py` | ➡️ Merge |
| | `test_coverage_90_qr_gif_paths.py` | `test_qr_code.py` | ➡️ Merge |
| | `test_coverage_90_qr_reader.py` | `test_qr_code.py` | ➡️ Merge |
| | `test_coverage_qr_code.py` | `test_qr_code.py` | ➡️ Merge |
| | `test_core_qr_code_generator.py` | `test_qr_code.py` | ➡️ Merge |
| | `test_core_qr_reader_unit.py` | `test_qr_code.py` | ➡️ Merge |
| `ascii_qr.py` | `test_ascii_qr.py` | `test_qr_code.py` | ➡️ Merge |

**Merge Task 8:** ALL gif_handler files → `test_gif_handler.py`  
**Merge Task 9:** ALL qr_code files → `test_qr_code.py`

---

## 6. STEGANOGRAPHY FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `stego_advanced.py` | `test_stego_advanced.py` | `test_stego.py` | 🔀 Rename to canonical |
| | `test_coverage_90_stego.py` | `test_stego.py` | ➡️ Merge |
| `ninja_cat_ultra.py` | `test_ninja_cat.py` | `test_stego.py` | ➡️ Merge |
| `logo_eyes.py` | `test_logo_eyes.py` | `test_stego.py` | ➡️ Merge |

**Merge Task 10:** ALL stego files → `test_stego.py` (rename from test_stego_advanced.py)

---

## 7. SCHRÖDINGER/QUANTUM FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `schrodinger_encode.py` | `test_schrodinger.py` | `test_schrodinger.py` | 🔀 Canonical |
| `schrodinger_decode.py` | `test_schrodinger_comprehensive.py` | `test_schrodinger.py` | ➡️ Merge |
| | `test_schrodinger_roundtrip.py` | `test_schrodinger.py` | ➡️ Merge |
| | `test_schrodinger_security.py` | `test_schrodinger.py` | ➡️ Merge |
| | `test_coverage_90_schrodinger.py` | `test_schrodinger.py` | ➡️ Merge |
| | `test_phase3_schrodinger_security.py` | `test_schrodinger.py` | ➡️ Merge |
| | `integration/test_schrodinger_e2e.py` | `test_schrodinger.py` | ➡️ Merge |
| `quantum_mixer.py` | `test_quantum_mixer.py` | `test_schrodinger.py` | ➡️ Merge |
| `multi_secret.py` | `test_multi_secret.py` | `test_schrodinger.py` | ➡️ Merge (related) |

**Merge Task 11:** ALL Schrödinger files → `test_schrodinger.py`

---

## 8. DURESS/DECOY/TIMELOCK FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `duress_mode.py` | `test_duress_mode.py` | `test_duress.py` | 🔀 Rename to canonical |
| | `test_duress_mode_aggressive.py` | `test_duress.py` | ➡️ Merge |
| | `test_duress_modes.py` | `test_duress.py` | ➡️ Merge |
| | `test_coverage_90_duress_mode.py` | `test_duress.py` | ➡️ Merge |
| | `test_coverage_90_duress_paths.py` | `test_duress.py` | ➡️ Merge |
| | `test_phase4_duress_timing.py` | `test_duress.py` | ➡️ Merge |
| | `verify_duress_e2e.py` | `test_duress.py` | ➡️ Merge |
| `decoy_generator.py` | `test_decoy_generator.py` | `test_duress.py` | ➡️ Merge |
| `timelock_duress.py` | `test_timelock_duress.py` | `test_duress.py` | ➡️ Merge |
| | `test_coverage_90_security_advanced.py` | `test_duress.py` | ➡️ Merge (has timelock tests) |
| `deadmans_switch_cli.py` | `test_deadmans_switch.py` | `test_duress.py` | ➡️ Merge |

**Merge Task 12:** ALL duress/decoy/timelock files → `test_duress.py`

---

## 9. POST-QUANTUM FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `pq_crypto_real.py` | `test_pq_crypto.py` | `test_pq.py` | 🔀 Rename to canonical |
| | `test_pq_crypto_real.py` | `test_pq.py` | ➡️ Merge (if different) |
| | `test_coverage_90_pq_crypto.py` | `test_pq.py` | ➡️ Merge |
| `pq_hybrid.py` | `test_pq_hybrid.py` | `test_pq.py` | ➡️ Merge |
| | `test_pq_hybrid_fail_closed.py` | `test_pq.py` | ➡️ Merge |
| | `test_phase4_pq_integration.py` | `test_pq.py` | ➡️ Merge |
| `pq_signatures.py` | `test_pq_signatures.py` | `test_pq.py` | ➡️ Merge |

**Merge Task 13:** ALL PQ files → `test_pq.py`

---

## 10. HARDWARE FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `hardware_integration.py` | `test_hardware_integration.py` | `test_hardware.py` | 🔀 Rename to canonical |
| | `test_hardware_integration_comprehensive.py` | `test_hardware.py` | ➡️ Merge |
| | `test_coverage_90_hardware.py` | `test_hardware.py` | ➡️ Merge |
| | `test_phase5_hardware_mocks.py` | `test_hardware.py` | ➡️ Merge |
| `hardware_keys.py` | `test_hardware_keys.py` | `test_hardware.py` | ➡️ Merge |
| | `test_hardware_mocks.py` | `test_hardware.py` | ➡️ Merge |

**Merge Task 14:** ALL hardware files → `test_hardware.py`

---

## 11. CONFIG/CLI/UX FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `config.py` | `test_config.py` | `test_config.py` | 🔀 Canonical |
| | `test_config_aggressive.py` | `test_config.py` | ➡️ Merge |
| | `test_coverage_90_config.py` | `test_config.py` | ➡️ Merge |
| CLI tests | `test_cli.py` | `test_cli.py` | 🔀 Canonical |
| | `test_cli_consolidated.py` | `test_cli.py` | ➡️ Merge |
| | `test_coverage_90_cli.py` | `test_cli.py` | ➡️ Merge |
| | `test_coverage_targeted_cli_paths.py` | `test_cli.py` | ➡️ Merge |
| `cat_utils.py` | `test_cat_utils.py` | `test_cat_utils.py` | ✅ Keep |
| | `test_coverage_90_cat_utils.py` | `test_cat_utils.py` | ➡️ Merge |
| `progress.py` | `test_progress.py` | `test_progress.py` | ✅ Keep |
| | `test_coverage_90_progress.py` | `test_progress.py` | ➡️ Merge |
| | `test_coverage_90_deep_progress.py` | `test_progress.py` | ➡️ Merge |
| `security_warnings.py` | `test_security_warnings.py` | `test_security_warnings.py` | ✅ Keep |

**Merge Task 15:** Config aggressive → `test_config.py`  
**Merge Task 16:** ALL CLI files → `test_cli.py`  
**Merge Task 17:** Cat utils + progress merges

---

## 12. METADATA FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| `metadata_obfuscation.py` | `test_metadata_obfuscation.py` | `test_metadata.py` | 🔀 Rename to canonical |
| | `test_metadata_obfuscation_aggressive.py` | `test_metadata.py` | ➡️ Merge |
| | `test_metadata.py` | `test_metadata.py` | ➡️ Merge |
| | `test_coverage_90_metadata.py` | `test_metadata.py` | ➡️ Merge |
| | `test_coverage_90_metadata_paths.py` | `test_metadata.py` | ➡️ Merge |

**Merge Task 18:** ALL metadata files → `test_metadata.py`

---

## 13. SECURITY/ADVERSARIAL FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| Security tests | `test_security.py` | `test_security.py` | 🔀 Canonical |
| | `test_adversarial.py` | `test_security.py` | ➡️ Merge |
| | `test_tamper_detection.py` | `test_security.py` | ➡️ Merge |
| | `test_grok_security.py` | `test_security.py` | ➡️ Merge |
| | `test_phase2_security.py` | `test_security.py` | ➡️ Merge |
| | `test_coverage_90_deep_security.py` | `test_security.py` | ➡️ Merge |
| | `test_invariants.py` | `test_security.py` | ➡️ Merge |
| | `test_kdf.py` | `test_security.py` | ➡️ Merge |

**Merge Task 19:** ALL security files → `test_security.py`

---

## 14. MISC/INTEGRATION FAMILY

| Source File | Current Test Files | Canonical Target | Action |
|-------------|-------------------|------------------|--------|
| Integration | `test_integration.py` | `test_integration.py` | 🔀 Canonical |
| | `test_e2e.py` | `test_integration.py` | ➡️ Merge |
| | `integration/test_comprehensive.py` | `test_integration.py` | ➡️ Merge |
| | `integration/test_full_roundtrip.py` | `test_integration.py` | ➡️ Merge |
| | `test_encode_decode.py` | `test_integration.py` | ➡️ Merge |
| | `test_core_encode_decode_unit.py` | `test_integration.py` | ➡️ Merge |
| | `test_fuzz_roundtrip.py` | `test_integration.py` | ➡️ Merge |
| Misc | `test_misc_utils.py` | `test_utils.py` | 🔀 Rename to canonical |
| | `test_coverage_90_utils.py` | `test_utils.py` | ➡️ Merge |
| | `test_coverage_90_resume_and_misc.py` | `test_utils.py` | ➡️ Merge |
| | `test_coverage_90_edge_cases.py` | `test_utils.py` | ➡️ Merge |
| | `test_edge_cases.py` | `test_utils.py` | ➡️ Merge |
| `entropy_boost.py` | `test_entropy_boost.py` | `test_utils.py` | ➡️ Merge |
| `bidirectional.py` | `test_bidirectional.py` | `test_utils.py` | ➡️ Merge |
| `clowder_*.py` | `test_clowder.py` | `test_clowder.py` | ✅ Keep separate |
| Property-based | `test_property_based.py` | `test_property_based.py` | ✅ Keep separate |
| Webcam | `test_webcam_enhanced.py` | `test_webcam.py` | ✅ Keep (rename) |
| Resume | `test_resume_secured.py` | `test_resume.py` | ✅ Keep (rename) |
| Prowling | `test_prowling_mode.py` | `test_prowling.py` | ✅ Keep (rename) |
| High sec | `test_high_security.py` | `test_high_security.py` | ✅ Keep |
| UX | `test_ux_features.py` | `test_ux.py` | ✅ Keep (rename) |

**Merge Task 20:** ALL integration files → `test_integration.py`  
**Merge Task 21:** ALL misc/utils files → `test_utils.py`

---

## 15. FILES TO DEPRECATE (after merge)

### Coverage_90 files (12 total - verified 2026-02-01)
- [ ] `test_coverage_90_all_imports.py` → `test_imports.py` (keep separate for import validation)
- [ ] `test_coverage_90_cli.py` → `test_cli.py`
- [ ] `test_coverage_90_deep_core.py` → `test_integration.py`
- [ ] `test_coverage_90_deep_progress.py` → `test_progress.py`
- [ ] `test_coverage_90_deep_security.py` → `test_security.py`
- [ ] `test_coverage_90_duress_paths.py` → `test_duress.py`
- [ ] `test_coverage_90_metadata_mac.py` → `test_frame_mac.py`
- [ ] `test_coverage_90_metadata_paths.py` → `test_metadata.py`
- [ ] `test_coverage_90_qr_gif.py` → `test_qr_code.py`
- [ ] `test_coverage_90_qr_gif_paths.py` → `test_qr_code.py`
- [ ] `test_coverage_90_qr_reader.py` → `test_qr_code.py`
- [ ] `test_coverage_90_utils.py` → `test_utils.py`

### Aggressive files (6 total - verified 2026-02-01)
- [ ] `test_config_aggressive.py` → `test_config.py`
- [ ] `test_duress_mode_aggressive.py` → `test_duress.py`
- [ ] `test_gif_handler_aggressive.py` → `test_gif_handler.py`
- [ ] `test_merkle_tree_aggressive.py` → `test_fountain.py`
- [ ] `test_metadata_obfuscation_aggressive.py` → `test_metadata.py`
- [ ] `test_qr_code_aggressive.py` → `test_qr_code.py`

### Phase files (7 total - verified 2026-02-01)
- [ ] `test_phase2_security.py` → `test_security.py`
- [ ] `test_phase3_schrodinger_security.py` → `test_schrodinger.py`
- [ ] `test_phase4_dudect_timing.py` → `test_sidechannel.py`
- [ ] `test_phase4_duress_timing.py` → `test_duress.py`
- [ ] `test_phase4_manifest_migration.py` → `test_crypto.py`
- [ ] `test_phase5_hardware_mocks.py` → `test_hardware.py`
- [ ] `test_phase5_thread_stress.py` → `test_integration.py`

### Core files (7 total - verified 2026-02-01)
- [ ] `test_core_coverage.py` → `test_integration.py`
- [ ] `test_core_encode_decode_unit.py` → `test_integration.py`
- [ ] `test_core_gif_handler.py` → `test_gif_handler.py`
- [ ] `test_core_gif_handler_more.py` → `test_gif_handler.py`
- [ ] `test_core_qr_code_generator.py` → `test_qr_code.py`
- [ ] `test_core_qr_reader_unit.py` → `test_qr_code.py`
- [ ] `test_core_runpy_selftests.py` → `test_integration.py`

### Other coverage files (8 total - verified 2026-02-01)
- [ ] `test_coverage_boost.py` → `test_integration.py`
- [ ] `test_coverage_boost_v2.py` → `test_integration.py`
- [ ] `test_coverage_comprehensive.py` → `test_integration.py`
- [ ] `test_coverage_final_push.py` → `test_integration.py`
- [ ] `test_coverage_imports_and_main.py` → `test_imports.py`
- [ ] `test_coverage_qr_code.py` → `test_qr_code.py`
- [ ] `test_coverage_stage2.py` → `test_integration.py`
- [ ] `test_core_coverage.py` → `test_integration.py`

### Integration subdir (7 total)
- [ ] `integration/test_cli_forward_secrecy.py` → `test_forward_secrecy.py`
- [ ] `integration/test_comprehensive.py` → `test_integration.py`
- [ ] `integration/test_forward_secrecy.py` → `test_forward_secrecy.py`
- [ ] `integration/test_fountain_fix.py` → `test_fountain.py`
- [ ] `integration/test_fs_integration.py` → `test_forward_secrecy.py`
- [ ] `integration/test_full_roundtrip.py` → `test_integration.py`
- [ ] `integration/test_schrodinger_e2e.py` → `test_schrodinger.py`

### Misc to merge
- [ ] `debug_forward_secrecy.py` → `test_forward_secrecy.py`
- [ ] `verify_duress_e2e.py` → `test_duress.py`
- [ ] `test_duress_modes.py` → `test_duress.py`
- [ ] `test_control_channel_bug.py` → `test_integration.py`
- [ ] `test_file_io.py` → `test_utils.py`

---

## EXECUTION CHECKLIST

### Phase 1: Highest Priority Merges (TOP 10)

- [ ] **Merge 1:** Fountain family → `test_fountain.py` ⏳ PENDING
  - Sources: `test_catnip_fountain.py`
  - Note: Other files (test_fountain_aggressive.py, test_coverage_90_fountain*.py, integration/test_fountain_fix.py, test_merkle_tree_aggressive.py) do not exist
  - [ ] Verify which source files exist
  - [ ] Merge unique tests into `test_fountain.py`
  - [ ] Add deprecation headers to old files
  - [ ] Verify pytest passes

- [ ] **Merge 2:** QR family → `test_qr_code.py` ⏳ PENDING (10 files still exist)
  - Canonical: `test_qr_code.py`
  - Sources to merge (verified exist):
    - `test_qr_code_aggressive.py`
    - `test_coverage_90_qr_gif.py`
    - `test_coverage_90_qr_gif_paths.py`
    - `test_coverage_90_qr_reader.py`
    - `test_coverage_qr_code.py`
    - `test_core_qr_code_generator.py`
    - `test_core_qr_reader_unit.py`
    - `test_ascii_qr.py`
  - [ ] Read all source files
  - [ ] Identify unique tests
  - [ ] Merge into `test_qr_code.py`
  - [ ] Add deprecation headers to old files

- [ ] **Merge 3:** GIF handler family → `test_gif_handler.py` ⏳ PENDING (4 files still exist)
  - Canonical: `test_gif_handler.py`
  - Sources to merge (verified exist):
    - `test_gif_handler_aggressive.py`
    - `test_core_gif_handler.py`
    - `test_core_gif_handler_more.py`
  - Note: `test_coverage_90_gif_handler.py` does not exist
  - [ ] Read all source files
  - [ ] Merge into `test_gif_handler.py`
  - [ ] Add deprecation headers

- [ ] **Merge 4:** Forward secrecy family → Multiple canonical files ⏳ PENDING
  - Strategy: Keep 4 canonical unit test files + 1 integration file
  - Canonical files to keep:
    - `test_forward_secrecy_x25519.py` (39 tests)
    - `test_forward_secrecy_decoder.py` (28 tests)
    - `test_forward_secrecy_encoder.py` (23 tests)
    - `test_double_ratchet.py` (16 tests)
    - `integration/test_forward_secrecy_integration.py` (exists, keep)
  - Files to deprecate (verified exist):
    - `debug_forward_secrecy.py` - needs deprecation header
    - `integration/test_forward_secrecy.py` - needs deprecation header
    - `integration/test_cli_forward_secrecy.py` - needs deprecation header
    - `integration/test_fs_integration.py` - needs deprecation header
  - [ ] Add deprecation headers to old files
  - [ ] Verify pytest skips deprecated files

- [ ] **Merge 5:** Duress family → `test_duress.py` ⏳ PENDING
  - Sources: ALL duress/decoy/timelock files (10+ files)
  - [ ] Create `test_duress.py` from `test_duress_mode.py`
  - [ ] Merge all others
  - [ ] Add deprecation headers

- [ ] **Merge 6:** Schrödinger family → `test_schrodinger.py` ⏳ PENDING (7+ files still exist)
  - Canonical: `test_schrodinger.py`
  - Sources to merge: `test_schrodinger_comprehensive.py`, `test_schrodinger_roundtrip.py`,
    `test_schrodinger_security.py`, `test_phase3_schrodinger_security.py`,
    `test_quantum_mixer.py`, `test_multi_secret.py`, `integration/test_schrodinger_e2e.py`
  - [ ] Merge into `test_schrodinger.py`
  - [ ] Add deprecation headers

- [x] **Merge 7:** Encode pipeline → `test_encode.py` ✅ VERIFIED
  - Status: Deprecation headers added to source files
  - Canonical: `test_encode.py` (61 tests)
  - Canonical: `test_forward_secrecy_encoder.py` (23 tests) - kept separate
  - Deprecated (verified): `test_encode_decode.py` has deprecation header
  - Deprecated (verified): `test_core_encode_decode_unit.py` has deprecation header
  - **Total:** 84 passing, skipped tests in deprecated files

- [x] **Merge 8:** Decode pipeline → `test_decode_gif.py` ✅ VERIFIED
  - Status: Canonical files in place, sources deprecated
  - Canonical: `test_decode_gif.py` (45+ tests)
  - Canonical: `test_forward_secrecy_decoder.py` (28 tests) - kept separate
  - **Total:** 73 passing

- [x] **Merge 9:** PQ family → `test_pq.py` ✅ VERIFIED
  - Status: Only 3 canonical files remain (verified via filesystem)
  - Canonical: `test_pq.py` (27 tests)
  - Canonical: `test_pq_integration.py` (14 tests)
  - Canonical: `test_pq_signatures.py` (29 tests)
  - Deleted: test_pq_hybrid.py, test_pq_hybrid_fail_closed.py (verified not on disk)
  - **Total:** 70 tests (37 pass, 33 skipped - liboqs not installed)

- [ ] **Merge 10:** Security family → `test_security.py`
  - Sources: ALL security/adversarial files (8 files)
  - [ ] Merge into `test_security.py`
  - [ ] Add deprecation headers

### Phase 2: Secondary Merges

- [ ] **Merge 11:** CLI family → `test_cli.py`
- [ ] **Merge 12:** Config family → `test_config.py`
- [ ] **Merge 13:** Stego family → `test_stego.py`
- [ ] **Merge 14:** Hardware family → `test_hardware.py`
- [ ] **Merge 15:** Metadata family → `test_metadata.py`
- [ ] **Merge 16:** Integration family → `test_integration.py`
- [ ] **Merge 17:** Utils family → `test_utils.py`
- [ ] **Merge 18:** Streaming family → `test_streaming_crypto.py`
- [ ] **Merge 19:** Cat utils → `test_cat_utils.py`
- [ ] **Merge 20:** Progress → `test_progress.py`

---

## DETAILED FILE LISTS FOR EACH MERGE

### Merge 1: Fountain Family → `test_fountain.py`

**Canonical target:** `tests/test_fountain.py`

| Source File (Path) | Est. Tests | Priority |
|--------------------|------------|----------|
| `tests/test_fountain.py` | KEEP | Canonical |
| `tests/test_fountain_aggressive.py` | ~10 | Merge |
| `tests/test_coverage_90_fountain.py` | ~15 | Merge |
| `tests/test_coverage_90_fountain_paths.py` | ~8 | Merge |
| `tests/integration/test_fountain_fix.py` | ~5 | Merge |
| `tests/test_catnip_fountain.py` | ~6 | Merge |
| `tests/test_merkle_tree_aggressive.py` | ~4 | Merge |

---

### Merge 2: QR Family → `test_qr_code.py`

**Canonical target:** `tests/test_qr_code.py`

| Source File (Path) | Est. Tests | Priority |
|--------------------|------------|----------|
| `tests/test_qr_code.py` | KEEP | Canonical |
| `tests/test_qr_code_aggressive.py` | ~8 | Merge |
| `tests/test_coverage_90_qr_gif.py` | ~12 | Merge |
| `tests/test_coverage_90_qr_gif_paths.py` | ~6 | Merge |
| `tests/test_coverage_90_qr_reader.py` | ~8 | Merge |
| `tests/test_coverage_qr_code.py` | ~10 | Merge |
| `tests/test_core_qr_code_generator.py` | ~5 | Merge |
| `tests/test_core_qr_reader_unit.py` | ~5 | Merge |
| `tests/test_ascii_qr.py` | ~4 | Merge |

---

### Merge 3: GIF Handler Family → `test_gif_handler.py`

**Canonical target:** `tests/test_gif_handler.py`

| Source File (Path) | Est. Tests | Priority |
|--------------------|------------|----------|
| `tests/test_gif_handler.py` | KEEP | Canonical |
| `tests/test_gif_handler_aggressive.py` | ~8 | Merge |
| `tests/test_coverage_90_gif_handler.py` | ~10 | Merge |
| `tests/test_core_gif_handler.py` | ~6 | Merge |
| `tests/test_core_gif_handler_more.py` | ~4 | Merge |

---

### Merge 4: Forward Secrecy Family → Multiple Canonical Files ⏳ PENDING

**Strategy:** Forward Secrecy has 6 source modules, so we keep 4 canonical unit test files aligned with their modules, plus 1 consolidated integration file.

| Source Module | Canonical Test File | Tests | Status |
|---------------|---------------------|-------|--------|
| `forward_secrecy_x25519.py` | `test_forward_secrecy_x25519.py` | 39 | ✅ Keep |
| `x25519_forward_secrecy.py` | `test_forward_secrecy_x25519.py` | (included) | ✅ Keep |
| `forward_secrecy_decoder.py` | `test_forward_secrecy_decoder.py` | 28 | ✅ Keep |
| `forward_secrecy_encoder.py` | `test_forward_secrecy_encoder.py` | 23 | ✅ Keep |
| `double_ratchet.py` | `test_double_ratchet.py` | 16 | ✅ Keep |
| Integration tests | `integration/test_forward_secrecy_integration.py` | 10 | ⏳ CREATE |

**Files To Deprecate (NOT YET DONE - no deprecation headers added):**

| File | Tests | Status |
|------|-------|--------|
| `debug_forward_secrecy.py` | 1 | ⏳ NEEDS deprecation header |
| `integration/test_forward_secrecy.py` | 4 | ⏳ NEEDS deprecation header |
| `integration/test_cli_forward_secrecy.py` | 3 | ⏳ NEEDS deprecation header |
| `integration/test_fs_integration.py` | 4 | ⏳ NEEDS deprecation header |

**NEXT ACTION:** Add deprecation headers to 4 files listed above, then mark this merge COMPLETE.

---

### Merge 5: Duress Family → `test_duress.py`

**Canonical target:** `tests/test_duress.py` (rename from test_duress_mode.py)

| Source File (Path) | Est. Tests | Priority |
|--------------------|------------|----------|
| `tests/test_duress_mode.py` | KEEP→Rename | Canonical |
| `tests/test_duress_mode_aggressive.py` | ~8 | Merge |
| `tests/test_duress_modes.py` | ~6 | Merge |
| `tests/test_coverage_90_duress_paths.py` | ~8 | Merge |
| `tests/test_phase4_duress_timing.py` | ~4 | Merge |
| `tests/verify_duress_e2e.py` | ~3 | Merge |
| `tests/test_decoy_generator.py` | ~6 | Merge |
| `tests/test_timelock_duress.py` | ~8 | Merge |
| `tests/test_deadmans_switch.py` | ~5 | Merge |

*Note: Files previously listed but not found: test_coverage_90_duress_mode.py, test_coverage_90_security_advanced.py*

---

### Merge 6: Schrödinger Family → `test_schrodinger.py` ⏳ PENDING

**Canonical target:** `tests/test_schrodinger.py`

**Status:** Tests pass individually but consolidation NOT DONE - 8 source files still exist.

| Source File (Path) | Tests | Status |
|--------------------|-------|--------|
| `tests/test_schrodinger.py` | 34 pass, 1 skip | ✅ Canonical |
| `tests/test_schrodinger_comprehensive.py` | 20 | ⏳ Needs deprecation |
| `tests/test_schrodinger_roundtrip.py` | 1 | ⏳ Needs deprecation |
| `tests/test_schrodinger_security.py` | 6 | ⏳ Needs deprecation |
| `tests/test_phase3_schrodinger_security.py` | 13 | ⏳ Needs deprecation |
| `tests/integration/test_schrodinger_e2e.py` | 5 | ⏳ Needs deprecation |
| `tests/test_quantum_mixer.py` | 28 | ⏳ Needs deprecation |
| `tests/test_multi_secret.py` | 58 | ⏳ Needs deprecation |

**NEXT ACTION:** Add deprecation headers to 7 source files and merge unique tests into canonical file.

---

### Merge 7: Encode Pipeline → `test_encode.py` ✅ VERIFIED

**Canonical target:** `tests/test_encode.py`

| Source File (Path) | Est. Tests | Status |
|--------------------|------------|--------|
| `tests/test_encode.py` | 61 pass, 1 slow | ✅ Canonical (fixed purr logger pollution) |
| `tests/test_encode_decode.py` | 19 skipped | ✅ Already handled |
| `tests/test_core_encode_decode_unit.py` | 3 skipped | ✅ Already handled |
| `tests/test_forward_secrecy_encoder.py` | 23 pass | ✅ Verified |

**Fix Applied:** Added `reset_purr_logger` autouse fixture to test_encode.py (lines 15-27) to reset global `_purr_logger` singleton after each test, preventing state pollution from `--purr-mode` tests.

**SLOW TEST:** `test_encode_large_file` marked with `@pytest.mark.slow` - deselect with `-m "not slow"`

**Total: 84 passing, 22 skipped, 1 slow**

---

### Merge 8: Decode Pipeline → `test_decode_gif.py` ✅ VERIFIED

**Canonical target:** `tests/test_decode_gif.py`

| Source File (Path) | Est. Tests | Priority | Status |
|--------------------|------------|----------|--------|
| `tests/test_decode_gif.py` | KEEP | Canonical | ✅ 45 pass, 1 skip |
| `tests/test_forward_secrecy_decoder.py` | 28 | Clean | ✅ 28 pass |
| `tests/test_coverage_90_decode.py` | ~15 | Merge | ❌ Does not exist |
| `tests/test_decode_gif_aggressive.py` | ~10 | Merge | ❌ Does not exist |
| `tests/test_core_cli_decode_main.py` | ~5 | Merge | ❌ Does not exist |
| `tests/test_core_decode_gif_more.py` | ~6 | Merge | ❌ Does not exist |
| `tests/test_coverage_decode_gif_verbose_and_macs.py` | ~8 | Merge | ❌ Does not exist |
| `tests/test_coverage_90_encode_decode_cli.py` | SPLIT | Decode portion | ❌ Does not exist |

**Fixes Applied:**
1. `test_manifest_without_mac_size` - Added missing `from meow_decoder.decode_gif import decode_gif`
2. `test_droplet_mac_rejection_verbose` - Added missing `from meow_decoder.decode_gif import decode_gif`
3. `test_yubikey_pin_prompt_called` - Fixed monkeypatch target from `getpass.getpass` to `meow_decoder.decode_gif.getpass`
4. `test_hsm_pin_prompt_called` - Fixed monkeypatch target from `getpass.getpass` to `meow_decoder.decode_gif.getpass`

**Total: 73 passing, 1 skipped**

---

### Merge 9: PQ Family → `test_pq.py` ✅ VERIFIED

**Status:** CONSOLIDATION COMPLETE

**Actions Taken:**
1. **test_pq_crypto.py** → renamed to **test_pq.py** (canonical)
2. **test_pq_hybrid.py** → DELETED (was identical duplicate - same MD5 hash as test_pq_crypto.py)
3. **test_pq_hybrid_fail_closed.py** → DELETED (3 tests merged into test_pq.py as TestPQFailClosed class)
4. **test_phase4_pq_integration.py** → renamed to **test_pq_integration.py** (kept separate - detailed security documentation with GAP-02 annotations)
5. **test_pq_signatures.py** → kept as-is (29 tests)
6. **test_pq_crypto_real.py** → DID NOT EXIST
7. **test_coverage_90_pq_crypto.py** → DID NOT EXIST

**Final PQ Test Files (3):**
| File | Tests | Status |
|------|-------|--------|
| `test_pq.py` | 27 (24 original + 3 merged) | ✅ Canonical |
| `test_pq_integration.py` | 14 | ✅ Security integration tests |
| `test_pq_signatures.py` | 29 | ✅ Signature-specific tests |

**Test Results:** 37 passed, 33 skipped (all skips are liboqs not installed - intentional)

---

### Merge 10: Security Family → `test_security.py`

**Canonical target:** `tests/test_security.py`

| Source File (Path) | Est. Tests | Priority |
|--------------------|------------|----------|
| `tests/test_security.py` | KEEP | Canonical |
| `tests/test_adversarial.py` | ~12 | Merge |
| `tests/test_tamper_detection.py` | ~8 | Merge |
| `tests/test_grok_security.py` | ~6 | Merge |
| `tests/test_phase2_security.py` | ~8 | Merge |
| `tests/test_coverage_90_deep_security.py` | ~10 | Merge |
| `tests/test_invariants.py` | ~6 | Merge |
| `tests/test_kdf.py` | ~5 | Merge |

---

### Merge 11-20: Secondary Merges (Quick Reference)

| Merge | Canonical Target | Key Source Files (Verified Existing) |
|-------|------------------|--------------------------------------|
| **11: CLI** | `test_cli.py` | `test_coverage_90_cli.py` |
| **12: Config** | `test_config.py` | `test_config_aggressive.py` |
| **13: Stego** | `test_stego_advanced.py` | `test_logo_eyes.py` |
| **14: Hardware** | `test_hardware_integration.py` | `test_hardware_integration_comprehensive.py`, `test_phase5_hardware_mocks.py`, `test_hardware_keys.py`, `test_hardware_mocks.py` |
| **15: Metadata** | `test_metadata.py` | `test_metadata_obfuscation.py`, `test_metadata_obfuscation_aggressive.py`, `test_coverage_90_metadata_paths.py`, `test_coverage_90_metadata_mac.py` |
| **16: Integration** | `test_integration.py` | `test_e2e.py`, `integration/test_comprehensive.py`, `integration/test_full_roundtrip.py`, `test_encode_decode.py`, `test_core_encode_decode_unit.py`, `test_fuzz_roundtrip.py` |
| **17: Utils** | `test_misc_utils.py` | `test_coverage_90_utils.py`, `test_edge_cases.py`, `test_entropy_boost.py`, `test_bidirectional.py` |
| **18: Streaming** | `test_streaming_crypto.py` | `test_streaming.py` |
| **19: Cat Utils** | `test_cat_utils.py` | (none - standalone) |
| **20: Progress** | `test_progress.py` | `test_coverage_90_deep_progress.py` |

---

### Phase 3: Cleanup

- [ ] Run full test suite: `pytest tests/ -v`
- [ ] Run coverage: `pytest tests/ --cov=meow_decoder --cov-report=html`
- [ ] Verify no regressions
- [ ] Delete deprecated files (after verification)
- [ ] Update testtodo.md

---

## FINAL TARGET STRUCTURE

After consolidation, `tests/` should contain approximately:

```
tests/
├── __init__.py
├── conftest.py
├── test_cat_utils.py
├── test_cli.py
├── test_clowder.py
├── test_config.py
├── test_constant_time.py
├── test_crypto.py
├── test_crypto_backend.py
├── test_crypto_enhanced.py
├── test_decode_gif.py
├── test_duress.py
├── test_encode.py
├── test_forward_secrecy.py
├── test_fountain.py
├── test_frame_mac.py
├── test_gif_handler.py
├── test_hardware.py
├── test_high_security.py
├── test_imports.py
├── test_integration.py
├── test_metadata.py
├── test_pq.py
├── test_progress.py
├── test_property_based.py
├── test_prowling.py
├── test_qr_code.py
├── test_resume.py
├── test_schrodinger.py
├── test_secure_bridge.py
├── test_secure_cleanup.py
├── test_security.py
├── test_security_warnings.py
├── test_sidechannel.py
├── test_stego.py
├── test_streaming_crypto.py
├── test_utils.py
├── test_ux.py
├── test_webcam.py
└── spec_v12/
    └── test_spec_v12_core.py
```

**Target: ~40 canonical files** (down from 120)

---

## DEPRECATION HEADER TEMPLATE

Add this to the TOP of every file being merged away:

```python
# =============================================================================
# DEPRECATED — MERGED INTO test_XXXXXXXX.py
# All content moved on 2026-01-31. Do not add new tests here.
# This file will be deleted after verification.
# =============================================================================
```

---

## MERGE PRIORITY MATRIX (Verified 2026-02-01)

This matrix uses numbering consistent with the MASTER MAPPING TABLE above.

| Merge Task | Family | # Files to Merge | Status |
|------------|--------|------------------|--------|
| **Tasks 1-3:** Crypto (3 small merges) | crypto_paths, streaming, frame_mac | 3 | ⏳ PENDING |
| **Task 4:** Forward Secrecy | Keep 4 canonical + deprecate integration | 4 deprecated | ⏳ PENDING (no headers) |
| **Task 5:** Fountain | fountain_aggressive, coverage_90 files, catnip, merkle | 5 | ⏳ PENDING |
| **Tasks 6-7:** Encode/Decode | encode_aggressive, coverage_90 files | 6 | ✅ VERIFIED (7+8) |
| **Tasks 8-9:** GIF/QR | gif_aggressive, qr_aggressive, coverage_90 files | 8 | ⏳ PENDING (files exist) |
| **Task 10:** Stego | coverage_90_stego, ninja_cat, logo_eyes | 3 | ⏳ PENDING |
| **Task 11:** Schrödinger | 5 files → test_schrodinger.py | 5 | ⏳ PENDING (files exist) |
| **Task 12:** Duress | 7 files → test_duress.py | 7 | ⏳ PENDING |
| **Task 13:** PQ | pq_crypto, pq_hybrid, pq_signatures | 3 | ✅ VERIFIED (merge 9) |
| **Task 14:** Hardware | hardware_integration, hardware_keys, mocks | 5 | ⏳ PENDING |
| **Tasks 15-17:** Config/CLI/Cat | config, cli, cat_utils merges | 5 | ⏳ PENDING |
| **Task 18:** Metadata | metadata files | 4 | ⏳ PENDING |
| **Task 19:** Security | adversarial, tamper, grok, phase2 | 6 | ⏳ PENDING |
| **Tasks 20-21:** Integration/Utils | e2e, comprehensive, misc_utils | 8 | ⏳ PENDING |

**Summary:**
- ✅ VERIFIED DONE: 3 merges (Encode, Decode, PQ)
- ⏳ PENDING: 18 merges
- **Estimated files to process:** ~72 files → ~35-40 canonical targets

---

## MERGE PROCEDURE TEMPLATE

For each merge task, follow this procedure:

### Step 1: Inventory Source Files
```bash
# List all files to be merged for this family
ls -la tests/test_*<family>*.py
ls -la tests/test_coverage_90_*<family>*.py
ls -la tests/integration/*<family>*.py 2>/dev/null || true
```

### Step 2: Read and Catalog Tests
For each source file:
- Count number of test classes
- Count number of test functions
- Note any fixtures specific to that file
- Note any pytest marks used

### Step 3: Check for True Duplicates
```python
# Tests that test the same thing - candidates for removal:
# - Same function name, same assertions
# - Identical test logic with different names
```

### Step 4: Merge into Canonical File
- Copy all non-duplicate test classes/functions
- Preserve all docstrings
- Combine imports (sorted alphabetically)
- Keep all fixtures (move to conftest.py if shared)

### Step 5: Add Deprecation Header to Source Files
```python
# =============================================================================
# DEPRECATED — MERGED INTO test_XXXXXXXX.py
# All content moved on 2026-01-31. Do not add new tests here.
# This file will be deleted after verification.
# =============================================================================
```

### Step 6: Verify
```bash
pytest tests/test_<canonical>.py -v
```

---

## PROGRESS TRACKER

### ✅ Completed Merges (Verified via Filesystem)
| Merge | Status | Date | Notes |
|-------|--------|------|-------|
| **Merge 7:** Encode pipeline | ✅ VERIFIED | 2026-02-01 | Deprecation headers added to test_encode_decode.py, test_core_encode_decode_unit.py. Canonical: test_encode.py |
| **Merge 8:** Decode pipeline | ✅ VERIFIED | 2026-02-01 | Canonical files in place: test_decode_gif.py, test_forward_secrecy_decoder.py |
| **Merge 9:** PQ family | ✅ VERIFIED | 2026-02-01 | Only 3 files remain on disk: test_pq.py, test_pq_integration.py, test_pq_signatures.py. Duplicates deleted. |

### ⏳ Pending Merges (Source Files Still Exist)
| Merge | Status | Files Remaining | Notes |
|-------|--------|-----------------|-------|
| **Merge 1:** Fountain family | ⏳ PENDING | test_catnip_fountain.py | Need to verify if other sources exist |
| **Merge 2:** QR family | ⏳ PENDING | 9 files on disk | test_qr_code_aggressive.py, test_coverage_*.py, test_core_qr_*.py, test_ascii_qr.py |
| **Merge 3:** GIF handler | ⏳ PENDING | 4 files on disk | test_gif_handler_aggressive.py, test_core_gif_handler*.py |
| **Merge 4:** Forward Secrecy | ⏳ PENDING | debug_forward_secrecy.py + 3 integration files | Need deprecation headers |
| **Merge 5:** Duress family | ⏳ PENDING | 10+ files | Not started |
| **Merge 6:** Schrödinger family | ⏳ PENDING | 7+ files | Not started |
| **Merge 10:** Security family | ⏳ PENDING | 8 files | Not started |
| **Merge 11-20:** Secondary families | ⏳ PENDING | ~40 files | Not started |

### Summary
- **Verified Complete:** 3 merges (7, 8, 9)
- **Pending:** 17+ merges (1-6, 10-20)
- **Files processed:** ~15 of 120 files addressed
- **Files remaining:** ~105 files need consolidation

---

## SPECIAL CASES TO HANDLE

### 1. Test Files with Shared Fixtures
These files have fixtures that multiple tests use:
- `conftest.py` - KEEP (shared fixtures)
- Files with local fixtures → Move fixtures to conftest.py or inline

### 2. Files with Skip Markers
Some tests are marked with `@pytest.mark.skip` or conditionals:
- Preserve all skip conditions
- Keep `skipif` decorators intact
- Document why tests are skipped

### 3. Tests Requiring External Resources
- Webcam tests → Keep in `test_webcam.py` (requires hardware)
- HSM/TPM tests → Keep in `test_hardware.py` (mock-heavy)
- Network tests → Flag as integration tests

### 4. Property-Based Tests
- Keep `test_property_based.py` separate (Hypothesis framework)
- Don't merge into unit test files

### 5. Spec Tests
- Keep `spec_v12/` directory intact
- These test protocol specification compliance

---

## FILE INVENTORY (Current State)

Run this command to get current file count:
```bash
find tests/ -name "test_*.py" -type f | wc -l
```

### Breakdown by Pattern (Verified 2026-02-01)

| Pattern | Count | Action |
|---------|-------|--------|
| `test_coverage_90_*.py` | 12 | Merge into canonical |
| `test_*_aggressive.py` | 6 | Merge into canonical |
| `test_phase*.py` | 7 | Merge into canonical |
| `test_core_*.py` | 7 | Merge into canonical |
| `test_coverage_*.py` (other) | 7 | Merge into canonical |
| `integration/*.py` | 7 | Merge into canonical |
| Canonical files | ~74 | KEEP (remainder after patterns) |
| Deprecated/debug files | 2 | Merge or delete (debug_*, verify_*) |

**Total cleanup pattern files:** 46 (12+6+7+7+7+7=46, minus some overlap)

---

## VALIDATION CHECKLIST (Per Merge)

### Pre-Merge Verification
- [ ] Identified all source files for this merge
- [ ] Ran all source tests individually to confirm they pass
- [ ] Noted any skip markers or special conditions
- [ ] Identified shared fixtures needed

### During Merge
- [ ] Created backup of canonical file
- [ ] Merged imports (deduplicated, alphabetized)
- [ ] Merged fixtures (avoid duplicates)
- [ ] Merged test classes (preserve names)
- [ ] Merged standalone test functions
- [ ] Resolved any naming conflicts

### Post-Merge Verification
- [ ] Canonical file runs without errors: `pytest tests/test_<name>.py -v`
- [ ] Same or more tests passing vs. sum of sources
- [ ] Coverage not decreased for module
- [ ] No warnings about duplicate test names
- [ ] All assertions preserved

### Cleanup
- [ ] Add deprecation header to source files
- [ ] Update this document's progress tracker
- [ ] Commit with descriptive message

---

## COMMON MERGE PATTERNS

### Pattern A: Simple Append
When source tests are independent and use no shared fixtures:
```python
# Just append all tests from source files to end of canonical
# Minimal conflict potential
```

### Pattern B: Fixture Consolidation
When multiple source files define similar fixtures:
```python
@pytest.fixture
def sample_data():
    """Consolidated fixture from multiple sources."""
    return {...}

# Use same fixture across all merged tests
```

### Pattern C: Class Grouping
Organize merged tests into logical classes:
```python
class TestFountainEncoding:
    """Tests from test_fountain.py + test_fountain_aggressive.py"""
    pass

class TestFountainDecoding:
    """Tests from test_coverage_90_fountain.py"""
    pass

class TestFountainEdgeCases:
    """Tests from test_coverage_90_fountain_paths.py"""
    pass
```

### Pattern D: Parametrize Expansion
When source files test same function with different inputs:
```python
# Before (in separate files):
def test_encrypt_small(): ...
def test_encrypt_large(): ...

# After (merged with parametrize):
@pytest.mark.parametrize("size", ["small", "medium", "large"])
def test_encrypt(size): ...
```

### Pattern E: Skip Preservation
Always preserve skip decorators:
```python
@pytest.mark.skipif(not HAS_LIBOQS, reason="liboqs not installed")
def test_pq_encryption():
    ...
```

---

## NOTES

- Do NOT delete any test logic during merge
- Deduplicate only truly identical tests
- Combine imports alphabetically
- Keep fixtures and marks
- Run pytest after each major merge batch
- If a file is >2000 lines after merge, consider splitting by class/theme

---

## RISK MITIGATION

### Before Starting
- [ ] Commit current state: `git add -A && git commit -m "Pre-merge checkpoint"`
- [ ] Create backup branch: `git checkout -b test-cleanup-backup`
- [ ] Return to main: `git checkout main`

### After Each Merge
- [ ] Run `pytest tests/test_<merged>.py -v`
- [ ] Check coverage hasn't dropped: `pytest tests/test_<merged>.py --cov`
- [ ] Commit: `git commit -am "Merge <family> tests into test_<canonical>.py"`

### Rollback Plan
```bash
git checkout test-cleanup-backup -- tests/
```

---

## QUICK REFERENCE COMMANDS

### Discovery Commands
```bash
# Count all test files
find tests/ -name "test_*.py" -type f | wc -l

# List files by pattern
find tests/ -name "test_coverage_90_*.py" -type f | sort
find tests/ -name "test_*_aggressive.py" -type f | sort
find tests/ -name "test_phase*.py" -type f | sort
find tests/ -name "test_core_*.py" -type f | sort

# Count tests in a file
pytest tests/test_<name>.py --collect-only | grep "test_" | wc -l

# Find tests using a specific fixture
grep -l "def sample_data" tests/test_*.py
```

### Merge Commands
```bash
# Run single canonical test file
pytest tests/test_fountain.py -v

# Run with coverage for specific module
pytest tests/test_fountain.py --cov=meow_decoder/fountain --cov-report=term-missing

# Compare test counts before/after merge
pytest tests/test_fountain*.py --collect-only 2>/dev/null | grep "<Function" | wc -l
```

### Cleanup Commands
```bash
# Find duplicate test function names
grep -h "def test_" tests/test_*.py | sort | uniq -d

# List all imports in a test file
grep "^import\|^from" tests/test_fountain.py | sort -u

# Find shared fixtures
grep -l "@pytest.fixture" tests/test_*.py

# Check for orphaned imports after merge
python -c "import tests.test_fountain"  # Should have no errors
```

### Git Commands
```bash
# Pre-merge checkpoint
git add -A && git commit -m "Pre-merge checkpoint: $(date +%Y%m%d)"

# Create backup branch
git checkout -b test-cleanup-backup && git checkout main

# After each merge
git diff --stat tests/
git add tests/test_<canonical>.py tests/test_<deprecated>.py
git commit -m "Merge <family> tests into test_<canonical>.py"

# Rollback single file
git checkout HEAD~1 -- tests/test_<file>.py

# Full rollback
git checkout test-cleanup-backup -- tests/
```

---

## ESTIMATED TIMELINE

| Phase | Merges | Estimated Time | Cumulative |
|-------|--------|----------------|------------|
| Phase 1 | 1-10 (Core) | 4-6 hours | 4-6 hours |
| Phase 2 | 11-20 (Secondary) | 3-4 hours | 7-10 hours |
| Phase 3 | Cleanup/Verify | 1-2 hours | 8-12 hours |

**Total estimated effort:** 8-12 hours (1-2 work days)

---

## DEPRECATION WORKFLOW

### Step 1: Add Deprecation Header to Source File

After merging tests into canonical file, add this header to the deprecated file:

```python
"""
⚠️ DEPRECATED - DO NOT ADD NEW TESTS HERE ⚠️

This file has been merged into: tests/test_<canonical>.py
Date: YYYY-MM-DD
Reason: Test suite consolidation (see cleanuptests.md)

This file will be removed in a future cleanup. All tests have been
preserved in the canonical file.

To run the consolidated tests:
    pytest tests/test_<canonical>.py -v
"""

import warnings
warnings.warn(
    "This test module is deprecated. Use test_<canonical>.py instead.",
    DeprecationWarning,
    stacklevel=2
)

# Original code below (kept for reference during transition)
```

### Step 2: Update conftest.py (Optional)

Add collection ignore for deprecated files:
```python
# In tests/conftest.py
collect_ignore = [
    "test_coverage_90_fountain.py",  # Merged into test_fountain.py
    "test_fountain_aggressive.py",   # Merged into test_fountain.py
    # ... add more as merged
]
```

### Step 3: Final Deletion (Phase 3)

After verifying all tests pass in canonical files:
```bash
# Remove deprecated files
git rm tests/test_coverage_90_*.py
git rm tests/test_*_aggressive.py
git rm tests/test_phase*.py
# ... etc

git commit -m "Remove deprecated test files after consolidation"
```

---

## POST-CLEANUP VERIFICATION

### Coverage Check
```bash
# Full test suite coverage
pytest tests/ --cov=meow_decoder --cov-report=html

# Compare before/after
# Before cleanup: record total coverage %
# After cleanup: should be >= before
```

### Test Count Verification
```bash
# Count all test functions
pytest tests/ --collect-only 2>/dev/null | grep "<Function" | wc -l

# Should be approximately same as before (minus exact duplicates)
```

### CI Pipeline Check
- [ ] All GitHub Actions workflows pass
- [ ] No missing imports
- [ ] No broken fixtures
- [ ] Coverage gates met

---

## KNOWN EDGE CASES

### 1. Circular Fixture Dependencies
Some test files share fixtures defined in multiple places. Resolution:
- Move shared fixtures to `tests/conftest.py`
- Or create `tests/fixtures/<module>_fixtures.py`

### 2. Test Class Name Conflicts
If two source files have `class TestFountain`:
- Rename to `TestFountainEncoding` and `TestFountainDecoding`
- Or merge into single class with all methods

### 3. Parametrize Conflicts
If two files have same test name with different parametrize:
```python
# Combine into single parametrize
@pytest.mark.parametrize("input,expected", [
    # From file A
    ("a", 1),
    ("b", 2),
    # From file B  
    ("c", 3),
    ("d", 4),
])
def test_combined(input, expected): ...
```

### 4. Skip Marker Differences
If same test is skipped in one file but not another:
- Keep the skip marker (conservative approach)
- Document why in the test

### 5. Integration Tests in Unit Test Files
Some `test_coverage_90_*.py` files have integration tests:
- Move true integration tests to `tests/integration/`
- Keep unit tests in canonical file

---

## SUCCESS CRITERIA

The cleanup is complete when:

- [ ] Test file count: 120 → ~35-40 (goal: 67% reduction)
- [ ] All tests passing: `pytest tests/ -v` → 0 failures
- [ ] Coverage maintained: ≥ previous coverage %
- [ ] No duplicate test names: `grep -h "def test_" tests/test_*.py | sort | uniq -d` → empty
- [ ] CI green: All GitHub Actions workflows pass
- [ ] Documentation updated: This file marked COMPLETE
- [ ] Deprecated files removed (Phase 3)

---

## APPENDIX: FULL FILE LIST (FOR REFERENCE)

To generate current list of all test files:
```bash
find tests/ -name "test_*.py" -type f | sort > test_files_current.txt
```

### Expected Final Structure

```
tests/
├── conftest.py                    # Shared fixtures
├── __init__.py
│
├── # Core Crypto (6 files)
├── test_crypto.py
├── test_crypto_backend.py
├── test_crypto_enhanced.py
├── test_constant_time.py
├── test_streaming_crypto.py
├── test_frame_mac.py
│
├── # Security (4 files)
├── test_security.py
├── test_sidechannel.py
├── test_secure_bridge.py
├── test_secure_cleanup.py
│
├── # Forward Secrecy (1 file)
├── test_forward_secrecy.py
│
├── # Fountain/Encoding (4 files)
├── test_fountain.py
├── test_encode.py
├── test_decode_gif.py
├── test_e2e.py
│
├── # QR/GIF (2 files)
├── test_qr_code.py
├── test_gif_handler.py
│
├── # Advanced Features (5 files)
├── test_schrodinger.py
├── test_duress.py
├── test_pq.py
├── test_stego.py
├── test_hardware.py
│
├── # Utilities (5 files)
├── test_config.py
├── test_cli.py
├── test_metadata.py
├── test_cat_utils.py
├── test_progress.py
│
├── # Specialized (keep separate)
├── test_webcam.py                 # Requires hardware
├── test_property_based.py         # Hypothesis framework
├── test_fuzz.py                   # Fuzzing harness
│
├── # Integration (subdirectory)
└── integration/
    ├── test_integration.py
    └── test_comprehensive.py
```

**Total: ~35-40 files** (down from 120)

---

## NEXT SESSION ACTION ITEMS (Priority Order)

This section provides a concrete checklist for the next work session to continue the consolidation.

### Immediate Priority: Complete Merge 4 (Forward Secrecy)

**Status:** 4 files need deprecation headers added

**Files to Process:**
1. `tests/debug_forward_secrecy.py` → Add deprecation header
2. `tests/integration/test_forward_secrecy.py` → Add deprecation header
3. `tests/integration/test_cli_forward_secrecy.py` → Add deprecation header
4. `tests/integration/test_fs_integration.py` → Add deprecation header

**Commands:**
```bash
# Add deprecation header to each file, then verify:
pytest tests/test_forward_secrecy_x25519.py tests/test_forward_secrecy_decoder.py tests/test_forward_secrecy_encoder.py tests/test_double_ratchet.py -v
```

### High Priority: Complete Merge 6 (Schrödinger)

**Status:** 7 files need deprecation headers + unique tests merged

**Files to Process:**
1. `tests/test_schrodinger_comprehensive.py` (20 tests)
2. `tests/test_schrodinger_roundtrip.py` (1 test)
3. `tests/test_schrodinger_security.py` (6 tests)
4. `tests/test_phase3_schrodinger_security.py` (13 tests)
5. `tests/integration/test_schrodinger_e2e.py` (5 tests)
6. `tests/test_quantum_mixer.py` (28 tests)
7. `tests/test_multi_secret.py` (58 tests)

**Canonical Target:** `tests/test_schrodinger.py`

### Medium Priority: Complete Merges 1-3 (Fountain, QR, GIF)

**Merge 1 - Fountain:**
- Canonical: `tests/test_fountain.py`
- Merge: test_catnip_fountain.py, test_merkle_tree_aggressive.py

**Merge 2 - QR:**
- Canonical: `tests/test_qr_code.py`
- Merge: 9 files (test_qr_code_aggressive.py, test_coverage_*, test_core_qr_*, test_ascii_qr.py)

**Merge 3 - GIF:**
- Canonical: `tests/test_gif_handler.py`
- Merge: 4 files (test_gif_handler_aggressive.py, test_core_gif_handler*.py)

### Lower Priority: Merges 5, 10-20

After completing merges 1-6, proceed with:
- Merge 5: Duress family (10+ files)
- Merge 10: Security family (8 files)
- Merges 11-20: Secondary families (~40 files)

---

## GITHUB WORKFLOWS STATUS

**Validated:** 2026-02-02

All 7 GitHub Actions workflows have been verified:

| Workflow | Status | Notes |
|----------|--------|-------|
| `ci.yml` | ✅ Valid YAML | Main test suite + coverage |
| `security-ci.yml` | ✅ Valid YAML | Security tests, pip-audit, cargo-audit |
| `fuzz.yml` | ✅ Valid YAML | Atheris + AFL++ fuzzing (weekly) |
| `rust-crypto.yml` | ✅ Valid YAML | Multi-platform wheel builds |
| `formal-verification.yml` | ✅ Valid YAML | ProVerif + TLA+ |
| `codeql.yml` | ✅ Valid YAML | CodeQL security scanning |
| `cleanup.yml` | ✅ Valid YAML | Workflow run cleanup |

**Actions Versions:** All using current versions (v4/v5 where applicable)

---

## SESSION LOG

| Date | Session | Work Completed |
|------|---------|----------------|
| 2026-02-01 | Initial | Created document, verified merges 7-9 |
| 2026-02-02 | Continuation | Verified workflows, added action items |

---

**Last updated:** 2026-02-02 (Verified: Merges 7, 8, 9 complete; Merges 1-6, 10-20 pending; All workflows validated)
