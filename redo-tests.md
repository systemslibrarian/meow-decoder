# 🐱 Meow Decoder Test Engineering Progress

**Last Updated:** 2026-02-02  
**Overall Status:** 1/23 files complete  
**Current File:** crypto.py  

---

## ⚠️ IMPORTANT: Using tests-archved for Templates

> **PERMANENT NOTE (preserve across all sessions):**
>
> The `tests-archved` folder contains archived older test files with proven:
> - Adversarial test patterns
> - Fixtures and Hypothesis strategies  
> - Mocks for crypto, forward secrecy, duress, hardware, stego, etc.
>
> **Workflow requirement:** Before writing tests for ANY file:
> 1. Reuse proven patterns instead of starting from scratch
> 2. This speeds up work and improves test quality significantly

---

## 📋 Master Checklist

### 1. crypto_backend.py ✅ COMPLETE
- [x] Fetch/review code
- [x] Review existing tests: Template from _test_crypto_backend.py (if exists)
- [x] Analyze gaps: Rust FFI boundaries, panic handling, fallback paths
- [x] Create new tests: Mock Rust errors, invalid bindings, parity checks
- [x] Verify coverage: **98% statement, 100% branch** (3 lines uncoverable: import fallback + YubiKey hardware)
- [x] Pass all tests: **All passing**
- [ ] Gitflow: Branch/PR/merge (optional - working on main)

### 2. crypto.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_crypto.py
- [ ] Analyze gaps: Nonce reuse, tag failures, key derivation branches
- [ ] Create new tests: AEAD tamper, truncation attacks
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 3. crypto_enhanced.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_crypto_enhanced.py
- [ ] Analyze gaps: Enhanced AAD, hybrid mode branches
- [ ] Create new tests: AAD tampering, mode switches
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 4. constant_time.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_constant_time.py
- [ ] Analyze gaps: Timing comparison branches, variable-length inputs
- [ ] Create new tests: Dudect-style mocks, side-channel simulations
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 5. secure_cleanup.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_secure_cleanup.py
- [ ] Analyze gaps: Overwrite failures, memory leak paths
- [ ] Create new tests: Mock os.unlink errors, zeroization verification
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 6. forward_secrecy.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_forward_secrecy.py
- [ ] Analyze gaps: Ratchet compromise branches
- [ ] Create new tests: Old-key attacks, session fuzzing
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 7. x25519_forward_secrecy.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_x25519_forward_secrecy.py
- [ ] Analyze gaps: Curve validation, ephemeral key branches
- [ ] Create new tests: Invalid points, key mismatch
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 8. double_ratchet.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_double_ratchet.py
- [ ] Analyze gaps: Ratchet steps, message reorder/loss
- [ ] Create new tests: Fuzz sequences, recovery from compromise
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 9. pq_crypto_real.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_pq.py
- [ ] Analyze gaps: ML-KEM/Dilithium param branches
- [ ] Create new tests: Invalid params, forgery attempts
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 10. pq_hybrid.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_pq_integration.py
- [ ] Analyze gaps: Hybrid fallback, classical attacks
- [ ] Create new tests: Fallback triggers, combined failures
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 11. pq_signatures.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_pq_signatures.py
- [ ] Analyze gaps: Dilithium verify branches
- [ ] Create new tests: Tampered sigs, key size edges
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 12. duress_mode.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_duress_mode.py
- [ ] Analyze gaps: Duress trigger paths, decoy branches
- [ ] Create new tests: Password distinction, wipe failures
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 13. timelock_duress.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_timelock_duress.py
- [ ] Analyze gaps: Deadline branches, time-based races
- [ ] Create new tests: Freezegun jumps, grace period edges
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 14. encode.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_encode.py
- [ ] Analyze gaps: Input validation, compression branches
- [ ] Create new tests: Malformed files, large inputs
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 15. meow_encode.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_encode_decode.py
- [ ] Analyze gaps: Cat-themed flag branches
- [ ] Create new tests: Flag combos, error paths
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 16. spec_v12/encode.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_core_encode_decode_unit.py
- [ ] Analyze gaps: v1.2 unified key branches
- [ ] Create new tests: v1.2 roundtrips
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 17. decode_gif.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_decode_gif.py
- [ ] Analyze gaps: Corrupted frames, incomplete GIFs
- [ ] Create new tests: Fuzz GIFs, decode failures
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 18. spec_v12/decode.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_core_encode_decode_unit.py
- [ ] Analyze gaps: v1.2 verify branches
- [ ] Create new tests: Version mismatches, sig tampers
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 19. frame_mac.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_frame_mac.py
- [ ] Analyze gaps: MAC computation branches
- [ ] Create new tests: Tamper detection, invalid tags
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 20. stego_advanced.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_stego_advanced.py
- [ ] Analyze gaps: Embedding/extraction branches
- [ ] Create new tests: Malformed carriers, detection resistance
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 21. metadata_obfuscation.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_metadata_obfuscation.py
- [ ] Analyze gaps: Obfuscation/reveal branches
- [ ] Create new tests: Forensic recovery mocks
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 22. hardware_integration.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_hardware_integration.py
- [ ] Analyze gaps: HSM/TPM fallback branches
- [ ] Create new tests: Mock hardware failures, pin errors
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

### 23. hardware_keys.py
- [ ] Fetch/review code
- [ ] Review existing tests: Template from _test_hardware_keys.py
- [ ] Analyze gaps: Key derive/seal branches
- [ ] Create new tests: PCR mismatches, slot errors
- [ ] Verify coverage: 95–100%
- [ ] Pass all tests
- [ ] Gitflow: Branch/PR/merge

---

## 📝 Completion Notes

| File | Coverage | Key Tests Added | Branch/PR |
|------|----------|-----------------|-----------|
| (none yet) | - | - | - |

---

## 🔄 Resumption Instructions

To resume this work:
1. Paste this file back into the conversation, OR
2. Say "Resume from redo-tests.md"
3. Agent will continue from the next unchecked file

**Next file to start:** crypto_backend.py

---

*😼 Purr-fect security starts with purr-fect tests!*
