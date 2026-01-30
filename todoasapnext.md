# 🐱 Meow Decoder v1.3.1 Spec — Execution Checklist (TODO NEXT)

**Source:** MEOW-DECODER CRYPTOGRAPHIC SPECIFICATION v1.3.1  
**Status:** Not started  
**Tracking:** Check items as completed to signal progress

---

## ✅ Phase 0 — Planning & Validation
- [ ] Read and cross-check v1.3.1 spec for gaps/ambiguities
- [ ] Confirm target modules/files do not conflict with existing pipeline
- [ ] Identify external deps needed (PyNaCl, cryptography)

---

## 🔐 Phase 1 — Core Single-Tier Crypto (v1.2/0x0002)
### encode.py (v1.2)
- [x] Implement `encode_file()` with unified Ed25519 keys
- [x] Ed25519 → X25519 conversion (RFC 8410 or libsodium)
- [x] HKDF-SHA-512 derivation (salt/info)
- [x] Enhanced AAD w/ signature placeholder
- [x] Ed25519 sign-header-then-encrypt-payload
- [x] Dynamic GIF insertion (no hard-coded offset)
- [x] Secure zeroization of secrets

### decode.py (v1.2)
- [x] Implement `decode_file()` with unified Ed25519 keys
- [x] Verify recipient pk in header (generic error on mismatch)
- [x] Verify signature before decryption
- [x] AEAD decrypt w/ AAD including signature (non-placeholder)
- [x] Constant-time operations for verification
- [x] Uniform error: "Decryption failed"
- [x] Secure zeroization of secrets

---

## 🧵 Phase 2 — Multi-Tier Decoy System (v1.2)
### multi_tier.py
- [x] Implement `encode_multi_tier()` with identical padding across tiers
- [x] Implement `decode_multi_tier()` constant-time processing of ALL tiers
- [x] Enforce equal ciphertext lengths (reject if mismatch)
- [x] Parse tiers safely and deterministically
- [x] Uniform errors ("Decryption failed")

---

## 🗝️ Phase 3 — Unified Key Management
### key_management.py
- [x] Ed25519 KeyBackend interface (sign + export pk)
- [x] Ed25519 → X25519 conversion helpers
- [x] SecureEnclave backend (stub/guarded)
- [x] TPM backend (stub/guarded)
- [x] StrongBox backend (stub/guarded)
- [x] Software fallback with warning logs
- [x] Backend selection helper (`get_best_backend()`)

---

## 🖼️ Phase 4 — Steganography Carrier I/O
### steganography.py
- [x] `find_gif_insertion_point()` (dynamic insertion)
- [x] `embed_in_gif()` with Application Extension block
- [x] `extract_from_gif()` with MEOW-PAYLOAD marker validation
- [x] Input validation for malformed/truncated payloads

---

## 🧪 Phase 5 — Tests (pytest)
### test_crypto.py
- [x] KAT: ECDH + HKDF v1.2 vectors
- [x] Signature domain separator test
- [x] AAD placeholder construction test
- [x] Roundtrip encode/decode v1.2
- [x] Unified key conversion test
- [x] recipient_pk_in_header test (generic error)
- [x] Dynamic GIF insertion tests (no ext / app ext / comment ext)
- [x] Multi-tier constant-time test (timing within 5%)
- [x] Multi-tier padding size test
- [x] Malformed input tests (wrong version, signature tamper, AAD tamper)

---

## 📘 Phase 6 — Documentation
### README.md updates
- [x] Unified key management explanation
- [x] v1.2 improvements summary
- [x] Threat model summary
- [x] Install instructions (PyNaCl + cryptography)
- [x] Usage examples for v1.2 keys
- [x] Security warnings (error uniformity, timing)

---

## ✅ Phase 7 — Final Verification
- [ ] Run unit tests (pytest)
- [ ] Run integration tests
- [ ] Check lint/formatting (if required)
- [ ] Validate error uniformity across decode paths
- [ ] Confirm constant-time tier handling

---

## 🧾 Completion Checklist
- [ ] All new modules wired into package imports
- [ ] All tests passing
- [ ] Docs updated and consistent with v1.3.1
- [ ] Security invariants validated (AAD binding, signature, constant-time)
