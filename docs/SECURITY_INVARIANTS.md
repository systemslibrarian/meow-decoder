# 🔒 Security Invariants - Meow Decoder

**Version:** 1.0.0 (INTERNAL REVIEW — no external audit)
**Last Updated:** 2026-02-17
**Classification:** Security-Critical Documentation

---

## Overview

This document formally specifies the **security invariants** that Meow Decoder MUST uphold. These are mathematical properties that must hold for ALL inputs - violating any invariant is a security vulnerability.

Invariants are verified through:
1. **Property-based testing** (Hypothesis) - Random input fuzzing
2. **Unit tests** - Specific edge cases
3. **Fuzzing** (AFL++) - Crash detection
4. **Code review** - Manual verification

---

## Critical Invariants

### INV-001: Encrypt-Decrypt Roundtrip

```
∀ plaintext, password, keyfile:
    decrypt(encrypt(plaintext, password, keyfile), password, keyfile) == plaintext
```

**Description:** Decryption must exactly recover the original plaintext for any valid inputs.

**Verification:**
- `tests/test_property_based.py::TestEncryptDecryptInvariants::test_aes_gcm_roundtrip_*`
- `tests/test_property_based.py::TestEncryptDecryptInvariants::test_file_encrypt_decrypt_roundtrip`
- `tests/test_encode.py` / `tests/test_decode_gif.py` (encode-decode roundtrip)

**Failure Impact:** Data corruption, unrecoverable files.

---

### INV-002: Authentication Before Decryption

```
∀ ciphertext, key, nonce, aad:
    IF tampered(ciphertext) OR tampered(aad) THEN
        decrypt(ciphertext, key, nonce, aad) RAISES Exception
```

**Description:** AES-GCM MUST verify the authentication tag BEFORE releasing any plaintext. This prevents chosen-ciphertext attacks.

**Implementation:**
- AES-GCM authentication tag (16 bytes)
- Manifest HMAC-SHA256 (32 bytes)
- Per-frame MAC (8 bytes)

**Verification:**
- `tests/test_property_based.py::TestTamperDetection::test_ciphertext_tampering_detected`
- `tests/test_property_based.py::TestTamperDetection::test_aad_tampering_detected`
- `tests/test_security.py::TestTamperDetection`

**Failure Impact:** Forgery attacks, accepting malicious data.

---

### INV-003: Nonce Uniqueness

```
∀ encryptions e1, e2 with same key K:
    IF e1 ≠ e2 THEN nonce(e1) ≠ nonce(e2)
```

**Description:** Nonce reuse with the same key completely breaks AES-GCM security. Each encryption MUST use a unique (salt, nonce) pair.

**Implementation:**
- **Deterministic synthetic IV via HKDF-SHA-256** (primary mechanism):
  ```
  nonce = HKDF-SHA-256(
      IKM  = transfer_root_key,
      salt = frame_counter (u64 BE) || SHA-256(manifest),
      info = b"aes-gcm-nonce-v1",
      len  = 12
  )
  ```
- Collision resistance: requires HKDF-SHA-256 collision (computationally infeasible).
- Crash-safe: no persistent counter state needed across restarts.
- Multi-process safe: manifest hash unique per transfer session.
- Schrödinger isolation: `additional_context` byte distinguishes sub-streams.
- Per-process reuse guard: `NonceGenerator` tracks used `frame_counter` values
  and raises `RuntimeError` on duplicate (defense-in-depth).
- Legacy fallback: 96-bit random nonce + 128-bit salt (224 bits combined)
  retained for backward compatibility (non-ratchet, non-SIV paths).

**Verification:**
- `tests/security/test_nonce_uniqueness.py` (23 tests: sequential, crash/restart,
  multi-thread, Schrödinger isolation, edge cases)
- `tests/test_property_based.py::TestNonceUniqueness::test_nonces_never_repeat`
- `tests/test_security.py::test_nonce_uniqueness`

**Failure Impact:** Complete cipher break, XOR of plaintexts revealed.

---

### INV-004: AAD Binding (Manifest Integrity)

```
∀ manifest M, ciphertext C encrypted with key K:
    M is bound to C via AES-GCM AAD
    Changing any field in M invalidates decryption
```

**Description:** The manifest (containing lengths, hashes, parameters) MUST be cryptographically bound to the ciphertext. This prevents substitution attacks.

**AAD Contents:**
```python
# Canonical AAD construction (see canonical_aad.py)
aad = struct.pack('<QQ', orig_len, comp_len)  # Lengths
aad += salt                                     # Salt
aad += sha256                                   # Original hash
aad += MAGIC                                    # Version
if ephemeral_public_key:
    aad += ephemeral_public_key                 # FS key binding
if pq_ciphertext:
    aad += pq_ciphertext                        # PQ ciphertext binding (MEOW4/MEOW5)
```

**Verification:**
- `tests/test_invariants.py::TestSecurityInvariants::test_invariant_aad_modification_rejected`
- `tests/test_security.py::TestTamperDetection::test_manifest_tampering`
- `tests/test_crypto.py` — deterministic construction, backward compat, roundtrip

**Failure Impact:** Length oracle attacks, version downgrade attacks.

---

### INV-005: Rust Backend Required

```
backend == "rust"
```

**Description:** The Rust backend is mandatory; Python fallback is disabled. This preserves constant-time guarantees; memory zeroing is guaranteed in Rust (via `zeroize` crate), best-effort in Python.

**Verification:**
- `tests/test_crypto_backend.py::TestBackendAvailability::test_rust_backend_available`
- `tests/conftest.py` enforces Rust backend availability

**Failure Impact:** Loss of constant-time guarantees and guaranteed Rust-side memory zeroing (security regression).

---

### INV-006: Key Derivation Determinism

```
∀ password P, salt S, keyfile K:
    derive_key(P, S, K) == derive_key(P, S, K)  // Same inputs → same output

∀ P1 ≠ P2, S:
    derive_key(P1, S) ≠ derive_key(P2, S)       // Different passwords → different keys

∀ P, S1 ≠ S2:
    derive_key(P, S1) ≠ derive_key(P, S2)       // Different salts → different keys
```

**Description:** Key derivation must be deterministic (for decryption to work) but also ensure different inputs produce different keys.

**Verification:**
- `tests/test_property_based.py::TestKeyDerivationInvariants::*`

**Failure Impact:** Decryption failure, key collision attacks.

---

### INV-007: Constant-Time Comparison

```
∀ a, b with len(a) == len(b):
    time(compare(a, b)) is independent of (a, b)
```

**Description:** All security-critical comparisons MUST execute in constant time to prevent timing attacks.

**Implementation:**
- `secrets.compare_digest()` for password/MAC comparison
- Rust `subtle` crate for constant-time ops
- Timing equalization delays (1-5ms jitter)

**Verification:**
- `tests/test_property_based.py::TestConstantTimeInvariants::*`
- `tests/test_constant_time.py`

**Failure Impact:** Timing attacks can leak password/key bits.

---

### INV-008: Manifest Serialization Lossless

```
∀ manifest M:
    unpack_manifest(pack_manifest(M)) == M
```

**Description:** Manifest serialization must be perfectly reversible with no data loss.

**Verification:**
- `tests/test_property_based.py::TestManifestInvariants::test_manifest_roundtrip`

**Failure Impact:** Data corruption, decryption parameter loss.

---

### INV-009: Fountain Code Recoverability

```
∀ data D, with k_blocks K:
    IF received >= ceil(K * 1.05) droplets THEN
        decode_probability > 0.99
```

**Description:** Fountain codes (Luby Transform) must allow recovery with approximately k blocks (with small overhead).

**Verification:**
- `tests/test_property_based.py::TestFountainCodeInvariants::test_fountain_roundtrip`
- `tests/test_fountain.py`

**Failure Impact:** Unrecoverable data despite sufficient frames.

---

### INV-010: X25519 Commutativity

```
∀ keypairs (a, A) and (b, B):
    ECDH(a, B) == ECDH(b, A)
```

**Description:** X25519 key exchange must be commutative - both parties derive the same shared secret.

**Verification:**
- `tests/test_property_based.py::TestX25519Invariants::test_x25519_shared_secret_commutative`

**Failure Impact:** Forward secrecy broken, key mismatch.

---

### INV-011: HMAC Tamper Detection

```
∀ key K, message M, tag T = HMAC(K, M):
    ∀ M' ≠ M: HMAC_verify(K, M', T) == False
```

**Description:** HMAC verification must reject any modification to the authenticated message.

**Verification:**
- `tests/test_property_based.py::TestTamperDetection::test_hmac_tampering_detected`

**Failure Impact:** Message forgery, manifest tampering.

---

### INV-012: Wrong Password Rejection

```
∀ ciphertext C encrypted with password P:
    ∀ P' ≠ P: decrypt(C, P') RAISES Exception
```

**Description:** Decryption with an incorrect password MUST fail cleanly (not produce garbage).

**Implementation:**
- HMAC verification before decryption
- AES-GCM tag verification
- SHA-256 hash verification of decrypted data

**Verification:**
- `tests/test_encode.py` / `tests/test_decode_gif.py` (wrong password rejection)
- `tests/test_invariants.py::test_invariant_wrong_password_rejected`

**Failure Impact:** Silent data corruption, oracle attacks.

---

### INV-013: Secure Memory Zeroing

```
∀ sensitive data S (passwords, keys):
    AFTER use: S is overwritten with zeros
```

**Description:** Sensitive data should be zeroed after use to limit memory forensics exposure. Rust-side zeroing is guaranteed via the `zeroize` crate; Python-side zeroing (e.g., `SecureBytes`, `ctypes.memset`) is best-effort due to GC and allocator limitations.

**Implementation:**
- `SecureBytes` class with `__del__` zeroing (best-effort in Python)
- Rust `zeroize` crate for guaranteed automatic zeroing
- `mlock()` to prevent swap (where available)

**Verification:**
- `tests/test_constant_time.py::test_secure_memory_zeroing`

**Failure Impact:** Key recovery via memory forensics.

---

### INV-014: Duress Detection Timing

```
∀ passwords P (normal), D (duress):
    time(check(P)) ≈ time(check(D))
```

**Description:** Checking for a duress password must not reveal whether the password was the duress password through timing.

**Implementation:**
- Constant-time comparison with `secrets.compare_digest()`
- Timing equalization with random delays

**Verification:**
- `tests/test_duress_mode.py::test_duress_timing`

**Failure Impact:** Attacker can distinguish duress from real password.

---

### INV-015: Frame MAC Authentication

```
∀ frame F with MAC M computed with key K, salt S, index I:
    IF modified(F) OR modified(M) THEN
        verify_frame_mac(F, M, K, S, I) == False
```

**Description:** Per-frame MACs prevent injection of malicious frames into the QR stream.

**Verification:**
- `tests/test_frame_mac.py`
- `tests/test_adversarial.py::test_frame_injection`

**Failure Impact:** DoS via malicious frame injection.

---

### INV-016: Steganography Nonce Uniqueness

```
∀ stego encryptions e1, e2:
    nonce(e1) ≠ nonce(e2)
```

**Description:** Each multi-layer steganography encryption MUST use a fresh 96-bit random nonce. Nonce reuse with AES-GCM completely breaks confidentiality (XOR of plaintexts revealed).

**Implementation:**
- `os.urandom(12)` generated per encryption call
- Nonce prepended to ciphertext for transmission
- Previously: hardcoded zero-nonce (FIXED 2026-02-20)

**Verification:**
- `tests/test_stego_adversarial.py::TestNonceUniqueness`
- `tests/test_stego_fuzz.py` (Hypothesis roundtrip tests)

**Failure Impact:** Complete cipher break — XOR of plaintexts revealed.

---

### INV-017: Steganography Fail-Closed Encryption

```
∀ stego operations:
    IF crypto_backend_unavailable THEN
        RAISE RuntimeError (never silently skip encryption)
```

**Description:** Multi-layer steganography MUST raise an exception if the cryptographic backend is unavailable. Previously logged a warning and continued with unencrypted data.

**Implementation:**
- `raise RuntimeError` when no crypto backend available
- Previously: `logger.warning()` (fail-open, FIXED 2026-02-20)

**Verification:**
- `tests/test_stego_adversarial.py::TestFailClosedEncryption`

**Failure Impact:** Plaintext embedded without encryption — total confidentiality loss.

---

### INV-018: STC Encode-Decode Correctness

```
∀ message M, cover C, shared_key K:
    stc_decode(stc_encode(M, C, K), K) == M
```

**Description:** Syndrome-Trellis Codes MUST correctly roundtrip: encoding a message into a cover signal and decoding it back MUST recover the original message exactly.

**Implementation:**
- Viterbi trellis algorithm with checkpoint-based backtracking (Rust), rate 1/4
- Previously: GF(2) Gaussian elimination (FIXED 2026-02-20), then replaced with Viterbi (Session 3)

**Verification:**
- `tests/test_stego_adversarial.py::TestSTCCorrectness`
- `tests/test_stego_fuzz.py::test_stc_roundtrip` (Hypothesis)

**Failure Impact:** Data corruption — embedded payload unrecoverable.

---

### INV-019: Payload Capacity Bounds Enforcement

```
∀ payload P, capacity C:
    IF len(P) > C THEN
        RAISE ValueError (never silently truncate or warn-only)
```

**Description:** When the payload exceeds the steganographic capacity of the cover image, the system MUST reject the operation with an exception. Silent truncation or warning-only causes data loss.

**Implementation:**
- `raise ValueError` when payload exceeds capacity
- Previously: `logger.warning()` (FIXED 2026-02-20)

**Verification:**
- `tests/test_stego_adversarial.py::TestCapacityEnforcement`

**Failure Impact:** Silent data truncation — receiver gets corrupted/incomplete payload.

---

### INV-020: Stego LSB Lossless Roundtrip (APNG)

```
∀ payload P, cover frames F[]:
    IF format == APNG (lossless) THEN
        LSB_extract(LSB_embed(F[], P)) == P
    IF format == GIF (palette-quantized) THEN
        LSB_extract(LSB_embed(F[], P)) ≠ P  (NOT guaranteed)
```

**Description:** Steganographic LSB embedding MUST use a lossless image format (APNG) to preserve pixel values. GIF uses 256-color palette quantization which corrupts LSB-embedded data beyond recovery. Cat mode MUST output APNG (.png), never GIF (.gif).

**Implementation:**
- Cat mode encoder outputs APNG via `apng.APNG` (lossless animated PNG)
- GIF path reserved for non-stego (QR-only) output
- Stego extraction fallback in `decode_gif.py` tries LSB depths 2, 1, 3

**Verification:**
- `web_demo/test_cat_mode.py` — APNG cat mode encode→decode roundtrip
- `web_demo/test_all_modes.py` — Cat APNG × 5 runs (100% pass rate)
- `tests/test_stego_phase1.py::TestTemporalChannel::test_embed_extract_roundtrip_*`

**Failure Impact:** Complete data loss — QR frames unrecoverable from GIF-quantized stego images.

---

### INV-021: Frame MAC Index Correctness Under Stego Extraction

```
∀ stego-encoded animation A with N total frames:
    LET extracted[] = stego_extract(A)  // may skip frames
    LET qr_frame_indices[] = original frame positions of extracted QR codes
    ∀ i in extracted[]:
        verify_frame_mac(extracted[i], key, salt, qr_frame_indices[i]) == True
```

**Description:** When decoding stego-encoded animations, not all frames yield readable QR codes. Frame MAC verification MUST use the original frame index (position in the animation), not the sequential index in the extracted list. Using sequential indices causes MAC failures for frames after the first skipped frame.

**Implementation:**
- `decode_gif.py` tracks `qr_frame_indices[]` during both normal QR scan and stego extraction
- Frame MAC verification uses `actual_frame_idx = qr_frame_indices[idx + 1]` instead of `idx + 1`

**Verification:**
- `web_demo/test_all_modes.py` — Cat mode with MAC verification (100% MAC success rate)
- `web_demo/test_cat_mode.py` — Single roundtrip with MAC check

**Failure Impact:** False MAC rejection — valid frames rejected when stego extraction skips frames, causing decode failure despite correct data.

---

## Invariant Test Matrix

| Invariant | Property Tests | Unit Tests | Fuzzing | Status |
|-----------|---------------|------------|---------|--------|
| INV-001 | ✅ | ✅ | ✅ | VERIFIED |
| INV-002 | ✅ | ✅ | ✅ | VERIFIED |
| INV-003 | ✅ | ✅ | - | VERIFIED |
| INV-004 | ✅ | ✅ | ✅ | VERIFIED |
| INV-005 | ✅ | ✅ | - | VERIFIED |
| INV-006 | ✅ | ✅ | - | VERIFIED |
| INV-007 | ✅ | ✅ | - | PARTIAL* |
| INV-008 | ✅ | ✅ | ✅ | VERIFIED |
| INV-009 | ✅ | ✅ | ✅ | VERIFIED |
| INV-010 | ✅ | ✅ | - | VERIFIED |
| INV-011 | ✅ | ✅ | - | VERIFIED |
| INV-012 | ✅ | ✅ | - | VERIFIED |
| INV-013 | - | ✅ | - | PARTIAL* |
| INV-014 | - | ✅ | - | PARTIAL* |
| INV-015 | - | ✅ | - | VERIFIED |
| INV-016 | ✅ | ✅ | - | VERIFIED |
| INV-017 | - | ✅ | - | VERIFIED |
| INV-018 | ✅ | ✅ | - | VERIFIED |
| INV-019 | - | ✅ | - | VERIFIED |
| INV-020 | - | ✅ | - | VERIFIED |
| INV-021 | - | ✅ | - | VERIFIED |

---

### INV-022: Ratchet Forward Secrecy (No Backward Key Derivation)

```
∀ chain positions i < j:
    Given chain_key[j], it is computationally infeasible to derive chain_key[i]
    (HKDF-SHA256 is one-way)
```

**Description:** Compromising the ratchet state at frame N reveals nothing about frames 0..N-1. Each chain_key is zeroized immediately after deriving its successor. There is no API, state transition, or code path that allows recovering a previous chain key.

**Implementation:**
- `ratchet_step()` derives `chain_key[i+1]` then drops `chain_key[i]` handle
- Skip cache stores only `message_key` handles (not chain keys)
- Rust `zeroize` crate guarantees handle memory is wiped on drop

**Verification:**
- `tests/security/test_ratchet_forward_secrecy.py::TestForwardSecrecy`
- `tests/test_ratchet.py::TestRatchetForwardSecrecy`

**Failure Impact:** Loss of forward secrecy — past messages exposed on chain compromise.

---

### INV-023: Ratchet Fail-Closed on AAD/Sequence Mismatch

```
∀ ratchet-encrypted frames F:
    IF aad_mismatch(F) OR sequence_invalid(F) THEN
        abort_entire_decode()  // no partial plaintext
```

**Description:** Any AAD mismatch, sequence number violation, or key commitment failure during ratchet decryption MUST abort the entire decode operation. No partial plaintext is ever emitted.

**Verification:**
- `tests/security/test_ratchet_forward_secrecy.py::TestRatchetFailClosed`
- `tests/test_ratchet.py::TestRatchetReplay`

**Failure Impact:** Partial plaintext leak under active attack.

---

### INV-024: No Ratchet Rollback

```
∀ ratchet states S at position P:
    ¬∃ operation that produces state S' at position P' < P
```

**Description:** The ratchet state machine has no backward transition. Once a chain key is consumed, it cannot be re-derived. The consumed-set prevents re-processing the same frame index.

**Verification:**
- `tests/security/test_ratchet_forward_secrecy.py::TestNoRollback`

**Failure Impact:** Replay attacks, forward secrecy violation.

---

### INV-025: Schrödinger Mode Deniability Limitations (Honest Disclosure)

```
⚠️ Schrödinger mode provides LIMITED deniability:
    - Casual inspection: two valid decryptions exist (plausible deniability)
    - Nation-state forensic analysis: statistical distinguishability
      MAY be detectable via timing, file size patterns, entropy analysis,
      or comparison of multiple files from the same user
    - This is NOT perfect cryptographic deniability against unlimited
      compute and multiple samples
```

**Description:** Schrödinger mode is designed so that both sub-streams (real + decoy/dummy) are always present and each password reveals only its own stream. However, advanced forensic analysis MAY detect dual encoding. Users in high-risk environments should not rely on deniability alone.

**What IS guaranteed:**
- Each password independently decrypts only its sub-stream
- Both sub-streams always present (even in "single secret" mode)
- Independent Argon2id, ratchet, fountain, and GCM keys per stream
- No cross-commitments between streams

**What is NOT guaranteed (with mitigations noted):**
- Perfect indistinguishability under forensic comparison of multiple files *(mitigated by INV-030 fixed-size padding + INV-031 fixed QR + `decorrelation.py` — best-effort)*
- ~~Resistance to timing side-channels during encode/decode~~ → *Mitigated by INV-029 `timing_equalizer.py` — best-effort, Python GC is non-constant-time*
- ~~Deniability if attacker has access to swap/memory forensics~~ → *Mitigated by INV-026 `memory_guard.py` (mlockall + MADV_DONTDUMP) — best-effort*
- ~~Deniability if attacker compares file sizes across users~~ → *Mitigated by INV-030 `size_normalizer.py` (fixed size classes)*

> **Note (2026-02-22):** The above mitigations significantly raise the bar but are best-effort. Python's GC, interpreter scheduling, and OS-level page cache remain outside software control.

**Verification:**
- `tests/security/test_deniability.py` (statistical distinguishability tests)
- `tests/security/test_timing_equalizer.py`, `test_size_normalizer.py`, `test_memory_guard.py`

**Failure Impact:** False sense of security for users in rogue states.

*PARTIAL indicates implementation is best-effort due to Python limitations.

---

### INV-026: Memory Guard Active

**Status:** ✅ ENFORCED
**Category:** Memory Hardening
**Implemented In:** `meow_decoder/memory_guard.py` (274 lines)

**Description:** At process start, `activate_memory_guard()` enforces:
1. `mlockall(MCL_CURRENT | MCL_FUTURE)` — prevent all pages from swap
2. `RLIMIT_CORE = 0` — prevent core dump generation
3. `PR_SET_DUMPABLE = 0` — prevent ptrace attachment
4. `MADV_DONTDUMP` on sensitive memory regions

**What IS guaranteed:**
- Best-effort prevention of key material in swap and core dumps (Linux/macOS)
- Process is non-dumpable and non-ptraceable

**What is NOT guaranteed:**
- Protection on Windows (deferred)
- Protection against root-level memory access or cold boot attacks

**Verification:** `tests/security/test_memory_guard.py`, `tests/security/test_dontdump.py`
**Failure Impact:** Key material in swap/core dumps recoverable by forensic examiner.

---

### INV-027: No Persistent Temp Files

**Status:** ✅ ENFORCED
**Category:** Forensic Countermeasures
**Implemented In:** `meow_decoder/secure_temp.py` (265 lines)

**Description:** All temporary file operations use tmpfs-backed storage (`/dev/shm` preferred). Falls back to `/tmp` with a `SecurityWarning` if no tmpfs is available.

**Verification:** `tests/security/test_secure_temp.py`
**Failure Impact:** Temp files persisted to disk, recoverable by forensic examiner.

---

### INV-028: Forensic Cleanup on Exit

**Status:** ✅ ENFORCED (best-effort)
**Category:** Forensic Countermeasures
**Implemented In:** `meow_decoder/forensic_cleanup.py` (387 lines)

**Description:** On graceful exit, `ForensicCleaner.clean_all()` removes:
- File manager thumbnails (GNOME, KDE, macOS QuickLook, Windows)
- Recent file lists (`recently-used.xbel`)
- Clipboard contents (xclip/pbcopy)
- Shell history entries containing meow-related commands
- Temp files matching `meow_*`

**Limitation:** Best-effort and OS-dependent. Cannot clean kernel page cache or filesystem journal from userspace.

**Verification:** `tests/security/test_forensic_cleanup.py`
**Failure Impact:** OS artifacts reveal file operation history to forensic examiner.

---

### INV-029: Constant-Time Decode

**Status:** ✅ ENFORCED (best-effort)
**Category:** Timing Side-Channels
**Implemented In:** `meow_decoder/timing_equalizer.py` (281 lines)

**Description:** `TimingEqualizer` wraps decode operations to produce constant wall-clock time regardless of success/failure. Uses CSPRNG jitter (±5%) to prevent statistical averaging.

**Limitation:** Python GC and interpreter scheduling are inherently non-constant-time. Rust-side crypto uses `subtle` crate for true constant-time.

**Verification:** `tests/security/test_timing_equalizer.py`
**Failure Impact:** Timing oracle reveals password validity.

---

### INV-030: Fixed Output Size

**Status:** ✅ ENFORCED
**Category:** Indistinguishability
**Implemented In:** `meow_decoder/size_normalizer.py` (288 lines)

**Description:** GIF output is padded to fixed size classes (4KB, 16KB, 64KB, 256KB, 1MB, 4MB, 16MB, 64MB) to prevent file size fingerprinting.

**Verification:** `tests/security/test_size_normalizer.py`
**Failure Impact:** File size reveals payload size, enabling profiling.

---

### INV-031: Fixed QR Version

**Status:** ✅ ENFORCED
**Category:** Indistinguishability
**Implemented In:** `meow_decoder/qr_code.py`, `meow_decoder/config.py`

**Description:** QR version is fixed at v25 regardless of payload size. Prevents QR structure from leaking payload size metadata.

**Verification:** Config-level enforcement; QR version not auto-selected.
**Failure Impact:** QR version metadata reveals payload size class.

---

### INV-032: Content Expiry

**Status:** ✅ ENFORCED
**Category:** Anti-Forensics
**Implemented In:** `meow_decoder/expiry.py` (332 lines)

**Description:** Encoded content can include an expiry timestamp. On decode, expiry is checked BEFORE decryption. Expired content triggers self-destruct (multi-pass overwrite + unlink) rather than silent decryption.

**Verification:** `tests/security/test_expiry.py`
**Failure Impact:** Expired secrets remain accessible indefinitely.

---

## Adding New Invariants

When adding a new security-critical feature:

1. **Document the invariant** in this file
2. **Add property-based tests** in `tests/test_property_based.py`
3. **Add targeted unit tests** in appropriate test file
4. **Add fuzz target** in `fuzz/` if parsing is involved
5. **Update the test matrix** above

---

## Verification Commands

```bash
# Run all property-based tests
pytest tests/test_property_based.py -v --hypothesis-show-statistics

# Run invariant tests only
pytest tests/test_invariants.py -v

# Run full security test suite
pytest tests/test_security.py tests/test_invariants.py tests/test_property_based.py -v

# Run with coverage for crypto paths
pytest --cov=meow_decoder.crypto --cov=meow_decoder.crypto_backend \
    --cov-report=html --cov-fail-under=90

# Run fuzzing
python -m atheris fuzz/fuzz_manifest.py
```

---

## References

- [AES-GCM Nonce Reuse Attack](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Argon2 OWASP Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Timing Attacks on Web Applications](https://www.usenix.org/conference/usenixsecurity11/timing-attacks-web-applications)
- [NIST SP 800-63B Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**Security Contact:** Open a GitHub issue with [SECURITY] tag
