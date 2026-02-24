# 🔒 Security Invariants - Meow Decoder

**Version:** 1.2.0 (INTERNAL REVIEW — no external audit)
**Last Updated:** 2026-02-24
**Classification:** Security-Critical Documentation

---

## Overview

This document formally specifies the **security invariants** that Meow Decoder MUST uphold. These are mathematical properties that must hold for ALL inputs - violating any invariant is a security vulnerability.

Invariants are verified through:
1. **Property-based testing** (Hypothesis) - Random input fuzzing
2. **Unit tests** - Specific edge cases
3. **Fuzzing** (AFL++) - Crash detection
4. **Code review** - Manual verification
5. **Formal proofs** (where available) - Machine-checked mathematical proofs

### Formal Verification Status (v1.2 — post audit fixes F-01 through F-10)

> Last audited: 2026-02-24 — branch `main` (`3289c0a`).  All rows marked ✅
> are CI-gated on every push and pull-request that touches the relevant source
> (see `.github/workflows/formal-verification.yml`).

| Property set | Tool | CI-gated? | Artefact |
|---|---|---|---|
| Guard-page memory safety — POSIX (GB-001–GB-008) | Verus | ✅ | `verus_guarded_buffer.rs` |
| Guard-page memory safety — Windows VirtualProtect (WG-001–WG-007) | Verus | ✅ | `verus_windows_guard.rs` |
| AEAD nonce uniqueness, auth-gated plaintext, key zeroization, no-bypass (AEAD-001–004) | Verus | ✅ | `aead_wrapper.rs` |
| AEAD INT-CTXT, AAD binding, fail-closed, ratchet independence (AEAD-005–012) | Verus | ✅ | `aead_wrapper.rs` ⚠️ abstract (see note) |
| KDF parameter security, HKDF domain separation (KDF-001–004) | Verus | ✅ | `verus_kdf_proofs.rs` |
| Shamir reconstruction constant-time (CT-001–004) | Verus | ✅ | `verus_kdf_proofs.rs` |
| Protocol state machine (auth-then-output, replay, duress) | TLA+ | ✅ | `MeowEncode.tla`, `MeowFountain.tla`, `MeowStreaming.tla` |
| Ratchet index monotonicity, skip-key DoS, key uniqueness | TLA+ | ✅ | `MeowRatchet.tla` |
| Constant-time execution model (jitter-tolerant ≤1 · Jitter) | TLA+ | ✅ | `TimingEqualizer.tla` |
| Message expiry fail-closed | TLA+ | ✅ | `ExpiryProtocol.tla` |
| Cross-session forward secrecy (master ratchet) | TLA+ | ✅ | `MasterRatchet.tla` |
| Dolev-Yao secrecy & authentication | ProVerif | ✅ | `meow_encode.pv` |
| PQ beacon PCS restoration (ML-KEM-768 + X25519 hybrid) | ProVerif | ✅ | `pq_beacon_pcs.pv` |
| Manifest HMAC integrity | ProVerif | ✅ | `manifest_signing.pv` |
| Dead-man’s switch duress enforcement | ProVerif | ✅ | `deadmans_switch_duress.pv` |
| **INV-004: 8-field canonical AAD binding** | ProVerif | ✅ | `meow_aad_8field_binding.pv` |
| MEOW3 duress observational equivalence | Tamarin | ✅ | `MeowDuressEquiv.spthy` |
| MEOW4/5 PQ duress OE | Tamarin | ✅ | `MeowDuressEquivPQ.spthy` |
| AEAD 4-ary AAD binding | Tamarin | ✅ | `MeowAEADBinding.spthy` |
| Full Schrödinger deniability game (15 lemmas) | Tamarin | ✅ | `MeowSchrodingerDeniability.spthy` |
| Invisible-salamanders key-commitment prevention | Tamarin | ✅ | `MeowKeyCommitment.spthy` |
| Per-frame forward secrecy + PCS via beacon | Tamarin | ✅ | `MeowRatchetFS.spthy` |
| Guard-page overflow/underflow (symbolic) | Tamarin | ✅ | `secure_alloc_guard_pages.spthy` |
| Dead-man’s switch deadline (4 lemmas) | Tamarin | ✅ | `meow_deadmans_switch.spthy` |
| Header encryption OE (frame-index indistinguishability) | Tamarin | ✅ | `MeowRatchetHeaderOE.spthy` |
| Schrödinger OE (dual-password indistinguishability, simplified) | Tamarin | ✅ | `MeowSchrodingerOE.spthy` |
| Encoding observational equivalence (minimal) | Tamarin | ✅ | `meow_encode_equiv.spthy` |
| Fountain code LT-correctness (machine-checked) | Lean 4 | ✅ | `FountainCodes.lean` (1 approved sorry) |
| Shamir threshold security (field axiom) | Lean 4 | ✅ | `ShamirSecretSharing.lean` (1 approved axiom) |
| HKDF domain separation (10 theorems) | Lean 4 | ✅ | `DomainSeparation.lean` |

> **Note on AEAD-005–012:** The Verus lemmas are *abstract* — preconditions directly
> subsume postconditions.  They verify the spec is internally consistent but do not
> check that the `aes-gcm` crate implementation satisfies INT-CTXT.  True
> implementation-level INT-CTXT proof requires a GF(2¹²⁸) GHASH model in Verus
> (open research; documented as approved limitation RL-1 in `formal-10x-audit.md`).

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
- Rust nonce counter uses **compare-and-swap (CAS) loop** instead of `fetch_add`
  to prevent u64 overflow wrap-around causing nonce reuse (`aead_wrapper.rs`, `nonce.rs`).
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

### INV-005: Rust Backend Required (Core Crypto Path)

```
backend == "rust"
```

**Description:** Core encryption path requires Rust backend for constant-time guarantees and memory zeroing. Auxiliary modules (PQ signing, ML-KEM beacons) must fail closed when secure backends (Rust, OQS, or certified pure-Python implementations) are unavailable. Insecure fallback stubs are permanently disabled in production.

**Verification:**
- `tests/test_crypto_backend.py::TestBackendAvailability::test_rust_backend_available`
- `tests/test_security_hardening.py::test_insecure_mldsa_stubs_disabled`
- `tests/test_security_hardening.py::test_insecure_mlkem_stubs_disabled`
- `tests/conftest.py` enforces Rust backend availability

**Failure Impact:** Loss of constant-time guarantees and guaranteed Rust-side memory zeroing, or accidental insecure fallback behavior in production (security regression).

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

### INV-008A: Manifest Signature Compatibility Policy

```
IF manifest signature is present:
    decoder MUST verify it and reject on failure

IF manifest signature is absent AND signing is enabled (default):
    decoder MUST reject with ValueError (fail-closed)

IF manifest signature is absent AND signing is explicitly disabled
    (MEOW_MANIFEST_SIGNING=off):
    decoder MAY continue, but MUST emit a prominent
    unsigned-manifest warning to stderr
```

**Description:** Signature verification is mandatory by default (fail-closed). Unsigned manifests are rejected unless the operator explicitly disables signing via `MEOW_MANIFEST_SIGNING=off` for legacy compatibility. When signing is disabled, unsigned manifests are accepted with an explicit stderr warning.

**Critical Warning:** Disabling signing (`MEOW_MANIFEST_SIGNING=off`) removes manifest forgery protection. Only use for legacy/transport-limited streams where re-encoding is not possible.

**Verification:**
- `tests/test_security_hardening.py::test_decoder_rejects_unsigned_manifest_when_signing_enabled`
- `tests/test_decode_gif.py::test_decode_gif_signed_manifest_verifies`
- `tests/test_decode_gif.py::test_decode_gif_tampered_signature_rejected`

**Failure Impact:** Silent acceptance of forged metadata or unsafe operator assumptions in coercive/adversarial environments.

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

### INV-010A: X25519 All-Zero Shared Secret Rejection

```
∀ private key sk, public key pk:
    IF ECDH(sk, pk) == [0x00; 32] THEN RAISE Error
```

**Description:** X25519 exchange must reject all-zero shared secrets, which indicate small-subgroup attack.
The Rust backend (`x25519_exchange()` in `pure.rs`) performs constant-time all-zero check and returns `Err`.

**Verification:**
- `rust_crypto/tests/comprehensive_tests.rs` (X25519 zero-check tests)
- `rust_crypto/tests/additional_security_tests.rs`

**Failure Impact:** Key agreement with attacker-controlled public key yields known shared secret.

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

### INV-033: Guard Page Memory Isolation

**Status:** ✅ ENFORCED
**Category:** Memory Safety
**Implemented In:** `meow_decoder/memory_guard.py`

```
∀ GuardedBuffer(size):
    write(data, offset) with offset + len(data) > size → RAISES ValueError
    read(length, offset) with offset + length > size → RAISES ValueError
    close() → zero(buffer) ∧ munmap(pages)
    close(); close() → NO CRASH (idempotent)
    close(); write(data) → RAISES RuntimeError
```

**Description:** `GuardedBuffer` allocates memory with PROT_NONE guard pages above and below the data region. Any out-of-bounds access traps to a signal/exception. Double-free and use-after-free are handled safely. Buffer contents are zeroed on close to prevent forensic recovery.

**Verification:**
- `tests/test_fuzz_coverage_integration.py::TestGuardedBuffer` (9 tests)
- `fuzz/fuzz_windows_guard.py` (8 fuzz functions)

**Failure Impact:** Sensitive key material leaked via buffer overread; use-after-free produces undefined behavior.

---

### INV-034: Mouse Gesture Quantization Stability

**Status:** ✅ ENFORCED
**Category:** Authentication
**Implemented In:** `meow_decoder/secure_keyboard.py::MouseGesturePassword`

```
∀ points, grid_size:
    quantize(points) is deterministic
    ∀ p₁, p₂ in same grid cell: collect(p₁) == collect(p₂)
    ∀ p₁, p₂ in different cells: collect(p₁) ≠ collect(p₂) (collision-resistant)
    BLAKE2b(quantized, person=b"meow_gesture_v1", digest_size=32)
```

**Description:** Mouse gesture authentication quantizes continuous (x,y) coordinates to a discrete grid (default 16×16). Points within the same cell produce identical keys. The BLAKE2b person tag `b"meow_gesture_v1"` provides domain separation, preventing cross-protocol key reuse. Output is a 32-byte (64 hex char) key.

**Verification:**
- `tests/test_fuzz_coverage_integration.py::TestMouseGesturePassword` (8 tests)
- `fuzz/fuzz_mouse_gesture.py` (10 fuzz functions)

**Failure Impact:** Gesture key instability causes authentication failures; missing domain separation enables cross-protocol attacks.

---

### INV-035: Tamper Detection Checkpoint Integrity

**Status:** ✅ ENFORCED
**Category:** Integrity
**Implemented In:** `meow_decoder/tamper_detection.py`

```
∀ TamperState s:
    from_bytes(to_bytes(s)).baseline_hashes == s.baseline_hashes
    from_bytes(corrupt(to_bytes(s))) == None  (HMAC reject)
    from_bytes(truncate(to_bytes(s))) == None  (HMAC reject)
    ∀ seed: silent_poison_bytes(n, seed) == silent_poison_bytes(n, seed)
    ∀ seed₁ ≠ seed₂: silent_poison_bytes(n, seed₁) ≠ silent_poison_bytes(n, seed₂)
```

**Description:** TamperState serialization includes an HMAC-SHA256 authentication tag computed from the state key. Deserialization verifies the HMAC before returning the state; any corruption or truncation causes rejection (returns None). `silent_poison_bytes` provides deterministic-per-seed random bytes for poisoning tampered outputs without revealing the tamper detection mechanism.

**Verification:**
- `tests/test_fuzz_coverage_integration.py::TestTamperState` (4 tests)
- `tests/test_fuzz_coverage_integration.py::TestSilentPoison` (3 tests)
- `tests/test_fuzz_coverage_integration.py::TestTamperDetector` (2 tests)
- `fuzz/fuzz_tamper_detection.py` (10 fuzz functions)

**Failure Impact:** Attacker modifies checkpoint to disable tamper detection; poisoned output leaks real data.

---

### INV-036: Adversarial Stego Rotation Differential

**Status:** ✅ ENFORCED
**Category:** Steganography
**Implemented In:** `meow_decoder/adversarial_carrier.py`, `meow_decoder/stego_advanced.py`

```
∀ seed, width, height:
    sensor(seed) ≠ texture(seed) ≠ dct(seed) ≠ combined(seed)
    ∀ algo: algo(seed₁) == algo(seed₁) (deterministic)
    ∀ algo, seed₁ ≠ seed₂: algo(seed₁) ≠ algo(seed₂) (non-degenerate)
    rotation_schedule = ["sensor", "texture", "dct", "combined"]
    ∀ i: frame_algo = schedule[i % 4]
    carrier_noise ∈ [-128, 127] ∧ integer
```

**Description:** The adversarial steganography rotation schedule cycles through four noise algorithms (sensor, texture, DCT, combined) to defeat steganalysis detectors. Each algorithm must produce distinct statistical fingerprints for the same seed. The schedule is deterministic and covers all four algorithms within every 4 frames. Carrier noise is integer-valued within signed byte range.

**Verification:**
- `tests/test_fuzz_coverage_integration.py::TestAdversarialNoiseGenerator` (9 tests)
- `fuzz/fuzz_adversarial_stego.py` (10 fuzz functions, differential)

**Failure Impact:** Steganalysis detector trains on single noise pattern; rotation bypass enables carrier detection.

---

### INV-037: Schrödinger Deniability Game

**Status:** ✅ FORMALLY VERIFIED (Tamarin)
**Category:** Deniability
**Implemented In:** `meow_decoder/quantum_mixer.py`, `meow_decoder/schrodinger_encode.py`
**Formal Model:** `formal/tamarin/MeowSchrodingerDeniability.spthy`

```
∀ pass_A, pass_B, payload_A, payload_B:
    QuantumNoise = XOR(KDF(pass_A), KDF(pass_B))
    Stream_A = Enc(pass_A, payload_A ⊕ QuantumNoise)
    Stream_B = Enc(pass_B, payload_B ⊕ QuantumNoise)
    Deniability: Observe(Stream_A) reveals nothing about payload_B (and vice versa)
    Coercion Safety: revealing pass_A reveals only payload_A
    KDF Commitment: commit(KDF(pass)) is binding
    No Cross-Leak: decode(pass_A) never outputs payload_B
```

**Description:** Schrödinger mode encodes two independent secrets into a single GIF using quantum plausible deniability. The XOR of password-derived KDF outputs creates a noise layer that is computationally indistinguishable from random without both passwords. A coerced user revealing one password cannot be proven to possess the second secret. Formalized as observational equivalence in Tamarin with 10 lemmas including deniability, integrity, no-cross-leak, coercion safety, and KDF commitment binding.

**Verification:**
- `formal/tamarin/MeowSchrodingerDeniability.spthy` (10 lemmas)
- `formal/tamarin/MeowSchrodingerOE.spthy` (6 lemmas, observational equivalence)
- `tests/test_fuzz_coverage_integration.py::TestSchrodingerStructure` (3 tests)
- `fuzz/fuzz_schrodinger.py` (existing fuzz target)

**Failure Impact:** Adversary distinguishes which secret was accessed; deniability claim is false.

---

### INV-038: Guard Page Memory Safety Under Stress

**Status:** ✅ FUZZ-TESTED
**Category:** Memory Safety
**Implemented In:** `meow_decoder/memory_guard.py`
**Fuzz Target:** `fuzz/fuzz_windows_guard.py` (11 functions)

```
∀ alloc_free_cycles:
    rapid_alloc_free(N cycles) → no leak, no crash
    boundary_write(buf, size) succeeds; boundary_write(buf, size+1) raises
    zero_wipe(buf)^N is idempotent: read(buf) = 0x00 * size
```

**Description:** GuardedBuffer must survive rapid allocation/deallocation cycles without memory leaks, correctly enforce write boundaries, and produce consistently zeroed state after multiple wipe operations. Fuzz targets exercise guard page traps, VirtualLock/VirtualProtect lifecycle, double-free safety, use-after-free detection, concurrent alloc/free, and boundary conditions.

**Verification:**
- `fuzz/fuzz_windows_guard.py` (11 fuzz functions)
- `tests/test_fuzz_coverage_integration.py::TestGuardedBuffer` (9 tests)
- `tests/test_fuzz_coverage_integration.py::TestGuardedBufferEnhanced` (4 tests)

**Failure Impact:** Memory corruption, information leakage via unwiped buffers, or denial of service.

---

### INV-039: Mouse Gesture Auth BLAKE2b Domain Separation

**Status:** ✅ FUZZ-TESTED
**Category:** Authentication
**Implemented In:** `meow_decoder/secure_keyboard.py`
**Fuzz Target:** `fuzz/fuzz_mouse_gesture.py` (13 functions)

```
∀ gesture_points, grid_size:
    BLAKE2b(gesture, person=b"meow_gesture_v1\x00") ≠ BLAKE2b(gesture)
    quantize(points) is deterministic for fixed grid_size
    ∀ i ≠ j: gesture_i ≠ gesture_j → key_i ≠ key_j (collision resistance)
    replay_resistance: H(gesture || salt_1) ≠ H(gesture || salt_2) for salt_1 ≠ salt_2
```

**Description:** Mouse gesture authentication derives keys via BLAKE2b with a mandatory `person` tag for domain separation. Quantization must be deterministic across grid sizes, person tag must affect output, and different gestures must produce different keys. Fuzz targets exercise quantization extremes (zero/huge/negative coords), perturbation stability, collision resistance, person tag consistency, replay resistance via salts, and grid boundary behavior.

**Verification:**
- `fuzz/fuzz_mouse_gesture.py` (13 fuzz functions)
- `tests/test_fuzz_coverage_integration.py::TestMouseGesturePassword` (8 tests)
- `tests/test_fuzz_coverage_integration.py::TestMouseGestureEnhanced` (5 tests)

**Failure Impact:** Auth bypass via gesture collision, domain confusion with other BLAKE2b uses, or replay attacks.

---

### INV-040: Tamper Detection State Integrity and Poison Quality

**Status:** ✅ FUZZ-TESTED
**Category:** Tamper Resistance
**Implemented In:** `meow_decoder/tamper_detection.py`
**Fuzz Target:** `fuzz/fuzz_tamper_detection.py` (13 functions)

```
∀ state, data:
    TamperState.deserialize(corrupt(serialize(state))) raises ValueError
    silent_poison(seed, n) has Shannon entropy > 5.0 bits/byte
    silent_poison(seed_1, n) ≠ silent_poison(seed_2, n) for seed_1 ≠ seed_2
    checkpoint_hmac(state) is binding: flip(checkpoint) → rejection
    state_version_corruption → rejection
```

**Description:** TamperState serialization must reject corrupted data (bit flips, truncation, version corruption). Silent poison output must be high-entropy and seed-dependent. Checkpoint HMAC integrity must be fail-closed. Fuzz targets exercise state roundtrip, corruption variants, poison determinism/uniqueness/randomness/entropy, detector with fake modules, poison output length, checkpoint HMAC integrity, baseline reinit, version field corruption, and checkpoint replay scenarios.

**Verification:**
- `fuzz/fuzz_tamper_detection.py` (13 fuzz functions)
- `tests/test_fuzz_coverage_integration.py::TestTamperState` (4 tests)
- `tests/test_fuzz_coverage_integration.py::TestSilentPoison` (3 tests)
- `tests/test_fuzz_coverage_integration.py::TestTamperDetector` (2 tests)
- `tests/test_fuzz_coverage_integration.py::TestTamperDetectionEnhanced` (5 tests)

**Failure Impact:** Undetected code tampering, low-entropy poison output enabling timing attacks, or checkpoint rollback attacks.

---

### INV-041: Adversarial Stego Rotation Statistical Independence

**Status:** ✅ FUZZ-TESTED
**Category:** Steganography
**Implemented In:** `meow_decoder/adversarial_carrier.py`
**Fuzz Target:** `fuzz/fuzz_adversarial_stego.py` (13 functions)

```
∀ seed_1 ≠ seed_2:
    noise(seed_1) ≠ noise(seed_2)
    |correlation(noise(seed_1), noise(seed_2))| < 0.5
∀ method ∈ {sensor, texture, dct, combined}:
    noise_method(seed) is deterministic
    all values are finite (no NaN/Inf)
∀ frames(100+):
    rotation_schedule visits ≥ 3 of 4 algorithms
```

**Description:** Adversarial stego noise generators must produce statistically independent outputs for different seeds, with low cross-correlation. All noise values must be finite. The rotation schedule must visit all algorithm variants over sufficient frames to prevent single-pattern detection. Fuzz targets exercise rotation differential, per-algorithm determinism, histogram equalization, DCT matching PSNR, combined component completeness, carrier noise range, pairs test, rotation schedule coverage, noise profile extremes, rotation frequency distribution, statistical uniformity, and cross-seed independence.

**Verification:**
- `fuzz/fuzz_adversarial_stego.py` (13 fuzz functions)
- `tests/test_fuzz_coverage_integration.py::TestAdversarialNoiseGenerator` (9 tests)
- `tests/test_fuzz_coverage_integration.py::TestAdversarialStegoEnhanced` (5 tests)

**Failure Impact:** Steganalysis detector identifies noise pattern; carrier detection compromises steganographic concealment.

---

### INV-042: Ratchet PQ Beacon Integration and Forward Secrecy

**Status:** ✅ TESTED + FORMALLY MODELED
**Category:** Forward Secrecy / Post-Quantum
**Implemented In:** `meow_decoder/ratchet.py`
**Formal Model:** `formal/tamarin/MeowSchrodingerDeniability.spthy` (15 lemmas)

```
DEFAULT_REKEY_INTERVAL > 0  (asymmetric rekey enabled by default)
_generate_kem_beacon / _recover_kem_beacon: REMOVED (dead code cleanup)
Active PQ path: _generate_asym_rekey / _recover_asym_rekey (MSR v2.0)
PQ_BEACON_MIX_INFO ≠ REKEY_BEACON_INFO ≠ REKEY_BEACON_KEM_INFO (domain separation)
HEADER_ENC_INFO ≠ HEADER_MASK_INFO ≠ REKEY_BEACON_INFO (domain separation)
Tamarin lemmas 11-15: RatchetForwardSecrecy, PQBeaconDomainSeparation,
    MultiSessionUnlinkability, AsymRekeyPCS, HeaderEncryptionConfidentiality
```

**Description:** The MSR v2.0 ratchet provides per-frame forward secrecy via HKDF chain ratcheting and periodic asymmetric rekey (X25519 ECDH + optional ML-KEM-1024). Legacy dead-code KEM beacon functions were removed; active PQ integration uses `_generate_asym_rekey`/`_recover_asym_rekey`. `DEFAULT_REKEY_INTERVAL` is set to 32 (enabled by default). Tamarin model extended with 5 new lemmas covering ratchet forward secrecy, PQ beacon domain separation, multi-session unlinkability, asymmetric rekey PCS, and header encryption confidentiality.

**Verification:**
- `formal/tamarin/MeowSchrodingerDeniability.spthy` (15 lemmas)
- `tests/test_fuzz_coverage_integration.py::TestRatchetIntegration` (5 tests)
- `tests/test_ratchet.py` (existing ratchet tests)
- `tests/test_asymmetric_rekey.py` (asymmetric rekey tests)

**Failure Impact:** Compromise of chain_key yields past/future frame keys; PQ beacon provides no quantum resistance; traffic analysis via unencrypted frame indices.

### INV-043: Fountain Code Thread Safety

**Status:** ✅ TESTED
**Category:** Correctness / Thread Safety
**Implemented In:** `meow_decoder/fountain.py`

```
∀ concurrent calls to FountainEncoder.droplet(seed):
    output(seed) is deterministic AND independent of global PRNG state
```

**Description:** `FountainEncoder.droplet()` now uses a local `random.Random(seed)` instance
instead of the global `random` module, ensuring thread safety and reproducible output
regardless of concurrent access. `sample_degree()` accepts an optional `rng` parameter.

**Verification:**
- `tests/test_fountain.py` (deterministic droplet generation tests)
- `tests/test_e2e_crypto_fountain.py` (end-to-end pipeline)

**Failure Impact:** Non-deterministic fountain encoding; intermittent decode failures under concurrent use.

### INV-044: HKDF Output Length Enforcement

**Status:** ✅ TESTED
**Category:** Cryptographic Safety
**Implemented In:** `rust_crypto/src/handles.rs`

```
∀ HKDF handle calls: output_len == 32 OR RAISE Error
```

**Description:** All 6 HKDF handle functions in the Rust backend enforce `output_len == 32`.
This prevents callers from accidentally requesting non-standard key lengths that could
weaken security or cause protocol mismatches.

**Verification:**
- `rust_crypto/tests/comprehensive_tests.rs` (HKDF output length tests)

**Failure Impact:** Callers could request shorter keys, weakening cipher security.

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

# Run fuzz coverage integration tests (INV-033 through INV-042)
pytest tests/test_fuzz_coverage_integration.py -v

# Run full security test suite
pytest tests/test_security.py tests/test_invariants.py tests/test_property_based.py -v

# Run with coverage for crypto paths
pytest --cov=meow_decoder.crypto --cov=meow_decoder.crypto_backend \
    --cov-report=html --cov-fail-under=90

# Run fuzzing (new targets)
python -m atheris fuzz/fuzz_manifest.py
python fuzz/fuzz_windows_guard.py       # Guard page memory safety
python fuzz/fuzz_mouse_gesture.py       # Gesture auth quantization
python fuzz/fuzz_tamper_detection.py    # Tamper detection + poisoning
python fuzz/fuzz_adversarial_stego.py   # Stego rotation differential
```

---

## References

- [AES-GCM Nonce Reuse Attack](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Argon2 OWASP Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Timing Attacks on Web Applications](https://www.usenix.org/conference/usenixsecurity11/timing-attacks-web-applications)
- [NIST SP 800-63B Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**Security Contact:** Open a GitHub issue with [SECURITY] tag
