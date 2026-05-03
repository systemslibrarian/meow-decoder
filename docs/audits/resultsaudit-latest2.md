# resultsaudit-latest2.md

**Independent Security Audit — Meow Decoder**
**Date:** 2026-02-25
**Auditor scope:** Full codebase review (main branch, commit post-remediation)
**Methodology:** Static source review + automated test verification; no runtime penetration testing

---

## 1. Verification of the 8 Hardening Items

### 1.1 Full Windows Parity (VirtualLock + VirtualProtect)

- **Status:** Fully Implemented
- **Production path:** Yes — `SecureBox<T>` in `crypto_core/src/secure_alloc.rs` is used by the Rust crypto backend called from both encode and decode paths.
- **Reachability:** production
- **Evidence:**
  - POSIX: `crypto_core/src/secure_alloc.rs` L105-189 — `mmap` PROT_NONE guard pages, `mprotect` data, `mlock`, `MADV_DONTDUMP`
  - Windows: `crypto_core/src/secure_alloc.rs` L213-296 — `VirtualAlloc` PAGE_NOACCESS, `VirtualProtect` PAGE_READWRITE, `VirtualLock`, `VirtualFree`, `VirtualUnlock`
  - Zeroization on Drop: `crypto_core/src/secure_alloc.rs` L302-304 — `T::zeroize()` + `munmap`/`VirtualFree`
- **Remaining weakness:**
  - **Observed** (Medium): `mlock` failure is silent in release builds (`secure_alloc.rs` L159-166). Keys may reside on swappable memory without caller awareness. `is_locked()` accessor exists but no production caller checks it.
  - **Observed** (Low): macOS lacks `MADV_DONTDUMP` equivalent — key material appears in core dumps on macOS.
  - **Fixed this session** (Low): `sysconf(_SC_PAGESIZE)` return value was cast to `usize` without checking for -1 error. Now fails closed with `MmapFailed(0)`.

### 1.2 Mandatory ML-DSA Manifest Signing + PQ Ratchet Beacon

- **Status:** Fully Implemented (signing bypassable by env var — fixed this session)
- **Production path:** Yes
- **Reachability:** production
- **Evidence:**
  - ML-DSA-65 + Ed25519 hybrid signing: `meow_decoder/manifest_signing.py` — `sign_manifest()`, `verify_manifest_signature()`
  - Encode integration: `meow_decoder/encode.py` L356-401 — signature appended as multi-part QR frames
  - Decode integration: `meow_decoder/decode_gif.py` L730-757 — unsigned manifests rejected (fail-closed) when signing enabled
  - PQ ratchet beacon: `meow_decoder/ratchet.py` L470-513 — `_fold_pq_into_root()` folds ML-KEM-1024 shared secret into root key via HKDF
  - PQ beacon frame: `meow_decoder/pq_ratchet_beacon.py` — ML-KEM-1024 encapsulation/decapsulation
- **Remaining weakness:**
  - **Fixed this session** (was Critical → now Medium): `MEOW_MANIFEST_SIGNING=off` previously allowed disabling signing in production mode. Now blocked when `MEOW_PRODUCTION_MODE=1` and `MEOW_TEST_MODE` is not set. See `encode.py` L346-355, `decode_gif.py` L592-598.
  - **Observed** (Low): PQ-only fallback (no X25519) mixes PQ shared secret into message key but does NOT perform root rotation (`ratchet.py` L1168-1178). Documented limitation.

### 1.3 On-Screen Randomized Keyboard + Mouse-Gesture Password Auth

- **Status:** Fully Implemented
- **Production path:** Yes — activated via `--password-mode secure-keyboard` or `--password-mode mouse-gesture`
- **Reachability:** production (when CLI flag set)
- **Evidence:**
  - Full tkinter GUI: `meow_decoder/secure_keyboard.py` — randomized key layout, timing jitter, decoy character injection
  - `MouseGesturePassword`: same file — BLAKE2b hashing of gesture coordinates
  - `SecureString` class with `bytearray` zeroization on `__del__`
  - Imported by both `encode.py` and `decode_gif.py`
- **Remaining weakness:** None significant. CLI fallback via `getpass` with `timing_normalized_input()` is acceptable.

### 1.4 Active Tamper Detection + Silent Poisoning

- **Status:** Partially Implemented — **code exists but is NOT wired into production paths**
- **Production path:** **No**
- **Reachability:** unreachable (from production encode/decode)
- **Evidence:**
  - Module: `meow_decoder/tamper_detection.py` — `protect_function` decorator, `TamperDetector`, `_self_check()`
  - **Observed** (High): Neither `encode.py` nor `decode_gif.py` nor `__main__.py` imports `tamper_detection`. Verified via grep — zero references.
  - **Observed** (Medium): `_save_state()` silently swallows `IOError` (`tamper_detection.py` L321) — tamper state persistence can be blocked by an attacker.
  - **Observed** (Medium): `TamperState.to_bytes()` stores `state_key` in plaintext alongside the HMAC value (`tamper_detection.py` L207).
- **Remaining weakness:** The entire module is dead code in production. Zero runtime integrity protection.

### 1.5 Adversarial Carrier Generation + Stego Algorithm Rotation

- **Status:** Fully Implemented
- **Production path:** Conditional — activated when steganography is enabled in PARANOID stealth level
- **Reachability:** production (when stego + PARANOID mode enabled)
- **Evidence:**
  - Integration: `meow_decoder/stego_advanced.py` L525-537 — imports `adversarial_carrier.adversarial_embed()`, applies noise per-frame with algorithm rotation
  - Carrier module: `meow_decoder/adversarial_carrier.py` — sensor, texture, DCT, combined noise generators
  - Session-unique seeding: `session_seed = secrets.token_bytes(32)` + per-frame SHA-256 derivation
- **Remaining weakness:**
  - **Observed** (Low): `ImportError` on `adversarial_carrier` is silently caught (`stego_advanced.py` L536-537) — if the module fails to import, paranoid mode silently degrades to standard embedding.

### 1.6 Shamir-Style Multi-GIF Split Redundancy

- **Status:** Fully Implemented
- **Production path:** Yes — via `--shamir-split THRESHOLD TOTAL` CLI flag
- **Reachability:** production
- **Evidence:**
  - Module: `meow_decoder/shamir_split.py` — GF(2^8), `split_gif_to_files()`, `combine_files_to_files()`, CLI workflow
  - Encode integration: `meow_decoder/encode.py` L1891-1902 — post-encode split, original GIF deleted
  - Duplicate share rejection, checksum verification on combine
- **Remaining weakness:**
  - **Observed** (Low): Windows binary mode set at module import level (`shamir_split.py` L460) — affects any module that imports shamir_split, not just CLI use.
  - **Observed** (Low): `set_id` is random 4-byte tag (checksum only, not HMAC-bound). Acceptable for intended use.

### 1.7 Portable Single-Executable Mode + Isolation Checks

- **Status:** Fully Implemented
- **Production path:** Conditional
- **Reachability:** production
- **Evidence:**
  - PyInstaller spec: `meow_decoder.spec` — single-binary packaging
  - Environment safety: `meow_decoder/env_safety.py` — VM/debugger/container detection, activated by `MEOW_STRICT_ISOLATION=1`
  - Entry point: `meow_decoder/__main__.py` — calls `require_safe_environment()` when env var set
- **Remaining weakness:**
  - **Observed** (Medium): Every individual env check has `except Exception: pass` (`env_safety.py` L260). An attacker who triggers exceptions in specific checks bypasses those detections.
  - **Observed** (Low): Process detection via `ps ax` is easily evadable by renaming processes. Defense-in-depth only.

### 1.8 Expanded Formal Verification + Public Bounty Program

- **Status:** Partially Implemented
- **Production path:** CI-gated (structural checks only for Verus; real invocation for TLA+, ProVerif, Tamarin, Lean 4)
- **Reachability:** test-only (formal verification) / docs-only (bounty)
- **Evidence:**
  - Verus proofs: `verus_guarded_buffer.rs`, `verus_kdf_proofs.rs`, `aead_wrapper.rs`, `verus_windows_guard.rs` — structural annotations present, **NOT Z3-checked in CI**
  - TLA+/ProVerif/Tamarin/Lean 4: CI-gated with real tool invocation per `docs/SECURITY_INVARIANTS.md` L39-64
  - Bounty: SECURITY.md references responsible disclosure — no formal bounty program found in README or SECURITY.md
- **Remaining weakness:**
  - **Observed** (Medium): Verus proof AEAD-007 domain separation checks byte positions [0..4] but the implementation places the random prefix at bytes [8..12] (`aead_wrapper.rs` L185-187 vs L688). Proof specification doesn't match implementation.
  - **Inferred** (Low): No formal bug bounty program with monetary rewards found. SECURITY.md has responsible disclosure process only.

---

## 2. Cryptographic Correctness Audit

### 2.1 AES-GCM Nonce Generation and Reuse Prevention

- **Status:** Sound with defense-in-depth
- **Findings:**
  - **Observed** (Low): `Nonce::random()` in `pure_crypto.rs` L152-157 generates fully random 12-byte nonces with birthday bound at ~2^48. Production paths use fresh `secrets.token_bytes(12)` per encryption.
  - **Observed** (Information): Python-side nonce reuse guard with 10K LRU cache in `crypto.py` L292-315. Best-effort per-process only.
  - **Observed** (Information): Counter-based `NonceManager` in `aead_wrapper.rs` L120-190 uses 8-byte counter + 4-byte random prefix. Strictly monotonic — cannot collide.
  - **Fixed this session** (Medium): `encrypt_raw()`/`decrypt_raw()` in `aead_wrapper.rs` L375-410 bypassed nonce tracking and were `pub`. Now `#[doc(hidden)]` with clear warnings.
- **Severity:** Low (random nonces used sparingly; counter-based in high-volume paths)
- **Reachability:** production

### 2.2 Argon2id Usage and Domain Separation

- **Status:** Strong
- **Findings:**
  - **Observed** (Information): 4 presets in `argon2_presets.py`: paranoid (512 MiB/20 iter), balanced (256 MiB/8), activist-fast (194 MiB/4), test (32 MiB/1). Production default is paranoid (8x OWASP).
  - **Observed** (Information): Handle-based derivation in `crypto.py` L506-555 — key NEVER enters Python memory.
  - **Observed** (Information): Duress key domain-separated via HKDF info `meow_duress_tag_v2` in `crypto.py` L378-389.
  - **Observed** (Low): `pure_crypto.rs` `argon2_derive` has no minimum password length check (`pure_crypto.rs` L429). Python layer enforces 8-char NIST minimum upstream.
- **Severity:** Low
- **Reachability:** production

### 2.3 Ratchet Forward Secrecy (including PQ Beacon)

- **Status:** Strong — correctly implemented PQXDH-style integration
- **Findings:**
  - **Observed** (Information): PQ fold uses HKDF with X25519 root as salt, PQ shared secret as IKM, epoch binding in info — `ratchet.py` L470-513. Both inputs required for prediction.
  - **Observed** (Information): 10 unique HKDF domain separation constants. Bounded skip-key cache (MAX_SKIP_KEYS = 2000).
  - **Observed** (Information): Header encryption with XOR-masked frame indices.
  - **Observed** (Low): Key commitment tags (16 bytes) prevent invisible salamanders. Tamarin model: `formal/tamarin/MeowKeyCommitment.spthy`.
- **Severity:** Low
- **Reachability:** production

### 2.4 Manifest Signing, AAD Binding, and HMAC Verification

- **Status:** Strong with one mitigated bypass
- **Findings:**
  - **Observed** (Information): 8-field canonical AAD in `crypto.py` L118-153: `AAD_VERSION || orig_len || comp_len || salt || sha256 || magic || [mode_byte] || [ephemeral_pk] || [pq_ciphertext]`
  - **Observed** (Information): HMAC verification is mandatory before any field use. Manifest HMAC covers ALL packed fields including cipher_len, block_size, k_blocks, duress_tag.
  - **Observed** (Information): Decode path rejects unsigned manifests when signing enabled — fail-closed at `decode_gif.py` L749-757.
  - **Fixed this session** (was Critical): `MEOW_MANIFEST_SIGNING=off` bypass now blocked in production mode at `encode.py` L346-355 and `decode_gif.py` L592-598.
  - **Observed** (Medium): Rust `aad: Option<&[u8]>` in `pure_crypto.rs` L246-267 allows `None` (empty AAD). Violates stated invariant "aad=None is never allowed". Python layer always provides non-empty AAD.
- **Severity:** Medium (AAD bypass possible at Rust API level, mitigated by Python layer)
- **Reachability:** production

### 2.5 Zeroization and Memory Wiping

- **Status:** Strong (Rust layer); Best-effort (Python layer)
- **Findings:**
  - **Observed** (Information): All key types use `#[derive(Zeroize, ZeroizeOnDrop)]` — `SecretKey`, `AeadKey`, `X25519KeyPair`, `MlKemKeyPair`, `SecurePin`.
  - **Observed** (Information): `SecureBox<T>`: data zeroized → munlock → munmap/VirtualFree. Correct sequence.
  - **Fixed this session** (was Medium): `export_key()` test-mode escape eliminated — `MEOW_TEST_MODE=1` can no longer override production guard. Gate now checks `_PRODUCTION_MODE` alone at `crypto_backend.py` L645.
  - **Observed** (Low): `panic = "abort"` prevents `Drop` (and thus zeroization) on panic paths. Combined with `unreachable!()` macro usage, any unexpected path aborts without zeroization.
  - **Observed** (Low): HSM PIN clone (`hsm.rs` L345) — `pin.pin.clone()` for `AuthPin` may leave unzeroed copy in memory.
- **Severity:** Low
- **Reachability:** production

### 2.6 Constant-Time Guarantees

- **Status:** Strong for critical paths
- **Findings:**
  - **Observed** (Information): AES-GCM tag comparison via `subtle::ConstantTimeEq`. HMAC verification via `ct_eq`. `secrets.compare_digest()` in Python.
  - **Observed** (Information): `constant_time_eq` in `pure_crypto.rs` L588-593 leaks length on mismatch — acceptable for fixed-length MAC/tag comparisons.
  - **Observed** (Low): CTR counter addition uses variable-time carry propagation (`pure_crypto.rs` L345-351). Counter is not secret — low risk.
- **Severity:** Low
- **Reachability:** production

### 2.7 Side-Channel Leaks

- **Status:** Mitigated with documented limitations
- **Findings:**
  - **Inferred** (Low): `opt-level = "s"` (`Cargo.toml`) optimizes for size rather than speed, which may affect constant-time properties of some operations. `subtle` crate is designed for this.
  - **Observed** (Low): `NonceTracker` uses `HashSet::contains` (`nonce.rs` L266-283) — not constant-time, but nonce is not secret.
  - **Observed** (Information): Python cannot guarantee true constant-time execution due to GIL, GC, and JIT. The `timing_equalizer` module provides best-effort path timing normalization.
- **Severity:** Low
- **Reachability:** production

---

## 3. Steganography & Indistinguishability Audit

### 3.1 Adversarial Carrier Generation and Algorithm Rotation

- **Status:** Implemented, integrated at PARANOID stealth level
- **Findings:**
  - **Observed** (Information): Four noise algorithms (sensor, texture, DCT, combined) with per-frame rotation. Session-unique seed via `secrets.token_bytes(32)`.
  - **Observed** (Information): Integration at `stego_advanced.py` L525-537 — applies `adversarial_embed()` per frame with algorithm rotation schedule.
  - **Observed** (Low): `ImportError` on adversarial_carrier is silently caught — PARANOID mode degrades without notice.
  - **Assumption** (Low): No formal steganalysis resistance evaluation against modern ML-based detectors (e.g., SRNet, YeNet). The doc acknowledges this.
- **Severity:** Low
- **Reachability:** production (PARANOID mode only)

### 3.2 Statistical Indistinguishability

- **Status:** Partially addressed
- **Findings:**
  - **Observed** (Medium): Schrodinger mode uses `QuantumNoise = XOR(Hash(Pass_A), Hash(Pass_B))` with entropy tests for indistinguishability. However, inter-file correlation (e.g., multiple GIFs from same session) is not addressed.
  - **Observed** (Information): `chi_square_test()` and `pairs_test()` in adversarial_carrier verify noise distribution properties.
  - **Inferred** (Medium): Cat steganography uses APNG (not GIF, which destroys LSB) — correct engineering choice. But APNG format itself is an unusual file format that could be a steganographic indicator.
- **Severity:** Medium
- **Reachability:** production (stego modes)

### 3.3 Fixed-Size Padding and Decorrelation

- **Status:** Implemented
- **Findings:**
  - **Observed** (Information): Length padding via `metadata_obfuscation.add_length_padding()` in `crypto.py` L595-601.
  - **Observed** (Information): QR codes at fixed 600x600 pixels, fixed 10 FPS default.
  - **Observed** (Information): `decorrelation.py` module exists for traffic analysis resistance.
- **Severity:** Low
- **Reachability:** production

### 3.4 Steganalysis Resistance

- **Status:** Best-effort, not formally evaluated
- **Findings:**
  - **Assumption** (Medium): No empirical steganalysis benchmarks against standard tools (StegExpose, SRNet, etc.) were found in the codebase. The adversarial carrier generation is theoretically sound but untested against production steganalysis.
  - **Observed** (Low): Floyd-Steinberg dithering and PSNR quality estimation provide defense-in-depth.
- **Severity:** Medium (absence of formal evaluation)
- **Reachability:** production (stego modes)

---

## 4. General Bug & Regression Hunt

### 4.1 Dead-Man Switch Fail-Open (FIXED)

- **Finding:** Inner `except Exception` caught all dead-man switch errors and continued normal decoding, allowing an attacker who corrupts the deadman.json state file to bypass the decoy mechanism.
- **Severity:** High (was) → Fixed this session
- **Evidence:** `decode_gif.py` L147-159 — now raises `RuntimeError` with fail-closed message.
- **Reachability:** production

### 4.2 HMAC Unreachable Error Returns All-Zero MAC (FIXED)

- **Finding:** `hmac_sha256()` in Rust returned `[0u8; HMAC_SIZE]` on the theoretically-unreachable error path. An attacker with a zero-MAC oracle could forge authentication tags.
- **Severity:** Medium (was) → Fixed this session
- **Evidence:** `pure_crypto.rs` L552-555 — now uses `unreachable!()` which aborts rather than returning a potentially forgeable value.
- **Reachability:** production (unreachable in practice, but defense-in-depth)

### 4.3 `sysconf` Unchecked Cast (FIXED)

- **Finding:** `sysconf(_SC_PAGESIZE)` returning -1 was cast to `usize::MAX`, causing allocation arithmetic to wrap.
- **Severity:** Low (was) → Fixed this session
- **Evidence:** `secure_alloc.rs` L116-121 — now checks `<= 0` and returns `MmapFailed(0)`.
- **Reachability:** production (extremely unlikely but correct defense)

### 4.4 `export_key()` Test-Mode Escape (FIXED)

- **Finding:** `MEOW_TEST_MODE=1` could override `MEOW_PRODUCTION_MODE=1` to extract raw key bytes from handles.
- **Severity:** High (was) → Fixed this session
- **Evidence:** `crypto_backend.py` L638-659 — now gates on `_PRODUCTION_MODE` alone.
- **Reachability:** production

### 4.5 Tamper Detection Dead Code

- **Finding:** `tamper_detection.py` is complete (528 lines, `protect_function` decorator, `TamperDetector` class) but never imported by production encode/decode paths.
- **Severity:** High (module provides zero runtime protection)
- **Evidence:** `grep -rn 'import.*tamper_detection' meow_decoder/encode.py meow_decoder/decode_gif.py meow_decoder/__main__.py` → zero results.
- **Reachability:** unreachable

### 4.6 Memory Guard Not Called

- **Finding:** `memory_guard.py` provides `activate_memory_guard()` and `require_memory_guard()` but neither is called in production pipeline.
- **Severity:** Medium → High (memory locking, core dump prevention, ptrace blocking are all opt-in only)
- **Evidence:** `grep -rn 'import.*memory_guard' meow_decoder/encode.py meow_decoder/decode_gif.py meow_decoder/__main__.py` → zero results.
- **Reachability:** unreachable (from default production paths)

### 4.7 Forensic Cleanup Never Invoked

- **Finding:** `forensic_cleanup.py` provides shell history scrubbing, clipboard clearing, temp file cleanup but is never imported by production paths.
- **Severity:** Low (utility module, not a security control)
- **Evidence:** Not imported by encode.py, decode_gif.py, or __main__.py.
- **Reachability:** unreachable (from production paths; available as standalone tool)

### 4.8 Hardware Key Derivation Silent Fallback

- **Finding:** When hardware derivation (HSM/TPM) fails, code falls back to software mode unless `--no-hardware-fallback` is set.
- **Severity:** Medium (default behavior is fail-open for hardware security)
- **Evidence:** `decode_gif.py` L366-370 — `except Exception` falls through to software derivation.
- **Reachability:** production

### 4.9 Pre-Release PQ Dependencies

- **Finding:** `ml-kem = "0.3.0-pre"` and `ml-dsa = ">=0.1.0-rc.5, <0.2"` are pre-release crates. The `>=` range for ml-dsa could pull untested RCs.
- **Severity:** Low (PQ features are experimental/optional)
- **Evidence:** `crypto_core/Cargo.toml`
- **Reachability:** production (when PQ features enabled)

### 4.10 `From<&[u8]> for AssociatedData` Panics on Oversized Input

- **Finding:** With `panic = "abort"`, passing > 16KB AAD to `From<&[u8]>` aborts the process with no Drop cleanup.
- **Severity:** Low (caller-controlled input; defensive types.rs has `TryFrom` recommendation in comment)
- **Evidence:** `crypto_core/src/types.rs` L143-148
- **Reachability:** production

---

## 5. Documentation Verification

### 5.1 SECURITY_INVARIANTS.md

- **Assessment:** **Exemplary transparency.** The Verus/formal verification table correctly distinguishes "STRUCTURAL" (CI grep-based) from real CI-gated invocation. The note at the bottom accurately explains CI limitations.
- **Evidence:** `docs/SECURITY_INVARIANTS.md` L39-79
- **Finding:** VERIFIED — no overclaims.

### 5.2 THREAT_MODEL.md

- **Assessment:** Body text is thorough and honest. **Scorecard at the end contradicts the nuanced body.**
- **Findings:**
  - **Observed** (Medium): Memory Forensics marked "STRONG" in scorecard but body text correctly calls it "Platform-dependent" and "best-effort" (`THREAT_MODEL.md` L905 vs L559-575). Should be "MITIGATED".
  - **Observed** (Medium): Timing Attacks marked "STRONG" but body says Python "cannot guarantee true constant-time execution" (`THREAT_MODEL.md` L906 vs L577-597). Should be "MITIGATED".
  - **Observed** (Medium): OS Artifact Leakage marked "STRONG" but `forensic_cleanup.py` is "best-effort and OS-dependent" and never called in production paths (`THREAT_MODEL.md` L907).

### 5.3 SECURITY.md

- **Findings:**
  - **Observed** (Medium): Verus properties table at `SECURITY.md` L404-408 says "Verus-proven" for nonce uniqueness, auth-gated plaintext, key zeroization, no-bypass. CI does not run Z3. Should say "Verus-specified (structural CI, local Z3)".
  - **Observed** (Low): Test count discrepancies — documentation says one count, `cargo test` produces a different count. Should be consistent with one methodology.

### 5.4 PROTOCOL.md

- **Assessment:** VERIFIED — no significant issues. Protocol description matches implementation.
- **Evidence:** `docs/PROTOCOL.md`

### 5.5 README.md

- **Findings:**
  - **Observed** (Low): "Military-grade authenticated encryption" at `README.md` L195 — marketing overclaim. AES-256-GCM is solid but "military-grade" is meaningless without formal audit/FIPS certification.
  - **Observed** (Low): Mobile app claims "267 passing, >=95% coverage" — cannot be verified in the devcontainer.

---

## 6. Final Independent Verdict

### Overall Security Score: 7.5 / 10

This is a **conservative** score reflecting the gap between the strong crypto foundations and the incomplete production integration.

### Strengths (driving the score up)
- **Crypto foundations are excellent:** Handle-based Rust backend keeps secrets out of Python, AES-256-GCM with 8-field AAD binding, Argon2id at 8x OWASP, HMAC-before-use, fail-closed on auth failures.
- **Ratchet is well-engineered:** PQXDH-style PQ fold, 10 domain-separation constants, bounded skip-key cache, header encryption, key commitment tags.
- **Formal verification coverage is genuine and honestly disclosed:** TLA+, ProVerif, Tamarin, Lean 4 — all CI-gated with real tool invocation. Verus limitations correctly labeled "STRUCTURAL".
- **Multiple defense layers:** Fountain codes for loss tolerance, Schrodinger mode for deniability, Shamir splitting for physical redundancy.

### Weaknesses (reducing the score)
- **Tamper detection is dead code:** An entire security module providing runtime integrity protection is never imported in production. This is not a partial implementation — it's zero implementation in the paths that matter.
- **Memory guard is opt-in only:** Guard pages, mlock, core dump prevention, ptrace blocking are all available but never activated by default in encode/decode paths.
- **3 documentation overclaims:** THREAT_MODEL.md scorecard inflates ratings vs. its own body text. SECURITY.md overstates Verus as "proven" when CI only does structural checks.

### Is the current implementation ready for high-stakes use?

**No.** The cryptographic primitives and protocol design are sound, but three remaining High-severity items must be addressed:

1. **Tamper detection must be wired into production paths** — or removed to eliminate false confidence
2. **Memory guard should be activated by default** in encode/decode (at least best-effort `activate_memory_guard()`)
3. **Hardware key derivation fallback should be fail-closed by default** — software fallback should require explicit `--allow-software-fallback` flag

### Remaining Critical/High Issues

| ID | Severity | Finding |
|----|----------|---------|
| 4.5 | High | Tamper detection is dead code — zero runtime protection |
| 4.6 | Medium→High | Memory guard never called in production paths |
| 4.8 | Medium | Hardware derivation fails open to software |
| 1.8 | Medium | Verus AEAD-007 proof checks wrong byte positions |

### One-sentence recommendation before release

Wire tamper detection and memory guards into the default production pipeline, make hardware-derivation fallback opt-in rather than default, and downgrade the THREAT_MODEL.md scorecard entries to match the honest body text.

---

*Bugs fixed during this audit session:*
1. Dead-man switch fail-open → fail-closed (`decode_gif.py` L147-159)
2. `MEOW_MANIFEST_SIGNING=off` production bypass → blocked (`encode.py` L346-355, `decode_gif.py` L592-598)
3. `export_key()` test-mode escape → production gate hardened (`crypto_backend.py` L638-659)
4. HMAC zero-MAC on unreachable path → `unreachable!()` abort (`pure_crypto.rs` L552-555)
5. `sysconf` unchecked cast → fail-closed check (`secure_alloc.rs` L116-121)
