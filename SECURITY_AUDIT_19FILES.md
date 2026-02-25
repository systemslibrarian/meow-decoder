# Security Audit: 19 Production Python Files

**Scope:** `meow_decoder/*.py` — 19 files listed below
**Date:** 2025-01-XX
**Methodology:** Full manual source review of every line in all 19 files

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Per-File Audit](#per-file-audit)
3. [Cross-Cutting Findings](#cross-cutting-findings)
4. [Special Focus Areas](#special-focus-areas)

---

## Executive Summary

**Overall posture: Strong, with several notable gaps.**

The codebase demonstrates mature security engineering: handle-based Rust crypto keeps secrets out of Python memory, AES-GCM AAD bindings are pervasive, and fail-closed patterns dominate. However, several findings require attention:

| Severity | Count | Summary |
|----------|-------|---------|
| **CRITICAL** | 2 | Manifest signing disableable via env var; tamper detection not wired into encode/decode |
| **HIGH** | 5 | Dead-man switch fail-open; PQ shared secret briefly in Python; `export_key()` test-mode escape hatch; `_save_state()` silent IOError; hardware fallback on exception |
| **MEDIUM** | 6 | `MEOW_MANIFEST_SIGNING=off` prints warning to stderr only; `env_safety` exception suppression; `forensic_cleanup` best-effort everywhere; Windows msvcrt side effect on import; OQS private attribute hack; `deactivate_memory_guard()` exists |
| **LOW/INFO** | 7 | `__main__` blocks as example code; cat-themed aliases; `KeyDeletionReport` test-only class; catnip HKDF salt (harmless meme) |

---

## Per-File Audit

### 1. `encode.py` (1924 lines)

**Production usage:** YES — primary encode pipeline. Called from `__main__.py` and CLI.

**Bugs / Security Flaws:**

- **[CRITICAL] Manifest signing disableable via env var** ([encode.py](meow_decoder/encode.py#L342-L355)): `MEOW_MANIFEST_SIGNING=off` completely disables ML-DSA + Ed25519 manifest signing. The only feedback is a `print()` to stderr. An attacker with env var control (e.g., shared hosting, container escape) can silently strip authentication. Should at minimum refuse in `MEOW_PRODUCTION_MODE=1`.

- **[HIGH] Hardware key derivation exception → silent fallback** ([encode.py](meow_decoder/encode.py#L1763-L1776)): When hardware derivation (HSM/TPM/auto) fails with an exception, the code falls back to software mode unless `--no-hardware-fallback` is set. Default behavior is fail-open for hardware security.

- **[MEDIUM] Password visible in process list** ([encode.py](meow_decoder/encode.py#L910-L914)): `--password` CLI arg leaks to `/proc/PID/cmdline`. Warning is printed but the arg is still accepted. Consider requiring `--password-mode standard` for interactive input by default.

**Stubs / TODOs / NotImplementedError:** None found. All code paths are implemented.

**Mocks / Test-only code:** `_run_self_test()` function (line ~1225) is gated behind `--self-test` flag — acceptable.

**Fail-open behavior:**
- Hardware fallback (see above)
- Dead-man's switch setup failure is non-fatal ([encode.py](meow_decoder/encode.py#L1878)): `except Exception as e: print(...)` — encoding succeeds even if dead-man switch fails.
- Shamir split failure is non-fatal ([encode.py](meow_decoder/encode.py#L1893)): encoding output already exists.

**Hardcoded secrets / weak defaults:**
- `--fps` default is 2, `--block-size` default 512, `--redundancy` 1.5 — all reasonable.
- `--hsm-key-label` defaults to `"meow-master"` (fine for deriving; not a secret).

---

### 2. `decode_gif.py` (1537 lines)

**Production usage:** YES — primary decode pipeline.

**Bugs / Security Flaws:**

- **[HIGH] Dead-man's switch exception → fail-open** ([decode_gif.py](meow_decoder/decode_gif.py#L149-L152)): Inner `except Exception as e: if verbose: print(...)` swallows ALL dead-man switch errors and continues normal decoding. If the dead-man switch JSON file is corrupted or the deadline check throws, the file decodes normally when it should have triggered the decoy. This is a fail-open for coercion resistance.

- **[CRITICAL → mitigated] Manifest signing disableable on decode** ([decode_gif.py](meow_decoder/decode_gif.py#L589-L591)): Same `MEOW_MANIFEST_SIGNING=off` env var disables signature verification on decode. Unsigned manifests are then silently accepted. When signing is enabled (default), unsigned manifests are correctly rejected ([decode_gif.py](meow_decoder/decode_gif.py#L750-L755) — fail-closed).

- **[MEDIUM] `--allow-legacy` flag** ([decode_gif.py](meow_decoder/decode_gif.py#L1084)): Accepts manifests without explicit mode byte. Legacy manifests may lack AAD fields that newer formats bind, potentially weakening authentication.

**Stubs / TODOs / NotImplementedError:** None found.

**Mocks / Test-only code:** None in production path.

**Fail-open behavior:**
- Dead-man switch (see above)
- Mobile bridge callback has simplified fountain decoder integration ([decode_gif.py](meow_decoder/decode_gif.py#L1198-L1214)) — commented as "simplified callback; full implementation would integrate directly."

**Hardcoded secrets / weak defaults:** None.

---

### 3. `ratchet.py` (1738 lines)

**Production usage:** YES — per-frame symmetric ratchet, imported by both encode.py and decode_gif.py.

**Bugs / Security Flaws:**

- **[INFO] `KeyDeletionReport` class** ([ratchet.py](meow_decoder/ratchet.py#L1670-L1704)): Test-only audit class. Never instantiated in production paths. Acceptable.

- **[LOW] Cat-themed aliases registered on `MEOW_CAT_API=1`** ([ratchet.py](meow_decoder/ratchet.py#L1725-L1738)): Aliases like `PawState`, `WhiskerKeys`, `bury_in_litter` are injected into module namespace. Harmless but increases attack surface minimally (module attributes).

- **[INFO] `MAX_SKIP_KEYS = 2000`** — bounded DoS prevention on out-of-order frames. Appropriate.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** `KeyDeletionReport` (test-only, not imported in production).

**Fail-open behavior:** None — all crypto failures raise `ValueError` or `RuntimeError`.

**Hardcoded secrets / weak defaults:**
- `DEFAULT_REKEY_INTERVAL` — checked at module level. Uses a sane default.
- Domain separation constants (10 unique HKDF info strings) — well-designed.

---

### 4. `frame_mac.py` (382 lines)

**Production usage:** YES — per-frame MAC authentication, imported by encode.py and decode_gif.py.

**Bugs / Security Flaws:** None found. Truncated HMAC (8 bytes) is appropriate for DoS resistance (not primary auth — AES-GCM tag provides that). Constant-time verification delegated to Rust.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** `__main__` block (example/demo only, lines ~360-382).

**Fail-open behavior:** None — `verify_frame_mac()` raises `ValueError` on mismatch.

**Hardcoded secrets / weak defaults:** None.

---

### 5. `pq_hybrid.py` (659 lines)

**Production usage:** YES — post-quantum hybrid crypto. Imported by encode.py, decode_gif.py, ratchet.py.

**Bugs / Security Flaws:**

- **[HIGH] PQ shared secret briefly in Python** ([pq_hybrid.py](meow_decoder/pq_hybrid.py#L520)): During ML-KEM encapsulation, the PQ shared secret exists as Python `bytes` before being passed to HKDF. Code acknowledges this in comment. Mitigation: the Rust handle-based `pqxdh_encapsulate()` keeps it in Rust, but the non-handle path exposes it.

- **[MEDIUM] `LIBOQS_AVAILABLE` aliased from Rust PQ check** ([pq_hybrid.py](meow_decoder/pq_hybrid.py#L71-L78)): The name `LIBOQS_AVAILABLE` is misleading — it's actually `True` when *Rust PQ* is available, not Python liboqs. Decode path in decode_gif.py checks this flag. Functionally correct but confusing for auditors.

- **[LOW] `__main__` block** ([pq_hybrid.py](meow_decoder/pq_hybrid.py#L630-L659)): Example code at module end. Not reachable in production imports.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** None in production paths.

**Fail-open behavior:** None — `PRODUCTION_MODE` gate raises `RuntimeError` when Rust PQ unavailable.

**Hardcoded secrets / weak defaults:** None.

---

### 6. `pq_ratchet_beacon.py` (441 lines)

**Production usage:** YES — ML-KEM-1024 beacon for ratchet PQ root rotation. Imported by ratchet.py.

**Bugs / Security Flaws:**

- **[MEDIUM] OQS backend private attribute hack** ([pq_ratchet_beacon.py](meow_decoder/pq_ratchet_beacon.py#L161)): `kem._secret_key = sk` sets a private attribute on the OQS KEM object. This may break silently in newer OQS versions. However, OQS path is effectively dead code in production (Rust PQ is required).

- **[LOW] Three-tier backend fallback** (Rust → ml-kem → OQS): In production mode, only Rust backend is usable. The fallback chain exists for development/testing only.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** None.

**Fail-open behavior:** None — raises `RuntimeError` if no backend available.

**Hardcoded secrets / weak defaults:** None. Uses ML-KEM-1024 (NIST Level 5) — appropriate for paranoid mode.

---

### 7. `crypto_backend.py` (719 lines)

**Production usage:** YES — core crypto abstraction used by every other module.

**Bugs / Security Flaws:**

- **[HIGH] `export_key()` production gate has test-mode escape** ([crypto_backend.py](meow_decoder/crypto_backend.py#L539-L550)): `export_key()` extracts raw key bytes from handles. Blocked in production (`MEOW_PRODUCTION_MODE=1`) UNLESS `MEOW_TEST_MODE=1` is also set. An attacker who can set env vars can set both simultaneously to extract secrets.

- **[MEDIUM] `MEOW_CRYPTO_BACKEND` env var override** ([crypto_backend.py](meow_decoder/crypto_backend.py#L225-L227)): Overrides backend selection via env var. Only "rust" is accepted (anything else raises RuntimeError), so this is safe but unnecessary attack surface.

- **[INFO] Module-level `__main__` block** ([crypto_backend.py](meow_decoder/crypto_backend.py#L577-L619)): Self-test code. Uses faster params for testing. Not reachable via import.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** `export_key()` gating discussed above. The self-test block.

**Fail-open behavior:** None — all crypto operations fail-closed via Rust backend.

**Hardcoded secrets / weak defaults:** `memory_kib=32768, iterations=2` in self-test block (fast params, test-only context — acceptable).

---

### 8. `nonce.py` (~170 lines)

**Production usage:** YES — HKDF-based deterministic nonce generation.

**Bugs / Security Flaws:** None found. Thread-safe with `threading.Lock()`. Reuse detection via `_used_nonces` set. `derive_transfer_nonce()` is stateless (documented — caller-managed reuse prevention).

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** None.

**Fail-open behavior:** None — `generate()` raises `RuntimeError` on nonce reuse.

**Hardcoded secrets / weak defaults:** None.

---

### 9. `manifest_signing.py` (433 lines)

**Production usage:** YES — ML-DSA-65 + Ed25519 hybrid signing. Imported by encode.py and decode_gif.py.

**Bugs / Security Flaws:**

- **[INFO] `SIGNING_MANDATORY = True`** ([manifest_signing.py](meow_decoder/manifest_signing.py#L51)): Correctly set. However, this constant is not checked by encode.py/decode_gif.py — they rely on `MEOW_MANIFEST_SIGNING` env var instead. The `SIGNING_MANDATORY` flag is only used internally for error messages.

- **[INFO] `MLDSA65_SK_SIZE = 32`** ([manifest_signing.py](meow_decoder/manifest_signing.py#L69)): Uses compact seed representation (32 bytes), not expanded secret key. Correct for ML-DSA-65.

- **[LOW] Backend fallback chain** (Rust → cryptography → ml-dsa → OQS): Multiple backends for Ed25519 and ML-DSA. In production, Rust is required. Other paths exist for development.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** None.

**Fail-open behavior:** None — `verify_manifest_signature()` raises `ValueError` on failure.

**Hardcoded secrets / weak defaults:** None.

---

### 10. `constant_time.py` (411 lines)

**Production usage:** YES — constant-time compare, secure memory, timing equalization.

**Bugs / Security Flaws:** None found. Correctly delegates to Rust `subtle` crate for constant-time operations. `equalize_timing()` uses calibrated delay for path timing normalization.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** `__main__` block (demo/benchmark code).

**Fail-open behavior:** None.

**Hardcoded secrets / weak defaults:** None.

---

### 11. `memory_guard.py` (890 lines)

**Production usage:** PARTIAL — NOT imported by encode.py or decode_gif.py directly. Available for caller code to invoke. `__main__.py` does not call it either.

**Bugs / Security Flaws:**

- **[MEDIUM] `deactivate_memory_guard()` exists** ([memory_guard.py](meow_decoder/memory_guard.py#L846-L869)): Reverses ALL memory protections — `munlockall()`, restores core dumps, re-enables ptrace. Comment says "for testing only" but no production mode gate.

- **[INFO] `activate_memory_guard()` is best-effort by default** ([memory_guard.py](meow_decoder/memory_guard.py#L669-L741)): Warns on failure but continues. `require_memory_guard()` is the fail-closed variant. Neither is called in the main encode/decode pipeline.

- **[LOW] Windows `VirtualLock` is per-buffer** — no `mlockall()` equivalent. Documented limitation.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** `deactivate_memory_guard()` (see above).

**Fail-open behavior:** `activate_memory_guard()` is explicitly warn-only. `require_memory_guard()` is fail-closed.

**Hardcoded secrets / weak defaults:** None.

---

### 12. `secure_keyboard.py` (832 lines)

**Production usage:** YES — imported by both encode.py and decode_gif.py for `--password-mode secure-keyboard` and `--password-mode mouse-gesture`.

**Bugs / Security Flaws:** None significant found. Real tkinter GUI implementation with randomized key layout, timing jitter, decoy characters. CLI fallback via `timing_normalized_input()` using `getpass`. `SecureString` class with `bytearray` zeroization on `__del__`. `MouseGesturePassword` uses BLAKE2b hashing.

**Stubs / TODOs / NotImplementedError:** None — full implementation.

**Mocks / Test-only code:** None.

**Fail-open behavior:** None — returns `None` on GUI cancel (callers check and `sys.exit(1)`).

**Hardcoded secrets / weak defaults:** None.

---

### 13. `tamper_detection.py` (528 lines)

**Production usage:** NO — **NOT imported or called by encode.py or decode_gif.py**. Zero integration with the production encode/decode pipeline.

**Bugs / Security Flaws:**

- **[CRITICAL] Not wired into production** — The `protect_function` decorator ([tamper_detection.py](meow_decoder/tamper_detection.py#L476-L497)) and `TamperDetector` class exist but are never applied to `encode_file()` or `decode_gif()`. The `_self_check()` on module load only runs if the module is imported (which it isn't from encode/decode).

- **[HIGH] `_save_state()` silently passes on IOError** ([tamper_detection.py](meow_decoder/tamper_detection.py#L325)): If the tamper state file can't be written (disk full, permissions), the error is silently swallowed. A tampered module could then force an IOError to prevent detection from persisting across restarts.

- **[MEDIUM] `TamperState.to_bytes()` stores `state_key` in plaintext** ([tamper_detection.py](meow_decoder/tamper_detection.py#L207)): The HMAC key used for state integrity is stored alongside the HMAC value. An attacker with file access can modify state and recompute the HMAC.

**Stubs / TODOs / NotImplementedError:** None — code is complete, just unused.

**Mocks / Test-only code:** None.

**Fail-open behavior:** `_save_state()` IOError suppression (see above).

**Hardcoded secrets / weak defaults:** The `state_key` stored in the state file (weak by design — relies on OS file permissions).

---

### 14. `adversarial_carrier.py` (659 lines)

**Production usage:** INDIRECT — imported by `stego_advanced.py` ([stego_advanced.py](meow_decoder/stego_advanced.py#L528)) which is called by encode.py when steganography is enabled. Not directly in the critical crypto path.

**Bugs / Security Flaws:** None significant. Procedural noise generation (sensor, texture, DCT) is information-theoretic — doesn't handle secrets. `SeededRNG` based on SHA-256 for deterministic noise.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** `chi_square_test()` and `pairs_test()` are verification functions (lines ~530-605), not test stubs.

**Fail-open behavior:** None — noise generation failures would propagate naturally.

**Hardcoded secrets / weak defaults:** None.

---

### 15. `shamir_split.py` (491 lines)

**Production usage:** YES — CLI workflow via `main()` with split/combine subcommands. Called from encode.py `--shamir-split` flag ([encode.py](meow_decoder/encode.py#L1891-L1902)).

**Bugs / Security Flaws:**

- **[MEDIUM] Windows binary mode side effect on import** ([shamir_split.py](meow_decoder/shamir_split.py#L460)): `msvcrt.setmode(0, os.O_BINARY)` runs at module level on Windows even when not using CLI. Could affect other modules that import shamir_split.

- **[LOW] `set_id` in v2 share format** — set_id is a random 4-byte tag to prevent mixing shares from different sets. This is not cryptographically bound (only a checksum, not HMAC). Acceptable for intended use.

**Stubs / TODOs / NotImplementedError:** None — working GF(2^8) implementation.

**Mocks / Test-only code:** None.

**Fail-open behavior:** None — `shamir_combine()` raises `ValueError` if insufficient shares or corrupt data.

**Hardcoded secrets / weak defaults:** None.

---

### 16. `env_safety.py` (655 lines)

**Production usage:** CONDITIONAL — only called when `MEOW_STRICT_ISOLATION=1` env var is set (from `__main__.py`).

**Bugs / Security Flaws:**

- **[MEDIUM] Exception suppression in all checks** ([env_safety.py](meow_decoder/env_safety.py#L260)): Every individual check has `except Exception: pass`. If a check crashes, it's silently skipped. An attacker who can trigger exceptions in specific checks (e.g., by making `/proc/self/status` unreadable) bypasses those detections.

- **[MEDIUM] `silent_unsafe_handler()`** ([env_safety.py](meow_decoder/env_safety.py#L650-L655)): A provided callback that does literally nothing on unsafe environment. Meant for "proceed with poison," but could be misused to silently ignore all safety checks.

- **[LOW] Process detection via `ps ax`** — easily evadable by renaming processes. This is defense-in-depth, not a security boundary. Documented as such.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** None.

**Fail-open behavior:** Non-strict mode (default) only fails on high/critical risks. Individual check exceptions are suppressed.

**Hardcoded secrets / weak defaults:** None.

---

### 17. `forensic_cleanup.py` (386 lines)

**Production usage:** NOT imported by encode.py or decode_gif.py. Available as standalone utility.

**Bugs / Security Flaws:**

- **[MEDIUM] Best-effort everywhere** — Every cleanup operation returns `success: True` even on partial failure. `clean_clipboard()` returns `success: True` with `error` set on exception ([forensic_cleanup.py](meow_decoder/forensic_cleanup.py#L318)). `clean_shell_history()` silently skips unreadable files ([forensic_cleanup.py](meow_decoder/forensic_cleanup.py#L371)).

- **[LOW] `_clean_gvfs_metadata()` is a no-op** ([forensic_cleanup.py](meow_decoder/forensic_cleanup.py#L233-L250)): Comments acknowledge inability to selectively scrub binary gvfs files. The function returns `success: True` with `items_cleaned: 0`.

- **[LOW] Shell history scrubbing is substring-based** ([forensic_cleanup.py](meow_decoder/forensic_cleanup.py#L362-L371)): Case-sensitive substring match on history lines. Could miss obfuscated commands.

**Stubs / TODOs / NotImplementedError:** `_clean_gvfs_metadata()` is effectively a stub.

**Mocks / Test-only code:** None.

**Fail-open behavior:** Everything is best-effort with `success: True` returns.

**Hardcoded secrets / weak defaults:** None.

---

### 18. `argon2_presets.py` (~170 lines)

**Production usage:** YES — imported by crypto pipeline for KDF parameter selection.

**Bugs / Security Flaws:** None found. 4 well-defined presets:
- **paranoid**: 512 MiB / 20 iter (default, 8× OWASP recommendation)
- **balanced**: 256 MiB / 8 iter
- **activist-fast**: 194 MiB / 4 iter (field use)
- **test**: 32 MiB / 1 iter

Auto-selects "test" when `MEOW_TEST_MODE=1`. `MEOW_KDF_PRESET` env var overrides.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** Test preset gated behind `MEOW_TEST_MODE=1`.

**Fail-open behavior:** None.

**Hardcoded secrets / weak defaults:** None — defaults are conservatively strong.

---

### 19. `__main__.py` (~40 lines)

**Production usage:** YES — CLI entry point dispatcher.

**Bugs / Security Flaws:** None found. Minimal dispatcher logic. `MEOW_STRICT_ISOLATION=1` triggers `require_safe_environment()`.

**Stubs / TODOs / NotImplementedError:** None.

**Mocks / Test-only code:** None.

**Fail-open behavior:** None.

**Hardcoded secrets / weak defaults:** None.

---

## Cross-Cutting Findings

### F1: Tamper Detection Is Dead Code in Production

`tamper_detection.py` defines a `protect_function` decorator and `TamperDetector` class, but **neither encode.py nor decode_gif.py import them**. The module's `_self_check()` runs on module load, but since no production code imports `tamper_detection`, the check never executes during normal encode/decode operations. This module provides zero runtime integrity protection.

**Recommendation:** Either wire `protect_function` into `encode_file()` and `decode_gif()`, or remove the module to reduce false confidence.

### F2: Memory Guard Is Opt-In Only

`memory_guard.py` provides `activate_memory_guard()` and `require_memory_guard()`, but **neither is called anywhere in the production encode/decode pipeline**. Memory locking, core dump prevention, and ptrace blocking are never activated automatically. Users must call these functions explicitly.

**Recommendation:** Call `activate_memory_guard()` early in encode.py/decode_gif.py `main()`, or at least in `__main__.py`.

### F3: Forensic Cleanup Is Never Invoked

`forensic_cleanup.py` is never imported by encode.py or decode_gif.py. Shell history scrubbing, clipboard clearing, and temp file cleanup happen only if the user explicitly invokes the module.

**Recommendation:** Consider adding `--cleanup` flag to encode/decode CLIs, or at minimum document the standalone usage prominently.

### F4: `MEOW_MANIFEST_SIGNING=off` Undermines ML-DSA

Both encode.py ([L342-L355](meow_decoder/encode.py#L342-L355)) and decode_gif.py ([L589-L591](meow_decoder/decode_gif.py#L589-L591)) check the same env var to disable manifest signing. This creates a single point of failure: any attacker with env var access can strip ML-DSA + Ed25519 authentication from both encode and decode paths.

**Recommendation:** In `MEOW_PRODUCTION_MODE=1`, refuse to honor `MEOW_MANIFEST_SIGNING=off`. Print an error and abort.

### F5: `export_key()` Test-Mode Escape

`HandleBackend.export_key()` ([crypto_backend.py](meow_decoder/crypto_backend.py#L539-L550)) is gated by `_PRODUCTION_MODE and not _TEST_MODE`. An attacker who can set `MEOW_TEST_MODE=1` alongside `MEOW_PRODUCTION_MODE=1` can extract raw key bytes from any handle.

**Recommendation:** Make `export_key()` gate on `_PRODUCTION_MODE` alone (deny in production regardless of test mode), or require a separate compile-time feature flag.

---

## Special Focus Areas

### ML-DSA Manifest Signing Wiring

**Status: WIRED but bypassable.**

- Encode path: `sign_manifest()` called at [encode.py#L373](meow_decoder/encode.py#L373). Signature appended to GIF as multi-part QR frames after manifest and droplets.
- Decode path: `verify_manifest_signature()` called at [decode_gif.py#L732](meow_decoder/decode_gif.py#L732). Unsigned manifests rejected ([L750-L755](meow_decoder/decode_gif.py#L750-L755)) — fail-closed when signing enabled.
- **Bypass:** `MEOW_MANIFEST_SIGNING=off` env var disables both paths (Finding F4).
- ML-DSA-65 + Ed25519 hybrid: both signatures required for verification. Backend chain: Rust → cryptography → ml-dsa → OQS.

### PQ Ratchet Beacon ML-KEM-1024 Usage

**Status: FULLY WIRED and functional.**

- Encoder: When both `receiver_public_key` (X25519) and `receiver_pq_public_key` (ML-KEM-1024) are provided, the PQ beacon folds ML-KEM-1024 shared secret into root key via `_fold_pq_into_root()` ([ratchet.py#L1130-L1145](meow_decoder/ratchet.py#L1130-L1145)). Chain is re-derived from PQ-hybrid root — critical fix ensuring chain keys depend on BOTH X25519 AND ML-KEM-1024.
- Decoder: `_execute_rekey()` ([ratchet.py#L1345-L1380](meow_decoder/ratchet.py#L1345-L1380)) mirrors encoder exactly — decapsulates PQ ciphertext, folds into root, re-derives chain.
- PQ-only fallback: When only PQ key is available (no X25519), PQ shared secret is mixed into message key ([ratchet.py#L1168-L1178](meow_decoder/ratchet.py#L1168-L1178)). No root rotation in this path (documented limitation).
- `PQBeaconFrame` serialization for header embedding.

### On-Screen Keyboard Implementation

**Status: REAL implementation, not a stub.**

- Full tkinter GUI with randomized key layout per session
- Timing jitter (inter-keystroke delay normalization) to defeat keystroke timing analysis
- Decoy character injection
- `MouseGesturePassword` with BLAKE2b hashing of gesture coordinates
- CLI fallback via `getpass` with `timing_normalized_input()`
- `SecureString` class with `bytearray.__del__` zeroization
- Imported and used by both encode.py and decode_gif.py when `--password-mode secure-keyboard` or `--password-mode mouse-gesture` is specified

### Tamper Detection Fail-Closed

**Status: IMPLEMENTED but NOT CONNECTED.**

- `protect_function` decorator ([tamper_detection.py#L476](meow_decoder/tamper_detection.py#L476)): Correctly raises `RuntimeError` if tamper is detected. Fail-closed design.
- `TamperDetector.check()`: Computes SHA-256 hashes of critical module source files and compares with stored baseline.
- **Problem:** Zero integration with production paths. Neither `encode.py` nor `decode_gif.py` import `tamper_detection`. The `_self_check()` only runs if the module is imported.
- `_save_state()` IOError suppression: tamper state persistence can be silently blocked.

### Adversarial Carrier Integration

**Status: INTEGRATED via stego_advanced.py.**

- `adversarial_carrier.py` is imported by `stego_advanced.py` at [stego_advanced.py#L528](meow_decoder/stego_advanced.py#L528).
- `adversarial_embed()` applies noise (sensor/texture/DCT/combined) to carrier images.
- Called when steganography is enabled in the encode pipeline.
- Not in the critical crypto path — operates on already-encrypted ciphertext.
- Pure noise generation — no secrets handled.

### Shamir CLI Workflow

**Status: COMPLETE and functional.**

- CLI entry via `main()` with split/combine subcommands using `argparse`.
- GF(2^8) implementation with proper polynomial evaluation.
- `split_gif_to_files()` and `combine_files_to_files()` helpers.
- Integrated into encode.py via `--shamir-split THRESHOLD TOTAL` flag ([encode.py#L1891](meow_decoder/encode.py#L1891)).
- Original GIF deleted after splitting (reduced exposure).
- Duplicate share ID rejection and checksum verification on combine.
- **Issue:** Windows binary mode set at module import level ([shamir_split.py#L460](meow_decoder/shamir_split.py#L460)).

---

## Recommendations (Priority Order)

1. **Gate `MEOW_MANIFEST_SIGNING` in production mode** — refuse `off` when `MEOW_PRODUCTION_MODE=1`
2. **Wire tamper detection into production pipeline** or remove the module
3. **Fix dead-man switch fail-open** — make exception handling fail-closed (raise, don't continue)
4. **Eliminate `export_key()` test-mode escape** in production builds
5. **Call `activate_memory_guard()` in main entry points** (encode/decode CLI)
6. **Add `--cleanup` flag** to invoke forensic cleanup after operations
7. **Fix `_save_state()` IOError suppression** in tamper detection
8. **Move Windows msvcrt call** behind `if __name__ == "__main__"` guard in shamir_split.py
