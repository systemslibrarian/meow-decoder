# Schrödinger Mode — Targeted Security Audit

**Auditor:** Independent review (15+ years deniable encryption / coercion-resistant systems)
**Scope:** Schrödinger dual-secret plausible deniability as of `main` branch, commit `fd7aff8` (2026-02-21)
**Classification:** INTERNAL — NOT AN EXTERNAL AUDIT. All conclusions are advisory.
**Threat model:** Nation-state adversary, compelled disclosure, unlimited forensic resources.

---

## 1. Current Schrödinger Mode Implementation Summary

### 1.1 Architecture: Dual-Stream Always-On

As of HEAD (`fd7aff8 feat(security): make Schrödinger mode cryptographically indistinguishable from single-secret`), Schrödinger mode has been refactored into a **dual-stream always-on** design in [meow_decoder/dual_stream.py](meow_decoder/dual_stream.py). This replaces the older `schrodinger_encode.py` (version 0x07) with a new manifest version **0x08**.

**Core design:**

Every encode — single-secret or dual-secret — produces **exactly two independent sub-streams**, interleaved byte-by-byte via [quantum_mixer.py](meow_decoder/quantum_mixer.py):

```
payload → compress → encrypt (stream A)  ──┐
decoy/random → encrypt (stream B)         ──┤
                                            ▼
                                 interleave(A, B)  [even=A, odd=B]
                                            ▼
                                 fountain encode → QR → GIF
```

In single-secret mode, stream B is a **real AES-256-GCM encryption of random data under a random password** ([dual_stream.py L243–L250](meow_decoder/dual_stream.py#L243)):

```python
dummy_password = secrets.token_hex(32)
dummy_data = secrets.token_bytes(len(real_data))
comp_b, sha_b, salt_enc_b, nonce_enc_b, cipher_b, key_handle_b = \
    encrypt_file_bytes_handle(dummy_data, dummy_password, use_length_padding=True)
```

### 1.2 Multiplexing Details

| Component | Stream A | Stream B | Independence |
|-----------|----------|----------|-------------|
| Argon2id salt | `salt_a` (16 bytes, random) | `salt_b` (16 bytes, random) | Fully independent |
| AES-GCM nonce | `nonce_a` (12 bytes, random) | `nonce_b` (12 bytes, random) | Fully independent |
| Argon2id key derivation | Via `real_password` + `salt_a` | Via `decoy_password` + `salt_b` | Fully independent |
| HKDF domain separation | `meow_dual_enc_a_v1` / `meow_dual_hmac_a_v1` | `meow_dual_enc_b_v1` / `meow_dual_hmac_b_v1` | Correctly separated |
| HMAC authentication | HMAC(hmac_key_a, manifest_core) | HMAC(hmac_key_b, manifest_core) | Independent keys, shared authenticated data |
| Encrypted metadata | 104 bytes (AES-GCM) | 104 bytes (AES-GCM) | Independent keys/nonces |
| Manifest wire size | Fixed 382 bytes | Same manifest | Always identical |

### 1.3 Key Security Claims from README

From [README.md L315–L325](README.md#L315):

> **⚠️ Honest Security Assessment:**
> Schrödinger mode attempts to encode two independent secrets into one output file... Cryptographic deniability is **limited**: while the two encodings are designed to look superficially similar, advanced statistical analysis, timing differences, or comparison of multiple files from the same user may allow a nation-state forensic team to detect the presence of dual encoding... **Do not rely on this feature alone against a determined state adversary.**

From [README.md L362–L363](README.md#L362):

> **⚠️ Warning:** Neither feature protects against determined adversaries with forensic capabilities or physical torture.

From [docs/THREAT_MODEL.md L560–L600](docs/THREAT_MODEL.md#L560):

> **What does NOT work against a determined state adversary:**
> - Comparison of multiple files from the same user reveals patterns
> - File size, frame count, and timing may leak dual-encoding presence
> - Memory/swap forensics may recover both key sets
> - Physical torture / legal compulsion to reveal both passwords

From [docs/SECURITY_CLAIMS.md](docs/SECURITY_CLAIMS.md):

> **What This Project Is NOT:** Not externally audited. Not Signal. Not formally verified. Not NIST-certified.

**Assessment: The project's honesty about limitations is commendable and rare.** These warnings are accurate and appropriately conservative.

### 1.4 Existing Security Features

| Feature | Implementation | Location |
|---------|---------------|----------|
| Rust `zeroize` crate on all key types | `#[derive(Zeroize, ZeroizeOnDrop)]` on `SecretKey`, `AeadKey`, `X25519KeyPair`, `MlKemKeyPair` | [crypto_core/src/pure_crypto.rs L119](crypto_core/src/pure_crypto.rs#L119), [types.rs L24](crypto_core/src/types.rs#L24) |
| Opaque handle system | Keys never enter Python; Rust `HandleBackend` with `MAX_HANDLES=65536` | [rust_crypto/src/handles.rs L31–L211](rust_crypto/src/handles.rs#L31) |
| `subtle` crate constant-time comparisons | `a.ct_eq(b).into()` via `ConstantTimeEq` | [pure_crypto.rs L590](crypto_core/src/pure_crypto.rs#L590) |
| Python `mlock` on `SecureBuffer` / `secure_memory()` | `libc.mlock()` per-buffer (not system-wide) | [constant_time.py L116–L160](meow_decoder/constant_time.py#L116) |
| Duress mode with timing equalization | Both branches execute equivalent work | [duress_mode.py L120–L175](meow_decoder/duress_mode.py#L120) |
| HKDF domain separation | Unique info strings per key purpose | [dual_stream.py L66–L69](meow_decoder/dual_stream.py#L66) |
| HMAC manifest authentication | Per-stream HMAC covers full manifest core | [dual_stream.py L335–L343](meow_decoder/dual_stream.py#L335) |
| Handle drop with explicit zeroization | `hb.drop(handle)` in `finally` blocks | [dual_stream.py L348–L353](meow_decoder/dual_stream.py#L348) |
| Chi-squared + entropy CI tests | Ciphertext uniformity, entropy >7.8 bits/byte, gap <0.1 | [tests/security/test_dual_stream.py L258–L312](tests/security/test_dual_stream.py#L258) |
| Timing side-channel test suite | 500-iteration statistical measurements | [tests/test_sidechannel.py L97–L310](tests/test_sidechannel.py#L97) |

### 1.5 Recent Commits Improving Security

| Commit | Description | Impact |
|--------|-------------|--------|
| `fd7aff8` (HEAD) | Schrödinger mode → always-two-stream (manifest v0x08) | Eliminates structural distinguisher between single/dual mode |
| `d13b634` | ZERO PYTHON KEY BYTES — production paths never materialize secret keys | Python never holds raw key bytes (Rust handles only) |
| `a79e75e` | M1-M9 opaque handle migration complete | 139 tests covering Schrödinger handle migration |
| `eeddd81` | Rust test coverage + deadlock fix | 352 Rust tests, ASan/UBSan/Miri fuzzing |
| `20d2e0e` | Phase 0+1 multi-layer steganography | APNG carrier, STC Viterbi encoding |

---

## 2. Audit Against Hardening Categories

### A. Memory Hardening

**What is implemented:**

- **Rust `zeroize` crate**: All secret key types (`SecretKey`, `AeadKey`, `X25519KeyPair`, `MlKemKeyPair`) derive `Zeroize + ZeroizeOnDrop`. Handles are removed from the global `REGISTRY: Mutex<HashMap>` and types are dropped → zeroized. ([handles.rs L1021–L1025](rust_crypto/src/handles.rs#L1021))
- **Per-buffer `mlock`**: `secure_memory()` context manager in [constant_time.py L116–L160](meow_decoder/constant_time.py#L116) calls `libc.mlock()` on individual `bytearray` buffers. `SecureBuffer` class does the same.
- **Python `secure_zero_memory`**: Best-effort `ctypes.memset` zeroing of `bytearray` / `ctypes.Array`. Fallback to manual loop. ([constant_time.py L72–L106](meow_decoder/constant_time.py#L72))
- **Handle count monitoring**: Test at [test_dual_stream.py L571–L582](tests/security/test_dual_stream.py#L571) verifies handle count doesn't grow unboundedly.

**What is missing or insufficient:**

1. **No `mlockall(MCL_CURRENT | MCL_FUTURE)`**: Only individual buffers are locked. The Python interpreter's heap, stack, and any intermediate copies remain pageable to swap. A hibernation event or OOM condition will dump unlocked pages.

2. **No guard pages**: The `SecureBuffer` class allocates a plain `bytearray`. No `mmap` + `PROT_NONE` guard pages to detect buffer overflows or catch out-of-bounds access to adjacent key material.

3. **No canary values**: No sentinel values around key buffers to detect corruption/overflow.

4. **No 4-pass wipe**: `secure_zero_memory` does single-pass zeroing. On magnetic media (still used in some target environments), multi-pass overwrite patterns may be needed for physical data remanence.

5. **Python GC leak prevention is best-effort only**: The project correctly notes this limitation. However, `password.encode("utf-8")` in [dual_stream.py L229](meow_decoder/dual_stream.py#L229) creates an **immutable `bytes` object** containing the password that CPython may intern or cache. The `password_buf = bytearray(password.encode("utf-8"))` in `secure_decode_and_zeroize()` ([L459](meow_decoder/dual_stream.py#L459)) creates a zeroable copy, but the original `str` argument and its `.encode()` intermediate remain in Python's memory until GC collects them — which may be **never** if reference counts stick.

6. **No `PR_SET_DUMPABLE(0)` / `prctl` to disable core dumps**: If the process crashes or is killed with `SIGQUIT`, a core dump containing all keys will be written to disk.

7. **No `madvise(MADV_DONTDUMP)`**: Even with `mlock`, the locked pages will be included in core dumps unless explicitly excluded.

**Life-or-death vulnerability:**

> A forensic examiner runs `strings` on swap partition or a hibernation image. Password strings, Argon2id intermediate states, and plaintext fragments from Python's allocator are visible. The adversary recovers both passwords from a single memory dump. **This is not theoretical — tools like Volatility automate this.**

**Recommendation:**

```python
# meow_decoder/memory_hardening.py
import ctypes, os, resource

def harden_process_memory():
    """Call once at process start. Defense-in-depth, not a guarantee."""
    libc = ctypes.CDLL("libc.so.6")
    # Disable core dumps
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # mlockall: lock all current and future pages
    MCL_CURRENT, MCL_FUTURE = 1, 2
    libc.mlockall(MCL_CURRENT | MCL_FUTURE)
    # Disable ptrace attachment (Linux)
    PR_SET_DUMPABLE = 4
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
```

Add test: Verify `RLIMIT_CORE == 0` and `mlockall` return code in CI (requires `CAP_IPC_LOCK` or sufficient `RLIMIT_MEMLOCK`).

---

### B. Constant-Time Operations

**What is implemented:**

- **Rust `subtle::ConstantTimeEq`** for all MAC and password comparisons ([pure_crypto.rs L590](crypto_core/src/pure_crypto.rs#L590)).
- **Python delegates to Rust** for `constant_time_compare` ([crypto_backend.py L157](meow_decoder/crypto_backend.py#L157)).
- **Randomized timing jitter** in `timing_safe_equal_with_delay()` ([constant_time.py L160–L185](meow_decoder/constant_time.py#L160)).
- **Duress handler** executes both branches (dummy wipe on non-duress, real wipe on duress) with `_equalize_timing()` ([duress_mode.py L120–L175](meow_decoder/duress_mode.py#L120)).
- **500-iteration timing side-channel tests** with statistical analysis ([test_sidechannel.py L97–L310](tests/test_sidechannel.py#L97)).

**What is missing or insufficient:**

1. **CRITICAL: `dual_stream_try_decode_stream()` is NOT constant-time.** In [dual_stream.py L390–L440](meow_decoder/dual_stream.py#L390), the function tries stream A first; if it matches, it **returns immediately without trying stream B**. This creates a timing oracle:

   ```python
   if _secrets.compare_digest(computed_hmac_a, manifest.hmac_a):
       # Password matches stream A
       ...
       return cipher_a, 0   # ← EARLY RETURN, skips Stream B Argon2id
   ```

   An adversary measuring decode time can distinguish:
   - **Match on A**: ~5 seconds (1 Argon2id)
   - **Match on B**: ~10 seconds (2 Argon2ids)
   - **No match**: ~10 seconds (2 Argon2ids)

   **This leaks which stream the user's password belongs to.** If the adversary compels password A, they now know stream A was the one used — and can infer stream B exists and contains a different secret.

   The `secure_decode_and_zeroize()` function ([L444](meow_decoder/dual_stream.py#L444)) has a `duress` flag that forces both paths, but:
   - It's **opt-in**, not the default.
   - Even with `duress=True`, the code path is `if not matched_a or duress:` ([L492](meow_decoder/dual_stream.py#L492)), which still executes different code paths depending on `matched_a`.

2. **Branching on `matched_a`**: The `if matched_a:` / `if not matched_a:` branching at [L481](meow_decoder/dual_stream.py#L481) and [L492](meow_decoder/dual_stream.py#L492) is data-dependent branching on secret information (which password matched). While the Argon2id dominates timing, micro-architectural side channels (branch prediction, cache lines) can leak this bit.

3. **No minimum decode time enforcement**: There is no `equalize_timing()` call wrapping the entire decode operation. The randomized jitter in `_equalize_timing()` on duress adds 100–500ms, but Argon2id variance (~5s) dwarfs this.

**Life-or-death vulnerability:**

> Adversary forces victim to decode a file while monitoring wall-clock time with a stopwatch. If decode takes ~5s, password matched stream A. If ~10s, either wrong or matched stream B. Over multiple forced decryptions, the adversary builds a statistical model proving two streams exist. **The victim is then tortured for the second password.**

**Recommendation:**

```python
def dual_stream_try_decode_stream(manifest, password, interleaved):
    """ALWAYS derive both Argon2id keys, ALWAYS try both HMACs."""
    # Try A
    master_a = hb.derive_key_argon2id(...)
    hmac_key_a = hb.derive_key_hkdf(...)
    computed_a = hb.hmac_sha256(...)
    matched_a = _secrets.compare_digest(computed_a, manifest.hmac_a)

    # ALWAYS try B (no branching on matched_a)
    master_b = hb.derive_key_argon2id(...)
    hmac_key_b = hb.derive_key_hkdf(...)
    computed_b = hb.hmac_sha256(...)
    matched_b = _secrets.compare_digest(computed_b, manifest.hmac_b)

    # Select result without branching (constant-time select)
    # ...
```

This is the single most critical fix for Schrödinger mode's deniability.

---

### C. Entropy Indistinguishability

**What is implemented:**

- **Chi-squared uniformity tests** on ciphertext in CI: [test_dual_stream.py L258–L277](tests/security/test_dual_stream.py#L258) tests `chi_squared < 400` for both single and dual modes.
- **Shannon entropy tests**: [test_dual_stream.py L280–L312](tests/security/test_dual_stream.py#L280) asserts entropy > 7.8 bits/byte and gap between single/dual < 0.1.
- **Byte-pair (digram) entropy** in [test_ci_distinguishability.py](tests/security/test_ci_distinguishability.py).
- **Steganalysis metrics**: RS analysis, Sample Pair Analysis, chi-squared for LSB stego ([test_stego_adversarial.py L524–L536](tests/test_stego_adversarial.py#L524)).

**What is missing or insufficient:**

1. **CRITICAL: The `flags` field is a distinguisher.** [dual_stream.py L238](meow_decoder/dual_stream.py#L238) sets `flags = 0x01` for dual-secret and `flags = 0x00` for single-secret:

   ```python
   if is_dual:
       flags = 0x01  # stream_b_is_real
   else:
       flags = 0x00  # stream_b_is_dummy
   ```

   This byte is written into the manifest at byte offset 5 and is **plaintext** (not encrypted). A forensic examiner reading the GIF can extract the manifest, check byte 5, and **immediately determine whether two real secrets exist**.

   **SPECULATION (moderate confidence):** The `flags` field is HMAC-authenticated (included in `pack_core_for_auth()`), so it can't be tampered with — but it's **readable without any password**. This completely defeats plausible deniability. *(Verification: [dual_stream.py L126](meow_decoder/dual_stream.py#L126) — `pack_core_for_auth()` includes `struct.pack("BB", self.version, self.flags)` — yes, the flags byte is in the manifest wire format, visible to anyone.)*

2. **No NIST SP 800-22 test suite**: The chi-squared and Shannon entropy tests are necessary but not sufficient. NIST's Statistical Test Suite (frequency, runs, serial, approximate entropy, cumulative sums, random excursions, etc.) would detect subtler patterns. Dieharder suite is also absent.

3. **Interleaving pattern is deterministic**: `entangle_realities()` in [quantum_mixer.py L34–L50](meow_decoder/quantum_mixer.py#L34) always places stream A at even indices and stream B at odd indices. A known-plaintext attack on one stream (e.g., the adversary knows the decoy content) reveals the exact positions of every byte of the real stream.

4. **Padding is `secrets.token_bytes`**: [quantum_mixer.py L44](meow_decoder/quantum_mixer.py#L44) pads shorter streams with random bytes. However, the padding position (only at the end of the shorter stream) is deterministic. If cipher_a and cipher_b have detectably different lengths (from compressed data sizes), the transition from ciphertext to padding is a forensic marker.

5. **No compression ratio normalization**: Stream A (real secret, e.g., a compressed PDF) and stream B (random data, incompressible) will produce different `comp_len` values in the metadata. While metadata is encrypted, the ciphertext lengths (`cipher_a`, `cipher_b`) may differ and are padded only by `use_length_padding=True` (block-level padding, not perfect).

**Life-or-death vulnerability:**

> **The `flags` byte (0x00 vs 0x01) is a cleartext distinguisher readable without any password.** An adversary opens the GIF, extracts the manifest QR code (frame 0), reads byte 5, and knows instantly whether this is a dual-secret file. If `flags == 0x01`, they know two real secrets exist and will coerce both passwords. This completely negates Schrödinger mode's purpose.

**Recommendation:**

**MANDATORY (P0):** Remove the `flags` field or always set it to a fixed value regardless of mode. Single-secret and dual-secret manifests MUST be byte-identical in observable structure. The decoder should be blind to whether stream B is "real" — it simply tries to decrypt whatever is there.

```python
# ALWAYS set flags = 0x00 regardless of mode
flags = 0x00  # NEVER encode whether stream B is real
```

The `stream_b_is_real` property should be removed entirely. A decoder with password B either succeeds (it's real) or fails (it's random garbage). There is no need to pre-announce this.

---

### D. Forensic Countermeasures

**What is implemented:**

- **Secure file wipe**: [high_security.py L196](meow_decoder/high_security.py#L196) implements 7-pass DoD 5220.22-M overwrite for source files.
- **Resume file wipe**: [duress_mode.py L270–L300](meow_decoder/duress_mode.py#L270) securely wipes `~/.cache/meowdecoder/resume/` with configurable passes.
- **No-logs mode**: `enable_high_security_mode()` disables all Python logging ([high_security.py L152](meow_decoder/high_security.py#L152)).
- **Generic error messages**: `HighSecurityConfig.generic_errors = True` ([high_security.py L99](meow_decoder/high_security.py#L99)).

**What is missing or insufficient:**

1. **No swap/hibernation protection**: No `swapoff`, no encrypted swap verification, no `/proc/sys/kernel/randomize_va_space` check. `mlock()` on individual buffers does NOT prevent the Python interpreter's internal allocator from having copies in pageable memory.

2. **No thumbnail/preview prevention**: If the output GIF is saved to a filesystem with thumbnail generation (GNOME, KDE, Windows Explorer), the system creates thumbnail caches containing the QR frames. These survive file deletion.

3. **No journal/WAL protection**: Ext4/NTFS journals may contain file metadata (name, size, timestamps) even after deletion. No `O_TMPFILE` or ramfs usage for intermediate files.

4. **No timestamp randomization**: File creation/modification times on the output GIF reveal when encoding happened. On filesystems with birth time (`statx`), this is irrecoverable.

5. **No tmpfs enforcement**: The `no_temp_files` config flag exists but is not enforced at the OS level. If any library creates a temporary file in `/tmp` (which may be on-disk), it persists.

6. **Python `__pycache__` leaks**: `.pyc` files contain import timestamps and bytecode. They reveal that `schrodinger_encode.py` was imported, proving the user used deniability features.

**Life-or-death vulnerability:**

> Forensic examiner finds `meow_decoder/__pycache__/schrodinger_encode.cpython-312.pyc` with a recent timestamp. This proves the user invoked Schrödinger mode, regardless of what the GIF contains. Combined with the `flags` byte distinguisher, this removes all deniability.

**Recommendation:**

- Set `PYTHONDONTWRITEBYTECODE=1` in `enable_high_security_mode()`.
- Add `tmpfs` mount check (warn if `/tmp` is not tmpfs).
- Add `thumbnail_prevention()` that writes `.hidden` / `.nomedia` files beside outputs.
- Document that output GIF timestamps should be randomized (or use `touch -t`).

---

### E. Coercion Detection

**What is implemented:**

- **Duress password** triggers decoy content + memory wipe ([duress_mode.py L120–L175](meow_decoder/duress_mode.py#L120)).
- **Constant-time duress detection** with timing equalization ([duress_mode.py L139–L175](meow_decoder/duress_mode.py#L139)).
- **Dead man's switch**: `CountdownDuress` and `DeadManSwitch` classes exist (tests at [test_timelock_duress.py](tests/test_timelock_duress.py)).

**What is missing or insufficient:**

1. **No keystroke rhythm / hesitation detection**: Typing under duress produces measurable behavioral differences (longer pauses, more corrections, different inter-key timing). No biometric coercion signal is implemented.

2. **No mouse jitter / input pattern analysis**: Desktop GUI users under coercion exhibit different cursor trajectories and click patterns.

3. **No "panic gesture" (e.g., triple-click, specific USB device insertion)**: Hardware-triggered emergency wipe is not implemented.

4. **Duress password is visible in command-line arguments**: `--duress-password` in [duress_mode.py L484](meow_decoder/duress_mode.py#L484) puts the duress password in `argv`, visible via `ps aux` and `/proc/*/cmdline`. The `--duress-password-prompt` option exists, but the flag itself reveals duress was configured.

5. **Duress wipe is incomplete**: `_secure_zero()` in `DuressHandler` ([L67–L73](meow_decoder/duress_mode.py#L67)) uses a simple Python loop — no `ctypes.memset`, no Rust backend delegation. This is weaker than the `secure_zero_memory()` function elsewhere.

**Life-or-death vulnerability:**

> Adversary checks `~/.bash_history` or `~/.zsh_history` and finds `meow-decode --duress-password ...`. The mere presence of the flag proves the user had a duress password, which implies a real password exists. The adversary applies coercion for the real password.

**Recommendation:**

- Always use `--duress-password-prompt` in documentation; deprecate the `--duress-password` flag.
- Clear command-line arguments from `/proc/self/cmdline` after parsing (Linux: overwrite `argv` in-place via `ctypes`).
- Add optional keystroke timing biometric via `getpass()` wrapper.

---

### F. Quantum Resistance

**What is implemented:**

- **ML-KEM-768 (default) / ML-KEM-1024 (paranoid)** hybrid key exchange for standard MEOW4/MEOW5 manifests ([pq_hybrid.py](meow_decoder/pq_hybrid.py)).
- **PQXDH-style** two-step HKDF transcript binding.
- **PQ key types** with `Zeroize + ZeroizeOnDrop` ([pure_crypto.rs L802](crypto_core/src/pure_crypto.rs#L802)).

**What is missing or insufficient:**

1. **Schrödinger mode (v0x07/v0x08) does NOT use PQ crypto at all.** Neither `schrodinger_encode.py` nor `dual_stream.py` imports or uses `pq_hybrid.py`, `MlKemKeyPair`, or any post-quantum primitives. The encryption keys are derived solely from Argon2id (password-based), with no ephemeral key exchange.

2. **No PQ blinding for stream separation**: Even if PQ key exchange were added, there's no mechanism to use separate PQ public keys per stream to create quantum-resistant stream separation.

3. **Argon2id is inherently resistant to quantum speedup** (Grover's algorithm provides at most √ speedup, and memory-hard functions resist quantum parallelism). However, AES-256-GCM is reduced to ~128-bit security under quantum attack, which remains adequate but should be documented for Schrödinger mode specifically.

**Life-or-death vulnerability:**

> **Low immediate risk.** Harvest-now-decrypt-later is the primary PQ threat. For Schrödinger mode, the lack of PQ is less critical than the `flags` byte and timing oracle vulnerabilities. However, failing to integrate PQ creates a gap compared to standard MEOW5 encryption, which may confuse users expecting uniform protection.

**Recommendation:**

- Document that Schrödinger mode v0x08 uses **password-only** key derivation (no PQ, no FS).
- Add PQ hybrid support in a future version (new manifest v0x09).
- Priority: LOW. Fix the `flags` byte and timing oracle first.

---

### G. Gradual Self-Destruct

**What is implemented:**

- **Dead Man's Switch** (`DeadManSwitch` class tested in [test_timelock_duress.py](tests/test_timelock_duress.py)).
- **Time-lock puzzles** for delayed decryption.
- **Countdown duress** (encrypted data auto-destroys after N failed attempts or time period).

**What is missing or insufficient:**

1. **No progressive bit-rot simulation**: There's no mechanism to gradually degrade the ciphertext over time or repeated incorrect attempts, making forensic recovery increasingly difficult.

2. **No tamper-evident hardware integration**: USB dead man's switch, Yubikey challenge-response (YubiKey PIV stub exists but is incomplete — [crypto_core/src/yubikey_piv.rs](crypto_core/src/yubikey_piv.rs)).

3. **Self-destruct relies on software wiping**: On flash storage (SSD/eMMC), `secure_wipe_file()` with 7-pass overwrite is **ineffective** due to wear leveling. The SSD controller may retain old blocks indefinitely. Only full-disk encryption with key destruction provides guarantees on flash.

**Life-or-death vulnerability:**

> **Medium risk.** Software wipe on SSD fails. Old ciphertext blocks remain on flash cells. With JTAG access or flash chip removal, a forensic lab can recover "deleted" data.

**Recommendation:**

- Document SSD limitation prominently.
- Implement TRIM/discard after wipe (best-effort for flash).
- Consider per-file encryption wrapping where the key file can be reliably destroyed (e.g., on a separate hardware token).

---

## 3. Overall Risk Posture

### Strengths

1. **Honest disclosure**: The project's threat model, security claims, and README warnings are unusually honest for an open-source crypto tool. INV-025 explicitly lists what Schrödinger mode does NOT protect against.

2. **Rust crypto backend with `zeroize`/`subtle`**: Key material genuinely never enters Python in the production path. The opaque handle system with `MAX_HANDLES` DoS protection is well-designed.

3. **Dual-stream always-on**: The `fd7aff8` commit's approach of always producing two streams is the correct architectural direction. This eliminates the "single vs dual" structural distinction at the container level.

4. **Comprehensive timing test suite**: 500-iteration statistical measurements with `TimingAnalyzer` covering password comparison, HMAC verification, frame MAC, Argon2id consistency, and duress equalization.

5. **Chi-squared + Shannon entropy CI tests**: Automated statistical indistinguishability checks in CI prevent regression.

6. **Domain separation**: Correct unique HKDF info strings for every key derivation context.

### Risks (Life-or-Death)

1. **P0 — `flags` byte is a cleartext deniability-killing distinguisher.** Any forensic examiner can read byte 5 of the manifest and determine `0x01` (dual-real) vs `0x00` (single/dummy). This **completely defeats Schrödinger mode** against any adversary who reads the file format.

2. **P0 — Timing oracle in `dual_stream_try_decode_stream()`.** Password matching stream A returns in ~5s (1 Argon2id). Password matching stream B returns in ~10s (2 Argon2ids). A stopwatch reveals which stream the user accessed. Over multiple observations, this proves two independent streams exist.

3. **P1 — No `mlockall` / no swap protection / no core dump prevention.** All key material, including both passwords, can be recovered from swap, hibernation images, or crash dumps.

4. **P1 — Python memory leaks.** `str` and `bytes` objects containing passwords are immutable and cannot be zeroed. CPython's internal allocator may cache them indefinitely.

5. **P2 — `__pycache__` / bash_history / argv leaks** prove the user used Schrödinger/duress features.

6. **P2 — No NIST/Dieharder randomness tests.** Chi-squared and Shannon entropy are necessary but may miss autocorrelation, run-length, or spectral patterns.

7. **P3 — Interleave pattern is fixed (even=A, odd=B).** Known-plaintext on one stream reveals exact byte positions of the other.

### Final Verdict

| Threat Level | Verdict |
|-------------|---------|
| Casual inspection (employer, customs agent) | **STRONG** |
| Journalist protecting sources (target: police forensics) | **MARGINAL** — P0 bugs defeat it |
| Activist in authoritarian regime (nation-state, forensic lab) | **UNACCEPTABLE** — `flags` byte + timing oracle = immediate detection |
| Dissident in Tehran/Pyongyang (torture-backed compelled disclosure) | **UNACCEPTABLE** — multiple independently fatal flaws |

**Final verdict: UNACCEPTABLE for the stated threat model (nation-state adversary, compelled disclosure under torture).**

**One-sentence recommendation to push toward STRONG:**
Fix the three P0/P1 bugs (remove `flags` distinguisher, force dual-Argon2id in all decode paths, add `mlockall` + core dump prevention), then commission an external audit — the architecture is sound but implementation leaks break the deniability contract.

---

## 4. Concrete Next Steps

### 4.1 Prioritized Changes

| Priority | File | Change | Breaking? |
|----------|------|--------|-----------|
| **P0** | [meow_decoder/dual_stream.py](meow_decoder/dual_stream.py) | Remove `flags` field distinguisher: always set `flags = 0x00`. Remove `stream_b_is_real` property. Decoder should be blind to stream type. | **YES** — manifest v0x08 backward compat break. Bump to v0x09 or define flags=0x00 as the only valid value. |
| **P0** | [meow_decoder/dual_stream.py](meow_decoder/dual_stream.py) | `dual_stream_try_decode_stream()`: ALWAYS derive both Argon2id keys regardless of which HMAC matches first. Use constant-time select for result. | No — behavioral change only. |
| **P0** | [meow_decoder/dual_stream.py](meow_decoder/dual_stream.py) | `secure_decode_and_zeroize()`: Change `duress` parameter default to `True`, or remove the parameter entirely and always execute both paths. | No — timing change only. |
| **P1** | New file: `meow_decoder/memory_hardening.py` | Create `harden_process_memory()`: `mlockall(MCL_CURRENT\|MCL_FUTURE)`, `RLIMIT_CORE=0`, `prctl(PR_SET_DUMPABLE, 0)`, `PYTHONDONTWRITEBYTECODE=1`. Call from `enable_high_security_mode()`. | No |
| **P1** | [meow_decoder/constant_time.py](meow_decoder/constant_time.py) | `secure_zero_memory()`: Add `madvise(MADV_DONTDUMP)` on locked pages. | No |
| **P2** | [meow_decoder/high_security.py](meow_decoder/high_security.py) | Add `os.environ["PYTHONDONTWRITEBYTECODE"] = "1"` in `enable_high_security_mode()`. | No |
| **P2** | [meow_decoder/duress_mode.py](meow_decoder/duress_mode.py) | Deprecate `--duress-password` CLI flag. Log warning if used. Always prefer `--duress-password-prompt`. | No |
| **P2** | [meow_decoder/duress_mode.py L67](meow_decoder/duress_mode.py#L67) | `_secure_zero()`: Replace Python loop with `ctypes.memset` or delegate to Rust `secure_zero`. | No |
| **P3** | [meow_decoder/quantum_mixer.py](meow_decoder/quantum_mixer.py) | Randomize interleave pattern using HKDF-derived permutation instead of fixed even/odd. | **YES** — protocol change, new manifest field needed. |

### 4.2 README / THREAT_MODEL.md Wording Updates

**Add to THREAT_MODEL.md, section "Coercion Resistance":**

> **KNOWN ISSUE (pre-audit):** Schrödinger mode manifest version 0x08 contains a plaintext `flags` byte that distinguishes single-secret from dual-secret encoding. This must be fixed before Schrödinger mode provides meaningful deniability. Track issue #XXX.

**Add to README.md, Schrödinger Mode section:**

> **⛔ CRITICAL LIMITATION (v0x08, pre-fix):** The current dual-stream manifest contains a plaintext flag that reveals whether one or two real secrets are encoded. Until this is fixed, Schrödinger mode does NOT provide deniability against any adversary who can read the file. Use standard encryption (MEOW5) for actual security-critical transfers.

**Add to SECURITY_CLAIMS.md:**

> **Schrödinger mode is NOT deniable** against forensic examination in the current version. Known issues: plaintext `flags` byte, timing oracle on Argon2id derivation count, no swap/core dump protection. These are tracked for remediation.

### 4.3 Tests to Add

| Test | File | What it validates |
|------|------|-------------------|
| **Flags byte indistinguishability** | `tests/security/test_dual_stream.py` | `assert manifest_single.flags == manifest_dual.flags` — single and dual MUST produce identical manifest bytes except for encrypted fields |
| **Timing oracle: decode time indistinguishability** | `tests/test_sidechannel.py` | 100-iteration timing measurement: `abs(median_time_stream_a - median_time_stream_b) < 500ms` — both streams must take the same wall-clock time to decode |
| **Forced dual Argon2id** | `tests/security/test_dual_stream.py` | Verify that `dual_stream_try_decode_stream()` always calls Argon2id exactly twice, regardless of which password matches |
| **Core dump prevention** | `tests/test_high_security.py` | After `harden_process_memory()`, verify `RLIMIT_CORE == 0` |
| **mlockall** | `tests/test_high_security.py` | Verify `mlockall` called (may require `CAP_IPC_LOCK` in CI; skip if unprivileged) |
| **NIST SP 800-22 frequency/runs** | `tests/security/test_ci_distinguishability.py` | Implement monobit frequency test and runs test on output ciphertext; compare single vs dual |
| **`__pycache__` prevention** | `tests/test_high_security.py` | After `enable_high_security_mode()`, verify `PYTHONDONTWRITEBYTECODE=1` in `os.environ` |
| **argv scrubbing** | `tests/test_duress_mode.py` | After argument parsing, verify `sys.argv` does not contain password strings |
| **Interleave permutation** (if P3 implemented) | `tests/security/test_dual_stream.py` | Verify interleave positions are unpredictable without key material |

### 4.4 Protocol-Breaking Changes

| Change | Version Impact | Migration |
|--------|---------------|-----------|
| Remove `flags` distinguisher | Manifest v0x08 → v0x09 (or redefine v0x08 to always-zero flags) | Old v0x08 decoders will continue working (flags field is informational, not used for decryption). New encoders will always write `flags=0x00`. |
| Randomized interleave pattern (P3) | Requires new manifest field (interleave seed or HKDF derivation) | Protocol-breaking. Bump to v0x09 or v0x0A. Old decoders cannot decode new format. |
| Force dual Argon2id on decode | No protocol change | Backward compatible (only changes timing behavior). |

---

## Appendix: Audit Scope and Assumptions

### Files Reviewed

| File | Lines | Status |
|------|-------|--------|
| [meow_decoder/dual_stream.py](meow_decoder/dual_stream.py) | 528 | Primary target |
| [meow_decoder/schrodinger_encode.py](meow_decoder/schrodinger_encode.py) | 497 | Legacy (v0x07) |
| [meow_decoder/quantum_mixer.py](meow_decoder/quantum_mixer.py) | 67 | Reviewed |
| [meow_decoder/constant_time.py](meow_decoder/constant_time.py) | 350 | Reviewed |
| [meow_decoder/duress_mode.py](meow_decoder/duress_mode.py) | 563 | Reviewed |
| [meow_decoder/crypto_backend.py](meow_decoder/crypto_backend.py) | 693 | Reviewed |
| [meow_decoder/crypto.py](meow_decoder/crypto.py) | 2063 | Key functions reviewed |
| [meow_decoder/high_security.py](meow_decoder/high_security.py) | 534 | Reviewed |
| [meow_decoder/config.py](meow_decoder/config.py) | 287 | Reviewed |
| [meow_decoder/frame_mac.py](meow_decoder/frame_mac.py) | 289 | Reviewed |
| [meow_decoder/decoy_generator.py](meow_decoder/decoy_generator.py) | 176 | Reviewed |
| [crypto_core/src/pure_crypto.rs](crypto_core/src/pure_crypto.rs) | 1256 | Key sections |
| [crypto_core/src/types.rs](crypto_core/src/types.rs) | 289 | Reviewed |
| [crypto_core/src/aead_wrapper.rs](crypto_core/src/aead_wrapper.rs) | 659 | Key sections |
| [rust_crypto/src/handles.rs](rust_crypto/src/handles.rs) | 1491 | Key sections |
| [tests/security/test_dual_stream.py](tests/security/test_dual_stream.py) | 599 | Reviewed |
| [tests/test_sidechannel.py](tests/test_sidechannel.py) | 575 | Reviewed |
| [tests/test_duress_mode.py](tests/test_duress_mode.py) | 846 | Reviewed |
| [tests/test_adversarial.py](tests/test_adversarial.py) | 448 | Reviewed |
| [tests/test_security.py](tests/test_security.py) | 456 | Reviewed |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | 982 | Reviewed |
| [docs/SECURITY_CLAIMS.md](docs/SECURITY_CLAIMS.md) | 76 | Reviewed |
| [docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md) | 641 | Reviewed |
| [README.md](README.md) | — | Key sections |
| [CHANGELOG.md](CHANGELOG.md) | — | Key sections |

### Assumptions and Speculation Markers

- **CONFIRMED**: `flags` byte at manifest offset 5 is plaintext-visible (verified in `pack()` and `unpack()` methods).
- **CONFIRMED**: `dual_stream_try_decode_stream()` returns early after first HMAC match (verified in source).
- **CONFIRMED**: No `mlockall`, `PR_SET_DUMPABLE`, `MADV_DONTDUMP` anywhere in codebase (grep verified).
- **ASSUMPTION**: Argon2id takes ~5s per derivation in production mode (512 MiB, 20 iterations). Actual timing depends on hardware. The relative 2× difference between 1-derivation and 2-derivation paths is what matters for the timing oracle.
- **ASSUMPTION**: CPython's small-object allocator may cache password strings. This is well-documented Python behavior but not verified for this specific runtime version.
- **SPECULATION (low confidence)**: The Verus proof stubs (`assume(false)`) in [aead_wrapper.rs](crypto_core/src/aead_wrapper.rs) suggest formal verification is aspirational, not complete. This aligns with SECURITY_CLAIMS.md's honest disclosure.

---

*End of audit. Report generated 2026-02-21. This is an internal security review, not a formal external audit. Critical findings (P0) should be addressed before any deployment in the stated threat model.*
