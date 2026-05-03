# Meow Decoder — Follow-up items (post-audit)

Items logged here require human decision or deeper work before fixing.
Populated during audit phases; see `AUDIT-2026-04-18.md` for the full audit record.

## Architectural decisions needed

*(Populated when a phase identifies an issue requiring protocol/API redesign.)*

## Fixed in `audit-followup-fixes` (commit 8522477, 2026-04-18)

- **Finding 3.1 — `save_receiver_keypair` key-byte zero-loop.** Fixed in `meow_decoder/x25519_forward_secrecy.py:338-341` — exported key bytes are now held in a `bytearray` so the `finally`-block zero-loop can overwrite them. Rust FFI + file write coerce back to `bytes` at call sites.
- **Finding 3.4 — Ed25519 fallback production gate.** Fixed in `meow_decoder/manifest_signing.py:_require_rust_ed25519()` — pure-Python Ed25519 fallback now raises `RuntimeError` when `MEOW_PRODUCTION_MODE=1` and the Rust backend isn't available. `MEOW_TEST_MODE=1` still allows it for CI.
- **Finding 6.1 — Decrypt error message sanitization.** Fixed in `meow_decoder/crypto.py:decrypt_to_raw()` — underlying exception text no longer embedded in the user-facing error. The FIX-A2 AAD precondition check is hoisted above the try-block so `ValueError` propagates (programming error, not tamper event). PQ-downgrade branch remains distinct.
- **Finding 7.1 — rsa crate Marvin Attack guard.** Fixed in `crypto_core/src/yubikey_piv.rs:386-420` — `YubiKey::decrypt()` now returns `YubiKeyError::NotSupported` for `AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048`, forcing callers onto ECDH only.
- **Finding 9.1 — Fountain encoder sanity checks.** Fixed in `meow_decoder/fountain.py:137-149` — rejects non-positive `k_blocks`/`block_size` and caps `total_size` at 10 GiB.
- **Finding 10.3 — GIF frame-count limit.** Fixed in `meow_decoder/gif_handler.py` — added `MAX_GIF_FRAMES=100_000` class constant and checks in both `extract_frames` and `extract_frames_bytes`.
- **Finding 11.2 — `download_tokens` dict race.** Fixed in `web_demo/app.py` — added `download_tokens_lock = threading.Lock()` and wrapped cleanup iteration/mutation, download-file access, and `@response.call_on_close` cleanup pop in the lock.
- **Finding 12.1 — Release profile strip.** Fixed in `crypto_core/Cargo.toml` — added `strip = "symbols"` under `[profile.release]`.
- **Finding 14.1 — README `--pq` qualifier.** Fixed in `README.md:531` — PQ threat-model line now reads `(ML-KEM-768 with --pq / ML-KEM-1024 with --paranoid) — opt-in; default is classical X25519 (MEOW3)`.

Also fixed earlier in the audit (pre-FOLLOWUP):
- **Finding 5.5 — web_demo bounds check** (`web_demo/app.py:1121-1135`, commit 896958b)
- **Finding 6.3 — TPM PcrSlot map_err** (`crypto_core/src/tpm.rs:421-428`, commit 896958b)

## Medium-severity items still deferred

- **Finding 7.3 — npm audit root devDependencies (4 HIGH / 1 MODERATE).** Transitive via jest/playwright/selenium/canvas. ReDoS + path-traversal. Not in shipped artifacts. **Recommended fix:** `npm audit fix --force` then re-run `npm test` on both root and web_demo. Deferred: touches devDeps that could break tests, needs triage with maintainer.
- **Finding 12.6 — `cargo build --features tpm` fails on main.** `crypto_core/src/tpm.rs:525,540` — `SensitiveData::as_bytes` and `KeyHandle→ObjectHandle` type errors against current `tss-esapi 7.5` API. **Recommended fix:** rename `as_bytes()` calls to `bytes()`; add `.into()` to convert `KeyHandle` to `ObjectHandle` at the unseal call site. Deferred: needs hardware to validate, feature is opt-in.

## Low-severity items still deferred

- **Finding 4.5 — `random.choice` in `meow_decoder/high_security.py:446-447`.** Unused function `generate_innocuous_filename`. If ever exposed, switch to `secrets.choice`.
- **Finding 6.2 — `TpmContext::connect_tcti` panics on invalid TCTI parse** at `crypto_core/src/tpm.rs:328`. Internal callers pass hardcoded values, but `pub fn` exposes panic to external Rust users. Replace with `.map_err(|e| TpmError::CommunicationFailed(e.to_string()))?`.
- **Finding 6.6 — `Auth::from_bytes(&a.auth).unwrap()`** at `crypto_core/src/tpm.rs:417`. Auth blob is caller-controlled; panic on out-of-range length. Replace with `TpmError::InvalidAuth`.
- **Finding 7.2 — pip 24.0 + wheel 0.45.1 CVEs.** Build-time only. Bump dev env to pip≥25 / wheel≥0.46.
- **Finding 7.4 — npm audit web_demo devDependencies (1 HIGH / 1 MODERATE).** Jest transitive. Bump alongside root npm update.
- **Finding 3.2 — `HybridKeyPair` / `PQBeaconKeyPair` no `__del__`.** `meow_decoder/pq_hybrid.py:131`, `meow_decoder/pq_ratchet_beacon.py:176`. Python memory zeroization is best-effort. Add explicit `__del__` or replace raw bytes with a zeroizing wrapper.
- **Finding 3.7 — Keyfile HKDF intermediate lives in Python.** `meow_decoder/crypto.py:471-481`. Prefer the handle-based `derive_key_argon2id_with_keyfile` path.
- **Finding 11.1 — Backend singleton init not explicitly locked.** `meow_decoder/crypto_backend.py:301,668`. Add `threading.Lock`.
- **Finding 12.2 — Pre-commit lacks secret-scanning.** `.pre-commit-config.yaml`. Add `detect-secrets` / `trufflehog` / `gitleaks` hook.
- **Finding 13 coverage gaps.** Add `MEOW_PRODUCTION_MODE=0` to `tests/TEST_SUITE_README.md`; cover `# pragma: no cover` decompression-bomb branches.

## Tamarin formal-verification model issues (needs cryptographer review)

After Tamarin 1.10.0 → 1.12.0 (PR #171, accepting Maude 3.5.1), three CI shards
remain red. Tamarin/Maude are confirmed working — the failures are real model
bugs that 1.10.0 was lenient about and 1.12.0's stricter wellformedness checks
now surface. **Do not auto-patch — claiming a security proof works when it
does not is worse than failing CI.**

Severity-ordered findings:

- **HIGH — `formal/tamarin/MeowKeyCommitment.spthy:52-80`** — `CommitmentNonForgeability`
  lemma is genuinely **falsified** (2-step trace). Root cause: `let` bindings
  reference unfreshened `mk, salt, nonce, pt` while premises declare `~mk, ~salt,
  ~nonce, ~pt`, AND `ReceiverVerifyDecrypt` freshly generates its own `~mk, ~salt`
  instead of consuming the sender's `!SentWithCommit(...)` persistent state.
  Receiver thus uses random keys uncorrelated with sender — trivial forgery.
  **Fix requires cryptographer:** wire receiver to `!SentWithCommit` correctly,
  not just rename variables.

- **MEDIUM — `formal/tamarin/MeowRatchetFS.spthy:~180`** — undefined predicate
  `FrameEncrypted/4` referenced by lemma; no rule emits this action fact.
  Adjacent: `m+'1'` multiset notation is fine (builtin imported line 45) but
  whatever rule should produce `FrameEncrypted` is missing.

- **MEDIUM — `formal/tamarin/MeowRatchetHeaderOE.spthy:~88,113`** — unguarded
  variable `hk` in lemma quantifier (1.12.0 enforcement).

- **LOW (mechanical) — `formal/tamarin/MeowSchrodingerDeniabilityTiming.spthy:68`** —
  custom `h/1` collides with `builtins: hashing`. Rename to `hash_fn` or drop
  hashing import. Verify no other model imports this file's signature.

- **LOW (mechanical) — `formal/tamarin/secure_alloc_guard_pages.spthy:33`** —
  custom `zero/1` is a reserved name. Rename to `zero_buf` and update all use
  sites in the same file.

- **CI infra — `.github/workflows/formal-verification.yml:630`** — shard 1's
  `docker run --rm meow-tamarin` (no timeout, no memory cap) ran for 1h6m and
  the runner died with "lost communication with the server" (OOM/heartbeat).
  Wrap in `timeout 1800` and add `--memory=6g --cpus=2`. Independent of the
  model bugs above; will at least give clean failure output instead of runner
  blackout.

## Pre-existing test failures (not caused by audit)

- **`tests/test_cat_js_runner.py::TestCat5SpeedsJS::test_cat_5speeds_pipeline`** — Marked `xfail` in the audit-followup commit. Confirmed pre-existing by `git stash` test on bare main. Root cause: `web_demo/preamble-calibration.js` over-measures preamble duration when the sync word uses the same `1010...` pattern. NRZ decoder then locks onto sync *inside* the preamble, overshoots by 8 bits, and byte[0] comes out as `0xca` (second half of magic `0xfe 0xca`) instead of `0xfe`. Node probe in `/tmp/debug_cat.js` reproduces deterministically. **Recommended fix:** preamble-calibration should stop at the expected 16-bit boundary (using known `bitPeriod`) rather than measuring the extent of alternation.
- **Gate 5 (Security Coverage) — 65.67% vs 85% threshold.** Pre-existing on main. `schrodinger_encode.py` (0%), `memory_guard.py` (23%), `master_ratchet.py` (45%), `pq_hybrid.py` (69%), `manifest_signing.py` (63%), `secure_temp.py` (77%) are all in `.coveragerc-security` include list but insufficiently exercised by `-m "security or crypto or adversarial"` selection. **Recommended fix:** either (a) add `security` marker to existing tests that already exercise these modules, or (b) trim include list to the genuinely covered-by-markers set and ratchet up from there. Not attempted in this audit — would need test-by-test triage.

## Tests to add

*(Populated in Phase 13.)*

## Attempted but reverted fixes

*(Populated when a fix breaks tests and is reverted.)*
