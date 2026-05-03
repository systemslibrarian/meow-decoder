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

## Fixed in `audit/cat-mode-fixes` (2026-05-03)

- **Finding 4.5** — `random.choice` → `secrets.choice` in `meow_decoder/high_security.py`.
- **Finding 6.2** — `TpmContext::connect_tcti` no longer panics; uses `TctiNameConf::from_str(tcti)?` propagating via `TpmError::CommunicationFailed`.
- **Finding 6.6** — `Auth::try_from(...).unwrap()` replaced with `match` arm that maps the `Err` to a new `TpmError::InvalidAuth` variant; no panic on caller-supplied auth blob.
- **Finding 11.1** — `crypto_backend.get_default_backend()` and `get_handle_backend()` wrapped in `threading.Lock` with double-checked init (CPython 3.13+ free-threading safety).
- **Finding 3.2** — `HybridKeyPair` and `PQBeaconKeyPair` carry `__del__` best-effort zeroization (defense in depth; for hard guarantees use handle-based APIs).
- **Finding 12.2** — `.pre-commit-config.yaml` now includes `detect-secrets` (Yelp v1.5.0) with baseline `.secrets.baseline`. Excludes test fixtures, formal-method outputs, lock files.
- **Finding 12.6** — `cargo build --features tpm` now compiles cleanly. `crypto_core/src/tpm.rs` migrated through 16 distinct API breaks against `tss-esapi 7.6.0` (Marshall/UnMarshall traits, `try_from` constructors, `value()` accessors, `PcrSlot` bitflag enum, `TctiNameConf::from_str`, `CreateKeyResult` struct, `KeyHandle→ObjectHandle` via `.into()`). One judgment call flagged in commit `e43577e` for cryptographer review (`Context::create()` `SensitiveData` slot — the original code at that site appears to have been broken too).

## Still deferred

### Medium

- **Finding 7.3 — npm audit root devDependencies (4 HIGH / 1 MODERATE).** `npm audit fix` blocked by `canvas`/`node-pre-gyp` build failure under Node v24 — `canvas` needs a major-version bump (the v2.x line uses node-pre-gyp; v3.x switched to prebuilt binaries). Best handled by the dependabot path or a dedicated `canvas` upgrade PR rather than `--force`.
- **Finding 7.4 — npm audit web_demo devDependencies (1 HIGH / 1 MODERATE).** Same root cause as above (jest/picomatch transitive via `canvas`). Bumps with the same upgrade.

### Low

- **Finding 7.2 — pip 24.0 + wheel 0.45.1 CVEs.** Build-time only; touches the dev environment image rather than this repo. Bump pip≥25 / wheel≥0.46 in the codespace base image.
- **Finding 3.7 — Keyfile HKDF intermediate lives in Python.** `meow_decoder/crypto.py:471-481`. Refactor toward the handle-based `derive_key_argon2id_with_keyfile` path. Defensive cleanup; not a vulnerability.
- **Finding 13 coverage gaps.** Add `MEOW_PRODUCTION_MODE=0` to `tests/TEST_SUITE_README.md`; cover `# pragma: no cover` decompression-bomb branches.

## Real protocol state-machine bugs (needs cryptographer review + speculative-state refactor)

Surfaced by deep code review (gemini_suggestions_v2.md). Both verified
against the actual source. **Do not auto-patch** — the fix requires
restructuring the ratchet state-machine and re-validating against
`MeowRatchetFS.spthy` invariants and forward-secrecy properties the
current test suite does not cover.

- **HIGH — `meow_decoder/ratchet.py:1356-1369` — silent ratchet desync via PQ implicit rejection.**
  `_execute_rekey()` calls `_mlkem1024_decapsulate(...)` and folds the
  result into `new_root_h` (line 1358), then commits `self._state.root_key
  = new_root_h` (line 1368), all *before* the commit_tag verification at
  line 1583. ML-KEM Fujisaki-Okamoto implicit rejection means a tampered
  PQ ciphertext returns a pseudorandom shared secret instead of erroring.
  That pseudorandom secret is folded into the root, the state is
  irreversibly mutated, and the subsequent MAC fails — but rollback
  doesn't happen. Session is permanently desynced.
  **Fix sketch:** compute `new_root_h` and the new chain in local
  variables; derive the message key from the *speculative* chain; verify
  commit_tag with that key; only assign `self._state.root_key = new_root_h`
  if verification succeeds.

- **MEDIUM — `meow_decoder/ratchet.py:1525-1608` — frame-corruption burns msg key permanently.**
  Case 1 path (`frame_index in self._skipped_keys`) does
  `self._skipped_keys.pop(frame_index)` at line 1528 *before* the
  commit_tag verification at line 1583. The `finally` block at line 1606+
  drops the handle on exception. Net effect: a single corrupted-but-MAC-
  pretending frame removes the cached key permanently — even a clean
  re-scan of that QR frame will then fail. For an asymmetric rekey
  beacon frame, `state.position` has also been advanced, compounding the
  problem: the user can't recover the rekey epoch transition.
  **Fix sketch:** speculative pop — copy the handle without removing from
  cache, verify MAC, only `pop()` on success. Same speculative-state
  pattern as the HIGH item above.

## Design choices flagged but not bugs

- **`meow_decoder/schrodinger_encode.py` `frame_mac_seed` is public** —
  gemini_suggestions_v2.md item #1 framed this as a CPU-exhaustion DoS
  vector. The codebase explicitly documents the choice
  (`schrodinger_encode.py:88-99`): *"frame_mac_seed is stored UNENCRYPTED.
  It is NOT a secret. It provides only per-GIF key uniqueness for the
  DoS-filter frame MACs. Content authentication is always provided by
  the Argon2id HMAC layer (reality_a/b_hmac + AES-GCM)."* The dual-
  reality property requires either-password verifiability; binding the
  MAC to a secret only one password holder knows breaks that property.
  Real authentication is layered below. **Not a bug** per documented
  threat model — but worth empirically measuring Fountain decoder CPU
  behavior under a flood of valid-MAC garbage droplets.

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
