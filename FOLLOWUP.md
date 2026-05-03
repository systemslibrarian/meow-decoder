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

- ~~**Finding 7.2 — pip 24.0 + wheel 0.45.1 CVEs.**~~ FIXED on this branch — `.devcontainer/devcontainer.json` `postCreateCommand` now runs `pip install --upgrade 'pip>=25' 'wheel>=0.46'` before installing the project. Verified locally: pip 26.1, wheel 0.47.0 after upgrade. Build-time CVE chain on the codespace image is closed for new container builds.
- **Finding 3.7 — Keyfile HKDF intermediate lives in Python.** `meow_decoder/crypto.py:471-481`. Refactor toward the handle-based `derive_key_argon2id_with_keyfile` path. Defensive cleanup; not a vulnerability.
- **Finding 13 coverage gaps.** Add `MEOW_PRODUCTION_MODE=0` to `tests/TEST_SUITE_README.md`; cover `# pragma: no cover` decompression-bomb branches.

## Real protocol state-machine bugs — FIXED (2026-05-03, audit/cat-mode-fixes)

Surfaced by deep code review (gemini_suggestions_v2.md). Both fixed via
a speculative-state pattern in `meow_decoder/ratchet.py`. **Still
recommend cryptographer review** of the rollback paths and Tamarin
re-run against `MeowRatchetFS.spthy`; existing forward-secrecy tests
all pass and three new regression tests cover the specific bugs (see
`tests/test_ratchet.py::TestSpeculativeStateRollback`).

- **HIGH — silent ratchet desync via PQ implicit rejection (FIXED).**
  Was: `_execute_rekey()` decapsulated ML-KEM, folded junk into root,
  dropped old root/chain, committed `self._state` — all before
  `commit_tag` verification. Tampered PQ ciphertext → pseudorandom
  shared secret (FO implicit rejection) → state mutated with junk →
  MAC fails but no rollback → permanent desync.
  Fix: `_execute_rekey()` now snapshots the pre-rekey root/chain/
  position/epoch into `self._pending_rollback` and does NOT drop the
  old handles. `decrypt()` calls `_commit_rekey()` (drops old) on
  commit_tag pass, or `_rollback_rekey()` (restores old, drops new
  junk) on any verification failure — including AES-GCM auth failure
  downstream. New regression test:
  `test_tampered_pq_ciphertext_does_not_desync_ratchet` flips a byte
  inside the PQ ciphertext, asserts decrypt raises, verifies the
  pre-rekey state handles are unchanged, and proves a clean rekey
  frame still decrypts. `finalize()` also drops a stale
  `_pending_rollback` so an interrupted decrypt does not leak handles.

- **MEDIUM — frame-corruption burns msg key permanently (FIXED).**
  Was: Case 1 path (`frame_index in self._skipped_keys`) eagerly
  popped the cached handle before commit_tag verification. The
  `finally` block dropped on exception → cache permanently empty →
  re-scans of the same QR frame failed.
  Fix: `decrypt()` now peeks (`self._skipped_keys[frame_index]`)
  with an `owns_handle` ownership flag. The pop happens only after
  commit_tag + AES-GCM both pass. Beacon-mix derivations along the
  way create new owned handles and never drop the cache value while
  it is still tracked as not-owned. Two new regression tests:
  `test_cached_key_survives_commit_tag_failure` (regular frame) and
  `test_cached_rekey_frame_survives_commit_tag_failure` (rekey frame
  through the beacon-mix path).

Verification: 225/225 ratchet tests pass (`test_ratchet.py`,
`test_property_ratchet_pq.py`, `test_asymmetric_rekey.py`,
`security/test_ratchet_forward_secrecy.py`); 88/88 broader e2e +
audit-fixes + web-demo sweep passes; 1 pre-existing xfail unchanged.

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
  Real authentication is layered below.

  **Empirically measured** (commit on this branch, 2026-05-03):
  10,000 forged-but-valid-MAC droplets fed into a fresh
  `FountainDecoder` complete in **0.01 seconds wall time** with
  effectively zero RSS growth. Reason: `_process_pending` (the
  belief-propagation loop, the only place an O(|pending|²) cost could
  surface) runs only after a legitimate degree-1 decode. Without
  legitimate input the garbage just appends to `pending_droplets`,
  which is bounded by the GIF parser's `MAX_GIF_FRAMES = 100,000`.

  The test (`tests/test_schrodinger_dos.py`) asserts conservative
  ceilings (30s wall, 64 MB RSS) for the 10K-droplet flood and acts
  as a CI regression net for any future change that removes the
  GIF cap or pessimizes the pending data structure. **Confirmed
  bounded; gemini v2 #1 closed.**

## Tamarin formal-verification model issues — ALL ADDRESSED

After Tamarin 1.10.0 → 1.12.0 (PR #171, accepting Maude 3.5.1), three CI shards
were red. Tamarin/Maude are confirmed working — the failures were real model
bugs that 1.10.0 was lenient about and 1.12.0's stricter wellformedness checks
surface. **All findings now patched in this branch. CI run + cryptographer
review still recommended before claiming the proofs are sound** — the
reformulated `CommitmentNonForgeability` lemma especially.

Severity-ordered status:

- **HIGH — `formal/tamarin/MeowKeyCommitment.spthy` (FIXED, this branch).**
  `CommitmentNonForgeability` had two compounded root causes:
  1. `SenderCommitEncrypt` and `ReceiverVerifyDecrypt` `let` blocks referenced
     unfreshened `mk, salt, nonce, pt` (free variables), while premises
     declared `~mk, ~salt, ~nonce, ~pt` — Tamarin treats them as distinct
     terms, so derived `enc_key`/`auth_key` weren't derived from the actual
     fresh master keys.
  2. `ReceiverVerifyDecrypt` had its own `Fr(~mk), Fr(~salt)` premises,
     freshly generating keys uncorrelated with the sender's commit instead
     of consuming the persistent `!SentWithCommit(...)` fact.
  Fix:
  * `let` blocks now use `~mk, ~salt, ~nonce, ~pt` consistently.
  * `ReceiverVerifyDecrypt` consumes `!SentWithCommit` for `auth_key`,
    `enc_key`, `nonce`, then verifies the wire frame via a structural
    `In(<ct_recv, truncate16(hmac(auth_key, ct_recv)), nonce>)` pattern —
    the rule only fires when the wire tag matches the recomputed tag.
  * `CommitmentNonForgeability` reformulated: any `AdversaryForgeOutput`
    that happens to equal a real `CommitEncrypt`'s tag for the same `ct`
    implies the adversary knew the real auth_key. New
    `AdversaryForgeOutput/2` action fact carries the produced tag.
  * `AdversaryForgeAttempt/3` retained for future lemmas.
  Cryptographer review of the reformulation is requested before merging:
  the new lemma's intent matches the original property but the
  formalization is novel.

- **MEDIUM — `formal/tamarin/MeowRatchetFS.spthy` (FIXED, this branch).**
  `FrameEncrypted/5` is what the rule actually emits; three lemmas
  referenced `FrameEncrypted/4` (PerFrameForwardSecrecy missed `@ #t`,
  PostCompromiseSecurityViaBeacon used wrong arities for multiple action
  facts, KeyCommitmentBinding used /4 + missed `mk` arg). All lemmas now
  match emitted arities; `RegisterReceiverPK` action fact promoted to
  `RegisterPK/3` so PCS lemma can reference receiver's static `rsk`
  without unguarded quantification.

- **MEDIUM — `formal/tamarin/MeowRatchetHeaderOE.spthy` (FIXED, this
  branch).** `SentFrameWithIdx`/`ReceivedFrameWithIdx` promoted to /5 to
  bind the header key `hk` for lemma quantifiers; all four lemmas updated.

- **LOW — `MeowSchrodingerDeniabilityTiming.spthy` `h/1`** — DONE in 6aa5b8e.

- **LOW — `secure_alloc_guard_pages.spthy` `zero/1`** — DONE in 6aa5b8e.

- **CI infra — `formal-verification.yml:634` shard-1 `timeout 1800` +
  `--memory=6g --cpus=2`** — DONE in 6aa5b8e.

## Pre-existing test failures (not caused by audit)

- **`tests/test_cat_js_runner.py::TestCat5SpeedsJS::test_cat_5speeds_pipeline`** — Marked `xfail` in the audit-followup commit. Confirmed pre-existing by `git stash` test on bare main. Root cause: `web_demo/preamble-calibration.js` over-measures preamble duration when the sync word uses the same `1010...` pattern. NRZ decoder then locks onto sync *inside* the preamble, overshoots by 8 bits, and byte[0] comes out as `0xca` (second half of magic `0xfe 0xca`) instead of `0xfe`. Node probe in `/tmp/debug_cat.js` reproduces deterministically. **Recommended fix:** preamble-calibration should stop at the expected 16-bit boundary (using known `bitPeriod`) rather than measuring the extent of alternation.
- **Gate 5 (Security Coverage) — 65.67% vs 85% threshold.** Pre-existing on main. `schrodinger_encode.py` (0%), `memory_guard.py` (23%), `master_ratchet.py` (45%), `pq_hybrid.py` (69%), `manifest_signing.py` (63%), `secure_temp.py` (77%) are all in `.coveragerc-security` include list but insufficiently exercised by `-m "security or crypto or adversarial"` selection. **Recommended fix:** either (a) add `security` marker to existing tests that already exercise these modules, or (b) trim include list to the genuinely covered-by-markers set and ratchet up from there. Not attempted in this audit — would need test-by-test triage.

## Tests to add

*(Populated in Phase 13.)*

## Attempted but reverted fixes

*(Populated when a fix breaks tests and is reverted.)*
