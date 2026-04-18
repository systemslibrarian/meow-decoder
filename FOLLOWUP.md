# Meow Decoder — Follow-up items (post-audit)

Items logged here require human decision or deeper work before fixing.
Populated during audit phases; see `AUDIT-2026-04-18.md` for the full audit record.

## Architectural decisions needed

*(Populated when a phase identifies an issue requiring protocol/API redesign.)*

## Medium-severity items deferred

- **Finding 7.1 — rsa crate Marvin Attack via yubikey 0.8.** `crypto_core/src/yubikey_piv.rs:386-407` exposes `decrypt()` which can dispatch to RSA via PIV. Currently unused by production pipelines (only ECDH is exercised), and project-level acceptance is documented in `osv-scanner.toml:14` / `.github/workflows/security-ci.yml:171`. **Recommended fix:** add an explicit algorithm guard inside `YubiKey::decrypt()` that returns `YubiKeyError::NotSupported` for `AlgorithmId::Rsa*`, or remove the function until needed. Blocks future misuse without waiting for yubikey upstream fix.
- **Finding 7.3 — npm audit root devDependencies (4 HIGH / 1 MODERATE).** Transitive via jest/playwright/selenium/canvas. ReDoS + path-traversal. Not in shipped artifacts. **Recommended fix:** `npm audit fix --force` then re-run `npm test` on both root and web_demo.
- **Finding 11.2 — `download_tokens` global dict not explicitly locked.** `web_demo/app.py:57-92`. Concurrent cleanup + insert under threaded Flask may produce token-routing collisions. **Recommended fix:** wrap all mutations in `threading.Lock()` or use `cachetools.TTLCache`.
- **Finding 12.6 — `cargo build --features tpm` fails on main.** `crypto_core/src/tpm.rs:525,540` — `SensitiveData::as_bytes` and `KeyHandle→ObjectHandle` type errors against current `tss-esapi 7.5` API. **Recommended fix:** rename `as_bytes()` calls to `bytes()`; add `.into()` to convert `KeyHandle` to `ObjectHandle` at the unseal call site. Unrelated to audit-phase-6 PcrSlot fix.

## Low-severity items deferred

- **Finding 1.6 — README "Does Protect Against ... Quantum computers" overstates.** PQ is experimental and requires `--pq` flag. Add qualifier in README line 531 or track in Phase 14.
- **Finding 4.5 — `random.choice` in `meow_decoder/high_security.py:446-447`.** Unused function `generate_innocuous_filename`. If ever exposed, switch to `secrets.choice`.
- **Finding 6.1 — Decrypt error message embeds `{e}`** at `meow_decoder/crypto.py:1485,1492`. Minor content-channel; Argon2id runs first so timing is closed. Sanitize to constant string while keeping the PQ-downgrade branch as a distinct message.
- **Finding 6.2 — `TpmContext::connect_tcti` panics on invalid TCTI parse** at `crypto_core/src/tpm.rs:328`. Internal callers pass hardcoded values, but `pub fn` exposes panic to external Rust users. Replace with `.map_err(|e| TpmError::CommunicationFailed(e.to_string()))?`.
- **Finding 6.6 — `Auth::from_bytes(&a.auth).unwrap()`** at `crypto_core/src/tpm.rs:417`. Auth blob is caller-controlled; panic on out-of-range length. Replace with `TpmError::InvalidAuth`.
- **Finding 7.2 — pip 24.0 + wheel 0.45.1 CVEs.** Build-time only. Bump dev env to pip≥25 / wheel≥0.46.
- **Finding 7.4 — npm audit web_demo devDependencies (1 HIGH / 1 MODERATE).** Jest transitive. Bump alongside root npm update.
- **Finding 3.1 — `save_receiver_keypair` leaks exported key bytes.** `meow_decoder/x25519_forward_secrecy.py:336-367`. `isinstance(bytes, (bytearray, memoryview))` is false, so the `finally`-block zero-loop never runs. Fix: `private_key_bytes = bytearray(hb.export_key(private_key))`.
- **Finding 3.2 — `HybridKeyPair` / `PQBeaconKeyPair` no `__del__`.** `meow_decoder/pq_hybrid.py:131`, `meow_decoder/pq_ratchet_beacon.py:176`. Python memory zeroization is best-effort. Add explicit `__del__` or replace raw bytes with a zeroizing wrapper.
- **Finding 3.4 — Ed25519 fallback path is not production-gated.** `meow_decoder/manifest_signing.py:196-208`. Raise `RuntimeError` if `_RUST_ED25519_AVAILABLE is False and MEOW_PRODUCTION_MODE=1`.
- **Finding 3.7 — Keyfile HKDF intermediate lives in Python.** `meow_decoder/crypto.py:471-481`. Prefer the handle-based `derive_key_argon2id_with_keyfile` path.
- **Finding 9.1 — Fountain encoder lacks per-call `total_size` assertion.** `meow_decoder/fountain.py:141`. Belt-and-suspenders assertion.
- **Finding 10.3 — GIF frame-count limit.** `meow_decoder/gif_handler.py` — add `MAX_GIF_FRAMES=100_000` guard for defence-in-depth against crafted GIFs.
- **Finding 11.1 — Backend singleton init not explicitly locked.** `meow_decoder/crypto_backend.py:301,668`. Add `threading.Lock`.
- **Finding 12.1 — Release profile does not strip debug symbols.** `crypto_core/Cargo.toml:268-273`. Add `strip = "symbols"` — doesn't leak secrets, but reveals function/type names to reverse engineers.
- **Finding 12.2 — Pre-commit lacks secret-scanning.** `.pre-commit-config.yaml`. Add `detect-secrets` / `trufflehog` / `gitleaks` hook.
- **Finding 14.1 — README:531 "Quantum computers" without `--pq` qualifier.** Add "(with `--pq` or `--paranoid` flag)" or promote MEOW5 to true default once ml-kem reaches stable 1.0.
- **Finding 13 coverage gaps.** Add `MEOW_PRODUCTION_MODE=0` to `tests/TEST_SUITE_README.md`; cover `# pragma: no cover` decompression-bomb branches.

## Low-severity items deferred

*(Populated as Phase 2–14 complete.)*

## Pre-existing test failures (not caused by audit)

- **`tests/test_cat_js_runner.py::TestCat5SpeedsJS::test_cat_5speeds_pipeline`** — Baseline failure confirmed by `git stash` test on main before any audit changes. JS-side signal pipeline produces 118 bytes when 104 expected, first byte mismatch `0xca` vs `0x3`. Root cause is in `test_cat_5speeds.js` or upstream JS encoder/decoder. Not blocked by audit work. Recommended owner: whoever last touched `ac7d026` ("simplify preamble to 16-bit").

## Tests to add

*(Populated in Phase 13.)*

## Attempted but reverted fixes

*(Populated when a fix breaks tests and is reverted.)*
