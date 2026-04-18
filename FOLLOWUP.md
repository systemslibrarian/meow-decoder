# Meow Decoder — Follow-up items (post-audit)

Items logged here require human decision or deeper work before fixing.
Populated during audit phases; see `AUDIT-2026-04-18.md` for the full audit record.

## Architectural decisions needed

*(Populated when a phase identifies an issue requiring protocol/API redesign.)*

## Medium-severity items deferred

- **Finding 7.1 — rsa crate Marvin Attack via yubikey 0.8.** `crypto_core/src/yubikey_piv.rs:386-407` exposes `decrypt()` which can dispatch to RSA via PIV. Currently unused by production pipelines (only ECDH is exercised), and project-level acceptance is documented in `osv-scanner.toml:14` / `.github/workflows/security-ci.yml:171`. **Recommended fix:** add an explicit algorithm guard inside `YubiKey::decrypt()` that returns `YubiKeyError::NotSupported` for `AlgorithmId::Rsa*`, or remove the function until needed. Blocks future misuse without waiting for yubikey upstream fix.
- **Finding 7.3 — npm audit root devDependencies (4 HIGH / 1 MODERATE).** Transitive via jest/playwright/selenium/canvas. ReDoS + path-traversal. Not in shipped artifacts. **Recommended fix:** `npm audit fix --force` then re-run `npm test` on both root and web_demo.

## Low-severity items deferred

- **Finding 1.6 — README "Does Protect Against ... Quantum computers" overstates.** PQ is experimental and requires `--pq` flag. Add qualifier in README line 531 or track in Phase 14.
- **Finding 4.5 — `random.choice` in `meow_decoder/high_security.py:446-447`.** Unused function `generate_innocuous_filename`. If ever exposed, switch to `secrets.choice`.
- **Finding 6.1 — Decrypt error message embeds `{e}`** at `meow_decoder/crypto.py:1485,1492`. Minor content-channel; Argon2id runs first so timing is closed. Sanitize to constant string while keeping the PQ-downgrade branch as a distinct message.
- **Finding 6.2 — `TpmContext::connect_tcti` panics on invalid TCTI parse** at `crypto_core/src/tpm.rs:328`. Internal callers pass hardcoded values, but `pub fn` exposes panic to external Rust users. Replace with `.map_err(|e| TpmError::CommunicationFailed(e.to_string()))?`.
- **Finding 6.6 — `Auth::from_bytes(&a.auth).unwrap()`** at `crypto_core/src/tpm.rs:417`. Auth blob is caller-controlled; panic on out-of-range length. Replace with `TpmError::InvalidAuth`.
- **Finding 7.2 — pip 24.0 + wheel 0.45.1 CVEs.** Build-time only. Bump dev env to pip≥25 / wheel≥0.46.
- **Finding 7.4 — npm audit web_demo devDependencies (1 HIGH / 1 MODERATE).** Jest transitive. Bump alongside root npm update.

## Low-severity items deferred

*(Populated as Phase 2–14 complete.)*

## Tests to add

*(Populated in Phase 13.)*

## Attempted but reverted fixes

*(Populated when a fix breaks tests and is reverted.)*
