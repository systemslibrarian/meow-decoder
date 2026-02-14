# What Actually Needs to Be Done

**Created:** 2026-02-14
**Replaces:** SPRINT_1_COMPLETE.md, PHASE_5_ROADMAP.md, PHASE_5_WEEK_1_COMPLETE.md, TASK_5.1.2_COMPLETE.md, TASK_5.1.3_COMPLETE.md, todofromchatgpt.md (all deleted — content preserved here or in todocatmode.md)
**Living trackers kept:** todocatmode.md (cat mode detail), todo-formal.md (formal verification)

---

## What's Done (no longer tracked here)

| Area | Status | Evidence |
|------|--------|----------|
| Cat Mode Phases 1-3 (core decode) | ✅ 14/14 tasks | 92% decode, 94% CRC. See todocatmode.md |
| Cat Mode Phase 5.1 (CI hardening) | ✅ Code complete | golden-video-lib.js, error_injection_lib.js, playwright.config.js, all generated videos exist |
| Cat Mode Phase 5.2 (failure mode fixes) | ✅ Code complete | GradientCompensator, adaptive preamble, Gaussian confidence masking all in code |
| ChatGPT hardening (8 items) | ✅ 8/8 done | Monte Carlo tests, DecodeError enum, memory budget, entropy validation |
| Formal verification (17/26) | ✅ See todo-formal.md | Lean proofs, ProVerif PQ, TLA+ streaming. 9 blocked/deferred |
| Python test suite | ✅ 87 files, 2413 tests | 1-to-1 module mapping, all passing |
| Rust crypto crate | ✅ 151 tests | Verus proofs, 110 formal verification tests |
| Documentation | ✅ All updated | 12+ MD files cleaned of stale refs, 2026-02-14 |

---

## Priority 0: Validate What Exists

Code was written but never executed end-to-end. This is the #1 gap.

### V1. Install JS/browser test dependencies
```bash
npm install canvas @playwright/test
npx playwright install chromium firefox webkit
```
- [ ] Dependencies install cleanly in dev container
- [ ] `node -e "require('canvas')"` succeeds

### V2. Validate golden video pipeline
```bash
npm run generate-golden-videos
```
- [ ] 3 golden videos regenerated with matching checksums
- [ ] `npm run test:golden` passes

### V3. Validate error injection pipeline
```bash
npm run generate-error-tests
npm run test:errors
```
- [ ] 18 error-injected videos generated
- [ ] Error test suite passes (18/18)
- [ ] Error messages are user-friendly (not just "failed")

### V4. Validate cross-browser tests
```bash
npm run test:browsers
```
- [ ] 14 tests × 8 browser configs = 112 test cases
- [ ] Chromium, Firefox, WebKit all pass
- [ ] Mobile configs pass (or fail gracefully with clear reason)

### V5. Validate CI gates actually run
- [ ] Push a branch and confirm `ci.yml` gates 2a, 3a, 3b execute
- [ ] Golden video checksum verification works in CI
- [ ] Error injection tests run in CI
- [ ] Cross-browser tests run in CI

---

## Priority 1: Unstarted Work (~16h total)

### Cat Mode Phase 5.3: Performance & UX Polish (11h)

**5.3.1: Decode Time Optimization (4h)**
- [ ] Profile WASM decode path, identify bottlenecks
- [ ] Implement Web Worker for background decoding
- [ ] Target: <2s decode for typical payload
- Files: `examples/wasm_browser_example.html`

**5.3.2: Mobile PWA Integration (4h)**
- [ ] Add `manifest.json` for installable PWA
- [ ] Add service worker for offline capability
- [ ] Test on iOS Safari + Chrome Android
- [ ] Camera permission handling for mobile
- Files: `examples/sw.js` (exists), `examples/wasm_browser_example.html`

**5.3.3: User-Friendly Error Recovery UX (3h)**
- [ ] Replace technical errors with actionable guidance
- [ ] Add retry suggestions ("Move closer", "Better lighting", "Hold steady")
- [ ] Progress indicator during decode
- [ ] Timeout with helpful message (not silent hang)
- Files: `examples/wasm_browser_example.html`

### Cat Mode Phase 5.5: Security Hardening (5h)

**5.5.1: Timing Side-Channel Mitigation (3h)**
- [ ] Audit cat-mode decode for timing leaks
- [ ] Constant-time comparison for session IDs and CRC
- [ ] No early-exit on partial match
- Files: `examples/cat-mode-protocol.js`, `examples/nrz-decoder.js`

**5.5.2: Secure Diagnostics Sanitization (2h)**
- [ ] Strip sensitive data from diagnostics JSON export
- [ ] No plaintext, keys, or passwords in logs
- [ ] Sanitize before any export/download
- Files: `examples/wasm_browser_example.html`

---

## Priority 2: Nice to Have

| Item | Est. | Notes |
|------|------|-------|
| CI threshold gate (fail if fountain success <99.5%) | 1h | From todofromchatgpt.md. One-liner in ci.yml |
| Cut v1.1.0 release | 2h | Significant unreleased work. Tag when P0+P1 done |
| Auto ROI detection (face/eye tracking) | 4h | todocatmode Task 2.3, marked Optional |
| Multi-speed adaptive encoding | 4h | todocatmode Task 4.1, data-driven |

---

## Priority 3: Deferred (don't start unless bored)

| Item | Notes |
|------|-------|
| Reed-Solomon FEC | Marked "LIKELY UNNECESSARY" — fountain codes handle loss |
| Multi-resolution encoding | No evidence of need |
| FFT-based bit rate detection | Research item |
| Differential encoding | No evidence of need |
| Rust-native frame parser | Only if WASM decoder moves to Rust |
| BLAKE3 feature flag | Marginal over HMAC-SHA256 |
| Reproducible build diff verification | Pedantic |

---

## Formal Verification (tracked separately)

See [todo-formal.md](todo-formal.md) for the complete formal verification tracker.

**TL;DR:** 17/26 items done. 9 blocked/deferred:
- 2 Tamarin tasks blocked on Maude (Docker targets exist: `make formal-tamarin-docker`)
- 2 Verus tasks blocked on musl (Docker targets exist: `make formal-verus-docker`)
- 5 deferred (stego model, session resume, side-channel CT-Verif, upstream libs, Python verification)

---

## Files Deleted in This Cleanup

| File | Lines | Why |
|------|-------|-----|
| SPRINT_1_COMPLETE.md | 312 | Historical — Sprint 1 done, all info in todocatmode.md |
| PHASE_5_ROADMAP.md | 878 | Stale — every task said "Not Started" despite work being done |
| PHASE_5_WEEK_1_COMPLETE.md | 392 | Completion report — content captured above and in todocatmode.md |
| TASK_5.1.2_COMPLETE.md | 275 | Completion report for error injection — content in todocatmode.md |
| TASK_5.1.3_COMPLETE.md | 496 | Completion report for cross-browser — content in todocatmode.md |
| todofromchatgpt.md | 282 | 8/8 items done — 5 remaining low-priority items captured in P2/P3 above |
