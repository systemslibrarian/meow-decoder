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
| ChatGPT hardening | ⚠️ 5/8 done | DecodeError enum, memory budget, entropy validation exist. **Monte Carlo tests do NOT exist** (prior doc was incorrect). Frame reorder/duplicate tests not found. |
| Formal verification (17/26) | ✅ See todo-formal.md | Lean proofs, ProVerif PQ, TLA+ streaming. 9 blocked/deferred |
| Python test suite | ✅ 87 files, 2413 tests | 1-to-1 module mapping, all passing |
| Rust crypto crate | ✅ 151 tests | Verus proofs, 110 formal verification tests |
| Documentation | ✅ All updated | 12+ MD files cleaned of stale refs, 2026-02-14 |
| Cat Mode Phase 5.5 (security) | ✅ DONE 2026-02-14 | Timing side-channel fixes, diagnostics sanitization |
| Cat Mode Phase 5.3.3 (UX) | ✅ DONE 2026-02-14 | User-friendly error messages with suggestions |

---

## Priority 0: Validate What Exists

Code was written but never executed end-to-end. This is the #1 gap.

### V1. Install JS/browser test dependencies ✅
```bash
npm install canvas @playwright/test
npx playwright install chromium firefox webkit
apk add chromium  # Alpine native fallback
```
- [x] Dependencies installed (canvas, @playwright/test) — 2026-02-14
- [x] `node -e "require('canvas')"` succeeds
- [x] Chromium installed (Alpine native + Playwright)

### V2. Validate golden video pipeline ⚠️ BLOCKED
```bash
npm run generate-golden-videos
```
- [x] 3 golden videos regenerated
- [ ] `npm run test:golden` **BLOCKED**: Headless Chrome on Alpine can't decode VP9 video — all frames extract as black (greenScore=0). Tests will pass in CI (Ubuntu with codecs).
- **Fixed**: `tests/run_golden_test.js` now uses Playwright API (not `--dump-dom`)
- **Fixed**: `examples/preamble-calibration.js` line 362 — missing `allScores` argument to `detectPreambleWithFallback()` caused `.slice() on undefined` crash

### V3. Validate error injection pipeline ⚠️ BLOCKED
- [ ] Same VP9 codec limitation as V2. Will work in Ubuntu CI.

### V4. Validate cross-browser tests ⚠️ BLOCKED
- [ ] Same VP9 codec limitation. Playwright framework validated; video decode blocked on Alpine.

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

**5.3.3: User-Friendly Error Recovery UX (3h)** ✅ DONE 2026-02-14
- [x] Added `getUserFriendlyError()` helper — maps technical errors to friendly titles + suggestions
- [x] 6 error categories: video too short, sync not found, weak signal, data corruption, wrong password, timeout
- [x] Each category has specific actionable suggestions  
- [x] Technical details hidden in collapsible `<details>` section
- [x] Updated both catModeDecode and catVideoAnalyze error handlers
- Files changed: `examples/wasm_browser_example.html`

### Cat Mode Phase 5.5: Security Hardening (5h) ✅ COMPLETE

**5.5.1: Timing Side-Channel Mitigation (3h)** ✅ DONE 2026-02-14
- [x] Audited cat-mode decode for timing leaks — 8 issues found
- [x] Added `constantTimeEqual32()` for session ID comparison
- [x] CRC is now always computed regardless of earlier validation failures
- [x] Error messages coalesced to generic `packet_rejected` (no enumeration)
- [x] Session lock rejection uses constant-time comparison
- [x] NRZ decoder verbose logging gated behind `NRZ_DEBUG` flag
- Files changed: `examples/cat-mode-protocol.js`, `examples/nrz-decoder.js`

**5.5.2: Secure Diagnostics Sanitization (2h)** ✅ DONE 2026-02-14
- [x] Audited `wasm_browser_example.html` for sensitive data in logs/diagnostics
- [x] `checkDuress()` function — marked as legacy (never invoked)
- [x] Stats counters renamed: `packets_crc_pass/fail` → consolidated `packets_accepted/rejected`
- [x] Error types unified: `crc_mismatch`, `session_mismatch`, `invalid_magic` → `packet_rejected`
- [x] `tests/test_cat_protocol.html` updated for new API
- [x] `tests/test_cat_mode_golden.html` assertions fixed
- Files changed: `examples/wasm_browser_example.html`, `tests/test_cat_protocol.html`, `tests/test_cat_mode_golden.html`

---

## Priority 2: Nice to Have

| Item | Est. | Notes |
|------|------|-------|
| Monte Carlo fountain stress test | 3h | **NOT DONE** — todofromchatgpt.md claimed this was done but no test exists. Run 1000 trials at 30%/50% drop, verify ≥99.5% success rate. |
| Frame reorder + duplicate injection tests | 2h | **NOT DONE** — also claimed but not found. Add to test_fountain.py |
| CI threshold gate (fail if fountain success <99.5%) | 1h | Add after Monte Carlo tests exist |
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

