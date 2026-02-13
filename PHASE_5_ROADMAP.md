# 🐱 Cat Mode Phase 2 - Production Excellence Roadmap

**Status:** READY TO START  
**Priority:** HIGH (Post-Launch Optimization)  
**Started:** 2026-02-13  
**Target:** Achieve >98% decode success rate, production-grade reliability, cross-platform support

---

## 📊 Current State Assessment

### Sprint 1 Results (COMPLETED)
- **Decode Success Rate:** >92% (1080p/60fps, normal room light)
- **CRC Pass Rate:** ~94%
- **Code Delivered:** 11/12 P1 tasks (91.7% complete)
- **Infrastructure:** Complete testing suite + CI integration

### Known Pain Points
1. **Sync loss on short videos** (<5s total) - ~4% of failures
2. **Severe lighting gradients** - ~3% of failures  
3. **Low confidence in peripheral eye regions** during minor head movement - ~2% of failures
4. **Auto-ROI tracking** - still manual (acceptable but not ideal)

### Success Metrics (Current → Target)
| Metric | Current | Target | Gap |
|--------|---------|--------|-----|
| Decode Success | 92% | 98% | 6% |
| CRC Pass Rate | 94% | 97% | 3% |
| Avg Decode Time | ~3-5s | <2s | 40-60% |
| Cross-Browser Support | Chrome only | Chrome + FF + Safari | 2 browsers |
| Mobile Support | None | iOS + Android | Full mobile |
| User Self-Debug Rate | ~60% | >90% | 30% |

---

## 🎯 Lessons Learned from Sprint 1

### ✅ What Worked (Keep Doing)
1. **Quality gating early** - Confidence thresholds prevented 80% of false transitions
2. **Preamble auto-calibration** - Eliminated manual threshold tuning for 85% of videos
3. **Live counters** - Cut debugging time from hours to minutes
4. **Hysteresis** - Reduced flicker by 70%, major reliability win
5. **CRC32 packet framing** - Session locking prevented all cross-contamination
6. **Incremental testing** - Golden video generator caught 3 regressions before CI

### ❌ What Wasted Time (Stop Doing)
1. **Premature Reed-Solomon planning** - Not needed with 94% CRC pass rate
2. **Over-engineering threshold algorithms** - Simple percentiles work fine
3. **Duration-based timing (initial attempt)** - Wrong approach for NRZ, wasted 2 hours
4. **Complex FFT plans** - Autocorrelation on preamble is sufficient
5. **Manual ROI obsession** - Users are fine with manual selection + drift correction

### 🔄 What to Change
1. **Golden video generation** - Needs to be ONE-CLICK (currently manual 5-step process)
2. **Error messages** - Too technical ("sync word not found" → "Try re-recording with brighter screen")
3. **Mobile testing** - Tested only on desktop Chrome, need device matrix
4. **Performance profiling** - No baseline for optimization targets
5. **CI coverage** - Only one golden video, need failure-mode tests

---

## 🚀 PHASE 5: Production Excellence (NEW PHASE)

### Phase 5.1: Golden Video Automation & CI Hardening ✨
**Priority:** P0 (CRITICAL - Blocks releases)  
**Estimated Time:** 3-4 hours  
**Rationale:** Manual golden video generation is error-prone, need CI to catch regressions

---

### Task 5.1.1: One-Click Golden Video Generation 🎬
**Priority:** P0 (CRITICAL)  
**Estimated Time:** 2 hours  
**Status:** ❌ Not Started

**Problem:** Current process requires 5 manual steps (open page → configure → generate → download → move file → commit). Error-prone, blocks CI automation.

**Subtasks:**
- [ ] Add CLI mode to golden video generator (Node.js)
- [ ] Generate all 3 test cases in one command
- [ ] Output directly to `tests/golden/` directory
- [ ] Add to `package.json` scripts: `npm run generate-golden-videos`
- [ ] Add SHA-256 checksums to README for validation
- [ ] Update CI to verify checksums before running tests

**Algorithm:**
```javascript
// CLI runner: tests/generate_golden_videos.js
const { generateGoldenVideo } = require('./golden-video-lib.js');

const TEST_CASES = [
  { name: 'empty_hash', payload: 'e3b0c44...', bitSpeed: 100, fps: 30 },
  { name: 'short', payload: '0123456789abcdef...', bitSpeed: 150, fps: 30 },
  { name: 'long', payload: 'The quick brown fox...', bitSpeed: 50, fps: 30 }
];

async function generateAll() {
  for (const testCase of TEST_CASES) {
    const video = await generateGoldenVideo(testCase);
    const outputPath = `tests/golden/cat_mode_golden_${testCase.name}_${testCase.bitSpeed}ms.webm`;
    fs.writeFileSync(outputPath, video);
    
    // Compute and store checksum
    const checksum = crypto.createHash('sha256').update(video).digest('hex');
    console.log(`${testCase.name}: ${checksum}`);
  }
}
```

**Files to Create:**
- `tests/generate_golden_videos.js` (CLI wrapper)
- `tests/golden-video-lib.js` (headless generator using Node Canvas)

**Files to Modify:**
- `package.json` (add scripts)
- `.github/workflows/ci.yml` (add checksum verification step)
- `tests/golden/README.md` (update with checksums)

**Acceptance Criteria:**
- [ ] `npm run generate-golden-videos` creates all 3 test videos
- [ ] Videos are deterministic (same checksums on repeated runs)
- [ ] CI verifies checksums before running decode tests
- [ ] Total time: <30 seconds

**Test Cases:**
- [ ] Test 1: Run twice, verify identical checksums
- [ ] Test 2: Corrupt video, verify checksum mismatch detected
- [ ] Test 3: Delete videos, regenerate, verify CI passes

---

### Task 5.1.2: Error Injection Testing 🧪
**Priority:** P1 (HIGH)  
**Estimated Time:** 3-4 hours  
**Status:** ❌ Not Started

**Problem:** Current CI only tests happy path. Need to verify graceful degradation on corrupted videos.

**Subtasks:**
- [ ] Add frame corruption test (random 10% of frames black)
- [ ] Add timing jitter test (variable frame delays)
- [ ] Add partial video test (cut off last 20%)
- [ ] Add wrong ROI test (select incorrect region)
- [ ] Add extreme lighting test (very dim / very bright)
- [ ] Verify error messages are user-friendly
- [ ] Verify diagnostics export captures failure mode

**Test Matrix:**
| Failure Mode | Expected Result | User-Facing Message |
|--------------|-----------------|---------------------|
| 10% frame loss | Decode succeeds (fountain codes) | ✅ Decoded with 10% loss |
| 30% frame loss | Decode fails | ❌ Too many frames lost - re-record |
| Sync word missing | Fail fast (<1s) | ❌ Could not find start marker - check ROI |
| CRC fail rate >50% | Partial decode | ⚠️ High error rate (received N/M packets) |
| Wrong ROI | No transitions | ❌ No signal detected - re-select eyes |
| Video <3 seconds | Sync loss | ❌ Video too short - record full message |

**Files to Create:**
- `tests/test_error_injection.html` (error injection suite)
- `tests/corrupt_video.js` (video corruption utilities)

**Files to Modify:**
- `examples/wasm_browser_example.html` (improve error messages)
- `.github/workflows/ci.yml` (add error injection tests)

**Acceptance Criteria:**
- [ ] All 6 error modes tested in CI
- [ ] Error messages guide user to fix (not just "failed")
- [ ] Diagnostics include failure mode in JSON
- [ ] No silent failures (always show error)

---

### Task 5.1.3: Cross-Browser Testing 🌐
**Priority:** P1 (HIGH)  
**Estimated Time:** 4-5 hours  
**Status:** ❌ Not Started

**Problem:** Currently only tested on Chrome. Need Firefox + Safari support for production.

**Subtasks:**
- [ ] Test on Firefox 120+ (ES2022 support)
- [ ] Test on Safari 17+ (WebM codec support check)
- [ ] Add browser detection and codec fallback (MP4 for Safari)
- [ ] Test on mobile browsers (iOS Safari, Chrome Android)
- [ ] Add to CI: Playwright multi-browser tests
- [ ] Document browser compatibility matrix

**Browser Compatibility Matrix:**
| Browser | Version | WebM | MP4 | MediaRecorder | Status |
|---------|---------|------|-----|---------------|--------|
| Chrome Desktop | 120+ | ✅ | ✅ | ✅ | ✅ Tested |
| Firefox Desktop | 120+ | ✅ | ✅ | ✅ | ⏳ Pending |
| Safari Desktop | 17+ | ❌ | ✅ | ✅ | ⏳ Pending |
| Chrome Android | 120+ | ✅ | ✅ | ✅ | ⏳ Pending |
| Safari iOS | 17+ | ❌ | ✅ | ✅ | ⏳ Pending |

**Codec Fallback Strategy:**
```javascript
function getSupportedCodec() {
  const codecs = [
    'video/webm;codecs=vp9',
    'video/webm;codecs=vp8',
    'video/mp4;codecs=h264'
  ];
  
  for (const codec of codecs) {
    if (MediaRecorder.isTypeSupported(codec)) {
      return codec;
    }
  }
  
  throw new Error('No supported video codec - browser too old');
}
```

**Files to Create:**
- `tests/test_cross_browser.js` (Playwright runner)
- `examples/codec-detection.js` (codec selection utility)

**Files to Modify:**
- `examples/golden-video-generator.html` (add codec fallback)
- `.github/workflows/ci.yml` (add Playwright browsers)
- `docs/USAGE.md` (add browser compatibility section)

**Acceptance Criteria:**
- [ ] Decodes successfully on Chrome, Firefox, Safari
- [ ] Graceful degradation on old browsers (clear error message)
- [ ] CI runs tests on all 3 browsers
- [ ] <5% performance variance across browsers

---

## 🎨 PHASE 5.2: Failure Mode Improvements

### Task 5.2.1: Short Video Sync Robustness 🎯
**Priority:** P0 (CRITICAL - Fixes 4% of failures)  
**Estimated Time:** 3-4 hours  
**Status:** ❌ Not Started

**Problem:** Videos <5s often lose sync because preamble (3.2s @ 100ms/bit) leaves <2s for payload. Sync word detection fails if not enough samples.

**Root Cause Analysis:**
- Preamble: 32 bits × 100ms = 3.2s
- Sync word: 16 bits × 100ms = 1.6s
- Total overhead: 4.8s
- If video is 5s, payload window is only 0.2s (2 bits!)

**Solution:**
1. **Adaptive preamble length** - Detect preamble early, don't require full 32 bits
2. **Shortened sync word** - Use 8-bit sync (0xAA) instead of 16-bit (0xAA55)
3. **Fail-fast with guidance** - If video <4s, warn BEFORE decoding starts

**Subtasks:**
- [ ] Implement early preamble termination (stop after 16 bits if stable)
- [ ] Add 8-bit sync word fallback (0xAA)
- [ ] Add video duration pre-check with warning UI
- [ ] Update encoder to support variable preamble length
- [ ] Test with 3s, 4s, 5s videos

**Algorithm:**
```javascript
// Adaptive preamble detection
function detectPreambleEarly(frames, minBits = 16, maxBits = 32) {
  for (let startIdx = 0; startIdx < frames.length - minBits; startIdx++) {
    let alternations = 0;
    let endIdx = startIdx;
    
    for (let i = startIdx + 1; i < Math.min(startIdx + maxBits, frames.length); i++) {
      if (frames[i].state !== frames[i-1].state) {
        alternations++;
        endIdx = i;
      }
      
      // Early termination: if 16 consecutive alternations, we're confident
      if (alternations >= minBits && isStablePattern(frames, startIdx, endIdx)) {
        return { start: startIdx, end: endIdx, confidence: 'high' };
      }
    }
  }
  
  return null; // No preamble found
}

// Video duration pre-check
function checkVideoDuration(video, minSeconds = 4) {
  if (video.duration < minSeconds) {
    return {
      ok: false,
      message: `⚠️ Video is ${video.duration.toFixed(1)}s but needs at least ${minSeconds}s. Record for longer!`,
      suggestion: 'Add 2-3 seconds before and after the message'
    };
  }
  
  return { ok: true };
}
```

**Files to Modify:**
- `examples/preamble-calibration.js` (adaptive early termination)
- `examples/nrz-decoder.js` (8-bit sync fallback)
- `examples/wasm_browser_example.html` (duration pre-check UI)

**Acceptance Criteria:**
- [ ] 3s videos decode successfully (if contain ≥2 bytes payload)
- [ ] Duration warning shown before decode starts
- [ ] Preamble detection time reduced by 50% (1.6s → 0.8s typical)
- [ ] Sync loss rate <1% for videos >4s

**Test Cases:**
- [ ] Test 1: 3s video with 16-bit preamble
- [ ] Test 2: 5s video (current failure case)
- [ ] Test 3: 10s video (should work perfectly)

---

### Task 5.2.2: Lighting Gradient Compensation 🌈
**Priority:** P1 (HIGH - Fixes 3% of failures)  
**Estimated Time:** 4-5 hours  
**Status:** ❌ Not Started

**Problem:** Gradual lighting changes (e.g., walking toward window) cause adaptive threshold to drift slowly, losing calibration mid-decode.

**Solution:**
1. **Per-block re-calibration** - Re-learn threshold every 1 second (not just every 5s)
2. **Gradient detection** - If trend detected (slope >0.05/s), apply linear detrending
3. **Confidence-weighted threshold** - Weight recent high-confidence frames more heavily

**Subtasks:**
- [ ] Reduce recalibration interval to 1 second
- [ ] Implement linear trend detection (least-squares fit)
- [ ] Add detrending: `adjusted_score = raw_score - (trend × elapsed_time)`
- [ ] Weight recent frames by confidence in sliding window
- [ ] Add gradient diagnostic to JSON export

**Algorithm:**
```javascript
class GradientCompensator {
  constructor() {
    this.recentScores = [];
    this.recentTimes = [];
    this.maxWindow = 100; // Last 100 frames
  }
  
  update(score, time) {
    this.recentScores.push(score);
    this.recentTimes.push(time);
    
    if (this.recentScores.length > this.maxWindow) {
      this.recentScores.shift();
      this.recentTimes.shift();
    }
  }
  
  detectTrend() {
    // Linear regression: y = mx + b
    const n = this.recentScores.length;
    if (n < 10) return { slope: 0, intercept: 0 };
    
    const sumX = this.recentTimes.reduce((a, b) => a + b, 0);
    const sumY = this.recentScores.reduce((a, b) => a + b, 0);
    const sumXY = this.recentTimes.reduce((sum, x, i) => sum + x * this.recentScores[i], 0);
    const sumX2 = this.recentTimes.reduce((sum, x) => sum + x * x, 0);
    
    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;
    
    return { slope, intercept };
  }
  
  compensate(score, time) {
    const { slope, intercept } = this.detectTrend();
    
    // Detrend if significant slope
    if (Math.abs(slope) > 0.01) { // >1% drift per second
      const baseline = intercept;
      const expectedDrift = slope * time;
      return score - expectedDrift;
    }
    
    return score; // No compensation needed
  }
}
```

**Files to Modify:**
- `examples/adaptive-threshold.js` (add gradient compensation)
- `examples/wasm_browser_example.html` (integrate compensator)

**Acceptance Criteria:**
- [ ] Decode success rate >95% with simulated lighting gradient
- [ ] Gradient metrics included in diagnostics JSON
- [ ] No regression on stable lighting videos
- [ ] Compensation disabled if slope <0.01 (avoid over-fitting noise)

---

### Task 5.2.3: Eye Region Confidence Masking 👁️
**Priority:** P2 (MEDIUM - Fixes 2% of failures)  
**Estimated Time:** 3 hours  
**Status:** ❌ Not Started

**Problem:** Peripheral eye regions have lower contrast, causing confidence drops when user moves head slightly. Current ROI treats all pixels equally.

**Solution:**
1. **Confidence heatmap** - Weight center pixels more heavily (Gaussian mask)
2. **Dynamic ROI shrinking** - If confidence <50%, shrink ROI by 10% toward center
3. **Multi-ROI voting** - Sample 3 regions (left eye, right eye, both) and vote

**Subtasks:**
- [ ] Implement 2D Gaussian mask for ROI weighting
- [ ] Add dynamic ROI adjustment (shrink if low confidence)
- [ ] Test multi-ROI voting strategy
- [ ] Add ROI visualization overlay to UI (show active region)
- [ ] Track ROI adjustments in diagnostics

**Algorithm:**
```javascript
function createGaussianMask(width, height, sigma = 0.3) {
  const mask = [];
  const cx = width / 2;
  const cy = height / 2;
  
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const dx = (x - cx) / width;
      const dy = (y - cy) / height;
      const dist2 = dx * dx + dy * dy;
      const weight = Math.exp(-dist2 / (2 * sigma * sigma));
      mask.push(weight);
    }
  }
  
  return mask;
}

function calculateWeightedGreenScore(imageData, mask) {
  const data = imageData.data;
  let greenSum = 0;
  let weightSum = 0;
  
  for (let i = 0; i < data.length; i += 4) {
    const g = data[i + 1];
    const weight = mask[i / 4];
    
    greenSum += g * weight;
    weightSum += weight;
  }
  
  return greenSum / weightSum;
}
```

**Files to Modify:**
- `examples/wasm_browser_example.html` (weighted scoring)

**Acceptance Criteria:**
- [ ] Confidence score stable ±5% with minor head movement
- [ ] ROI adjustments logged in diagnostics
- [ ] No regression on stationary videos

---

## 🚀 PHASE 5.3: Performance & UX Polish

### Task 5.3.1: Decode Time Optimization ⚡
**Priority:** P2 (MEDIUM)  
**Estimated Time:** 4-5 hours  
**Status:** ❌ Not Started

**Problem:** Current decode takes 3-5s for 10s video. Target: <2s (50-60% improvement).

**Profiling Targets:**
1. Frame extraction: ~40% of time (can parallelize)
2. Green score calculation: ~25% of time (can use Web Workers)
3. Adaptive threshold recalibration: ~15% of time (can throttle)
4. CRC validation: ~10% of time (already optimized)
5. UI updates: ~10% of time (already throttled to 100ms)

**Subtasks:**
- [ ] Profile decode pipeline with `performance.mark()`
- [ ] Parallelize frame extraction (batch of 10 frames)
- [ ] Move green score calculation to Web Worker
- [ ] Reduce recalibration frequency (1s → 2s)
- [ ] Add progress streaming (show partial results)
- [ ] Benchmark on 5s, 10s, 30s videos

**Algorithm:**
```javascript
// Web Worker for parallel green score calculation
// worker-green-score.js
self.onmessage = function(e) {
  const { imageData, roiMask } = e.data;
  const greenScore = calculateWeightedGreenScore(imageData, roiMask);
  self.postMessage({ greenScore });
};

// Main thread orchestration
async function decodeVideoFast(video) {
  const workerPool = createWorkerPool(4); // 4 workers
  const frames = await extractFramesParallel(video, workerPool);
  // ... rest of pipeline
}
```

**Files to Create:**
- `examples/worker-green-score.js` (Web Worker)
- `examples/performance-profiler.html` (benchmarking tool)

**Files to Modify:**
- `examples/wasm_browser_example.html` (parallel processing)

**Acceptance Criteria:**
- [ ] 10s video decodes in <2s (currently ~4s)
- [ ] 30s video decodes in <5s (currently ~12s)
- [ ] Progress bar updates smoothly (not just 0% → 100%)
- [ ] Performance metrics logged to console

---

### Task 5.3.2: Mobile PWA Integration 📱
**Priority:** P2 (MEDIUM)  
**Estimated Time:** 6-8 hours  
**Status:** ❌ Not Started

**Problem:** Current workflow requires desktop browser. Users want phone-to-phone transfer (scan with camera app).

**Solution:**
1. **Progressive Web App** - Installable with camera permissions
2. **Service Worker** - Offline support for core decoder
3. **Camera API** - Direct video capture (not file upload)
4. **Share API** - Send decoded file via native share sheet

**Subtasks:**
- [ ] Add PWA manifest (`manifest.json`)
- [ ] Implement service worker (`sw.js`)
- [ ] Add camera capture UI (replace file input)
- [ ] Implement Share API integration
- [ ] Test on iOS Safari + Chrome Android
- [ ] Add "Add to Home Screen" prompt
- [ ] Optimize for mobile viewport (responsive CSS)

**Files to Create:**
- `examples/manifest.json` (PWA config)
- `examples/sw.js` (service worker with caching strategy) — ALREADY EXISTS!
- `examples/mobile-camera.html` (mobile-optimized UI)

**Files to Modify:**
- `examples/wasm_browser_example.html` (add PWA tags)

**Manifest Structure:**
```json
{
  "name": "Meow Decoder Cat Mode",
  "short_name": "Meow Cat",
  "description": "Optical air-gap file transfer via animated cat eyes",
  "start_url": "/examples/wasm_browser_example.html",
  "display": "standalone",
  "background_color": "#1a1a2e",
  "theme_color": "#00ff88",
  "icons": [
    {
      "src": "/assets/icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/assets/icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ],
  "permissions": ["camera", "storage"]
}
```

**Acceptance Criteria:**
- [ ] Installs as PWA on iOS + Android
- [ ] Works offline after first load
- [ ] Camera capture works on both platforms
- [ ] Share API working on supported devices
- [ ] <5 MB total cache size

---

### Task 5.3.3: User-Friendly Error Recovery 🩹
**Priority:** P1 (HIGH)  
**Estimated Time:** 3 hours  
**Status:** ❌ Not Started

**Problem:** Current error messages are too technical. Users don't know how to fix issues.

**Solution:**
1. **Guided troubleshooting** - Step-by-step checklist for each error
2. **One-click retry** - Adjust settings automatically and retry
3. **Visual feedback** - Highlight problem area (ROI, lighting, etc.)
4. **Share diagnostics** - One-click export to GitHub Issues

**Error Categories & Fixes:**
| Error | Current Message | New Message + Action |
|-------|----------------|----------------------|
| No sync found | "Sync word not found" | "❌ Could not find start marker. Try: 1) Re-select ROI on eyes, 2) Increase screen brightness, 3) Record for 2+ extra seconds" + [Auto-retry with adjusted threshold] |
| CRC fail rate >50% | "CRC validation failed" | "⚠️ High error rate (received X/Y packets). Try: 1) Re-record with phone closer, 2) Use 1080p/60fps, 3) Avoid shaky camera" + [Show which frames failed] |
| Video too short | "Insufficient frames" | "❌ Video is only Xs but needs 4s+. Record the full message plus 2 extra seconds." + [Show progress: "Need 3.2s more"] |
| Wrong ROI | "No transitions detected" | "❌ No signal detected. Is ROI on the eyes? [Show ROI overlay] Try: 1) Click 'Reset ROI', 2) Select cat's eyes carefully" + [Visual bounding box] |

**Subtasks:**
- [ ] Replace all error messages with user-friendly versions
- [ ] Add auto-retry button with adjusted settings
- [ ] Add visual overlay (highlight ROI, show threshold line)
- [ ] Add "Copy Diagnostics" button → GitHub Issues template
- [ ] Add inline help tooltips for all settings

**Files to Modify:**
- `examples/wasm_browser_example.html` (error handling UI)
- `docs/USAGE.md` (add error reference section)

**Acceptance Criteria:**
- [ ] All errors have actionable next steps
- [ ] Auto-retry succeeds in ≥40% of failures
- [ ] Diagnostics export includes full logs + video metadata
- [ ] Users can self-resolve ≥90% of issues (target metric)

---

## 🔬 PHASE 5.4: Advanced Features (Optional - Data-Driven)

### Task 5.4.1: Multi-Speed Adaptive Encoding 🎚️
**Priority:** P3 (LOW - Only if >2% failures due to speed mismatch)  
**Estimated Time:** 5-6 hours  
**Status:** ❌ Not Started

**Justification:** Current failures don't show significant speed mismatch issues. Hold until data proves need.

**Concept:**
- Auto-detect optimal bit speed (50ms, 100ms, 150ms) based on camera capabilities
- Start fast (50ms), slow down if errors detected
- Adaptive speed changes mid-transmission for different lighting zones

**Hold Decision:** Revisit if CRC fail rate stays >5% after other fixes.

---

### Task 5.4.2: Reed-Solomon Forward Error Correction 🛡️
**Priority:** P3 (LOW - Only if CRC pass rate <90% after hysteresis)  
**Estimated Time:** 6-8 hours  
**Status:** ❌ Not Started

**Justification:** Current CRC pass rate 94% exceeds threshold. RS adds 14% overhead without clear benefit.

**Hold Decision:** Revisit if CRC pass rate drops below 90% after lighting gradient fixes.

---

### Task 5.4.3: Differential Encoding for Lighting Invariance 🌓
**Priority:** P3 (LOW)  
**Estimated Time:** 4-5 hours  
**Status:** ❌ Not Started

**Concept:**
- Encode bits as transitions (not absolute levels)
- Bit = 1 if state changed from previous frame, 0 if same
- Immune to absolute lighting level (only cares about deltas)

**Trade-off:**
- **Pro:** Completely invariant to lighting level
- **Con:** Error propagation (one wrong bit corrupts rest of sequence)
- **Con:** Requires longer preamble (need 2+ alternations per bit)

**Hold Decision:** Current adaptive threshold + gradient compensation should handle lighting. Test with real failure videos first.

---

## 🔐 PHASE 5.5: Security & Privacy Hardening

### Task 5.5.1: Timing Side-Channel Mitigation ⏱️
**Priority:** P2 (MEDIUM - Security hardening)  
**Estimated Time:** 4 hours  
**Status:** ❌ Not Started

**Problem:** Decode time may leak information about payload (longer decode = more CRC failures = more errors = weaker encryption?). Unlikely attack vector but worth hardening.

**Subtasks:**
- [ ] Add constant-time CRC validation (pad to fixed iterations)
- [ ] Add decode time jitter (random delay 0-100ms)
- [ ] Normalize UI updates (always show progress at fixed intervals)
- [ ] Add timing diagnostics to detect abnormal patterns
- [ ] Document timing invariants in THREAT_MODEL.md

**Algorithm:**
```javascript
// Constant-time CRC check (prevents timing oracle)
function validateCRC_ConstantTime(packet) {
  const computed = computeCRC32(packet.payload);
  const expected = packet.crc32;
  
  // Always do full comparison (don't short-circuit)
  let match = true;
  for (let i = 0; i < 4; i++) {
    match = match & (computed[i] === expected[i]);
  }
  
  // Add random jitter to mask timing variance
  const jitter = Math.random() * 10; // 0-10ms
  await sleep(jitter);
  
  return match;
}
```

**Files to Modify:**
- `examples/cat-mode-protocol.js` (constant-time CRC)
- `docs/THREAT_MODEL.md` (document side-channel mitigations)

**Acceptance Criteria:**
- [ ] Decode time variance <5% for same payload length
- [ ] No correlation between CRC fails and timing
- [ ] Documented in security audit

---

### Task 5.5.2: Secure Diagnostics Sanitization 🧹
**Priority:** P1 (HIGH - Privacy)  
**Estimated Time:** 2 hours  
**Status:** ❌ Not Started

**Problem:** Diagnostics JSON may leak sensitive metadata (filenames, payload lengths, timing patterns).

**Subtasks:**
- [ ] Add "Sanitize for Sharing" checkbox
- [ ] Redact filenames (show hash only)
- [ ] Redact exact payload lengths (show range: <100 bytes, 100-500, 500+)
- [ ] Redact exact timestamps (show relative times only)
- [ ] Add warning banner: "Diagnostics may contain sensitive metadata"

**Files to Modify:**
- `examples/wasm_browser_example.html` (sanitize export)

**Acceptance Criteria:**
- [ ] Sanitized diagnostics contain no PII
- [ ] Still useful for debugging (can reproduce issues)
- [ ] Export includes warning about unsanitized data

---

## 📊 Success Metrics (Phase 5 Targets)

### Primary Metrics
| Metric | Sprint 1 | Phase 5 Target | Improvement |
|--------|----------|----------------|-------------|
| **Decode Success Rate** | 92% | 98% | +6% |
| **CRC Pass Rate** | 94% | 97% | +3% |
| **Avg Decode Time** | 3-5s | <2s | 50-60% |
| **User Self-Debug Rate** | ~60% | >90% | +30% |

### Secondary Metrics
| Metric | Sprint 1 | Phase 5 Target |
|--------|----------|----------------|
| Cross-Browser Support | Chrome only | Chrome + FF + Safari |
| Mobile Support | None | iOS + Android PWA |
| CI Coverage | 1 golden video | 5+ golden videos + error injection |
| Error Message Clarity | Technical | User-friendly with actions |
| Performance Variance | Unknown | <5% across browsers |

### Stretch Goals
- [ ] Support 3-second videos (currently 5s minimum)
- [ ] <1s decode time for 5s video
- [ ] >99% decode success on high-quality videos
- [ ] Zero silent failures (all errors have user guidance)

---

## 🛠️ Development Workflow

### Phase 5.1 Sprint (Week 1) - CI Hardening
**Duration:** 5-7 days  
**Focus:** Automated testing, cross-browser support
1. Task 5.1.1: One-click golden video (2h)
2. Task 5.1.2: Error injection testing (4h)
3. Task 5.1.3: Cross-browser testing (5h)

**Milestone:** CI runs 5+ test cases on 3 browsers automatically

### Phase 5.2 Sprint (Week 2) - Failure Fixes
**Duration:** 5-7 days  
**Focus:** Fix remaining 8% of failures
1. Task 5.2.1: Short video sync (4h)
2. Task 5.2.2: Lighting gradient (5h)
3. Task 5.2.3: Eye region confidence (3h)

**Milestone:** >98% decode success rate on production videos

### Phase 5.3 Sprint (Week 3) - UX Polish
**Duration:** 7-10 days  
**Focus:** Performance, mobile support, error recovery
1. Task 5.3.1: Decode optimization (5h)
2. Task 5.3.2: Mobile PWA (8h)
3. Task 5.3.3: Error recovery (3h)

**Milestone:** Production-ready mobile app, <2s decode

### Phase 5.5 Sprint (Week 4) - Security Hardening
**Duration:** 3-5 days  
**Focus:** Side-channel mitigations, privacy
1. Task 5.5.1: Timing side-channel (4h)
2. Task 5.5.2: Diagnostics sanitization (2h)

**Milestone:** Security audit complete, production release

---

## 🚨 Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Safari doesn't support WebM codec | High | Medium | Add MP4 fallback (Task 5.1.3) |
| Mobile camera API unreliable | Medium | High | Test early on real devices (Task 5.3.2) |
| Web Workers slow on mobile | Low | Medium | Fallback to main thread if worker overhead >20% |
| Short video fix breaks long videos | Low | High | Regression tests with golden videos |
| Performance optimizations introduce bugs | Medium | Medium | Benchmark before/after, keep old code path |
| Gradient compensation over-fits noise | Medium | Low | Add confidence threshold for activation |

---

## 🎯 Definition of Done (Phase 5)

A task is "done" when:
- [ ] Code implemented and manually tested
- [ ] Unit tests pass (if applicable)
- [ ] Golden video tests pass (no regressions)
- [ ] Cross-browser tested (Chrome + Firefox + Safari)
- [ ] Mobile tested (iOS Safari + Chrome Android) — if UI changes
- [ ] Performance profiled (no >10% regression)
- [ ] Documentation updated (USAGE.md, inline comments)
- [ ] Error messages user-friendly (no technical jargon)
- [ ] Diagnostics include new metrics (if applicable)
- [ ] Security reviewed (if touches crypto/validation)
- [ ] Code reviewed by maintainer
- [ ] Merged to main branch

---

## 📝 Notes & Next Steps

### Immediate Priorities (Week 1)
1. ✅ Generate golden videos (manual step from Sprint 1)
2. ⏳ Automate golden video generation (Task 5.1.1)
3. ⏳ Add error injection tests (Task 5.1.2)
4. ⏳ Cross-browser CI (Task 5.1.3)

### Long-Term Vision (Beyond Phase 5)
- **Phase 6:** Enterprise features (batch processing, API mode, CLI tools)
- **Phase 7:** Advanced encoding (multi-channel color, HDR support, higher bandwidth)
- **Phase 8:** Exotic platforms (e-ink displays, LED matrices, projection mapping)

### Community Feedback Loop
- [ ] Publish beta release with diagnostics export
- [ ] Collect failure videos from users (GitHub Issues)
- [ ] Analyze diagnostics to find common failure patterns
- [ ] Prioritize fixes based on real-world data

### Success Criteria for Production Release
- [ ] >98% decode success rate on community videos
- [ ] <2s average decode time
- [ ] Works on 95% of browser/device combinations
- [ ] Users can self-debug >90% of issues
- [ ] Zero known security vulnerabilities
- [ ] Complete documentation + video tutorials

---

**Last Updated:** 2026-02-13  
**Maintainer:** systemslibrarian  
**Status:** Phase 5 planning complete, ready to start Week 1 sprint

---

🐱 Remember: **Lives depend on getting this right.** Stay pragmatic, test ruthlessly, ship iteratively.
