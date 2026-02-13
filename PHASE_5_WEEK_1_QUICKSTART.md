# Phase 5 Week 1 - Quick Start Guide

## 🚀 Installation (One-Time Setup)

### Automatic Installation (Recommended)

```bash
# Make script executable
chmod +x scripts/install_phase5_dependencies.sh

# Run installation script
bash scripts/install_phase5_dependencies.sh
```

### Manual Installation (Alpine Linux)

If the automatic script fails, run these commands individually:

```bash
# 1. Install system packages
apk update
apk add --no-cache ffmpeg build-base cairo-dev pango-dev jpeg-dev giflib-dev librsvg-dev pixman-dev pkgconfig

# 2. Rebuild canvas with native bindings
npm install canvas --build-from-source

# 3. Install Playwright browsers
npx playwright install chromium firefox webkit --with-deps
```

### Manual Installation (Ubuntu/Debian)

```bash
# 1. Install system packages
sudo apt-get update
sudo apt-get install -y ffmpeg build-essential libcairo2-dev libpango1.0-dev libjpeg-dev libgif-dev librsvg2-dev pkg-config

# 2. Rebuild canvas with native bindings
npm install canvas --build-from-source

# 3. Install Playwright browsers
npx playwright install chromium firefox webkit --with-deps
```

### Verify Installation

```bash
# Check ffmpeg
ffmpeg -version

# Check canvas
node -e "require('canvas'); console.log('✅ canvas works')"

# Check playwright
npx playwright --version
```

## 📹 Generate Golden Videos (Task 5.1.1)

```bash
npm run generate-golden-videos
```

**Expected output:**
- Creates 3 WebM videos in `tests/golden/`
- Displays SHA-256 checksums
- Updates `tests/golden/README.md`
- Takes ~30-60 seconds

**Files created:**
- `tests/golden/cat_mode_golden_empty_hash_100ms.webm` (~200KB)
- `tests/golden/cat_mode_golden_short_150ms.webm` (~150KB)
- `tests/golden/cat_mode_golden_long_50ms.webm` (~180KB)

## 🧪 Generate Error Test Videos (Task 5.1.2)

```bash
npm run generate-error-tests
```

**Expected output:**
- Creates 21 error-injected videos in `tests/golden/errors/`
- Generates `manifest.json` with metadata
- Updates `tests/golden/errors/README.md`
- Takes ~5-10 minutes

**Files created:**
- 21 WebM videos (various error modes)
- `tests/golden/errors/manifest.json`
- `tests/golden/errors/README.md`

## 🌐 Run Cross-Browser Tests (Task 5.1.3)

```bash
npm run test:browsers
```

**Expected output:**
- Runs 112 test cases (14 tests × 8 browsers)
- Generates HTML report in `tests/playwright-report/`
- Saves results to `tests/playwright-results.json`
- Takes ~20-30 minutes

**To view results:**
```bash
npx playwright show-report tests/playwright-report
```

## 🔍 Troubleshooting

### Error: "Cannot find module 'canvas'"

**Cause:** Canvas requires native compilation with system libraries

**Solution:**
```bash
# Install system dependencies (Alpine)
apk add --no-cache build-base cairo-dev pango-dev jpeg-dev giflib-dev librsvg-dev

# Rebuild canvas
npm install canvas --build-from-source
```

### Error: "ffmpeg not found"

**Cause:** FFmpeg system package not installed

**Solution:**
```bash
# Alpine
apk add ffmpeg

# Ubuntu/Debian
sudo apt-get install ffmpeg

# macOS
brew install ffmpeg
```

### Error: "playwright: not found"

**Cause:** Playwright browsers not installed

**Solution:**
```bash
npx playwright install chromium firefox webkit --with-deps
```

### Error: "Permission denied" when running script

**Cause:** Script not executable

**Solution:**
```bash
chmod +x scripts/install_phase5_dependencies.sh
```

### Canvas build fails with "node-gyp" error

**Cause:** Missing build tools or Python

**Solution:**
```bash
# Alpine
apk add python3 make g++

# Ubuntu/Debian
sudo apt-get install python3 build-essential

# macOS (install Xcode Command Line Tools)
xcode-select --install
```

## 📊 Expected Results

### Golden Videos (Task 5.1.1)

All 3 videos should generate with deterministic checksums:

```
✅ empty_hash: SHA-256 checksum consistent across runs
✅ short: SHA-256 checksum consistent across runs
✅ long: SHA-256 checksum consistent across runs
```

### Error Tests (Task 5.1.2)

All 21 error videos should validate structural integrity:

```
✅ frame_corruption: 10% frames corrupted
✅ timing_jitter: ±20% frame timing variance
✅ partial_video: Last 20% removed
✅ wrong_roi: 50px offset from correct region
✅ extreme_lighting (dim): 30% brightness
✅ extreme_lighting (bright): 170% brightness
✅ resolution_degradation: 50% resolution
```

### Cross-Browser Tests (Task 5.1.3)

Expected pass rate: ≥90% (106/112 tests)

```
✅ Chromium (desktop): 14/14 pass
✅ Firefox (desktop): 14/14 pass
⚠️ WebKit (desktop): 12-13/14 pass (WebM fallback expected)
✅ Chrome Android: 13-14/14 pass
⚠️ Safari iOS: 12-13/14 pass (camera permissions, WebM fallback)
✅ Tablet: 13-14/14 pass
⚠️ Low-end mobile: 11-12/14 pass (performance limits expected)
✅ High DPI: 14/14 pass
```

## ⏭️ Next Steps

After all Week 1 tasks complete: 1. Commit generated videos:
   ```bash
   git add tests/golden/*.webm tests/golden/errors/*.webm
   git commit -m "feat: Add golden and error test videos (Phase 5 Week 1)"
   git push
   ```

2. Verify CI passes:
   - Watch GitHub Actions for Gate 2 (golden), 3a (errors), 3b (cross-browser)

3. Move to Week 2 (Failure Mode Fixes):
   - Task 5.2.1: Short video sync fix
   - Task 5.2.2: Lighting gradient compensation
   - Task 5.2.3: Eye region confidence masking

## 📞 Getting Help

If you encounter issues not covered here:

1. Check logs in:
   - `tests/golden/errors/test_results.json` (error test diagnostics)
   - `tests/playwright-report/` (cross-browser HTML reports)

2. Export diagnostics:
   ```bash
   npm run generate-golden-videos 2>&1 | tee golden_log.txt
   npm run generate-error-tests 2>&1 | tee error_log.txt
   npm run test:browsers 2>&1 | tee browser_log.txt
   ```

3. Check system requirements:
   - Node.js ≥16.0.0: `node --version`
   - npm ≥7.0.0: `npm --version`
   - FFmpeg ≥4.0: `ffmpeg -version`
   - Python ≥3.8: `python3 --version`

---

🐱 **Lives depend on it.** Complete Week 1, proceed to Week 2!
