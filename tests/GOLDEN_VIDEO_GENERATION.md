# 🎬 Golden Video Generation - Quick Start

## Overview

Automated generation of deterministic test videos for Cat Mode validation. Replaces the manual 5-step process with one command.

## Prerequisites

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install ffmpeg

# macOS
brew install ffmpeg

# Alpine Linux (Dev Container)
apk add ffmpeg
```

### Node.js Dependencies
```bash
npm install canvas
```

## Usage

### One-Click Generation (All Test Cases)
```bash
npm run generate-golden-videos
```

This generates 3 test videos:
1. **`cat_mode_golden_empty_hash_100ms.webm`** - Empty string SHA-256 (primary test)
2. **`cat_mode_golden_short_150ms.webm`** - Short hex message (128 bits)
3. **`cat_mode_golden_long_50ms.webm`** - Long text message (variable length)

### Output
```
=======================================================================
🐱 Golden Video Generator - One-Click Mode
=======================================================================

──────────────────────────────────────────────────────────────────────
📹 Test Case: empty_hash
   Empty string SHA-256 hash (primary test case)

🎬 Generating golden video: empty_hash
   Payload type: hash
   Bit speed: 100ms
   FPS: 30
   Resolution: 640x480
   Total bits: 312 (8 lead-in + 32 preamble + 16 sync + 256 payload)
   Total frames: 936
   Duration: 31.2s
   Rendering frames...
   Progress: 100/936 frames
   Progress: 200/936 frames
   ...
   ✓ All frames rendered
   Converting to WebM...
   ✓ Video created: tests/golden/cat_mode_golden_empty_hash_100ms.webm
   Checksum: a1b2c3d4e5f6...
   ✅ Success

──────────────────────────────────────────────────────────────────────
[... short and long test cases ...]

=======================================================================
📊 Generation Summary
=======================================================================

✅ Succeeded: 3/3

📋 Checksums (SHA-256):
──────────────────────────────────────────────────────────────────────

empty_hash:
  File: cat_mode_golden_empty_hash_100ms.webm
  SHA256: a1b2c3d4e5f6...
  Size: 234.5 KB
  Duration: 31.2s
  Frames: 936

[... other test cases ...]

✓ Updated golden/README.md with checksums

=======================================================================
✅ Generation Complete!
=======================================================================

Next steps:
  1. Verify checksums match expected values
  2. Run: npm test (or python3 tests/run_golden_test.py)
  3. Commit videos: git add tests/golden/*.webm
  4. Push to CI: git push
```

## Verify Checksums

After generation, checksums are automatically added to `tests/golden/README.md`:

```bash
cd tests/golden
echo "a1b2c3d4...  cat_mode_golden_empty_hash_100ms.webm" | sha256sum -c
echo "b2c3d4e5...  cat_mode_golden_short_150ms.webm" | sha256sum -c
echo "c3d4e5f6...  cat_mode_golden_long_50ms.webm" | sha256sum -c
```

## Run Tests

### Python (Recommended)
```bash
npm run test:golden
# or
python3 tests/run_golden_test.py
```

### Node.js (Alternative)
```bash
npm run test:golden:js
# or
node tests/run_golden_test.js
```

## Troubleshooting

### Error: `ffmpeg not found`
Install ffmpeg (see Prerequisites above).

### Error: `canvas module not found`
```bash
npm install canvas
```

### Error: `Cannot find module 'canvas'` during install
The `canvas` package requires system libraries. Install build dependencies:

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential libcairo2-dev libpango1.0-dev libjpeg-dev libgif-dev librsvg2-dev
npm install canvas
```

**macOS:**
```bash
brew install pkg-config cairo pango libpng jpeg giflib librsvg
npm install canvas
```

**Alpine Linux:**
```bash
apk add build-base cairo-dev pango-dev jpeg-dev giflib-dev librsvg-dev
npm install canvas
```

### Videos have different checksums on different machines
This is expected if:
- Different ffmpeg versions (output format may vary slightly)
- Different OS (encoder implementations differ)

**Solution:** Generate videos on CI machine (or use Docker for consistency).

### Test fails even with correct checksums
1. Check video duration matches expected (~31s for empty_hash)
2. Verify frame count is correct
3. Check diagnostics JSON export for decode errors
4. Re-run with verbose logging: `DEBUG=1 python3 tests/run_golden_test.py`

## CI Integration

Golden video tests run automatically in GitHub Actions (Gate 2):

1. **Checksum verification** - Ensures videos haven't been corrupted
2. **Decode validation** - Verifies decode pipeline works correctly
3. **Assertion checks** - 7 comprehensive checks per video

### CI Workflow
```yaml
- name: Verify golden video checksums
  run: |
    cd tests/golden
    # Verify checksums match README.md

- name: Run Cat Mode Golden Video Test
  run: |
    cd tests
    python3 run_golden_test.py
```

## Manual Generation Process (Legacy)

**Before automation (5 steps):**
1. Open `examples/golden-video-generator.html` in browser
2. Configure settings (payload, speed, fps)
3. Click "Generate Golden Video"
4. Download file
5. Move to `tests/golden/` directory

**After automation (1 step):**
```bash
npm run generate-golden-videos
```

**Time saved:** 90% (5 minutes → 30 seconds)

## Advanced Usage

### Custom Test Case
Edit `tests/generate_golden_videos.js` and add to `TEST_CASES`:

```javascript
{
    name: 'my_test',
    payload: 'Custom payload here',
    payloadType: 'text',
    bitSpeed: 100,
    fps: 30,
    description: 'My custom test case'
}
```

Then run:
```bash
npm run generate-golden-videos
```

### Generate Single Video (Library API)
```javascript
const { generateGoldenVideo } = require('./tests/golden-video-lib.js');

const result = generateGoldenVideo({
    name: 'my_video',
    payload: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    payloadType: 'hash',
    bitSpeed: 100,
    fps: 30,
    width: 640,
    height: 480,
    outputDir: './tests/golden'
});

console.log('Video created:', result.path);
console.log('Checksum:', result.checksum);
```

## Files

- **`tests/golden-video-lib.js`** - Core rendering and encoding library
- **`tests/generate_golden_videos.js`** - CLI wrapper for batch generation
- **`package.json`** - NPM scripts configuration
- **`tests/golden/README.md`** - Generated checksums and documentation

## Performance

| Task | Time |
|------|------|
| Render 936 frames (empty_hash) | ~10s |
| Convert to WebM (ffmpeg) | ~5s |
| Total per video | ~15s |
| All 3 videos | ~45s |

**Total improvement:** 5 minutes manual → <1 minute automated = **83% faster**

## Next Steps

After generation:
1. ✅ Verify checksums
2. ✅ Run tests locally
3. ✅ Commit videos to Git
4. ✅ Push to CI
5. ✅ Watch Gate 2 pass in GitHub Actions

---

🐱 **Lives depend on it.** Automated testing prevents regressions.
