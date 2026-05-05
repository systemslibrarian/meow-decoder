# Golden Test Videos

This directory contains deterministic test videos for CI/CD validation of Cat Mode decoding.

## Files

### `cat_mode_golden_empty_hash_100ms.webm`
- **Payload:** Empty string SHA-256 hash
- **Expected:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- **Bit Speed:** 100ms
- **FPS:** 30
- **Resolution:** 640x480
- **Duration:** ~7 seconds (56 bits lead-in/preamble/sync + 256 bits payload)

## Generating Golden Videos

1. Open `examples/golden-video-generator.html` in browser
2. Configure settings (default: empty hash, 100ms, 30fps)
3. Click "Generate Golden Video"
4. Move downloaded file to this directory

## Validating Golden Videos

1. Open `tests/test_cat_mode_golden.html` in browser
2. Load golden video
3. Decode should complete with matching hash
4. Any mismatch = test failure

## CI Integration

See `.github/workflows/test.yml` for automated golden video testing in CI.

## Test Cases

| File | Payload Type | Bit Speed | Expected Result | Status |
|------|-------------|-----------|-----------------|--------|
| `cat_mode_golden_empty_hash_100ms.webm` | Empty SHA-256 | 100ms | Match hash | ⏳ Pending |
| `cat_mode_golden_short_150ms.webm` | Short message | 150ms | Match text | ⏳ Pending |
| `cat_mode_golden_long_50ms.webm` | Long message | 50ms | Match text | ⏳ Pending |

## Notes

- Golden videos must be deterministic (same payload → same video)
- Use fixed session ID (0x12345678) for consistency
- Videos stored in Git LFS to avoid repo bloat
- Maximum file size: 5 MB per video




## 🔐 Checksums (SHA-256)

**Verify golden videos before running tests:**

```bash
cd tests/golden
echo "a57ace710a93d874480759a5fde9f11b347d74a7d773cb1c7dc8dc7d58c91540  cat_mode_golden_empty_hash_100ms.webm" | sha256sum -c
echo "cbf62dca07afdcfbe54cdad8e664c221f6a9f5ed414e513ecc80582e4363880a  cat_mode_golden_short_150ms.webm" | sha256sum -c
echo "2bddfb514d9581224acea75f9588615e434ae94767ad8f165914d09dd2a53e1b  cat_mode_golden_long_50ms.webm" | sha256sum -c
```

| File | SHA-256 Checksum |
|------|------------------|
| `cat_mode_golden_empty_hash_100ms.webm` | `a57ace710a93d874...` |
| `cat_mode_golden_short_150ms.webm` | `cbf62dca07afdcfb...` |
| `cat_mode_golden_long_50ms.webm` | `2bddfb514d958122...` |

**Generated:** 2026-05-04T16:22:13.714Z
