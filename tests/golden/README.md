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
echo "9f139d73a90a197bbd92c0ced137c9816a9113eb9700caca2ae5c9c597b3938a  cat_mode_golden_empty_hash_100ms.webm" | sha256sum -c
echo "61bdad9c06eb7ae5eaa17a9be4af59ab2f90bbe055fc63d787899ebb307f7e0d  cat_mode_golden_short_150ms.webm" | sha256sum -c
echo "85d16135835123887aa6baee3bdee2e75d25e3301037237692379c9c1f293213  cat_mode_golden_long_50ms.webm" | sha256sum -c
```

| File | SHA-256 Checksum |
|------|------------------|
| `cat_mode_golden_empty_hash_100ms.webm` | `9f139d73a90a197b...` |
| `cat_mode_golden_short_150ms.webm` | `61bdad9c06eb7ae5...` |
| `cat_mode_golden_long_50ms.webm` | `85d1613583512388...` |

**Generated:** 2026-05-04T12:04:40.071Z
