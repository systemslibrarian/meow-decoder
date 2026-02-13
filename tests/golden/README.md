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
echo "47f6a05c28f5c8faf59a77f70b10c904964e30e9bd6e71d09e9031bbded44437  cat_mode_golden_empty_hash_100ms.webm" | sha256sum -c
echo "f456e86141ec5e94f356b45f395781240a014fa539889e619ff247bf16bf5568  cat_mode_golden_short_150ms.webm" | sha256sum -c
echo "a1fdde1e00e795df7812cca2cf1030e99c9be1f6d4bbf4088f38a87da6475c41  cat_mode_golden_long_50ms.webm" | sha256sum -c
```

| File | SHA-256 Checksum |
|------|------------------|
| `cat_mode_golden_empty_hash_100ms.webm` | `47f6a05c28f5c8fa...` |
| `cat_mode_golden_short_150ms.webm` | `f456e86141ec5e94...` |
| `cat_mode_golden_long_50ms.webm` | `a1fdde1e00e795df...` |

**Generated:** 2026-02-13T17:06:03.905Z
