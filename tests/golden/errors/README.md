# Error Injection Test Videos

**Generated:** 2026-02-13T17:13:40.285Z

## Overview

These videos are error-injected variants of the golden test videos, designed to validate:
- Error detection and handling
- Diagnostic message quality
- User-facing error messages
- Graceful degradation under adverse conditions

## Test Matrix

| Error Mode | Description | Expected Outcome |
|------------|-------------|------------------|
| `frame_corruption` | Random 10% of frames rendered black (simulates dropped frames) | Should detect corruption via CRC errors, report frame loss in diagnostics |
| `timing_jitter` | Variable frame delays ±20% (simulates buffering/lag) | Should maintain sync via adaptive threshold, may trigger timeout warnings |
| `partial_video` | Video cut off after 80% (simulates recording stopped early) | Should detect incomplete payload, report "Partial data received" error |
| `wrong_roi` | ROI shifted 50px from correct center (simulates user error) | Should fail eye detection or detect no valid bits, suggest ROI adjustment |
| `extreme_lighting` | Very dim lighting (30% brightness) | Should struggle with eye detection, may require contrast boost in preprocessing |
| `extreme_lighting` | Very bright lighting (170% brightness) | Should saturate pixels, may fail eye/pupil separation |
| `resolution_degradation` | Downscaled to 50% resolution and upscaled (simulates low-quality camera) | Should work with reduced confidence, may increase CRC error rate |

## Test Cases (18 total)

### cat_mode_golden_empty_hash_100ms_ERROR_timing_jitter.webm

**Error Mode:** timing_jitter  
**Base Video:** cat_mode_golden_empty_hash_100ms  
**Checksum (SHA-256):** `26d87d89994e3464af656e38f7da54eee64bfc12dd15974cd352b4fbc58b1bcf`  
**File Size:** 26.3 KB

**Configuration:**
```json
{
  "mode": "timing_jitter",
  "variance": 0.2,
  "description": "Variable frame delays ±20% (simulates buffering/lag)",
  "expectedOutcome": "Should maintain sync via adaptive threshold, may trigger timeout warnings",
  "options": {
    "seed": 43
  }
}
```

**Metadata:**
```json
{
  "errorMode": "timing_jitter",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_empty_hash_100ms.webm",
  "jitteredPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_empty_hash_100ms_ERROR_timing_jitter.webm",
  "jitterVariance": 0.2,
  "totalFrames": 936,
  "baseFps": 30,
  "avgFrameDuration": 0.033440733802033426,
  "minFrameDuration": 0.02666676839192713,
  "maxFrameDuration": 0.03999684652313443,
  "effectiveFps": 29.90365001916295,
  "seed": 43,
  "checksum": "26d87d89994e3464af656e38f7da54eee64bfc12dd15974cd352b4fbc58b1bcf",
  "fileSize": 26963,
  "testCaseName": "cat_mode_golden_empty_hash_100ms",
  "errorConfig": {
    "mode": "timing_jitter",
    "variance": 0.2,
    "description": "Variable frame delays ±20% (simulates buffering/lag)",
    "expectedOutcome": "Should maintain sync via adaptive threshold, may trigger timeout warnings",
    "options": {
      "seed": 43
    }
  }
}
```

---

### cat_mode_golden_empty_hash_100ms_ERROR_partial_video.webm

**Error Mode:** partial_video  
**Base Video:** cat_mode_golden_empty_hash_100ms  
**Checksum (SHA-256):** `32c915ce5ec2643869effb15c124832dc6b1d37617e19373d7c4ff7b90d39563`  
**File Size:** 25.1 KB

**Configuration:**
```json
{
  "mode": "partial_video",
  "cutoff": 0.2,
  "description": "Video cut off after 80% (simulates recording stopped early)",
  "expectedOutcome": "Should detect incomplete payload, report \"Partial data received\" error"
}
```

**Metadata:**
```json
{
  "errorMode": "partial_video",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_empty_hash_100ms.webm",
  "truncatedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_empty_hash_100ms_ERROR_partial_video.webm",
  "cutoffFraction": 0.2,
  "originalDuration": 31.2,
  "truncatedDuration": 24.96,
  "removedDuration": 6.239999999999998,
  "checksum": "32c915ce5ec2643869effb15c124832dc6b1d37617e19373d7c4ff7b90d39563",
  "fileSize": 25693,
  "testCaseName": "cat_mode_golden_empty_hash_100ms",
  "errorConfig": {
    "mode": "partial_video",
    "cutoff": 0.2,
    "description": "Video cut off after 80% (simulates recording stopped early)",
    "expectedOutcome": "Should detect incomplete payload, report \"Partial data received\" error"
  }
}
```

---

### cat_mode_golden_empty_hash_100ms_ERROR_wrong_roi.webm

**Error Mode:** wrong_roi  
**Base Video:** cat_mode_golden_empty_hash_100ms  
**Checksum (SHA-256):** `125a1f3c09a24fc1a9a31408c8f48688be3238314c3636c0db80186f6e1fd420`  
**File Size:** 31.3 KB

**Configuration:**
```json
{
  "mode": "wrong_roi",
  "offset": [
    50,
    50
  ],
  "description": "ROI shifted 50px from correct center (simulates user error)",
  "expectedOutcome": "Should fail eye detection or detect no valid bits, suggest ROI adjustment"
}
```

**Metadata:**
```json
{
  "errorMode": "wrong_roi",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_empty_hash_100ms.webm",
  "croppedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_empty_hash_100ms_ERROR_wrong_roi.webm",
  "offset": [
    50,
    50
  ],
  "actualCrop": [
    0,
    0
  ],
  "originalDimensions": [
    640,
    480
  ],
  "outputDimensions": [
    640,
    480
  ],
  "checksum": "125a1f3c09a24fc1a9a31408c8f48688be3238314c3636c0db80186f6e1fd420",
  "fileSize": 32021,
  "testCaseName": "cat_mode_golden_empty_hash_100ms",
  "errorConfig": {
    "mode": "wrong_roi",
    "offset": [
      50,
      50
    ],
    "description": "ROI shifted 50px from correct center (simulates user error)",
    "expectedOutcome": "Should fail eye detection or detect no valid bits, suggest ROI adjustment"
  }
}
```

---

### cat_mode_golden_empty_hash_100ms_ERROR_extreme_lighting.webm

**Error Mode:** extreme_lighting  
**Base Video:** cat_mode_golden_empty_hash_100ms  
**Checksum (SHA-256):** `fbb2ee92da8bd3e8e8e4d1e01fe9e39ed630a80479732c8d45d4d783461a4414`  
**File Size:** 31.3 KB

**Configuration:**
```json
{
  "mode": "extreme_lighting",
  "brightness": 0.3,
  "description": "Very dim lighting (30% brightness)",
  "expectedOutcome": "Should struggle with eye detection, may require contrast boost in preprocessing"
}
```

**Metadata:**
```json
{
  "errorMode": "extreme_lighting",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_empty_hash_100ms.webm",
  "adjustedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_empty_hash_100ms_ERROR_extreme_lighting.webm",
  "brightnessFactor": 0.3,
  "condition": "dim",
  "checksum": "fbb2ee92da8bd3e8e8e4d1e01fe9e39ed630a80479732c8d45d4d783461a4414",
  "fileSize": 32021,
  "testCaseName": "cat_mode_golden_empty_hash_100ms",
  "errorConfig": {
    "mode": "extreme_lighting",
    "brightness": 0.3,
    "description": "Very dim lighting (30% brightness)",
    "expectedOutcome": "Should struggle with eye detection, may require contrast boost in preprocessing"
  }
}
```

---

### cat_mode_golden_empty_hash_100ms_ERROR_extreme_lighting.webm

**Error Mode:** extreme_lighting  
**Base Video:** cat_mode_golden_empty_hash_100ms  
**Checksum (SHA-256):** `32f3541a8dd803a539965c0651ff4e7344996b949d9ce2e6ee5bf15be7e1e972`  
**File Size:** 31.3 KB

**Configuration:**
```json
{
  "mode": "extreme_lighting",
  "brightness": 1.7,
  "description": "Very bright lighting (170% brightness)",
  "expectedOutcome": "Should saturate pixels, may fail eye/pupil separation"
}
```

**Metadata:**
```json
{
  "errorMode": "extreme_lighting",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_empty_hash_100ms.webm",
  "adjustedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_empty_hash_100ms_ERROR_extreme_lighting.webm",
  "brightnessFactor": 1.7,
  "condition": "bright",
  "checksum": "32f3541a8dd803a539965c0651ff4e7344996b949d9ce2e6ee5bf15be7e1e972",
  "fileSize": 32007,
  "testCaseName": "cat_mode_golden_empty_hash_100ms",
  "errorConfig": {
    "mode": "extreme_lighting",
    "brightness": 1.7,
    "description": "Very bright lighting (170% brightness)",
    "expectedOutcome": "Should saturate pixels, may fail eye/pupil separation"
  }
}
```

---

### cat_mode_golden_empty_hash_100ms_ERROR_resolution_degradation.webm

**Error Mode:** resolution_degradation  
**Base Video:** cat_mode_golden_empty_hash_100ms  
**Checksum (SHA-256):** `2739b6abf6ca5ea650816e8b87f0ef56013b5c25646c3eb0b9fa2ff388cb8671`  
**File Size:** 31.3 KB

**Configuration:**
```json
{
  "mode": "resolution_degradation",
  "scale": 0.5,
  "description": "Downscaled to 50% resolution and upscaled (simulates low-quality camera)",
  "expectedOutcome": "Should work with reduced confidence, may increase CRC error rate"
}
```

**Metadata:**
```json
{
  "errorMode": "resolution_degradation",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_empty_hash_100ms.webm",
  "degradedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_empty_hash_100ms_ERROR_resolution_degradation.webm",
  "scaleFactor": 0.5,
  "originalResolution": [
    640,
    480
  ],
  "intermediateResolution": [
    320,
    240
  ],
  "checksum": "2739b6abf6ca5ea650816e8b87f0ef56013b5c25646c3eb0b9fa2ff388cb8671",
  "fileSize": 32021,
  "testCaseName": "cat_mode_golden_empty_hash_100ms",
  "errorConfig": {
    "mode": "resolution_degradation",
    "scale": 0.5,
    "description": "Downscaled to 50% resolution and upscaled (simulates low-quality camera)",
    "expectedOutcome": "Should work with reduced confidence, may increase CRC error rate"
  }
}
```

---

### cat_mode_golden_long_50ms_ERROR_timing_jitter.webm

**Error Mode:** timing_jitter  
**Base Video:** cat_mode_golden_long_50ms  
**Checksum (SHA-256):** `88fcf76f371508962cc3da15534f0e0147f3cedd201744537c772fb2ec51b1f8`  
**File Size:** 40.8 KB

**Configuration:**
```json
{
  "mode": "timing_jitter",
  "variance": 0.2,
  "description": "Variable frame delays ±20% (simulates buffering/lag)",
  "expectedOutcome": "Should maintain sync via adaptive threshold, may trigger timeout warnings",
  "options": {
    "seed": 43
  }
}
```

**Metadata:**
```json
{
  "errorMode": "timing_jitter",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_long_50ms.webm",
  "jitteredPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_long_50ms_ERROR_timing_jitter.webm",
  "jitterVariance": 0.2,
  "totalFrames": 1472,
  "baseFps": 30,
  "avgFrameDuration": 0.033307777783252966,
  "minFrameDuration": 0.02666676839192713,
  "maxFrameDuration": 0.03999684652313443,
  "effectiveFps": 30.02301764192736,
  "seed": 43,
  "checksum": "88fcf76f371508962cc3da15534f0e0147f3cedd201744537c772fb2ec51b1f8",
  "fileSize": 41819,
  "testCaseName": "cat_mode_golden_long_50ms",
  "errorConfig": {
    "mode": "timing_jitter",
    "variance": 0.2,
    "description": "Variable frame delays ±20% (simulates buffering/lag)",
    "expectedOutcome": "Should maintain sync via adaptive threshold, may trigger timeout warnings",
    "options": {
      "seed": 43
    }
  }
}
```

---

### cat_mode_golden_long_50ms_ERROR_partial_video.webm

**Error Mode:** partial_video  
**Base Video:** cat_mode_golden_long_50ms  
**Checksum (SHA-256):** `89a106631c7ef8e205b67803c088c2c28f531414574228218992703b3b06bfb0`  
**File Size:** 39.2 KB

**Configuration:**
```json
{
  "mode": "partial_video",
  "cutoff": 0.2,
  "description": "Video cut off after 80% (simulates recording stopped early)",
  "expectedOutcome": "Should detect incomplete payload, report \"Partial data received\" error"
}
```

**Metadata:**
```json
{
  "errorMode": "partial_video",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_long_50ms.webm",
  "truncatedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_long_50ms_ERROR_partial_video.webm",
  "cutoffFraction": 0.2,
  "originalDuration": 49.066,
  "truncatedDuration": 39.25280000000001,
  "removedDuration": 9.813199999999995,
  "checksum": "89a106631c7ef8e205b67803c088c2c28f531414574228218992703b3b06bfb0",
  "fileSize": 40163,
  "testCaseName": "cat_mode_golden_long_50ms",
  "errorConfig": {
    "mode": "partial_video",
    "cutoff": 0.2,
    "description": "Video cut off after 80% (simulates recording stopped early)",
    "expectedOutcome": "Should detect incomplete payload, report \"Partial data received\" error"
  }
}
```

---

### cat_mode_golden_long_50ms_ERROR_wrong_roi.webm

**Error Mode:** wrong_roi  
**Base Video:** cat_mode_golden_long_50ms  
**Checksum (SHA-256):** `1f7b2ed2c6761493fb22df0c09c8f7d8f18dd5156510c711924f589e976dd859`  
**File Size:** 48.8 KB

**Configuration:**
```json
{
  "mode": "wrong_roi",
  "offset": [
    50,
    50
  ],
  "description": "ROI shifted 50px from correct center (simulates user error)",
  "expectedOutcome": "Should fail eye detection or detect no valid bits, suggest ROI adjustment"
}
```

**Metadata:**
```json
{
  "errorMode": "wrong_roi",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_long_50ms.webm",
  "croppedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_long_50ms_ERROR_wrong_roi.webm",
  "offset": [
    50,
    50
  ],
  "actualCrop": [
    0,
    0
  ],
  "originalDimensions": [
    640,
    480
  ],
  "outputDimensions": [
    640,
    480
  ],
  "checksum": "1f7b2ed2c6761493fb22df0c09c8f7d8f18dd5156510c711924f589e976dd859",
  "fileSize": 50021,
  "testCaseName": "cat_mode_golden_long_50ms",
  "errorConfig": {
    "mode": "wrong_roi",
    "offset": [
      50,
      50
    ],
    "description": "ROI shifted 50px from correct center (simulates user error)",
    "expectedOutcome": "Should fail eye detection or detect no valid bits, suggest ROI adjustment"
  }
}
```

---

### cat_mode_golden_long_50ms_ERROR_extreme_lighting.webm

**Error Mode:** extreme_lighting  
**Base Video:** cat_mode_golden_long_50ms  
**Checksum (SHA-256):** `a744f999c49da3632fdb2450a2479f1680c49fd977e1d229693bf8e6d2a8ea97`  
**File Size:** 48.8 KB

**Configuration:**
```json
{
  "mode": "extreme_lighting",
  "brightness": 0.3,
  "description": "Very dim lighting (30% brightness)",
  "expectedOutcome": "Should struggle with eye detection, may require contrast boost in preprocessing"
}
```

**Metadata:**
```json
{
  "errorMode": "extreme_lighting",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_long_50ms.webm",
  "adjustedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_long_50ms_ERROR_extreme_lighting.webm",
  "brightnessFactor": 0.3,
  "condition": "dim",
  "checksum": "a744f999c49da3632fdb2450a2479f1680c49fd977e1d229693bf8e6d2a8ea97",
  "fileSize": 50021,
  "testCaseName": "cat_mode_golden_long_50ms",
  "errorConfig": {
    "mode": "extreme_lighting",
    "brightness": 0.3,
    "description": "Very dim lighting (30% brightness)",
    "expectedOutcome": "Should struggle with eye detection, may require contrast boost in preprocessing"
  }
}
```

---

### cat_mode_golden_long_50ms_ERROR_extreme_lighting.webm

**Error Mode:** extreme_lighting  
**Base Video:** cat_mode_golden_long_50ms  
**Checksum (SHA-256):** `82dda831daaef4c825531fe788d8352a15d88eacc8dad1895861467920249a23`  
**File Size:** 48.8 KB

**Configuration:**
```json
{
  "mode": "extreme_lighting",
  "brightness": 1.7,
  "description": "Very bright lighting (170% brightness)",
  "expectedOutcome": "Should saturate pixels, may fail eye/pupil separation"
}
```

**Metadata:**
```json
{
  "errorMode": "extreme_lighting",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_long_50ms.webm",
  "adjustedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_long_50ms_ERROR_extreme_lighting.webm",
  "brightnessFactor": 1.7,
  "condition": "bright",
  "checksum": "82dda831daaef4c825531fe788d8352a15d88eacc8dad1895861467920249a23",
  "fileSize": 49999,
  "testCaseName": "cat_mode_golden_long_50ms",
  "errorConfig": {
    "mode": "extreme_lighting",
    "brightness": 1.7,
    "description": "Very bright lighting (170% brightness)",
    "expectedOutcome": "Should saturate pixels, may fail eye/pupil separation"
  }
}
```

---

### cat_mode_golden_long_50ms_ERROR_resolution_degradation.webm

**Error Mode:** resolution_degradation  
**Base Video:** cat_mode_golden_long_50ms  
**Checksum (SHA-256):** `ca25182107787f788bef1458371f9d1e88ba750d4079421f45aadfa9cd093213`  
**File Size:** 48.8 KB

**Configuration:**
```json
{
  "mode": "resolution_degradation",
  "scale": 0.5,
  "description": "Downscaled to 50% resolution and upscaled (simulates low-quality camera)",
  "expectedOutcome": "Should work with reduced confidence, may increase CRC error rate"
}
```

**Metadata:**
```json
{
  "errorMode": "resolution_degradation",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_long_50ms.webm",
  "degradedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_long_50ms_ERROR_resolution_degradation.webm",
  "scaleFactor": 0.5,
  "originalResolution": [
    640,
    480
  ],
  "intermediateResolution": [
    320,
    240
  ],
  "checksum": "ca25182107787f788bef1458371f9d1e88ba750d4079421f45aadfa9cd093213",
  "fileSize": 50021,
  "testCaseName": "cat_mode_golden_long_50ms",
  "errorConfig": {
    "mode": "resolution_degradation",
    "scale": 0.5,
    "description": "Downscaled to 50% resolution and upscaled (simulates low-quality camera)",
    "expectedOutcome": "Should work with reduced confidence, may increase CRC error rate"
  }
}
```

---

### cat_mode_golden_short_150ms_ERROR_timing_jitter.webm

**Error Mode:** timing_jitter  
**Base Video:** cat_mode_golden_short_150ms  
**Checksum (SHA-256):** `90ec60c8ff09ee1b4e33cbbeba5438dee30f58ca6a88bb575e7ac47e778ce291`  
**File Size:** 25.9 KB

**Configuration:**
```json
{
  "mode": "timing_jitter",
  "variance": 0.2,
  "description": "Variable frame delays ±20% (simulates buffering/lag)",
  "expectedOutcome": "Should maintain sync via adaptive threshold, may trigger timeout warnings",
  "options": {
    "seed": 43
  }
}
```

**Metadata:**
```json
{
  "errorMode": "timing_jitter",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_short_150ms.webm",
  "jitteredPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_short_150ms_ERROR_timing_jitter.webm",
  "jitterVariance": 0.2,
  "totalFrames": 920,
  "baseFps": 30,
  "avgFrameDuration": 0.03344421196108497,
  "minFrameDuration": 0.02666676839192713,
  "maxFrameDuration": 0.03999684652313443,
  "effectiveFps": 29.900540074425447,
  "seed": 43,
  "checksum": "90ec60c8ff09ee1b4e33cbbeba5438dee30f58ca6a88bb575e7ac47e778ce291",
  "fileSize": 26501,
  "testCaseName": "cat_mode_golden_short_150ms",
  "errorConfig": {
    "mode": "timing_jitter",
    "variance": 0.2,
    "description": "Variable frame delays ±20% (simulates buffering/lag)",
    "expectedOutcome": "Should maintain sync via adaptive threshold, may trigger timeout warnings",
    "options": {
      "seed": 43
    }
  }
}
```

---

### cat_mode_golden_short_150ms_ERROR_partial_video.webm

**Error Mode:** partial_video  
**Base Video:** cat_mode_golden_short_150ms  
**Checksum (SHA-256):** `74945d04b9c9d2d90610f220347864344f915dc0b4ab1e05b7ee41981c60a21b`  
**File Size:** 24.7 KB

**Configuration:**
```json
{
  "mode": "partial_video",
  "cutoff": 0.2,
  "description": "Video cut off after 80% (simulates recording stopped early)",
  "expectedOutcome": "Should detect incomplete payload, report \"Partial data received\" error"
}
```

**Metadata:**
```json
{
  "errorMode": "partial_video",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_short_150ms.webm",
  "truncatedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_short_150ms_ERROR_partial_video.webm",
  "cutoffFraction": 0.2,
  "originalDuration": 30.666,
  "truncatedDuration": 24.5328,
  "removedDuration": 6.133199999999999,
  "checksum": "74945d04b9c9d2d90610f220347864344f915dc0b4ab1e05b7ee41981c60a21b",
  "fileSize": 25264,
  "testCaseName": "cat_mode_golden_short_150ms",
  "errorConfig": {
    "mode": "partial_video",
    "cutoff": 0.2,
    "description": "Video cut off after 80% (simulates recording stopped early)",
    "expectedOutcome": "Should detect incomplete payload, report \"Partial data received\" error"
  }
}
```

---

### cat_mode_golden_short_150ms_ERROR_wrong_roi.webm

**Error Mode:** wrong_roi  
**Base Video:** cat_mode_golden_short_150ms  
**Checksum (SHA-256):** `a7827838117f2c877de961f5ef1081e537a3177ed64f7bb3703194f4c5300895`  
**File Size:** 30.8 KB

**Configuration:**
```json
{
  "mode": "wrong_roi",
  "offset": [
    50,
    50
  ],
  "description": "ROI shifted 50px from correct center (simulates user error)",
  "expectedOutcome": "Should fail eye detection or detect no valid bits, suggest ROI adjustment"
}
```

**Metadata:**
```json
{
  "errorMode": "wrong_roi",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_short_150ms.webm",
  "croppedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_short_150ms_ERROR_wrong_roi.webm",
  "offset": [
    50,
    50
  ],
  "actualCrop": [
    0,
    0
  ],
  "originalDimensions": [
    640,
    480
  ],
  "outputDimensions": [
    640,
    480
  ],
  "checksum": "a7827838117f2c877de961f5ef1081e537a3177ed64f7bb3703194f4c5300895",
  "fileSize": 31493,
  "testCaseName": "cat_mode_golden_short_150ms",
  "errorConfig": {
    "mode": "wrong_roi",
    "offset": [
      50,
      50
    ],
    "description": "ROI shifted 50px from correct center (simulates user error)",
    "expectedOutcome": "Should fail eye detection or detect no valid bits, suggest ROI adjustment"
  }
}
```

---

### cat_mode_golden_short_150ms_ERROR_extreme_lighting.webm

**Error Mode:** extreme_lighting  
**Base Video:** cat_mode_golden_short_150ms  
**Checksum (SHA-256):** `ca22155adde83c292edddd482bdb545408090ffa48d893a8c2f09c31ebcfcc20`  
**File Size:** 30.8 KB

**Configuration:**
```json
{
  "mode": "extreme_lighting",
  "brightness": 0.3,
  "description": "Very dim lighting (30% brightness)",
  "expectedOutcome": "Should struggle with eye detection, may require contrast boost in preprocessing"
}
```

**Metadata:**
```json
{
  "errorMode": "extreme_lighting",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_short_150ms.webm",
  "adjustedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_short_150ms_ERROR_extreme_lighting.webm",
  "brightnessFactor": 0.3,
  "condition": "dim",
  "checksum": "ca22155adde83c292edddd482bdb545408090ffa48d893a8c2f09c31ebcfcc20",
  "fileSize": 31493,
  "testCaseName": "cat_mode_golden_short_150ms",
  "errorConfig": {
    "mode": "extreme_lighting",
    "brightness": 0.3,
    "description": "Very dim lighting (30% brightness)",
    "expectedOutcome": "Should struggle with eye detection, may require contrast boost in preprocessing"
  }
}
```

---

### cat_mode_golden_short_150ms_ERROR_extreme_lighting.webm

**Error Mode:** extreme_lighting  
**Base Video:** cat_mode_golden_short_150ms  
**Checksum (SHA-256):** `87bc4183723e18d3b9957fefe236c993b71c2130faed73f8dd4ca7adacedabcb`  
**File Size:** 30.7 KB

**Configuration:**
```json
{
  "mode": "extreme_lighting",
  "brightness": 1.7,
  "description": "Very bright lighting (170% brightness)",
  "expectedOutcome": "Should saturate pixels, may fail eye/pupil separation"
}
```

**Metadata:**
```json
{
  "errorMode": "extreme_lighting",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_short_150ms.webm",
  "adjustedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_short_150ms_ERROR_extreme_lighting.webm",
  "brightnessFactor": 1.7,
  "condition": "bright",
  "checksum": "87bc4183723e18d3b9957fefe236c993b71c2130faed73f8dd4ca7adacedabcb",
  "fileSize": 31479,
  "testCaseName": "cat_mode_golden_short_150ms",
  "errorConfig": {
    "mode": "extreme_lighting",
    "brightness": 1.7,
    "description": "Very bright lighting (170% brightness)",
    "expectedOutcome": "Should saturate pixels, may fail eye/pupil separation"
  }
}
```

---

### cat_mode_golden_short_150ms_ERROR_resolution_degradation.webm

**Error Mode:** resolution_degradation  
**Base Video:** cat_mode_golden_short_150ms  
**Checksum (SHA-256):** `c11af751ab23d1964e7841fb2d5c38264fc597ca574ef08482ecea9d1de8bfed`  
**File Size:** 30.8 KB

**Configuration:**
```json
{
  "mode": "resolution_degradation",
  "scale": 0.5,
  "description": "Downscaled to 50% resolution and upscaled (simulates low-quality camera)",
  "expectedOutcome": "Should work with reduced confidence, may increase CRC error rate"
}
```

**Metadata:**
```json
{
  "errorMode": "resolution_degradation",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_short_150ms.webm",
  "degradedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_short_150ms_ERROR_resolution_degradation.webm",
  "scaleFactor": 0.5,
  "originalResolution": [
    640,
    480
  ],
  "intermediateResolution": [
    320,
    240
  ],
  "checksum": "c11af751ab23d1964e7841fb2d5c38264fc597ca574ef08482ecea9d1de8bfed",
  "fileSize": 31493,
  "testCaseName": "cat_mode_golden_short_150ms",
  "errorConfig": {
    "mode": "resolution_degradation",
    "scale": 0.5,
    "description": "Downscaled to 50% resolution and upscaled (simulates low-quality camera)",
    "expectedOutcome": "Should work with reduced confidence, may increase CRC error rate"
  }
}
```

---


## Verify Checksums

```bash
cd tests/golden/errors

# Verify all checksums
echo "26d87d89994e3464af656e38f7da54eee64bfc12dd15974cd352b4fbc58b1bcf  cat_mode_golden_empty_hash_100ms_ERROR_timing_jitter.webm" | sha256sum -c
echo "32c915ce5ec2643869effb15c124832dc6b1d37617e19373d7c4ff7b90d39563  cat_mode_golden_empty_hash_100ms_ERROR_partial_video.webm" | sha256sum -c
echo "125a1f3c09a24fc1a9a31408c8f48688be3238314c3636c0db80186f6e1fd420  cat_mode_golden_empty_hash_100ms_ERROR_wrong_roi.webm" | sha256sum -c
echo "fbb2ee92da8bd3e8e8e4d1e01fe9e39ed630a80479732c8d45d4d783461a4414  cat_mode_golden_empty_hash_100ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "32f3541a8dd803a539965c0651ff4e7344996b949d9ce2e6ee5bf15be7e1e972  cat_mode_golden_empty_hash_100ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "2739b6abf6ca5ea650816e8b87f0ef56013b5c25646c3eb0b9fa2ff388cb8671  cat_mode_golden_empty_hash_100ms_ERROR_resolution_degradation.webm" | sha256sum -c
echo "88fcf76f371508962cc3da15534f0e0147f3cedd201744537c772fb2ec51b1f8  cat_mode_golden_long_50ms_ERROR_timing_jitter.webm" | sha256sum -c
echo "89a106631c7ef8e205b67803c088c2c28f531414574228218992703b3b06bfb0  cat_mode_golden_long_50ms_ERROR_partial_video.webm" | sha256sum -c
echo "1f7b2ed2c6761493fb22df0c09c8f7d8f18dd5156510c711924f589e976dd859  cat_mode_golden_long_50ms_ERROR_wrong_roi.webm" | sha256sum -c
echo "a744f999c49da3632fdb2450a2479f1680c49fd977e1d229693bf8e6d2a8ea97  cat_mode_golden_long_50ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "82dda831daaef4c825531fe788d8352a15d88eacc8dad1895861467920249a23  cat_mode_golden_long_50ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "ca25182107787f788bef1458371f9d1e88ba750d4079421f45aadfa9cd093213  cat_mode_golden_long_50ms_ERROR_resolution_degradation.webm" | sha256sum -c
echo "90ec60c8ff09ee1b4e33cbbeba5438dee30f58ca6a88bb575e7ac47e778ce291  cat_mode_golden_short_150ms_ERROR_timing_jitter.webm" | sha256sum -c
echo "74945d04b9c9d2d90610f220347864344f915dc0b4ab1e05b7ee41981c60a21b  cat_mode_golden_short_150ms_ERROR_partial_video.webm" | sha256sum -c
echo "a7827838117f2c877de961f5ef1081e537a3177ed64f7bb3703194f4c5300895  cat_mode_golden_short_150ms_ERROR_wrong_roi.webm" | sha256sum -c
echo "ca22155adde83c292edddd482bdb545408090ffa48d893a8c2f09c31ebcfcc20  cat_mode_golden_short_150ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "87bc4183723e18d3b9957fefe236c993b71c2130faed73f8dd4ca7adacedabcb  cat_mode_golden_short_150ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "c11af751ab23d1964e7841fb2d5c38264fc597ca574ef08482ecea9d1de8bfed  cat_mode_golden_short_150ms_ERROR_resolution_degradation.webm" | sha256sum -c
```

## Run Error Tests

```bash
# Run Python error test suite
python3 tests/run_error_tests.py

# Run Node.js error test suite
node tests/run_error_tests.js
```

## Expected Failures

All test cases in this directory are **intentionally broken** and should produce specific error messages:

1. **frame_corruption**: CRC errors, frame loss detected
2. **timing_jitter**: Timeout warnings, sync maintained
3. **partial_video**: Incomplete payload error
4. **wrong_roi**: Eye detection failure, suggest ROI adjustment
5. **extreme_lighting** (dim): Low confidence, contrast boost suggested
6. **extreme_lighting** (bright): Saturation detected, exposure adjustment suggested
7. **resolution_degradation**: Reduced confidence, increased CRC errors

## CI Integration

Error tests run as **Gate 3** in CI pipeline:
- Verifies error detection works correctly
- Validates diagnostic messages are user-friendly
- Ensures no crashes on malformed input

## Regenerate

To regenerate error test videos:

```bash
npm run generate-error-tests
```

This will recreate all 18 test cases with consistent checksums (due to seeded RNG).
