# Error Injection Test Videos

**Generated:** 2026-02-13T17:36:46.317Z

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

## Test Cases (21 total)

### cat_mode_golden_empty_hash_100ms_ERROR_frame_corruption.webm

**Error Mode:** frame_corruption  
**Base Video:** cat_mode_golden_empty_hash_100ms  
**Checksum (SHA-256):** `94a0873002e1fd0e41d92655edb69791512f4eff69dda7179cc2beadcc6bc660`  
**File Size:** 31.3 KB

**Configuration:**
```json
{
  "mode": "frame_corruption",
  "rate": 0.1,
  "description": "Random 10% of frames rendered black (simulates dropped frames)",
  "expectedOutcome": "Should detect corruption via CRC errors, report frame loss in diagnostics",
  "options": {
    "seed": 42
  }
}
```

**Metadata:**
```json
{
  "errorMode": "frame_corruption",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_empty_hash_100ms.webm",
  "corruptedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_empty_hash_100ms_ERROR_frame_corruption.webm",
  "corruptionRate": 0.1,
  "totalFrames": 936,
  "corruptedFrames": 93,
  "corruptedIndices": [
    0,
    16,
    17,
    41,
    60,
    65,
    72,
    73,
    78,
    103,
    119,
    143,
    153,
    154,
    157,
    160,
    163,
    178,
    179,
    188,
    193,
    198,
    203,
    206,
    211,
    216,
    222,
    227,
    230,
    234,
    237,
    238,
    240,
    246,
    247,
    250,
    265,
    297,
    306,
    307,
    348,
    351,
    356,
    358,
    401,
    416,
    420,
    427,
    438,
    440,
    455,
    461,
    466,
    490,
    496,
    504,
    507,
    510,
    524,
    530,
    532,
    561,
    573,
    606,
    608,
    619,
    646,
    662,
    690,
    696,
    749,
    752,
    758,
    768,
    771,
    778,
    784,
    795,
    807,
    815,
    817,
    821,
    830,
    837,
    841,
    842,
    867,
    870,
    871,
    878,
    895,
    901,
    928
  ],
  "seed": 42,
  "checksum": "94a0873002e1fd0e41d92655edb69791512f4eff69dda7179cc2beadcc6bc660",
  "fileSize": 32021,
  "testCaseName": "cat_mode_golden_empty_hash_100ms",
  "errorConfig": {
    "mode": "frame_corruption",
    "rate": 0.1,
    "description": "Random 10% of frames rendered black (simulates dropped frames)",
    "expectedOutcome": "Should detect corruption via CRC errors, report frame loss in diagnostics",
    "options": {
      "seed": 42
    }
  }
}
```

---

### cat_mode_golden_empty_hash_100ms_ERROR_timing_jitter.webm

**Error Mode:** timing_jitter  
**Base Video:** cat_mode_golden_empty_hash_100ms  
**Checksum (SHA-256):** `69103d35e5c817bf28d022b46a5c87ace0aa029d6afb1e56adab208c4b247fe5`  
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
  "checksum": "69103d35e5c817bf28d022b46a5c87ace0aa029d6afb1e56adab208c4b247fe5",
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
**Checksum (SHA-256):** `1aca0b7f9238dc1dedcfe94ff01bb93e09f5d91990e34212b88b3e8ca9f60324`  
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
  "checksum": "1aca0b7f9238dc1dedcfe94ff01bb93e09f5d91990e34212b88b3e8ca9f60324",
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
**Checksum (SHA-256):** `5b4e399b725cd60c6327ad8a5fe606505cd3baf1342cfcbcac88555150ef2807`  
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
  "checksum": "5b4e399b725cd60c6327ad8a5fe606505cd3baf1342cfcbcac88555150ef2807",
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
**Checksum (SHA-256):** `5a3513a7f284acc95b7d07e94879fe0c08cd4806fe11056769433ad39e812822`  
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
  "checksum": "5a3513a7f284acc95b7d07e94879fe0c08cd4806fe11056769433ad39e812822",
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
**Checksum (SHA-256):** `429b81680226b417eab7a7f021ebb16caff9958a53e9e4e6c88de766829f5d15`  
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
  "checksum": "429b81680226b417eab7a7f021ebb16caff9958a53e9e4e6c88de766829f5d15",
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
**Checksum (SHA-256):** `f1b6349d93ccecbf10357a39790d658663bea22f40cfd489053f4ed2cc8f324e`  
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
  "checksum": "f1b6349d93ccecbf10357a39790d658663bea22f40cfd489053f4ed2cc8f324e",
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

### cat_mode_golden_long_50ms_ERROR_frame_corruption.webm

**Error Mode:** frame_corruption  
**Base Video:** cat_mode_golden_long_50ms  
**Checksum (SHA-256):** `cadb392c6c9d72d583847680dac21e6e16c2f9fcd0c2dbb3fca8dd659dab2553`  
**File Size:** 48.8 KB

**Configuration:**
```json
{
  "mode": "frame_corruption",
  "rate": 0.1,
  "description": "Random 10% of frames rendered black (simulates dropped frames)",
  "expectedOutcome": "Should detect corruption via CRC errors, report frame loss in diagnostics",
  "options": {
    "seed": 42
  }
}
```

**Metadata:**
```json
{
  "errorMode": "frame_corruption",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_long_50ms.webm",
  "corruptedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_long_50ms_ERROR_frame_corruption.webm",
  "corruptionRate": 0.1,
  "totalFrames": 1472,
  "corruptedFrames": 147,
  "corruptedIndices": [
    0,
    16,
    23,
    26,
    27,
    52,
    61,
    64,
    71,
    72,
    94,
    100,
    103,
    106,
    114,
    115,
    116,
    122,
    138,
    149,
    152,
    162,
    164,
    178,
    186,
    188,
    225,
    229,
    241,
    242,
    247,
    253,
    256,
    280,
    281,
    296,
    304,
    312,
    319,
    324,
    325,
    333,
    340,
    350,
    357,
    362,
    369,
    370,
    372,
    373,
    375,
    378,
    388,
    389,
    394,
    416,
    457,
    467,
    470,
    475,
    481,
    484,
    506,
    548,
    549,
    552,
    553,
    559,
    563,
    564,
    600,
    604,
    611,
    631,
    655,
    661,
    671,
    689,
    692,
    703,
    716,
    718,
    726,
    733,
    754,
    770,
    771,
    776,
    781,
    784,
    789,
    793,
    798,
    802,
    825,
    833,
    834,
    838,
    839,
    847,
    883,
    895,
    898,
    902,
    954,
    956,
    973,
    988,
    1003,
    1016,
    1040,
    1041,
    1045,
    1085,
    1095,
    1105,
    1122,
    1178,
    1179,
    1182,
    1192,
    1208,
    1213,
    1224,
    1233,
    1246,
    1250,
    1270,
    1282,
    1285,
    1292,
    1305,
    1316,
    1323,
    1324,
    1364,
    1369,
    1371,
    1374,
    1378,
    1380,
    1408,
    1417,
    1446,
    1460,
    1470,
    1471
  ],
  "seed": 42,
  "checksum": "cadb392c6c9d72d583847680dac21e6e16c2f9fcd0c2dbb3fca8dd659dab2553",
  "fileSize": 50021,
  "testCaseName": "cat_mode_golden_long_50ms",
  "errorConfig": {
    "mode": "frame_corruption",
    "rate": 0.1,
    "description": "Random 10% of frames rendered black (simulates dropped frames)",
    "expectedOutcome": "Should detect corruption via CRC errors, report frame loss in diagnostics",
    "options": {
      "seed": 42
    }
  }
}
```

---

### cat_mode_golden_long_50ms_ERROR_timing_jitter.webm

**Error Mode:** timing_jitter  
**Base Video:** cat_mode_golden_long_50ms  
**Checksum (SHA-256):** `bff14edf88b68f9115a4e021ad7c2aeebc8cb2461461285ec70ace4070927b90`  
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
  "checksum": "bff14edf88b68f9115a4e021ad7c2aeebc8cb2461461285ec70ace4070927b90",
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
**Checksum (SHA-256):** `f25f07948115595e349e229b947d5558222c3ba61a167047dfe5d107d11c4e13`  
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
  "checksum": "f25f07948115595e349e229b947d5558222c3ba61a167047dfe5d107d11c4e13",
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
**Checksum (SHA-256):** `e5687ac99702e41f5d15f9a19503c2cc188c65e0c2360a51b898d78794ca27b7`  
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
  "checksum": "e5687ac99702e41f5d15f9a19503c2cc188c65e0c2360a51b898d78794ca27b7",
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
**Checksum (SHA-256):** `e1abacc0cce92201f5aa72fe30901926fa9a271f6347680bf9eab0577ec02d3b`  
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
  "checksum": "e1abacc0cce92201f5aa72fe30901926fa9a271f6347680bf9eab0577ec02d3b",
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
**Checksum (SHA-256):** `469b9cf37de3465220976da5e2e75201ed88a024b95edeb379adc1f8e561fd42`  
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
  "checksum": "469b9cf37de3465220976da5e2e75201ed88a024b95edeb379adc1f8e561fd42",
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
**Checksum (SHA-256):** `26c04e7bd098e58284fe7d85b2583f1a7c677dacb57d1ab4d451b72021b050ed`  
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
  "checksum": "26c04e7bd098e58284fe7d85b2583f1a7c677dacb57d1ab4d451b72021b050ed",
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

### cat_mode_golden_short_150ms_ERROR_frame_corruption.webm

**Error Mode:** frame_corruption  
**Base Video:** cat_mode_golden_short_150ms  
**Checksum (SHA-256):** `2aed4ad207fc65014b3559624c6d15901c17c0167b56ed10df1e00d04f6d0c6f`  
**File Size:** 30.8 KB

**Configuration:**
```json
{
  "mode": "frame_corruption",
  "rate": 0.1,
  "description": "Random 10% of frames rendered black (simulates dropped frames)",
  "expectedOutcome": "Should detect corruption via CRC errors, report frame loss in diagnostics",
  "options": {
    "seed": 42
  }
}
```

**Metadata:**
```json
{
  "errorMode": "frame_corruption",
  "originalPath": "/workspaces/meow-decoder/tests/golden/cat_mode_golden_short_150ms.webm",
  "corruptedPath": "/workspaces/meow-decoder/tests/golden/errors/cat_mode_golden_short_150ms_ERROR_frame_corruption.webm",
  "corruptionRate": 0.1,
  "totalFrames": 920,
  "corruptedFrames": 92,
  "corruptedIndices": [
    0,
    16,
    17,
    40,
    59,
    64,
    71,
    72,
    76,
    86,
    101,
    117,
    140,
    151,
    154,
    158,
    160,
    175,
    176,
    185,
    190,
    195,
    199,
    202,
    208,
    212,
    218,
    223,
    226,
    230,
    233,
    234,
    236,
    242,
    243,
    246,
    260,
    292,
    300,
    302,
    342,
    345,
    349,
    352,
    394,
    409,
    413,
    419,
    431,
    432,
    448,
    453,
    458,
    481,
    488,
    495,
    499,
    501,
    515,
    521,
    523,
    552,
    564,
    596,
    597,
    608,
    635,
    650,
    678,
    684,
    736,
    739,
    745,
    755,
    758,
    765,
    770,
    781,
    793,
    801,
    803,
    807,
    816,
    822,
    827,
    852,
    855,
    856,
    863,
    880,
    886,
    913
  ],
  "seed": 42,
  "checksum": "2aed4ad207fc65014b3559624c6d15901c17c0167b56ed10df1e00d04f6d0c6f",
  "fileSize": 31493,
  "testCaseName": "cat_mode_golden_short_150ms",
  "errorConfig": {
    "mode": "frame_corruption",
    "rate": 0.1,
    "description": "Random 10% of frames rendered black (simulates dropped frames)",
    "expectedOutcome": "Should detect corruption via CRC errors, report frame loss in diagnostics",
    "options": {
      "seed": 42
    }
  }
}
```

---

### cat_mode_golden_short_150ms_ERROR_timing_jitter.webm

**Error Mode:** timing_jitter  
**Base Video:** cat_mode_golden_short_150ms  
**Checksum (SHA-256):** `d97949a18fcee921c7d966e8ca9bfc9f936bab93055f140067ff76b61a642a4a`  
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
  "checksum": "d97949a18fcee921c7d966e8ca9bfc9f936bab93055f140067ff76b61a642a4a",
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
**Checksum (SHA-256):** `fde7e66419b19e6a304d6634be517e72e5ba57db5a9e636ee56f34af43ad768f`  
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
  "checksum": "fde7e66419b19e6a304d6634be517e72e5ba57db5a9e636ee56f34af43ad768f",
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
**Checksum (SHA-256):** `02c3acbc38ca2eeaccba63b22765d5d8af6c84cfc1a73723a0b651a32fa861e0`  
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
  "checksum": "02c3acbc38ca2eeaccba63b22765d5d8af6c84cfc1a73723a0b651a32fa861e0",
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
**Checksum (SHA-256):** `f0c252ac18946e4ece4af400860f3b1e33c29ad3951b6dc9dc73cd3de94c6af6`  
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
  "checksum": "f0c252ac18946e4ece4af400860f3b1e33c29ad3951b6dc9dc73cd3de94c6af6",
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
**Checksum (SHA-256):** `d5905978584f6c6545c829dfefde4540f5a8463a98d9edbac0d3b47e71ddd4a8`  
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
  "checksum": "d5905978584f6c6545c829dfefde4540f5a8463a98d9edbac0d3b47e71ddd4a8",
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
**Checksum (SHA-256):** `507c0a880e24aaac28b71594ad92cc17d3ddc73878ece226b322cc9d9000bec9`  
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
  "checksum": "507c0a880e24aaac28b71594ad92cc17d3ddc73878ece226b322cc9d9000bec9",
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
echo "94a0873002e1fd0e41d92655edb69791512f4eff69dda7179cc2beadcc6bc660  cat_mode_golden_empty_hash_100ms_ERROR_frame_corruption.webm" | sha256sum -c
echo "69103d35e5c817bf28d022b46a5c87ace0aa029d6afb1e56adab208c4b247fe5  cat_mode_golden_empty_hash_100ms_ERROR_timing_jitter.webm" | sha256sum -c
echo "1aca0b7f9238dc1dedcfe94ff01bb93e09f5d91990e34212b88b3e8ca9f60324  cat_mode_golden_empty_hash_100ms_ERROR_partial_video.webm" | sha256sum -c
echo "5b4e399b725cd60c6327ad8a5fe606505cd3baf1342cfcbcac88555150ef2807  cat_mode_golden_empty_hash_100ms_ERROR_wrong_roi.webm" | sha256sum -c
echo "5a3513a7f284acc95b7d07e94879fe0c08cd4806fe11056769433ad39e812822  cat_mode_golden_empty_hash_100ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "429b81680226b417eab7a7f021ebb16caff9958a53e9e4e6c88de766829f5d15  cat_mode_golden_empty_hash_100ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "f1b6349d93ccecbf10357a39790d658663bea22f40cfd489053f4ed2cc8f324e  cat_mode_golden_empty_hash_100ms_ERROR_resolution_degradation.webm" | sha256sum -c
echo "cadb392c6c9d72d583847680dac21e6e16c2f9fcd0c2dbb3fca8dd659dab2553  cat_mode_golden_long_50ms_ERROR_frame_corruption.webm" | sha256sum -c
echo "bff14edf88b68f9115a4e021ad7c2aeebc8cb2461461285ec70ace4070927b90  cat_mode_golden_long_50ms_ERROR_timing_jitter.webm" | sha256sum -c
echo "f25f07948115595e349e229b947d5558222c3ba61a167047dfe5d107d11c4e13  cat_mode_golden_long_50ms_ERROR_partial_video.webm" | sha256sum -c
echo "e5687ac99702e41f5d15f9a19503c2cc188c65e0c2360a51b898d78794ca27b7  cat_mode_golden_long_50ms_ERROR_wrong_roi.webm" | sha256sum -c
echo "e1abacc0cce92201f5aa72fe30901926fa9a271f6347680bf9eab0577ec02d3b  cat_mode_golden_long_50ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "469b9cf37de3465220976da5e2e75201ed88a024b95edeb379adc1f8e561fd42  cat_mode_golden_long_50ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "26c04e7bd098e58284fe7d85b2583f1a7c677dacb57d1ab4d451b72021b050ed  cat_mode_golden_long_50ms_ERROR_resolution_degradation.webm" | sha256sum -c
echo "2aed4ad207fc65014b3559624c6d15901c17c0167b56ed10df1e00d04f6d0c6f  cat_mode_golden_short_150ms_ERROR_frame_corruption.webm" | sha256sum -c
echo "d97949a18fcee921c7d966e8ca9bfc9f936bab93055f140067ff76b61a642a4a  cat_mode_golden_short_150ms_ERROR_timing_jitter.webm" | sha256sum -c
echo "fde7e66419b19e6a304d6634be517e72e5ba57db5a9e636ee56f34af43ad768f  cat_mode_golden_short_150ms_ERROR_partial_video.webm" | sha256sum -c
echo "02c3acbc38ca2eeaccba63b22765d5d8af6c84cfc1a73723a0b651a32fa861e0  cat_mode_golden_short_150ms_ERROR_wrong_roi.webm" | sha256sum -c
echo "f0c252ac18946e4ece4af400860f3b1e33c29ad3951b6dc9dc73cd3de94c6af6  cat_mode_golden_short_150ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "d5905978584f6c6545c829dfefde4540f5a8463a98d9edbac0d3b47e71ddd4a8  cat_mode_golden_short_150ms_ERROR_extreme_lighting.webm" | sha256sum -c
echo "507c0a880e24aaac28b71594ad92cc17d3ddc73878ece226b322cc9d9000bec9  cat_mode_golden_short_150ms_ERROR_resolution_degradation.webm" | sha256sum -c
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

This will recreate all 21 test cases with consistent checksums (due to seeded RNG).
