# Sound Assets

Placeholder directory for audio cue files used by `useAudioCues.ts`.

## Required Files

| File | Duration | Purpose |
|------|----------|---------|
| `meow_start.wav` | ~100ms | Session capture begins |
| `meow_milestone.wav` | ~100ms | 25% / 50% / 75% progress |
| `meow_complete.wav` | ~200ms | Fountain complete (100%) |
| `meow_error.wav` | ~150ms | Error notification |

## Requirements

- **Format**: WAV (16-bit, 44.1kHz mono) — universally supported on both platforms
- **Volume**: Normalized to -12 dB LUFS (subtle, not startling)
- **Character**: Soft, cat-themed tones (gentle chime, soft purr, light bell)
- **Size**: Each file < 20 KB (no bloat)

## Installation

### Android
Copy files to: `android/app/src/main/res/raw/`
```
android/app/src/main/res/raw/meow_start.wav
android/app/src/main/res/raw/meow_milestone.wav
android/app/src/main/res/raw/meow_complete.wav
android/app/src/main/res/raw/meow_error.wav
```

### iOS
Add files to the Xcode project bundle:
1. Drag files into `ios/MeowCapture/` in Xcode
2. Ensure "Copy items if needed" is checked
3. Ensure target membership for `MeowCapture` is enabled
