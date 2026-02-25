## 🐱 Meow Capture v{VERSION}

> Secure optical air-gap QR capture for Android & iOS

### Downloads

| Platform | File | SHA-256 |
|----------|------|---------|
| Android (AAB) | `meow-capture-v{VERSION}.aab` | `<sha256>` |
| Android (APK, universal) | `meow-capture-v{VERSION}-universal.apk` | `<sha256>` |
| iOS (IPA, ad-hoc) | `meow-capture-v{VERSION}.ipa` | `<sha256>` |

### Verify Integrity

```bash
# Verify the APK
sha256sum meow-capture-v{VERSION}-universal.apk
# Expected: <sha256>

# Optional: verify APK signature (Android)
apksigner verify --print-certs meow-capture-v{VERSION}-universal.apk
```

### What's New

- <!-- List key user-facing changes here -->
- <!-- e.g. "Proactive low-light coaching with auto-exposure nudge" -->
- <!-- e.g. "Optional audio cues for eyes-free capture" -->

### Security Notes

- AES-256-GCM encryption unchanged
- Zero network permissions — fully air-gapped
- Biometric gate on export
- FLAG_SECURE active on all screens
- All dependencies audited — no new native modules with network access

### Install (Android side-load)

```bash
# Transfer APK to phone via USB
adb install meow-capture-v{VERSION}-universal.apk

# Or install AAB via bundletool
bundletool install-apks --apks=meow-capture-v{VERSION}.apks
```

### Install (iOS ad-hoc)

1. Open the `.ipa` in Apple Configurator 2 or Xcode Devices
2. Or use `ios-deploy`: `ios-deploy --bundle meow-capture-v{VERSION}.ipa`

### Build from Source

```bash
git clone https://github.com/user/meow-decoder.git
cd meow-decoder/mobile
npm install
cd android && ./gradlew assembleRelease  # Android
# or
cd ios && xcodebuild -workspace MeowCapture.xcworkspace -scheme MeowCapture archive  # iOS
```

### Compatibility

- Android 8.0+ (API 26+), arm64-v8a / x86_64
- iOS 15.0+, iPhone 8 or later
- React Native 0.73.4 (Hermes engine)

---

*Full changelog: [CHANGELOG.md](./CHANGELOG.md)*
