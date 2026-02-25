# Release Build Guide — meow-decoder Mobile

> Version 3.2.0 · Last updated with v3.2 feature set

This document covers every step to produce a signed, production-ready release build for both Android (AAB/APK) and iOS (IPA).

---

## Security pre‑flight

Before cutting any release build, confirm the following invariants:

| Check | File | Expected |
|---|---|---|
| `APP_VERSION` reflects the current semver | `src/constants/config.ts` | `'3.x.x'` |
| `FLAG_SECURE` is set on `CaptureActivity` | `android/app/src/main/.../MainActivity.kt` | `window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)` |
| Hermes enabled | `android/gradle.properties` | `hermesEnabled=true` |
| Bitcode disabled (iOS) | Xcode Build Settings | `ENABLE_BITCODE = NO` |
| No debug keys in release keystore path | `~/.gradle/gradle.properties` | Only `*.jks` paths |

> **FLAG_SECURE note for Play Store screenshots:** Google Play Console's automated screenshot capture is blocked by `FLAG_SECURE`. When you submit screenshots for the store listing, supply the manually-captured assets in `assets/store_screenshots/`. Do **not** disable `FLAG_SECURE` to work around this.

---

## Android

### 1 — Generate a release keystore (once)

```bash
keytool -genkey -v \
  -keystore ~/meow-decoder-release.jks \
  -alias meow-release \
  -keyalg RSA \
  -keysize 4096 \
  -validity 10000 \
  -storepass "$ANDROID_KEYSTORE_PASS" \
  -keypass "$ANDROID_KEY_PASS" \
  -dname "CN=meow-decoder, OU=Mobile, O=meow-decoder, L=, S=, C=US"
```

Store the `.jks` file **outside** the repository tree and back it up to offline storage immediately. Loss of this keystore means a new Play Store listing.

### 2 — Signing config in `gradle.properties`

Never commit credentials to the repo. Add to `~/.gradle/gradle.properties` (or inject via CI environment):

```properties
MEOW_STORE_FILE=/home/ci/.secrets/meow-decoder-release.jks
MEOW_STORE_PASSWORD=<store password>
MEOW_KEY_ALIAS=meow-release
MEOW_KEY_PASSWORD=<key password>
```

Reference in `android/app/build.gradle`:

```groovy
android {
    signingConfigs {
        release {
            storeFile     file(MEOW_STORE_FILE)
            storePassword MEOW_STORE_PASSWORD
            keyAlias      MEOW_KEY_ALIAS
            keyPassword   MEOW_KEY_PASSWORD
        }
    }
    buildTypes {
        release {
            signingConfig   signingConfigs.release
            minifyEnabled   true
            shrinkResources true
            proguardFiles   getDefaultProguardFile('proguard-android-optimize.txt'),
                            'proguard-rules.pro'
        }
    }
}
```

### 3 — ProGuard rules (`android/app/proguard-rules.pro`)

```proguard
# React Native — keep JS bridge entry points
-keep class com.facebook.react.** { *; }
-keep class com.facebook.hermes.** { *; }

# react-native-vision-camera — JNI / native frame processor glue
-keep class com.mrousavy.camera.** { *; }
-keepclassmembers class com.mrousavy.camera.** { *; }

# react-native-mmkv — JNI storage
-keep class com.tencent.mmkv.** { *; }

# Biometric / fingerprint
-keep class androidx.biometric.** { *; }

# Kotlin metadata (required for coroutines)
-keepattributes *Annotation*, InnerClasses, Signature, EnclosingMethod
-keep class kotlin.Metadata { *; }

# ZXing (QR) — if bundled
-keep class com.google.zxing.** { *; }

# Zod / JS — tree-shaken by Metro so no R8 rules needed

# Remove log calls in release
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}
```

### 4 — Build the App Bundle (AAB)

```bash
cd android
./gradlew bundleRelease
```

Output: `android/app/build/outputs/bundle/release/app-release.aab`

Submit this file to Google Play Console (Production, Open Testing, or Internal track).

### 5 — Build a standalone APK (sideloading / air-gap delivery)

```bash
./gradlew assembleRelease
```

Output: `android/app/build/outputs/apk/release/app-release.apk`

### 6 — Verify signing

```bash
apksigner verify --verbose android/app/build/outputs/apk/release/app-release.apk
```

Confirm `Verified using v2 scheme: true` and `Verified using v3 scheme: true`.

---

## iOS

### 1 — Certificates and provisioning profiles

1. In Xcode → Signing & Capabilities, select your Apple Developer Team.
2. Set **Bundle Identifier** to `com.meow-decoder.mobile` (or your registered ID).
3. Choose **Distribution** provisioning profile (App Store or Ad Hoc).
4. Ensure **Automatically manage signing** is **off** for CI — pin exact profile UUIDs.

### 2 — Build settings checklist

| Setting | Value |
|---|---|
| `ENABLE_BITCODE` | `NO` |
| `SWIFT_OPTIMIZATION_LEVEL` | `-O` (release) |
| `GCC_OPTIMIZATION_LEVEL` | `s` |
| `DEBUG_INFORMATION_FORMAT` | `dwarf-with-dsym` |
| `PRODUCT_BUNDLE_IDENTIFIER` | `com.meow-decoder.mobile` |

### 3 — Archive and export from Xcode

```bash
xcodebuild archive \
  -workspace ios/MeowDecoder.xcworkspace \
  -scheme MeowDecoder \
  -configuration Release \
  -archivePath build/MeowDecoder.xcarchive \
  CODE_SIGN_STYLE=Manual \
  PROVISIONING_PROFILE_SPECIFIER="MeowDecoder AppStore"

xcodebuild -exportArchive \
  -archivePath build/MeowDecoder.xcarchive \
  -exportPath build/MeowDecoder-ipa \
  -exportOptionsPlist ios/ExportOptions.plist
```

Sample `ios/ExportOptions.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>app-store</string>
  <key>teamID</key><string>YOUR_TEAM_ID</string>
  <key>uploadBitcode</key><false/>
  <key>uploadSymbols</key><true/>
</dict></plist>
```

Upload the resulting `.ipa` via `xcrun altool` or Transporter.

---

## CI / CD (GitHub Actions sketch)

```yaml
jobs:
  android-release:
    runs-on: ubuntu-latest
    env:
      MEOW_STORE_FILE: /tmp/release.jks
      MEOW_STORE_PASSWORD: ${{ secrets.ANDROID_KEYSTORE_PASS }}
      MEOW_KEY_ALIAS: meow-release
      MEOW_KEY_PASSWORD: ${{ secrets.ANDROID_KEY_PASS }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
      - name: Decode keystore
        run: echo "${{ secrets.ANDROID_KEYSTORE_B64 }}" | base64 -d > /tmp/release.jks
      - run: cd android && ./gradlew bundleRelease
      - uses: actions/upload-artifact@v4
        with:
          name: aab
          path: android/app/build/outputs/bundle/release/app-release.aab
```

**Required secrets:** `ANDROID_KEYSTORE_B64` (base64-encoded `.jks`), `ANDROID_KEYSTORE_PASS`, `ANDROID_KEY_PASS`.

---

## Hermes engine

Hermes is the recommended JS engine for React Native 0.73+. Confirm it is enabled in `android/gradle.properties`:

```properties
hermesEnabled=true
```

And in `ios/Podfile`:

```ruby
use_react_native!(
  :path => config[:reactNativePath],
  :hermes_enabled => true
)
```

Benefits for this app: ~30% faster startup, lower peak memory during fountain-decode batch loops, smaller `.aab` size.

---

## Android Build Flavors (no-network vs bridge)

Meow Capture ships two Android product flavors that share all JS/RN code but differ only in declared Android permissions.

| Flavor | Permissions | Use case |
|--------|-------------|----------|
| `secure` | Camera, Vibrate, Biometrics, Read/Write Storage | **Default** — zero internet; air-gap policy enforced by OS |
| `bridge` | + INTERNET (local LAN only) | USB/Wi-Fi bridge mode (meow-bridge CLI) |

### Flavor configuration in `android/app/build.gradle`

```groovy
android {
    flavorDimensions "network"

    productFlavors {
        secure {
            dimension "network"
            applicationIdSuffix ""
            versionNameSuffix "-secure"
            // No INTERNET permission — manifest merger removes it
        }
        bridge {
            dimension "network"
            applicationIdSuffix ".bridge"
            versionNameSuffix "-bridge"
            // AndroidManifest.xml in src/bridge/ adds INTERNET
        }
    }
}
```

### Flavor-specific manifests

`android/app/src/secure/AndroidManifest.xml` — explicitly removes INTERNET:
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:tools="http://schemas.android.com/tools">
    <!-- Remove any INTERNET permission that might be inherited from dependencies -->
    <uses-permission android:name="android.permission.INTERNET"
                     tools:node="remove"/>
</manifest>
```

`android/app/src/bridge/AndroidManifest.xml` — restricts INTERNET to loopback in description:
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET"/>
    <!-- Note: bridge flavor only connects to 127.0.0.1 / LAN addresses.
         No external network calls are made by app code. -->
</manifest>
```

### Building flavored APKs

```bash
# Secure flavor (recommended for distribution)
cd android && ./gradlew assembleSecureRelease

# Bridge flavor
cd android && ./gradlew assembleBridgeRelease

# Both at once
cd android && ./gradlew assembleRelease
```

Outputs land in `android/app/build/outputs/apk/<flavor>/release/`.

> **Security note:** The `secure` flavor is the recommended distribution artifact.
> The `bridge` flavor is intended for developers running the `meow-bridge` CLI on
> the same LAN — not for production air-gap operations.

---

## Checklist before upload

- [ ] `APP_VERSION` bumped in `src/constants/config.ts`
- [ ] `versionCode` (Android) / `CFBundleVersion` (iOS) incremented
- [ ] `minifyEnabled true` + `shrinkResources true` in `build.gradle`
- [ ] `FLAG_SECURE` confirmed active on all screens containing capture data
- [ ] ProGuard rules include VisionCamera + MMKV entries
- [ ] Store screenshots supplied manually (FLAG_SECURE blocks automated capture)
- [ ] Keystore + provisioning profiles stored in Password Manager + offline backup
- [ ] `npx tsc --noEmit` and `npx jest` pass on the release commit
- [ ] Git tag created: `git tag -a v3.x.x -m "Release v3.x.x" && git push --tags`
