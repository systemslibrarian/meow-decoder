# Mobile App 10/10 Hardening Review & Fixes

> **Date:** 2025-01-20
> **Scope:** `mobile/` — Meow Capture React Native companion app (v3.2.0)
> **Verdict:** ✅ **Release-ready after fixes applied below.**

---

## Executive Summary

The Meow Capture mobile app is a well-engineered, security-first optical air-gap
companion. This review audited **all 45+ source files** across screens, hooks,
services, components, constants, types, and platform configs (Android + iOS). Nine
TypeScript strict-mode errors were found and fixed. Documentation drift (test count,
clipboard timer) was corrected. Versioning was unified to use a single source of
truth. The diagnostics panel was enriched with device/security/protocol metadata. No
critical security gaps were discovered — the zero-network, memory-only, biometric-gated
architecture is sound.

**Final verification:** 0 TypeScript errors (`tsc --noEmit`), 274/274 Jest tests passing.

---

## Priority A — Feature Completeness & UI Honesty

### Findings

| Area | Status | Notes |
|------|--------|-------|
| Feature flags | ✅ | `FEATURE_FLAGS.VIDEO_IMPORT = false` properly gates UI button in HomeScreen (line 407) |
| Conditional hook init | ✅ | `useVideoImport` only initialised when flag is on; no-op stubs provided when off |
| CalibrationWizard | ✅ | Present and functional (5-step preflight) |
| CaptureCoachPanel | ✅ | Priority-ranked live hints (shake, brightness, decode rate, safe-to-stop) |
| DiagnosticsPanel | ✅ | Long-press version badge; enhanced with device/security/protocol info (see fixes) |
| Request QR scanner | ✅ | Scans capture request from sender screen using VisionCamera |
| Settings screen | ✅ | Strict / Convenience security mode with MMKV persistence |
| QR fallback export | ✅ | Chunked QR display with per-chunk + payload checksums (v2 envelope) |

**No phantom features** — every documented feature has a working implementation or is
properly gated behind a feature flag.

### Fixes Applied

1. **HomeScreen unused parameter** — `frames` callback param in `useVideoImport` was
   unused with `noUnusedParameters` strict flag. Renamed to `_frames`.

---

## Priority B — Android Manifest

### `AndroidManifest.xml` Audit

| Check | Result |
|-------|--------|
| `INTERNET` permission absent | ✅ Not present — OS-enforced air gap |
| `CAMERA` permission present | ✅ Required for QR scanning |
| `VIBRATE` permission present | ✅ Required for haptic feedback |
| `WRITE_EXTERNAL_STORAGE` (maxSdkVersion=28) | ✅ Scoped correctly for legacy Android |
| `usesCleartextTraffic="false"` | ✅ Present |
| `networkSecurityConfig` referenced | ✅ Present |
| `exported="true"` on main activity | ✅ Required for Android 12+ launch |
| Single `<application>` tag | ✅ Clean, no duplicates |
| `FLAG_SECURE` | ✅ Set in `MainActivity.kt` `onCreate()` |
| No debug/test permissions leaked | ✅ Clean |

**No issues found.** Manifest is production-ready.

---

## Priority C — iOS Readiness

### `Info.plist` Audit

| Check | Result |
|-------|--------|
| `CFBundleShortVersionString` | ✅ `3.2.0` — matches `config.ts` and `package.json` |
| `CFBundleVersion` (build number) | ✅ `1` — proper integer build number |
| `NSCameraUsageDescription` | ✅ Present with clear privacy string |
| `NSFaceIDUsageDescription` | ✅ Present for biometric export gate |
| ATS exceptions | ✅ None — no network exceptions needed (zero-network app) |
| `UIBackgroundModes` | ✅ None — app doesn't run in background |
| Privacy manifest (`NSPrivacyAccessedAPITypes`) | ⚠️ See follow-up (Apple may require for App Store in 2025+) |

**One informational gap:** Apple's evolving privacy manifest requirements (required
API declarations) may need a `PrivacyInfo.xcprivacy` file before App Store submission.
Not blocking for development builds.

---

## Priority D — Versioning Consistency

### Before Fixes

| Location | Version | Issue |
|----------|---------|-------|
| `package.json` | `3.2.0` | ✅ Source of truth |
| `config.ts` `APP_VERSION` | `3.2.0` | ✅ Constant |
| `Info.plist` `CFBundleShortVersionString` | `3.2.0` | ✅ Matches |
| HomeScreen version badge | Hardcoded `"3.2.0"` | ❌ Not using `APP_VERSION` |
| SettingsScreen about text | Hardcoded `"Meow Capture v3.2.0"` | ❌ Not using `APP_VERSION` |
| DiagnosticsPanel debug report | Missing version + protocol | ❌ Not included |

### Fixes Applied

1. **HomeScreen** — Imported `APP_VERSION` from `config.ts`, replaced hardcoded string
   with `v${APP_VERSION}` in the version badge.
2. **SettingsScreen** — Imported `APP_VERSION` from `config.ts`, replaced hardcoded
   `Meow Capture v3.2.0` with `Meow Capture v${APP_VERSION}`.
3. **DiagnosticsPanel** — Imported `APP_VERSION` and `PROTOCOL_VERSION`, added them to
   the copyable debug report.

**After fixes:** All version references derive from `config.ts` `APP_VERSION`. Updating
the version in one place propagates everywhere.

---

## Priority E — Diagnostics Panel Enhancement

### Before

The debug report contained: session info, frame info, quality metrics, timestamps.

### After (Fixes Applied)

Enhanced the copyable debug report in `DiagnosticsPanel.tsx` with three new sections:

```
── Device ──
OS: ios / android
Font Scale: 1.0
Pixel Ratio: 3.0
App Version: 3.2.0
Protocol Version: 1

── Security ──
Trust Model: untrusted-optical-sensor
Network: none (no INTERNET permission)
Screen Privacy: FLAG_SECURE (Android) / overlay (iOS)
Frame Storage: memory-only (wiped on background)

Note: This report contains no sensitive data — only
session metadata and device info. Safe to share for debugging.
```

Also: Session ID truncated to last 8 chars in report (was full UUID) to minimize
fingerprinting while remaining useful for support correlation.

---

## Priority F — Capture UX Review

### Assessment

The capture experience is **comprehensive and well-polished**:

| Feature | Implementation | Quality |
|---------|---------------|---------|
| Stall detection | `useStallDetector` — 4s timeout with graduated recovery | ✅ Excellent |
| Low-light auto-nudge | `useLowLightDetector` — exposure bias nudge | ✅ Excellent |
| Camera health self-test | `useCameraHealthCheck` — warns on stuck camera | ✅ Good |
| Coaching panel | `CaptureCoachPanel` — priority-ranked hints | ✅ Excellent |
| Stability indicator | Accelerometer-based shake warning | ✅ Good |
| Milestone toasts | 25/50/75/100% with haptics + VoiceOver | ✅ Excellent |
| Memory pressure | Warning toast + banner at 800 frames | ✅ Good |
| Pause/resume | Mid-session pause without losing frames | ✅ Good |
| Panic wipe | 3s long-press cancel, immediate wipe | ✅ Essential |
| Android back guard | Confirmation alert before discarding | ✅ Good |
| Foreground recovery | Returns to Home after backgrounding (security wipe) | ✅ Correct |
| Purr haptics | Gentle tactile pulse per frame batch | ✅ Nice touch |

**No capture UX changes needed.** The graduated stall recovery (toast → auto-expose →
torch suggestion) is particularly well designed.

---

## Priority G — QR Export Integrity

### `jsonExporter.ts` Audit

The QR fallback export system is **already hardened** with a v2 envelope format:

| Feature | Present | Implementation |
|---------|---------|---------------|
| Per-chunk checksum | ✅ | `checksumHex()` — FNV-1a + DJB2a dual hash (collision-resistant) |
| Payload checksum | ✅ | Computed over full JSON payload, included in last chunk |
| Byte-length verification | ✅ | `payload_bytes` field for length cross-check |
| Version field | ✅ | `v: 2` in envelope |
| Verification function | ✅ | `verifyQRExportReassembly()` — validates checksum + byte count |
| Total chunk count | ✅ | `total` field in each chunk |
| Chunk index | ✅ | `i` field (0-based) |

### ExportScreen QR UI Audit

The ExportScreen correctly renders:
- Chunk-level checksums displayed per QR frame
- Reassembly verification box on the last chunk (payload checksum + chunk count)
- Navigation controls (Previous / Next / Done) with proper accessibility labels

**No additional hardening needed.** The implementation already exceeds typical QR
fallback integrity standards.

---

## Priority H — Documentation Alignment

### Drift Found & Fixed

| Document | Issue | Fix |
|----------|-------|-----|
| `README.md` v3.2 header | "267/267 tests" | → "274/274 tests" |
| `README.md` v3.1 header | "267/267 tests" | → "274/274 tests" |
| `README.md` Development section | "267 tests" | → "274 tests" |
| `README.md` Security table | "clipboard 30 s" | → "45 s" (matches `CLIPBOARD_WIPE_DELAY_MS`) |

### Documentation Accuracy Confirmed

| Claim | Verified |
|-------|----------|
| VisionCamera v4 `useCodeScanner` (not deprecated worklet) | ✅ `useQRScanner.ts` uses native `useCodeScanner` |
| No `react-native-worklets-core` dependency | ✅ Removed in v2 per README |
| Fountain 1.5× overhead | ✅ `FOUNTAIN_OVERHEAD = 1.5` in `config.ts` |
| Biometric export gate | ✅ `ExportScreen.tsx` uses `react-native-biometrics` |
| `FLAG_SECURE` on Android | ✅ Referenced in `MainActivity.kt` |
| MMKV for preferences only (never frame data) | ✅ `useCapture.ts` stores indices only |
| Zod strict schema validation | ✅ `requestValidator.ts` uses `.strict()` |
| Deep link support (`meow://capture?…`) | ✅ `AppNavigator.tsx` linking config |
| ARCHITECTURE.md component tree | ✅ Matches actual file structure |
| Permission tables | ✅ Match AndroidManifest.xml and Info.plist |

---

## All TypeScript Errors Fixed (9 total)

| # | File | Error | Fix |
|---|------|-------|-----|
| 1–5 | `ExportScreen.tsx` | Broken StyleSheet — `qrChecksumText`, `qrVerifyBox`, `qrVerifyTitle`, `qrVerifyText`, `qrVerifyHash` nested inside `qrControls` definition | Restructured: close `qrControls` first, define new styles separately |
| 6 | `CaptureCoachPanel.tsx` | `accessibilityRole="status"` not valid RN type | Changed to `"text"` |
| 7 | `FrameOverlay.tsx` | `accessibilityRole="status"` not valid RN type | Changed to `"text"` |
| 8 | `HomeScreen.tsx` | Unused `frames` parameter (TS6133) | Renamed to `_frames` |
| 9 | `ExportScreen.tsx` | Missing `borderWidth` in `qrVerifyBox` (cascading from broken stylesheet) | Fixed by stylesheet restructure |

---

## Remaining Gaps (Non-Blocking)

| Priority | Item | Impact | Effort |
|----------|------|--------|--------|
| Low | iOS `PrivacyInfo.xcprivacy` | May be required for App Store submission (2025+ Apple requirement) | 1 hour |
| Low | `react-native-sensors` not New Arch compatible | Blocks Fabric/TurboModules migration when ready | 2-3 days |
| Info | `react-native-biometrics` not yet a TurboModule | Works via Bridge interop; no functional impact | - |
| Info | Video import feature flag is `false` | Intentionally gated; TurboModule stub present for future use | - |
| Info | Bridge mode (`bridge/`) not wired | Documented as future; reference implementation exists | - |

---

## Verification Results

```
$ npx tsc --noEmit
(zero output — clean)

$ npx jest --verbose
Test Suites: 8 passed, 8 total
Tests:       274 passed, 274 total
Snapshots:   0 total
Time:        0.861 s
```

---

## Manual Test Plan

For pre-release validation on physical devices:

### Android

1. **Permission flow**: Fresh install → OnboardingScreen → grant camera → proceed
2. **Permission denied recovery**: Deny camera → "Open Settings" button → grant → works
3. **Screenshot blocking**: Take screenshot during CaptureScreen → verify blocked by FLAG_SECURE
4. **Task switcher**: Switch apps during capture → verify privacy overlay shown
5. **Hardware back**: Press back during capture → verify confirmation alert
6. **Panic wipe**: Long-press Cancel 3s → verify immediate return to Home
7. **Biometric gate**: Export → verify fingerprint/PIN prompt before file write
8. **No network**: Verify no INTERNET permission in `adb shell dumpsys package`
9. **ADB extract**: Verify `adb pull` retrieves export JSON from Downloads
10. **QR fallback**: Export via QR mode → scan all chunks → verify checksums

### iOS

1. **Face ID gate**: Export → verify Face ID prompt (or passcode fallback)
2. **Background wipe**: Background the app during capture → return → verify Home screen
3. **Privacy overlay**: Enter app switcher → verify solid overlay (not capture preview)
4. **Share sheet**: Export → Share → verify JSON content and auto-cleanup
5. **Reduce Motion**: Enable in Settings → verify SplashScreen, FrameOverlay, CatToast respect it
6. **VoiceOver**: Capture session → verify milestone announcements at 25/50/75/100%
7. **Dynamic Type**: Increase text size → verify layouts don't break

### Cross-Platform

1. **Fountain capture**: Display animated GIF → capture until 100% → export → verify desktop decode
2. **Single-frame capture**: Display static MEOW QR → verify auto-complete
3. **Stall detection**: Cover camera → verify toast after 4s
4. **Low light**: Dim screen → verify exposure nudge suggestion
5. **Calibration wizard**: Run preflight → complete all 5 steps
6. **Diagnostics**: Long-press version badge → verify panel with all sections → copy report
7. **Settings**: Toggle Strict/Convenience → verify persistence across restart

---

## Android-Specific Notes

- `minSdkVersion` should be verified in `build.gradle` (recommend ≥ 24 for VisionCamera v4)
- `WRITE_EXTERNAL_STORAGE` has `maxSdkVersion=28` — correct for scoped storage migration
- `networkSecurityConfig` is referenced — ensure `res/xml/network_security_config.xml` exists and is restrictive
- ProGuard/R8 rules: verify VisionCamera, Reanimated, and MMKV JNI classes are kept

## iOS-Specific Notes

- `CFBundleVersion` is `"1"` — must be incremented for each App Store / TestFlight upload
- No `UIRequiredDeviceCapabilities` for `arkit` or similar — camera-only app doesn't need them
- `NSCameraUsageDescription` string should be reviewed by legal before submission
- Consider adding `ITSAppUsesNonExemptEncryption = NO` to avoid export compliance prompts (app does zero crypto)

---

## Release Readiness Assessment

| Criterion | Status |
|-----------|--------|
| TypeScript strict: zero errors | ✅ |
| Jest: 274/274 passing | ✅ |
| Android manifest: clean + secure | ✅ |
| iOS Info.plist: correct + private | ✅ |
| Version consistency: single source | ✅ |
| Feature flags: no phantom features | ✅ |
| QR export integrity: checksummed | ✅ |
| Documentation: accurate | ✅ |
| Security model: zero-network + biometric + wipe | ✅ |
| Accessibility: VoiceOver + TalkBack + Reduce Motion | ✅ |

**Rating: Ready for physical device testing and TestFlight / internal track distribution.**

---

## Prioritised Follow-Up

1. **iOS Privacy Manifest** — Add `PrivacyInfo.xcprivacy` before App Store submission
2. **`ITSAppUsesNonExemptEncryption`** — Add to Info.plist to skip export compliance
3. **Increment `CFBundleVersion`** — Before each TestFlight/App Store upload
4. **New Architecture migration** — Replace `react-native-sensors` with `expo-sensors` when ready
5. **End-to-end device test** — Run full manual test plan on Android 14+ and iOS 17+

---

## Files Modified

| File | Changes |
|------|---------|
| `src/screens/ExportScreen.tsx` | Fixed broken StyleSheet (5 styles nested inside `qrControls`) |
| `src/components/CaptureCoachPanel.tsx` | `accessibilityRole="status"` → `"text"` |
| `src/components/FrameOverlay.tsx` | `accessibilityRole="status"` → `"text"` |
| `src/screens/HomeScreen.tsx` | Unused `frames` → `_frames`; imported + used `APP_VERSION` |
| `src/screens/SettingsScreen.tsx` | Imported + used `APP_VERSION` |
| `src/components/DiagnosticsPanel.tsx` | Added `PixelRatio`, `APP_VERSION`, `PROTOCOL_VERSION` imports; enriched debug report with Device/Security/Protocol sections; truncated session ID |
| `README.md` | Test count 267→274 (×3); clipboard wipe 30s→45s |
