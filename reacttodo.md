# meow-decoder Mobile App — React Native Build Tracker

## Status Legend
- [ ] Not started
- [x] Complete
- [~] In progress

---

## Phase 1 — Types & Validation Layer
- [x] `src/types/capture.ts` — CaptureRequest, CapturedFrame, CaptureResponse, CaptureState
- [x] `src/types/navigation.ts` — Navigation param types for React Navigation
- [x] `src/services/requestValidator.ts` — Zod schemas, validateRequest()
- [x] `src/services/qrDecoder.ts` — parseQRPayload(), validateBase64(), opaque data handling

## Phase 2 — Constants & Utils
- [x] `src/constants/config.ts` — Timeouts, thresholds, FOUNTAIN_OVERHEAD, GIF detection params
- [x] `src/constants/theme.ts` — Colors, fonts, cat-themed palette
- [x] `src/utils/base64.ts` — isValidBase64(), estimateDecodedBytes() — no actual decode
- [x] `src/utils/formatters.ts` — formatElapsed(), formatPercent(), formatFileSize()

## Phase 3 — Services Layer
- [x] `src/services/frameCollector.ts` — FrameCollector class, dedup, size tracking
- [x] `src/services/jsonExporter.ts` — exportResponse(), chunked export at 5MB boundary

## Phase 4 — Hooks Layer
- [x] `src/hooks/useCapture.ts` — Full state machine reducer (IDLE→CAPTURING→COMPLETE)
- [x] `src/hooks/useQRScanner.ts` — Vision Camera frame processor, GIF auto-detection
- [x] `src/hooks/useStabilityMonitor.ts` — Accelerometer shake detection
- [x] `src/hooks/useSessionManager.ts` — Progress calculations, recoverability metrics

## Phase 5 — Components Layer
- [x] `src/components/CameraPreview.tsx` — Vision Camera wrapper with frame processor
- [x] `src/components/ProgressHUD.tsx` — Circular progress, frame count, recoverability bar
- [x] `src/components/FrameOverlay.tsx` — QR bounding box, status badges
- [x] `src/components/StabilityIndicator.tsx` — Shake/blur warning overlay
- [x] `src/components/CatToast.tsx` — Themed notification toasts with cat sounds

## Phase 6 — Screens Layer
- [x] `src/screens/SplashScreen.tsx` — Animated cat logo, version display
- [x] `src/screens/OnboardingScreen.tsx` — First-run: air-gap explanation, camera permission
- [x] `src/screens/HomeScreen.tsx` — Load capture request or manual session entry
- [x] `src/screens/CaptureScreen.tsx` — Camera preview + overlay + progress HUD
- [x] `src/screens/ExportScreen.tsx` — Review results, save JSON, QR fallback display

## Phase 7 — App Entry & Navigation
- [x] `src/App.tsx` — Navigation container, theme provider, AppState lifecycle
- [x] `src/navigation/AppNavigator.tsx` — Stack navigator wiring all screens

## Phase 8 — Project Config
- [x] `package.json` — All dependencies per spec (vision-camera, zod, reanimated, etc.)
- [x] `tsconfig.json` — Strict TypeScript config
- [x] `.eslintrc.js` — ESLint + Prettier rules
- [x] `babel.config.js` — Reanimated plugin, worklets support

## Phase 9 — Tests
- [x] `__tests__/captureReducer.test.ts` — All state transition tests
- [x] `__tests__/requestValidator.test.ts` — Zod validation edge cases
- [x] `__tests__/frameCollector.test.ts` — Dedup and accumulation tests
- [x] `__tests__/jsonExporter.test.ts` — Export and chunking tests
- [x] `__tests__/formatters.test.ts` — Utility formatter tests
- [x] `__tests__/base64.test.ts` — Base64 validation tests

## Phase 10 — Platform & README
- [x] `android/app/src/main/AndroidManifest.xml` — Camera-only permissions
- [x] `ios/MeowCapture/Info.plist` — NSCameraUsageDescription
- [x] `README.md` — Full updated README per spec

---

## Security Invariants (cross-check on each phase)
- [x] No network permissions in any manifest (AndroidManifest — no INTERNET; Info.plist — NSAppTransportSecurity blocks all; network_security_config.xml — all cleartext blocked)
- [x] No frame data written to disk except during explicit export (state lives in React useReducer; AppState listener dispatches RESET on background)
- [x] No crypto keys or passwords ever referenced in app code (app is capture-only; decryption happens on desktop)
- [x] All incoming JSON validated with Zod before processing (CaptureRequestSchema.strict() in requestValidator.ts)
- [x] AppState background handler clears frame data from memory (useCapture.ts AppState addEventListener dispatches RESET)
- [x] No `any` type escapes in TypeScript (tsconfig strict + @typescript-eslint/no-explicit-any as ESLint error)
- [x] No `console.log(frameData)` or similar data leaks in production paths (no-console as ESLint error in .eslintrc.js)
