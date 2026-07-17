/**
 * HomeScreen.tsx — Main landing screen.
 *
 * Primary action:
 *   • Scan Sender Screen — point camera at the QR shown by the desktop
 *     sender; the app reads the capture request and starts capture.
 *
 * Advanced fallbacks (for the request-first workflow when no live sender
 * is available):
 *   • Import request (JSON) — file picker for a saved capture request
 *   • Import video / GIF — pick a previously recorded .mp4/.gif and
 *     extract QR frames via the native extraction bridge
 *   • Manual entry — type session ID and expected frame count
 *
 * Validates all loaded JSON with Zod before allowing navigation to
 * CaptureScreen, showing clear field-level errors on failure.
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import {
  View,
  Text,
  Image,
  StyleSheet,
  TouchableOpacity,
  TextInput,
  ScrollView,
  SafeAreaView,
  Platform,
  ActivityIndicator,
  KeyboardAvoidingView,
  Modal,
} from 'react-native';
import {
  Camera,
  useCameraDevice,
  useCameraPermission,
  useCodeScanner,
} from 'react-native-vision-camera';
import { useFocusEffect } from '@react-navigation/native';
import ReactNativeHapticFeedback from 'react-native-haptic-feedback';
import DocumentPicker from 'react-native-document-picker';
import RNFS from 'react-native-fs';
import { z } from 'zod';
import {
  validateRequestFromString,
  firstErrorMessage,
} from '../services/requestValidator';
import { deriveExpectedFramesFromFrame } from '../services/qrDecoder';
import { makeSessionId } from '../utils/session';
import { useVideoImport } from '../hooks/useVideoImport';
import { DiagnosticsPanel } from '../components/DiagnosticsPanel';
import type { CaptureRequest } from '../types/capture';
import type { HomeScreenProps } from '../types/navigation';
import { Colors, Typography, Spacing, Radius, Shadows } from '../constants/theme';
import { DEFAULT_TIMEOUT_SECONDS, FEATURE_FLAGS, APP_VERSION } from '../constants/config';
import meowLogo from '../assets/meow-decoder-logo-notagline.png';
import {
  readCaptureCheckpoint,
  clearCaptureCheckpoint,
  type SessionCheckpoint,
} from '../hooks/useCapture';

// ── Component ─────────────────────────────────────────────────────────────────

export function HomeScreen({ navigation }: HomeScreenProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [interruptedSession, setInterruptedSession] = useState<SessionCheckpoint | null>(null);

  // ── Request QR scanner state ──────────────────────────────────────────────
  const [scanningRequest, setScanningRequest] = useState(false);
  const [barcodeModulePending, setBarcodeModulePending] = useState(false);
  const qrHandledRef = useRef(false); // prevent double-fire in the modal
  // Live feedback so the scanner never looks like a dead "Cancel-only" screen:
  //   'searching' → camera up, nothing seen yet
  //   'foreign'   → saw a QR, but it wasn't a capture request
  //   'slow'      → several seconds with nothing found → show a concrete tip
  const [scanFeedback, setScanFeedback] = useState<'searching' | 'foreign' | 'slow'>('searching');
  const scanFeedbackRef = useRef<'searching' | 'foreign' | 'slow'>('searching');
  const setScanFeedbackBoth = useCallback((f: 'searching' | 'foreign' | 'slow') => {
    scanFeedbackRef.current = f;
    setScanFeedback(f);
  }, []);

  // ── Diagnostics panel ─────────────────────────────────────────────────────
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const versionLongPressTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { hasPermission, requestPermission } = useCameraPermission();
  const device = useCameraDevice('back');

  // ── Video import hook ────────────────────────────────────────────────────────
  const [showVideoImportInfo, setShowVideoImportInfo] = useState(false);

  // Always call unconditionally (React hooks rules requirement).
  // When VIDEO_IMPORT is disabled, isNativeBridgeAvailable returns false and
  // handleVideoImport shows the "coming soon" modal instead of invoking import.
  const videoImportHook = useVideoImport(
    useCallback((_frames: import('../hooks/useVideoImport').VideoFramePayload[]) => {
      ReactNativeHapticFeedback.trigger('notificationSuccess', {
        enableVibrateFallback: true,
        ignoreAndroidSystemSettings: false,
      });
      setError(null);
    }, []),
  );

  const { importFromVideo, isImporting, importError, clearError: clearImportError, isNativeBridgeAvailable } = videoImportHook;

  /**
   * Graceful gating: if the native bridge is not linked, show a friendly
   * "Coming Soon" modal with a manual workaround instead of an opaque error.
   */
  const handleVideoImport = useCallback(() => {
    if (!isNativeBridgeAvailable) {
      setShowVideoImportInfo(true);
      return;
    }
    importFromVideo();
  }, [isNativeBridgeAvailable, importFromVideo]);

  // Fold video import error into the shared error banner
  React.useEffect(() => {
    if (importError) setError(importError);
  }, [importError]);

  // ── Request QR code scanner ───────────────────────────────────────────────
  const requestCodeScanner = useCodeScanner({
    codeTypes: ['qr'],
    onCodeScanned: useCallback(
      (codes) => {
        if (!scanningRequest || qrHandledRef.current) return;
        const value = codes[0]?.value;
        if (!value) return;
        // Accept both raw JSON and URI-encoded meow-request:// links
        let json = value;
        if (value.startsWith('meow-request://')) {
          try { json = decodeURIComponent(value.slice('meow-request://'.length)); }
          catch { return; }
        }
        // 1. Preferred: a setup/capture-request QR (carries session + frame count).
        try {
          const request = validateRequestFromString(json);
          qrHandledRef.current = true;
          setScanningRequest(false);
          ReactNativeHapticFeedback.trigger('notificationSuccess', {
            enableVibrateFallback: true,
            ignoreAndroidSystemSettings: false,
          });
          navigateToCapture(request);
          return;
        } catch {
          // not a request — fall through to direct-frame handling
        }

        // 2. No setup QR? Start capture straight from the looping transfer frames.
        //    The frame itself tells us how many source frames to expect, and the
        //    capture screen auto-stops once it has seen the whole loop and
        //    captured enough to recover (loop-exhausted / fountain-complete).
        const expected = deriveExpectedFramesFromFrame(value);
        if (expected !== null) {
          qrHandledRef.current = true;
          setScanningRequest(false);
          ReactNativeHapticFeedback.trigger('notificationSuccess', {
            enableVibrateFallback: true,
            ignoreAndroidSystemSettings: false,
          });
          navigateToCapture({
            action: 'capture',
            session_id: makeSessionId(),
            expected_frames: expected,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
          });
          return;
        }

        // 3. A QR, but not a meow transfer — tell the user rather than sitting silent.
        if (scanFeedbackRef.current !== 'foreign') setScanFeedbackBoth('foreign');
      },
      // eslint-disable-next-line react-hooks/exhaustive-deps
      [scanningRequest],
    ),
  });

  // CodeScanner config in vision-camera 4.x has no onError hook — surface
  // ML-Kit-module-pending errors via the parent <Camera onError> prop instead.
  const onCameraError = useCallback((error: Error) => {
    const msg = error.message?.toLowerCase() ?? '';
    if (msg.includes('module') || msg.includes('download')) {
      setBarcodeModulePending(true);
    }
  }, []);

  const openRequestQrScanner = useCallback(async () => {
    // Guard: no point opening the scanner if there's no physical rear camera.
    if (!device) {
      setError('No rear camera found on this device. Cannot scan a QR code.');
      return;
    }
    let permitted = hasPermission;
    if (!permitted) {
      // Request permission on-demand rather than silently failing — the user
      // may not have gone through onboarding or may have denied then re-enabled.
      permitted = await requestPermission();
    }
    if (!permitted) {
      setError('Camera permission denied. Enable it in Settings → Apps → Meow Capture → Permissions.');
      return;
    }
    qrHandledRef.current = false;
    setBarcodeModulePending(false);
    setScanFeedbackBoth('searching');
    setScanningRequest(true);
  }, [device, hasPermission, requestPermission, setScanFeedbackBoth]);

  // After a few seconds with nothing found, upgrade the hint to a concrete tip
  // instead of leaving the user staring at an apparently-dead camera.
  useEffect(() => {
    if (!scanningRequest) return;
    const timer = setTimeout(() => {
      if (scanFeedbackRef.current === 'searching') setScanFeedbackBoth('slow');
    }, 6_000);
    return () => clearTimeout(timer);
  }, [scanningRequest, setScanFeedbackBoth]);

  // Clear stale error and surface any interrupted session on focus
  useFocusEffect(
    useCallback(() => {
      setError(null);
      clearImportError();
      const cp = readCaptureCheckpoint();
      if (cp && Date.now() - cp.saved_at < 30 * 60 * 1000) {
        setInterruptedSession(cp);
      } else {
        clearCaptureCheckpoint();
        setInterruptedSession(null);
      }
    }, [clearImportError]),
  );

  // Manual entry state
  const [manualMode, setManualMode] = useState(false);
  const [sessionId, setSessionId] = useState('');
  const [expectedFrames, setExpectedFrames] = useState('');
  const [timeoutSecs, setTimeoutSecs] = useState(String(DEFAULT_TIMEOUT_SECONDS));

  const navigateToCapture = useCallback(
    (request: CaptureRequest) => {
      navigation.navigate('Capture', { request });
    },
    [navigation],
  );

  // ── Load from JSON file ────────────────────────────────────────────────────

  const loadFromFile = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      const results = await DocumentPicker.pick({
        type: [DocumentPicker.types.json],
        allowMultiSelection: false,
      });
      // With noUncheckedIndexedAccess, index access can be T | undefined; guard it.
      const result = results[0];
      if (!result) return;

      // On Android, DocumentPicker returns content:// URIs which RNFS cannot
      // read directly. Copy to a temp cache path first, read it, then clean up.
      let readUri: string;
      if (Platform.OS === 'android') {
        const tmpPath = `${RNFS.CachesDirectoryPath}/meow_import_${Date.now()}.json`;
        await RNFS.copyFile(result.uri, tmpPath);
        readUri = tmpPath;
      } else {
        readUri = decodeURIComponent(result.uri);
      }
      const content = await RNFS.readFile(readUri, 'utf8');
      if (Platform.OS === 'android') {
        RNFS.unlink(readUri).catch(() => {}); // best-effort temp cleanup
      }

      const request = validateRequestFromString(content);
      ReactNativeHapticFeedback.trigger('notificationSuccess', { enableVibrateFallback: true, ignoreAndroidSystemSettings: false });
      navigateToCapture(request);
    } catch (err) {
      if (DocumentPicker.isCancel(err)) {
        // User cancelled — not an error
        return;
      }
      if (err instanceof z.ZodError) {
        setError(`Invalid request file: ${firstErrorMessage(err)}. Check that you selected the correct capture-request JSON from meow-encoder.`);
      } else if (err instanceof SyntaxError) {
        setError('This file is not valid JSON. Make sure you selected the .json capture request file generated by meow-encoder, not a different file.');
      } else {
        setError('Could not read the selected file. Check file permissions and try again.');
      }
    } finally {
      setLoading(false);
    }
  }, [navigateToCapture]);

  // ── Manual entry ───────────────────────────────────────────────────────────

  const startManual = useCallback(() => {
    setError(null);
    const rawRequest = {
      action: 'capture',
      session_id: sessionId.trim(),
      expected_frames: parseInt(expectedFrames.trim(), 10),
      timeout_seconds: parseInt(timeoutSecs.trim(), 10) || DEFAULT_TIMEOUT_SECONDS,
    };

    try {
      const request = validateRequestFromString(JSON.stringify(rawRequest));
      navigateToCapture(request);
    } catch (err) {
      if (err instanceof z.ZodError) {
        setError(firstErrorMessage(err));
      } else {
        setError('Invalid input');
      }
    }
  }, [sessionId, expectedFrames, timeoutSecs, navigateToCapture]);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <SafeAreaView style={styles.safe}>
      <KeyboardAvoidingView
        style={styles.flex}
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      >
        <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        {/* Header */}
        <View style={styles.headerRow}>
          <TouchableOpacity
            onPress={() => navigation.navigate('Settings')}
            hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
            accessibilityRole="button"
            accessibilityLabel="Open Settings"
            style={styles.settingsGear}
          >
            <Text style={styles.settingsGearText}>⚙️</Text>
          </TouchableOpacity>
          <Image
            source={meowLogo}
            style={styles.headerLogo}
            resizeMode="contain"
            accessible={false}
          />
          <View style={styles.headerTitleBlock}>
            <Text style={styles.title} accessibilityRole="header">Meow Capture</Text>
            <Text style={styles.domainText}>www.meowdecoder.com</Text>
            <Text style={styles.subtitle}>Secure QR Capture · Air-Gap Transfer</Text>
          </View>
        </View>
        {/* Interrupted session resume banner (enriched) */}
        {interruptedSession && (() => {
          const ageMs = Date.now() - interruptedSession.saved_at;
          const ageMins = Math.round(ageMs / 60_000);
          const shortId = interruptedSession.session_id.slice(0, 8);
          const frameCount = interruptedSession.frame_count;
          return (
            <View
              style={styles.resumeBanner}
              accessibilityLiveRegion="polite"
              accessibilityLabel={`Interrupted session ${shortId} — ${frameCount} frame indices, ${ageMins} minutes ago`}
            >
              <Text style={styles.resumeTitle}>⚡ Interrupted session found</Text>
              {/* React Native on Android rejects null as a Text child in some
               * RN builds — use an empty string for the singular case instead. */}
              <Text style={styles.resumeDetail}>
                ID …{shortId} · {frameCount} frame{frameCount !== 1 ? 's' : ''} · {ageMins < 1 ? 'just now' : `${ageMins}m ago`}
              </Text>
              <Text style={styles.resumeSecurityNote}>
                Frame payloads were not saved — only indices are kept on disk as a security invariant.
                {interruptedSession.request
                  ? ' The original capture request is available — tap Re-open to start a fresh capture with the same session parameters.'
                  : ' Start a fresh session with the same request to recapture.'}
              </Text>
              <View style={styles.resumeActions}>
                {interruptedSession.request && (
                  <TouchableOpacity
                    style={styles.resumeReopenBtn}
                    onPress={() => {
                      const req = interruptedSession.request!;
                      clearCaptureCheckpoint();
                      setInterruptedSession(null);
                      ReactNativeHapticFeedback.trigger('impactMedium', { enableVibrateFallback: true, ignoreAndroidSystemSettings: false });
                      navigateToCapture(req);
                    }}
                    accessibilityRole="button"
                    accessibilityLabel="Re-open the interrupted session with the same capture request"
                  >
                    <Text style={styles.resumeReopenText}>▶ Re-open session</Text>
                  </TouchableOpacity>
                )}
                <TouchableOpacity
                  style={styles.resumeRestartBtn}
                  onPress={() => {
                    clearCaptureCheckpoint();
                    setInterruptedSession(null);
                    ReactNativeHapticFeedback.trigger('impactLight', { enableVibrateFallback: true, ignoreAndroidSystemSettings: false });
                  }}
                  accessibilityRole="button"
                  accessibilityLabel="Dismiss — I understand, start fresh"
                >
                  <Text style={styles.resumeRestartText}>↺ Start fresh</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={styles.resumeWipeBtn}
                  onPress={() => {
                    clearCaptureCheckpoint();
                    setInterruptedSession(null);
                    ReactNativeHapticFeedback.trigger('notificationError', { enableVibrateFallback: true, ignoreAndroidSystemSettings: false });
                  }}
                  accessibilityRole="button"
                  accessibilityLabel="Discard and wipe session record"
                >
                  <Text style={styles.resumeWipeText}>✕ Discard & wipe</Text>
                </TouchableOpacity>
              </View>
            </View>
          );
        })()}

        {/* Error banner */}
        {error && (
          <View
            style={styles.errorBanner}
            accessibilityLiveRegion="assertive"
            accessibilityLabel={error}
          >
            <Text style={styles.errorText}>🙀 {error}</Text>
          </View>
        )}

        {/* Primary action — scan the sender screen */}
        <View style={styles.card}>
          <Text style={styles.cardTitle} accessibilityRole="header">Start Capture</Text>
          <Text style={styles.cardBody}>
            Point your camera at the sender screen to begin. The app will pick up the
            transfer details from the QR code shown there.
          </Text>
          <TouchableOpacity
            style={styles.primaryButton}
            onPress={openRequestQrScanner}
            accessibilityRole="button"
            accessibilityLabel="Scan the sender screen to begin capture"
            accessibilityHint="Opens the camera so the app can read the transfer QR code shown on the desktop"
          >
            <Text style={styles.primaryButtonText}>📷 Scan Sender Screen</Text>
          </TouchableOpacity>
        </View>

        {/* Helper context text */}
        <Text style={styles.captureHelperText}>
          The desktop sender shows a setup QR followed by the transfer itself — keep scanning
          and the app will follow along.
        </Text>

        {/* Advanced setup — fallback paths for the request-first workflow */}
        <View style={styles.advancedHeaderRow}>
          <View style={styles.dividerLine} />
          <Text style={styles.advancedHeaderText}>Advanced setup</Text>
          <View style={styles.dividerLine} />
        </View>
        <Text style={styles.advancedHelperText}>
          Use these only if you have a saved capture request from{' '}
          <Text style={styles.code}>meow-encode</Text> instead of a live sender screen.
        </Text>
        <View style={styles.card}>
          <View style={styles.altButtonRow}>
            <TouchableOpacity
              style={styles.altButton}
              onPress={loadFromFile}
              disabled={loading}
              accessibilityRole="button"
              accessibilityLabel="Import capture request from a JSON file"
              accessibilityHint="Opens file picker to select a JSON capture request saved from meow-encode"
            >
              {loading ? (
                <ActivityIndicator color={Colors.catOrange} size="small" />
              ) : (
                <Text style={styles.altButtonText}>📂 Import request (JSON)</Text>
              )}
            </TouchableOpacity>

            {/* Cat presentation uses the same native fountain QR scanner as the recommended path. */}
            {FEATURE_FLAGS.CAT_MODE && (
              <TouchableOpacity
                style={styles.altButton}
                onPress={() => void openRequestQrScanner()}
                accessibilityRole="button"
                accessibilityLabel="Scan an Experimental Cat Mode fountain transmission"
                accessibilityHint="Opens the native QR scanner and collects encrypted fountain droplets"
              >
                <Text style={styles.altButtonText}>😺 Cat Mode · Experimental</Text>
              </TouchableOpacity>
            )}

            {/* ── Import Video / GIF — hidden when feature flag is off ── */}
            {FEATURE_FLAGS.VIDEO_IMPORT && (
              <TouchableOpacity
                style={styles.altButton}
                onPress={handleVideoImport}
                disabled={isImporting}
                accessibilityRole="button"
                accessibilityLabel="Import a previously recorded video or GIF file"
                accessibilityHint="Opens a file picker to select a video or animated GIF"
              >
                {isImporting ? (
                  <ActivityIndicator color={Colors.catOrange} size="small" />
                ) : (
                  <Text style={styles.altButtonText}>🎞 Import Video</Text>
                )}
              </TouchableOpacity>
            )}
          </View>
        </View>

        {/* ── Request QR scanner modal (item 5) ── */}
        <Modal
          visible={scanningRequest}
          animationType="slide"
          onRequestClose={() => setScanningRequest(false)}
          statusBarTranslucent
          accessibilityViewIsModal
        >
          <View style={styles.qrModalContainer}>
            <Text style={styles.qrModalTitle} accessibilityRole="header">📷 Scan Sender Screen</Text>
            <Text style={styles.qrModalSubtitle}>
              Point at the QR code shown on the sender desktop. The app will pick up the
              transfer details and start capture automatically.
            </Text>

            {device ? (
              barcodeModulePending ? (
                <View style={styles.qrCameraPlaceholder}>
                  <Text style={styles.qrCameraPlaceholderText}>
                    {`⏳ Downloading barcode scanner…\n(requires Google Play Services)\n\nPlease wait a moment, then try again.`}
                  </Text>
                </View>
              ) : (
                // key forces a full Camera unmount when the modal closes,
                // preventing the ML Kit pipeline from error-spamming during dismiss
                <Camera
                  key={scanningRequest ? 'scanner-on' : 'scanner-off'}
                  style={styles.qrCamera}
                  device={device}
                  isActive={scanningRequest && !barcodeModulePending}
                  onError={onCameraError}
                  {...(scanningRequest ? { codeScanner: requestCodeScanner } : {})}
                />
              )
            ) : (
              <View style={styles.qrCameraPlaceholder}>
                <Text style={styles.qrCameraPlaceholderText}>Camera unavailable</Text>
              </View>
            )}

            {/* Live feedback — so an empty frame never reads as a dead screen */}
            {device && !barcodeModulePending && (
              <View
                style={styles.qrFeedbackRow}
                accessibilityLiveRegion="polite"
                accessibilityLabel={scanFeedbackMessage(scanFeedback)}
              >
                {scanFeedback === 'searching' && (
                  <ActivityIndicator color={Colors.catOrange} size="small" />
                )}
                <Text
                  style={[
                    styles.qrFeedbackText,
                    scanFeedback === 'foreign' && styles.qrFeedbackWarn,
                  ]}
                >
                  {scanFeedbackMessage(scanFeedback)}
                </Text>
              </View>
            )}

            <TouchableOpacity
              style={styles.qrCancelButton}
              onPress={() => setScanningRequest(false)}
              accessibilityRole="button"
              accessibilityLabel="Cancel QR scan"
            >
              <Text style={styles.qrCancelText}>✕ Cancel</Text>
            </TouchableOpacity>
          </View>
        </Modal>

        {/* ── Video Import Info modal (F1 — graceful fallback) ── */}
        <Modal
          visible={showVideoImportInfo}
          animationType="fade"
          transparent
          onRequestClose={() => setShowVideoImportInfo(false)}
          accessibilityViewIsModal
        >
          <View style={styles.videoInfoOverlay}>
            <View style={styles.videoInfoCard}>
              <Text style={styles.videoInfoTitle} accessibilityRole="header">
                🎞 Video Import — Coming Soon
              </Text>
              <Text style={styles.videoInfoBody}>
                Direct video import requires a native bridge module that is not yet linked in this build.
              </Text>
              <Text style={[styles.videoInfoBody, { marginTop: Spacing.sm }]}>
                {/* fontWeight must be a TextStyle weight string — cast through the
                 * correct type instead of `as any` to avoid silencing type errors. */}
                <Text style={{ fontWeight: Typography.bold as '700' }}>Workaround:</Text>
                {' '}Record the animated GIF on your phone screen, then use the{' '}
                <Text style={styles.code}>Scan Sender Screen</Text>
                {' '}button to capture frames live from the camera — the fountain codes
                tolerate up to 33% frame loss.
              </Text>
              <TouchableOpacity
                style={styles.videoInfoDismiss}
                onPress={() => setShowVideoImportInfo(false)}
                accessibilityRole="button"
                accessibilityLabel="Dismiss video import info"
              >
                <Text style={styles.videoInfoDismissText}>Got it</Text>
              </TouchableOpacity>
            </View>
          </View>
        </Modal>

        {/* Manual entry — advanced fallback */}
        <TouchableOpacity
          style={styles.manualToggle}
          onPress={() => setManualMode((v) => !v)}
          accessibilityRole="button"
          accessibilityState={{ expanded: manualMode }}
          accessibilityLabel={manualMode ? 'Hide manual session entry form' : 'Show manual session entry form'}
        >
          <Text style={styles.manualToggleText}>
            {manualMode ? '▲ Hide manual session entry' : '▼ Enter session details manually'}
          </Text>
        </TouchableOpacity>

        {manualMode && (
          <View style={styles.card}>
            <LabelledInput
              label="Session ID (UUID)"
              value={sessionId}
              onChangeText={setSessionId}
              placeholder="550e8400-e29b-41d4-a716-446655440000"
              autoCapitalize="none"
              autoCorrect={false}
            />
            <LabelledInput
              label="Expected Frames"
              value={expectedFrames}
              onChangeText={setExpectedFrames}
              placeholder="45"
              keyboardType="number-pad"
            />
            <LabelledInput
              label={`Timeout (seconds, default ${DEFAULT_TIMEOUT_SECONDS})`}
              value={timeoutSecs}
              onChangeText={setTimeoutSecs}
              placeholder={String(DEFAULT_TIMEOUT_SECONDS)}
              keyboardType="number-pad"
            />
            <TouchableOpacity
              style={styles.primaryButton}
              onPress={startManual}
              accessibilityRole="button"
              accessibilityLabel="Start capture with manual session details"
            >
              <Text style={styles.primaryButtonText}>🐾 Start Capture</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* Info footer */}
        <View style={styles.footer}>
          <Text style={styles.footerText}>
            Frames are exported as JSON to Downloads for USB retrieval.
            No data is transmitted over the network.
          </Text>
        </View>
      </ScrollView>
      </KeyboardAvoidingView>
      {/* Version badge — absolute bottom-right corner, long-press 1.5 s to open diagnostics */}
      <TouchableOpacity
        style={styles.versionCorner}
        onPressIn={() => {
          versionLongPressTimer.current = setTimeout(() => setShowDiagnostics(true), 1500);
        }}
        onPressOut={() => {
          if (versionLongPressTimer.current) clearTimeout(versionLongPressTimer.current);
        }}
        accessibilityRole="text"
        accessibilityLabel={`Version ${APP_VERSION}. Long-press for diagnostics.`}
        hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
      >
        <Text style={styles.versionBadge}>v{APP_VERSION}</Text>
      </TouchableOpacity>
      <DiagnosticsPanel
        visible={showDiagnostics}
        onDismiss={() => setShowDiagnostics(false)}
        {...(interruptedSession?.session_id !== undefined ? { sessionId: interruptedSession.session_id } : {})}
        framesCaptured={interruptedSession?.frame_count ?? 0}
      />
    </SafeAreaView>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scanFeedbackMessage(state: 'searching' | 'foreign' | 'slow'): string {
  switch (state) {
    case 'foreign':
      return "That QR isn't a capture request — point at the small setup QR the sender shows first.";
    case 'slow':
      return 'Still looking… make sure the sender\'s setup QR is on screen and fills the frame, with good light and no glare.';
    case 'searching':
    default:
      return '🔍 Looking for the sender\'s QR code…';
  }
}

// ── Sub-component ─────────────────────────────────────────────────────────────

function LabelledInput({
  label,
  ...props
}: { label: string } & React.ComponentProps<typeof TextInput>) {
  return (
    <View style={inputStyles.container}>
      <Text style={inputStyles.label} accessibilityRole="text">{label}</Text>
      <TextInput
        style={inputStyles.input}
        placeholderTextColor={Colors.textDisabled}
        accessibilityLabel={label}
        {...props}
      />
    </View>
  );
}

const inputStyles = StyleSheet.create({
  container: { marginBottom: Spacing.md },
  input: {
    backgroundColor: Colors.backgroundTertiary,
    borderColor: Colors.surfaceBorder,
    borderRadius: Radius.sm,
    borderWidth: 1,
    color: Colors.textPrimary,
    fontSize: Typography.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
  },
  label: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    marginBottom: Spacing.xxs,
  },
});

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  safe: { backgroundColor: Colors.background, flex: 1 },
  flex: { flex: 1 },
  scroll: { padding: Spacing.lg, paddingBottom: Spacing.xxxl },
  title: {
    color: Colors.catOrange,
    fontSize: Typography.xxl,
    fontWeight: Typography.heavy,
    textAlign: 'left',
  },
  subtitle: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    marginTop: 2,
    textAlign: 'left',
  },
  headerRow: {
    alignItems: 'center',
    marginBottom: Spacing.xs,
    marginTop: Spacing.xl,
  },
  headerLogo: {
    height: 160,
    marginBottom: Spacing.sm,
    width: 160,
  },
  headerTitleBlock: {
    alignItems: 'center',
  },
  domainText: {
    color: Colors.accent,
    fontSize: Typography.xs,
    marginBottom: 2,
    marginTop: 2,
    opacity: 0.5,
  },
  settingsGear: {
    padding: 4,
    position: 'absolute',
    right: 0,
    top: 0,
  },
  settingsGearText: {
    fontSize: 22,
  },
  versionCorner: {
    bottom: 8,
    position: 'absolute',
    right: 12,
  },
  versionBadge: {
    color: Colors.textSecondary,
    fontSize: Typography.xs ?? 10,
    opacity: 0.35,
  },
  errorBanner: {
    backgroundColor: 'rgba(255,59,48,0.15)',
    borderLeftColor: Colors.danger,
    borderLeftWidth: 3,
    borderRadius: Radius.md,
    marginBottom: Spacing.md,
    padding: Spacing.md,
  },
  errorText: {
    color: Colors.danger,
    fontSize: Typography.sm,
  },
  card: {
    backgroundColor: Colors.backgroundSecondary,
    borderRadius: Radius.lg,
    marginBottom: Spacing.lg,
    padding: Spacing.lg,
    ...Shadows.subtle,
  },
  cardTitle: {
    color: Colors.textPrimary,
    fontSize: Typography.lg,
    fontWeight: Typography.semibold,
    marginBottom: Spacing.xs,
  },
  cardBody: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    lineHeight: Typography.sm * 1.5,
    marginBottom: Spacing.lg,
  },
  code: {
    color: Colors.catOrangeLight,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  primaryButton: {
    alignItems: 'center',
    backgroundColor: Colors.catOrange,
    borderRadius: Radius.full,
    paddingVertical: Spacing.md,
  },
  primaryButtonText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.bold,
  },
  dividerLine: {
    backgroundColor: Colors.surfaceBorder,
    flex: 1,
    height: 1,
  },
  manualToggle: { alignItems: 'center', marginVertical: Spacing.md },
  manualToggleText: {
    color: Colors.catOrange,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
  footer: {
    alignItems: 'center',
    marginTop: Spacing.xl,
  },
  footerText: {
    color: Colors.textTertiary,
    fontSize: Typography.xs,
    lineHeight: Typography.xs * 1.6,
    textAlign: 'center',
  },
  resumeBanner: {
    backgroundColor: 'rgba(255,200,50,0.12)',
    borderLeftColor: Colors.catGold,
    borderLeftWidth: 3,
    borderRadius: Radius.lg,
    marginBottom: Spacing.md,
    padding: Spacing.md,
  },
  resumeTitle: {
    color: Colors.catGold,
    fontSize: Typography.md,
    fontWeight: Typography.semibold,
    marginBottom: Spacing.xxs,
  },
  resumeDetail: {
    color: Colors.textSecondary,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    fontSize: Typography.sm,
    marginBottom: Spacing.xs,
  },
  resumeSecurityNote: {
    color: Colors.textTertiary,
    fontSize: Typography.xs,
    lineHeight: Typography.xs * 1.5,
    marginBottom: Spacing.sm,
  },
  resumeActions: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: Spacing.sm,
  },
  resumeReopenBtn: {
    alignItems: 'center',
    backgroundColor: Colors.catOrange,
    borderRadius: Radius.full,
    flex: 2,
    marginBottom: Spacing.xxs,
    minWidth: '100%',
    paddingVertical: Spacing.xs,
  },
  resumeReopenText: {
    color: Colors.textPrimary,
    fontSize: Typography.sm,
    fontWeight: Typography.bold,
  },
  resumeRestartBtn: {
    alignItems: 'center',
    backgroundColor: 'rgba(255,200,50,0.18)',
    borderRadius: Radius.full,
    flex: 1,
    paddingVertical: Spacing.xs,
  },
  resumeRestartText: {
    color: Colors.catGold,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
  resumeWipeBtn: {
    alignItems: 'center',
    backgroundColor: 'rgba(255,59,48,0.15)',
    borderRadius: Radius.full,
    flex: 1,
    paddingVertical: Spacing.xs,
  },
  resumeWipeText: {
    color: Colors.danger,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
  // ── Alt entry-path buttons (QR scan + video import) ──────────────────────
  altButtonRow: {
    flexDirection: 'row',
    gap: Spacing.sm,
    marginTop: Spacing.sm,
  },
  altButton: {
    alignItems: 'center',
    backgroundColor: Colors.backgroundTertiary,
    borderColor: Colors.surfaceBorder,
    borderRadius: Radius.full,
    borderWidth: 1,
    flex: 1,
    paddingVertical: Spacing.sm,
  },
  altButtonText: {
    color: Colors.catOrange,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
  captureHelperText: {
    color: Colors.textSecondary,
    fontSize: Typography.xs ?? 11,
    marginBottom: Spacing.xs,
    marginTop: Spacing.sm,
    opacity: 0.65,
    paddingHorizontal: Spacing.xl,
    textAlign: 'center',
  },
  advancedHeaderRow: {
    alignItems: 'center',
    flexDirection: 'row',
    marginBottom: Spacing.sm,
    marginTop: Spacing.xl,
  },
  advancedHeaderText: {
    color: Colors.textTertiary,
    fontSize: Typography.xs ?? 11,
    letterSpacing: 1,
    marginHorizontal: Spacing.sm,
    textTransform: 'uppercase',
  },
  advancedHelperText: {
    color: Colors.textTertiary,
    fontSize: Typography.xs ?? 11,
    lineHeight: (Typography.xs ?? 11) * 1.5,
    marginBottom: Spacing.md,
    opacity: 0.7,
    paddingHorizontal: Spacing.xl,
    textAlign: 'center',
  },
  // ── Request QR scanner modal ──────────────────────────────────────────────
  qrModalContainer: {
    alignItems: 'center',
    backgroundColor: Colors.background,
    flex: 1,
    paddingHorizontal: Spacing.lg,
    paddingTop: Platform.OS === 'ios' ? 64 : 48,
  },
  qrModalTitle: {
    color: Colors.textPrimary,
    fontSize: Typography.xl,
    fontWeight: Typography.bold,
    marginBottom: Spacing.xs,
  },
  qrModalSubtitle: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    lineHeight: Typography.sm * 1.5,
    marginBottom: Spacing.xl,
    textAlign: 'center',
  },
  qrCamera: {
    aspectRatio: 1,
    borderRadius: Radius.lg,
    marginBottom: Spacing.xl,
    overflow: 'hidden',
    width: '100%',
  },
  qrCameraPlaceholder: {
    alignItems: 'center',
    aspectRatio: 1,
    backgroundColor: Colors.backgroundSecondary,
    borderRadius: Radius.lg,
    justifyContent: 'center',
    marginBottom: Spacing.xl,
    width: '100%',
  },
  qrCameraPlaceholderText: {
    color: Colors.textTertiary,
    fontSize: Typography.md,
  },
  qrFeedbackRow: {
    alignItems: 'center',
    flexDirection: 'row',
    gap: Spacing.sm,
    justifyContent: 'center',
    marginBottom: Spacing.lg,
    minHeight: 24,
    paddingHorizontal: Spacing.lg,
  },
  qrFeedbackText: {
    color: Colors.textSecondary,
    flexShrink: 1,
    fontSize: Typography.sm,
    textAlign: 'center',
  },
  qrFeedbackWarn: {
    color: Colors.catGold,
  },
  qrCancelButton: {
    backgroundColor: 'rgba(255,59,48,0.85)',
    borderRadius: Radius.full,
    paddingHorizontal: Spacing.xxxl,
    paddingVertical: Spacing.md,
  },
  qrCancelText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.bold,
  },
  // ── Video Import Info modal (F1) ──────────────────────────────────────────
  videoInfoOverlay: {
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.6)',
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: Spacing.lg,
  },
  videoInfoCard: {
    backgroundColor: Colors.backgroundSecondary,
    borderRadius: Radius.lg,
    maxWidth: 380,
    padding: Spacing.xl,
    width: '100%',
    ...Shadows.subtle,
  },
  videoInfoTitle: {
    color: Colors.catOrange,
    fontSize: Typography.lg,
    fontWeight: Typography.bold,
    marginBottom: Spacing.md,
    textAlign: 'center',
  },
  videoInfoBody: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    lineHeight: Typography.sm * 1.5,
  },
  videoInfoDismiss: {
    alignItems: 'center',
    backgroundColor: Colors.catOrange,
    borderRadius: Radius.full,
    justifyContent: 'center',
    marginTop: Spacing.lg,
    minHeight: 44,
    paddingVertical: Spacing.sm,
  },
  videoInfoDismissText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.bold,
  },
});
