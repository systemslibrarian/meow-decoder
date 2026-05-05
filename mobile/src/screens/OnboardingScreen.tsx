/**
 * OnboardingScreen.tsx — First-run air-gap explanation and camera permission.
 *
 * Explains the security model in plain language before requesting
 * the camera permission. Only shown once; subsequent launches go
 * directly to HomeScreen.
 */

import React, { useCallback, useState } from 'react';
import {
  View,
  Text,
  Image,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  SafeAreaView,
  Linking,
} from 'react-native';
import { useCameraPermission } from 'react-native-vision-camera';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';
import { MMKV } from 'react-native-mmkv';
import type { OnboardingScreenProps } from '../types/navigation';
import meowLogo from '../assets/meow-decoder-logo-notagline.png';

// MMKV instance — same id/key as App.tsx so both read the same value
const storage = new MMKV({ id: 'meow_settings' });
const FIRST_LAUNCH_KEY = 'has_completed_onboarding';

// ── Screen ────────────────────────────────────────────────────────────────────

export function OnboardingScreen({ navigation }: OnboardingScreenProps) {
  const { requestPermission } = useCameraPermission();
  const [permissionDenied, setPermissionDenied] = useState(false);

  const handleGrant = useCallback(async () => {
    const granted = await requestPermission();
    if (granted) {
      storage.set(FIRST_LAUNCH_KEY, true);
      navigation.replace('Home');
    } else {
      setPermissionDenied(true);
    }
  }, [requestPermission, navigation]);

  const handleSkip = useCallback(() => {
    storage.set(FIRST_LAUNCH_KEY, true);
    navigation.replace('Home');
  }, [navigation]);

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll} bounces={false}>
        {/* Hero */}
        <Image source={meowLogo} style={styles.heroLogo} resizeMode="contain" />
        <Text style={styles.title}>Welcome to Meow Capture</Text>
        <Text style={styles.subtitle}>Move files offline — the phone is the bridge.</Text>

        {/* How it works */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>How it works</Text>
          {STEPS.map((step) => (
            <View key={step.number} style={styles.step}>
              <View style={styles.stepNumber}>
                <Text style={styles.stepNumberText}>{step.number}</Text>
              </View>
              <View style={styles.stepContent}>
                <Text style={styles.stepTitle}>{step.title}</Text>
                <Text style={styles.stepBody}>{step.body}</Text>
              </View>
            </View>
          ))}
        </View>

        {/* Security guarantees */}
        <View style={[styles.section, styles.securityBox]}>
          <Text style={styles.sectionTitle}>🔒 Security guarantees</Text>
          {SECURITY_POINTS.map((point, i) => (
            <Text key={i} style={styles.securityPoint}>
              {'✓ '}{point}
            </Text>
          ))}
        </View>

        {/* Camera permission rationale */}
        <View style={styles.section}>
          <Text style={styles.permissionRationale}>
            The camera is how the phone reads the transfer from the sender screen.
            Nothing is stored, transmitted, or shared. Camera is the{' '}
            <Text style={styles.bold}>only</Text> permission requested.
          </Text>
        </View>

        {/* CTA */}
        <TouchableOpacity
          style={styles.primaryButton}
          onPress={handleGrant}
          accessibilityRole="button"
        >
          <Text style={styles.primaryButtonText}>Allow Camera  →</Text>
        </TouchableOpacity>
        {permissionDenied && (
          <>
            <Text style={styles.deniedText}>
              Camera access was denied. To use meow-decoder, enable it in Settings.
            </Text>
            <TouchableOpacity
              style={[styles.primaryButton, styles.settingsButton]}
              onPress={() => Linking.openSettings()}
              accessibilityRole="button"
              accessibilityLabel="Open Settings to enable camera access"
            >
              <Text style={styles.primaryButtonText}>⚙️ Open Settings</Text>
            </TouchableOpacity>
          </>
        )}
        <TouchableOpacity onPress={handleSkip} accessibilityRole="button">
          <Text style={styles.skipText}>Skip for now</Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

// ── Content ───────────────────────────────────────────────────────────────────

const STEPS = [
  {
    number: '1',
    title: 'Open the sender on your computer',
    body: 'Encrypt a file with meow-decoder (CLI or web demo). The sender will show a transfer on screen.',
  },
  {
    number: '2',
    title: 'Scan the sender screen',
    body: 'Tap Scan Sender Screen, point your phone at the QR, and hold steady. The app will tell you when capture is complete.',
  },
  {
    number: '3',
    title: 'Export and recover',
    body: 'Export the captured transfer, then move it to your receiving computer to recover the original file.',
  },
];

const SECURITY_POINTS = [
  'No decryption on device — the phone is a sensor, not a trust anchor',
  'No network access — the app makes no outbound connections',
  'Frame data cleared on app background or cancel',
  'Keys and passwords never touch this device',
];

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: Colors.background },
  scroll: {
    padding: Spacing.lg,
    paddingBottom: Spacing.xxxl,
    alignItems: 'center',
  },
  hero: { fontSize: 80, marginTop: Spacing.xl, marginBottom: Spacing.md },
  heroLogo: {
    width: 120,
    height: 94,
    marginTop: Spacing.xl,
    marginBottom: Spacing.md,
  },
  title: {
    color: Colors.textPrimary,
    fontSize: Typography.xl,
    fontWeight: Typography.bold,
    textAlign: 'center',
  },
  subtitle: {
    color: Colors.textSecondary,
    fontSize: Typography.md,
    marginTop: Spacing.xs,
    marginBottom: Spacing.xl,
    textAlign: 'center',
  },
  section: {
    width: '100%',
    marginBottom: Spacing.xl,
  },
  sectionTitle: {
    color: Colors.catOrange,
    fontSize: Typography.lg,
    fontWeight: Typography.semibold,
    marginBottom: Spacing.md,
  },
  step: {
    flexDirection: 'row',
    marginBottom: Spacing.md,
    alignItems: 'flex-start',
  },
  stepNumber: {
    width: 32,
    height: 32,
    borderRadius: Radius.full,
    backgroundColor: Colors.catOrange,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: Spacing.md,
    marginTop: 2,
  },
  stepNumberText: {
    color: Colors.textPrimary,
    fontSize: Typography.sm,
    fontWeight: Typography.bold,
  },
  stepContent: { flex: 1 },
  stepTitle: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.semibold,
    marginBottom: 2,
  },
  stepBody: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    lineHeight: Typography.sm * 1.5,
  },
  securityBox: {
    backgroundColor: Colors.backgroundSecondary,
    borderRadius: Radius.md,
    padding: Spacing.md,
    borderLeftWidth: 3,
    borderLeftColor: Colors.success,
  },
  securityPoint: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    lineHeight: Typography.sm * 1.8,
  },
  permissionRationale: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    textAlign: 'center',
    lineHeight: Typography.sm * 1.6,
  },
  bold: { fontWeight: Typography.bold, color: Colors.textPrimary },
  primaryButton: {
    backgroundColor: Colors.catOrange,
    paddingHorizontal: Spacing.xxl,
    paddingVertical: Spacing.md,
    borderRadius: Radius.full,
    marginBottom: Spacing.md,
    width: '100%',
    alignItems: 'center',
  },
  primaryButtonText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.bold,
  },
  skipText: {
    color: Colors.textTertiary,
    fontSize: Typography.sm,
  },
  deniedText: {
    color: Colors.danger,
    fontSize: Typography.sm,
    textAlign: 'center',
    marginBottom: Spacing.md,
    lineHeight: Typography.sm * 1.5,
  },
  settingsButton: {
    backgroundColor: Colors.backgroundSecondary,
    borderWidth: 1,
    borderColor: Colors.catOrange,
    marginBottom: Spacing.md,
  },
});
