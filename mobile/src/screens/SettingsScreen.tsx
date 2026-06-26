/**
 * SettingsScreen.tsx — App-wide settings with strict/convenience toggle.
 *
 * Accessible from HomeScreen via the gear icon in the top-right header.
 * No network calls; no analytics; no telemetry.
 */

import React, { useCallback, useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  Switch,
  StyleSheet,
  ScrollView,
  Platform,
  StatusBar,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useNavigation } from '@react-navigation/native';
import { SecurityMode, useSecurityMode } from '../hooks/useSecurityMode';
import { isSoundEnabled, setSoundEnabled } from '../hooks/useAudioCues';
import { isCalibrationEnabled, setCalibrationEnabled } from '../utils/captureSettings';
import { Typography } from '../constants/theme';
import { APP_VERSION } from '../constants/config';
import type { SettingsScreenProps } from '../types/navigation';

// ── Colours (duplicated from theme rather than adding a dep here) ─────────────
const colors = {
  bg: '#0a0a0f',
  card: '#13131a',
  border: '#1e1e2a',
  catGold: '#f5c842',
  catGoldMuted: '#b8933a',
  textPrimary: '#e8e8f0',
  textSecondary: '#8888a8',
  textMono: '#a0d4b8',
  modeStrictBg: '#1a1a2a',
  modeConvBg: '#1a2218',
  modeStrictBorder: '#3a3a60',
  modeConvBorder: '#2a4030',
  modeStrictLabel: '#8888c8',
  modeConvLabel: '#60a878',
  selectedBg: '#1e1e30',
  selectedBorder: '#f5c842',
};

// ── Mode option data ──────────────────────────────────────────────────────────

interface ModeOption {
  id: SecurityMode;
  emoji: string;
  title: string;
  subtitle: string;
  pros: string[];
  cons: string[];
  bgColor: string;
  borderColor: string;
  labelColor: string;
}

const MODE_OPTIONS: ModeOption[] = [
  {
    id: 'strict',
    emoji: '🔒',
    title: 'Strict',
    subtitle: 'Maximum paranoia — recommended for adversarial environments.',
    pros: [
      'Frame data wiped on any background/inactive transition',
      'No session resume across app restarts',
      'Clipboard helper never auto-copies',
      'Privacy overlay on task-switcher (FLAG_SECURE + iOS blur)',
    ],
    cons: ['You must complete capture in one uninterrupted session'],
    bgColor: colors.modeStrictBg,
    borderColor: colors.modeStrictBorder,
    labelColor: colors.modeStrictLabel,
  },
  {
    id: 'convenience',
    emoji: '🟢',
    title: 'Convenience',
    subtitle: 'Sensible default for everyday air-gap use at home or the office.',
    pros: [
      'Session checkpoint persists across app restarts (indices only — no payload data)',
      'ADB pull command auto-copies to clipboard after export',
      'Background wipe still fires — payload strings are never retained',
      'FLAG_SECURE and iOS overlay still active',
    ],
    cons: [
      'Checkpoint indices written to MMKV (never payload data)',
      'Clipboard may briefly hold ADB command string',
    ],
    bgColor: colors.modeConvBg,
    borderColor: colors.modeConvBorder,
    labelColor: colors.modeConvLabel,
  },
];

// ── Component ─────────────────────────────────────────────────────────────────

export const SettingsScreen: React.FC<SettingsScreenProps> = () => {
  const insets = useSafeAreaInsets();
  const navigation = useNavigation();
  const { mode, setMode } = useSecurityMode();
  const [soundOn, setSoundOn] = useState(() => isSoundEnabled());
  const [calibrationOn, setCalibrationOn] = useState(() => isCalibrationEnabled());

  const handleSelectMode = useCallback(
    (next: SecurityMode) => {
      setMode(next);
    },
    [setMode],
  );

  return (
    <View style={[styles.container, { paddingTop: insets.top }]}>
      <StatusBar barStyle="light-content" backgroundColor={colors.bg} />

      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity
          onPress={() => navigation.goBack()}
          hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
          accessibilityRole="button"
          accessibilityLabel="Back"
        >
          <Text style={styles.backChevron}>‹</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Settings</Text>
        <View style={styles.headerSpacer} />
      </View>

      <ScrollView
        contentContainerStyle={[styles.scroll, { paddingBottom: insets.bottom + 32 }]}
        showsVerticalScrollIndicator={false}
      >
        {/* Section title */}
        <Text style={styles.sectionLabel} accessibilityRole="header">SECURITY MODE</Text>
        <Text style={styles.sectionDescription}>
          Controls what happens when the app backgrounds, whether sessions
          persist, and clipboard behaviour. Cryptographic strength is{' '}
          <Text style={styles.emphasisText}>identical in both modes.</Text>
        </Text>

        {/* Mode cards */}
        {MODE_OPTIONS.map(opt => {
          const selected = mode === opt.id;
          return (
            <TouchableOpacity
              key={opt.id}
              style={[
                styles.modeCard,
                { backgroundColor: opt.bgColor, borderColor: opt.borderColor },
                selected && styles.modeCardSelected,
              ]}
              onPress={() => handleSelectMode(opt.id)}
              accessibilityRole="radio"
              accessibilityState={{ checked: selected }}
              accessibilityLabel={`${opt.title} mode. ${opt.subtitle}`}
            >
              {/* Card header */}
              <View style={styles.modeCardHeader}>
                <Text style={styles.modeEmoji}>{opt.emoji}</Text>
                <View style={styles.modeTitleRow}>
                  <Text style={[styles.modeTitle, { color: opt.labelColor }]}>
                    {opt.title}
                  </Text>
                  {opt.id === 'strict' && (
                    <View style={styles.recommendedPill}>
                      <Text style={styles.recommendedText}>Recommended</Text>
                    </View>
                  )}
                </View>
                {selected && <Text style={styles.checkmark}>✓</Text>}
              </View>

              {/* Subtitle */}
              <Text style={styles.modeSubtitle}>{opt.subtitle}</Text>

              {/* Pros */}
              <View style={styles.modeDetailsSection}>
                {opt.pros.map((pro, i) => (
                  <Text key={i} style={styles.proBullet}>
                    {'  ✓  '}
                    {pro}
                  </Text>
                ))}
              </View>

              {/* Cons */}
              {opt.cons.length > 0 && (
                <View style={styles.modeDetailsSection}>
                  {opt.cons.map((con, i) => (
                    <Text key={i} style={styles.conBullet}>
                      {'  ·  '}
                      {con}
                    </Text>
                  ))}
                </View>
              )}
            </TouchableOpacity>
          );
        })}

        {/* Security disclaimer */}
        <View style={styles.disclaimerCard}>
          <Text style={styles.disclaimerTitle} accessibilityRole="header">🔐 What never changes</Text>
          <Text style={styles.disclaimerBody}>
            Regardless of the mode you choose:{'\n'}
            {'  · '}AES-256-GCM encryption with Argon2id key derivation{'\n'}
            {'  · '}No network permissions declared (zero internet access){'\n'}
            {'  · '}Frame payload strings wiped from JS memory on background{'\n'}
            {'  · '}FLAG_SECURE active (screen blocked from screenshots / task-switcher){'\n'}
            {'  · '}Panic wipe (3 s long-press on Capture HUD) always available{'\n'}
            {'  · '}Biometric gate on export
          </Text>
        </View>

        {/* Sound settings */}
        <Text style={styles.sectionLabel} accessibilityRole="header">AUDIO</Text>
        <View style={styles.soundRow}>
          <View style={styles.soundLabelRow}>
            <Text
              style={styles.soundLabel}
              maxFontSizeMultiplier={1.4}
            >
              Sound effects
            </Text>
            <Text
              style={styles.soundDescription}
              maxFontSizeMultiplier={1.4}
            >
              Play subtle audio cues at capture milestones (25%, 50%, 75%, done).
              Helpful for eyes-free or headphone operation.
            </Text>
          </View>
          <Switch
            value={soundOn}
            onValueChange={(v) => {
              setSoundOn(v);
              setSoundEnabled(v);
            }}
            trackColor={{ false: colors.border, true: colors.catGoldMuted }}
            thumbColor={soundOn ? colors.catGold : '#ccc'}
            accessibilityRole="switch"
            accessibilityLabel="Sound effects"
            accessibilityState={{ checked: soundOn }}
            accessibilityHint="Toggle audio feedback during capture milestones"
            style={styles.soundSwitch}
          />
        </View>

        {/* Capture calibration settings */}
        <Text style={styles.sectionLabel} accessibilityRole="header">CAPTURE</Text>
        <View style={styles.soundRow}>
          <View style={styles.soundLabelRow}>
            <Text style={styles.soundLabel} maxFontSizeMultiplier={1.4}>
              Pre-capture calibration
            </Text>
            <Text style={styles.soundDescription} maxFontSizeMultiplier={1.4}>
              Show the guided light/distance check before each capture. Off by default —
              on some phones it can briefly tie up the camera and delay the start of capture.
            </Text>
          </View>
          <Switch
            value={calibrationOn}
            onValueChange={(v) => {
              setCalibrationOn(v);
              setCalibrationEnabled(v);
            }}
            trackColor={{ false: colors.border, true: colors.catGoldMuted }}
            thumbColor={calibrationOn ? colors.catGold : '#ccc'}
            accessibilityRole="switch"
            accessibilityLabel="Pre-capture calibration"
            accessibilityState={{ checked: calibrationOn }}
            accessibilityHint="Toggle the guided calibration step before capture"
            style={styles.soundSwitch}
          />
        </View>

        {/* Version */}
        <Text style={styles.versionText}>Meow Capture v{APP_VERSION}</Text>
      </ScrollView>
    </View>
  );
};

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.bg,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  backChevron: {
    fontSize: 28,
    color: colors.catGold,
    lineHeight: 32,
    marginRight: 4,
  },
  headerTitle: {
    flex: 1,
    fontSize: 17,
    fontWeight: '600',
    color: colors.textPrimary,
    textAlign: 'center',
  },
  headerSpacer: { width: 32 },
  scroll: {
    paddingHorizontal: 16,
    paddingTop: 24,
  },
  sectionLabel: {
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 1.2,
    color: colors.textSecondary,
    marginBottom: 6,
  },
  sectionDescription: {
    fontSize: 13,
    color: colors.textSecondary,
    lineHeight: 19,
    marginBottom: 20,
  },
  emphasisText: {
    color: colors.textPrimary,
    fontWeight: '600',
  },
  modeCard: {
    borderWidth: 1,
    borderRadius: 12,
    padding: 14,
    marginBottom: 12,
  },
  modeCardSelected: {
    borderColor: colors.selectedBorder,
    borderWidth: 2,
  },
  modeCardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 6,
  },
  modeEmoji: {
    fontSize: 20,
    marginRight: 8,
  },
  modeTitleRow: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  modeTitle: {
    fontSize: 16,
    fontWeight: '700',
  },
  recommendedPill: {
    backgroundColor: '#2a2a10',
    borderRadius: 8,
    paddingHorizontal: 7,
    paddingVertical: 2,
    borderWidth: 1,
    borderColor: colors.catGoldMuted,
  },
  recommendedText: {
    fontSize: 10,
    color: colors.catGoldMuted,
    fontWeight: '600',
  },
  checkmark: {
    fontSize: 18,
    color: colors.catGold,
    marginLeft: 8,
  },
  modeSubtitle: {
    fontSize: 12,
    color: colors.textSecondary,
    lineHeight: 17,
    marginBottom: 10,
  },
  modeDetailsSection: {
    marginTop: 4,
  },
  proBullet: {
    fontSize: 12,
    color: '#70c890',
    lineHeight: 19,
  },
  conBullet: {
    fontSize: 12,
    color: colors.textSecondary,
    lineHeight: 19,
  },
  disclaimerCard: {
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    padding: 14,
    marginTop: 8,
    marginBottom: 24,
    backgroundColor: colors.card,
  },
  disclaimerTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: colors.textPrimary,
    marginBottom: 8,
  },
  disclaimerBody: {
    fontSize: 12,
    color: colors.textSecondary,
    lineHeight: 20,
    fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace' }),
  },
  versionText: {
    fontSize: 11,
    color: colors.textSecondary,
    textAlign: 'center',
    opacity: 0.5,
  },
  // Sound toggle
  soundRow: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.card,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    padding: 14,
    marginBottom: 24,
    gap: 12,
  },
  soundLabelRow: {
    flex: 1,
  },
  soundLabel: {
    fontSize: Typography.md,
    fontWeight: '600',
    color: colors.textPrimary,
    marginBottom: 4,
  },
  soundDescription: {
    fontSize: Typography.sm,
    color: colors.textSecondary,
    lineHeight: Typography.sm * 1.4,
  },
  soundSwitch: {
    // Ensure the switch doesn't get squeezed when dynamic type scales up labels
    flexShrink: 0,
  },
});

export default SettingsScreen;
