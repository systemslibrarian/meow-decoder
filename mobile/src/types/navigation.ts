/**
 * navigation.ts — React Navigation parameter types.
 *
 * Defining these explicitly enforces type-safe navigation throughout the app
 * and prevents accidental data leaks via untyped route params.
 */

import type { NativeStackNavigationProp, NativeStackScreenProps } from '@react-navigation/native-stack';
import type { CaptureRequest, CaptureResponse } from './capture';

// ── Root Stack ────────────────────────────────────────────────────────────────

/**
 * Root stack navigator param list.
 * All screens are defined here for type inference.
 */
export type RootStackParamList = {
  /** Animated splash / loading screen */
  Splash: undefined;
  /** First-run onboarding: air-gap explanation + camera permission */
  Onboarding: undefined;
  /** Main home screen: load request or start manual session */
  Home: undefined;
  /** Live camera capture screen */
  Capture: {
    /** The validated capture request loaded from JSON file or manual entry */
    request: CaptureRequest;
  };
  /** Results review + export screen */
  Export: {
    /** The completed capture response to export */
    response: CaptureResponse;
    /** Whether capture completed fully, partially (timeout), or manually stopped */
    reason: 'complete' | 'timeout' | 'manual';
  };
};

// ── Convenience Screen Props Types ───────────────────────────────────────────

export type SplashScreenProps = NativeStackScreenProps<RootStackParamList, 'Splash'>;
export type OnboardingScreenProps = NativeStackScreenProps<RootStackParamList, 'Onboarding'>;
export type HomeScreenProps = NativeStackScreenProps<RootStackParamList, 'Home'>;
export type CaptureScreenProps = NativeStackScreenProps<RootStackParamList, 'Capture'>;
export type ExportScreenProps = NativeStackScreenProps<RootStackParamList, 'Export'>;

// ── Navigation Prop Shortcuts ─────────────────────────────────────────────────

export type AppNavigationProp = NativeStackNavigationProp<RootStackParamList>;
