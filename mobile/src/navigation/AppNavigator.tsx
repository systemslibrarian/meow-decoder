/**
 * AppNavigator.tsx — Stack navigator wiring all screens.
 *
 * Uses a native stack for maximum performance on camera-heavy flows.
 * Enables swipe-back on iOS; disables gesture on CaptureScreen to prevent
 * accidental dismissal mid-scan.
 */

import React from 'react';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../types/navigation';
import { SplashScreen } from '../screens/SplashScreen';
import { OnboardingScreen } from '../screens/OnboardingScreen';
import { HomeScreen } from '../screens/HomeScreen';
import { CaptureScreen } from '../screens/CaptureScreen';
import { ExportScreen } from '../screens/ExportScreen';
import { Colors } from '../constants/theme';

// ── Types ─────────────────────────────────────────────────────────────────────

interface AppNavigatorProps {
  initialRoute: keyof RootStackParamList;
  hasCompletedOnboarding: boolean;
  onOnboardingComplete: () => void;
}

// ── Navigator ─────────────────────────────────────────────────────────────────

const Stack = createNativeStackNavigator<RootStackParamList>();

export function AppNavigator({
  initialRoute,
  hasCompletedOnboarding,
}: AppNavigatorProps): React.ReactElement {
  return (
    <Stack.Navigator
      initialRouteName={initialRoute}
      screenOptions={{
        headerShown: false,
        contentStyle: { backgroundColor: Colors.background },
        animation: 'fade',
      }}
    >
      <Stack.Screen name="Splash" component={SplashScreen} />

      <Stack.Screen
        name="Onboarding"
        component={OnboardingScreen}
        options={{ gestureEnabled: false }}
      />

      <Stack.Screen
        name="Home"
        component={HomeScreen}
        options={{ gestureEnabled: !hasCompletedOnboarding }}
      />

      <Stack.Screen
        name="Capture"
        component={CaptureScreen}
        options={{
          // Disable swipe-back on CaptureScreen — accidental swipe loses frames
          gestureEnabled: false,
          animation: 'slide_from_bottom',
        }}
      />

      <Stack.Screen
        name="Export"
        component={ExportScreen}
        options={{
          gestureEnabled: false,
          animation: 'slide_from_right',
        }}
      />
    </Stack.Navigator>
  );
}
