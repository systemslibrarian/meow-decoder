/**
 * App.tsx — Root application component.
 *
 * Wraps the navigator with:
 *  - NavigationContainer (React Navigation)
 *  - CatToastProvider (global toast context)
 *  - StatusBar configuration
 *
 * First-launch detection uses react-native-mmkv for fast synchronous reads.
 * On first launch, the navigator starts on Onboarding; thereafter on Home.
 */

import React, { useMemo } from 'react';
import { StatusBar } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { MMKV } from 'react-native-mmkv';
import { CatToastProvider } from './components/CatToast';
import { AppNavigator } from './navigation/AppNavigator';
import { Colors } from './constants/theme';

// MMKV instance for non-sensitive settings only (preferences, first-launch flag)
// SECURITY: Frame data is NEVER written to MMKV or any persistent store.
const storage = new MMKV({ id: 'meow_settings' });
const FIRST_LAUNCH_KEY = 'has_completed_onboarding';

export default function App(): React.ReactElement {
  // Determine initial route synchronously (MMKV is synchronous)
  const initialRoute = useMemo<'Splash'>(() => {
    // Always start from Splash; Splash navigates to Onboarding or Home
    // based on the has_completed_onboarding flag.
    return 'Splash';
  }, []);

  const hasCompletedOnboarding = storage.getBoolean(FIRST_LAUNCH_KEY) ?? false;

  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <StatusBar barStyle="light-content" backgroundColor={Colors.background} />
      <CatToastProvider>
        <NavigationContainer>
          <AppNavigator
            initialRoute={initialRoute}
            hasCompletedOnboarding={hasCompletedOnboarding}
          />
        </NavigationContainer>
      </CatToastProvider>
    </GestureHandlerRootView>
  );
}
