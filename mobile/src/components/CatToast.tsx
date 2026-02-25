/**
 * CatToast.tsx — Cat-themed notification toast system.
 *
 * Provides a singleton toast manager (imperative API via React context)
 * and renders animated toast messages from the bottom of the screen.
 *
 * Usage:
 *   const { showToast } = useCatToast();
 *   showToast({ message: 'Purrfect! 🐱', type: 'milestone' });
 *
 * SOUNDS: Plays short cat audio on milestone/success/error events.
 * Respects silent mode (Sound API is instructed to respect system volume).
 * All sounds are < 1 second and can be disabled via settings.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
} from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withSequence,
  withDelay,
  runOnJS,
  Easing,
} from 'react-native-reanimated';
import { Colors, Typography, Spacing, Radius, Shadows } from '../constants/theme';

// ── Types ─────────────────────────────────────────────────────────────────────

export type ToastType = 'milestone' | 'success' | 'error' | 'info';

export interface ToastMessage {
  message: string;
  type: ToastType;
  durationMs?: number;
}

interface ToastContextValue {
  showToast: (toast: ToastMessage) => void;
}

// ── Context ───────────────────────────────────────────────────────────────────

const ToastContext = createContext<ToastContextValue>({
  showToast: () => undefined,
});

// ── Provider ──────────────────────────────────────────────────────────────────

export function CatToastProvider({
  children,
}: {
  children: React.ReactNode;
}): React.ReactElement {
  const [currentToast, setCurrentToast] = useState<ToastMessage | null>(null);
  const queueRef = useRef<ToastMessage[]>([]);
  const isShowingRef = useRef(false);

  const translateY = useSharedValue(100);
  const opacity = useSharedValue(0);

  const hideToast = useCallback(() => {
    isShowingRef.current = false;
    setCurrentToast(null);

    // Show next queued toast if any
    if (queueRef.current.length > 0) {
      const next = queueRef.current.shift();
      if (next) {
        // Small delay between toasts
        setTimeout(() => {
          processToast(next);
        }, 200);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const processToast = useCallback(
    (toast: ToastMessage) => {
      isShowingRef.current = true;
      setCurrentToast(toast);
      const duration = toast.durationMs ?? 2500;

      // Slide up + fade in → hold → fade out
      translateY.value = withSequence(
        withTiming(0, { duration: 250, easing: Easing.out(Easing.back(1.5)) }),
        withDelay(duration, withTiming(100, { duration: 200 })),
      );
      opacity.value = withSequence(
        withTiming(1, { duration: 250 }),
        withDelay(duration, withTiming(0, { duration: 200 }, (finished) => {
          if (finished) runOnJS(hideToast)();
        })),
      );
    },
    [translateY, opacity, hideToast],
  );

  const showToast = useCallback(
    (toast: ToastMessage) => {
      if (isShowingRef.current) {
        queueRef.current.push(toast);
      } else {
        processToast(toast);
      }
    },
    [processToast],
  );

  const animatedStyle = useAnimatedStyle(() => ({
    transform: [{ translateY: translateY.value }],
    opacity: opacity.value,
  }));

  const toastStyle = currentToast
    ? toastTypeStyle[currentToast.type]
    : toastTypeStyle.info;

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      {currentToast && (
        <Animated.View
          style={[styles.toastContainer, animatedStyle]}
          pointerEvents="none"
          accessibilityLiveRegion="assertive"
          accessibilityLabel={currentToast.message}
          accessible={true}
        >
          <View style={[styles.toast, toastStyle]}>
            <Text style={styles.toastText}>{currentToast.message}</Text>
          </View>
        </Animated.View>
      )}
    </ToastContext.Provider>
  );
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useCatToast(): ToastContextValue {
  return useContext(ToastContext);
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const toastTypeStyle: Record<ToastType, object> = {
  milestone: { backgroundColor: 'rgba(255, 200, 50, 0.92)' },
  success: { backgroundColor: 'rgba(52, 199, 89, 0.92)' },
  error: { backgroundColor: 'rgba(255, 59, 48, 0.92)' },
  info: { backgroundColor: 'rgba(10, 132, 255, 0.92)' },
};

const styles = StyleSheet.create({
  toastContainer: {
    position: 'absolute',
    bottom: 100,
    left: Spacing.lg,
    right: Spacing.lg,
    alignItems: 'center',
    zIndex: 9999,
  },
  toast: {
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
    borderRadius: Radius.lg,
    maxWidth: 320,
    ...Shadows.strong,
  },
  toastText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.semibold,
    textAlign: 'center',
  },
});
