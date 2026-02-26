/**
 * ErrorBoundary.tsx — Top-level React error boundary.
 *
 * Catches unhandled render errors (including "Text strings must be rendered
 * within a <Text> component") and shows a safe recovery UI rather than a
 * blank screen or an OS-level crash dialog.
 *
 * WHY THIS IS NEEDED:
 *   React Native on Android throws a JavascriptException for render errors
 *   (e.g. raw string nodes in a View). Without a boundary the whole JS thread
 *   dies with a FATAL EXCEPTION on the mqt_native_modules thread, giving the
 *   user a force-close dialog instead of a recoverable error screen.
 *
 * SECURITY NOTE:
 *   The error message shown to the user is intentionally vague. Full stack
 *   traces are only shown in __DEV__ mode.
 */

import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
} from 'react-native';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';

// ── Types ─────────────────────────────────────────────────────────────────────

interface ErrorBoundaryProps {
  children: React.ReactNode;
  /** Optional override title shown in the recovery UI */
  title?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  errorMessage: string | null;
  errorStack: string | null;
}

// ── Component ─────────────────────────────────────────────────────────────────

export class ErrorBoundary extends React.Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, errorMessage: null, errorStack: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      errorMessage: error?.message ?? 'Unknown error',
      errorStack: error?.stack ?? null,
    };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    // In production keep this silent; in dev log for debugging.
    if (__DEV__) {
      console.error('[ErrorBoundary] Caught render error:', error, info);
    }
  }

  handleReset = (): void => {
    this.setState({ hasError: false, errorMessage: null, errorStack: null });
  };

  render(): React.ReactNode {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <View style={styles.container}>
        <ScrollView contentContainerStyle={styles.content}>
          <Text style={styles.icon} importantForAccessibility="no">
            🙀
          </Text>
          <Text style={styles.title} accessibilityRole="header">
            {this.props.title ?? 'Something went wrong'}
          </Text>
          <Text style={styles.body}>
            The app ran into an unexpected error. Your captured data has not
            been lost — tap below to try recovering.
          </Text>

          {/* In dev only: show the raw error to aid debugging */}
          {__DEV__ && this.state.errorMessage ? (
            <View style={styles.devBox}>
              <Text style={styles.devLabel}>DEV — Error message:</Text>
              <Text style={styles.devText}>{this.state.errorMessage}</Text>
              {this.state.errorStack ? (
                <>
                  <Text style={styles.devLabel}>Stack trace (truncated):</Text>
                  <Text style={styles.devText} numberOfLines={20}>
                    {this.state.errorStack.slice(0, 2000)}
                  </Text>
                </>
              ) : null}
            </View>
          ) : null}

          <TouchableOpacity
            style={styles.button}
            onPress={this.handleReset}
            accessibilityRole="button"
            accessibilityLabel="Try to recover from the error"
          >
            <Text style={styles.buttonText}>↺ Try to recover</Text>
          </TouchableOpacity>
        </ScrollView>
      </View>
    );
  }
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: Colors.background,
    justifyContent: 'center',
  },
  content: {
    padding: Spacing.xl,
    alignItems: 'center',
  },
  icon: {
    fontSize: 64,
    marginBottom: Spacing.lg,
    textAlign: 'center',
  },
  title: {
    color: Colors.danger,
    fontSize: Typography.xl,
    fontWeight: Typography.bold,
    textAlign: 'center',
    marginBottom: Spacing.md,
  },
  body: {
    color: Colors.textSecondary,
    fontSize: Typography.md,
    textAlign: 'center',
    lineHeight: Typography.md * 1.5,
    marginBottom: Spacing.xl,
  },
  button: {
    backgroundColor: Colors.catOrange,
    borderRadius: Radius.full,
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xxxl,
    alignItems: 'center',
    marginTop: Spacing.lg,
  },
  buttonText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.bold,
  },
  devBox: {
    backgroundColor: Colors.backgroundSecondary,
    borderRadius: Radius.md,
    padding: Spacing.md,
    width: '100%',
    marginBottom: Spacing.lg,
  },
  devLabel: {
    color: Colors.warning,
    fontSize: Typography.xs,
    fontWeight: Typography.bold,
    marginBottom: Spacing.xxs,
    marginTop: Spacing.sm,
  },
  devText: {
    color: Colors.textSecondary,
    fontSize: Typography.xs,
    fontFamily: 'monospace',
    lineHeight: Typography.xs * 1.6,
  },
});
