/**
 * declarations.d.ts — Ambient module declarations for packages whose types
 * are bundled inside the npm package (and therefore not available until
 * `npm install` runs in CI / device builds).
 *
 * These stubs satisfy `tsc --noEmit` in the source-only dev environment.
 * They are intentionally minimal — just enough for the call-sites in this app.
 */

declare module 'react-native-biometrics' {
  export interface IsSensorAvailableResult {
    available: boolean;
    biometryType?: 'TouchID' | 'FaceID' | 'Biometrics';
    error?: string;
  }

  export interface SimplePromptParams {
    promptMessage: string;
    cancelButtonText?: string;
    fallbackPromptMessage?: string;
  }

  export interface SimplePromptResult {
    success: boolean;
    error?: string;
  }

  export interface ReactNativeBiometricsOptions {
    allowDeviceCredentials?: boolean;
  }

  export const BiometryTypes: {
    TouchID: 'TouchID';
    FaceID: 'FaceID';
    Biometrics: 'Biometrics';
  };

  export default class ReactNativeBiometrics {
    constructor(options?: ReactNativeBiometricsOptions);
    isSensorAvailable(): Promise<IsSensorAvailableResult>;
    simplePrompt(params: SimplePromptParams): Promise<SimplePromptResult>;
    createKeys(): Promise<{ publicKey: string }>;
    biometricKeysExist(): Promise<{ keysExist: boolean }>;
    deleteKeys(): Promise<{ keysDeleted: boolean }>;
  }
}

// ── react-native-svg ──────────────────────────────────────────────────────────
// Minimal stubs for the SVG primitives used in ProgressHUD.
// The real package ships full TypeScript definitions; these stubs
// only need to satisfy `tsc --noEmit` before `npm install` is run.
declare module 'react-native-svg' {
  import type React from 'react';
  import type { ViewProps } from 'react-native';

  interface CommonSvgProps extends ViewProps {
    fill?: string;
    stroke?: string;
    strokeWidth?: number | string;
    strokeLinecap?: 'butt' | 'round' | 'square';
    strokeDasharray?: number | string;
    strokeDashoffset?: number | string;
    transform?: string;
    opacity?: number | string;
    [key: string]: unknown;
  }

  interface SvgProps extends CommonSvgProps {
    width?: number | string;
    height?: number | string;
    viewBox?: string;
  }

  interface CircleProps extends CommonSvgProps {
    cx?: number | string;
    cy?: number | string;
    r?: number | string;
  }

  interface EllipseProps extends CommonSvgProps {
    cx?: number | string;
    cy?: number | string;
    rx?: number | string;
    ry?: number | string;
  }

  interface LineProps extends CommonSvgProps {
    x1?: number | string;
    y1?: number | string;
    x2?: number | string;
    y2?: number | string;
  }

  const Svg: React.ComponentType<SvgProps>;
  const Circle: React.ComponentType<CircleProps>;
  const Ellipse: React.ComponentType<EllipseProps>;
  const Line: React.ComponentType<LineProps>;
  const G: React.ComponentType<CommonSvgProps>;
  const Path: React.ComponentType<CommonSvgProps & { d?: string }>;
  const Rect: React.ComponentType<CommonSvgProps & { x?: number | string; y?: number | string; width?: number | string; height?: number | string; rx?: number | string }>;
  const Defs: React.ComponentType<CommonSvgProps>;
  const LinearGradient: React.ComponentType<CommonSvgProps & { id?: string; x1?: string; x2?: string; y1?: string; y2?: string }>;
  const Stop: React.ComponentType<CommonSvgProps & { offset?: string; stopColor?: string }>;

  export default Svg;
  export { Svg, Circle, Ellipse, Line, G, Path, Rect, Defs, LinearGradient, Stop };
}

// ── Image assets ─────────────────────────────────────────────────────────────
declare module '*.png' {
  import { ImageSourcePropType } from 'react-native';
  const value: ImageSourcePropType;
  export default value;
}

// ── @react-native-clipboard/clipboard ────────────────────────────────────────
declare module '@react-native-clipboard/clipboard' {
  const Clipboard: {
    setString(content: string): void;
    getString(): Promise<string>;
    hasString(): Promise<boolean>;
  };
  export default Clipboard;
}

// ── React Native runtime globals ──────────────────────────────────────────────
// __DEV__ is injected by Metro / Hermes at bundle time to indicate whether the
// app is running in development mode. TypeScript needs an ambient declaration
// since the tsconfig overrides `types` to ["node", "jest"] (dropping the
// built-in @tsconfig/react-native declaration of this global).
declare const __DEV__: boolean;
