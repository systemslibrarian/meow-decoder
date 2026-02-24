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
