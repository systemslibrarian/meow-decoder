/**
 * __mocks__/react-native-biometrics.ts
 *
 * Test double for react-native-biometrics@3.x.
 * Defaults to: sensor available, simple prompt succeeds.
 * Override per-test via jest.mocked() or mockImplementationOnce().
 */

export const BiometryTypes = {
  TouchID: 'TouchID',
  FaceID: 'FaceID',
  Biometrics: 'Biometrics',
} as const;

const mockInstance = {
  isSensorAvailable: jest.fn().mockResolvedValue({ available: true, biometryType: 'FaceID' }),
  simplePrompt: jest.fn().mockResolvedValue({ success: true }),
  createKeys: jest.fn().mockResolvedValue({ publicKey: 'mock-public-key' }),
  biometricKeysExist: jest.fn().mockResolvedValue({ keysExist: false }),
  deleteKeys: jest.fn().mockResolvedValue({ keysDeleted: true }),
  createSignature: jest.fn().mockResolvedValue({ success: true, signature: 'mock-sig' }),
};

const ReactNativeBiometrics = jest.fn().mockImplementation(() => mockInstance);

export default ReactNativeBiometrics;
