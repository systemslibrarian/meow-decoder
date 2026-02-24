/**
 * Mock: react-native-vision-camera
 *
 * Covers VisionCamera v4 API surface used by the app:
 *   - Camera component
 *   - useCameraDevice, useCameraPermission
 *   - useCodeScanner (v4 native code scanner — replaces worklet-based scanner)
 */
module.exports = {
  Camera: 'Camera',
  useCameraDevice: jest.fn(() => ({
    id: 'back',
    position: 'back',
    hasFlash: false,
    hasTorch: true,
    minZoom: 1,
    maxZoom: 10,
    neutralZoom: 1,
    minExposure: -6,
    maxExposure: 6,
  })),
  useCameraPermission: jest.fn(() => ({
    hasPermission: true,
    requestPermission: jest.fn(() => Promise.resolve(true)),
  })),
  // VisionCamera v4 native code scanner — used by useQRScanner
  useCodeScanner: jest.fn(({ onCodeScanned }: { onCodeScanned: (...args: unknown[]) => void }) => ({
    __type: 'CodeScanner',
    onCodeScanned,
  })),
  // Legacy frame processor API — kept for any remaining test references
  useFrameProcessor: jest.fn((fn: unknown) => fn),
  runAtTargetFps: jest.fn((_fps: unknown, fn: unknown): void => {
    if (typeof fn === 'function') (fn as () => void)();
  }),
};
