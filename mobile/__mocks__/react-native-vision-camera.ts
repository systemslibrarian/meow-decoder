/**
 * Mock: react-native-vision-camera
 */
module.exports = {
  Camera: 'Camera',
  useCameraDevice: jest.fn(() => ({
    id: 'back',
    position: 'back',
    hasFlash: false,
    hasTorch: false,
  })),
  useCameraPermission: jest.fn(() => ({
    hasPermission: true,
    requestPermission: jest.fn(() => Promise.resolve(true)),
  })),
  useFrameProcessor: jest.fn((fn: unknown) => fn),
  runAtTargetFps: jest.fn((_fps: unknown, fn: unknown): void => {
    if (typeof fn === 'function') fn();
  }),
};
