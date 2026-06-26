module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
    ['@babel/plugin-proposal-class-properties', { loose: true }],
    // react-native-reanimated/plugin MUST be last. It also performs the
    // 'worklet' transform used by VisionCamera frame processors + the Cat Mode
    // brightness sampler (react-native-worklets-core), so no separate
    // worklets-core babel plugin is required here.
    'react-native-reanimated/plugin',
  ],
};
