module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
    // react-native-reanimated MUST be last
    'react-native-reanimated/plugin',
    // react-native-worklets-core
    ['@babel/plugin-proposal-class-properties', { loose: true }],
  ],
};
