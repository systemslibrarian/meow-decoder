/**
 * Mock: react-native-haptic-feedback
 */
module.exports = {
  default: {
    trigger: jest.fn(),
  },
  HapticFeedbackTypes: {
    impactLight: 'impactLight',
    impactMedium: 'impactMedium',
    impactHeavy: 'impactHeavy',
    notificationSuccess: 'notificationSuccess',
    notificationWarning: 'notificationWarning',
    notificationError: 'notificationError',
  },
};
