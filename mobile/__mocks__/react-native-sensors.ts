/**
 * Mock: react-native-sensors
 */
const { Subject } = require('rxjs');
const accelerometerSubject = new Subject();

module.exports = {
  accelerometer: accelerometerSubject,
  setUpdateIntervalForType: jest.fn(),
  SensorTypes: { accelerometer: 'accelerometer' },
};
