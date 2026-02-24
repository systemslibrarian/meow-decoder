/**
 * Mock: react-native-document-picker
 */
module.exports = {
  default: {
    pick: jest.fn(() =>
      Promise.resolve([
        {
          uri: 'file:///mock/test.json',
          name: 'test.json',
          size: 256,
          type: 'application/json',
        },
      ]),
    ),
    isCancel: jest.fn(() => false),
    types: {
      allFiles: '*/*',
      json: 'application/json',
    },
  },
  isCancel: jest.fn(() => false),
  pick: jest.fn(() =>
    Promise.resolve([
      {
        uri: 'file:///mock/test.json',
        name: 'test.json',
        size: 256,
        type: 'application/json',
      },
    ]),
  ),
  types: {
    allFiles: '*/*',
    json: 'application/json',
  },
};
