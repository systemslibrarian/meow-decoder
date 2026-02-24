/**
 * Mock: react-native-mmkv
 */
const storage: Record<string, string | number | boolean> = {};

const MMKV = jest.fn().mockImplementation(() => ({
  set: jest.fn((key: string, value: string | number | boolean) => {
    storage[key] = value;
  }),
  getString: jest.fn((key: string) => storage[key] as string | undefined),
  getNumber: jest.fn((key: string) => storage[key] as number | undefined),
  getBoolean: jest.fn((key: string) => storage[key] as boolean | undefined),
  delete: jest.fn((key: string) => {
    delete storage[key];
  }),
  clearAll: jest.fn(() => {
    Object.keys(storage).forEach(k => delete storage[k]);
  }),
  contains: jest.fn((key: string) => key in storage),
}));

module.exports = { MMKV };
