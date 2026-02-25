/**
 * __mocks__/@react-native-clipboard/clipboard.ts
 *
 * Jest mock for @react-native-clipboard/clipboard.
 * Provides in-memory string storage so tests can verify clipboard interactions
 * without a real native module.
 */

let _clipboardContent = '';

const Clipboard = {
  getString: jest.fn(async () => _clipboardContent),
  setString: jest.fn((content: string) => {
    _clipboardContent = content;
  }),
  hasString: jest.fn(async () => _clipboardContent.length > 0),
  /** Test helper: reset the simulated clipboard. */
  _reset() {
    _clipboardContent = '';
    (Clipboard.getString as jest.Mock).mockClear();
    (Clipboard.setString as jest.Mock).mockClear();
    (Clipboard.hasString as jest.Mock).mockClear();
  },
};

export default Clipboard;
