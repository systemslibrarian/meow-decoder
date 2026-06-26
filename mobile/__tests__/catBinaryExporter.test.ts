/**
 * catBinaryExporter.test.ts — unit tests for saving the Cat Mode binary pattern.
 */

import RNFS from 'react-native-fs';
import Clipboard from '@react-native-clipboard/clipboard';
import {
  exportCatBinary,
  copyCatBinary,
  isValidBinaryPattern,
  CatBinaryError,
} from '../src/services/catBinaryExporter';

const RNFSMock = RNFS as unknown as {
  _reset: () => void;
  _getWrittenFiles: () => Record<string, string>;
  DownloadDirectoryPath: string;
  DocumentDirectoryPath: string;
};
const ClipboardMock = Clipboard as unknown as { _reset: () => void };

beforeEach(() => {
  RNFSMock._reset();
  ClipboardMock._reset();
});

describe('isValidBinaryPattern', () => {
  it('accepts non-empty 0/1 strings', () => {
    expect(isValidBinaryPattern('0101')).toBe(true);
    expect(isValidBinaryPattern('1')).toBe(true);
  });
  it('rejects empty or non-binary strings', () => {
    expect(isValidBinaryPattern('')).toBe(false);
    expect(isValidBinaryPattern('012')).toBe(false);
    expect(isValidBinaryPattern('10 01')).toBe(false);
    expect(isValidBinaryPattern('abc')).toBe(false);
  });
});

describe('exportCatBinary', () => {
  it('writes a file containing the raw binary and a header', async () => {
    const binary = '0110100101011010';
    const result = await exportCatBinary(binary, { blinkPeriodMs: 200 });

    expect(result.bits).toBe(binary.length);
    expect(result.filename).toMatch(/^meow-catmode-.*\.txt$/);
    // Platform-agnostic: Android → Downloads, iOS → Documents (jest default OS).
    const inExportDir =
      result.path.startsWith(RNFSMock.DownloadDirectoryPath) ||
      result.path.startsWith(RNFSMock.DocumentDirectoryPath);
    expect(inExportDir).toBe(true);
    expect(result.path.endsWith(result.filename)).toBe(true);

    const written = RNFSMock._getWrittenFiles()[result.path];
    expect(written).toBeDefined();
    expect(written).toContain(binary);
    expect(written).toContain(`bits=${binary.length}`);
    expect(written).toContain('blink_period_ms=200');
    expect(written).toContain(`checksum=${result.checksum}`);
  });

  it('writes the binary as its own line for easy extraction', async () => {
    const binary = '111000111000';
    const result = await exportCatBinary(binary);
    const written = RNFSMock._getWrittenFiles()[result.path] ?? '';
    const lines = written.trimEnd().split('\n');
    expect(lines[lines.length - 1]).toBe(binary);
  });

  it('rejects an invalid pattern without writing', async () => {
    await expect(exportCatBinary('not-binary')).rejects.toBeInstanceOf(CatBinaryError);
    expect(Object.keys(RNFSMock._getWrittenFiles())).toHaveLength(0);
  });

  it('produces a stable checksum for identical input', async () => {
    const a = await exportCatBinary('0101010101');
    RNFSMock._reset();
    const b = await exportCatBinary('0101010101');
    expect(a.checksum).toBe(b.checksum);
  });
});

describe('copyCatBinary', () => {
  it('copies the raw bits to the clipboard', () => {
    copyCatBinary('10101010');
    // eslint-disable-next-line @typescript-eslint/unbound-method -- jest mock assertion, not a call
    expect(Clipboard.setString).toHaveBeenCalledWith('10101010');
  });
  it('rejects an invalid pattern', () => {
    expect(() => copyCatBinary('xyz')).toThrow(CatBinaryError);
    // eslint-disable-next-line @typescript-eslint/unbound-method -- jest mock assertion, not a call
    expect(Clipboard.setString).not.toHaveBeenCalled();
  });
});
