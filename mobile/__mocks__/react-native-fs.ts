/**
 * Mock: react-native-fs
 */
const mockDownloadDir = '/mock/downloads';
const mockDocDir = '/mock/documents';

const mockWrittenFiles: Record<string, string> = {};

module.exports = {
  DocumentDirectoryPath: mockDocDir,
  DownloadDirectoryPath: mockDownloadDir,
  writeFile: jest.fn(async (path: string, content: string) => {
    mockWrittenFiles[path] = content;
    return Promise.resolve();
  }),
  readFile: jest.fn(async (path: string) => {
    return mockWrittenFiles[path] ?? '';
  }),
  exists: jest.fn(async (_path: string) => Promise.resolve(false)),
  unlink: jest.fn(async (_path: string) => Promise.resolve()),
  mkdir: jest.fn(async (_path: string) => Promise.resolve()),
  _getWrittenFiles: () => mockWrittenFiles,
  _reset: () => {
    Object.keys(mockWrittenFiles).forEach(k => delete mockWrittenFiles[k]);
  },
};
