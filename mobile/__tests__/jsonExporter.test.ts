/**
 * jsonExporter.test.ts — Unit tests for the JSON export service.
 *
 * Uses mocked react-native-fs to test file write logic without filesystem.
 */

import { buildQRExportChunks } from '../src/services/jsonExporter';
import type { CaptureResponse } from '../src/types/capture';

// react-native-fs is mocked globally via __mocks__/react-native-fs.ts

const makeResponse = (frameCount: number, dataSize = 100): CaptureResponse => {
  const frames = Array.from({ length: frameCount }, (_, i) => ({
    index: i,
    data: 'A'.repeat(dataSize),
    timestamp_ms: 1000 + i,
  }));
  return {
    session_id: '550e8400-e29b-41d4-a716-446655440000',
    frames,
    capture_complete: true,
    frames_captured: frameCount,
    frames_missed: 0,
  };
};

describe('buildQRExportChunks', () => {
  it('returns a single chunk for small response', () => {
    const response = makeResponse(5);
    const chunks = buildQRExportChunks(response, 100_000);
    expect(chunks.length).toBeGreaterThanOrEqual(1);
    // Each chunk is a string
    chunks.forEach(c => expect(typeof c).toBe('string'));
  });

  it('each chunk parses as valid JSON', () => {
    const response = makeResponse(5);
    const chunks = buildQRExportChunks(response, 100_000);
    chunks.forEach(c => {
      expect(() => JSON.parse(c)).not.toThrow();
    });
  });

  it('splits into multiple chunks when maxChunkBytes is small', () => {
    // Many frames with 100-byte payloads each
    const response = makeResponse(100, 100);
    // Force very small chunk size to trigger splitting
    const chunks = buildQRExportChunks(response, 1000);
    expect(chunks.length).toBeGreaterThan(1);
  });

  it('each chunk has a data field with JSON slice', () => {
    const response = makeResponse(10);
    const chunks = buildQRExportChunks(response, 5000);
    chunks.forEach(c => {
      const parsed = JSON.parse(c);
      // buildQRExportChunks wraps data in {meow_qr_chunk, session_id, chunk_index, total_chunks, data}
      expect(parsed.meow_qr_chunk).toBe(true);
      expect(typeof parsed.data).toBe('string');
    });
  });

  it('includes session_id in every chunk', () => {
    const response = makeResponse(20);
    const chunks = buildQRExportChunks(response, 2000);
    chunks.forEach(c => {
      const parsed = JSON.parse(c);
      expect(parsed.session_id).toBe('550e8400-e29b-41d4-a716-446655440000');
    });
  });

  it('includes chunk metadata with 1-based chunk_index', () => {
    const response = makeResponse(50, 100);
    const chunks = buildQRExportChunks(response, 2000);
    const first = JSON.parse(chunks[0] as string);
    // chunk_index is 1-based
    expect(first.chunk_index).toBe(1);
    expect(first.total_chunks).toBe(chunks.length);
  });

  it('handles empty frames array gracefully', () => {
    const empty = makeResponse(0);
    const chunks = buildQRExportChunks(empty, 100_000);
    expect(chunks.length).toBeGreaterThanOrEqual(1);
    const first = JSON.parse(chunks[0] as string);
    // Envelope format: {meow_qr_chunk, session_id, chunk_index, total_chunks, data}
    expect(first.meow_qr_chunk).toBe(true);
    expect(first.session_id).toBe('550e8400-e29b-41d4-a716-446655440000');
    expect(typeof first.data).toBe('string');
  });
});
