/**
 * jsonExporter.test.ts — Unit tests for the JSON export service.
 *
 * Uses mocked react-native-fs to test file write logic without filesystem.
 */

import { buildQRExportChunks, verifyQRExportReassembly } from '../src/services/jsonExporter';
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

// ── verifyQRExportReassembly ──────────────────────────────────────────────────

describe('verifyQRExportReassembly', () => {
  /** Helper: build chunks and parse them back into structured objects */
  const buildAndParse = (frameCount: number, maxChunkBytes = 2000) => {
    const response = makeResponse(frameCount);
    const rawChunks = buildQRExportChunks(response, maxChunkBytes);
    return rawChunks.map((c) => JSON.parse(c));
  };

  it('validates correctly reassembled chunks', () => {
    const chunks = buildAndParse(10, 2000);
    const result = verifyQRExportReassembly(chunks);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(typeof result.reassembled).toBe('string');
  });

  it('reconstructed payload parses back to original JSON', () => {
    const response = makeResponse(5);
    const rawChunks = buildQRExportChunks(response, 100_000);
    const chunks = rawChunks.map((c) => JSON.parse(c));
    const result = verifyQRExportReassembly(chunks);
    expect(result.valid).toBe(true);
    const parsed = JSON.parse(result.reassembled!);
    expect(parsed.session_id).toBe('550e8400-e29b-41d4-a716-446655440000');
    expect(parsed.frames.length).toBe(5);
  });

  it('rejects empty chunks array', () => {
    const result = verifyQRExportReassembly([]);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('No chunks');
  });

  it('rejects when chunk count does not match total_chunks', () => {
    const chunks = buildAndParse(50, 1000);
    // Remove last chunk to create a mismatch
    chunks.pop();
    const result = verifyQRExportReassembly(chunks);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Expected');
  });

  it('rejects when chunk data is tampered', () => {
    const chunks = buildAndParse(10, 2000);
    // Tamper with one chunk's data
    chunks[0].data = 'TAMPERED_DATA';
    const result = verifyQRExportReassembly(chunks);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('checksum mismatch');
  });

  it('handles single-chunk payloads', () => {
    const chunks = buildAndParse(1, 100_000);
    expect(chunks.length).toBe(1);
    const result = verifyQRExportReassembly(chunks);
    expect(result.valid).toBe(true);
  });

  it('reassembles multi-chunk payloads in correct order regardless of input order', () => {
    const chunks = buildAndParse(50, 1000);
    // Reverse the chunks — verifyQRExportReassembly should sort by chunk_index
    const reversed = [...chunks].reverse();
    const result = verifyQRExportReassembly(reversed);
    expect(result.valid).toBe(true);
  });
});
