/**
 * frameCollector.ts — Stateful accumulator for captured QR frames.
 *
 * FrameCollector is a plain class (not a hook) so it can be unit-tested
 * without React and used in contexts where hooks aren't available.
 *
 * SECURITY: Frame data lives only in memory. The collector imposes a hard
 * cap to defend against accidental memory exhaustion on large captures.
 * Frames are keyed by index so duplicates are silently discarded.
 */

import type { CapturedFrame } from '../types/capture';
import { MEMORY_WARN_FRAME_COUNT } from '../constants/config';

/** Maximum number of frames we'll hold in memory before rejecting new ones */
const HARD_CAP_FRAMES = 10_000;

export interface FrameCollectorStats {
  totalAccepted: number;
  totalDuplicated: number;
  totalRejected: number;
  estimatedMemoryBytes: number;
  isNearMemoryLimit: boolean;
}

export class FrameCollector {
  /** Map from frame index → frame; provides O(1) dedup and sorted access */
  private readonly frames: Map<number, CapturedFrame> = new Map();

  private _totalDuplicated = 0;
  private _totalRejected = 0;

  /**
   * Attempts to add a frame to the collection.
   *
   * @returns 'accepted' | 'duplicate' | 'rejected'
   *   - 'accepted': first time we've seen this index, stored
   *   - 'duplicate': we already have this index, existing kept
   *   - 'rejected': hard memory cap reached
   */
  add(frame: CapturedFrame): 'accepted' | 'duplicate' | 'rejected' {
    if (this.frames.size >= HARD_CAP_FRAMES) {
      this._totalRejected++;
      return 'rejected';
    }

    if (this.frames.has(frame.index)) {
      this._totalDuplicated++;
      return 'duplicate';
    }

    this.frames.set(frame.index, frame);
    return 'accepted';
  }

  /** Returns all frames sorted by index ascending */
  getSorted(): CapturedFrame[] {
    return Array.from(this.frames.values()).sort((a, b) => a.index - b.index);
  }

  /** Returns the total unique frame count */
  get size(): number {
    return this.frames.size;
  }

  /** Returns true if we have a frame for the given index */
  has(index: number): boolean {
    return this.frames.has(index);
  }

  /**
   * Securely clears all frame data from memory.
   * Called on session cancel, app background, and unmount.
   */
  clear(): void {
    this.frames.clear();
    this._totalDuplicated = 0;
    this._totalRejected = 0;
  }

  get stats(): FrameCollectorStats {
    // Rough estimate: each frame ~= overhead (JSON keys) + base64 data
    // Average fountain droplet ≈ 800 bytes → base64 ≈ 1067 chars ≈ ~2KB per frame entry
    const estimatedBytesPerFrame = 2048;
    const estimatedMemoryBytes = this.frames.size * estimatedBytesPerFrame;

    return {
      totalAccepted: this.frames.size,
      totalDuplicated: this._totalDuplicated,
      totalRejected: this._totalRejected,
      estimatedMemoryBytes,
      isNearMemoryLimit: this.frames.size >= MEMORY_WARN_FRAME_COUNT,
    };
  }
}
