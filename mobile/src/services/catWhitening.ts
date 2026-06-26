/**
 * catWhitening.ts — Cat Mode bit whitening / de-whitening.
 *
 * The Cat Mode optical channel XORs the payload bit-stream with a deterministic
 * LCG ("MEOW") keystream before transmission. This breaks up long runs of the
 * same eye-state (e.g. the 13+ leading zero bits of the payload header), which
 * would otherwise merge into ambiguous long blinks and defeat NRZ decoding.
 *
 * The operation is a pure XOR against a fixed keystream, so it is its own
 * inverse: `dewhiten(whiten(x)) === x`. The receiver therefore runs the exact
 * same transform to recover the original ("raw") binary pattern.
 *
 * This is the bit-true port of `whitenBinary()` in
 * `web_demo/cat_mode.html` (transmitter) and `whiten()` in
 * `meow_decoder/cat_video.py` (server decoder). The keystream MUST match those
 * byte-for-byte or the recovered binary will be garbage.
 *
 * SECURITY: whitening is NOT encryption — it carries no key and provides no
 * confidentiality. It is a line-coding aid only. The real AES-256-GCM payload
 * is already encrypted before it ever reaches this layer.
 */

// LCG seed: the ASCII bytes "MEOW" interpreted as a big-endian 32-bit word.
const MEOW_SEED = 0x4d454f57;
// glibc-style LCG constants (multiplier, increment) and a 31-bit modulus.
const LCG_MULT = 1103515245;
const LCG_INC = 12345;
const LCG_MOD_MASK = 0x7fffffff; // (1 << 31) - 1

/**
 * XOR a binary string ("0"/"1" characters) with the MEOW LCG keystream.
 *
 * Self-inverse: applying it twice returns the original string. Use it to
 * whiten before transmission or to de-whiten after reception — same call.
 *
 * Characters other than "0"/"1" are not expected; any non-"1" char is treated
 * as a 0 bit (matching the transmitter's `parseInt(char)` behaviour, where a
 * stray char would coerce — callers should pass clean binary).
 *
 * @param binary  String of "0"/"1" characters.
 * @returns       Whitened (or de-whitened) string of the same length.
 */
export function whiten(binary: string): string {
  let seed = MEOW_SEED;
  let out = '';
  for (let i = 0; i < binary.length; i++) {
    // Advance the LCG BEFORE deriving the mask bit — this ordering matches the
    // transmitter exactly. Math.imul gives the correct low-32-bit product so
    // the masked 31-bit state agrees with the Python/JS references.
    const lo = Math.imul(seed, LCG_MULT) >>> 0;
    seed = (lo + LCG_INC) & LCG_MOD_MASK;
    const mask = (seed >>> 16) & 1;
    const bit = binary.charCodeAt(i) === 49 /* '1' */ ? 1 : 0;
    out += bit ^ mask ? '1' : '0';
  }
  return out;
}

/**
 * De-whiten a received binary string back to the raw payload bit-pattern.
 * Alias for {@link whiten} (the transform is its own inverse) — provided as a
 * named export so call-sites read by intent.
 */
export function dewhiten(binary: string): string {
  return whiten(binary);
}
