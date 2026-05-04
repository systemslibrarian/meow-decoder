/**
 * Minimal MediaRecorder-WebM EBML demuxer.
 *
 * Scoped to the subset of EBML/Matroska that browsers' MediaRecorder
 * produces (Chromium VP8/VP9, Firefox VP8): EBML header → Segment →
 * Info (TimecodeScale) → Tracks → Cluster (Timecode + SimpleBlock).
 *
 * Designed for `convert-webm-to-mp4.js` Branch 2: feed each emitted
 * packet straight into a `VideoDecoder`.
 *
 * NOT a general-purpose Matroska parser. Out of scope:
 *   - BlockGroup wrapping (MediaRecorder uses SimpleBlock)
 *   - Lacing (MediaRecorder emits unlaced frames)
 *   - Multiple video tracks (MediaRecorder emits one)
 *   - Audio tracks (we route audio separately if needed)
 *   - Cues, Chapters, Tags, Attachments
 *   - Streaming reads (this parser is whole-buffer only)
 *
 * Usage:
 *   import { demuxWebMToVideoPackets } from './webm-demuxer.mjs';
 *   const buf = await blob.arrayBuffer();
 *   const { codec, width, height, packets } = demuxWebMToVideoPackets(buf);
 *   // codec: "V_VP8" | "V_VP9"
 *   // packets: [{ data: Uint8Array, timestampUs: number, isKeyframe: bool }, ...]
 *
 * Cross-checked against the Matroska spec
 * (https://www.matroska.org/technical/elements.html) and the WebM
 * profile (https://www.webmproject.org/docs/container/).
 */

// EBML element IDs we care about. IDs are written as a single integer
// including the "marker bit" of the VINT width (so 0x1A45DFA3 has its
// own width self-encoded). See VINT_LENGTH_LOOKUP below.
const ID_EBML_HEADER = 0x1A45DFA3;
const ID_SEGMENT = 0x18538067;
const ID_SEEKHEAD = 0x114D9B74;
const ID_INFO = 0x1549A966;
const ID_TIMECODE_SCALE = 0x2AD7B1;
const ID_TRACKS = 0x1654AE6B;
const ID_TRACK_ENTRY = 0xAE;
const ID_TRACK_NUMBER = 0xD7;
const ID_TRACK_TYPE = 0x83;
const ID_CODEC_ID = 0x86;
const ID_VIDEO = 0xE0;
const ID_PIXEL_WIDTH = 0xB0;
const ID_PIXEL_HEIGHT = 0xBA;
const ID_CLUSTER = 0x1F43B675;
const ID_CLUSTER_TIMECODE = 0xE7;
const ID_SIMPLE_BLOCK = 0xA3;
const ID_BLOCK_GROUP = 0xA0;
const ID_BLOCK = 0xA1;
const ID_VOID = 0xEC;
const ID_CRC32 = 0xBF;

// Element IDs that contain other elements (master elements). Used by
// the parser to recurse into nested structure rather than treating the
// payload as opaque data.
const MASTER_ELEMENTS = new Set([
    ID_EBML_HEADER,
    ID_SEGMENT,
    ID_SEEKHEAD,
    ID_INFO,
    ID_TRACKS,
    ID_TRACK_ENTRY,
    ID_VIDEO,
    ID_CLUSTER,
    ID_BLOCK_GROUP,
]);

// VINT width = position of the leading 1-bit in the first byte (1-8).
// Lookup table avoids per-byte branching in the hot path.
const VINT_LENGTH_LOOKUP = (() => {
    const lut = new Uint8Array(256);
    for (let b = 1; b < 256; b++) {
        let len = 1;
        let mask = 0x80;
        while (!(b & mask) && len < 8) {
            len += 1;
            mask >>= 1;
        }
        lut[b] = len;
    }
    return lut;
})();

/**
 * Read a VINT starting at `offset`. Returns { value, length, valueWithoutMarker }.
 *
 * EBML element IDs keep the marker bit; element sizes strip it. We
 * return both forms so callers can choose.
 */
function readVint(view, offset) {
    if (offset >= view.byteLength) {
        throw new Error(`readVint: offset ${offset} past end ${view.byteLength}`);
    }
    const first = view.getUint8(offset);
    if (first === 0) {
        throw new Error(`readVint: invalid 0x00 byte at offset ${offset}`);
    }
    const length = VINT_LENGTH_LOOKUP[first];
    if (offset + length > view.byteLength) {
        throw new Error(
            `readVint: VINT length ${length} at ${offset} runs past buffer end ${view.byteLength}`
        );
    }
    let raw = first;
    for (let i = 1; i < length; i++) {
        raw = raw * 256 + view.getUint8(offset + i);
    }
    // Strip marker bit (the leading 1-bit) for the size form.
    const markerBitMask = 1 << (8 - length);
    const stripMask = (markerBitMask * (256 ** (length - 1))) - 1;
    const valueWithoutMarker = raw & stripMask;
    return { value: raw, length, valueWithoutMarker };
}

/** Read a fixed-width unsigned integer payload (EBML uint, big-endian). */
function readUint(view, offset, length) {
    if (length < 1 || length > 8) {
        throw new Error(`readUint: invalid length ${length}`);
    }
    let v = 0;
    for (let i = 0; i < length; i++) {
        v = v * 256 + view.getUint8(offset + i);
    }
    return v;
}

/** Read a fixed-width signed integer payload (EBML sint, big-endian, two's-complement). */
function readSint(view, offset, length) {
    if (length < 1 || length > 8) {
        throw new Error(`readSint: invalid length ${length}`);
    }
    let v = view.getInt8(offset);
    for (let i = 1; i < length; i++) {
        v = v * 256 + view.getUint8(offset + i);
    }
    return v;
}

/** Read an ASCII string element payload. */
function readAscii(view, offset, length) {
    let s = "";
    for (let i = 0; i < length; i++) {
        s += String.fromCharCode(view.getUint8(offset + i));
    }
    return s;
}

/**
 * Parse a SimpleBlock body and return { trackNumber, timecodeRel, isKeyframe, frameOffset }.
 * `frameOffset` is relative to the SimpleBlock body start — call sites add
 * it to the body's absolute offset to get the frame-data window.
 */
function parseSimpleBlockHeader(view, bodyOffset) {
    const trackVint = readVint(view, bodyOffset);
    const timecodeRel = view.getInt16(bodyOffset + trackVint.length, false);
    const flags = view.getUint8(bodyOffset + trackVint.length + 2);
    const isKeyframe = !!(flags & 0x80);
    const lacing = (flags >> 1) & 0x03;
    if (lacing !== 0) {
        throw new Error(
            `webm-demuxer: laced SimpleBlock (lacing=${lacing}) not supported. ` +
            'MediaRecorder normally emits unlaced frames; this file may be from ' +
            'a different muxer.'
        );
    }
    return {
        trackNumber: trackVint.valueWithoutMarker,
        timecodeRel,
        isKeyframe,
        frameOffset: trackVint.length + 2 + 1, // VINT(track) + 16-bit timecode + 1-byte flags
    };
}

/**
 * Walk the EBML element tree depth-first.
 *
 * The visitor is called with `(id, bodyOffset, bodySize, view, phase)`
 * where phase ∈ {'leaf', 'enter', 'exit'}. Returning `false` from an
 * 'enter' call skips descent into that master element (the matching
 * 'exit' is still fired so callers can balance scratch state).
 *
 * Bodies with "unknown size" (all-1-bits VINT) are treated as
 * "rest of parent" per the Matroska spec.
 */
function walkEbml(view, startOffset, endOffset, visitor) {
    let offset = startOffset;
    while (offset < endOffset) {
        const idVint = readVint(view, offset);
        const id = idVint.value;
        offset += idVint.length;
        if (offset >= endOffset) break;

        const sizeVint = readVint(view, offset);
        offset += sizeVint.length;

        // Detect "unknown size" (all 1-bits in the size field after marker
        // strip = (1 << (7*length)) - 1). Treat as "rest of parent".
        const unknownSize = (() => {
            const allOnes = (1 << (7 * sizeVint.length)) - 1;
            return sizeVint.valueWithoutMarker === allOnes;
        })();
        const bodySize = unknownSize ? endOffset - offset : sizeVint.valueWithoutMarker;
        const bodyEnd = Math.min(offset + bodySize, endOffset);

        if (MASTER_ELEMENTS.has(id)) {
            const descend = visitor(id, offset, bodySize, view, 'enter');
            if (descend !== false) {
                walkEbml(view, offset, bodyEnd, visitor);
            }
            visitor(id, offset, bodySize, view, 'exit');
        } else {
            visitor(id, offset, bodySize, view, 'leaf');
        }

        offset = bodyEnd;
    }
}

/**
 * Demux an entire MediaRecorder-WebM ArrayBuffer into a flat list of video
 * packets ready for VideoDecoder.
 *
 * Returns:
 *   {
 *     codec:           "V_VP8" | "V_VP9",
 *     width:           number,
 *     height:          number,
 *     timecodeScaleNs: number, // typically 1_000_000 (= 1ms ticks)
 *     packets: [
 *       { data: Uint8Array, timestampUs: number, isKeyframe: boolean },
 *       ...
 *     ]
 *   }
 *
 * Throws on malformed input or unsupported features (laced blocks, multiple
 * video tracks, no video track, missing codec ID).
 */
export function demuxWebMToVideoPackets(arrayBuffer) {
    if (!(arrayBuffer instanceof ArrayBuffer)) {
        throw new TypeError('demuxWebMToVideoPackets: expected ArrayBuffer');
    }
    const view = new DataView(arrayBuffer);

    let codec = null;
    let width = 0;
    let height = 0;
    let timecodeScaleNs = 1_000_000; // Matroska default
    let videoTrackNumber = null;
    let currentClusterTimecode = 0;
    const packets = [];

    // Per-track-entry scratch for the Tracks pass.
    let inTrackEntry = false;
    let trackEntryNumber = null;
    let trackEntryType = null;
    let trackEntryCodec = null;
    let trackEntryWidth = 0;
    let trackEntryHeight = 0;

    function flushTrackEntry() {
        if (trackEntryType === 1 /* video */ && videoTrackNumber === null) {
            videoTrackNumber = trackEntryNumber;
            codec = trackEntryCodec;
            width = trackEntryWidth;
            height = trackEntryHeight;
        }
        inTrackEntry = false;
        trackEntryNumber = null;
        trackEntryType = null;
        trackEntryCodec = null;
        trackEntryWidth = 0;
        trackEntryHeight = 0;
    }

    walkEbml(view, 0, view.byteLength, (id, bodyOffset, bodySize, v, phase) => {
        if (phase === 'enter') {
            switch (id) {
                case ID_TRACK_ENTRY:
                    inTrackEntry = true;
                    return true;
                case ID_CLUSTER:
                    // Reset per-cluster timecode; will be set by ID_CLUSTER_TIMECODE leaf.
                    currentClusterTimecode = 0;
                    return true;
                default:
                    return true;
            }
        }

        if (phase === 'exit') {
            if (id === ID_TRACK_ENTRY) {
                flushTrackEntry();
            }
            return;
        }

        // phase === 'leaf'
        switch (id) {
            case ID_TIMECODE_SCALE:
                timecodeScaleNs = readUint(v, bodyOffset, bodySize);
                break;

            case ID_TRACK_NUMBER:
                if (inTrackEntry) trackEntryNumber = readUint(v, bodyOffset, bodySize);
                break;
            case ID_TRACK_TYPE:
                if (inTrackEntry) trackEntryType = readUint(v, bodyOffset, bodySize);
                break;
            case ID_CODEC_ID:
                if (inTrackEntry) trackEntryCodec = readAscii(v, bodyOffset, bodySize);
                break;
            case ID_PIXEL_WIDTH:
                if (inTrackEntry) trackEntryWidth = readUint(v, bodyOffset, bodySize);
                break;
            case ID_PIXEL_HEIGHT:
                if (inTrackEntry) trackEntryHeight = readUint(v, bodyOffset, bodySize);
                break;

            case ID_CLUSTER_TIMECODE:
                currentClusterTimecode = readUint(v, bodyOffset, bodySize);
                break;

            case ID_SIMPLE_BLOCK: {
                const hdr = parseSimpleBlockHeader(v, bodyOffset);
                if (videoTrackNumber !== null && hdr.trackNumber === videoTrackNumber) {
                    const frameStart = bodyOffset + hdr.frameOffset;
                    const frameLen = bodySize - hdr.frameOffset;
                    const frameBytes = new Uint8Array(
                        v.buffer,
                        v.byteOffset + frameStart,
                        frameLen
                    );
                    // Cluster timecode is in TimecodeScale ticks; SimpleBlock
                    // adds its own ms-resolution relative offset (per spec,
                    // SimpleBlock timecode is always in milliseconds, not
                    // TimecodeScale ticks).
                    const clusterUs = (currentClusterTimecode * timecodeScaleNs) / 1000;
                    const blockUs = hdr.timecodeRel * 1000;
                    packets.push({
                        data: frameBytes,
                        timestampUs: Math.round(clusterUs + blockUs),
                        isKeyframe: hdr.isKeyframe,
                    });
                }
                break;
            }

            case ID_BLOCK: {
                // Inside BlockGroup. Same body layout as SimpleBlock minus
                // the keyframe flag (which lives in the Block's parent
                // BlockGroup via ReferenceBlock — absent ReferenceBlock
                // implies keyframe). MediaRecorder doesn't emit BlockGroup
                // in our scope, but we handle it defensively.
                const hdr = parseSimpleBlockHeader(v, bodyOffset);
                if (videoTrackNumber !== null && hdr.trackNumber === videoTrackNumber) {
                    const frameStart = bodyOffset + hdr.frameOffset;
                    const frameLen = bodySize - hdr.frameOffset;
                    const frameBytes = new Uint8Array(
                        v.buffer,
                        v.byteOffset + frameStart,
                        frameLen
                    );
                    const clusterUs = (currentClusterTimecode * timecodeScaleNs) / 1000;
                    const blockUs = hdr.timecodeRel * 1000;
                    packets.push({
                        data: frameBytes,
                        timestampUs: Math.round(clusterUs + blockUs),
                        // We don't see ReferenceBlock here (it's a sibling),
                        // so default to true on Block to avoid false negatives.
                        // SimpleBlock is the strict path.
                        isKeyframe: true,
                    });
                }
                break;
            }

            case ID_VOID:
            case ID_CRC32:
                // Skip padding / CRC.
                break;

            default:
                // Unknown leaf — ignore. WebM/Matroska is forward-compatible.
                break;
        }
    });

    // Flush the final track entry if we ended inside one (rare, but possible
    // if the buffer is truncated mid-Tracks). The walkEbml-visitor model
    // doesn't fire a master-exit hook, so we rely on the videoTrackNumber
    // being set by the time we hit the first Cluster — which is the spec
    // ordering guarantee.
    if (inTrackEntry) flushTrackEntry();

    if (videoTrackNumber === null) {
        throw new Error(
            'webm-demuxer: no video track found. Either this WebM has only audio, ' +
            'or the EBML structure is malformed.'
        );
    }
    if (!codec) {
        throw new Error('webm-demuxer: video track missing CodecID');
    }
    if (codec !== 'V_VP8' && codec !== 'V_VP9') {
        throw new Error(
            `webm-demuxer: unsupported video codec ${codec}. ` +
            'MediaRecorder typically emits V_VP8 or V_VP9.'
        );
    }
    if (width <= 0 || height <= 0) {
        throw new Error(
            `webm-demuxer: invalid dimensions ${width}x${height} from PixelWidth/PixelHeight`
        );
    }

    return {
        codec,
        width,
        height,
        timecodeScaleNs,
        packets,
    };
}

// Re-export the low-level helpers for testability.
export const __test = {
    readVint,
    readUint,
    readSint,
    readAscii,
    parseSimpleBlockHeader,
    walkEbml,
    VINT_LENGTH_LOOKUP,
};
