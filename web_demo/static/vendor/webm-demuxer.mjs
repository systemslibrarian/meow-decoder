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
const ID_AUDIO = 0xE1;
const ID_SAMPLING_FREQUENCY = 0xB5;
const ID_CHANNELS = 0x9F;
const ID_CODEC_PRIVATE = 0x63A2;
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
    ID_AUDIO,
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

/** Read an EBML float (4 or 8 bytes, big-endian IEEE 754). */
function readFloat(view, offset, length) {
    if (length === 4) return view.getFloat32(offset, false);
    if (length === 8) return view.getFloat64(offset, false);
    if (length === 0) return 0.0;
    throw new Error(`readFloat: invalid length ${length} (must be 0/4/8)`);
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
    // Back-compat shim — return only the video portion of demuxWebM.
    const r = demuxWebM(arrayBuffer);
    return {
        codec: r.video.codec,
        width: r.video.width,
        height: r.video.height,
        timecodeScaleNs: r.timecodeScaleNs,
        packets: r.video.packets,
    };
}

/**
 * Full demux returning both video and audio tracks (when present).
 *
 * Returns:
 *   {
 *     timecodeScaleNs: number,
 *     video: {
 *       codec: "V_VP8" | "V_VP9",
 *       width, height: number,
 *       packets: [{ data, timestampUs, isKeyframe }, ...],
 *     },
 *     audio: null | {
 *       codec: "A_OPUS" | "A_VORBIS",
 *       sampleRate: number,
 *       channels: number,
 *       codecPrivate: Uint8Array | null,  // OpusHead / Vorbis setup blob
 *       packets: [{ data, timestampUs }, ...],
 *     },
 *   }
 *
 * `audio` is null when no audio track is present (the MediaRecorder
 * cat-mode case). Throws on missing/unsupported video.
 */
export function demuxWebM(arrayBuffer) {
    if (!(arrayBuffer instanceof ArrayBuffer)) {
        throw new TypeError('demuxWebM: expected ArrayBuffer');
    }
    const view = new DataView(arrayBuffer);

    let videoCodec = null;
    let videoWidth = 0;
    let videoHeight = 0;
    let timecodeScaleNs = 1_000_000; // Matroska default
    let videoTrackNumber = null;
    let currentClusterTimecode = 0;
    const videoPackets = [];

    // Audio track state.
    let audioCodec = null;
    let audioSampleRate = 0;
    let audioChannels = 0;
    let audioCodecPrivate = null;
    let audioTrackNumber = null;
    const audioPackets = [];

    // Per-track-entry scratch for the Tracks pass.
    let inTrackEntry = false;
    let inAudioMaster = false;
    let trackEntryNumber = null;
    let trackEntryType = null;
    let trackEntryCodec = null;
    let trackEntryWidth = 0;
    let trackEntryHeight = 0;
    let trackEntrySampleRate = 0;
    let trackEntryChannels = 0;
    let trackEntryCodecPrivate = null;

    function flushTrackEntry() {
        if (trackEntryType === 1 /* video */ && videoTrackNumber === null) {
            videoTrackNumber = trackEntryNumber;
            videoCodec = trackEntryCodec;
            videoWidth = trackEntryWidth;
            videoHeight = trackEntryHeight;
        } else if (trackEntryType === 2 /* audio */ && audioTrackNumber === null) {
            audioTrackNumber = trackEntryNumber;
            audioCodec = trackEntryCodec;
            audioSampleRate = trackEntrySampleRate || 48000;
            audioChannels = trackEntryChannels || 1;
            audioCodecPrivate = trackEntryCodecPrivate;
        }
        inTrackEntry = false;
        inAudioMaster = false;
        trackEntryNumber = null;
        trackEntryType = null;
        trackEntryCodec = null;
        trackEntryWidth = 0;
        trackEntryHeight = 0;
        trackEntrySampleRate = 0;
        trackEntryChannels = 0;
        trackEntryCodecPrivate = null;
    }

    walkEbml(view, 0, view.byteLength, (id, bodyOffset, bodySize, v, phase) => {
        if (phase === 'enter') {
            switch (id) {
                case ID_TRACK_ENTRY:
                    inTrackEntry = true;
                    return true;
                case ID_AUDIO:
                    inAudioMaster = true;
                    return true;
                case ID_CLUSTER:
                    currentClusterTimecode = 0;
                    return true;
                default:
                    return true;
            }
        }

        if (phase === 'exit') {
            if (id === ID_TRACK_ENTRY) {
                flushTrackEntry();
            } else if (id === ID_AUDIO) {
                inAudioMaster = false;
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
            case ID_SAMPLING_FREQUENCY:
                if (inAudioMaster) trackEntrySampleRate = Math.round(readFloat(v, bodyOffset, bodySize));
                break;
            case ID_CHANNELS:
                if (inAudioMaster) trackEntryChannels = readUint(v, bodyOffset, bodySize);
                break;
            case ID_CODEC_PRIVATE:
                // Capture for audio tracks (OpusHead, Vorbis setup).
                // Video CodecPrivate isn't useful for VP8/VP9 (no codec setup
                // is needed for VideoDecoder.configure).
                if (inTrackEntry) {
                    trackEntryCodecPrivate = new Uint8Array(
                        v.buffer, v.byteOffset + bodyOffset, bodySize
                    );
                }
                break;

            case ID_CLUSTER_TIMECODE:
                currentClusterTimecode = readUint(v, bodyOffset, bodySize);
                break;

            case ID_SIMPLE_BLOCK: {
                const hdr = parseSimpleBlockHeader(v, bodyOffset);
                const frameStart = bodyOffset + hdr.frameOffset;
                const frameLen = bodySize - hdr.frameOffset;
                const frameBytes = new Uint8Array(
                    v.buffer, v.byteOffset + frameStart, frameLen
                );
                const clusterUs = (currentClusterTimecode * timecodeScaleNs) / 1000;
                const blockUs = hdr.timecodeRel * 1000;
                const tsUs = Math.round(clusterUs + blockUs);
                if (videoTrackNumber !== null && hdr.trackNumber === videoTrackNumber) {
                    videoPackets.push({
                        data: frameBytes,
                        timestampUs: tsUs,
                        isKeyframe: hdr.isKeyframe,
                    });
                } else if (audioTrackNumber !== null && hdr.trackNumber === audioTrackNumber) {
                    // Opus / Vorbis frames in MediaRecorder output are
                    // self-contained — every frame is decodable on its own.
                    // No keyframe flag needed for audio.
                    audioPackets.push({
                        data: frameBytes,
                        timestampUs: tsUs,
                    });
                }
                break;
            }

            case ID_BLOCK: {
                const hdr = parseSimpleBlockHeader(v, bodyOffset);
                const frameStart = bodyOffset + hdr.frameOffset;
                const frameLen = bodySize - hdr.frameOffset;
                const frameBytes = new Uint8Array(
                    v.buffer, v.byteOffset + frameStart, frameLen
                );
                const clusterUs = (currentClusterTimecode * timecodeScaleNs) / 1000;
                const blockUs = hdr.timecodeRel * 1000;
                const tsUs = Math.round(clusterUs + blockUs);
                if (videoTrackNumber !== null && hdr.trackNumber === videoTrackNumber) {
                    videoPackets.push({ data: frameBytes, timestampUs: tsUs, isKeyframe: true });
                } else if (audioTrackNumber !== null && hdr.trackNumber === audioTrackNumber) {
                    audioPackets.push({ data: frameBytes, timestampUs: tsUs });
                }
                break;
            }

            case ID_VOID:
            case ID_CRC32:
                break;

            default:
                break;
        }
    });

    if (inTrackEntry) flushTrackEntry();

    if (videoTrackNumber === null) {
        throw new Error(
            'webm-demuxer: no video track found. Either this WebM has only audio, ' +
            'or the EBML structure is malformed.'
        );
    }
    if (!videoCodec) {
        throw new Error('webm-demuxer: video track missing CodecID');
    }
    if (videoCodec !== 'V_VP8' && videoCodec !== 'V_VP9') {
        throw new Error(
            `webm-demuxer: unsupported video codec ${videoCodec}. ` +
            'MediaRecorder typically emits V_VP8 or V_VP9.'
        );
    }
    if (videoWidth <= 0 || videoHeight <= 0) {
        throw new Error(
            `webm-demuxer: invalid dimensions ${videoWidth}x${videoHeight} from PixelWidth/PixelHeight`
        );
    }

    let audio = null;
    if (audioTrackNumber !== null) {
        if (audioCodec === 'A_OPUS' || audioCodec === 'A_VORBIS') {
            audio = {
                codec: audioCodec,
                sampleRate: audioSampleRate,
                channels: audioChannels,
                codecPrivate: audioCodecPrivate,
                packets: audioPackets,
            };
        }
        // Else: unsupported audio codec — silently drop the audio track.
        // Caller can detect via `result.audio === null` and warn the user
        // that their audio was lost.
    }

    return {
        timecodeScaleNs,
        video: {
            codec: videoCodec,
            width: videoWidth,
            height: videoHeight,
            packets: videoPackets,
        },
        audio,
    };
}

// Re-export the low-level helpers for testability.
export const __test = {
    readVint,
    readUint,
    readSint,
    readAscii,
    readFloat,
    parseSimpleBlockHeader,
    walkEbml,
    VINT_LENGTH_LOOKUP,
};
