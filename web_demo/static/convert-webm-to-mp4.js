/**
 * window.convertWebMToMp4(blob) → Promise<Blob>
 *
 * Cat-mode Safari/WebKit MP4 fallback + WebCodecs WebM→MP4 transcode
 * (gemini #5).
 *
 * Behaviour:
 *
 *   1. Input is ALREADY an MP4 (Safari/WebKit MediaRecorder produces
 *      `video/mp4` directly — see the MIME-type fall-through in
 *      wasm_browser_example_FULL.html line 4688). Return the blob
 *      unchanged with the correct MIME label.
 *
 *   2. Input is WebM (Chromium/Firefox MediaRecorder default) AND the
 *      browser exposes WebCodecs `VideoEncoder` + `VideoDecoder` with
 *      H.264 support → transcode in-browser to MP4 via WebCodecs
 *      decode → encode → mp4-muxer pipeline.
 *
 *   3. Input is WebM and WebCodecs/H.264 unavailable → reject with a
 *      clear, actionable error pointing the user at offline tools
 *      (`ffmpeg -i in.webm -c:v libx264 -c:a aac out.mp4`, HandBrake,
 *      VLC).
 *
 * Vendored dependencies (loaded lazily on the WebM branch only —
 * Safari users pay zero bytes):
 *   - static/vendor/mp4-muxer-5.2.2.mjs   (MIT, ~70 KB ESM)
 *   - static/vendor/webm-demuxer.mjs      (in-tree, ~9 KB ESM)
 */

(function () {
    'use strict';

    // Lazy-loaded ESM modules (cached after first call).
    let _mp4MuxerModule = null;
    let _webmDemuxerModule = null;

    async function loadMuxer() {
        if (_mp4MuxerModule) return _mp4MuxerModule;
        _mp4MuxerModule = await import('./vendor/mp4-muxer-5.2.2.mjs');
        return _mp4MuxerModule;
    }
    async function loadDemuxer() {
        if (_webmDemuxerModule) return _webmDemuxerModule;
        _webmDemuxerModule = await import('./vendor/webm-demuxer.mjs');
        return _webmDemuxerModule;
    }

    /** Return true if the blob's MIME type is already an MP4 container. */
    function isMp4Blob(blob) {
        if (!blob || typeof blob.type !== 'string') return false;
        const t = blob.type.toLowerCase();
        return t === 'video/mp4' || t.startsWith('video/mp4;');
    }

    /** Return true if WebCodecs + H.264 encoder appear available. */
    async function canTranscodeViaWebCodecs() {
        if (typeof VideoEncoder === 'undefined' || typeof VideoDecoder === 'undefined') {
            return false;
        }
        try {
            // Probe AVC1 baseline 3.1 (avc1.42E01F) — most permissive H.264
            // profile that should be supported wherever H.264 encoding works.
            const support = await VideoEncoder.isConfigSupported({
                codec: 'avc1.42E01F',
                width: 640,
                height: 480,
                bitrate: 1_000_000,
                framerate: 30,
            });
            return !!(support && support.supported);
        } catch (_) {
            return false;
        }
    }

    /**
     * @param {Blob} blob
     * @returns {Promise<Blob>}  An MP4 Blob.
     * @throws  {Error} if the input is not video, or transcoding is
     *                  required but unsupported in the current browser.
     */
    async function convertWebMToMp4(blob) {
        if (!(blob instanceof Blob)) {
            throw new TypeError('convertWebMToMp4: argument must be a Blob');
        }

        // Branch 1: already MP4 (Safari/WebKit recordings).
        if (isMp4Blob(blob)) {
            // Re-wrap to normalise the MIME type label for downstream consumers.
            return new Blob([blob], { type: 'video/mp4' });
        }

        // Branch 2: WebM input with WebCodecs available.
        const t = (blob.type || '').toLowerCase();
        const isWebm = t === 'video/webm' || t.startsWith('video/webm;') || t === '';
        if (!isWebm) {
            throw new Error(
                `convertWebMToMp4: unsupported input MIME "${blob.type}". ` +
                'Expected video/webm or video/mp4.'
            );
        }

        const transcodable = await canTranscodeViaWebCodecs();
        if (!transcodable) {
            // Branch 3: cannot transcode in-browser. Reject with a message
            // the UI can present verbatim. We deliberately do NOT fall back
            // to returning the WebM blob with a fake `video/mp4` label —
            // that would silently corrupt downstream players.
            throw new Error(
                'WebM → MP4 conversion requires either (a) recording in Safari ' +
                '(which produces MP4 natively), or (b) a browser with WebCodecs ' +
                'H.264 encoder support. Your browser provides neither. ' +
                'Save the WebM file directly, then convert offline with one of: ' +
                'ffmpeg -i input.webm -c:v libx264 -c:a aac output.mp4 ' +
                '(or HandBrake / VLC, which both ship a WebM→MP4 preset).'
            );
        }

        // Branch 2 implementation: WebCodecs decode → encode → mp4-muxer.
        return await transcodeWebMToMp4ViaWebCodecs(blob);
    }

    /**
     * Transcode a WebM (VP8/VP9 + optional Opus/Vorbis audio) Blob to MP4
     * (H.264 baseline + AAC-LC) via WebCodecs + mp4-muxer. Caller MUST
     * gate on `canTranscodeViaWebCodecs()` first.
     *
     * Implementation notes:
     *   - VideoDecoder for VP8 or VP9 source → VideoEncoder@`avc1.42E01F`
     *     (H.264 baseline 3.1). Bitrate scales with pixel count.
     *   - When source has audio (Opus/Vorbis): AudioDecoder → AudioEncoder
     *     @`mp4a.40.2` (AAC-LC). When the browser lacks AAC encoding
     *     support, audio is dropped silently (the MP4 ships video-only).
     *   - Frame timestamps come from the WebM SimpleBlock cluster +
     *     block-relative offset (microseconds).
     *   - Keyframe interval mirrors the source (every keyframe in the
     *     WebM forces a keyframe in the MP4 too — preserves the
     *     decoder restart points cat-mode relies on for resume).
     */
    async function transcodeWebMToMp4ViaWebCodecs(blob) {
        const buf = await blob.arrayBuffer();
        const demuxer = await loadDemuxer();
        const muxerMod = await loadMuxer();
        const { Muxer, ArrayBufferTarget } = muxerMod;

        const demuxed = demuxer.demuxWebM(buf);
        const { video, audio } = demuxed;
        const { codec: webmCodec, width, height, packets: videoPkts } = video;

        if (videoPkts.length === 0) {
            throw new Error('convertWebMToMp4: input has no video frames');
        }

        const decoderCodec = webmCodec === 'V_VP8' ? 'vp8' : 'vp09.00.10.08';

        // Bitrate heuristic: 0.1 bits per pixel per frame at 30fps =
        // ~width * height * 3.0. Cap at 8 Mbps to keep blobs sane.
        const bitrate = Math.min(8_000_000, Math.max(500_000, width * height * 3));

        // Audio capability probe — if AudioEncoder@AAC isn't supported,
        // we'll drop the audio rather than fail the whole transcode.
        let audioEnabled = false;
        if (audio && typeof AudioEncoder !== 'undefined' && typeof AudioDecoder !== 'undefined') {
            try {
                const aacSupport = await AudioEncoder.isConfigSupported({
                    codec: 'mp4a.40.2',
                    sampleRate: audio.sampleRate,
                    numberOfChannels: audio.channels,
                    bitrate: 128_000,
                });
                audioEnabled = !!(aacSupport && aacSupport.supported);
            } catch (_) {
                audioEnabled = false;
            }
        }

        const target = new ArrayBufferTarget();
        const muxerConfig = {
            target,
            video: { codec: 'avc', width, height },
            fastStart: 'in-memory',
            firstTimestampBehavior: 'offset',
        };
        if (audioEnabled) {
            muxerConfig.audio = {
                codec: 'aac',
                sampleRate: audio.sampleRate,
                numberOfChannels: audio.channels,
            };
        }
        const muxer = new Muxer(muxerConfig);

        // ── Video pipeline ─────────────────────────────────────────────
        let encoderError = null;
        const videoEncoder = new VideoEncoder({
            output: (chunk, meta) => muxer.addVideoChunk(chunk, meta),
            error: (e) => { encoderError = e; },
        });
        videoEncoder.configure({
            codec: 'avc1.42E01F',
            width,
            height,
            bitrate,
        });

        let decoderError = null;
        const pendingKeyframeFlags = [];
        const videoDecoder = new VideoDecoder({
            output: (frame) => {
                try {
                    if (encoderError) { frame.close(); return; }
                    const sourcePacket = pendingKeyframeFlags.shift();
                    videoEncoder.encode(frame, { keyFrame: !!sourcePacket });
                } finally {
                    frame.close();
                }
            },
            error: (e) => { decoderError = e; },
        });
        videoDecoder.configure({
            codec: decoderCodec,
            codedWidth: width,
            codedHeight: height,
        });

        for (const pkt of videoPkts) {
            pendingKeyframeFlags.push(pkt.isKeyframe);
            videoDecoder.decode(new EncodedVideoChunk({
                type: pkt.isKeyframe ? 'key' : 'delta',
                timestamp: pkt.timestampUs,
                data: pkt.data,
            }));
        }

        // ── Audio pipeline (parallel with video, when enabled) ─────────
        let audioEncoder = null;
        let audioDecoder = null;
        let audioEncoderError = null;
        let audioDecoderError = null;
        if (audioEnabled) {
            audioEncoder = new AudioEncoder({
                output: (chunk, meta) => muxer.addAudioChunk(chunk, meta),
                error: (e) => { audioEncoderError = e; },
            });
            audioEncoder.configure({
                codec: 'mp4a.40.2',
                sampleRate: audio.sampleRate,
                numberOfChannels: audio.channels,
                bitrate: 128_000,
            });

            audioDecoder = new AudioDecoder({
                output: (audioData) => {
                    try {
                        if (audioEncoderError) { audioData.close(); return; }
                        audioEncoder.encode(audioData);
                    } finally {
                        audioData.close();
                    }
                },
                error: (e) => { audioDecoderError = e; },
            });
            const decConfig = {
                codec: audio.codec === 'A_OPUS' ? 'opus' : 'vorbis',
                sampleRate: audio.sampleRate,
                numberOfChannels: audio.channels,
            };
            if (audio.codecPrivate && audio.codecPrivate.byteLength > 0) {
                decConfig.description = audio.codecPrivate;
            }
            audioDecoder.configure(decConfig);

            for (const pkt of audio.packets) {
                audioDecoder.decode(new EncodedAudioChunk({
                    type: 'key',  // Opus/Vorbis frames are self-contained
                    timestamp: pkt.timestampUs,
                    data: pkt.data,
                }));
            }
        }

        // ── Drain + finalise ───────────────────────────────────────────
        await videoDecoder.flush();
        if (decoderError) {
            try { videoDecoder.close(); } catch (_) {}
            try { videoEncoder.close(); } catch (_) {}
            if (audioDecoder) try { audioDecoder.close(); } catch (_) {}
            if (audioEncoder) try { audioEncoder.close(); } catch (_) {}
            throw new Error(`WebM video decode failed: ${decoderError.message || decoderError}`);
        }
        await videoEncoder.flush();
        if (encoderError) {
            try { videoDecoder.close(); } catch (_) {}
            try { videoEncoder.close(); } catch (_) {}
            if (audioDecoder) try { audioDecoder.close(); } catch (_) {}
            if (audioEncoder) try { audioEncoder.close(); } catch (_) {}
            throw new Error(`H.264 encode failed: ${encoderError.message || encoderError}`);
        }

        if (audioDecoder && audioEncoder) {
            try {
                await audioDecoder.flush();
                await audioEncoder.flush();
            } catch (_) {
                // Audio failure is non-fatal — the muxer keeps the video track.
            }
            try { audioDecoder.close(); } catch (_) {}
            try { audioEncoder.close(); } catch (_) {}
        }

        videoDecoder.close();
        videoEncoder.close();
        muxer.finalize();

        return new Blob([target.buffer], { type: 'video/mp4' });
    }

    if (typeof window !== 'undefined') {
        window.convertWebMToMp4 = convertWebMToMp4;
        // Expose a non-promise capability probe for tests / UI gating.
        window.convertWebMToMp4Capabilities = {
            mp4Identity: true,                    // Safari recordings handled
            webcodecsTranscode: true,             // Branch 2 wired (gemini #5)
            probeTranscodeSupport: canTranscodeViaWebCodecs,
        };
    }
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            convertWebMToMp4,
            isMp4Blob,
            canTranscodeViaWebCodecs,
            // Exposed for unit tests; not part of the public browser API.
            transcodeWebMToMp4ViaWebCodecs,
        };
    }
})();
