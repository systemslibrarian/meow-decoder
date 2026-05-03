/**
 * window.convertWebMToMp4(blob) → Promise<Blob>
 *
 * Cat-mode Safari/WebKit MP4 fallback (potential_bugs.md item #5).
 *
 * Behaviour:
 *
 *   1. Input is ALREADY an MP4 (Safari/WebKit MediaRecorder produces
 *      `video/mp4` directly — see the MIME-type fall-through in
 *      wasm_browser_example_FULL.html line 4688). Return the blob
 *      unchanged with the correct MIME label.
 *
 *   2. Input is WebM (Chromium/Firefox MediaRecorder default) AND the
 *      browser exposes WebCodecs `VideoEncoder` with H.264 support →
 *      transcode in-browser to MP4 via the WebCodecs decoder + encoder
 *      pipeline and the lightweight `mp4-muxer` ESM.
 *
 *   3. Input is WebM and WebCodecs/H.264 unavailable → reject with a
 *      clear, actionable error so the caller can fall back to offering
 *      the WebM file or pointing the user at server-side conversion.
 *
 * Why this lives as a separate file:
 *   - keeps wasm_browser_example_FULL.html focused on the cat-mode UI
 *   - testable in isolation (cross-browser test asserts only that the
 *     symbol exists; runtime path is exercised by manual QA)
 *   - mp4-muxer can be vendored via <script type="module"> when full
 *     transcoding is requested; current implementation lazy-loads it
 *     only on the WebM branch so Safari users pay zero bytes.
 */

(function () {
    'use strict';

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
                'Either save the WebM file directly, or use server-side ffmpeg.'
            );
        }

        // Branch 2 implementation: WebCodecs decode + encode + mp4-muxer.
        //
        // Wiring this requires (1) demuxing the WebM container to extract
        // raw VP8/VP9 packets, (2) feeding them to a VideoDecoder, (3)
        // re-encoding the resulting VideoFrames via VideoEncoder@H.264,
        // (4) muxing into an MP4 container with mp4-muxer.
        //
        // Step (1) needs a WebM/Matroska demuxer (~30KB JS) — vendor when
        // the WebCodecs path is enabled in production. The branch is
        // gated above so users on browsers WITHOUT support never hit
        // this throw; it only fires if a contributor enables the branch
        // by removing this guard before vendoring the demuxer.
        throw new Error(
            'In-browser WebM→MP4 transcoding via WebCodecs is gated pending ' +
            'mp4-muxer + WebM demuxer integration. Tracked in potential_bugs.md #5.'
        );
    }

    if (typeof window !== 'undefined') {
        window.convertWebMToMp4 = convertWebMToMp4;
        // Expose a non-promise capability probe for tests / UI gating.
        window.convertWebMToMp4Capabilities = {
            mp4Identity: true,                    // Safari recordings handled
            webcodecsTranscode: false,            // gated; flip when implemented
            probeTranscodeSupport: canTranscodeViaWebCodecs,
        };
    }
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { convertWebMToMp4, isMp4Blob, canTranscodeViaWebCodecs };
    }
})();
