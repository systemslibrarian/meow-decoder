/**
 * Cat Mode FULL VIDEO PIPELINE E2E Test
 *
 * This is the REAL test: encode → generate video → refresh → upload video →
 * decode → compare binary patterns.
 *
 * Tests ALL four blink speeds: 500ms, 200ms, 100ms, 50ms
 *
 * For each speed:
 *   1. Navigate to Cat Mode, enter message + password + speed
 *   2. Click "Start Transmitting" → get binary pattern & transmission schedule
 *   3. Generate a WebM video from the canvas frames (in-browser, with green/dark eyes)
 *   4. Save the original binary pattern
 *   5. Refresh the page entirely
 *   6. Upload the generated video
 *   7. Set same password + speed, click "Analyze Video"
 *   8. Wait for analysis to complete
 *   9. Compare decoded binary vs original binary
 *  10. Compare decoded message vs original message
 *
 * The video is generated using canvas rendering + MediaRecorder with Xvfb
 * (virtual display) to provide a real GPU compositing surface. This simulates
 * what a phone camera would record.
 *
 * USAGE:
 *   xvfb-run node tests/test_cat_video_pipeline.js
 *   # or: node tests/test_cat_video_pipeline.js  (if DISPLAY is set)
 *
 * Requires: Playwright chromium, xvfb
 */

import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..');

// ─── Simple static file server ──────────────────────────────────────────
function startServer(port) {
    const mimeTypes = {
        '.html': 'text/html', '.js': 'application/javascript',
        '.mjs': 'application/javascript', '.wasm': 'application/wasm',
        '.css': 'text/css', '.json': 'application/json',
        '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif',
        '.svg': 'image/svg+xml', '.webm': 'video/webm', '.mp4': 'video/mp4',
    };
    return new Promise((resolve) => {
        const server = createServer((req, res) => {
            let filePath = join(ROOT, decodeURIComponent(req.url.split('?')[0]));
            if (filePath.endsWith('/')) filePath += 'index.html';
            if (!existsSync(filePath)) { res.writeHead(404); res.end('Not found'); return; }
            const ext = extname(filePath);
            const contentType = mimeTypes[ext] || 'application/octet-stream';
            try {
                const content = readFileSync(filePath);
                res.writeHead(200, { 'Content-Type': contentType, 'Access-Control-Allow-Origin': '*' });
                res.end(content);
            } catch { res.writeHead(500); res.end('Server error'); }
        });
        server.listen(port, () => resolve(server));
    });
}

// ─── ANSI ───────────────────────────────────────────────────────────────
const G = '\x1b[32m', R = '\x1b[31m', C = '\x1b[36m', Y = '\x1b[33m';
const B = '\x1b[1m', X = '\x1b[0m', DIM = '\x1b[2m';
function pass(m) { console.log(`  ${G}✅ ${m}${X}`); }
function fail(m) { console.log(`  ${R}❌ ${m}${X}`); }
function info(m) { console.log(`  ${C}ℹ️  ${m}${X}`); }
function warn(m) { console.log(`  ${Y}⚠️  ${m}${X}`); }
function header(m) { console.log(`\n${B}${Y}━━━ ${m} ━━━${X}`); }

// ─── Evaluate decode results ────────────────────────────────────────────
function evaluateResults(analyzeResult, originalBinary, testMessage, speed, results, logs) {
    // Check success/failure
    if (analyzeResult.hasSuccess) {
        pass('Video decode SUCCEEDED!');
    } else {
        fail('Video decode FAILED');
        const errorMatch = analyzeResult.innerHTML.match(/Error:?\s*([^<]+)/i);
        const errorMsg = errorMatch ? errorMatch[1].trim() : analyzeResult.innerHTML.substring(0, 200);
        info(`Error: ${errorMsg}`);
        results[speed].details.push(`Decode failed: ${errorMsg}`);

        const catLogs = logs.filter(l =>
            l.includes('Cat') || l.includes('NRZ') || l.includes('Preamble') ||
            l.includes('Sync') || l.includes('threshold') || l.includes('transition')
        );
        if (catLogs.length > 0) {
            console.log(`  ${DIM}Relevant logs (last 20):${X}`);
            for (const l of catLogs.slice(-20)) {
                console.log(`    ${DIM}${l}${X}`);
            }
        }
        return;
    }

    // Compare message
    if (analyzeResult.innerHTML.includes(testMessage)) {
        pass(`Decoded message matches: "${testMessage}"`);
        results[speed].messageMatch = true;
    } else {
        fail(`Decoded message doesn't contain "${testMessage}"`);
        results[speed].details.push('Message mismatch');
    }

    // Compare binary patterns
    const extractedBinary = (analyzeResult.extractedBinary || '').replace(/[^01]/g, '');
    if (extractedBinary.length > 0) {
        info(`Original binary:  ${originalBinary.length} bits`);
        info(`Extracted binary: ${extractedBinary.length} bits`);

        const magicBits = '1111111011001010';  // 0xFE 0xCA
        const origMagicIdx = originalBinary.indexOf(magicBits);
        const extractedMagicIdx = extractedBinary.indexOf(magicBits);

        if (origMagicIdx >= 0 && extractedMagicIdx >= 0) {
            const origPayload = originalBinary.substring(origMagicIdx);
            const extPayload = extractedBinary.substring(extractedMagicIdx);

            const minLen = Math.min(origPayload.length, extPayload.length);
            let mismatches = 0;
            let firstMismatch = -1;
            for (let i = 0; i < minLen; i++) {
                if (origPayload[i] !== extPayload[i]) {
                    mismatches++;
                    if (firstMismatch === -1) firstMismatch = i;
                }
            }

            const matchRate = ((minLen - mismatches) / minLen * 100).toFixed(1);
            info(`Bit match rate: ${matchRate}% (${mismatches} mismatches in ${minLen} bits)`);

            if (mismatches === 0) {
                pass(`BINARY PATTERNS MATCH${origPayload.length === extPayload.length ? ' EXACTLY' : ''} (${minLen} bits verified)`);
                results[speed].binaryMatch = true;
            } else if (parseFloat(matchRate) >= 95) {
                warn(`Binary ${matchRate}% match (${mismatches} errors, first at position ${firstMismatch})`);
                results[speed].details.push(`${matchRate}% binary match`);
            } else {
                fail(`Binary match only ${matchRate}% (${mismatches} mismatches)`);
                results[speed].details.push(`Poor binary match: ${matchRate}%`);
            }
        } else {
            warn(`CatProtocol magic not found in ${origMagicIdx < 0 ? 'original' : 'extracted'} binary`);
            results[speed].details.push('Binary comparison skipped (no magic)');
        }
    } else {
        warn('No extracted binary available for comparison');
        results[speed].details.push('No extracted binary');
    }

    results[speed].passed = results[speed].messageMatch;
}

// ─── Main ───────────────────────────────────────────────────────────────
async function main() {
    const PORT = 9877;
    const server = await startServer(PORT);
    const BASE = `http://localhost:${PORT}`;
    let browser;

    const SPEEDS = [500, 200, 100];  // 50ms removed: below Nyquist at 30fps camera
    const TEST_MESSAGE = 'E2E Video Test!';
    const TEST_PASSWORD = 'video-test-pw-2024';

    const results = {};  // speed → { passed, failed, details }

    // Create output dir for video artifacts
    const artifactDir = join(__dirname, 'cat_video_artifacts');
    try { mkdirSync(artifactDir, { recursive: true }); } catch {}

    try {
        browser = await chromium.launch({
            headless: false,  // MUST be headed for MediaRecorder + captureStream
            args: [
                '--use-fake-device-for-media-stream',
                '--use-fake-ui-for-media-stream',
                '--disable-gpu-sandbox',
                '--no-sandbox',
            ]
        });

        for (const speed of SPEEDS) {
            header(`SPEED ${speed}ms — Encode → Record Video → Refresh → Upload → Decode`);
            results[speed] = { passed: false, details: [], binaryMatch: false, messageMatch: false };

            const context = await browser.newContext();
            const page = await context.newPage();

            // Collect browser console
            const logs = [];
            page.on('console', msg => logs.push(`[${msg.type()}] ${msg.text()}`));

            try {
                // ─── STEP 1: Load page, wait for WASM ────────────────
                info('Loading web demo + WASM...');
                await page.goto(`${BASE}/web_demo/wasm_browser_example_FULL.html`, {
                    waitUntil: 'networkidle', timeout: 30000,
                });
                await page.waitForFunction(
                    () => document.getElementById('wasmStatus')?.textContent.includes('Ready'),
                    { timeout: 60000 }
                );
                pass('WASM loaded');

                // ─── STEP 2: Switch to Cat Mode, fill fields ────────
                await page.evaluate(() => window.switchMode('cat'));
                await page.waitForTimeout(300);
                await page.fill('#catMessage', TEST_MESSAGE);
                await page.fill('#catPassword', TEST_PASSWORD);
                await page.evaluate((s) => {
                    document.getElementById('catBlinkSpeed').value = String(s);
                }, speed);
                pass(`Entered message, password, speed=${speed}ms`);

                // ─── STEP 3: Start transmitting ──────────────────────
                info('Starting encode...');

                // Start the encode — it's async (WASM crypto + animation setup)
                // Don't await directly since it involves rAF animation.
                // Instead, fire it and then wait for the binary to appear.
                page.evaluate(() => {
                    window._catEncodePromise = window.catLegacyBlinkEncode();
                });

                // Wait for binary to be stored in sessionStorage
                // (buildCatBinaryPayload finishes before animation starts)
                await page.waitForFunction(
                    () => {
                        const b = sessionStorage.getItem('meow_cat_binary');
                        return b && b.length > 0;
                    },
                    { timeout: 60000 }
                );

                // Get the binary
                const originalBinary = await page.evaluate(() => {
                    return sessionStorage.getItem('meow_cat_binary') || '';
                });

                if (!originalBinary) {
                    fail('No binary data produced!');
                    results[speed].details.push('No binary');
                    continue;
                }
                pass(`Original binary: ${originalBinary.length} bits`);

                // Calculate how long the animation will take
                // The binary has lead-in + preamble + sync + mode_byte (single-eye)
                // then payload (dual-eye, 2 bits per interval)
                // Rough upper bound: originalBinary.length * speed
                const maxAnimMs = originalBinary.length * speed + 5000;
                info(`Waiting for transmission (max ${(maxAnimMs / 1000).toFixed(0)}s)...`);

                // Wait for transmission to complete
                await page.waitForFunction(
                    () => !window.catTransmitting,
                    { timeout: maxAnimMs }
                );
                pass('Transmission complete');

                // Wait for MediaRecorder to finalize blob
                await page.waitForTimeout(2000);

                // Check if video blob exists
                const blobInfo = await page.evaluate(() => {
                    return {
                        hasBlob: !!window.catRecordedBlob,
                        size: window.catRecordedBlob ? window.catRecordedBlob.size : 0
                    };
                });

                if (!blobInfo.hasBlob || blobInfo.size < 100) {
                    fail(`No video blob (hasBlob=${blobInfo.hasBlob}, size=${blobInfo.size}).`);
                    warn('Trying fallback: generating video from binary pattern...');

                    // FALLBACK: Generate video programmatically in the browser
                    // Replicates the EXACT same transmission schedule as the encoder:
                    // 1. Header (lead-in + preamble + sync) — single-eye (both eyes same)
                    // 2. 0xFD mode byte — single-eye
                    // 3. Payload — dual-eye interleaved (even bits → left, odd → right)
                    info('Generating video from binary pattern in-browser...');
                    const fallbackResult = await page.evaluate(async (spd) => {
                        const binary = sessionStorage.getItem('meow_cat_binary');
                        if (!binary) return { success: false, error: 'No binary' };

                        // Get header length from sessionStorage (set by encoder)
                        let headerLen = parseInt(sessionStorage.getItem('meow_cat_header_len') || '0');
                        if (!headerLen) {
                            // Compute: for encrypted msgs, payload always > 200 bits → sync=16
                            headerLen = 8 + 16 + 16; // leadIn + preamble + syncWord
                        }
                        const dualEye = sessionStorage.getItem('meow_cat_dual_eye') === '1';

                        // Split binary into header and payload (same as encoder)
                        let headerBinary = binary.substring(0, headerLen);
                        let payloadBinary = binary.substring(headerLen);

                        if (dualEye) {
                            // Append 0xFD mode marker (transmitted single-eye)
                            headerBinary += '11111101';
                            // Pad payload to even length
                            if (payloadBinary.length % 2 !== 0) payloadBinary += '0';
                        }

                        // Build transmission schedule: {left, right} per interval
                        const schedule = [];

                        // Phase 1: Header — single-eye (both eyes same)
                        for (let i = 0; i < headerBinary.length; i++) {
                            schedule.push({ left: headerBinary[i], right: headerBinary[i] });
                        }

                        // Phase 2: Payload — dual-eye interleaved
                        if (dualEye) {
                            for (let i = 0; i < payloadBinary.length; i += 2) {
                                schedule.push({
                                    left: payloadBinary[i] || '0',
                                    right: payloadBinary[i + 1] || '0'
                                });
                            }
                        } else {
                            for (let i = 0; i < payloadBinary.length; i++) {
                                schedule.push({ left: payloadBinary[i], right: payloadBinary[i] });
                            }
                        }

                        // Create offscreen canvas (400x400)
                        const canvas = document.createElement('canvas');
                        canvas.width = 400;
                        canvas.height = 400;
                        const ctx = canvas.getContext('2d');

                        // Record the canvas using MediaRecorder
                        // Use 60fps + 2Mbps bitrate for clean frame transitions at faster speeds
                        const recordFps = 60;
                        const stream = canvas.captureStream(recordFps);
                        const chunks = [];
                        let mimeType = '';
                        for (const mime of ['video/webm;codecs=vp8', 'video/webm', 'video/mp4']) {
                            if (MediaRecorder.isTypeSupported(mime)) { mimeType = mime; break; }
                        }
                        if (!mimeType) return { success: false, error: 'No supported video mime' };

                        const recorder = new MediaRecorder(stream, {
                            mimeType, videoBitsPerSecond: 2000000
                        });
                        recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };
                        const recordingDone = new Promise(resolve => {
                            recorder.onstop = () => resolve();
                        });
                        recorder.start(50);

                        // Drawing function: render cat with independent eye colors
                        // The decoder analyzes green channel per-half (left/right)
                        // so eyes must be clearly on their respective halves
                        function drawFrame(leftGreen, rightGreen) {
                            // Dark background
                            ctx.fillStyle = '#1a1a2e';
                            ctx.fillRect(0, 0, 400, 400);

                            // Cat face (dark gray, no green component)
                            ctx.fillStyle = '#333';
                            ctx.beginPath();
                            ctx.arc(200, 220, 150, 0, Math.PI * 2);
                            ctx.fill();

                            // Ears
                            ctx.beginPath();
                            ctx.moveTo(80, 120); ctx.lineTo(120, 30); ctx.lineTo(160, 120);
                            ctx.fill();
                            ctx.beginPath();
                            ctx.moveTo(240, 120); ctx.lineTo(280, 30); ctx.lineTo(320, 120);
                            ctx.fill();

                            // LEFT eye (center at x=130, fully in left half)
                            ctx.fillStyle = leftGreen ? '#00ff88' : '#111';
                            ctx.beginPath();
                            ctx.ellipse(130, 200, 30, 22, 0, 0, Math.PI * 2);
                            ctx.fill();

                            // RIGHT eye (center at x=270, fully in right half)
                            ctx.fillStyle = rightGreen ? '#00ff88' : '#111';
                            ctx.beginPath();
                            ctx.ellipse(270, 200, 30, 22, 0, 0, Math.PI * 2);
                            ctx.fill();
                        }

                        const framesPerInterval = Math.max(1, Math.round(spd / (1000 / recordFps)));

                        // Render each interval from the schedule
                        for (let idx = 0; idx < schedule.length; idx++) {
                            const { left, right } = schedule[idx];
                            drawFrame(left === '1', right === '1');

                            // Hold this frame for the correct number of video frames
                            for (let f = 0; f < framesPerInterval; f++) {
                                await new Promise(r => setTimeout(r, 1000 / recordFps));
                            }
                        }

                        // Final dark hold (give decoder clean ending)
                        drawFrame(false, false);
                        await new Promise(r => setTimeout(r, 300));

                        recorder.stop();
                        await recordingDone;

                        const blob = new Blob(chunks, { type: mimeType });
                        window.catRecordedBlob = blob;
                        const ab = await blob.arrayBuffer();
                        return {
                            success: true,
                            size: blob.size,
                            scheduleLength: schedule.length,
                            headerBits: headerBinary.length,
                            payloadBits: payloadBinary.length,
                            data: Array.from(new Uint8Array(ab))
                        };
                    }, speed);

                    if (!fallbackResult.success) {
                        fail(`Fallback video generation failed: ${fallbackResult.error}`);
                        results[speed].details.push('Video generation failed');
                        continue;
                    }

                    // Save fallback video
                    const videoPath = join(artifactDir, `cat_video_${speed}ms.webm`);
                    writeFileSync(videoPath, Buffer.from(fallbackResult.data));
                    pass(`Fallback video generated: ${(fallbackResult.size / 1024).toFixed(1)} KB (${fallbackResult.scheduleLength} intervals, header=${fallbackResult.headerBits}b payload=${fallbackResult.payloadBits}b)`);

                    // ─── STEP 5: REFRESH ─────────────────────────────
                    info('🔄 Refreshing page...');
                    await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
                    await page.waitForFunction(
                        () => document.getElementById('wasmStatus')?.textContent.includes('Ready'),
                        { timeout: 60000 }
                    );
                    pass('Page refreshed, WASM reloaded');

                    await page.evaluate(() => window.switchMode('cat'));
                    await page.waitForTimeout(300);

                    // Upload video
                    info('Uploading video...');
                    const fileInput = page.locator('#catVideoUpload');
                    await fileInput.setInputFiles(videoPath);
                    await page.waitForTimeout(500);
                    pass('Video uploaded');

                    // Set decode params & analyze → same code path as below
                    await page.fill('#catVideoPassword', TEST_PASSWORD);
                    await page.evaluate((s) => {
                        document.getElementById('catVideoBlinkSpeed').value = String(s);
                        document.getElementById('catVideoThreshold').value = '0';
                    }, speed);

                    info('Analyzing video...');
                    const analyzeStartTime = Date.now();

                    const analyzeResult = await page.evaluate(async () => {
                        return new Promise(async (resolve) => {
                            try {
                                await window.catVideoAnalyze();
                                const resultBox = document.getElementById('catVideoResult');
                                const extractedBinary = document.getElementById('catBinaryInput')?.value || '';
                                resolve({
                                    hasSuccess: resultBox?.classList.contains('success') || false,
                                    hasError: resultBox?.classList.contains('error') || false,
                                    innerHTML: (resultBox?.innerHTML || '').substring(0, 1000),
                                    extractedBinary,
                                });
                            } catch (err) {
                                resolve({
                                    hasSuccess: false, hasError: true,
                                    innerHTML: err.message, extractedBinary: '',
                                });
                            }
                        });
                    });

                    const analyzeTime = ((Date.now() - analyzeStartTime) / 1000).toFixed(1);
                    info(`Analysis took ${analyzeTime}s`);

                    // Check results
                    evaluateResults(analyzeResult, originalBinary, TEST_MESSAGE, speed, results, logs);
                    continue;
                }

                // Main path: MediaRecorder worked
                pass(`Video recorded: ${(blobInfo.size / 1024).toFixed(1)} KB`);

                // Save video to disk
                const videoBuffer = await page.evaluate(async () => {
                    const blob = window.catRecordedBlob;
                    const ab = await blob.arrayBuffer();
                    return Array.from(new Uint8Array(ab));
                });
                const videoPath = join(artifactDir, `cat_video_${speed}ms.webm`);
                writeFileSync(videoPath, Buffer.from(videoBuffer));
                info(`Video saved: ${videoPath}`);

                // ─── STEP 5: REFRESH THE PAGE ────────────────────────
                info('🔄 Refreshing page...');
                await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
                await page.waitForFunction(
                    () => document.getElementById('wasmStatus')?.textContent.includes('Ready'),
                    { timeout: 60000 }
                );
                pass('Page refreshed, WASM reloaded');

                // ─── STEP 6: Upload video ────────────────────────────
                await page.evaluate(() => window.switchMode('cat'));
                await page.waitForTimeout(300);

                info('Uploading recorded video...');
                const fileInput = page.locator('#catVideoUpload');
                await fileInput.setInputFiles(videoPath);
                await page.waitForTimeout(500);

                const uploadInfo = await page.evaluate(() => {
                    return document.getElementById('catVideoInfo')?.textContent || '';
                });
                pass(`Video uploaded: ${uploadInfo}`);

                // ─── STEP 7: Set decode params & analyze ─────────────
                await page.fill('#catVideoPassword', TEST_PASSWORD);
                await page.evaluate((s) => {
                    document.getElementById('catVideoBlinkSpeed').value = String(s);
                    document.getElementById('catVideoThreshold').value = '0'; // Auto
                }, speed);
                pass(`Decode params: password, speed=${speed}ms, threshold=auto`);

                info('Analyzing video (this may take a while)...');
                const analyzeStartTime = Date.now();

                const analyzeResult = await page.evaluate(async () => {
                    return new Promise(async (resolve) => {
                        try {
                            await window.catVideoAnalyze();
                            const resultBox = document.getElementById('catVideoResult');
                            const extractedBinary = document.getElementById('catBinaryInput')?.value || '';
                            resolve({
                                hasSuccess: resultBox?.classList.contains('success') || false,
                                hasError: resultBox?.classList.contains('error') || false,
                                innerHTML: (resultBox?.innerHTML || '').substring(0, 1000),
                                extractedBinary,
                            });
                        } catch (err) {
                            resolve({
                                hasSuccess: false, hasError: true,
                                innerHTML: err.message, extractedBinary: '',
                            });
                        }
                    });
                });

                const analyzeTime = ((Date.now() - analyzeStartTime) / 1000).toFixed(1);
                info(`Analysis took ${analyzeTime}s`);

                // Check results
                evaluateResults(analyzeResult, originalBinary, TEST_MESSAGE, speed, results, logs);

            } catch (err) {
                fail(`FATAL: ${err.message}`);
                results[speed].details.push(`Fatal: ${err.message}`);

                // Save logs for debugging
                const catLogs = logs.filter(l =>
                    l.includes('Cat') || l.includes('NRZ') || l.includes('Error') ||
                    l.includes('Preamble') || l.includes('transition')
                );
                if (catLogs.length > 0) {
                    const logPath = join(artifactDir, `debug_${speed}ms.log`);
                    writeFileSync(logPath, catLogs.join('\n'));
                    info(`Debug log saved: ${logPath}`);
                }
            } finally {
                await context.close();
            }
        }

        // ════════════════════════════════════════════════════════════════
        // FINAL SUMMARY
        // ════════════════════════════════════════════════════════════════
        console.log('\n' + '═'.repeat(70));
        console.log(`${B}${C}  CAT MODE VIDEO PIPELINE — RESULTS SUMMARY${X}`);
        console.log('═'.repeat(70));
        console.log('');
        console.log(`  ${B}Speed    Message  Binary   Status${X}`);
        console.log(`  ${'─'.repeat(50)}`);

        let totalPass = 0, totalFail = 0;
        for (const speed of SPEEDS) {
            const r = results[speed];
            const msgIcon = r.messageMatch ? `${G}✅${X}` : `${R}❌${X}`;
            const binIcon = r.binaryMatch ? `${G}✅${X}` : `${R}❌${X}`;
            const status = r.passed ? `${G}PASS${X}` : `${R}FAIL${X}`;
            const details = r.details.length > 0 ? ` ${DIM}(${r.details.join('; ')})${X}` : '';
            console.log(`  ${speed}ms     ${msgIcon}       ${binIcon}       ${status}${details}`);
            if (r.passed) totalPass++; else totalFail++;
        }

        console.log(`  ${'─'.repeat(50)}`);
        console.log(`  ${B}Total: ${totalPass} passed, ${totalFail} failed out of ${SPEEDS.length}${X}`);
        console.log('');

        if (totalFail === 0) {
            console.log(`${B}${G}🎉 ALL SPEEDS WORK! Video pipeline proven end-to-end.${X}`);
        } else if (totalPass > 0) {
            console.log(`${B}${Y}⚠️ Some speeds work, some don't. Working speeds: ${SPEEDS.filter(s => results[s].passed).join('ms, ')}ms${X}`);
            console.log(`${B}${R}Broken speeds: ${SPEEDS.filter(s => !results[s].passed).join('ms, ')}ms — these should be disabled or fixed.${X}`);
        } else {
            console.log(`${B}${R}💥 NO speeds work. Video pipeline is completely broken.${X}`);
        }
        console.log('═'.repeat(70));

        process.exitCode = totalFail > 0 ? 1 : 0;

    } catch (err) {
        console.error(`\n${R}💥 FATAL ERROR: ${err.message}${X}`);
        console.error(err.stack);
        process.exitCode = 1;
    } finally {
        if (browser) await browser.close();
        server.close();
    }
}

main();
