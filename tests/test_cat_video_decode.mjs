/**
 * Cat Mode Video Decode E2E Test
 *
 * Tests the full video pipeline:
 *   encode → record synthetic video → reload page → upload video → decode
 *
 * Proven working config from test runs:
 *   - Dual-eye mode at 100ms blink speed passes reliably in headless
 *   - For real phone recordings, use 200ms + 2× redundancy (example7.webm)
 *
 * USAGE:
 *   xvfb-run --auto-servernum node tests/test_cat_video_decode.mjs
 *   SLOW_TESTS=1 xvfb-run ... node tests/test_cat_video_decode.mjs
 *
 * Requires: Playwright (npx playwright install chromium)
 */

import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..');
const SLOW = process.env.SLOW_TESTS === '1';

// ─── ANSI ───────────────────────────────────────────────────────────────
const GREEN = '\x1b[32m', RED = '\x1b[31m', CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m', BOLD = '\x1b[1m', RESET = '\x1b[0m';
function pass(msg) { console.log(`  ${GREEN}✅ ${msg}${RESET}`); }
function fail(msg) { console.log(`  ${RED}❌ ${msg}${RESET}`); }
function info(msg) { console.log(`  ${CYAN}ℹ️  ${msg}${RESET}`); }
function header(msg) { console.log(`\n${BOLD}${YELLOW}━━━ ${msg} ━━━${RESET}`); }

// ─── Static file server ────────────────────────────────────────────────
function startServer(port) {
    const mimeTypes = {
        '.html': 'text/html', '.js': 'application/javascript',
        '.mjs': 'application/javascript', '.wasm': 'application/wasm',
        '.css': 'text/css', '.json': 'application/json',
        '.png': 'image/png', '.webm': 'video/webm',
    };
    return new Promise((resolve) => {
        const s = createServer((req, res) => {
            let fp = join(ROOT, decodeURIComponent(req.url.split('?')[0]));
            if (fp.endsWith('/')) fp += 'index.html';
            if (!existsSync(fp)) { res.writeHead(404); res.end('Not found'); return; }
            const ext = extname(fp);
            res.writeHead(200, {
                'Content-Type': mimeTypes[ext] || 'application/octet-stream',
                'Access-Control-Allow-Origin': '*',
            });
            res.end(readFileSync(fp));
        });
        s.listen(port, () => resolve(s));
    });
}

// ─── Load page, wait WASM, switch to cat mode ──────────────────────────
async function loadPage(page, base) {
    await page.goto(`${base}/web_demo/wasm_browser_example_FULL.html`, {
        waitUntil: 'networkidle', timeout: 60000,
    });
    await page.waitForFunction(
        () => document.getElementById('wasmStatus')?.textContent.includes('Ready'),
        { timeout: 60000 }
    );
    await page.evaluate(() => window.switchMode('cat'));
    await page.waitForTimeout(300);
}

// ─── Upload video and run catVideoAnalyze ──────────────────────────────
async function analyzeVideo(page, videoPath, password, blinkSpeed, timeoutMs = 180000) {
    await page.locator('#catVideoUpload').setInputFiles(videoPath);
    await page.waitForTimeout(500);
    await page.evaluate(() => {
        const input = document.getElementById('catVideoUpload');
        if (input.files.length > 0) window.handleCatVideoUpload(input);
    });
    await page.waitForTimeout(500);

    await page.fill('#catVideoPassword', password);
    await page.evaluate((spd) => {
        document.getElementById('catVideoBlinkSpeed').value = String(spd);
        document.getElementById('catVideoThreshold').value = '0';
    }, blinkSpeed);

    return Promise.race([
        page.evaluate(async () => {
            try {
                await window.catVideoAnalyze();
                const rb = document.getElementById('catVideoResult');
                return {
                    hasSuccess: rb?.classList.contains('success') || false,
                    hasError: rb?.classList.contains('error') || false,
                    html: rb?.innerHTML?.substring(0, 1000) || '',
                };
            } catch (err) {
                return { error: err.message?.substring(0, 500), hasSuccess: false, hasError: true };
            }
        }),
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error(`catVideoAnalyze timed out (${timeoutMs}ms)`)), timeoutMs)
        ),
    ]);
}

// ─── Encode message → get binary → build synthetic video ────────────────
// Uses the page's real encode pipeline, then generates a video from
// the resulting binary using canvas + MediaRecorder.
async function encodeThenRecord(page, message, password, speed, dualEye) {
    await page.fill('#catMessage', message);
    await page.fill('#catPassword', password);
    await page.evaluate(({ s, dual }) => {
        document.getElementById('catBlinkSpeed').value = String(s);
        const cb = document.getElementById('catDualEye');
        if (cb) cb.checked = dual;
        const rd = document.getElementById('catRedundancy');
        if (rd) rd.checked = false;
    }, { s: speed, dual: dualEye });

    info('Encoding...');
    page.evaluate(() => { window._p = window.catModeEncode(); });

    await page.waitForFunction(
        () => sessionStorage.getItem('meow_cat_binary')?.length > 0,
        { timeout: 120000 }
    );
    const binary = await page.evaluate(() => sessionStorage.getItem('meow_cat_binary'));
    info(`Binary: ${binary.length} bits`);

    await page.waitForFunction(() => !window.catTransmitting, { timeout: 600000 });
    info('Transmission done, generating video...');

    const videoResult = await page.evaluate(async ({ spd, isDual }) => {
        const binary = sessionStorage.getItem('meow_cat_binary');
        const headerLen = parseInt(sessionStorage.getItem('meow_cat_header_len') || '0') || 40;
        const savedDual = sessionStorage.getItem('meow_cat_dual_eye') === '1';
        const useDual = isDual && savedDual;

        let headerBinary = binary.substring(0, headerLen);
        let payloadBinary = binary.substring(headerLen);

        if (useDual) {
            headerBinary += '11111101';
            if (payloadBinary.length % 2 !== 0) payloadBinary += '0';
        }

        const schedule = [];
        for (let i = 0; i < headerBinary.length; i++) {
            schedule.push({ left: headerBinary[i], right: headerBinary[i] });
        }
        if (useDual) {
            for (let i = 0; i < payloadBinary.length; i += 2) {
                schedule.push({ left: payloadBinary[i] || '0', right: payloadBinary[i + 1] || '0' });
            }
        } else {
            for (let i = 0; i < payloadBinary.length; i++) {
                schedule.push({ left: payloadBinary[i], right: payloadBinary[i] });
            }
        }

        const canvas = document.createElement('canvas');
        canvas.width = 400; canvas.height = 400;
        const ctx = canvas.getContext('2d');
        const recordFps = 60;
        const stream = canvas.captureStream(recordFps);
        const chunks = [];
        let mime = 'video/webm;codecs=vp8';
        if (!MediaRecorder.isTypeSupported(mime)) mime = 'video/webm';

        const recorder = new MediaRecorder(stream, { mimeType: mime, videoBitsPerSecond: 2000000 });
        recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };
        const done = new Promise(r => { recorder.onstop = r; });
        recorder.start(50);

        function draw(leftGreen, rightGreen) {
            ctx.fillStyle = '#1a1a2e';
            ctx.fillRect(0, 0, 400, 400);
            ctx.fillStyle = '#333';
            ctx.beginPath(); ctx.arc(200, 220, 150, 0, Math.PI * 2); ctx.fill();
            ctx.beginPath(); ctx.moveTo(80, 120); ctx.lineTo(120, 30); ctx.lineTo(160, 120); ctx.fill();
            ctx.beginPath(); ctx.moveTo(240, 120); ctx.lineTo(280, 30); ctx.lineTo(320, 120); ctx.fill();
            ctx.fillStyle = leftGreen ? '#00ff88' : '#111';
            ctx.beginPath(); ctx.ellipse(130, 200, 30, 22, 0, 0, Math.PI * 2); ctx.fill();
            ctx.fillStyle = rightGreen ? '#00ff88' : '#111';
            ctx.beginPath(); ctx.ellipse(270, 200, 30, 22, 0, 0, Math.PI * 2); ctx.fill();
        }

        const framesPerInterval = Math.max(1, Math.round(spd / (1000 / recordFps)));
        for (let idx = 0; idx < schedule.length; idx++) {
            draw(schedule[idx].left === '1', schedule[idx].right === '1');
            for (let f = 0; f < framesPerInterval; f++) {
                await new Promise(r => setTimeout(r, 1000 / recordFps));
            }
        }
        draw(false, false);
        await new Promise(r => setTimeout(r, 300));
        recorder.stop();
        await done;

        const blob = new Blob(chunks, { type: mime });
        const ab = await blob.arrayBuffer();
        return { bytes: Array.from(new Uint8Array(ab)), intervals: schedule.length };
    }, { spd: speed, isDual: dualEye });

    info(`Video: ${videoResult.bytes.length} bytes, ${videoResult.intervals} intervals`);
    return Buffer.from(videoResult.bytes);
}

// ════════════════════════════════════════════════════════════════════════
async function main() {
    console.log(`${BOLD}Cat Mode Video Decode E2E Tests${RESET}`);
    console.log(`Slow tests: ${SLOW ? 'ON' : 'OFF (SLOW_TESTS=1 to enable)'}`);

    const PORT = 9877 + Math.floor(Math.random() * 100);
    const server = await startServer(PORT);
    const BASE = `http://localhost:${PORT}`;
    let browser;
    let passed = 0, failed = 0;
    const failures = [];
    const tempFiles = [];

    try {
        info(`Server on port ${PORT}`);
        browser = await chromium.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
                   '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
        });
        info('Browser launched');

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TEST 1: Dual-eye 100ms → video → decode
        //         (proven: passed in prior test run)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        header('TEST 1: Dual-eye video roundtrip');
        try {
            const ctx = await browser.newContext();
            const page = await ctx.newPage();
            page.setDefaultTimeout(600000);
            const logs = [];
            page.on('console', m => logs.push(`[${m.type()}] ${m.text()}`));

            await loadPage(page, BASE);
            info('Page ready');

            // Dual-eye, 100ms, no redundancy — 324 intervals (~32s video gen)
            const videoData = await encodeThenRecord(page, 'Hi', 'test-video-pw', 100, true);
            const vPath = '/tmp/test_cat_dual.webm';
            writeFileSync(vPath, videoData);
            tempFiles.push(vPath);

            // Reload and decode
            await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
            await page.waitForFunction(
                () => document.getElementById('wasmStatus')?.textContent.includes('Ready'),
                { timeout: 60000 }
            );
            await page.evaluate(() => window.switchMode('cat'));
            await page.waitForTimeout(300);
            info('Decoding video...');

            const result = await analyzeVideo(page, vPath, 'test-video-pw', 100);

            if (result.hasSuccess) {
                pass('Dual-eye video roundtrip OK');
                passed++;
            } else {
                fail(`Dual-eye failed: ${result.error || result.html?.substring(0, 300)}`);
                failed++; failures.push('TEST 1');
                logs.filter(l => /NRZ|Sync|Preamble|Packet|CRC|decoded|Error|reject|Dual/i.test(l))
                    .slice(-15).forEach(l => console.log(`    ${l}`));
            }
            await ctx.close();
        } catch (err) {
            fail(`TEST 1 crashed: ${err.message}`);
            failed++; failures.push('TEST 1 (crash)');
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TEST 2: Golden artifact example7.webm
        //         (SLOW — real user video, 4178 frames)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        header('TEST 2: Golden artifact example7.webm');
        {
            const exPath = join(ROOT, 'assets', 'example7.webm');
            if (!SLOW) {
                info('SKIP — set SLOW_TESTS=1 to run (4178 frames, ~3 min)');
            } else if (!existsSync(exPath)) {
                info('SKIP — assets/example7.webm not found');
            } else {
                try {
                    const ctx = await browser.newContext();
                    const page = await ctx.newPage();
                    page.setDefaultTimeout(600000);
                    const logs = [];
                    page.on('console', m => logs.push(`[${m.type()}] ${m.text()}`));

                    await loadPage(page, BASE);
                    info('Decoding example7.webm (password: dogdogdog, 200ms)...');

                    const result = await analyzeVideo(page, exPath, 'dogdogdog', 200, 300000);

                    if (result.hasSuccess) {
                        pass('example7.webm decoded OK');
                        passed++;
                    } else {
                        fail(`example7.webm: ${result.error || result.html?.substring(0, 300)}`);
                        failed++; failures.push('TEST 2');
                        logs.filter(l => /NRZ|Sync|Preamble|Packet|CRC|decoded|Error/i.test(l))
                            .slice(-15).forEach(l => console.log(`    ${l}`));
                    }
                    await ctx.close();
                } catch (err) {
                    fail(`TEST 2 crashed: ${err.message}`);
                    failed++; failures.push('TEST 2 (crash)');
                }
            }
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TEST 3: Wrong password rejection (SLOW)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        header('TEST 3: Wrong password rejection');
        {
            const exPath = join(ROOT, 'assets', 'example7.webm');
            if (!SLOW) {
                info('SKIP — set SLOW_TESTS=1 to run');
            } else if (!existsSync(exPath)) {
                info('SKIP — assets/example7.webm not found');
            } else {
                try {
                    const ctx = await browser.newContext();
                    const page = await ctx.newPage();
                    page.setDefaultTimeout(600000);
                    page.on('console', () => {});

                    await loadPage(page, BASE);
                    info('Decoding with wrong password...');

                    const result = await analyzeVideo(page, exPath, 'wrong-password', 200, 300000);

                    if (!result.hasSuccess) {
                        pass('Wrong password correctly rejected');
                        passed++;
                    } else {
                        fail('Wrong password should have been rejected');
                        failed++; failures.push('TEST 3');
                    }
                    await ctx.close();
                } catch (err) {
                    fail(`TEST 3 crashed: ${err.message}`);
                    failed++; failures.push('TEST 3 (crash)');
                }
            }
        }

    } catch (err) {
        console.error(`\n${RED}Fatal: ${err.message}${RESET}`);
        console.error(err.stack);
        failed++; failures.push(`Fatal: ${err.message}`);
    } finally {
        if (browser) await browser.close();
        server.close();
        for (const f of tempFiles) { try { unlinkSync(f); } catch (_) {} }

        console.log(`\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
        console.log(`${BOLD}  Results: ${GREEN}${passed} passed${RESET}, ${failed > 0 ? RED : ''}${failed} failed${RESET}`);
        if (failures.length > 0) {
            console.log(`${RED}  Failures:${RESET}`);
            for (const f of failures) console.log(`    ${RED}• ${f}${RESET}`);
        }
        console.log(`${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n`);
        process.exit(failed > 0 ? 1 : 0);
    }
}

main();
