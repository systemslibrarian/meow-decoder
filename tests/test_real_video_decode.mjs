/**
 * REAL VIDEO DECODE TEST
 *
 * Uses the ACTUAL video recorded by the user (assets/example5.webm)
 * to prove the full decode pipeline works in a real browser.
 *
 * Video: 400x400 VP9 WebM, 30fps, 1923 frames (~64s)
 * Message: "Hello Cat! 🐱"
 * Password: "catcatcat"
 * Speed: 200ms (medium)
 *
 * USAGE: xvfb-run --auto-servernum node tests/test_real_video_decode.mjs
 */

import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

const B = '\x1b[1m', R = '\x1b[31m', G = '\x1b[32m', Y = '\x1b[33m', C = '\x1b[36m', X = '\x1b[0m';

// MIME types
const MIME = {
    '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript',
    '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm',
    '.webm': 'video/webm', '.png': 'image/png', '.jpg': 'image/jpeg',
    '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
};

function startServer(port) {
    return new Promise((resolve) => {
        const server = http.createServer((req, res) => {
            let url = req.url.split('?')[0];
            if (url === '/') url = '/web_demo/wasm_browser_example_FULL.html';
            const filePath = path.join(ROOT, url);
            if (!fs.existsSync(filePath)) { res.writeHead(404); return res.end('Not found'); }
            const ext = path.extname(filePath).toLowerCase();
            res.writeHead(200, {
                'Content-Type': MIME[ext] || 'application/octet-stream',
                'Cross-Origin-Opener-Policy': 'same-origin',
                'Cross-Origin-Embedder-Policy': 'require-corp',
            });
            fs.createReadStream(filePath).pipe(res);
        });
        server.listen(port, () => resolve(server));
    });
}

async function main() {
    const PORT = 9879;
    const server = await startServer(PORT);
    const BASE = `http://localhost:${PORT}`;

    const VIDEO_PATH = path.join(ROOT, 'assets', 'example5.webm');
    const EXPECTED_MESSAGE = 'Hello Cat! 🐱';
    const PASSWORD = 'catcatcat';
    const SPEED = 200;

    if (!fs.existsSync(VIDEO_PATH)) {
        console.error(`${B}${R}Video not found: ${VIDEO_PATH}${X}`);
        process.exit(1);
    }

    console.log(`\n${B}${C}══════════════════════════════════════════════════════════════════${X}`);
    console.log(`${B}${C}  REAL VIDEO DECODE TEST — assets/example5.webm${X}`);
    console.log(`${B}${C}  Message: "${EXPECTED_MESSAGE}"${X}`);
    console.log(`${B}${C}  Password: "${PASSWORD}"${X}`);
    console.log(`${B}${C}  Speed: ${SPEED}ms${X}`);
    console.log(`${B}${C}══════════════════════════════════════════════════════════════════${X}\n`);

    let browser;
    try {
        browser = await chromium.launch({
            headless: false,
            args: ['--no-sandbox', '--disable-gpu', '--window-size=1280,900'],
        });

        const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
        const page = await context.newPage();

        // Collect console logs
        const logs = [];
        page.on('console', msg => {
            const text = msg.text();
            logs.push(text);
            // Log EVERYTHING for full visibility
            console.log(`  ${C}[browser]${X} ${text.substring(0, 300)}`);
        });

        // Step 1: Load the page and wait for WASM
        console.log(`  ${C}Loading web demo + WASM...${X}`);
        await page.goto(`${BASE}/web_demo/wasm_browser_example_FULL.html`, {
            waitUntil: 'networkidle', timeout: 60000
        });

        await page.waitForFunction(
            () => document.getElementById('wasmStatus')?.textContent.includes('Ready'),
            { timeout: 60000 }
        );
        console.log(`  ${G}✅ WASM loaded${X}`);

        // Step 2: Navigate to Cat Mode tab
        await page.evaluate(() => window.switchMode('cat'));
        await page.waitForTimeout(500);

        // Step 3: Upload the REAL video
        console.log(`  ${C}Uploading real video: example5.webm (${(fs.statSync(VIDEO_PATH).size / 1024).toFixed(0)} KB)...${X}`);

        const fileInput = await page.$('#catVideoUpload');
        if (!fileInput) throw new Error('Video upload input not found');
        await fileInput.setInputFiles(VIDEO_PATH);
        await page.waitForTimeout(1000);

        // Verify the file was accepted
        const videoInfo = await page.evaluate(() => {
            const info = document.getElementById('catVideoInfo');
            return info ? info.textContent : '';
        });
        console.log(`  ${G}✅ Video uploaded${X} ${videoInfo ? `(${videoInfo})` : ''}`);

        // Step 4: Set password, speed, and threshold
        await page.fill('#catVideoPassword', PASSWORD);
        await page.selectOption('#catVideoBlinkSpeed', String(SPEED));
        // Use Auto threshold for best results with real recordings
        await page.selectOption('#catVideoThreshold', '0');
        console.log(`  ${G}✅ Password, speed, and threshold (Auto) set${X}`);

        // Step 5: Click "Analyze Video" and wait for result
        console.log(`  ${C}Analyzing video (this takes ~30-120s)...${X}`);

        // First, check if the video element works
        const videoStatus = await page.evaluate(() => {
            const video = document.querySelector('video') || document.getElementById('catVideoPlayer');
            if (!video) return { error: 'no video element found' };
            return {
                duration: video.duration,
                readyState: video.readyState,
                videoWidth: video.videoWidth,
                videoHeight: video.videoHeight,
                src: video.src ? video.src.substring(0, 100) : 'no src',
                catVideoFile: typeof catVideoFile !== 'undefined' ? (catVideoFile ? catVideoFile.name : 'null') : 'undefined'
            };
        });
        console.log(`  ${C}Video element status: ${JSON.stringify(videoStatus)}${X}`);

        const decodeBtn = await page.$('#catVideoDecodeBtn');
        if (!decodeBtn) throw new Error('Decode button not found');
        await decodeBtn.click();

        // Wait for result to appear (long timeout for real video analysis)
        const resultSelector = '#catVideoResult';
        await page.waitForFunction((sel) => {
            const el = document.querySelector(sel);
            if (!el) return false;
            const text = el.textContent || '';
            // Done when we see success, error, or failure message
            return text.includes('Decrypted Message') ||
                   text.includes('decrypted') ||
                   text.includes('Failed') ||
                   text.includes('Error') ||
                   text.includes('error') ||
                   text.includes('No signal') ||
                   text.includes('Could not') ||
                   text.includes('corruption') ||
                   text.length > 50;
        }, resultSelector, { timeout: 300000 });  // 5 min max

        // Step 6: Get the result
        const result = await page.evaluate((sel) => {
            const el = document.querySelector(sel);
            return el ? el.innerHTML : '';
        }, resultSelector);

        const resultText = await page.evaluate((sel) => {
            const el = document.querySelector(sel);
            return el ? el.textContent : '';
        }, resultSelector);

        console.log(`\n  ${B}━━━ RESULT ━━━${X}`);

        // Check for success
        const hasMessage = resultText.includes(EXPECTED_MESSAGE) ||
                          resultText.includes('Hello Cat!') ||
                          resultText.includes('Decrypted Message');

        const hasError = resultText.includes('Error') ||
                        resultText.includes('Failed') ||
                        resultText.includes('No signal') ||
                        resultText.includes('Could not') ||
                        resultText.includes('corruption');

        if (hasMessage && resultText.includes(EXPECTED_MESSAGE)) {
            console.log(`  ${B}${G}✅ SUCCESS! Decoded message: "${EXPECTED_MESSAGE}"${X}`);
            console.log(`  ${G}The REAL video pipeline works end-to-end!${X}`);
        } else if (hasMessage) {
            console.log(`  ${B}${Y}⚠️ Partial success — found 'Decrypted Message' but checking content...${X}`);
            // Extract the actual decoded message
            const msgMatch = resultText.match(/Decrypted Message[:\s]*(.*?)(?:\n|$)/i);
            if (msgMatch) {
                console.log(`  ${Y}Decoded: "${msgMatch[1].trim()}"${X}`);
                console.log(`  ${Y}Expected: "${EXPECTED_MESSAGE}"${X}`);
            }
        } else if (hasError) {
            console.log(`  ${B}${R}❌ DECODE FAILED${X}`);
        } else {
            console.log(`  ${B}${Y}⚠️ Unknown result${X}`);
        }

        // Print full result text
        console.log(`\n  ${C}Full result text (first 2000 chars):${X}`);
        console.log(`  ${resultText.substring(0, 2000)}`);

        // Print relevant console logs
        const relevantLogs = logs.filter(l =>
            l.includes('[Cat Video]') || l.includes('signal') || l.includes('NRZ') ||
            l.includes('preamble') || l.includes('decrypt') || l.includes('CatProtocol') ||
            l.includes('frames') || l.includes('bits')
        );
        if (relevantLogs.length > 0) {
            console.log(`\n  ${C}Key analysis logs (${relevantLogs.length}):${X}`);
            for (const log of relevantLogs.slice(-30)) {
                console.log(`    ${log.substring(0, 200)}`);
            }
        }

        // Read the #log element for the REAL analysis output
        const logContent = await page.evaluate(() => {
            const el = document.getElementById('log');
            return el ? el.textContent : '';
        });
        if (logContent) {
            console.log(`\n  ${C}=== FULL ANALYSIS LOG (from #log element) ===${X}`);
            const lines = logContent.split('\n').filter(l => l.trim());
            for (const line of lines) {
                console.log(`    ${line.substring(0, 300)}`);
            }
        }
        server.close();
        process.exit(hasMessage && resultText.includes(EXPECTED_MESSAGE) ? 0 : 1);

    } catch (err) {
        console.error(`${B}${R}Fatal error: ${err.message}${X}`);
        console.error(err.stack);
        if (browser) await browser.close();
        server.close();
        process.exit(1);
    }
}

main();
