#!/usr/bin/env node
/**
 * Legacy Cat Mode ("Blink the message with the cat's eyes (legacy)") UI test.
 *
 * Drives the REAL web demo in headless Chromium through the controls a person
 * uses — the legacy checkbox, Start/Stop, Download Video, the Step 2 upload
 * and Analyze — rather than internal aliases.
 *
 * Checks, in order:
 *   1. Static: every "Frame / blink interval" the encoder offers is also
 *      offered by the Step 2 "Blink Speed Used" select.
 *   2. Start/Stop interplay between the legacy blink loop and the fountain
 *      QR loop (one Stop click always stops; no false "Transmission
 *      Complete"; a double Start starts exactly one blink loop).
 *   3. Full cycle: tick the box, Start, hide and re-show the tab mid-run,
 *      wait for "Transmission Complete", Download Video, reload the page,
 *      upload the recording in Step 2, pick the matching speed, Analyze,
 *      and verify the decoded message.
 *
 * USAGE:
 *   node tests/test_cat_legacy_blink_ui.mjs            # all checks, fast cycle
 *   node tests/test_cat_legacy_blink_ui.mjs --quick    # checks 1 + 2 only (~1 min)
 *   MEOW_LEGACY_BLINK_MS=500 node tests/test_cat_legacy_blink_ui.mjs
 *       # cycle at the real UI default (≈10 min transmit + ≈15 min decode)
 *
 * The fast cycle injects a 200 ms option into both selects (a test-only
 * speed) and turns the hidden 2× packet redundancy off so the run takes
 * about five minutes instead of half an hour. The time-based encoder drops
 * a bit whenever a frame is delayed by more than one interval, so much
 * faster test speeds become flaky on a loaded machine. Set
 * MEOW_LEGACY_BLINK_MS to one of the shipped values (500/750/1000) to
 * exercise the UI exactly as shipped.
 *
 * Env:
 *   MEOW_BASE_URL          use an already running server instead of the
 *                          built-in static server (URL of the demo page)
 *   MEOW_PLAYWRIGHT_CHANNEL / MEOW_CHROMIUM_PATH   browser selection
 *   MEOW_CAT_CAPTURE_DIR   where the downloaded recording is kept
 *
 * Requires: npm ci && npx playwright install chromium
 */

import { chromium } from '@playwright/test';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const ROOT = resolve(HERE, '..');
const QUICK = process.argv.includes('--quick');
const SHIPPED_SPEEDS = ['500', '750', '1000'];
const BLINK_MS = Number(process.env.MEOW_LEGACY_BLINK_MS || 200);
const SHIPPED_SPEED = SHIPPED_SPEEDS.includes(String(BLINK_MS));
const MESSAGE = process.env.MEOW_LEGACY_MESSAGE || 'Hi';
const PASSWORD = 'legacy-blink-ui-test'; // pragma: allowlist secret
const OUTPUT_DIR = resolve(process.env.MEOW_CAT_CAPTURE_DIR || join(ROOT, 'test-results', 'cat-legacy-blink'));

let passed = 0;
let failed = 0;
function check(label, ok, detail = '') {
    if (ok) { passed++; console.log(`  PASS ${label}`); }
    else { failed++; console.log(`  FAIL ${label}${detail ? ' — ' + detail : ''}`); }
    return ok;
}
function header(title) { console.log(`\n=== ${title} ===`); }

function startServer() {
    const mimeTypes = {
        '.css': 'text/css', '.gif': 'image/gif', '.html': 'text/html',
        '.js': 'application/javascript', '.mjs': 'application/javascript',
        '.jpg': 'image/jpeg', '.json': 'application/json', '.png': 'image/png',
        '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.webm': 'video/webm',
    };
    const server = createServer((request, response) => {
        try {
            const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname);
            const requestedPath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
            const filePath = resolve(ROOT, requestedPath);
            if (relative(ROOT, filePath).startsWith('..') || !existsSync(filePath)) {
                response.writeHead(404).end('Not found');
                return;
            }
            response.writeHead(200, {
                'Cache-Control': 'no-store',
                'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream',
            });
            response.end(readFileSync(filePath));
        } catch (error) {
            response.writeHead(500).end(String(error));
        }
    });
    return new Promise((resolveServer, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => resolveServer(server));
    });
}

async function loadDemo(page, url) {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await page.waitForFunction(
        () => document.getElementById('wasmStatus')?.textContent?.includes('Ready'),
        undefined, { timeout: 120_000 },
    );
    await page.click('#tab-cat');
    await page.waitForTimeout(300);
}

function uiState(page) {
    return page.evaluate(() => ({
        fountain: window.catModeTransmission.status,
        serial: window.catModeTransmission.frameSerial,
        startShown: getComputedStyle(document.getElementById('catQrBtn')).display !== 'none',
        stopShown: getComputedStyle(document.getElementById('catStopBtn')).display !== 'none',
        fsStartDisabled: document.getElementById('catFsStartBtn').disabled,
        fsState: document.getElementById('catFsState').textContent,
        progress: getComputedStyle(document.getElementById('catProgress')).display !== 'none',
        opticalActive: document.getElementById('catCanvasStage').classList.contains('optical-active'),
        result: document.getElementById('catModeResult').textContent.replace(/\s+/g, ' ').trim(),
        download: Boolean(document.getElementById('catDownloadVideoBtn')),
        blinkLoops: (document.getElementById('log').textContent.match(/Transmitting: header=/g) || []).length,
    }));
}

function greenEyePixels(page) {
    return page.evaluate(() => {
        const canvas = document.getElementById('catCanvas');
        const data = canvas.getContext('2d')
            .getImageData(0, 0, canvas.width, Math.floor(canvas.height * 0.65)).data;
        let green = 0;
        for (let i = 0; i < data.length; i += 4) {
            if (data[i + 1] > 100 && data[i + 1] > data[i] * 1.3 && data[i + 3] > 100) green++;
        }
        return green;
    });
}

async function stopIfVisible(page) {
    if (await page.isVisible('#catStopBtn')) {
        await page.click('#catStopBtn');
        await page.waitForTimeout(400);
        return true;
    }
    return false;
}

async function startLegacy(page) {
    await page.check('#catLegacyBlink');
    await page.evaluate(() => sessionStorage.removeItem('meow_cat_binary'));
    await page.click('#catQrBtn');
    await page.waitForFunction(
        () => sessionStorage.getItem('meow_cat_binary')?.length > 0 &&
            document.getElementById('catStopBtn').style.display === 'inline-block',
        undefined, { timeout: 60_000 },
    );
    await page.waitForTimeout(800);
}

async function startFountain(page) {
    await page.uncheck('#catLegacyBlink');
    await page.click('#catQrBtn');
    await page.waitForFunction(
        () => window.catModeTransmission.status === 'transmitting',
        undefined, { timeout: 60_000 },
    );
}

async function ensureSpeedOption(page, selectId, value) {
    await page.evaluate(({ id, v }) => {
        const select = document.getElementById(id);
        if (![...select.options].some((o) => o.value === String(v))) {
            select.add(new Option(`${v}ms (test only)`, String(v)));
        }
        select.value = String(v);
    }, { id: selectId, v: value });
}

async function runStaticChecks(page) {
    header('1. Encoder and decoder speed options agree');
    const options = await page.evaluate(() => ({
        encoder: [...document.getElementById('catBlinkSpeed').options].map((o) => o.value),
        decoder: [...document.getElementById('catVideoBlinkSpeed').options].map((o) => o.value),
        encoderDefault: document.getElementById('catBlinkSpeed').value,
        decoderDefault: document.getElementById('catVideoBlinkSpeed').value,
        legacyBox: Boolean(document.getElementById('catLegacyBlink')),
    }));
    check('legacy checkbox is present', options.legacyBox);
    for (const speed of options.encoder) {
        check(`decoder offers ${speed}ms`, options.decoder.includes(speed),
            `decoder options: ${options.decoder.join(', ')}`);
    }
    check('encoder and decoder share the same default speed',
        options.encoderDefault === options.decoderDefault,
        `${options.encoderDefault} vs ${options.decoderDefault}`);
}

async function runInterplayChecks(page) {
    await page.addInitScript(() => {
        window.__MEOW_CAT_TEST_CONFIG__ = { countdownSeconds: 1, targetIntervalMs: 500 };
    });
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(
        () => document.getElementById('wasmStatus')?.textContent?.includes('Ready'),
        undefined, { timeout: 120_000 },
    );
    await page.click('#tab-cat');
    await page.waitForTimeout(300);
    await page.fill('#catMessage', 'Hi');
    await page.fill('#catPassword', PASSWORD);
    await ensureSpeedOption(page, 'catBlinkSpeed', '500');

    header('2a. Fountain running, box ticked, one Stop click');
    await startFountain(page);
    await page.check('#catLegacyBlink');
    await page.click('#catStopBtn');
    await page.waitForTimeout(1200);
    let state = await uiState(page);
    const serialAfterStop = state.serial;
    await page.waitForTimeout(1200);
    const later = await uiState(page);
    check('fountain loop stopped by a single Stop',
        state.fountain === 'idle' && later.serial === serialAfterStop);
    check('controls return to idle', state.startShown && !state.stopShown && !state.progress);
    await stopIfVisible(page);

    header('2b. Fountain running, box ticked, Start must hand over cleanly');
    await startFountain(page);
    await page.check('#catLegacyBlink');
    await page.evaluate(() => sessionStorage.removeItem('meow_cat_binary'));
    // Start is hidden while the fountain runs; exercise the shared dispatcher directly.
    await page.evaluate(() => window.catModeEncode());
    await page.waitForFunction(() => sessionStorage.getItem('meow_cat_binary')?.length > 0,
        undefined, { timeout: 60_000 });
    await page.waitForTimeout(800);
    state = await uiState(page);
    check('fountain loop stopped before the legacy loop started', state.fountain === 'idle');
    check('legacy state shown', /legacy/.test(state.fsState) && state.stopShown && !state.opticalActive);
    await stopIfVisible(page);

    header('2c. Legacy running, box unticked, Stop');
    await startLegacy(page);
    await page.uncheck('#catLegacyBlink');
    await page.click('#catStopBtn');
    await page.waitForTimeout(1500);
    state = await uiState(page);
    check('no false "Transmission Complete"', !/Transmission Complete/.test(state.result));
    check('no download button for a truncated recording', !state.download);
    check('controls return to idle', state.startShown && !state.stopShown && !state.progress);

    header('2d. Legacy Start then Stop during the warm-up frames');
    await page.check('#catLegacyBlink');
    const warmup = await page.evaluate(async () => {
        sessionStorage.removeItem('meow_cat_binary');
        document.getElementById('catQrBtn').click();
        await new Promise((resolveStop) => {
            const timer = setInterval(() => {
                if (document.getElementById('catStopBtn').style.display === 'inline-block') {
                    clearInterval(timer);
                    resolveStop();
                }
            }, 0);
        });
        document.getElementById('catStopBtn').click();
        await new Promise((r) => setTimeout(r, 1500));
        return {
            result: document.getElementById('catModeResult').textContent,
            startShown: getComputedStyle(document.getElementById('catQrBtn')).display !== 'none',
            download: Boolean(document.getElementById('catDownloadVideoBtn')),
        };
    });
    check('no false "Transmission Complete" after an immediate Stop',
        !/Transmission Complete/.test(warmup.result) && !warmup.download && warmup.startShown);

    header('2e. Double Start click while the key is still being derived');
    await page.check('#catLegacyBlink');
    const loopsBefore = (await uiState(page)).blinkLoops;
    await page.evaluate(() => {
        sessionStorage.removeItem('meow_cat_binary');
        document.getElementById('catQrBtn').click();
        setTimeout(() => document.getElementById('catQrBtn').click(), 150);
    });
    await page.waitForFunction(
        () => sessionStorage.getItem('meow_cat_binary')?.length > 0 &&
            document.getElementById('catStopBtn').style.display === 'inline-block',
        undefined, { timeout: 60_000 },
    );
    await page.waitForTimeout(4000);
    state = await uiState(page);
    check('exactly one blink loop started', state.blinkLoops - loopsBefore === 1,
        `${state.blinkLoops - loopsBefore} loops`);
    await stopIfVisible(page);

    header('2f. Legacy run, Stop, then a fountain run');
    await startLegacy(page);
    await page.waitForTimeout(1000);
    await page.click('#catStopBtn');
    await page.waitForTimeout(400);
    check('eyes restored after legacy Stop', (await greenEyePixels(page)) > 1000);
    await startFountain(page);
    await page.waitForTimeout(800);
    state = await uiState(page);
    check('fountain transmits after a legacy run', state.fountain === 'transmitting');
    await page.click('#catStopBtn');
    await page.waitForTimeout(400);
    state = await uiState(page);
    check('fountain Stop works with the box unticked', state.fountain === 'idle' && state.startShown);
}

async function runFullCycle(context, url) {
    header(`3. Full cycle through the UI at ${BLINK_MS}ms per bit${SHIPPED_SPEED ? ' (shipped speed)' : ' (test-only speed)'}`);
    mkdirSync(OUTPUT_DIR, { recursive: true });
    const page = await context.newPage();
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await loadDemo(page, url);

    if (!SHIPPED_SPEED) {
        await ensureSpeedOption(page, 'catBlinkSpeed', BLINK_MS);
        // Hidden 2× packet redundancy doubles the run; keep it only for shipped speeds.
        await page.evaluate(() => { document.getElementById('catRedundancy').checked = false; });
    } else {
        await page.selectOption('#catBlinkSpeed', String(BLINK_MS));
    }
    await page.check('#catLegacyBlink');
    await page.fill('#catMessage', MESSAGE);
    await page.fill('#catPassword', PASSWORD);
    await page.click('#catQrBtn');
    await page.waitForFunction(() => sessionStorage.getItem('meow_cat_binary')?.length > 0,
        undefined, { timeout: 120_000 });
    const bits = await page.evaluate(() => sessionStorage.getItem('meow_cat_binary').length);
    const expectedMs = bits * BLINK_MS;
    console.log(`  ${bits} bits scheduled, ≈${Math.round(expectedMs / 1000)}s of blinking`);

    let state = await uiState(page);
    check('transmitting state shown', state.stopShown && !state.startShown && state.progress &&
        /legacy/.test(state.fsState) && !state.opticalActive);

    const samples = [];
    const sampleUntil = Date.now() + Math.min(8000, expectedMs);
    while (Date.now() < sampleUntil) {
        samples.push(await greenEyePixels(page));
        await page.waitForTimeout(Math.max(10, BLINK_MS / 4));
    }
    check('eyes toggle between green and dark', new Set(samples).size >= 2 && Math.min(...samples) === 0,
        `samples: ${[...new Set(samples)].join(',')}`);

    // Long transmissions invite tab switching. Simulate the tab going hidden
    // for a moment: the encoder must pause the recorder and resume without
    // stretching or skipping an interval, or the recording will not decode.
    const setHidden = (hidden) => page.evaluate((h) => {
        Object.defineProperty(document, 'hidden', { configurable: true, get: () => h });
        document.dispatchEvent(new Event('visibilitychange'));
    }, hidden);
    await setHidden(true);
    await page.waitForTimeout(1500);
    await setHidden(false);
    state = await uiState(page);
    check('transmission still running after the tab was hidden and shown again', state.stopShown && !state.startShown);

    await page.waitForFunction(
        () => document.getElementById('catModeResult')?.textContent.includes('Transmission Complete'),
        undefined, { timeout: expectedMs + 120_000 },
    );
    await page.waitForTimeout(1500);
    state = await uiState(page);
    check('"Transmission Complete" with a Download Video button', state.download && state.startShown && !state.stopShown);
    check('completion notes the paused tab', /tab was briefly hidden/i.test(state.result));

    const [download] = await Promise.all([
        page.waitForEvent('download', { timeout: 30_000 }),
        page.click('#catDownloadVideoBtn'),
    ]);
    const videoPath = join(OUTPUT_DIR, `legacy-blink-${BLINK_MS}ms.webm`);
    await download.saveAs(videoPath);
    console.log(`  recording saved to ${videoPath}`);

    // Fresh page state, exactly like closing and reopening the demo.
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(
        () => document.getElementById('wasmStatus')?.textContent?.includes('Ready'),
        undefined, { timeout: 120_000 },
    );
    await page.click('#tab-cat');
    await page.waitForTimeout(300);
    await page.setInputFiles('#catVideoUpload', videoPath);
    await page.waitForFunction(() => !document.getElementById('catVideoDecodeBtn').disabled,
        undefined, { timeout: 10_000 });
    await page.fill('#catVideoPassword', PASSWORD);
    if (SHIPPED_SPEED) {
        await page.selectOption('#catVideoBlinkSpeed', String(BLINK_MS));
    } else {
        await ensureSpeedOption(page, 'catVideoBlinkSpeed', BLINK_MS);
    }
    await page.selectOption('#catVideoThreshold', '0'); // Auto
    const decodeStarted = Date.now();
    await page.click('#catVideoDecodeBtn');
    await page.waitForFunction(() => {
        const box = document.getElementById('catVideoResult');
        return box && (box.classList.contains('success') || box.classList.contains('error'));
    }, undefined, { timeout: 40 * 60_000 });
    const result = await page.evaluate(() => {
        const box = document.getElementById('catVideoResult');
        return {
            success: box.classList.contains('success'),
            text: box.textContent.replace(/\s+/g, ' ').trim().slice(0, 400),
        };
    });
    console.log(`  decode took ${Math.round((Date.now() - decodeStarted) / 1000)}s`);
    check('Step 2 decodes the recording', result.success, result.text);
    check(`decoded message is "${MESSAGE}"`, result.text.includes(MESSAGE), result.text);
    check('no page errors', pageErrors.length === 0, pageErrors.join('; '));
    await page.close();
}

async function main() {
    let server = null;
    let url = process.env.MEOW_BASE_URL;
    if (!url) {
        server = await startServer();
        url = `http://127.0.0.1:${server.address().port}/web_demo/wasm_browser_example_FULL.html`;
    }
    let browser;
    try {
        const launch = { headless: true, args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'] };
        if (process.env.MEOW_PLAYWRIGHT_CHANNEL) launch.channel = process.env.MEOW_PLAYWRIGHT_CHANNEL;
        if (process.env.MEOW_CHROMIUM_PATH) launch.executablePath = process.env.MEOW_CHROMIUM_PATH;
        browser = await chromium.launch(launch);
        const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
        const page = await context.newPage();
        await loadDemo(page, url);
        await runStaticChecks(page);
        await runInterplayChecks(page);
        await page.close();
        if (!QUICK) await runFullCycle(context, url);
    } finally {
        if (browser) await browser.close();
        if (server) await new Promise((resolveClose) => server.close(resolveClose));
    }
    console.log(`\n${failed === 0 ? 'ALL CHECKS PASSED' : `${failed} CHECK(S) FAILED`} (${passed} passed, ${failed} failed)`);
    process.exitCode = failed === 0 ? 0 : 1;
}

main().catch((error) => {
    console.error(error.stack || error.message || String(error));
    process.exitCode = 1;
});
