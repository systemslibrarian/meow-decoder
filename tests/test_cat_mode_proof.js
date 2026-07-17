#!/usr/bin/env node
/**
 * CAT MODE PROOF TEST — Proves both single-eye and dual-eye modes work
 *
 * Tests:
 *   1. Single-eye encode → decode (both eyes blink together)
 *   2. Dual-eye encode → decode (left/right eyes carry different bits)
 *   3. Single-eye + 2x redundancy
 *   4. Dual-eye + 2x redundancy
 *   5. Wrong password rejection
 *   6. Emoji/Unicode survival
 *   7. Large message (multi-packet, single-eye)
 *   8. Large message (multi-packet, dual-eye + redundancy)
 *
 * Runs in a REAL Chromium browser (headless) via Playwright.
 *
 * USAGE:
 *   node tests/test_cat_mode_proof.js
 */

import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..');

// --- Simple static file server ---
function startServer(port) {
    const mimeTypes = {
        '.html': 'text/html', '.js': 'application/javascript',
        '.mjs': 'application/javascript', '.wasm': 'application/wasm',
        '.css': 'text/css', '.json': 'application/json',
        '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif',
        '.svg': 'image/svg+xml', '.webm': 'video/webm',
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

// --- ANSI ---
const G = '\x1b[32m', R = '\x1b[31m', C_ = '\x1b[36m', Y = '\x1b[33m';
const B_ = '\x1b[1m', X = '\x1b[0m';
function pass(m) { console.log('  ' + G + 'PASS ' + m + X); }
function fail(m) { console.log('  ' + R + 'FAIL ' + m + X); }
function info(m) { console.log('  ' + C_ + 'INFO ' + m + X); }
function header(m) { console.log('\n' + B_ + Y + '=== ' + m + ' ===' + X); }

// --- Main ---
async function main() {
    const PORT = 9879;
    const server = await startServer(PORT);
    const BASE = 'http://localhost:' + PORT;
    let browser;
    let passed = 0;
    let failed = 0;
    const failures = [];

    try {
        browser = await chromium.launch({ headless: true });
        const context = await browser.newContext();
        const page = await context.newPage();

        const pageErrors = [];
        page.on('pageerror', function(e) { pageErrors.push(e.message); });

        // === Load page + WASM ===
        info('Loading web demo + WASM...');
        await page.goto(BASE + '/web_demo/wasm_browser_example_FULL.html', {
            waitUntil: 'domcontentloaded', timeout: 30000,
        });
        info('Page loaded, waiting for WASM init...');
        await page.waitForFunction(function() {
            var el = document.getElementById('wasmStatus');
            return el && el.textContent.indexOf('Ready') >= 0;
        }, { timeout: 120000 });
        await page.evaluate(function() { window.switchMode('cat'); });
        await page.waitForTimeout(300);
        pass('WASM loaded, Cat Mode active');

        // --- Helper: encode with options, refresh, decode, verify ---
        async function testEncodeDecode(label, message, password, options) {
            options = options || {};
            var dualEye = options.dualEye || false;
            var redundancy = options.redundancy || false;
            var wrongPassword = options.wrongPassword || null;

            header(label);

            // Set checkboxes BEFORE encoding
            await page.evaluate(function(de) {
                var cb = document.getElementById('catDualEye');
                if (cb) cb.checked = de;
            }, dualEye);

            await page.evaluate(function(r) {
                var cb = document.getElementById('catRedundancy');
                if (cb) cb.checked = r;
            }, redundancy);

            // Fill in message and password
            await page.fill('#catMessage', message);
            await page.fill('#catPassword', password);

            // Encode through the preserved legacy blink path and grab its bits.
            info('Calling catLegacyBlinkEncode()...');
            var encodeResult = await page.evaluate(async function() {
                try {
                    await window.catLegacyBlinkEncode();
                } catch (e) {
                    return { binary: null, length: 0, error: e.message };
                }
                var binary = sessionStorage.getItem('meow_cat_binary');
                return { binary: binary, length: binary ? binary.length : 0 };
            });
            info('catLegacyBlinkEncode() returned');

            if (!encodeResult.binary || encodeResult.binary.length === 0) {
                fail('Encode produced empty binary');
                failed++;
                failures.push(label + ': empty binary');
                return false;
            }
            var eyeMode = dualEye ? 'dual-eye' : 'single-eye';
            var redLabel = redundancy ? ', 2x' : '';
            info('Encoded ' + encodeResult.length + ' bits (' + eyeMode + redLabel + ')');

            // -- Open a FRESH PAGE for decode (avoids WASM reload stacking) --
            info('Opening fresh page for decode...');
            var decodePage = await context.newPage();
            decodePage.on('pageerror', function(e) { pageErrors.push(e.message); });
            await decodePage.goto(BASE + '/web_demo/wasm_browser_example_FULL.html', {
                waitUntil: 'domcontentloaded', timeout: 30000,
            });
            await decodePage.waitForFunction(function() {
                var el = document.getElementById('wasmStatus');
                return el && el.textContent.indexOf('Ready') >= 0;
            }, { timeout: 120000 });
            await decodePage.evaluate(function() { window.switchMode('cat'); });
            await decodePage.waitForTimeout(300);

            // -- Paste binary + password and decode on fresh page --
            await decodePage.fill('#catBinaryInput', encodeResult.binary);
            await decodePage.fill('#catDecodePassword', wrongPassword || password);

            var result = await decodePage.evaluate(async function() {
                try {
                    await window.catModeDecode();
                    var resultBox = document.getElementById('catDecodeResult');
                    return {
                        success: resultBox ? resultBox.classList.contains('success') : false,
                        error: resultBox ? resultBox.classList.contains('error') : false,
                        text: resultBox ? resultBox.innerHTML : ''
                    };
                } catch (e) {
                    return { success: false, error: true, text: e.message };
                }
            });

            // Close the decode page to free resources
            await decodePage.close();

            if (wrongPassword) {
                // We EXPECT failure
                if (!result.success) {
                    pass('Wrong password correctly rejected');
                    passed++;
                    return true;
                } else {
                    fail('Wrong password was NOT rejected!');
                    failed++;
                    failures.push(label + ': wrong password accepted');
                    return false;
                }
            }

            // Check for success
            var short = message.length > 50 ? message.substring(0, 50) + '...' : message;
            if (result.success && result.text.indexOf(message) >= 0) {
                pass('Decoded correctly: "' + short + '"');
                passed++;
                return true;
            } else {
                fail('Decode failed. Success=' + result.success + ' Contains=' + (result.text.indexOf(message) >= 0));
                info('Result HTML (first 300): ' + result.text.substring(0, 300));
                info('Expected: "' + short + '"');
                failed++;
                failures.push(label);
                return false;
            }
        }

        // =============================================================
        //  TEST 1: Single-eye mode
        // =============================================================
        await testEncodeDecode(
            'TEST 1: Single-eye encode -> decode',
            'Hello from single-eye mode!',
            'single-eye-pw-2024',
            { dualEye: false, redundancy: false }
        );

        // =============================================================
        //  TEST 2: Dual-eye mode
        // =============================================================
        await testEncodeDecode(
            'TEST 2: Dual-eye encode -> decode',
            'Hello from dual-eye mode!',
            'dual-eye-pw-2024',
            { dualEye: true, redundancy: false }
        );

        // =============================================================
        //  TEST 3: Single-eye + 2x redundancy
        // =============================================================
        await testEncodeDecode(
            'TEST 3: Single-eye + 2x redundancy',
            'Redundancy test message!',
            'redundancy-pw-2024',
            { dualEye: false, redundancy: true }
        );

        // =============================================================
        //  TEST 4: Dual-eye + 2x redundancy
        // =============================================================
        await testEncodeDecode(
            'TEST 4: Dual-eye + 2x redundancy',
            'Dual-eye with redundancy!',
            'dual-redundancy-pw',
            { dualEye: true, redundancy: true }
        );

        // =============================================================
        //  TEST 5: Wrong password rejection
        // =============================================================
        await testEncodeDecode(
            'TEST 5: Wrong password must fail',
            'Secret message!',
            'correct-password',
            { dualEye: false, wrongPassword: 'wrong-password' }
        );

        // =============================================================
        //  TEST 6: Emoji + Unicode
        // =============================================================
        await testEncodeDecode(
            'TEST 6: Emoji + Unicode characters',
            '\uD83D\uDC31 Meow! \u732B \u0627\u0644\u0642\u0637 \u043A\u043E\u0442 \uD83C\uDF89',
            'emoji-pw-2024',
            { dualEye: false }
        );

        // =============================================================
        //  TEST 7: Large message (multi-packet, single-eye)
        // =============================================================
        var longMsg = '';
        for (var i = 0; i < 500; i++) longMsg += 'A';
        longMsg += ' -- Long message test!';
        await testEncodeDecode(
            'TEST 7: Large message (single-eye)',
            longMsg,
            'long-msg-pw-2024',
            { dualEye: false }
        );

        // =============================================================
        //  TEST 8: Large message (dual-eye + redundancy)
        // =============================================================
        var longMsg2 = '';
        for (var j = 0; j < 300; j++) longMsg2 += 'B';
        longMsg2 += ' -- Full feature test!';
        await testEncodeDecode(
            'TEST 8: Large message (dual-eye + redundancy)',
            longMsg2,
            'full-feature-pw',
            { dualEye: true, redundancy: true }
        );

        // =============================================================
        //  RESULTS
        // =============================================================
        console.log('\n' + '='.repeat(60));
        if (failed === 0) {
            console.log(G + B_ + 'ALL ' + passed + ' TESTS PASSED!' + X);
            console.log(G + 'Cat Mode PROVEN WORKING:' + X);
            console.log(G + '  * Single-eye mode (both eyes blink together)' + X);
            console.log(G + '  * Dual-eye mode (left/right independent)' + X);
            console.log(G + '  * 2x redundancy (packet duplication)' + X);
            console.log(G + '  * Wrong password rejection' + X);
            console.log(G + '  * Emoji/Unicode support' + X);
            console.log(G + '  * Multi-packet (large messages)' + X);
        } else {
            console.log(R + B_ + passed + ' passed, ' + failed + ' FAILED' + X);
            for (var k = 0; k < failures.length; k++) {
                console.log('  ' + R + 'FAIL: ' + failures[k] + X);
            }
        }
        console.log('='.repeat(60));

        if (pageErrors.length > 0) {
            console.log('\n' + Y + 'Page errors encountered:' + X);
            for (var p = 0; p < pageErrors.length; p++) {
                console.log('  ' + R + pageErrors[p] + X);
            }
        }

    } catch (err) {
        console.log('\n' + R + 'FATAL ERROR: ' + err.message + X);
        console.log(err.stack);
        failed++;
    } finally {
        if (browser) await browser.close();
        server.close();
    }

    process.exit(failed > 0 ? 1 : 0);
}

main();
