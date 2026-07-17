/**
 * Cat Mode E2E Test — Proof that Encode → Refresh → Decode works
 *
 * This test launches the REAL web demo in a headless Chromium browser,
 * encrypts a message through Cat Mode, copies the binary pattern,
 * refreshes the page, pastes the binary + password, and verifies
 * that the decoded message matches exactly.
 *
 * USAGE:
 *   node tests/test_cat_mode_e2e.spec.js
 *
 * Requires: Playwright (npx playwright install chromium)
 */

import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..');

// ─── Simple static file server ──────────────────────────────────────────
function startServer(port) {
    const mimeTypes = {
        '.html': 'text/html',
        '.js': 'application/javascript',
        '.mjs': 'application/javascript',
        '.wasm': 'application/wasm',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml',
        '.webm': 'video/webm',
        '.mp4': 'video/mp4',
    };

    return new Promise((resolve) => {
        const server = createServer((req, res) => {
            let filePath = join(ROOT, decodeURIComponent(req.url.split('?')[0]));
            if (filePath.endsWith('/')) filePath += 'index.html';

            if (!existsSync(filePath)) {
                res.writeHead(404);
                res.end('Not found');
                return;
            }

            const ext = extname(filePath);
            const contentType = mimeTypes[ext] || 'application/octet-stream';

            // WASM needs special headers, and all JS modules need CORS
            const headers = {
                'Content-Type': contentType,
                'Access-Control-Allow-Origin': '*',
            };
            if (ext === '.wasm') {
                headers['Content-Type'] = 'application/wasm';
            }

            try {
                const content = readFileSync(filePath);
                res.writeHead(200, headers);
                res.end(content);
            } catch (err) {
                res.writeHead(500);
                res.end('Server error');
            }
        });

        server.listen(port, () => {
            console.log(`📡 Static server on http://localhost:${port}`);
            resolve(server);
        });
    });
}

// ─── ANSI colors ────────────────────────────────────────────────────────
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function pass(msg) { console.log(`  ${GREEN}✅ ${msg}${RESET}`); }
function fail(msg) { console.log(`  ${RED}❌ ${msg}${RESET}`); }
function info(msg) { console.log(`  ${CYAN}ℹ️  ${msg}${RESET}`); }
function header(msg) { console.log(`\n${BOLD}${YELLOW}━━━ ${msg} ━━━${RESET}`); }

// ─── Main test ──────────────────────────────────────────────────────────
async function main() {
    const PORT = 9876;
    const server = await startServer(PORT);
    const BASE = `http://localhost:${PORT}`;
    let browser;
    let passed = 0;
    let failed = 0;
    const failures = [];

    try {
        browser = await chromium.launch({ headless: true });
        const context = await browser.newContext();
        const page = await context.newPage();

        // Capture console logs from the page
        const pageLogs = [];
        page.on('console', (msg) => {
            pageLogs.push(`[${msg.type()}] ${msg.text()}`);
        });

        // ════════════════════════════════════════════════════════════════
        // TEST 1: Full pipeline — Encode → Copy binary → Refresh → Paste → Decode
        // ════════════════════════════════════════════════════════════════
        header('TEST 1: Encode → Refresh → Decode (text message)');

        const TEST_MESSAGE = 'Hello Cat Mode E2E!';
        const TEST_PASSWORD = 'test-password-2024';

        // Navigate to the web demo
        info('Loading web demo...');
        await page.goto(`${BASE}/web_demo/wasm_browser_example_FULL.html`, {
            waitUntil: 'networkidle',
            timeout: 30000,
        });

        // Wait for WASM to load
        info('Waiting for WASM initialization...');
        await page.waitForFunction(() => {
            const statusEl = document.getElementById('wasmStatus');
            return statusEl && statusEl.textContent.includes('Ready');
        }, { timeout: 60000 });
        pass('WASM loaded successfully');

        // Switch to Cat Mode tab
        info('Switching to Cat Mode tab...');
        await page.evaluate(() => window.switchMode('cat'));
        await page.waitForTimeout(500);

        // Verify Cat Mode UI is visible
        const catModeVisible = await page.isVisible('#catMode');
        if (catModeVisible) {
            pass('Cat Mode tab is visible');
        } else {
            fail('Cat Mode tab not visible');
            failed++;
            failures.push('Cat Mode tab not visible');
        }

        // Fill in message and password
        info(`Typing message: "${TEST_MESSAGE}"`);
        await page.fill('#catMessage', TEST_MESSAGE);
        await page.fill('#catPassword', TEST_PASSWORD);
        pass('Message and password entered');

        // Click encode
        info('Starting Cat Mode encode...');
        const encodePromise = page.evaluate(() => {
            return new Promise(async (resolve, reject) => {
                try {
                    // Call the encode function and wait for the binary to be stored
                    await window.catLegacyBlinkEncode();
                    // Return the binary data from sessionStorage
                    const binary = sessionStorage.getItem('meow_cat_binary');
                    const speed = sessionStorage.getItem('meow_cat_speed_ms');
                    resolve({ binary, speed, length: binary ? binary.length : 0 });
                } catch (err) {
                    reject(err.message);
                }
            });
        });

        const encodeResult = await encodePromise;

        if (encodeResult.binary && encodeResult.binary.length > 0) {
            pass(`Encoded ${encodeResult.length} bits of binary data`);
            passed++;
        } else {
            fail('No binary data produced');
            failed++;
            failures.push('No binary data produced');
        }

        // Save binary for comparison
        const originalBinary = encodeResult.binary;
        info(`Binary starts with: ${originalBinary.substring(0, 80)}...`);

        // ════════════════════════════════════════════════════════════════
        // REFRESH THE PAGE (simulate closing/reopening)
        // ════════════════════════════════════════════════════════════════
        info('🔄 Refreshing page (simulating new session)...');
        await page.reload({ waitUntil: 'networkidle', timeout: 30000 });

        // Wait for WASM to reload
        await page.waitForFunction(() => {
            const statusEl = document.getElementById('wasmStatus');
            return statusEl && statusEl.textContent.includes('Ready');
        }, { timeout: 60000 });
        pass('Page refreshed, WASM reloaded');

        // Switch to Cat Mode again
        await page.evaluate(() => window.switchMode('cat'));
        await page.waitForTimeout(500);

        // ════════════════════════════════════════════════════════════════
        // PASTE BINARY & PASSWORD → DECODE
        // ════════════════════════════════════════════════════════════════
        info('Pasting binary pattern into decode field...');
        await page.fill('#catBinaryInput', originalBinary);
        await page.fill('#catDecodePassword', TEST_PASSWORD);
        pass('Binary and password pasted');

        // Click decode
        info('Starting decode...');
        const decodeResult = await page.evaluate(() => {
            return new Promise(async (resolve, reject) => {
                try {
                    await window.catModeDecode();
                    // Read the result box
                    const resultBox = document.getElementById('catDecodeResult');
                    const innerHTML = resultBox ? resultBox.innerHTML : '';
                    const hasSuccess = resultBox ? resultBox.classList.contains('success') : false;
                    resolve({ innerHTML, hasSuccess });
                } catch (err) {
                    reject(err.message);
                }
            });
        });

        if (decodeResult.hasSuccess) {
            pass('Decode succeeded!');
            passed++;
        } else {
            fail('Decode did not produce success result');
            failed++;
            failures.push('Decode failed');
        }

        // Check that the decoded message matches
        const decodedMessageMatch = decodeResult.innerHTML.includes(TEST_MESSAGE);
        if (decodedMessageMatch) {
            pass(`Decoded message matches: "${TEST_MESSAGE}"`);
            passed++;
        } else {
            fail(`Decoded message does not contain "${TEST_MESSAGE}"`);
            info(`Result HTML: ${decodeResult.innerHTML.substring(0, 300)}`);
            failed++;
            failures.push('Message mismatch');
        }

        // ════════════════════════════════════════════════════════════════
        // TEST 2: Self-Test button (built-in self-test)
        // ════════════════════════════════════════════════════════════════
        header('TEST 2: Built-in catSelfTest()');

        // Make sure we're on Cat Mode with message + password
        await page.fill('#catMessage', 'Self-Test Message!');
        await page.fill('#catPassword', 'selftest-pass-123');

        info('Running catSelfTest()...');
        const selfTestResult = await page.evaluate(() => {
            return new Promise(async (resolve, reject) => {
                try {
                    await window.catSelfTest();
                    const resultBox = document.getElementById('catSelfTestResult');
                    const innerHTML = resultBox ? resultBox.innerHTML : '';
                    const hasSuccess = resultBox ? resultBox.classList.contains('success') : false;
                    resolve({ innerHTML, hasSuccess });
                } catch (err) {
                    reject(err.message);
                }
            });
        });

        if (selfTestResult.hasSuccess) {
            pass('catSelfTest() passed!');
            passed++;
        } else {
            fail('catSelfTest() failed');
            info(`Result: ${selfTestResult.innerHTML.substring(0, 300)}`);
            failed++;
            failures.push('catSelfTest failed');
        }

        // ════════════════════════════════════════════════════════════════
        // TEST 3: Wrong password should fail
        // ════════════════════════════════════════════════════════════════
        header('TEST 3: Wrong password should fail');

        // Re-encode with correct password
        await page.fill('#catMessage', 'Secret data');
        await page.fill('#catPassword', 'correct-password');

        const encResult2 = await page.evaluate(() => {
            return new Promise(async (resolve, reject) => {
                try {
                    await window.catLegacyBlinkEncode();
                    const binary = sessionStorage.getItem('meow_cat_binary');
                    resolve(binary);
                } catch (err) {
                    reject(err.message);
                }
            });
        });

        // Try decoding with wrong password
        await page.fill('#catBinaryInput', encResult2);
        await page.fill('#catDecodePassword', 'wrong-password!!');

        info('Attempting decode with wrong password...');
        const wrongPwResult = await page.evaluate(() => {
            return new Promise(async (resolve) => {
                try {
                    await window.catModeDecode();
                    const resultBox = document.getElementById('catDecodeResult');
                    resolve({
                        hasError: resultBox ? resultBox.classList.contains('error') : false,
                        hasSuccess: resultBox ? resultBox.classList.contains('success') : false,
                        innerHTML: resultBox ? resultBox.innerHTML : ''
                    });
                } catch (err) {
                    // Expected — wrong password should throw
                    resolve({ hasError: true, hasSuccess: false, innerHTML: err.message });
                }
            });
        });

        if (wrongPwResult.hasError && !wrongPwResult.hasSuccess) {
            pass('Wrong password correctly rejected');
            passed++;
        } else {
            fail('Wrong password was NOT rejected!');
            failed++;
            failures.push('Wrong password accepted');
        }

        // ════════════════════════════════════════════════════════════════
        // TEST 4: Encode + decode with special characters
        // ════════════════════════════════════════════════════════════════
        header('TEST 4: Special characters (emoji, unicode)');

        const SPECIAL_MSG = '🐱 Mëöw! 日本語テスト αβγ €£¥';
        const SPECIAL_PW = 'pässwörd-🔑';

        await page.fill('#catMessage', SPECIAL_MSG);
        await page.fill('#catPassword', SPECIAL_PW);

        const encSpecial = await page.evaluate(() => {
            return new Promise(async (resolve, reject) => {
                try {
                    await window.catLegacyBlinkEncode();
                    resolve(sessionStorage.getItem('meow_cat_binary'));
                } catch (err) {
                    reject(err.message);
                }
            });
        });

        await page.fill('#catBinaryInput', encSpecial);
        await page.fill('#catDecodePassword', SPECIAL_PW);

        const decSpecial = await page.evaluate(() => {
            return new Promise(async (resolve, reject) => {
                try {
                    await window.catModeDecode();
                    const resultBox = document.getElementById('catDecodeResult');
                    resolve({
                        hasSuccess: resultBox ? resultBox.classList.contains('success') : false,
                        innerHTML: resultBox ? resultBox.innerHTML : ''
                    });
                } catch (err) {
                    reject(err.message);
                }
            });
        });

        if (decSpecial.hasSuccess && decSpecial.innerHTML.includes('🐱')) {
            pass(`Special characters survived encode/decode`);
            passed++;
        } else {
            fail('Special characters failed to round-trip');
            info(`Result: ${decSpecial.innerHTML.substring(0, 300)}`);
            failed++;
            failures.push('Special characters failed');
        }

        // ════════════════════════════════════════════════════════════════
        // TEST 5: Binary pattern stability — same binary decodes correctly
        //         even after multiple page refreshes
        // ════════════════════════════════════════════════════════════════
        header('TEST 5: Binary stable across multiple refreshes');

        const STABLE_MSG = 'Stability test message';
        const STABLE_PW = 'stable-pw-42';

        await page.fill('#catMessage', STABLE_MSG);
        await page.fill('#catPassword', STABLE_PW);

        const stableBinary = await page.evaluate(() => {
            return new Promise(async (resolve, reject) => {
                try {
                    await window.catLegacyBlinkEncode();
                    resolve(sessionStorage.getItem('meow_cat_binary'));
                } catch (err) {
                    reject(err.message);
                }
            });
        });

        // Refresh twice
        info('Refreshing page twice...');
        await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
        await page.waitForFunction(() => document.getElementById('wasmStatus')?.textContent.includes('Ready'), { timeout: 60000 });
        await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
        await page.waitForFunction(() => document.getElementById('wasmStatus')?.textContent.includes('Ready'), { timeout: 60000 });

        await page.evaluate(() => window.switchMode('cat'));
        await page.waitForTimeout(300);

        // Paste and decode
        await page.fill('#catBinaryInput', stableBinary);
        await page.fill('#catDecodePassword', STABLE_PW);

        const stableResult = await page.evaluate(() => {
            return new Promise(async (resolve, reject) => {
                try {
                    await window.catModeDecode();
                    const resultBox = document.getElementById('catDecodeResult');
                    resolve({
                        hasSuccess: resultBox ? resultBox.classList.contains('success') : false,
                        innerHTML: resultBox ? resultBox.innerHTML : ''
                    });
                } catch (err) {
                    reject(err.message);
                }
            });
        });

        if (stableResult.hasSuccess && stableResult.innerHTML.includes(STABLE_MSG)) {
            pass(`Binary survives multiple refreshes, decoded: "${STABLE_MSG}"`);
            passed++;
        } else {
            fail('Binary did not survive multiple refreshes');
            info(`Result: ${stableResult.innerHTML.substring(0, 300)}`);
            failed++;
            failures.push('Multiple refresh decode failed');
        }

        // ════════════════════════════════════════════════════════════════
        // TEST 6: Verify binary pattern byte-level content
        // ════════════════════════════════════════════════════════════════
        header('TEST 6: Binary pattern contains CatProtocol magic bytes');

        // Check the binary starts with lead-in + preamble + sync, followed by 0xFE 0xCA
        const binaryContent = await page.evaluate((binary) => {
            // Convert binary string to bytes (skip preamble/sync)
            function binaryToBytes(bin) {
                const clean = bin.replace(/[^01]/g, '');
                const bytes = [];
                for (let i = 0; i + 8 <= clean.length; i += 8) {
                    bytes.push(parseInt(clean.substring(i, i + 8), 2));
                }
                return bytes;
            }

            const bytes = binaryToBytes(binary);

            // Find CatProtocol magic in the bytes (0xFE 0xCA = LE of 0xCAFE)
            let magicIndex = -1;
            for (let i = 0; i < bytes.length - 1; i++) {
                if (bytes[i] === 0xFE && bytes[i + 1] === 0xCA) {
                    magicIndex = i;
                    break;
                }
            }

            return {
                totalBytes: bytes.length,
                firstFewBytes: bytes.slice(0, 20).map(b => '0x' + b.toString(16).padStart(2, '0')),
                magicIndex,
                hasMagic: magicIndex >= 0,
            };
        }, stableBinary);

        info(`Total bytes: ${binaryContent.totalBytes}`);
        info(`First 20 bytes: [${binaryContent.firstFewBytes.join(', ')}]`);
        info(`CatProtocol magic (0xFE 0xCA) at index: ${binaryContent.magicIndex}`);

        if (binaryContent.hasMagic) {
            pass('Binary contains CatProtocol 0xCAFE magic bytes');
            passed++;
        } else {
            fail('CatProtocol magic not found in binary');
            failed++;
            failures.push('No CatProtocol magic in binary');
        }

        // ════════════════════════════════════════════════════════════════
        // PRINT SUMMARY
        // ════════════════════════════════════════════════════════════════
        console.log('\n' + '═'.repeat(60));
        if (failed === 0) {
            console.log(`${BOLD}${GREEN}🎉 ALL ${passed} TESTS PASSED!${RESET}`);
            console.log(`${GREEN}Cat Mode encode → refresh → decode is PROVEN WORKING.${RESET}`);
        } else {
            console.log(`${BOLD}${RED}💥 ${failed} FAILED, ${passed} PASSED${RESET}`);
            for (const f of failures) {
                console.log(`  ${RED}• ${f}${RESET}`);
            }
        }
        console.log('═'.repeat(60));

        // Also dump any page errors
        const pageErrors = pageLogs.filter(l => l.includes('ERROR') || l.includes('error'));
        if (pageErrors.length > 0) {
            console.log(`\n${YELLOW}Page errors/warnings:${RESET}`);
            for (const e of pageErrors.slice(0, 10)) {
                console.log(`  ${YELLOW}${e}${RESET}`);
            }
        }

        process.exitCode = failed > 0 ? 1 : 0;

    } catch (err) {
        console.error(`\n${RED}💥 FATAL ERROR: ${err.message}${RESET}`);
        console.error(err.stack);
        process.exitCode = 1;
    } finally {
        if (browser) await browser.close();
        server.close();
    }
}

main();
