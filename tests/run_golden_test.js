#!/usr/bin/env node

/**
 * Headless test runner for Cat Mode golden video validation
 * Uses Playwright to run test_cat_mode_golden.html and reports results
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// ====================================================================
// Configuration
// ====================================================================

const PORT = 8765;
const TEST_URL = `http://localhost:${PORT}/tests/test_cat_mode_golden.html`;
const TIMEOUT_MS = 120000; // 2 minutes

// ====================================================================
// HTTP Server
// ====================================================================

function startServer() {
    const server = http.createServer((req, res) => {
        let filePath = path.join(__dirname, '..', req.url);

        if (req.url === '/') {
            filePath = path.join(__dirname, '..', 'tests', 'test_cat_mode_golden.html');
        }

        const resolvedPath = path.resolve(filePath);
        const projectRoot = path.resolve(__dirname, '..');
        if (!resolvedPath.startsWith(projectRoot)) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Forbidden');
            return;
        }

        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Not Found: ' + req.url);
                return;
            }

            const ext = path.extname(filePath);
            const contentTypes = {
                '.html': 'text/html',
                '.js': 'application/javascript',
                '.json': 'application/json',
                '.css': 'text/css',
                '.webm': 'video/webm',
                '.mp4': 'video/mp4'
            };

            const contentType = contentTypes[ext] || 'application/octet-stream';
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(data);
        });
    });

    return new Promise((resolve) => {
        server.listen(PORT, () => {
            console.log(`✓ Test server running on http://localhost:${PORT}`);
            resolve(server);
        });
    });
}

// ====================================================================
// Playwright Test Runner
// ====================================================================

async function runHeadlessTest() {
    console.log('\n🧪 Running Cat Mode Golden Video Test via Playwright\n');

    const server = await startServer();

    try {
        let chromium;
        try {
            chromium = require('@playwright/test').chromium;
        } catch {
            try {
                chromium = require('playwright-core').chromium;
            } catch {
                throw new Error('Playwright not installed. Run: npm install @playwright/test');
            }
        }

        const browser = await chromium.launch({
            headless: true,
            executablePath: process.env.CHROME_BIN || '/usr/bin/chromium-browser',
            args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
        });

        const page = await browser.newPage();

        // Collect console messages
        const consoleLogs = [];
        page.on('console', msg => {
            consoleLogs.push(msg.text());
        });

        page.on('pageerror', err => {
            console.error('  [page error]', err.message);
        });

        await page.goto(TEST_URL, { waitUntil: 'domcontentloaded', timeout: 30000 });

        // Run all tests by calling the page's runAllTests function
        await page.evaluate(() => {
            if (typeof runAllTests === 'function') {
                return runAllTests();
            }
            const btn = document.getElementById('runBtn') || document.querySelector('button');
            if (btn) btn.click();
        });

        // Wait for results to appear
        await page.waitForFunction(() => {
            const status = document.querySelector('.status');
            return status && (status.classList.contains('pass') || status.classList.contains('fail'));
        }, { timeout: TIMEOUT_MS });

        // Extract assertions from the DOM
        const results = await page.evaluate(() => {
            const assertionDivs = document.querySelectorAll('.assertion');
            const assertions = [];
            for (const div of assertionDivs) {
                const pass = div.classList.contains('pass');
                const strong = div.querySelector('strong');
                const text = div.textContent;
                const expectedMatch = text.match(/Expected:\s*(.*?)(?:\n|Actual:)/s);
                const actualMatch = text.match(/Actual:\s*(.*?)$/s);
                assertions.push({
                    name: strong ? strong.textContent : 'Unknown',
                    expected: expectedMatch ? expectedMatch[1].trim() : 'N/A',
                    actual: actualMatch ? actualMatch[1].trim() : 'N/A',
                    pass
                });
            }
            const status = document.querySelector('.status');
            const allPass = status ? status.classList.contains('pass') : false;
            return { assertions, allPass };
        });

        await browser.close();

        // Print results
        console.log('\n' + '='.repeat(70));
        console.log('📊 Test Results');
        console.log('='.repeat(70) + '\n');

        if (results.assertions.length > 0) {
            for (const assertion of results.assertions) {
                const icon = assertion.pass ? '✓' : '✗';
                const color = assertion.pass ? '\x1b[32m' : '\x1b[31m';
                const reset = '\x1b[0m';

                console.log(`${color}${icon}${reset} ${assertion.name}`);
                console.log(`  Expected: ${assertion.expected}`);
                console.log(`  Actual:   ${assertion.actual}`);
                console.log('');
            }
        } else {
            console.log('No assertions captured from DOM. Console output:');
            for (const log of consoleLogs) {
                console.log('  [console]', log);
            }
        }

        console.log('='.repeat(70));

        if (results.allPass) {
            console.log('\x1b[32m✅ ALL TESTS PASSED\x1b[0m\n');
            return 0;
        } else {
            console.log('\x1b[31m❌ SOME TESTS FAILED\x1b[0m\n');
            if (results.assertions.length > 0) {
                console.log('Failed assertions:');
                for (const a of results.assertions.filter(a => !a.pass)) {
                    console.log(`  - ${a.name}: expected=${a.expected}, actual=${a.actual}`);
                }
            }
            console.log('');
            return 1;
        }

    } catch (error) {
        console.error('\n❌ Test execution failed:', error.message);
        return 1;
    } finally {
        server.close();
        console.log('✓ Test server stopped\n');
    }
}

// ====================================================================
// Main
// ====================================================================

if (require.main === module) {
    runHeadlessTest()
        .then(exitCode => {
            process.exit(exitCode);
        })
        .catch(error => {
            console.error('Fatal error:', error);
            process.exit(1);
        });
}

module.exports = { runHeadlessTest };
