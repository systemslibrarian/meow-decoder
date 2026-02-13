#!/usr/bin/env node

/**
 * Headless test runner for Cat Mode golden video validation
 * Runs test_cat_mode_golden.html in headless Chrome and reports results
 */

const { spawn } = require('child_process');
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
        
        // Default to index.html
        if (req.url === '/') {
            filePath = path.join(__dirname, '..', 'tests', 'test_cat_mode_golden.html');
        }
        
        // Security: prevent directory traversal
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
            
            // Determine content type
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
// Headless Chrome Test Runner
// ====================================================================

async function runHeadlessTest() {
    console.log('\n🧪 Running Cat Mode Golden Video Test in Headless Chrome\n');
    
    // Start HTTP server
    const server = await startServer();
    
    try {
        // Find Chrome/Chromium executable
        const chromePaths = [
            '/usr/bin/google-chrome',
            '/usr/bin/chromium-browser',
            '/usr/bin/chromium',
            '/snap/bin/chromium',
            process.env.CHROME_BIN
        ].filter(Boolean);
        
        let chromePath = null;
        for (const p of chromePaths) {
            if (fs.existsSync(p)) {
                chromePath = p;
                break;
            }
        }
        
        if (!chromePath) {
            throw new Error('Chrome/Chromium not found. Install with: apt-get install chromium-browser');
        }
        
        console.log(`✓ Using Chrome: ${chromePath}\n`);
        
        // Run headless Chrome
        const chromeArgs = [
            '--headless',
            '--disable-gpu',
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--disable-software-rasterizer',
            '--run-all-compositor-stages-before-draw',
            '--virtual-time-budget=120000', // 2 minutes virtual time
            '--dump-dom',
            TEST_URL
        ];
        
        const chrome = spawn(chromePath, chromeArgs);
        
        let stdout = '';
        let stderr = '';
        
        chrome.stdout.on('data', (data) => {
            stdout += data.toString();
        });
        
        chrome.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        const exitCode = await new Promise((resolve) => {
            chrome.on('close', resolve);
            
            setTimeout(() => {
                console.error('❌ Test timeout after 2 minutes');
                chrome.kill();
                resolve(1);
            }, TIMEOUT_MS);
        });
        
        // Parse test results from DOM output
        const results = parseTestResults(stdout);
        
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
        }
        
        console.log('='.repeat(70));
        
        if (results.allPass) {
            console.log('\x1b[32m✅ ALL TESTS PASSED\x1b[0m\n');
            return 0;
        } else {
            console.log('\x1b[31m❌ SOME TESTS FAILED\x1b[0m\n');
            console.log('Failed assertions:');
            for (const assertion of results.assertions.filter(a => !a.pass)) {
                console.log(`  - ${assertion.name}`);
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
// Results Parser
// ====================================================================

function parseTestResults(htmlOutput) {
    const assertions = [];
    let allPass = false;
    
    // Look for assertion elements in HTML
    const assertionRegex = /<div class="assertion (pass|fail)"[^>]*>(.*?)<\/div>/gs;
    const matches = [...htmlOutput.matchAll(assertionRegex)];
    
    for (const match of matches) {
        const pass = match[1] === 'pass';
        const content = match[2];
        
        // Extract name, expected, actual
        const nameMatch = content.match(/<strong>(.*?)<\/strong>/);
        const expectedMatch = content.match(/Expected: (.*?)(?:<br>|$)/);
        const actualMatch = content.match(/Actual: (.*?)$/);
        
        if (nameMatch) {
            assertions.push({
                name: nameMatch[1],
                expected: expectedMatch ? expectedMatch[1].replace(/<[^>]*>/g, '').trim() : 'N/A',
                actual: actualMatch ? actualMatch[1].replace(/<[^>]*>/g, '').trim() : 'N/A',
                pass
            });
        }
    }
    
    // Check for overall pass status
    if (htmlOutput.includes('TEST PASSED')) {
        allPass = true;
    } else if (htmlOutput.includes('TEST FAILED')) {
        allPass = false;
    } else if (assertions.length > 0) {
        allPass = assertions.every(a => a.pass);
    }
    
    return { assertions, allPass };
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
