/**
 * Analyze example8.webm decode failure — extract full diagnostics
 */
import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..');

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

async function main() {
    const port = 9950 + Math.floor(Math.random() * 50);
    const srv = await startServer(port);
    const base = `http://localhost:${port}`;
    console.log(`Server on port ${port}`);

    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    const logs = [];
    page.on('console', msg => {
        const t = msg.text();
        logs.push(t);
        if (t.includes('[Cat') || t.includes('Packet') || t.includes('packet') ||
            t.includes('NRZ') || t.includes('Sync') || t.includes('gap') ||
            t.includes('Gap') || t.includes('Invalid') || t.includes('magic') ||
            t.includes('Error') || t.includes('binary')) {
            console.log(`  [page] ${t.substring(0, 250)}`);
        }
    });

    await page.goto(`${base}/web_demo/wasm_browser_example_FULL.html`, {
        waitUntil: 'networkidle', timeout: 60000,
    });
    await page.waitForFunction(
        () => document.getElementById('wasmStatus')?.textContent.includes('Ready'),
        { timeout: 60000 }
    );
    await page.evaluate(() => window.switchMode('cat'));
    await page.waitForTimeout(500);
    console.log('Page ready, WASM loaded');

    const videoPath = join(ROOT, 'assets', 'example8.webm');
    await page.locator('#catVideoUpload').setInputFiles(videoPath);
    await page.waitForTimeout(500);
    await page.evaluate(() => {
        const input = document.getElementById('catVideoUpload');
        if (input.files.length > 0) window.handleCatVideoUpload(input);
    });
    await page.waitForTimeout(1000);

    await page.fill('#catVideoPassword', 'dogdogdog');
    await page.evaluate(() => {
        const sel = document.getElementById('catVideoBlinkSpeed');
        if (!Array.from(sel.options).some(o => o.value === '200')) {
            sel.add(new Option('200ms', '200'));
        }
        sel.value = '200';
        document.getElementById('catVideoThreshold').value = '0';
    });

    console.log('Starting catVideoAnalyze on example8.webm...');

    const result = await Promise.race([
        page.evaluate(async () => {
            try {
                await window.catVideoAnalyze();
                const rb = document.getElementById('catVideoResult');
                return {
                    hasSuccess: rb?.classList.contains('success') || false,
                    hasError: rb?.classList.contains('error') || false,
                    html: rb?.innerHTML?.substring(0, 4000) || '',
                };
            } catch (err) {
                return { error: err.message?.substring(0, 1000), hasSuccess: false, hasError: true };
            }
        }),
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Timed out after 5 minutes')), 300000)
        ),
    ]);

    console.log('\n=== RESULT ===');
    console.log(`Success: ${result.hasSuccess}, Error: ${result.hasError}`);
    if (result.error) console.log(`Error: ${result.error}`);

    const diag = await page.evaluate(() => {
        const d = window.catDiagnostics || {};
        return {
            frame_gaps: d.video?.frame_gaps || [],
            frame_gap_total_ms: d.video?.frame_gap_total_ms || 0,
            total_frames: d.video?.total_frames || 0,
            duration: d.video?.duration_sec || 0,
            decoding: d.decoding || {},
            error_msg: d.error?.message || null,
        };
    });

    console.log('\n=== VIDEO INFO ===');
    console.log(`Frames: ${diag.total_frames}, Duration: ${diag.duration}s`);
    console.log(`Frame gaps: ${diag.frame_gaps.length}, Total gap time: ${diag.frame_gap_total_ms}ms`);

    console.log('\n=== FRAME GAPS ===');
    for (const g of diag.frame_gaps) {
        console.log(`  ${g.startTime.toFixed(1)}s - ${g.endTime.toFixed(1)}s (${g.durationMs}ms, ${g.count} frames)`);
    }

    console.log('\n=== DECODING ===');
    console.log(JSON.stringify(diag.decoding, null, 2));

    if (diag.error_msg) console.log(`\n=== ERROR ===\n${diag.error_msg}`);

    console.log('\n=== RELEVANT LOG ENTRIES ===');
    for (const l of logs) {
        if (l.includes('Header@') || l.includes('Invalid packet') ||
            l.includes('No more') || l.includes('Payload:') ||
            l.includes('First 20 bytes') || l.includes('Expected total') ||
            l.includes('session') || l.includes('frame gap') ||
            l.includes('Detected ') || l.includes('alternation') ||
            l.includes('Data starts') || l.includes('Decoded ') ||
            l.includes('dual-eye') || l.includes('Dual-eye') ||
            l.includes('marker') || l.includes('0xFD')) {
            console.log(`  ${l.substring(0, 300)}`);
        }
    }

    await browser.close();
    srv.close();
    console.log('\nDone.');
}

main().catch(e => { console.error(e); process.exit(1); });
