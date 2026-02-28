import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { join, extname } from 'path';

const ROOT = '/workspaces/meow-decoder';
const mimeTypes = {
    '.html': 'text/html', '.js': 'application/javascript',
    '.wasm': 'application/wasm', '.css': 'text/css', '.json': 'application/json',
    '.png': 'image/png', '.webm': 'video/webm',
};

const server = await new Promise(resolve => {
    const s = createServer((req, res) => {
        let fp = join(ROOT, decodeURIComponent(req.url.split('?')[0]));
        if (fp.endsWith('/')) fp += 'index.html';
        if (!existsSync(fp)) { res.writeHead(404); res.end('Not found'); return; }
        const ext = extname(fp);
        res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream', 'Access-Control-Allow-Origin': '*' });
        res.end(readFileSync(fp));
    });
    s.listen(9899, () => resolve(s));
});

const browser = await chromium.launch({
    headless: false,
    args: ['--no-sandbox', '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream']
});

const page = await browser.newPage();
const allLogs = [];
page.on('console', msg => allLogs.push(`[${msg.type()}] ${msg.text()}`));
page.on('pageerror', err => allLogs.push(`[PAGE_ERROR] ${err.message}`));

console.log('1. Loading page...');
await page.goto('http://localhost:9899/web_demo/wasm_browser_example_FULL.html', { waitUntil: 'networkidle', timeout: 60000 });
await page.waitForFunction(() => document.getElementById('wasmStatus')?.textContent.includes('Ready'), { timeout: 60000 });
console.log('2. WASM loaded');

// Check deps right after load
const depsCheck = await page.evaluate(() => ({
    NRZDecoder: typeof window.NRZDecoder,
    PreambleCalibration: typeof window.PreambleCalibration,
    AdaptiveThreshold: typeof window.AdaptiveThreshold,
    AdaptiveHysteresis: typeof window.AdaptiveHysteresis,
    CatProtocol: typeof window.CatProtocol,
    catVideoAnalyze: typeof window.catVideoAnalyze,
}));
console.log('3. Dependencies after initial load:', JSON.stringify(depsCheck));

// Switch to cat mode, encode
await page.evaluate(() => window.switchMode('cat'));
await page.waitForTimeout(300);
await page.fill('#catMessage', 'Debug Test');
await page.fill('#catPassword', 'debug123');
await page.evaluate(() => { document.getElementById('catBlinkSpeed').value = '500'; });

// Start encode
page.evaluate(() => { window._p = window.catModeEncode(); });
await page.waitForFunction(() => {
    const b = sessionStorage.getItem('meow_cat_binary');
    return b && b.length > 0;
}, { timeout: 60000 });

const binary = await page.evaluate(() => sessionStorage.getItem('meow_cat_binary'));
console.log(`4. Binary: ${binary.length} bits`);

// Wait for transmission to end
await page.waitForFunction(() => !window.catTransmitting, { timeout: 600000 });
console.log('5. Transmission complete');
await page.waitForTimeout(2000);

// Check blob
const hasBlob = await page.evaluate(() => !!window.catRecordedBlob && window.catRecordedBlob.size > 0);
console.log(`6. Has blob: ${hasBlob}`);

// Generate fallback video
console.log('7. Generating fallback video...');
const videoResult = await page.evaluate(async () => {
    const binary = sessionStorage.getItem('meow_cat_binary');
    const canvas = document.createElement('canvas');
    canvas.width = 400; canvas.height = 400;
    const ctx = canvas.getContext('2d');
    
    const stream = canvas.captureStream(30);
    const chunks = [];
    let mime = 'video/webm;codecs=vp8';
    if (!MediaRecorder.isTypeSupported(mime)) mime = 'video/webm';
    
    const recorder = new MediaRecorder(stream, { mimeType: mime, videoBitsPerSecond: 500000 });
    recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };
    const done = new Promise(r => { recorder.onstop = r; });
    recorder.start(100);
    
    const fps = 30;
    const spd = 500;
    const framesPerBit = Math.max(1, Math.round(spd / (1000 / fps)));
    
    for (let i = 0; i < binary.length; i++) {
        const isGreen = binary[i] === '1';
        ctx.fillStyle = '#1a1a2e';
        ctx.fillRect(0, 0, 400, 400);
        // Cat face
        ctx.fillStyle = '#333';
        ctx.beginPath(); ctx.arc(200, 220, 150, 0, Math.PI * 2); ctx.fill();
        // Ears
        ctx.beginPath(); ctx.moveTo(80, 120); ctx.lineTo(120, 30); ctx.lineTo(160, 120); ctx.fill();
        ctx.beginPath(); ctx.moveTo(240, 120); ctx.lineTo(280, 30); ctx.lineTo(320, 120); ctx.fill();
        // Eyes
        ctx.fillStyle = isGreen ? '#00ff88' : '#111';
        ctx.beginPath(); ctx.ellipse(150, 200, 25, 20, 0, 0, Math.PI * 2); ctx.fill();
        ctx.beginPath(); ctx.ellipse(250, 200, 25, 20, 0, 0, Math.PI * 2); ctx.fill();
        
        for (let f = 0; f < framesPerBit; f++) {
            await new Promise(r => setTimeout(r, 1000 / fps));
        }
    }
    
    await new Promise(r => setTimeout(r, 500));
    recorder.stop();
    await done;
    
    const blob = new Blob(chunks, { type: mime });
    const ab = await blob.arrayBuffer();
    return { size: blob.size, data: Array.from(new Uint8Array(ab)) };
});

console.log(`8. Video generated: ${videoResult.size} bytes`);

// Save video
const videoPath = '/tmp/debug_cat_video.webm';
writeFileSync(videoPath, Buffer.from(videoResult.data));

// REFRESH
console.log('9. Refreshing page...');
await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
await page.waitForFunction(() => document.getElementById('wasmStatus')?.textContent.includes('Ready'), { timeout: 60000 });
console.log('10. Page reloaded');

// Check deps after reload
const depsCheck2 = await page.evaluate(() => ({
    NRZDecoder: typeof window.NRZDecoder,
    PreambleCalibration: typeof window.PreambleCalibration,
    AdaptiveThreshold: typeof window.AdaptiveThreshold,
    AdaptiveHysteresis: typeof window.AdaptiveHysteresis,
    CatProtocol: typeof window.CatProtocol,
    catVideoAnalyze: typeof window.catVideoAnalyze,
    catVideoFile: typeof window.catVideoFile,
}));
console.log('11. Dependencies after reload:', JSON.stringify(depsCheck2));

await page.evaluate(() => window.switchMode('cat'));
await page.waitForTimeout(300);

// Upload video
console.log('12. Uploading video...');
const fileInput = page.locator('#catVideoUpload');
await fileInput.setInputFiles(videoPath);
await page.waitForTimeout(1000);

// Check if catVideoFile was set
const videoFileCheck = await page.evaluate(() => ({
    catVideoFile: !!window.catVideoFile,
    catVideoFileSize: window.catVideoFile ? window.catVideoFile.size : 0,
    catVideoFileName: window.catVideoFile ? window.catVideoFile.name : 'none'
}));
console.log('13. Video file state:', JSON.stringify(videoFileCheck));

// Set decode params
await page.fill('#catVideoPassword', 'debug123');
await page.evaluate(() => {
    document.getElementById('catVideoBlinkSpeed').value = '500';
    document.getElementById('catVideoThreshold').value = '0';
});

// Analyze
console.log('14. Starting analysis...');
const t0 = Date.now();

const result = await page.evaluate(async () => {
    try {
        await window.catVideoAnalyze();
        const resultBox = document.getElementById('catVideoResult');
        return {
            success: true,
            hasSuccessClass: resultBox?.classList.contains('success'),
            hasErrorClass: resultBox?.classList.contains('error'),
            innerHTML: resultBox?.innerHTML?.substring(0, 2000) || '',
            extractedBinary: document.getElementById('catBinaryInput')?.value || '',
        };
    } catch (err) {
        return { success: false, error: err.message, stack: err.stack?.substring(0, 500) };
    }
});

console.log(`15. Analysis done in ${Date.now() - t0}ms`);
console.log('16. Result:', JSON.stringify(result).substring(0, 2000));

// Print relevant console logs
const catLogs = allLogs.filter(l => 
    l.includes('Cat') || l.includes('NRZ') || l.includes('Video') || l.includes('script') ||
    l.includes('error') || l.includes('Error') || l.includes('not defined') || l.includes('not loaded') ||
    l.includes('not a function') || l.includes('is not a constructor')
);
console.log('\n=== RELEVANT BROWSER LOGS ===');
for (const l of catLogs.slice(-40)) console.log('  ' + l);

console.log('\n=== ALL ERROR LOGS ===');
for (const l of allLogs.filter(l => l.startsWith('[error]') || l.startsWith('[PAGE_ERROR]'))) console.log('  ' + l);

await browser.close();
server.close();
process.exit(0);
