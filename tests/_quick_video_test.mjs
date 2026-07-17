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

const speed = 500;
const page = await browser.newPage();
const allLogs = [];
page.on('console', msg => allLogs.push(`[${msg.type()}] ${msg.text()}`));
page.on('pageerror', err => allLogs.push(`[PAGE_ERROR] ${err.message}`));

console.log('1. Loading page...');
await page.goto('http://localhost:9899/web_demo/wasm_browser_example_FULL.html', { waitUntil: 'networkidle', timeout: 60000 });
await page.waitForFunction(() => document.getElementById('wasmStatus')?.textContent.includes('Ready'), { timeout: 60000 });
console.log('2. WASM loaded');

// Check deps
const deps = await page.evaluate(() => ({
    NRZDecoder: typeof window.NRZDecoder,
    PreambleCalibration: typeof window.PreambleCalibration,
    AdaptiveThreshold: typeof window.AdaptiveThreshold,
    AdaptiveHysteresis: typeof window.AdaptiveHysteresis,
}));
console.log('3. Dependencies:', JSON.stringify(deps));

// Switch to cat mode, encode
await page.evaluate(() => window.switchMode('cat'));
await page.waitForTimeout(300);
await page.fill('#catMessage', 'E2E Video Test!');
await page.fill('#catPassword', 'video-test-pw-2024');
await page.evaluate(() => { document.getElementById('catBlinkSpeed').value = '500'; });

// Start encode  
page.evaluate(() => { window._p = window.catLegacyBlinkEncode(); });
await page.waitForFunction(() => {
    const b = sessionStorage.getItem('meow_cat_binary');
    return b && b.length > 0;
}, { timeout: 60000 });

const originalBinary = await page.evaluate(() => sessionStorage.getItem('meow_cat_binary'));
console.log(`4. Binary: ${originalBinary.length} bits`);

// Wait for transmission
await page.waitForFunction(() => !window.catTransmitting, { timeout: 600000 });
console.log('5. Transmission complete');
await page.waitForTimeout(1000);

// Check session storage
const stored = await page.evaluate(() => ({
    headerLen: sessionStorage.getItem('meow_cat_header_len'),
    dualEye: sessionStorage.getItem('meow_cat_dual_eye'),
    speed: sessionStorage.getItem('meow_cat_speed_ms'),
}));
console.log('6. Stored metadata:', JSON.stringify(stored));

// Generate fallback video with CORRECT dual-eye schedule
console.log('7. Generating fallback video with dual-eye schedule...');
const videoResult = await page.evaluate(async (spd) => {
    const binary = sessionStorage.getItem('meow_cat_binary');
    if (!binary) return { success: false, error: 'No binary' };

    let headerLen = parseInt(sessionStorage.getItem('meow_cat_header_len') || '0');
    if (!headerLen) headerLen = 40;
    const dualEye = sessionStorage.getItem('meow_cat_dual_eye') === '1';

    // Build schedule same as encoder
    let headerBinary = binary.substring(0, headerLen);
    let payloadBinary = binary.substring(headerLen);

    if (dualEye) {
        headerBinary += '11111101'; // 0xFD mode marker
        if (payloadBinary.length % 2 !== 0) payloadBinary += '0';
    }

    const schedule = [];
    for (let i = 0; i < headerBinary.length; i++) {
        schedule.push({ left: headerBinary[i], right: headerBinary[i] });
    }
    if (dualEye) {
        for (let i = 0; i < payloadBinary.length; i += 2) {
            schedule.push({ left: payloadBinary[i] || '0', right: payloadBinary[i+1] || '0' });
        }
    } else {
        for (let i = 0; i < payloadBinary.length; i++) {
            schedule.push({ left: payloadBinary[i], right: payloadBinary[i] });
        }
    }

    console.log(`[FALLBACK] Schedule: ${schedule.length} intervals (header=${headerBinary.length}, payload=${payloadBinary.length}, dualEye=${dualEye})`);

    const canvas = document.createElement('canvas');
    canvas.width = 400; canvas.height = 400;
    const ctx = canvas.getContext('2d');

    const stream = canvas.captureStream(30);
    const chunks = [];
    let mimeType = 'video/webm;codecs=vp8';
    if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm';

    const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 500000 });
    recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };
    const done = new Promise(r => { recorder.onstop = r; });
    recorder.start(100);

    function drawFrame(leftGreen, rightGreen) {
        ctx.fillStyle = '#1a1a2e';
        ctx.fillRect(0, 0, 400, 400);
        ctx.fillStyle = '#333';
        ctx.beginPath(); ctx.arc(200, 220, 150, 0, Math.PI * 2); ctx.fill();
        ctx.beginPath(); ctx.moveTo(80, 120); ctx.lineTo(120, 30); ctx.lineTo(160, 120); ctx.fill();
        ctx.beginPath(); ctx.moveTo(240, 120); ctx.lineTo(280, 30); ctx.lineTo(320, 120); ctx.fill();
        // Left eye at x=130 (left half)
        ctx.fillStyle = leftGreen ? '#00ff88' : '#111';
        ctx.beginPath(); ctx.ellipse(130, 200, 30, 22, 0, 0, Math.PI * 2); ctx.fill();
        // Right eye at x=270 (right half)
        ctx.fillStyle = rightGreen ? '#00ff88' : '#111';
        ctx.beginPath(); ctx.ellipse(270, 200, 30, 22, 0, 0, Math.PI * 2); ctx.fill();
    }

    const fps = 30;
    const framesPerInterval = Math.max(1, Math.round(spd / (1000 / fps)));

    for (let idx = 0; idx < schedule.length; idx++) {
        drawFrame(schedule[idx].left === '1', schedule[idx].right === '1');
        for (let f = 0; f < framesPerInterval; f++) {
            await new Promise(r => setTimeout(r, 1000 / fps));
        }
    }

    drawFrame(false, false);
    await new Promise(r => setTimeout(r, 300));
    recorder.stop();
    await done;

    const blob = new Blob(chunks, { type: mimeType });
    const ab = await blob.arrayBuffer();
    return { success: true, size: blob.size, scheduleLen: schedule.length, data: Array.from(new Uint8Array(ab)) };
}, speed);

console.log(`8. Video: ${videoResult.size} bytes, ${videoResult.scheduleLen} intervals`);

const videoPath = '/tmp/cat_video_500ms.webm';
writeFileSync(videoPath, Buffer.from(videoResult.data));

// REFRESH
console.log('9. Refreshing...');
await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
await page.waitForFunction(() => document.getElementById('wasmStatus')?.textContent.includes('Ready'), { timeout: 60000 });
console.log('10. Reloaded');

await page.evaluate(() => window.switchMode('cat'));
await page.waitForTimeout(300);

// Upload video  
const fileInput = page.locator('#catVideoUpload');
await fileInput.setInputFiles(videoPath);
await page.waitForTimeout(1000);

// Check if the video file input triggered the handler
// The handler is: onchange="handleCatVideoUpload(this)"
// Playwright setInputFiles should trigger 'change' event
// But let's also dispatch it manually just in case
await page.evaluate(() => {
    const input = document.getElementById('catVideoUpload');
    if (input.files.length > 0 && !document.getElementById('catVideoDecodeBtn').disabled === false) {
        window.handleCatVideoUpload(input);
    }
});
await page.waitForTimeout(500);

// Set decode params
await page.fill('#catVideoPassword', 'video-test-pw-2024');
await page.evaluate(() => {
    document.getElementById('catVideoBlinkSpeed').value = '500';
    document.getElementById('catVideoThreshold').value = '0';
});

console.log('11. Analyzing video...');
const t0 = Date.now();

const result = await page.evaluate(async () => {
    try {
        await window.catVideoAnalyze();
        const resultBox = document.getElementById('catVideoResult');
        return {
            success: true,
            hasSuccessClass: resultBox?.classList.contains('success'),
            hasErrorClass: resultBox?.classList.contains('error'),
            innerHTML: resultBox?.innerHTML?.substring(0, 3000) || '',
            extractedBinary: document.getElementById('catBinaryInput')?.value || '',
        };
    } catch (err) {
        return { success: false, error: err.message, stack: err.stack?.substring(0, 500) };
    }
});

const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`12. Analysis done in ${elapsed}s`);
console.log(`13. Success class: ${result.hasSuccessClass}, Error class: ${result.hasErrorClass}`);

// Check if message was decoded
if (result.innerHTML.includes('E2E Video Test!')) {
    console.log('✅ MESSAGE DECODED CORRECTLY!');
} else {
    console.log('❌ Message not found in result');
}

// Check binary
if (result.extractedBinary) {
    console.log(`14. Extracted binary: ${result.extractedBinary.length} chars`);
    
    // Find CatProtocol magic in both
    const magic = '1111111011001010'; // 0xFE 0xCA
    const origIdx = originalBinary.indexOf(magic);
    const extIdx = result.extractedBinary.indexOf(magic);
    console.log(`15. Magic at: original=${origIdx}, extracted=${extIdx}`);
    
    if (origIdx >= 0 && extIdx >= 0) {
        const orig = originalBinary.substring(origIdx);
        const ext = result.extractedBinary.substring(extIdx);
        const minLen = Math.min(orig.length, ext.length);
        let mismatches = 0;
        for (let i = 0; i < minLen; i++) {
            if (orig[i] !== ext[i]) mismatches++;
        }
        console.log(`16. Bit comparison: ${minLen} bits, ${mismatches} mismatches (${((minLen-mismatches)/minLen*100).toFixed(1)}% match)`);
    }
} else {
    console.log('14. No extracted binary');
}

// Print relevant logs
const catLogs = allLogs.filter(l =>
    l.includes('[Cat') || l.includes('[NRZ') || l.includes('[Sync') ||
    l.includes('[Preamble') || l.includes('[Dual') || l.includes('[Quality') ||
    l.includes('[Adaptive') || l.includes('FALLBACK') ||
    l.includes('error') || l.includes('Error') || l.includes('threshold')
);
console.log('\n=== RELEVANT BROWSER LOGS (last 30) ===');
for (const l of catLogs.slice(-30)) console.log('  ' + l);

// Print truncated result HTML
if (result.hasErrorClass) {
    // Extract the technical details
    const techMatch = result.innerHTML.match(/Technical details.*?<\/p>/s);
    if (techMatch) console.log('\n=== TECHNICAL DETAILS ===\n', techMatch[0].replace(/<[^>]+>/g, ''));
}

await browser.close();
server.close();
process.exit(result.hasSuccessClass ? 0 : 1);
