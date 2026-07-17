import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync, existsSync, writeFileSync } from 'fs';
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

const speed = 200;
const page = await browser.newPage();
const allLogs = [];
page.on('console', msg => allLogs.push(`[${msg.type()}] ${msg.text()}`));

console.log('Loading page...');
await page.goto('http://localhost:9899/web_demo/wasm_browser_example_FULL.html', { waitUntil: 'networkidle', timeout: 60000 });
await page.waitForFunction(() => document.getElementById('wasmStatus')?.textContent.includes('Ready'), { timeout: 60000 });

await page.evaluate(() => window.switchMode('cat'));
await page.waitForTimeout(300);
await page.fill('#catMessage', 'E2E Video Test!');
await page.fill('#catPassword', 'video-test-pw-2024');
await page.evaluate(() => { document.getElementById('catBlinkSpeed').value = '200'; });

page.evaluate(() => { window._p = window.catLegacyBlinkEncode(); });
await page.waitForFunction(() => {
    const b = sessionStorage.getItem('meow_cat_binary');
    return b && b.length > 0;
}, { timeout: 60000 });

const binary = await page.evaluate(() => sessionStorage.getItem('meow_cat_binary'));
console.log(`Binary: ${binary.length} bits`);

await page.waitForFunction(() => !window.catTransmitting, { timeout: 600000 });
console.log('Transmission complete');

// Generate video with HIGHER framerate (60fps instead of 30)
const videoResult = await page.evaluate(async (spd) => {
    const binary = sessionStorage.getItem('meow_cat_binary');
    let headerLen = parseInt(sessionStorage.getItem('meow_cat_header_len') || '0') || 40;
    const dualEye = sessionStorage.getItem('meow_cat_dual_eye') === '1';

    let headerBinary = binary.substring(0, headerLen);
    let payloadBinary = binary.substring(headerLen);
    if (dualEye) {
        headerBinary += '11111101';
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
    }

    const canvas = document.createElement('canvas');
    canvas.width = 400; canvas.height = 400;
    const ctx = canvas.getContext('2d');

    // Use 60fps for better temporal resolution
    const recordFps = 60;
    const stream = canvas.captureStream(recordFps);
    const chunks = [];
    let mimeType = 'video/webm;codecs=vp8';
    if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm';

    const recorder = new MediaRecorder(stream, {
        mimeType,
        videoBitsPerSecond: 2000000  // 2 Mbps for cleaner frames
    });
    recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };
    const done = new Promise(r => { recorder.onstop = r; });
    recorder.start(50); // More frequent data collection

    function drawFrame(leftGreen, rightGreen) {
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
    console.log(`[FALLBACK] ${framesPerInterval} frames/interval at ${recordFps}fps, ${schedule.length} intervals`);

    for (let idx = 0; idx < schedule.length; idx++) {
        drawFrame(schedule[idx].left === '1', schedule[idx].right === '1');
        for (let f = 0; f < framesPerInterval; f++) {
            await new Promise(r => setTimeout(r, 1000 / recordFps));
        }
    }

    drawFrame(false, false);
    await new Promise(r => setTimeout(r, 300));
    recorder.stop();
    await done;

    const blob = new Blob(chunks, { type: mimeType });
    const ab = await blob.arrayBuffer();
    return { success: true, size: blob.size, framesPerInterval, data: Array.from(new Uint8Array(ab)) };
}, speed);

console.log(`Video: ${videoResult.size} bytes, ${videoResult.framesPerInterval} frames/interval`);
const videoPath = '/tmp/cat_video_200ms.webm';
writeFileSync(videoPath, Buffer.from(videoResult.data));

// REFRESH & ANALYZE
await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
await page.waitForFunction(() => document.getElementById('wasmStatus')?.textContent.includes('Ready'), { timeout: 60000 });
await page.evaluate(() => window.switchMode('cat'));
await page.waitForTimeout(300);

await page.locator('#catVideoUpload').setInputFiles(videoPath);
await page.waitForTimeout(1000);
await page.evaluate(() => {
    const input = document.getElementById('catVideoUpload');
    if (input.files.length > 0) window.handleCatVideoUpload(input);
});
await page.waitForTimeout(500);

await page.fill('#catVideoPassword', 'video-test-pw-2024');
await page.evaluate(() => {
    document.getElementById('catVideoBlinkSpeed').value = '200';
    document.getElementById('catVideoThreshold').value = '0';
});

console.log('Analyzing...');
const result = await page.evaluate(async () => {
    try {
        await window.catVideoAnalyze();
        const rb = document.getElementById('catVideoResult');
        return {
            hasSuccess: rb?.classList.contains('success'),
            hasError: rb?.classList.contains('error'),
            extracted: document.getElementById('catBinaryInput')?.value || '',
            html: rb?.innerHTML?.substring(0, 500)
        };
    } catch (err) { return { error: err.message }; }
});

if (result.hasSuccess) {
    console.log('✅ SUCCESS');
    if (result.extracted) {
        const magic = '1111111011001010';
        const oi = binary.indexOf(magic), ei = result.extracted.indexOf(magic);
        if (oi >= 0 && ei >= 0) {
            const o = binary.substring(oi), e = result.extracted.substring(ei);
            const ml = Math.min(o.length, e.length);
            let mm = 0;
            for (let i = 0; i < ml; i++) if (o[i] !== e[i]) mm++;
            console.log(`Binary: ${ml} bits, ${mm} mismatches (${((ml-mm)/ml*100).toFixed(1)}%)`);
        }
    }
} else {
    console.log('❌ FAIL');
    // Print key logs
    const keyLogs = allLogs.filter(l => l.includes('NRZ') || l.includes('Sync') || l.includes('Preamble') || l.includes('Dual') || l.includes('decoded') || l.includes('bits'));
    for (const l of keyLogs.slice(-15)) console.log('  ' + l);
}

await browser.close();
server.close();
process.exit(result.hasSuccess ? 0 : 1);
