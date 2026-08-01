// Dev helper: transmit a Cat Blink v2 stream headed for device tests.
import { chromium } from 'playwright';

const page = await (await (await chromium.launch({ channel: 'msedge', headless: false, args: ['--start-maximized'] })).newContext({ viewport: null })).newPage();
page.on('pageerror', (e) => console.log('PAGEERROR', e.message.slice(0, 140)));
await page.goto('http://localhost:8799/web_demo/wasm_browser_example_FULL.html');
await page.waitForFunction(() => window.catBlinkV2Encode !== undefined, undefined, { timeout: 60_000 });
await page.click('#tab-cat');
await page.fill('#catMessage', 'hi');
await page.fill('#catPassword', 'pw');
// Faster blink for the device smoke test: inject a 200ms option (30fps
// camera oversamples ~6x per blink). Physics still makes this minutes/loop.
await page.evaluate(() => {
  const sel = document.getElementById('catBlinkSpeed');
  const opt = document.createElement('option');
  opt.value = '200'; opt.textContent = '200ms (test)'; opt.selected = true;
  sel.insertBefore(opt, sel.firstChild); sel.value = '200';
});
await page.evaluate(() => window.catBlinkV2Encode());
console.log('started v2 blink - polling state');
setInterval(async () => {
  try {
    const s = await page.evaluate(() => {
      const t = window.catBlinkV2State || {};
      return `${t.status} frame=${t.frameIndex}/${t.frameCount} k=${t.kBlocks} loop=${t.loopCount} bytes=${t.payloadBytesLen}`;
    });
    console.log(new Date().toISOString().slice(11, 19), s);
  } catch (e) { console.log('EVAL_FAIL', e.message.slice(0, 80)); }
}, 3000);
await new Promise(() => {});
