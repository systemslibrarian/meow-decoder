// Dev helper: open the Blended Cat Mode transmitter headed for device tests.
import { chromium } from 'playwright';
import { resolve } from 'path';

const page = await (await (await chromium.launch({ channel: 'msedge', headless: false, args: ['--start-maximized'] })).newContext({ viewport: null })).newPage();
await page.goto('http://localhost:8799/web_demo/wasm_browser_example_FULL.html');
await page.waitForFunction(() => window.catModeEncode !== undefined, undefined, { timeout: 60_000 });
await page.click('#tab-cat');
await page.fill('#catMessage', 'CAT-HW-0123456789abcdef '.repeat(8));
await page.fill('#catPassword', 'cat-hardware-test-2026');
await page.click('#catFullscreenBtn');
await page.click('#catFsStartBtn');
console.log('started - polling state');
setInterval(async () => {
  try {
    const s = await page.evaluate(() => {
      const t = window.catModeTransmission;
      return `${t.status} frame=${t.frameIndex + 1}/${t.frameCount} loop=${t.loopCount} err=${document.getElementById('catModeResult')?.textContent?.slice(0, 120) || ''}`;
    });
    console.log(new Date().toISOString().slice(11, 19), s);
  } catch (e) { console.log('EVAL_FAIL', e.message.slice(0, 80)); }
}, 3000);
await new Promise(() => {});
