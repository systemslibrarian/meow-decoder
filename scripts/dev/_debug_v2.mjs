import { chromium } from 'playwright';
const page = await (await (await chromium.launch({ channel: 'msedge', headless: true })).newContext()).newPage();
const errs = [];
page.on('pageerror', e => errs.push('PAGEERROR: ' + e.message));
page.on('console', m => { if (m.type()==='error') errs.push('CONSOLE: ' + m.text().slice(0,200)); });
await page.goto('http://localhost:8799/web_demo/wasm_browser_example_FULL.html');
await page.waitForFunction(() => window.catBlinkV2Encode !== undefined, undefined, { timeout: 60000 });
const diag = await page.evaluate(() => ({
  hasCatBlinkV2: typeof window.CatBlinkV2,
  hasFountainEncoder: typeof window.FountainEncoder,
  hasDroplet: typeof window.Droplet,
  hasPackPayload: typeof window.packPayload,
  hasCrypto: typeof window.crypto,
}));
console.log('DIAG', JSON.stringify(diag));
await page.click('#tab-cat');
await page.fill('#catMessage', 'hi');
await page.fill('#catPassword', 'pw');
const res = await page.evaluate(async () => {
  try { await window.catBlinkV2Encode(); return 'ok status=' + (window.catBlinkV2State||{}).status; }
  catch(e){ return 'THREW: ' + e.message + ' | ' + (e.stack||'').split('\n').slice(0,3).join(' <- '); }
});
console.log('ENCODE', res);
console.log('RESULT_EL', await page.evaluate(() => document.getElementById('catModeResult')?.textContent?.slice(0,160)));
console.log('ERRS', errs.slice(0,5).join(' || '));
process.exit(0);
