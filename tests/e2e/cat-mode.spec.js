#!/usr/bin/env node

import { chromium } from '@playwright/test';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const OUTPUT_DIR = resolve(
  process.env.MEOW_CAT_CAPTURE_DIR || join(ROOT, 'test-results', 'cat-mode'),
);
const TEST_MESSAGE = process.env.MEOW_CAT_TEST_MESSAGE ||
  'Cat optical loop closure 0123456789abcdef '.repeat(16);
const TEST_PASSWORD = process.env.MEOW_CAT_TEST_PASSWORD || 'cat-mode-test-password';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function startServer() {
  const mimeTypes = {
    '.css': 'text/css',
    '.gif': 'image/gif',
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.jpg': 'image/jpeg',
    '.json': 'application/json',
    '.mjs': 'application/javascript',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.wasm': 'application/wasm',
    '.webm': 'video/webm',
  };

  const server = createServer((request, response) => {
    try {
      const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname);
      const requestedPath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      const filePath = resolve(ROOT, requestedPath);
      if (relative(ROOT, filePath).startsWith('..') || !existsSync(filePath)) {
        response.writeHead(404).end('Not found');
        return;
      }
      response.writeHead(200, {
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store',
        'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream',
      });
      response.end(readFileSync(filePath));
    } catch (error) {
      response.writeHead(500).end(String(error));
    }
  });

  return new Promise((resolveServer, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolveServer(server));
  });
}

async function main() {
  mkdirSync(OUTPUT_DIR, { recursive: true });
  const server = await startServer();
  const address = server.address();
  assert(address && typeof address === 'object', 'Static server did not expose an address');

  let browser;
  try {
    const browserChannel = process.env.MEOW_PLAYWRIGHT_CHANNEL;
    browser = await chromium.launch({
      headless: true,
      ...(browserChannel ? { channel: browserChannel } : {}),
    });
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    const page = await context.newPage();
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));

    await page.addInitScript(() => {
      window.__MEOW_CAT_TEST_CONFIG__ = {
        countdownSeconds: 1,
        targetIntervalMs: 500,
      };
    });
    await page.goto(
      `http://127.0.0.1:${address.port}/web_demo/wasm_browser_example_FULL.html`,
      { waitUntil: 'domcontentloaded', timeout: 30_000 },
    );
    await page.waitForFunction(
      () => document.getElementById('wasmStatus')?.textContent?.includes('Ready'),
      undefined,
      { timeout: 120_000 },
    );

    await page.click('#tab-cat');
    await page.fill('#catMessage', TEST_MESSAGE);
    await page.fill('#catPassword', TEST_PASSWORD);

    await page.click('#catFullscreenBtn');
    await page.waitForFunction(() => {
      const stage = document.getElementById('catCanvasStage');
      return document.fullscreenElement === stage || stage?.classList.contains('fullscreen-fallback');
    }, undefined, { timeout: 5_000 });

    const fullscreenStart = page.locator('#catFsStartBtn');
    assert(await fullscreenStart.isVisible(), 'Start Transmitting is not visible in fullscreen');
    await fullscreenStart.click();

    await page.waitForFunction(
      () => ['countdown', 'transmitting'].includes(window.catModeTransmission?.status),
      undefined,
      { timeout: 10_000 },
    );
    await page.waitForFunction(
      () => window.catModeTransmission?.status === 'transmitting',
      undefined,
      { timeout: 10_000 },
    );

    const stage = page.locator('#catCanvasStage');
    const captures = [];
    let lastSerial = 0;
    const deadline = Date.now() + 60_000;

    while (Date.now() < deadline) {
      await page.waitForFunction(
        (serial) => {
          const state = window.catModeTransmission;
          return state?.status === 'transmitting' && state.frameSerial > serial;
        },
        lastSerial,
        { timeout: 10_000 },
      );
      const state = await page.evaluate(() => ({ ...window.catModeTransmission }));
      lastSerial = state.frameSerial;

      if (state.loopCount > 0) break;
      const filename = `frame-${String(captures.length).padStart(3, '0')}.png`;
      await stage.screenshot({ path: join(OUTPUT_DIR, filename), animations: 'disabled' });
      captures.push({
        filename,
        frameIndex: state.frameIndex,
        framePayload: state.framePayload,
        frameSerial: state.frameSerial,
      });

      if (captures.length === state.frameCount) break;
    }

    const finalState = await page.evaluate(() => ({ ...window.catModeTransmission }));
    assert(finalState.frameCount > 0, 'Cat Mode exposed no optical frames');
    assert(
      captures.length === finalState.frameCount,
      `Captured ${captures.length}/${finalState.frameCount} rendered frames`,
    );
    assert(
      captures.every((capture, index) => capture.frameIndex === index),
      'Rendered frame order was not contiguous from frame 0',
    );
    assert(
      captures.every((capture) => capture.framePayload.startsWith('FOUNTAIN:')),
      'Cat Mode did not render fountain QR payloads',
    );
    assert(finalState.targetIntervalMs === 500, 'Test target interval was not applied');
    assert(finalState.scheduler === 'requestAnimationFrame', 'Cat Mode did not report rAF pacing');
    assert(finalState.encryptedPayload?.startsWith('MEOW:'), 'Encrypted payload is missing');

    const stopButton = page.locator('#catFsStopBtn');
    if (await stopButton.isVisible()) await stopButton.click();

    writeFileSync(
      join(OUTPUT_DIR, 'metadata.json'),
      JSON.stringify({
        captures,
        encryptedPayload: finalState.encryptedPayload,
        frameCount: finalState.frameCount,
        kBlocks: finalState.kBlocks,
        blockSize: finalState.blockSize,
        targetIntervalMs: finalState.targetIntervalMs,
        viewport: { width: 1280, height: 720 },
      }, null, 2),
    );

    assert(pageErrors.length === 0, `Browser errors: ${pageErrors.join('; ')}`);
    console.log(`Captured ${captures.length} Cat Mode frames in ${OUTPUT_DIR}`);
  } finally {
    if (browser) await browser.close();
    await new Promise((resolveClose) => server.close(resolveClose));
  }
}

main().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});