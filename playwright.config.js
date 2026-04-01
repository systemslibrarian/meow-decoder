/**
 * Playwright Configuration for Cross-Browser Cat Mode Testing
 *
 * Tests Cat Mode decode across:
 * - Chromium (baseline)
 * - Firefox 120+ (ES2022 support)
 * - WebKit/Safari (WebM fallback to MP4)
 * - Mobile browsers (iOS Safari, Chrome Android)
 *
 * USAGE:
 *   npx playwright test
 *   npx playwright test --project=firefox
 *   npx playwright test --project=mobile-safari
 */

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testMatch: 'test_cross_browser.spec.js',

  // Test timeout
  timeout: 60000,  // 60s per test (video decode can be slow)

  // Expect timeout for assertions
  expect: {
    timeout: 10000
  },

  // Fail immediately on first failure (fast feedback)
  fullyParallel: false,

  // Forbid test.only in CI
  forbidOnly: !!process.env.CI,

  // Retries
  retries: process.env.CI ? 2 : 0,

  // Workers (parallel execution)
  workers: process.env.CI ? 1 : undefined,

  // Reporter
  reporter: [
    ['html', { outputFolder: 'tests/playwright-report' }],
    ['json', { outputFile: 'tests/playwright-results.json' }],
    ['line']
  ],

  // Shared settings
  use: {
    // Base URL for tests
    baseURL: 'http://localhost:8080',

    // Capture trace on failure
    trace: 'on-first-retry',

    // Screenshot on failure
    screenshot: 'only-on-failure',

    // Video on failure
    video: 'retain-on-failure',

    // Viewport
    viewport: { width: 1280, height: 720 }
  },

  // Project definitions (browsers to test)
  projects: [
    // ═══════════════════════════════════════════════════════════════════
    // DESKTOP BROWSERS
    // ═══════════════════════════════════════════════════════════════════

    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Enable camera access (simulated)
        permissions: ['camera'],
        // Chromium-specific flags
        launchOptions: {
          args: [
            '--use-fake-device-for-media-stream',
            '--use-fake-ui-for-media-stream'
          ]
        }
      }
    },

    {
      name: 'firefox',
      use: {
        ...devices['Desktop Firefox'],
        // Note: Playwright does not support 'camera' permission for Firefox
        // Firefox-specific preferences
        firefoxUserPrefs: {
          'media.navigator.streams.fake': true,
          'media.navigator.permission.disabled': true
        }
      }
    },

    {
      name: 'webkit',
      use: {
        ...devices['Desktop Safari'],
        // Note: Playwright does not support 'camera' permission for WebKit
        // WebKit requires MP4 fallback (no WebM support)
        // This will be handled in test logic
      }
    },

    // ═══════════════════════════════════════════════════════════════════
    // MOBILE BROWSERS
    // ═══════════════════════════════════════════════════════════════════

    {
      name: 'mobile-chrome',
      use: {
        ...devices['Pixel 5'],
        permissions: ['camera'],
        launchOptions: {
          args: [
            '--use-fake-device-for-media-stream',
            '--use-fake-ui-for-media-stream'
          ]
        }
      }
    },

    {
      name: 'mobile-safari',
      use: {
        ...devices['iPhone 13'],
        // Note: Playwright does not support 'camera' permission for WebKit
        // iOS Safari needs MP4 fallback
      }
    },

    {
      name: 'tablet',
      use: {
        ...devices['iPad Pro'],
        // iPad Pro uses WebKit engine; camera permission not supported
      }
    },

    // ═══════════════════════════════════════════════════════════════════
    // EDGE CASES
    // ═══════════════════════════════════════════════════════════════════

    {
      name: 'low-end-mobile',
      use: {
        ...devices['Moto G4'],
        permissions: ['camera'],
        // Simulates low-end device
        launchOptions: {
          args: [
            '--use-fake-device-for-media-stream',
            '--use-fake-ui-for-media-stream'
          ]
        }
      }
    },

    {
      name: 'high-dpi',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
        deviceScaleFactor: 2,  // Retina display
        permissions: ['camera'],
        launchOptions: {
          args: [
            '--use-fake-device-for-media-stream',
            '--use-fake-ui-for-media-stream'
          ]
        }
      }
    }
  ],

  // Web server for tests
  webServer: {
    command: 'python3 -m http.server 8080',
    port: 8080,
    timeout: 120 * 1000,
    reuseExistingServer: !process.env.CI
  }
});
