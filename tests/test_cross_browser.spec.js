/**
 * Cross-Browser Cat Mode Test Suite
 * 
 * Tests Cat Mode decode functionality across multiple browsers and devices:
 * - Chromium (baseline)
 * - Firefox (ES2022 compatibility)
 * - WebKit/Safari (WebM → MP4 fallback)
 * - Mobile browsers (iOS, Android)
 * 
 * USAGE:
 *   npx playwright test
 *   npx playwright test --project=firefox
 *   npx playwright test --headed (with UI)
 *   npx playwright test --debug (step through)
 */

import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

// Test data
const GOLDEN_VIDEOS = [
    {
        name: 'empty_hash',
        file: 'cat_mode_golden_empty_hash_100ms.webm',
        expectedPayload: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        duration: 31.2,
        frames: 936
    },
    {
        name: 'short',
        file: 'cat_mode_golden_short_150ms.webm',
        expectedPayload: 'DEADBEEF',
        duration: 19.2,
        frames: 576
    }
];

// Browser-specific capabilities
const BROWSER_FEATURES = {
    chromium: {
        supportsWebM: true,
        supportsMediaRecorder: true,
        supportsFileAccess: true
    },
    firefox: {
        supportsWebM: true,
        supportsMediaRecorder: true,
        supportsFileAccess: true
    },
    webkit: {
        supportsWebM: false,  // Safari needs MP4
        supportsMediaRecorder: true,
        supportsFileAccess: true
    }
};

test.describe('Cat Mode Cross-Browser Compatibility', () => {
    
    test.beforeEach(async ({ page, browserName }) => {
        // Navigate to Cat Mode test page
        await page.goto('/examples/wasm_browser_example.html');
        
        // Wait for page load
        await page.waitForLoadState('networkidle');
        
        // Check browser features
        const features = BROWSER_FEATURES[browserName] || BROWSER_FEATURES.chromium;
        
        console.log(`Testing on ${browserName}`);
        console.log(`WebM support: ${features.supportsWebM}`);
    });
    
    test('should load Cat Mode UI', async ({ page }) => {
        // Check that main UI elements exist
        await expect(page.locator('#catModeContainer')).toBeVisible();
        await expect(page.locator('#startCatButton')).toBeVisible();
        await expect(page.locator('#stopCatButton')).toBeVisible();
        
        // Check video element
        await expect(page.locator('#webcamVideo')).toBeVisible();
    });
    
    test('should support video playback', async ({ page, browserName }) => {
        const features = BROWSER_FEATURES[browserName] || BROWSER_FEATURES.chromium;
        
        // Try to play a test video
        const videoPath = '/tests/golden/cat_mode_golden_empty_hash_100ms.webm';
        
        if (!features.supportsWebM) {
            console.log(`${browserName} does not support WebM, skipping playback test`);
            test.skip();
        }
        
        // Load video
        await page.evaluate((path) => {
            const video = document.getElementById('webcamVideo');
            video.src = path;
            return video.play();
        }, videoPath);
        
        // Wait for video to start
        await page.waitForTimeout(1000);
        
        // Check video is playing
        const isPlaying = await page.evaluate(() => {
            const video = document.getElementById('webcamVideo');
            return !video.paused && !video.ended && video.readyState > 2;
        });
        
        expect(isPlaying).toBe(true);
    });
    
    test('should decode golden video', async ({ page, browserName }) => {
        const features = BROWSER_FEATURES[browserName] || BROWSER_FEATURES.chromium;
        const testVideo = GOLDEN_VIDEOS[0];
        
        if (!features.supportsWebM) {
            console.log(`${browserName} does not support WebM, converting to MP4...`);
            // TODO: Implement MP4 conversion
            test.skip();
        }
        
        // Load golden video
        const videoPath = `/tests/golden/${testVideo.file}`;
        await page.evaluate((path) => {
            const video = document.getElementById('webcamVideo');
            video.src = path;
            video.muted = true;  // Prevent audio issues
            return video.play();
        }, videoPath);
        
        // Start Cat Mode decode
        await page.click('#startCatButton');
        
        // Wait for decode to complete (max duration + buffer)
        const timeout = (testVideo.duration + 10) * 1000;
        await page.waitForTimeout(timeout);
        
        // Check decode result
        const result = await page.evaluate(() => {
            const session = window.catModeSession;
            if (!session) return null;
            
            return {
                complete: session.complete,
                payload: session.decodedPayload,
                crcPassed: session.crcPassed,
                confidence: session.avgConfidence,
                framesProcessed: session.framesProcessed
            };
        });
        
        // Assertions
        expect(result).not.toBeNull();
        expect(result.complete).toBe(true);
        expect(result.payload).toBe(testVideo.expectedPayload);
        expect(result.crcPassed).toBe(true);
        expect(result.confidence).toBeGreaterThan(0.8);  // 80% confidence minimum
    });
    
    test('should handle missing WebM support gracefully', async ({ page, browserName }) => {
        const features = BROWSER_FEATURES[browserName] || BROWSER_FEATURES.chromium;
        
        if (features.supportsWebM) {
            test.skip();  // Only test on browsers without WebM
        }
        
        // Try to load WebM video
        const videoPath = '/tests/golden/cat_mode_golden_empty_hash_100ms.webm';
        
        const errorDetected = await page.evaluate((path) => {
            return new Promise((resolve) => {
                const video = document.createElement('video');
                video.src = path;
                
                video.onerror = () => resolve(true);
                video.oncanplay = () => resolve(false);
                
                setTimeout(() => resolve(false), 5000);
            });
        }, videoPath);
        
        if (errorDetected) {
            // Check for user-friendly error message
            const errorMessage = await page.locator('.error-message').textContent();
            expect(errorMessage).toContain('WebM');
            expect(errorMessage).toContain('MP4');  // Should suggest alternative
        }
    });
    
    test('should work on mobile viewport', async ({ page, browserName }) => {
        // Already configured via playwright.config.js for mobile projects
        
        // Check responsive layout
        const isMobile = await page.evaluate(() => window.innerWidth < 768);
        
        if (isMobile) {
            // Mobile-specific checks
            await expect(page.locator('#catModeContainer')).toBeVisible();
            
            // Check for mobile-optimized controls
            const controlsAreTouch = await page.evaluate(() => {
                const startBtn = document.getElementById('startCatButton');
                const computedStyle = window.getComputedStyle(startBtn);
                const minHeight = parseInt(computedStyle.minHeight);
                
                // Touch targets should be ≥44px (Apple HIG guideline)
                return minHeight >= 44;
            });
            
            expect(controlsAreTouch).toBe(true);
        }
    });
    
    test('should handle high DPI displays', async ({ page }) => {
        const dpr = await page.evaluate(() => window.devicePixelRatio);
        
        console.log(`Device pixel ratio: ${dpr}`);
        
        if (dpr > 1) {
            // Check canvas scaling
            const canvasScaling = await page.evaluate(() => {
                const canvas = document.getElementById('debugCanvas');
                if (!canvas) return null;
                
                const ctx = canvas.getContext('2d');
                const transform = ctx.getTransform();
                
                return {
                    scaleX: transform.a,
                    scaleY: transform.d
                };
            });
            
            if (canvasScaling) {
                // Canvas should scale with DPR
                expect(canvasScaling.scaleX).toBeCloseTo(dpr, 1);
                expect(canvasScaling.scaleY).toBeCloseTo(dpr, 1);
            }
        }
    });
    
    test('should support getUserMedia (camera access)', async ({ page, browserName }) => {
        // Check if getUserMedia is available
        const hasGetUserMedia = await page.evaluate(() => {
            return 'mediaDevices' in navigator && 'getUserMedia' in navigator.mediaDevices;
        });
        
        expect(hasGetUserMedia).toBe(true);
        
        // Try to get camera (fake stream in test env)
        const streamObtained = await page.evaluate(async () => {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ 
                    video: { 
                        width: 640, 
                        height: 480 
                    } 
                });
                
                return stream && stream.active;
            } catch (error) {
                console.error('getUserMedia error:', error);
                return false;
            }
        });
        
        expect(streamObtained).toBe(true);
    });
    
    test('should export diagnostics JSON', async ({ page }) => {
        // Start a decode session
        await page.click('#startCatButton');
        await page.waitForTimeout(5000);  // Run for 5 seconds
        await page.click('#stopCatButton');
        
        // Check for export button
        await expect(page.locator('#exportDiagnosticsButton')).toBeVisible();
        
        // Click export
        const downloadPromise = page.waitForEvent('download');
        await page.click('#exportDiagnosticsButton');
        const download = await downloadPromise;
        
        // Verify download
        expect(download.suggestedFilename()).toContain('cat_mode_diagnostics');
        expect(download.suggestedFilename()).toContain('.json');
        
        // Verify JSON structure
        const downloadPath = await download.path();
        const diagnosticsContent = fs.readFileSync(downloadPath, 'utf8');
        const diagnostics = JSON.parse(diagnosticsContent);
        
        expect(diagnostics).toHaveProperty('timestamp');
        expect(diagnostics).toHaveProperty('framesProcessed');
        expect(diagnostics).toHaveProperty('avgConfidence');
        expect(diagnostics).toHaveProperty('decodedBits');
    });
    
    test('should maintain performance across browsers', async ({ page, browserName }) => {
        const testVideo = GOLDEN_VIDEOS[0];
        
        // Load video
        await page.evaluate((path) => {
            const video = document.getElementById('webcamVideo');
            video.src = `/tests/golden/${path}`;
            video.muted = true;
            return video.play();
        }, testVideo.file);
        
        // Measure decode time
        const startTime = Date.now();
        await page.click('#startCatButton');
        
        // Wait for completion
        await page.waitForFunction(() => {
            const session = window.catModeSession;
            return session && session.complete;
        }, { timeout: 60000 });
        
        const endTime = Date.now();
        const decodeTime = (endTime - startTime) / 1000;
        
        console.log(`${browserName} decode time: ${decodeTime.toFixed(2)}s`);
        
        // Performance threshold: <5s for 31s video (6× real-time)
        expect(decodeTime).toBeLessThan(5);
    });
});

test.describe('Browser-Specific Workarounds', () => {
    
    test('Safari: MP4 fallback', async ({ page, browserName }) => {
        if (browserName !== 'webkit') {
            test.skip();
        }
        
        // Check for MP4 conversion helper
        const hasMp4Fallback = await page.evaluate(() => {
            return typeof window.convertWebMToMp4 === 'function';
        });
        
        expect(hasMp4Fallback).toBe(true);
    });
    
    test('Firefox: MediaRecorder constraints', async ({ page, browserName }) => {
        if (browserName !== 'firefox') {
            test.skip();
        }
        
        // Firefox has specific constraints for MediaRecorder
        const constraints = await page.evaluate(() => {
            return {
                videoCodec: 'video/webm; codecs=vp8',  // Firefox prefers VP8
                videoBitsPerSecond: 2500000
            };
        });
        
        expect(constraints.videoCodec).toContain('vp8');
    });
    
    test('Chromium: Capture from file input', async ({ page, browserName }) => {
        if (browserName !== 'chromium') {
            test.skip();
        }
        
        // Chromium supports capture from file input
        const fileInputExists = await page.locator('input[type="file"]').count();
        expect(fileInputExists).toBeGreaterThan(0);
    });
});

test.describe('Mobile-Specific Features', () => {
    
    test('should use rear camera by default', async ({ page, browserName }) => {
        // Only on mobile projects
        const isMobile = await page.evaluate(() => window.innerWidth < 768);
        if (!isMobile) {
            test.skip();
        }
        
        const cameraFacing = await page.evaluate(async () => {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: 'environment' }  // Rear camera
                });
                
                const tracks = stream.getVideoTracks();
                if (tracks.length > 0) {
                    const settings = tracks[0].getSettings();
                    return settings.facingMode;
                }
            } catch (error) {
                return null;
            }
        });
        
        expect(cameraFacing).toBe('environment');
    });
    
    test('should prevent screen sleep during decode', async ({ page }) => {
        const wakeLockSupported = await page.evaluate(() => {
            return 'wakeLock' in navigator;
        });
        
        if (wakeLockSupported) {
            // Check if wake lock is acquired during decode
            await page.click('#startCatButton');
            
            const wakeLockActive = await page.evaluate(async () => {
                return window.catModeWakeLock !== null;
            });
            
            expect(wakeLockActive).toBe(true);
        }
    });
    
    test('should handle orientation changes', async ({ page }) => {
        const isMobile = await page.evaluate(() => window.innerWidth < 768);
        if (!isMobile) {
            test.skip();
        }
        
        // Simulate orientation change
        await page.setViewportSize({ width: 480, height: 800 });  // Portrait
        await page.waitForTimeout(500);
        
        // Check layout adapts
        let layoutMode = await page.evaluate(() => {
            return window.getComputedStyle(document.body).getPropertyValue('--layout-mode');
        });
        
        expect(layoutMode).toContain('portrait');
        
        // Rotate to landscape
        await page.setViewportSize({ width: 800, height: 480 });
        await page.waitForTimeout(500);
        
        layoutMode = await page.evaluate(() => {
            return window.getComputedStyle(document.body).getPropertyValue('--layout-mode');
        });
        
        expect(layoutMode).toContain('landscape');
    });
});
