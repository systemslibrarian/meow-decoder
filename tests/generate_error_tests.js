#!/usr/bin/env node
/**
 * Error Injection Test Generator - CLI
 * 
 * Generates error-injected test videos to validate error handling, diagnostics,
 * and user-facing error messages.
 * 
 * USAGE:
 *   node tests/generate_error_tests.js
 *   npm run generate-error-tests
 * 
 * OUTPUT:
 *   tests/golden/errors/ - Error-injected test videos
 *   tests/golden/errors/manifest.json - Test case metadata
 *   tests/golden/errors/README.md - Documentation with checksums
 * 
 * TEST MATRIX:
 *   3 base videos × 6 error modes = 18 test cases
 */

const { 
    batchInjectErrors,
    ERROR_MODES
} = require('./error_injection_lib.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Test configuration matrix
const ERROR_TEST_CONFIGS = [
    {
        mode: 'frame_corruption',
        rate: 0.1,  // 10% frames corrupted
        description: 'Random 10% of frames rendered black (simulates dropped frames)',
        expectedOutcome: 'Should detect corruption via CRC errors, report frame loss in diagnostics',
        options: { seed: 42 }  // Reproducible
    },
    {
        mode: 'timing_jitter',
        variance: 0.2,  // ±20% timing
        description: 'Variable frame delays ±20% (simulates buffering/lag)',
        expectedOutcome: 'Should maintain sync via adaptive threshold, may trigger timeout warnings',
        options: { seed: 43 }
    },
    {
        mode: 'partial_video',
        cutoff: 0.2,  // Remove last 20%
        description: 'Video cut off after 80% (simulates recording stopped early)',
        expectedOutcome: 'Should detect incomplete payload, report "Partial data received" error'
    },
    {
        mode: 'wrong_roi',
        offset: [50, 50],  // 50px x/y offset
        description: 'ROI shifted 50px from correct center (simulates user error)',
        expectedOutcome: 'Should fail eye detection or detect no valid bits, suggest ROI adjustment'
    },
    {
        mode: 'extreme_lighting',
        brightness: 0.3,  // Very dim
        description: 'Very dim lighting (30% brightness)',
        expectedOutcome: 'Should struggle with eye detection, may require contrast boost in preprocessing'
    },
    {
        mode: 'extreme_lighting',
        brightness: 1.7,  // Very bright
        description: 'Very bright lighting (170% brightness)',
        expectedOutcome: 'Should saturate pixels, may fail eye/pupil separation'
    },
    {
        mode: 'resolution_degradation',
        scale: 0.5,  // 50% resolution
        description: 'Downscaled to 50% resolution and upscaled (simulates low-quality camera)',
        expectedOutcome: 'Should work with reduced confidence, may increase CRC error rate'
    }
];

/**
 * Find golden videos in tests/golden/ directory
 */
function findGoldenVideos() {
    const goldenDir = path.join(__dirname, 'golden');
    
    if (!fs.existsSync(goldenDir)) {
        console.error('❌ Golden video directory not found:', goldenDir);
        console.error('   Run: npm run generate-golden-videos first');
        process.exit(1);
    }
    
    const videos = fs.readdirSync(goldenDir)
        .filter(f => f.endsWith('.webm') && f.startsWith('cat_mode_golden_'))
        .map(f => path.join(goldenDir, f));
    
    if (videos.length === 0) {
        console.error('❌ No golden videos found in', goldenDir);
        console.error('   Run: npm run generate-golden-videos first');
        process.exit(1);
    }
    
    return videos;
}

/**
 * Check for required dependencies
 */
function checkDependencies() {
    const { execSync } = require('child_process');
    
    // Check ffmpeg
    try {
        execSync('ffmpeg -version', { stdio: 'pipe' });
    } catch (error) {
        console.error('❌ ffmpeg not found. Please install:');
        console.error('   Ubuntu/Debian: sudo apt-get install ffmpeg');
        console.error('   macOS: brew install ffmpeg');
        console.error('   Alpine: apk add ffmpeg');
        process.exit(1);
    }
    
    // Check ffprobe
    try {
        execSync('ffprobe -version', { stdio: 'pipe' });
    } catch (error) {
        console.error('❌ ffprobe not found (should be included with ffmpeg)');
        process.exit(1);
    }
}

/**
 * Generate error-injected test videos
 */
async function main() {
    console.log('═══════════════════════════════════════════════════════════════════');
    console.log('🧪 Cat Mode Error Injection Test Generator');
    console.log('═══════════════════════════════════════════════════════════════════\n');
    
    // Check dependencies
    console.log('🔍 Checking dependencies...');
    checkDependencies();
    console.log('✅ All dependencies found\n');
    
    // Find base golden videos
    console.log('📹 Finding golden videos...');
    const goldenVideos = findGoldenVideos();
    console.log(`✅ Found ${goldenVideos.length} golden videos:\n`);
    goldenVideos.forEach(v => console.log(`   - ${path.basename(v)}`));
    console.log();
    
    // Create output directory
    const outputDir = path.join(__dirname, 'golden', 'errors');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    console.log(`📁 Output directory: ${outputDir}\n`);
    
    // Generate error-injected videos
    console.log('🎬 Generating error test cases...\n');
    const results = batchInjectErrors(goldenVideos, ERROR_TEST_CONFIGS, outputDir);
    
    // Create manifest with metadata
    const manifest = {
        generatedAt: new Date().toISOString(),
        goldenVideos: goldenVideos.map(v => path.basename(v)),
        errorConfigs: ERROR_TEST_CONFIGS,
        testCases: results,
        totalTestCases: results.length,
        errorModes: Object.keys(ERROR_MODES).length
    };
    
    const manifestPath = path.join(outputDir, 'manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(`📄 Manifest created: ${manifestPath}\n`);
    
    // Generate README with checksums
    generateReadme(outputDir, results, ERROR_TEST_CONFIGS);
    
    // Print summary
    printSummary(results);
}

/**
 * Generate README.md with checksums and usage instructions
 */
function generateReadme(outputDir, results, configs) {
    const readme = `# Error Injection Test Videos

**Generated:** ${new Date().toISOString()}

## Overview

These videos are error-injected variants of the golden test videos, designed to validate:
- Error detection and handling
- Diagnostic message quality
- User-facing error messages
- Graceful degradation under adverse conditions

## Test Matrix

| Error Mode | Description | Expected Outcome |
|------------|-------------|------------------|
${configs.map(c => `| \`${c.mode}\` | ${c.description} | ${c.expectedOutcome} |`).join('\n')}

## Test Cases (${results.length} total)

${results.map(r => {
    const videoName = path.basename(r.adjustedPath || r.corruptedPath || r.jitteredPath || r.truncatedPath || r.croppedPath || r.degradedPath);
    return `### ${videoName}

**Error Mode:** ${r.errorMode}  
**Base Video:** ${r.testCaseName}  
**Checksum (SHA-256):** \`${r.checksum}\`  
**File Size:** ${(r.fileSize / 1024).toFixed(1)} KB

**Configuration:**
\`\`\`json
${JSON.stringify(r.errorConfig, null, 2)}
\`\`\`

**Metadata:**
\`\`\`json
${JSON.stringify(r, null, 2)}
\`\`\`

---
`;
}).join('\n')}

## Verify Checksums

\`\`\`bash
cd tests/golden/errors

# Verify all checksums
${results.map(r => {
    const videoName = path.basename(r.adjustedPath || r.corruptedPath || r.jitteredPath || r.truncatedPath || r.croppedPath || r.degradedPath);
    return `echo "${r.checksum}  ${videoName}" | sha256sum -c`;
}).join('\n')}
\`\`\`

## Run Error Tests

\`\`\`bash
# Run Python error test suite
python3 tests/run_error_tests.py

# Run Node.js error test suite
node tests/run_error_tests.js
\`\`\`

## Expected Failures

All test cases in this directory are **intentionally broken** and should produce specific error messages:

1. **frame_corruption**: CRC errors, frame loss detected
2. **timing_jitter**: Timeout warnings, sync maintained
3. **partial_video**: Incomplete payload error
4. **wrong_roi**: Eye detection failure, suggest ROI adjustment
5. **extreme_lighting** (dim): Low confidence, contrast boost suggested
6. **extreme_lighting** (bright): Saturation detected, exposure adjustment suggested
7. **resolution_degradation**: Reduced confidence, increased CRC errors

## CI Integration

Error tests run as **Gate 3** in CI pipeline:
- Verifies error detection works correctly
- Validates diagnostic messages are user-friendly
- Ensures no crashes on malformed input

## Regenerate

To regenerate error test videos:

\`\`\`bash
npm run generate-error-tests
\`\`\`

This will recreate all ${results.length} test cases with consistent checksums (due to seeded RNG).
`;

    const readmePath = path.join(outputDir, 'README.md');
    fs.writeFileSync(readmePath, readme);
    console.log(`📝 README created: ${readmePath}\n`);
}

/**
 * Print generation summary
 */
function printSummary(results) {
    console.log('═══════════════════════════════════════════════════════════════════');
    console.log('📊 Generation Summary');
    console.log('═══════════════════════════════════════════════════════════════════\n');
    
    // Group by error mode
    const byMode = {};
    results.forEach(r => {
        if (!byMode[r.errorMode]) {
            byMode[r.errorMode] = [];
        }
        byMode[r.errorMode].push(r);
    });
    
    console.log('Error modes:');
    Object.keys(byMode).sort().forEach(mode => {
        const count = byMode[mode].length;
        const totalSize = byMode[mode].reduce((sum, r) => sum + r.fileSize, 0);
        console.log(`  - ${mode}: ${count} test cases (${(totalSize / 1024 / 1024).toFixed(2)} MB)`);
    });
    
    console.log();
    console.log(`✅ Total: ${results.length} error test videos generated`);
    
    const totalSize = results.reduce((sum, r) => sum + r.fileSize, 0);
    console.log(`   Total size: ${(totalSize / 1024 / 1024).toFixed(2)} MB`);
    
    console.log('\n═══════════════════════════════════════════════════════════════════');
    console.log('✅ Error Injection Complete!');
    console.log('═══════════════════════════════════════════════════════════════════\n');
    
    console.log('Next steps:');
    console.log('  1. Run: python3 tests/run_error_tests.py');
    console.log('  2. Verify error messages are user-friendly');
    console.log('  3. Commit error videos: git add tests/golden/errors/');
    console.log('  4. Push to CI: git push\n');
}

// Run if executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('\n❌ Error:', error.message);
        console.error(error.stack);
        process.exit(1);
    });
}

module.exports = { main };
