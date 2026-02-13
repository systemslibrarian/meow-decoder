#!/usr/bin/env node

/**
 * Golden Video Generation CLI
 * One-click generation of all test videos with deterministic checksums
 * 
 * Usage: node generate_golden_videos.js
 * Or: npm run generate-golden-videos
 */

const { generateGoldenVideo } = require('./golden-video-lib.js');
const fs = require('fs');
const path = require('path');

// ====================================================================
// Test Case Definitions
// ====================================================================

const TEST_CASES = [
    {
        name: 'empty_hash',
        payload: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        payloadType: 'hash',
        bitSpeed: 100,
        fps: 30,
        description: 'Empty string SHA-256 hash (primary test case)'
    },
    {
        name: 'short',
        payload: '0123456789abcdef0123456789abcdef',
        payloadType: 'hex',
        bitSpeed: 150,
        fps: 30,
        description: 'Short hex string (128 bits)'
    },
    {
        name: 'long',
        payload: 'The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs!',
        payloadType: 'text',
        bitSpeed: 50,
        fps: 30,
        description: 'Long text message (variable length)'
    }
];

// ====================================================================
// Main
// ====================================================================

async function main() {
    console.log('\n' + '='.repeat(70));
    console.log('🐱 Golden Video Generator - One-Click Mode');
    console.log('='.repeat(70));
    
    // Check for ffmpeg
    const { execSync } = require('child_process');
    try {
        execSync('ffmpeg -version', { stdio: 'ignore' });
    } catch (error) {
        console.error('\n❌ Error: ffmpeg not found. Install with:');
        console.error('   Ubuntu/Debian: sudo apt-get install ffmpeg');
        console.error('   macOS: brew install ffmpeg');
        console.error('   Alpine: apk add ffmpeg');
        process.exit(1);
    }
    
    // Check for canvas
    try {
        require('canvas');
    } catch (error) {
        console.error('\n❌ Error: canvas module not found. Install with:');
        console.error('   npm install canvas');
        process.exit(1);
    }
    
    // Create output directory
    const outputDir = path.join(__dirname, 'golden');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    
    // Generate all test cases
    const results = [];
    
    for (const testCase of TEST_CASES) {
        try {
            console.log(`\n${'─'.repeat(70)}`);
            console.log(`📹 Test Case: ${testCase.name}`);
            console.log(`   ${testCase.description}`);
            
            const result = generateGoldenVideo({
                ...testCase,
                outputDir
            });
            
            results.push(result);
            console.log(`   ✅ Success`);
            
        } catch (error) {
            console.error(`   ❌ Failed: ${error.message}`);
            results.push({
                name: testCase.name,
                error: error.message
            });
        }
    }
    
    // Print summary
    console.log('\n' + '='.repeat(70));
    console.log('📊 Generation Summary');
    console.log('='.repeat(70));
    
    const successCount = results.filter(r => !r.error).length;
    const failCount = results.filter(r => r.error).length;
    
    console.log(`\n✅ Succeeded: ${successCount}/${TEST_CASES.length}`);
    if (failCount > 0) {
        console.log(`❌ Failed: ${failCount}/${TEST_CASES.length}`);
    }
    
    // Print checksums table
    if (successCount > 0) {
        console.log('\n📋 Checksums (SHA-256):');
        console.log('─'.repeat(70));
        
        for (const result of results) {
            if (!result.error) {
                console.log(`\n${result.name}:`);
                console.log(`  File: ${path.basename(result.path)}`);
                console.log(`  SHA256: ${result.checksum}`);
                console.log(`  Size: ${(result.size / 1024).toFixed(1)} KB`);
                console.log(`  Duration: ${result.duration.toFixed(1)}s`);
                console.log(`  Frames: ${result.frames}`);
            }
        }
    }
    
    // Update README with checksums
    updateReadmeWithChecksums(results.filter(r => !r.error));
    
    console.log('\n' + '='.repeat(70));
    console.log('✅ Generation Complete!');
    console.log('='.repeat(70));
    console.log('\nNext steps:');
    console.log('  1. Verify checksums match expected values');
    console.log('  2. Run: npm test (or python3 tests/run_golden_test.py)');
    console.log('  3. Commit videos: git add tests/golden/*.webm');
    console.log('  4. Push to CI: git push');
    console.log('');
}

// ====================================================================
// README Update
// ====================================================================

function updateReadmeWithChecksums(results) {
    const readmePath = path.join(__dirname, 'golden', 'README.md');
    
    if (!fs.existsSync(readmePath)) {
        console.log('\n⚠️  Warning: golden/README.md not found, skipping checksum update');
        return;
    }
    
    let readme = fs.readFileSync(readmePath, 'utf8');
    
    // Build checksums section
    let checksumsSection = '\n## 🔐 Checksums (SHA-256)\n\n';
    checksumsSection += '**Verify golden videos before running tests:**\n\n';
    checksumsSection += '```bash\n';
    checksumsSection += 'cd tests/golden\n';
    
    for (const result of results) {
        const filename = path.basename(result.path);
        checksumsSection += `echo "${result.checksum}  ${filename}" | sha256sum -c\n`;
    }
    
    checksumsSection += '```\n\n';
    checksumsSection += '| File | SHA-256 Checksum |\n';
    checksumsSection += '|------|------------------|\n';
    
    for (const result of results) {
        const filename = path.basename(result.path);
        checksumsSection += `| \`${filename}\` | \`${result.checksum.substring(0, 16)}...\` |\n`;
    }
    
    checksumsSection += '\n**Generated:** ' + new Date().toISOString() + '\n';
    
    // Replace or append checksums section
    if (readme.includes('## 🔐 Checksums')) {
        // Replace existing section
        readme = readme.replace(
            /## 🔐 Checksums.*?(?=\n## |$)/s,
            checksumsSection
        );
    } else {
        // Append to end
        readme += '\n' + checksumsSection;
    }
    
    fs.writeFileSync(readmePath, readme);
    console.log('\n✓ Updated golden/README.md with checksums');
}

// ====================================================================
// Run
// ====================================================================

if (require.main === module) {
    main().catch(error => {
        console.error('\n❌ Fatal error:', error);
        process.exit(1);
    });
}

module.exports = { main };
