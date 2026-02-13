/**
 * Error Injection Library for Cat Mode Testing
 * 
 * Simulates realistic failure modes to validate error handling, diagnostics,
 * and user-facing error messages. Ensures graceful degradation under adverse
 * conditions.
 * 
 * ERROR MODES:
 * 1. Frame Corruption - Random frames rendered black (simulates dropped frames)
 * 2. Timing Jitter - Variable frame delays (simulates buffering/lag)
 * 3. Partial Video - Cut off last N% (simulates recording stopped early)
 * 4. Wrong ROI - Incorrect region selection (simulates user error)
 * 5. Extreme Lighting - Very dim/bright (simulates poor recording conditions)
 * 6. Resolution Degradation - Downscaled video (simulates low-quality camera)
 * 
 * USAGE:
 *   const { injectErrors } = require('./error_injection_lib.js');
 *   const corruptedVideo = injectErrors(originalVideo, {
 *       corruptionRate: 0.1,  // 10% frames black
 *       timingJitter: 0.2     // ±20% frame timing variance
 *   });
 */

const fs = require('fs');
const crypto = require('crypto');
const { execSync } = require('child_process');

/**
 * Error injection modes and their default configurations
 */
const ERROR_MODES = {
    FRAME_CORRUPTION: {
        name: 'frame_corruption',
        description: 'Random frames rendered black',
        defaultRate: 0.1,  // 10% of frames
        severity: 'high'
    },
    TIMING_JITTER: {
        name: 'timing_jitter',
        description: 'Variable frame delays',
        defaultVariance: 0.2,  // ±20% timing
        severity: 'medium'
    },
    PARTIAL_VIDEO: {
        name: 'partial_video',
        description: 'Video cut off early',
        defaultCutoff: 0.2,  // Last 20%
        severity: 'critical'
    },
    WRONG_ROI: {
        name: 'wrong_roi',
        description: 'Incorrect region of interest',
        defaultOffset: [50, 50],  // 50px x/y offset
        severity: 'high'
    },
    EXTREME_LIGHTING: {
        name: 'extreme_lighting',
        description: 'Very dim or bright',
        defaultBrightness: 0.3,  // 30% brightness (or 170%)
        severity: 'medium'
    },
    RESOLUTION_DEGRADATION: {
        name: 'resolution_degradation',
        description: 'Downscaled video',
        defaultScale: 0.5,  // 50% resolution
        severity: 'low'
    }
};

/**
 * Frame corruption: Replace random frames with black frames
 * 
 * @param {string} videoPath - Path to input video
 * @param {number} corruptionRate - Fraction of frames to corrupt (0.0-1.0)
 * @param {string} outputPath - Path for corrupted video
 * @param {object} options - Additional options (seed for reproducibility)
 * @returns {object} - Metadata about corruption
 */
function injectFrameCorruption(videoPath, corruptionRate, outputPath, options = {}) {
    const seed = options.seed || Math.random();
    const rng = new SeededRandom(seed);
    
    // Extract frames to temp directory
    const tempDir = fs.mkdtempSync('/tmp/error_inject_');
    const framesPattern = `${tempDir}/frame_%06d.png`;
    
    console.log(`📹 Extracting frames from ${videoPath}...`);
    execSync(`ffmpeg -i "${videoPath}" "${framesPattern}" -hide_banner -loglevel error`);
    
    // Count frames
    const frameFiles = fs.readdirSync(tempDir).filter(f => f.startsWith('frame_'));
    const totalFrames = frameFiles.length;
    const corruptCount = Math.floor(totalFrames * corruptionRate);
    
    console.log(`🎲 Corrupting ${corruptCount}/${totalFrames} frames (${(corruptionRate * 100).toFixed(1)}%)`);
    
    // Select random frames to corrupt
    const corruptIndices = new Set();
    while (corruptIndices.size < corruptCount) {
        const frameIdx = Math.floor(rng.next() * totalFrames);
        corruptIndices.add(frameIdx);
    }
    
    // Get first frame dimensions
    const firstFramePath = `${tempDir}/frame_000001.png`;
    const dimensions = execSync(`ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=s=x:p=0 "${firstFramePath}"`, { encoding: 'utf-8' }).trim();
    const [width, height] = dimensions.split('x').map(Number);
    
    // Corrupt selected frames (replace with black image)
    for (const idx of corruptIndices) {
        const frameNum = idx + 1;  // ffmpeg uses 1-based indexing
        const framePath = `${tempDir}/frame_${frameNum.toString().padStart(6, '0')}.png`;
        
        // Create black frame using ffmpeg
        execSync(`ffmpeg -f lavfi -i color=black:${width}x${height}:d=1 -frames:v 1 "${framePath}" -y -hide_banner -loglevel error`);
    }
    
    console.log(`🎬 Reassembling video...`);
    
    // Get original video metadata (fps, codec)
    let fps = 10; // Default fallback
    try {
        const fpsStr = execSync(`ffprobe -v error -select_streams v:0 -show_entries stream=r_frame_rate -of default=noprint_wrappers=1:nokey=1 "${videoPath}"`, { encoding: 'utf-8' }).trim();
        
        if (fpsStr && fpsStr !== 'N/A') {
            const [num, den] = fpsStr.split('/').map(Number);
            fps = den ? num / den : num;
            
            // Validate fps is a reasonable number
            if (isNaN(fps) || fps <= 0 || fps > 120) {
                console.warn(`⚠️  Invalid fps detected (${fps}), using default 10 fps`);
                fps = 10;
            }
        } else {
            console.warn(`⚠️  No fps metadata found, using default 10 fps`);
        }
    } catch (err) {
        console.warn(`⚠️  Could not read fps metadata, using default 10 fps`);
    }
    
    console.log(`📊 Using framerate: ${fps} fps`);
    
    // Reassemble video from frames
    execSync(`ffmpeg -framerate ${fps} -i "${framesPattern}" -c:v libvpx-vp9 -pix_fmt yuv420p -b:v 2M "${outputPath}" -y -hide_banner -loglevel error`);
    
    // Cleanup temp directory
    fs.rmSync(tempDir, { recursive: true, force: true });
    
    const checksum = calculateChecksum(outputPath);
    
    return {
        errorMode: 'frame_corruption',
        originalPath: videoPath,
        corruptedPath: outputPath,
        corruptionRate,
        totalFrames,
        corruptedFrames: corruptCount,
        corruptedIndices: Array.from(corruptIndices).sort((a, b) => a - b),
        seed,
        checksum,
        fileSize: fs.statSync(outputPath).size
    };
}

/**
 * Timing jitter: Add variable frame delays
 * 
 * @param {string} videoPath - Path to input video
 * @param {number} jitterVariance - Fraction of variance (0.0-1.0, e.g., 0.2 = ±20%)
 * @param {string} outputPath - Path for jittered video
 * @param {object} options - Additional options
 * @returns {object} - Metadata about jitter
 */
function injectTimingJitter(videoPath, jitterVariance, outputPath, options = {}) {
    const seed = options.seed || Math.random();
    const rng = new SeededRandom(seed);
    
    // Extract frames
    const tempDir = fs.mkdtempSync('/tmp/error_inject_');
    const framesPattern = `${tempDir}/frame_%06d.png`;
    
    console.log(`📹 Extracting frames from ${videoPath}...`);
    execSync(`ffmpeg -i "${videoPath}" "${framesPattern}" -hide_banner -loglevel error`);
    
    // Get original FPS with fallback
    let baseFps = 10; // Default fallback
    try {
        const fpsStr = execSync(`ffprobe -v error -select_streams v:0 -show_entries stream=r_frame_rate -of default=noprint_wrappers=1:nokey=1 "${videoPath}"`, { encoding: 'utf-8' }).trim();
        
        if (fpsStr && fpsStr !== 'N/A') {
            const [num, den] = fpsStr.split('/').map(Number);
            baseFps = den ? num / den : num;
            
            if (isNaN(baseFps) || baseFps <= 0 || baseFps > 120) {
                console.warn(`⚠️  Invalid fps detected (${baseFps}), using default 10 fps`);
                baseFps = 10;
            }
        } else {
            console.warn(`⚠️  No fps metadata found, using default 10 fps`);
        }
    } catch (err) {
        console.warn(`⚠️  Could not read fps metadata, using default 10 fps`);
    }
    
    console.log(`📊 Base framerate: ${baseFps} fps`);
    
    const frameFiles = fs.readdirSync(tempDir).filter(f => f.startsWith('frame_'));
    const totalFrames = frameFiles.length;
    
    console.log(`🎲 Adding timing jitter (±${(jitterVariance * 100).toFixed(0)}%)`);
    
    // Generate per-frame durations with jitter
    const frameDurations = [];
    for (let i = 0; i < totalFrames; i++) {
        const jitterFactor = 1 + (rng.next() * 2 - 1) * jitterVariance;  // [1-variance, 1+variance]
        const duration = (1 / baseFps) * jitterFactor;
        frameDurations.push(duration);
    }
    
    // Create concat demuxer file with per-frame durations
    const concatFile = `${tempDir}/concat.txt`;
    const concatLines = frameFiles.map((file, idx) => {
        return `file '${file}'\nduration ${frameDurations[idx].toFixed(6)}`;
    }).join('\n');
    
    // Add last frame without duration (ffmpeg requirement)
    const lastFrame = frameFiles[frameFiles.length - 1];
    fs.writeFileSync(concatFile, concatLines + `\nfile '${lastFrame}'`);
    
    console.log(`🎬 Reassembling video with jitter...`);
    
    // Reassemble with variable frame durations
    execSync(`ffmpeg -f concat -safe 0 -i "${concatFile}" -c:v libvpx-vp9 -pix_fmt yuv420p -b:v 2M "${outputPath}" -y -hide_banner -loglevel error`, { cwd: tempDir });
    
    // Cleanup
    fs.rmSync(tempDir, { recursive: true, force: true });
    
    const checksum = calculateChecksum(outputPath);
    const avgDuration = frameDurations.reduce((a, b) => a + b, 0) / frameDurations.length;
    const minDuration = Math.min(...frameDurations);
    const maxDuration = Math.max(...frameDurations);
    
    return {
        errorMode: 'timing_jitter',
        originalPath: videoPath,
        jitteredPath: outputPath,
        jitterVariance,
        totalFrames,
        baseFps,
        avgFrameDuration: avgDuration,
        minFrameDuration: minDuration,
        maxFrameDuration: maxDuration,
        effectiveFps: 1 / avgDuration,
        seed,
        checksum,
        fileSize: fs.statSync(outputPath).size
    };
}

/**
 * Partial video: Cut off last N% of video
 * 
 * @param {string} videoPath - Path to input video
 * @param {number} cutoffFraction - Fraction to remove (0.0-1.0, e.g., 0.2 = remove last 20%)
 * @param {string} outputPath - Path for truncated video
 * @returns {object} - Metadata about truncation
 */
function injectPartialVideo(videoPath, cutoffFraction, outputPath) {
    console.log(`✂️ Truncating video (removing last ${(cutoffFraction * 100).toFixed(0)}%)`);
    
    // Get original duration
    const durationStr = execSync(`ffprobe -v error -show_entries format=duration -of csv=s=,:p=0 "${videoPath}"`, { encoding: 'utf-8' }).trim();
    const originalDuration = parseFloat(durationStr);
    const targetDuration = originalDuration * (1 - cutoffFraction);
    
    // Trim video to target duration
    execSync(`ffmpeg -i "${videoPath}" -t ${targetDuration.toFixed(3)} -c:v libvpx-vp9 -pix_fmt yuv420p -b:v 2M "${outputPath}" -y -hide_banner -loglevel error`);
    
    const checksum = calculateChecksum(outputPath);
    
    return {
        errorMode: 'partial_video',
        originalPath: videoPath,
        truncatedPath: outputPath,
        cutoffFraction,
        originalDuration,
        truncatedDuration: targetDuration,
        removedDuration: originalDuration - targetDuration,
        checksum,
        fileSize: fs.statSync(outputPath).size
    };
}

/**
 * Wrong ROI: Crop video with incorrect region of interest
 * 
 * @param {string} videoPath - Path to input video
 * @param {Array<number>} offset - [x, y] pixel offset from correct center
 * @param {string} outputPath - Path for cropped video
 * @returns {object} - Metadata about ROI error
 */
function injectWrongROI(videoPath, offset, outputPath) {
    const [offsetX, offsetY] = offset;
    
    console.log(`📐 Shifting ROI by [${offsetX}, ${offsetY}] pixels`);
    
    // Get video dimensions
    const dimensions = execSync(`ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=s=x:p=0 "${videoPath}"`, { encoding: 'utf-8' }).trim();
    const [width, height] = dimensions.split('x').map(Number);
    
    // Calculate offset while keeping output size same
    // (simulate user selecting wrong region)
    const cropX = Math.max(0, Math.min(offsetX, width - 640));
    const cropY = Math.max(0, Math.min(offsetY, height - 480));
    
    // Apply crop filter
    execSync(`ffmpeg -i "${videoPath}" -vf "crop=640:480:${cropX}:${cropY}" -c:v libvpx-vp9 -pix_fmt yuv420p -b:v 2M "${outputPath}" -y -hide_banner -loglevel error`);
    
    const checksum = calculateChecksum(outputPath);
    
    return {
        errorMode: 'wrong_roi',
        originalPath: videoPath,
        croppedPath: outputPath,
        offset: [offsetX, offsetY],
        actualCrop: [cropX, cropY],
        originalDimensions: [width, height],
        outputDimensions: [640, 480],
        checksum,
        fileSize: fs.statSync(outputPath).size
    };
}

/**
 * Extreme lighting: Adjust brightness/contrast to simulate poor conditions
 * 
 * @param {string} videoPath - Path to input video
 * @param {number} brightnessFactor - Multiplier (0.3 = very dim, 1.7 = very bright)
 * @param {string} outputPath - Path for adjusted video
 * @returns {object} - Metadata about lighting adjustment
 */
function injectExtremeLighting(videoPath, brightnessFactor, outputPath) {
    const condition = brightnessFactor < 1.0 ? 'dim' : 'bright';
    console.log(`💡 Simulating ${condition} lighting (${(brightnessFactor * 100).toFixed(0)}% brightness)`);
    
    // Apply brightness/contrast filter
    // eq filter: brightness adjustment
    const brightnessAdjust = (brightnessFactor - 1.0) * 0.5;  // Convert to eq scale
    
    execSync(`ffmpeg -i "${videoPath}" -vf "eq=brightness=${brightnessAdjust.toFixed(3)}" -c:v libvpx-vp9 -pix_fmt yuv420p -b:v 2M "${outputPath}" -y -hide_banner -loglevel error`);
    
    const checksum = calculateChecksum(outputPath);
    
    return {
        errorMode: 'extreme_lighting',
        originalPath: videoPath,
        adjustedPath: outputPath,
        brightnessFactor,
        condition,
        checksum,
        fileSize: fs.statSync(outputPath).size
    };
}

/**
 * Resolution degradation: Downscale video to simulate low-quality camera
 * 
 * @param {string} videoPath - Path to input video
 * @param {number} scaleFactor - Scale multiplier (0.5 = 50% resolution)
 * @param {string} outputPath - Path for downscaled video
 * @returns {object} - Metadata about downscaling
 */
function injectResolutionDegradation(videoPath, scaleFactor, outputPath) {
    console.log(`📉 Downscaling video to ${(scaleFactor * 100).toFixed(0)}% resolution`);
    
    // Get original dimensions
    const dimensions = execSync(`ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=s=x:p=0 "${videoPath}"`, { encoding: 'utf-8' }).trim();
    const [width, height] = dimensions.split('x').map(Number);
    
    const newWidth = Math.floor(width * scaleFactor);
    const newHeight = Math.floor(height * scaleFactor);
    
    // Downscale and upscale back (introduces quality loss)
    execSync(`ffmpeg -i "${videoPath}" -vf "scale=${newWidth}:${newHeight},scale=${width}:${height}:flags=neighbor" -c:v libvpx-vp9 -pix_fmt yuv420p -b:v 2M "${outputPath}" -y -hide_banner -loglevel error`);
    
    const checksum = calculateChecksum(outputPath);
    
    return {
        errorMode: 'resolution_degradation',
        originalPath: videoPath,
        degradedPath: outputPath,
        scaleFactor,
        originalResolution: [width, height],
        intermediateResolution: [newWidth, newHeight],
        checksum,
        fileSize: fs.statSync(outputPath).size
    };
}

/**
 * Seeded random number generator for reproducibility
 */
class SeededRandom {
    constructor(seed) {
        this.seed = seed;
        this.m = 0x80000000;  // 2^31
        this.a = 1103515245;
        this.c = 12345;
        this.state = seed ? (seed * this.m) : Math.floor(Math.random() * (this.m - 1));
    }
    
    next() {
        this.state = (this.a * this.state + this.c) % this.m;
        return this.state / (this.m - 1);
    }
}

/**
 * Calculate SHA-256 checksum of file
 */
function calculateChecksum(filePath) {
    const hash = crypto.createHash('sha256');
    const buffer = fs.readFileSync(filePath);
    hash.update(buffer);
    return hash.digest('hex');
}

/**
 * Batch error injection: Apply multiple error modes to all test videos
 * 
 * @param {Array<string>} videoPaths - Array of input video paths
 * @param {Array<object>} errorConfigs - Array of {mode, params} objects
 * @param {string} outputDir - Directory for error-injected videos
 * @returns {Array<object>} - Metadata for all generated error variants
 */
function batchInjectErrors(videoPaths, errorConfigs, outputDir) {
    const results = [];
    
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    
    console.log('═══════════════════════════════════════════════════════════════════');
    console.log('🧪 Error Injection - Batch Mode');
    console.log('═══════════════════════════════════════════════════════════════════\n');
    
    for (const videoPath of videoPaths) {
        const videoName = videoPath.split('/').pop().replace('.webm', '');
        
        console.log(`──────────────────────────────────────────────────────────────────`);
        console.log(`📹 Processing: ${videoName}`);
        console.log(`──────────────────────────────────────────────────────────────────\n`);
        
        for (const config of errorConfigs) {
            const errorName = config.mode.toLowerCase().replace(/ /g, '_');
            const outputName = `${videoName}_ERROR_${errorName}.webm`;
            const outputPath = `${outputDir}/${outputName}`;
            
            console.log(`🎯 Applying: ${config.mode}`);
            
            let result;
            
            try {
                switch (config.mode) {
                    case 'frame_corruption':
                        result = injectFrameCorruption(videoPath, config.rate || 0.1, outputPath, config.options || {});
                        break;
                    case 'timing_jitter':
                        result = injectTimingJitter(videoPath, config.variance || 0.2, outputPath, config.options || {});
                        break;
                    case 'partial_video':
                        result = injectPartialVideo(videoPath, config.cutoff || 0.2, outputPath);
                        break;
                    case 'wrong_roi':
                        result = injectWrongROI(videoPath, config.offset || [50, 50], outputPath);
                        break;
                    case 'extreme_lighting':
                        result = injectExtremeLighting(videoPath, config.brightness || 0.3, outputPath);
                        break;
                    case 'resolution_degradation':
                        result = injectResolutionDegradation(videoPath, config.scale || 0.5, outputPath);
                        break;
                    default:
                        console.error(`❌ Unknown error mode: ${config.mode}`);
                        continue;
                }
                
                result.testCaseName = videoName;
                result.errorConfig = config;
                results.push(result);
                
                console.log(`✅ Created: ${outputName}`);
                console.log(`   Checksum: ${result.checksum}`);
                console.log(`   Size: ${(result.fileSize / 1024).toFixed(1)} KB\n`);
                
            } catch (error) {
                console.error(`❌ Error applying ${config.mode}: ${error.message}\n`);
            }
        }
    }
    
    console.log('═══════════════════════════════════════════════════════════════════');
    console.log(`✅ Batch injection complete: ${results.length} error variants created`);
    console.log('═══════════════════════════════════════════════════════════════════\n');
    
    return results;
}

module.exports = {
    ERROR_MODES,
    injectFrameCorruption,
    injectTimingJitter,
    injectPartialVideo,
    injectWrongROI,
    injectExtremeLighting,
    injectResolutionDegradation,
    batchInjectErrors,
    SeededRandom
};
