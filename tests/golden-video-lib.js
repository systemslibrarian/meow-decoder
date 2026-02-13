#!/usr/bin/env node

/**
 * Golden Video Generation Library
 * Headless rendering of synthetic cat face videos for deterministic testing
 * 
 * Requires: npm install canvas
 */

const { createCanvas } = require('canvas');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ====================================================================
// Cat Face Renderer (Deterministic)
// ====================================================================

class CatFaceRenderer {
    constructor(width = 640, height = 480) {
        this.canvas = createCanvas(width, height);
        this.ctx = this.canvas.getContext('2d');
        this.width = width;
        this.height = height;
    }
    
    clear() {
        this.ctx.fillStyle = '#000000';
        this.ctx.fillRect(0, 0, this.width, this.height);
    }
    
    drawCatFace(eyeColor = '#00ff00') {
        this.clear();
        
        const cx = this.width / 2;
        const cy = this.height / 2;
        const faceRadius = Math.min(this.width, this.height) * 0.35;
        
        // Face outline (gray)
        this.ctx.fillStyle = '#666666';
        this.ctx.beginPath();
        this.ctx.arc(cx, cy, faceRadius, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Left ear
        this.ctx.beginPath();
        this.ctx.moveTo(cx - faceRadius * 0.7, cy - faceRadius * 0.5);
        this.ctx.lineTo(cx - faceRadius * 1.1, cy - faceRadius * 1.3);
        this.ctx.lineTo(cx - faceRadius * 0.3, cy - faceRadius * 0.7);
        this.ctx.closePath();
        this.ctx.fill();
        
        // Right ear
        this.ctx.beginPath();
        this.ctx.moveTo(cx + faceRadius * 0.7, cy - faceRadius * 0.5);
        this.ctx.lineTo(cx + faceRadius * 1.1, cy - faceRadius * 1.3);
        this.ctx.lineTo(cx + faceRadius * 0.3, cy - faceRadius * 0.7);
        this.ctx.closePath();
        this.ctx.fill();
        
        // Eyes (the important part!)
        const eyeY = cy - faceRadius * 0.15;
        const eyeSpacing = faceRadius * 0.5;
        const eyeRadius = faceRadius * 0.25;
        
        // Left eye
        this.ctx.fillStyle = eyeColor;
        this.ctx.beginPath();
        this.ctx.arc(cx - eyeSpacing, eyeY, eyeRadius, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Right eye
        this.ctx.beginPath();
        this.ctx.arc(cx + eyeSpacing, eyeY, eyeRadius, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Pupils (vertical slits)
        this.ctx.fillStyle = '#000000';
        const pupilWidth = eyeRadius * 0.15;
        const pupilHeight = eyeRadius * 1.2;
        
        this.ctx.fillRect(cx - eyeSpacing - pupilWidth/2, eyeY - pupilHeight/2, pupilWidth, pupilHeight);
        this.ctx.fillRect(cx + eyeSpacing - pupilWidth/2, eyeY - pupilHeight/2, pupilWidth, pupilHeight);
        
        // Nose
        this.ctx.fillStyle = '#ff66aa';
        this.ctx.beginPath();
        this.ctx.moveTo(cx, cy + faceRadius * 0.15);
        this.ctx.lineTo(cx - faceRadius * 0.08, cy + faceRadius * 0.05);
        this.ctx.lineTo(cx + faceRadius * 0.08, cy + faceRadius * 0.05);
        this.ctx.closePath();
        this.ctx.fill();
        
        // Mouth
        this.ctx.strokeStyle = '#444444';
        this.ctx.lineWidth = 2;
        this.ctx.beginPath();
        this.ctx.moveTo(cx, cy + faceRadius * 0.15);
        this.ctx.lineTo(cx, cy + faceRadius * 0.25);
        this.ctx.stroke();
        
        // Whiskers
        this.ctx.strokeStyle = '#999999';
        this.ctx.lineWidth = 1.5;
        const whiskerY = cy + faceRadius * 0.1;
        
        // Left whiskers
        this.drawWhisker(cx - faceRadius * 0.2, whiskerY, cx - faceRadius * 0.9, whiskerY - faceRadius * 0.2);
        this.drawWhisker(cx - faceRadius * 0.2, whiskerY, cx - faceRadius * 0.9, whiskerY);
        this.drawWhisker(cx - faceRadius * 0.2, whiskerY, cx - faceRadius * 0.9, whiskerY + faceRadius * 0.2);
        
        // Right whiskers
        this.drawWhisker(cx + faceRadius * 0.2, whiskerY, cx + faceRadius * 0.9, whiskerY - faceRadius * 0.2);
        this.drawWhisker(cx + faceRadius * 0.2, whiskerY, cx + faceRadius * 0.9, whiskerY);
        this.drawWhisker(cx + faceRadius * 0.2, whiskerY, cx + faceRadius * 0.9, whiskerY + faceRadius * 0.2);
    }
    
    drawWhisker(x1, y1, x2, y2) {
        this.ctx.beginPath();
        this.ctx.moveTo(x1, y1);
        this.ctx.lineTo(x2, y2);
        this.ctx.stroke();
    }
    
    getImageData() {
        return this.ctx.getImageData(0, 0, this.width, this.height);
    }
    
    toBuffer() {
        return this.canvas.toBuffer('image/png');
    }
}

// ====================================================================
// Payload Encoding
// ====================================================================

function hexToBinary(hexString) {
    let binary = '';
    for (let i = 0; i < hexString.length; i++) {
        const hex = hexString[i];
        const bin = parseInt(hex, 16).toString(2).padStart(4, '0');
        binary += bin;
    }
    return binary;
}

function stringToBinary(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let binary = '';
    for (const byte of bytes) {
        binary += byte.toString(2).padStart(8, '0');
    }
    return binary;
}

function encodePayloadToBits(payload, payloadType) {
    let payloadBits = '';
    
    if (payloadType === 'hash' || payloadType === 'hex') {
        payloadBits = hexToBinary(payload);
    } else {
        payloadBits = stringToBinary(payload);
    }
    
    // Build full transmission:
    // Lead-in (8 bits dark) + Preamble (32 bits alternating) + Sync (16 bits 0xAA55) + Payload
    const leadIn = '00000000';
    const preamble = '10101010101010101010101010101010'; // 32 bits
    const syncWord = '1010101001010101'; // 0xAA55
    
    return leadIn + preamble + syncWord + payloadBits;
}

// ====================================================================
// Frame Sequence Generation
// ====================================================================

function generateFrameSequence(bits, fps, bitSpeed) {
    const frames = [];
    const framesPerBit = Math.max(1, Math.round(fps * (bitSpeed / 1000)));
    
    for (let bitIdx = 0; bitIdx < bits.length; bitIdx++) {
        const bit = bits[bitIdx];
        const eyeColor = bit === '1' ? '#00ff00' : '#003300';
        
        // Repeat this bit for required number of frames
        for (let frameIdx = 0; frameIdx < framesPerBit; frameIdx++) {
            frames.push({
                bitIndex: bitIdx,
                bit: bit,
                eyeColor: eyeColor,
                frameNumber: frames.length,
                timestamp: frames.length / fps
            });
        }
    }
    
    return frames;
}

// ====================================================================
// PNG Sequence to WebM Conversion (using ffmpeg)
// ====================================================================

function generateGoldenVideo(config) {
    const {
        name,
        payload,
        payloadType = 'hash',
        bitSpeed = 100,
        fps = 30,
        width = 640,
        height = 480,
        outputDir = path.join(__dirname, 'golden')
    } = config;
    
    console.log(`\n🎬 Generating golden video: ${name}`);
    console.log(`   Payload type: ${payloadType}`);
    console.log(`   Bit speed: ${bitSpeed}ms`);
    console.log(`   FPS: ${fps}`);
    console.log(`   Resolution: ${width}x${height}`);
    
    // Encode payload to bits
    const bits = encodePayloadToBits(payload, payloadType);
    console.log(`   Total bits: ${bits.length}`);
    
    // Generate frame sequence
    const frameSequence = generateFrameSequence(bits, fps, bitSpeed);
    console.log(`   Total frames: ${frameSequence.length}`);
    console.log(`   Duration: ${(frameSequence.length / fps).toFixed(1)}s`);
    
    // Create renderer
    const renderer = new CatFaceRenderer(width, height);
    
    // Create temporary directory for frames
    const tempDir = path.join(__dirname, '.tmp_frames', name);
    if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true });
    }
    fs.mkdirSync(tempDir, { recursive: true });
    
    // Render all frames to PNG files
    console.log(`   Rendering frames...`);
    for (let i = 0; i < frameSequence.length; i++) {
        const frame = frameSequence[i];
        renderer.drawCatFace(frame.eyeColor);
        
        const framePath = path.join(tempDir, `frame_${String(i).padStart(6, '0')}.png`);
        const buffer = renderer.toBuffer();
        fs.writeFileSync(framePath, buffer);
        
        if ((i + 1) % 100 === 0) {
            console.log(`   Progress: ${i + 1}/${frameSequence.length} frames`);
        }
    }
    
    console.log(`   ✓ All frames rendered`);
    
    // Convert PNG sequence to WebM using ffmpeg
    const outputPath = path.join(outputDir, `cat_mode_golden_${name}_${bitSpeed}ms.webm`);
    
    console.log(`   Converting to WebM...`);
    const { execSync } = require('child_process');
    
    try {
        // Use ffmpeg to create WebM video
        const ffmpegCmd = `ffmpeg -y -framerate ${fps} -i "${tempDir}/frame_%06d.png" -c:v libvpx-vp9 -pix_fmt yuv420p -b:v 2M "${outputPath}"`;
        
        execSync(ffmpegCmd, { stdio: 'inherit' });
        
        console.log(`   ✓ Video created: ${outputPath}`);
        
        // Calculate SHA-256 checksum
        const videoData = fs.readFileSync(outputPath);
        const checksum = crypto.createHash('sha256').update(videoData).digest('hex');
        console.log(`   Checksum: ${checksum}`);
        
        // Clean up temporary frames
        fs.rmSync(tempDir, { recursive: true });
        
        return {
            name,
            path: outputPath,
            checksum,
            size: videoData.length,
            frames: frameSequence.length,
            duration: frameSequence.length / fps,
            fps,
            bitSpeed
        };
        
    } catch (error) {
        console.error(`   ✗ Error: ${error.message}`);
        throw error;
    }
}

// ====================================================================
// Exports
// ====================================================================

module.exports = {
    generateGoldenVideo,
    CatFaceRenderer,
    encodePayloadToBits,
    generateFrameSequence
};

// CLI usage
if (require.main === module) {
    console.log('This is a library module. Use generate_golden_videos.js to generate videos.');
    process.exit(1);
}
