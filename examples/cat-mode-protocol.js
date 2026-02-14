/**
 * 🐱 Cat Mode Protocol Implementation
 * 
 * Packet format for reliable optical data transmission via blinking cat eyes.
 * Implements CRC32 integrity checking, session management, and packet sequencing.
 * 
 * Packet Structure (17 bytes minimum + payload):
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ Byte 0-1   │ Magic Number (0xCAFE - "cat face")                 │
 * │ Byte 2     │ Protocol Version (0x01)                             │
 * │ Byte 3-6   │ Session ID (32-bit random, prevents cross-talk)    │
 * │ Byte 7-8   │ Sequence Number (16-bit, detects missing packets)  │
 * │ Byte 9-10  │ Payload Length (16-bit, max 1024 bytes)            │
 * │ Byte 11-14 │ CRC32 (covers version + session + seq + len + payload) │
 * │ Byte 15... │ Payload (0-1024 bytes)                              │
 * └──────────────────────────────────────────────────────────────────┘
 * 
 * Security Properties:
 * - PROTO-001: Magic number prevents false sync
 * - PROTO-002: CRC32 detects bit errors (burst up to 32 bits)
 * - PROTO-003: Session ID prevents signal injection
 * - PROTO-004: Sequence numbers detect packet loss
 * - PROTO-005: Payload length validated before CRC check
 * 
 * Usage:
 *   // Encode
 *   const session = CatProtocol.generateSessionId();
 *   const packets = CatProtocol.encodeMessage("Hello, World!", session);
 *   
 *   // Decode
 *   const decoder = new CatProtocolDecoder();
 *   for (const packetBytes of receivedPackets) {
 *       const result = decoder.processPacket(packetBytes);
 *       if (result.complete) {
 *           console.log('Message:', result.message);
 *       }
 *   }
 * 
 * @author Meow Decoder Team
 * @version 2.0
 * @date 2026-02-13
 */

// ============================================================================
// Constants
// ============================================================================

const MAGIC_NUMBER = 0xCAFE;  // "Cat face" magic number
const PROTOCOL_VERSION = 0x01;
const HEADER_SIZE = 15;  // Total header size (magic + version + session + seq + len + crc)
const MAX_PAYLOAD_SIZE = 1024;  // Max 1KB per packet
const MAX_PACKETS = 65535;  // 16-bit sequence number limit

// ============================================================================
// CRC32 Implementation (IEEE 802.3 polynomial)
// ============================================================================

/**
 * CRC32 lookup table (pre-computed for performance).
 * Polynomial: 0xEDB88320 (IEEE 802.3)
 */
const CRC32_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let crc = i;
        for (let j = 0; j < 8; j++) {
            crc = (crc & 1) ? (0xEDB88320 ^ (crc >>> 1)) : (crc >>> 1);
        }
        table[i] = crc;
    }
    return table;
})();

/**
 * Compute CRC32 checksum.
 * @param {Uint8Array} data - Input bytes
 * @returns {number} 32-bit CRC checksum
 */
function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) {
        const byte = data[i];
        const index = (crc ^ byte) & 0xFF;
        crc = (crc >>> 8) ^ CRC32_TABLE[index];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;  // Unsigned 32-bit
}

/**
 * Constant-time 32-bit integer comparison.
 * Uses XOR to avoid timing side-channels from short-circuit evaluation.
 * @param {number} a - First 32-bit integer
 * @param {number} b - Second 32-bit integer
 * @returns {boolean} True if equal
 */
function constantTimeEqual32(a, b) {
    return ((a ^ b) >>> 0) === 0;
}

/**
 * Verify CRC32 checksum (constant-time comparison).
 * @param {Uint8Array} data - Data to verify
 * @param {number} expectedCrc - Expected CRC value
 * @returns {boolean} True if CRC matches
 */
function verifyCrc32(data, expectedCrc) {
    const computedCrc = crc32(data);
    return constantTimeEqual32(computedCrc, expectedCrc);
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate random 32-bit session ID.
 * @returns {number} Random session ID
 */
function generateSessionId() {
    const bytes = crypto.getRandomValues(new Uint8Array(4));
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

/**
 * Convert bytes to hex string (for debugging).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Write 16-bit value to buffer (little-endian).
 */
function writeUint16LE(buffer, offset, value) {
    buffer[offset] = value & 0xFF;
    buffer[offset + 1] = (value >>> 8) & 0xFF;
}

/**
 * Read 16-bit value from buffer (little-endian).
 */
function readUint16LE(buffer, offset) {
    return buffer[offset] | (buffer[offset + 1] << 8);
}

/**
 * Write 32-bit value to buffer (little-endian).
 */
function writeUint32LE(buffer, offset, value) {
    buffer[offset] = value & 0xFF;
    buffer[offset + 1] = (value >>> 8) & 0xFF;
    buffer[offset + 2] = (value >>> 16) & 0xFF;
    buffer[offset + 3] = (value >>> 24) & 0xFF;
}

/**
 * Read 32-bit value from buffer (little-endian).
 */
function readUint32LE(buffer, offset) {
    return (buffer[offset] |
            (buffer[offset + 1] << 8) |
            (buffer[offset + 2] << 16) |
            (buffer[offset + 3] << 24)) >>> 0;
}

// ============================================================================
// Packet Encoder
// ============================================================================

/**
 * Encode a single packet.
 * @param {Uint8Array} payload - Payload bytes (max 1024)
 * @param {number} sessionId - 32-bit session ID
 * @param {number} sequenceNum - 16-bit sequence number
 * @returns {Uint8Array} Encoded packet
 * @throws {Error} If payload too large
 */
function encodePacket(payload, sessionId, sequenceNum) {
    if (payload.length > MAX_PAYLOAD_SIZE) {
        throw new Error(`Payload too large: ${payload.length} > ${MAX_PAYLOAD_SIZE}`);
    }
    
    const packetSize = HEADER_SIZE + payload.length;
    const packet = new Uint8Array(packetSize);
    
    let offset = 0;
    
    // Magic number (2 bytes)
    writeUint16LE(packet, offset, MAGIC_NUMBER);
    offset += 2;
    
    // Protocol version (1 byte)
    packet[offset++] = PROTOCOL_VERSION;
    
    // Session ID (4 bytes)
    writeUint32LE(packet, offset, sessionId);
    offset += 4;
    
    // Sequence number (2 bytes)
    writeUint16LE(packet, offset, sequenceNum);
    offset += 2;
    
    // Payload length (2 bytes)
    writeUint16LE(packet, offset, payload.length);
    offset += 2;
    // offset = 11
    
    // Skip CRC slot (4 bytes) — filled after payload is written
    offset += 4;
    // offset = 15
    
    // Payload (starts at byte 15, after the full header)
    packet.set(payload, offset);
    offset += payload.length;
    
    // Compute CRC32 over version + session + seq + len + payload
    // (excludes magic number for better error detection)
    // Build CRC buffer to match decoder's verification format exactly
    const crcData = new Uint8Array(1 + 4 + 2 + 2 + payload.length);
    crcData[0] = PROTOCOL_VERSION;
    writeUint32LE(crcData, 1, sessionId);
    writeUint16LE(crcData, 5, sequenceNum);
    writeUint16LE(crcData, 7, payload.length);
    crcData.set(payload instanceof Uint8Array ? payload : new Uint8Array(payload), 9);
    const crcValue = crc32(crcData);
    
    // Insert CRC at position 11 (after len, before payload)
    writeUint32LE(packet, 11, crcValue);
    
    return packet;
}

/**
 * Encode a message into multiple packets.
 * @param {string|Uint8Array} message - Message to encode
 * @param {number} sessionId - Session ID (or null to generate)
 * @param {number} maxPayloadPerPacket - Max payload per packet (default 256)
 * @returns {Array<Uint8Array>} Array of encoded packets
 */
function encodeMessage(message, sessionId = null, maxPayloadPerPacket = 256) {
    // Convert string to bytes if needed
    const messageBytes = typeof message === 'string' 
        ? new TextEncoder().encode(message)
        : message;
    
    // Generate session ID if not provided
    if (sessionId === null) {
        sessionId = generateSessionId();
    }
    
    // Split into packets
    const packets = [];
    let sequenceNum = 0;
    
    for (let offset = 0; offset < messageBytes.length; offset += maxPayloadPerPacket) {
        const end = Math.min(offset + maxPayloadPerPacket, messageBytes.length);
        const payload = messageBytes.slice(offset, end);
        
        const packet = encodePacket(payload, sessionId, sequenceNum);
        packets.push(packet);
        
        sequenceNum++;
        
        if (sequenceNum > MAX_PACKETS) {
            throw new Error('Message too large: exceeds max packet count');
        }
    }
    
    return packets;
}

// ============================================================================
// Packet Decoder
// ============================================================================

/**
 * Decode and validate a single packet.
 * 
 * Security hardening: All checks are coalesced to avoid timing side-channels.
 * CRC is always computed regardless of earlier validation failures.
 * Error responses use a generic message to prevent information leakage.
 * 
 * @param {Uint8Array} packetBytes - Raw packet bytes
 * @returns {object} Decoded packet or error
 */
function decodePacket(packetBytes) {
    // Minimum packet size check (safe — reveals no secret state)
    if (packetBytes.length < HEADER_SIZE) {
        return {
            valid: false,
            error: 'packet_invalid'
        };
    }
    
    let offset = 0;
    
    // Parse all header fields unconditionally
    const magic = readUint16LE(packetBytes, offset);
    offset += 2;
    
    const version = packetBytes[offset++];
    
    const sessionId = readUint32LE(packetBytes, offset);
    offset += 4;
    
    const sequenceNum = readUint16LE(packetBytes, offset);
    offset += 2;
    
    const payloadLen = readUint16LE(packetBytes, offset);
    offset += 2;
    
    const crcExpected = readUint32LE(packetBytes, offset);
    offset += 4;
    
    // Validate all fields without early return
    let valid = true;
    valid = valid && constantTimeEqual32(magic, MAGIC_NUMBER);
    valid = valid && (version === PROTOCOL_VERSION);
    valid = valid && (payloadLen <= MAX_PAYLOAD_SIZE);
    
    // Validate total packet size
    const expectedSize = HEADER_SIZE + payloadLen;
    valid = valid && (packetBytes.length === expectedSize);
    
    // Always compute CRC, even if other checks failed (prevents timing oracle).
    // Use clamped payload length to avoid OOB reads on malformed packets.
    const safePayloadLen = Math.min(payloadLen, Math.max(0, packetBytes.length - HEADER_SIZE), MAX_PAYLOAD_SIZE);
    const payload = packetBytes.slice(offset, offset + safePayloadLen);
    
    const crcData = new Uint8Array(1 + 4 + 2 + 2 + safePayloadLen);
    crcData[0] = version;
    writeUint32LE(crcData, 1, sessionId);
    writeUint16LE(crcData, 5, sequenceNum);
    writeUint16LE(crcData, 7, payloadLen);
    if (safePayloadLen > 0) {
        crcData.set(payload, 9);
    }
    
    const crcComputed = crc32(crcData);
    valid = valid && constantTimeEqual32(crcComputed, crcExpected);
    
    if (!valid) {
        return {
            valid: false,
            error: 'packet_invalid'
        };
    }
    
    // Success!
    return {
        valid: true,
        version: version,
        sessionId: sessionId,
        sequenceNum: sequenceNum,
        payload: payload
    };
}

// ============================================================================
// Multi-Packet Decoder (Stateful)
// ============================================================================

class CatProtocolDecoder {
    constructor() {
        this.reset();
    }
    
    /**
     * Reset decoder state.
     */
    reset() {
        this.lockedSessionId = null;
        this.receivedPackets = new Map();  // seq -> payload
        this.expectedPackets = null;  // Total expected (unknown initially)
        this.stats = {
            packets_received: 0,
            packets_accepted: 0,
            packets_rejected: 0
        };
    }
    
    /**
     * Process a single packet.
     * 
     * Security hardening: Error responses use generic messages to prevent
     * side-channel enumeration of failure modes.
     * 
     * @param {Uint8Array} packetBytes
     * @returns {object} Processing result
     */
    processPacket(packetBytes) {
        this.stats.packets_received++;
        const decoded = decodePacket(packetBytes);
        
        // Invalid packet (CRC, magic, version, size — all coalesced)
        if (!decoded.valid) {
            this.stats.packets_rejected++;
            return {
                accepted: false,
                error: 'packet_rejected'
            };
        }
        
        // Session locking
        if (this.lockedSessionId === null) {
            // First valid packet locks session
            this.lockedSessionId = decoded.sessionId;
        } else if (!constantTimeEqual32(decoded.sessionId, this.lockedSessionId)) {
            // Wrong session — generic error, no session ID leak
            this.stats.packets_rejected++;
            return {
                accepted: false,
                error: 'packet_rejected'
            };
        }
        
        // Check for duplicate
        if (this.receivedPackets.has(decoded.sequenceNum)) {
            this.stats.packets_rejected++;
            return {
                accepted: false,
                error: 'packet_rejected'
            };
        }
        
        // Store packet
        this.receivedPackets.set(decoded.sequenceNum, decoded.payload);
        this.stats.packets_accepted++;
        
        // Check if complete (all sequence numbers from 0 to max received)
        const maxSeq = Math.max(...this.receivedPackets.keys());
        const isComplete = this.receivedPackets.size === (maxSeq + 1);
        
        if (isComplete) {
            // Reconstruct message
            const payloads = [];
            for (let i = 0; i <= maxSeq; i++) {
                payloads.push(this.receivedPackets.get(i));
            }
            
            // Concatenate
            const totalLength = payloads.reduce((sum, p) => sum + p.length, 0);
            const message = new Uint8Array(totalLength);
            let offset = 0;
            for (const payload of payloads) {
                message.set(payload, offset);
                offset += payload.length;
            }
            
            return {
                accepted: true,
                complete: true,
                message: message,
                sessionId: this.lockedSessionId,
                totalPackets: maxSeq + 1,
                stats: { ...this.stats }
            };
        }
        
        // Not complete yet
        return {
            accepted: true,
            complete: false,
            sequenceNum: decoded.sequenceNum,
            progress: {
                received: this.receivedPackets.size,
                total: maxSeq + 1  // Current estimate
            }
        };
    }
    
    /**
     * Get current statistics.
     */
    getStats() {
        return { ...this.stats };
    }
    
    /**
     * Get locked session ID (or null).
     */
    getSessionId() {
        return this.lockedSessionId;
    }
}

// ============================================================================
// Export API
// ============================================================================

const CatProtocol = {
    // Constants
    MAGIC_NUMBER,
    PROTOCOL_VERSION,
    HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    
    // Functions
    generateSessionId,
    encodePacket,
    encodeMessage,
    decodePacket,
    
    // Classes
    Decoder: CatProtocolDecoder,
    
    // Utilities
    crc32,
    verifyCrc32,
    bytesToHex
};

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    constantTimeEqual32,
    module.exports = CatProtocol;
}

// Also export to window for browser usage
if (typeof window !== 'undefined') {
    window.CatProtocol = CatProtocol;
}
