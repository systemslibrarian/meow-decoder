/**
 * Fountain Codes (Luby Transform) Implementation for JavaScript
 * 
 * Implements rateless erasure coding for loss-tolerant data transmission.
 * Based on the Python implementation in meow_decoder/fountain.py
 * 
 * Features:
 * - Robust Soliton distribution for optimal degree selection
 * - XOR-based encoding (simple and fast)
 * - Belief propagation decoding  
 * - Can recover from ~33% frame loss
 * 
 * Usage:
 *   const encoder = new FountainEncoder(data, 10, 100); // 10 blocks, 100 bytes each
 *   const droplet1 = encoder.generateDroplet(0);
 *   const droplet2 = encoder.generateDroplet(1);
 *   
 *   const decoder = new FountainDecoder(10, 100);
 *   decoder.addDroplet(droplet1);
 *   decoder.addDroplet(droplet2);
 *   // ... keep adding droplets until isComplete()
 *   const recovered = decoder.getData(originalLength);
 */

// Simple deterministic PRNG for reproducible block selection
class SeededRandom {
    constructor(seed) {
        this.seed = seed;
    }
    
    next() {
        // Linear congruential generator
        this.seed = (this.seed * 1103515245 + 12345) & 0x7fffffff;
        return this.seed / 0x7fffffff;
    }
    
    nextInt(max) {
        return Math.floor(this.next() * max);
    }
    
    // Fisher-Yates shuffle for sampling without replacement
    sample(array, k) {
        const result = [];
        const indices = Array.from({length: array.length}, (_, i) => i);
        
        for (let i = 0; i < Math.min(k, array.length); i++) {
            const j = i + this.nextInt(array.length - i);
            [indices[i], indices[j]] = [indices[j], indices[i]];
            result.push(array[indices[i]]);
        }
        
        return result.sort((a, b) => a - b);
    }
}

/**
 * Robust Soliton Distribution
 * 
 * Selects degrees for fountain code droplets to ensure:
 * - Good coverage of source blocks
 * - Efficient belief propagation decoding
 * - Low overhead (typically ~1.1-1.5x source blocks needed)
 */
class RobustSolitonDistribution {
    constructor(k, c = 0.1, delta = 0.5) {
        this.k = k;
        this.c = c;
        this.delta = delta;
        this.distribution = this._computeDistribution();
        this.cumulative = this._computeCumulative();
    }
    
    _computeDistribution() {
        const k = this.k;
        
        // Edge case: very small k
        if (k <= 1) {
            return [0.0, 1.0];
        }
        
        // Ideal Soliton distribution (ρ)
        const rho = new Array(k + 1).fill(0);
        rho[1] = 1.0 / k;
        for (let i = 2; i <= k; i++) {
            rho[i] = 1.0 / (i * (i - 1));
        }
        
        // Robust part (τ) - adds extra degree-1 droplets for reliability
        const R = this.c * Math.log(k / this.delta) * Math.sqrt(k);
        const tau = new Array(k + 1).fill(0);
        
        const m = Math.max(1, Math.min(Math.floor(k / R), k));
        
        for (let i = 1; i < m; i++) {
            tau[i] = R / (i * k);
        }
        tau[m] = R * Math.log(R / this.delta) / k;
        
        // Combine ρ and τ
        const mu = rho.map((r, i) => r + tau[i]);
        
        // Normalize
        const total = mu.reduce((sum, val) => sum + val, 0);
        if (total > 0) {
            return mu.map(m => m / total);
        }
        
        return rho; // Fallback
    }
    
    _computeCumulative() {
        const cumulative = [];
        let sum = 0;
        for (const prob of this.distribution) {
            sum += prob;
            cumulative.push(sum);
        }
        return cumulative;
    }
    
    sampleDegree() {
        const r = Math.random();
        for (let i = 0; i < this.cumulative.length; i++) {
            if (r < this.cumulative[i]) {
                return Math.max(1, i);
            }
        }
        return 1;
    }
}

/**
 * Fountain Code Droplet
 * 
 * A single encoded packet containing XOR of multiple source blocks.
 */
class Droplet {
    constructor(seed, blockIndices, data) {
        this.seed = seed;
        this.blockIndices = blockIndices;
        this.data = data;
    }
    
    /**
     * Pack droplet into bytes for transmission
     * Format: seed(4) + numIndices(2) + indices(2 each) + data
     */
    pack() {
        const buffer = new ArrayBuffer(4 + 2 + this.blockIndices.length * 2 + this.data.length);
        const view = new DataView(buffer);
        const uint8 = new Uint8Array(buffer);
        
        let offset = 0;
        
        // Seed (4 bytes, big-endian)
        view.setUint32(offset, this.seed, false);
        offset += 4;
        
        // Number of indices (2 bytes)
        view.setUint16(offset, this.blockIndices.length, false);
        offset += 2;
        
        // Indices (2 bytes each)
        for (const idx of this.blockIndices) {
            view.setUint16(offset, idx, false);
            offset += 2;
        }
        
        // Data
        uint8.set(this.data, offset);
        
        return new Uint8Array(buffer);
    }
    
    /**
     * Unpack droplet from bytes
     */
    static unpack(bytes, blockSize) {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let offset = 0;
        
        // Seed
        const seed = view.getUint32(offset, false);
        offset += 4;
        
        // Number of indices
        const numIndices = view.getUint16(offset, false);
        offset += 2;
        
        // Indices
        const blockIndices = [];
        for (let i = 0; i < numIndices; i++) {
            blockIndices.push(view.getUint16(offset, false));
            offset += 2;
        }
        
        // Data
        const data = new Uint8Array(bytes.buffer, bytes.byteOffset + offset, blockSize);
        
        return new Droplet(seed, blockIndices, data);
    }
}

/**
 * Fountain Encoder
 * 
 * Generates an unlimited stream of encoded droplets from source data.
 * Recipients can decode from any subset of droplets (with ~1.5x overhead).
 */
class FountainEncoder {
    constructor(data, kBlocks, blockSize) {
        this.kBlocks = kBlocks;
        this.blockSize = blockSize;
        this.dropletCount = 0;
        
        // Pad data to fill all blocks
        const totalSize = kBlocks * blockSize;
        const paddedData = new Uint8Array(totalSize);
        paddedData.set(data);
        
        // Split into blocks
        this.blocks = [];
        for (let i = 0; i < kBlocks; i++) {
            this.blocks.push(paddedData.slice(i * blockSize, (i + 1) * blockSize));
        }
        
        this.distribution = new RobustSolitonDistribution(kBlocks);
    }
    
    /**
     * Generate a single droplet
     * 
     * @param {number} seed - Optional seed (auto-assigned if undefined)
     * @returns {Droplet}
     */
    generateDroplet(seed) {
        if (seed === undefined) {
            seed = this.dropletCount;
        }
        this.dropletCount++;
        
        // OPTIMIZATION: First 2*k droplets are systematic (degree-1)
        // This dramatically improves decode reliability with no security cost
        // (payload is already encrypted high-entropy data)
        if (seed < 2 * this.kBlocks) {
            const blockIdx = seed % this.kBlocks;
            const data = new Uint8Array(this.blocks[blockIdx]);
            return new Droplet(seed, [blockIdx], data);
        }
        
        // Use seeded RNG for reproducibility
        const rng = new SeededRandom(seed);
        
        // Sample degree from distribution
        const degree = this.distribution.sampleDegree();
        
        // Select random blocks
        const blockIndices = rng.sample(
            Array.from({length: this.kBlocks}, (_, i) => i),
            Math.min(degree, this.kBlocks)
        );
        
        // XOR selected blocks
        const xorData = new Uint8Array(this.blockSize);
        for (const idx of blockIndices) {
            const block = this.blocks[idx];
            for (let i = 0; i < this.blockSize; i++) {
                xorData[i] ^= block[i];
            }
        }
        
        return new Droplet(seed, blockIndices, xorData);
    }
    
    /**
     * Generate multiple droplets
     */
    generateDroplets(n) {
        const droplets = [];
        for (let i = 0; i < n; i++) {
            droplets.push(this.generateDroplet());
        }
        return droplets;
    }
}

/**
 * Fountain Decoder
 * 
 * Reconstructs original data from received droplets using belief propagation.
 * Can handle missing/lost droplets (up to ~33% loss).
 */
class FountainDecoder {
    constructor(kBlocks, blockSize, originalLength = null) {
        this.kBlocks = kBlocks;
        this.blockSize = blockSize;
        this.originalLength = originalLength;
        
        // Decoded blocks
        this.blocks = new Array(kBlocks).fill(null);
        this.decoded = new Array(kBlocks).fill(false);
        this.decodedCount = 0;
        
        // Pending droplets (cannot decode yet)
        this.pendingDroplets = [];
    }
    
    /**
     * Check if decoding is complete
     */
    isComplete() {
        return this.decodedCount === this.kBlocks;
    }
    
    /**
     * Get decode progress (0.0 to 1.0)
     */
    getProgress() {
        return this.decodedCount / this.kBlocks;
    }
    
    /**
     * Add a droplet and attempt to decode
     * 
     * @param {Droplet} droplet
     * @returns {boolean} True if decoding is now complete
     */
    addDroplet(droplet) {
        // Reduce droplet using already-decoded blocks
        droplet = this._reduceDroplet(droplet);
        
        if (droplet.blockIndices.length === 0) {
            // Redundant droplet
            return this.isComplete();
        }
        
        if (droplet.blockIndices.length === 1) {
            // Degree-1 droplet - can decode immediately
            this._decodeBlock(droplet.blockIndices[0], droplet.data);
            
            // Process pending droplets (belief propagation)
            this._processPending();
        } else {
            // Degree > 1 - add to pending
            this.pendingDroplets.push(droplet);
        }
        
        return this.isComplete();
    }
    
    /**
     * Reduce droplet by XORing out already-decoded blocks
     */
    _reduceDroplet(droplet) {
        // Find unknown blocks
        const unknownIndices = droplet.blockIndices.filter(idx => !this.decoded[idx]);
        
        if (unknownIndices.length === droplet.blockIndices.length) {
            // No decoded blocks - return original
            return droplet;
        }
        
        // XOR out decoded blocks
        const reducedData = new Uint8Array(droplet.data);
        for (const idx of droplet.blockIndices) {
            if (this.decoded[idx]) {
                const block = this.blocks[idx];
                for (let i = 0; i < this.blockSize; i++) {
                    reducedData[i] ^= block[i];
                }
            }
        }
        
        return new Droplet(droplet.seed, unknownIndices, reducedData);
    }
    
    /**
     * Decode a block
     */
    _decodeBlock(blockIdx, blockData) {
        if (!this.decoded[blockIdx]) {
            this.blocks[blockIdx] = new Uint8Array(blockData);
            this.decoded[blockIdx] = true;
            this.decodedCount++;
        }
    }
    
    /**
     * Process pending droplets using belief propagation
     * 
     * This is called after decoding a block to check if any
     * pending droplets can now be decoded.
     */
    _processPending() {
        let madeProgress = true;
        
        while (madeProgress) {
            madeProgress = false;
            const newPending = [];
            
            for (const droplet of this.pendingDroplets) {
                // Reduce droplet
                const reduced = this._reduceDroplet(droplet);
                
                if (reduced.blockIndices.length === 0) {
                    // Redundant - skip
                    continue;
                } else if (reduced.blockIndices.length === 1) {
                    // Can decode now!
                    this._decodeBlock(reduced.blockIndices[0], reduced.data);
                    madeProgress = true;
                } else {
                    // Still pending
                    newPending.push(reduced);
                }
            }
            
            this.pendingDroplets = newPending;
        }
    }
    
    /**
     * Get reconstructed data
     * 
     * @param {number} originalLength - Original data length (before padding)
     * @returns {Uint8Array}
     * @throws {Error} If decoding is not complete
     */
    getData(originalLength = null) {
        if (!this.isComplete()) {
            throw new Error(
                `Decoding incomplete: ${this.decodedCount}/${this.kBlocks} blocks decoded`
            );
        }
        
        // Use provided length or stored length
        if (originalLength === null) {
            originalLength = this.originalLength;
        }
        
        if (originalLength === null) {
            throw new Error('originalLength must be provided');
        }
        
        // Concatenate blocks
        const fullData = new Uint8Array(this.kBlocks * this.blockSize);
        for (let i = 0; i < this.kBlocks; i++) {
            fullData.set(this.blocks[i], i * this.blockSize);
        }
        
        // Remove padding
        return fullData.slice(0, originalLength);
    }
}

// ─── Phase 3: WASM-backed fountain (gemini #6 unification) ─────────────
//
// When the Rust+WASM crypto_core module has been loaded by the page
// (via `import('./crypto_core.js')` in wasm_browser_example_FULL.html),
// the WASM module exposes `WasmFountainEncoder`, `WasmFountainDecoder`,
// and `WasmDroplet` classes. Calling `window.activateWasmFountain(mod)`
// hot-swaps the JS classes above with WASM-backed wrappers preserving
// the same API. Activation is idempotent and a no-op without WASM
// support (the legacy JS classes remain in effect).
//
// Output guarantee: when activated, droplets are byte-identical to the
// Python encoder's `pack_droplet()` output for the 16 golden vectors
// under tests/golden/fountain/.

(function () {
    if (typeof window === 'undefined') return;

    // Track whether WASM activation succeeded so callers can
    // introspect (`window.fountainBackend === 'wasm' | 'js'`).
    window.fountainBackend = 'js';

    window.activateWasmFountain = async function (wasmModule) {
        if (!wasmModule || !wasmModule.WasmFountainEncoder) {
            console.warn('[fountain] WASM activation skipped: missing exports');
            return false;
        }

        // Replace the class implementations on the global scope with
        // WASM-backed wrappers. The wrappers preserve the legacy API
        // (camelCase methods + same constructor signatures).
        window.FountainEncoder = class FountainEncoderWasm {
            constructor(data, kBlocks, blockSize) {
                this.kBlocks = kBlocks;
                this.blockSize = blockSize;
                // Pad with zeros up to kBlocks * blockSize (matches the
                // Python encoder's behaviour for short input).
                const total = kBlocks * blockSize;
                let padded = data;
                if (data.length < total) {
                    padded = new Uint8Array(total);
                    padded.set(data);
                }
                this._wasm = new wasmModule.WasmFountainEncoder(padded, kBlocks, blockSize);
                this.dropletCount = 0;
            }
            // Legacy API name from the original JS impl.
            generateDroplet(seed) {
                if (seed === undefined || seed === null) {
                    seed = this.dropletCount;
                }
                this.dropletCount += 1;
                const w = this._wasm.droplet(seed >>> 0);
                // Materialise into a plain Droplet so callers can
                // serialise/inspect without keeping the WASM handle.
                const d = new Droplet(seed, Array.from(w.blockIndices), w.data);
                w.free();
                return d;
            }
        };

        window.FountainDecoder = class FountainDecoderWasm {
            constructor(kBlocks, blockSize, originalLength = null) {
                this.kBlocks = kBlocks;
                this.blockSize = blockSize;
                this.originalLength = originalLength;
                this._wasm = new wasmModule.WasmFountainDecoder(kBlocks, blockSize);
            }
            get decodedCount() { return this._wasm.decodedCount; }
            isComplete() { return this._wasm.isComplete(); }
            addDroplet(droplet) {
                // Build wire bytes (BE u32 seed + BE u16 count + indices + data)
                // and let the WASM side parse — keeps the FFI surface narrow.
                const indices = Array.isArray(droplet.blockIndices)
                    ? droplet.blockIndices
                    : Array.from(droplet.blockIndices);
                const buf = new Uint8Array(4 + 2 + 2 * indices.length + droplet.data.length);
                const dv = new DataView(buf.buffer);
                dv.setUint32(0, droplet.seed >>> 0, false); // big-endian
                dv.setUint16(4, indices.length, false);
                for (let i = 0; i < indices.length; i++) {
                    dv.setUint16(6 + 2 * i, indices[i], false);
                }
                buf.set(droplet.data, 6 + 2 * indices.length);
                const w = wasmModule.WasmDroplet.fromWire(buf, this.blockSize);
                return this._wasm.addDroplet(w);
            }
            getData(originalLength = null) {
                if (!this.isComplete()) {
                    throw new Error(
                        `Decoding incomplete: ${this.decodedCount}/${this.kBlocks} blocks decoded`
                    );
                }
                if (originalLength === null) originalLength = this.originalLength;
                if (originalLength === null) {
                    throw new Error('originalLength must be provided');
                }
                const full = this._wasm.recoveredData();
                return full.slice(0, originalLength);
            }
        };

        window.fountainBackend = 'wasm';
        console.log('[fountain] WASM backend active — byte-identical to Python encoder');
        return true;
    };
})();

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        FountainEncoder,
        FountainDecoder,
        Droplet,
        RobustSolitonDistribution
    };
}
