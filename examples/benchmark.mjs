/**
 * Meow Decoder - Performance Benchmark (Node.js)
 *
 * Run with: node examples/benchmark.mjs
 *
 * This measures timing of each crypto operation to identify bottlenecks.
 */

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load the WASM module (ESM with async init)
const wasmModule = await import(join(__dirname, '..', 'crypto_core', 'pkg', 'crypto_core.js'));
const wasmPath = join(__dirname, '..', 'crypto_core', 'pkg', 'crypto_core_bg.wasm');
const wasmBytes = await readFile(wasmPath);
await wasmModule.default(wasmBytes);
const wasm = wasmModule;

// ANSI colors for terminal output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    bold: '\x1b[1m',
};

function formatMs(ms) {
    if (ms > 1000) return `${(ms / 1000).toFixed(2)}s`;
    return `${ms.toFixed(2)}ms`;
}

function getStatus(ms) {
    if (ms > 1000) return { text: 'SLOW', color: colors.red };
    if (ms > 100) return { text: 'MEDIUM', color: colors.yellow };
    return { text: 'FAST', color: colors.green };
}

async function timeAsync(label, fn) {
    const start = performance.now();
    const result = await fn();
    const elapsed = performance.now() - start;
    return { result, elapsed, label };
}

function printHeader(text) {
    console.log('\n' + colors.bold + colors.cyan + '═'.repeat(60) + colors.reset);
    console.log(colors.bold + ' ' + text + colors.reset);
    console.log(colors.cyan + '═'.repeat(60) + colors.reset);
}

function printTiming(timing) {
    const status = getStatus(timing.elapsed);
    console.log(
        `  ${timing.label.padEnd(45)} ${formatMs(timing.elapsed).padStart(10)} ${status.color}[${status.text}]${colors.reset}`
    );
}

async function runFullBenchmark() {
    printHeader('🔬 FULL CRYPTO BENCHMARK');

    const encoder = new TextEncoder();
    const testMessage = 'Hello, this is a test message for benchmarking! '.repeat(10);
    const password = 'TestPassword123!';
    const timings = [];

    // 1. Generate salt
    const saltTiming = await timeAsync('1. Generate salt (16 bytes)', async () => {
        return wasm.generate_salt();
    });
    timings.push(saltTiming);
    const salt = saltTiming.result.data;

    // 2. Generate nonce
    const nonceTiming = await timeAsync('2. Generate nonce (12 bytes)', async () => {
        return wasm.generate_nonce();
    });
    timings.push(nonceTiming);
    const nonce = nonceTiming.result.data;

    // 3. Key derivation (Argon2id)
    const keyTiming = await timeAsync('3. Key derivation (Argon2id, 64MiB, 3 iter)', async () => {
        return wasm.derive_key(encoder.encode(password), salt, null, null);
    });
    timings.push(keyTiming);
    const key = keyTiming.result.data;

    // 4. Encryption
    const encryptTiming = await timeAsync(`4. Encryption (AES-256-GCM, ${testMessage.length} bytes)`, async () => {
        return wasm.encrypt(encoder.encode(testMessage), key, nonce, null);
    });
    timings.push(encryptTiming);
    const ciphertext = encryptTiming.result.data;

    // 5. Decryption
    const decryptTiming = await timeAsync(`5. Decryption (AES-256-GCM, ${ciphertext.length} bytes)`, async () => {
        return wasm.decrypt(ciphertext, key, nonce, null);
    });
    timings.push(decryptTiming);

    // Print results
    console.log('\n  Operation                                       Time       Status');
    console.log('  ' + '-'.repeat(56));
    for (const t of timings) {
        printTiming(t);
    }

    const total = timings.reduce((sum, t) => sum + t.elapsed, 0);
    const keyPct = ((keyTiming.elapsed / total) * 100).toFixed(1);

    console.log('  ' + '-'.repeat(56));
    console.log(`  ${colors.bold}TOTAL${colors.reset}`.padEnd(55) + formatMs(total).padStart(10));

    console.log('\n' + colors.bold + '📊 Analysis:' + colors.reset);
    console.log(`  • Key derivation is ${keyPct}% of total time`);
    console.log(`  • This is expected - Argon2id is intentionally slow for security`);
    console.log(`  • The Web Worker keeps UI responsive during this operation`);

    return timings;
}

async function runKeyDerivationComparison() {
    printHeader('🔑 KEY DERIVATION PARAMETER COMPARISON');

    const encoder = new TextEncoder();
    const password = 'TestPassword123!';
    const salt = wasm.generate_salt().data;

    const configs = [
        { memory: 8192, iterations: 1, label: '8 MiB, 1 iter (Demo mode)' },
        { memory: 16384, iterations: 1, label: '16 MiB, 1 iter' },
        { memory: 32768, iterations: 2, label: '32 MiB, 2 iter (Fast)' },
        { memory: 65536, iterations: 3, label: '64 MiB, 3 iter (Default)' },
        { memory: 131072, iterations: 4, label: '128 MiB, 4 iter (High sec)' },
    ];

    console.log('\n  Configuration                                   Time       Status');
    console.log('  ' + '-'.repeat(56));

    for (const cfg of configs) {
        const t = await timeAsync(`${cfg.label}`, async () => {
            return wasm.derive_key(encoder.encode(password), salt, cfg.memory, cfg.iterations);
        });
        printTiming(t);
    }

    console.log('\n' + colors.bold + '💡 Recommendations:' + colors.reset);
    console.log('  • Demo/testing: 8-16 MiB, 1 iter (~50-100ms)');
    console.log('  • Interactive use: 32 MiB, 2 iter (~300-500ms)');
    console.log('  • Default (secure): 64 MiB, 3 iter (~1-2s)');
    console.log('  • High security: 128+ MiB, 4+ iter (slower but more secure)');
}

async function runEncryptionScaling() {
    printHeader('📦 ENCRYPTION PERFORMANCE BY DATA SIZE');

    const encoder = new TextEncoder();
    const password = 'TestPassword123!';
    const salt = wasm.generate_salt().data;
    const nonce = wasm.generate_nonce().data;

    // Use faster key derivation for this test
    console.log('  Using fast key derivation (8 MiB, 1 iter) for base measurement...');
    const key = wasm.derive_key(encoder.encode(password), salt, 8192, 1).data;

    const sizes = [100, 1000, 10000, 50000, 100000, 500000, 1000000];

    console.log('\n  Data Size                                       Time       Throughput');
    console.log('  ' + '-'.repeat(60));

    for (const size of sizes) {
        const data = new Uint8Array(size).fill(65);
        const start = performance.now();
        wasm.encrypt(data, key, nonce, null);
        const elapsed = performance.now() - start;

        const throughput = (size / 1024 / 1024) / (elapsed / 1000); // MB/s
        const sizeStr = size >= 1000000 ? `${(size/1000000).toFixed(1)} MB` :
                        size >= 1000 ? `${(size/1000).toFixed(0)} KB` : `${size} B`;

        console.log(
            `  Encrypt ${sizeStr.padEnd(40)} ${formatMs(elapsed).padStart(10)} ${throughput.toFixed(1)} MB/s`
        );
    }
}

async function main() {
    console.log(colors.bold + colors.green);
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║      🐱 MEOW DECODER - PERFORMANCE PROFILER               ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log(colors.reset);

    await runFullBenchmark();
    await runKeyDerivationComparison();
    await runEncryptionScaling();

    console.log('\n' + colors.green + '✅ Benchmark complete!' + colors.reset + '\n');
}

main().catch(console.error);
