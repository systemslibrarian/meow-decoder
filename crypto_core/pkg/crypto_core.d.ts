/* tslint:disable */
/* eslint-disable */

/**
 * WASM result type for JavaScript interop
 */
export class WasmResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Get result data as Uint8Array
     */
    readonly data: Uint8Array;
    /**
     * Get error message if failed
     */
    readonly error: string | undefined;
    /**
     * Check if operation succeeded
     */
    readonly success: boolean;
}

/**
 * X25519 key pair for WASM
 */
export class WasmX25519KeyPair {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Generate a new X25519 key pair
     */
    constructor();
    /**
     * Get public key bytes
     */
    readonly public_key: Uint8Array;
}

/**
 * Compare two byte arrays in constant time
 */
export function constant_time_compare(a: Uint8Array, b: Uint8Array): boolean;

/**
 * Decode data from transfer format
 *
 * # Arguments
 *
 * * `encoded` - Encoded data from encode_data()
 * * `password` - Decryption password
 *
 * # Returns
 *
 * Original plaintext data
 */
export function decode_data(encoded: Uint8Array, password: string): WasmResult;

/**
 * Decrypt data with AES-256-GCM
 *
 * # Arguments
 *
 * * `ciphertext` - Encrypted data (with tag appended)
 * * `key` - 32-byte encryption key
 * * `nonce` - 12-byte nonce used during encryption
 * * `aad` - Optional AAD (must match encryption)
 *
 * # Returns
 *
 * WasmResult containing plaintext
 */
export function decrypt(ciphertext: Uint8Array, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): WasmResult;

/**
 * Decrypt with forward secrecy using X25519
 *
 * # Arguments
 * * `encrypted` - ephemeral_public (32) || nonce (12) || ciphertext
 * * `my_secret` - Recipient's 32-byte X25519 secret key
 * * `password` - Password used during encryption
 */
export function decrypt_with_forward_secrecy(encrypted: Uint8Array, my_secret: Uint8Array, password: string): WasmResult;

/**
 * Derive encryption key from password using Argon2id
 *
 * # Arguments
 *
 * * `password` - User password (UTF-8 bytes)
 * * `salt` - 16-byte random salt
 * * `memory_kib` - Memory cost in KiB (default: 65536 = 64 MiB for browser)
 * * `iterations` - Time cost (default: 3 for browser)
 *
 * # Returns
 *
 * WasmResult containing 32-byte key
 *
 * # Note
 *
 * Browser environments should use lower memory settings than native.
 * Default browser settings: 64 MiB, 3 iterations (~1 second)
 */
export function derive_key(password: Uint8Array, salt: Uint8Array, memory_kib?: number | null, iterations?: number | null): WasmResult;

/**
 * Encode data for transfer (compress + encrypt + add metadata)
 *
 * This is the high-level API matching the Python encode workflow.
 *
 * # Arguments
 *
 * * `data` - Raw file data
 * * `password` - Encryption password
 * * `block_size` - Fountain code block size (default: 512)
 *
 * # Returns
 *
 * JSON-encoded manifest + encrypted blocks
 */
export function encode_data(data: Uint8Array, password: string, block_size?: number | null): WasmResult;

/**
 * Encrypt data with AES-256-GCM
 *
 * # Arguments
 *
 * * `plaintext` - Data to encrypt
 * * `key` - 32-byte encryption key
 * * `nonce` - 12-byte unique nonce
 * * `aad` - Optional additional authenticated data
 *
 * # Returns
 *
 * WasmResult containing ciphertext || tag
 */
export function encrypt(plaintext: Uint8Array, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array | null): WasmResult;

/**
 * Encrypt with forward secrecy using X25519 ephemeral key exchange
 *
 * # Arguments
 * * `plaintext` - Data to encrypt
 * * `recipient_public` - Recipient's 32-byte X25519 public key
 * * `password` - Password for additional key derivation
 *
 * # Returns
 * ephemeral_public (32) || nonce (12) || ciphertext
 */
export function encrypt_with_forward_secrecy(plaintext: Uint8Array, recipient_public: Uint8Array, password: string): WasmResult;

/**
 * Generate random 12-byte nonce
 */
export function generate_nonce(): WasmResult;

/**
 * Generate random 16-byte salt
 */
export function generate_salt(): WasmResult;

/**
 * Compute SHA-256 hash
 */
export function hash_sha256(data: Uint8Array): Uint8Array;

/**
 * Derive key material using HKDF-SHA256
 */
export function hkdf(input_key_material: Uint8Array, salt: Uint8Array | null | undefined, info: Uint8Array, length: number): WasmResult;

/**
 * Compute HMAC-SHA256
 */
export function hmac(key: Uint8Array, data: Uint8Array): Uint8Array;

/**
 * Initialize the WASM module (call once on page load)
 */
export function init(): void;

/**
 * Check if post-quantum features are available
 */
export function pq_available(): boolean;

/**
 * Generate cryptographically secure random bytes
 *
 * Uses getrandom which sources from browser's crypto.getRandomValues()
 */
export function random(length: number): WasmResult;

/**
 * Securely clear a byte array by overwriting with zeros
 *
 * WASM memory is not automatically zeroed, so call this for sensitive data.
 */
export function secure_clear(data: Uint8Array): void;

/**
 * Verify HMAC-SHA256 in constant time
 */
export function verify_hmac(key: Uint8Array, data: Uint8Array, expected_mac: Uint8Array): boolean;

/**
 * Get library version
 */
export function version(): string;

/**
 * Perform X25519 Diffie-Hellman key exchange
 *
 * # Arguments
 * * `my_secret` - 32-byte secret key
 * * `their_public` - 32-byte public key
 *
 * # Returns
 * 32-byte shared secret
 */
export function x25519_diffie_hellman(my_secret: Uint8Array, their_public: Uint8Array): WasmResult;

/**
 * Generate X25519 key pair and return as WasmResult with secret||public (64 bytes)
 */
export function x25519_generate_keypair(): WasmResult;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmresult_free: (a: number, b: number) => void;
    readonly __wbg_wasmx25519keypair_free: (a: number, b: number) => void;
    readonly constant_time_compare: (a: number, b: number, c: number, d: number) => number;
    readonly decode_data: (a: number, b: number, c: number, d: number) => number;
    readonly decrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly decrypt_with_forward_secrecy: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly derive_key: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly encode_data: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly encrypt_with_forward_secrecy: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly generate_nonce: () => number;
    readonly generate_salt: () => number;
    readonly hash_sha256: (a: number, b: number) => any;
    readonly hkdf: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
    readonly hmac: (a: number, b: number, c: number, d: number) => any;
    readonly init: () => void;
    readonly pq_available: () => number;
    readonly random: (a: number) => number;
    readonly secure_clear: (a: number, b: number, c: any) => void;
    readonly verify_hmac: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly version: () => [number, number];
    readonly wasmresult_data: (a: number) => any;
    readonly wasmresult_error: (a: number) => [number, number];
    readonly wasmresult_success: (a: number) => number;
    readonly wasmx25519keypair_new: () => [number, number, number];
    readonly wasmx25519keypair_public_key: (a: number) => any;
    readonly x25519_diffie_hellman: (a: number, b: number, c: number, d: number) => number;
    readonly x25519_generate_keypair: () => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
