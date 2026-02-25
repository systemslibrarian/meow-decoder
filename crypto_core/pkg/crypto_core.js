/* @ts-self-types="./crypto_core.d.ts" */

//#region exports

/**
 * WASM result type for JavaScript interop
 */
export class WasmResult {
    constructor() {
        throw new Error('cannot invoke `new` directly');
    }
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmResult.prototype);
        obj.__wbg_ptr = ptr;
        WasmResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmresult_free(ptr, 0);
    }
    /**
     * Get result data as Uint8Array
     * @returns {Uint8Array}
     */
    get data() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.wasmresult_data(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get error message if failed
     * @returns {string | undefined}
     */
    get error() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.wasmresult_error(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Check if operation succeeded
     * @returns {boolean}
     */
    get success() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.wasmresult_success(this.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) WasmResult.prototype[Symbol.dispose] = WasmResult.prototype.free;

/**
 * X25519 key pair for WASM
 */
export class WasmX25519KeyPair {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmX25519KeyPairFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmx25519keypair_free(ptr, 0);
    }
    /**
     * Generate a new X25519 key pair
     */
    constructor() {
        const ret = wasm.wasmx25519keypair_new();
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmX25519KeyPairFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Get public key bytes
     * @returns {Uint8Array}
     */
    get public_key() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.wasmx25519keypair_public_key(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) WasmX25519KeyPair.prototype[Symbol.dispose] = WasmX25519KeyPair.prototype.free;

/**
 * Compare two byte arrays in constant time
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function constant_time_compare(a, b) {
    const ptr0 = passArray8ToWasm0(a, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(b, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.constant_time_compare(ptr0, len0, ptr1, len1);
    return ret !== 0;
}

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
 * @param {Uint8Array} encoded
 * @param {string} password
 * @returns {WasmResult}
 */
export function decode_data(encoded, password) {
    const ptr0 = passArray8ToWasm0(encoded, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.decode_data(ptr0, len0, ptr1, len1);
    return WasmResult.__wrap(ret);
}

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
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array | null} [aad]
 * @returns {WasmResult}
 */
export function decrypt(ciphertext, key, nonce, aad) {
    const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(aad) ? 0 : passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.decrypt(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return WasmResult.__wrap(ret);
}

/**
 * Decrypt with forward secrecy using X25519
 *
 * # Arguments
 * * `encrypted` - ephemeral_public (32) || nonce (12) || ciphertext
 * * `my_secret` - Recipient's 32-byte X25519 secret key
 * * `password` - Password used during encryption
 * @param {Uint8Array} encrypted
 * @param {Uint8Array} my_secret
 * @param {string} password
 * @returns {WasmResult}
 */
export function decrypt_with_forward_secrecy(encrypted, my_secret, password) {
    const ptr0 = passArray8ToWasm0(encrypted, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(my_secret, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.decrypt_with_forward_secrecy(ptr0, len0, ptr1, len1, ptr2, len2);
    return WasmResult.__wrap(ret);
}

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
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number | null} [memory_kib]
 * @param {number | null} [iterations]
 * @returns {WasmResult}
 */
export function derive_key(password, salt, memory_kib, iterations) {
    const ptr0 = passArray8ToWasm0(password, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    if (!isLikeNone(memory_kib)) {
        _assertNum(memory_kib);
    }
    if (!isLikeNone(iterations)) {
        _assertNum(iterations);
    }
    const ret = wasm.derive_key(ptr0, len0, ptr1, len1, isLikeNone(memory_kib) ? 0x100000001 : (memory_kib) >>> 0, isLikeNone(iterations) ? 0x100000001 : (iterations) >>> 0);
    return WasmResult.__wrap(ret);
}

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
 * @param {Uint8Array} data
 * @param {string} password
 * @param {number | null} [block_size]
 * @returns {WasmResult}
 */
export function encode_data(data, password, block_size) {
    const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    if (!isLikeNone(block_size)) {
        _assertNum(block_size);
    }
    const ret = wasm.encode_data(ptr0, len0, ptr1, len1, isLikeNone(block_size) ? 0x100000001 : (block_size) >>> 0);
    return WasmResult.__wrap(ret);
}

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
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array | null} [aad]
 * @returns {WasmResult}
 */
export function encrypt(plaintext, key, nonce, aad) {
    const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(aad) ? 0 : passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.encrypt(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return WasmResult.__wrap(ret);
}

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
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} recipient_public
 * @param {string} password
 * @returns {WasmResult}
 */
export function encrypt_with_forward_secrecy(plaintext, recipient_public, password) {
    const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(recipient_public, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.encrypt_with_forward_secrecy(ptr0, len0, ptr1, len1, ptr2, len2);
    return WasmResult.__wrap(ret);
}

/**
 * Generate random 12-byte nonce
 * @returns {WasmResult}
 */
export function generate_nonce() {
    const ret = wasm.generate_nonce();
    return WasmResult.__wrap(ret);
}

/**
 * Generate random 16-byte salt
 * @returns {WasmResult}
 */
export function generate_salt() {
    const ret = wasm.generate_salt();
    return WasmResult.__wrap(ret);
}

/**
 * Compute SHA-256 hash
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function hash_sha256(data) {
    const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.hash_sha256(ptr0, len0);
    return ret;
}

/**
 * Derive key material using HKDF-SHA256
 * @param {Uint8Array} input_key_material
 * @param {Uint8Array | null | undefined} salt
 * @param {Uint8Array} info
 * @param {number} length
 * @returns {WasmResult}
 */
export function hkdf(input_key_material, salt, info, length) {
    const ptr0 = passArray8ToWasm0(input_key_material, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(salt) ? 0 : passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
    var len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(info, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    _assertNum(length);
    const ret = wasm.hkdf(ptr0, len0, ptr1, len1, ptr2, len2, length);
    return WasmResult.__wrap(ret);
}

/**
 * Compute HMAC-SHA256
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function hmac(key, data) {
    const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.hmac(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Initialize the WASM module (call once on page load)
 */
export function init() {
    wasm.init();
}

/**
 * Check if post-quantum features are available
 * @returns {boolean}
 */
export function pq_available() {
    const ret = wasm.pq_available();
    return ret !== 0;
}

/**
 * Generate cryptographically secure random bytes
 *
 * Uses getrandom which sources from browser's crypto.getRandomValues()
 * @param {number} length
 * @returns {WasmResult}
 */
export function random(length) {
    _assertNum(length);
    const ret = wasm.random(length);
    return WasmResult.__wrap(ret);
}

/**
 * Securely clear a byte array by overwriting with zeros
 *
 * WASM memory is not automatically zeroed, so call this for sensitive data.
 * @param {Uint8Array} data
 */
export function secure_clear(data) {
    var ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.secure_clear(ptr0, len0, data);
}

/**
 * Verify HMAC-SHA256 in constant time
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @param {Uint8Array} expected_mac
 * @returns {boolean}
 */
export function verify_hmac(key, data, expected_mac) {
    const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(expected_mac, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verify_hmac(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Get library version
 * @returns {string}
 */
export function version() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.version();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Perform X25519 Diffie-Hellman key exchange
 *
 * # Arguments
 * * `my_secret` - 32-byte secret key
 * * `their_public` - 32-byte public key
 *
 * # Returns
 * 32-byte shared secret
 * @param {Uint8Array} my_secret
 * @param {Uint8Array} their_public
 * @returns {WasmResult}
 */
export function x25519_diffie_hellman(my_secret, their_public) {
    const ptr0 = passArray8ToWasm0(my_secret, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(their_public, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.x25519_diffie_hellman(ptr0, len0, ptr1, len1);
    return WasmResult.__wrap(ret);
}

/**
 * Generate X25519 key pair and return as WasmResult with secret||public (64 bytes)
 * @returns {WasmResult}
 */
export function x25519_generate_keypair() {
    const ret = wasm.x25519_generate_keypair();
    return WasmResult.__wrap(ret);
}

//#endregion

//#region wasm imports

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_copy_to_typed_array_281f659934f5228b: function(arg0, arg1, arg2) {
            new Uint8Array(arg2.buffer, arg2.byteOffset, arg2.byteLength).set(getArrayU8FromWasm0(arg0, arg1));
        },
        __wbg___wbindgen_is_function_18bea6e84080c016: function(arg0) {
            const ret = typeof(arg0) === 'function';
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_object_8d3fac158b36498d: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_string_4d5f2c5b2acf65b0: function(arg0) {
            const ret = typeof(arg0) === 'string';
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_undefined_4a711ea9d2e1ef93: function(arg0) {
            const ret = arg0 === undefined;
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_throw_df03e93053e0f4bc: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_85e5437fa1ab109d: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function() { return logError(function (arg0) {
            const ret = arg0.crypto;
            return ret;
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_length_5e07cf181b2745fb: function() { return logError(function (arg0) {
            const ret = arg0.length;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_msCrypto_bd5a034af96bcba6: function() { return logError(function (arg0) {
            const ret = arg0.msCrypto;
            return ret;
        }, arguments); },
        __wbg_new_from_slice_e98c2bb0a59c32a0: function() { return logError(function (arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_new_with_length_9b57e4a9683723fa: function() { return logError(function (arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function() { return logError(function (arg0) {
            const ret = arg0.node;
            return ret;
        }, arguments); },
        __wbg_process_44c7a14e11e9f69e: function() { return logError(function (arg0) {
            const ret = arg0.process;
            return ret;
        }, arguments); },
        __wbg_prototypesetcall_d1a7133bc8d83aa9: function() { return logError(function (arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        }, arguments); },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_THIS_6614f2f4998e3c4c: function() { return logError(function () {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_GLOBAL_d8e8a2fefe80bc1d: function() { return logError(function () {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_SELF_e29eaf7c465526b1: function() { return logError(function () {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_WINDOW_66e7ca3eef30585a: function() { return logError(function () {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_subarray_f36da54ffa7114f5: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        }, arguments); },
        __wbg_versions_276b2795b1c6a219: function() { return logError(function (arg0) {
            const ret = arg0.versions;
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000001: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000002: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        }, arguments); },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./crypto_core_bg.js": import0,
    };
}


//#endregion
const WasmResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmresult_free(ptr >>> 0, 1));
const WasmX25519KeyPairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmx25519keypair_free(ptr >>> 0, 1));


//#region intrinsics
function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertBoolean(n) {
    if (typeof(n) !== 'boolean') {
        throw new Error(`expected a boolean argument, found ${typeof(n)}`);
    }
}

function _assertNum(n) {
    if (typeof(n) !== 'number') throw new Error(`expected a number argument, found ${typeof(n)}`);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function logError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        let error = (function () {
            try {
                return e instanceof Error ? `${e.message}\n\nStack:\n${e.stack}` : e.toString();
            } catch(_) {
                return "<failed to stringify thrown value>";
            }
        }());
        console.error("wasm-bindgen: imported JS function that was not marked as `catch` threw an error:", error);
        throw e;
    }
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (typeof(arg) !== 'string') throw new Error(`expected a string argument, found ${typeof(arg)}`);
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);
        if (ret.read !== arg.length) throw new Error('failed to pass whole string');
        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;


//#endregion

//#region wasm loading
let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('crypto_core_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
//#endregion
export { wasm as __wasm }
