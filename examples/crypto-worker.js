/**
 * Meow Decoder - Web Worker for Crypto Operations
 * 
 * This worker handles CPU-intensive cryptographic operations off the main thread,
 * keeping the UI responsive during key derivation and encryption/decryption.
 * 
 * Usage from main thread:
 *   const worker = new Worker('crypto-worker.js', { type: 'module' });
 *   worker.postMessage({ type: 'derive_key', id: 1, payload: { password, salt } });
 *   worker.onmessage = (e) => { console.log(e.data); };
 */

let wasm = null;
let wasmReady = false;

// Initialize WASM module inside the worker
async function initWasm() {
    try {
        // Import the WASM module - path relative to worker location (examples/)
        const wasmModule = await import('../crypto_core/pkg/crypto_core.js');
        await wasmModule.default();
        wasm = wasmModule;
        wasmReady = true;
        
        postMessage({ type: 'ready', success: true });
    } catch (err) {
        postMessage({ 
            type: 'ready', 
            success: false, 
            error: `Failed to load WASM in worker: ${err.message}` 
        });
    }
}

// Handle incoming messages from main thread
self.onmessage = async function(e) {
    const { type, id, payload } = e.data;
    
    // Wait for WASM if not ready yet
    if (!wasmReady && type !== 'ping') {
        postMessage({ 
            type: 'error', 
            id, 
            error: 'WASM not initialized yet' 
        });
        return;
    }
    
    try {
        switch (type) {
            case 'ping':
                // Health check
                postMessage({ type: 'pong', id, ready: wasmReady });
                break;
                
            case 'derive_key': {
                // Key derivation with Argon2id
                // payload: { password: Uint8Array, salt: Uint8Array, memory_kib?: number, iterations?: number }
                const result = wasm.derive_key(
                    payload.password,
                    payload.salt,
                    payload.memory_kib || null,
                    payload.iterations || null
                );
                
                if (result.success) {
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: true, 
                        data: result.data 
                    });
                } else {
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: false, 
                        error: result.error 
                    });
                }
                break;
            }
            
            case 'encrypt': {
                // AES-256-GCM encryption
                // payload: { plaintext: Uint8Array, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array }
                const result = wasm.encrypt(
                    payload.plaintext,
                    payload.key,
                    payload.nonce,
                    payload.aad || null
                );
                
                if (result.success) {
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: true, 
                        data: result.data 
                    });
                } else {
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: false, 
                        error: result.error 
                    });
                }
                break;
            }
            
            case 'decrypt': {
                // AES-256-GCM decryption
                // payload: { ciphertext: Uint8Array, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array }
                const result = wasm.decrypt(
                    payload.ciphertext,
                    payload.key,
                    payload.nonce,
                    payload.aad || null
                );
                
                if (result.success) {
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: true, 
                        data: result.data 
                    });
                } else {
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: false, 
                        error: result.error 
                    });
                }
                break;
            }
            
            case 'generate_salt': {
                const result = wasm.generate_salt();
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: result.success, 
                    data: result.data,
                    error: result.error 
                });
                break;
            }
            
            case 'generate_nonce': {
                const result = wasm.generate_nonce();
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: result.success, 
                    data: result.data,
                    error: result.error 
                });
                break;
            }
            
            case 'x25519_generate_keypair': {
                // Generate X25519 key pair for forward secrecy
                const result = wasm.x25519_generate_keypair();
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: result.success, 
                    data: result.data,
                    error: result.error 
                });
                break;
            }
            
            case 'x25519_diffie_hellman': {
                // X25519 Diffie-Hellman key exchange
                // payload: { my_secret: Uint8Array, their_public: Uint8Array }
                const result = wasm.x25519_diffie_hellman(
                    payload.my_secret,
                    payload.their_public
                );
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: result.success, 
                    data: result.data,
                    error: result.error 
                });
                break;
            }
            
            case 'encrypt_with_forward_secrecy': {
                // Encrypt with X25519 forward secrecy
                // payload: { plaintext: Uint8Array, recipient_public: Uint8Array, password: string }
                const result = wasm.encrypt_with_forward_secrecy(
                    payload.plaintext,
                    payload.recipient_public,
                    payload.password
                );
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: result.success, 
                    data: result.data,
                    error: result.error 
                });
                break;
            }
            
            case 'decrypt_with_forward_secrecy': {
                // Decrypt with X25519 forward secrecy
                // payload: { encrypted: Uint8Array, my_secret: Uint8Array, password: string }
                const result = wasm.decrypt_with_forward_secrecy(
                    payload.encrypted,
                    payload.my_secret,
                    payload.password
                );
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: result.success, 
                    data: result.data,
                    error: result.error 
                });
                break;
            }
            
            // ================================================================
            // Post-Quantum (ML-KEM-1024) Operations
            // ================================================================
            
            case 'pq_available': {
                // Check if post-quantum crypto is available
                const available = wasm.pq_available ? wasm.pq_available() : false;
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: true, 
                    data: available
                });
                break;
            }
            
            case 'mlkem_generate_keypair': {
                // Generate ML-KEM-1024 key pair
                // Returns: { secretKey: Uint8Array(3168), publicKey: Uint8Array(1568) }
                const result = wasm.mlkem_generate_keypair();
                if (result.success) {
                    // Keys are packed: secret_key (3168) || public_key (1568)
                    const secretKey = result.data.slice(0, 3168);
                    const publicKey = result.data.slice(3168);
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: true, 
                        secretKey: secretKey,
                        publicKey: publicKey
                    });
                } else {
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: false, 
                        error: result.error 
                    });
                }
                break;
            }
            
            case 'mlkem_key_sizes': {
                // Get ML-KEM key sizes as array of 4 uint32 values
                const result = wasm.mlkem_key_sizes();
                if (result.success) {
                    const view = new DataView(result.data.buffer, result.data.byteOffset, 16);
                    postMessage({ 
                        type: 'result', 
                        id, 
                        success: true, 
                        sizes: {
                            secretKey: view.getUint32(0, true),
                            publicKey: view.getUint32(4, true),
                            ciphertext: view.getUint32(8, true),
                            sharedSecret: view.getUint32(12, true)
                        }
                    });
                } else {
                    postMessage({ type: 'result', id, success: false, error: result.error });
                }
                break;
            }
            
            case 'encrypt_hybrid_pq': {
                // Hybrid X25519 + ML-KEM + AES-256-GCM encryption
                // payload: { plaintext, x25519_public, mlkem_public, password }
                const result = wasm.encrypt_hybrid_pq(
                    payload.plaintext,
                    payload.x25519_public,
                    payload.mlkem_public,
                    payload.password || ''
                );
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: result.success, 
                    data: result.data,
                    error: result.error 
                });
                break;
            }
            
            case 'decrypt_hybrid_pq': {
                // Hybrid X25519 + ML-KEM + AES-256-GCM decryption
                // payload: { encrypted, x25519_secret, mlkem_secret, password }
                const result = wasm.decrypt_hybrid_pq(
                    payload.encrypted,
                    payload.x25519_secret,
                    payload.mlkem_secret,
                    payload.password || ''
                );
                postMessage({ 
                    type: 'result', 
                    id, 
                    success: result.success, 
                    data: result.data,
                    error: result.error 
                });
                break;
            }
            
            default:
                postMessage({ 
                    type: 'error', 
                    id, 
                    error: `Unknown message type: ${type}` 
                });
        }
    } catch (err) {
        postMessage({ 
            type: 'error', 
            id, 
            error: err.message || 'Unknown error in worker' 
        });
    }
};

// Start WASM initialization immediately
initWasm();
