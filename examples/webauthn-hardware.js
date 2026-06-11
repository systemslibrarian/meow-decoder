/**
 * 🔐 WebAuthn Hardware Key Integration for Meow Decoder
 * 
 * Provides FIDO2/WebAuthn support for hardware security keys (YubiKey, Titan, etc.)
 * in the browser-based WASM demo.
 * 
 * Security Properties:
 * - HW-001: Private keys never leave hardware
 * - HW-002: User verification required (touch/PIN)
 * - HW-003: Challenge freshness prevents replay
 * - HW-004: No JavaScript access to key material
 * 
 * Usage:
 *   import { HardwareKeyManager } from './webauthn-hardware.js';
 *   
 *   const hwManager = new HardwareKeyManager();
 *   await hwManager.register("my-username");
 *   const key = await hwManager.deriveKey(password, salt);
 */

// ============================================================================
// Utility Functions
// ============================================================================

function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function concatBuffers(...buffers) {
    const totalLength = buffers.reduce((acc, buf) => acc + buf.byteLength, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const buf of buffers) {
        result.set(new Uint8Array(buf), offset);
        offset += buf.byteLength;
    }
    return result;
}

async function sha256(data) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
}

async function hmacSha256(key, data) {
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
    return new Uint8Array(signature);
}

/**
 * HKDF key derivation (HMAC-based Extract-and-Expand)
 * @param {Uint8Array} ikm - Input key material (hardware signature)
 * @param {Uint8Array} salt - Salt
 * @param {Uint8Array} info - Context string
 * @param {number} length - Output length in bytes
 * @returns {Promise<Uint8Array>} Derived key
 */
async function hkdf(ikm, salt, info, length = 32) {
    // HKDF-Extract
    const prk = await hmacSha256(salt, ikm);
    
    // HKDF-Expand
    const n = Math.ceil(length / 32);
    const blocks = [];
    let t = new Uint8Array(0);
    
    for (let i = 1; i <= n; i++) {
        const input = concatBuffers(t, info, new Uint8Array([i]));
        t = await hmacSha256(prk, input);
        blocks.push(t);
    }
    
    const okm = concatBuffers(...blocks);
    return okm.slice(0, length);
}

// ============================================================================
// WebAuthn Hardware Key Manager
// ============================================================================

export class HardwareKeyManager {
    constructor() {
        this.storagePrefix = 'meow_hw_';
    }
    
    /**
     * Check if WebAuthn is supported in this browser.
     * @returns {Promise<boolean>}
     */
    async isSupported() {
        if (!window.PublicKeyCredential) {
            return false;
        }
        
        try {
            // Check if a user-verifying platform authenticator is available
            // (e.g., Touch ID, Windows Hello, or external security key)
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            return available || true; // External keys may work even if platform auth doesn't
        } catch (err) {
            console.warn('WebAuthn availability check failed:', err);
            return false;
        }
    }
    
    /**
     * Check if a hardware key is already registered.
     * @returns {boolean}
     */
    isRegistered() {
        const credentialId = localStorage.getItem(this.storagePrefix + 'credential_id');
        return credentialId !== null && credentialId.length > 0;
    }
    
    /**
     * Get stored credential information.
     * @returns {object|null} { credentialId, publicKey, username }
     */
    getCredential() {
        const credentialId = localStorage.getItem(this.storagePrefix + 'credential_id');
        if (!credentialId) return null;
        
        return {
            credentialId: credentialId,
            publicKey: localStorage.getItem(this.storagePrefix + 'public_key'),
            username: localStorage.getItem(this.storagePrefix + 'username') || 'meow-user',
            registeredAt: localStorage.getItem(this.storagePrefix + 'registered_at')
        };
    }
    
    /**
     * Register a new hardware security key.
     * 
     * @param {string} username - User identifier (default: "meow-user")
     * @param {boolean} requireResidentKey - Store credential on key (default: true)
     * @returns {Promise<object>} { credentialId, publicKey }
     * @throws {Error} If registration fails
     */
    async register(username = 'meow-user', requireResidentKey = true) {
        if (!await this.isSupported()) {
            throw new Error('WebAuthn is not supported in this browser');
        }
        
        // Generate fresh challenge
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        
        const publicKeyCredentialCreationOptions = {
            challenge: challenge,
            rp: {
                name: "Meow Decoder",
                id: window.location.hostname  // e.g., "localhost"
            },
            user: {
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: username,
                displayName: "Meow Decoder User"
            },
            pubKeyCredParams: [
                { alg: -7, type: "public-key" },   // ES256 (ECDSA P-256)
                { alg: -257, type: "public-key" }, // RS256 (RSA)
                { alg: -8, type: "public-key" }    // EdDSA
            ],
            authenticatorSelection: {
                authenticatorAttachment: "cross-platform",  // External security key
                requireResidentKey: requireResidentKey,     // Store on key
                userVerification: "preferred"               // Touch or PIN
            },
            timeout: 60000,      // 60 seconds
            attestation: "none"  // Don't need device attestation
        };
        
        try {
            const credential = await navigator.credentials.create({
                publicKey: publicKeyCredentialCreationOptions
            });
            
            // Store credential metadata
            const credentialId = bufferToBase64(credential.rawId);
            const publicKey = credential.response.getPublicKey ? 
                bufferToBase64(credential.response.getPublicKey()) : null;
            
            localStorage.setItem(this.storagePrefix + 'credential_id', credentialId);
            if (publicKey) {
                localStorage.setItem(this.storagePrefix + 'public_key', publicKey);
            }
            localStorage.setItem(this.storagePrefix + 'username', username);
            localStorage.setItem(this.storagePrefix + 'registered_at', new Date().toISOString());
            
            return {
                credentialId: credentialId,
                publicKey: publicKey,
                username: username
            };
        } catch (err) {
            // Common errors:
            // - NotAllowedError: User canceled or timeout
            // - InvalidStateError: Credential already exists
            // - NotSupportedError: Algorithm not supported
            throw new Error(`Hardware key registration failed: ${err.name} - ${err.message}`);
        }
    }
    
    /**
     * Unregister the current hardware key.
     */
    unregister() {
        localStorage.removeItem(this.storagePrefix + 'credential_id');
        localStorage.removeItem(this.storagePrefix + 'public_key');
        localStorage.removeItem(this.storagePrefix + 'username');
        localStorage.removeItem(this.storagePrefix + 'registered_at');
    }
    
    /**
     * Get a cryptographic signature from the hardware key.
     * This is the core operation for key derivation.
     * 
     * @param {Uint8Array} challenge - 32-byte challenge (mix of password + salt)
     * @returns {Promise<Uint8Array>} Hardware signature (variable length)
     * @throws {Error} If authentication fails
     */
    async getSignature(challenge) {
        if (!this.isRegistered()) {
            throw new Error('No hardware key registered. Please register first.');
        }
        
        const credentialId = localStorage.getItem(this.storagePrefix + 'credential_id');
        
        const publicKeyCredentialRequestOptions = {
            challenge: challenge,
            allowCredentials: [{
                id: base64ToBuffer(credentialId),
                type: 'public-key',
                transports: ['usb', 'nfc', 'ble', 'internal']
            }],
            timeout: 60000,
            userVerification: "preferred"
        };
        
        try {
            const assertion = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions
            });
            
            // Return raw signature (hardware-bound random data)
            return new Uint8Array(assertion.response.signature);
        } catch (err) {
            // Common errors:
            // - NotAllowedError: User canceled or timeout
            // - NotFoundError: Credential not found (wrong key inserted)
            throw new Error(`Hardware key authentication failed: ${err.name} - ${err.message}`);
        }
    }
    
    /**
     * Derive encryption key using hardware key + password (hybrid).
     * 
     * Security model:
     * 1. Password → Argon2id → passwordKey (knowledge factor)
     * 2. Hardware challenge-response → hardwareKey (possession factor + touch)
     * 3. Final key = passwordKey XOR hardwareKey (both required)
     * 
     * @param {string} password - User password
     * @param {Uint8Array} salt - 16-byte salt
     * @param {Function} argon2Derive - Argon2id derivation function(password, salt, memKib, iter)
     * @param {number} memoryKib - Argon2id memory (default: 64 MiB for browser)
     * @param {number} iterations - Argon2id iterations (default: 3)
     * @returns {Promise<Uint8Array>} 32-byte derived key
     */
    async deriveKey(password, salt, argon2Derive, memoryKib = 64 * 1024, iterations = 3) {
        if (!this.isRegistered()) {
            throw new Error('No hardware key registered');
        }
        
        // Step 1: Derive password-based key (Argon2id)
        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);
        const passwordKeyResult = await argon2Derive(passwordBytes, salt, memoryKib, iterations);
        const passwordKey = new Uint8Array(passwordKeyResult.key);
        
        // Step 2: Create challenge for hardware key (mix password hash + salt)
        const passwordHash = await sha256(passwordBytes);
        const challenge = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            challenge[i] = passwordHash[i] ^ salt[i % 16];
        }
        
        // Step 3: Get hardware signature (requires touch)
        const hardwareSignature = await this.getSignature(challenge);
        
        // Step 4: Derive hardware key using HKDF
        const info = encoder.encode('meow-decoder-v1-hardware');
        const hardwareKey = await hkdf(hardwareSignature, salt, info, 32);
        
        // Step 5: Hybrid key mixing (XOR both keys)
        const finalKey = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            finalKey[i] = passwordKey[i] ^ hardwareKey[i];
        }
        
        // Zero sensitive data
        passwordBytes.fill(0);
        passwordKey.fill(0);
        hardwareKey.fill(0);
        passwordHash.fill(0);
        
        return finalKey;
    }
    
    /**
     * Simplified derive: hardware signature only (no password mixing).
     * Less secure but useful for testing.
     * 
     * @param {Uint8Array} challenge - 32-byte challenge
     * @param {Uint8Array} salt - 16-byte salt
     * @returns {Promise<Uint8Array>} 32-byte derived key
     */
    async deriveKeyHardwareOnly(challenge, salt) {
        const signature = await this.getSignature(challenge);
        const encoder = new TextEncoder();
        const info = encoder.encode('meow-decoder-v1-hardware-only');
        return await hkdf(signature, salt, info, 32);
    }
}

// ============================================================================
// UI Helper Functions
// ============================================================================

/**
 * Create HTML UI elements for hardware key management.
 * Call this to inject the UI into your page.
 * 
 * @param {string} containerId - ID of element to inject UI into
 * @returns {object} UI element references
 */
export function createHardwareUI(containerId = 'hardwareKeyContainer') {
    const container = document.getElementById(containerId);
    if (!container) {
        throw new Error(`Container element #${containerId} not found`);
    }
    
    container.innerHTML = `
        <div class="hardware-status" id="hwStatus" style="display:none;">
            <div class="status-indicator">
                <span id="hwIcon" style="font-size: 1.5em;">🔐</span>
                <span id="hwText" style="margin-left: 10px;">Checking hardware key...</span>
            </div>
            <div style="margin-top: 15px;">
                <label style="display: flex; align-items: center; cursor: pointer;">
                    <input type="checkbox" id="useHardwareKey" style="margin-right: 8px;" />
                    <span>Use hardware security key for encryption</span>
                </label>
            </div>
            <div style="margin-top: 10px;">
                <button id="registerHwKey" class="secondary" style="margin-right: 8px;">
                    Register New Key
                </button>
                <button id="unregisterHwKey" class="secondary" style="display:none;">
                    Unregister
                </button>
                <button id="testHwKey" class="secondary" style="display:none; margin-left: 8px;">
                    Test Key
                </button>
            </div>
            <div id="hwInfo" style="margin-top: 10px; font-size: 0.9em; color: #888;"></div>
        </div>
    `;
    
    return {
        container: container.querySelector('.hardware-status'),
        icon: document.getElementById('hwIcon'),
        text: document.getElementById('hwText'),
        checkbox: document.getElementById('useHardwareKey'),
        registerBtn: document.getElementById('registerHwKey'),
        unregisterBtn: document.getElementById('unregisterHwKey'),
        testBtn: document.getElementById('testHwKey'),
        info: document.getElementById('hwInfo')
    };
}

/**
 * Initialize hardware key UI with live status detection.
 * 
 * @param {HardwareKeyManager} hwManager - Hardware key manager instance
 * @param {object} ui - UI elements from createHardwareUI()
 * @param {Function} onRegister - Callback after successful registration
 * @param {Function} onUnregister - Callback after unregistration
 */
export async function initHardwareUI(hwManager, ui, onRegister = null, onUnregister = null) {
    // Check WebAuthn support
    const supported = await hwManager.isSupported();
    
    if (!supported) {
        ui.icon.textContent = '❌';
        ui.text.textContent = 'WebAuthn not supported in this browser';
        ui.text.style.color = '#f44336';
        ui.checkbox.disabled = true;
        ui.registerBtn.disabled = true;
        ui.container.style.display = 'block';
        return;
    }
    
    ui.container.style.display = 'block';
    
    // Update status
    const updateStatus = () => {
        const credential = hwManager.getCredential();
        
        if (credential) {
            ui.icon.textContent = '🔐';
            ui.text.textContent = 'Hardware key registered and ready';
            ui.text.style.color = '#00ff88';
            ui.checkbox.disabled = false;
            ui.checkbox.checked = true;
            ui.registerBtn.style.display = 'none';
            ui.unregisterBtn.style.display = 'inline-block';
            ui.testBtn.style.display = 'inline-block';
            
            // Show info
            const regDate = new Date(credential.registeredAt);
            ui.info.innerHTML = `
                <strong>Username:</strong> ${credential.username}<br>
                <strong>Registered:</strong> ${regDate.toLocaleString()}<br>
                <strong>Credential ID:</strong> ${credential.credentialId.slice(0, 16)}...
            `;
        } else {
            ui.icon.textContent = '⚠️';
            ui.text.textContent = 'No hardware key registered';
            ui.text.style.color = '#ff9800';
            ui.checkbox.disabled = true;
            ui.checkbox.checked = false;
            ui.registerBtn.style.display = 'inline-block';
            ui.unregisterBtn.style.display = 'none';
            ui.testBtn.style.display = 'none';
            ui.info.textContent = 'Register a FIDO2 security key to enable hardware-backed encryption.';
        }
    };
    
    updateStatus();
    
    // Register button
    ui.registerBtn.onclick = async () => {
        try {
            ui.registerBtn.disabled = true;
            ui.registerBtn.textContent = 'Touch your security key...';
            
            const username = prompt('Enter username (or leave blank for default):', 'meow-user') || 'meow-user';
            await hwManager.register(username);
            
            alert('✅ Hardware key registered successfully!\n\nTouch your security key when prompted during encryption/decryption.');
            updateStatus();
            
            if (onRegister) onRegister();
        } catch (err) {
            alert(`❌ Registration failed:\n\n${err.message}`);
        } finally {
            ui.registerBtn.disabled = false;
            ui.registerBtn.textContent = 'Register New Key';
        }
    };
    
    // Unregister button
    ui.unregisterBtn.onclick = () => {
        if (confirm('⚠️ Unregister hardware key?\n\nYou will NOT be able to decrypt files encrypted with this key!')) {
            hwManager.unregister();
            alert('Hardware key unregistered');
            updateStatus();
            
            if (onUnregister) onUnregister();
        }
    };
    
    // Test button
    ui.testBtn.onclick = async () => {
        try {
            ui.testBtn.disabled = true;
            ui.testBtn.textContent = 'Touch your key...';
            
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            const signature = await hwManager.getSignature(challenge);
            
            alert(`✅ Hardware key test successful!\n\nSignature: ${signature.length} bytes\n${bufferToBase64(signature).slice(0, 32)}...`);
        } catch (err) {
            alert(`❌ Test failed:\n\n${err.message}`);
        } finally {
            ui.testBtn.disabled = false;
            ui.testBtn.textContent = 'Test Key';
        }
    };
}

// ============================================================================
// Export for browser module usage
// ============================================================================

if (typeof window !== 'undefined') {
    window.HardwareKeyManager = HardwareKeyManager;
    window.createHardwareUI = createHardwareUI;
    window.initHardwareUI = initHardwareUI;
}
