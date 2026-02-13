# 🔐 WebAuthn Integration Plan for WASM Demo

## Overview

This document outlines the implementation strategy for integrating WebAuthn hardware security keys (FIDO2, YubiKey, Titan, etc.) into the Meow Decoder WASM browser demo.

## Problem Statement

**Current:** Browser demo only supports software-based key derivation (Argon2id).

**Goal:** Use hardware security keys to:
1. Generate/store non-exportable encryption keys
2. Perform challenge-response for key derivation
3. Provide hardware-backed plausible deniability (Schrödinger mode)
4. Match CLI feature parity for hardware security

## Security Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ Browser (Untrusted JavaScript)                              │
│  - WebAuthn API calls                                       │
│  - Receives signed challenges (no private key access)       │
└─────────────────────────────────────────────────────────────┘
                    ↓ WebAuthn API
┌─────────────────────────────────────────────────────────────┐
│ Hardware Security Key (Trusted)                             │
│  - Private key never leaves device                          │
│  - Signs challenges with resident key                       │
│  - User presence verification (touch/PIN)                   │
└─────────────────────────────────────────────────────────────┘
```

### Security Properties

| Property | Implementation |
|----------|---------------|
| **HW-001: Key Isolation** | Private keys are non-exportable, generated in hardware |
| **HW-002: User Verification** | Physical touch or PIN required for operations |
| **HW-003: Challenge Freshness** | Nonces prevent replay attacks |
| **HW-004: No JavaScript Access** | Browser never sees private key material |
| **HW-005: Platform Binding** | Optional: bind to specific origin (rpID) |

## WebAuthn API Integration Points

### 1. Registration (Key Generation)

Generate a new credential on the hardware key:

```javascript
/**
 * Register a new hardware key for encryption.
 * Creates a non-exportable ECDSA P-256 key pair in the authenticator.
 */
async function registerHardwareKey(username = "meow-user") {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    
    const publicKeyCredentialCreationOptions = {
        challenge: challenge,
        rp: {
            name: "Meow Decoder",
            id: window.location.hostname  // e.g., "localhost" or "meow-decoder.app"
        },
        user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: username,
            displayName: "Meow Decoder User"
        },
        pubKeyCredParams: [
            { alg: -7, type: "public-key" },  // ES256 (ECDSA P-256)
            { alg: -8, type: "public-key" }   // EdDSA (optional)
        ],
        authenticatorSelection: {
            authenticatorAttachment: "cross-platform",  // External security key
            requireResidentKey: true,   // Store credential on key
            userVerification: "preferred"  // Touch or PIN
        },
        timeout: 60000,
        attestation: "none"  // Don't need device attestation for encryption
    };
    
    const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
    });
    
    // Store credential ID for future authentication
    const credentialId = bufferToBase64(credential.rawId);
    localStorage.setItem('meow_hw_credential_id', credentialId);
    localStorage.setItem('meow_hw_public_key', bufferToBase64(credential.response.getPublicKey()));
    
    return {
        credentialId: credentialId,
        publicKey: credential.response.getPublicKey()
    };
}
```

### 2. Authentication (Challenge-Response for Key Derivation)

Use the hardware key to sign a challenge and derive encryption keys:

```javascript
/**
 * Derive encryption key using hardware key challenge-response.
 * 
 * Flow:
 * 1. Generate challenge from password + salt
 * 2. Hardware key signs challenge (requires touch)
 * 3. Use signature as key derivation input (mixing with Argon2id)
 * 
 * This provides hybrid security: 
 * - Password (knowledge factor)
 * - Hardware key (possession factor)
 * - Touch (presence factor)
 */
async function deriveKeyWithHardware(password, salt) {
    const credentialId = localStorage.getItem('meow_hw_credential_id');
    if (!credentialId) {
        throw new Error("No hardware key registered. Please register first.");
    }
    
    // Mix password and salt into challenge
    const passwordHash = await sha256(new TextEncoder().encode(password));
    const challenge = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        challenge[i] = passwordHash[i] ^ salt[i % 16];
    }
    
    const publicKeyCredentialRequestOptions = {
        challenge: challenge,
        allowCredentials: [{
            id: base64ToBuffer(credentialId),
            type: 'public-key',
            transports: ['usb', 'nfc', 'ble']
        }],
        timeout: 60000,
        userVerification: "preferred"
    };
    
    // This prompts for hardware key touch/PIN
    const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
    });
    
    // Extract signature (hardware-bound random data)
    const signature = new Uint8Array(assertion.response.signature);
    
    // Derive key using HKDF(HMAC-SHA256) with hardware signature
    // Mix the hardware response with password-based Argon2id for defense-in-depth
    const hardwareKey = await deriveKeyFromSignature(signature, salt);
    const passwordKey = await crypto.deriveKey(
        new TextEncoder().encode(password), 
        salt, 
        64 * 1024,  // 64 MiB (faster in browser, still secure with hardware)
        3           // 3 iterations
    );
    
    // XOR both keys together (hybrid strength)
    const finalKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        finalKey[i] = hardwareKey[i] ^ passwordKey[i];
    }
    
    return finalKey;
}

/**
 * Derive 32-byte key from hardware signature using HKDF.
 */
async function deriveKeyFromSignature(signature, salt) {
    const ikm = signature;  // Input Key Material
    const info = new TextEncoder().encode("meow-decoder-v1-hardware");
    
    // HKDF-Extract
    const prk = await hmacSha256(salt, ikm);
    
    // HKDF-Expand to 32 bytes
    const key = await hmacSha256(prk, concatBuffers(info, new Uint8Array([0x01])));
    
    return key.slice(0, 32);
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

async function sha256(data) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
}
```

### 3. Integration with Existing Crypto Pipeline

Modify the encryption flow in `wasm_browser_example.html`:

```javascript
// Current implementation (software-only)
const keyResult = await crypto.deriveKey(passwordBytes, salt, memoryKib, iterations);

// New implementation with hardware option
async function encryptWithOptionalHardware(file, password, useHardware = false) {
    const salt = await crypto.generateSalt();
    const nonce = await crypto.generateNonce();
    
    let key;
    if (useHardware && await isHardwareKeyAvailable()) {
        // Hardware-backed key derivation
        key = await deriveKeyWithHardware(password, salt);
        log("🔐 Using hardware security key for encryption");
    } else {
        // Standard Argon2id derivation
        const params = getSecurityParams();
        const keyResult = await crypto.deriveKey(
            new TextEncoder().encode(password),
            salt,
            params.memoryKib,
            params.iterations
        );
        key = keyResult.key;
        log(`🔑 Using software key derivation (${params.label})`);
    }
    
    // Rest of encryption flow unchanged
    const plaintext = await file.arrayBuffer();
    const ciphertext = await crypto.encrypt(
        new Uint8Array(plaintext),
        key,
        nonce,
        null  // AAD
    );
    
    // Pack with hardware flag in manifest
    const packed = packPayloadWithHardwareFlag(
        salt, nonce, ciphertext, file.name, 
        useHardware  // Store this so decryption knows
    );
    
    return packed;
}
```

### 4. Manifest Extension for Hardware Keys

Extend the MEOW payload format to include hardware key metadata:

```
MEOW5 Format (new):
┌─────────────────────────────────────────────────────────────┐
│ Version: 0x05 (1 byte)                                      │
│ Flags: (1 byte)                                             │
│   Bit 0: Hardware key required (1 = yes)                    │
│   Bit 1: Touch required (1 = yes)                           │
│   Bit 2-7: Reserved                                         │
│ Argon2id Memory: (4 bytes, little-endian)                   │
│ Argon2id Iterations: (1 byte)                               │
│ Reserved: (1 byte)                                          │
│ Filename Length: (1 byte)                                   │
│ Filename: (N bytes, UTF-8)                                  │
│ Credential ID Length: (2 bytes, little-endian, if HW flag) │
│ Credential ID: (M bytes, if HW flag)                        │
│ Salt: (16 bytes)                                            │
│ Nonce: (12 bytes)                                           │
│ Ciphertext: (remainder)                                     │
└─────────────────────────────────────────────────────────────┘
```

JavaScript packing function:

```javascript
function packPayloadWithHardwareFlag(salt, nonce, ciphertext, fileName, useHardware, credentialId = null) {
    const encoder = new TextEncoder();
    const fnBytes = encoder.encode(fileName || '');
    const credBytes = credentialId ? base64ToBuffer(credentialId) : new Uint8Array(0);
    
    const flags = (useHardware ? 0x01 : 0x00) | 0x02;  // Hardware + touch required
    const memoryKib = getSecurityParams().memoryKib;
    const iterations = getSecurityParams().iterations;
    
    const totalLen = 8 + fnBytes.length + 2 + credBytes.length + 16 + 12 + ciphertext.length;
    const packed = new Uint8Array(totalLen);
    const dv = new DataView(packed.buffer);
    
    let offset = 0;
    packed[offset++] = 0x05;  // Version 5
    packed[offset++] = flags;
    dv.setUint32(offset, memoryKib, true); offset += 4;
    packed[offset++] = iterations;
    packed[offset++] = 0x00;  // Reserved
    packed[offset++] = fnBytes.length;
    packed.set(fnBytes, offset); offset += fnBytes.length;
    
    if (useHardware) {
        dv.setUint16(offset, credBytes.length, true); offset += 2;
        packed.set(credBytes, offset); offset += credBytes.length;
    } else {
        dv.setUint16(offset, 0, true); offset += 2;
    }
    
    packed.set(salt, offset); offset += 16;
    packed.set(nonce, offset); offset += 12;
    packed.set(ciphertext, offset);
    
    return packed;
}
```

## UI Integration

### Hardware Key Status Indicator

Add UI elements to show hardware key status:

```html
<!-- Add to wasm_browser_example.html in Step 1 -->
<div class="hardware-status" id="hwStatus" style="display:none;">
    <div class="status ready">
        <span id="hwIcon">🔐</span>
        <span id="hwText">Hardware key detected</span>
    </div>
    <label>
        <input type="checkbox" id="useHardwareKey" />
        Use hardware security key for encryption
    </label>
    <button id="registerHwKey" class="secondary">Register New Hardware Key</button>
</div>

<style>
.hardware-status {
    margin: 15px 0;
    padding: 15px;
    background: rgba(0, 255, 136, 0.1);
    border-radius: 8px;
    border-left: 4px solid #00ff88;
}
.hardware-status label {
    display: flex;
    align-items: center;
    margin: 10px 0;
}
</style>
```

### Detection and Initialization

```javascript
// Check if WebAuthn is available
async function isWebAuthnAvailable() {
    return window.PublicKeyCredential !== undefined &&
           typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
}

// Check if hardware key is registered
async function isHardwareKeyAvailable() {
    if (!await isWebAuthnAvailable()) return false;
    const credentialId = localStorage.getItem('meow_hw_credential_id');
    return credentialId !== null;
}

// Initialize hardware key UI on page load
async function initHardwareKeyUI() {
    if (!await isWebAuthnAvailable()) {
        console.log("⚠️ WebAuthn not available in this browser");
        return;
    }
    
    const hwStatus = document.getElementById('hwStatus');
    const hwText = document.getElementById('hwText');
    const hwIcon = document.getElementById('hwIcon');
    const useHwCheckbox = document.getElementById('useHardwareKey');
    
    hwStatus.style.display = 'block';
    
    if (await isHardwareKeyAvailable()) {
        hwIcon.textContent = '🔐';
        hwText.textContent = 'Hardware key registered and ready';
        useHwCheckbox.checked = true;
    } else {
        hwIcon.textContent = '⚠️';
        hwText.textContent = 'No hardware key registered';
        useHwCheckbox.disabled = true;
    }
    
    // Register button handler
    document.getElementById('registerHwKey').onclick = async () => {
        try {
            await registerHardwareKey();
            alert("✅ Hardware key registered successfully!\n\nTouch your security key when prompted during encryption/decryption.");
            await initHardwareKeyUI();  // Refresh UI
        } catch (err) {
            alert(`❌ Failed to register hardware key:\n${err.message}`);
        }
    };
}

// Call on page load
document.addEventListener('DOMContentLoaded', initHardwareKeyUI);
```

## Testing Strategy

### Manual Testing

1. **Registration Flow**
   - Click "Register New Hardware Key"
   - Touch YubiKey/Titan when prompted
   - Verify credential stored in localStorage

2. **Encryption with Hardware**
   - Enable "Use hardware security key"
   - Encrypt a file
   - Verify touch required
   - Check payload has version 0x05 and HW flag

3. **Decryption with Hardware**
   - Decode QR code with HW-encrypted payload
   - Verify touch required
   - Confirm file decrypts correctly

4. **Error Handling**
   - Try decrypting without hardware key present
   - Try with wrong hardware key
   - Verify graceful error messages

### Browser Compatibility

| Browser | WebAuthn Support | Notes |
|---------|-----------------|-------|
| Chrome 67+ | ✅ Full | Recommended |
| Firefox 60+ | ✅ Full | Recommended |
| Safari 13+ | ✅ Full | iOS requires Safari |
| Edge 18+ | ✅ Full | Chromium-based |
| Opera 54+ | ✅ Full | Chromium-based |
| Mobile Chrome | ✅ With USB OTG | Android only |
| Mobile Safari | ⚠️ Limited | iOS 13.3+, Face ID only |

### Security Testing Checklist

- [ ] Private key never exposed to JavaScript
- [ ] Touch required for each operation (can't be bypassed)
- [ ] Challenge freshness prevents replay
- [ ] Hardware-encrypted files fail gracefully on wrong key
- [ ] Schrödinger mode works with hardware keys (dual credentials)
- [ ] Origin binding prevents phishing (rpID validation)
- [ ] Timeout enforced (60 seconds)
- [ ] Error messages don't leak key state

## Schrödinger Mode with Hardware Keys

For plausible deniability with hardware keys:

```javascript
async function schrodingerEncodeWithHardware(realFile, decoyFile, realPassword, decoyPassword) {
    // Register TWO separate hardware credentials
    const realCred = await registerHardwareKey("meow-real");
    const decoyCred = await registerHardwareKey("meow-decoy");
    
    const salt = await crypto.generateSalt();
    
    // Derive two independent keys from two hardware keys
    const realKey = await deriveKeyWithHardware(realPassword, salt, realCred.credentialId);
    const decoyKey = await deriveKeyWithHardware(decoyPassword, salt, decoyCred.credentialId);
    
    // Encrypt both files
    const realNonce = await crypto.generateNonce();
    const realCiphertext = await crypto.encrypt(await realFile.arrayBuffer(), realKey, realNonce);
    
    const decoyNonce = await crypto.generateNonce();
    const decoyCiphertext = await crypto.encrypt(await decoyFile.arrayBuffer(), decoyKey, decoyNonce);
    
    // Pack with quantum mixer (XOR entropy)
    const quantumPayload = quantumMixDualSecrets(
        { salt, nonce: realNonce, ciphertext: realCiphertext, credentialId: realCred.credentialId },
        { salt, nonce: decoyNonce, ciphertext: decoyCiphertext, credentialId: decoyCred.credentialId }
    );
    
    return quantumPayload;
}
```

**Security Property:** An attacker with one hardware key cannot prove the other exists.

## Implementation Phases

### Phase 1: Basic Hardware Support (1-2 weeks)
- [ ] WebAuthn registration UI
- [ ] Challenge-response key derivation
- [ ] MEOW5 manifest format
- [ ] Basic encrypt/decrypt with hardware
- [ ] Browser compatibility testing

### Phase 2: CLI Interoperability (1 week)
- [ ] Python WebAuthn decoder (using `webauthn` library)
- [ ] Manifest version backwards compatibility
- [ ] Cross-platform testing (CLI ↔ Web)

### Phase 3: Advanced Features (2-3 weeks)
- [ ] Schrödinger mode with dual hardware keys
- [ ] Duress mode with hardware wipe
- [ ] Multi-device sync (credential portability)
- [ ] Hardware key management UI

### Phase 4: Production Hardening (1-2 weeks)
- [ ] Security audit
- [ ] Error handling polish
- [ ] Documentation
- [ ] Performance optimization

**Total Estimated Time:** 5-8 weeks for full feature parity

## Alternative: Simpler "Hybrid" Mode

If full WebAuthn integration is too complex, implement a **hybrid mode**:

```javascript
// Simplified: Use hardware key as an EXTRA factor only
async function hybridEncrypt(file, password) {
    // Always use Argon2id
    const passwordKey = await crypto.deriveKey(password, salt, 512*1024, 20);
    
    // OPTIONALLY mix in hardware signature
    if (document.getElementById('useHardwareKey').checked) {
        const hwSig = await getHardwareSignature(salt);
        // XOR with password-derived key
        for (let i = 0; i < 32; i++) {
            passwordKey[i] ^= hwSig[i];
        }
        log("🔐 Hardware key mixed into encryption");
    }
    
    // Rest is unchanged
    return encryptWithKey(file, passwordKey);
}
```

**Pros:**
- Simpler implementation (~1 week)
- Graceful fallback (works without hardware)
- Backwards compatible

**Cons:**
- Weaker security model (password still sufficient if hardware bypassed)
- Not true hardware isolation

## Conclusion

WebAuthn integration would provide:
- ✅ True hardware key isolation (keys never in JavaScript)
- ✅ Multi-factor authentication (password + possession + touch)
- ✅ Feature parity with CLI hardware support
- ✅ Platform-portable (any FIDO2 key works)

**Recommended Path:** Start with Phase 1 (basic support), validate UX, then expand.

## References

- [WebAuthn Spec](https://www.w3.org/TR/webauthn-2/)
- [WebAuthn Guide (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [FIDO2 Overview](https://fidoalliance.org/fido2/)
- [YubiKey WebAuthn](https://developers.yubico.com/WebAuthn/)
- [Meow Decoder Hardware Integration](../meow_decoder/hardware_integration.py)
