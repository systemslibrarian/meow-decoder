# WebAuthn Hardware Key Integration - Quick Start

This directory contains the WebAuthn/FIDO2 hardware security key integration for the Meow Decoder WASM demo.

## Files

- **`webauthn-hardware.js`** - Core WebAuthn integration module (production-ready)
- **`test_webauthn_integration.html`** - Browser-based unit tests
- **`wasm_browser_example.html`** - Full demo with WebAuthn integration (in progress)

## Quick Test

Open `test_webauthn_integration.html` in your browser to run all unit tests:

```bash
cd examples
python3 -m http.server 8080
# Open http://localhost:8080/test_webauthn_integration.html
```

## Basic Usage

### 1. Import the Module

```html
<script type="module">
    import { HardwareKeyManager, createHardwareUI, initHardwareUI } from './webauthn-hardware.js';
</script>
```

### 2. Initialize Hardware Key Manager

```javascript
const hwManager = new HardwareKeyManager();

// Check if WebAuthn is supported
if (await hwManager.isSupported()) {
    console.log('✅ WebAuthn supported');
} else {
    console.log('❌ WebAuthn not available');
}
```

### 3. Register a Security Key

```javascript
try {
    const result = await hwManager.register('my-username');
    console.log('Registered:', result.credentialId);
} catch (err) {
    console.error('Registration failed:', err.message);
}
```

### 4. Derive Encryption Key (Hybrid Mode)

```javascript
// Mock Argon2id function (replace with real WASM implementation)
async function argon2Derive(password, salt, memKib, iterations) {
    // In production, call WASM crypto_core.derive_key()
    return { key: new Uint8Array(32) };  // Dummy key
}

const password = 'my-password';
const salt = crypto.getRandomValues(new Uint8Array(16));

// Derive key with hardware + password
const hybridKey = await hwManager.deriveKey(
    password,
    salt,
    argon2Derive,
    64 * 1024,  // 64 MiB
    3           // 3 iterations
);

console.log('Hybrid key derived:', hybridKey.length, 'bytes');
```

### 5. Create UI

```html
<div id="hardwareKeyContainer"></div>

<script type="module">
    import { HardwareKeyManager, createHardwareUI, initHardwareUI } from './webauthn-hardware.js';
    
    const hwManager = new HardwareKeyManager();
    const ui = createHardwareUI('hardwareKeyContainer');
    
    await initHardwareUI(hwManager, ui, 
        () => console.log('Registered!'),
        () => console.log('Unregistered!')
    );
</script>
```

## Integration with WASM Demo

To integrate into `wasm_browser_example.html`:

### Step 1: Add Script Tag

```html
<!-- Add after fountain-codes.js -->
<script type="module" src="webauthn-hardware.js"></script>
```

### Step 2: Add UI Container

```html
<!-- Add in Step 1 section, after password input -->
<div id="hardwareKeyContainer"></div>
```

### Step 3: Initialize on Page Load

```javascript
// In the initWasm() function or similar
import { HardwareKeyManager, createHardwareUI, initHardwareUI } from './webauthn-hardware.js';

const hwManager = new HardwareKeyManager();
const hwUI = createHardwareUI('hardwareKeyContainer');
await initHardwareUI(hwManager, hwUI);
```

### Step 4: Modify Encryption Flow

```javascript
// In encryptFile() or similar
const useHardware = document.getElementById('useHardwareKey')?.checked || false;

let key;
if (useHardware && hwManager.isRegistered()) {
    // Use hardware-backed key derivation
    key = await hwManager.deriveKey(
        password,
        salt,
        crypto.deriveKey,  // Pass the existing Argon2id function
        secParams.memoryKib,
        secParams.iterations
    );
    console.log('🔐 Using hardware security key');
} else {
    // Standard Argon2id
    const keyResult = await crypto.deriveKey(passwordBytes, salt, secParams.memoryKib, secParams.iterations);
    key = keyResult.key;
    console.log('🔑 Using software key derivation');
}

// Rest of encryption unchanged
const ciphertext = await crypto.encrypt(plaintext, key, nonce, aad);
```

## Security Properties

✅ **Private keys never leave hardware** - Non-exportable key generation  
✅ **Touch required** - Physical presence verification  
✅ **Hybrid strength** - XORs hardware signature with Argon2id  
✅ **Multi-factor** - Knowledge (password) + Possession (key) + Presence (touch)  

## Browser Compatibility

| Browser | Support | Notes |
|---------|---------|-------|
| Chrome 67+ | ✅ Full | Recommended |
| Firefox 60+ | ✅ Full | Recommended |
| Safari 13+ | ✅ Full | macOS/iOS |
| Edge 18+ | ✅ Full | Chromium-based |

## Supported Hardware Keys

- YubiKey 5 Series (FIDO2)
- Google Titan Security Key
- Nitrokey FIDO2
- SoloKeys
- Windows Hello (platform authenticator)
- Touch ID (macOS/iOS)
- Any FIDO2/WebAuthn compliant device

## Testing

### Unit Tests

Open `test_webauthn_integration.html` and click "▶️ Run All Tests":

- ✅ 4 utility function tests (SHA-256, HMAC)
- ✅ 5 HKDF key derivation tests
- ✅ 6 hybrid key mixing tests
- ⚠️ 5 WebAuthn tests (require hardware key and user interaction)

**Expected Results:**
- 15 tests pass without hardware key
- 20 tests pass with registered hardware key

### Manual Testing

1. **Register Key**: Click "Register New Key" button
2. **Touch Key**: When prompted, touch your security key
3. **Test Signature**: Click "Test Key" to verify hardware works
4. **Encrypt**: Use checkbox to enable hardware encryption
5. **Decrypt**: Hardware key required for decryption

### Troubleshooting

**"WebAuthn not supported"**
- Use Chrome/Firefox 67+ or Safari 13+
- Check browser security settings
- Must use HTTPS or localhost

**"Registration failed: NotAllowedError"**
- User canceled or timeout (60 seconds)
- Try again and touch key when light blinks

**"Authentication failed: NotFoundError"**
- Wrong security key inserted
- Key was unregistered
- Try re-registering

**"No hardware key registered"**
- Click "Register New Key" first
- Check localStorage for credentials

## API Reference

### `HardwareKeyManager`

#### Constructor
```javascript
const hwManager = new HardwareKeyManager();
```

#### Methods

##### `isSupported(): Promise<boolean>`
Check if WebAuthn is available in browser.

##### `isRegistered(): boolean`
Check if a hardware key is registered.

##### `getCredential(): object | null`
Get stored credential info: `{ credentialId, publicKey, username, registeredAt }`

##### `register(username, requireResidentKey): Promise<object>`
Register new security key. Returns `{ credentialId, publicKey, username }`.

##### `unregister(): void`
Remove registered credential from localStorage.

##### `getSignature(challenge): Promise<Uint8Array>`
Get hardware signature for challenge (requires touch).

##### `deriveKey(password, salt, argon2Derive, memKib, iterations): Promise<Uint8Array>`
Derive hybrid key: `passwordKey XOR hardwareKey`. Returns 32 bytes.

##### `deriveKeyHardwareOnly(challenge, salt): Promise<Uint8Array>`
Derive key from hardware signature only (no password). Returns 32 bytes.

### `createHardwareUI(containerId): object`
Create HTML UI elements for hardware key management.

### `initHardwareUI(hwManager, ui, onRegister, onUnregister): Promise<void>`
Initialize UI with live status detection and event handlers.

## Security Considerations

### Threat Model

**Protected Against:**
- 🛡️ Password theft (hardware key also required)
- 🛡️ Memory dumps (private key never in JavaScript)
- 🛡️ Malware keylogging (requires physical key)
- 🛡️ Remote attacks (touch required)

**NOT Protected Against:**
- ❌ Physical coercion (rubber-hose cryptanalysis)
- ❌ Compromised browser (malware can intercept plaintext)
- ❌ Evil maid attacks (physical access to device)
- ❌ Supply chain attacks (compromised hardware)

### Best Practices

1. **Always use HTTPS** (or localhost for testing)
2. **Validate origin** (WebAuthn enforces rpID)
3. **Set reasonable timeouts** (60 seconds default)
4. **Clear storage securely** (zero sensitive data)
5. **Test in multiple browsers** (compatibility varies)

## Examples

### Minimal Registration

```javascript
const hwManager = new HardwareKeyManager();
await hwManager.register('alice');
console.log('Registered!');
```

### Signature Test

```javascript
const challenge = crypto.getRandomValues(new Uint8Array(32));
const sig = await hwManager.getSignature(challenge);
console.log('Signature:', sig.length, 'bytes');
```

### Hybrid Encryption

```javascript
// Derive hybrid key
const key = await hwManager.deriveKey(password, salt, argon2Fn);

// Encrypt with AES-GCM
const nonce = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await encryptAESGCM(plaintext, key, nonce);
```

## Roadmap

- ✅ Core WebAuthn integration
- ✅ Hybrid key derivation (hardware + password)
- ✅ Browser UI components
- ✅ Unit test suite
- 🔄 Full WASM demo integration (in progress)
- 📋 CLI interoperability (Python WebAuthn decoder)
- 📋 Schrödinger mode with dual hardware keys
- 📋 Duress mode with hardware wipe
- 📋 Multi-device credential portability

## References

- [WebAuthn Spec](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 Overview](https://fidoalliance.org/fido2/)
- [YubiKey WebAuthn Guide](https://developers.yubico.com/WebAuthn/)
- [MDN WebAuthn API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [Full Integration Plan](../docs/WEBAUTHN_INTEGRATION_PLAN.md)

## License

Same as Meow Decoder project.
