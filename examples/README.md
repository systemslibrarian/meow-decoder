# 📚 Meow Decoder - Examples

Example scripts showing how to use Meow Decoder.

## 🚀 Basic Examples

### Simple Encode/Decode

```bash
# Encode a file
python3 basic_encode.py

# Decode a file
python3 basic_decode.py
```

### With All Features

```bash
# Encode with quantum + forward secrecy + steganography
python3 advanced_encode.py

# Decode with nine lives retry
python3 advanced_decode.py
```

### Cat Utilities

```bash
# Use all cat features
python3 cat_features_demo.py
```

### GUI

```bash
# Launch GUI dashboard
python3 gui_example.py
```

## 🌐 WASM / Browser Examples

### Browser Demo Setup

The `wasm_browser_example.html` demonstrates the crypto core running in the browser.

> **Note:** The WASM module (`crypto_core/pkg/` folder) must be built before the demo works.

#### Web Worker for Responsive UI

The demo uses a **Web Worker** (`crypto-worker.js`) to run CPU-intensive cryptographic operations off the main thread. This keeps the UI responsive during key derivation (Argon2id can take 1-2 seconds).

- **Automatic fallback:** If Web Workers aren't supported or fail to load, the demo falls back to running crypto on the main thread
- **Files involved:**
  - `examples/crypto-worker.js` — Worker script that loads WASM and handles crypto ops
  - `examples/wasm_browser_example.html` — Main demo page with worker integration

#### Service Worker Caching

The demo includes a **Service Worker** (`sw.js`) that caches the WASM module and assets for faster repeat loads:

- **First visit:** WASM module is fetched from server and cached
- **Subsequent visits:** WASM loads instantly from cache
- **Files involved:**
  - `examples/sw.js` — Caches WASM, JS, and image assets

#### First Time Setup

```bash
# Build the WASM module (installs wasm-pack if needed)
make build-wasm
```

This compiles the Rust crypto core to WebAssembly. The output is cached in `crypto_core/pkg/`.

#### Codespaces / Dev Container Notes

**Port forwarding is disabled by default** to prevent confusing popups and "Cannot GET /" errors. This is configured in `.devcontainer/devcontainer.json`.

- **On first clone:** Run `make build-wasm` once (takes ~1-2 minutes)
- **On resume/reopen:** Built files persist — no rebuild needed
- **After container rebuild:** Re-run `make build-wasm` (rebuilds delete `pkg/`)
- **After Rust code changes:** Re-run to pick up changes

#### Running the Demo

**Quick Start (recommended):**
```bash
make meow-build
```
This builds WASM (if needed) and starts the server. Open http://localhost:8080/examples/wasm_browser_example.html

**Manual steps:**
1. **Start a local HTTP server** (from project root):
   ```bash
   python3 -m http.server 8080
   ```

2. **Forward the port** (Codespaces only):
   - Open the **Ports** tab in the bottom panel
   - Port 8080 will appear — click to open, or right-click → "Open in Browser"
   - Navigate to `/examples/wasm_browser_example.html`

3. **Open in browser:**
   - Local: http://localhost:8080/examples/wasm_browser_example.html
   - Codespaces: Use the forwarded port URL + `/examples/wasm_browser_example.html`

> **Why a server?** Browsers block WASM loading from `file://` URLs due to CORS. The HTTP server provides proper MIME types.

#### Demo Workflow

The demo simulates a complete air-gap transfer:

**On Computer A (Sender):**
1. **Step 1 - Create Secret:** Enter a message and password → Click "Encrypt & Generate QR"
2. **Step 2 - QR Code:** View and save the encrypted QR code

**Transfer via Air Gap:**
3. **📸 Take a photo** of the QR code with your phone

**On Computer B (Receiver):**
4. **Step 3 - Upload QR:** Click "Choose Image" and select the photo from your phone
5. **Step 3 - Decrypt:** Enter the password → Click "Decrypt" to reveal the hidden message

#### Try These Experiments

- 📸 **Air-gap transfer:** Generate a QR, photo it with phone, upload on different browser/device
- 🔓 **Correct password:** Enter the right password → Message revealed
- 🎭 **Wrong password:** Click "Try Wrong Password" → See authentication fail (AES-GCM detects tampering)
- 💾 **Share the QR:** Save/email the QR image — it's encrypted, safe to share publicly
- 📋 **Manual paste:** Copy encrypted payload text instead of using QR

Features demonstrated:
- 🔑 **Argon2id key derivation** - Password to key (4 security levels: 64-512 MiB)
- 🔐 **AES-256-GCM encryption** - Encrypt any data
- 🔓 **Decryption** - Decrypt and verify integrity
- 📱 **QR code generation** - Encrypted data in scannable format
- 📸 **QR code scanning** - Decode QR from uploaded photo
- 🎲 **Secure random generation** - Browser-safe randomness via WASM

#### Available Encryption Modes

The web demo provides **8 encryption modes**:

| Mode | Description | Payload Prefix |
|------|-------------|----------------|
| 🔐 **Standard** | AES-256-GCM + Argon2id | `MEOW:` |
| 🔑 **Forward Secrecy** | X25519 ephemeral keys | `FS:` |
| 🔮 **Post-Quantum** | ML-KEM-1024 + X25519 hybrid | `HYBRID-PQ:` |
| 🐱 **Schrödinger** | Dual-secret deniability | `QUANTUM:` |
| 🖼️ **Stego** | LSB steganography | Image-embedded |
| 📹 **Webcam** | Live QR scanner | All types supported |
| 🚨 **Duress** | Panic password wipe | Destroys localStorage |
| 😺 **Cat Mode** | Blinking cat eyes | Visual encoding |

#### Security Level Selection

The web demo lets users choose security strength:

| Level | Memory | Iterations | Approx. Time | Recommendation |
|-------|--------|------------|--------------|----------------|
| ⚡ Fast | 64 MiB | 3 | ~1 sec | Quick demos only |
| 🔒 Standard | 128 MiB | 8 | ~3 sec | General use |
| 🛡️ High | 256 MiB | 15 | ~8 sec | Sensitive data |
| 🔐 Paranoid | 512 MiB | 20 | ~20 sec | **Matches CLI** |

⚠️ **For life-critical data, always select "Paranoid"** — this matches the Python CLI's default security parameters.

#### Building with Post-Quantum Support

To enable ML-KEM-1024 post-quantum cryptography:

```bash
# Standard build (X25519 + AES-256-GCM)
make build-wasm

# With Post-Quantum ML-KEM-1024 hybrid
wasm-pack build crypto_core --target web --release --features wasm-pq
```

The Post-Quantum mode combines X25519 (classical) with ML-KEM-1024 (quantum-resistant) for hybrid security — the message remains secure if either algorithm holds.

### Node.js Usage

```bash
# Build for Node.js
make build-wasm-node

# Use in Node.js
node nodejs_example.js
```

### Schrödinger Mode Demo

```bash
# Demo dual-secret quantum encoding
python3 demo_schrodinger.py
```

---

## 🌐 Hosting the WASM Demo

Want to host the browser demo on your own server?

### PythonAnywhere (Free)

See [PYTHONANYWHERE_HOSTING.md](PYTHONANYWHERE_HOSTING.md) for complete instructions.

Quick start:
```bash
# Prepare files for upload
./scripts/prepare_pythonanywhere.sh

# Upload the pythonanywhere-deploy/ folder to PythonAnywhere
```

### Other Platforms

The WASM demo is static files — works on any host that serves:
- HTML files
- `.wasm` files with `application/wasm` MIME type

Platforms that work out of the box:
- **GitHub Pages** (free, static)
- **Netlify** (free tier, static)
- **Vercel** (free tier, static)
- **Cloudflare Pages** (free tier, static)
- **Any VPS** with nginx/Apache

---

**🐾 Have fun experimenting! 😸**

