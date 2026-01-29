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

### Browser Demo

The `wasm_browser_example.html` demonstrates the crypto core running in the browser:

1. **Build the WASM module:**
   ```bash
   make build-wasm
   ```

2. **Serve the examples directory:**
   ```bash
   cd examples
   python3 -m http.server 8080
   ```

3. **Open in browser:**
   ```
   http://localhost:8080/wasm_browser_example.html
   ```

Features demonstrated:
- 🔑 **Argon2id key derivation** - Password to key
- 🔐 **AES-256-GCM encryption** - Encrypt any data
- 🔓 **Decryption** - Decrypt and verify integrity
- 🎲 **Secure random generation** - Browser-safe randomness

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

**🐾 Have fun experimenting! 😸**

