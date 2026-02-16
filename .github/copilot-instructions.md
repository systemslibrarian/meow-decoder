# Meow Decoder - AI Coding Agent Instructions

## Project Overview

Meow Decoder is a security-focused optical air-gap file transfer system that encrypts files into animated GIFs containing QR codes. Core flow: `file → compress → encrypt (AES-256-GCM) → fountain encode → QR frames → animated GIF → camera → decode`.

**Key Innovation:** Schrödinger Mode provides quantum plausible deniability - two completely separate secrets encoded in one GIF, where neither can be proven to exist without the correct password.

## Architecture & Data Flow

### Core Pipeline Components

1. **Encryption** ([crypto.py](../meow_decoder/crypto.py), [crypto_enhanced.py](../meow_decoder/crypto_enhanced.py))
   - AES-256-GCM with Argon2id key derivation (512 MiB, 20 iterations in production; 32 MiB, 1 iteration in test mode)
   - Manifest versions: MEOW2 (base), MEOW3 (forward secrecy), MEOW4 (post-quantum)
   - HMAC-SHA256 authentication with domain separation
   - AAD includes: orig_len, comp_len, salt, sha256, magic, ephemeral_public_key, pq_ciphertext
   - Nonce reuse guard: LRU cache (10K cap) + HKDF-derived synthetic IV for HSM mode
   - Frame MAC: fail-closed (ValueError on invalid MAC, never silently disables)

2. **Fountain Coding** ([fountain.py](../meow_decoder/fountain.py), [fountain-codes.js](../examples/fountain-codes.js))
   - Luby Transform rateless codes with Robust Soliton distribution
   - Enables decoding from any ~1.5× k_blocks (tolerates 33% frame loss)
   - Droplets XOR multiple blocks using reproducible seed-based selection
   - **JavaScript implementation** for web demo (414 lines, production-ready)
   - Frame format: `FOUNTAIN:<k>:<block_size>:<length>:<droplet_b64>`

3. **Encoding/Decoding** ([encode.py](../meow_decoder/encode.py), [decode_gif.py](../meow_decoder/decode_gif.py))
   - Frame 0 = manifest (collar tag), Frame 1+ = fountain droplets
   - QR codes at 600×600 pixels, 10 FPS default
   - Optional steganography modes: photographic cat camouflage, logo-eyes carrier
   - **Web Demo**: Multi-frame QR with real-time fountain decoding in webcam scanner

4. **Forward Secrecy** ([forward_secrecy.py](../meow_decoder/forward_secrecy.py), [x25519_forward_secrecy.py](../meow_decoder/x25519_forward_secrecy.py))
   - Optional X25519 ephemeral key exchange (MEOW3)
   - Per-block key derivation using HKDF
   - Signal-style key ratcheting support
   - Full transcript binding (FIX-C3 v2): `derive_shared_secret()` binds `protocol_version`, `mode_flags`, `receiver_public_hash`, `ephemeral_public`, `pq_ciphertext_hash` in HKDF info

5. **Post-Quantum Hybrid** ([pq_hybrid.py](../meow_decoder/pq_hybrid.py))
   - ML-KEM-1024 (Kyber1024) + X25519 hybrid key exchange (MEOW4)
   - Fully wired end-to-end: `encode.py` → `hybrid_encapsulate()`, `decode_gif.py` → `hybrid_decapsulate()`
   - HKDF salt = `ephemeral_public_bytes` (not empty)
   - PQ ciphertext: 1568 bytes, bound in both HMAC and AAD
   - Manifest sizes: MEOW4 = 1715 bytes, MEOW4 + duress = 1747 bytes

6. **Schrödinger Mode** ([schrodinger_encode.py](../meow_decoder/schrodinger_encode.py), [quantum_mixer.py](../meow_decoder/quantum_mixer.py))
   - Dual-secret quantum superposition: `QuantumNoise = XOR(Hash(Pass_A), Hash(Pass_B))`
   - Statistical indistinguishability enforced via entropy tests
   - Merkle tree integrity, automatic decoy generation

## Critical Development Patterns

### Module Import Structure
```python
from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
from meow_decoder.fountain import FountainEncoder, FountainDecoder
from meow_decoder.config import EncodingConfig, MeowConfig
```

Core modules live in `meow_decoder/`, tests in `tests/`, examples in `examples/`.

### Manifest Versions (Critical!)
When editing crypto code, respect manifest version boundaries:
- **MEOW2**: Base encryption (password-only, no forward secrecy) — mode_byte=0x02
- **MEOW3**: Forward secrecy support (X25519 ephemeral keys optional) — mode_byte=0x03
- **MEOW4**: Post-quantum hybrid (ML-KEM-1024 + X25519) — mode_byte=0x04
- **Duress flag**: mode_byte |= 0x80

The explicit `mode_byte` field (FIX-D3) is bound in both AAD and HMAC.
Legacy manifests (mode_byte=0) are still accepted for backward compatibility.

Check version in [encode.py](../meow_decoder/encode.py) lines 56-73 for proper mode selection.

### Testing Requirements
All security-critical changes must include tests in `tests/test_security.py` or `tests/test_adversarial.py`:
- **Tamper detection**: Verify modified manifests/ciphertext are rejected
- **Authentication**: Wrong password must fail cleanly
- **Corruption handling**: Partial frames, corrupted QR codes
- **Forward secrecy**: Key derivation, ratchet state

Run tests: `make test` or `pytest tests/ -v --cov=meow_decoder`

### Security Invariants (NEVER violate!)
1. **AAD binding**: Manifest must be bound to ciphertext via AES-GCM AAD — includes `orig_len`, `comp_len`, `salt`, `sha256`, `magic`, `ephemeral_public_key`, `pq_ciphertext`
2. **No AAD bypass**: `decrypt_to_raw()` requires all AAD params; `aad=None` is never allowed
3. **HMAC verification**: Compute and verify manifest HMAC before using any fields
4. **Constant-time comparisons**: Use `secrets.compare_digest()` for auth tags/passwords
5. **Secure cleanup**: Zero sensitive bytes after use (see [constant_time.py](../meow_decoder/constant_time.py))
6. **Domain separation**: Use unique context strings for different HKDF derivations
7. **Fail-closed**: Frame MAC verification must raise `ValueError` on failure, never silently disable
8. **PQ ciphertext integrity**: When present, PQ ciphertext bound in both HMAC and AAD

## Command Reference

### Development Workflow
```bash
make install     # Install dependencies
make dev         # Install dev dependencies + pre-commit hooks
make test        # Run pytest with coverage
make lint        # Run flake8, black, mypy, bandit
make format      # Auto-format with black
```

### Common CLI Operations
```bash
# Basic encode/decode
meow-encode -i secret.pdf -o secret.gif -p "password123"
meow-decode-gif -i secret.gif -o output.pdf -p "password123"

# Forward secrecy mode (MEOW3)
python -m meow_decoder.forward_secrecy_encoder -i file.txt -o fs.gif -p "pass"
python -m meow_decoder.forward_secrecy_decoder -i fs.gif -o out.txt -p "pass"

# Schrödinger mode (dual-secret)
python -m meow_decoder.schrodinger_encode -i secret.pdf -i2 decoy.txt \
    -p1 "real_pass" -p2 "decoy_pass" -o dual.gif
```

### Docker Testing
```bash
docker-compose up --build  # Runs full integration tests
docker run -it meow-decoder python -m pytest tests/
```

## Fountain Codes - Frame Loss Tolerance

### Python Implementation ([fountain.py](../meow_decoder/fountain.py))
- **506 lines** implementing Luby Transform codes
- `RobustSolitonDistribution`: Optimal degree selection (c=0.1, δ=0.5)
- `FountainEncoder`: Generate unlimited droplets from source blocks
- `FountainDecoder`: Belief propagation reconstruction

### JavaScript Implementation ([examples/fountain-codes.js](../examples/fountain-codes.js))
- **414 lines** for web demo (production-ready, no dependencies)
- Identical algorithm to Python version for compatibility
- Classes: `FountainEncoder`, `FountainDecoder`, `Droplet`, `RobustSolitonDistribution`, `SeededRandom`
- Integrated into `wasm_browser_example.html` webcam scanner

### Frame Format
```
FOUNTAIN:<k_blocks>:<block_size>:<original_length>:<base64_droplet>

Example: FOUNTAIN:5:600:2847:AABgAC...
         ↑        ↑ ↑   ↑    ↑
         marker   │ │   │    droplet data (seed + indices + XOR)
                  │ │   original payload length
                  │ block size in bytes
                  number of source blocks
```

### Key Properties
- **Rateless**: Can generate unlimited droplets until decode succeeds
- **Loss-tolerant**: Decode from ANY ~67% of frames (with 1.5× redundancy)
- **Stateless**: No need to track which specific frames were received
- **Efficient**: Systematic optimization (first 2k droplets are degree-1)

### Integration Points

**Python CLI:**
```python
from meow_decoder.fountain import FountainEncoder, FountainDecoder

# Encode
encoder = FountainEncoder(data, k_blocks=10, block_size=800)
droplets = encoder.generateDroplets(15)  # 1.5× redundancy

# Decode
decoder = FountainDecoder(k_blocks=10, block_size=800, original_length=7843)
for droplet in received_droplets:
    if decoder.addDroplet(droplet):
        break  # Complete!
recovered = decoder.getData()
```

**JavaScript Web Demo:**
```javascript
// Encode (wasm_browser_example.html line ~2540)
const encoder = new FountainEncoder(payloadBytes, kBlocks, blockSize);
const numDroplets = Math.ceil(kBlocks * 1.5);
for (let i = 0; i < numDroplets; i++) {
    const droplet = encoder.generateDroplet(i);
    const framePayload = `FOUNTAIN:${kBlocks}:${blockSize}:${length}:${bytesToBase64(droplet.pack())}`;
    // Generate QR from framePayload
}

// Decode (scanWebcamFrame line ~5800)
if (code.data.startsWith('FOUNTAIN:')) {
    const [_, k, blockSize, length, dropletB64] = code.data.split(':');
    const decoder = new FountainDecoder(parseInt(k), parseInt(blockSize), parseInt(length));
    const droplet = Droplet.unpack(base64ToBytes(dropletB64), blockSize);
    if (decoder.addDroplet(droplet) && decoder.isComplete()) {
        const payload = decoder.getData();  // Success!
    }
}
```

### Testing
- **Python**: `tests/test_fountain.py` - comprehensive unit tests
- **JavaScript**: `examples/test_fountain.html` - browser-based test suite
- Run both: `pytest tests/test_fountain.py` and open test_fountain.html in browser

### Performance Tuning
- **block_size**: 600-800 bytes balances QR capacity vs frame count
- **redundancy**: 1.5× (50% overhead) tolerates 33% loss; 2.0× tolerates 50% loss
- **Systematic optimization**: First 2k droplets are degree-1, dramatically improves decode speed

### Security Note
Fountain codes operate on **already-encrypted** ciphertext. They are information-theoretic erasure codes, not encryption. Observing partial droplets reveals nothing about plaintext. No security regression from adding fountain encoding.

## Common Gotchas

1. **pyzbar dependency**: Requires system library (`libzbar0` on Ubuntu, `brew install zbar` on macOS)
2. **Fountain decoder belief propagation**: Don't modify [fountain.py](../meow_decoder/fountain.py) lines 200-350 without deep understanding of LT codes
3. **Manifest packing format**: Fixed struct layout, versioned - see [crypto.py](../meow_decoder/crypto.py) `pack_manifest()` for exact byte positions
4. **QR capacity limits**: Max ~2953 bytes per QR code at high error correction (L level), adjust `block_size` if hitting limits
5. **GIF frame timing**: Default 100ms (10 FPS) balances camera capture speed and file size

## Documentation Deep-Dives

- [ARCHITECTURE.md](../docs/ARCHITECTURE.md): Full data flow diagrams, component interactions (750+ lines)
- [FOUNTAIN_CODES_INTEGRATION.md](../docs/FOUNTAIN_CODES_INTEGRATION.md): Complete fountain codes technical spec (400+ lines)
- [SCHRODINGER.md](../docs/SCHRODINGER.md): Quantum plausible deniability theory, security proofs
- [THREAT_MODEL.md](../docs/THREAT_MODEL.md): Attack surface, what's protected vs. limitations
- [QUICKSTART.md](../QUICKSTART.md): 5-minute phone capture demo, step-by-step usage

## File Naming Conventions

- `*_DEBUG.py`: Verbose debug versions with extra logging
- `*_enhanced.py`: Extended feature versions (e.g., crypto_enhanced.py adds length padding)
- `clowder_*.py`: Multi-device streaming protocols
- `*_forward_secrecy*.py`: MEOW3 forward secrecy implementations
- `pq_*.py`: Post-quantum crypto (ML-KEM-1024, production-ready)

## Configuration & Tuning

Key parameters in [config.py](../meow_decoder/config.py):
- `block_size`: Fountain code block size (default 800 bytes)
- `redundancy`: Fountain code redundancy factor (default 1.5 = 50% overhead)
- `qr_version`: Auto-selected based on data size
- `fps`: GIF frame rate (default 10)

Argon2id params in [crypto.py](../meow_decoder/crypto.py) lines 28-37:
```python
# Test mode (MEOW_TEST_MODE=1):
ARGON2_MEMORY = 32768      # 32 MiB (fast)
ARGON2_ITERATIONS = 1      # 1 pass
ARGON2_PARALLELISM = 1     # 1 thread

# Production mode:
ARGON2_MEMORY = 524288     # 512 MiB (8x OWASP recommendation)
ARGON2_ITERATIONS = 20     # 20 passes
ARGON2_PARALLELISM = 4     # 4 threads
```

## When Modifying Crypto Code

1. Read [THREAT_MODEL.md](../docs/THREAT_MODEL.md) first to understand security boundaries
2. Add security tests BEFORE implementation (TDD for crypto)
3. Verify AAD bindings still work (`tests/test_security.py::TestTamperDetection`)
4. Run `bandit -r meow_decoder/` to catch common crypto mistakes
5. Check backward compatibility with older manifest versions
6. Update [CHANGELOG.md](../CHANGELOG.md) with security implications

## Key Dependencies

- `cryptography>=41.0.0`: AES-GCM, X25519, HKDF
- `argon2-cffi>=23.1.0`: Argon2id KDF
- `qrcode[pil]>=7.4.2` + `pyzbar>=0.1.9`: QR encode/decode
- `opencv-python>=4.8.0`: Webcam capture, image processing
- `liboqs-python>=0.9.0`: Post-quantum crypto (ML-KEM-1024)

## Examples Worth Reading

- [examples/basic_encode.py](../examples/basic_encode.py): Minimal encoding example
- [examples/demo_schrodinger.py](../examples/demo_schrodinger.py): Dual-secret workflow
- [examples/test_fountain.html](../examples/test_fountain.html): Browser-based fountain code tests
- [examples/fountain-codes.js](../examples/fountain-codes.js): JavaScript LT implementation
- [tests/test_encode.py](../tests/test_encode.py): Encoding pipeline and roundtrip patterns
- [tests/test_decode_gif.py](../tests/test_decode_gif.py): GIF decoding and frame extraction
- [tests/test_fountain.py](../tests/test_fountain.py): Python fountain code unit tests
- [tests/test_audit_fixes.py](../tests/test_audit_fixes.py): OPUS-AUDIT remediation verification
- [tests/test_e2e_crypto_fountain.py](../tests/test_e2e_crypto_fountain.py): End-to-end crypto+fountain pipeline tests
- [examples/demo_schrodinger.py](../examples/demo_schrodinger.py): Dual-secret workflow
