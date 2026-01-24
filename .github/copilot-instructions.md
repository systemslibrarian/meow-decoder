# Meow Decoder - AI Coding Agent Instructions

## Project Overview

Meow Decoder is a security-focused optical air-gap file transfer system that encrypts files into animated GIFs containing QR codes. Core flow: `file → compress → encrypt (AES-256-GCM) → fountain encode → QR frames → animated GIF → camera → decode`.

**Key Innovation:** Schrödinger Mode provides quantum plausible deniability - two completely separate secrets encoded in one GIF, where neither can be proven to exist without the correct password.

## Architecture & Data Flow

### Core Pipeline Components

1. **Encryption** ([crypto.py](../meow_decoder/crypto.py), [crypto_enhanced.py](../meow_decoder/crypto_enhanced.py))
   - AES-256-GCM with Argon2id key derivation (64 MiB, 3 iterations)
   - Manifest versions: MEOW2 (base), MEOW3 (forward secrecy), MEOW4 (post-quantum)
   - HMAC-SHA256 authentication with domain separation

2. **Fountain Coding** ([fountain.py](../meow_decoder/fountain.py))
   - Luby Transform rateless codes with Robust Soliton distribution
   - Enables decoding from any ~1.5× k_blocks (tolerates 33% frame loss)
   - Droplets XOR multiple blocks using reproducible seed-based selection

3. **Encoding/Decoding** ([encode.py](../meow_decoder/encode.py), [decode_gif.py](../meow_decoder/decode_gif.py))
   - Frame 0 = manifest (collar tag), Frame 1+ = fountain droplets
   - QR codes at 600×600 pixels, 10 FPS default
   - Optional steganography modes: photographic cat camouflage, logo-eyes carrier

4. **Forward Secrecy** ([forward_secrecy.py](../meow_decoder/forward_secrecy.py), [x25519_forward_secrecy.py](../meow_decoder/x25519_forward_secrecy.py))
   - Optional X25519 ephemeral key exchange (MEOW3)
   - Per-block key derivation using HKDF
   - Signal-style key ratcheting support

5. **Schrödinger Mode** ([schrodinger_encode.py](../meow_decoder/schrodinger_encode.py), [quantum_mixer.py](../meow_decoder/quantum_mixer.py))
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
- **MEOW2**: Base encryption (password-only, no forward secrecy)
- **MEOW3**: Forward secrecy support (X25519 ephemeral keys optional)
- **MEOW4**: Post-quantum hybrid (ML-KEM-768 + X25519)

Check version in [encode.py](../meow_decoder/encode.py) lines 56-73 for proper mode selection.

### Testing Requirements
All security-critical changes must include tests in `tests/test_security.py` or `tests/test_adversarial.py`:
- **Tamper detection**: Verify modified manifests/ciphertext are rejected
- **Authentication**: Wrong password must fail cleanly
- **Corruption handling**: Partial frames, corrupted QR codes
- **Forward secrecy**: Key derivation, ratchet state

Run tests: `make test` or `pytest tests/ -v --cov=meow_decoder`

### Security Invariants (NEVER violate!)
1. **AAD binding**: Manifest must be bound to ciphertext via AES-GCM AAD (see [crypto.py](../meow_decoder/crypto.py) line ~280)
2. **HMAC verification**: Compute and verify manifest HMAC before using any fields
3. **Constant-time comparisons**: Use `secrets.compare_digest()` for auth tags/passwords
4. **Secure cleanup**: Zero sensitive bytes after use (see [constant_time.py](../meow_decoder/constant_time.py))
5. **Domain separation**: Use unique context strings for different HKDF derivations

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

## Common Gotchas

1. **pyzbar dependency**: Requires system library (`libzbar0` on Ubuntu, `brew install zbar` on macOS)
2. **Fountain decoder belief propagation**: Don't modify [fountain.py](../meow_decoder/fountain.py) lines 200-350 without deep understanding of LT codes
3. **Manifest packing format**: Fixed struct layout, versioned - see [crypto.py](../meow_decoder/crypto.py) `pack_manifest()` for exact byte positions
4. **QR capacity limits**: Max ~2953 bytes per QR code at high error correction (L level), adjust `block_size` if hitting limits
5. **GIF frame timing**: Default 100ms (10 FPS) balances camera capture speed and file size

## Documentation Deep-Dives

- [ARCHITECTURE.md](../docs/ARCHITECTURE.md): Full data flow diagrams, component interactions (700 lines)
- [SCHRODINGER.md](../docs/SCHRODINGER.md): Quantum plausible deniability theory, security proofs
- [THREAT_MODEL.md](../docs/THREAT_MODEL.md): Attack surface, what's protected vs. limitations
- [QUICKSTART.md](../QUICKSTART.md): 5-minute phone capture demo, step-by-step usage

## File Naming Conventions

- `*_DEBUG.py`: Verbose debug versions with extra logging
- `*_enhanced.py`: Extended feature versions (e.g., crypto_enhanced.py adds length padding)
- `clowder_*.py`: Multi-device streaming protocols
- `*_forward_secrecy*.py`: MEOW3 forward secrecy implementations
- `pq_*.py`: Post-quantum crypto experiments (ML-KEM-768, not yet stable)

## Configuration & Tuning

Key parameters in [config.py](../meow_decoder/config.py):
- `block_size`: Fountain code block size (default 800 bytes)
- `redundancy`: Fountain code redundancy factor (default 1.5 = 50% overhead)
- `qr_version`: Auto-selected based on data size
- `fps`: GIF frame rate (default 10)

Argon2id params in [crypto.py](../meow_decoder/crypto.py) lines 19-21:
```python
ARGON2_MEMORY = 65536     # 64 MiB
ARGON2_ITERATIONS = 3     # 3 passes
ARGON2_PARALLELISM = 4    # 4 threads
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
- `liboqs-python>=0.9.0`: Optional post-quantum crypto (experimental)

## Examples Worth Reading

- [examples/basic_encode.py](../examples/basic_encode.py): Minimal encoding example
- [examples/demo_schrodinger.py](../examples/demo_schrodinger.py): Dual-secret workflow
- [tests/test_e2e.py](../tests/test_e2e.py): Full encode→decode roundtrip patterns
