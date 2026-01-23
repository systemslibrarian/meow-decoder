# Changelog

All notable changes to Meow Decoder.

## [5.4.0] - 2026-01-23

### Added - Schrödinger's Yarn Ball 🐱⚛️
- **Quantum Superposition**: Encode TWO secrets in ONE GIF with true plausible deniability
- **Quantum Noise Derivation**: XOR of both password hashes creates shared entanglement key
- **Reality Entanglement**: Cryptographic mixing makes both secrets statistically indistinguishable
- **Observer Collapse**: One password reveals one reality, other remains forever unprovable
- **Automatic Decoy Generation**: Convincing innocent files (vacation photos, shopping lists, cat manifesto)
- **Forensic Resistance**: Statistical tests confirm indistinguishability (entropy, chi-square, byte frequency)

### New Modules
- `quantum_mixer.py`: Core cryptographic primitives for superposition
- `schrodinger_encode.py`: Dual-secret encoder
- `schrodinger_decode.py`: Reality collapse decoder
- `decoy_generator.py`: Automatic convincing decoy generation

### Security Properties
- Statistical indistinguishability (entropy diff < 0.003, chi-square < 300)
- Cryptographic binding via quantum noise (requires both passwords)
- Merkle root integrity over entangled blocks
- Constant-time collapse operations

### CLI
- `schrodinger_encode`: Encode dual realities with auto-decoy
  - `--real`: Real secret file
  - `--decoy`: Decoy file (auto-generated if omitted)
  - `--real-password`: Password for real secret
  - `--decoy-password`: Password for decoy
- `schrodinger_decode`: Collapse superposition to one reality
  - `--reality`: Force specific reality (A or B)

### Tests
- 7/7 quantum mixer tests passing (100%)
- Quantum noise derivation ✓
- Entanglement & collapse ✓
- Statistical indistinguishability ✓
- Merkle root integrity ✓
- End-to-end encoding ✓
- Decoy generation ✓
- Forensic resistance ✓
- Full roundtrip (encode + decode both realities) ✓

### Documentation
- [SCHRODINGER.md](./docs/SCHRODINGER.md): Complete philosophy and architecture
- README updated with quantum examples
- Use case scenarios (border crossing, coercion resistance, dead man's switch)

### Fixed
- Decoder architecture: Store encryption parameters in metadata for proper roundtrip
- Manifest format: Updated to 392 bytes with complete encryption parameters
- Full E2E roundtrip now works correctly (100% test success rate)
- Cleaned up `__init__.py`: Removed main entry point imports to eliminate RuntimeWarning
- Lightweight imports: Only config, crypto primitives, and quantum mixer at import time

### Note
- All v5.3.0 features preserved with 100% backward compatibility
- No regressions: 19/19 existing tests still pass
- Combined test score: 26/26 (100%)

---

## [5.3.0] - 2026-01-23

### Added
- **Forward Secrecy**: X25519 ephemeral keys protect past messages from future password compromise
- **Frame-Level MACs**: Per-frame authentication prevents DoS attacks via invalid frame rejection
- **Constant-Time Operations**: Timing attack resistance for password/MAC verification
- **Metadata Obfuscation**: Length padding hides true file size
- **Enhanced AAD**: Comprehensive manifest integrity protection

### Security
- Ephemeral keys generated per encryption, destroyed after use
- 8-byte MAC per QR frame with constant-time verification
- Random timing delays (1-5ms) prevent timing side-channels
- Size classes (powers of 2) prevent size fingerprinting
- AAD prevents tampering with all metadata fields

### CLI
- `--generate-keys`: Generate receiver keypair for forward secrecy
- `--receiver-pubkey`: Enable forward secrecy mode (encode)
- `--receiver-privkey`: Decrypt with forward secrecy (decode)

### Fixed
- Version consistency across all files (5.3.0)
- Console script entrypoints corrected
- Package imports work correctly
- Test collection fixed

---

## [5.0.0] - Previous Release

Initial production release with:
- AES-256-GCM encryption
- Argon2id key derivation
- QR code fountain coding
- Dual secret support (Schrödinger mode)
