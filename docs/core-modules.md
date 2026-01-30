## Code Overview: Core Modules in `meow_decoder/`

This table summarizes the main Python source files in the `meow_decoder/` package — the cryptographic, steganographic, forward secrecy, deniability, and utility heart of the project.

| File Path                              | Module Name                  | Description                                                                 |
|----------------------------------------|------------------------------|-----------------------------------------------------------------------------|
| meow_decoder/__init__.py               | (package init)               | Package initialization and exports for the meow_decoder module.             |
| meow_decoder/ascii_qr.py               | ascii_qr                     | Handles ASCII representation and manipulation of QR codes for debugging or fallback stego. |
| meow_decoder/bidirectional.py          | bidirectional                | Supports bidirectional data flows or challenge-response in secure protocols. |
| meow_decoder/cat_utils.py              | cat_utils                    | Cat-themed utility functions (e.g., fun naming, theming helpers for deniability). |
| meow_decoder/catnip_fountain.py        | catnip_fountain              | Themed variant of fountain codes for loss-resilient, cat-flavored data streaming. |
| meow_decoder/clowder_decode.py         | clowder_decode               | Decodes multi-file/group ("clowder") payloads with shared secrets or deniability. |
| meow_decoder/clowder_encode.py         | clowder_encode               | Encodes data across multiple files or carriers in a group context.           |
| meow_decoder/config.py                 | config                       | Loads, validates, and manages secure configuration defaults and overrides.   |
| meow_decoder/constant_time.py          | constant_time                | Constant-time operations and comparisons to mitigate timing and cache attacks. |
| meow_decoder/crypto.py                 | crypto                       | High-level cryptographic API: symmetric/asymmetric encryption, key derivation. |
| meow_decoder/crypto_backend.py         | crypto_backend               | Bridges Python to constant-time Rust backend for performance-critical crypto. |
| meow_decoder/crypto_enhanced.py        | crypto_enhanced              | Extended crypto modes (e.g., AEAD variants, hybrid enhancements).            |
| meow_decoder/decode_gif.py             | decode_gif                   | Extracts and decodes hidden payloads from steganographic GIF frames.         |
| meow_decoder/decoy_generator.py        | decoy_generator              | Creates plausible dummy content for coercion resistance and deniability.     |
| meow_decoder/double_ratchet.py         | double_ratchet               | Implements the Double Ratchet algorithm for secure forward-secrecy messaging. |
| meow_decoder/duress_mode.py            | duress_mode                  | Handles panic/duress passwords: triggers wipe, decoy reveal, or limited access. |
| meow_decoder/encode.py                 | encode                       | Main entrypoint for encoding arbitrary data into steganographic carriers.    |
| meow_decoder/entropy_boost.py          | entropy_boost                | Supplements system entropy for stronger cryptographic randomness.            |
| meow_decoder/forward_secrecy.py        | forward_secrecy              | Core forward secrecy ratcheting and session key management.                  |
| meow_decoder/forward_secrecy_decoder.py| forward_secrecy_decoder      | Decoder-side logic for deriving session keys with forward secrecy.           |
| meow_decoder/forward_secrecy_encoder.py| forward_secrecy_encoder      | Encoder-side ephemeral key generation and ratchet advancement.               |
| meow_decoder/forward_secrecy_x25519.py | forward_secrecy_x25519       | X25519-based ephemeral key exchange for forward secrecy.                     |
| meow_decoder/fountain.py               | fountain                     | Luby Transform / fountain codes for erasure-coded, loss-tolerant transmission. |
| meow_decoder/frame_mac.py              | frame_mac                    | Computes and verifies per-frame MACs for integrity in animated/streamed data. |
| meow_decoder/gif_handler.py            | gif_handler                  | Low-level GIF parsing, frame manipulation, and assembly for stego embedding. |
| meow_decoder/high_security.py          | high_security                | Enforces strict security policies (e.g., no weak modes, mandatory checks).   |
| meow_decoder/logo_eyes.py              | logo_eyes                    | Steganographic technique embedding data in logo/eye regions of images.       |
| meow_decoder/meow_encode.py            | meow_encode                  | Specialized "meow" themed encoding with cat-meme flair and custom stego.     |
| meow_decoder/merkle_tree.py            | merkle_tree                  | Builds and verifies Merkle trees for efficient data integrity proofs.        |
| meow_decoder/metadata_obfuscation.py   | metadata_obfuscation         | Strips, randomizes, or fakes file metadata to enhance stealth.               |
| meow_decoder/multi_secret.py           | multi_secret                 | Supports hiding or recovering multiple secrets in a single payload.          |
| meow_decoder/ninja_cat_ultra.py        | ninja_cat_ultra              | Ultra-stealth mode with aggressive obfuscation and minimal footprint.        |
| meow_decoder/pq_crypto_real.py         | pq_crypto_real               | Concrete post-quantum primitives (ML-KEM / Kyber implementations).           |
| meow_decoder/pq_hybrid.py              | pq_hybrid                    | Hybrid classical + post-quantum encryption (X25519 + ML-KEM).                |
| meow_decoder/pq_signatures.py          | pq_signatures                | Post-quantum signatures (Dilithium) for authentication and non-repudiation.  |
| meow_decoder/progress.py               | progress                     | Core progress tracking logic for long-running encode/decode operations.      |
| meow_decoder/progress_bar.py           | progress_bar                 | CLI-friendly progress bar rendering (e.g., using tqdm wrappers).             |
| meow_decoder/prowling_mode.py          | prowling_mode                | Low-observability / stealth operation mode for covert usage.                 |
| meow_decoder/qr_code.py                | qr_code                      | QR code encoding, error correction, and extraction utilities.                |
| meow_decoder/quantum_mixer.py          | quantum_mixer                | Quantum-inspired randomness mixing or key material shuffling.                |
| meow_decoder/resume_secured.py         | resume_secured               | Securely resumes interrupted encoding/decoding sessions without state leaks. |
| meow_decoder/schrodinger_decode.py     | schrodinger_decode           | Decodes Schrödinger-mode payloads: selects real vs. decoy based on password. |
| meow_decoder/schrodinger_encode.py     | schrodinger_encode           | Encodes dual secrets with plausible deniability (Schrödinger's cat style).   |
| meow_decoder/secure_bridge.py          | secure_bridge                | Secure inter-process or cross-system data bridging with crypto guarantees.   |
| meow_decoder/secure_cleanup.py         | secure_cleanup               | Securely wipes memory, files, and traces using multi-pass overwrites.        |
| meow_decoder/security_warnings.py      | security_warnings            | Detects and emits warnings for weak configs, passwords, or risky modes.      |
| meow_decoder/stego_advanced.py         | stego_advanced               | Advanced steganography: multi-level LSB, noise injection, carrier analysis.  |
| meow_decoder/streaming_crypto.py       | streaming_crypto             | Applies crypto to streaming or chunked data without full buffering.          |
| meow_decoder/timelock_duress.py        | timelock_duress              | Time-locked duress mechanisms (e.g., dead-man’s switch for data exposure).   |
| meow_decoder/webcam_enhanced.py        | webcam_enhanced              | Enhanced decoding from live webcam feeds with error recovery and resume.     |
| meow_decoder/x25519_forward_secrecy.py | x25519_forward_secrecy       | Forward secrecy protocol built specifically around X25519 curves.           |

**Notes**:
- This list covers runtime/production modules only. Debug, demo, profiling, and hardware-specific files are excluded to keep focus on the secure core.
- Many modules are highly interdependent (e.g., crypto → pq_hybrid → forward_secrecy → encode/decode paths).
- For subpackages like `spec_v12/`, see the [Protocol Specs](./spec_v12/README.md) section (add if you create one).

Contributions welcome — especially more tests and formal verification for the crypto heart!