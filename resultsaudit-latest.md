# resultsaudit-latest.md

## 1. Verification of the 8 Hardening Items

1) Full Windows parity (VirtualLock + VirtualProtect in secure_alloc.rs / memory_guard.py)
- Status: Fully Implemented
- Is it correctly wired into production paths? Yes
- Reachability: production
- Evidence: [meow_decoder/memory_guard.py](meow_decoder/memory_guard.py#L340-L522), [crypto_core/src/secure_alloc.rs](crypto_core/src/secure_alloc.rs#L207-L275)
- Any remaining weakness, stub, or incomplete integration? None observed in these paths.

2) Mandatory ML-DSA manifest signing + full PQ ratchet beacon (ML-KEM-1024 integrated into ratchet path)
- Status: Partially Implemented
- Is it correctly wired into production paths? Partially
- Reachability: production (signing), production-only optional (ratchet), PQ ratchet not wired
- Evidence: Mandatory signing in [meow_decoder/manifest_signing.py](meow_decoder/manifest_signing.py#L1-L58); encoder fail-closed on missing ML-DSA backend in [meow_decoder/encode.py](meow_decoder/encode.py#L340-L391); decoder enforces signature by default in [meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L573-L699). PQ ratchet beacon logic exists in [meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1006-L1170) and [meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1308-L1660).
- Any remaining weakness, stub, or incomplete integration? Encoder ratchet is instantiated without `receiver_pq_public_key` in production path ([meow_decoder/encode.py](meow_decoder/encode.py#L420-L439)), and decoder ratchet is instantiated without `receiver_pq_keypair` ([meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L487-L510)), so ML-KEM-1024 PQ ratchet beacons are implemented but not wired into production CLI paths. Signing can be disabled via `MEOW_MANIFEST_SIGNING=off`, which weakens mandatory enforcement ([meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L573-L699)).

3) On-screen randomized keyboard + mouse-gesture password auth (full working implementation)
- Status: Fully Implemented
- Is it correctly wired into production paths? Yes
- Reachability: production
- Evidence: Randomized on-screen keyboard and mouse-gesture implementation in [meow_decoder/secure_keyboard.py](meow_decoder/secure_keyboard.py#L1-L200); CLI password modes invoking secure keyboard and mouse gesture in [meow_decoder/encode.py](meow_decoder/encode.py#L1502-L1548).
- Any remaining weakness, stub, or incomplete integration? None observed.

4) Active tamper detection + silent poisoning (fail-closed, no side-effect leaks)
- Status: Fully Implemented
- Is it correctly wired into production paths? Yes (PyInstaller runtime)
- Reachability: production (packed binary), optional in non-packed runs
- Evidence: Poison output path in [meow_decoder/tamper_detection.py](meow_decoder/tamper_detection.py#L400-L421); runtime hook aborts on tamper detection in [scripts/pyinstaller_runtime_hook.py](scripts/pyinstaller_runtime_hook.py#L57-L69).
- Any remaining weakness, stub, or incomplete integration? Tamper protections are activated automatically only in the PyInstaller runtime hook; non-packed executions rely on manual invocation.

5) Adversarial carrier generation + stego algorithm rotation (integrated into encode path)
- Status: Partially Implemented
- Is it correctly wired into production paths? Yes, but only when stego is enabled and set to PARANOID level
- Reachability: production (optional path)
- Evidence: Rotation schedule and adversarial embed in [meow_decoder/stego_advanced.py](meow_decoder/stego_advanced.py#L501-L519); encode path applies stego pipeline in [meow_decoder/encode.py](meow_decoder/encode.py#L609-L680).
- Any remaining weakness, stub, or incomplete integration? Rotation and adversarial embedding only occur at PARANOID level; default stego levels do not invoke adversarial noise.

6) Shamir-style multi-GIF split redundancy (threshold secret sharing with CLI workflow)
- Status: Fully Implemented
- Is it correctly wired into production paths? Yes
- Reachability: production
- Evidence: Shamir split implementation in [meow_decoder/shamir_split.py](meow_decoder/shamir_split.py#L1-L160); CLI flags and split-to-files integration in [meow_decoder/encode.py](meow_decoder/encode.py#L1127-L1875).
- Any remaining weakness, stub, or incomplete integration? None observed.

7) Portable single-executable mode + isolation checks (PyInstaller single binary + env safety)
- Status: Fully Implemented
- Is it correctly wired into production paths? Yes for PyInstaller builds; optional for non-packed runs
- Reachability: production (packed binary), optional in standard Python runs
- Evidence: PyInstaller runtime hook and env safety inclusion in [meow_decoder.spec](meow_decoder.spec#L1-L113); runtime hook enforces env safety and tamper checks in [scripts/pyinstaller_runtime_hook.py](scripts/pyinstaller_runtime_hook.py#L1-L69); strict isolation path in [meow_decoder/__main__.py](meow_decoder/__main__.py#L1-L33).
- Any remaining weakness, stub, or incomplete integration? Non-packed runs do not automatically enable env_safety unless `MEOW_STRICT_ISOLATION=1` is set.

8) Expanded formal verification (Verus proofs for timing/expiry/tamper/secure_alloc) + public bounty program in README
- Status: Partially Implemented
- Is it correctly wired into production paths? Formal artifacts are present; no runtime wiring needed
- Reachability: docs-only for proofs; policy is public
- Evidence: Formal methods overview in [formal/README.md](formal/README.md#L1-L30); Verus guarded-buffer proofs in [crypto_core/src/verus_guarded_buffer.rs](crypto_core/src/verus_guarded_buffer.rs#L1-L131); timing uniformity notes in [crypto_core/src/verus_kdf_proofs.rs](crypto_core/src/verus_kdf_proofs.rs#L340-L425). Public bounty program in [README.md](README.md#L1073-L1088) and [SECURITY.md](SECURITY.md#L119-L155).
- Any remaining weakness, stub, or incomplete integration? Verus AEAD proofs are explicitly described as stubs in [crypto_core/src/lib.rs](crypto_core/src/lib.rs#L42-L50), and SECURITY_INVARIANTS confirms AEAD proofs are not Verus-proven ([docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md#L24-L30)). No Verus proofs for expiry or tamper were located (NOT FOUND).

## 2. Cryptographic Correctness Audit

- AES-GCM nonce generation and reuse prevention
  - Status: Mixed
  - Findings: Observed random nonce generation in production encrypt path, not deterministic HKDF nonces as described in protocol docs. Observed per-process reuse guard.
  - Severity: Medium
  - Evidence / reachability: Random nonces in production encryption [meow_decoder/crypto.py](meow_decoder/crypto.py#L1018-L1046); deterministic NonceGenerator exists but is not referenced in production [meow_decoder/nonce.py](meow_decoder/nonce.py#L1-L80); protocol doc claims deterministic HKDF-derived nonce [docs/PROTOCOL.md](docs/PROTOCOL.md#L43-L72).

- Argon2id usage and domain separation
  - Status: Implemented
  - Findings: Observed Argon2id parameters from presets and handle-based derivation; observed domain separation constants for HMAC and keyfile mixing.
  - Severity: Low
  - Evidence / reachability: Presets and parameters in [meow_decoder/crypto.py](meow_decoder/crypto.py#L36-L72); canonical AAD layout and domain separation constants in [meow_decoder/crypto.py](meow_decoder/crypto.py#L60-L150); handle-based derivation in [meow_decoder/crypto.py](meow_decoder/crypto.py#L930-L1038).

- Ratchet forward secrecy (including PQ beacon integration)
  - Status: Partially Implemented
  - Findings: Observed ratchet supports asymmetric rekey and PQ hybrid fold with ML-KEM-1024. Observed production CLI wiring does not pass PQ ratchet keys.
  - Severity: High
  - Evidence / reachability: PQ beacon logic in [meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1006-L1170) and [meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1308-L1660); encoder ratchet instantiated without PQ public key [meow_decoder/encode.py](meow_decoder/encode.py#L420-L439); decoder ratchet instantiated without PQ keypair [meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L487-L510).

- Manifest signing, AAD binding, and HMAC verification
  - Status: Implemented
  - Findings: Observed canonical AAD construction includes mode byte and optional PQ/FS fields; observed HMAC verified in decode before decryption; observed signing enforced by default and fail-closed.
  - Severity: Low
  - Evidence / reachability: AAD construction in [meow_decoder/crypto.py](meow_decoder/crypto.py#L98-L150); HMAC verification in decode path [meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L441-L466); signing enforcement in [meow_decoder/encode.py](meow_decoder/encode.py#L340-L391) and [meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L573-L699).

- Zeroization and memory wiping reliability
  - Status: Implemented (best-effort in Python, stronger in Rust)
  - Findings: Observed secure_zero_memory invoked for sensitive buffers; observed ratchet finalize zeroizes and drops handles.
  - Severity: Medium
  - Evidence / reachability: Python zeroization in [meow_decoder/crypto.py](meow_decoder/crypto.py#L470-L495); ratchet state zeroization in [meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1188-L1217) and [meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1600-L1630); Verus guarded-buffer proofs in [crypto_core/src/verus_guarded_buffer.rs](crypto_core/src/verus_guarded_buffer.rs#L1-L131).

- Constant-time guarantees across decode paths
  - Status: Implemented (best-effort)
  - Findings: Observed constant-time compare via Rust backend, with timing equalization on HMAC checks.
  - Severity: Medium
  - Evidence / reachability: constant_time_compare in [meow_decoder/constant_time.py](meow_decoder/constant_time.py#L81-L105); equalize_timing in [meow_decoder/constant_time.py](meow_decoder/constant_time.py#L246-L271); HMAC verification uses constant_time_compare and equalize_timing in [meow_decoder/crypto.py](meow_decoder/crypto.py#L1261-L1310) and [meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L451-L459).

- Side-channel leaks (timing, cache, branch prediction)
  - Status: Partially mitigated
  - Findings: Assumption that Rust backend provides constant-time primitives; observed equalize_timing used to reduce timing variance but no formal side-channel guarantees are provided.
  - Severity: Medium
  - Evidence / reachability: equalize_timing in [meow_decoder/constant_time.py](meow_decoder/constant_time.py#L246-L271); timing uniformity notes in [crypto_core/src/verus_kdf_proofs.rs](crypto_core/src/verus_kdf_proofs.rs#L340-L425).

## 3. Steganography & Indistinguishability Audit

- Adversarial carrier generation and stego algorithm rotation
  - Status: Implemented (Paranoid mode only)
  - Findings: Observed rotation schedule and adversarial carrier embedding used when stealth level is PARANOID.
  - Severity: Low
  - Evidence / reachability: rotation and adversarial embed in [meow_decoder/stego_advanced.py](meow_decoder/stego_advanced.py#L501-L519); encode path calls stego pipeline in [meow_decoder/encode.py](meow_decoder/encode.py#L609-L680).

- Statistical indistinguishability (single vs dual mode, inter-file correlation)
  - Status: Best-effort
  - Findings: Observed adversarial carrier module explicitly documents limitations; no evidence of formal indistinguishability proof.
  - Severity: Medium
  - Evidence / reachability: limitations and threat model in [meow_decoder/adversarial_carrier.py](meow_decoder/adversarial_carrier.py#L1-L20).

- Fixed-size padding, fixed QR parameters, decorrelation
  - Status: Partially implemented
  - Findings: Observed length padding at encryption; QR parameters are configurable rather than fixed.
  - Severity: Low
  - Evidence / reachability: length padding in production encrypt path [meow_decoder/crypto.py](meow_decoder/crypto.py#L910-L944); QR parameters configured in encoder [meow_decoder/encode.py](meow_decoder/encode.py#L458-L478).

- Resistance to common steganalysis techniques
  - Status: Best-effort
  - Findings: Observed adversarial carrier noise targets chi-square and LSB steganalysis but explicitly notes detection is still possible.
  - Severity: Medium
  - Evidence / reachability: adversarial carrier threat model and limitations [meow_decoder/adversarial_carrier.py](meow_decoder/adversarial_carrier.py#L1-L20).

## 4. General Bug & Regression Hunt

- Finding: PQ ratchet beacons are implemented but not wired into production CLI paths.
  - Severity: High
  - Evidence / reachability: PQ beacon logic in [meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1006-L1170) and [meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1308-L1660) but encoder/decoder do not pass PQ key material in [meow_decoder/encode.py](meow_decoder/encode.py#L420-L439) and [meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L487-L510).

- Finding: Protocol documentation claims deterministic HKDF nonces, but production encryption uses random nonces.
  - Severity: Medium
  - Evidence / reachability: protocol nonce derivation [docs/PROTOCOL.md](docs/PROTOCOL.md#L43-L72); random nonce generation in production encryption [meow_decoder/crypto.py](meow_decoder/crypto.py#L1018-L1046).

- Finding: Environment safety checks are enforced only in PyInstaller runtime hook or when `MEOW_STRICT_ISOLATION=1` is set.
  - Severity: Medium
  - Evidence / reachability: runtime hook [scripts/pyinstaller_runtime_hook.py](scripts/pyinstaller_runtime_hook.py#L1-L69); optional strict isolation path in [meow_decoder/__main__.py](meow_decoder/__main__.py#L1-L33).

- Finding: Manifest signing can be disabled via environment policy, weakening mandatory guarantees.
  - Severity: Medium
  - Evidence / reachability: policy toggle in [meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L573-L699).

## 5. Documentation Verification

- Overclaim/inconsistency: README states post-quantum is default while threat model says PQ requires explicit opt-in.
  - Quote: "ML-KEM-768 (default, Signal PQXDH)" in [README.md](README.md#L185-L185)
  - Counter-evidence: "not default; requires explicit opt-in" in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#L199-L199)
  - Corrected wording (prose): Post-quantum features are available but only enabled when the user sets `--pq` (and `--paranoid` for ML-KEM-1024), not by default.

- Overclaim/inconsistency: Protocol spec mandates deterministic HKDF nonces, while production encryption uses random nonces.
  - Quote: "Nonce: 12 bytes deterministic via HKDF" in [docs/PROTOCOL.md](docs/PROTOCOL.md#L43-L72)
  - Counter-evidence: random nonce generation in [meow_decoder/crypto.py](meow_decoder/crypto.py#L1018-L1046)
  - Corrected wording (prose): Production encryption currently uses random 96-bit nonces with a reuse guard; deterministic HKDF nonces are implemented in nonce.py but not used in the main encrypt path.

- Overclaim/inconsistency: Formal verification claims vs implementation notes.
  - Quote: "Verus ... Complete" in [formal/README.md](formal/README.md#L9-L13)
  - Counter-evidence: "Verus proofs are stubs" for AEAD in [crypto_core/src/lib.rs](crypto_core/src/lib.rs#L42-L50) and SECURITY_INVARIANTS notes AEAD proofs are not Verus-proven [docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md#L24-L30)
  - Corrected wording (prose): Verus proofs are complete for guarded-buffer memory safety; AEAD proofs are not machine-checked and are enforced via type system and tests.

## 6. Final Independent Verdict

- Overall security score out of 10 (conservative): 7.2/10
- Is the current implementation ready for high-stakes use? No, not without resolving the PQ ratchet beacon wiring gap and the nonce-specification mismatch.
- Remaining Critical/High issues that must be addressed before release:
  - High: PQ ratchet beacon is implemented but not wired into production encode/decode flows; this undermines the full PQ ratchet beacon hardening claim ([meow_decoder/ratchet.py](meow_decoder/ratchet.py#L1006-L1170), [meow_decoder/encode.py](meow_decoder/encode.py#L420-L439), [meow_decoder/decode_gif.py](meow_decoder/decode_gif.py#L487-L510)).
- One-sentence recommendation before release: Align PQ and nonce behavior between code and documentation, and wire PQ ratchet beacons into the production CLI paths before claiming full PQ ratchet coverage.
