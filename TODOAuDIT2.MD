# TODOAuDIT2 — Fail-Closed Post-Rust Migration Audit

**Last Updated**: 2026-02-18
**Status**: ✅ Core Fixes Complete, Handles Operational

---

## ✅ Completed

| ID   | Owner  | Task | Rule(s) | Verification |
|------|--------|------|---------|-------------|
| A1   | Rust   | Opaque handle registry: `handles.rs` (SessionState, RatchetState, StreamState, HmacKey, SymmetricKey, X25519Key) — 65536-cap registry, zeroize on Drop, lazy_static Mutex<HashMap> | #2, #9 | `cargo test --lib` (50 pass) |
| A2   | PyO3   | Handle FFI bindings in `lib.rs`: 20+ `#[pyfunction]` wrappers (derive, encrypt, decrypt, HMAC, X25519, session, stream, ratchet, lifecycle) | #2, #9 | `python -c "import meow_crypto_rs; print(meow_crypto_rs.handle_count())"` |
| A3   | Python | `HandleBackend` class in `crypto_backend.py` + `get_handle_backend()` factory — full Python wrapper for all handle operations | #2, #9 | All handle tests in enforcement suite |
| B1   | Python | **Fix A**: Removed `from .experimental import crypto_enhanced` in `high_security.py` (lines 151-158) — dead import to phantom module | #1, #4 | CI forbidden-import scanner |
| B2   | Python | **Fix C**: Removed ALL `import oqs` and `oqs.KeyEncapsulation()` from `pq_hybrid.py` — PQ is Rust-only or hard error | #1, #4 | `TestNoPythonPQFallback` (2 tests) |
| B2b  | Python | **Fix C**: Removed `oqs as _pq_oqs` import and `oqs.KeyEncapsulation` fallback from `decode_gif.py` line 1151 — Rust PQ or RuntimeError | #1, #4 | `TestForbiddenProductionStrings` |
| B3   | Python | **Fix D**: Hardened streaming bypass in `streaming_crypto.py` — `expected_mac` now `bytes=b""` (not `Optional[None]`), added `_mac_verified` guard, Rust HMAC verify | #3 | `TestStreamingFailClosed` (4 tests) |
| B4   | Python | **Fix E**: All `secrets.compare_digest` → `Rust constant_time_compare` across 12 files: constant_time.py, bidirectional.py, frame_mac.py, duress_mode.py, crypto.py, ratchet.py, schrodinger_decode.py, multi_secret.py, merkle_tree.py, decode_webcam_with_resume.py | #6 | `TestForbiddenProductionStrings` scanner |
| B5   | Python | Handle-based crypto wrappers: `derive_key_handle()`, `encrypt_file_bytes_handle()`, `decrypt_to_raw_handle()`, `compute_manifest_hmac_handle()` in `crypto.py` — key NEVER enters Python | #2, #9 | `TestOpaqueHandleAPI` (6 tests) |
| CI1  | CI     | Enforcement test suite expanded: 47 tests across 17 test classes — import ban, handle API, streaming fail-closed, forbidden strings, protocol invariants, PQ enforcement, edge cases, golden vectors | #7 | `pytest tests/test_crypto_enforcement.py` 47/47 |
| CI2  | CI     | Golden vectors: SHA256 (NIST), HMAC (RFC 4231), AES-CTR, HKDF (RFC 5869), handle AES-GCM, handle HMAC | #7, #8 | `TestGoldenVectors` + `TestHandleGoldenVectors` |

## 🧪 Test Results

| Suite | Tests | Status | Command |
|-------|-------|--------|---------|
| test_crypto_enforcement.py | 47 | ✅ ALL PASS | `pytest tests/test_crypto_enforcement.py -v` |
| test_streaming_crypto.py | 145 | ✅ ALL PASS | `pytest tests/test_streaming_crypto.py` |
| test_security.py | 62 | ✅ ALL PASS | `pytest tests/test_security.py` |
| test_crypto.py | 17 | ✅ ALL PASS | `pytest tests/test_crypto.py` |
| test_constant_time.py | 23 | ✅ ALL PASS | `pytest tests/test_constant_time.py` |
| test_crypto_backend.py | 33 | ✅ ALL PASS | `pytest tests/test_crypto_backend.py` |
| test_frame_mac.py | varies | ✅ ALL PASS | `pytest tests/test_frame_mac.py` |
| test_bidirectional.py | varies | ✅ ALL PASS | `pytest tests/test_bidirectional.py` |
| **Full regression** | **416** | **✅ ALL PASS** | `pytest tests/ -q (8 key suites)` |
| Rust unit tests | 50 | ✅ ALL PASS | `cd rust_crypto && cargo test --lib` |

## 📋 Enforcement Tests Added (Test Classes 11-17)

| Class | Tests | What it enforces |
|-------|-------|-----------------|
| TestOpaqueHandleAPI | 6 | Rule #2: derive_key returns handle (int), roundtrip, HMAC via handle, wrong-password fail-closed, registry bounded, exports present |
| TestStreamingFailClosed | 4 | Rule #3: MAC tag produced, empty/wrong MAC rejected, None MAC rejected, _decrypt_verified_stream requires prior MAC |
| TestForbiddenProductionStrings | 1 | Rule #4/#6: no `import oqs`, no `oqs.KeyEncapsulation`, no `secrets.compare_digest` in executable code (AST-aware docstring skip) |
| TestProtocolInvariants | 4 | Rule #8: AAD includes all fields, manifest roundtrip lossless, HMAC rejects tampering, invalid mode bytes rejected |
| TestNoPythonPQFallback | 2 | Rule #4: pq_hybrid.py has no oqs import, check_pq_available uses Rust |
| TestHandleEdgeCases | 4 | Rule #5: invalid handle raises ValueError (no panic), X25519 private never exposed, DH exchange via handles |
| TestHandleGoldenVectors | 2 | Rule #7/#8: handle AES-GCM matches raw API, handle HMAC matches raw API |

## 🔮 Remaining Migration Work (Non-Critical)

These items deepen the handle migration but do NOT block the core security fixes above:

| ID   | Task | Rule(s) | Priority |
|------|------|---------|----------|
| M1   | Migrate `streaming_crypto.py` `self.key`/`self._mac_key` to stream handles | #2, #9 | Medium |
| M2   | Migrate `ratchet.py` chain/message keys to RatchetStateHandle | #2, #9 | Medium |
| M3   | Migrate `bidirectional.py` `self.auth_key` to handle | #2, #9 | Low |
| M4   | Migrate `frame_mac.py` frame keys to handles | #2, #9 | Low |
| M5   | Migrate `double_ratchet.py` `KeyPair._private_bytes` to handle | #2, #9 | Low |
| M6   | Migrate `schrodinger_encode/decode.py` keys to handles | #2, #9 | Low |
| M7   | Migrate `x25519_forward_secrecy.py` private keys to handles | #2, #9 | Medium |
| M8   | Move entropy generation to Rust (`secrets.token_bytes` → `backend.random_bytes`) | #1 | Low |
| M9   | Quarantine `spec_v12/` from production entrypoints | #1 | Low |

## 🛡️ Security Guarantees

### Rule Coverage Matrix

| Rule | Description | Status | Evidence |
|------|-------------|--------|----------|
| #1 — All secret crypto in Rust | Encryption, KDF, HMAC, X25519 all via meow_crypto_rs | ✅ | CI import ban (TestPythonCryptoBan) |
| #2 — Python never holds secret key bytes | Handle API available; legacy bytes API deprecated | ⚠️ Partial | HandleBackend + handle_* functions available; full caller migration ongoing (M1-M9) |
| #3 — No unauthenticated plaintext | Streaming: MAC mandatory, _mac_verified guard | ✅ | TestStreamingFailClosed (4 tests) |
| #4 — No silent downgrade paths | experimental import removed, oqs fallback removed | ✅ | TestForbiddenProductionStrings + TestNoPythonPQFallback |
| #5 — Rust no panic on adversarial input | Edge cases return errors | ✅ | TestRustNoPanic (4 tests) + TestHandleEdgeCases |
| #6 — Constant-time comparisons in Rust | All 12 files migrated from secrets.compare_digest | ✅ | TestForbiddenProductionStrings scanner |
| #7 — CI fails on regression | 47 enforcement tests, forbidden import/string scanners | ✅ | test_crypto_enforcement.py |
| #8 — Protocol invariants hold | AAD completeness, manifest roundtrip, HMAC tampering, mode byte validation | ✅ | TestProtocolInvariants (4 tests) |
| #9 — FFI boundary no secret leak | Handle API exports int IDs, not key bytes | ⚠️ Partial | TestOpaqueHandleAPI (6 tests); full caller migration ongoing |
| #10 — Protocol compatibility | Manifest pack/unpack roundtrip, golden vectors match | ✅ | TestGoldenVectors + TestProtocolInvariants |

## 📁 Files Modified

### Rust
- `rust_crypto/src/handles.rs` — **NEW**: Opaque handle registry (HandlePayload, REGISTRY, all handle_* ops)
- `rust_crypto/src/lib.rs` — **MODIFIED**: `pub mod handles;` + 20+ PyO3 handle bindings
- `rust_crypto/Cargo.toml` — **MODIFIED**: `lazy_static = "1.4"` added

### Python — Security Fixes
- `meow_decoder/crypto.py` — Handle-based wrappers added, `secrets.compare_digest` → `Rust`
- `meow_decoder/crypto_backend.py` — `HandleBackend` class + `get_handle_backend()` factory
- `meow_decoder/high_security.py` — Experimental import removed (Fix A)
- `meow_decoder/streaming_crypto.py` — MAC bypass hardened (Fix D)
- `meow_decoder/pq_hybrid.py` — `import oqs` removed entirely (Fix C)
- `meow_decoder/decode_gif.py` — `oqs.KeyEncapsulation` fallback removed, `_pq_oqs` import removed
- `meow_decoder/constant_time.py` — `secrets.compare_digest` → Rust
- `meow_decoder/bidirectional.py` — `secrets.compare_digest` → Rust
- `meow_decoder/frame_mac.py` — `secrets.compare_digest` → Rust
- `meow_decoder/duress_mode.py` — `secrets.compare_digest` → Rust
- `meow_decoder/ratchet.py` — `secrets.compare_digest` → Rust
- `meow_decoder/schrodinger_decode.py` — `secrets.compare_digest` → Rust
- `meow_decoder/multi_secret.py` — `secrets.compare_digest` → Rust
- `meow_decoder/merkle_tree.py` — `secrets.compare_digest` → Rust
- `meow_decoder/decode_webcam_with_resume.py` — Direct `!=` HMAC → Rust `constant_time_compare`

### Tests
- `tests/test_crypto_enforcement.py` — **EXPANDED**: 24 → 47 tests, 7 new test classes

## 📎 Evidence Links

- Rust backend: `rust_crypto/src/lib.rs`
- Opaque handle registry: `rust_crypto/src/handles.rs`
- Python backend: `meow_decoder/crypto_backend.py`
- Enforcement tests: `tests/test_crypto_enforcement.py`
- Streaming crypto: `meow_decoder/streaming_crypto.py`

## 🔧 Workflow / CI Status

- **Fuzz tests**: ✅ All 122 fuzz target tests pass (no API breakage from security fixes)
- **Rust formatting**: ✅ `cargo fmt --check` passes (fixed pre-existing formatting in test files)
- **Rust clippy**: ✅ `cargo clippy -- -D warnings` passes (fixed dead_code warnings on reserved handle fields)
- **Rust unit tests**: ✅ 50/50 pass
- **Python tests**: ✅ 476 pass, 5 skip
