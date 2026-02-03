# 🐱 STOP BEING LAZY - Coverage Improvement Tracker

**Last Updated:** 2026-02-03 (session update)  
**Overall Coverage:** 96% (Target: 98-100%)

## 📊 Module Coverage Status

| Module | Coverage | Missing Lines | Priority | Status |
|--------|----------|---------------|----------|--------|
| frame_mac.py | **100%** | 0 | ✅ Done | COMPLETE |
| metadata_obfuscation.py | **100%** | 0 | ✅ Done | COMPLETE |
| x25519_forward_secrecy.py | **100%** | 0 | ✅ Done | COMPLETE |
| forward_secrecy_decoder.py | **100%** | 0 | ✅ Done | COMPLETE |
| forward_secrecy.py | **99%** | 2 branches | ✅ Good | SKIP |
| crypto_backend.py | **99%** | 2 stmts | ✅ Good | SKIP |
| decode_gif.py | **98%** | 8 branches | ✅ Good | SKIP |
| crypto.py | **97%** | 13 stmts | 🔸 LOW | IMPROVE |
| gif_handler.py | **97%** | 1 stmt, 2 branches | 🔸 LOW | IMPROVE |
| constant_time.py | **96%** | 1 stmt, 5 branches | 🔸 LOW | IMPROVE |
| encode.py | **95%** | 17 stmts, 6 branches | 🔸 MED | IMPROVE |
| forward_secrecy_encoder.py | **95%** | 2 stmts | 🔸 LOW | IMPROVE |
| config.py | **94%** | 10 branches | 🔸 MED | IMPROVE |
| fountain.py | **94%** | 6 stmts, 6 branches | 🔸 MED | IMPROVE |
| forward_secrecy_x25519.py | **93%** | 4 stmts, 2 branches | 🟡 HIGH | IMPROVE |
| qr_code.py | **92% → ?%** | 4 stmts, 8 branches | 🟡 HIGH | 🔄 IN PROGRESS |

## 🎯 Priority Order (Lowest Coverage First)

1. **qr_code.py (92%)** - ✅ TESTS ADDED - WebcamQRReader edge cases:
   - Line 285: `return None` when webcam read fails
   - Line 295: loop continuation when no QR found
   - Line 313: loop continuation when read_next returns None
   - Line 320: release() when self.cap is None
   - Added __del__ test for cleanup
2. **forward_secrecy_x25519.py (93%)** - Some edge cases
3. **fountain.py (94%)** - Edge cases in decode
4. **config.py (94%)** - Branch coverage gaps
5. **encode.py (95%)** - CLI paths untested
6. **forward_secrecy_encoder.py (95%)** - Minor gaps

## ✅ Special Test Files Status

| File | Tests | Status |
|------|-------|--------|
| tests/test_security.py | 20 | ✅ ALL PASSING |
| tests/test_adversarial.py | 20 | ✅ ALL PASSING |
| tests/test_property_based.py | 20 | ✅ ALL PASSING |

## 📝 Next Actions

1. ~~Add tests for WebcamQRReader mock (qr_code.py)~~ ✅ DONE
2. Add edge case tests for forward_secrecy_x25519.py
3. Improve fountain.py branch coverage
4. Add config save/load edge case tests

## 📈 Progress Log

- **2026-02-03**: Created tracker from HTML coverage report
- All 60 special security tests passing
- Overall coverage at 96%, target 98%
