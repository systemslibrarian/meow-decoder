# 📋 Tests Overall - Comprehensive Test Summary

**Last Updated:** 2026-02-03  
**Total Test Files:** 34  
**Overall Coverage:** 96%

## 📊 Test File Inventory

### Core Module Tests
| Test File | Tests | Coverage Target |
|-----------|-------|-----------------|
| test_crypto.py | Crypto operations | crypto.py, crypto_backend.py |
| test_fountain.py | Fountain coding | fountain.py |
| test_frame_mac.py | Frame authentication | frame_mac.py |
| test_encode.py | Encoding pipeline | encode.py |
| test_decode_gif.py | Decoding pipeline | decode_gif.py |
| test_qr_code.py | QR generation/reading | qr_code.py |
| test_gif_handler.py | GIF operations | gif_handler.py |
| test_config.py | Configuration | config.py |
| test_constant_time.py | Timing operations | constant_time.py |

### Security Tests (CANONICAL)
| Test File | Tests | Purpose |
|-----------|-------|---------|
| test_security.py | 20 | Security invariants, tamper detection |
| test_adversarial.py | 20 | Attack simulation, fuzzing |
| test_property_based.py | 20 | Hypothesis property-based tests |

### Forward Secrecy Tests
| Test File | Tests | Coverage Target |
|-----------|-------|-----------------|
| test_forward_secrecy.py | FS manager | forward_secrecy.py |
| test_x25519_forward_secrecy.py | X25519 operations | x25519_forward_secrecy.py |
| test_forward_secrecy_encoder.py | FS encoding | forward_secrecy_encoder.py |
| test_forward_secrecy_decoder.py | FS decoding | forward_secrecy_decoder.py |

### Schrödinger Mode Tests
| Test File | Tests | Coverage Target |
|-----------|-------|-----------------|
| test_schrodinger.py | Dual-secret encoding | schrodinger_encode.py |
| test_quantum_mixer.py | Quantum mixing | quantum_mixer.py |

## 🔒 Security Test Classes

### test_security.py (20 tests)
- TestTamperDetection (5)
- TestAuthenticationFailures (5)
- TestFrameMACSecurityInvariants (5)
- TestDuressSecurityInvariants (3)
- TestManifestParsingSecurityInvariants (2)

### test_adversarial.py (20 tests)
- TestFuzzingAttacks (5)
- TestFrameInjectionAttacks (4)
- TestReplayReorderingAttacks (4)
- TestConstantTimeOperations (4)
- TestMemoryZeroingAttacks (3)

### test_property_based.py (20 tests)
- TestEncryptDecryptInvariants (4)
- TestKeyDerivationInvariants (4)
- TestFountainCodeInvariants (4)
- TestManifestInvariants (4)
- TestFrameMACInvariants (4)

## 📈 Coverage by Module

| Module | Stmt Cov | Branch Cov | Total | Status |
|--------|----------|------------|-------|--------|
| frame_mac.py | 100% | 100% | 100% | ✅ |
| metadata_obfuscation.py | 100% | 100% | 100% | ✅ |
| x25519_forward_secrecy.py | 100% | 100% | 100% | ✅ |
| forward_secrecy_decoder.py | 100% | 100% | 100% | ✅ |
| forward_secrecy.py | 100% | 94% | 99% | ✅ |
| crypto_backend.py | 98% | 100% | 99% | ✅ |
| decode_gif.py | 100% | 93% | 98% | ✅ |
| crypto.py | 96% | 100% | 97% | 🔸 |
| gif_handler.py | 99% | 90% | 97% | 🔸 |
| constant_time.py | 99% | 88% | 96% | 🔸 |
| encode.py | 95% | 92% | 95% | 🔸 |
| forward_secrecy_encoder.py | 95% | 100% | 95% | 🔸 |
| config.py | 100% | 69% | 94% | 🔸 |
| fountain.py | 96% | 88% | 94% | 🔸 |
| forward_secrecy_x25519.py | 95% | 88% | 93% | 🟡 |
| qr_code.py | 96% | 76% | 92% | 🟡 |

## 🎯 Coverage Improvement Plan

### Phase 1: Get to 98% (Current Focus)
1. Add WebcamQRReader mock tests
2. Improve branch coverage for config.py
3. Add edge cases for fountain.py

### Phase 2: Get to 100%
1. Cover all exception paths
2. All branch conditions
3. Edge cases for all modules

## ✅ Test Run Commands

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=meow_decoder --cov-report=term-missing

# Run security tests only
pytest tests/test_security.py tests/test_adversarial.py tests/test_property_based.py -v

# Run specific module tests
pytest tests/test_crypto.py -v

# Run with HTML coverage report
pytest tests/ --cov=meow_decoder --cov-report=html
```

## 📝 Notes

- All tests require `MEOW_TEST_MODE=1` for fast key derivation
- Property-based tests use Hypothesis (may take 20-30s)
- Coverage HTML report in `htmlcov/index.html`
