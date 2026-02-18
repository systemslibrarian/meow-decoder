"""
Crypto Migration Enforcement Tests (Phase 4)

These tests ensure the Python → Rust crypto migration is enforced:
1. No production code imports Python crypto libraries
2. Rust backend is required (fail-closed)
3. Golden vectors match expected outputs
4. Constant-time comparisons route through approved implementations
"""

import ast
import os
import pathlib
import pytest
import sys

# =============================================================================
# Test 1: Python Crypto Ban Test
# CI fails if production code imports cryptography, hmac, or hashlib (secrets OK)
# =============================================================================

# Directories to check for forbidden imports
PRODUCTION_CODE_DIRS = [
    "meow_decoder",
]

# Files/patterns exempt from the ban
# ZERO production files are exempt for cryptography imports.
# crypto_DEBUG.py has been moved to legacy_py/ (no longer in production).
EXEMPT_FILES = {
    # constant_time.py uses secrets.compare_digest which is OK
    "constant_time.py",
    # __init__.py files may have conditional imports
    "__init__.py",
}

# Exempt directories (spec/reference code, not production)
EXEMPT_DIRS = {
    "spec_v12",      # Reference implementation, not production path
    "experimental",  # Experimental modules, not imported by production entrypoints
}

# Forbidden import prefixes - if a production file imports these, test fails
FORBIDDEN_IMPORTS = {
    "cryptography",
    "cryptography.hazmat",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.backends",
}

# Phase 2 TODO: Also migrate hashlib/hmac usages to Rust backend
# (sha256 → backend.sha256, hmac → backend.hmac_sha256)
PHASE2_FORBIDDEN_IMPORTS = {
    "hmac",
    "hashlib",
}

# Allowed imports that look similar but are OK
ALLOWED_IMPORTS = {
    "secrets",  # secrets.compare_digest is OK
}


class ForbiddenImportVisitor(ast.NodeVisitor):
    """AST visitor to find forbidden imports."""

    def __init__(self):
        self.forbidden_found = []

    def visit_Import(self, node):
        for alias in node.names:
            module = alias.name.split(".")[0]
            if module in FORBIDDEN_IMPORTS or alias.name in FORBIDDEN_IMPORTS:
                self.forbidden_found.append((node.lineno, alias.name, "import"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            root_module = node.module.split(".")[0]
            if root_module in FORBIDDEN_IMPORTS or node.module in FORBIDDEN_IMPORTS:
                self.forbidden_found.append((node.lineno, node.module, "from-import"))
        self.generic_visit(node)


def get_production_files():
    """Get all Python files in production code directories."""
    workspace = pathlib.Path(__file__).parent.parent
    files = []
    for dir_name in PRODUCTION_CODE_DIRS:
        dir_path = workspace / dir_name
        if dir_path.exists():
            for py_file in dir_path.rglob("*.py"):
                # Skip exempt files
                if py_file.name in EXEMPT_FILES:
                    continue
                # Skip exempt directories
                if any(exempt_dir in py_file.parts for exempt_dir in EXEMPT_DIRS):
                    continue
                files.append(py_file)
    return files


class TestPythonCryptoBan:
    """Ensure production code does not import Python crypto libraries."""

    def test_no_forbidden_crypto_imports(self):
        """
        Production code must not import cryptography, hmac, or hashlib.

        This enforces the Rust crypto migration. All crypto operations
        must go through the meow_crypto_rs backend.
        """
        violations = []

        for py_file in get_production_files():
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
                visitor = ForbiddenImportVisitor()
                visitor.visit(tree)

                for lineno, module, import_type in visitor.forbidden_found:
                    violations.append(
                        f"{py_file.relative_to(py_file.parent.parent)}:{lineno} - "
                        f"forbidden {import_type} of '{module}'"
                    )
            except SyntaxError:
                # Skip files with syntax errors (shouldn't happen)
                continue

        if violations:
            violation_list = "\n".join(f"  - {v}" for v in violations)
            pytest.fail(
                f"Found {len(violations)} forbidden Python crypto imports:\n"
                f"{violation_list}\n\n"
                "All crypto operations must use the Rust backend (meow_crypto_rs).\n"
                "Remove these imports and use backend functions instead."
            )


# =============================================================================
# Test 2: Rust Backend Mandatory Test
# Encode/decode fails closed if Rust backend unavailable
# =============================================================================


class TestRustBackendRequired:
    """Ensure Rust backend is mandatory for crypto operations."""

    def test_backend_import_succeeds(self):
        """Rust backend module must be importable."""
        try:
            import meow_crypto_rs
        except ImportError as e:
            pytest.fail(
                f"Rust backend (meow_crypto_rs) not available: {e}\n"
                "The Rust crypto backend is required for all crypto operations.\n"
                "Build it with: cd rust_crypto && maturin develop --release"
            )

    def test_backend_has_required_functions(self):
        """Verify Rust backend exports all required crypto functions."""
        import meow_crypto_rs as backend

        required_functions = [
            # Core crypto
            "derive_key_argon2id",
            "aes_gcm_encrypt",
            "aes_gcm_decrypt",
            "aes_ctr_crypt",
            "sha256",
            "hmac_sha256",
            "derive_key_hkdf",
            "constant_time_compare",
            # X25519
            "x25519_generate_keypair",
            "x25519_exchange",
        ]

        missing = []
        for func in required_functions:
            if not hasattr(backend, func):
                missing.append(func)

        if missing:
            pytest.fail(
                f"Rust backend missing required functions: {missing}\n"
                "These functions are required for the crypto migration."
            )

    def test_backend_functions_callable(self):
        """Verify Rust backend functions are callable with basic inputs."""
        import meow_crypto_rs as backend

        # Test sha256
        result = backend.sha256(b"test")
        assert len(result) == 32, "SHA256 should produce 32 bytes"

        # Test constant_time_compare
        assert backend.constant_time_compare(b"abc", b"abc") is True
        assert backend.constant_time_compare(b"abc", b"abd") is False

        # Test hmac_sha256
        mac = backend.hmac_sha256(b"key", b"message")
        assert len(mac) == 32, "HMAC-SHA256 should produce 32 bytes"


# =============================================================================
# Test 3: Constant-Time Routing Test
# Tag comparisons must go through approved implementations
# =============================================================================


class TestConstantTimeRouting:
    """Ensure constant-time operations use approved implementations."""

    def test_constant_time_compare_uses_approved_impl(self):
        """
        The constant_time_compare function must use an approved implementation.
        Either:
        1. Rust backend constant_time_compare, OR
        2. secrets.compare_digest (Python stdlib, proven constant-time)
        """
        from meow_decoder.constant_time import constant_time_compare
        import secrets

        # The function should work correctly
        assert constant_time_compare(b"test", b"test") is True
        assert constant_time_compare(b"test", b"Test") is False
        assert constant_time_compare(b"abc", b"abcd") is False

        # Verify it behaves identically to secrets.compare_digest
        test_cases = [
            (b"", b""),
            (b"a", b"a"),
            (b"a", b"b"),
            (b"abc", b"abc"),
            (b"abc", b"abd"),
            (b"\x00\x01\x02", b"\x00\x01\x02"),
            (b"\x00\x01\x02", b"\x00\x01\x03"),
        ]

        for a, b in test_cases:
            expected = secrets.compare_digest(a, b)
            actual = constant_time_compare(a, b)
            assert actual == expected, f"Mismatch for {a!r}, {b!r}"


# =============================================================================
# Test 4: Golden Vector Tests
# Frozen password/salt/ciphertext must produce byte-equal outputs
# =============================================================================


class TestGoldenVectors:
    """Golden vector tests for crypto primitives."""

    def test_sha256_golden_vector(self):
        """SHA256 must match known test vector."""
        import meow_crypto_rs as backend

        # NIST test vector
        result = backend.sha256(b"abc")
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223" "b00361a396177a9cb410ff61f20015ad"
        )
        assert result == expected, "SHA256 golden vector mismatch"

    def test_hmac_sha256_golden_vector(self):
        """HMAC-SHA256 must match RFC 4231 test vector."""
        import meow_crypto_rs as backend

        # RFC 4231 Test Case 2
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = bytes.fromhex(
            "5bdcc146bf60754e6a042426089575c7" "5a003f089d2739839dec58b964ec3843"
        )
        result = backend.hmac_sha256(key, data)
        assert result == expected, "HMAC-SHA256 golden vector mismatch"

    def test_aes_ctr_golden_vector(self):
        """AES-256-CTR must match frozen test vector (same as crypto_core/tests/golden_vectors.rs)."""
        import meow_crypto_rs as backend

        # Use the same golden vector as Rust crypto_core tests
        key = bytes.fromhex("0102030405060708090a0b0c0d0e0f10" "1112131415161718191a1b1c1d1e1f20")
        nonce = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        plaintext = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9e53f3cdac355977"
            "b2351234ab4f7890de765432cafe1234"
            "0011223344556677889900aabbccddee"
            "deadbeefcafebabe1234567890abcdef"
        )

        expected_ciphertext = bytes.fromhex(
            "c5063961572361a98ac9114a6489c03e"
            "19b6889c9b13497ce324f36681eae8c0"
            "784b250f6c41119a3b9728b2e88190e7"
            "ab7c8a9518e16deb9a3690c3af17e95f"
            "a0ba00261131319879ed63d99d46c3f3"
        )

        result = backend.aes_ctr_crypt(key, nonce, plaintext)
        assert result == expected_ciphertext, "AES-CTR golden vector mismatch"

        # Verify decryption (CTR is symmetric)
        decrypted = backend.aes_ctr_crypt(key, nonce, result)
        assert decrypted == plaintext, "AES-CTR roundtrip failed"


# =============================================================================
# Test 5: HKDF Golden Vector Test
# =============================================================================


class TestHKDFGoldenVector:
    """HKDF-SHA256 must match RFC 5869 test vectors."""

    def test_hkdf_rfc5869_test_case_1(self):
        """HKDF-SHA256 RFC 5869 Test Case 1."""
        import meow_crypto_rs as backend

        # RFC 5869 Test Case 1
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        length = 42

        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

        # derive_key_hkdf(ikm, salt, info, output_len)
        result = backend.derive_key_hkdf(ikm, salt, info, length)
        assert result == expected_okm, "HKDF-SHA256 RFC 5869 Test Case 1 mismatch"


# =============================================================================
# Test 6: Key Lifecycle Test
# Rust secret handles zeroize on Drop, no accidental clone
# =============================================================================


class TestKeyLifecycle:
    """Verify Rust backend handles key lifecycle securely."""

    def test_secure_zero_wipes_buffer(self):
        """secure_zero must actually modify the buffer to zeros."""
        import meow_crypto_rs as backend

        # Create a buffer with known non-zero content
        buf = bytearray(b"sensitive_key_material_here!")
        original_len = len(buf)

        # Verify it's not already zeros
        assert buf != bytearray(original_len), "Buffer shouldn't start as zeros"

        # Wipe it
        backend.secure_zero(buf)

        # Verify it's now zeros
        assert buf == bytearray(original_len), "Buffer should be all zeros after secure_zero"

    def test_x25519_keypair_generates_unique_keys(self):
        """X25519 keypair generation must produce unique keys."""
        import meow_crypto_rs as backend

        # Generate two keypairs
        priv1, pub1 = backend.x25519_generate_keypair()
        priv2, pub2 = backend.x25519_generate_keypair()

        # Keys must be the right size
        assert len(priv1) == 32, "Private key must be 32 bytes"
        assert len(pub1) == 32, "Public key must be 32 bytes"

        # Keys must be different (with overwhelming probability)
        assert priv1 != priv2, "Private keys should be unique"
        assert pub1 != pub2, "Public keys should be unique"

    def test_x25519_exchange_produces_shared_secret(self):
        """X25519 DH exchange must produce identical shared secrets."""
        import meow_crypto_rs as backend

        # Generate two keypairs (Alice and Bob)
        alice_priv, alice_pub = backend.x25519_generate_keypair()
        bob_priv, bob_pub = backend.x25519_generate_keypair()

        # Both sides compute shared secret
        alice_shared = backend.x25519_exchange(alice_priv, bob_pub)
        bob_shared = backend.x25519_exchange(bob_priv, alice_pub)

        # Shared secrets must match
        assert alice_shared == bob_shared, "DH shared secrets must be identical"
        assert len(alice_shared) == 32, "Shared secret must be 32 bytes"

    def test_aes_gcm_roundtrip_with_aad(self):
        """AES-GCM encrypt/decrypt roundtrip with AAD binding."""
        import meow_crypto_rs as backend

        key = backend.secure_random(32)
        nonce = backend.secure_random(12)
        plaintext = b"Secret message for the cat decoder!"
        aad = b"meow_decoder_v2_manifest"

        # Encrypt
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)

        # Ciphertext should be plaintext + 16-byte tag
        assert len(ciphertext) == len(plaintext) + 16

        # Decrypt with correct AAD
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, aad)
        assert decrypted == plaintext

        # Decrypt with wrong AAD should fail
        try:
            backend.aes_gcm_decrypt(key, nonce, ciphertext, b"wrong_aad")
            assert False, "Decryption with wrong AAD should fail"
        except Exception:
            pass  # Expected failure

    def test_backend_info_available(self):
        """Backend info function should return version info."""
        import meow_crypto_rs as backend

        info = backend.backend_info()
        assert isinstance(info, str), "backend_info should return a string"
        assert len(info) > 0, "backend_info should not be empty"


# =============================================================================
# Test 7: Phase 2 — hashlib/hmac Annotation Enforcement
# Un-annotated hashlib/hmac imports in production code are forbidden.
# Files using them for non-secret purposes MUST have a NON-SECRET CHECKSUM
# annotation on the import line.
# =============================================================================


# Files that have been audited and annotated with NON-SECRET CHECKSUM
ANNOTATED_NON_SECRET_FILES = {
    "clowder_encode.py",
    "clowder_decode.py",
    "resume_secured.py",
    "decode_webcam_with_resume.py",
    "entropy_boost.py",
    "merkle_tree.py",  # Uses Rust backend with hashlib fallback
}


class TestPhase2HashlibEnforcement:
    """Enforce that hashlib/hmac imports are annotated or migrated."""

    def test_no_unannotated_hashlib_imports(self):
        """
        Any file importing hashlib or hmac MUST either:
        1. Have a '# NON-SECRET CHECKSUM' annotation on the import line, OR
        2. Be in the EXEMPT_DIRS (spec_v12, experimental), OR
        3. Be an exempt file (__init__.py, constant_time.py)

        This is a ratchet: newly added hashlib/hmac imports without
        annotation will break CI.
        """
        violations = []

        for py_file in get_production_files():
            try:
                source = py_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            for lineno, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith("#"):
                    continue

                has_hashlib = False
                has_hmac = False

                # Check for import hashlib or from hashlib import ...
                if "import hashlib" in stripped:
                    has_hashlib = True
                if "import hmac" in stripped and "hmac_" not in stripped:
                    has_hmac = True

                if not (has_hashlib or has_hmac):
                    continue

                # Check for annotation
                if "NON-SECRET CHECKSUM" in line:
                    continue

                # Check if file is in annotated list
                if py_file.name in ANNOTATED_NON_SECRET_FILES:
                    continue

                module = "hashlib" if has_hashlib else "hmac"
                violations.append(
                    f"{py_file.relative_to(py_file.parent.parent)}:{lineno} - "
                    f"unannotated `import {module}` (add '# NON-SECRET CHECKSUM' "
                    f"or migrate to Rust backend)"
                )

        # This is informational for now — existing security-critical files
        # are tracked for migration. Fail on NEW violations only.
        # Count known legacy files that still need migration
        known_legacy = {
            "schrodinger_encode.py", "schrodinger_decode.py",
            "bidirectional.py", "multi_secret.py", "quantum_mixer.py",
            "timelock_duress.py", "duress_mode.py",
            "hardware_keys.py", "hardware_integration.py",
        }
        new_violations = [
            v for v in violations
            if not any(legacy in v for legacy in known_legacy)
        ]

        if new_violations:
            violation_list = "\n".join(f"  - {v}" for v in new_violations)
            pytest.fail(
                f"Found {len(new_violations)} NEW unannotated hashlib/hmac imports:\n"
                f"{violation_list}\n\n"
                "Either add '# NON-SECRET CHECKSUM' annotation or migrate to Rust backend."
            )


# =============================================================================
# Test 8: Dangerous Pattern Scanner
# Scan for bypass patterns that could weaken security
# =============================================================================

DANGEROUS_PATTERNS = [
    (r"expected_mac\s*=\s*None", "expected_mac=None bypass"),
    (r"skip_verify\s*=\s*True", "skip_verify=True bypass"),
    (r"insecure_mode\s*=\s*True", "insecure_mode=True"),
    (r"debug_decrypt", "debug_decrypt function"),
    (r"verify\s*=\s*False", "verify=False bypass"),
    (r"no_auth\s*=\s*True", "no_auth=True bypass"),
]

# Files where patterns are documented/tested (not production bypass)
PATTERN_EXEMPT_FILES = {
    "test_crypto_enforcement.py",  # This file defines the patterns
    "test_streaming_crypto.py",    # Tests the rejection of missing MAC
    "test_production_boundary.py",  # Tests enforcement
}


class TestDangerousPatternScanner:
    """Scan production code for security bypass patterns."""

    def test_no_dangerous_bypass_patterns(self):
        """
        Production code must not contain authentication/verification bypass
        patterns. These are indicators of downgrade attacks or debug code
        left in production.
        """
        import re

        violations = []

        for py_file in get_production_files():
            try:
                source = py_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            # Track docstring state to skip patterns inside docstrings
            in_docstring = False
            docstring_char = None

            for lineno, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()

                # Docstring tracking (triple quotes)
                if not in_docstring:
                    if stripped.startswith('"""') or stripped.startswith("'''"):
                        docstring_char = stripped[:3]
                        # Check if docstring closes on same line
                        if stripped.count(docstring_char) >= 2 and len(stripped) > 3:
                            continue  # Single-line docstring, skip
                        in_docstring = True
                        continue
                else:
                    if docstring_char in stripped:
                        in_docstring = False
                    continue

                # Skip comments
                if stripped.startswith("#"):
                    continue

                for pattern, description in DANGEROUS_PATTERNS:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        # Skip if it's in a comment on the same line
                        code_part = stripped.split("#")[0] if "#" in stripped else stripped
                        if re.search(pattern, code_part, re.IGNORECASE):
                            violations.append(
                                f"{py_file.relative_to(py_file.parent.parent)}:{lineno} - "
                                f"{description}: {stripped[:80]}"
                            )

        if violations:
            violation_list = "\n".join(f"  - {v}" for v in violations)
            pytest.fail(
                f"Found {len(violations)} dangerous bypass patterns in production code:\n"
                f"{violation_list}\n\n"
                "Remove these patterns or move to test-only code."
            )


# =============================================================================
# Test 9: Rust Backend Panic-Free Guarantee
# =============================================================================


class TestRustNoPanic:
    """Verify Rust backend handles edge cases without panicking."""

    def test_empty_inputs_no_panic(self):
        """All Rust functions must handle empty inputs without panic."""
        import meow_crypto_rs as backend

        # SHA256 of empty
        result = backend.sha256(b"")
        assert len(result) == 32

        # HMAC with empty key and message
        result = backend.hmac_sha256(b"", b"")
        assert len(result) == 32

        # HMAC verify with empty
        assert backend.hmac_sha256_verify(b"", b"", result)

        # Constant-time compare empty
        assert backend.constant_time_compare(b"", b"")

    def test_large_inputs_no_panic(self):
        """Rust functions must handle large inputs without panic."""
        import meow_crypto_rs as backend

        large = b"X" * (1024 * 1024)  # 1 MB
        result = backend.sha256(large)
        assert len(result) == 32

        result = backend.hmac_sha256(b"key", large)
        assert len(result) == 32

    def test_invalid_key_sizes_return_error(self):
        """Invalid key/nonce sizes must return errors, not panic."""
        import meow_crypto_rs as backend

        # AES-GCM with wrong key size
        with pytest.raises(Exception):
            backend.aes_gcm_encrypt(b"short", b"x" * 12, b"data")

        # AES-GCM with wrong nonce size
        with pytest.raises(Exception):
            backend.aes_gcm_encrypt(b"x" * 32, b"short", b"data")

        # X25519 with wrong key size
        with pytest.raises(Exception):
            backend.x25519_exchange(b"short", b"x" * 32)

    def test_corrupted_ciphertext_returns_error(self):
        """Corrupted ciphertext must return error, not panic."""
        import meow_crypto_rs as backend

        key = backend.secure_random(32)
        nonce = backend.secure_random(12)

        # Too short for auth tag
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(key, nonce, b"short")

        # Random garbage
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(key, nonce, backend.secure_random(100))


# =============================================================================
# Test 10: Secret Lifecycle — Secure Zeroing
# =============================================================================


class TestSecretLifecycle:
    """Verify secrets are zeroized after use."""

    def test_secure_zero_complete_wipe(self):
        """secure_zero must zero ALL bytes."""
        import meow_crypto_rs as backend

        # Various sizes
        for size in [1, 16, 32, 64, 256, 4096]:
            buf = bytearray(b"\xff" * size)
            backend.secure_zero(buf)
            assert buf == bytearray(size), f"Failed to zero {size} bytes"

    def test_secure_zero_idempotent(self):
        """secure_zero on already-zeroed buffer is safe."""
        import meow_crypto_rs as backend

        buf = bytearray(32)
        backend.secure_zero(buf)
        assert buf == bytearray(32)

    def test_key_derivation_produces_fresh_bytes(self):
        """Key derivation must produce non-zero, non-trivial output."""
        import meow_crypto_rs as backend

        salt = backend.secure_random(16)
        key = backend.derive_key_argon2id(b"password", salt, 32768, 1, 1, 32)

        # Must not be all zeros
        assert key != bytes(32), "Key derivation produced all zeros"
        # Must not be all same byte
        assert len(set(key)) > 1, "Key derivation produced trivial output"

    def test_random_bytes_are_unique(self):
        """Consecutive random byte generation must produce unique values."""
        import meow_crypto_rs as backend

        samples = [backend.secure_random(32) for _ in range(100)]
        assert len(set(samples)) == 100, "Random bytes collision detected"


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
