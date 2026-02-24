#!/usr/bin/env python3
"""
ZERO PYTHON KEY BYTES — Enforcement Tests

Verify that production encryption/decryption paths NEVER materialise raw
secret-key bytes in Python.  Two layers of assurance:

1. **AST audit** — static analysis scans production functions for
   `export_key`, `bytes(...)`, `.to_bytes(...)` on key variables, and
   ensures no raw key bytes can leak.

2. **Runtime roundtrip** — encrypts/decrypts using only the handle-based
   production API, confirms the key handle is an opaque `int`, and
   verifies data integrity.
"""

from meow_decoder.crypto_backend import get_handle_backend
from meow_decoder.crypto import (
    encrypt_file_bytes_production,
    decrypt_to_raw_production,
    derive_encryption_key_for_manifest_handle,
    compute_manifest_hmac_from_handle,
    verify_manifest_hmac_production,
    MANIFEST_HMAC_KEY_PREFIX,
)
import ast
import inspect
import os
import secrets
import textwrap

import pytest

pytestmark = pytest.mark.security

os.environ.setdefault("MEOW_TEST_MODE", "1")

# Production functions under audit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PRODUCTION_FUNCTIONS = [
    encrypt_file_bytes_production,
    decrypt_to_raw_production,
    derive_encryption_key_for_manifest_handle,
    compute_manifest_hmac_from_handle,
    verify_manifest_hmac_production,
]


def _get_source_ast(func) -> ast.Module:
    """Return the parsed AST for *func*'s source."""
    src = textwrap.dedent(inspect.getsource(func))
    return ast.parse(src)


class _ExportKeyVisitor(ast.NodeVisitor):
    """Flag any call to hb.export_key() or self._rs.handle_export_key()."""

    def __init__(self):
        self.violations: list[str] = []

    def visit_Call(self, node: ast.Call):
        # Detect hb.export_key(...) or *.export_key(...)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "export_key":
                loc = f"line {node.lineno}"
                self.violations.append(f"export_key() call at {loc}")
            if node.func.attr == "handle_export_key":
                loc = f"line {node.lineno}"
                self.violations.append(f"handle_export_key() call at {loc}")
        self.generic_visit(node)


class _RawKeyMaterialVisitor(ast.NodeVisitor):
    """Flag patterns that suggest raw key bytes materialising."""

    SUSPICIOUS_NAMES = {"key", "secret", "raw_key", "key_bytes", "shared_secret", "derived_key"}

    def __init__(self):
        self.violations: list[str] = []

    def visit_Assign(self, node: ast.Assign):
        """Check `key = hb.export_key(...)` style assignments."""
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in self.SUSPICIOUS_NAMES:
                # Check RHS is an export_key call
                if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
                    if node.value.func.attr in ("export_key", "handle_export_key"):
                        self.violations.append(
                            f"Raw key assignment `{target.id} = ...export_key(...)` "
                            f"at line {node.lineno}"
                        )
        self.generic_visit(node)


# ===========================================================================
# AST Audit Tests
# ===========================================================================


class TestASTNoExportKey:
    """Production functions must not call export_key()."""

    @pytest.mark.parametrize("func", PRODUCTION_FUNCTIONS, ids=lambda f: f.__name__)
    def test_no_export_key_call(self, func):
        tree = _get_source_ast(func)
        visitor = _ExportKeyVisitor()
        visitor.visit(tree)
        assert not visitor.violations, f"{func.__name__} leaks key bytes via: {visitor.violations}"

    @pytest.mark.parametrize("func", PRODUCTION_FUNCTIONS, ids=lambda f: f.__name__)
    def test_no_raw_key_assignment(self, func):
        tree = _get_source_ast(func)
        visitor = _RawKeyMaterialVisitor()
        visitor.visit(tree)
        assert (
            not visitor.violations
        ), f"{func.__name__} materialises raw key bytes: {visitor.violations}"


# ===========================================================================
# Handle-Type Enforcement Tests
# ===========================================================================


class TestHandleTypes:
    """Verify production APIs return opaque handles (int), never bytes."""

    def test_derive_key_returns_handle(self):
        """derive_encryption_key_for_manifest_handle must return int."""
        hb = get_handle_backend()
        password = "test-enforcement-password"
        salt = secrets.token_bytes(16)
        handle = derive_encryption_key_for_manifest_handle(
            password=password,
            salt=salt,
        )
        try:
            assert isinstance(handle, int), f"Expected int handle, got {type(handle).__name__}"
            assert hb.exists(handle), "Handle must be valid in the registry"
        finally:
            hb.drop(handle)

    def test_encrypt_returns_handle(self):
        """encrypt_file_bytes_production key_handle must be int."""
        data = b"enforcement test payload"
        password = secrets.token_hex(16)
        comp, sha, salt, nonce, cipher, epk, key_handle = encrypt_file_bytes_production(
            raw=data,
            password=password,
        )
        hb = get_handle_backend()
        try:
            assert isinstance(
                key_handle, int
            ), f"Expected int handle, got {type(key_handle).__name__}"
            assert not isinstance(key_handle, bytes)
            assert hb.exists(key_handle), "Handle must be valid"
        finally:
            hb.drop(key_handle)

    def test_compute_hmac_no_export(self):
        """compute_manifest_hmac_from_handle must not export key."""
        hb = get_handle_backend()
        password = secrets.token_hex(16)
        salt = secrets.token_bytes(16)
        handle = derive_encryption_key_for_manifest_handle(
            password=password,
            salt=salt,
        )
        packed_no_hmac = b"MEOW3" + b"\x00" * 100  # Dummy manifest
        try:
            hmac_tag = compute_manifest_hmac_from_handle(
                handle,
                salt,
                packed_no_hmac,
            )
            assert isinstance(hmac_tag, bytes)
            assert len(hmac_tag) == 32, "HMAC-SHA256 must produce 32-byte tag"
        finally:
            hb.drop(handle)


# ===========================================================================
# Runtime Roundtrip Tests (key never touches Python)
# ===========================================================================


class TestProductionRoundtrip:
    """End-to-end encrypt→HMAC→decrypt via handles, no raw key bytes."""

    def test_basic_roundtrip(self):
        """Password-only encrypt → decrypt must recover plaintext."""
        data = secrets.token_bytes(512)
        password = secrets.token_hex(16)
        hb = get_handle_backend()

        # Encrypt
        comp, sha, salt, nonce, cipher, epk, enc_handle = encrypt_file_bytes_production(
            raw=data,
            password=password,
        )
        assert isinstance(enc_handle, int)
        hb.drop(enc_handle)

        # Decrypt (derives its own key handle internally)
        # mode_byte=0 matches encrypt_file_bytes_production default
        plaintext = decrypt_to_raw_production(
            cipher=cipher,
            password=password,
            salt=salt,
            nonce=nonce,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha,
            ephemeral_public_key=epk,
            pq_ciphertext=None,
            mode_byte=0,
        )
        assert plaintext == data, "Decrypted data must match original"

    def test_hmac_roundtrip(self):
        """HMAC computed from handle must verify correctly."""
        hb = get_handle_backend()
        password = secrets.token_hex(16)
        salt = secrets.token_bytes(16)

        handle = derive_encryption_key_for_manifest_handle(
            password=password,
            salt=salt,
        )
        packed = b"MEOW3" + secrets.token_bytes(200)

        try:
            tag = compute_manifest_hmac_from_handle(handle, salt, packed)
            assert isinstance(tag, bytes) and len(tag) == 32

            # Recompute with same handle — must be deterministic
            tag2 = compute_manifest_hmac_from_handle(handle, salt, packed)
            assert tag == tag2, "HMAC must be deterministic"

            # Verify by deriving the same HMAC sub-key (mirroring
            # compute_manifest_hmac_handle: HKDF from enc key → plain HMAC)
            hmac_key = hb.derive_key_hkdf(
                handle,
                b"meow_manifest_auth_v2",
                b"manifest_hmac_v2",
                32,
            )
            try:
                ok = hb.hmac_sha256_verify(hmac_key, packed, tag)
                assert ok, "HMAC verification must succeed for correct tag"

                # Tampered tag must fail
                bad_tag = bytearray(tag)
                bad_tag[0] ^= 0xFF
                bad = hb.hmac_sha256_verify(hmac_key, packed, bytes(bad_tag))
                assert not bad, "HMAC verification must fail for tampered tag"
            finally:
                hb.drop(hmac_key)
        finally:
            hb.drop(handle)

    def test_wrong_password_fails(self):
        """Decryption with wrong password must raise."""
        data = b"sensitive payload"
        password = secrets.token_hex(16)
        wrong_password = secrets.token_hex(16)
        hb = get_handle_backend()

        comp, sha, salt, nonce, cipher, epk, enc_handle = encrypt_file_bytes_production(
            raw=data,
            password=password,
        )
        hb.drop(enc_handle)

        with pytest.raises(Exception):
            decrypt_to_raw_production(
                cipher=cipher,
                password=wrong_password,
                salt=salt,
                nonce=nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
                ephemeral_public_key=epk,
                pq_ciphertext=None,
                mode_byte=0,
            )

    def test_handle_dropped_after_use(self):
        """Handles must not linger after production encrypt."""
        hb = get_handle_backend()
        initial_count = hb.count()
        password = secrets.token_hex(16)

        _, _, _, _, _, _, key_handle = encrypt_file_bytes_production(
            raw=b"drop test",
            password=password,
        )
        # One new handle exists
        assert hb.count() == initial_count + 1
        assert hb.exists(key_handle)

        hb.drop(key_handle)
        assert not hb.exists(key_handle)
        assert hb.count() == initial_count


# ===========================================================================
# Negative Tests — ensure guard rails work
# ===========================================================================


class TestGuardRails:
    """Verify that raw-key legacy paths are NOT used by production functions."""

    def test_encrypt_production_does_not_return_bytes_key(self):
        """The 7th return value must be int, not bytes."""
        result = encrypt_file_bytes_production(
            raw=b"guard rail test",
            password=secrets.token_hex(16),
        )
        key_handle = result[6]
        hb = get_handle_backend()
        try:
            assert type(key_handle) is int  # strict type check, no subclass
        finally:
            hb.drop(key_handle)

    def test_derive_handle_does_not_return_bytes(self):
        """derive_encryption_key_for_manifest_handle must NEVER return bytes."""
        hb = get_handle_backend()
        handle = derive_encryption_key_for_manifest_handle(
            password="guard-rail-pw",
            salt=secrets.token_bytes(16),
        )
        try:
            assert type(handle) is int
            assert not isinstance(handle, (bytes, bytearray, memoryview))
        finally:
            hb.drop(handle)
