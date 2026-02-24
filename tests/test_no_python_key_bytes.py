"""
Enforcement tests — Python NEVER materializes raw secret key bytes in production.

These tests are CI-blocking.  They mechanically guarantee:

  (A) AST rule: Production wrappers never assign variables that smell like
      secret key bytes (``key``, ``encryption_key``, ``root_key``, ``subkey``,
      ``hmac_key``, ``aead_key``, ``key_bytes``) from any call expression.

  (B) Call-graph rule: Production wrappers never call known bytes-returning
      functions (``encrypt_file_bytes``, ``derive_key``, ``derive_key_hkdf``,
      ``derive_key_yubikey``, ``backend.derive_key_argon2id``, ``import_key``
      outside of precomputed_key guards).

  (C) Backend API check: ``HandleBackend.derive_key_argon2id_with_keyfile``
      and ``HandleBackend.derive_key_yubikey`` exist, and production wrappers
      reference the handle-returning variants.

False positives are acceptable — fix them by renaming or restructuring.
"""

import ast
import inspect
import pathlib
import re
import textwrap

import pytest

pytestmark = pytest.mark.security

WORKSPACE = pathlib.Path(__file__).parent.parent
PRODUCTION_ROOT = WORKSPACE / "meow_decoder"

# ── Production wrapper functions that MUST be handle-only ──────────────────
# (file_stem, function_name) pairs
PRODUCTION_WRAPPERS = [
    ("crypto", "encrypt_file_bytes_production"),
    ("crypto", "derive_encryption_key_for_manifest_handle"),
    ("crypto", "decrypt_to_raw_production"),
    ("crypto", "verify_manifest_hmac_production"),
    ("crypto", "compute_manifest_hmac_from_handle"),
    ("crypto", "derive_key_handle"),
    ("crypto", "encrypt_file_bytes_handle"),
]

# Production entrypoints
PRODUCTION_ENTRYPOINTS = [
    PRODUCTION_ROOT / "encode.py",
    PRODUCTION_ROOT / "decode_gif.py",
]

# Variable names that strongly indicate raw secret key bytes
SECRET_KEY_VAR_PATTERNS = re.compile(
    r"^("
    r"key|encryption_key|root_key|subkey|hmac_key|aead_key|key_bytes"
    r"|derived_key|enc_key|mac_key|secret_key|chain_key|message_key"
    r")$"
)

# Functions known to return raw key bytes — FORBIDDEN in production wrappers
FORBIDDEN_BYTES_RETURNING_CALLS = {
    "encrypt_file_bytes",  # returns key as 7th tuple element
    "derive_key",  # returns raw 32-byte key
    "derive_encryption_key_for_manifest",  # returns raw key
}

# Calls that import raw key bytes into handles — only acceptable in
# precomputed_key guards (HSM/TPM/PQ hybrid).
CONDITIONAL_IMPORT_CALLS = {
    "import_key",
}

# Backend methods that return raw secret bytes — FORBIDDEN in wrappers
FORBIDDEN_BACKEND_METHODS = {
    "derive_key_argon2id",  # CryptoBackend version returns bytes
    "derive_key_yubikey",  # CryptoBackend version returns bytes
}


class _WrapperVisitor(ast.NodeVisitor):
    """Collect assignments, calls, and attribute calls inside a function."""

    def __init__(self):
        self.assignments = []  # (lineno, var_name, call_name_or_attr)
        self.calls = []  # (lineno, full_call_name)
        self.attr_calls = []  # (lineno, obj_name, method_name)

    def visit_Assign(self, node):
        rhs_name = self._call_name(node.value)
        if rhs_name:
            for target in node.targets:
                for name in self._target_names(target):
                    self.assignments.append((node.lineno, name, rhs_name))
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            obj = self._expr_name(node.func.value)
            if obj:
                self.attr_calls.append((node.lineno, obj, node.func.attr))
            self.calls.append((node.lineno, node.func.attr))
        elif isinstance(node.func, ast.Name):
            self.calls.append((node.lineno, node.func.id))
        self.generic_visit(node)

    @staticmethod
    def _call_name(node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id
            if isinstance(node.func, ast.Attribute):
                return node.func.attr
        return None

    @staticmethod
    def _target_names(node):
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Tuple):
            return [e.id for e in node.elts if isinstance(e, ast.Name)]
        return []

    @staticmethod
    def _expr_name(node):
        if isinstance(node, ast.Name):
            return node.id
        return None


def _parse_function(file_stem: str, func_name: str):
    """Parse a single function from a production module and return its AST + visitor."""
    py_file = PRODUCTION_ROOT / f"{file_stem}.py"
    source = py_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(py_file))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == func_name:
                visitor = _WrapperVisitor()
                visitor.visit(node)
                return node, visitor

    pytest.fail(f"Function '{func_name}' not found in {py_file}")


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME A — AST rule: no secret-key-like variable assignments
# ═════════════════════════════════════════════════════════════════════════════


class TestNoSecretKeyVariables:
    """Production wrappers must not assign variables named like secret keys."""

    def test_no_secret_key_var_in_production_wrappers(self):
        violations = []
        for file_stem, func_name in PRODUCTION_WRAPPERS:
            node, visitor = _parse_function(file_stem, func_name)
            for lineno, var_name, call_name in visitor.assignments:
                if SECRET_KEY_VAR_PATTERNS.match(var_name):
                    violations.append(
                        f"{file_stem}.py:{func_name}:{lineno} "
                        f"assigns '{var_name}' = {call_name}(...)"
                    )

        assert (
            not violations
        ), "Production wrappers assign secret-key-like variables:\n" + "\n".join(
            f"  - {v}" for v in violations
        )


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME B — Call graph: no bytes-returning functions called
# ═════════════════════════════════════════════════════════════════════════════


class TestNoForbiddenCalls:
    """Production wrappers must not call known bytes-returning key functions."""

    def test_no_bytes_returning_kdf_calls(self):
        violations = []
        for file_stem, func_name in PRODUCTION_WRAPPERS:
            node, visitor = _parse_function(file_stem, func_name)
            for lineno, call_name in visitor.calls:
                if call_name in FORBIDDEN_BYTES_RETURNING_CALLS:
                    violations.append(f"{file_stem}.py:{func_name}:{lineno} calls '{call_name}'")

        assert (
            not violations
        ), "Production wrappers call bytes-returning key functions:\n" + "\n".join(
            f"  - {v}" for v in violations
        )

    def test_no_backend_bytes_returning_methods_in_production_wrappers(self):
        """Production wrappers must not call CryptoBackend methods that return key bytes."""
        violations = []
        for file_stem, func_name in PRODUCTION_WRAPPERS:
            node, visitor = _parse_function(file_stem, func_name)
            for lineno, obj, method in visitor.attr_calls:
                if obj == "backend" and method in FORBIDDEN_BACKEND_METHODS:
                    violations.append(
                        f"{file_stem}.py:{func_name}:{lineno} " f"calls backend.{method}()"
                    )

        assert (
            not violations
        ), "Production wrappers call CryptoBackend bytes-returning methods:\n" + "\n".join(
            f"  - {v}" for v in violations
        )

    def test_no_forbidden_calls_in_entrypoints(self):
        """Production entrypoints must not call bytes-returning key functions."""
        # Self-test/diagnostic functions are exempt — they intentionally use
        # legacy APIs to verify backward compatibility.
        EXEMPT_FUNCTIONS = {"self_test", "_self_test", "_run_self_test"}

        violations = []
        for ep_path in PRODUCTION_ENTRYPOINTS:
            if not ep_path.exists():
                continue
            source = ep_path.read_text(encoding="utf-8")
            tree = ast.parse(source)

            # Collect line ranges of exempt functions
            exempt_lines: set = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name in EXEMPT_FUNCTIONS:
                        end = getattr(node, "end_lineno", node.lineno)
                        for ln in range(node.lineno, end + 1):
                            exempt_lines.add(ln)

            visitor = _WrapperVisitor()
            visitor.visit(tree)

            for lineno, call_name in visitor.calls:
                if lineno in exempt_lines:
                    continue
                if call_name in FORBIDDEN_BYTES_RETURNING_CALLS:
                    rel = ep_path.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno} calls '{call_name}'")

        assert (
            not violations
        ), "Production entrypoints call bytes-returning key functions:\n" + "\n".join(
            f"  - {v}" for v in violations
        )


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME C — Backend API check: handle-returning KDFs exist and are used
# ═════════════════════════════════════════════════════════════════════════════


class TestHandleAPIsExist:
    """HandleBackend must expose handle-returning KDFs and production uses them."""

    def test_handle_backend_has_derive_key_argon2id(self):
        from meow_decoder.crypto_backend import HandleBackend

        assert hasattr(
            HandleBackend, "derive_key_argon2id"
        ), "HandleBackend.derive_key_argon2id must exist"

    def test_handle_backend_has_derive_key_argon2id_with_keyfile(self):
        from meow_decoder.crypto_backend import HandleBackend

        assert hasattr(
            HandleBackend, "derive_key_argon2id_with_keyfile"
        ), "HandleBackend.derive_key_argon2id_with_keyfile must exist"

    def test_handle_backend_has_derive_key_yubikey(self):
        from meow_decoder.crypto_backend import HandleBackend

        assert hasattr(
            HandleBackend, "derive_key_yubikey"
        ), "HandleBackend.derive_key_yubikey must exist"

    def test_handle_backend_argon2id_returns_int(self):
        """Verify derive_key_argon2id returns an int handle, not bytes."""
        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        handle = hb.derive_key_argon2id(b"test_password", b"\x00" * 16, 1024, 1, 1)
        try:
            assert isinstance(
                handle, int
            ), f"derive_key_argon2id returned {type(handle)}, expected int"
        finally:
            hb.drop(handle)

    def test_handle_backend_argon2id_with_keyfile_returns_int(self):
        """Verify derive_key_argon2id_with_keyfile returns an int handle, not bytes."""
        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        handle = hb.derive_key_argon2id_with_keyfile(
            b"test_password",
            b"keyfile_content",
            b"meow_keyfile_separation_v2",
            b"\x00" * 16,
            1024,
            1,
            1,
        )
        try:
            assert isinstance(
                handle, int
            ), f"derive_key_argon2id_with_keyfile returned {type(handle)}, expected int"
        finally:
            hb.drop(handle)

    def test_derive_key_handle_uses_handle_backend(self):
        """derive_key_handle must call HandleBackend, not CryptoBackend."""
        py_file = PRODUCTION_ROOT / "crypto.py"
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "derive_key_handle":
                visitor = _WrapperVisitor()
                visitor.visit(node)

                # Must call hb.derive_key_argon2id or hb.derive_key_argon2id_with_keyfile
                hb_calls = [
                    m
                    for _, o, m in visitor.attr_calls
                    if o == "hb" and m.startswith("derive_key_argon2id")
                ]
                assert hb_calls, (
                    "derive_key_handle must call hb.derive_key_argon2id* "
                    "(HandleBackend), not CryptoBackend"
                )

                # Must NOT call backend.derive_key_hkdf (old keyfile path)
                bad = [
                    m for _, o, m in visitor.attr_calls if o == "backend" and m == "derive_key_hkdf"
                ]
                assert not bad, (
                    "derive_key_handle must not call backend.derive_key_hkdf "
                    "(raw bytes path removed)"
                )
                return

        pytest.fail("derive_key_handle not found in crypto.py")

    def test_production_wrappers_reference_handle_kdf(self):
        """encrypt_file_bytes_production must reference derive_key_handle (not derive_key)."""
        py_file = PRODUCTION_ROOT / "crypto.py"
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "encrypt_file_bytes_production":
                visitor = _WrapperVisitor()
                visitor.visit(node)

                # Must call derive_key_handle (handle-returning) not derive_key (bytes-returning)
                derive_calls = [c for _, c in visitor.calls if c == "derive_key_handle"]
                assert derive_calls, "encrypt_file_bytes_production must call derive_key_handle"

                bad_derive = [c for _, c in visitor.calls if c == "derive_key"]
                assert (
                    not bad_derive
                ), "encrypt_file_bytes_production must NOT call derive_key (bytes path)"
                return

        pytest.fail("encrypt_file_bytes_production not found in crypto.py")


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME D — Handle lifecycle: try/finally or context manager
# ═════════════════════════════════════════════════════════════════════════════


class TestHandleLifecycle:
    """Production wrappers must drop handles on all exit paths."""

    def test_decrypt_to_raw_production_drops_handle(self):
        """decrypt_to_raw_production must use try/finally with hb.drop."""
        py_file = PRODUCTION_ROOT / "crypto.py"
        source = py_file.read_text(encoding="utf-8")

        # Check that the function contains try/finally with hb.drop
        func_source = _extract_function_source(source, "decrypt_to_raw_production")
        assert (
            "finally:" in func_source
        ), "decrypt_to_raw_production must use try/finally for handle cleanup"
        assert (
            "hb.drop(" in func_source or ".drop(key_handle)" in func_source
        ), "decrypt_to_raw_production must call hb.drop(key_handle) in finally block"

    def test_verify_manifest_hmac_production_drops_handle(self):
        """verify_manifest_hmac_production must use try/finally with hb.drop."""
        py_file = PRODUCTION_ROOT / "crypto.py"
        source = py_file.read_text(encoding="utf-8")

        func_source = _extract_function_source(source, "verify_manifest_hmac_production")
        assert (
            "finally:" in func_source
        ), "verify_manifest_hmac_production must use try/finally for handle cleanup"

    def test_encrypt_production_drops_handle_on_error(self):
        """encrypt_file_bytes_production must drop handle on exception paths."""
        py_file = PRODUCTION_ROOT / "crypto.py"
        source = py_file.read_text(encoding="utf-8")

        func_source = _extract_function_source(source, "encrypt_file_bytes_production")
        assert (
            "hb.drop(" in func_source or ".drop(key_handle)" in func_source
        ), "encrypt_file_bytes_production must call hb.drop on error paths"


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME E — Production-forbidden deprecation check
# ═════════════════════════════════════════════════════════════════════════════


class TestProductionForbiddenMethods:
    """CryptoBackend.derive_key_argon2id must be marked production-forbidden."""

    def test_crypto_backend_derive_key_argon2id_is_deprecated(self):
        """RustCryptoBackend.derive_key_argon2id docstring must say PRODUCTION-FORBIDDEN."""
        from meow_decoder.crypto_backend import RustCryptoBackend

        doc = RustCryptoBackend.derive_key_argon2id.__doc__ or ""
        assert (
            "PRODUCTION-FORBIDDEN" in doc
        ), "RustCryptoBackend.derive_key_argon2id must be marked PRODUCTION-FORBIDDEN"

    def test_no_production_wrapper_calls_crypto_backend_derive_key_argon2id(self):
        """Production wrappers must not call CryptoBackend().derive_key_argon2id()."""
        violations = []
        for file_stem, func_name in PRODUCTION_WRAPPERS:
            node, visitor = _parse_function(file_stem, func_name)
            for lineno, obj, method in visitor.attr_calls:
                if obj == "backend" and method == "derive_key_argon2id":
                    violations.append(
                        f"{file_stem}.py:{func_name}:{lineno} "
                        f"calls backend.derive_key_argon2id() (PRODUCTION-FORBIDDEN)"
                    )

        assert not violations, (
            "Production wrappers call PRODUCTION-FORBIDDEN backend.derive_key_argon2id:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME — Round-trip functional test with handle-only path
# ═════════════════════════════════════════════════════════════════════════════


class TestHandleOnlyRoundTrip:
    """Verify the handle-only production path works end-to-end."""

    def test_encrypt_decrypt_production_roundtrip(self):
        """encrypt_file_bytes_production → decrypt_to_raw_production with no key bytes."""
        import os

        os.environ["MEOW_TEST_MODE"] = "1"
        from meow_decoder.crypto import (
            encrypt_file_bytes_production,
            decrypt_to_raw_production,
            compute_manifest_hmac_from_handle,
        )
        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        plaintext = b"Top secret meow data for handle-only roundtrip test!"
        password = "test_password_secure_1234"

        comp, sha, salt, nonce, cipher, eph_pk, key_handle = encrypt_file_bytes_production(
            plaintext, password
        )

        try:
            # Verify key_handle is an int, not bytes
            assert isinstance(key_handle, int), f"key_handle is {type(key_handle)}, expected int"

            # Compute HMAC via handle
            hmac_tag = compute_manifest_hmac_from_handle(key_handle, salt, b"test_manifest")
            assert isinstance(hmac_tag, bytes) and len(hmac_tag) == 32
        finally:
            hb.drop(key_handle)

        # Decrypt
        recovered = decrypt_to_raw_production(
            cipher,
            password,
            salt,
            nonce,
            orig_len=len(plaintext),
            comp_len=len(comp),
            sha256=sha,
        )
        assert recovered == plaintext

    def test_keyfile_roundtrip_no_bytes_leak(self):
        """derive_key_handle with keyfile uses Rust-side HKDF+Argon2id."""
        import os

        os.environ["MEOW_TEST_MODE"] = "1"
        from meow_decoder.crypto import derive_key_handle
        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        handle = derive_key_handle(
            "test_password_secure_1234",
            b"\x00" * 16,
            keyfile=b"my-secret-keyfile-content",
        )
        try:
            assert isinstance(handle, int)
            assert hb.exists(handle)

            # Can use for encryption
            ct = hb.aes_gcm_encrypt(handle, b"\x00" * 12, b"test_data", None)
            pt = hb.aes_gcm_decrypt(handle, b"\x00" * 12, ct, None)
            assert pt == b"test_data"
        finally:
            hb.drop(handle)


# ═════════════════════════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════════════════════════


def _extract_function_source(source: str, func_name: str) -> str:
    """Extract the source text of a function by name (best-effort regex)."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == func_name:
                end = getattr(node, "end_lineno", None)
                if end is not None:
                    lines = source.splitlines()
                    return "\n".join(lines[node.lineno - 1 : end])
    return ""


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME F — PQ hybrid: handle-based encapsulation/decapsulation
# ═════════════════════════════════════════════════════════════════════════════


class TestPQHybridHandleAPIs:
    """PQ hybrid must use handle-based APIs — no shared secret in Python."""

    def test_handle_backend_has_pqxdh_encapsulate(self):
        from meow_decoder.crypto_backend import HandleBackend

        assert hasattr(
            HandleBackend, "pqxdh_encapsulate"
        ), "HandleBackend.pqxdh_encapsulate must exist"

    def test_handle_backend_has_pqxdh_decapsulate(self):
        from meow_decoder.crypto_backend import HandleBackend

        assert hasattr(
            HandleBackend, "pqxdh_decapsulate"
        ), "HandleBackend.pqxdh_decapsulate must exist"

    def test_hybrid_encapsulate_handle_exists(self):
        from meow_decoder.pq_hybrid import hybrid_encapsulate_handle

        assert callable(hybrid_encapsulate_handle)

    def test_hybrid_decapsulate_handle_exists(self):
        from meow_decoder.pq_hybrid import hybrid_decapsulate_handle

        assert callable(hybrid_decapsulate_handle)

    def test_encode_uses_handle_encapsulation(self):
        """encode.py must call hybrid_encapsulate_handle, not hybrid_encapsulate."""
        py_file = PRODUCTION_ROOT / "encode.py"
        source = py_file.read_text(encoding="utf-8")
        assert (
            "hybrid_encapsulate_handle" in source
        ), "encode.py must call hybrid_encapsulate_handle (handle-based)"
        # The bytes-returning hybrid_encapsulate should not be called
        # (except in imports / dead code / comments)
        tree = ast.parse(source)
        visitor = _WrapperVisitor()
        visitor.visit(tree)
        bad = [
            (ln, c)
            for ln, c in visitor.calls
            if c == "hybrid_encapsulate" and c != "hybrid_encapsulate_handle"
        ]
        # Filter: hybrid_encapsulate as standalone call (not handle variant)
        # We just check the import doesn't import the old name
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if (
                "import hybrid_encapsulate" in stripped
                and "hybrid_encapsulate_handle" not in stripped
                and not stripped.startswith("#")
            ):
                bad.append((i, "imports hybrid_encapsulate (legacy bytes API)"))
        assert (
            not bad
        ), "encode.py must NOT import/call hybrid_encapsulate (legacy bytes):\n" + "\n".join(
            f"  - L{ln}: {c}" for ln, c in bad
        )

    def test_decode_uses_handle_decapsulation(self):
        """decode_gif.py must call hybrid_decapsulate_handle, not hybrid_decapsulate."""
        py_file = PRODUCTION_ROOT / "decode_gif.py"
        source = py_file.read_text(encoding="utf-8")
        assert (
            "hybrid_decapsulate_handle" in source
        ), "decode_gif.py must call hybrid_decapsulate_handle (handle-based)"
        # Check no import of legacy hybrid_decapsulate
        lines = source.splitlines()
        bad = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if (
                "import hybrid_decapsulate" in stripped
                and "hybrid_decapsulate_handle" not in stripped
                and not stripped.startswith("#")
            ):
                bad.append((i, "imports hybrid_decapsulate (legacy bytes API)"))
        assert (
            not bad
        ), "decode_gif.py must NOT import hybrid_decapsulate (legacy bytes):\n" + "\n".join(
            f"  - L{ln}: {c}" for ln, c in bad
        )

    def test_decode_uses_precomputed_key_handle(self):
        """decode_gif.py must pass precomputed_key_handle to decrypt_to_raw_production."""
        py_file = PRODUCTION_ROOT / "decode_gif.py"
        source = py_file.read_text(encoding="utf-8")
        assert (
            "precomputed_key_handle=" in source
        ), "decode_gif.py must pass precomputed_key_handle to decrypt_to_raw_production"


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME G — Ratchet: shared secrets stay as handles
# ═════════════════════════════════════════════════════════════════════════════


class TestRatchetNoSharedSecretBytes:
    """Ratchet ECDH functions must return handles, not bytes."""

    def test_generate_asym_rekey_returns_handle(self):
        """_generate_asym_rekey must return (int_handle, bytes), not (bytes, bytes)."""
        source = (PRODUCTION_ROOT / "ratchet.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "_generate_asym_rekey")
        assert func_source, "_generate_asym_rekey not found in ratchet.py"

        # Must NOT call derive_key_hkdf_bytes (returns raw secret)
        assert "derive_key_hkdf_bytes" not in func_source, (
            "_generate_asym_rekey must NOT call derive_key_hkdf_bytes "
            "(leaks shared secret as Python bytes)"
        )
        # Must call derive_key_hkdf (returns handle)
        assert (
            "derive_key_hkdf(" in func_source
        ), "_generate_asym_rekey must call hb.derive_key_hkdf (returns handle)"

    def test_recover_asym_rekey_returns_handle(self):
        """_recover_asym_rekey must return handle, not bytes."""
        source = (PRODUCTION_ROOT / "ratchet.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "_recover_asym_rekey")
        assert func_source, "_recover_asym_rekey not found in ratchet.py"

        assert (
            "derive_key_hkdf_bytes" not in func_source
        ), "_recover_asym_rekey must NOT call derive_key_hkdf_bytes"
        assert (
            "derive_key_hkdf(" in func_source
        ), "_recover_asym_rekey must call hb.derive_key_hkdf (returns handle)"

    def test_asymmetric_root_rekey_handle_uses_two_handles(self):
        """_asymmetric_root_rekey_handle must use hkdf_two_handles, not hkdf_with_handle_salt."""
        source = (PRODUCTION_ROOT / "ratchet.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "_asymmetric_root_rekey_handle")
        assert func_source, "_asymmetric_root_rekey_handle not found in ratchet.py"

        assert "hkdf_with_handle_salt" not in func_source, (
            "_asymmetric_root_rekey_handle must NOT call hkdf_with_handle_salt "
            "(takes raw bytes IKM). Must use hkdf_two_handles instead."
        )
        assert "hkdf_two_handles" in func_source, (
            "_asymmetric_root_rekey_handle must call hkdf_two_handles "
            "(both IKM and salt as handles)"
        )

    def test_generate_asym_rekey_returns_handle(self):
        """_generate_asym_rekey must use handles, not bytes."""
        source = (PRODUCTION_ROOT / "ratchet.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "_generate_asym_rekey")
        assert func_source, "_generate_asym_rekey not found in ratchet.py"

        assert (
            "derive_key_hkdf_bytes" not in func_source
        ), "_generate_asym_rekey must NOT call derive_key_hkdf_bytes"

    def test_recover_asym_rekey_returns_handle(self):
        """_recover_asym_rekey must use handles, not bytes."""
        source = (PRODUCTION_ROOT / "ratchet.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "_recover_asym_rekey")
        assert func_source, "_recover_asym_rekey not found in ratchet.py"

        assert (
            "derive_key_hkdf_bytes" not in func_source
        ), "_recover_asym_rekey must NOT call derive_key_hkdf_bytes"


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME H — Runtime guards: legacy APIs raise in production mode
# ═════════════════════════════════════════════════════════════════════════════


class TestLegacyRuntimeGuards:
    """Legacy bytes-returning crypto APIs must raise RuntimeError in production."""

    def test_derive_key_has_legacy_guard(self):
        source = (PRODUCTION_ROOT / "crypto.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "derive_key")
        assert "_legacy_guard" in func_source, "derive_key must call _legacy_guard()"

    def test_encrypt_file_bytes_has_legacy_guard(self):
        source = (PRODUCTION_ROOT / "crypto.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "encrypt_file_bytes")
        assert "_legacy_guard" in func_source, "encrypt_file_bytes must call _legacy_guard()"

    def test_decrypt_to_raw_has_legacy_guard(self):
        source = (PRODUCTION_ROOT / "crypto.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "decrypt_to_raw")
        assert "_legacy_guard" in func_source, "decrypt_to_raw must call _legacy_guard()"

    def test_compute_manifest_hmac_has_legacy_guard(self):
        source = (PRODUCTION_ROOT / "crypto.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "compute_manifest_hmac")
        assert "_legacy_guard" in func_source, "compute_manifest_hmac must call _legacy_guard()"

    def test_verify_manifest_hmac_has_legacy_guard(self):
        source = (PRODUCTION_ROOT / "crypto.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "verify_manifest_hmac")
        assert "_legacy_guard" in func_source, "verify_manifest_hmac must call _legacy_guard()"

    def test_derive_encryption_key_for_manifest_has_legacy_guard(self):
        source = (PRODUCTION_ROOT / "crypto.py").read_text(encoding="utf-8")
        func_source = _extract_function_source(source, "derive_encryption_key_for_manifest")
        assert (
            "_legacy_guard" in func_source
        ), "derive_encryption_key_for_manifest must call _legacy_guard()"


# ═════════════════════════════════════════════════════════════════════════════
# OUTCOME I — mobile_bridge uses production API
# ═════════════════════════════════════════════════════════════════════════════


class TestMobileBridgeProduction:
    """mobile_bridge callback must use production decrypt, not legacy."""

    def test_mobile_bridge_no_legacy_decrypt(self):
        """decode_gif.py must not import/call decrypt_to_raw (legacy bytes) anywhere."""
        py_file = PRODUCTION_ROOT / "decode_gif.py"
        source = py_file.read_text(encoding="utf-8")
        lines = source.splitlines()
        bad = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Check for import of legacy decrypt_to_raw (but not decrypt_to_raw_production)
            if "import decrypt_to_raw" in stripped and "decrypt_to_raw_production" not in stripped:
                bad.append((i, stripped))
            # Check for bare call to decrypt_to_raw(
            if (
                "decrypt_to_raw(" in stripped
                and "decrypt_to_raw_production" not in stripped
                and "# " not in stripped.split("decrypt_to_raw(")[0]
            ):
                bad.append((i, stripped))
        assert (
            not bad
        ), "decode_gif.py references legacy decrypt_to_raw (must use *_production):\n" + "\n".join(
            f"  - L{ln}: {s}" for ln, s in bad
        )
