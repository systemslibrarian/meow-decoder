"""
Fail-Closed Enforcement Tests — Rust Owns Secrets

These tests mechanically guarantee the following invariants:

1. legacy_py/ does not exist in the repository.
2. No production code imports legacy_py.
3. Production entrypoints (encode.py, decode_gif.py) never call key-returning
   APIs that leak raw key bytes into Python.
4. No production module exposes key-returning symbols in its public interface.

All tests are CI-blocking.  Any failure MUST fail the PR.
"""

import ast
import os
import pathlib
import re
import sys

import pytest

WORKSPACE = pathlib.Path(__file__).parent.parent
PRODUCTION_ROOT = WORKSPACE / "meow_decoder"

# Directories excluded from production scanning
EXCLUDED_DIRS = {"_testonly", "experimental", "__pycache__"}

# Production entrypoints that MUST NOT hold raw key bytes
PRODUCTION_ENTRYPOINTS = [
    PRODUCTION_ROOT / "encode.py",
    PRODUCTION_ROOT / "decode_gif.py",
]

# Self-test / diagnostic functions allowed to use raw APIs (pragma: no cover)
SELF_TEST_FUNCTION_NAMES = {"_run_self_test"}

# Functions that return raw key bytes — FORBIDDEN in production call graph
FORBIDDEN_KEY_RETURNING_CALLS = {
    "derive_key",
    "encrypt_file_bytes",           # returns key as 7th tuple element
    "derive_encryption_key_for_manifest",
}

# Symbols that, if exported from production modules, indicate raw-key leakage
FORBIDDEN_EXPORT_PATTERNS = [
    re.compile(r"^derive_key$"),
    re.compile(r"^derive_encryption_key_for_manifest$"),
]

# Imports that MUST appear in production entrypoints (handle-based APIs)
REQUIRED_HANDLE_IMPORTS = {
    "encode.py": [
        "encrypt_file_bytes_production",
        "compute_manifest_hmac_from_handle",
    ],
    "decode_gif.py": [
        "decrypt_to_raw_production",
        "derive_encryption_key_for_manifest_handle",
    ],
}


def _get_production_files():
    """Get all .py files under meow_decoder/ minus exclusions."""
    files = []
    for py_file in PRODUCTION_ROOT.rglob("*.py"):
        rel_parts = py_file.relative_to(PRODUCTION_ROOT).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        files.append(py_file)
    return sorted(files)


class _CallVisitor(ast.NodeVisitor):
    """AST visitor collecting function calls and imports."""

    def __init__(self):
        self.calls = []       # (lineno, func_name)
        self.imports = []     # (lineno, module_path)
        self.assignments = []  # (lineno, target_name, rhs_call_name)

    def visit_Call(self, node):
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name:
            self.calls.append((node.lineno, name))
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append((node.lineno, alias.name))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.append((node.lineno, node.module))
            for alias in node.names:
                full = f"{node.module}.{alias.name}" if node.module else alias.name
                self.imports.append((node.lineno, full))
        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            call_name = None
            if isinstance(node.value.func, ast.Name):
                call_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                call_name = node.value.func.attr
            if call_name:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.assignments.append((node.lineno, target.id, call_name))
                    elif isinstance(target, ast.Tuple):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                self.assignments.append((node.lineno, elt.id, call_name))
        self.generic_visit(node)


# ═══════════════════════════════════════════════════════════════════════════════
# OUTCOME 1 — No legacy_py/ in repository
# ═══════════════════════════════════════════════════════════════════════════════


class TestLegacyPyRemoved:
    """Enforces that legacy_py/ directory does not exist."""

    def test_legacy_py_removed(self):
        """legacy_py/ must not exist in the repository."""
        legacy_dir = WORKSPACE / "legacy_py"
        assert not legacy_dir.exists(), (
            f"legacy_py/ still exists at {legacy_dir}. "
            "Delete it with `git rm -r legacy_py` — no downgrade paths allowed."
        )

    def test_no_legacy_imports(self):
        """No production code may import legacy_py."""
        violations = []
        for py_file in _get_production_files():
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue

            visitor = _CallVisitor()
            visitor.visit(tree)

            for lineno, module in visitor.imports:
                if "legacy_py" in module:
                    rel = py_file.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno} imports '{module}'")

        assert not violations, (
            "Production code imports legacy_py:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_packaging_excludes_legacy_py(self):
        """pyproject.toml must exclude legacy_py from packaging."""
        pyproject_path = WORKSPACE / "pyproject.toml"
        content = pyproject_path.read_text()
        # Must NOT include legacy_py in packages
        assert "legacy_py" not in content.split("include = ")[1].split("]")[0] if "include = " in content else True, (
            "pyproject.toml includes legacy_py in shipped packages"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# OUTCOME 2 — Production uses handle-only crypto (no key bytes in Python)
# ═══════════════════════════════════════════════════════════════════════════════


class TestNoKeyBytesInProduction:
    """Enforce that production entrypoints never call key-returning APIs."""

    def test_no_key_bytes_api_used_in_production(self):
        """Production entrypoints must not call functions that return raw key bytes.

        Self-test functions (e.g. _run_self_test) are excluded because they
        intentionally exercise raw APIs for diagnostics and are never part of
        the production data path.
        """
        violations = []
        for ep_path in PRODUCTION_ENTRYPOINTS:
            if not ep_path.exists():
                continue
            source = ep_path.read_text(encoding="utf-8")
            tree = ast.parse(source)

            # Collect line ranges of self-test functions to exclude
            selftest_ranges = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name in SELF_TEST_FUNCTION_NAMES:
                    end = getattr(node, "end_lineno", node.lineno + 999)
                    selftest_ranges.add((node.lineno, end))

            def _in_selftest(lineno):
                return any(start <= lineno <= end for start, end in selftest_ranges)

            visitor = _CallVisitor()
            visitor.visit(tree)

            for lineno, func_name in visitor.calls:
                if func_name in FORBIDDEN_KEY_RETURNING_CALLS and not _in_selftest(lineno):
                    rel = ep_path.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno} calls '{func_name}'")

            # Also check for direct imports of forbidden functions
            for lineno, module in visitor.imports:
                if _in_selftest(lineno):
                    continue
                parts = module.rsplit(".", 1)
                imported_name = parts[-1] if len(parts) > 1 else parts[0]
                if imported_name in FORBIDDEN_KEY_RETURNING_CALLS:
                    rel = ep_path.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno} imports '{imported_name}'")

        assert not violations, (
            "Production entrypoints use key-returning APIs (Rule #2 violation):\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_no_encryption_key_variable_in_entrypoints(self):
        """Production entrypoints must not assign to 'encryption_key' variable."""
        violations = []
        for ep_path in PRODUCTION_ENTRYPOINTS:
            if not ep_path.exists():
                continue
            source = ep_path.read_text(encoding="utf-8")
            tree = ast.parse(source)

            visitor = _CallVisitor()
            visitor.visit(tree)

            for lineno, target_name, call_name in visitor.assignments:
                if target_name == "encryption_key":
                    rel = ep_path.relative_to(WORKSPACE)
                    violations.append(
                        f"{rel}:{lineno} assigns encryption_key = {call_name}(...)"
                    )

        assert not violations, (
            "Production entrypoints hold raw key bytes in 'encryption_key' variable:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_handle_apis_used_in_entrypoints(self):
        """Production entrypoints must import handle-based APIs."""
        for ep_name, required_imports in REQUIRED_HANDLE_IMPORTS.items():
            ep_path = PRODUCTION_ROOT / ep_name
            if not ep_path.exists():
                continue
            source = ep_path.read_text(encoding="utf-8")
            tree = ast.parse(source)

            visitor = _CallVisitor()
            visitor.visit(tree)

            imported_names = set()
            for _, module in visitor.imports:
                parts = module.rsplit(".", 1)
                imported_names.add(parts[-1] if len(parts) > 1 else parts[0])

            for req in required_imports:
                assert req in imported_names, (
                    f"{ep_name} does not import handle-based API '{req}'. "
                    f"Production must use handle-only crypto."
                )

    def test_no_key_returning_symbols_in_production_exports(self):
        """Production modules must not expose key-returning symbols in __all__."""
        violations = []
        for py_file in _get_production_files():
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "__all__":
                            if isinstance(node.value, (ast.List, ast.Tuple)):
                                for elt in node.value.elts:
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                        for pat in FORBIDDEN_EXPORT_PATTERNS:
                                            if pat.match(elt.value):
                                                rel = py_file.relative_to(WORKSPACE)
                                                violations.append(
                                                    f"{rel}:{node.lineno} exports '{elt.value}'"
                                                )

        # If __all__ is not used (common in this codebase), do a def-scan
        # for forbidden function definitions at module level
        for py_file in _get_production_files():
            name = py_file.stem
            # Skip crypto library modules — they legitimately define key
            # derivation functions. Enforcement is on ENTRYPOINTS not calling them.
            if name in ("crypto", "crypto_enhanced", "crypto_backend", "crypto_hsm"):
                continue
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    for pat in FORBIDDEN_EXPORT_PATTERNS:
                        if pat.match(node.name):
                            rel = py_file.relative_to(WORKSPACE)
                            violations.append(
                                f"{rel}:{node.lineno} defines '{node.name}'"
                            )

        assert not violations, (
            "Production modules expose key-returning symbols:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )


# ═══════════════════════════════════════════════════════════════════════════════
# OUTCOME 3 — Static scan for suspicious key-byte patterns
# ═══════════════════════════════════════════════════════════════════════════════


class TestStaticKeyByteScan:
    """Grep-level scan for patterns that suggest key bytes in Python."""

    # Patterns that suggest raw key bytes flowing through Python
    SUSPICIOUS_PATTERNS = [
        # Direct key derivation result stored in variable
        re.compile(r"encryption_key\s*=\s*derive_"),
        # Key bytes passed to function
        re.compile(r"encryption_key\s*=\s*precomputed_key"),
        # bytearray of key (best-effort zeroing = violation crutch)
        re.compile(r"encryption_key_buf\s*=\s*bytearray\(encryption_key\)"),
    ]

    def test_no_suspicious_key_patterns_in_entrypoints(self):
        """Entrypoints must not contain patterns suggesting raw key bytes."""
        violations = []
        for ep_path in PRODUCTION_ENTRYPOINTS:
            if not ep_path.exists():
                continue
            source = ep_path.read_text(encoding="utf-8")
            for i, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for pat in self.SUSPICIOUS_PATTERNS:
                    if pat.search(stripped):
                        rel = ep_path.relative_to(WORKSPACE)
                        violations.append(f"{rel}:{i} matches pattern: {pat.pattern}")

        assert not violations, (
            "Production entrypoints contain suspicious key-byte patterns:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_no_derive_key_import_in_entrypoints(self):
        """Entrypoints must not import derive_key (raw key function)."""
        for ep_path in PRODUCTION_ENTRYPOINTS:
            if not ep_path.exists():
                continue
            source = ep_path.read_text(encoding="utf-8")
            # Check for import of derive_key specifically
            if re.search(r"from\s+\.crypto\s+import[^)]*\bderive_key\b", source):
                rel = ep_path.relative_to(WORKSPACE)
                pytest.fail(f"{rel} imports derive_key from .crypto")
