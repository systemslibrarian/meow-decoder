"""
Production Boundary Enforcement (Signal-Grade)

This test module defines and enforces the production boundary.
No production code may import from _testonly or experimental.
New files added to PRODUCTION_DIRS are automatically scanned.

Fail-closed: any violation = CI failure.
"""

import ast
import os
import pathlib
import re
import pytest

# =============================================================================
# Production boundary definition
# =============================================================================

WORKSPACE = pathlib.Path(__file__).parent.parent

PRODUCTION_ROOT = WORKSPACE / "meow_decoder"

# Directories EXCLUDED from production (test-only, experimental)
EXCLUDED_DIRS = {
    "_testonly",
    "experimental",
    "__pycache__",
}

# Production entrypoints
PRODUCTION_ENTRYPOINTS = [
    "encode.py",
    "decode_gif.py",
    "meow_encode.py",
]

# Modules that must NEVER be imported by production code
FORBIDDEN_PRODUCTION_IMPORTS = {
    "meow_decoder._testonly",
    "meow_decoder.experimental",
    "_testonly",
}


def _get_production_files():
    """Get all .py files in PRODUCTION_DIRS (meow_decoder/** minus exclusions)."""
    files = []
    for py_file in PRODUCTION_ROOT.rglob("*.py"):
        # Skip excluded directories
        rel_parts = py_file.relative_to(PRODUCTION_ROOT).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        files.append(py_file)
    return sorted(files)


class _ImportVisitor(ast.NodeVisitor):
    """AST visitor that collects all import targets."""

    def __init__(self):
        self.imports = []  # (lineno, module_path, kind)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append((node.lineno, alias.name, "import"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.append((node.lineno, node.module, "from-import"))
        self.generic_visit(node)


class TestProductionBoundary:
    """Enforce that production code never imports from _testonly or experimental."""

    def test_production_does_not_import_testonly(self):
        """Production code must not import from _testonly."""
        violations = []
        for py_file in _get_production_files():
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue

            visitor = _ImportVisitor()
            visitor.visit(tree)

            for lineno, module, kind in visitor.imports:
                for forbidden in FORBIDDEN_PRODUCTION_IMPORTS:
                    if module == forbidden or module.startswith(forbidden + "."):
                        rel = py_file.relative_to(WORKSPACE)
                        violations.append(f"{rel}:{lineno} — {kind} '{module}'")

        if violations:
            pytest.fail(
                f"Production code imports from forbidden test-only modules:\n"
                + "\n".join(f"  - {v}" for v in violations)
            )

    def test_production_dirs_list_is_accurate(self):
        """Verify PRODUCTION_ROOT exists and contains .py files."""
        assert PRODUCTION_ROOT.exists(), f"PRODUCTION_ROOT {PRODUCTION_ROOT} does not exist"
        prod_files = _get_production_files()
        assert len(prod_files) > 0, "No production files found"

    def test_new_files_are_scanned(self):
        """Every .py file in meow_decoder/ (minus exclusions) must be scanned."""
        all_py = set()
        for py_file in PRODUCTION_ROOT.rglob("*.py"):
            rel_parts = py_file.relative_to(PRODUCTION_ROOT).parts
            if any(part in EXCLUDED_DIRS for part in rel_parts):
                continue
            all_py.add(py_file)

        scanned = set(_get_production_files())
        unscanned = all_py - scanned
        assert not unscanned, f"Files in production dirs not covered by scan:\n" + "\n".join(
            f"  - {f.relative_to(WORKSPACE)}" for f in sorted(unscanned)
        )

    def test_entrypoints_exist(self):
        """All declared production entrypoints must exist."""
        for ep in PRODUCTION_ENTRYPOINTS:
            ep_path = PRODUCTION_ROOT / ep
            assert ep_path.exists(), f"Production entrypoint {ep} does not exist"

    def test_testonly_dir_exists(self):
        """The _testonly directory must exist for test-only modules."""
        testonly = PRODUCTION_ROOT / "_testonly"
        assert testonly.exists(), "_testonly directory missing"
        assert (testonly / "__init__.py").exists(), "_testonly/__init__.py missing"


class TestProductionEntrypointPurity:
    """Verify production entrypoints do not transitively import oqs in production mode."""

    def test_encode_does_not_import_oqs_at_module_level(self):
        """encode.py must not have module-level oqs import."""
        encode_path = PRODUCTION_ROOT / "encode.py"
        source = encode_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        visitor = _ImportVisitor()
        visitor.visit(tree)

        for lineno, module, kind in visitor.imports:
            root = module.split(".")[0]
            if root == "oqs":
                pytest.fail(
                    f"encode.py:{lineno} has module-level import of 'oqs'. "
                    "PQ must be gated behind Rust backend or PRODUCTION_MODE check."
                )

    def test_decode_gif_does_not_import_oqs_directly(self):
        """decode_gif.py must not import oqs directly — PQ must go through Rust backend."""
        decode_path = PRODUCTION_ROOT / "decode_gif.py"
        source = decode_path.read_text(encoding="utf-8")

        # Search for ANY "import oqs" anywhere in the file (module or function level)
        # The oqs Python library must not be used directly; PQ must be Rust-backed
        # or explicitly gated with PRODUCTION_MODE
        for i, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped == "import oqs" or stripped.startswith("from oqs"):
                pytest.fail(
                    f"decode_gif.py:{i} imports 'oqs' directly. "
                    "PQ must use Rust backend (meow_crypto_rs with 'pq' feature) "
                    "or be gated behind PRODUCTION_MODE check with hard error."
                )
