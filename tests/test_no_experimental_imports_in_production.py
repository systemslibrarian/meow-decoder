"""
Experimental Import Enforcement Tests

Ensures that production code (meow_decoder/**/*.py, excluding experimental/)
does not import from meow_decoder.experimental at module level.

Lazy/conditional imports gated behind try/except or pragma: no cover are
flagged but accepted if they are clearly user-opt-in paths.
"""

import ast
import pathlib

import pytest

WORKSPACE = pathlib.Path(__file__).parent.parent
PRODUCTION_ROOT = WORKSPACE / "meow_decoder"

EXCLUDED_DIRS = {"_testonly", "_archive", "experimental", "__pycache__"}


def _get_production_files():
    """Get all .py files under meow_decoder/ minus exclusions."""
    files = []
    for py_file in PRODUCTION_ROOT.rglob("*.py"):
        rel_parts = py_file.relative_to(PRODUCTION_ROOT).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        files.append(py_file)
    return sorted(files)


class _ImportVisitor(ast.NodeVisitor):
    """AST visitor that collects all imports at module level (not inside functions)."""

    def __init__(self):
        self.module_level_imports = []  # (lineno, module_name)
        self._in_function = False

    def visit_FunctionDef(self, node):
        # Don't recurse into function bodies for module-level scan
        pass

    def visit_AsyncFunctionDef(self, node):
        pass

    def visit_Import(self, node):
        if not self._in_function:
            for alias in node.names:
                self.module_level_imports.append((node.lineno, alias.name))

    def visit_ImportFrom(self, node):
        if not self._in_function and node.module:
            self.module_level_imports.append((node.lineno, node.module))
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                self.module_level_imports.append((node.lineno, full))


class _AllImportVisitor(ast.NodeVisitor):
    """AST visitor that collects ALL imports (including inside functions)."""

    def __init__(self):
        self.all_imports = []  # (lineno, module_name)

    def visit_Import(self, node):
        for alias in node.names:
            self.all_imports.append((node.lineno, alias.name))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.all_imports.append((node.lineno, node.module))
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                self.all_imports.append((node.lineno, full))
        self.generic_visit(node)


class TestNoExperimentalImportsInProduction:
    """CI-enforced: production code must not import from meow_decoder.experimental."""

    def test_no_module_level_experimental_imports(self):
        """No production .py file may import meow_decoder.experimental at module level."""
        violations = []
        for py_file in _get_production_files():
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue

            visitor = _ImportVisitor()
            visitor.visit(tree)

            for lineno, module in visitor.module_level_imports:
                if module.startswith("meow_decoder.experimental") or module == "experimental":
                    rel = py_file.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno} imports '{module}'")

        assert not violations, (
            "Production code has module-level imports of experimental modules:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_no_unconditional_experimental_imports(self):
        """No production .py file may unconditionally import experimental modules.

        Conditional imports inside try/except or under pragma: no cover are
        allowed for user-opt-in features, but unconditional (module-level,
        no try/except guard) imports are forbidden.
        """
        violations = []
        for py_file in _get_production_files():
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue

            # Check module-level only (already checked above, but be thorough)
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module = None
                    if isinstance(node, ast.ImportFrom) and node.module:
                        module = node.module
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name.startswith("meow_decoder.experimental") or alias.name == "experimental":
                                rel = py_file.relative_to(WORKSPACE)
                                violations.append(
                                    f"{rel}:{node.lineno} unconditionally imports '{alias.name}'"
                                )
                    if module and (module.startswith("meow_decoder.experimental") or module == "experimental"):
                        rel = py_file.relative_to(WORKSPACE)
                        violations.append(
                            f"{rel}:{node.lineno} unconditionally imports '{module}'"
                        )

        assert not violations, (
            "Production code unconditionally imports experimental modules:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_experimental_init_has_warning(self):
        """experimental/__init__.py must contain a warning about non-production status."""
        init_path = PRODUCTION_ROOT / "experimental" / "__init__.py"
        if not init_path.exists():
            pytest.skip("experimental/ directory does not exist")
        content = init_path.read_text(encoding="utf-8")
        assert "NOT" in content or "not" in content, (
            "experimental/__init__.py must contain a warning about non-production status"
        )
        assert "production" in content.lower(), (
            "experimental/__init__.py must mention 'production' in its warning"
        )
