"""
Surface area regression test — ensures production only imports from the allowlist.

Enforces:
1. Static AST reachability from entrypoints stays within the production allowlist.
2. No production module imports from meow_decoder._archive.
3. _archive is excluded from package metadata (setuptools config).
"""

import ast
import pathlib
from collections import deque

import pytest

WORKSPACE = pathlib.Path(__file__).resolve().parent.parent
PRODUCTION_ROOT = WORKSPACE / "meow_decoder"

# Production entrypoints (from pyproject.toml [project.scripts])
ENTRYPOINTS = [
    "encode.py",
    "decode_gif.py",
    "deadmans_switch_cli.py",
]

# Modules that MUST be the ONLY ones reachable from entrypoints.
# If a new module is added to production, add it here explicitly.
PRODUCTION_ALLOWLIST = frozenset(
    {
        "meow_decoder",
        "meow_decoder.adversarial_carrier",
        "meow_decoder.argon2_presets",
        "meow_decoder.cat_errors",
        "meow_decoder.cat_utils",
        "meow_decoder.config",
        "meow_decoder.constant_time",
        "meow_decoder.crypto",
        "meow_decoder.crypto_backend",
        "meow_decoder.deadmans_switch_cli",
        "meow_decoder.decode_gif",
        "meow_decoder.duress_mode",
        "meow_decoder.encode",
        "meow_decoder.fountain",
        "meow_decoder.frame_mac",
        "meow_decoder.gif_handler",
        "meow_decoder.hardware_integration",
        "meow_decoder.high_security",
        "meow_decoder.logo_eyes",
        "meow_decoder.manifest_signing",
        "meow_decoder.metadata_obfuscation",
        "meow_decoder.mobile_bridge",
        "meow_decoder.pq_hybrid",
        "meow_decoder.pq_ratchet_beacon",
        "meow_decoder.progress",
        "meow_decoder.qr_code",
        "meow_decoder.ratchet",
        "meow_decoder.secure_keyboard",
        "meow_decoder.security_warnings",
        "meow_decoder.shamir_split",
        "meow_decoder.stego_advanced",
        "meow_decoder.tamper_report",
        "meow_decoder.timelock_duress",
        "meow_decoder.x25519_forward_secrecy",
    }
)

FORBIDDEN_PREFIXES = (
    "meow_decoder._archive",
    "meow_decoder.experimental",
)

EXCLUDED_DIRS = {"_archive", "_testonly", "experimental", "__pycache__"}


# ── Helpers ──────────────────────────────────────────────────────────────


def _file_to_module(filepath: pathlib.Path) -> str:
    rel = filepath.relative_to(WORKSPACE)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _module_to_file(mod_name: str) -> pathlib.Path | None:
    parts = mod_name.split(".")
    pkg_path = WORKSPACE / "/".join(parts) / "__init__.py"
    if pkg_path.exists():
        return pkg_path
    mod_path = (
        WORKSPACE / "/".join(parts[:-1]) / (parts[-1] + ".py")
        if len(parts) > 1
        else WORKSPACE / (parts[0] + ".py")
    )
    if mod_path.exists():
        return mod_path
    return None


def _get_imports(filepath: pathlib.Path) -> set[str]:
    """Return all meow_decoder.* imports from a Python file (AST-based)."""
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError):
        return set()

    rel = filepath.relative_to(WORKSPACE)
    parts = list(rel.with_suffix("").parts)
    pkg_parts = parts[:-1] if parts[-1] != "__init__" else parts[:-1]

    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("meow_decoder"):
                    imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                base = list(pkg_parts)
                for _ in range(node.level - 1):
                    if base:
                        base.pop()
                full = ".".join(base) + ("." + node.module if node.module else "")
                if full.startswith("meow_decoder"):
                    imports.add(full)
            elif node.module and node.module.startswith("meow_decoder"):
                imports.add(node.module)
    return imports


def _compute_reachable() -> set[str]:
    """BFS from entrypoints to find all reachable meow_decoder modules."""
    reachable: set[str] = set()
    graph: dict[str, set[str]] = {}
    queue: deque[str] = deque()

    # Seed with entrypoints + package __init__
    for ep in ENTRYPOINTS:
        fp = PRODUCTION_ROOT / ep
        if fp.exists():
            mod = _file_to_module(fp)
            reachable.add(mod)
            queue.append(mod)

    init = PRODUCTION_ROOT / "__init__.py"
    if init.exists():
        reachable.add("meow_decoder")
        queue.append("meow_decoder")

    while queue:
        mod = queue.popleft()
        if mod in graph:
            continue
        fp = _module_to_file(mod)
        if fp is None:
            graph[mod] = set()
            continue
        deps = _get_imports(fp)
        graph[mod] = deps
        for dep in deps:
            if dep not in reachable:
                reachable.add(dep)
                queue.append(dep)

    return reachable


def _get_production_files() -> list[pathlib.Path]:
    """All .py files under meow_decoder/ excluding _archive, _testonly, etc."""
    result = []
    for py_file in PRODUCTION_ROOT.rglob("*.py"):
        rel_parts = py_file.relative_to(PRODUCTION_ROOT).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        if "__pycache__" in str(py_file):
            continue
        result.append(py_file)
    return result


# ── Tests ────────────────────────────────────────────────────────────────


class TestProductionImportBoundary:
    """Verify production surface area stays minimal."""

    def test_reachable_modules_in_allowlist(self):
        """Every module reachable from entrypoints must be in the allowlist."""
        reachable = _compute_reachable()
        unexpected = reachable - PRODUCTION_ALLOWLIST
        assert not unexpected, (
            f"New modules reachable from production entrypoints but NOT in allowlist: "
            f"{sorted(unexpected)}. If intentional, add them to PRODUCTION_ALLOWLIST "
            f"in this test file."
        )

    def test_allowlist_modules_are_reachable(self):
        """Every module in the allowlist must be reachable (no stale entries)."""
        reachable = _compute_reachable()
        stale = PRODUCTION_ALLOWLIST - reachable
        assert not stale, (
            f"Modules in PRODUCTION_ALLOWLIST but no longer reachable from entrypoints: "
            f"{sorted(stale)}. Remove them from the allowlist."
        )

    def test_no_production_imports_archive(self):
        """No production module may import from _archive or experimental."""
        violations = []
        for py_file in _get_production_files():
            imports = _get_imports(py_file)
            for imp in imports:
                if any(imp.startswith(prefix) for prefix in FORBIDDEN_PREFIXES):
                    violations.append(f"{_file_to_module(py_file)} imports {imp}")
        assert not violations, f"Production code imports from forbidden packages:\n" + "\n".join(
            f"  - {v}" for v in violations
        )

    def test_archive_not_in_package_config(self):
        """_archive must be excluded from setuptools package discovery."""
        pyproject = WORKSPACE / "pyproject.toml"
        content = pyproject.read_text(encoding="utf-8")
        assert (
            "meow_decoder._archive" in content
        ), "pyproject.toml must exclude meow_decoder._archive from packaging"

    def test_archive_init_raises_importerror(self):
        """Importing meow_decoder._archive must raise ImportError."""
        with pytest.raises(ImportError, match="archive"):
            import meow_decoder._archive  # noqa: F401
