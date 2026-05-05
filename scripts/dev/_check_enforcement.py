#!/usr/bin/env python3
"""Quick standalone enforcement check - not a test file."""

import ast
import pathlib
import sys

EXEMPT_FILES = {
    "constant_time.py",
    "__init__.py",
    "crypto_DEBUG.py",
    "pq_crypto_real.py",
    "pq_signatures.py",
    "x25519_forward_secrecy.py",
}
EXEMPT_DIRS = {"spec_v12"}
FORBIDDEN_ROOTS = {"cryptography", "hmac", "hashlib"}

workspace = pathlib.Path(__file__).parent
violations = []

for py_file in (workspace / "meow_decoder").rglob("*.py"):
    if py_file.name in EXEMPT_FILES:
        continue
    if any(d in py_file.parts for d in EXEMPT_DIRS):
        continue
    try:
        tree = ast.parse(py_file.read_text())
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_ROOTS:
                    violations.append(
                        f"  {py_file.relative_to(workspace)}:{node.lineno} import {alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in FORBIDDEN_ROOTS:
                violations.append(
                    f"  {py_file.relative_to(workspace)}:{node.lineno} from {node.module}"
                )

if violations:
    print(f"FAIL: {len(violations)} forbidden imports found:")
    for v in violations:
        print(v)
    sys.exit(1)
else:
    print("PASS: No forbidden crypto imports in production code")
    sys.exit(0)
