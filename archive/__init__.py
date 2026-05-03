"""
archive/ — Historical reference, not part of the meow_decoder package.

This directory holds modules that were once on the production path but
have since been replaced by Rust-backed handle implementations or by
stricter top-level entrypoints in `meow_decoder/`.

It lives at the repo root (NOT inside `meow_decoder/`) on purpose:

* setuptools never includes it in built wheels
* bandit / mypy / pytest do not walk it during `meow_decoder` scans
* importing `archive.*` is intentionally undefined — no `import archive`
  call exists anywhere in the production graph (enforced by
  `tests/test_production_import_boundary.py`)

If you need to reference an archived module, read the source. Do not
import it. To restore one to production: copy it back into
`meow_decoder/`, run the surface-area-minimization import-graph
analysis, and add tests + bandit-clean coverage.
"""

raise ImportError(
    "archive/ is a reference-only directory at the repo root. "
    "It is not part of the `meow_decoder` package and must not be "
    "imported. See archive/__init__.py for restoration steps."
)
