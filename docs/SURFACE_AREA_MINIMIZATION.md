# Python Surface Area Minimization Report

**Date:** 2026-02-18
**Method:** AST-based BFS from production entrypoints + dynamic runtime import trace

## Production Entrypoints

- `meow_decoder/encode.py` → `meow-encode` CLI
- `meow_decoder/decode_gif.py` → `meow-decode-gif` CLI
- `meow_decoder/deadmans_switch_cli.py` → `meow-deadmans-switch` CLI

## Module Classification Table

### REQUIRED (28 modules — reachable from entrypoints)

| Module | Reason |
|--------|--------|
| `meow_decoder.__init__` | Package init |
| `meow_decoder.cat_errors` | Imported by encode, decode_gif |
| `meow_decoder.cat_utils` | Imported by encode, decode_gif, crypto, progress |
| `meow_decoder.config` | Imported by encode, decode_gif, duress_mode, high_security |
| `meow_decoder.constant_time` | Imported by decode_gif, crypto |
| `meow_decoder.crypto` | Core encryption — imported by encode, decode_gif |
| `meow_decoder.crypto_backend` | Rust backend bridge — imported by many modules |
| `meow_decoder.deadmans_switch_cli` | CLI entrypoint (pyproject.toml) |
| `meow_decoder.decode_gif` | Primary decode entrypoint |
| `meow_decoder.duress_mode` | Imported by decode_gif, cat_utils |
| `meow_decoder.encode` | Primary encode entrypoint |
| `meow_decoder.fountain` | Fountain codes — imported by encode, decode_gif |
| `meow_decoder.frame_mac` | Imported by encode |
| `meow_decoder.gif_handler` | GIF I/O — imported by encode, decode_gif |
| `meow_decoder.hardware_integration` | Imported by encode, decode_gif |
| `meow_decoder.high_security` | Imported by encode |
| `meow_decoder.logo_eyes` | Imported by encode |
| `meow_decoder.metadata_obfuscation` | Imported by crypto (length padding) |
| `meow_decoder.mobile_bridge` | Imported by decode_gif |
| `meow_decoder.pq_hybrid` | Post-quantum — imported by encode, decode_gif |
| `meow_decoder.progress` | Imported by encode, decode_gif |
| `meow_decoder.qr_code` | QR generation — imported by encode, decode_gif |
| `meow_decoder.ratchet` | Frame ratchet — imported by encode, decode_gif |
| `meow_decoder.security_warnings` | Imported by pq_hybrid |
| `meow_decoder.stego_advanced` | Imported by encode |
| `meow_decoder.tamper_report` | Imported by decode_gif |
| `meow_decoder.timelock_duress` | Imported by deadmans_switch_cli |
| `meow_decoder.x25519_forward_secrecy` | Imported by encode, decode_gif, crypto, cat_utils |

### ARCHIVED (45 modules — moved to `meow_decoder/_archive/`)

| Module | Reason |
|--------|--------|
| `meow_decoder._testonly` | Test-only helpers |
| `meow_decoder.ascii_qr` | Unreachable from entrypoints |
| `meow_decoder.bidirectional` | Unreachable — multi-device protocol |
| `meow_decoder.cat_api` | Unreachable — network API |
| `meow_decoder.catnip_fountain` | Unreachable — experimental fountain variant |
| `meow_decoder.clowder_decode` | Unreachable — multi-device streaming |
| `meow_decoder.clowder_encode` | Unreachable — multi-device streaming |
| `meow_decoder.crypto_enhanced` | Unreachable — replaced by crypto.py |
| `meow_decoder.decode_webcam_with_resume` | Unreachable — webcam GUI |
| `meow_decoder.decoy_generator` | Unreachable — Schrödinger helper |
| `meow_decoder.double_ratchet` | Unreachable — superseded by ratchet.py |
| `meow_decoder.encode_DEBUG` | Debug variant |
| `meow_decoder.entropy_boost` | Unreachable |
| `meow_decoder.experimental.__init__` | Experimental package |
| `meow_decoder.experimental.pq_signatures` | Experimental PQ signatures |
| `meow_decoder.forward_secrecy` | Unreachable — legacy FS module |
| `meow_decoder.forward_secrecy_decoder` | Unreachable — legacy FS decoder |
| `meow_decoder.forward_secrecy_encoder` | Unreachable — legacy FS encoder |
| `meow_decoder.forward_secrecy_x25519` | Unreachable — replaced by x25519_forward_secrecy.py |
| `meow_decoder.gui_logo_example` | GUI example |
| `meow_decoder.hardware_keys` | Unreachable — YubiKey helpers |
| `meow_decoder.meow_dashboard_demo` | GUI demo |
| `meow_decoder.meow_encode` | Legacy encode wrapper |
| `meow_decoder.meow_gui_enhanced` | GUI |
| `meow_decoder.merkle_tree` | Unreachable |
| `meow_decoder.multi_secret` | Unreachable |
| `meow_decoder.ninja_cat_ultra` | Unreachable — experimental |
| `meow_decoder.profiling_improved` | Profiling tool |
| `meow_decoder.progress_bar` | Unreachable — replaced by progress.py |
| `meow_decoder.prowling_mode` | Unreachable |
| `meow_decoder.quantum_mixer` | Unreachable — Schrödinger helper |
| `meow_decoder.resume_secured` | Unreachable |
| `meow_decoder.schrodinger_decode` | Unreachable |
| `meow_decoder.schrodinger_encode` | Unreachable |
| `meow_decoder.secure_bridge` | Unreachable — network bridge |
| `meow_decoder.secure_cleanup` | Unreachable |
| `meow_decoder.setup` | Legacy setup.py |
| `meow_decoder.spec_v12.__init__` | Unreachable — spec v1.2 package |
| `meow_decoder.spec_v12.decode` | Unreachable — spec v1.2 |
| `meow_decoder.spec_v12.encode` | Unreachable — spec v1.2 |
| `meow_decoder.spec_v12.key_management` | Unreachable — spec v1.2 |
| `meow_decoder.spec_v12.multi_tier` | Unreachable — spec v1.2 |
| `meow_decoder.spec_v12.steganography` | Unreachable — spec v1.2 |
| `meow_decoder.streaming_crypto` | Unreachable |
| `meow_decoder.webcam_enhanced` | Unreachable — webcam GUI |

**Production surface: 28 modules. Archived: 45 modules (62% reduction).**

## Changes Made

### Files Moved

| Change | Details |
|--------|---------|
| 45 source modules | `meow_decoder/*.py` → `meow_decoder/_archive/*.py` (preserving subdirs `_testonly/`, `experimental/`, `spec_v12/`) |
| 52 test files | `tests/test_*.py` → `tests/_archive/test_*.py` (37 archive-only + 15 mixed) |

#### Post-Archive Corrections

| File | Issue | Resolution |
|------|-------|------------|
| `test_x25519_forward_secrecy.py` | Wrongly archived — only imports production modules. 5 coverage-boost tests at tail imported `forward_secrecy_x25519` (archived). | Restored to `tests/`, stripped the 5 archived-import tests. 42 production tests retained. |
| `test_progress.py` | Archived as mixed — also imported `ascii_qr` and `ninja_cat_ultra`. | Recreated in `tests/` with only the 6 `TestProgressBar` production tests. |

### Import Guard

`meow_decoder/_archive/__init__.py` raises `ImportError` if anything attempts to import from the archive:

```python
raise ImportError(
    "meow_decoder._archive is an archive of non-production modules. "
    "Importing from it is forbidden."
)
```

### Config Updates

| File | Change |
|------|--------|
| `pyproject.toml` | Added `norecursedirs = ["_archive"]` to pytest config; excluded `meow_decoder._archive*` from setuptools packaging |
| `MANIFEST.in` | Added `prune meow_decoder/_archive` |
| `.coveragerc` | Added `meow_decoder/_archive/*` to omit |
| `tests/test_production_boundary.py` | Added `_archive` to `EXCLUDED_DIRS`; fixed entrypoints list; updated `_testonly` check |
| `tests/test_no_experimental_imports_in_production.py` | Added `_archive` to `EXCLUDED_DIRS` |
| `tests/test_fail_closed_enforcement.py` | Added `_archive` to `EXCLUDED_DIRS` |

### Regression Tests Added

`tests/test_production_import_boundary.py` — 5 tests:

| Test | Enforces |
|------|----------|
| `test_reachable_modules_in_allowlist` | Every module reachable from entrypoints is in a hardcoded allowlist |
| `test_allowlist_modules_are_reachable` | No stale entries in allowlist (bidirectional check) |
| `test_no_production_imports_archive` | No production code imports from `_archive` or `experimental` |
| `test_archive_not_in_package_config` | `_archive` is excluded in pyproject.toml |
| `test_archive_init_raises_importerror` | `import meow_decoder._archive` raises `ImportError` |

## Test Results

**Python (`pytest -q`):** 1492 passed, 21 skipped, 29 failed. All 29 failures are **pre-existing** (Rust backend `meow_crypto_rs` missing attributes + 1 flaky timing test). Zero new failures from archiving.

**Post-correction verification:** `test_progress.py` (6 tests) + `test_x25519_forward_secrecy.py` (42 tests) = 48 tests, all passing.

All 27 production modules (excluding `__init__`) now have a dedicated test file in `tests/`.

**Rust (`cargo test -q`):** 465 passed, 0 failed, 1 ignored. All green.

## Restoring an Archived Module

If an archived module is needed in production:

1. Move it from `meow_decoder/_archive/` back to `meow_decoder/`
2. Add it to `PRODUCTION_ALLOWLIST` in `tests/test_production_import_boundary.py`
3. Run `pytest tests/test_production_import_boundary.py` to verify
4. Move its tests from `tests/_archive/` back to `tests/`
5. If the test file was mixed, strip imports of still-archived modules before restoring
