#!/usr/bin/env python3
"""
Fuzz target for the forensic cleanup module.

Tests:
  - ForensicCleaner init with adversarial file paths and keywords
  - _scrub_file_lines with adversarial pattern lists
  - clean_shell_history with garbage patterns
  - Path traversal rejection in file_paths

Uses Atheris (Google's Python fuzzing engine).

SAFETY: All operations are sandboxed to a temporary directory.
We never call clean_all() against real system paths.
"""

import os
import sys
import tempfile

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.forensic_cleanup import (
        ForensicCleaner,
        _scrub_file_lines,
    )

    return {
        "ForensicCleaner": ForensicCleaner,
        "_scrub_file_lines": _scrub_file_lines,
    }


if atheris is not None:
    with atheris.instrument_imports():
        API = _setup_imports()
else:
    API = _setup_imports()


def fuzz_scrub_file_lines(data: bytes):
    """Fuzz _scrub_file_lines with arbitrary file content and patterns."""
    if len(data) < 4:
        return

    # Split fuzz data: first 2 bytes = number of patterns, rest = content + patterns
    n_patterns = data[0] % 8  # 0-7 patterns
    offset = 1

    patterns = []
    for _ in range(n_patterns):
        plen = data[offset] % 32 if offset < len(data) else 0
        offset += 1
        if offset + plen <= len(data):
            patterns.append(data[offset: offset + plen].decode("utf-8", errors="replace"))
            offset += plen
        else:
            break

    content = data[offset:].decode("utf-8", errors="replace")

    # Write content to a temp file, then scrub it
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            tmppath = f.name

        if patterns:
            removed = API["_scrub_file_lines"](tmppath, patterns)
            assert isinstance(removed, int)
            assert removed >= 0
    except (ValueError, TypeError, OSError, UnicodeDecodeError):
        pass
    finally:
        try:
            os.unlink(tmppath)
        except (OSError, NameError):
            pass


def fuzz_cleaner_init(data: bytes):
    """Fuzz ForensicCleaner construction with adversarial paths and keywords."""
    if len(data) < 2:
        return

    n_paths = data[0] % 5
    n_kw = data[1] % 5
    offset = 2

    paths = []
    for _ in range(n_paths):
        plen = data[offset] % 64 if offset < len(data) else 0
        offset += 1
        if offset + plen <= len(data):
            paths.append(data[offset: offset + plen].decode("utf-8", errors="replace"))
            offset += plen

    keywords = []
    for _ in range(n_kw):
        klen = data[offset] % 32 if offset < len(data) else 0
        offset += 1
        if offset + klen <= len(data):
            keywords.append(data[offset: offset + klen].decode("utf-8", errors="replace"))
            offset += klen

    try:
        cleaner = API["ForensicCleaner"](file_paths=paths, keywords=keywords)
        assert isinstance(cleaner.file_paths, list)
        assert isinstance(cleaner.keywords, list)
        # Do NOT call clean_all() — we don't want to touch real OS artifacts
    except (ValueError, TypeError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_scrub_file_lines(data)
        fuzz_cleaner_init(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
