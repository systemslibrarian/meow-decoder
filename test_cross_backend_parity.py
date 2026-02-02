#!/usr/bin/env python3
"""Deprecated: cross-backend parity tests removed (Rust backend required)."""

import pytest

pytest.skip(
    "Cross-backend parity tests removed; Rust backend is mandatory.",
    allow_module_level=True,
)
