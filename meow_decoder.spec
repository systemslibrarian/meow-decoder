# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for Meow Decoder single-binary distribution.

Creates a portable single executable with:
- All Python dependencies bundled
- Rust crypto backend (.so/.dll/.dylib) embedded
- QR code libraries included
- Environment safety checks active

Usage:
    # Install PyInstaller first
    pip install pyinstaller

    # Build single binary
    pyinstaller meow_decoder.spec

    # Output: dist/meow-decoder (or meow-decoder.exe on Windows)

Security:
- Binary includes VM/debugger detection (env_safety.py)
- Memory guards activated on startup
- No Python bytecode extraction (--key for encryption)
"""

import os
import platform
import sys
from pathlib import Path

# Detect platform
PLATFORM = platform.system()

# Root directory
ROOT = Path(SPECPATH)

# Binary name
BINARY_NAME = "meow-decoder"
if PLATFORM == "Windows":
    BINARY_NAME += ".exe"

# Hidden imports that PyInstaller might miss
HIDDEN_IMPORTS = [
    "PIL.Image",
    "PIL.ImageFilter",
    "qrcode",
    "qrcode.image.pil",
    "pyzbar.pyzbar",
    "cv2",
    "numpy",
    "cryptography",
    "cryptography.hazmat.backends.openssl",
    "cryptography.hazmat.primitives.ciphers.aead",
    "argon2",
    "meow_decoder",
    "meow_decoder.crypto",
    "meow_decoder.encode",
    "meow_decoder.decode_gif",
    "meow_decoder.fountain",
    "meow_decoder.ratchet",
    "meow_decoder.pq_hybrid",
    "meow_decoder.memory_guard",
    "meow_decoder.env_safety",
    "meow_decoder.tamper_detection",
    "meow_decoder.shamir_split",
    "meow_decoder.secure_keyboard",
    "meow_decoder.adversarial_carrier",
    "meow_decoder.manifest_signing",
    "meow_decoder.pq_ratchet_beacon",
    "meow_decoder.master_ratchet",
]

# Data files to include
DATA_FILES = [
    # Rust shared library
    (str(ROOT / "crypto_core" / "pkg" / "*.so"), "crypto_core/pkg"),
    (str(ROOT / "crypto_core" / "pkg" / "*.dll"), "crypto_core/pkg"),
    (str(ROOT / "crypto_core" / "pkg" / "*.dylib"), "crypto_core/pkg"),
    # Assets
    (str(ROOT / "assets" / "*"), "assets"),
]

# Binary dependencies (Rust .so/.dll)
BINARIES = []
rust_lib_dir = ROOT / "crypto_core" / "pkg"
if rust_lib_dir.exists():
    for ext in ["*.so", "*.dll", "*.dylib"]:
        for lib in rust_lib_dir.glob(ext):
            BINARIES.append((str(lib), "."))

# Also check target/release
target_release = ROOT / "target" / "release"
if target_release.exists():
    for ext in ["libmeow_crypto_rs.so", "meow_crypto_rs.dll", "libmeow_crypto_rs.dylib"]:
        lib = target_release / ext.replace("*", "")
        if lib.exists():
            BINARIES.append((str(lib), "."))

# Analysis
a = Analysis(
    [str(ROOT / "meow_decoder" / "__main__.py")],
    pathex=[str(ROOT)],
    binaries=BINARIES,
    datas=DATA_FILES,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(ROOT / "scripts" / "pyinstaller_runtime_hook.py")],
    excludes=[
        "tkinter",  # Only needed for secure_keyboard GUI, fallback to CLI
        "matplotlib",
        "scipy",
        "pandas",
        "IPython",
        "jupyter",
        "notebook",
    ],
    noarchive=False,
    optimize=2,
)

# Remove test files
a.datas = [d for d in a.datas if "test" not in d[0].lower()]

# PYZ archive
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

# Single executable
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=BINARY_NAME.replace(".exe", ""),
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,  # Strip symbols (reduces size, hardens)
    upx=True,  # UPX compression (optional, may slow startup)
    upx_exclude=[],
    runtime_tmpdir=None,  # Don't extract to temp (more secure)
    console=True,
    disable_windowed_traceback=True,  # Don't leak tracebacks
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Windows-specific
    version=str(ROOT / "scripts" / "version_info.txt") if PLATFORM == "Windows" else None,
    icon=str(ROOT / "assets" / "meow.ico") if (ROOT / "assets" / "meow.ico").exists() else None,
)
