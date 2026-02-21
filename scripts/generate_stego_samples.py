#!/usr/bin/env python3
"""
Generate Meow Decoder Stego Samples for Steganalysis Testing
=============================================================

Creates stego test outputs using both the CLI path (stego_advanced) and
the MultiLayerStegoEncoder (production multi-channel) for external tool
testing against StegX's claimed evasion baselines.

Usage:
    python scripts/generate_stego_samples.py [--output-dir ./stego_samples]

Produces:
    stego_samples/
        carrier_green.png           # Synthetic green-rich carrier
        carrier_cat_procedural.gif  # Procedurally generated cat
        sample_cli_level3.gif       # CLI stego_advanced level 3
        sample_cli_level4.gif       # CLI stego_advanced level 4 (paranoid)
        sample_multilayer_stc.png   # MultiLayer with STC + keyed walk
        sample_multilayer_full.png  # MultiLayer all channels + adversarial
        sample_clean_carrier.png    # Clean carrier (no embedding) for comparison
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np
from PIL import Image

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def create_green_rich_carrier(output_path: Path, size: tuple = (320, 240), frames: int = 10):
    """Create a synthetic green-rich photographic carrier (natural-looking gradient).

    Green-rich images are ideal for steganographic embedding because:
    - Human visual system is most sensitive to green (more quantization levels)
    - Natural images (foliage, grass) have green-dominant spectra
    - Provides high variance in green channel for STC cost function
    """
    images = []
    rng = np.random.RandomState(42)

    for f in range(frames):
        # Base gradient (simulates outdoor scene)
        h, w = size[1], size[0]
        y_grad = np.linspace(0.2, 0.8, h).reshape(-1, 1)
        x_grad = np.linspace(0.3, 0.7, w).reshape(1, -1)

        # Green-dominant with natural variation
        r = (60 + 40 * y_grad + rng.normal(0, 8, (h, w))).clip(0, 255).astype(np.uint8)
        g = (100 + 80 * x_grad + 30 * np.sin(2 * np.pi * f / frames) +
             rng.normal(0, 12, (h, w))).clip(0, 255).astype(np.uint8)
        b = (40 + 30 * y_grad + rng.normal(0, 6, (h, w))).clip(0, 255).astype(np.uint8)

        frame = np.stack([r, g, b], axis=-1)
        images.append(Image.fromarray(frame))

    # Save as animated GIF (System A carrier) and first frame as PNG
    images[0].save(
        str(output_path.with_suffix('.gif')),
        save_all=True,
        append_images=images[1:],
        duration=100,
        loop=0,
    )
    images[0].save(str(output_path.with_suffix('.png')))
    print(f"  Created carrier: {output_path.with_suffix('.gif')} ({frames} frames)")
    print(f"  Created carrier: {output_path.with_suffix('.png')} (single frame)")
    return output_path.with_suffix('.gif'), output_path.with_suffix('.png')


def create_secret_payload(size_bytes: int = 256) -> bytes:
    """Create a reproducible test payload (small secret file)."""
    # Use a fixed seed for reproducibility
    rng = np.random.RandomState(12345)
    return bytes(rng.randint(0, 256, size_bytes, dtype=np.uint8))


def generate_multilayer_samples(
    output_dir: Path,
    carrier_gif: Path,
    carrier_png: Path,
    payload: bytes,
):
    """Generate MultiLayerStegoEncoder samples with various configurations."""
    try:
        from meow_decoder.stego_multilayer import (
            MultiLayerConfig,
            MultiLayerStegoEncoder,
            MultiLayerStegoDecoder,
            validate_stego,
            CoercionLevel,
        )
    except ImportError as e:
        print(f"  ⚠️  Cannot import MultiLayerStegoEncoder: {e}")
        print("     Skipping multilayer samples. Run: pip install -e .")
        return

    master_key = b"\x42" * 32  # Fixed test key

    # -----------------------------------------------------------------------
    # Sample 1: STC + keyed walk only (primary channel, max stealth)
    # -----------------------------------------------------------------------
    print("\n  Generating: multilayer_stc_only.png (primary channel, STC + keyed walk)")
    config_stc = MultiLayerConfig(
        enable_primary=True,
        enable_secondary=False,
        enable_tertiary=False,
        enable_disposal=False,
        enable_comment=False,
        enable_temporal=False,
        lsb_bits=1,
        use_stc=True,
        use_adaptive_cost=True,
        use_saliency_costs=False,
        immunize=False,
        adversarial_strength=0,
        procedural_cat=False,
        compress=True,
        encrypt=True,
        coercion_level=CoercionLevel.FULL,
    )
    try:
        encoder = MultiLayerStegoEncoder(config_stc, master_key)
        out_path = str(output_dir / "sample_multilayer_stc.png")
        metadata = encoder.encode(
            payload=payload,
            carrier_path=str(carrier_gif),
            output_path=out_path,
        )
        actual_path = metadata.get("output_path", out_path)
        print(f"    → Saved to: {actual_path}")
        print(f"    → Channels: {metadata.get('channels_used', 'N/A')}")

        # Validate
        try:
            result = validate_stego(actual_path)
            print(f"    → Validation: {result.summary}")
        except Exception as ve:
            print(f"    → Validation error: {ve}")
    except Exception as e:
        print(f"    → ERROR: {e}")

    # -----------------------------------------------------------------------
    # Sample 2: Full multi-channel + adversarial hardening (paranoid)
    # -----------------------------------------------------------------------
    print("\n  Generating: multilayer_full.png (all channels + adversarial)")
    config_full = MultiLayerConfig(
        enable_primary=True,
        enable_secondary=True,
        enable_tertiary=True,
        enable_disposal=True,
        enable_comment=True,
        enable_temporal=True,
        lsb_bits=1,
        use_stc=True,
        use_adaptive_cost=True,
        use_saliency_costs=True,
        immunize=True,
        immunize_sigma=0.5,
        adversarial_strength=2,  # MEDIUM
        adversarial_preserve_histogram=True,
        procedural_cat=False,
        compress=True,
        encrypt=True,
        coercion_level=CoercionLevel.FULL,
    )
    try:
        encoder = MultiLayerStegoEncoder(config_full, master_key)
        out_path = str(output_dir / "sample_multilayer_full.png")
        metadata = encoder.encode(
            payload=payload,
            carrier_path=str(carrier_gif),
            output_path=out_path,
        )
        actual_path = metadata.get("output_path", out_path)
        print(f"    → Saved to: {actual_path}")
        print(f"    → Channels: {metadata.get('channels_used', 'N/A')}")

        try:
            result = validate_stego(actual_path)
            print(f"    → Validation: {result.summary}")
        except Exception as ve:
            print(f"    → Validation error: {ve}")
    except Exception as e:
        print(f"    → ERROR: {e}")

    # -----------------------------------------------------------------------
    # Sample 3: Procedural cat carrier (no external image needed)
    # -----------------------------------------------------------------------
    print("\n  Generating: multilayer_proccat.png (procedural cat carrier)")
    config_cat = MultiLayerConfig(
        enable_primary=True,
        enable_secondary=True,
        enable_tertiary=True,
        enable_disposal=True,
        enable_comment=True,
        enable_temporal=True,
        lsb_bits=1,
        use_stc=True,
        use_adaptive_cost=True,
        immunize=True,
        adversarial_strength=2,
        procedural_cat=True,
        procedural_cat_frames=10,
        procedural_cat_size=(320, 240),
        compress=True,
        encrypt=True,
    )
    try:
        encoder = MultiLayerStegoEncoder(config_cat, master_key)
        out_path = str(output_dir / "sample_multilayer_proccat.png")
        metadata = encoder.encode(
            payload=payload,
            carrier_path=None,  # Procedural generation
            output_path=out_path,
        )
        actual_path = metadata.get("output_path", out_path)
        print(f"    → Saved to: {actual_path}")

        try:
            result = validate_stego(actual_path)
            print(f"    → Validation: {result.summary}")
        except Exception as ve:
            print(f"    → Validation error: {ve}")
    except Exception as e:
        print(f"    → ERROR: {e}")


def generate_cli_samples(output_dir: Path, carrier_gif: Path, payload_file: Path):
    """Generate samples using the CLI encode path (stego_advanced)."""
    import subprocess

    for level in [3, 4]:
        print(f"\n  Generating: cli_level{level}.gif (stego_advanced via CLI)")
        out = output_dir / f"sample_cli_level{level}.gif"
        cmd = [
            sys.executable, "-m", "meow_decoder.encode",
            "-i", str(payload_file),
            "-o", str(out),
            "-p", "test_password_42",
            "--stego-level", str(level),
            "--carrier", str(carrier_gif),
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                env={**os.environ, "MEOW_TEST_MODE": "1"},
            )
            if result.returncode == 0:
                print(f"    → Saved to: {out}")
            else:
                print(f"    → CLI error (rc={result.returncode}): {result.stderr[:200]}")
        except Exception as e:
            print(f"    → ERROR: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate Meow stego samples for steganalysis testing"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("stego_samples"),
        help="Directory for output samples (default: stego_samples/)"
    )
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  Meow Decoder — Stego Sample Generator")
    print("=" * 60)

    # 1. Create carriers
    print("\n[1/4] Creating synthetic carriers...")
    carrier_gif, carrier_png = create_green_rich_carrier(
        output_dir / "carrier_green", size=(320, 240), frames=10
    )

    # Save clean carrier for comparison
    import shutil
    clean_path = output_dir / "sample_clean_carrier.png"
    shutil.copy2(str(carrier_png), str(clean_path))
    print(f"  Clean carrier (no embedding): {clean_path}")

    # 2. Create payload
    print("\n[2/4] Creating test payload...")
    payload = create_secret_payload(256)  # 256 bytes — moderate payload
    payload_file = output_dir / "test_secret.bin"
    payload_file.write_bytes(payload)
    print(f"  Payload: {len(payload)} bytes → {payload_file}")

    # 3. MultiLayer samples
    print("\n[3/4] Generating MultiLayerStegoEncoder samples...")
    generate_multilayer_samples(output_dir, carrier_gif, carrier_png, payload)

    # 4. CLI samples
    print("\n[4/4] Generating CLI (stego_advanced) samples...")
    generate_cli_samples(output_dir, carrier_gif, payload_file)

    print("\n" + "=" * 60)
    print("  Sample generation complete!")
    print(f"  Output directory: {output_dir}/")
    print()
    print("  Next steps:")
    print("    1. Run external steganalysis tools:")
    print(f"       ./scripts/steganalysis_test_runner.sh {output_dir}/sample_multilayer_stc.png")
    print(f"       ./scripts/steganalysis_test_runner.sh {output_dir}/sample_multilayer_full.png")
    print()
    print("    2. Run chi-square comparison:")
    print(f"       python scripts/steganalysis_chi_square.py {output_dir}/sample_clean_carrier.png --per-channel")
    print(f"       python scripts/steganalysis_chi_square.py {output_dir}/sample_multilayer_stc.png --per-channel")
    print()
    print("    3. Compare results against StegX baselines (see docs/STEGX_COMPARISON.md)")
    print("=" * 60)


if __name__ == "__main__":
    main()
