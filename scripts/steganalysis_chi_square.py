#!/usr/bin/env python3
"""
Chi-Square Steganalysis Test for Meow Decoder Stego Outputs
============================================================

Implements the Westfeld chi-square attack on LSB planes of PNG/APNG/GIF
carrier images. Designed for comparison against StegX's claimed 13K chi²
statistic baseline.

Usage:
    python scripts/steganalysis_chi_square.py <image_path> [--per-channel] [--json]
    python scripts/steganalysis_chi_square.py stego_output.png --per-channel --json

Output interpretation:
    - Low chi² statistic = pixel value pairs NOT equalized = no LSB replacement detected
    - High p-value (>0.95) = pairs ARE equalized = LSB embedding likely
    - StegX baseline: ~13K on their test images vs Steghide's ~119K (lower is better)
    - Meow target: <15K at moderate payloads (<0.15 bpp effective)

References:
    - Westfeld & Pfitzmann, "Attacks on Steganographic Systems" (1999)
    - StegX README chi-square comparison (Delta-Sec/StegX)
"""

from __future__ import annotations

import argparse
import json
import sys
from math import erfc, sqrt
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from PIL import Image


def chi2_survival(chi_stat: float, dof: int) -> float:
    """Compute chi-square survival function P(X > chi_stat) for given dof.

    Uses scipy if available; falls back to Wilson-Hilferty normal approximation
    (accurate for dof > 30, which is typical for images).
    """
    if dof <= 0:
        return 1.0
    try:
        from scipy.stats import chi2  # type: ignore
        return float(1.0 - chi2.cdf(chi_stat, dof))
    except ImportError:
        pass

    # Wilson-Hilferty transform fallback
    k = float(dof)
    t = (chi_stat / k) ** (1.0 / 3.0)
    mu = 1.0 - 2.0 / (9.0 * k)
    sigma = sqrt(2.0 / (9.0 * k))
    if sigma < 1e-15:
        return 1.0 if chi_stat <= k else 0.0
    z = (t - mu) / sigma
    p = 0.5 * erfc(z / sqrt(2.0))
    return max(0.0, min(1.0, p))


def chi_square_lsb_channel(pixel_values: np.ndarray) -> Dict[str, Any]:
    """Chi-square test on a single channel's pixel values.

    Groups values into pairs (2k, 2k+1) and tests whether the counts
    within each pair are equalized — a hallmark of naive LSB replacement.

    STC-based embedding does NOT equalize pairs (it minimizes flips via
    syndrome coding), so this test should yield LOW chi² for Meow output.
    """
    flat = pixel_values.flatten().astype(np.int32)
    n_pixels = len(flat)

    # Group into PoV (Pairs of Values): (0,1), (2,3), (4,5), ...
    pairs = flat // 2
    unique_pairs = np.unique(pairs)

    even_counts: List[int] = []
    odd_counts: List[int] = []
    pair_labels: List[int] = []

    for pv in unique_pairs:
        val_even = int(pv) * 2
        val_odd = int(pv) * 2 + 1
        c_even = int(np.sum(flat == val_even))
        c_odd = int(np.sum(flat == val_odd))
        total = c_even + c_odd
        if total > 4:  # Min count filter to avoid spurious pairs
            even_counts.append(c_even)
            odd_counts.append(c_odd)
            pair_labels.append(int(pv))

    n_pairs = len(even_counts)
    if n_pairs < 10:
        return {
            "chi_stat": 0.0,
            "dof": 0,
            "p_value": 1.0,
            "n_pairs": n_pairs,
            "n_pixels": n_pixels,
            "verdict": "INSUFFICIENT_DATA",
        }

    even = np.array(even_counts, dtype=np.float64)
    odd = np.array(odd_counts, dtype=np.float64)
    expected = (even + odd) / 2.0
    expected = np.maximum(expected, 1.0)  # Avoid /0

    chi_stat = float(
        np.sum((even - expected) ** 2 / expected + (odd - expected) ** 2 / expected)
    )
    dof = n_pairs - 1
    p_value = chi2_survival(chi_stat, dof)

    # Interpretation:
    # p_value > 0.95 → pairs are equalized → LSB replacement likely detected
    # p_value < 0.50 → pairs are NOT equalized → clean or STC-embedded
    if p_value > 0.95:
        verdict = "DETECTED (pair equalization — LSB replacement likely)"
    elif p_value > 0.80:
        verdict = "SUSPICIOUS (moderate pair equalization)"
    elif p_value > 0.50:
        verdict = "BORDERLINE (slight anomaly)"
    else:
        verdict = "CLEAN (no pair equalization detected)"

    return {
        "chi_stat": round(chi_stat, 2),
        "dof": dof,
        "p_value": round(p_value, 6),
        "n_pairs": n_pairs,
        "n_pixels": n_pixels,
        "verdict": verdict,
    }


def analyze_image(
    image_path: str,
    per_channel: bool = False,
) -> Dict[str, Any]:
    """Run chi-square analysis on an image file.

    Supports PNG, APNG (first frame), GIF (first frame), BMP, JPEG.
    For animated formats, extracts and analyzes each frame.

    Args:
        image_path: Path to image file
        per_channel: If True, analyze R/G/B channels independently

    Returns:
        Dictionary with chi² statistics, p-values, and verdicts
    """
    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")

    results: Dict[str, Any] = {
        "file": str(path),
        "file_size_bytes": path.stat().st_size,
    }

    # Try to load frames (animated GIF/APNG)
    frames: List[np.ndarray] = []
    try:
        img = Image.open(image_path)
        results["format"] = img.format or "UNKNOWN"
        results["mode"] = img.mode
        results["size"] = f"{img.width}x{img.height}"

        # Extract all frames for animated images
        frame_idx = 0
        while True:
            try:
                img.seek(frame_idx)
                frame = np.array(img.convert("RGB"))
                frames.append(frame)
                frame_idx += 1
            except EOFError:
                break

        if not frames:
            frames = [np.array(img.convert("RGB"))]

    except Exception as e:
        raise RuntimeError(f"Failed to open image: {e}")

    results["n_frames"] = len(frames)
    results["frames"] = []

    # Analyze each frame
    aggregate_chi = []
    for fidx, frame in enumerate(frames):
        frame_result: Dict[str, Any] = {"frame": fidx}

        if per_channel:
            channel_names = ["R", "G", "B"]
            for ch_idx, ch_name in enumerate(channel_names):
                ch_data = frame[:, :, ch_idx]
                ch_result = chi_square_lsb_channel(ch_data)
                frame_result[ch_name] = ch_result
                aggregate_chi.append(ch_result["chi_stat"])
            # Also compute combined
            combined = chi_square_lsb_channel(frame)
            frame_result["combined"] = combined
            aggregate_chi.append(combined["chi_stat"])
        else:
            combined = chi_square_lsb_channel(frame)
            frame_result["combined"] = combined
            aggregate_chi.append(combined["chi_stat"])

        results["frames"].append(frame_result)

    # Aggregate statistics
    if aggregate_chi:
        results["aggregate"] = {
            "mean_chi_stat": round(float(np.mean(aggregate_chi)), 2),
            "max_chi_stat": round(float(np.max(aggregate_chi)), 2),
            "min_chi_stat": round(float(np.min(aggregate_chi)), 2),
            "stegx_comparison": _stegx_comparison(float(np.mean(aggregate_chi))),
        }

    return results


def _stegx_comparison(mean_chi: float) -> str:
    """Compare against StegX's claimed baselines.

    StegX README claims:
    - StegX output: ~13K chi² statistic
    - Steghide output: ~119K chi² statistic
    - "Low anomaly" = chi² < ~20K on their test images

    NOTE: Direct comparison requires same image size and content.
    Chi² scales with number of pixels, so normalize by pixel count
    for fair comparison. These thresholds are rough guidelines.
    """
    if mean_chi < 5_000:
        return "EXCELLENT — well below StegX baseline (~13K)"
    elif mean_chi < 15_000:
        return "GOOD — comparable to StegX baseline (~13K)"
    elif mean_chi < 50_000:
        return "MODERATE — above StegX but well below Steghide (~119K)"
    elif mean_chi < 120_000:
        return "POOR — approaching Steghide levels (~119K)"
    else:
        return "CRITICAL — exceeds Steghide baseline (~119K)"


def print_report(results: Dict[str, Any], as_json: bool = False) -> None:
    """Print human-readable or JSON report."""
    if as_json:
        print(json.dumps(results, indent=2))
        return

    print(f"\n{'='*70}")
    print(f"  Chi-Square LSB Steganalysis Report")
    print(f"{'='*70}")
    print(f"  File:    {results['file']}")
    print(f"  Format:  {results.get('format', 'N/A')}")
    print(f"  Size:    {results.get('size', 'N/A')}")
    print(f"  Mode:    {results.get('mode', 'N/A')}")
    print(f"  Frames:  {results['n_frames']}")
    print(f"  File sz: {results['file_size_bytes']:,} bytes")
    print(f"{'='*70}")

    for fr in results["frames"]:
        print(f"\n  Frame {fr['frame']}:")
        if "combined" in fr:
            c = fr["combined"]
            print(f"    Combined: chi²={c['chi_stat']:>12,.2f}  "
                  f"dof={c['dof']:>6}  p={c['p_value']:.6f}  "
                  f"→ {c['verdict']}")
        for ch in ["R", "G", "B"]:
            if ch in fr:
                c = fr[ch]
                print(f"    {ch} chan:   chi²={c['chi_stat']:>12,.2f}  "
                      f"dof={c['dof']:>6}  p={c['p_value']:.6f}  "
                      f"→ {c['verdict']}")

    if "aggregate" in results:
        agg = results["aggregate"]
        print(f"\n{'='*70}")
        print(f"  AGGREGATE")
        print(f"    Mean chi²:  {agg['mean_chi_stat']:>12,.2f}")
        print(f"    Max  chi²:  {agg['max_chi_stat']:>12,.2f}")
        print(f"    Min  chi²:  {agg['min_chi_stat']:>12,.2f}")
        print(f"    vs StegX:   {agg['stegx_comparison']}")
    print(f"{'='*70}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Chi-square LSB steganalysis — compare against StegX baselines"
    )
    parser.add_argument("image", help="Path to stego image (PNG/APNG/GIF/BMP)")
    parser.add_argument(
        "--per-channel", action="store_true",
        help="Analyze R/G/B channels independently"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output JSON instead of human-readable report"
    )
    args = parser.parse_args()

    results = analyze_image(args.image, per_channel=args.per_channel)
    print_report(results, as_json=args.json)


if __name__ == "__main__":
    main()
