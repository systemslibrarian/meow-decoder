"""
meow_decoder/merge.py — Multi-device capture merge utility.

When multiple phones capture the same GIF transfer simultaneously (Clowder
mode), each individual capture JSON may contain different subsets of fountain
code droplets.  This CLI module merges two or more capture JSONs into one
unified response that maximises frame coverage before handing off to the
decoder.

Usage (CLI):
    python -m meow_decoder.merge \\
        --input capture-phone-a.json capture-phone-b.json \\
        --output merged.json

Usage (Python):
    from meow_decoder.merge import merge_captures
    merged = merge_captures(['capture-a.json', 'capture-b.json'])
    # or from in-memory dicts:
    merged = merge_capture_dicts([dict_a, dict_b])

Security notes:
    - All inputs must share the same session_id.  Merging captures from
      different sessions is rejected (ValueError).
    - Duplicate frame indices are deduplicated; the first-seen payload wins
      (they are all cryptographically identical for the same index).
    - No network I/O.  Reads and writes local files only.
    - The merged output is structurally identical to a single-device capture
      JSON and is accepted by meow-decode-gif without modification.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ── Types (mirrors mobile/src/types/capture.ts CaptureResponse) ───────────────

CaptureResponse = dict[str, Any]


# ── Core merge logic ──────────────────────────────────────────────────────────


def merge_capture_dicts(responses: list[CaptureResponse]) -> CaptureResponse:
    """Merge a list of CaptureResponse dicts into one unified response.

    Parameters
    ----------
    responses:
        Two or more capture response dicts (parsed from JSON).  All must share
        the same ``session_id``.

    Returns
    -------
    CaptureResponse
        A single merged response.  ``frames_captured`` and ``frames_missed``
        are recalculated from the deduplicated frame set.

    Raises
    ------
    ValueError
        If fewer than two responses are supplied, or if responses have
        mismatched session IDs.
    """
    if len(responses) < 1:
        raise ValueError("merge_capture_dicts requires at least one response")

    if len(responses) == 1:
        return responses[0]

    # Validate session_id consistency
    session_ids = {r.get("session_id") for r in responses}
    if len(session_ids) > 1:
        raise ValueError(f"Cannot merge captures from different sessions: {session_ids!r}")
    session_id: str = next(iter(session_ids)) or ""

    # Use the first response as the base; it carries all session-level metadata
    # (expected_frames, timeout_seconds, block_size, etc.)
    base = dict(responses[0])

    # Deduplicate frames by index.  We keep a dict[index -> payload] so the
    # first-seen payload wins.  All legitimate payloads for the same index are
    # identical (fountain droplet is deterministic given the seed).
    seen: dict[int, str] = {}

    for resp in responses:
        for frame_entry in resp.get("frames", []):
            idx: int = frame_entry.get("index", -1)
            if idx not in seen:
                seen[idx] = frame_entry

    # Rebuild the merged frame list sorted by index
    merged_frames = [seen[k] for k in sorted(seen.keys())]

    # Recalculate expected vs. captured / missed
    expected: int = base.get("frames_expected", base.get("expected_frames", 0))
    captured = len(merged_frames)
    missed = max(0, expected - captured)

    base["frames"] = merged_frames
    base["frames_captured"] = captured
    base["frames_missed"] = missed
    base["session_id"] = session_id
    base["_merge_source_count"] = len(responses)

    return base


def merge_captures(paths: list[str]) -> CaptureResponse:
    """Load capture JSONs from *paths* and merge them.

    Parameters
    ----------
    paths:
        Paths to one or more capture JSON files produced by Meow Capture.

    Returns
    -------
    CaptureResponse
        The merged capture response.
    """
    responses: list[CaptureResponse] = []
    for p in paths:
        text = Path(p).read_text(encoding="utf-8")
        data = json.loads(text)
        # Accept both a bare response object and a wrapped {"response": ...}
        if "response" in data and isinstance(data["response"], dict):
            data = data["response"]
        responses.append(data)

    return merge_capture_dicts(responses)


# ── CLI entry point ───────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m meow_decoder.merge",
        description="Merge two or more Meow Capture JSON files into one.",
    )
    parser.add_argument(
        "--input",
        "-i",
        nargs="+",
        required=True,
        metavar="FILE",
        help="Input capture JSON file(s). At least two recommended.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="-",
        metavar="FILE",
        help="Output path.  Use '-' for stdout (default).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print the output JSON (default: on).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        merged = merge_captures(args.input)
    except (ValueError, json.JSONDecodeError, FileNotFoundError) as exc:
        print(f"[merge] Error: {exc}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    out_text = json.dumps(merged, indent=indent, ensure_ascii=False)

    if args.output == "-":
        print(out_text)
    else:
        out_path = Path(args.output)
        out_path.write_text(out_text, encoding="utf-8")
        src_count = merged.get("_merge_source_count", len(args.input))
        frames_captured = merged.get("frames_captured", "?")
        frames_expected = merged.get("frames_expected", merged.get("expected_frames", "?"))
        print(
            f"[merge] Merged {src_count} capture(s) → {out_path}  "
            f"({frames_captured}/{frames_expected} frames)",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
