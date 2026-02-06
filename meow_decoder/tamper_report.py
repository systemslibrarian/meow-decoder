"""
Tamper Timeline Visualization.

Generates frame-by-frame MAC verification reports in ASCII or JSON format.
Highlights suspicious patterns such as clustered failures that may indicate
targeted frame injection attacks.

MT-7 from tasklists.md.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import List, Optional

# ── Data Structures ──────────────────────────────────────────────────────────


@dataclass
class FrameResult:
    """Verification result for a single frame."""

    index: int
    valid: bool
    detail: str = ""  # optional extra info (e.g. "MAC mismatch", "QR unreadable")


@dataclass
class TamperReport:
    """Aggregated tamper timeline report."""

    total_frames: int = 0
    results: List[FrameResult] = field(default_factory=list)
    clusters: List[dict] = field(default_factory=list)  # detected suspicious clusters

    # ── Recording ────────────────────────────────────────────────────────

    def record(self, index: int, valid: bool, detail: str = "") -> None:
        self.results.append(FrameResult(index=index, valid=valid, detail=detail))
        self.total_frames += 1

    # ── Analysis ─────────────────────────────────────────────────────────

    @property
    def valid_count(self) -> int:
        return sum(1 for r in self.results if r.valid)

    @property
    def invalid_count(self) -> int:
        return sum(1 for r in self.results if not r.valid)

    @property
    def success_rate(self) -> float:
        if self.total_frames == 0:
            return 0.0
        return self.valid_count / self.total_frames

    def detect_clusters(self, window: int = 5, threshold: float = 0.6) -> List[dict]:
        """Detect suspicious clusters of failures.

        A *cluster* is a sliding window of ``window`` consecutive frames where
        the failure ratio meets or exceeds ``threshold``.

        Returns a list of dicts: ``{"start": int, "end": int, "failures": int}``.
        """
        if not self.results:
            self.clusters = []
            return self.clusters

        # Build a dense validity array indexed by frame number
        max_idx = max(r.index for r in self.results)
        # None = no data for that index, True/False = result
        validity: List[Optional[bool]] = [None] * (max_idx + 1)
        for r in self.results:
            validity[r.index] = r.valid

        clusters: List[dict] = []
        i = 0
        while i <= max_idx - window + 1:
            chunk = validity[i : i + window]
            # Only consider positions where we have data
            data_points = [v for v in chunk if v is not None]
            if len(data_points) >= 2:
                fail_count = sum(1 for v in data_points if not v)
                ratio = fail_count / len(data_points)
                if ratio >= threshold:
                    # Extend cluster to the right while failures continue
                    end = i + window - 1
                    while end + 1 <= max_idx:
                        next_val = validity[end + 1]
                        if next_val is not None and not next_val:
                            end += 1
                        else:
                            break
                    clusters.append(
                        {
                            "start": i,
                            "end": end,
                            "failures": sum(
                                1 for v in validity[i : end + 1] if v is not None and not v
                            ),
                        }
                    )
                    i = end + 1
                    continue
            i += 1

        self.clusters = clusters
        return clusters

    # ── Output Formatters ────────────────────────────────────────────────

    def ascii_timeline(self, width: int = 60) -> str:
        """Render an ASCII timeline of frame verification results.

        ``width`` controls how many columns the bar occupies.  Each column
        represents one or more frames (bucketed).

        Legend:  ``█`` = all valid,  ``▒`` = mixed,  ``░`` = all invalid,
                 ``·`` = no data
        """
        if not self.results:
            return "(no frames recorded)"

        max_idx = max(r.index for r in self.results)
        # Build a dense validity map
        validity: List[Optional[bool]] = [None] * (max_idx + 1)
        for r in self.results:
            validity[r.index] = r.valid

        bucket_size = max(1, math.ceil((max_idx + 1) / width))
        cols: List[str] = []

        for b in range(0, max_idx + 1, bucket_size):
            chunk = validity[b : b + bucket_size]
            data = [v for v in chunk if v is not None]
            if not data:
                cols.append("·")
            elif all(data):
                cols.append("█")
            elif not any(data):
                cols.append("░")
            else:
                cols.append("▒")

        bar = "".join(cols)

        # Build full report
        lines: List[str] = []
        lines.append("┌─ Tamper Timeline ─────────────────────────────────────────┐")
        lines.append(
            f"│ Frames: {self.total_frames:>5}  "
            f"Valid: {self.valid_count:>5}  "
            f"Invalid: {self.invalid_count:>5}  "
            f"Rate: {self.success_rate * 100:5.1f}% │"
        )
        lines.append("├───────────────────────────────────────────────────────────┤")
        lines.append(f"│ [{bar:<{width}}] │")
        lines.append("│ Legend: █ valid  ▒ mixed  ░ invalid  · no data           │")

        # Clusters
        self.detect_clusters()
        if self.clusters:
            lines.append("├───────────────────────────────────────────────────────────┤")
            lines.append("│ ⚠  Suspicious clusters detected:                        │")
            for c in self.clusters:
                desc = f"  Frames {c['start']}–{c['end']}: {c['failures']} failures"
                lines.append(f"│{desc:<59}│")
        else:
            lines.append("├───────────────────────────────────────────────────────────┤")
            lines.append("│ ✓  No suspicious failure clusters detected               │")

        lines.append("└───────────────────────────────────────────────────────────┘")

        # Detailed failure list
        failed = [r for r in self.results if not r.valid]
        if failed:
            lines.append("")
            lines.append("Failed frames:")
            for r in failed[:20]:  # cap at 20 to avoid flooding
                detail_str = f" ({r.detail})" if r.detail else ""
                lines.append(f"  Frame {r.index:>5}: FAIL{detail_str}")
            if len(failed) > 20:
                lines.append(f"  ... and {len(failed) - 20} more")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Serialize report as JSON for machine consumption."""
        self.detect_clusters()
        return json.dumps(
            {
                "total_frames": self.total_frames,
                "valid": self.valid_count,
                "invalid": self.invalid_count,
                "success_rate": round(self.success_rate, 4),
                "clusters": self.clusters,
                "frames": [
                    {"index": r.index, "valid": r.valid, "detail": r.detail} for r in self.results
                ],
            },
            indent=2,
        )
