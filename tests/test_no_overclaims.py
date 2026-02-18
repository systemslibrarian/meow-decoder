"""
Overclaim Enforcement Tests

Ensures that documentation does not contain forbidden marketing phrases
that imply unearned security properties. CI-blocking.

Checked phrases:
- "Signal parity" (without qualification)
- "Signal-grade" (without qualification)
- "NIST Level 5" used as marketing (allowed in technical context with "(experimental)")
- "formally verified" without qualification
- "security-reviewed v1.0" implying external audit
"""

import pathlib
import re

import pytest

WORKSPACE = pathlib.Path(__file__).parent.parent

# Files to scan for overclaims
SCANNED_FILES = [
    WORKSPACE / "README.md",
    WORKSPACE / "docs" / "ARCHITECTURE.md",
    WORKSPACE / "docs" / "PROTOCOL.md",
    WORKSPACE / "docs" / "RATCHET_PROTOCOL.md",
    WORKSPACE / "docs" / "THREAT_MODEL.md",
    WORKSPACE / "docs" / "SECURITY_CLAIMS.md",
    WORKSPACE / "SECURITY.md",
    WORKSPACE / "CHANGELOG.md",
]

# Phrases that MUST NOT appear in scanned docs — exact or regex patterns.
# Each entry: (compiled regex, human-readable description, allowed_contexts)
FORBIDDEN_PHRASES = [
    (
        re.compile(r"Signal[- ]parity", re.IGNORECASE),
        '"Signal parity" — implies equivalence with Signal protocol',
        # Allowed inside code blocks, table-of-contents anchors, or quoted as "old" text
        {"Instead of...", "Signal-parity hardening", "copilot-instructions"},
    ),
    (
        re.compile(r"Signal[- ]grade", re.IGNORECASE),
        '"Signal-grade" — implies Signal-equivalent security',
        {"Instead of...", "Signal-grade PCS"},
    ),
    (
        re.compile(r"NIST Level 5(?!\s*\()", re.IGNORECASE),
        '"NIST Level 5" without qualification — implies certification',
        # Allowed when followed by parenthetical like "(experimental)" or "(ML-KEM-1024, experimental)"
        set(),
    ),
    (
        re.compile(r"(?<!not )formally verified(?!\s*\(|\s*where|\s*in the)", re.IGNORECASE),
        '"formally verified" without qualification — implies proven correctness',
        {"not formally verified", "Formally Verified (Verus)", "proof sketches"},
    ),
    (
        re.compile(r"SECURITY-REVIEWED v1\.0(?!\s*INTERNAL|\s*\(INTERNAL)", re.IGNORECASE),
        '"SECURITY-REVIEWED v1.0" — implies external audit',
        set(),
    ),
]


def _scan_file(filepath: pathlib.Path):
    """Scan a file for forbidden phrases. Returns list of violations."""
    if not filepath.exists():
        return []

    violations = []
    content = filepath.read_text(encoding="utf-8")
    lines = content.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip lines that are inside "Instead of..." tables (allowed context)
        # Skip HTML comments
        if stripped.startswith("<!--") or stripped.startswith("```"):
            continue

        for pattern, description, allowed in FORBIDDEN_PHRASES:
            match = pattern.search(stripped)
            if match:
                matched_text = match.group(0)
                # Check if line contains allowed context
                if any(ctx in stripped for ctx in allowed):
                    continue
                # Allow in SECURITY_CLAIMS.md "Instead of..." table
                if filepath.name == "SECURITY_CLAIMS.md" and "Instead of" in stripped:
                    continue
                # Allow "not formally verified"
                if "not formally verified" in stripped.lower():
                    continue
                rel = filepath.relative_to(WORKSPACE)
                violations.append(
                    f"{rel}:{lineno}: {description}\n"
                    f"    Line: {stripped[:120]}"
                )

    return violations


class TestNoOverclaims:
    """CI-enforced: documentation must not contain forbidden marketing phrases."""

    def test_no_signal_parity(self):
        """'Signal parity' must not appear in docs (implies protocol equivalence)."""
        violations = []
        pattern = re.compile(r"Signal[- ]parity", re.IGNORECASE)
        for filepath in SCANNED_FILES:
            if not filepath.exists():
                continue
            content = filepath.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    # Allow in "Instead of..." context in SECURITY_CLAIMS.md
                    if filepath.name == "SECURITY_CLAIMS.md":
                        continue
                    # Allow "Signal-parity" as historical label in changelog headers
                    # Only if it's clearly past-tense / renamed
                    rel = filepath.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno}: {line.strip()[:100]}")

        assert not violations, (
            "'Signal parity' found in documentation (overclaim):\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_no_signal_grade(self):
        """'Signal-grade' must not appear in docs (implies equivalence)."""
        violations = []
        pattern = re.compile(r"Signal[- ]grade", re.IGNORECASE)
        for filepath in SCANNED_FILES:
            if not filepath.exists():
                continue
            content = filepath.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    if filepath.name == "SECURITY_CLAIMS.md":
                        continue
                    rel = filepath.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno}: {line.strip()[:100]}")

        assert not violations, (
            "'Signal-grade' found in documentation (overclaim):\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_no_unqualified_nist_level_5(self):
        """'NIST Level 5' must include qualification (e.g., '(experimental)')."""
        violations = []
        # Match "NIST Level 5" that is NOT followed by "(experimental" or "(ML-KEM" or "(not"
        pattern = re.compile(
            r"NIST Level 5(?!\s*\((?:experimental|not|ML-KEM|Kyber|target))",
            re.IGNORECASE,
        )
        for filepath in SCANNED_FILES:
            if not filepath.exists():
                continue
            content = filepath.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    if filepath.name == "SECURITY_CLAIMS.md":
                        continue
                    rel = filepath.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno}: {line.strip()[:100]}")

        assert not violations, (
            "'NIST Level 5' without qualification found (overclaim):\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_no_security_reviewed_v1_marketing(self):
        """'SECURITY-REVIEWED v1.0' must not appear in docs (implies audit).

        SECURITY_CLAIMS.md is excluded because it quotes the phrase in a
        mapping table telling authors what NOT to write.
        """
        violations = []
        pattern = re.compile(r"SECURITY-REVIEWED v1\.0", re.IGNORECASE)
        for filepath in SCANNED_FILES:
            if not filepath.exists():
                continue
            if filepath.name == "SECURITY_CLAIMS.md":
                continue
            content = filepath.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    rel = filepath.relative_to(WORKSPACE)
                    violations.append(f"{rel}:{lineno}: {line.strip()[:100]}")

        assert not violations, (
            "'SECURITY-REVIEWED v1.0' found in documentation:\n"
            + "\n".join(f"  - {v}" for v in violations)
            + "\nUse 'INTERNAL REVIEW — no external audit' instead."
        )

    def test_security_claims_exists(self):
        """SECURITY_CLAIMS.md must exist as canonical truth file."""
        claims_path = WORKSPACE / "docs" / "SECURITY_CLAIMS.md"
        assert claims_path.exists(), (
            "docs/SECURITY_CLAIMS.md does not exist. "
            "This file is the canonical source of truth for security claims."
        )

    def test_security_claims_has_disclaimers(self):
        """SECURITY_CLAIMS.md must contain required disclaimers."""
        claims_path = WORKSPACE / "docs" / "SECURITY_CLAIMS.md"
        if not claims_path.exists():
            pytest.skip("SECURITY_CLAIMS.md not found")
        content = claims_path.read_text(encoding="utf-8")

        required = [
            "Not Signal",
            "no equivalence claim",
            "No external audit",
            "experimental",
        ]
        for phrase in required:
            assert phrase.lower() in content.lower(), (
                f"SECURITY_CLAIMS.md missing required disclaimer phrase: '{phrase}'"
            )
