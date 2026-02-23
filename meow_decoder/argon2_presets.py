"""
Argon2id KDF Presets for Meow Decoder

Provides named parameter presets for Argon2id key derivation, balancing
security against usability for different threat models and time constraints.

Presets:
    paranoid       — 512 MiB, 20 iterations, 4 threads (~10-40s on 2020 laptop)
                     Strongest vs non-state attackers (default).
    balanced       — 256 MiB, 8 iterations, 4 threads (~4-15s on 2020 laptop)
                     Good compromise for regular use.
    activist-fast  — 194 MiB, 4 iterations, 4 threads (~2-8s on 2020 laptop)
                     Still meaningfully expensive for consumer/small-team
                     attackers, but usable under time pressure.
    test           — 32 MiB, 1 iteration, 1 thread (~0.1s)
                     CI/testing only. NOT for production.

⚠️ WARNING: Even strong Argon2id parameters do not protect against a state
actor who obtains the real password via coercion (physical torture, legal
compulsion, or $5 wrench attack). Password-based encryption is the last
line of defense, not the only one. Consider operational security measures
(dead-man switches, duress passwords, Schrödinger mode) as additional layers.

See also:
    - OWASP Password Storage Cheat Sheet
    - NIST SP 800-63B
    - docs/THREAT_MODEL.md
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Argon2Preset:
    """Immutable Argon2id parameter preset.

    Attributes:
        name: Human-readable preset name.
        memory_kib: Memory cost in KiB.
        iterations: Time cost (number of passes).
        parallelism: Degree of parallelism (threads).
        description: User-facing description of security level.
        approximate_time: Rough timing estimate on 2020 laptop.
    """

    name: str
    memory_kib: int
    iterations: int
    parallelism: int
    description: str
    approximate_time: str


# ── Named Presets ────────────────────────────────────────────────────────────

PRESET_PARANOID = Argon2Preset(
    name="paranoid",
    memory_kib=524288,  # 512 MiB
    iterations=20,
    parallelism=4,
    description=(
        "Maximum brute-force resistance. 8x OWASP minimum. " "Very strong vs non-state attackers."
    ),
    approximate_time="~10-40s on 2020 laptop",
)

PRESET_BALANCED = Argon2Preset(
    name="balanced",
    memory_kib=262144,  # 256 MiB
    iterations=8,
    parallelism=4,
    description=("Strong security with reasonable wait time. " "Good for regular use."),
    approximate_time="~4-15s on 2020 laptop",
)

PRESET_ACTIVIST_FAST = Argon2Preset(
    name="activist-fast",
    memory_kib=198656,  # 194 MiB (194 * 1024)
    iterations=4,
    parallelism=4,
    description=(
        "Still meaningfully expensive for consumer/small-team attackers, "
        "but usable under time pressure (border crossings, protests, etc.)."
    ),
    approximate_time="~2-8s on 2020 laptop",
)

PRESET_TEST = Argon2Preset(
    name="test",
    memory_kib=32768,  # 32 MiB
    iterations=1,
    parallelism=1,
    description="CI/testing only. NOT for production use.",
    approximate_time="~0.1s",
)

# Registry of all presets
PRESETS = {
    "paranoid": PRESET_PARANOID,
    "balanced": PRESET_BALANCED,
    "activist-fast": PRESET_ACTIVIST_FAST,
    "test": PRESET_TEST,
}

# Default preset name (overridden by MEOW_TEST_MODE or MEOW_KDF_PRESET env vars)
DEFAULT_PRESET_NAME = "paranoid"


def get_preset(name: Optional[str] = None) -> Argon2Preset:
    """Get an Argon2id preset by name.

    Resolution order:
        1. Explicit ``name`` argument.
        2. MEOW_KDF_PRESET environment variable.
        3. MEOW_TEST_MODE=1 → "test" preset.
        4. DEFAULT_PRESET_NAME ("paranoid").

    Args:
        name: Preset name, or None to auto-detect.

    Returns:
        Argon2Preset with the resolved parameters.

    Raises:
        ValueError: If the preset name is not recognized.
    """
    if name is None:
        name = os.environ.get("MEOW_KDF_PRESET", "").strip().lower()

    if not name:
        test_mode = os.environ.get("MEOW_TEST_MODE", "").lower() in ("1", "true", "yes")
        if test_mode:
            name = "test"
        else:
            name = DEFAULT_PRESET_NAME

    if name not in PRESETS:
        valid = ", ".join(sorted(PRESETS.keys()))
        raise ValueError(f"Unknown Argon2id preset '{name}'. Valid presets: {valid}")

    return PRESETS[name]


def get_active_parameters() -> Argon2Preset:
    """Get the currently active Argon2id parameters.

    Convenience function that resolves the active preset from
    environment variables and returns it.
    """
    return get_preset()


def list_presets() -> str:
    """Return a formatted string listing all available presets.

    Suitable for CLI --help or user documentation.
    """
    lines = ["Available Argon2id presets:"]
    for name, preset in sorted(PRESETS.items()):
        lines.append(f"  {name:16s} — {preset.description}")
        lines.append(
            f"                     Memory: {preset.memory_kib // 1024} MiB, "
            f"Iterations: {preset.iterations}, "
            f"Parallelism: {preset.parallelism}"
        )
        lines.append(f"                     Estimated time: {preset.approximate_time}")
    lines.append("")
    lines.append(
        "⚠️  Even strong parameters do not protect against a state actor "
        "who obtains the real password via coercion."
    )
    return "\n".join(lines)
