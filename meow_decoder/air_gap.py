"""
Air-Gap Verification

Best-effort checks that the system appears to be air-gapped
(no active network connectivity). This is informational — it
warns the user but does not block operations.

Usage:
    from meow_decoder.air_gap import verify_air_gap

    status = verify_air_gap()
    if not status["air_gapped"]:
        print("WARNING: System may not be air-gapped!")
        for check, result in status["checks"].items():
            print(f"  {check}: {result}")

Security Properties:
    - Checks active network interfaces (excluding loopback)
    - Checks DNS resolver configuration
    - Checks for WiFi adapters
    - Checks for Bluetooth adapters
    - All checks are best-effort and OS-dependent

Limitations:
    - Cannot detect covert channels (USB, audio, EM)
    - Cannot detect network interfaces hidden by rootkits
    - Only works on Linux (returns unknown on other platforms)
    - A sophisticated adversary can spoof these checks
"""

import os
import platform
import subprocess
from pathlib import Path
from typing import Dict, Optional, Any

__all__ = [
    "verify_air_gap",
    "AirGapStatus",
]


class AirGapStatus:
    """Structured result from air-gap verification."""

    def __init__(self):
        self.checks: Dict[str, Optional[bool]] = {}
        self.details: Dict[str, str] = {}

    @property
    def air_gapped(self) -> bool:
        """True if all checks passed (no network detected)."""
        # None = could not check; treat as ambiguous (not failing)
        return all(v is True for v in self.checks.values() if v is not None)

    @property
    def unknown(self) -> bool:
        """True if any check returned None (could not determine)."""
        return any(v is None for v in self.checks.values())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to plain dict for serialization."""
        return {
            "air_gapped": self.air_gapped,
            "unknown": self.unknown,
            "checks": dict(self.checks),
            "details": dict(self.details),
        }


def verify_air_gap() -> AirGapStatus:
    """
    Best-effort check that the system appears to be air-gapped.

    Returns:
        AirGapStatus with per-check results.

    Checks performed (Linux only):
        - no_active_network: No non-loopback interfaces in UP state
        - no_dns: No nameservers configured in /etc/resolv.conf
        - no_wifi: No wireless adapters detected
        - no_bluetooth: No Bluetooth adapters detected
        - no_default_route: No default gateway configured
    """
    status = AirGapStatus()

    if platform.system() != "Linux":
        status.checks["platform"] = None
        status.details["platform"] = (
            f"Air-gap checks only supported on Linux (got {platform.system()})"
        )
        return status

    _check_network_interfaces(status)
    _check_dns(status)
    _check_wifi(status)
    _check_bluetooth(status)
    _check_default_route(status)

    return status


def _check_network_interfaces(status: AirGapStatus) -> None:
    """Check for active non-loopback network interfaces."""
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show", "up"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            status.checks["no_active_network"] = None
            status.details["no_active_network"] = "ip command failed"
            return

        active = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            # Format: "N: ifname: <FLAGS> ..."
            parts = line.split(":")
            if len(parts) >= 2:
                ifname = parts[1].strip()
                # Skip loopback
                if ifname == "lo":
                    continue
                active.append(ifname)

        status.checks["no_active_network"] = len(active) == 0
        if active:
            status.details["no_active_network"] = f"Active interfaces: {', '.join(active)}"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        status.checks["no_active_network"] = None
        status.details["no_active_network"] = "Could not check (ip command unavailable)"


def _check_dns(status: AirGapStatus) -> None:
    """Check for configured DNS resolvers."""
    try:
        resolv = Path("/etc/resolv.conf")
        if not resolv.exists():
            status.checks["no_dns"] = True
            return

        content = resolv.read_text()
        nameservers = [
            line.split()[1]
            for line in content.split("\n")
            if line.strip().startswith("nameserver") and len(line.split()) >= 2
        ]

        # Filter out localhost resolvers (they're local, not external)
        external = [ns for ns in nameservers if ns not in ("127.0.0.1", "::1", "127.0.0.53")]

        status.checks["no_dns"] = len(external) == 0
        if external:
            status.details["no_dns"] = f"External nameservers: {', '.join(external)}"
    except (OSError, PermissionError):
        status.checks["no_dns"] = None
        status.details["no_dns"] = "Could not read /etc/resolv.conf"


def _check_wifi(status: AirGapStatus) -> None:
    """Check for wireless network adapters."""
    try:
        # /sys/class/net/*/wireless existence indicates WiFi
        wireless_found = []
        net_dir = Path("/sys/class/net")
        if net_dir.exists():
            for iface in net_dir.iterdir():
                wireless_dir = iface / "wireless"
                if wireless_dir.exists():
                    wireless_found.append(iface.name)

        # Also check rfkill for WiFi
        if not wireless_found:
            try:
                result = subprocess.run(
                    ["rfkill", "list", "wifi"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.stdout.strip():
                    wireless_found.append("(rfkill detected)")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        status.checks["no_wifi"] = len(wireless_found) == 0
        if wireless_found:
            status.details["no_wifi"] = f"WiFi adapters: {', '.join(wireless_found)}"
    except OSError:
        status.checks["no_wifi"] = None
        status.details["no_wifi"] = "Could not check wireless adapters"


def _check_bluetooth(status: AirGapStatus) -> None:
    """Check for Bluetooth adapters."""
    try:
        bt_found = False

        # Check /sys/class/bluetooth
        bt_dir = Path("/sys/class/bluetooth")
        if bt_dir.exists() and any(bt_dir.iterdir()):
            bt_found = True

        # Also check rfkill for Bluetooth
        if not bt_found:
            try:
                result = subprocess.run(
                    ["rfkill", "list", "bluetooth"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.stdout.strip():
                    bt_found = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        status.checks["no_bluetooth"] = not bt_found
        if bt_found:
            status.details["no_bluetooth"] = "Bluetooth adapter detected"
    except OSError:
        status.checks["no_bluetooth"] = None
        status.details["no_bluetooth"] = "Could not check Bluetooth"


def _check_default_route(status: AirGapStatus) -> None:
    """Check for a default network route."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        has_default = bool(result.stdout.strip())
        status.checks["no_default_route"] = not has_default
        if has_default:
            status.details["no_default_route"] = (
                f"Default route: {result.stdout.strip().split(chr(10))[0]}"
            )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        status.checks["no_default_route"] = None
        status.details["no_default_route"] = "Could not check routes"
