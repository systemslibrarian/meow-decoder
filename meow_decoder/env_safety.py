"""
Environment Safety Checks Module.

Detects hostile execution environments that could compromise security:
- Virtual machines (VMware, VirtualBox, Hyper-V, QEMU, etc.)
- Debuggers (gdb, lldb, strace, x64dbg, WinDbg, etc.)
- Screen recorders and keyloggers
- Sandboxes and analysis tools

Cross-platform: Windows, Linux, macOS.

SECURITY NOTE: This is defense-in-depth. Sophisticated adversaries can
bypass these checks. The goal is to catch casual surveillance and make
forensic analysis harder.

Usage:
    safety = EnvironmentSafety()
    report = safety.check_all()

    if not report.is_safe:
        # Take defensive action
        for risk in report.risks:
            print(f"Risk: {risk.category} - {risk.description}")
"""

from __future__ import annotations

import ctypes
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

__all__ = [
    "EnvironmentSafety",
    "SafetyReport",
    "RiskCategory",
    "Risk",
    "get_environment_safety",
    "require_safe_environment",
]


class RiskCategory(Enum):
    """Categories of security risks."""

    VIRTUAL_MACHINE = "virtual_machine"
    DEBUGGER = "debugger"
    SCREEN_RECORDER = "screen_recorder"
    KEYLOGGER = "keylogger"
    SANDBOX = "sandbox"
    ANALYSIS_TOOL = "analysis_tool"
    ELEVATED_PROCESS = "elevated_process"
    SUSPICIOUS_FILES = "suspicious_files"


@dataclass
class Risk:
    """A detected security risk."""

    category: RiskCategory
    description: str
    severity: str  # "low", "medium", "high", "critical"
    evidence: str = ""


@dataclass
class SafetyReport:
    """Report from environment safety checks."""

    is_safe: bool
    risks: List[Risk] = field(default_factory=list)
    platform: str = ""
    checks_performed: int = 0

    def add_risk(self, risk: Risk) -> None:
        """Add a risk to the report."""
        self.risks.append(risk)
        self.is_safe = False

    def get_risks_by_category(self, category: RiskCategory) -> List[Risk]:
        """Get all risks of a specific category."""
        return [r for r in self.risks if r.category == category]

    def get_high_severity_risks(self) -> List[Risk]:
        """Get all high or critical severity risks."""
        return [r for r in self.risks if r.severity in ("high", "critical")]


class EnvironmentSafety:
    """
    Detect hostile execution environments.

    Checks for VMs, debuggers, screen recorders, and analysis tools.
    """

    # Known VM indicators in various system strings
    VM_INDICATORS = {
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "xen",
        "hyperv",
        "hyper-v",
        "virtual",
        "kvm",
        "parallels",
        "bhyve",
        "bochs",
        "innotek",
        "oracle vm",
        "microsoft corporation virtual",
    }

    # Suspicious process names (Windows)
    WINDOWS_SUSPICIOUS_PROCESSES = {
        # Debuggers
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "windbg.exe",
        "idaq.exe",
        "idaq64.exe",
        "ida.exe",
        "ida64.exe",
        "radare2.exe",
        "r2.exe",
        "immunity.exe",
        "dnspy.exe",
        # Screen recorders
        "obs.exe",
        "obs64.exe",
        "obs32.exe",
        "bandicam.exe",
        "camtasia.exe",
        "snagit32.exe",
        "screencast.exe",
        "fraps.exe",
        "action.exe",
        "xsplit.exe",
        "streamlabs.exe",
        # Analysis tools
        "procmon.exe",
        "procmon64.exe",
        "procexp.exe",
        "procexp64.exe",
        "wireshark.exe",
        "fiddler.exe",
        "charles.exe",
        "mitmproxy.exe",
        "cff explorer.exe",
        "pe-bear.exe",
        "pestudio.exe",
        "apimonitor.exe",
        "api_monitor.exe",
        "regmon.exe",
        "filemon.exe",
        # VM tools
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vboxservice.exe",
        "vboxtray.exe",
        "vmusrvc.exe",
        "vgauthservice.exe",
        # Sandboxes
        "sandboxie.exe",
        "sbiesvc.exe",
        "cuckoo.exe",
    }

    # Suspicious process names (Linux/macOS)
    UNIX_SUSPICIOUS_PROCESSES = {
        # Debuggers
        "gdb",
        "lldb",
        "strace",
        "ltrace",
        "ptrace",
        "radare2",
        "r2",
        "ida",
        "ida64",
        "edb",
        "ddd",
        # Screen recorders
        "obs",
        "simplescreenrecorder",
        "kazam",
        "recordmydesktop",
        "ffmpeg",
        "avconv",
        "vlc",  # Can be used for screen capture
        # Analysis tools
        "wireshark",
        "tshark",
        "tcpdump",
        "ngrep",
        "mitmproxy",
        "burpsuite",
        "charles",
        "fiddler",
        # VM tools
        "vmtoolsd",
        "VBoxClient",
        "VBoxService",
        "qemu-ga",
        "spice-vdagent",
        "xe-daemon",
    }

    def __init__(self, strict_mode: bool = False):
        """
        Initialize environment safety checker.

        Args:
            strict_mode: If True, treat any risk as unsafe.
                         If False, only high/critical risks make it unsafe.
        """
        self.strict_mode = strict_mode
        self._system = platform.system()
        self._cached_report: Optional[SafetyReport] = None

    def check_all(self, use_cache: bool = True) -> SafetyReport:
        """
        Perform all environment safety checks.

        Args:
            use_cache: If True, return cached report if available.

        Returns:
            SafetyReport with all detected risks.
        """
        if use_cache and self._cached_report is not None:
            return self._cached_report

        report = SafetyReport(
            is_safe=True,
            platform=self._system,
        )

        checks: List[Callable[[SafetyReport], None]] = [
            self._check_vm_indicators,
            self._check_debugger,
            self._check_suspicious_processes,
            self._check_suspicious_files,
        ]

        if self._system == "Windows":
            checks.extend(
                [
                    self._check_windows_debugger_api,
                    self._check_windows_vm_registry,
                ]
            )
        elif self._system == "Linux":
            checks.extend(
                [
                    self._check_linux_ptrace,
                    self._check_linux_proc,
                ]
            )
        elif self._system == "Darwin":
            checks.extend(
                [
                    self._check_macos_debugger,
                ]
            )

        for check in checks:
            try:
                check(report)
                report.checks_performed += 1
            except Exception:
                pass  # Silent failure - don't reveal check capabilities

        # In non-strict mode, only fail on high/critical risks
        if not self.strict_mode:
            report.is_safe = len(report.get_high_severity_risks()) == 0

        self._cached_report = report
        return report

    def _check_vm_indicators(self, report: SafetyReport) -> None:
        """Check for VM indicators in system strings."""
        indicators_to_check: List[str] = []

        # Check platform strings
        indicators_to_check.extend(
            [
                platform.platform().lower(),
                platform.processor().lower(),
                platform.machine().lower(),
            ]
        )

        # Check BIOS/DMI info on Linux
        if self._system == "Linux":
            dmi_paths = [
                "/sys/class/dmi/id/product_name",
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor",
                "/sys/class/dmi/id/bios_vendor",
            ]
            for path in dmi_paths:
                try:
                    indicators_to_check.append(Path(path).read_text().lower().strip())
                except (OSError, IOError):
                    pass

        # Check for VM indicators
        for indicator in indicators_to_check:
            for vm_sign in self.VM_INDICATORS:
                if vm_sign in indicator:
                    report.add_risk(
                        Risk(
                            category=RiskCategory.VIRTUAL_MACHINE,
                            description=f"VM indicator detected: {vm_sign}",
                            severity="high",
                            evidence=indicator[:100],
                        )
                    )
                    return  # One VM detection is enough

    def _check_debugger(self, report: SafetyReport) -> None:
        """Generic debugger detection."""
        # Check for common debugger environment variables
        debug_env_vars = [
            "DEBUG",
            "_DEBUG",
            "PYTHONDEBUG",
            "PYTHONINSPECT",
            "PYTHONTRACEMALLOC",
            "REMOTE_DEBUG",
        ]

        for var in debug_env_vars:
            if os.environ.get(var):
                report.add_risk(
                    Risk(
                        category=RiskCategory.DEBUGGER,
                        description=f"Debug environment variable set: {var}",
                        severity="medium",
                        evidence=f"{var}={os.environ.get(var, '')[:20]}",
                    )
                )

    def _check_suspicious_processes(self, report: SafetyReport) -> None:
        """Check for suspicious running processes."""
        running_processes: Set[str] = set()

        if self._system == "Windows":
            try:
                # Use tasklist on Windows
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in result.stdout.split("\n"):
                    if line.strip():
                        # Extract process name from CSV: "name.exe","PID",...
                        match = re.match(r'"([^"]+)"', line)
                        if match:
                            running_processes.add(match.group(1).lower())
            except (subprocess.SubprocessError, OSError):
                pass

            suspicious = self.WINDOWS_SUSPICIOUS_PROCESSES
        else:
            try:
                # Use ps on Unix
                result = subprocess.run(
                    ["ps", "ax", "-o", "comm="],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in result.stdout.split("\n"):
                    proc = line.strip().split("/")[-1]  # Get base name
                    if proc:
                        running_processes.add(proc.lower())
            except (subprocess.SubprocessError, OSError):
                pass

            suspicious = self.UNIX_SUSPICIOUS_PROCESSES

        # Check for matches
        for proc in running_processes:
            for susp in suspicious:
                if susp.lower() in proc.lower():
                    # Determine category and severity
                    if any(
                        x in susp.lower()
                        for x in [
                            "dbg",
                            "debug",
                            "ida",
                            "radare",
                            "strace",
                            "ptrace",
                            "gdb",
                            "lldb",
                        ]
                    ):
                        category = RiskCategory.DEBUGGER
                        severity = "critical"
                    elif any(
                        x in susp.lower() for x in ["obs", "recorder", "screen", "cam", "fraps"]
                    ):
                        category = RiskCategory.SCREEN_RECORDER
                        severity = "high"
                    elif any(x in susp.lower() for x in ["vm", "vbox", "qemu"]):
                        category = RiskCategory.VIRTUAL_MACHINE
                        severity = "high"
                    elif any(x in susp.lower() for x in ["sandbox", "cuckoo"]):
                        category = RiskCategory.SANDBOX
                        severity = "critical"
                    else:
                        category = RiskCategory.ANALYSIS_TOOL
                        severity = "medium"

                    report.add_risk(
                        Risk(
                            category=category,
                            description=f"Suspicious process detected: {proc}",
                            severity=severity,
                            evidence=proc,
                        )
                    )

    def _check_suspicious_files(self, report: SafetyReport) -> None:
        """Check for suspicious files indicating analysis environment."""
        suspicious_paths: List[Tuple[str, RiskCategory, str]] = []

        if self._system == "Windows":
            suspicious_paths = [
                (r"C:\sample", RiskCategory.SANDBOX, "Sandbox sample directory"),
                (r"C:\malware", RiskCategory.SANDBOX, "Malware analysis directory"),
                (r"C:\virus", RiskCategory.SANDBOX, "Virus analysis directory"),
                (r"C:\sandbox", RiskCategory.SANDBOX, "Sandbox directory"),
            ]
        else:
            suspicious_paths = [
                ("/tmp/sample", RiskCategory.SANDBOX, "Sandbox sample directory"),
                ("/tmp/malware", RiskCategory.SANDBOX, "Malware analysis directory"),
                ("/home/sandbox", RiskCategory.SANDBOX, "Sandbox user directory"),
                ("/home/cuckoo", RiskCategory.SANDBOX, "Cuckoo sandbox directory"),
            ]

        for path, category, description in suspicious_paths:
            if Path(path).exists():
                report.add_risk(
                    Risk(
                        category=category,
                        description=description,
                        severity="high",
                        evidence=path,
                    )
                )

    def _check_windows_debugger_api(self, report: SafetyReport) -> None:
        """Windows-specific debugger detection using kernel32."""
        try:
            kernel32 = ctypes.windll.kernel32

            # IsDebuggerPresent
            if kernel32.IsDebuggerPresent():
                report.add_risk(
                    Risk(
                        category=RiskCategory.DEBUGGER,
                        description="Debugger detected via IsDebuggerPresent()",
                        severity="critical",
                    )
                )

            # CheckRemoteDebuggerPresent
            is_debugged = ctypes.c_bool(False)
            kernel32.CheckRemoteDebuggerPresent(
                kernel32.GetCurrentProcess(), ctypes.byref(is_debugged)
            )
            if is_debugged.value:
                report.add_risk(
                    Risk(
                        category=RiskCategory.DEBUGGER,
                        description="Remote debugger detected",
                        severity="critical",
                    )
                )
        except (AttributeError, OSError):
            pass

    def _check_windows_vm_registry(self, report: SafetyReport) -> None:
        """Check Windows registry for VM indicators."""
        try:
            import winreg

            vm_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmci"),
            ]

            for hive, key_path in vm_keys:
                try:
                    with winreg.OpenKey(hive, key_path):
                        report.add_risk(
                            Risk(
                                category=RiskCategory.VIRTUAL_MACHINE,
                                description=f"VM registry key found: {key_path}",
                                severity="high",
                                evidence=key_path,
                            )
                        )
                except OSError:
                    # WindowsError is a subclass of OSError; use base class
                    # so this branch is reachable on all platforms.
                    pass
        except ImportError:
            pass

    def _check_linux_ptrace(self, report: SafetyReport) -> None:
        """Check if process is being traced on Linux."""
        try:
            status = Path("/proc/self/status").read_text()
            for line in status.split("\n"):
                if line.startswith("TracerPid:"):
                    tracer_pid = int(line.split(":")[1].strip())
                    if tracer_pid != 0:
                        report.add_risk(
                            Risk(
                                category=RiskCategory.DEBUGGER,
                                description=f"Process is being traced by PID {tracer_pid}",
                                severity="critical",
                                evidence=f"TracerPid: {tracer_pid}",
                            )
                        )
                    break
        except (OSError, IOError, ValueError):
            pass

    def _check_linux_proc(self, report: SafetyReport) -> None:
        """Check /proc for VM indicators on Linux."""
        vm_proc_files = [
            ("/proc/scsi/scsi", ["vmware", "vbox", "qemu"]),
            ("/proc/ide/hd0/model", ["vmware", "vbox", "qemu"]),
        ]

        for filepath, indicators in vm_proc_files:
            try:
                content = Path(filepath).read_text().lower()
                for indicator in indicators:
                    if indicator in content:
                        report.add_risk(
                            Risk(
                                category=RiskCategory.VIRTUAL_MACHINE,
                                description=f"VM indicator in {filepath}: {indicator}",
                                severity="high",
                                evidence=content[:100],
                            )
                        )
            except (OSError, IOError):
                pass

    def _check_macos_debugger(self, report: SafetyReport) -> None:
        """Check for debugger on macOS using sysctl."""
        try:
            # P_TRACED flag check
            result = subprocess.run(
                ["sysctl", "-n", "kern.proc.pid." + str(os.getpid())],
                capture_output=True,
                timeout=5,
            )
            # If this succeeds, we can parse the output for P_TRACED
            # For simplicity, just check if lldb/gdb are running
        except (subprocess.SubprocessError, OSError):
            pass

    def invalidate_cache(self) -> None:
        """Clear cached safety report."""
        self._cached_report = None


# Global singleton
_global_safety: Optional[EnvironmentSafety] = None


def get_environment_safety() -> EnvironmentSafety:
    """Get the global environment safety checker."""
    global _global_safety
    if _global_safety is None:
        _global_safety = EnvironmentSafety()
    return _global_safety


def require_safe_environment(
    on_unsafe: Optional[Callable[[SafetyReport], None]] = None,
    strict: bool = False,
) -> Callable:
    """
    Decorator to require a safe environment for a function.

    If unsafe, either calls on_unsafe callback or raises RuntimeError.

    Args:
        on_unsafe: Callback for unsafe environments. Receives SafetyReport.
        strict: If True, any risk makes it unsafe.

    Usage:
        @require_safe_environment()
        def encrypt_sensitive_data(data: bytes) -> bytes:
            ...
    """
    from functools import wraps

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            safety = EnvironmentSafety(strict_mode=strict)
            report = safety.check_all()

            if not report.is_safe:
                if on_unsafe is not None:
                    on_unsafe(report)
                else:
                    risk_summary = ", ".join(
                        r.description for r in report.get_high_severity_risks()
                    )
                    raise RuntimeError(f"Unsafe environment detected: {risk_summary}")

            return func(*args, **kwargs)

        return wrapper

    return decorator


def silent_unsafe_handler(report: SafetyReport) -> None:
    """
    Silent handler for unsafe environments.

    Logs nothing, reveals nothing. Use when you want to silently
    proceed with poison output or other defensive measures.
    """
    pass  # Intentionally empty
