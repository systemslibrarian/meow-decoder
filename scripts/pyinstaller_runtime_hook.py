"""
PyInstaller Runtime Hook for Meow Decoder.

Executed BEFORE the main application starts.
Activates security protections:
1. Memory guards (mlockall, no core dumps, no ptrace)
2. Environment safety checks (VM, debugger detection)
3. Tamper detection baseline

WARNING: This hook runs in the packed binary context.
         All security modules must be available at runtime.
"""

import os
import sys
import warnings

# Suppress warnings during startup (security: don't leak info)
warnings.filterwarnings("ignore")


def _activate_security_on_startup():
    """Activate all security protections at process start."""

    # 1. Memory guards — prevent swap, core dumps, ptrace
    try:
        from meow_decoder.memory_guard import activate_memory_guard

        activate_memory_guard(warn_on_failure=False)
        # Silent — don't reveal protection status to potential attacker
    except ImportError:
        pass
    except Exception:
        pass

    # 2. Environment safety — detect hostile environment
    try:
        from meow_decoder.env_safety import get_environment_safety

        safety = get_environment_safety()
        report = safety.check_all()

        # Critical risks: abort immediately
        critical_risks = [r for r in report.risks if r.severity == "critical"]
        if critical_risks:
            # Silent exit — don't reveal why
            sys.exit(1)

        # High risks: warn but continue (let user decide)
        high_risks = report.get_high_severity_risks()
        if high_risks:
            # Set flag for main app to check
            os.environ["MEOW_ENV_UNSAFE"] = "1"
    except ImportError:
        pass
    except Exception:
        pass

    # 3. Tamper detection — establish baseline
    try:
        from meow_decoder.tamper_detection import get_tamper_detector

        detector = get_tamper_detector()
        if detector.is_tampered():
            # Tampered binary — silent poison mode activated internally
            os.environ["MEOW_TAMPERED"] = "1"
            sys.exit(1)
    except ImportError:
        pass
    except Exception:
        pass


# Run on import (before main)
_activate_security_on_startup()
