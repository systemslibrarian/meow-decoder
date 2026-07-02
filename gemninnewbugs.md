# Meow Decoder - Comprehensive Bug Analysis Report
*Generated via Static Analysis (Bandit, Flake8, Mypy) and Manual Inspection*

## 🔴 High Severity

*No immediate critical vulnerabilities (e.g., plaintext recovery, immediate RCE) were found, but the following logical/cryptographic flaw severely compromises a core security feature of the project.*

## 🟠 Medium Severity

### 1. Weak PRNG used for Plausible Deniability (Security / Cryptanalysis flaw)
* **Location:** `meow_decoder/duress_mode.py` (`generate_deterministic_decoy`)
* **Issue:** Bandit correctly flagged `B311: Standard pseudo-random generators are not suitable for security/cryptographic purposes`. The code seeds Python's standard `random.Random(seed)` with the SHA-256 of the salt and generates "fake" binary chunks using `rng.randbytes()`.
* **Impact:** Python's standard generator is a Mersenne Twister. Its output is statistically distinguishable from True Random or highly-entropic AES-GCM data. An adversary performing entropy analysis would easily identify the "fake" compressed data, breaking the plausible deniability of the Schrödinger/Duress mode.
* **Recommended Fix:** Use a deterministic cryptographic construction to generate decoy bytes (e.g., AES-CTR initialized with the salt, or `hashlib.shake_256`).

### 2. API Misuse / Missing Submodules in Examples (Code logic)
* **Location:** `examples/demo_schrodinger.py`
* **Issue:** Found via MyPy static analysis. The example imports a function that does not exist or has been renamed.
* **Details:** `from meow_decoder.quantum_mixer import verify_indistinguishability` raises an `ImportError` / `AttributeError`, causing the core Schrödinger demo to crash immediately upon execution.
* **Recommended Fix:** Ensure the example points to the correct entrypoints within `quantum_mixer`.

### 3. Unbounded Memory Leak in Nonce Generator (Concurrency / Memory)
* **Location:** `meow_decoder/nonce.py`
* **Issue:** The `NonceGenerator` tracks used nonces for collision prevention using `self._used_counters: set = set()`.
* **Impact:** While it successfully prevents catastrophic repeated nonces, the set is unbounded and will grow indefinitely. For streaming continuous feeds (millions of frames), this creates a monotonic memory leak over the application's lifecycle.
* **Recommended Fix:** Instead of storing all counters, pair it tightly with the existing monotonic `self._high_water_mark`. If out-of-order bounds are needed, use a capped cache (like `LRUCache`) or a sliding window.

## 🟡 Low Severity

### 1. Untrusted Pathing in the Air-Gap Subprocess Calls (Security / Path Injection)
* **Location:** `meow_decoder/air_gap.py`
* **Issue:** Flagged by Bandit (`B607: Starting a process with a partial executable path`).
* **Details:** `subprocess.run` calls directly use short-hand commands like `["ip", "route", "show", "default"]` and `["rfkill", "list", "wifi"]` without specifying their absolute `/bin/` or `/sbin/` paths.
* **Impact:** If `meow-encode` runs in an environment where the `PATH` variable has been tampered with or modified by an attacker, malicious executables named `ip` or `rfkill` could be executed.
* **Recommended Fix:** Use absolute paths like `["/sbin/ip", ...]` or resolve the binaries cleanly using `shutil.which()`.

### 2. Aggressive Blind Exception Catching (Unhandled Exceptions)
* **Location:** Extensive instances across `meow_decoder/crypto.py`, `dual_stream.py`, `decode_gif.py`, and `memory_guard.py`
* **Issue:** Bandit flagged 75 instances of `B110: Try, Except, Pass`.
* **Details:** Many cleanup algorithms dropping Rust crypto backend handles blind-catch all errors (`except Exception: pass`).
* **Impact:** While intended to ensure teardown processes don't stall, broadly catching `Exception` means critical systemic errors — such as `MemoryError` or `SegFault` equivalents surfaced by PyO3 mappings — are completely swallowed, masking larger stability issues.
* **Recommended Fix:** Catch the specific handle or cryptography errors (e.g., `CryptoBackendError` or `ValueError`) rather than Python's base `Exception`.

### 3. Legacy Stub Hardcoded Passwords in Error/Mock Tests
* **Location:** `meow_decoder/cat_errors.py`
* **Issue:** Bandit (`B105`) flagged false-positive pseudo-passwords within mock-ups and UI suggestions.
* **Recommended Fix:** This is mostly a false positive from funny string keys, but should be managed or `# nosec B105` tagged to clear build logs for security audits.