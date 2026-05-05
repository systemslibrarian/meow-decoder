# Potential Bugs and Security Issues - Meow Decoder

Based on a comprehensive analysis, recent audits (`AUDIT-2026-04-18.md`, `FOLLOWUP.md`), and automated scanning tools (`npm audit`, `bandit`), the following potential bugs and security findings have been identified:

## 1. Rust TPM Feature Compilation Failure
**Severity**: Medium
**Location**: `crypto_core/src/tpm.rs`
**Proof**: Running `cargo build --features tpm` breaks on the main branch. The `tss-esapi 7.5/7.6` API changes mean that methods like `SensitiveData::as_bytes` and `KeyHandle -> ObjectHandle` throws type errors during build. Mentioned in the `FOLLOWUP.md` finding 12.6, but deferred because it requires hardware to validate.

## 2. Unpatched NPM Transitive Vulnerabilities
**Severity**: High (in development environment)
**Location**: `package.json`
**Proof**: `npm audit` flags multiple `HIGH` and `MODERATE` severity bugs stemming from devDependencies (`jest`, `playwright`, `selenium`). These vulnerabilities manifest as ReDoS (Regular Expression Denial of Service) and path-traversal risks. Though restricted to dev paths, a malicious pull request or CI compromise could exploit these test artifacts.
- Mentioned as deferred finding 7.3 in *FOLLOWUP.md* because fixing requires triage with Jest internals.

## 3. Insecure Default Randomness (Historical / Fallback)
**Severity**: Low / Structural
**Location**: `meow_decoder/_archive/catnip_fountain.py` (lines 171, 454)
**Proof**: `bandit` security scans flag the standard pseudo-random generators (`random`) which are not suitable for cryptographic operations. While situated in `_archive`, structural references to non-CSPRNG could be maliciously repurposed in test deployments if not strictly audited out via `secrets`.

## 4. Hardcoded Empty Password in Bidirectional Mode
**Severity**: Low
**Location**: `meow_decoder/_archive/bidirectional.py:173`
**Proof**: Found via the `bandit` CI scanner: `[B107] Possible hardcoded password: ''`. The `BiDirectionalSender` was instantiated with a default empty string for `password`, resulting in potential bypasses for authentication if it was ever brought into the production payload path.

## 5. Unimplemented MP4 Conversion
**Severity**: Functional Task/Bug
**Location**: `tests/test_cross_browser.spec.js:123` & `408`
**Proof**: The test comments explicitly specify `// TODO: Implement MP4 conversion` and skip cross-browser testing for the missing functionality. Failing to implement MP4 support impacts Webkit and certain strict environment users who cannot leverage standard Cat-mode UI payloads.

## 6. Deprecated Build Tools Exposing CVEs
**Severity**: Low
**Location**: Python pip virtualenv builds
**Proof**: Finding 7.2 of the recent audit explicitly noted that building relies on `pip 24.0` + `wheel 0.45.1` which ship with known CVEs. Requires bumping environments to `pip >= 25` and `wheel >= 0.46` to secure dependency chains against supply-chain spoofing.

## 7. Python Memory Zeroization (`__del__` limits)
**Severity**: Low 
**Location**: `meow_decoder/pq_hybrid.py:193`
**Proof**: As logged in FOLLOWUP item 3.2, `Python doesn't guarantee __del__ runs (cycles, interpreter exit)`. Memory zeroization in Python for sensitive key material relies on a best-effort `__del__` method, meaning sensitive intermediate data can linger in RAM longer than anticipated, exposing keys to cold-boot or memory-scraping attacks. 

## 8. Unlocked Singleton Initialization Race Condition
**Severity**: Low
**Location**: `meow_decoder/crypto_backend.py`
**Proof**: Finding 11.1 from the code audit highlights that the Rust-backed singleton initialization in `crypto_backend.py` lacks an explicit `threading.Lock`. In heavily parallelized environments, this could result in race conditions during startup.
