# What Do the Tests in meow-decoder Actually Do?

meow-decoder is **not** a typical app. It's a high-stakes security tool designed to protect sensitive files from powerful adversaries — including governments, law enforcement, or coercive actors who might force someone to reveal a password.

Because the stakes are so high (lives, freedom, safety of dissidents/journalists/activists), the tests in this project are **very different** from what you might see in a normal web app, game, or utility.

### Goal #1: Prove the Code Actually Works Securely (Not Just "It Runs")
The primary job of these tests is to confirm that:

- The cryptography behaves **exactly** as it should — no secret leaks, no weak spots
- Forward secrecy (ratcheting keys) actually protects past messages if a key is compromised
- Plausible deniability (Schrödinger / duress modes) really works: an attacker can't tell which password is real vs. decoy
- Dead-man's switch / timelock duress triggers correctly without leaving forensic traces
- Constant-time operations in Rust actually prevent timing side-channels
- Errors are **uniform** (always say "Decryption failed" — never leak info like "wrong key" vs. "corrupt data")
- Bad/malformed/corrupted inputs are rejected safely (no crashes, no partial decodes, no info leaks)

We do **not** mainly test "happy paths" (everything works perfectly).  
We **ruthlessly** test failure modes, edge cases, and attacks because that's where real vulnerabilities hide.

### Goal #2: Achieve High Branch Coverage on Risky Paths
We aim for **≥90% branch coverage** (measured with `coverage.py --branch`).

This means we try to execute **every possible decision point** in the code — especially the ones that could:

- Leak a key
- Reuse a nonce
- Fall back insecurely
- Fail to wipe memory
- Distinguish duress vs. normal decryption
- Allow forgery or replay

High branch coverage here is **not** about "clean code" — it's about making sure we've forced every security-critical `if`/`else`, `try`/`except`, and Rust–Python boundary to run at least once and behave correctly.

### What We Do NOT Care About (Much)
These tests are **not** trying to:

- Enforce style (PEP 8, black, flake8) → that's handled by linters/CI
- Check readability or maintainability → that's for code review
- Test documentation strings or type hints → separate tools
- Measure "code quality" in a general sense (cyclomatic complexity, etc.)

If the code is ugly but passes every adversarial test with zero security violations → it still passes the most important bar.

### Types of Tests You'll See
- **Property-based / fuzz-style** (using Hypothesis): Generates thousands of weird binary inputs, invalid keys, truncated streams, etc.
- **Fault injection**: Mock Rust panics, side-channel errors, or import failures to force Python fallback paths
- **Time mocking** (freezegun): Jump forward/backward in time to test timelock/duress deadlines without `time.sleep()`
- **Exception forcing**: Deliberately trigger ValueError, InvalidSignature, CryptoError, etc., to ensure uniform handling
- **Rust–Python boundary tests**: Check that secrets don't leak across the FFI bridge
- **Adversarial inputs**: Corrupted GIF frames, wrong headers, replayed nonces, malformed fountain codes, etc.

### Why This Matters for New Contributors
If you're adding or changing code in crypto, forward secrecy, duress, encoding/decoding, or cleanup paths:

1. **Write tests first** (or at the same time) — especially for any new branch/decision
2. Focus on **what could go wrong** — not just "what works"
3. Run `pytest --cov=meow_decoder --cov-branch --cov-report=html` and look at uncovered branches
4. If a branch is security-relevant and uncovered → that's a red flag

The tests are paranoid by design.  
They treat every uncovered branch in critical code as a **potential vulnerability** until proven otherwise.

Welcome to meow-decoder — where "it works on my machine" is never good enough. 😼

Questions? Ask in issues or chat — we're all learning how to build tools that can actually resist real threats.