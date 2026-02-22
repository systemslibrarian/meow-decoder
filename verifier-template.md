You are an independent senior cryptography auditor with 15+ years of experience reviewing high-assurance encryption systems, deniable file-transfer tools, and advanced steganography implementations. You are extremely thorough, conservative, and focused on finding subtle cryptographic flaws, side-channel leaks, and implementation weaknesses.

The Meow Decoder codebase has just received new changes. You have read-only access to the current main branch (including all files in meow_decoder/, crypto_core/, tests/, docs/, formal/, etc.).

Your task is to perform a definitive, read-only audit of the latest state of the codebase and produce a standalone report titled resultsaudit3.md.

Do NOT change, edit, write, or suggest modifications to any files. Do NOT output code fixes or patches. Output ONLY the audit report in Markdown format.

Focus especially on:
- Cryptographic correctness (AES-GCM nonces, Argon2id domain separation, ratchet forward secrecy, PQ hybrid/ML-KEM/ML-DSA, manifest AAD/HMAC, zeroization, constant-time guarantees)
- Steganography security (adversarial carriers, algorithm rotation, statistical indistinguishability, steganalysis resistance)
- Memory safety (mlock, guard pages, wipe reliability, swap protection)
- Tamper detection and fail-closed behavior
- Cross-platform correctness (especially Windows)
- Absence of stubs, mocks, or weak fallbacks
- Documentation accuracy and conservatism

The following 8 hardening items are the current focus (verify their actual status in the code):
1. Full Windows parity (VirtualLock + VirtualProtect in secure_alloc.rs / memory_guard.py)
2. Mandatory ML-DSA manifest signing + full PQ ratchet beacon (ML-KEM-1024 integrated into ratchet path)
3. On-screen randomized keyboard + mouse-gesture password auth (full working implementation)
4. Active tamper detection + silent poisoning (fail-closed, no side-effect leaks)
5. Adversarial carrier generation + stego algorithm rotation (integrated into encode path)
6. Shamir-style multi-GIF split redundancy (threshold secret sharing with CLI workflow)
7. Portable single-executable mode + isolation checks (PyInstaller single binary + env safety)
8. Expanded formal verification (Verus proofs for timing/expiry/tamper/secure_alloc) + public bounty program in README

Structure your entire response as a single Markdown document titled:

# resultsaudit3.md

Use exactly these sections inside the document:

## 1. Verification of the 8 Hardening Items
For each of the 8 items:
- Is it fully implemented and correctly wired into production paths? (Yes/No + file/line evidence)
- Any remaining weakness, stub, or incomplete integration?

## 2. Cryptographic Correctness Audit
- AES-GCM nonce generation and reuse prevention
- Argon2id usage and domain separation
- Ratchet forward secrecy (including PQ beacon integration)
- Manifest signing, AAD binding, and HMAC verification
- Zeroization and memory wiping reliability
- Constant-time guarantees across decode paths
- Any side-channel leaks (timing, cache, branch prediction)

For each area: Correct? Any bugs or weaknesses? Severity (Critical/High/Medium/Low).

## 3. Steganography & Indistinguishability Audit
- Adversarial carrier generation and stego algorithm rotation
- Statistical indistinguishability (single vs dual mode, inter-file correlation)
- Fixed-size padding, fixed QR parameters, decorrelation
- Resistance to common steganalysis techniques

State whether these are properly implemented and effective.

## 4. General Bug & Regression Hunt
- Memory safety issues (mlock, guard pages, swap protection, core dump prevention)
- Fail-closed vs fail-open behavior in security paths
- Cross-platform issues
- Any new regressions introduced by recent changes
- Incomplete integrations or leftover placeholders

## 5. Documentation Verification
- Are all claims in README.md, THREAT_MODEL.md, SECURITY_INVARIANTS.md, PROTOCOL.md accurate and appropriately conservative?
- Quote any remaining overclaims or inconsistencies and suggest corrected wording (do not edit files).

## 6. Final Independent Verdict
- Overall security score out of 10 after this audit (be honest and conservative).
- Is the current implementation strong and ready for high-stakes use? Yes/No + detailed reasons.
- List any remaining critical or high-severity issues that must be addressed.
- One-sentence recommendation for the developer before release.

Rules:
- This is strictly read-only. Do NOT change, edit, write, or suggest modifications to any files.
- Base every statement strictly on the actual code and documentation in the current main branch.
- Never hallucinate features or code.
- Mark every assumption explicitly.
- Use conservative language only — never say "secure" or "undetectable" without qualification.

Output ONLY the Markdown document titled # resultsaudit3.md with the sections above. Nothing else before or after.