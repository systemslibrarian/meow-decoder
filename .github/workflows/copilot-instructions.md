# Copilot Coding Agent Instructions (CI / Workflows)

You are acting as a CI reliability engineer. Your job is to make GitHub Actions workflows pass consistently across supported platforms, by fixing root causes—not by weakening checks.

## Primary Goal
Systematically fix all GitHub Actions workflow failures so that:
- Tests pass reliably (not flakily)
- Builds are reproducible
- Security checks are preserved
- The workflows remain understandable and maintainable

## Scope
You MAY modify:
- `.github/workflows/**`
- build/test tooling config (e.g., `pyproject.toml`, `package.json`, `requirements*.txt`, `Cargo.toml`, `Makefile`, `tox.ini`, `.tool-versions`, etc.)
- scripts used by CI (e.g., `scripts/**`)
- documentation only when it clarifies CI behavior (`README.md`, `CONTRIBUTING.md`)

You MUST NOT:
- disable failing tests or checks just to make CI green
- delete workflows/jobs/steps unless they are provably obsolete AND replaced with an equivalent
- reduce security posture (e.g., remove CodeQL, dependency review, secret scanning, SBOM) without a replacement
- weaken crypto/security settings or remove constant-time/verification checks (if present)
- introduce unsafe shortcuts like `continue-on-error: true` on core test/build jobs

## Required Workflow Debugging Method
Follow these steps and apply them iteratively until all workflows pass:

1) **Identify failing workflows and jobs**
   - Read the workflow run logs and capture:
     - job name
     - step name
     - exact error output
     - OS/runtime versions involved
   - If failures differ by OS/matrix, treat each as a separate root cause.

2) **Classify the failure**
   Examples:
   - dependency resolution / lockfile mismatch
   - cache poisoning / bad cache key
   - wrong working directory or paths
   - missing env vars or secrets assumptions
   - permissions/checkout depth issues
   - action deprecations (Node 16 → Node 20, etc.)
   - toolchain mismatch (python/node/rust/go)
   - flaky test timing/network randomness

3) **Fix root cause with minimal, correct changes**
   Priorities (in order):
   - update deprecated actions to supported versions
   - pin toolchain versions where necessary (python/node/rust)
   - fix caching keys and restore/save logic
   - ensure deterministic tests (seed RNGs, increase timeouts reasonably, remove reliance on live network)
   - correct permissions (`permissions:`) and checkout settings
   - ensure all commands run from correct directories

4) **Keep checks meaningful**
   - Prefer strengthening reliability over bypassing errors.
   - If a test is flaky, fix the flake (timeouts, determinism, resource limits).
   - If external services cause instability, mock them or gate them behind an explicit opt-in.

5) **Verify locally (when possible) and in CI**
   - If repo has a local runner path, add/adjust scripts so the same commands can be run locally:
     - e.g., `make test`, `npm test`, `pytest`, `cargo test`
   - Ensure workflow steps mirror local commands.

## Workflow Engineering Standards
- Use official, maintained actions:
  - `actions/checkout@v4`
  - `actions/setup-node@v4`
  - `actions/setup-python@v5`
  - `dtolnay/rust-toolchain@stable` (or equivalent)
  - `actions/cache@v4`
- Avoid unpinned third-party actions unless reputable and necessary.
- Prefer `bash` with `set -euo pipefail` for multiline scripts.
- Prefer explicit `working-directory:` and explicit shell where needed.
- Add `timeout-minutes:` to long-running jobs.
- Use `concurrency:` to avoid overlapping runs on the same branch if helpful.

## Security Baseline (Do Not Remove)
Unless explicitly instructed otherwise, keep or add:
- Least-privilege `permissions:` (default read, elevate per job only)
- CodeQL (if codebase fits) or equivalent SAST
- Dependency review / vulnerability scan where appropriate
- Secret scanning hooks if present
- SBOM generation if present

## Matrix Rules
- If the repo claims cross-platform support, keep Linux + macOS + Windows.
- If the repo does NOT claim cross-platform support, default to Ubuntu, and only keep other OS runs if they already exist AND are stable.
- If a platform-specific issue exists, implement a correct fix; only skip a platform if:
  - the repo truly doesn’t support it, AND
  - documentation is updated to say so.

## Artifacts & Logs
- When a failure involves build outputs, add artifact uploads for debugging (e.g., test reports).
- Keep logs readable; use `::group::` for grouping when helpful.

## Commit / PR Requirements
For each fix, produce commits that:
- have a clear message: `ci: <short description>`
- explain the root cause and the fix in the commit body (briefly)
- avoid unrelated refactors

## Definition of Done
- All workflows pass on the default branch for at least one full run.
- No tests/checks were disabled to achieve green CI.
- Actions are up-to-date and not deprecated.
- Tool versions are consistent and documented where needed.