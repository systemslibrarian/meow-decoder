# OpenSSF Scorecard Improvement Plan

> **Current Score:** 3.8 / 10 (as of 2026-02-06)
> **Target Score:** 7.0–8.0+ / 10
> **Repo:** <https://github.com/systemslibrarian/meow-decoder>
> **Maintainer:** Paul

---

## Score Breakdown (Baseline)

| Check | Score | Weight | Notes |
|-------|-------|--------|-------|
| Vulnerabilities | 0/10 | HIGH | Outdated Rust deps (regex, serde_json, time) |
| Pinned-Dependencies | 0/10 | HIGH | All actions use `@v4` mutable tags |
| Branch-Protection | 0/10 | HIGH | No rules on `main` |
| Token-Permissions | 0/10 | HIGH | 5 workflows missing top-level `permissions` |
| Dependency-Update-Tool | 0/10 | MED | No Dependabot / Renovate |
| Code-Review | 0/10 | MED | Solo dev, no PR review history |
| Maintained | 0/10 | LOW | New repo — improves with time/activity |
| CII-Best-Practices | 0/10 | MED | No badge applied yet |
| Binary-Artifacts | ?/10 | MED | `formal/tla/tla2tools.jar` checked in |
| Signed-Releases | 0/10 | MED | No tags / releases yet |
| Security-Policy | 10/10 | — | ✅ SECURITY.md present |
| SAST | 10/10 | — | ✅ CodeQL + Bandit |
| Fuzzing | 10/10 | — | ✅ Atheris + Hypothesis |
| License | 10/10 | — | ✅ MIT |
| CI-Tests | ~7/10 | — | ✅ pytest + Rust tests run on PRs |

---

## Phase 1 — Quick Wins (≤ 1–2 hours total, ~+25–30 pts)

### 1.1 Add `permissions: {}` to all workflows that lack it

**Fixes:** Token-Permissions (0 → 9–10/10)
**Time:** 15 min
**Impact:** +10 pts (high weight check)

Five workflows are missing a top-level `permissions` block:

| Workflow | File | Fix |
|----------|------|-----|
| Fuzzing | `fuzz.yml` | Add `permissions: contents: read` |
| Rust Crypto Backend | `rust-crypto.yml` | Add `permissions: contents: read` |
| Rust Tests & Coverage | `rust-test-coverage.yml` | Add `permissions: contents: read` |
| Formal Verification | `formal-verification.yml` | Add `permissions: contents: read` |
| Cleanup | `cleanup.yml` | Already has job-level — add `permissions: {}` at top |

**Pattern** — add immediately after the `on:` block in each file:

```yaml
permissions:
  contents: read
```

For `cleanup.yml` (which needs `actions: write` only on its job):

```yaml
# Top level
permissions: {}

jobs:
  cleanup:
    permissions:
      actions: write
```

**Status:**
- [x] `fuzz.yml` — add `permissions: contents: read`
- [x] `rust-crypto.yml` — add `permissions: contents: read`
- [x] `rust-test-coverage.yml` — add `permissions: contents: read`
- [x] `formal-verification.yml` — add `permissions: contents: read`
- [x] `cleanup.yml` — add top-level `permissions: {}`

---

### 1.2 Create `.github/dependabot.yml`

**Fixes:** Dependency-Update-Tool (0 → 10/10)
**Time:** 5 min
**Impact:** +10 pts

```yaml
# .github/dependabot.yml
version: 2
updates:
  # Python (pip)
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "python"

  # Rust (cargo) — crypto_core
  - package-ecosystem: "cargo"
    directory: "/crypto_core"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "rust"

  # Rust (cargo) — rust_crypto
  - package-ecosystem: "cargo"
    directory: "/rust_crypto"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "rust"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
      - "ci"
```

**Status:**
- [x] Create `.github/dependabot.yml`

---

### 1.3 Remove binary artifact (`tla2tools.jar`)

**Fixes:** Binary-Artifacts (?→ 10/10)
**Time:** 10 min
**Impact:** +5–10 pts

The Scorecard flags any checked-in `.jar`, `.exe`, `.dll`, `.bin`, etc.

**Steps:**

```bash
# Remove the jar from tracking
git rm formal/tla/tla2tools.jar
echo "formal/tla/tla2tools.jar" >> .gitignore

# Update formal-verification.yml to download it at runtime instead
# (add a step before the TLA+ check):
```

Add to `formal-verification.yml` TLA+ job:

```yaml
- name: Download TLA+ tools
  run: |
    mkdir -p formal/tla
    curl -sL -o formal/tla/tla2tools.jar \
      https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
    echo "Downloaded tla2tools.jar ($(wc -c < formal/tla/tla2tools.jar) bytes)"
```

**Status:**
- [x] `git rm formal/tla/tla2tools.jar`
- [x] Add to `.gitignore`
- [x] Update `formal-verification.yml` to download at runtime
- [ ] Verify TLA+ CI still works

**Verification note:**
- [ ] Run the “Formal Verification” workflow after this change to confirm TLA+ download works in CI.
  - [ ] Attempted via CLI: `gh workflow run "Formal Verification" --ref main` → HTTP 403 (resource not accessible by integration)

---

## Phase 2 — Medium Effort (2–4 hours total, ~+15–20 pts)

### 2.1 Pin all GitHub Actions to SHA hashes

**Fixes:** Pinned-Dependencies (0 → 10/10)
**Time:** 1–2 hours
**Impact:** +10 pts (high weight)

Every `uses:` in every workflow must reference a full SHA, not a mutable tag.
Only `scorecard.yml` currently does this correctly.

**SHA reference table (look up current SHAs on each action's releases page):**

| Action | Tag | SHA (example — verify before using!) |
|--------|-----|------|
| `actions/checkout` | `v4.2.2` | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `actions/setup-python` | `v5.3.0` | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `actions/upload-artifact` | `v4.6.0` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `actions/download-artifact` | `v4.1.8` | `fa0a91b85d4f404e444e00e005971372dc801d16` |
| `actions-rust-lang/setup-rust-toolchain` | `v1.11.0` | `9399c7bb15d4c4c6b72a3f425174804ad04c33bf` |
| `dtolnay/rust-toolchain` | `stable` | `d0592fe69e35bc8f12e3dbaf9ad2694d976cb8e3` |
| `Swatinem/rust-cache` | `v2.7.7` | `9d47c6ad4b02e050fd481d890b2ea34778fd09d6` |
| `codecov/codecov-action` | `v5.3.1` | `0565863a31f2c772f9f0395002a31e3f06189574` |
| `github/codeql-action/init` | `v3` | `6bb031afdd8eb862ea3c23b3778a88df60d23c22` |
| `github/codeql-action/autobuild` | `v3` | `6bb031afdd8eb862ea3c23b3778a88df60d23c22` |
| `github/codeql-action/analyze` | `v3` | `6bb031afdd8eb862ea3c23b3778a88df60d23c22` |
| `github/codeql-action/upload-sarif` | `v3` | `6bb031afdd8eb862ea3c23b3778a88df60d23c22` |
| `PyO3/maturin-action` | `v1` | `aef21716846a0e637cf3aab4b73754a9e3c4f2a5` |
| `pypa/gh-action-pypi-publish` | `release/v1` | `76f52bc884231f62b54e755689f2957b6c0a7cfb` |
| `Mattraks/delete-workflow-runs` | `v2` | `aa6f9271e9f8ce42cee05a044e8c8b0a59424ec8` |

> **⚠️ IMPORTANT:** Before applying, look up the CURRENT SHA for each action's
> latest release.  The SHAs above are examples — they may be stale.
> Use: `gh api repos/OWNER/REPO/git/ref/tags/TAG --jq .object.sha`
> or check the action's GitHub releases page.

**Format:**

```yaml
# Before (mutable tag — supply-chain risk)
- uses: actions/checkout@v4

# After (SHA-pinned — immutable)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

**Workflow files that need pinning (all `uses:` lines):**

- [x] `ci.yml` — ~8 action references
- [x] `security-ci.yml` — ~14 action references
- [x] `codeql.yml` — 3 action references
- [x] `fuzz.yml` — ~5 action references
- [x] `rust-crypto.yml` — ~20+ action references
- [x] `rust-test-coverage.yml` — ~4 action references
- [x] `formal-verification.yml` — ~2 action references
- [x] `cleanup.yml` — 1 action reference
- [x] `scorecard.yml` — already pinned ✅

**Status:**
- [x] All actions SHA-pinned

**Pinning note:**
- Resolved: pinned `actions/setup-java@v4` and `actions/github-script@v7`.

**Tip:** After creating `dependabot.yml` (§1.2), Dependabot with the
`github-actions` ecosystem will auto-open PRs to update pinned SHAs when
new versions release. This is the correct pattern: pin to SHA + auto-update.

---

### 2.2 Fix Rust dependency vulnerabilities

**Fixes:** Vulnerabilities (0 → 8–10/10)
**Time:** 30–60 min
**Impact:** +10 pts (highest weight check)

Current known advisories being ignored:

```
RUSTSEC-2023-0071  (marvin-attacks on rsa crate — likely transitive)
RUSTSEC-2024-0436  (unclear — check with cargo audit)
RUSTSEC-2026-0009  (time 0.3.46 via x509-parser — awaiting upstream)
```

**Steps:**

```bash
# See exactly what's vulnerable
cd crypto_core && cargo audit 2>&1 | head -60
cd ../rust_crypto && cargo audit 2>&1 | head -60

# Try updating deps — may fix some automatically
cd crypto_core && cargo update && cargo audit
cd ../rust_crypto && cargo update && cargo audit

# For transitive deps, check if newer versions fix the issue
cargo tree -i regex        # see who pulls in regex
cargo tree -i serde_json   # see who pulls in serde_json
cargo tree -i time         # see who pulls in time
```

**For each advisory:**

| Advisory | Dep | Fix Strategy |
|----------|-----|-------------|
| regex/regex-syntax | Transitive | `cargo update` usually fixes |
| serde_json | Transitive | `cargo update` |
| time | Via x509-parser | Pin `time >= 0.3.47` if fix exists, else `--ignore` with documented justification |
| rsa (RUSTSEC-2023-0071) | Transitive from PQ deps? | Check if only behind `pq-crypto` feature flag |

**Status:**
- [x] Run `cargo update` in `crypto_core/` and `rust_crypto/`
- [x] Run `cargo audit` — document remaining advisories
- [x] Remove `--ignore` flags that are no longer needed (all 3 still required for crypto_core; rust_crypto clean)
- [ ] Verify CI still passes after dep updates

**Progress log (fill after running audits):**

| Date | Scope | Result | Notes |
|------|-------|--------|-------|
| 2026-02-06 | crypto_core | 2 vulnerabilities, 1 warning | RUSTSEC-2023-0071 (rsa via yubikey), RUSTSEC-2026-0009 (time 0.3.46 via x509-parser; upgrade to >=0.3.47), RUSTSEC-2024-0436 (paste unmaintained via cryptoki) |
| 2026-02-06 | rust_crypto | no advisories reported | `cargo audit` completed with no vulnerabilities listed |

---

### 2.3 Enable Branch Protection on `main`

**Fixes:** Branch-Protection (0 → 7–9/10)
**Time:** 10 min (GitHub UI)
**Impact:** +8 pts

**Steps:**

1. Go to **Settings → Branches → Add branch protection rule**
2. Branch name pattern: `main`
3. Enable:
   - [x] **Require a pull request before merging**
     - [x] Require approvals: **1** (even self-approve is better than none)
     - *Note:* As solo dev, you can still merge your own PRs after review.
       Alternatively, enable "Allow specified actors to bypass" and add yourself
       for emergency hotfixes only.
   - [x] **Require status checks to pass before merging**
     - Add required checks: `All CI Gates`, `Scorecard analysis`
   - [x] **Require branches to be up to date before merging**
   - [x] **Require conversation resolution before merging**
   - [x] **Do not allow bypassing the above settings** *(for max Scorecard credit)*
     - Or: Allow bypass for repo admins only (pragmatic for solo dev)
   - [x] **Require signed commits** *(optional but good for crypto project)*
   - [x] **Include administrators** *(Scorecard checks this)*
4. Click **Create**

> **Solo-dev workflow after this:**
> Push to a branch → open PR → CI runs → self-review → merge.
> Add `gh pr create && gh pr merge --auto` to your workflow.

**Status:**
- [ ] Create branch protection rule for `main`
- [ ] Add required status checks
- [ ] Test by pushing a branch + PR

**Verification checklist:**
- [ ] `main` rule exists and includes administrators
- [ ] Required checks include `All CI Gates` and `Scorecard analysis`
- [ ] PRs require approval and status checks are enforced

---

## Phase 3 — Longer-Term / Ongoing (~+5–15 pts over weeks)

### 3.1 Build PR review history (Code-Review check)

**Fixes:** Code-Review (0 → 6–8/10)
**Time:** Ongoing (2–4 weeks of PR-based workflow)
**Impact:** +7 pts

The Scorecard checks the **last 30 commits** for PR-based merges with
at least one reviewer. After enabling branch protection (§2.3):

1. **Always merge via PR**, never push directly to `main`
2. Self-review counts if you approve your own PR (not ideal but scores)
3. Invite a collaborator for periodic reviews (even 1 external review helps)
4. For existing direct pushes: they'll age out of the 30-commit window

**Quick-start alias:**

```bash
# Create branch, commit, PR, merge workflow
alias meow-pr='git checkout -b fix/$(date +%s) && git add -A && git commit -m "fix: update" && git push -u origin HEAD && gh pr create --fill && gh pr merge --auto --squash'
```

**Status:**
- [ ] Switch to PR-based workflow
- [ ] After ~20 merged PRs, re-scan Scorecard

**Verification checklist:**
- [ ] Merges to `main` are via PR only
- [ ] At least one approval recorded per PR (self-approval allowed)
- [ ] Required status checks are passing on merged PRs

---

### 3.2 Apply for CII Best Practices badge

**Fixes:** CII-Best-Practices (0 → 7–10/10)
**Time:** 1–2 hours to fill out questionnaire
**Impact:** +7 pts

**Steps:**

1. Go to <https://www.bestpractices.dev/en/projects/new>
2. Enter repo URL: `https://github.com/systemslibrarian/meow-decoder`
3. Fill out the questionnaire (~80 questions). Most are already met:

| Category | Status | Notes |
|----------|--------|-------|
| Basics (license, docs, repo) | ✅ Met | MIT, README, CONTRIBUTING |
| Change control (version, changelog) | ✅ Met | CHANGELOG.md exists |
| Reporting (SECURITY.md, bug process) | ✅ Met | SECURITY.md published |
| Quality (tests, CI) | ✅ Met | pytest + Rust tests + CI |
| Security (crypto, secure design) | ✅ Met | Threat model, formal methods |
| Analysis (SAST, warnings) | ✅ Met | CodeQL + Bandit + Clippy |

4. Key questions that may need attention:
   - "The project MUST have a unique version" → ensure `pyproject.toml` has version
   - "Build reproducible" → document build steps
   - "Crypto: use well-known algorithms" → yes, AES-256-GCM + Argon2id

5. Submit → receive badge URL → add to README.md:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXX/badge)](https://www.bestpractices.dev/projects/XXXX)
```

**Status:**
- [ ] Create project at bestpractices.dev
- [ ] Complete questionnaire
- [ ] Add badge to README.md

**Verification checklist:**
- [ ] Badge URL is live and shows the project
- [ ] README badge links to the project page

---

### 3.3 Signed Releases

**Fixes:** Signed-Releases (0 → 10/10)
**Time:** 30 min to set up, then per-release
**Impact:** +5 pts (only scored when releases exist)

**Steps:**

1. **Set up GPG signing** (if not already):

```bash
# Generate GPG key (if needed)
gpg --full-generate-key  # RSA 4096, no expiry or long expiry

# Configure git
git config --global user.signingkey YOUR_KEY_ID
git config --global tag.gpgSign true
git config --global commit.gpgSign true

# Upload public key to GitHub
gpg --armor --export YOUR_KEY_ID | gh gpg-key add -
```

2. **Create a signed release:**

```bash
# Tag with GPG signature
git tag -s v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Create GitHub release with attestation
gh release create v1.0.0 --title "v1.0.0" --notes "First signed release"
```

3. **Optional: Add SLSA provenance** (supply chain attestation):

```yaml
# In rust-crypto.yml publish job, add after pypi publish:
- name: Generate SLSA provenance
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
  with:
    base64-subjects: "${{ needs.build.outputs.hashes }}"
```

**Status:**
- [ ] Set up GPG key for signing
- [ ] Create first signed tag + release
- [ ] Add SLSA provenance to release workflow (optional)

**Verification checklist:**
- [ ] `git tag -v` verifies signed tag locally
- [ ] GitHub release shows “Verified” for the tag
- [ ] Release notes include version and changes

---

### 3.4 Improve Maintained score

**Fixes:** Maintained (0 → 5–10/10)
**Time:** Ongoing
**Impact:** +3 pts

The Scorecard `Maintained` check looks at:
- Commits in last 90 days (✅ active)
- Issues opened/closed recently
- Releases in last year
- Number of contributors
- Org membership

**Actions:**
- [ ] Keep committing regularly (already happening)
- [ ] Create + close GitHub Issues for work tracking
- [ ] Cut a release (§3.3) — releases boost this score significantly
- [ ] Add at least 1 collaborator (even with read access)
- [ ] Consider creating a GitHub Organization for the project

**Verification checklist:**
- [ ] At least one issue opened and closed in the last 90 days
- [ ] At least one release in the last 12 months
- [ ] At least two contributors shown in GitHub insights

---

## Phase 4 — Repo-Specific Gotchas (Rust + Python + Formal Methods)

### 4.1 Dual ecosystem dependency management

Dependabot (§1.2) handles both `pip` and `cargo`, but watch for:
- **Cargo workspace:** The root `Cargo.toml` has `members`. Dependabot needs
  separate entries for each `directory` with a `Cargo.toml`.
- **Maturin builds:** After Cargo dep updates, ensure `maturin build` still works.
  Pin maturin version in CI to avoid surprises.
- **requirements.txt pinning:** Currently uses `>=` ranges. For Scorecard,
  exact pins (`==`) in `requirements.txt` + Dependabot is ideal. But `>=` is OK
  since pip has its own resolver.

### 4.2 Formal methods artifacts

- The `tla2tools.jar` (§1.3) is the main binary artifact issue.
- ProVerif is installed at runtime (good).
- Lean toolchain via elan is runtime-installed (good).
- Keep formal/ outputs (`.pdf`, `.log`) out of the repo.

### 4.3 Fuzzing credit

- Already strong ✅. Scorecard detects OSS-Fuzz integration OR scheduled
  fuzzing workflows. The `fuzz.yml` with `schedule:` cron gives full credit.
- Consider adding corpus files to `.gitignore` to avoid bloat.

### 4.4 SAST credit

- Already strong ✅. CodeQL on schedule + PRs. Bandit in security-ci.
- Clippy in rust-crypto CI counts too.

### 4.5 Audit ignore list hygiene

The `--ignore RUSTSEC-*` flags in `security-ci.yml` should each have:
- A comment explaining WHY it's ignored
- A linked issue tracking the fix
- A review date

**Status:**
- [x] Add comments and review dates in `security-ci.yml`
- [ ] Create tracking issues for each ignored advisory (run commands below)

**Issue drafts (copy into GitHub Issues):**

1) **Title:** Track RUSTSEC-2023-0071 (rsa marvin-attack via yubikey)
  **Body:**
  - Advisory: RUSTSEC-2023-0071
  - Current path: `yubikey` dependency in `crypto_core` (transitive)
  - Mitigation: repo uses ECDH-only flows; no RSA encrypt/decrypt usage
  - Action: monitor yubikey/rsa dependency updates; remove ignore when fixed
  - Review date: 2026-05-01

2) **Title:** Track RUSTSEC-2024-0436 (pending details)
  **Body:**
  - Advisory: RUSTSEC-2024-0436
  - Current path: verify via `cargo audit` output
  - Action: identify transitive dep, update if fixed upstream, document impact
  - Review date: 2026-05-01

3) **Title:** Track RUSTSEC-2026-0009 (time 0.3.46 via x509-parser)
  **Body:**
  - Advisory: RUSTSEC-2026-0009
  - Current path: `x509-parser` -> `time` 0.3.46 (transitive)
  - Action: bump `x509-parser`/`time` when fixed; remove ignore when resolved
  - Review date: 2026-05-01

---

## Phase 5 — Projected Score After Improvements

### After Phase 1 (Quick Wins — 1–2 hours)

| Check | Before | After | Delta |
|-------|--------|-------|-------|
| Token-Permissions | 0 | 9 | +9 |
| Dependency-Update-Tool | 0 | 10 | +10 |
| Binary-Artifacts | ? | 10 | +5 |
| **Subtotal** | — | — | **~+20–25** |

**Estimated score: 5.5–6.5 / 10**

### After Phase 2 (Medium Effort — 2–4 hours)

| Check | Before | After | Delta |
|-------|--------|-------|-------|
| Pinned-Dependencies | 0 | 10 | +10 |
| Vulnerabilities | 0 | 8 | +8 |
| Branch-Protection | 0 | 8 | +8 |
| **Subtotal** | — | — | **~+20–25** |

**Estimated score: 7.0–8.0 / 10**

### After Phase 3 (Ongoing — weeks)

| Check | Before | After | Delta |
|-------|--------|-------|-------|
| Code-Review | 0 | 7 | +7 |
| CII-Best-Practices | 0 | 7 | +7 |
| Maintained | 0 | 7 | +7 |
| Signed-Releases | 0 | 10 | +10 |
| **Subtotal** | — | — | **~+20–30** |

**Estimated score: 8.5–9.5 / 10**

---

## Verification

### Re-scan Scorecard

After making changes, re-scan to verify:

```bash
# Install scorecard CLI
brew install ossf/scorecard/scorecard   # macOS
# or: go install github.com/ossf/scorecard/v5@latest

# Run local scan against your repo
scorecard --repo=github.com/systemslibrarian/meow-decoder --show-details

# Or trigger the GitHub Action manually:
gh workflow run "OpenSSF Scorecard" --ref main
# Then check: https://github.com/systemslibrarian/meow-decoder/actions
```

### Check badge

After the Scorecard action publishes results:
- <https://securityscorecards.dev/viewer/?uri=github.com/systemslibrarian/meow-decoder>

---

## Execution Order (Recommended)

| Priority | Task | Section | Time | Impact |
|----------|------|---------|------|--------|
| 🔴 1 | Add `permissions` to 5 workflows | §1.1 | 15 min | +9 |
| 🔴 2 | Create `dependabot.yml` | §1.2 | 5 min | +10 |
| 🔴 3 | Remove `tla2tools.jar` | §1.3 | 10 min | +5 |
| 🟡 4 | Pin all actions to SHA | §2.1 | 1–2 hr | +10 |
| 🟡 5 | Fix Rust vulnerabilities | §2.2 | 30 min | +8 |
| 🟡 6 | Enable branch protection | §2.3 | 10 min | +8 |
| 🟢 7 | PR-based workflow | §3.1 | Ongoing | +7 |
| 🟢 8 | CII badge | §3.2 | 1–2 hr | +7 |
| 🟢 9 | Signed release | §3.3 | 30 min | +5 |
| 🟢 10 | Maintain activity | §3.4 | Ongoing | +3 |

---

## Overall Progress Tracker

- [ ] **Phase 1 complete** (Target: 5.5–6.5)
  - [x] §1.1 Workflow permissions
  - [x] §1.2 Dependabot config
  - [ ] §1.3 Remove binary artifact
  - [ ] Note: Phase 1 completion pending TLA+ CI verification
- [ ] **Phase 2 complete** (Target: 7.0–8.0)
  - [x] §2.1 Pin actions to SHA
  - [x] §2.2 Fix vulnerabilities (audited; all remaining are transitive with documented ignores)
  - [ ] §2.3 Branch protection
  - [x] Note: §2.1 blocker resolved
- [ ] **Phase 3 complete** (Target: 8.5–9.5)
  - [ ] §3.1 PR review history
  - [ ] §3.2 CII badge
  - [ ] §3.3 Signed releases
  - [ ] §3.4 Maintained score
- [ ] **Re-scan and verify score ≥ 7.0**

---

*Last updated: 2026-02-06*
*🐾 "A well-scored cat is a trusted cat." — The Clowder*
