# OpenSSF Scorecard Improvement Plan

Current scores from [securityscorecards.dev](https://securityscorecards.dev/viewer/?uri=github.com/systemslibrarian/meow-decoder)

## ✅ Completed (Score 10)

- [x] **Fuzzing** (10/10) - Project uses fuzzing
- [x] **License** (10/10) - MIT license defined
- [x] **CI-Tests** (10/10) - Tests run before PR merge

## 🔴 HIGH Priority

### Branch-Protection (? → 10)
Determines if default and release branches are protected with GitHub's branch protection settings.

**Actions Required:**
- [ ] Go to repo Settings → Branches → Add rule for `main`
- [ ] Enable "Require a pull request before merging"
- [ ] Enable "Require approvals" (at least 1)
- [ ] Enable "Dismiss stale pull request approvals when new commits are pushed"
- [ ] Enable "Require status checks to pass before merging"
  - [ ] Add required checks: `test`, `security-coverage`, `lint`
- [ ] Enable "Require branches to be up to date before merging"
- [ ] Enable "Require signed commits" (optional but recommended)
- [ ] Enable "Do not allow bypassing the above settings"
- [ ] Restrict who can push to matching branches

### Signed-Releases (? → 10)
Determines if the project cryptographically signs release artifacts.

**Actions Required:**
- [ ] Generate GPG key for releases (or use existing)
- [ ] Add GPG public key to GitHub account
- [ ] Update `.github/workflows/release.yml` to sign artifacts:
  ```yaml
  - name: Sign release artifacts
    run: |
      gpg --armor --detach-sign dist/*.whl
      gpg --armor --detach-sign dist/*.tar.gz
  ```
- [ ] Upload `.asc` signature files alongside release artifacts
- [ ] Consider using Sigstore/cosign for keyless signing:
  ```yaml
  - uses: sigstore/cosign-installer@v3
  - run: cosign sign-blob --yes dist/*.whl
  ```

## 🟡 MEDIUM Priority

### Pinned-Dependencies (6 → 10)
**Status:** Mostly complete. Remaining warnings are local/editable installs.

**Completed:**
- [x] Hash-pinned all requirements*.lock files
- [x] Pinned pip version to 24.3.1
- [x] Added `--no-deps` to local installs

**Cannot improve further:**
- `pip install -e .` (editable local source)
- `pip install dist/*.whl` (freshly-built local wheels)

These inherently can't have hashes since they're built at runtime.

## 🟢 LOW Priority

### CII-Best-Practices (2 → 10)
Requires completing the OpenSSF Best Practices Badge questionnaire.

**Actions Required:**
- [ ] Go to https://www.bestpractices.dev/en
- [ ] Sign in with GitHub
- [ ] Add project: `systemslibrarian/meow-decoder`
- [ ] Complete questionnaire (~100 questions covering):
  - [ ] Basic project info
  - [ ] Change control
  - [ ] Reporting
  - [ ] Quality
  - [ ] Security
  - [ ] Analysis
- [ ] Earn "Passing" badge (currently at 2% likely means just started)

### Contributors (0 → 10)
Requires contributors from multiple organizations/companies.

**This is organic growth - cannot be artificially improved.**

Possible actions:
- [ ] Encourage external contributions via good first issues
- [ ] Promote project in security/crypto communities
- [ ] Accept PRs from external contributors
- [ ] Document contribution guidelines clearly (CONTRIBUTING.md exists)

---

## Score Summary

| Check | Current | Target | Priority |
|-------|---------|--------|----------|
| Branch-Protection | ? | 10 | 🔴 HIGH |
| Signed-Releases | ? | 10 | 🔴 HIGH |
| Pinned-Dependencies | 6 | 8+ | 🟡 MEDIUM |
| CII-Best-Practices | 2 | 10 | 🟢 LOW |
| Contributors | 0 | 5+ | 🟢 LOW |

## Quick Wins

1. **Branch Protection** - 5 minutes in GitHub Settings
2. **Signed Releases** - Add Sigstore/cosign to release workflow
3. **Best Practices Badge** - Complete questionnaire (1-2 hours)

---

*Last updated: 2026-02-08*
