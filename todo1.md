# OpenSSF Scorecard Improvement TODO

## Current Status
- ✅ Scorecard workflow added: `.github/workflows/scorecard.yml`
- ✅ Badge already in README.md
- ⏳ Waiting for first scan to complete and propagate to OpenSSF API

## Already Implemented
- ✅ Code-Review (PRs)
- ✅ CI-Tests
- ✅ SAST (CodeQL)
- ✅ Fuzzing
- ✅ License
- ✅ Security-Policy (SECURITY.md)

## Quick Wins to Improve Score

### 1. Branch Protection on `main` (+1-2 points)
- [ ] Enable "Require pull request reviews before merging"
- [ ] Enable "Require status checks to pass before merging"
- [ ] Enable "Do not allow force pushes"
- [ ] Enable "Do not allow deletions"

Go to: https://github.com/systemslibrarian/meow-decoder/settings/branches

### 2. Pin All GitHub Actions to Commit SHAs (+1 point)
- [ ] Audit all `.github/workflows/*.yml` files
- [ ] Replace tag references (e.g., `@v4`) with full commit hashes
- [ ] Already done in scorecard.yml, verify others

### 3. SECURITY.md Contact Email
- [ ] Add security contact email to SECURITY.md if missing
- [ ] Ensures Security-Policy check passes fully

### 4. Signed Commits (+1 point)
- [ ] Configure GPG or SSH commit signing locally
- [ ] Enable "Require signed commits" in branch protection
- [ ] Improves Signed-Releases metric

### 5. Create Signed Releases (+1-2 points)
- [ ] Use `gh release create --notes-file CHANGELOG.md` with GPG signing
- [ ] Attach release artifacts (wheels, tarballs)
- [ ] Creates provenance for Signed-Releases check

## Verification Links
- Scorecard Viewer: https://securityscorecards.dev/viewer/?uri=github.com/systemslibrarian/meow-decoder
- GitHub Security Tab: https://github.com/systemslibrarian/meow-decoder/security/code-scanning
- Workflow Runs: https://github.com/systemslibrarian/meow-decoder/actions/workflows/scorecard.yml
