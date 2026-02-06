#!/usr/bin/env bash
# Don't use set -e so partial failures don't abort
cd /workspaces/meow-decoder

echo "=== 1/5: Creating tracking issues ==="

gh issue create \
  --title "Track RUSTSEC-2023-0071 (rsa marvin-attack via yubikey)" \
  --body "## Advisory: RUSTSEC-2023-0071

- **Crate:** rsa 0.9.10
- **Severity:** 5.9 (medium)
- **Title:** Marvin Attack: potential key recovery through timing sidechannels
- **Dependency path:** \`rsa 0.9.10 → yubikey 0.8.0 → crypto_core 0.2.0\`
- **Mitigation:** This repo uses ECDH-only flows; no RSA encrypt/decrypt usage. The rsa crate is pulled transitively by yubikey HSM support.
- **Fix available:** No fixed upgrade available upstream.
- **Action:** Monitor yubikey/rsa dependency updates; remove \`--ignore\` from security-ci.yml when fixed.
- **Review date:** 2026-05-01

Related: OpenSSF Scorecard §2.2 / §4.5 vulnerability remediation"

gh issue create \
  --title "Track RUSTSEC-2024-0436 (paste unmaintained via cryptoki)" \
  --body "## Advisory: RUSTSEC-2024-0436

- **Crate:** paste 1.0.15
- **Warning:** unmaintained
- **Title:** paste - no longer maintained
- **Dependency path:** \`paste 1.0.15 → cryptoki 0.6.2 → crypto_core 0.2.0\`
- **Mitigation:** paste is a compile-time proc macro; no runtime security impact. cryptoki uses it for PKCS#11 bindings.
- **Action:** Monitor cryptoki updates for paste replacement; remove \`--ignore\` from security-ci.yml when resolved.
- **Review date:** 2026-05-01

Related: OpenSSF Scorecard §2.2 / §4.5 vulnerability remediation"

gh issue create \
  --title "Track RUSTSEC-2026-0009 (time 0.3.46 DoS via x509-parser)" \
  --body "## Advisory: RUSTSEC-2026-0009

- **Crate:** time 0.3.46
- **Severity:** 6.8 (medium)
- **Title:** Denial of Service via Stack Exhaustion
- **Fix:** Upgrade to time >= 0.3.47
- **Dependency path:** \`time 0.3.46 → x509-parser 0.18.0 → ctap-hid-fido2 3.5.8 → crypto_core 0.2.0\`
- **Mitigation:** Transitive dep; waiting for x509-parser to update its time dependency.
- **Action:** Bump x509-parser/time when fixed upstream; remove \`--ignore\` from security-ci.yml when resolved.
- **Review date:** 2026-05-01

Related: OpenSSF Scorecard §2.2 / §4.5 vulnerability remediation"

echo ""
echo "=== 2/5: Triggering Formal Verification workflow ==="
gh workflow run "Formal Verification" --ref main || echo "⚠️ Workflow dispatch failed (may need GitHub UI)"

echo ""
echo "=== 3/5: Setting up branch protection ==="
gh api repos/systemslibrarian/meow-decoder/branches/main/protection \
  --method PUT \
  --input - <<'EOF' || echo "⚠️ Branch protection failed (may need GitHub UI)"
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["All CI Gates"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "required_conversation_resolution": true
}
EOF

echo ""
echo "=== 4/5: Committing plan updates ==="
git add -A
git commit -m "docs: update OpenSSF plan - audit complete, add tracking script

- Mark §2.2 ignore flags reviewed (all 3 still needed for crypto_core)
- rust_crypto audit clean (no advisories)
- Add openssf_remaining.sh for issue creation + branch protection
- Update overall progress tracker"

echo ""
echo "=== 5/5: Pushing ==="
git push

echo ""
echo "✅ Done! Check:"
echo "  - Issues: https://github.com/systemslibrarian/meow-decoder/issues"
echo "  - Actions: https://github.com/systemslibrarian/meow-decoder/actions"
echo "  - Branch protection: https://github.com/systemslibrarian/meow-decoder/settings/branches"
