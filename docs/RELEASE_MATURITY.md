# Release Maturity Matrix

**Tracking:** Milestone C from `docs/ROADMAP.md` Product & UX Track —
"packaging and release maturity communication". Companion to
`docs/TRUST_CENTER.md`, which defines the Recommended / Advanced /
Experimental tiers in user-facing language. This page is the
honest, per-artifact engineering view.

## What this document is

For each thing we release, this page answers four questions:

1. **What is it?** (CLI binary, Python wheel, web demo, mobile APK,
   Rust crate, …)
2. **What's the trust tier?** (Recommended / Advanced / Experimental
   per `docs/TRUST_CENTER.md`)
3. **How is it signed and distributed?** (Sigstore, cosign, Play
   Store, GitHub Releases, in-tree raw URL, …)
4. **What's the support story?** (versioning, deprecation policy,
   how bugs are reported)

## Per-artifact matrix

### Python distribution — `meow-decoder` wheel + sdist

| Property | Value |
|---|---|
| **Tier** | Recommended |
| **What it ships** | `meow-encode`, `meow-decode-gif`, `meow-shamir`, `meow-schrodinger-encode`, `meow-deadmans-switch` CLIs |
| **Built by** | `.github/workflows/release.yml` (signed) |
| **Signing** | Sigstore cosign — `.whl.sig` + `.whl.pem` published alongside the artifact |
| **Provenance** | SLSA `multiple.intoto.jsonl` published per release |
| **Hash pinning** | `requirements*.lock` files; pip install flow uses hash-checking lockfiles |
| **Distribution** | GitHub Releases (e.g. `https://github.com/.../releases/download/v1.0.0/meow_decoder-1.0.0-py3-none-any.whl`) |
| **Versioning** | Semver. v1.0.0 is the current public release tag |
| **Bug reports** | GitHub Issues |
| **Verification** | `cosign verify-blob --bundle <name>.sig --certificate <name>.pem <wheel>` |

### Rust crypto core — `crypto_core` (in-repo crate)

| Property | Value |
|---|---|
| **Tier** | Recommended (consumed by Python via PyO3, by browser via wasm-bindgen — see below) |
| **What it ships** | `meow_crypto_rs` Python extension, `crypto_core_bg.wasm` for browser |
| **Built by** | `.github/workflows/rust-tests.yml` and the maturin pipeline in `release.yml` |
| **Distribution** | Embedded in the Python wheel (PyO3 binding); WASM artifact tracked in tree (see below) |
| **Versioning** | Pinned to the wheel version; not published as a standalone crate |
| **Bug reports** | GitHub Issues |

### Web demo (Flask + WASM frontend)

| Property | Value |
|---|---|
| **Tier** | Recommended (Standard encode/decode flow); Advanced (modes, fountain tuning); Experimental (Cat Mode, Schrödinger) |
| **What it ships** | `web_demo/app.py` Flask app + static HTML/JS/WASM frontend |
| **Distribution** | Run from source (`python web_demo/app.py`); a public demo lives at `meowdecoder.com` |
| **WASM artifact** | `web_demo/static/crypto_core_bg.wasm` (and copies in `examples/`, `web_demo/`). See `docs/SURFACE_AREA_MINIMIZATION.md` "Tracked Build Artifacts" — intentionally tracked so a fresh clone can run without `wasm-pack`. Regenerate via `scripts/build_wasm.sh` |
| **Signing** | None — the WASM is built from a signed source release; the running web app is not separately signed |
| **Versioning** | Tracked alongside the Python package version |
| **Bug reports** | GitHub Issues |

### Mobile — Meow Capture (Android)

| Property | Value |
|---|---|
| **Tier** | Recommended (Scan Sender Screen + standard export); Advanced (manual / JSON-import fallbacks); Experimental (per `mobile/README.md`) |
| **What it ships** | React Native APK |
| **Current distribution** | Sideload via in-tree `releases/android/meow-decoder-v3.2.1-release.apk` (raw GitHub URL). See `docs/SURFACE_AREA_MINIMIZATION.md` — intentional pre-store retention |
| **Signing** | APK signed with the Android release keystore (`mobile/android/app/release.keystore`, gitignored). The fingerprint is the source of truth for sideload integrity |
| **Future distribution** | Google Play Store (announced; not yet listed). `releases/android/*.apk` is now `.gitignored` so future APKs go directly to GitHub Releases / Play Store, not the source tree |
| **Versioning** | Independent semver line (currently `v3.2.x`) — tracked in `mobile/RELEASE.md` |
| **Bug reports** | GitHub Issues |

### Mobile — Meow Capture (iOS)

| Property | Value |
|---|---|
| **Tier** | Not yet released |
| **Status** | Active development. Source lives in `mobile/ios/`. Build instructions in `mobile/README.md` |
| **Future distribution** | Apple App Store (announced; not yet listed) |
| **Interim path** | iOS users can use the web demo in Safari to scan transfers (per README) |

## Cross-cutting properties

### Supply-chain posture

| Mechanism | Where | Status |
|---|---|---|
| Sigstore cosign signed-blob signatures | All GitHub Release artifacts | ✅ Active (`release.yml`, cosign v2.6.1 pinned per `8ba892d`) |
| SLSA Build Provenance | `multiple.intoto.jsonl` per release | ✅ Active |
| Hash-pinned Python deps | `requirements*.lock` | ✅ Active |
| `cargo deny` for Rust deps | `deny.toml` + CI workflow | ✅ Active |
| `pip-audit` + Bandit + CodeQL | Security CI | ✅ Active |
| `npm audit` for web/mobile JS | CI + regular Dependabot bumps | ✅ Active (root + web_demo cleared in `audit/cat-mode-fixes`) |
| Detect-secrets pre-commit hook | `.pre-commit-config.yaml` + `.secrets.baseline` | ✅ Active |
| `cargo audit` Rust CVE scan | Security CI | ✅ Active |

### Deprecation policy

The current public-facing version is **v1.0.0 (INTERNAL REVIEW)**.
Anything below v1.0 in internal milestone numbering (v5.x, v6.x in
historical CHANGELOG entries) has been consolidated into the v1.0
public release.

When a CLI flag, config option, or wire-format field is removed,
the policy is:

1. Mark deprecated in the CHANGELOG and release notes.
2. Keep the path working for at least one minor version with a
   runtime deprecation warning.
3. Remove no earlier than the next minor (when the deprecation
   warning has been visible to users for at least one cycle).

Wire-format constants (manifest MAGIC bytes, droplet header layout,
ratchet domain-separation strings) are versioned by the MAGIC byte
itself — older readers fail closed on a MAGIC bump rather than
silently misinterpret newer payloads.

### Release cadence

There is no fixed cadence. Releases are cut when material security
fixes or feature work justifies one. The `audit/cat-mode-fixes`
branch ahead of `main` represents an active in-flight set of
hardening + product/UX commits intended to land as a bundled PR.

### How to verify a release

For the signed Python wheel artifacts (the canonical distribution):

```sh
# Download wheel + sig + cert from GitHub Releases
WHEEL=meow_decoder-1.0.0-py3-none-any.whl
curl -LO "https://github.com/systemslibrarian/meow-decoder/releases/download/v1.0.0/${WHEEL}"
curl -LO "https://github.com/systemslibrarian/meow-decoder/releases/download/v1.0.0/${WHEEL}.sig"
curl -LO "https://github.com/systemslibrarian/meow-decoder/releases/download/v1.0.0/${WHEEL}.pem"

# Verify with cosign (v2.x recommended for compatibility with the published bundle)
cosign verify-blob \
    --certificate "${WHEEL}.pem" \
    --bundle "${WHEEL}.sig" \
    --certificate-identity-regexp 'https://github.com/systemslibrarian/meow-decoder/.+' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "${WHEEL}"
```

For the Android APK, verify the signing certificate fingerprint
matches the one published in `mobile/RELEASE.md`:

```sh
keytool -printcert -jarfile meow-decoder-v3.2.1-release.apk
```

## What this document is NOT

- **Not a marketing comparison.** For competitive positioning see
  `docs/MEOW_VS_STEGX_VS_SIGNAL.md`.
- **Not a threat model.** For what each tier protects against see
  `docs/THREAT_MODEL.md`.
- **Not a feature checklist.** For features by tier see
  `docs/TRUST_CENTER.md`.
- **Not a hardware test matrix.** For HSM / YubiKey / TPM coverage
  see `docs/HARDWARE_TEST_MATRIX.md`.

## Related documents

- `docs/TRUST_CENTER.md` — user-facing tier framing
- `docs/SURFACE_AREA_MINIMIZATION.md` — what's tracked in the
  source tree and why
- `docs/HARDWARE_TEST_MATRIX.md` — hardware-path validation status
- `docs/THREAT_MODEL.md` — what the project is and isn't protecting against
- `docs/SECURITY.md` (`SECURITY.md` at repo root) — responsible disclosure
- `mobile/RELEASE.md` — Android release process
