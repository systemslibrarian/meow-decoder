# External Audit Readiness Checklist

**Tracking:** Milestone C from `docs/ROADMAP.md` Product & UX Track —
"external audit readiness". Phase 10 of the security roadmap
(third-party professional audit) depends on this material being
available to a prospective auditor on day one.

## What this document is

A one-stop pre-audit checklist for an external security firm. It
lives at the level *above* the individual security artifacts —
each row points at the canonical document an auditor will want
before starting work, and explains how the artifact was built up
internally so the firm doesn't have to reverse-engineer that.

If you are a prospective auditor: start at the top. If you are a
maintainer: keep this page accurate as the underlying artifacts
evolve.

## 1. Scope and threat model

| Item | Where | Status |
|---|---|---|
| Threat model with explicit in-scope / out-of-scope adversaries | `docs/THREAT_MODEL.md` | ✅ Maintained |
| Security assumptions (what the project trusts) | `docs/SECURITY_ASSUMPTIONS.md` | ✅ Maintained |
| Security invariants (properties the implementation must preserve) | `docs/SECURITY_INVARIANTS.md` | ✅ Maintained |
| Security claims (what we claim to provide vs. don't) | `docs/SECURITY_CLAIMS.md` | ✅ Maintained |
| Trust tiers (Recommended / Advanced / Experimental) | `docs/TRUST_CENTER.md` | ✅ Shipped 2026-05-04 |
| Per-artifact release maturity | `docs/RELEASE_MATURITY.md` | ✅ Shipped 2026-05-05 |

**Suggested audit scope (first engagement):** the **Recommended**
tier surfaces only — the standard encrypted offline-transfer flow
(`meow-encode` → animated GIF → mobile capture → `meow-decode-gif`),
the Rust crypto core that backs it, and the protocol definition.
Experimental-tier features (Cat Mode, Schrödinger, Duress) are
intentionally lower priority for a first pass.

## 2. Protocol definition

| Item | Where |
|---|---|
| Wire format (manifest, frames, droplets) | `docs/PROTOCOL.md` |
| Ratchet protocol (forward secrecy, PQ hybrid, header encryption) | `docs/RATCHET_PROTOCOL.md` |
| Spec cross-reference (where each PROTOCOL claim lives in code) | `docs/SPEC_REFERENCE.md` |
| Architecture overview | `docs/ARCHITECTURE.md` |
| Fountain (Luby Transform) implementation + Rust/WASM unification | `docs/FOUNTAIN_RUST_WASM_MIGRATION.md` |

## 3. Implementation surface

| Layer | Where | Notes |
|---|---|---|
| Pure Rust crypto core | `crypto_core/` | Workspace member, both PyO3 and wasm-bindgen targets |
| Python bindings | `rust_crypto/src/lib.rs` | 73+ PyO3 wrappers; opaque handle registry for keys |
| Python production package | `meow_decoder/` | Surface area minimized — see `docs/SURFACE_AREA_MINIMIZATION.md` for the production-allowlist boundary |
| Web demo (Flask + WASM frontend) | `web_demo/` | Flagship UI for the Recommended path |
| Mobile (React Native, Android-first) | `mobile/` | Sender-screen scanning is the primary action |

The production package boundary is enforced by
`tests/test_production_import_boundary.py` — any production import
of an archived or experimental module fails the test suite.

## 4. Test coverage

| Suite | Where | Count |
|---|---|---|
| Python tests | `tests/test_*.py` | 2462+ as of last full run |
| Rust unit tests | `crypto_core/`, `rust_crypto/` | 973+ |
| Property-based tests (Hypothesis) | `tests/test_property_*.py` | 14+ proptest properties on the Rust side |
| Adversarial / stego-audit tests | `tests/test_stego_adversarial.py` + `tests/test_stego_fuzz.py` | 92 passing |
| Cross-browser end-to-end | `tests/test_cross_browser.spec.js` | Playwright; Chromium, Firefox, WebKit |
| Production import boundary | `tests/test_production_import_boundary.py` | 5 tests |
| Decompression-bomb regressions | `tests/test_decompression_bomb.py` | 5 tests |
| Schrödinger DoS empirical bound | `tests/test_schrodinger_dos.py` | Established 10K forged droplets bounded under 30s wall, 64 MB RSS |
| Timing-equalizer harness | `tests/test_timing_equalizer.py` | Statistical timing tests for password / duress paths |
| Differential testing | Archived after Rust-only enforcement | n/a |

Markers (`pytest -m`): `security`, `adversarial`, `crypto`, `fuzz`,
`slow`, `integration`, `cat` — see `pyproject.toml`
`[tool.pytest.ini_options]`.

## 5. Continuous fuzzing

| Target language | Where | Targets |
|---|---|---|
| Python (Atheris) | `fuzz/fuzz_*.py` | 18 fuzz targets covering manifest, fountain, crypto, ratchet, stego, PQ, schrödinger, etc. |
| Rust (cargo-fuzz / libFuzzer) | `rust_crypto/fuzz/fuzz_targets/` | 5 targets: `fuzz_decrypt_frame`, `fuzz_header_parse`, `fuzz_hybrid_decapsulate`, `fuzz_ratchet_step`, `fuzz_full_decode_pipeline` |
| Rust (crypto core) | `crypto_core/fuzz/fuzz_targets/` | 4 targets: `fuzz_nonce`, `fuzz_aead`, `fuzz_secure_alloc`, `fuzz_pure_crypto` |
| FFI boundary tests | `rust_crypto/` test files | 19 tests simulating Python→Rust calls with attacker-controlled inputs |

CI workflow: `.github/workflows/rust-security-suite.yml` runs the
Rust security suite (cargo-fuzz, ASan, UBSan, Miri) on every PR.

## 6. Formal methods

| Tool | Models | Status |
|---|---|---|
| **Tamarin Prover 1.12.0 / Maude 3.5.1** | `formal/tamarin/*.spthy` (10 models including ratchet forward secrecy, key commitment, Schrödinger deniability, deadman's switch) | ✅ All shards green; deadman's switch + Schrödinger Deniability (Core + Ratchet) promoted nonblocking → blocking on `audit/cat-mode-fixes` |
| **TLA+** | `formal/tla/` | Models exist; not currently in CI gate |
| **ProVerif** | `formal/proverif/` | Models exist; output excluded via .gitignore |
| **Lean** | `formal/lean/` | Models exist; `.lake/` excluded via .gitignore |

Open formal-method items requiring cryptographer review are
itemized in `FOLLOWUP.md` under "Tamarin formal-verification model
issues — ALL ADDRESSED".

## 7. Hardware-backed paths

The HSM / YubiKey / TPM integration is implemented end-to-end and
covered by mock providers in CI. Real-device validation status is
honestly itemized per-device in `docs/HARDWARE_TEST_MATRIX.md`.

Auditors evaluating the hardware paths should know:

- The integration code is the audit target, not the device itself.
- Real-device validation matrix is open by design (CI runners
  don't have real HSMs/TPMs).
- One TPM cryptographer-review item is flagged in commit
  `e43577e` (`Context::create()` `SensitiveData` slot).
- The `rsa` crate Marvin Attack class is structurally avoided —
  `YubiKey::decrypt()` returns `NotSupported` for RSA1024/2048;
  ECDH is the only YubiKey path.

## 8. Recently closed audit findings

The `audit/cat-mode-fixes` branch (PR #172, in flight at time of
writing) closes a substantial list of findings. Auditors evaluating
recent posture should read:

- `FOLLOWUP.md` — current branch ledger, organized by finding ID
- `CHANGELOG.md` `[Unreleased]` section — narrative rollup
- `docs/audits/AUDIT-2026-04-18.md` — internal audit record
- `docs/audits/RATCHET_SPECULATIVE_ROLLBACK.md` — cryptographer-
  review brief on the speculative-state rollback pattern fix to
  the PQ implicit-rejection desync (HIGH severity, fixed)

Highlights from this branch:

- HIGH ratchet PQ-implicit-rejection silent desync — fixed via
  speculative-state rollback (`meow_decoder/ratchet.py`)
- MEDIUM cached message-key burned on commit_tag failure — fixed
  via peek-not-pop ownership tracking
- 16 security/correctness fixes from the comprehensive Feb 25
  bug audit (Rust nonce CAS, X25519 zero-check, HKDF length, etc.)
- 11 stego bugs across the 4-session multi-layer audit (4
  critical, 4 high, 3 medium)
- Tamarin model bugs across 4 .spthy files — all addressed; 14
  lemmas verify under Tamarin 1.12.0
- Cat-mode / Gate 2 golden-video chain — 9 sequential fixes
- Several Rust handle migration commits closing `gemini #1`
  long-tail items

## 9. Supply-chain posture

Cross-references `docs/RELEASE_MATURITY.md` § "Supply-chain
posture". Highlights:

| Mechanism | Status |
|---|---|
| Sigstore cosign signed-blob (release artifacts) | ✅ Active, cosign v2.6.1 pinned |
| SLSA Build Provenance (`multiple.intoto.jsonl`) | ✅ Active per release |
| Hash-pinned Python deps (`requirements*.lock`) | ✅ Active |
| `cargo deny` Rust dep policy | ✅ Active per `deny.toml` |
| `pip-audit`, `cargo-audit`, Bandit, CodeQL | ✅ Active in CI |
| `npm audit` (root + web_demo) | ✅ 0 vulnerabilities on this branch |
| `detect-secrets` pre-commit hook | ✅ Active with baseline |
| OpenSSF Scorecard | ✅ Tracked |

## 10. Responsible disclosure

The disclosure process lives in **`SECURITY.md`** at the repo
root. An external auditor finding an undisclosed vulnerability
should follow that document. The CVE process is recorded as
"planned" in `docs/ROADMAP.md` Phase 10 — establishing it is
itself an audit-readiness deliverable that may fall out of the
first external engagement.

## 11. Known gaps the audit should look at

These are the items the maintainers are most uncertain about and
would value an outside opinion on:

1. **Tamarin reformulations.** Several Tamarin lemmas were
   rewritten on `audit/cat-mode-fixes` to address wellformedness
   bugs Tamarin 1.10 was lenient about. The reformulations are
   intent-preserving but novel. See `FOLLOWUP.md` "Tamarin formal-
   verification model issues" — cryptographer review of the new
   `CommitmentNonForgeability` lemma especially.
2. **Speculative-state ratchet rollback paths.**
   `meow_decoder/ratchet.py::DecoderRatchet._execute_rekey()` and
   `decrypt()` were rewritten with speculative-state snapshot +
   rollback on verification failure. Three new regression tests
   cover the specific failure modes. Review brief in
   `docs/audits/RATCHET_SPECULATIVE_ROLLBACK.md`.
3. **Schrödinger frame-MAC seed design choice.** Public seed is
   bounded by an empirical CPU/RSS test
   (`tests/test_schrodinger_dos.py`). Worth a fresh look from
   outside the project.
4. **TPM `SensitiveData` slot.** Flagged in commit `e43577e`.
   See `docs/HARDWARE_TEST_MATRIX.md` § TPM 2.0.
5. **Multi-layer stego strength under adaptive steganalysis.**
   Internal evaluation in `docs/STEGO_STRENGTH_EVALUATION.md`;
   external steganalysis review would strengthen the claims.

## 12. What an audit will likely NOT find new on this codebase

(Stated honestly so the audit budget can be focused.)

- Common Python crypto pitfalls (timing attacks on password
  comparison, mode confusion, missing AAD) are caught by
  existing tests + `constant_time` + `subtle` crate boundaries.
- npm / pip CVE chain: actively maintained to zero on this
  branch.
- Memory-safety bugs in the Rust core: covered by ASan/UBSan/Miri
  + cargo-fuzz.
- Concurrency races in Python singletons: hardened with
  threading locks (Finding 11.1, 11.2).

## Related documents

- `docs/RELEASE_MATURITY.md` — per-artifact distribution + signing
- `docs/HARDWARE_TEST_MATRIX.md` — hardware path coverage
- `docs/SURFACE_AREA_MINIMIZATION.md` — what's tracked and why
- `docs/THREAT_MODEL.md` — what the project is and isn't protecting against
- `docs/SECURITY_INVARIANTS.md` — invariants the implementation must preserve
- `FOLLOWUP.md` — current branch ledger of closed audit findings
- `CHANGELOG.md` — narrative changelog by release
- `SECURITY.md` (repo root) — responsible disclosure
