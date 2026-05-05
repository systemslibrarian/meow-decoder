# The 10/10 Perfection Plan for Meow Decoder

Status: strategic roadmap note, updated on 2026-05-05 to reflect current repo state.

This document started as a forward-looking improvement list. Several items were already implemented or substantially advanced on `audit/cat-mode-fixes`, while a few remain genuinely useful as open strategic directions.

This file now distinguishes:

- already done or mostly done
- partially open
- still worth pursuing

## Executive Summary

The underlying instincts in the original note were mostly sound:

- move secret handling into Rust where possible
- harden thread-safety around shared state
- reduce duplicated algorithm implementations
- keep dependency noise under control
- shrink technical-debt surface area

The problem was status accuracy. Read literally, the original version overstated how much foundational work remained.

Current summary by item:

- Item 1: substantially advanced, with more branch work now completed
- Item 2: substantially advanced, with some review and maintenance still prudent
- Item 3: fixed for the specific dependency issues that motivated the original note
- Item 4: fixed for the identified hotspots
- Item 5: strategically useful; the technical MP4 path is shipped and the broader product/UX work this item gestured at is now the dedicated Product & UX track in `docs/ROADMAP.md` (Milestones A and B shipped 2026-05-04 → 05)
- Item 6: substantially done in staged form
- Item 7: still strategically useful

A separate Product & UX track now lives in `docs/ROADMAP.md`, with supporting specs in `docs/TRUST_CENTER.md` and `docs/DEFAULT_WORKFLOW_SPEC.md`. Several "broader product polish" themes implicit in this document (especially Item 5) are now tracked there as concrete milestones rather than as adjacent commentary in this strategic note.

## 1. Absolute Cryptographic Memory Safety

Original direction:

- move sensitive key lifecycle management into Rust
- expose opaque handles to Python instead of raw bytes
- rely on Rust zeroization and deterministic cleanup where possible

Current status: substantially advanced, with additional branch work completed.

What is already true in the repo:

- The roadmap records full Rust migration of secret-handling crypto as complete
- Opaque handle APIs exist and are used broadly
- Current hardening work continues to push Python-side intermediates out of key derivation paths
- The current branch follow-up explicitly records one HKDF intermediate removal from Python memory
- The current branch also records new handle-based seal/unseal primitives and additional handle migration work in long-lived ratchet and stego key paths

What remains true:

- Not every Python-visible byte buffer can be made impossible in a mixed Python system
- Defense-in-depth cleanup in Python still matters where export to bytes is unavoidable

Verdict:

- Good architectural principle
- No longer a headline missing capability

## 2. Complete Hardware Security Module Stability

Original direction:

- stabilize TPM and hardware-backed flows
- modernize `tpm.rs`
- ensure hardware-backed security paths are trustworthy across targets

Current status: substantially advanced.

What is already true in the repo:

- The roadmap marks HSM, YubiKey, and TPM integration as complete
- The branch follow-up records multiple TPM hardening and panic-removal fixes
- The current branch also records API migration work against `tss-esapi 7.6.0`

What remains open in practice:

- Hardware support is the sort of surface that always needs ongoing compatibility maintenance
- Cryptographer and platform validation still matter for confidence, especially across real devices and driver environments

Verdict:

- Useful ongoing quality area
- Not a missing foundational architecture item anymore

## 3. Zero-Tolerance for Dependency Vulnerabilities

Original direction:

- drive `npm audit` and `pip-audit` to zero warnings
- patch or vendor stubborn transitive dependencies
- update build tools with known CVEs

Current status: fixed for the concrete issues that motivated the original note, with normal dependency maintenance still ongoing.

What is already true in the repo:

- The branch follow-up records `pip` and `wheel` upgrade hardening as fixed in the devcontainer path
- The branch follow-up now also records the repo-root and `web_demo` npm audit chains as fixed after the `canvas` v3 and jest upgrades

Reality check:

- A literal zero-warning policy is sometimes operationally expensive when the remaining issues are in test or tooling transitive dependencies
- The better standard is to track, classify, and deliberately burn down meaningful residual risk

Verdict:

- The original concern produced useful work and is now closed for the named issues on this branch
- Ongoing dependency hygiene still matters, but this is no longer an active gap in the same form

## 4. Eliminate Concurrency Footguns

Original direction:

- add explicit locking to Rust FFI singleton initialization
- harden other shared mutable structures like web-demo token stores

Current status: fixed for the named examples.

What is already true in the repo:

- `crypto_backend.py` singleton initialization now uses locks
- `web_demo/app.py` download token cleanup was also hardened with a lock per follow-up notes

What remains prudent:

- Continue treating shared mutable state in Python web surfaces as something to review systematically
- Add narrow concurrency regression checks where practical rather than relying on informal reasoning

Verdict:

- Good advice
- The examples named in the original draft are already addressed

## 5. Ubiquitous Platform Support via Video Capabilities

Original direction:

- reduce dependence on GIF transport
- improve cross-browser and mobile reliability via real video support
- complete MP4-oriented workflow support where practical

Current status: technical path shipped; the "broader product polish and transport UX" half is now an active workstream.

Why this still matters:

- This is more product and transport quality than cryptography
- Browser and mobile capture reliability can improve materially with better media transport options
- The branch follow-up records shipped WebM to MP4 support work, including Safari identity handling, WebCodecs transcoding, UI wiring, Playwright coverage, and audio passthrough
- The remaining opportunity is broader product polish and transport UX, not the absence of a technical MP4 path

Adjacent product/UX work shipped in this branch:

- The Product & UX track in `docs/ROADMAP.md` Milestones A and B converted the "transport UX" framing here into a concrete default-flow story (outcome-led README, Recommended/Advanced/Experimental taxonomy, Scan Sender Screen as the mobile primary action, capture and export state language aligned with `docs/DEFAULT_WORKFLOW_SPEC.md`)
- The technical media-transport question in this item and the product-shape question of how users actually experience capture are now tracked separately

Verdict:

- Still a strong strategic direction for the technical path
- The MP4 implementation has landed
- The product-shape companion is now its own track and Milestones A and B are shipped; Milestone C (release maturity, external audit readiness) remains

## 6. Rust and WASM Fountain Code Unification

Original direction:

- unify fountain logic in Rust
- expose it to Python and browser surfaces
- remove logic drift between Python and JavaScript implementations

Current status: substantially done in staged form.

What is already true in the repo:

- `docs/FOUNTAIN_RUST_WASM_MIGRATION.md` exists specifically to track this item
- Rust bindings for Python are in place
- WASM-backed activation exists for the web demo
- The Python fountain layer is now a thin shim around Rust for the main path
- The JS fallback remains intentional for environments without WASM

What remains open:

- Cleanup of legacy fallback implementations remains intentionally deferred
- Some downstream docs and cleanup items are still incomplete

Verdict:

- Excellent direction
- No longer a hypothetical migration

## 7. Clean the Litter Box (Technical Debt)

Original direction:

- reduce archive and legacy code noise
- keep scanners and static analysis focused on current surfaces
- move historical material out of the active workspace when possible

Current status: still useful.

Why this still matters:

- The repo has a large historical surface, including archive and test-archive content
- Tooling signal is better when current production surfaces are clearly separated from retained history
- This helps maintainability and reduces review noise

Important nuance:

- Deleting history is not always the right move
- The higher-value goal is separating executable current code from historical reference and making tooling scope deliberate

Verdict:

- Still worth doing
- Needs disciplined scoping rather than blanket deletion language

## Non-Code Review Pass on This Document

Strengths:

- Good directional instincts
- Focuses on real long-term quality levers rather than cosmetic issues
- Correctly values Rust unification, handle-based secrets, and operational rigor

Weaknesses:

- Poor status tracking relative to the current repo
- Too much perfection language and not enough milestone language
- Blends security, product, build, and maintenance goals without clear prioritization
- Some items are now better treated as maintenance or product work than as high-severity architecture gaps

What this document should be used for now:

- Strategic themes
- Long-term quality checklist
- Explanation of why certain migration and cleanup efforts matter

What it should not be used for now:

- Current branch action list
- Severity-ordered engineering backlog
- Evidence that the repo still lacks core Rust or fountain unification work

## Recommended Current Priorities Derived from This Note

If converted into a present-tense backlog, the still-relevant work is roughly:

1. keep hardware-backed paths stable across real environments
2. continue reducing technical-debt noise and archive ambiguity
3. keep pushing Python-visible secret material out of critical paths where practical
4. ~~improve product-level transport UX around the now-shipped video path~~ — now tracked under the Product & UX track in `docs/ROADMAP.md` (Milestones A and B shipped; Milestone C in progress)
5. keep dependency hygiene deliberate as the toolchain evolves

## Bottom Line

This document had good instincts, but it overstated how much foundational work was still missing.

Today it is best read as:

- a strategic note with several wins already realized
- a reminder of remaining cleanup and product-quality opportunities
- not a literal map of missing core architecture

Branch-specific bottom line:

- gemini #1 has seen substantial new handle-migration work on this branch
- gemini #3 is closed for the concrete root and `web_demo` dependency chains that originally motivated it
- gemini #5's technical MP4 path is shipped, and the product-UX half is now an explicit Product & UX track in `docs/ROADMAP.md` with Milestones A and B shipped (default-flow story across docs, web demo, and the mobile receiver)
