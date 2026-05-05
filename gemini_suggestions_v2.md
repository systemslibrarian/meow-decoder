# Deep Architectural and Cryptographic Review: Meow Decoder

Status: historical review artifact, updated on 2026-05-04 to reflect current branch state.

This document originally captured four architectural concerns. Two of them surfaced real ratchet-state bugs that were fixed on `audit/cat-mode-fixes`. One item was investigated and closed as a bounded design choice rather than a defect. One item was already fixed by follow-up hardening on this branch.

This file should no longer be read as four currently open critical flaws. It is now a dispositioned review record.

## Executive Summary

Original value:

- Useful as a deep-review input
- Correctly identified two real ratchet-state bugs
- Correctly identified a real singleton-init threading issue
- Flagged a Schrodinger frame-MAC design choice that warranted investigation

Current status:

- Item 1: investigated, bounded, and closed as a design choice, not a confirmed bug
- Item 2: fixed on this branch
- Item 3: fixed on this branch
- Item 4: fixed on this branch

At this point, none of the four original items remain open as originally stated.

Recommended interpretation:

- Keep this document as historical context
- Do not use it as the current source of truth for open findings
- Use `FOLLOWUP.md` and current tests for branch status

## 1. Schrodinger Mode: Public Frame-MAC Seed and DoS Concern

Original claim:

- A public `frame_mac_seed` allows forged-but-valid frame MACs
- An attacker could poison the Fountain decoder and drive unbounded CPU or memory exhaustion

Current disposition: closed as a design choice after investigation.

What changed:

- The codebase explicitly documents that `frame_mac_seed` is public and is intended only to provide per-GIF uniqueness for a DoS-filter MAC layer
- The real authentication boundary remains the Argon2id HMAC plus AES-GCM layer below it
- The branch follow-up added an empirical stress test for forged-but-valid-MAC droplets

Current assessment:

- The public seed does allow an attacker to create forged-but-valid outer frame-MAC droplets
- That fact alone does not prove a practical CPU-exhaustion break in the current decoder implementation
- On this branch, the attack was tested and found bounded under current parser and decoder behavior

Evidence recorded in follow-up:

- 10,000 forged droplets completed in approximately 0.01 seconds wall time
- RSS growth stayed effectively flat under the tested ceiling
- The pending-droplet behavior is bounded in practice by the GIF parser frame cap
- Regression coverage was added in `tests/test_schrodinger_dos.py`

Residual risk:

- This remains a design tradeoff worth documenting
- If future decoder changes remove current bounds or change pending-droplet behavior, this should be re-evaluated

Verdict:

- Not currently tracked as an open protocol bug
- Keep as a design note, not an active critical finding

## 2. Ratchet Desync via PQ Implicit Rejection

Original claim:

- ML-KEM decapsulation happened before `commit_tag` verification
- A tampered PQ ciphertext could silently introduce junk entropy into the root state
- The receiver could permanently desynchronize from the sender

Current disposition: fixed on `audit/cat-mode-fixes`.

What changed:

- Ratchet rekeying now uses a speculative-state pattern
- Pre-rekey state is snapshotted before mutating root and chain state
- On verification success, the speculative rekey is committed
- On any verification failure, the speculative state is rolled back and junk state is discarded

Current assessment:

- The original issue was real and important
- The implemented fix is coherent and well targeted
- This still merits cryptographer review because rollback logic in ratchets is subtle

Regression coverage now referenced in follow-up:

- `test_tampered_pq_ciphertext_does_not_desync_ratchet`
- broader ratchet and forward-secrecy tests remain green on the branch

Verdict:

- No longer open on this branch
- Historical finding preserved for audit traceability

## 3. Ratchet Key Destruction on Frame Corruption

Original claim:

- Corrupted frames could burn a message key permanently before verification succeeded
- Re-scanning the same frame could fail because the key was already consumed or dropped
- Rekey frames were especially dangerous because a bad path could desynchronize the session

Current disposition: fixed on `audit/cat-mode-fixes`.

What changed:

- Cached skipped keys are now peeked rather than popped before verification
- Ownership of the message-key handle is tracked explicitly
- The cached key is only consumed after both `commit_tag` and AES-GCM validation succeed
- Failure paths keep the cache intact and roll back speculative rekey state when present

Current assessment:

- The original issue was real
- The new ownership model and delayed consumption are the right shape of fix
- This is exactly the kind of failure mode that is easy to miss without state-machine review

Regression coverage now referenced in follow-up:

- `test_cached_key_survives_commit_tag_failure`
- `test_cached_rekey_frame_survives_commit_tag_failure`

Verdict:

- No longer open on this branch
- Historical finding preserved for audit traceability

## 4. `crypto_backend.py` Threading Race Conditions

Original claim:

- Rust backend singleton initialization lacked locking
- Concurrent web or multithreaded flows could race during backend instantiation

Current disposition: fixed on this branch.

What changed:

- `get_default_backend()` and `get_handle_backend()` now use `threading.Lock()` with double-checked initialization
- The branch follow-up explicitly records this as fixed for CPython free-threading safety

Current assessment:

- This was a concrete and useful hardening suggestion
- It should no longer appear as an open finding in current-facing review material

Verdict:

- Closed on this branch

## Non-Code Review Pass on This Document

Strengths:

- Good at identifying subtle state-machine interactions
- Focused on real protocol-control points rather than superficial issues
- Useful as a source artifact for deeper follow-up work

Weaknesses:

- The original wording overstated current severity once fixes landed
- It mixed confirmed defects, plausible risks, and design disagreements too aggressively
- It used perfection language that is not helpful for engineering tracking
- It did not separate open, fixed, and design-choice states

What this document should be used for now:

- Historical context
- Audit provenance
- Explanation of why certain ratchet rollback tests exist

What it should not be used for now:

- Current status dashboard
- Executive summary of branch risk
- Prioritization input without cross-checking `FOLLOWUP.md`

## Recommended Remaining Follow-Up

- Keep cryptographer review on the speculative rollback paths in `meow_decoder/ratchet.py`
- Re-run or re-check the relevant Tamarin ratchet model after the rollback changes
- Keep the Schrodinger DoS regression test in CI as a guard against future decoder regressions

## Bottom Line

This review was useful, but it is no longer current as originally written.

The durable outcome is:

- two real ratchet bugs were found and fixed
- one real threading hardening gap was fixed
- one design concern was investigated and closed as bounded under the current implementation
- all four original findings are now dispositioned on this branch
