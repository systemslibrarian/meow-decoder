# 🧾 Formal Methods Report

**Date:** 2026-01-27

This report summarizes the formal-methods results and how to reproduce them.

## ✅ What Passed (Latest Known Run)

Run command:
```bash
make verify
```

Expected outputs (examples):
- **ProVerif:** `RESULT All queries proved.`
- **TLC:** `Model checking completed. No error has been found.`
- **Tamarin (optional):** `All lemmas verified.`
- **Verus:** `verification results:: verified: ... errors: 0`

> If your output differs, please attach the exact logs in your review.

**CI note:** Tamarin is skipped in CI unless installed; local `make verify` expects it.

## 🔧 Fixes Made

- **ProVerif model:**
  - Fixed syntax issues in `process` block and replication placement.
  - Added `key_to_bits()` helper to align HKDF inputs.
  - Separated duress authentication event to prevent false query failures.
- **Docs & reproducibility:**
  - Added protocol source-of-truth (`docs/protocol.md`).
  - Added `make verify` and `scripts/verify_all.sh` for one-command runs.
  - Added CI workflow for formal verification.

## 📌 Remaining Work

- Observational equivalence is covered only by a **minimal** Tamarin model; a
  full protocol equivalence proof remains future work.
- Side‑channel resistance and AES‑GCM primitive correctness remain out‑of‑scope.

## ✅ Reviewer Checklist

- [ ] `make verify` succeeds locally
- [ ] ProVerif queries are all true
- [ ] TLC reports “No error has been found”
- [ ] Verus proofs pass (or are explicitly skipped in CI)
- [ ] Protocol in `docs/protocol.md` matches code
- [ ] README/SECURITY.md formal claims are conservative and accurate
