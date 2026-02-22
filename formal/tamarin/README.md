# 🧠 Tamarin Observational Equivalence (Minimal)

This directory contains a **minimal** Tamarin model to reason about observational equivalence between two variants of the protocol (real vs decoy). It is intentionally small and focuses on **trace indistinguishability** at the symbolic level.

## Scope

- **Goal:** Provide a minimal formalization for *observational equivalence* that is not expressible in ProVerif.
- **Not a full protocol model:** Cryptographic details are abstracted; the model only captures a representative message flow.
- **Optional:** This check runs only if `tamarin-prover` is installed.

## Files

| File | Purpose |
|---|---|
| `meow_encode_equiv.spthy` | Minimal observational equivalence model (MEOW3) |
| `MeowDuressEquiv.spthy` | Duress mode observational equivalence (MEOW3) |
| `MeowDuressEquivPQ.spthy` | PQ hybrid OE model (MEOW4/MEOW5 ML-KEM-768/1024) |
| `secure_alloc_guard_pages.spthy` | Symbolic guard-page model (overflow/underflow at abstract level) |
| `run.sh` | Runs tamarin-prover on the model |

> **Note:** The symbolic guard-page model (`secure_alloc_guard_pages.spthy`) reasons
> about overflow/underflow at the abstract trace level.  The same properties are now
> also **machine-checked at the implementation level** by real `verus!{}` proofs in
> `crypto_core/src/verus_guarded_buffer.rs` (GB-001 through GB-008), providing a
> concrete complement to the symbolic Tamarin claims.

## Run

```bash
cd /workspaces/meow-decoder/formal/tamarin
./run.sh
```

**Expected output (success):**
```
All lemmas verified.
```

## Attacker Model

- Full control of the public channel (Dolev–Yao).
- Perfect cryptography assumption.

## What this demonstrates

- If the attacker only sees ciphertexts under the same key, the two variants are observationally indistinguishable (within the abstraction).
- This does **not** prove real/decoy indistinguishability of the full implementation.

Protocol source of truth: [docs/protocol.md](../../docs/protocol.md)
