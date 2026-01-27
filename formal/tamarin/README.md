# 🧠 Tamarin Observational Equivalence (Minimal)

This directory contains a **minimal** Tamarin model to reason about observational equivalence between two variants of the protocol (real vs decoy). It is intentionally small and focuses on **trace indistinguishability** at the symbolic level.

## Scope

- **Goal:** Provide a minimal formalization for *observational equivalence* that is not expressible in ProVerif.
- **Not a full protocol model:** Cryptographic details are abstracted; the model only captures a representative message flow.
- **Optional:** This check runs only if `tamarin-prover` is installed.

## Files

| File | Purpose |
|---|---|
| `meow_encode_equiv.spthy` | Minimal equivalence model |
| `run.sh` | Runs tamarin-prover on the model |

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
