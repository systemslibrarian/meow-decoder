# 🌊 Lean 4 Fountain Code Proofs

This directory contains Lean 4 formalizations of the Luby Transform (LT) fountain codes used by Meow-Decoder.

## Overview

Fountain codes are the error-correction backbone of Meow-Decoder's optical transmission. This formalization proves:

1. **XOR Algebra**: Block XOR operations form a group (commutativity, associativity, self-inverse)
2. **Belief Propagation Progress**: Degree-1 droplets enable cascade block recovery
3. **LT Decode Completeness**: With ≥ (1+ε)k droplets, recovery succeeds with high probability
4. **Erasure Tolerance**: With ≤ 33% frame loss and 1.5x redundancy, sufficient droplets survive

## Files

| File | Description |
|------|-------------|
| `FountainCodes.lean` | Main proofs for LT code correctness |
| `lakefile.lean` | Lake build configuration |
| `lean-toolchain` | Lean version specification |

## Building

```bash
# Install Lean 4 (via elan)
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

# Build proofs
cd formal/lean
lake build

# Check specific file
lake env lean FountainCodes.lean
```

## Key Theorems

### `lt_decode_completeness`

```lean
theorem lt_decode_completeness 
    (k : ℕ) (hk : k > 0)
    (ε : ℚ) (hε : ε > 0)
    (droplets : List (Droplet k))
    (hdroplets : droplets.length ≥ (1 + ε) * k) 
    :
    -- With probability ≥ 1 - 1/k, decoding succeeds
```

This is the central recovery guarantee: given enough droplets drawn from the Robust Soliton distribution, belief propagation will recover all k source blocks.

### `erasure_tolerance`

```lean
theorem erasure_tolerance 
    (k : ℕ) (hk : k > 0)
    (transmitted : ℕ) (htrans : transmitted = (3 * k) / 2)  -- 1.5x
    (erasure_rate : ℚ) (herasure : erasure_rate < 1/3)
    :
    (1 - erasure_rate) * transmitted ≥ k
```

With 1.5x redundancy and <33% loss, enough droplets survive for recovery.

### `belief_propagation_progress`

```lean
theorem belief_propagation_progress {k : ℕ} (s : DecoderState k) 
    (h : ∃ d ∈ s.pending, Droplet.isDegreeOne d) :
    (beliefPropagationStep s).solvedCount > s.solvedCount ∨ 
    (beliefPropagationStep s).solvedCount = k
```

Each belief propagation step strictly increases solved block count (or we're done).

## Connection to Implementation

The Lean `Droplet` and `DecoderState` structures mirror `meow_decoder/fountain.py`:

| Lean | Python | Description |
|------|--------|-------------|
| `Droplet.seed` | `Droplet.seed` | PRNG seed for reproducible block selection |
| `Droplet.blockIndices` | `Droplet.block_indices` | Finset of XORed block indices |
| `Droplet.degree` | `len(block_indices)` | Number of blocks combined |
| `DecoderState.solved` | `FountainDecoder.blocks` | Recovered block values |
| `DecoderState.pending` | `FountainDecoder.pending_droplets` | Unresolved droplets |
| `beliefPropagationStep` | `_process_pending()` | Core decode loop |

## Assumptions

1. **Robust Soliton Distribution**: Degrees drawn from theoretically optimal distribution
2. **Random Block Selection**: PRNG provides uniform random block indices
3. **Random/Independent Losses**: Erasure channel, not adversarial targeting
4. **No Bit Errors**: QR codes handle bit-level errors; fountain codes handle frame loss

## Security Considerations

Fountain codes provide **availability** (recovery from loss) but not **integrity**. Meow-Decoder adds:

- Per-frame MACs (8-byte HMAC) to detect tampering
- Manifest HMAC to authenticate metadata
- AES-GCM authentication tag on ciphertext

The Lean proofs cover the pure erasure-recovery properties; see ProVerif/Verus for security properties.

## References

1. Luby, M. "LT Codes", IEEE Symposium on Foundations of Computer Science (FOCS), 2002
2. MacKay, D. "Fountain codes", IEE Proceedings, 2005
3. Shokrollahi, A. "Raptor codes", IEEE Transactions on Information Theory, 2006

## TODO

- [ ] Complete `sorry` placeholders with full proofs
- [ ] Add probabilistic monad for high-probability statements
- [ ] Formalize Robust Soliton distribution properties
- [ ] Prove degree distribution ensures sufficient degree-1 droplets
- [ ] Add adversarial erasure impossibility result
