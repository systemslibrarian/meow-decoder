# 🔬 TLA+ Formal Verification for Meow-Encode

This directory contains TLA+ specifications for formal model checking of the Meow-Encode/Decode protocol.

## Overview

The TLA+ model captures the complete state machine of the Meow-Encode protocol, including:

- **Encoder States**: Idle → KeyDerivation → Encrypt → FrameEncode → Transmit → Done
- **Decoder States**: Idle → Receive → FrameDecode → Decrypt → OutputReal/OutputDecoy → Done
- **Attacker Model**: Full Dolev-Yao capabilities (drop, replay, reorder, duplicate, tamper)

## Files

| File | Description |
|------|-------------|
| `MeowEncode.tla` | Main TLA+ specification (~350 lines) |
| `MeowEncode.cfg` | TLC model checker configuration |
| `README.md` | This file |

## Safety Invariants

The model verifies these critical security properties:

### INV-001: DuressNeverOutputsReal
```tla
decoderState = "OutputDecoy" => decoderOutput /= "real"
```
**Property**: When a duress password is used, the decoder MUST output the decoy, never the real plaintext. This protects coerced users.

### INV-002: NoOutputOnAuthFailure
```tla
authResult = "failure" => (decoderState = "Error" /\ decoderOutput = "none")
```
**Property**: If authentication fails (wrong password, tampered data), no plaintext is ever output. The decoder enters Error state with `output = "none"`.

### INV-003: ReplayNeverSucceeds
```tla
(hasReplayAction /\ frameFromDifferentSession) => authResult /= "success"
```
**Property**: Replayed frames from a different session are always detected and rejected. Frame MACs with session binding prevent replay attacks.

### INV-004: NonceNeverReused
```tla
\A n \in usedNonces : (unique per session)
```
**Property**: Each encryption uses a fresh nonce. The encoder only proceeds if the nonce hasn't been used before. Nonce reuse would catastrophically break AES-GCM.

### INV-005: TamperedFramesRejected
```tla
(\E frame : frame.corrupted) => authResult /= "success"
```
**Property**: Any tampered frame (corrupted ciphertext or invalid tag) causes authentication failure. AES-GCM authentication tag verification catches all modifications.

### INV-006: NoAuthBypass
```tla
(decoderState \in {"OutputReal", "OutputDecoy", "Done"}) => authResult = "success"
```
**Property**: There is no code path to output states without passing through authentication. The state machine enforces auth-then-output.

## Running the Model Checker

### Prerequisites

1. Install TLA+ Toolbox or TLC command-line:
   ```bash
   # Using TLA+ Toolbox (GUI)
   # Download from: https://github.com/tlaplus/tlaplus/releases
   
   # Or command-line TLC
   wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
   ```

2. Or use Docker:
   ```bash
   # Option 1: Official TLA+ Community Edition image (recommended)
   docker pull ghcr.io/hwayne/tlacli:latest
   
   # Option 2: Alternative image
   docker pull toolsmiths/tla:latest
   ```

### Running TLC

#### Command Line
```bash
# Navigate to this directory
cd formal/tla

# Run TLC with the configuration
java -jar tla2tools.jar -config MeowEncode.cfg MeowEncode.tla

# With more memory for larger state spaces
java -Xmx8g -jar tla2tools.jar -config MeowEncode.cfg MeowEncode.tla

# Parallel model checking (4 workers)
java -jar tla2tools.jar -workers 4 -config MeowEncode.cfg MeowEncode.tla
```

#### Docker (Recommended for quick setup)
```bash
# Option 1: Using tlacli (easiest)
cd formal/tla
docker run --rm -v "$(pwd)":/spec ghcr.io/hwayne/tlacli tlc MeowEncode.tla -config MeowEncode.cfg

# Option 2: Using toolsmiths/tla image
docker run --rm -v "$(pwd)":/models -w /models toolsmiths/tla:latest tlc -config MeowEncode.cfg MeowEncode.tla

# Option 3: Download and run JAR directly (no Docker)
wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
java -jar tla2tools.jar -config MeowEncode.cfg MeowEncode.tla
```

#### TLA+ Toolbox (GUI)
1. Open TLA+ Toolbox
2. File → Open Spec → Add New Spec
3. Select `MeowEncode.tla`
4. Create new model (TLC Model Checker → New Model)
5. In "What to check?" add invariants: `Safety`
6. Run TLC

### Expected Output

A successful verification looks like:
```
TLC2 Version 2.18 of Day Month 20xx (rev: abc123)
Running breadth-first search Model-Checking with fp 123 and target level 15
...
Model checking completed. No error has been found.
  Estimates of the progress of the work:
  Coverage...
  States found: 123456, distinct: 12345
  States left: 0
```

If an invariant is violated, TLC outputs a counterexample trace showing the exact sequence of states that leads to the violation.

## Extending the Model

### Adding New Attacks

To model a new attacker capability:

```tla
AttackerNewCapability ==
    /\ <preconditions>
    /\ channel' = <modified channel>
    /\ attackerActions' = Append(attackerActions, "new_capability")
    /\ UNCHANGED <<other variables>>
```

Then add to the `Next` relation.

### Adding New Invariants

```tla
NewSecurityProperty ==
    <boolean expression over state variables>

\* Add to Safety
Safety ==
    /\ DuressNeverOutputsReal
    /\ NoOutputOnAuthFailure
    /\ ...
    /\ NewSecurityProperty
```

### Tuning State Space

For faster verification:
- Reduce `MaxFrames` (fewer frames = fewer states)
- Reduce `MaxSessions` (fewer concurrent sessions)
- Add state constraints in `.cfg` file

For more thorough verification:
- Increase constants
- Add symmetry optimizations
- Use distributed TLC across multiple machines

## Mapping to Implementation

| TLA+ Concept | Implementation |
|--------------|----------------|
| `EncoderEncrypt` | `crypto.py:encrypt_file_bytes()` |
| `DecoderDecrypt` | `crypto.py:decrypt_to_raw()` |
| `usedNonces` | `crypto.py:_nonce_reuse_cache` |
| `authResult` | AES-GCM authentication tag verification |
| `Frame.tag` | Frame MAC in `frame_mac.py` |
| `DuressPasswords` | `config.py:DuressConfig` |
| `OutputDecoy` | `duress_mode.py:DuressHandler.get_decoy_data()` |

## Limitations

1. **Abstraction**: The TLA+ model abstracts cryptographic operations. It cannot verify the correctness of AES-GCM itself, only its usage patterns.

2. **Finite Model**: TLC explores a finite state space. The constants bound the verification to a representative subset of behaviors.

3. **Attacker Bound**: The attacker can perform unbounded actions in theory, but TLC explores a finite number of attacker action sequences.

4. **No Timing**: TLA+ doesn't model timing. Side-channel attacks are out of scope for this model (see ProVerif and constant-time implementation).

## Related Verification

- **ProVerif** (`../proverif/`): Symbolic protocol verification with Dolev-Yao attacker
- **Verus** (`../../crypto_core/verus/`): Rust code verification for nonce uniqueness, auth-then-output

## References

- [TLA+ Home](https://lamport.azurewebsites.net/tla/tla.html)
- [Practical TLA+ Book](https://www.learntla.com/)
- [TLC Model Checker](https://github.com/tlaplus/tlaplus)
- [AEAD Security Proofs](https://eprint.iacr.org/2017/664.pdf)

---

**Maintained by**: Meow Decoder Project  
**Last Updated**: January 2026
