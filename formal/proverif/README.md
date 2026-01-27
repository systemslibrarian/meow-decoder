# 🔐 ProVerif Symbolic Protocol Analysis for Meow-Encode

This directory contains ProVerif specifications for symbolic verification of the Meow-Encode/Decode protocol's cryptographic security.

## Overview

ProVerif uses the Dolev-Yao attacker model to symbolically verify security properties. Unlike TLA+ (which models state machines), ProVerif focuses on the cryptographic protocol and proves properties like secrecy and authentication against a powerful network attacker.

### Attacker Model
- Full control of public channel (intercept, drop, replay, reorder, tamper)
- Perfect cryptography assumption (cannot break AES‑GCM, HMAC, HKDF)
- Cannot read private channels or secrets marked `[private]`

### What is Proven
- Secrecy of real/decoy plaintext and passwords
- Authentication (auth‑then‑output for real decrypt path)
- Replay resistance (session/nonce binding abstraction)
- Duress safety (decoy output does not imply real authentication)

### Not Proven
- Observational equivalence / indistinguishability (requires a biprocess or Tamarin)
- Side‑channel resistance
- Implementation correctness of AES‑GCM/HMAC primitives

## Files

| File | Description |
|------|-------------|
| `meow_encode.pv` | Main ProVerif specification (~700 lines) |
| `run.sh` | Shell script to run analysis with various options |
| `README.md` | This file |

## Quick Start

```bash
# Navigate to this directory
cd /workspaces/meow-decoder/formal/proverif

# Run ProVerif (basic analysis - 10-30 seconds)
eval $(opam env)
proverif meow_encode.pv

# Generate HTML report in output/ directory
proverif -html output meow_encode.pv
```

Protocol source of truth: [docs/protocol.md](../../docs/protocol.md)

**Expected output (success):**
```
RESULT not attacker(real_secret[]) is true.
RESULT not attacker(real_password[]) is true.
...
RESULT All queries proved.
```

Makefile shortcuts:

```bash
make formal-proverif
make formal-proverif-html
```

**Expected result**: All 7+ queries should show `is true` or `is false` (for secrecy).

---

## Installation

ProVerif is **not available via apt**. Install via OPAM (OCaml package manager):

```bash
# 1. Install OPAM
sudo apt-get install -y opam

# 2. Initialize OPAM (one-time setup, takes a few minutes)
opam init -y --disable-sandboxing
eval $(opam env)

# 3. Install ProVerif
opam install -y proverif

# 4. Verify installation
proverif --version
```

### Alternative: Build from Source

```bash
# Install OCaml
sudo apt-get install -y ocaml

# Download and build ProVerif
cd /workspaces/meow-decoder/formal/proverif
curl -LO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz
cd proverif2.05
./build

# Run (use local binary)
./proverif ../meow_encode.pv
```

### Alternative: Docker

```bash
# Note: Official Docker image may not exist; build locally if needed
docker run --rm -v $(pwd):/work ocaml/opam:latest \
  bash -c "opam install -y proverif && proverif /work/meow_encode.pv"
```

---

## Full Documentation

```bash
# Using the provided script
./run.sh                    # Basic analysis
./run.sh --html             # Generate HTML output in output/
./run.sh --verbose          # Show attack traces for failed queries
./run.sh --docker           # Use Docker instead of local ProVerif

# Or manually
proverif meow_encode.pv
```

## Security Queries

The ProVerif model verifies 7 security properties plus implicit nonce uniqueness:

### Query 1: Plaintext Secrecy
```proverif
query attacker(real_secret).
query attacker(decoy_secret).
```
**Property**: The attacker cannot derive the plaintext, even with full control of the network. AES-256-GCM provides semantic security. The `[private]` annotation ensures these never appear on public channels.

**Expected Result**: `RESULT not attacker(real_secret[]) is true.`

### Query 2: Password Secrecy
```proverif
query attacker(real_password).
query attacker(duress_password).
```
**Property**: Passwords never leak through protocol messages. Argon2id (512 MiB, 20 iterations) derives keys that don't reveal the password. Salt is public but password remains secret.

**Expected Result**: `RESULT not attacker(real_password[]) is true.`

### Query 3: Payload Authenticity (Injective)
```proverif
query sid: sessionid, pt: plaintext, n: nonce, s: salt;
    event(DecoderOutputReal(sid, pt)) ==> 
        event(EncoderEncrypted(sid, pt, n, s)).
```
**Property**: If the decoder outputs plaintext, the encoder must have encrypted that exact plaintext with those exact parameters. AAD binding prevents substitution attacks.

**Expected Result**: `RESULT event(DecoderOutputReal(...)) ==> event(EncoderEncrypted(...)) is true.`

### Query 4: Replay Resistance
```proverif
query sid: sessionid, n: nonce, s: salt;
    event(DecoderAuthenticated(sid, n, s)) ==> event(EncoderStarted(sid)).

(* Stronger: nonce binding *)
query sid: sessionid, n: nonce, s: salt;
    event(DecoderAuthenticated(sid, n, s)) ==> event(EncoderGeneratedNonce(sid, n)).
```
**Property**: Each successful decryption corresponds to a genuine encoding session with that specific nonce. Replaying old frames cannot cause acceptance.

**Expected Result**: Both queries true.

### Query 5: Duress Mode Safety
```proverif
query sid: sessionid, pt: plaintext;
    event(DuressPasswordUsed(sid)) && event(DecoderOutputReal(sid, pt)) ==> false.

query sid: sessionid, pt: plaintext;
    event(DuressPasswordUsed(sid)) && event(DecoderOutputDecoy(sid, pt)) ==> 
        event(DuressCheckPassed(sid)).
```
**Property**: When duress password is detected, real plaintext is NEVER output. Duress path only outputs decoy after successful duress verification.

**Expected Result**: Both queries true.

### Query 6: No Output Without Authentication
```proverif
query sid: sessionid, pt: plaintext, n: nonce, s: salt;
    event(DecoderOutputReal(sid, pt)) ==> event(DecoderAuthenticated(sid, n, s)).

query sid: sessionid, pt: plaintext, n: nonce, s: salt;
    event(DecoderOutputDecoy(sid, pt)) ==> event(DecoderAuthenticated(sid, n, s)).
```
**Property**: No plaintext (real or decoy) is output without first successfully authenticating. Prevents bypass attacks.

**Expected Result**: Both queries true.

### Query 7: Nonce Uniqueness (Implicit)
ProVerif models `new n: nonce` as generating a fresh, unique value. The model structure ensures each encryption uses a fresh nonce, preventing nonce reuse attacks on AES-GCM.

## Dolev-Yao Attacker Model

ProVerif automatically considers an attacker who can:

| Capability | Description |
|------------|-------------|
| **Intercept** | Read all messages on public channels |
| **Inject** | Send arbitrary messages |
| **Replay** | Re-send previously captured messages |
| **Block** | Prevent message delivery |
| **Modify** | Alter message contents (but can't forge valid MACs) |
| **Derive** | Combine known values to derive new ones |
| **Compute** | Apply any public function to known values |

The attacker CANNOT:
- Invert hash functions (Argon2id, SHA-256)
- Decrypt without the key
- Forge valid authentication tags
- Break the DH assumption (X25519)

## Running ProVerif

### Prerequisites

1. Install ProVerif:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install proverif
   
   # macOS (via Homebrew)
   brew install proverif
   
   # From source
   wget https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
   tar xzf proverif2.05.tar.gz
   cd proverif2.05 && ./build
   ```

2. Or use Docker:
   ```bash
   docker pull proverif/proverif:latest
   ```

### Running Analysis

#### Command Line
```bash
# Navigate to this directory
cd formal/proverif

# Run ProVerif
proverif meow_encode.pv

# With HTML output
proverif -html output meow_encode.pv

# More verbose output
proverif -log meow_encode.pv
```

#### Docker
```bash
docker run --rm -v $(pwd):/spec proverif/proverif:latest meow_encode.pv
```

### Expected Output

A successful verification shows:
```
Verification summary:

Query not attacker(real_secret[]) is true.
Query not attacker(decoy_secret[]) is true.
Query not attacker(real_password[]) is true.
Query not attacker(duress_password[]) is true.
Query event(DecoderOutputReal(sid,pt)) ==> event(EncoderEncrypted(sid,pt,n)) is true.
Query event(DecoderAuthenticated(sid)) ==> event(EncoderStarted(sid)) is true.
Query event(DuressPasswordUsed(sid)) && event(DecoderOutputReal(sid,pt)) ==> false is true.

--------------------------------------------------------------
Verification result: 7 queries verified.
--------------------------------------------------------------
```

If a query fails, ProVerif outputs an attack trace showing the sequence of messages that violates the property.

## Protocol Variants Modeled

### 1. Standard Protocol (Password Only)
```
Encoder                                    Decoder
   |                                          |
   |  k = argon2id(password, salt)            |
   |  ct = AES-GCM(k, nonce, plaintext, aad)  |
   |  mac = HMAC(frame_key, ct)               |
   |                                          |
   |  --- (manifest, frame) --->              |
   |                                          |
   |                    Verify MAC, Decrypt   |
   |                    Output plaintext      |
```

### 2. Forward Secrecy Protocol (X25519 + Password)
```
Encoder                                    Decoder
   |                                          |
   |  ephemeral_priv = random()               |
   |  ephemeral_pub = X25519(ephemeral_priv)  |
   |  shared = X25519(ephemeral_priv, recv_pub)|
   |  k = HKDF(argon2id(pwd, salt), shared)   |
   |  ct = AES-GCM(k, nonce, plaintext, aad)  |
   |                                          |
   |  --- (ephemeral_pub, manifest, frame) -->|
   |                                          |
   |           shared = X25519(recv_priv, ephemeral_pub)
   |           Verify, Decrypt, Output        |
```

### 3. Duress Mode
```
Encoder                                    Decoder (Duress)
   |                                          |
   |  (normal encoding)                       |
   |                                          |
   |  --- (manifest, frame) --->              |
   |                                          |
   |                    Detect duress password|
   |                    Output DECOY only     |
   |                    (real never exposed)  |
```

## Cryptographic Modeling

| Real Primitive | ProVerif Model |
|----------------|----------------|
| AES-256-GCM | `aes_gcm_encrypt/decrypt` with perfect AEAD |
| Argon2id | `argon2id(password, salt)` - perfect hash |
| HMAC-SHA256 | `hmac_sha256(key, msg)` with `hmac_verify` |
| X25519 | `x25519_shared` with DH commutativity equation |
| HKDF | `hkdf_expand(key, info)` - perfect PRF |

## Limitations

1. **Symbolic Model**: ProVerif uses symbolic (perfect) cryptography. It cannot find implementation bugs or side-channel attacks.

2. **No Probability**: ProVerif proves or disproves properties absolutely. It doesn't quantify attack success probability.

3. **Termination**: ProVerif may not terminate for some queries. The model is designed to avoid infinite loops.

4. **Abstraction**: Fountain codes and QR encoding are abstracted away. The focus is on cryptographic security.

## Extending the Model

### Adding a New Attack Query
```proverif
(* Add after existing queries *)
query sid: sessionid;
    event(SomeNewEvent(sid)) ==> event(SomeRequiredPrecondition(sid)).
```

### Modeling a New Protocol Feature
```proverif
(* Add new process *)
let NewFeature(sid: sessionid, ...) =
    (* Protocol steps *)
    event NewFeatureStarted(sid);
    ...
    event NewFeatureCompleted(sid).
```

### Adding to Main Process
```proverif
process
    (* Existing processes *)
    | (
        !new sid_new: sessionid;
        NewFeature(sid_new, ...)
    )
```

## Related Verification

- **TLA+** (`../tla/`): State machine model checking for protocol states
- **Verus** (`../../crypto_core/verus/`): Rust implementation verification

## References

- [ProVerif Manual](https://bblanche.gitlabpages.inria.fr/proverif/)
- [Dolev-Yao Model](https://en.wikipedia.org/wiki/Dolev–Yao_model)
- [AEAD Security](https://eprint.iacr.org/2014/206.pdf)
- [X25519 RFC](https://www.rfc-editor.org/rfc/rfc7748)

---

**Maintained by**: Meow Decoder Project  
**Last Updated**: January 2026
