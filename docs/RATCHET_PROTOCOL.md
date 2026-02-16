# MEOW Symmetric Ratchet Protocol Specification (MSR v1)

**Version**: 1.1  
**Date**: 2026-02-16  
**Status**: Implemented with rekey beacons, pending formal verification  
**Authors**: meow-decoder contributors  

---

## 1. Overview

The MEOW Symmetric Ratchet (MSR v1) provides **per-frame forward secrecy** for fountain-coded QR/GIF air-gap file transfers. It is a symmetric hash ratchet inspired by Signal's Double Ratchet, adapted for **unidirectional** data channels where no back-channel exists for asymmetric re-keying.

### 1.1 Design Goals

| Goal | Mechanism |
|------|-----------|
| Per-frame forward secrecy | HKDF-SHA256 hash chain: chain_key[i] → chain_key[i+1] is one-way |
| Key isolation | Domain-separated HKDF derivations for every key type |
| Replay prevention | Frame index bound in AES-GCM AAD; consumed-set tracking |
| Out-of-order support | Skip key cache for fountain code frame reordering |
| DoS resistance | Bounded skip cache (MAX_SKIP_KEYS = 2000) |
| Secure cleanup | Bytearray + Rust backend zeroization of all key material |

### 1.2 Non-Goals / Limitations

| Limitation | Reason | Mitigation |
|-----------|--------|------------|
| No DH ratchet | Air-gap = no back-channel | Chain keys exist only during session |
| No post-compromise security | Unidirectional → no asymmetric re-keying possible | **Sender rekey beacons** (§7) inject fresh entropy periodically |
| Frame index is plaintext | Decoder needs index to derive correct key | Authenticated via AAD |

---

## 2. Key Hierarchy

```
root_key (from Argon2id / X25519 / PQ hybrid)
     │
     │  HKDF-SHA256(root_key, salt, "meow_ratchet_root_v1", 32)
     ▼
chain_key[0]
     │
     ├──── HKDF(ck[0], salt, "meow_ratchet_msg_v1", 32)  ──► message_key[0]
     │                                                              │
     │  HKDF(ck[0], salt, "meow_ratchet_step_v1", 32)      ┌──────┼──────┐
     ▼                                                      │      │      │
chain_key[1]                                            enc_key  nonce  mac_key
     │                                                  (32B)   (12B)  (32B)
     ├──── message_key[1]                                ▲       ▲       ▲
     │                                                   │       │       │
     ▼                                      HKDF domains: _enc_ / _nonce_ / _mac_
chain_key[2]  ...
     │
     ⋮  (continues for each droplet frame)
```

### 2.1 Derivation Functions

All derivations use HKDF-SHA256 (RFC 5869) with domain separation via unique `info` parameters.

| Derivation | Input | Salt | Info | Output Length |
|-----------|-------|------|------|---------------|
| chain_key[0] | root_key | session salt (16B) | `meow_ratchet_root_v1` | 32 bytes |
| chain_key[i+1] | chain_key[i] | session salt | `meow_ratchet_step_v1` | 32 bytes |
| message_key[i] | chain_key[i] | session salt | `meow_ratchet_msg_v1` | 32 bytes |
| enc_key | message_key[i] | session salt | `meow_ratchet_frame_enc_v1` | 32 bytes |
| nonce | message_key[i] | session salt | `meow_ratchet_frame_nonce_v1` | 12 bytes |
| mac_key | message_key[i] | session salt | `meow_ratchet_frame_mac_v1` | 32 bytes |

### 2.2 Domain Separation Constants

```python
RATCHET_ROOT_INFO  = b"meow_ratchet_root_v1"
RATCHET_STEP_INFO  = b"meow_ratchet_step_v1"
RATCHET_MSG_INFO   = b"meow_ratchet_msg_v1"
FRAME_ENC_INFO     = b"meow_ratchet_frame_enc_v1"
FRAME_NONCE_INFO   = b"meow_ratchet_frame_nonce_v1"
FRAME_MAC_INFO     = b"meow_ratchet_frame_mac_v1"

# Rekey beacon constants (§7)
REKEY_BEACON_INFO     = b"meow_ratchet_rekey_v1"
REKEY_BEACON_KEM_INFO = b"meow_ratchet_kem_v1"
```

**Invariant**: All six constants are unique. This is verified by `test_ratchet.py::TestDomainSeparation::test_all_constants_unique`.

---

## 3. Frame Encryption

### 3.1 Cipher Suite

- **Algorithm**: AES-256-GCM (AEAD)
- **Key**: 32-byte `enc_key` derived from message_key
- **Nonce**: 12-byte `nonce` derived from message_key
- **Tag**: 16-byte GCM authentication tag

### 3.2 Encrypted Frame Format

**Standard frame** (non-beacon):
```
┌─────────────────┬────────────────────────────────────┐
│  frame_index    │  AES-GCM ciphertext + tag          │
│  (4 bytes, BE)  │  (len(plaintext) + 16 bytes)       │
└─────────────────┴────────────────────────────────────┘
```

**Beacon frame** (at rekey intervals, see §7):
```
┌─────────────────┬──────────────────┬────────────────────────────────────┐
│  frame_index    │  beacon_data     │  AES-GCM ciphertext + tag          │
│  (4 bytes, BE)  │  (32 bytes)      │  (len(plaintext) + 16 bytes)       │
└─────────────────┴──────────────────┴────────────────────────────────────┘
```

- `frame_index`: 32-bit big-endian unsigned integer. Transmitted in plaintext (authenticated via AAD).
- `beacon_data`: 32 bytes of rekey material (X25519 ephemeral public key or random entropy). Present only on beacon frames.
- `ciphertext + tag`: AES-256-GCM output. The 16-byte authentication tag is appended.

### 3.3 Additional Authenticated Data (AAD)

```
┌─────────────────┬──────────────┬────────────┬──────────────┬──────────────┬──────────┐
│ MEOW_RATCHET_V1 │ frame_index  │ k_blocks   │ block_size   │ total_frames │ salt     │
│ (15 bytes)      │ (4B, LE)     │ (2B, LE)   │ (2B, LE)     │ (4B, LE)     │ (16B)    │
└─────────────────┴──────────────┴────────────┴──────────────┴──────────────┴──────────┘
Total: 43 bytes
```

**AAD bindings prevent**:
- Frame reordering (`frame_index`)
- Cross-session replay (`salt`)
- Parameter substitution (`k_blocks`, `block_size`, `total_frames`)

---

## 4. State Machines

### 4.1 Encoder State Machine

```
INIT ──(encrypt_next)──► ENCODING ──(all frames done)──► FINALIZED
                              │                               │
                              │ chain_key[i] zeroized         │ chain_key zeroized
                              │ message_key[i] zeroized       │
                              └───────────────────────────────┘
```

**Encoder** processes frames sequentially (frame 0, 1, 2, ...).  
Each `encrypt_next()` call:
1. Derives `message_key[i]` from `chain_key[i]`
2. Derives `chain_key[i+1]` (irreversible)
3. Zeroizes `chain_key[i]`
4. Derives subkeys from `message_key[i]`
5. Encrypts frame data with AES-GCM
6. Zeroizes `message_key[i]` and all subkeys

### 4.2 Decoder State Machine

```
INIT ──(decrypt)──► DECODING ──(finalize)──► FINALIZED
                        │
                        ├── frame_idx == position:   advance chain, decrypt
                        ├── frame_idx > position:    fast-forward, cache skipped keys, decrypt
                        └── frame_idx < position:    consume from skip cache, decrypt
                             └── not in cache → IRRECOVERABLE (ValueError)
```

**Out-of-order handling** (for fountain codes):
- When frame `N` arrives but chain is at position `P < N`:
  1. Advance chain from `P` to `N`, caching `message_key[P]` through `message_key[N-1]`
  2. Derive and use `message_key[N]`
- When frame `M < P` arrives and `M` is in skip cache:
  1. Pop `message_key[M]` from cache
  2. Decrypt using that key
- When frame `M < P` arrives and `M` is NOT in cache:
  1. Raise `ValueError` — key is irrecoverable (forward secrecy)

**DoS bound**: `len(skip_cache) + skip_count ≤ MAX_SKIP_KEYS` (2000).

---

## 5. Key Deletion Timeline

```
Time ──────────────────────────────────────────────────────►

Frame 0:  derive ck[0] ──► derive mk[0] ──► derive ck[1] ──► ZERO(ck[0]) ──► derive subkeys ──► encrypt ──► ZERO(mk[0],subkeys)
Frame 1:  derive mk[1] ──► derive ck[2] ──► ZERO(ck[1]) ──► derive subkeys ──► encrypt ──► ZERO(mk[1],subkeys)
Frame 2:  derive mk[2] ──► derive ck[3] ──► ZERO(ck[2]) ──► ...
  ⋮
Frame N:  derive mk[N] ──► derive ck[N+1] ──► ZERO(ck[N]) ──► ... ──► ZERO(mk[N],subkeys)
Finalize: ZERO(ck[N+1])

After finalize: NO keys exist in memory. An attacker who captures memory
AFTER encoding/decoding completes finds zero cryptographic material.
```

---

## 6. Manifest Integration

### 6.1 MODE_RATCHET Flag

`MODE_RATCHET = 0x10` is OR'd into the manifest `mode_byte`:

| Manifest | mode_byte | Meaning |
|----------|-----------|---------|
| MEOW2 | `0x02` | Base encryption |
| MEOW2 + ratchet | `0x12` | Base + per-frame ratchet |
| MEOW3 | `0x03` | Forward secrecy (X25519) |
| MEOW3 + ratchet | `0x13` | FS + per-frame ratchet |
| MEOW4 | `0x04` | Post-quantum hybrid |
| MEOW4 + ratchet | `0x14` | PQ + per-frame ratchet |
| Any + duress | `0x8X` | Duress flag (OR `0x80`) |

### 6.2 Frame 0 Exemption

**Frame 0 (manifest/collar tag) is NOT ratchet-encrypted.** Rationale:
- The decoder needs the manifest to obtain `salt`, `k_blocks`, `block_size` which are required to initialize the ratchet
- Chicken-and-egg: can't decrypt manifest without ratchet, can't init ratchet without manifest
- The manifest is already HMAC-authenticated (existing security invariant)
- Only fountain droplet frames (1, 2, 3, ...) are ratchet-encrypted

### 6.3 Ratchet Initialization

```python
# Encoder (encode.py)
encryption_key = derive_key(password, salt)  # Argon2id / X25519 / PQ
ratchet = EncoderRatchet(
    root_key=encryption_key,
    salt=salt,
    k_blocks=k_blocks,
    block_size=config.block_size,
    total_frames=num_droplets,  # NOT including manifest
)

# Frame 0: manifest (NOT ratcheted)
frames[0] = manifest_bytes

# Frames 1..N: droplets (ratcheted)
for droplet in droplets:
    frames.append(ratchet.encrypt_next(droplet.pack()))
ratchet.finalize()
```

```python
# Decoder (decode_gif.py)
encryption_key = derive_key(password, salt)
ratchet = DecoderRatchet(
    root_key=encryption_key,
    salt=salt,
    k_blocks=manifest.k_blocks,
    block_size=manifest.block_size,
    total_frames=total_droplet_frames,
)

# Skip frame 0 (manifest, already parsed)
for encrypted_droplet in droplet_frames:
    raw = ratchet.decrypt(encrypted_droplet)
    fountain_decoder.add_droplet(raw)
ratchet.finalize()
```

---

## 7. Sender Rekey Beacons (Post-Compromise Security)

### 7.1 Problem Statement

The base MSR v1 symmetric ratchet provides forward secrecy but **not** post-compromise security (PCS). If an attacker compromises `chain_key[N]`, they can derive all subsequent keys. In Signal, the DH ratchet solves this by injecting fresh asymmetric entropy on each reply. In a unidirectional air-gap, there is no reply channel.

### 7.2 Solution: Periodic Entropy Injection

Rekey beacons inject fresh entropy at periodic intervals (`rekey_interval`). At every beacon frame, the `message_key` is enhanced:

```
enhanced_key = HKDF(message_key || beacon_secret, salt, "meow_ratchet_rekey_v1", 32)
```

This makes the enhanced key dependent on **both** the chain state AND the beacon secret — which the attacker doesn't have at compromise time.

### 7.3 Beacon Modes

**Mode A: Plaintext Beacon (MEOW2)**

```
beacon_secret = random(32)      // OS CSPRNG
beacon_data   = beacon_secret   // Embedded in frame header
```

- Protects against **memory-only compromise** (attacker has `chain_key` but not the GIF)
- If attacker has both chain state AND the GIF, the beacon data is visible → no PCS
- Use case: Post-capture RAM dump without physical access to the encoded GIF

**Mode B: KEM Beacon (MEOW3/4 with receiver key)**

```
ephemeral_private = X25519PrivateKey.generate()
ephemeral_public  = ephemeral_private.public_key()
raw_shared        = ephemeral_private.exchange(receiver_public_key)
beacon_secret     = HKDF(raw_shared, "", "meow_ratchet_kem_v1", 32)
beacon_data       = ephemeral_public.raw_bytes()   // 32 bytes in frame header
ZEROIZE(ephemeral_private, raw_shared)
```

- **Real PCS**: Attacker with chain state + GIF still cannot recover `beacon_secret` without `receiver_private_key`
- Uses X25519 ephemeral key exchange per beacon (fresh keypair each time)
- Requires receiver to have X25519 keypair (standard in MEOW3/4)

### 7.4 Beacon Frame Layout

```
Is beacon frame?  = (rekey_interval > 0) AND (frame_index > 0) AND (frame_index % rekey_interval == 0)

Standard frame: [frame_index(4)] [ciphertext + tag]
Beacon frame:   [frame_index(4)] [beacon_data(32)] [ciphertext + tag]
```

The decoder detects beacon frames by checking the same `rekey_interval` condition. It strips `beacon_data` from the frame, recovers `beacon_secret`, mixes it into the message key, then decrypts normally.

### 7.5 Key Derivation at Beacon Points

```
# At frame_index where is_beacon == True:

message_key = HKDF(chain_key[i], salt, "meow_ratchet_msg_v1", 32)    // standard step
beacon_secret = <mode A or mode B above>
enhanced_key = HKDF(message_key || beacon_secret, salt, "meow_ratchet_rekey_v1", 32)
ZEROIZE(message_key)  // enhanced_key replaces it

# enhanced_key is used for subkey derivation (enc_key, nonce, mac_key)
# The chain continues normally — beacon does NOT alter the chain itself
```

**Critical property**: Beacons enhance only the `message_key` for beacon frames. The `chain_key` advancement is unaffected. This means out-of-order fountain code delivery works identically.

### 7.6 Configuration

```python
# Encoder
EncodingConfig(
    enable_ratchet=True,
    rekey_beacon_interval=32,     # Beacon every 32 frames (0 = disabled)
)

# Decoder
DecodingConfig(
    rekey_beacon_interval=32,     # Must match encoder
)
```

**Recommended values**:
- `0`: Disabled (base MSR v1, no PCS)
- `32`: Good balance between PCS refresh rate and frame overhead
- `8`: Aggressive PCS (higher overhead, stronger guarantees)

### 7.7 Security Analysis

| Scenario | Plaintext Beacon | KEM Beacon |
|----------|-----------------|------------|
| Chain compromise only (no GIF) | ✅ PCS: enhanced keys unrecoverable | ✅ PCS: enhanced keys unrecoverable |
| Chain + GIF compromise | ❌ beacon visible in frame | ✅ PCS: needs receiver private key |
| Chain + GIF + receiver key | N/A | ❌ Full compromise |
| GIF capture only (no chain) | ✅ Forward secrecy intact | ✅ Forward secrecy intact |

### 7.8 Fountain Code Compatibility

Beacons are fully compatible with out-of-order frame reception:
- The `_is_rekey_frame()` check uses only `frame_index`, which is in the plaintext header
- The skip cache stores standard `message_key` values; beacon mixing happens after cache lookup
- Frame size difference (32 bytes larger for beacons) is handled transparently

---

## 8. Signal Double Ratchet Comparison

| Property | Signal Double Ratchet | MEOW MSR v1.1 |
|----------|----------------------|--------------|
| **Symmetric ratchet** | ✓ Per-message | ✓ Per-frame |
| **DH ratchet** | ✓ Per-reply (X3DH → DH) | ✗ (unidirectional air-gap) |
| **Forward secrecy** | ✓ Per-message | ✓ Per-frame |
| **Post-compromise security** | ✓ Via DH ratchet re-keying | ⚡ Via sender rekey beacons (§7) |
| **Out-of-order support** | Bounded window (typically ~2000) | Full (fountain code, up to 2000 cached) |
| **Key zeroization** | ✓ | ✓ (Rust backend when available) |
| **Header encryption** | ✓ (double-encrypted header) | ✗ (frame index is plaintext, authenticated via AAD) |
| **KDF** | HMAC-SHA256 chain | HKDF-SHA256 with domain separation |
| **AEAD** | AES-256-CBC + HMAC-SHA256 | AES-256-GCM |

### 8.1 Why No DH Ratchet?

The air-gap file transfer protocol is **strictly unidirectional**:
```
Sender ──(GIF/QR → camera)──► Receiver
         └── no back-channel
```

Signal's DH ratchet requires the receiver to send a new public key back to the sender. This is impossible in an air-gap scenario. Therefore:

- **If `chain_key[N]` is compromised, all `chain_key[N+1], chain_key[N+2], ...` are derivable.** This is an inherent limitation of ANY unidirectional protocol.
- **Mitigation**: Chain keys exist only during the encode/decode session. They are never persisted to disk. The primary threat model is post-capture forensic analysis of a completed transfer, where all keys have been zeroized.

### 8.2 What We DO Achieve

Despite lacking a DH ratchet, MSR v1.1 provides:

1. **Backward secrecy**: Compromising `chain_key[N]` reveals nothing about `chain_key[0..N-1]` or any `message_key[0..N-1]`.
2. **Per-frame key isolation**: Each frame uses a unique `(enc_key, nonce, mac_key)` triple.
3. **Key lifetime minimization**: Each key exists in memory only during its frame's encryption/decryption.
4. **Post-session security**: After `finalize()`, zero key material remains in memory.
5. **Partial PCS via rekey beacons**: KEM beacons (§7) provide true PCS for frames at beacon intervals when `receiver_public_key` is used.

---

## 9. Attack Simulation Walkthrough

### Scenario: Temporary Device Compromise at Frame N

**Setup**: Attacker gains read access to encoder memory during frame N's encryption.

**What attacker obtains**:
- `chain_key[N+1]` (just derived)
- `message_key[N]` (about to be zeroized)
- `enc_key[N]`, `nonce[N]`, `mac_key[N]` (about to be zeroized)

**What attacker can do**:
- Decrypt frame N (has `message_key[N]`)
- Derive `chain_key[N+2]`, `chain_key[N+3]`, ... and all subsequent `message_key[M]` for `M > N`
- If they captured the GIF, decrypt frames N+1, N+2, ... (future frames)

**What attacker CANNOT do** (forward secrecy):
- Derive `chain_key[N-1]`, `chain_key[N-2]`, ... (HKDF one-wayness)
- Derive `message_key[0..N-1]` (already zeroized)
- Decrypt frames 0 through N-1 (keys irrecoverable)

**Window of vulnerability**:
- Only exists during active encoding/decoding session
- Shrinks as more frames are processed (more keys zeroized)
- Zero after `finalize()` — post-session capture reveals nothing
- **With KEM beacons**: Even within the vulnerability window, beacon frames require `receiver_private_key` — reducing the attack surface further

---

## 10. Known Edge Cases

### 10.1 Fountain Code Redundancy

Fountain codes generate more droplets than needed (typically 1.5× k_blocks). This means:
- `total_frames` may be larger than strictly necessary for decoding
- The decoder may call `finalize()` before receiving all frames
- Uncached skipped keys are irrecoverable — this is by design

### 10.2 Frame Index Overflow

Frame indices are 32-bit unsigned integers (max 4,294,967,295). For reasonable file sizes and block sizes, this limit will never be reached. The ratchet raises `ValueError` on overflow.

### 10.3 GIF Frame Loss

If QR frames are lost during camera capture:
- **With fountain codes**: Tolerable if enough frames survive (~67% with 1.5× redundancy)
- **With ratchet**: The decoder fast-forwards past missing frames, caching their keys
- **Combined**: Lost frames consume skip cache budget but don't prevent decoding

### 10.4 Skip Cache Exhaustion

If more than MAX_SKIP_KEYS (2000) frames arrive out-of-order, the decoder raises `ValueError`. This bounds memory usage and prevents DoS from adversarial frame index inflation. In practice, 2000 is far more than fountain codes need.

---

## 11. Hardening Recommendations (Future Work)

1. **Header encryption**: Encrypt the frame index to hide traffic analysis metadata. Requires a separate header key derivation.

2. **Ephemeral ratchet salt**: Derive a unique salt for the ratchet (separate from the manifest salt) to provide additional domain separation from the main encryption pipeline.

3. **Ratchet version negotiation**: Include ratchet version in manifest to support future ratchet protocol upgrades (MSR v2, etc.).

4. **Formal verification**: Model the ratchet state machine in ProVerif or Tamarin to prove forward secrecy and beacon PCS properties formally.

5. **Side-channel resistance**: Use constant-time comparison for frame indices in the decoder's skip cache lookup (currently uses Python `dict`/`set` which may leak timing).

6. **Adaptive beacon interval**: Dynamically adjust `rekey_interval` based on frame count / threat posture.

---

## 12. Test Coverage

Comprehensive tests in `tests/test_ratchet.py` (120 tests):

| Test Class | What It Verifies |
|-----------|------------------|
| `TestDomainSeparation` | All 8 HKDF info constants are unique and well-formed |
| `TestInitRatchet` | Correct initial state, determinism, key independence |
| `TestRatchetStep` | Chain advancement, key uniqueness, old key zeroization |
| `TestForwardSecrecy` | HKDF one-wayness: chain_key[N+1] ↛ chain_key[N] |
| `TestSubkeyIndependence` | enc_key / nonce / mac_key are cryptographically independent |
| `TestBuildFrameAAD` | AAD determinism, field encoding, binding completeness |
| `TestFrameEncryptDecrypt` | Roundtrip, index mismatch, wrong key, bit flip, truncation |
| `TestEncoderRatchet` | State machine, position tracking, finalization |
| `TestDecoderRatchet` | In-order + out-of-order roundtrip, replay, DoS bound |
| `TestEncoderDecoderRoundtrip` | Full pipeline: 1 frame, 100 frames, shuffled, partial |
| `TestKeyZeroization` | State/subkey/cache zeroization after finalize |
| `TestCrossSessionIsolation` | Different salts → independent ciphertext |
| `TestModeRatchet` | MODE_RATCHET flag and valid mode byte combinations |
| `TestConfigIntegration` | `enable_ratchet` flag in EncodingConfig |
| **`TestMSRv1SecurityInvariants`** | **6 critical invariants: backward secrecy, DoS bound, OOO, replay, cross-session, nonce uniqueness** |
| **`TestRekeyBeacons`** | **Beacon roundtrip (plaintext + KEM), OOO, size verification, wrong-key rejection** |
| **`TestMeowAliases`** | **Cat-themed API: PawState, WhiskerKeys, bury_in_litter, knead_subkey, prime_cat** |

---

## 13. References

- [Signal Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869)
- [RFC 5116: An Interface and Algorithms for Authenticated Encryption](https://tools.ietf.org/html/rfc5116)
- [Luby Transform Codes (Fountain Codes)](https://en.wikipedia.org/wiki/Luby_transform_code)
- [ARCHITECTURE.md](ARCHITECTURE.md): Full meow-decoder data flow
- [THREAT_MODEL.md](THREAT_MODEL.md): Attack surface analysis
