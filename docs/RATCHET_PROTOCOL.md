# MEOW Symmetric Ratchet Protocol Specification (MSR v1/v2)

**Version**: 2.0
**Date**: 2026-02-16
**Status**: Implemented with **asymmetric entropy reinjection** (Signal-inspired PCS goals)
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
| ~~No DH ratchet~~ | ~~Air-gap = no back-channel~~ | **RESOLVED (v2.0)**: Asymmetric root key rotation via periodic X25519 ECDH (§7A) |
| ~~No post-compromise security~~ | ~~Unidirectional → no asymmetric re-keying possible~~ | **RESOLVED (v2.0)**: Signal-inspired PCS via asymmetric entropy reinjection (§7A) |
| PCS healing latency = K frames | Unidirectional → no immediate reply channel | Inherent; Signal heals in 1 round-trip, MEOW heals in ≤K frames |
| ~~Frame index is plaintext~~ | ~~Decoder needs index~~ | **RESOLVED (v1.2)**: Header encryption via HKDF-XOR mask (§8.3) |

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

# Rekey beacon constants (§7, v1.x fallback)
REKEY_BEACON_INFO     = b"meow_ratchet_rekey_v1"
REKEY_BEACON_KEM_INFO = b"meow_ratchet_kem_v1"

# Asymmetric entropy reinjection constants (§7A, MSR v2.0)
ASYM_REKEY_ROOT_INFO      = b"meow_asym_rekey_root_v1"   # Root rotation HKDF info
ASYM_REKEY_CHAIN_INFO     = b"meow_asym_rekey_chain_v1"  # Post-rekey chain derivation
ASYM_REKEY_KEM_INFO       = b"meow_asym_rekey_kem_v1"    # ECDH shared secret KDF
ASYM_REKEY_ROOT_INIT_INFO = b"meow_ratchet_root_store_v1" # Initial root storage

# Header encryption constants (§8)
HEADER_ENC_INFO  = b"meow_ratchet_header_v1"
HEADER_MASK_INFO = b"meow_header_mask_v1"
```

**Key commitment**: The per-frame `mac_key` is used to compute a 16-byte HMAC-SHA256 commitment tag over the frame body. This prevents key commitment attacks ("invisible salamanders") where AES-GCM alone allows two different keys to both produce valid decryptions.

**Invariant**: All 14 constants are unique. This is verified by `test_ratchet.py::TestDomainSeparation::test_all_constants_unique` and `test_asymmetric_rekey.py::TestDomainSeparation::test_all_constants_unique`.

---

## 3. Frame Encryption

### 3.1 Cipher Suite

- **Algorithm**: AES-256-GCM (AEAD)
- **Key**: 32-byte `enc_key` derived from message_key
- **Nonce**: 12-byte `nonce` derived from message_key
- **Tag**: 16-byte GCM authentication tag

### 3.2 Encrypted Frame Format

**Standard frame** (non-beacon, MSR v1.2 hardened):
```
┌─────────────────┬────────────────┬──────────────────────────────────┐
│  encrypted_index  │  commitment_tag │  AES-GCM ciphertext + tag          │
│  (4 bytes, XOR)   │  (16 bytes)     │  (len(plaintext) + 16 bytes)       │
└─────────────────┴────────────────┴──────────────────────────────────┘
```

**Beacon frame** (at rekey intervals, see §7):
```
┌─────────────────┬────────────────┬──────────────────┬──────────────────────────────────┐
│  encrypted_index  │  commitment_tag │  beacon_data      │  AES-GCM ciphertext + tag          │
│  (4 bytes, XOR)   │  (16 bytes)     │  (32 bytes)       │  (len(plaintext) + 16 bytes)       │
└─────────────────┴────────────────┴──────────────────┴──────────────────────────────────┘
```

- `encrypted_index`: 4-byte frame index XOR-masked with HKDF-derived pseudorandom mask. Prevents traffic analysis of frame ordering (Signal header encryption parity).
- `commitment_tag`: 16-byte truncated HMAC-SHA256(mac_key, frame_body). Prevents key commitment attacks ("invisible salamanders") where AES-GCM alone allows multi-key decryption.
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
| MEOW4 | `0x04` | Post-quantum hybrid (ML-KEM-1024 paranoid) |
| MEOW4 + ratchet | `0x14` | PQ paranoid + per-frame ratchet |
| MEOW5 | `0x05` | Post-quantum default (ML-KEM-768) |
| MEOW5 + ratchet | `0x15` | PQ default + per-frame ratchet |
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

**Mode C: PQ KEM Beacon (MEOW5 with ML-KEM-1024)**

```
(pk_receiver, sk_receiver) = ML-KEM-1024.KeyGen()     // Receiver generates ahead of time
(ct, shared_secret)        = ML-KEM-1024.Encaps(pk_receiver)
beacon_secret              = HKDF(shared_secret, "", "meow_pq_beacon_mix_v1", 32)
beacon_data                = ct                         // 1568 bytes in frame header
ZEROIZE(shared_secret)
```

- **Post-quantum PCS**: Resists harvest-now-decrypt-later even for ratchet beacons
- Uses ML-KEM-1024 (NIST FIPS 203, Level 5 security) via `pq_ratchet_beacon.py`
- **Fail-closed**: Insecure stubs permanently disabled — `RuntimeError` raised if no real ML-KEM backend (Rust, ml-kem, or OQS) is available
- Larger beacon overhead: 1568 bytes per beacon frame (vs 32 bytes for Mode B)
- Requires receiver to have ML-KEM-1024 keypair
- **Note**: PQ beacons are implemented but not auto-integrated into the default ratchet path. Use `PQRatchetBeacon` class directly when PQ post-compromise security is needed.

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

## 7A. Asymmetric Root Key Rotation (MSR v2.0 — Signal-Inspired PCS)

### 7A.1 Overview

MSR v2.0 upgrades rekey beacons from message-key mixing (§7) to **asymmetric root key rotation**, achieving post-compromise security goals inspired by Signal's DH ratchet (not Signal; no equivalence claim). Instead of mixing beacon entropy into individual message keys, the receiver's long-term X25519 public key is used to perform ECDH at each rekey boundary, rotating the root key and deriving an entirely new chain.

### 7A.2 State Machine

```
                    ┌─────────────────┐
                    │  INIT (epoch 0) │
                    │  root_key_0     │
                    │  chain_key_0    │
                    └────────┬────────┘
                             │
          frame 0..K-1: symmetric ratchet on chain_key_0
                             │
                    ┌────────▼────────┐
                    │  REKEY (frame K) │
                    │  eph = X25519() │
                    │  shared = ECDH  │
                    └────────┬────────┘
                             │
          root_key_1 = HKDF(shared, salt=root_key_0, info || epoch_1)
          chain_key_K = HKDF(root_key_1, salt, chain_info)
          ZEROIZE(root_key_0, old_chain)
                             │
                    ┌────────▼────────┐
                    │  EPOCH 1        │
                    │  root_key_1     │
                    │  chain_key_K    │
                    └────────┬────────┘
                             │
          frame K..2K-1: symmetric ratchet on chain_key_K
                             │
                    ┌────────▼────────┐
                    │  REKEY (frame 2K)│
                    │  eph' = X25519()│
                    └────────┬────────┘
                             │
                            ⋮  (continues for each epoch)
```

### 7A.3 HKDF Derivation Details

| Step | IKM | Salt | Info | Output |
|------|-----|------|------|--------|
| Initial root | root_key | session salt | `meow_ratchet_root_store_v1` | ratchet_root (32B) |
| ECDH KDF | raw_shared | `""` | `meow_asym_rekey_kem_v1` | shared_secret (32B) |
| Root rotation | shared_secret | old_root_key | `meow_asym_rekey_root_v1 \|\| BE32(epoch)` | new_root (32B) |
| Chain derivation | new_root | session salt | `meow_asym_rekey_chain_v1` | new_chain (32B) |

**Epoch binding**: The epoch counter (big-endian uint32) is appended to the root rotation info string. This prevents cross-epoch replay: an attacker who captures ephemeral keys from epoch E cannot use them to compute root keys for epoch E'.

### 7A.4 Encoder Flow

```python
# At frame_index where is_rekey_frame AND receiver_public_key available:

# 1. Generate fresh X25519 ephemeral keypair
ephemeral_private = X25519PrivateKey.generate()
ephemeral_public  = ephemeral_private.public_key()

# 2. ECDH with receiver's long-term public key
raw_shared = ephemeral_private.exchange(receiver_public_key)
shared_secret = HKDF(raw_shared, "", "meow_asym_rekey_kem_v1", 32)

# 3. Root rotation with epoch binding
epoch += 1
new_root = HKDF(IKM=shared_secret, salt=old_root_key,
                info="meow_asym_rekey_root_v1" || BE32(epoch), length=32)
new_chain = HKDF(new_root, salt, "meow_asym_rekey_chain_v1", 32)

# 4. Key lifecycle: zeroize old, install new
ZEROIZE(old_root_key, old_chain_key, ephemeral_private)
root_key  = new_root
chain_key = new_chain

# 5. Normal ratchet step from new chain → message_key
message_key, chain_key = ratchet_step(chain_key, salt)

# 6. Embed ephemeral_public (32 bytes) in frame header (same slot as v1.x beacon)
beacon_header = ephemeral_public.raw_bytes()
```

### 7A.5 Decoder Flow

```python
# At frame_index where is_rekey_frame AND receiver_private_key available:

# 1. Extract ephemeral public key from frame header (before chain advancement)
eph_pub = frame_body[:32]
epoch = frame_index // rekey_interval
store_rekey_material(epoch, eph_pub)

# 2. During _advance_to(), at the rekey boundary:
raw_shared = receiver_private_key.exchange(eph_pub)
shared_secret = HKDF(raw_shared, "", "meow_asym_rekey_kem_v1", 32)
new_root = HKDF(IKM=shared_secret, salt=old_root_key,
                info="meow_asym_rekey_root_v1" || BE32(epoch), length=32)
new_chain = HKDF(new_root, salt, "meow_asym_rekey_chain_v1", 32)
ZEROIZE(old_root_key, old_chain_key)

# 3. Ratchet step and decrypt
message_key, chain_key = ratchet_step(new_chain, salt)
plaintext = AES_GCM_decrypt(message_key, ciphertext)
```

### 7A.6 Out-of-Order Handling

Fountain codes may deliver frames out of order. MSR v2.0 handles this:

| Scenario | Behavior |
|----------|----------|
| Frame from current epoch | Normal chain advancement (skip cache for gaps) |
| Rekey frame received | Ephemeral key stored; chain advancement executes rekey at boundary |
| Frame from future epoch (rekey received) | Chain fast-forwards through rekey; post-rekey frames decryptable |
| Frame from future epoch (rekey NOT received) | `ValueError` raised; treated as frame loss by fountain codes |
| Frame from past epoch | Use skip cache (key was cached during prior fast-forward) |

**Key constraint**: Rekey frames MUST be received before frames in their epoch can be decrypted. In GIF mode (in-order), this is automatic. In webcam mode, rekey frames are ~3% of total frames and very likely captured. Missing a rekey frame loses ≤K frames — within the fountain code's ~33% loss tolerance.

### 7A.7 Security Analysis

| Property | Status | Mechanism |
|----------|--------|-----------|
| **Post-compromise security** | ✅ | Root rotation uses ECDH with receiver's long-term key (not in ratchet state) |
| **Forward secrecy** | ✅ | Old root + chain zeroed; HKDF one-wayness prevents recovery |
| **Epoch isolation** | ✅ | Epoch counter bound in HKDF info; cross-epoch replay impossible |
| **Tamper detection** | ✅ | Modified ephemeral key → wrong ECDH → wrong chain → commitment/GCM failure |
| **Replay resistance** | ✅ | Consumed-index tracking + epoch binding in HKDF |
| **Key zeroization** | ✅ | Old root/chain zeroed on rekey; ephemeral private never stored |

**Comparison with Signal:**

| Aspect | Signal | MSR v2.0 |
|--------|--------|----------|
| DH ratchet trigger | Per reply (bidirectional) | Every K frames (unidirectional) |
| PCS healing latency | 1 round-trip | ≤K frames |
| DH target | Receiver's ephemeral key (changes per reply) | Receiver's long-term key (fixed) |
| Root key in state | ✓ (required for rotation) | ✓ (same trade-off) |
| Air-gap compatible | ✗ | ✓ |

The only property weaker than Signal is PCS healing latency: Signal heals on the next message from the other party (1 round-trip); MEOW heals at the next rekey boundary (≤K frames). This is inherent to unidirectional protocols.

### 7A.8 Fallback Behavior

When `receiver_public_key` is not available, MSR v2.0 falls back to the plaintext beacon mode (§7.2 Mode A):
- Random 32-byte beacon mixed into message key
- No root key rotation
- No PCS (memory-only compromise protection)

---

## 8. Signal Double Ratchet Comparison

| Property | Signal Double Ratchet | MEOW MSR v2.0 |
|----------|----------------------|---------------|
| **Symmetric ratchet** | ✓ Per-message | ✓ Per-frame |
| **DH ratchet** | ✓ Per-reply (X3DH → DH) | ✓ Per-epoch via X25519 ECDH (§7A) |
| **Forward secrecy** | ✓ Per-message | ✓ Per-frame |
| **Post-compromise security** | ✓ Via DH ratchet re-keying | ✓ Via asymmetric root rotation (§7A) |
| **PCS healing latency** | 1 round-trip (immediate on reply) | ≤K frames (unidirectional constraint) |
| **Root key rotation** | ✓ Per DH step | ✓ Per epoch (every K frames) |
| **Out-of-order support** | Bounded window (typically ~2000) | Full (fountain code, up to 2000 cached) |
| **Key zeroization** | ✓ | ✓ (Rust backend when available) |
| **Header encryption** | ✓ (double-encrypted header) | ✓ HKDF-XOR mask per frame index (§8.3) |
| **Key commitment** | Implicit (HMAC covers ciphertext) | ✓ HMAC-SHA256 commitment tag (§8.4) |
| **KDF** | HMAC-SHA256 chain | HKDF-SHA256 with 14 domain constants |
| **AEAD** | AES-256-CBC + HMAC-SHA256 | AES-256-GCM + commitment tag |

### 8.1 Asymmetric DH Ratchet Adaptation (MSR v2.0)

The air-gap file transfer protocol is **strictly unidirectional**:
```
Sender ──(GIF/QR → camera)──► Receiver
         └── no back-channel
```

Signal's DH ratchet requires the receiver to send a new public key back to the sender. This is impossible in an air-gap scenario. **MSR v2.0** solves this by using the receiver's **long-term** X25519 public key (already available from MEOW3/4 forward secrecy) as the DH ratchet target:

```
At every K frames (rekey_interval):
  1. Sender generates fresh ephemeral X25519 keypair
  2. ECDH(ephemeral_private, receiver_public) → shared_secret
  3. new_root = HKDF(IKM=shared_secret, salt=old_root, info="meow_asym_rekey_root_v1" || epoch)
  4. new_chain = HKDF(new_root, salt, "meow_asym_rekey_chain_v1")
  5. ZEROIZE(old_root, old_chain, ephemeral_private)
  6. Embed ephemeral_public (32 bytes) in frame header
```

- **If `chain_key[N]` is compromised**: Attacker can derive keys up to the next rekey boundary. After rekey, the new chain depends on a fresh ECDH shared secret, which requires `receiver_private_key` — NOT present in the ratchet state.
- **Healing**: Within ≤K frames of any compromise, the root key rotates with asymmetric entropy, closing the compromise window.
- **Trade-off**: The root key IS stored in the ratchet state (required for rotation). This is the same trade-off Signal makes. The net security gain from PCS outweighs the exposure risk.

### 8.2 What We DO Achieve

Despite lacking a DH ratchet, MSR v1.2 provides:

1. **Backward secrecy**: Compromising `chain_key[N]` reveals nothing about `chain_key[0..N-1]` or any `message_key[0..N-1]`.
2. **Per-frame key isolation**: Each frame uses a unique `(enc_key, nonce, mac_key)` triple.
3. **Key lifetime minimization**: Each key exists in memory only during its frame's encryption/decryption.
4. **Post-session security**: After `finalize()`, zero key material remains in memory.
5. **Post-compromise security (PCS)**: Asymmetric root rotation (§7A) provides Signal-inspired PCS — compromise of `chain_key[N]` and `root_key[epoch_E]` is healed after the next rekey, because `root_key[epoch_E+1]` requires `receiver_private_key`. Not Signal; no equivalence claim.
6. **Header encryption**: Frame indices are XOR-masked with HKDF-derived pseudorandom masks, preventing traffic analysis.
7. **Key commitment**: HMAC-SHA256 commitment tags prevent invisible salamanders attacks against AES-GCM.

### 8.3 Header Encryption (Signal-Inspired)

Signal encrypts message headers so observers cannot determine message ordering. MSR v1.2 achieves a similar goal with HKDF-derived XOR masks (not Signal; no equivalence claim):

```
header_key = HKDF(root_key, salt, "meow_ratchet_header_v1", 32)
mask[i]    = HKDF(header_key, BE32(i), "meow_header_mask_v1", 4)
encrypted_index[i] = frame_index[i] ⊕ mask[i]
```

**Properties**:
- Each frame gets a unique pseudorandom mask (HKDF domain separation)
- Encrypted indices appear random to observers (no sequential pattern)
- Decoder precomputes lookup table: `O(n)` at init, `O(1)` per frame
- Cross-session isolation: different salts → different header keys → different masks

### 8.4 Key Commitment (Invisible Salamanders Defense)

AES-GCM is not key-committing: an adversary can find two keys that both produce valid GCM authentication tags for the same ciphertext, yielding different plaintexts (Grubbs et al., "Message Franking via Committing Authenticated Encryption", 2017).

MSR v1.2 adds a 16-byte commitment tag: `HMAC-SHA256(mac_key, frame_body)[:16]`, where `mac_key` is deterministically derived from `message_key` via domain-separated HKDF.

**Verification order** (fail-closed):
1. Header decryption → look up frame index
2. Replay detection → reject consumed indices
3. Ratchet key derivation → get message key
4. Beacon mixing → enhance key if rekey frame
5. **Key commitment check** → HMAC(mac_key, body) must match tag
6. AES-GCM decryption → decrypt ciphertext with AAD

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
- **With asymmetric rekey (MSR v2.0)**: Compromise window is bounded to ≤K frames. After rekey, the attacker needs `receiver_private_key` (NOT in ratchet state) to derive the new root key. All frames after rekey are unrecoverable by the attacker.

### Scenario: Asymmetric Rekey Healing (MSR v2.0)

**Setup**: Attacker compromises ratchet state (chain_key + root_key) at frame N.

1. **Frames N to next rekey**: Attacker CAN derive message keys (same chain).
2. **At rekey frame (M = ceil(N/K) * K)**:
   - Encoder generates fresh X25519: `eph_priv, eph_pub = X25519.generate()`
   - `shared = ECDH(eph_priv, receiver_public)` — attacker has `root_key` but NOT `receiver_private_key`
   - `new_root = HKDF(shared, salt=root_key, info=... || epoch)` — attacker CANNOT compute this
3. **Frames M+1 onward**: Attacker CANNOT decrypt (new chain is derived from new root).

**PCS guarantee**: Compromise at frame N is healed at frame M ≤ N + K.

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

1. ~~**Header encryption**~~: **DONE (v1.2, §8.3)** — Frame indices XOR-masked with HKDF-derived pseudorandom masks, preventing traffic analysis.

2. ~~**Key commitment**~~: **DONE (v1.2, §8.4)** — HMAC-SHA256 commitment tags prevent invisible salamanders attacks against AES-GCM.

3. ~~**Constant-time index lookup**~~: **DONE (v1.2)** — Decoder precomputes encrypted-index lookup table during init; O(1) lookup per frame.

4. **Ephemeral ratchet salt**: Derive a unique salt for the ratchet (separate from the manifest salt) to provide additional domain separation from the main encryption pipeline.

5. **Ratchet version negotiation**: Include ratchet version in manifest to support future ratchet protocol upgrades (MSR v2, etc.).

6. **Formal verification**: Model the ratchet state machine in ProVerif or Tamarin to prove forward secrecy and beacon PCS properties formally.

7. **Adaptive beacon interval**: Dynamically adjust `rekey_interval` based on frame count / threat posture.

---

## 12. Test Coverage

Comprehensive tests in `tests/test_ratchet.py` (142 tests) and `tests/test_asymmetric_rekey.py` (43 tests):

| Test Class | What It Verifies |
|-----------|------------------|
| `TestDomainSeparation` | All 14 HKDF info constants are unique and well-formed |
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
| **`TestMeowAliases`** | **Cat-themed API (opt-in via `MEOW_CAT_API=1`): PawState, WhiskerKeys, bury_in_litter, knead_subkey, prime_cat** |
| **`TestHeaderEncryption`** | **HKDF-XOR mask uniqueness, encryption/decryption roundtrip, observer indistinguishability** |
| **`TestKeyCommitment`** | **HMAC-SHA256 commitment determinism, wrong-key rejection, truncation to 128 bits** |
| **`TestSignalParityHardening`** | **Full encoder/decoder roundtrip with header encryption + key commitment, tamper detection** |
| **`TestAsymmetricRekeyPrimitives`** | **ECDH roundtrip, ephemeral uniqueness, wrong-key detection, epoch binding, output lengths** |
| **`TestRatchetStateV2`** | **root_key storage, zeroization, ratchet_step preservation, backward compat** |
| **`TestAsymmetricRekeyRoundtrip`** | **Full encoder/decoder roundtrip across multiple epochs with root rotation** |
| **`TestPostCompromiseSecurity`** | **PCS verification: compromised state cannot decrypt post-rekey frames; chain independence** |
| **`TestForwardSecrecyV2`** | **Old chain_key zeroization, old root_key zeroization on rekey** |
| **`TestOutOfOrderDecoding`** | **Epoch-aware OOO: in-order, within-epoch shuffle, rekey-first, missing-rekey rejection** |
| **`TestRollbackResistance`** | **Epoch binding prevents cross-epoch reuse; old root cannot derive future chains** |
| **`TestPlaintextBeaconFallback`** | **Roundtrip without receiver key; no root rotation verification** |
| **`TestSignalComparison`** | **Root rotation assertion, chain isolation, PCS healing latency bound** |
| **`TestEdgeCases`** | **Boundary: interval=total, interval=1, disabled, large epoch count, single frame** |
| **`TestTamperDetectionV2`** | **Modified ephemeral key rejected, replay rejected** |

---

## 13. References

- [Signal Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869)
- [RFC 5116: An Interface and Algorithms for Authenticated Encryption](https://tools.ietf.org/html/rfc5116)
- [Luby Transform Codes (Fountain Codes)](https://en.wikipedia.org/wiki/Luby_transform_code)
- [ARCHITECTURE.md](ARCHITECTURE.md): Full meow-decoder data flow
- [THREAT_MODEL.md](THREAT_MODEL.md): Attack surface analysis
