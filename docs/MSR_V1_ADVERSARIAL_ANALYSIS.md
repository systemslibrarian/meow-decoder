# MSR v1.2 Adversarial Break Attempt Analysis

**Date**: 2026-02-16  
**Protocol**: MEOW Symmetric Ratchet v1.2  
**Methodology**: Red-team analysis from the perspective of a nation-state adversary with temporary device compromise and partial memory extraction capabilities.

> **v1.2 Hardening Note**: This version adds header encryption (HKDF-XOR masks on frame indices), key commitment (HMAC-SHA256 tags preventing invisible salamanders attacks), and constant-time index lookup (precomputed table). These mitigate Attacks 8, 11, and 12 below.

---

## Adversary Model

**Capabilities**:
- Full passive capture of the encoded GIF (all QR frames)
- Temporary read-only access to encoder/decoder memory during an active session
- Unlimited offline computation (no constraint on hash inversions beyond computational infeasibility)
- Knowledge of the protocol specification (Kerckhoffs's principle)

**Constraints**:
- No write access to device memory (cannot inject or modify keys)
- No knowledge of the password
- No persistent implant (access is temporary, e.g., cold boot attack during encoding)

---

## Attack 1: Chain Key Extraction (Memory Snapshot)

**Scenario**: Adversary snapshots encoder memory during frame N encryption.

**Extracted material**:
| Key | Status at snapshot time |
|-----|----------------------|
| `chain_key[0..N-1]` | Already zeroized ❌ |
| `chain_key[N]` | Being consumed, partially zeroized ⚠️ (race condition) |
| `chain_key[N+1]` | Just derived, in memory ✅ |
| `message_key[N]` | In memory (about to be consumed) ✅ |
| `root_key` | NOT stored in ratchet state ❌ |

**Damage assessment**:
- **Frames 0..N-1**: SAFE. Keys are irrecoverable (HKDF one-wayness). Even with unlimited computation, inverting `HKDF-SHA256(ck[N-1], salt, info) → ck[N]` is infeasible.
- **Frame N**: COMPROMISED. `message_key[N]` is in memory.
- **Frames N+1..end**: COMPROMISED. `chain_key[N+1]` allows derivation of all subsequent keys: `ck[N+2] = HKDF(ck[N+1], salt, step_info)`, etc.

**Verdict**: Forward secrecy holds for frames 0..N-1. No backward secrecy for frames N+1..end (inherent limitation of all unidirectional symmetric ratchets, including Signal's sending chain when the DH ratchet hasn't been triggered).

**Rating**: **Working as designed**. The ratchet's security claim is forward secrecy, not post-compromise security. The limitation is documented in the protocol spec.

---

## Attack 2: HKDF Collision / Preimage

**Goal**: Find `x` such that `HKDF(x, salt, "meow_ratchet_step_v1") = chain_key[N]`, thereby recovering `chain_key[N-1]`.

**Analysis**: This requires a preimage attack on HKDF-SHA256. The best known attack against HMAC-SHA256 (the core of HKDF) is brute force over the 256-bit key space: $2^{256}$ operations. This is computationally infeasible for any adversary, including nation-states.

**Verdict**: **Not viable.** HKDF-SHA256 preimage resistance is the foundation of the protocol's forward secrecy guarantee.

---

## Attack 3: Domain Separation Bypass

**Goal**: Exploit a relationship between keys derived with different `info` parameters from the same input.

**Analysis**: HKDF guarantees independence of outputs for different `info` strings (this is the "expand" step's purpose). Given:
```
ck[1] = HKDF(ck[0], salt, "meow_ratchet_step_v1")
mk[0] = HKDF(ck[0], salt, "meow_ratchet_msg_v1")
```

Knowing `ck[1]` reveals nothing about `mk[0]` and vice versa. The six domain separation constants are all unique (verified in tests), so there is no "collision" between derivation paths.

**Verdict**: **Not viable.** Domain separation prevents cross-derivation attacks.

---

## Attack 4: AAD Manipulation (Frame Reordering)

**Goal**: Reorder frames to trick the decoder into accepting frames in the wrong position.

**Analysis**: Each frame's AAD includes its `frame_index`:
```
AAD = "MEOW_RATCHET_V1" || frame_index(4 LE) || k_blocks(2 LE) || block_size(2 LE) || total_frames(4 LE) || salt(16)
```

If an attacker changes the frame_index in the 4-byte header, the AAD computed by the decoder won't match the AAD used during encryption, causing AES-GCM authentication to fail.

If an attacker reorders frames without modifying them, the frame_index in the header won't match the `expected_index` parameter in `decrypt_frame()`, which raises `ValueError` (for direct calls). For `DecoderRatchet.decrypt()`, the decoder uses the frame_index from the header to select the correct key, and the AAD authenticates this binding, so reordering is detected.

**Verdict**: **Not viable.** Frame index binding in AAD prevents reordering attacks.

---

## Attack 5: Cross-Session Replay

**Goal**: Replay frames from a previous session into a new session.

**Analysis**: The `salt` is included in both the AAD and the HKDF derivation chain. Different sessions use different salts (16 bytes of randomness from `secrets.token_bytes(16)`). Therefore:
- `chain_key[0](session_A) ≠ chain_key[0](session_B)` (different salt in HKDF)
- `AAD(session_A) ≠ AAD(session_B)` (different salt in AAD)

Replaying a frame from session A into session B will fail AES-GCM authentication because:
1. The decoder's ratchet chain produces different keys (wrong salt in HKDF)
2. Even if keys somehow matched, the AAD wouldn't match (wrong salt in AAD)

**Verdict**: **Not viable.** Session salt provides replay isolation.

---

## Attack 6: Skip Cache Poisoning (DoS)

**Goal**: Exhaust the decoder's skip key cache to cause denial of service.

**Scenario**: Attacker injects a single frame with a very high frame_index (e.g., 999999), forcing the decoder to fast-forward and cache ~999999 keys.

**Analysis**: The decoder enforces `MAX_SKIP_KEYS = 2000`:
```python
if len(self._skipped_keys) + skip_count > MAX_SKIP_KEYS:
    raise ValueError("Too many skipped keys ...")
```

Any frame index that would require caching more than 2000 keys is rejected immediately. Memory consumption is bounded at `2000 × 32 bytes = 64 KB`.

However, this means a legitimate session with more than 2000 frames received wildly out of order could fail. In practice, fountain codes deliver frames in approximately sequential order with some jitter, so this bound is unlikely to be hit.

**Mitigation**: The bound could be made configurable, but 2000 is conservative for the expected use case (GIF with ~15-100 frames).

**Verdict**: **Mitigated.** DoS is bounded. Legitimate sessions with reasonable frame counts are unaffected.

---

## Attack 7: Manifest Frame Compromise

**Goal**: Since frame 0 (manifest) is not ratchet-encrypted, extract information from it.

**Analysis**: The manifest is already encrypted with AES-256-GCM using the main encryption key (from Argon2id/X25519/PQ). It is also HMAC-authenticated. The ratchet exempts frame 0 because:
- The decoder needs the manifest to learn `salt`, `k_blocks`, etc. required to initialize the ratchet
- The manifest doesn't contain payload data — only encoding metadata

The security of frame 0 is unchanged from the pre-ratchet protocol. It relies on the main encryption layer's guarantees (AES-256-GCM + HMAC-SHA256 + Argon2id KDF).

**Verdict**: **Not a regression.** Manifest security is handled by the existing crypto layer.

---

## Attack 8: Timing Side Channel on Skip Cache Lookup

**Goal**: Determine whether a specific frame index has been previously received by measuring decoder response time.

**Analysis**: ~~The decoder's skip cache uses a Python `dict`~~ **v1.2 mitigated**: The decoder now precomputes a full encrypted-index→real-index lookup table during initialization. Frame index lookup is a constant-time dict hit on the encrypted index. The plaintext frame index is never directly exposed in the lookup path.

Additionally, with header encryption, the frame indices in the wire format are pseudorandom XOR-masked values, not sequential integers. An observer cannot correlate encrypted indices to frame positions without the header key.

**Verdict**: **Mitigated (v1.2)**. Header encryption + precomputed lookup table eliminates practical timing side channels.

---

## Attack 9: GCM Nonce Reuse

**Goal**: Find two frames that use the same (key, nonce) pair, enabling GCM key-stream recovery.

**Analysis**: Each frame derives its nonce via:
```
nonce = HKDF(message_key[i], salt, "meow_ratchet_frame_nonce_v1", 12)
```

Since each `message_key[i]` is unique (derived from a unique `chain_key[i]` with unique position), each nonce is unique. The only way to get a nonce collision is if two different `message_key` values hash to the same nonce under HKDF — a 96-bit collision. Birthday bound: $\sqrt{2^{96}} = 2^{48}$, meaning ~281 trillion frames before expecting a collision. With typical file transfers having <1000 frames, this is not a concern.

**Verdict**: **Not viable.** Nonce uniqueness is guaranteed by message key uniqueness.

---

## Attack 10: Root Key Recovery from chain_key[0]

**Goal**: Given `chain_key[0] = HKDF(root_key, salt, "meow_ratchet_root_v1")`, recover `root_key`.

**Analysis**: This is a preimage attack on HKDF-SHA256 with a 256-bit input. Infeasible (see Attack 2).

Even if `chain_key[0]` were stolen, the `root_key` is also used for the main AES-256-GCM encryption layer. Compromising the ratchet's initial state does NOT compromise the root key or the main encryption.

**Verdict**: **Not viable.** HKDF preimage resistance + domain separation.

---

## Summary Matrix

| Attack | Target | Viable? | Forward Secrecy Impact |
|--------|--------|---------|----------------------|
| 1. Memory snapshot | chain_key[N+1] | By design (limitation) | Frames 0..N-1 protected |
| 2. HKDF preimage | chain_key[N-1] | No ($2^{256}$) | N/A |
| 3. Domain separation bypass | Cross-path key | No | N/A |
| 4. AAD manipulation | Frame reordering | No | N/A |
| 5. Cross-session replay | Session isolation | No | N/A |
| 6. Skip cache DoS | Memory exhaustion | Mitigated (bounded) | N/A |
| 7. Manifest compromise | Frame 0 | Not a regression | N/A |
| 8. Timing side channel | Cache membership | Mitigated (v1.2: header enc + precomputed table) | N/A |
| 9. GCM nonce reuse | Key-stream recovery | No ($2^{48}$ frames) | N/A |
| 10. Root key recovery | Main encryption | No ($2^{256}$) | N/A |

### v1.2 Hardening Summary

| Feature | Attack Mitigated | Mechanism |
|---------|-----------------|----------|
| Header encryption | Traffic analysis, timing | HKDF-XOR mask per frame index |
| Key commitment | Invisible salamanders (multi-key decryption) | HMAC-SHA256 commitment tag (16 bytes) |
| Precomputed lookup | Timing side channel on skip cache | O(N) init, O(1) per-frame |

**Overall assessment**: MSR v1.2 achieves its stated security goals, with three additional Signal-parity hardening features. The only "attack" that succeeds (memory snapshot) is an inherent limitation of unidirectional protocols, honestly documented in the protocol specification. Forward secrecy for past frames is maintained under all analyzed attack scenarios. Header encryption prevents traffic analysis, and key commitment prevents multi-key attacks against AES-GCM.
