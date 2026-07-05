# Fable Bug Hunt — Results

**Adversarial security + correctness audit of the meow-decoder crypto core.**

| | |
|---|---|
| Date | 2026-07-05 |
| Model | Claude Fable 5 (finders, skeptics, and synthesis) |
| Method | 12 parallel subsystem "finder" agents → independent adversarial "skeptic" verifier per finding (defaults to *not-a-bug*, must confirm against real code) → dedupe + rank |
| Agents run | 59 |
| Subagent tokens | ~1.85M |
| Confirmed findings | 34 (deduplicated to 28 distinct issues) |

## Remediation status (all findings addressed)

All 28 findings were fixed in the branch that adds this document. Rust crates
(`crypto_core` native/pq/wasm, `rust_crypto`) build clean and all Rust tests
pass; the Python suite is green except pre-existing Windows-only environmental
failures (missing `pyzbar`/`libzbar` QR DLL, cp1252 codec on emoji, Unix-only
`resource` module). On-disk/wire formats were changed backward-compatibly
(old artifacts still decode; new at-rest formats bump their magic — MRCV3,
`MEOW_X25519\x03`).

Both formerly-partial items are now **fully implemented and tested** (see
`tests/test_fable_bug_hunt_poc.py`):
- **L8** — the signer's in-band public key is now bound to the password-derived
  key material. The encoder MACs `compute_public_key_commitment(pk)` (previously
  dead code) with a key derived from the same handle that frame-MACs the
  signature-chunk transport and appends the 32-byte tag to the signature blob;
  the decoder recomputes it over the transported pk and rejects a mismatch
  (fail-closed). The tag is detected purely by blob length, so there is **no
  signature/manifest format-version break** — old artifacts carry no tag and old
  decoders ignore it. (Literal binding into the manifest HMAC is infeasible
  because the signing pubkey is not available at manifest-HMAC-check time on
  decode; this frame-key-bound tag achieves the same key-substitution resistance
  and is verified independently of the frame-MAC transport.)
- **M4** — `decode_gif` now **fails closed by default** on the legacy fast-SHA-256
  frame-MAC KDF: if the modern (Argon2id-derived) frame MAC fails, the legacy
  fallback is refused unless the caller passes the existing `--allow-legacy`
  opt-in, which then decodes pre-v2 files with a loud warning.

## How to read this

Every finding below survived a second, independent agent whose job was to **refute** it by re-reading the cited code and its guards. "Verified" means two independent reads of the actual source agree the bug is triggerable — **not** that an exploit was executed. Severities are the skeptic's *corrected* rating (finders' initial guesses were often downgraded). PoC tests that actually trigger the top findings are tracked separately (see "Proof-of-concept status" at the end).

## Coverage & caveats

- **One subsystem did not complete.** The `py-stego-shamir` finder (targeting `stego_multilayer.py`, `stego_advanced.py`, `schrodinger_encode.py`, `shamir_split.py`, `high_security.py`) **failed with a Fable content-safety error** and returned no findings. That surface is **not covered** by this report and should be re-run (e.g. on a different model) for completeness. Note the Schrödinger *decode* path is still covered (H1 below).
- **One fix was already applied during the hunt.** Finding **L13** was fixed in the working tree by a verifier agent (`meow_decoder/ratchet.py`, drop the orphaned cached handle); `tests/test_ratchet.py` passed (144 passed, 4 skipped) and the leak repro went to 0. Review that diff before committing.
- Working tree also contains a pre-existing comment-only edit to `crypto_core/src/meow_fountain/wire.rs` and the unrelated `web_demo/templates/cat_mode.html` fullscreen change — neither is part of this audit.

---

# Prioritised Findings

34 confirmed findings deduplicated to 28 distinct issues (merges noted inline). Ordered by severity; subsystem tagged on each item.

---

## CRITICAL

### C1. `--high-security` with no receiver keys produces an undecodable artifact, then securely wipes the source `[py-fountain-encode]`
**`meow_decoder/encode.py:127-145,169,254-258,292-309` (wipe: 1416-1419, 1848-1873)**
- **Impact/trigger:** `encode_file()` selects MEOW4/MEOW5 mode whenever `use_pq=True` regardless of key presence. With no receiver key the PQ/FS encapsulation is skipped (only a verbose-gated warning), so `pack_manifest()` serializes a PQ-mode manifest with `ephemeral_public_key=None`/`pq_ciphertext=None`. `unpack_manifest()` (crypto.py:1704-1714) hard-rejects exactly this shape, so the file is permanently undecodable. `--high-security` auto-sets `pq=True` + `wipe_source=True`, so encode "succeeds" and then securely wipes the only plaintext copy. Reproduced empirically (mode_byte=0x05, decode raises "PQ ciphertext is missing").
- **Fix:** Only select MEOW4/5 when `use_pq` AND `receiver_public_key` AND `receiver_pq_public` are all present (mirror the FS branch); otherwise hard-error (fail-closed). Add mode/field consistency validation in `pack_manifest` and make the downgrade warning unconditional.

---

## HIGH

### H1. `FountainDecoder::new` performs unbounded allocation on attacker-controlled `k_blocks` (OOM DoS) `[rust-fountain / rust-stego / py-decode]`
**`crypto_core/src/meow_fountain/decoder.rs:43-51` (`vec![None; k_blocks]` at line 47)** — merges findings for the same root cause reached via three paths.
- **Impact/trigger:** `FountainDecoder::new(k_blocks, block_size)` allocates with zero validation, while the encoder (encoder.rs:81-90) enforces `k_blocks > 0`, `<= u16::MAX`, and a 10 GiB ceiling. Reachability:
  - **Remote DoS (HIGH):** `schrodinger_decode_file()` (schrodinger_decode.py:382) passes `manifest.block_count`/`block_size` (unauthenticated 4-byte fields, `SchrodingerManifest.unpack()` does no bounds check) straight to the decoder *before* the password check. `block_count≈4.29e9` → ~100 GB alloc. The frame-0 MAC gate does not stop this: v0x07 skips MAC, v0x08 derives the key from the *public* `frame_mac_seed` in the manifest, so an attacker forges a valid frame-0 MAC.
  - **Client self-DoS (MEDIUM):** browser QR path (`wasm.rs:1514-1519`, `webcam.html:352-366`) parses `k`/`block_size` from a scanned `FOUNTAIN:` string and constructs the decoder pre-auth, crashing the victim's own scan tab.
- **Fix:** Make `FountainDecoder::new` return `Result` and reject `k_blocks==0`/`block_size==0`, `k_blocks > u16::MAX`, and `k_blocks*block_size > MAX_TOTAL_SIZE`. Validate in `SchrodingerManifest.unpack()` (cap against crypto.py's `MAX_K_BLOCKS`=1M / `MAX_BLOCK_SIZE`=65535) and clamp the browser-parsed values. Allocate `blocks` lazily.

### H2. Master ratchet state file sealed under unsalted, unstretched password KEK — cheap offline brute force `[py-ratchet]`
**`meow_decoder/master_ratchet.py:247-258`**
- **Impact/trigger:** `_derive_state_key_handle()` derives the at-rest KEK as a single `HKDF-SHA256(password, salt=b"", DOMAIN_STATE_KEY)`. Empty salt + fixed info → one precomputed table works against every user; GCM tag verification is a per-guess oracle at ~1 HKDF+1 GCM open. The in-code justification ("KDF cost lives in chain init") is wrong — `from_password()` also uses plain HKDF, and chain-init entropy never gates the state-file unseal. `master_salt` is already in the file header and could have salted it.
- **Fix:** Derive the KEK via Argon2id(password, master_salt) then HKDF-expand with `DOMAIN_STATE_KEY`; bump magic to MRCV3 to reject old files.

---

## MEDIUM

### M1. Hybrid-PQ / forward-secrecy WASM paths leave shared secrets, ephemeral keys, IKM and derived AES keys un-zeroized in WASM linear memory `[rust-pq]`
**`crypto_core/src/wasm.rs:473-506, 595-608, 851-908, 1000, 1043-1058`**
- **Impact/trigger:** `encrypt/decrypt_hybrid_pq` and `encrypt/decrypt_with_forward_secrecy` build heap/stack copies dropped without wiping: X25519 ephemeral secret Vec (+`.clone()` at 861), `ikm` = shared||shared||password, the `key_bytes` AES key returned by `hkdf_derive` (only copied into the ZeroizeOnDrop `SecretKey`), and `x25519_secret_arr` holding the long-term recipient secret. Violates the documented CRYPTO-002 property that the native `handles.rs` path honors. Any same-origin script (XSS) can read persistent key material/passwords from un-scrubbed WASM memory.
- **Fix:** Wrap `ikm`/`key_bytes` in `Zeroizing<Vec<u8>>`, zeroize the ephemeral-secret Vec and stack arrays after `StaticSecret` construction, and avoid the `.clone()` (use `try_into` on the original). Same pattern in all four functions.

### M2. X25519 DH lacks all-zero (low-order point) shared-secret rejection in pure_crypto/wasm, inconsistent with `handles.rs` `[rust-pq]`
**`crypto_core/src/pure_crypto.rs:525-533` (also `wasm.rs:439,490,592,867,1003`)**
- **Impact/trigger:** `diffie_hellman` returns `shared.to_bytes()` with no non-zero check; all five wasm DH sites likewise. `rust_crypto/src/handles.rs:142-145` and `pure.rs:363-371` do reject it. In `decrypt_with_forward_secrecy` the attacker fully controls the embedded ephemeral public key; a low-order point forces `shared=0^32`, so key = HKDF(0^32 || password), independent of the recipient's private key (universal cross-recipient blob). Violates RFC 7748 §6.1.
- **Fix:** After every `diffie_hellman`, fail if the secret is all-zero (`SharedSecret::was_contributory()`), mirroring `handles.rs`.

### M3. Stream chunk MAC does not bind byte offset or chunk index — reordered/replayed chunks carry valid MACs `[rust-ffi-handles]`
**`rust_crypto/src/handles.rs:791-866` (MAC input at 813-816 / 839-842)**
- **Impact/trigger:** Per-chunk MAC is `HMAC(mac_key, nonce || ciphertext)` using the same static 16-byte nonce for every chunk, with no offset/index/length framing. `handle_stream_decrypt` verifies this position-independent MAC then decrypts at its own advancing offset, so any `(ciphertext, tag)` pair is valid at *any* position — enabling reorder, replay, and truncation of the stream while passing all MAC checks. (Exported to Python; no current non-test caller, but a misdesigned primitive.)
- **Fix:** Include pre-encryption `byte_offset` (+ monotonic chunk counter + final-chunk flag) in the MAC input and compute it over the receiver's own tracked offset on decrypt.

### M4. Legacy frame-MAC key derivation is a fast SHA-256 password KDF — offline password oracle for legacy files `[py-crypto]`
**`meow_decoder/frame_mac.py:111-118` (reached via `decode_gif.py:596`)**
- **Impact/trigger:** `derive_frame_master_key_legacy` = single `SHA-256(password+salt+b"frame_mac_key")`. The decoder auto-falls back to this when the modern HKDF-from-Argon2id frame MAC fails. Frame MACs are public (8-byte tag prepended to every frame; salt in the public manifest), so capturing one legacy frame gives a fully offline password oracle at ~µs/guess, defeating Argon2id for legacy files.
- **Fix:** Derive the legacy frame key from the Argon2id-derived encryption key (HKDF), not the bare password; or gate the fallback behind `--allow-legacy-frame-mac`; preferably deprecate/remove and treat pre-v2 frame MACs as unverifiable.

### M5. No encode-side cap on `k_blocks`: inputs > `block_size*65535` crash with `struct.error` deep into encoding `[py-fountain-encode]`
**`meow_decoder/encode.py:275` (also `fountain.py:199-207, 240-249, 478-484`)**
- **Impact/trigger:** Droplet indices are packed as u16 but `k_blocks` is unbounded at encode. The Rust encoder's `KBlocksOverflowU16` guard is caught and *silently* swallowed (fountain.py:201-205), falling back to the pure-Python encoder which emits index >65535; `pack_droplet` then raises `struct.error` at ~frame 65536 (k_blocks ≥ 65537), after Argon2 and ~65k QR generations. Availability/usability only.
- **Fix:** Raise a clear error right after computing `k_blocks` when `> 65535` (tell user to raise `--block-size`); narrow the `except` so shape errors propagate; validate `idx <= 0xFFFF` in `pack_droplet`.

### M6. Steganography / logo-eyes failures silently fall back to plain visible QR codes; void mode suppresses even the warning `[py-fountain-encode]`
**`meow_decoder/encode.py:632-635, 751-754` (void: 1464-1468)**
- **Impact/trigger:** Both concealment paths use bare `except Exception:` and continue with plain QR frames, printing the notice only `if verbose`. "void" mode forces `stego_level=4` AND `verbose=False`, so a stego failure (e.g. PSNR < 35 dB threshold, PIL error) yields a GIF of trivially-detectable plain QR codes while the CLI reports success — silently dropping the advertised "maximum paranoid stealth" property.
- **Fix:** Fail closed (re-raise / non-zero exit) when a requested stego level cannot be applied; never gate the degradation notice behind verbose.

### M7. X25519 receiver private key encrypted at rest with plain single HKDF; empty password silently stores plaintext `[py-ratchet]`
**`meow_decoder/x25519_forward_secrecy.py:348-366, 399-406`**
- **Impact/trigger:** Storage key = one `HKDF-SHA256(password, salt, b"meow_x25519_key_storage_v2")` — no memory-hard stretching, so the stolen `receiver_private.pem` is brute-forceable at HKDF speed (GCM as oracle). Also `if password:` treats "" as no password, so pressing Enter twice writes a PLAINTEXT long-term private key while the CLI prints "Private key is encrypted with your password." (same unguarded prompt at encode.py:1336-1352).
- **Fix:** Use Argon2id(password, salt) for the storage key; refuse empty passwords (or use a distinct magic + accurate warning).

### M8. OQS fallback ML-KEM decapsulation sets nonexistent `_secret_key` — decapsulation always fails on liboqs-only installs `[py-ratchet]`
**`meow_decoder/pq_ratchet_beacon.py:174-178`**
- **Impact/trigger:** `kem._secret_key = sk; kem.decap_secret(ct)` — liboqs-python stores the key in `self.secret_key` (set only via constructor); `decap_secret` reads that, so it raises `AttributeError`. liboqs is the only declared PQ dependency, so OQS-only installs can encode but never decode (fail-closed crash at every rekey boundary, ratchet.py:1391/1726).
- **Fix:** `with oqs.KeyEncapsulation("Kyber1024", secret_key=sk) as kem: return kem.decap_secret(ct)`; add an OQS-backend round-trip test.

---

## LOW

### L1. Derived key material and combined hybrid shared secrets not zeroized in `pure_crypto` `[rust-pq]`
**`crypto_core/src/pure_crypto.rs:479-486, 911-923`** — merges the two overlapping `hybrid_key_derive` findings.
- **Impact:** `hkdf_derive_key` drops the plain `output` Vec after copying into `SecretKey`; `hybrid_key_derive` drops the 64-byte `combined` (x25519||mlkem) IKM unwiped — the IKM fully determines the returned key. Related same-module gaps: `mldsa65_keygen` seed stack copy (726-737), `backend::decapsulate` `dk_array` (694-699), `generate_keypair` expanded-bytes (664). Contradicts CRYPTO-002; `tpm.rs:681-694`/`yubikey_piv.rs:599` do zeroize the analogous IKM. Requires local memory disclosure.
- **Fix:** `output.zeroize()` after `SecretKey::from_bytes`; wrap `combined` in `Zeroizing`; zeroize `seed_bytes`/`dk_array`/expanded intermediates.

### L2. Password folded into plain HKDF-SHA256 (no memory-hard KDF) in wasm hybrid-PQ / FS encryption `[rust-pq]`
**`crypto_core/src/wasm.rs:497, 599, 898, 1048`**
- **Impact:** `ikm = shared_secret(s) || password` fed to HKDF; each guess ≈ 2 SHA-256 compressions. The same module uses Argon2id for `encode_data` (1208), and the archived Python predecessor Argon2id-stretched the password. Only matters if the recipient's keys are already compromised; callers are demo/example code.
- **Fix:** Pre-stretch the password with `argon2_derive` (salt in blob header) and feed the Argon2 output into the HKDF IKM.

### L3. Handle HKDF functions and PQXDH PRK copy secrets to un-zeroized heap/stack, violating the module's stated invariant `[rust-ffi-handles]`
**`rust_crypto/src/handles.rs:303-309, 398-404, 1000-1004, 1033-1037, 1068-1078, 1425, 1502`** — merges the standalone PQXDH-PRK finding.
- **Impact:** Header claims "All secret material is zeroized on drop," yet `ikm_bytes`/`salt_bytes`/`prk_bytes` in five HKDF helpers, and the PQXDH `prk` (extract output, key-equivalent to the session key), are dropped unwiped — despite `handle_pqxdh_*`'s own docstring (1388-1390) claiming the PRK is zeroized, and adjacent `combined_ikm`/`okm` being wiped. `handle_mix_hkdf:974` proves it's an oversight. Also: `lib.rs:1276,1305` "No secret bytes cross FFI" is inaccurate (`pq_shared_secret: Option<&[u8]>` transits Python). Reachable via ratchet/PQXDH production Python. Requires memory-dump access.
- **Fix:** Bind as `let mut …; .zeroize()` on all paths (or `Zeroizing<Vec<u8>>`); `let mut prk = mac.finalize().into_bytes(); … prk.zeroize()`; correct/implement the FFI docstrings.

### L4. `SecureBox<Vec<u8>>`/heap-indirect `T` silently bypasses all mlock/guard/DONTDUMP protections `[rust-memory]`
**`crypto_core/src/secure_alloc.rs:3-38, 111, 186-188, 314-318`**
- **Impact:** Only `size_of::<T>()` bytes go in the protected region; for `Vec<u8>` that's the 24-byte header, and the secret bytes live in ordinary swappable/dumpable/unguarded heap — yet docs, Drop comments, and the fuzz target present `Vec<u8>` as supported. Latent API hazard; all in-repo callers use `[u8; N]` (fully protected), no production crypto path uses `SecureBox`.
- **Fix:** Constrain the API (e.g. `T: Zeroize + Copy`, or a `SecureBytes` type allocating its buffer inside the mmap region); at minimum add a loud warning + debug assertion and fix the misleading comments/fuzz target.

### L5. `SecureBox` unsound for over-aligned `T`: page-aligned data pointer → UB when `align_of::<T>() > page_size` `[rust-memory]`
**`crypto_core/src/secure_alloc.rs:148, 186-191` (unix); `262, 292-297` (windows)**
- **Impact:** Layout math uses only `size_of`, never `align_of`; `data_ptr` is only page-aligned, so `ptr::write`, `NonNull::as_ref/as_mut`, and `drop_in_place` on a `#[repr(align(16384))]` `T` are UB. Safe public constructor, so safe code can trigger UB; no accidental trigger in crypto usage (all callers use align-1 arrays).
- **Fix:** Fail closed: `if align_of::<T>() > page_size { return Err(...) }` in both constructors.

### L6. Verus GB-002 "GuardedBuffer Safety" theorem is weaker than the documented guarantee — intra-page overflows never fault `[rust-memory]`
**`crypto_core/src/verus_guarded_buffer.rs:241-273, 461-503` (docs 30-33)**
- **Impact:** GB-002's postcondition is `in_upper_guard(...) || in_data_region(...)`; for any overflow index in `[data_size, data_region_size)` (page padding, up to page_size-1 bytes for a 32-byte key) the access lands in R/W pages and does NOT fault. The guard-page clause only holds when `data_size == data_region_size`, false for every real key size. The "no silent data corruption" prose and the "index >= data_size lands in PROT_NONE guard" registry entry (674-679) are unproved/false. Only matters to `unsafe` callers and to consumers of the "formally verified" claim.
- **Fix:** Correct specs/docs to the true page-granular guarantee (faults at offsets ≥ `data_region_size` and < 0); fix the GB-002 registry description and reword/strengthen the theorem.

### L7. `palette_encode`/`palette_decode` integer & shift overflow for ≥21 permutable entries `[rust-stego]`
**`rust_crypto/src/stego.rs:827-831, 894-903, 914-917`**
- **Impact:** Lehmer-code index packed in a single u64, but `factorial_bits(n) > 64` for n≥21. `1u64 << i` / `number >> i` with i≥64 and `multiplier *= n` overflow: debug panic (process abort, `panic="abort"`) / release silent masking/wrap. Exported public API + PyO3, but the production pipeline never calls `palette_decode` (tertiary channel is an unimplemented stub), so no attacker-reachable path today.
- **Fix:** Cap `max_bits = factorial_bits(n).min(63)`; use `checked_mul`; guard all shifts with `i < 64` (or use u128/bignum).

### L8. "Mandatory" manifest signature is self-signed with an in-band ephemeral key — no sender authenticity; INV-041 unimplemented; signing keys never zeroized `[py-fountain-encode / py-decode / py-pq-manifest]`
**`encode.py:377-399`; `decode_gif.py:793-803`; `manifest_signing.py:128-151, 438-451`** — merges the three overlapping self-signed-manifest findings.
- **Impact:** A fresh Ed25519+ML-DSA-65 keypair is generated per encode and its public key embedded in the same artifact; the decoder verifies against that in-band key with no pinning/trust anchor. Anyone who can rewrite the artifact can re-sign a tampered manifest with their own key and pass verification, yet the code treats the signature as "mandatory tamper protection" (fail-closed both sides). The documented mitigation `compute_public_key_commitment` (INV-041) is dead code (tests/fuzz only). Also `SigningKeyPair` stores secret keys as plain bytes and `_keypair` is never wiped. Bounded because the password-keyed manifest HMAC independently authenticates before the signature check.
- **Fix:** Bind `compute_public_key_commitment(public_key)` into the HMAC-covered manifest core and constant-time-compare on decode; or pin the signer out-of-band (`--expected-signer-fingerprint`). Best-effort zeroize the private key after signing.

### L9. `MEOW_MANIFEST_SIGNING=off` production gate is bypassable by the same env-var attacker it claims to stop `[py-fountain-encode]`
**`meow_decoder/encode.py:339-351`**
- **Impact:** Production/test mode is itself derived from env vars, so `MEOW_MANIFEST_SIGNING=off MEOW_TEST_MODE=1` (or `MEOW_PRODUCTION_MODE=0`) disables signing with only a stderr warning — the guard adds nothing against its stated env-var threat model. Bounded (loud, needs env control on both ends, ephemeral in-band signing key adds little anyway).
- **Fix:** Don't derive override permission from other env vars — require a CLI flag, or always warn + record the downgrade in the artifact.

### L10. Interactive password confirmation crashes with `TypeError` for non-ASCII passwords `[py-fountain-encode]`
**`meow_decoder/encode.py:1605`**
- **Impact:** `secrets.compare_digest(password, password_confirm)` on `str` raises `TypeError: comparing strings with non-ASCII characters is not supported` for any non-ASCII password (e.g. "pässwört"), aborting the CLI with a traceback. Workaround: `--password` flag. No security impact.
- **Fix:** Compare UTF-8 encodings (`.encode('utf-8')`) or plain `==` for this local double-entry check.

### L11. No lower bound on `--redundancy`: values < 1.0 silently produce a GIF with fewer droplets than `k_blocks` (undecodable) `[py-fountain-encode]`
**`meow_decoder/encode.py:276` (CLI 1023-1028; `config.py:69`)**
- **Impact:** `num_droplets = int(k_blocks * redundancy)` with no floor; `--redundancy 0.8` (or small files → 0 droplets) yields a mathematically undecodable artifact, encode reports success, and `--wipe-source` (auto-set by `--high-security`) then destroys the only copy. Requires user to pass a nonsensical value.
- **Fix:** Validate at config/encode: require `redundancy >= 1.1` and `num_droplets >= k_blocks + max(2, 0.1*k)`.

### L12. Ineffective zeroization of ML-KEM shared secrets and decrypted X25519 key (rebinding immutable bytes) `[py-ratchet]`
**`meow_decoder/ratchet.py:1131, 1165, 1406, 1736` (also `x25519_forward_secrecy.py:411-413`)**
- **Impact:** `pq_shared = b"\x00" * len(pq_shared)` merely rebinds the name; the original immutable 32-byte ML-KEM secret stays in heap until GC. Likewise `load_x25519_private_key_pem()` only wipes `raw_private` if it's a `bytearray`, but `aes_gcm_decrypt` returns `bytes`, so the decrypted long-term private key is never wiped. Requires post-capture memory access.
- **Fix:** Return/copy secrets into `bytearray` and `_secure_zero()` in a `finally` block; coerce the decrypted key to `bytearray` and zero unconditionally.

### L13. `DecoderRatchet` leaks the original cached message-key handle when a beacon-mixed skip-cache key succeeds `[py-ratchet]` — **FIX ALREADY APPLIED (review before commit)**
**`meow_decoder/ratchet.py:1704-1713, 1721-1736, 1773-1779`**
- **Impact:** When a rekey frame is served from `_skipped_keys` (peek, `owns_handle=False`) and the beacon/PQ path replaces `msg_key_handle` with a fresh mixed handle without clearing `cache_idx`, the success path `pop`s the original raw handle but never drops it; `finally` drops only the mixed handle — orphaning a live secret key in the Rust handle table until process exit. Empirically reproduced (1 leaked handle).
- **Fix (applied):** On success, if `cache_idx` is set and the popped handle differs from `msg_key_handle`, `hb.drop()` it. `tests/test_ratchet.py` passed (144 passed, 4 skipped); leak repro now shows 0. Diff is in the working tree.

### L14. `_advance_to` overwrites existing skip-cache entries without dropping the prior handle after a rekey rollback `[py-ratchet]`
**`meow_decoder/ratchet.py:1551-1554, 1499-1503`**
- **Impact:** `_rollback_rekey()` restores `position` but leaves handles cached ahead of it; a later `_advance_to()` over the same range does `self._skipped_keys[idx] = msg_key_handle`, silently replacing (never dropping) the prior handles — leaking un-zeroized secret message-key allocations. Reachable via reordered/corrupted frames; bounded per-cycle growth, no confidentiality break.
- **Fix:** Drop any pre-existing entry before overwrite, or purge cache entries ≥ restored position in `_rollback_rekey`.

### L15. Master ratchet state file has no rollback protection — replacing it with an older copy rewinds the chain `[py-ratchet]`
**`meow_decoder/master_ratchet.py:267-295, 439-466`**
- **Impact:** The AEAD seal binds fields but nothing prevents wholesale replay of an earlier authentic MRCV2 blob (backup/VSS/attacker write access). `load()` accepts it, restoring an older generation's chain key and reproducing previously-used file keys — violating documented "chain cannot be rewound"/FS claims. No production caller today; requires local write + password.
- **Fix:** Record an expected minimum generation out-of-band (or warn when a loaded generation is lower than last observed); document that old state copies must be destroyed.

### L16. 4-byte encrypted-index lookup table silently overwrites colliding entries, making a frame permanently undecodable `[py-ratchet]`
**`meow_decoder/ratchet.py:566-583, 1610-1617`**
- **Impact:** `_encrypt_index()` XORs each index with a per-index HKDF mask (a random function, not a permutation), so two indices can collide to the same 4-byte value; `_build_header_lookup()` inserts into a dict where the later index overwrites the earlier. The collided frame resolves to the wrong index, its commitment tag fails, and it can never be decrypted that session. ~1.2% collision odds at ~10k frames; usually absorbed by 2.5× fountain redundancy.
- **Fix:** Detect collisions in `_build_header_lookup()` (raise so encoder re-salts), or use a keyed 4-byte format-preserving PRP so the mapping is bijective.

### L17. Tamper-detection checkpoint stores its own HMAC key inline — integrity MAC forgeable, baseline spoofable `[py-pq-manifest]`
**`meow_decoder/tamper_detection.py:199-215 / 217-247`**
- **Impact:** `to_bytes()` serializes `state_key(32) || mac(32) || len || data` where `mac = HMAC(state_key, data)`; `from_bytes()` reads the key from the file and verifies with it. Anyone who can write the checkpoint can forge a valid state with arbitrary `baseline_hashes`. Bounded: deleting the file causes silent re-baseline anyway, and the module disclaims protection against code-execution attackers.
- **Fix:** Derive the checkpoint MAC key from a machine/user secret not stored in the file (OS keyring / device-bound secret); at minimum document that it only detects accidental corruption.

---

## Themes / Systemic Patterns

1. **Incomplete zeroization is the dominant pattern (9 findings: L1, L3, L12–L14, M1, plus parts of L8).** Both Rust and Python paths repeatedly copy key material (HKDF IKM/PRK/OKM, ML-KEM/X25519 shared secrets, ephemeral secrets) into plain `Vec`/`bytes`/stack arrays that are dropped or *rebound* without wiping — despite explicit module contracts (CRYPTO-002, "All secret material is zeroized on drop") and even function docstrings claiming the opposite. Python's immutable `bytes` makes name-rebinding zeroization a systemic no-op. Native `handles.rs`/`tpm.rs` show the correct pattern exists but is applied inconsistently.

2. **Missing input-bounds validation → allocation/overflow DoS (H1, M5, L7, L11).** Attacker- or user-controlled length fields (`k_blocks`, `block_count`, permutable-entry count, redundancy) flow into allocation/packing with the encoder's guards not mirrored on the decoder/other paths — including the encoder's own `u16` guard being silently swallowed.

3. **Fail-open concealment/authentication controls (C1, M6, L8, L9, L17).** Several "mandatory"/"paranoid" security controls degrade silently or are trivially bypassable: PQ mode without keys emits an undecodable+wiped artifact, stego failures fall back to plain QR, the "mandatory" manifest signature is self-signed with an in-band key (INV-041 dead code), the signing env gate is bypassable by its own threatened attacker, and the tamper MAC key ships with the data. Warnings are frequently gated behind `verbose`, hiding the downgrade.

4. **Weak/absent password stretching for at-rest and hybrid key material (H2, M4, M7, L2).** Multiple paths use a single fast HKDF-SHA256 (or bare SHA-256) over the raw password instead of the project's own Argon2id standard, creating cheap offline brute-force oracles — often with empty salts or empty-password plaintext fallbacks.

5. **Consistency gap: correct implementations exist but aren't applied uniformly.** X25519 low-order rejection, IKM zeroization, Argon2id stretching, and pk-commitment binding are all implemented *somewhere* in the repo (`handles.rs`, `tpm.rs`, `encode_data`, `compute_public_key_commitment`) but omitted on parallel WASM/pure/legacy/Schrödinger paths — the WASM and legacy/Schrödinger surfaces are the recurring weak spots.

6. **Documentation/spec overclaim (L3, L6, L8, plus C1's misleading rationale).** Formal-verification registries, docstrings, and CLI success messages assert guarantees stronger than the code delivers (vacuous Verus theorem, "PRK zeroized," "signature verified," "encrypted with your password"), which risks downstream consumers trusting invariants that don't hold.

---

## Proof-of-concept status

Executable PoCs live in **`tests/test_fable_bug_hunt_poc.py`** (3 tests, all passing — i.e. all three reproduce the vulnerable behavior). Run them with:

```
PYTHONIOENCODING=utf-8 python -m pytest tests/test_fable_bug_hunt_poc.py -v -o addopts=""
```

(`-o addopts=""` clears the repo's coverage flags since `pytest-cov` isn't installed here; `PYTHONIOENCODING=utf-8` avoids a Windows-console emoji crash in `conftest.py`.)

- **C1 — DEMONSTRATED.** `test_c1_pq_mode_without_ciphertext_is_packable_but_undecodable`: `pack_manifest` serializes a MEOW5 (PQ) manifest with `pq_ciphertext=None` without complaint, then `unpack_manifest` raises `ValueError: …PQ ciphertext is missing` on that exact blob — an artifact the encoder can emit but the decoder can never read.
- **H1 — DEMONSTRATED.** `test_h1_schrodinger_manifest_accepts_absurd_block_count`: `SchrodingerManifest.unpack()` accepts `block_count = 0xFFFFFFFF` (~4300× over `MAX_K_BLOCKS`) with no error. `test_h1_fountain_decoder_has_no_upper_bound_on_k_blocks`: `FountainDecoder(k_blocks=70_000, …)` constructs fine despite exceeding the encoder's own u16 cap (the test uses 70k so it allocates a couple MB instead of the ~100 GB an attacker would force).

Each test asserts the *current vulnerable* behavior (so it passes today) and carries a `TODO(fix)` note showing how to invert it into a regression guard once the fix lands.
