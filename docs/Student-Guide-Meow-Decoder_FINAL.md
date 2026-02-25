# Student Guide: Learning Real Cryptography Engineering with Meow Decoder

Meow Decoder is an **open-source educational codebase** designed to teach real-world cryptography engineering through a complete, paranoid air-gapped file transfer pipeline:

**files → authenticated encryption → fountain-coded animated QR/GIF → optical transmission → secure verification & recovery**

This guide helps students and self-learners understand **how secure systems are actually built** — focusing on primitive composition, invariant enforcement, fail-safe design, threat modeling, and rigorous testing — by reading, running, and breaking real code.

> ⚠️ **CRITICAL – NOT FOR REAL SECRETS**
> This is a **learning/research** project only.
> **Never** use it to protect actual sensitive data.
> Always read `docs/THREAT_MODEL.md` and `docs/SECURITY_CLAIMS.md` first.

## What you’ll learn by reading and running this project

- Turning cryptographic primitives into a complete secure protocol
- Defining and enforcing security invariants in code
- Building fail-closed systems (tamper → hard reject)
- Correct real-world usage of KDFs, AEAD, AAD, nonces
- Realistic forward secrecy limits in one-way / offline channels
- Concrete post-quantum hybrid key schedules (no hand-waving)
- Handling lossy optical channels (frame loss, per-frame MACs)
- Reading & critiquing crypto code like a security engineer

## Quick first experiment (5–10 minutes)

After following the setup in `docs/QUICKSTART.md`:

```bash
# Encode a tiny file
python -m meow_decoder encode --password "meow123" secret.txt output.gif

# Decode it back
python -m meow_decoder decode output.gif --password "meow123"
```

**Safety note:** Use a throwaway directory and tiny dummy files for all experiments.

Now tamper with it deliberately:

1) Open `output.gif` in a hex editor and change **one single byte**
2) Run the decode command again — observe how and where it fails
3) Try decoding with a wrong password — compare the behavior

This single round-trip + deliberate tamper teaches more about verification, fail-closed design, and error reporting than hours of passive reading.

## Fast onboarding path (20–40 minutes)

Read these documents in order — they quickly build the correct mental model:

1) `docs/THREAT_MODEL.md` — assumed attacker capabilities and explicit non-goals
2) `docs/SECURITY_INVARIANTS.md` — the short list of rules the implementation must never violate
3) `docs/ARCHITECTURE.md` — high-level components and data-flow diagram
4) Run the quick experiment above

## Deeper study path (1–3 focused sessions)

### System-level understanding

- `docs/SECURITY_CLAIMS.md` — precise security promises vs. explicit limitations
- `docs/PROTOCOL.md` — framing structure (on-disk / “on-the-wire”)
- `docs/SPEC_REFERENCE.md` — detailed field layouts, domain separation, versioning rules

### Crypto core (start reading code here)

- `meow_decoder/crypto.py` — main encrypt/decrypt flow, AEAD + AAD usage
- `meow_decoder/crypto_backend.py` — safety boundaries around the crypto provider
- `meow_decoder/argon2_presets.py` — password-to-key derivation presets and rationale
- `meow_decoder/nonce.py` — strict nonce generation and discipline
- `meow_decoder/manifest_signing.py` — manifest-based whole-pipeline integrity

### One-way “forward secrecy” & post-quantum hybrid

- `meow_decoder/ratchet.py` + `docs/RATCHET_PROTOCOL.md` — ratchet design and offline limitations
- `meow_decoder/pq_hybrid.py` — concrete post-quantum + classical key schedule

### Optical / lossy transport realism

- `meow_decoder/fountain.py` — fountain codes for loss-tolerant recovery
- `meow_decoder/qr_code.py` + `meow_decoder/gif_handler.py` — frame → animated GIF encoding
- `meow_decoder/frame_mac.py` — per-frame authentication and tamper rejection
- `mobile/` — **[Meow Capture](../mobile/README.md)** iOS/Android companion app: zero-network live QR scanner that exports fountain-decoded payloads as signed JSON for desktop decode; study `mobile/src/hooks/` for React Native security patterns
- `meow_decoder/merge.py` — multi-device capture merge CLI: deduplication + session validation

### Advanced / experimental features (read claims very carefully)

- `meow_decoder/schrodinger_*.py` / `duress_mode.py` — decoy and duress mechanics
- Steganography-related modules — read `docs/STEGO_STRENGTH_EVALUATION.md` first

## Code map: where to learn each major concept

**★☆☆ Beginner-friendly**
- `crypto.py` — AEAD usage, AAD, framing integration
- `argon2_presets.py` — password → key derivation choices, presets, and tradeoffs

**★★☆ Intermediate**
- `manifest_signing.py` — whole-pipeline integrity via manifest
- `ratchet.py` (and `master_ratchet.py` if present) — one-way ratchet design and realistic limits
- `fountain.py` — loss tolerance + recovery with fountain codes

**★★★ Advanced / research-oriented**
- `pq_hybrid.py` — practical post-quantum + classical hybrid construction
- `schrodinger_*.py`, `duress_mode.py` — deniability and duress patterns (read claims first!)
- Steganography modules — understand weaknesses via `docs/STEGO_STRENGTH_EVALUATION.md`

## Exercises: turn reading into understanding

### A) Trace integrity end-to-end (easy → medium)

List every piece of data that is authenticated. For each piece:

- Where is the MAC/signature produced?
- Where is it verified?
- What happens on failure (fail-closed behavior)?

**Suggested deliverable:** a short markdown table or list you can keep in your notes, e.g.:

- Payload → `encrypt()` → `verify_manifest_and_decrypt()` → reject & log
- Manifest → `sign_manifest()` → `verify_manifest()` → reject entire session
- Per-frame data → `frame_mac.py` → `frame_mac.verify()` → skip frame & report

### B) “What breaks if…?” threat modeling warm-up (medium)

For each of these mistakes, identify:

- Which invariant from `docs/SECURITY_INVARIANTS.md` would be violated
- One realistic attack that becomes possible

Scenarios:

- Reusing the same nonce across messages
- Feeding the password directly into AAD instead of using a slow KDF
- Decrypting the payload before verifying the manifest
- Allowing unknown or older protocol versions without strict rejection

**Suggested deliverable:** a short markdown list or table (scenario → invariant → attack).

### C) Ratchet reasoning (medium → hard)

Draw or describe the key derivation tree for a single encode → decode session. Answer:

- What state advances per message or frame?
- Which keys protect which parts of the data?
- Why is full forward secrecy impossible in a strict one-way/offline setting?

**Suggested deliverable:** a short markdown diagram or bullet list of the key tree + answers.

### D) Fuzz thinking (medium)

Choose one untrusted input boundary (e.g. manifest, frame, GIF container). Then:

- List 5 realistic hostile input classes (truncation, reordering, duplicate frames, corrupted length fields, invalid UTF-8)
- Suggest one fuzzing strategy or negative test case for each class

**Suggested deliverable:** a short markdown table (input class → test idea → expected fail-closed behavior).

## How to read crypto code like a security engineer

Use this loop for every module you study:

1) Read the relevant invariant from `docs/SECURITY_INVARIANTS.md`
2) Locate where the code enforces it (assertions, early returns, strict parsing)
3) Find the tests that demonstrate it (unit, integration, property-based, fuzz)
4) Assume hostile inputs at every parsing boundary
5) Value explicit failure over silent or “best-effort” recovery

If something is unclear, treat it as a learning opportunity:

- What additional test would remove ambiguity?
- What assertion or check would make the safety intent obvious?

## Anti-patterns to notice and avoid (in any crypto project)

- Implementing custom AES-CBC + HMAC instead of using a modern AEAD
- Deriving keys from passwords without a memory-hard, slow KDF (Argon2id, scrypt, etc.)
- Decrypt-first-then-verify behavior
- Missing strict checks on length, version, or type of untrusted input
- Assuming metadata or headers are not attacker-controlled

## Contributing as a student

High-value contributions that teach real crypto engineering:

- Add a test that enforces one specific invariant
- Write negative tests (tamper, truncation, replay, reordering, wrong password)
- Improve test clarity (“tests as living documentation”)
- Reduce attack surface at any parsing or input boundary

Before opening a pull request:

- Read `CONTRIBUTING.md`
- Run the entire test suite
- Never modify crypto logic without new tests that verify the intended security properties

## Final advice for students

The fastest way to learn crypto engineering is:

1) Run experiments and deliberately break things
2) Trace invariants from docs → code → tests
3) Write one failing test before you believe any claim

If something still confuses you — that’s the best place to dig deeper.

Good luck and stay paranoid. 🐾
