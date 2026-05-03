# Ratchet Speculative-State Rollback — Cryptographer Review Brief

**Subject:** `meow_decoder/ratchet.py::DecoderRatchet` — two-phase commit
on asymmetric rekey + skipped-key cache peek pattern.
**Commit:** `8a3bb48` on branch `audit/cat-mode-fixes`.
**Branch base:** `8b0a0fd`.
**Test surface:** `tests/test_ratchet.py::TestSpeculativeStateRollback`
(3 new tests) plus the unchanged 144-test ratchet suite.

The change replaces a destructive-on-fail decoder with a deferred-commit
one. The two source bugs are gone, but the new control flow has more
surface area than what the existing Tamarin model covers. **This brief
exists so a cryptographer can review the rollback paths without paging
through the full diff.** A Tamarin re-run against `MeowRatchetFS.spthy`
is the most concrete validation step and is the explicit ask at the end.

## What was wrong

### Bug #1 — silent ratchet desync via ML-KEM implicit rejection (HIGH)

`_execute_rekey()`, called from inside `_advance_to()`, decapsulated the
peer's ML-KEM-1024 ciphertext and folded the result into the new root
key, then dropped the old root + chain handles, then committed
`self._state` — all *before* the frame's `commit_tag` was verified.

ML-KEM uses Fujisaki-Okamoto implicit rejection. A tampered ciphertext
does not raise; it returns a pseudorandom shared secret. That junk
secret was being folded into the root, the old (real) root + chain
were destroyed, the chain advanced producing a junk message key,
`commit_tag` predictably failed — but rollback never happened. The
session was permanently desynced from the sender; every subsequent
frame's MAC failed.

### Bug #2 — cached message-key burned on commit_tag failure (MEDIUM)

When `decrypt()` found `frame_index in self._skipped_keys` it eagerly
called `self._skipped_keys.pop(frame_index)` *before* `commit_tag`
verification. The `finally` block then dropped the handle on any
exception. A single tampered scan of an out-of-order frame removed the
cached key permanently — even a clean re-scan of the same QR frame
afterwards failed with "Frame is behind chain position and not in skip
cache."

## The fix at a glance

```text
DecoderRatchet
├─ self._pending_rollback: Optional[tuple]   # snapshot for Bug #1
├─ self._skipped_keys: Dict[int, int]         # peek-don't-pop for Bug #2
│
├─ _execute_rekey(epoch)
│     # Computes new (root, chain) handles, mutates self._state with
│     # them, but does NOT drop the old handles. Stores the old root,
│     # chain, position, epoch into self._pending_rollback.
│
├─ _commit_rekey()
│     # Drops the saved old root + chain (forward-secrecy advance).
│     # Pops the consumed _received_rekey_material[epoch] entry.
│     # Idempotent.
│
├─ _rollback_rekey()
│     # Drops the (possibly junk) new root + chain currently in
│     # self._state, restores the snapshot. Pops the rekey material
│     # that produced junk so a retry will not loop forever.
│     # Idempotent.
│
└─ decrypt(frame)
      # 1. Header lookup, replay/index checks (no state mutation).
      # 2. Get msg_key:
      #      Case 1: peek self._skipped_keys[frame_index]
      #              → owns_handle = False, cache_idx = frame_index
      #      Case 2: _advance_to(frame_index) — may invoke
      #              _execute_rekey, which arms _pending_rollback
      #              → owns_handle = True
      # 3. Beacon-mix derivations (rekey frames). Each mix replaces
      #    msg_key with a fresh derived handle and sets owns_handle
      #    = True; never drops the cache value while not-owned.
      # 4. derive_frame_keys + commit_tag verify.
      # 5. AES-GCM decrypt.
      # 6. SUCCESS: pop cache (we now own the handle), call
      #    _commit_rekey() to drop saved old handles, mark frame
      #    consumed, return plaintext.
      # 7. FAILURE (any exception in the try block): call
      #    _rollback_rekey(), re-raise. The cache value (if we never
      #    popped) stays intact.
      # finally: drop msg_key only if owns_handle == True.
```

## Invariants the new code is supposed to preserve

I-1. **Forward secrecy advance.** On a successful decrypt, the
pre-existing chain key for `position - 1` is unrecoverable. The chain
key in `self._state` after success is one ratchet step further than it
was before.

I-2. **Forward secrecy across rekey.** On a successful asymmetric
rekey, the pre-rekey root + chain handles are dropped (forward
secrecy: an attacker who later compromises the new root cannot derive
the old chain). `_commit_rekey()` is the *only* code path that drops
these.

I-3. **Pre-failure state preservation.** On any decrypt failure, the
state visible to subsequent calls is the state that existed at decrypt
entry — modulo `_consumed_indices` (only added on success) and
`_skipped_keys` (entries are *peeked* on Case 1, only popped on
success).

I-4. **No double-drop.** Every handle in `self._state.root_key`,
`self._state.chain_key`, the cache, and the snapshot is owned by
exactly one logical owner at any time. Verified by:

* `_execute_rekey` snapshot stores the OLD handles; the NEW handles go
  into `self._state`. Two distinct sets of references.
* `_commit_rekey` drops only the snapshot's old handles.
* `_rollback_rekey` drops only `self._state`'s current new handles.
* `finalize()` drops whatever is in `self._state` AND any
  `_pending_rollback` entry (defensive — covers an interrupted
  decrypt, e.g. KeyboardInterrupt between `_execute_rekey` and the
  commit/rollback decision).

I-5. **No leaked handles on partial failure inside `_execute_rekey`.**
If `_asymmetric_root_rekey_handle` succeeds but `_fold_pq_into_root` or
the post-fold `_hkdf_derive_handle` raises, the partial handles are
dropped in the inner try/except before the snapshot is armed. State
mutation does not happen until the function reaches its tail.

I-6. **Skipped-key cache integrity (Bug #2).** When `decrypt(frame_X)`
fires for a frame whose key is in `_skipped_keys`, the handle is
peeked, used for verification, and only popped from the cache on full
success. On any failure, the cache entry is preserved untouched. A
clean re-scan of `frame_X` therefore succeeds.

## Where the proofs need to be redone

The `MeowRatchetFS.spthy` Tamarin model captures `RatchetStep` and
`BeaconRekey` as monolithic transitions: each consumes its inputs,
emits an action fact, and produces the new state. **The model has no
analogue of the speculative-state pattern** — it neither has a
"pre-commit" rule that emits new state then waits, nor a `Rollback`
rule that restores it.

This means:

* The model currently proves the *intended* protocol property
  (PerFrameForwardSecrecy, PostCompromiseSecurityViaBeacon) but does
  not prove that the Python implementation faithfully realises that
  protocol. The new pattern is purely an implementation choice; it
  should be transparent to the model.

* But: if a reviewer wants to be *certain* the rollback path doesn't
  expose any extra capability to the adversary, the model could grow
  a `Rollback` rule that:
   1. consumes the post-rekey RatchetState,
   2. emits the pre-rekey RatchetState,
   3. discards the consumed `BeaconRekey` material.

  Adding that rule and re-running the existing PCS lemma should still
  succeed. It should *not* introduce new attacks.

## Concrete asks for the reviewer

1. **Tamarin re-run.** Confirm `MeowRatchetFS.spthy` lemmas
   (`PerFrameForwardSecrecy`, `PostCompromiseSecurityViaBeacon`,
   `KeyCommitmentBinding`, `ChainKeyFreshness`, `Executability`) all
   still pass on `fa04a1f` of `audit/cat-mode-fixes`. The arity fixes
   landed in `b143d76` are pre-requisites for parsing.

2. **Optional: rollback rule.** If you want belt-and-braces,
   add a `Rollback` rule per the sketch above and verify it doesn't
   falsify any lemma.

3. **Implementation review of `_execute_rekey` / `_commit_rekey` /
   `_rollback_rekey`.** Specifically:
   * Is the snapshot tuple immutable / safe across concurrent calls
     (the ratchet is single-threaded by contract — confirm no test
     parallelism violates this)?
   * Are the `# nosec` exception swallows (`try: hb.drop(h) except:
     pass`) acceptable, or should `finalize` log on failure?
   * Should `_rollback_rekey` also clear `_consumed_indices` of any
     entries added speculatively? (It currently does not — but
     `_consumed_indices` is only added on success, so there's nothing
     to clear.)

4. **Concurrent-decrypt edge case.** If a future change makes
   `decrypt()` callable from multiple threads, the
   `_pending_rollback` slot would race. Today this is OK — single-
   threaded by contract — but worth a doc note in `RATCHET_PROTOCOL.md`
   (NOT yet added; flagging here).

## Test coverage of the rollback paths

`tests/test_ratchet.py::TestSpeculativeStateRollback`:

| Test | Bug | What it asserts |
|---|---|---|
| `test_cached_key_survives_commit_tag_failure` | #2 | After tampered scan of an out-of-order frame, `frame_idx in _skipped_keys` still true; clean re-scan succeeds. |
| `test_cached_rekey_frame_survives_commit_tag_failure` | #2 | Same but for plaintext-beacon rekey frame (exercises beacon-mix ownership tracking). |
| `test_tampered_pq_ciphertext_does_not_desync_ratchet` | #1 | Flips a byte in the ML-KEM ciphertext on an asymmetric rekey frame. Asserts `decrypt` raises, `_state.root_key`/`chain_key`/`position`/`epoch` unchanged from snapshot, `_pending_rollback is None` after the failure path runs, and a clean rekey frame for the same epoch decrypts cleanly afterward. (Skipped if ML-KEM backend unavailable.) |

These are the minimum to demonstrate the bug fixes. They do **not**
exercise:

* Multiple consecutive rekey failures followed by a successful one
  (only one pending rollback at a time — but a long flaky session
  might invoke the path repeatedly).
* `_advance_to` with multiple intermediate ratchet steps before a
  rekey at the target frame (the typical case in this codebase has
  position == frame_index when `_execute_rekey` runs, but skipped-
  delivery scenarios force the loop body to run first).
* Interrupted decrypt (KeyboardInterrupt mid-`_execute_rekey`) — the
  `finalize()` defensive cleanup is wired but not test-covered.

If any of these gaps matter for your threat model, please flag and I
will add tests.

## Files / lines of interest

* `meow_decoder/ratchet.py:1304-1310` — `_pending_rollback` slot
  declaration + comment.
* `meow_decoder/ratchet.py:1325-~1448` — `_execute_rekey`,
  `_commit_rekey`, `_rollback_rekey`.
* `meow_decoder/ratchet.py:~1525-1620` — rewritten `decrypt()` body
  (Bug #2 fix + commit/rollback hooks).
* `meow_decoder/ratchet.py:~1820-1840` — `finalize()` defensive drain
  of `_pending_rollback`.
* `tests/test_ratchet.py::TestSpeculativeStateRollback` — three
  regression tests.

— end —
