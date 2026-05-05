# Gemini Code Audit & Hardening Recommendations (v3)

**Status:** dispositioned 2026-05-05 against `main` (after PR #172 merge,
commit `9774afb`). Of six findings: 1 was a real critical bug and is
fixed; 4 were already addressed in earlier work and the recommendations
are stale; 1 misunderstands how Gate 5 selects tests and has been
re-scoped.

## Disposition summary

| # | Finding | Severity claimed | Real? | Status |
|---|---------|------------------|-------|--------|
| 1 | Password length leak in `timing_normalized_input` | 🔴 Critical | **Yes** | ✅ **Fixed** in `meow_decoder/secure_keyboard.py` |
| 2 | `HybridKeyPair` / `PQBeaconKeyPair` missing `__del__` | 🟡 Medium | No | ✅ Already implemented (gemini was stale) |
| 3 | `test_cat_5speeds_pipeline` xpass | 🟡 Medium | No | ✅ xfail already removed; test passes cleanly |
| 4 | npm audit reports new vulnerabilities | 🟡 Medium | No | ✅ Both root + web_demo at 0 vulnerabilities (gemini was looking at a different env) |
| 5 | Gate 5 fix via `@pytest.mark.security` decorators | 🟡 Medium | Partial | ❌ **Recommendation rejected** — Gate 5 shards select by file list, not markers; current state is documented/intentional |
| 6 | Verify `secrets.choice` in carrier-naming paths | 🟡 Medium | No | ✅ `meow_decoder/high_security.py:447-448` already uses `secrets.choice` |

---

## Finding 1 (CRITICAL) — Password length leak — ✅ FIXED

**Real bug.** `meow_decoder/secure_keyboard.py::timing_normalized_input`
previously computed:

```python
simulated_time = len(password) * (
    secrets.randbelow(max_keystroke_ms - min_keystroke_ms) + min_keystroke_ms
)
```

A local observer (or any side-channel attacker with wall-time access)
could derive the character length of the master / duress password from
the post-input delay.

**Fix (this commit):** the post-input delay now multiplies a
**constant** `simulated_chars` (default 32, simulating a long
password) instead of `len(password)`. The user's password length
never enters the timing computation. The function signature gains
`simulated_chars: int = 32` as an explicit parameter so the
constant nature is documented in the API surface.

```python
def timing_normalized_input(
    prompt: str = "Password: ",
    min_keystroke_ms: int = 50,
    max_keystroke_ms: int = 200,
    simulated_chars: int = 32,    # NEW — fixed constant, not len(password)
) -> str:
    ...
    keystroke_range = max(1, max_keystroke_ms - min_keystroke_ms)
    simulated_time = simulated_chars * (
        secrets.randbelow(keystroke_range) + min_keystroke_ms
    )
    actual_delay = secrets.randbelow(simulated_time // 2 + 1)
    time.sleep(actual_delay / 1000.0)
    return password
```

**Verified:** AST walk confirms `len(password)` no longer appears in
the function body — only inside the docstring's "previously" note
explaining why the change was made.

---

## Finding 2 (MEDIUM) — `HybridKeyPair` / `PQBeaconKeyPair` destructors — ✅ ALREADY DONE

Gemini's recommendation here is **stale** — both classes already
have `__del__` zeroization on `audit/cat-mode-fixes` (now merged
to `main`). Confirmed by grep:

```
meow_decoder/pq_hybrid.py:193:    def __del__(self):
meow_decoder/pq_hybrid.py:201:        for attr in ("_classical_private_bytes", "_pq_secret_bytes"):
meow_decoder/pq_hybrid.py:206:                    secure_zero_memory(mut)
meow_decoder/pq_ratchet_beacon.py:96:    def __del__(self):
meow_decoder/pq_ratchet_beacon.py:108:                secure_zero_memory(bytearray(sk))
```

`FOLLOWUP.md` records this as Finding 3.2 — closed on this branch.

---

## Finding 3 (MEDIUM) — `test_cat_5speeds_pipeline` xpass — ✅ ALREADY DONE

Gemini's recommendation here is **stale**. The `@pytest.mark.xfail`
decorator was removed in commits `623bdd9` + `06ad9dc` (the cat-mode
audit fixes). Verified locally:

```
$ python -m pytest tests/test_cat_js_runner.py -v --no-cov
tests/test_cat_js_runner.py::TestCatBinaryJS::test_cat_binary_roundtrip PASSED
tests/test_cat_js_runner.py::TestCat5SpeedsJS::test_cat_5speeds_pipeline PASSED
============================== 2 passed in 1.12s ===============================
```

Both tests pass as ordinary passes (not xpass). No further action.

---

## Finding 4 (MEDIUM) — npm audit contradiction — ✅ ALREADY 0 VULNS

Gemini's recommendation here is **stale or based on a different
environment**. Current state on this branch:

```
$ npm audit --omit=optional
found 0 vulnerabilities

$ cd web_demo && npm audit --omit=optional
found 0 vulnerabilities
```

The PR description's claim is accurate. The `tar` / `node-pre-gyp` /
`minimatch` / `brace-expansion` / `picomatch` chains Gemini cited
were cleared by the canvas v2→v3 upgrade and the jest 30.x bump
recorded in `FOLLOWUP.md` (Findings 7.3 / 7.4) and on this branch.

If Gemini's report came from a `npm install` against a pinned
older lockfile, that would explain the discrepancy — but the
checked-in `package-lock.json` files on this branch resolve to the
fixed versions.

---

## Finding 5 (MEDIUM) — Gate 5 marker recommendation — ❌ REJECTED

Gemini's specific recommendation ("decorate end-to-end test cases
with `@pytest.mark.security` and `@pytest.mark.crypto` to pull them
into the security-coverage shards") **does not work** for the
current Gate 5 architecture.

The Gate 5 shards in `.github/workflows/ci.yml:556-640` select tests
by **explicit file-name list**, not by marker:

```yaml
case "${{ matrix.shard_id }}" in
  1)
    pytest --cov --cov-config=.coveragerc-security \
      tests/test_adversarial.py \
      tests/test_stego_adversarial.py \
      tests/test_security_crypto.py \
      ... [22 file paths total in shard 1]
```

Adding markers to the e2e tests has zero effect on which tests run
under `--cov-config=.coveragerc-security`. To actually pull
`test_e2e_crypto_fountain.py` into Gate 5, it would need to be
appended to one of the shard file lists.

The current state (~65.67% TOTAL across the security include set)
is documented and intentional — see commit `af92566`'s message and
the workflow-file comment block at line 590. Per-module coverage
**improved** materially in `af92566`:

| Module | Before | After |
|---|---:|---:|
| `master_ratchet.py` | 45% | 77% |
| `schrodinger_encode.py` | 0% | 40% |
| `constant_time.py` | 19% | 98% |
| `frame_mac.py` | 34% | 82% |
| `crypto_backend.py` | 72% | 81% |

The **TOTAL** number stays around 65% because `memory_guard.py` is
412 LOC at 27% in Linux CI (its `mlock` / `madvise` / Windows
Job-Object branches are structurally hard to exercise from CI). The
85% aspirational target stays in `.coveragerc-security`;
`--cov-fail-under=0` keeps the gate non-blocking on the TOTAL
number until either:
1. Those OS-specific `memory_guard` paths get tested (cross-platform
   CI matrix expansion), or
2. `memory_guard.py` is trimmed from the security-include set.

Both options are recorded in the workflow comment block. Marker
decoration would not help.

---

## Finding 6 (MEDIUM) — `secrets.choice` in carrier naming — ✅ ALREADY DONE

Gemini's recommendation here is **stale**. `meow_decoder/high_security.py`
already uses `secrets.choice`:

```
meow_decoder/high_security.py:445:    # who sees the carrier name no useful signal. random.choice is seeded
meow_decoder/high_security.py:446:    # from time and predictable; secrets.choice draws from the OS CSPRNG.
meow_decoder/high_security.py:447:    prefix = secrets.choice(prefixes)
meow_decoder/high_security.py:448:    year = secrets.choice(years)
```

`FOLLOWUP.md` records this as Finding 4.5 — closed on this branch.

The remaining `random.choice` calls in `meow_decoder/cat_utils.py`
and `meow_decoder/cat_errors.py` are for innocuous user-facing
content (cat facts, motivational meows, error suggestions) — not
security-relevant. Gemini itself acknowledges these "safely use
`random.choice()` for generating innocuous user-facing messages."

---

## Net result

| Severity | Real and fixed | Stale (already addressed) | Rejected |
|---|---:|---:|---:|
| 🔴 Critical | 1 | 0 | 0 |
| 🟡 Medium | 0 | 4 | 1 |

The one real finding (password length leak) is fixed in this commit.
The other four medium-severity items were already closed on the
`audit/cat-mode-fixes` branch (now merged) — Gemini was reviewing
against an earlier state. The Gate 5 marker recommendation
misunderstands the shard-by-file-list architecture and has been
re-scoped to the actual remaining gap (`memory_guard.py` OS-specific
coverage, recorded in the workflow file).
