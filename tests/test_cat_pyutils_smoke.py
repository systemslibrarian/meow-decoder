"""Smoke tests for cat_utils + cat_errors after audit fixes.

These verify the bug fixes from the cat-mode audit:
  * cat_tqdm yields items (was silently empty when tqdm installed)
  * pounce_on_errors(reraise=False) returns None instead of re-raising
  * cat_nap_timeout supports sub-second timeouts and worker threads
"""
from __future__ import annotations

import threading
import time

import pytest

from meow_decoder.cat_errors import (
    NapInterruptError,
    cat_nap_timeout,
    pounce_on_errors,
)
from meow_decoder.cat_utils import cat_tqdm


# ─── cat_tqdm ────────────────────────────────────────────────────────


def test_cat_tqdm_yields_all_items():
    """cat_tqdm previously mixed yield+return and silently emitted nothing."""
    items = list(cat_tqdm([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
    assert items == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]


def test_cat_tqdm_no_iterable_returns_iterable():
    """cat_tqdm(total=N) returns an iterable up to N elements."""
    items = list(cat_tqdm(total=5))
    assert len(items) <= 5


# ─── pounce_on_errors ───────────────────────────────────────────────


def test_pounce_default_reraises():
    @pounce_on_errors(lives=2)
    def boom():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        boom()


def test_pounce_reraise_false_returns_none():
    """The bug fix — `reraise=False` previously still re-raised."""
    @pounce_on_errors(lives=2, reraise=False)
    def boom():
        raise ValueError("boom")

    assert boom() is None


def test_pounce_succeeds_first_try():
    state = {"count": 0}

    @pounce_on_errors(lives=3)
    def succeed():
        state["count"] += 1
        return "ok"

    assert succeed() == "ok"
    assert state["count"] == 1


def test_pounce_retries_until_success():
    state = {"count": 0}

    @pounce_on_errors(lives=3)
    def maybe_fail():
        state["count"] += 1
        if state["count"] < 3:
            raise ValueError(f"fail {state['count']}")
        return "ok"

    assert maybe_fail() == "ok"
    assert state["count"] == 3


# ─── cat_nap_timeout ─────────────────────────────────────────────────


def test_cat_nap_timeout_subsecond_fires():
    """The bug fix — alarm(int(0.5)) == alarm(0) silently disabled timeouts."""

    @cat_nap_timeout(0.3)
    def slow():
        time.sleep(2)

    start = time.time()
    with pytest.raises(NapInterruptError):
        slow()
    elapsed = time.time() - start
    assert 0.2 < elapsed < 0.6, f"expected ~0.3s, got {elapsed:.2f}s"


def test_cat_nap_timeout_full_second_fires():
    @cat_nap_timeout(1.0)
    def slow():
        time.sleep(3)

    start = time.time()
    with pytest.raises(NapInterruptError):
        slow()
    elapsed = time.time() - start
    assert 0.8 < elapsed < 1.5, f"expected ~1.0s, got {elapsed:.2f}s"


def test_cat_nap_timeout_completes_within_limit():
    @cat_nap_timeout(2.0)
    def fast():
        time.sleep(0.1)
        return "done"

    assert fast() == "done"


def test_cat_nap_timeout_no_crash_in_worker_thread():
    """The bug fix — signal.signal raises ValueError off the main thread."""

    @cat_nap_timeout(0.5)
    def fn():
        return "thread ok"

    result: list[str] = []
    error: list[BaseException] = []

    def runner():
        try:
            result.append(fn())
        except BaseException as e:  # noqa: BLE001
            error.append(e)

    th = threading.Thread(target=runner)
    th.start()
    th.join(timeout=2)

    assert not error, f"thread invocation crashed: {error}"
    assert result == ["thread ok"]
