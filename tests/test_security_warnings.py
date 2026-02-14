import importlib
import warnings

import meow_decoder.security_warnings as security_warnings


def test_warn_pq_experimental_emits_once():
    security_warnings._warn_pq_experimental.cache_clear()

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        security_warnings.warn_pq_experimental()
        security_warnings.warn_pq_experimental()

    pq_warnings = [
        w
        for w in captured
        if issubclass(w.category, security_warnings.PostQuantumExperimentalWarning)
    ]
    assert len(pq_warnings) == 1


def test_warn_python_backend_emits_once():
    security_warnings._warn_python_backend.cache_clear()

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        security_warnings.warn_python_backend()
        security_warnings.warn_python_backend()

    backend_warnings = [
        w for w in captured if issubclass(w.category, security_warnings.SecurityDeprecationWarning)
    ]
    assert len(backend_warnings) == 1


def test_warn_pq_experimental_silenced(monkeypatch):
    monkeypatch.setenv("MEOW_SILENCE_PQ_WARNING", "1")
    reloaded = importlib.reload(security_warnings)
    reloaded._warn_pq_experimental.cache_clear()

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        reloaded.warn_pq_experimental()

    pq_warnings = [
        w for w in captured if issubclass(w.category, reloaded.PostQuantumExperimentalWarning)
    ]
    assert len(pq_warnings) == 0

    monkeypatch.delenv("MEOW_SILENCE_PQ_WARNING", raising=False)
    importlib.reload(security_warnings)


def test_get_frame_mac_rationale_contains_header():
    rationale = security_warnings.get_frame_mac_rationale()
    assert "FRAME MAC DESIGN RATIONALE" in rationale
