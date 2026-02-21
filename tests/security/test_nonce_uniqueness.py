"""
Security Test Suite: Nonce Uniqueness

Tests that the deterministic nonce generation via HKDF-SHA-256 prevents
catastrophic AES-GCM nonce reuse across:
  - Normal sequential frame encoding
  - Simulated crash + restart scenarios
  - Multiple concurrent processes/threads
  - Schrödinger dual-stream isolation

These tests verify INV-003 (Nonce Uniqueness) from SECURITY_INVARIANTS.md.
"""

from meow_decoder.crypto_backend import get_default_backend
from meow_decoder.nonce import NonceGenerator, derive_transfer_nonce, MAX_FRAME_COUNTER
import os
import struct
import secrets
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

# Ensure test mode
os.environ["MEOW_TEST_MODE"] = "1"
os.environ["MEOW_PRODUCTION_MODE"] = "0"


@pytest.fixture
def backend():
    return get_default_backend()


@pytest.fixture
def root_key(backend):
    """32-byte random root key for testing."""
    return secrets.token_bytes(32)


@pytest.fixture
def manifest_hash(backend):
    """32-byte manifest hash."""
    return backend.sha256(b"test_manifest_content_v1")


@pytest.fixture
def nonce_gen(root_key, manifest_hash):
    """NonceGenerator instance for testing."""
    return NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)


class TestNonceUniqueness:
    """Test that nonces are unique across all scenarios."""

    def test_sequential_nonces_unique(self, nonce_gen):
        """Sequential frame counters produce unique nonces."""
        nonces = set()
        for i in range(1000):
            nonce = nonce_gen.generate(i)
            assert len(nonce) == 12, f"Nonce must be 12 bytes, got {len(nonce)}"
            assert nonce not in nonces, f"Nonce collision at frame {i}!"
            nonces.add(nonce)

    def test_deterministic_same_inputs(self, root_key, manifest_hash):
        """Same inputs always produce the same nonce (deterministic)."""
        gen1 = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        gen2 = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        for i in range(100):
            n1 = gen1.generate(i)
            n2 = gen2.generate(i)
            assert n1 == n2, f"Determinism violated at frame {i}"

    def test_different_keys_different_nonces(self, manifest_hash):
        """Different root keys produce different nonces for same counter."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        gen1 = NonceGenerator(root_key=key1, manifest_hash=manifest_hash)
        gen2 = NonceGenerator(root_key=key2, manifest_hash=manifest_hash)
        for i in range(100):
            assert gen1.generate(i) != gen2.generate(i)

    def test_different_manifest_hash_different_nonces(self, root_key, backend):
        """Different manifest hashes produce different nonces for same counter."""
        hash1 = backend.sha256(b"transfer_session_1")
        hash2 = backend.sha256(b"transfer_session_2")
        gen1 = NonceGenerator(root_key=root_key, manifest_hash=hash1)
        gen2 = NonceGenerator(root_key=root_key, manifest_hash=hash2)
        for i in range(100):
            assert gen1.generate(i) != gen2.generate(i)

    def test_reuse_detection_raises(self, nonce_gen):
        """Using the same frame_counter twice raises RuntimeError."""
        nonce_gen.generate(42)
        with pytest.raises(RuntimeError, match="Nonce reuse detected"):
            nonce_gen.generate(42)

    def test_non_sequential_counters_unique(self, nonce_gen):
        """Non-sequential (but unique) counters produce unique nonces."""
        counters = [999, 0, 500, 1, 42, 7777, 3]
        nonces = set()
        for c in counters:
            n = nonce_gen.generate(c)
            assert n not in nonces
            nonces.add(n)

    def test_high_water_mark_tracking(self, nonce_gen):
        """High water mark tracks the highest counter used."""
        assert nonce_gen.high_water_mark == -1
        nonce_gen.generate(5)
        assert nonce_gen.high_water_mark == 5
        nonce_gen.generate(3)
        assert nonce_gen.high_water_mark == 5
        nonce_gen.generate(100)
        assert nonce_gen.high_water_mark == 100


class TestCrashRestartNonceReuse:
    """Simulate crash + restart scenarios to verify no nonce reuse."""

    def test_crash_restart_different_manifest_hash(self, root_key, backend):
        """After crash + restart, fresh manifest_hash prevents reuse.

        Real scenario: encoder crashes mid-transfer, restarts with a new
        salt/manifest.  The new manifest_hash ensures all nonces differ.
        """
        hash1 = backend.sha256(b"session_before_crash")
        hash2 = backend.sha256(b"session_after_crash_new_salt")

        gen_before = NonceGenerator(root_key=root_key, manifest_hash=hash1)
        gen_after = NonceGenerator(root_key=root_key, manifest_hash=hash2)

        before_nonces = {gen_before.generate(i) for i in range(100)}
        after_nonces = {gen_after.generate(i) for i in range(100)}

        # No overlap between pre-crash and post-crash nonces
        overlap = before_nonces & after_nonces
        assert len(overlap) == 0, f"Found {len(overlap)} nonce collisions across crash boundary!"

    def test_crash_restart_same_manifest_same_counter_same_nonce(self, root_key, manifest_hash):
        """If manifest_hash is somehow identical (resume), nonces match deterministically.

        This is the SIV property: same input = same nonce = safe for GCM
        (encrypting the same plaintext with the same key and nonce is
        not a security issue, it's deterministic encryption).
        """
        gen1 = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        gen2 = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)

        # Same frame counter -> same nonce -> safe (SIV property)
        n1 = gen1.generate(0)
        n2 = gen2.generate(0)
        assert n1 == n2

    def test_simulated_multi_restart_no_collision(self, backend):
        """Simulate 50 crash/restart cycles, each with fresh salt."""
        all_nonces = set()
        for session in range(50):
            key = secrets.token_bytes(32)
            manifest_hash = backend.sha256(f"session_{session}_{secrets.token_hex(8)}".encode())
            gen = NonceGenerator(root_key=key, manifest_hash=manifest_hash)
            for frame in range(20):
                nonce = gen.generate(frame)
                assert nonce not in all_nonces, (
                    f"Collision in session {session}, frame {frame}"
                )
                all_nonces.add(nonce)
        assert len(all_nonces) == 50 * 20


class TestMultiProcessNonceIsolation:
    """Test that concurrent processes/threads cannot produce collisions."""

    def test_threaded_nonce_generation(self, root_key, manifest_hash):
        """Multiple threads generating nonces concurrently never collide."""
        gen = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        results = {}
        errors = []

        def generate_range(start, count):
            try:
                for i in range(start, start + count):
                    nonce = gen.generate(i)
                    results[i] = nonce
            except Exception as e:
                errors.append(e)

        threads = []
        for t in range(10):
            thread = threading.Thread(target=generate_range, args=(t * 100, 100))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0, f"Errors: {errors}"
        assert len(results) == 1000
        # All nonces unique
        nonce_set = set(results.values())
        assert len(nonce_set) == 1000, "Nonce collision detected across threads!"

    def test_independent_generators_per_process(self, backend):
        """Independent generators (simulating separate processes) produce unique nonces."""
        generators = []
        for i in range(10):
            key = secrets.token_bytes(32)
            mhash = backend.sha256(f"process_{i}".encode())
            generators.append(NonceGenerator(root_key=key, manifest_hash=mhash))

        all_nonces = set()
        for gen in generators:
            for frame in range(50):
                nonce = gen.generate(frame)
                assert nonce not in all_nonces
                all_nonces.add(nonce)

    def test_concurrent_thread_pool_no_collision(self, root_key, manifest_hash):
        """ThreadPoolExecutor stress test."""
        gen = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        nonces = {}

        def gen_nonce(counter):
            return counter, gen.generate(counter)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(gen_nonce, i) for i in range(500)]
            for f in futures:
                counter, nonce = f.result()
                nonces[counter] = nonce

        assert len(set(nonces.values())) == 500


class TestNonceEdgeCases:
    """Edge case and boundary testing."""

    def test_zero_counter(self, nonce_gen):
        """Frame counter 0 is valid."""
        nonce = nonce_gen.generate(0)
        assert len(nonce) == 12

    def test_max_counter(self, root_key, manifest_hash):
        """Maximum u64 counter is valid."""
        gen = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        nonce = gen.generate(MAX_FRAME_COUNTER)
        assert len(nonce) == 12

    def test_negative_counter_rejected(self, nonce_gen):
        """Negative frame counter raises ValueError."""
        with pytest.raises(ValueError, match="non-negative"):
            nonce_gen.generate(-1)

    def test_overflow_counter_rejected(self, nonce_gen):
        """Counter exceeding u64 raises ValueError."""
        with pytest.raises(ValueError):
            nonce_gen.generate(MAX_FRAME_COUNTER + 1)

    def test_invalid_manifest_hash_length(self, root_key):
        """manifest_hash must be exactly 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            NonceGenerator(root_key=root_key, manifest_hash=b"short")

    def test_stateless_derive_matches_generator(self, root_key, manifest_hash):
        """Stateless derive_transfer_nonce matches NonceGenerator output."""
        gen = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        for i in range(50):
            gen_nonce = gen.generate(i)
            stateless_nonce = derive_transfer_nonce(root_key, i, manifest_hash)
            assert gen_nonce == stateless_nonce


class TestSchrodingerNonceIsolation:
    """Test nonce isolation between Schrödinger dual streams."""

    def test_additional_context_isolates_streams(self, root_key, manifest_hash):
        """Different additional_context produces different nonces."""
        gen = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        stream_a = gen.generate_for_transfer(0, additional_context=b"stream_A")
        stream_b = gen.generate_for_transfer(0, additional_context=b"stream_B")
        assert stream_a != stream_b

    def test_dual_stream_no_collision(self, root_key, manifest_hash):
        """Two sub-streams with full nonce sets never collide."""
        gen = NonceGenerator(root_key=root_key, manifest_hash=manifest_hash)
        stream_a_nonces = set()
        stream_b_nonces = set()

        for i in range(500):
            na = gen.generate_for_transfer(i, additional_context=b"\x00")
            nb = gen.generate_for_transfer(i, additional_context=b"\x01")
            stream_a_nonces.add(na)
            stream_b_nonces.add(nb)

        # No overlap
        assert len(stream_a_nonces & stream_b_nonces) == 0
        # All unique within each stream
        assert len(stream_a_nonces) == 500
        assert len(stream_b_nonces) == 500


class TestNonceGeneratorReset:
    """Test reset behavior."""

    def test_reset_allows_reuse(self, nonce_gen):
        """After reset, counters can be reused (new session)."""
        nonce_gen.generate(0)
        nonce_gen.generate(1)
        nonce_gen.reset()
        # Should not raise after reset
        nonce_gen.generate(0)
        nonce_gen.generate(1)

    def test_reset_clears_high_water_mark(self, nonce_gen):
        """Reset clears the high water mark."""
        nonce_gen.generate(99)
        assert nonce_gen.high_water_mark == 99
        nonce_gen.reset()
        assert nonce_gen.high_water_mark == -1
