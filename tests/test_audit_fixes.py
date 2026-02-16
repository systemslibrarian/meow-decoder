#!/usr/bin/env python3
"""
Tests for OPUS-AUDIT.md security fixes.

Validates that all FAIL findings from the hostile crypto audit have been
properly remediated. Each test is named after the audit finding ID.
"""

import os
import secrets
import warnings

import pytest

os.environ.setdefault("MEOW_TEST_MODE", "1")

# ---------------------------------------------------------------------------
# FIX-A1: Nonce guard uses LRU eviction, warns on HSM mode
# ---------------------------------------------------------------------------


class TestFixA1NonceGuard:
    """A1: Nonce reuse guard improvements."""

    def test_nonce_guard_lru_eviction_preserves_recent(self):
        """After exceeding max cache size, recent entries are still tracked."""
        from meow_decoder.crypto import (
            _register_nonce_use,
            _nonce_reuse_cache,
            _NONCE_REUSE_CACHE_MAX,
        )

        _nonce_reuse_cache.clear()

        # Insert a known nonce
        key = b"\x01" * 32
        nonce = b"\x01" * 12
        _register_nonce_use(key, nonce)

        # Fill up to max (use unique nonces)
        for i in range(_NONCE_REUSE_CACHE_MAX + 10):
            _register_nonce_use(secrets.token_bytes(32), secrets.token_bytes(12))

        # The original nonce was evicted (it was the oldest), so inserting
        # it again should NOT raise (it was evicted, not cleared)
        # However, a recent nonce should still be detected
        recent_key = secrets.token_bytes(32)
        recent_nonce = secrets.token_bytes(12)
        _register_nonce_use(recent_key, recent_nonce)

        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(recent_key, recent_nonce)

        _nonce_reuse_cache.clear()

    def test_nonce_guard_hsm_mode_warning(self, caplog):
        """HSM/TPM precomputed_key mode emits a warning log."""
        import logging
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache

        _nonce_reuse_cache.clear()

        with caplog.at_level(logging.WARNING, logger="meow_decoder.crypto.nonce_guard"):
            _register_nonce_use(
                secrets.token_bytes(32),
                secrets.token_bytes(12),
                precomputed_key_mode=True,
            )

        assert "per-process only" in caplog.text
        _nonce_reuse_cache.clear()

    def test_nonce_guard_reuse_detected(self):
        """Duplicate key+nonce raises RuntimeError."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache

        _nonce_reuse_cache.clear()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        _register_nonce_use(key, nonce)
        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(key, nonce)

        _nonce_reuse_cache.clear()


# ---------------------------------------------------------------------------
# FIX-A2: AAD bypass removal
# ---------------------------------------------------------------------------


class TestFixA2AADBypass:
    """A2: AAD parameters are mandatory for decryption."""

    def test_decrypt_rejects_missing_orig_len(self):
        """decrypt_to_raw raises when orig_len is None."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

        plaintext = b"test data for AAD bypass check"
        password = "password123"
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(plaintext, password)

        with pytest.raises((ValueError, RuntimeError), match="AAD parameters.*required"):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=None,  # Missing
                comp_len=len(comp),
                sha256=sha,
            )

    def test_decrypt_rejects_missing_comp_len(self):
        """decrypt_to_raw raises when comp_len is None."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

        plaintext = b"test data for AAD bypass check"
        password = "password123"
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(plaintext, password)

        with pytest.raises((ValueError, RuntimeError), match="AAD parameters.*required"):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(plaintext),
                comp_len=None,  # Missing
                sha256=sha,
            )

    def test_decrypt_rejects_missing_sha256(self):
        """decrypt_to_raw raises when sha256 is None."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

        plaintext = b"test data for AAD bypass check"
        password = "password123"
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(plaintext, password)

        with pytest.raises((ValueError, RuntimeError), match="AAD parameters.*required"):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(plaintext),
                comp_len=len(comp),
                sha256=None,  # Missing
            )

    def test_decrypt_succeeds_with_all_aad(self):
        """decrypt_to_raw works normally when all AAD params are present."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

        plaintext = b"test data for AAD full round-trip"
        password = "password123"
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(plaintext, password)

        result = decrypt_to_raw(
            cipher,
            password,
            salt,
            nonce,
            orig_len=len(plaintext),
            comp_len=len(comp),
            sha256=sha,
        )
        assert result == plaintext


# ---------------------------------------------------------------------------
# FIX-C3: Transcript binding in forward secrecy HKDF
# ---------------------------------------------------------------------------


class TestFixC3TranscriptBinding:
    """C3: Protocol version bound into FS HKDF info."""

    def test_protocol_version_changes_derived_key(self):
        """Different protocol_version values produce different keys."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            generate_receiver_keypair,
            derive_shared_secret,
        )

        sender_keys = generate_ephemeral_keypair()
        _, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        password = "password123"

        secret_v3 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
            protocol_version=3,
        )
        secret_v4 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
            protocol_version=4,
        )

        assert secret_v3 != secret_v4
        assert len(secret_v3) == 32
        assert len(secret_v4) == 32

    def test_protocol_version_none_uses_legacy_info(self):
        """protocol_version=None falls back to legacy info parameter."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            generate_receiver_keypair,
            derive_shared_secret,
        )

        sender_keys = generate_ephemeral_keypair()
        _, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        password = "password123"

        # Without protocol_version, should use the info parameter
        secret_legacy = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
            info=b"meow_forward_secrecy_v1",
        )
        # With protocol_version, should use bound info
        secret_bound = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
            protocol_version=3,
        )

        assert secret_legacy != secret_bound

    def test_protocol_version_deterministic(self):
        """Same protocol_version produces same key."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            generate_receiver_keypair,
            derive_shared_secret,
        )

        sender_keys = generate_ephemeral_keypair()
        _, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        password = "password123"

        s1 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
            protocol_version=3,
        )
        s2 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
            protocol_version=3,
        )

        assert s1 == s2


# ---------------------------------------------------------------------------
# FIX-D1: PQ HKDF salt (non-empty) and XOR combiner deprecation
# ---------------------------------------------------------------------------


class TestFixD1PQHKDFSalt:
    """D1: pq_hybrid.py uses ephemeral public key as HKDF salt."""

    def test_hybrid_encapsulate_decapsulate_roundtrip(self):
        """Encapsulate + decapsulate with the new salt still produces matching secrets."""
        from meow_decoder.pq_hybrid import (
            HybridKeyPair,
            hybrid_encapsulate,
            hybrid_decapsulate,
            LIBOQS_AVAILABLE,
        )

        if not LIBOQS_AVAILABLE:
            pytest.skip("liboqs not available")

        keypair = HybridKeyPair(use_pq=True)

        from cryptography.hazmat.primitives import serialization

        receiver_classical_public = keypair.classical_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        receiver_pq_public = keypair.pq_public

        shared_enc, eph_pub, pq_ct, _ = hybrid_encapsulate(
            receiver_classical_public, receiver_pq_public
        )
        shared_dec = hybrid_decapsulate(eph_pub, pq_ct, keypair)

        assert shared_enc == shared_dec
        assert len(shared_enc) == 32

    def test_classical_only_roundtrip(self):
        """Classical-only mode (no PQ) still works with the salt fix."""
        from meow_decoder.pq_hybrid import (
            HybridKeyPair,
            hybrid_encapsulate,
            hybrid_decapsulate,
        )
        from cryptography.hazmat.primitives import serialization

        keypair = HybridKeyPair(use_pq=False)

        receiver_classical_public = keypair.classical_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        shared_enc, eph_pub, _, _ = hybrid_encapsulate(
            receiver_classical_public, receiver_pq_public=None
        )
        shared_dec = hybrid_decapsulate(eph_pub, None, keypair)

        assert shared_enc == shared_dec
        assert len(shared_enc) == 32


class TestFixD1XORCombinerDeprecation:
    """D1: pq_crypto_real.py emits DeprecationWarning on import."""

    def test_pq_crypto_real_deprecation_warning(self):
        """Importing pq_crypto_real raises DeprecationWarning."""
        import importlib
        import sys

        # Remove from cache to trigger fresh import
        mod_name = "meow_decoder.pq_crypto_real"
        if mod_name in sys.modules:
            del sys.modules[mod_name]

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            importlib.import_module(mod_name)
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) >= 1
            assert "deprecated" in str(deprecation_warnings[0].message).lower()
            assert "XOR" in str(deprecation_warnings[0].message)


# ---------------------------------------------------------------------------
# FIX-E1: Frame MAC fail-closed
# ---------------------------------------------------------------------------


class TestFixE1FrameMACFailClosed:
    """E1: Invalid frame MAC now raises ValueError instead of silently disabling."""

    def test_frame_mac_invalid_raises_error(self, tmp_path, monkeypatch):
        """When manifest frame MAC is invalid, decode_gif raises ValueError."""
        from PIL import Image
        from meow_decoder.crypto import Manifest, pack_manifest
        from meow_decoder.fountain import Droplet, pack_droplet

        # Build a minimal manifest
        plaintext = b"plaintext"
        import hashlib
        import zlib

        comp = zlib.compress(plaintext)
        sha = hashlib.sha256(plaintext).digest()
        manifest = Manifest(
            salt=b"\x00" * 16,
            nonce=b"\x00" * 12,
            orig_len=len(plaintext),
            comp_len=len(comp),
            cipher_len=len(comp) + 16,
            sha256=sha,
            block_size=800,
            k_blocks=1,
            hmac=b"\x00" * 32,
        )
        manifest_bytes = pack_manifest(manifest)
        # Prepend 8-byte fake MAC to trigger frame MAC mode
        manifest_with_mac = b"\x00" * 8 + manifest_bytes

        droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
        droplet_bytes = pack_droplet(droplet)

        # Stub out dependencies
        monkeypatch.setattr(
            decode_mod,
            "GIFDecoder",
            lambda: _DummyGIFDecoder(
                frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]
            ),
        )
        monkeypatch.setattr(
            decode_mod,
            "QRCodeReader",
            lambda preprocessing=None: _SequenceQRCodeReader([manifest_with_mac, droplet_bytes]),
        )
        monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
        monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
        monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

        import meow_decoder.frame_mac as frame_mac

        def _invalid_manifest(*args, **kwargs):
            return (False, b"")

        monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", _invalid_manifest)

        out_path = tmp_path / "out.bin"

        # FIX-E1: Should now raise ValueError instead of succeeding
        with pytest.raises((ValueError, RuntimeError), match="[Ff]rame MAC"):
            decode_mod.decode_gif(
                tmp_path / "in.gif",
                out_path,
                password="password123",
                verbose=True,
            )


# ---------------------------------------------------------------------------
# FIX-D3: PQ downgrade error message
# ---------------------------------------------------------------------------


class TestFixD3PQDowngradeMessage:
    """D3: Better error message when PQ ciphertext is missing in FS mode."""

    def test_pq_downgrade_hint_in_error(self):
        """When FS mode decryption fails with no pq_ciphertext, error mentions downgrade."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

        plaintext = b"test pq downgrade"
        password = "password123"
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(plaintext, password)

        # Simulate: ephemeral_public_key present (FS mode) but no pq_ciphertext
        # Use a wrong password to trigger decryption failure
        with pytest.raises(RuntimeError, match="[Pp]ost-quantum|PQ downgrade"):
            decrypt_to_raw(
                cipher,
                "wrong_password",
                salt,
                nonce,
                orig_len=len(plaintext),
                comp_len=len(comp),
                sha256=sha,
                ephemeral_public_key=b"\x00" * 32,  # Fake FS key
                receiver_private_key=b"\x00" * 32,  # Fake receiver
                pq_ciphertext=None,  # No PQ = potential downgrade
            )


# ---------------------------------------------------------------------------
# Helpers (imported by test_decode_gif.py style tests)
# ---------------------------------------------------------------------------
import meow_decoder.decode_gif as decode_mod
from PIL import Image


class _DummyGIFDecoder:
    def __init__(self, frames=None):
        if frames is None:
            frames = [Image.new("RGB", (64, 64))]
        self._frames = frames

    def extract_frames(self, input_path):
        return list(self._frames)


class _SequenceQRCodeReader:
    def __init__(self, sequence):
        self._sequence = list(sequence)

    def read_image(self, frame):
        if self._sequence:
            return [self._sequence.pop(0)]
        return []


class _DummyFountainDecoder:
    def __init__(self, *args, **kwargs):
        self.decoded_count = 1
        self.k_blocks = 1

    def add_droplet(self, *args, **kwargs):
        return True

    def is_complete(self):
        return True

    def get_data(self, *args, **kwargs):
        return b"\x00" * 8
