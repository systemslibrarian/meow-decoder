#!/usr/bin/env python3
"""
Tests for OPUS-AUDIT.md security fixes.

Validates that all FAIL findings from the hostile crypto audit have been
properly remediated. Each test is named after the audit finding ID.
"""

from PIL import Image
import meow_decoder.decode_gif as decode_mod
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
        """FIX-A1 v2: synthetic_iv_mode skips nonce-reuse error (SIV property)."""
        import logging
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache

        _nonce_reuse_cache.clear()

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        # First call registers normally
        _register_nonce_use(key, nonce, synthetic_iv_mode=True)
        # Second call with same key+nonce should NOT raise in synthetic_iv_mode
        # because SIV property means same plaintext → same nonce intentionally
        _register_nonce_use(key, nonce, synthetic_iv_mode=True)

        # But without synthetic_iv_mode, reuse IS detected
        _nonce_reuse_cache.clear()
        _register_nonce_use(key, nonce)
        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(key, nonce)

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

        receiver_classical_public, receiver_pq_public = keypair.export_public_keys()

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

        keypair = HybridKeyPair(use_pq=False)

        receiver_classical_public, _ = keypair.export_public_keys()

        shared_enc, eph_pub, _, _ = hybrid_encapsulate(
            receiver_classical_public, receiver_pq_public=None
        )
        shared_dec = hybrid_decapsulate(eph_pub, None, keypair)

        assert shared_enc == shared_dec
        assert len(shared_enc) == 32


class TestFixD1XORCombinerDeprecation:
    """D1: pq_crypto_real.py is hard-disabled (RuntimeError on import).
    Module quarantined to legacy_py/ — no longer in production path."""

    def test_pq_crypto_real_removed_from_production(self):
        """FIX-D1: pq_crypto_real is no longer importable from meow_decoder/."""
        import importlib
        import sys

        mod_name = "meow_decoder.pq_crypto_real"
        if mod_name in sys.modules:
            del sys.modules[mod_name]

        with pytest.raises((ImportError, ModuleNotFoundError)):
            importlib.import_module(mod_name)

    def test_pq_crypto_real_legacy_raises_runtime_error(self):
        """FIX-D1 v2: legacy_py/pq_crypto_real raises RuntimeError."""
        import importlib
        import sys

        mod_name = "legacy_py.pq_crypto_real"
        if mod_name in sys.modules:
            del sys.modules[mod_name]

        with pytest.raises(RuntimeError, match="DISABLED.*insecure XOR"):
            importlib.import_module(mod_name)


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


# ===========================================================================
# AUDIT v2 FIXES — Second hostile audit remediation
# ===========================================================================


class TestV2FixA1SyntheticIV:
    """A1 v2: Synthetic IV mode (SIV property) for precomputed_key."""

    def test_synthetic_iv_mode_allows_nonce_reuse(self):
        """Same key+nonce in synthetic_iv_mode does NOT raise."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache

        _nonce_reuse_cache.clear()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        _register_nonce_use(key, nonce, synthetic_iv_mode=True)
        # Should NOT raise — SIV property means same plaintext → same nonce
        _register_nonce_use(key, nonce, synthetic_iv_mode=True)
        _nonce_reuse_cache.clear()

    def test_non_synthetic_mode_rejects_nonce_reuse(self):
        """Same key+nonce without synthetic_iv_mode raises RuntimeError."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache

        _nonce_reuse_cache.clear()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        _register_nonce_use(key, nonce, synthetic_iv_mode=False)
        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(key, nonce, synthetic_iv_mode=False)
        _nonce_reuse_cache.clear()

    def test_synthetic_iv_deterministic(self):
        """Precomputed key + same plaintext (no padding) → same synthetic nonce."""
        from meow_decoder.crypto import encrypt_file_bytes, _nonce_reuse_cache

        _nonce_reuse_cache.clear()
        plaintext = b"deterministic nonce test data!!"
        password = "password12345678"
        precomputed_key = secrets.token_bytes(32)

        _, _, salt1, nonce1, _, _, _ = encrypt_file_bytes(
            plaintext,
            password,
            precomputed_key=precomputed_key,
            use_length_padding=False,
        )
        _nonce_reuse_cache.clear()
        _, _, _, nonce2, _, _, _ = encrypt_file_bytes(
            plaintext,
            password,
            precomputed_key=precomputed_key,
            precomputed_salt=salt1,
            use_length_padding=False,
        )
        # Same key + same plaintext + same salt + no random padding → same nonce (SIV)
        assert nonce1 == nonce2, "Synthetic nonce should be deterministic"
        _nonce_reuse_cache.clear()


class TestV2FixC3TranscriptBinding:
    """C3 v2: Full transcript binding in derive_shared_secret."""

    def test_different_mode_flags_yield_different_keys(self):
        """Mode flag change → different derived key."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            derive_shared_secret,
            deserialize_public_key,
        )

        sender = generate_ephemeral_keypair()
        receiver = generate_ephemeral_keypair()
        password = "password12345678"
        salt = secrets.token_bytes(16)

        receiver_pub = deserialize_public_key(receiver.ephemeral_public)

        key_fs = derive_shared_secret(
            sender.ephemeral_private,
            receiver_pub,
            password,
            salt,
            protocol_version=3,
            mode_flags=0x01,
        )
        key_pq = derive_shared_secret(
            sender.ephemeral_private,
            receiver_pub,
            password,
            salt,
            protocol_version=3,
            mode_flags=0x03,
        )
        assert key_fs != key_pq, "Different mode flags must yield different keys"

    def test_pq_ciphertext_hash_changes_key(self):
        """Binding PQ ciphertext hash changes the derived key."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            derive_shared_secret,
            deserialize_public_key,
        )
        import hashlib

        sender = generate_ephemeral_keypair()
        receiver = generate_ephemeral_keypair()
        password = "password12345678"
        salt = secrets.token_bytes(16)

        receiver_pub = deserialize_public_key(receiver.ephemeral_public)

        pq_hash = hashlib.sha256(b"fake_pq_ciphertext").digest()

        key_without = derive_shared_secret(
            sender.ephemeral_private,
            receiver_pub,
            password,
            salt,
            protocol_version=3,
            mode_flags=0x03,
        )
        key_with = derive_shared_secret(
            sender.ephemeral_private,
            receiver_pub,
            password,
            salt,
            protocol_version=3,
            mode_flags=0x03,
            pq_ciphertext_hash=pq_hash,
        )
        assert key_without != key_with, "PQ ciphertext hash must change key"

    def test_ephemeral_public_binding(self):
        """Binding ephemeral public key changes the derived key."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            derive_shared_secret,
            deserialize_public_key,
        )

        sender = generate_ephemeral_keypair()
        receiver = generate_ephemeral_keypair()
        password = "password12345678"
        salt = secrets.token_bytes(16)

        receiver_pub = deserialize_public_key(receiver.ephemeral_public)

        key_without_eph = derive_shared_secret(
            sender.ephemeral_private,
            receiver_pub,
            password,
            salt,
            protocol_version=3,
            mode_flags=0x01,
        )
        key_with_eph = derive_shared_secret(
            sender.ephemeral_private,
            receiver_pub,
            password,
            salt,
            protocol_version=3,
            mode_flags=0x01,
            ephemeral_public=sender.ephemeral_public,
        )
        assert key_without_eph != key_with_eph, "Ephemeral public binding must change key"


class TestV2FixD3ManifestModeByte:
    """D3 v2: Explicit mode byte in manifest."""

    def test_mode_byte_in_manifest_dataclass(self):
        """Manifest has mode_byte field."""
        from meow_decoder.crypto import Manifest

        m = Manifest(
            salt=b"\x00" * 16,
            nonce=b"\x00" * 12,
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=b"\x00" * 32,
            block_size=800,
            k_blocks=1,
            hmac=b"\x00" * 32,
            mode_byte=0x03,
        )
        assert m.mode_byte == 0x03

    def test_pack_unpack_roundtrip_with_mode_byte(self):
        """Manifest with mode_byte roundtrips through pack/unpack."""
        from meow_decoder.crypto import (
            Manifest,
            pack_manifest,
            unpack_manifest,
            MODE_MEOW3,
        )

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=800,
            k_blocks=1,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            mode_byte=MODE_MEOW3,
        )
        packed = pack_manifest(m)
        unpacked = unpack_manifest(packed)
        assert unpacked.mode_byte == MODE_MEOW3
        assert unpacked.salt == m.salt
        assert unpacked.nonce == m.nonce
        assert unpacked.ephemeral_public_key == m.ephemeral_public_key

    def test_legacy_manifest_has_mode_legacy(self):
        """Legacy manifest (mode_byte=0) roundtrips correctly."""
        from meow_decoder.crypto import (
            Manifest,
            pack_manifest,
            unpack_manifest,
            MODE_LEGACY,
        )

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=800,
            k_blocks=1,
            hmac=secrets.token_bytes(32),
        )
        packed = pack_manifest(m)
        assert len(packed) == 115  # Legacy size
        unpacked = unpack_manifest(packed)
        assert unpacked.mode_byte == MODE_LEGACY

    def test_new_manifest_is_one_byte_longer(self):
        """New manifest with mode_byte is 1 byte longer than legacy."""
        from meow_decoder.crypto import (
            Manifest,
            pack_manifest,
            MODE_MEOW3,
        )

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=800,
            k_blocks=1,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            mode_byte=MODE_MEOW3,
        )
        packed = pack_manifest(m)
        assert len(packed) == 148  # 147 + 1 mode byte

    def test_mode_byte_mismatch_rejected(self):
        """Mode byte saying MEOW2 but with ephemeral key → rejected."""
        from meow_decoder.crypto import (
            Manifest,
            pack_manifest,
            unpack_manifest,
            MODE_MEOW2,
        )

        # Build a manifest claiming MEOW2 but including an ephemeral key
        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=800,
            k_blocks=1,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            mode_byte=MODE_MEOW2,
        )
        packed = pack_manifest(m)
        with pytest.raises(ValueError, match="MEOW2.*ephemeral"):
            unpack_manifest(packed)

    def test_invalid_mode_byte_rejected(self):
        """Invalid mode byte value → rejected."""
        from meow_decoder.crypto import (
            Manifest,
            pack_manifest,
            unpack_manifest,
            MODE_MEOW3,
        )

        # Manually craft a manifest with invalid mode byte
        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=800,
            k_blocks=1,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            mode_byte=MODE_MEOW3,
        )
        packed = bytearray(pack_manifest(m))
        packed[5] = 0xFF  # Invalid mode byte
        with pytest.raises(ValueError, match="Invalid manifest mode byte"):
            unpack_manifest(bytes(packed))

    def test_mode_byte_in_aad(self):
        """Mode byte is included in AAD when non-zero."""
        from meow_decoder.crypto import build_canonical_aad, MODE_MEOW3

        salt = secrets.token_bytes(16)
        sha = secrets.token_bytes(32)

        aad_legacy = build_canonical_aad(100, 80, salt, sha, b"MEOW3")
        aad_with_mode = build_canonical_aad(100, 80, salt, sha, b"MEOW3", mode_byte=MODE_MEOW3)
        assert aad_legacy != aad_with_mode, "Mode byte must change AAD"
        assert len(aad_with_mode) == len(aad_legacy) + 1


class TestV2FixD1HardDisable:
    """D1 v2: pq_crypto_real is hard-disabled and quarantined to legacy_py/."""

    def test_removed_from_production(self):
        """pq_crypto_real no longer importable from meow_decoder/."""
        import importlib
        import sys

        mod_name = "meow_decoder.pq_crypto_real"
        if mod_name in sys.modules:
            del sys.modules[mod_name]

        with pytest.raises((ImportError, ModuleNotFoundError)):
            importlib.import_module(mod_name)

    def test_legacy_import_raises_runtime_error(self):
        """legacy_py/pq_crypto_real raises RuntimeError."""
        import importlib
        import sys

        mod_name = "legacy_py.pq_crypto_real"
        if mod_name in sys.modules:
            del sys.modules[mod_name]

        with pytest.raises(RuntimeError, match="DISABLED.*insecure XOR"):
            importlib.import_module(mod_name)

    def test_pq_hybrid_still_works(self):
        """pq_hybrid.py (the correct module) still imports fine."""
        from meow_decoder.pq_hybrid import check_pq_available

        available, msg = check_pq_available()
        # Should return a result (available depends on liboqs installation)
        assert isinstance(available, bool)
        assert isinstance(msg, str)
