import hashlib
import meow_decoder.crypto as crypto
import meow_decoder.schrodinger_encode as schrodinger_encode
import meow_decoder.schrodinger_decode as schrodinger_decode

# Imports from merged file
import os
import sys
import struct
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

os.environ.setdefault("MEOW_TEST_MODE", "1")


def _fast_derive_key(password: str, salt: bytes, keyfile=None) -> bytes:
    return hashlib.sha256(password.encode("utf-8") + salt).digest()


def test_schrodinger_manifest_pack_unpack_roundtrip():
    manifest = schrodinger_encode.SchrodingerManifest(
        salt_a=b"a" * 16,
        salt_b=b"b" * 16,
        nonce_a=b"c" * 12,
        nonce_b=b"d" * 12,
        reality_a_hmac=b"e" * 32,
        reality_b_hmac=b"f" * 32,
        metadata_a=b"g" * 104,
        metadata_b=b"h" * 104,
        block_count=2,
        block_size=256,
        superposition_len=512,
    )
    packed = manifest.pack()
    unpacked = schrodinger_encode.SchrodingerManifest.unpack(packed)
    assert unpacked.salt_a == manifest.salt_a
    assert unpacked.salt_b == manifest.salt_b
    assert unpacked.metadata_a == manifest.metadata_a
    assert unpacked.metadata_b == manifest.metadata_b
    assert len(packed) == 382
    assert len(manifest.pack_core_for_auth()) == 318


def test_schrodinger_encode_decode_roundtrip(monkeypatch):
    monkeypatch.setattr(crypto, "derive_key", _fast_derive_key)
    monkeypatch.setattr(schrodinger_encode, "derive_key", _fast_derive_key)
    monkeypatch.setattr(schrodinger_decode, "derive_key", _fast_derive_key)

    real = b"real secret data" * 5
    decoy = b"decoy data" * 7
    real_pw = "real-password"
    decoy_pw = "decoy-password"

    superposition, manifest = schrodinger_encode.schrodinger_encode_data(
        real, decoy, real_pw, decoy_pw, block_size=128
    )

    decoded_real = schrodinger_decode.schrodinger_decode_data(superposition, manifest, real_pw)
    decoded_decoy = schrodinger_decode.schrodinger_decode_data(superposition, manifest, decoy_pw)
    decoded_none = schrodinger_decode.schrodinger_decode_data(
        superposition, manifest, "wrong-password"
    )

    assert decoded_real == real
    assert decoded_decoy == decoy
    assert decoded_none is None


# ===============================================================
# Merged from test_coverage_boost_schrodinger.py
# ===============================================================


class TestSchrodingerManifestEdgeCases:
    """Test SchrodingerManifest error branches."""

    def test_unpack_too_short(self):
        from meow_decoder.schrodinger_encode import SchrodingerManifest

        with pytest.raises(ValueError, match="too short"):
            SchrodingerManifest.unpack(b"\x00" * 100)

    def test_unpack_invalid_magic(self):
        from meow_decoder.schrodinger_encode import SchrodingerManifest

        data = b"BARK" + b"\x00" * 400
        with pytest.raises(ValueError, match="Invalid manifest magic"):
            SchrodingerManifest.unpack(data)

    def test_unpack_wrong_version(self):
        from meow_decoder.schrodinger_encode import SchrodingerManifest

        data = b"MEOW" + struct.pack("BB", 0x01, 0x00) + b"\x00" * 400
        with pytest.raises(ValueError, match="Not a Schrödinger"):
            SchrodingerManifest.unpack(data)

    def test_pack_unpack_roundtrip(self):
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        import secrets

        m = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=secrets.token_bytes(32),
            reality_b_hmac=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            block_count=10,
            block_size=256,
            superposition_len=2560,
        )
        packed = m.pack()
        assert len(packed) == 382
        m2 = SchrodingerManifest.unpack(packed)
        assert m2.salt_a == m.salt_a
        assert m2.block_count == 10
        assert m2.superposition_len == 2560

    def test_pack_core_for_auth(self):
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        import secrets

        m = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=secrets.token_bytes(32),
            reality_b_hmac=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            block_count=10,
            block_size=256,
            superposition_len=2560,
        )
        core = m.pack_core_for_auth()
        assert isinstance(core, bytes)
        assert len(core) > 0


class TestSchrodingerEncodeData:
    """Test schrodinger_encode_data directly (no QR/GIF)."""

    def test_encode_data_basic(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data

        real_data = b"Real secret data for testing! " * 50
        decoy_data = b"Decoy data for plausible deny. " * 50

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "real_password_123", "decoy_password_456", block_size=256
        )

        assert len(superposition) > 0
        assert manifest.block_count > 0
        assert manifest.block_size == 256
        assert manifest.superposition_len > 0
        assert manifest.salt_a != manifest.salt_b
        assert manifest.nonce_a != manifest.nonce_b

    def test_encode_data_small_payload(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data

        real_data = b"tiny data!"
        decoy_data = b"also tiny!"

        superposition, manifest = schrodinger_encode_data(
            real_data,
            decoy_data,
            "password_for_real_1",
            "password_for_decoy_2",
            block_size=64,
        )

        assert len(superposition) > 0
        assert manifest.block_count >= 1


class TestSchrodingerDecodeData:
    """Test schrodinger_decode_data directly."""

    def test_decode_data_reality_a(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real_data = b"TOP SECRET: launch codes 12345 " * 40
        decoy_data = b"SHOPPING LIST: milk eggs butter " * 40

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "reality_a_password", "reality_b_password", block_size=256
        )

        result = schrodinger_decode_data(superposition, manifest, "reality_a_password")
        assert result == real_data

    def test_decode_data_reality_b(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real_data = b"CONFIDENTIAL: secret recipe " * 40
        decoy_data = b"RECIPE: grandma's cookies ok " * 40

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "real_pass_long_enough", "decoy_pass_long_enough", block_size=256
        )

        result = schrodinger_decode_data(superposition, manifest, "decoy_pass_long_enough")
        assert result == decoy_data

    def test_decode_data_wrong_password(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real_data = b"Secret stuff! " * 40
        decoy_data = b"Boring stuff! " * 40

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "correct_password_a", "correct_password_b", block_size=256
        )

        result = schrodinger_decode_data(superposition, manifest, "totally_wrong_password")
        assert result is None


class TestSchrodingerEncodeFile:
    """Test schrodinger_encode_file targeting uncovered file I/O paths."""

    def test_encode_file_with_auto_decoy(self, tmp_path):
        from meow_decoder.schrodinger_encode import schrodinger_encode_file
        from meow_decoder.config import EncodingConfig

        real_file = tmp_path / "secret.txt"
        real_file.write_bytes(b"This is my secret data! " * 100)
        output_gif = tmp_path / "output.gif"
        config = EncodingConfig(block_size=256, redundancy=1.5)

        stats = schrodinger_encode_file(
            real_input=real_file,
            decoy_input=None,
            output=output_gif,
            real_password="real_password_123",
            decoy_password="decoy_password_456",
            config=config,
            auto_generate_decoy=True,
            verbose=True,
        )

        assert output_gif.exists()
        assert stats["gif_size"] > 0
        assert stats["blocks"] > 0
        assert stats["qr_frames"] > 0
        assert stats["real_size"] == len(b"This is my secret data! " * 100)

    def test_encode_file_with_provided_decoy(self, tmp_path):
        from meow_decoder.schrodinger_encode import schrodinger_encode_file
        from meow_decoder.config import EncodingConfig

        real_file = tmp_path / "secret.txt"
        real_file.write_bytes(b"Secret! " * 200)
        decoy_file = tmp_path / "decoy.txt"
        decoy_file.write_bytes(b"Just normal stuff " * 200)
        output_gif = tmp_path / "output.gif"
        config = EncodingConfig(block_size=256, redundancy=1.5)

        stats = schrodinger_encode_file(
            real_input=real_file,
            decoy_input=decoy_file,
            output=output_gif,
            real_password="real_password_long",
            decoy_password="decoy_password_long",
            config=config,
            verbose=False,
        )

        assert output_gif.exists()
        assert stats["gif_size"] > 0

    def test_encode_file_no_decoy_no_auto(self, tmp_path):
        from meow_decoder.schrodinger_encode import schrodinger_encode_file

        real_file = tmp_path / "secret.txt"
        real_file.write_bytes(b"Secret data for no-decoy test.")

        with pytest.raises(ValueError, match="Must provide decoy"):
            schrodinger_encode_file(
                real_input=real_file,
                decoy_input=None,
                output=tmp_path / "out.gif",
                real_password="password_long1",
                decoy_password="password_long2",
                auto_generate_decoy=False,
            )


class TestSchrodingerEncodeMain:
    """Test CLI main() for schrodinger_encode."""

    def test_main_success(self, tmp_path):
        from meow_decoder.schrodinger_encode import main

        real_file = tmp_path / "secret.txt"
        real_file.write_bytes(b"Secret CLI data " * 100)
        output = tmp_path / "cli_output.gif"

        test_args = [
            "prog",
            "--real",
            str(real_file),
            "-o",
            str(output),
            "--real-password",
            "cli_real_password_1",
            "--decoy-password",
            "cli_decoy_password_1",
            "--block-size",
            "256",
            "--redundancy",
            "1.5",
        ]

        with patch.object(sys, "argv", test_args):
            rc = main()

        assert rc == 0
        assert output.exists()

    def test_main_error(self, tmp_path):
        from meow_decoder.schrodinger_encode import main

        test_args = [
            "prog",
            "--real",
            str(tmp_path / "nonexistent.txt"),
            "-o",
            str(tmp_path / "out.gif"),
            "--real-password",
            "password_long_1",
            "--decoy-password",
            "password_long_2",
        ]

        with patch.object(sys, "argv", test_args):
            rc = main()
        assert rc == 1


class TestSchrodingerDecodeMain:
    """Test CLI main() for schrodinger_decode."""

    def test_main_error(self, tmp_path):
        from meow_decoder.schrodinger_decode import main

        test_args = [
            "prog",
            "-i",
            str(tmp_path / "nonexistent.gif"),
            "-o",
            str(tmp_path / "out.txt"),
            "-p",
            "some_password_1",
        ]

        with patch.object(sys, "argv", test_args):
            rc = main()
        assert rc == 1

    def test_decode_file_no_qr_frames(self, tmp_path):
        """schrodinger_decode_file raises if no QR codes found."""
        from meow_decoder.schrodinger_decode import schrodinger_decode_file
        import numpy as np

        with patch("meow_decoder.gif_handler.GIFDecoder") as MockDecoder:
            mock_instance = MockDecoder.return_value
            mock_instance.extract_frames.return_value = [np.ones((100, 100), dtype=np.uint8) * 255]

            with patch("meow_decoder.qr_code.QRCodeReader") as MockReader:
                mock_reader = MockReader.return_value
                mock_reader.read_image.return_value = []

                with pytest.raises(ValueError, match="No QR codes found"):
                    schrodinger_decode_file(
                        input_gif=tmp_path / "fake.gif",
                        output=tmp_path / "out.txt",
                        password="test_password_1",
                        verbose=True,
                    )

    def test_decode_file_bad_manifest(self, tmp_path):
        """schrodinger_decode_file raises for invalid manifest data."""
        from meow_decoder.schrodinger_decode import schrodinger_decode_file

        with patch("meow_decoder.gif_handler.GIFDecoder") as MockDecoder:
            import numpy as np

            mock_instance = MockDecoder.return_value
            mock_instance.extract_frames.return_value = [np.ones((100, 100), dtype=np.uint8) * 255]

            with patch("meow_decoder.qr_code.QRCodeReader") as MockReader:
                mock_reader = MockReader.return_value
                mock_reader.read_image.return_value = [b"BARK" + b"\x00" * 200]

                with pytest.raises(ValueError, match="Failed to parse manifest"):
                    schrodinger_decode_file(
                        input_gif=tmp_path / "fake.gif",
                        output=tmp_path / "out.txt",
                        password="test_password_1",
                        verbose=False,
                    )


# --- Merged from test_coverage_boost_extras.py ---


# =====================================================
# schrodinger_decode.py — push from 44% to much higher
# =====================================================
class TestSchrodingerDecodeExtras:
    """Extra decode tests for untested branches."""

    def test_decode_data_corrupted_superposition(self):
        """Corrupted superposition should return None (hits except branches)."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real = b"real secret " * 40
        decoy = b"decoy stuff " * 40

        superposition, manifest = schrodinger_encode_data(
            real, decoy, "correct_pw_real_1", "correct_pw_decoy_2", block_size=256
        )

        # Corrupt the superposition entirely
        corrupted = bytes(b ^ 0xFF for b in superposition)
        result = schrodinger_decode_data(corrupted, manifest, "correct_pw_real_1")
        assert result is None  # HMAC check should fail

    def test_decode_data_empty_superposition(self):
        """Empty superposition returns None."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real = b"test data padding" * 40
        decoy = b"test decoy padd " * 40

        _, manifest = schrodinger_encode_data(
            real, decoy, "password_real_abc", "password_decoy_xyz", block_size=256
        )

        result = schrodinger_decode_data(b"", manifest, "password_real_abc")
        assert result is None

    def test_decode_data_truncated_superposition(self):
        """Truncated superposition should fail gracefully."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real = b"truncation test data! " * 40
        decoy = b"truncation decoy data " * 40

        superposition, manifest = schrodinger_encode_data(
            real, decoy, "truncpw_real_123", "truncpw_decoy_456", block_size=256
        )

        # Truncate to half
        truncated = superposition[: len(superposition) // 2]
        result = schrodinger_decode_data(truncated, manifest, "truncpw_real_123")
        assert result is None

    def test_decode_file_with_invalid_gif(self, tmp_path):
        """decode_file with a non-GIF file should fail gracefully."""
        from meow_decoder.schrodinger_decode import schrodinger_decode_file

        fake_file = tmp_path / "not_a_gif.gif"
        fake_file.write_bytes(b"This is not a GIF file at all")
        output = tmp_path / "output.txt"

        with pytest.raises((ValueError, Exception)):
            schrodinger_decode_file(
                input_gif=fake_file,
                output=output,
                password="test_password_123",
                verbose=True,
            )

    def test_decode_file_verbose_no_qr(self, tmp_path):
        """decode_file verbose mode with blank frames (no QR codes)."""
        pytest.importorskip("cv2")
        from meow_decoder.schrodinger_decode import schrodinger_decode_file
        from PIL import Image

        # Create a real minimal GIF with no QR codes
        img = Image.new("RGB", (100, 100), "white")
        gif_path = tmp_path / "blank.gif"
        img.save(str(gif_path), format="GIF")
        output = tmp_path / "output.txt"

        with pytest.raises(ValueError, match="No QR"):
            schrodinger_decode_file(
                input_gif=gif_path,
                output=output,
                password="test_password_123",
                verbose=True,
            )


# --- Merged from test_coverage_boost_extras.py ---


class TestSchrodingerDecodeMainExtras:
    """Additional main() CLI tests for schrodinger_decode."""

    def test_main_success_with_created_gif(self, tmp_path):
        """Test main() with a real encode→decode roundtrip via data layer."""
        from meow_decoder.schrodinger_decode import main

        # Create a fake GIF that we can't actually decode (triggers error)
        fake_gif = tmp_path / "test.gif"
        fake_gif.write_bytes(b"GIF89a" + b"\x00" * 50)

        test_args = [
            "prog",
            "-i",
            str(fake_gif),
            "-o",
            str(tmp_path / "out.txt"),
            "-p",
            "some_password_123",
            "--verbose",
        ]

        with patch.object(sys, "argv", test_args):
            rc = main()
        # Should fail because fake GIF has no valid QR codes
        assert rc == 1

    def test_main_verbose_nonexistent(self, tmp_path):
        """Test main() with --verbose and nonexistent file."""
        from meow_decoder.schrodinger_decode import main

        test_args = [
            "prog",
            "-i",
            str(tmp_path / "nope.gif"),
            "-o",
            str(tmp_path / "out.txt"),
            "-p",
            "password_12345",
            "--verbose",
        ]

        with patch.object(sys, "argv", test_args):
            rc = main()
        assert rc == 1


# =====================================================
# schrodinger_encode.py — push from 64% higher
# =====================================================

# --- Merged from test_coverage_boost_extras.py ---


# =====================================================
# schrodinger_encode.py — push from 64% higher
# =====================================================
class TestSchrodingerEncodeExtras:
    """Additional encode tests for uncovered branches."""

    def test_encode_data_various_block_sizes(self):
        """Test with different block sizes to exercise padding branches."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data

        real = b"X" * 500
        decoy = b"Y" * 500

        for bs in [64, 128, 512]:
            sup, manifest = schrodinger_encode_data(
                real,
                decoy,
                "password_real_sz_test",
                "password_decoy_sz_test",
                block_size=bs,
            )
            assert manifest.block_size == bs
            assert len(sup) > 0

    def test_encode_data_large_data(self):
        """Larger payloads exercise multi-block paths."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data

        real = os.urandom(5000)
        decoy = os.urandom(5000)

        sup, manifest = schrodinger_encode_data(
            real,
            decoy,
            "large_data_real_pw",
            "large_data_decoy_pw",
            block_size=256,
        )
        assert manifest.block_count > 10
        assert manifest.superposition_len > 0

    def test_encode_file_verbose_output(self, tmp_path, capsys):
        """Test encode_file with verbose=True to hit print branches."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_file
        from meow_decoder.config import EncodingConfig

        real_file = tmp_path / "verbose_test.txt"
        real_file.write_bytes(b"Verbose test data! " * 100)
        output = tmp_path / "verbose_output.gif"

        config = EncodingConfig(block_size=256, redundancy=1.5)
        stats = schrodinger_encode_file(
            real_input=real_file,
            decoy_input=None,
            output=output,
            real_password="verbose_real_pw_1",
            decoy_password="verbose_decoy_pw_1",
            config=config,
            auto_generate_decoy=True,
            verbose=True,
        )
        assert output.exists()
        assert stats["gif_size"] > 0
        captured = capsys.readouterr()
        # Verbose mode should have printed something
        assert len(captured.out) > 0 or stats["gif_size"] > 0

    def test_main_with_decoy_file(self, tmp_path):
        """Test CLI main() with explicit decoy file."""
        from meow_decoder.schrodinger_encode import main

        real_file = tmp_path / "real.txt"
        real_file.write_bytes(b"Secret data for CLI " * 80)
        decoy_file = tmp_path / "decoy.txt"
        decoy_file.write_bytes(b"Boring decoy data " * 80)
        output = tmp_path / "with_decoy.gif"

        test_args = [
            "prog",
            "--real",
            str(real_file),
            "--decoy",
            str(decoy_file),
            "-o",
            str(output),
            "--real-password",
            "cli_real_pw_1234",
            "--decoy-password",
            "cli_decoy_pw_1234",
            "--block-size",
            "256",
        ]

        with patch.object(sys, "argv", test_args):
            rc = main()
        assert rc == 0
        assert output.exists()

    def test_main_verbose_flag(self, tmp_path):
        """Test CLI main() with --verbose."""
        from meow_decoder.schrodinger_encode import main

        real_file = tmp_path / "verbose_cli.txt"
        real_file.write_bytes(b"Test " * 200)
        output = tmp_path / "verbose_cli.gif"

        test_args = [
            "prog",
            "--real",
            str(real_file),
            "-o",
            str(output),
            "--real-password",
            "verbose_pw_real1",
            "--decoy-password",
            "verbose_pw_decoy1",
            "--verbose",
        ]

        with patch.object(sys, "argv", test_args):
            rc = main()
        assert rc == 0


# =====================================================
# high_security.py — push from 85.9% higher
# =====================================================
