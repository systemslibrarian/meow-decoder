"""
Tests to boost coverage for schrodinger_decode.py and schrodinger_encode.py.
Focus on direct data-level testing to avoid QR/GIF roundtrip issues.
"""
import os
import sys
import struct
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

os.environ.setdefault('MEOW_TEST_MODE', '1')


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
        data = b"MEOW" + struct.pack('BB', 0x01, 0x00) + b"\x00" * 400
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
            real_data, decoy_data,
            "real_password_123", "decoy_password_456",
            block_size=256
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
            real_data, decoy_data,
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
            real_data, decoy_data,
            "reality_a_password",
            "reality_b_password",
            block_size=256
        )

        result = schrodinger_decode_data(superposition, manifest, "reality_a_password")
        assert result == real_data

    def test_decode_data_reality_b(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real_data = b"CONFIDENTIAL: secret recipe " * 40
        decoy_data = b"RECIPE: grandma's cookies ok " * 40

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            "real_pass_long_enough",
            "decoy_pass_long_enough",
            block_size=256
        )

        result = schrodinger_decode_data(superposition, manifest, "decoy_pass_long_enough")
        assert result == decoy_data

    def test_decode_data_wrong_password(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real_data = b"Secret stuff! " * 40
        decoy_data = b"Boring stuff! " * 40

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            "correct_password_a",
            "correct_password_b",
            block_size=256
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
        assert stats['gif_size'] > 0
        assert stats['blocks'] > 0
        assert stats['qr_frames'] > 0
        assert stats['real_size'] == len(b"This is my secret data! " * 100)

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
        assert stats['gif_size'] > 0

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
            'prog',
            '--real', str(real_file),
            '-o', str(output),
            '--real-password', 'cli_real_password_1',
            '--decoy-password', 'cli_decoy_password_1',
            '--block-size', '256',
            '--redundancy', '1.5',
        ]

        with patch.object(sys, 'argv', test_args):
            rc = main()

        assert rc == 0
        assert output.exists()

    def test_main_error(self, tmp_path):
        from meow_decoder.schrodinger_encode import main

        test_args = [
            'prog',
            '--real', str(tmp_path / "nonexistent.txt"),
            '-o', str(tmp_path / "out.gif"),
            '--real-password', 'password_long_1',
            '--decoy-password', 'password_long_2',
        ]

        with patch.object(sys, 'argv', test_args):
            rc = main()
        assert rc == 1


class TestSchrodingerDecodeMain:
    """Test CLI main() for schrodinger_decode."""

    def test_main_error(self, tmp_path):
        from meow_decoder.schrodinger_decode import main

        test_args = [
            'prog',
            '-i', str(tmp_path / "nonexistent.gif"),
            '-o', str(tmp_path / "out.txt"),
            '-p', 'some_password_1',
        ]

        with patch.object(sys, 'argv', test_args):
            rc = main()
        assert rc == 1

    def test_decode_file_no_qr_frames(self, tmp_path):
        """schrodinger_decode_file raises if no QR codes found."""
        from meow_decoder.schrodinger_decode import schrodinger_decode_file
        import numpy as np

        with patch('meow_decoder.gif_handler.GIFDecoder') as MockDecoder:
            mock_instance = MockDecoder.return_value
            mock_instance.extract_frames.return_value = [
                np.ones((100, 100), dtype=np.uint8) * 255
            ]

            with patch('meow_decoder.qr_code.QRCodeReader') as MockReader:
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

        with patch('meow_decoder.gif_handler.GIFDecoder') as MockDecoder:
            import numpy as np
            mock_instance = MockDecoder.return_value
            mock_instance.extract_frames.return_value = [
                np.ones((100, 100), dtype=np.uint8) * 255
            ]

            with patch('meow_decoder.qr_code.QRCodeReader') as MockReader:
                mock_reader = MockReader.return_value
                mock_reader.read_image.return_value = [b"BARK" + b"\x00" * 200]

                with pytest.raises(ValueError, match="Failed to parse manifest"):
                    schrodinger_decode_file(
                        input_gif=tmp_path / "fake.gif",
                        output=tmp_path / "out.txt",
                        password="test_password_1",
                        verbose=False,
                    )
