"""
Critical Invariants Tests — Part 1 of 3

TestCriticalInvariants: fundamental security properties that MUST NEVER be violated.
Runs in CI batch 1 in parallel with test_invariants_fail_closed.py (batch 2)
and test_invariants_regressions.py (batch 3).
"""

from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
from meow_decoder.config import EncodingConfig
from meow_decoder.decode_gif import decode_gif
from meow_decoder.encode import encode_file
from pathlib import Path
import tempfile
import secrets
import pytest

pytestmark = [pytest.mark.security, pytest.mark.slow]


class TestCriticalInvariants:
    """Tests that verify security invariants that must NEVER be violated."""

    def test_invariant_tampered_data_rejected(self, tmp_path):
        """
        INVARIANT: Tampered ciphertext MUST be rejected.

        Critical: If this fails, attackers can modify encrypted data.
        """
        data = b"Critical secret data"
        password = "password"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        tampered_cipher = bytearray(cipher)
        tampered_cipher[0] ^= 0x01

        with pytest.raises(Exception):
            decrypt_to_raw(
                bytes(tampered_cipher),
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    def test_invariant_wrong_password_rejected(self, tmp_path):
        """
        INVARIANT: Wrong password MUST be rejected.

        Critical: If this fails, password protection is broken.
        """
        input_file = tmp_path / "secret.txt"
        input_file.write_text("Secret")

        gif_file = tmp_path / "secret.gif"
        output_file = tmp_path / "output.txt"

        encode_file(input_file, gif_file, "correct_password")

        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, "wrong_password")

    def test_invariant_nonce_never_reused(self):
        """
        INVARIANT: Nonces MUST NEVER be reused.

        Critical: Nonce reuse breaks AES-GCM security completely.
        """
        data = b"Test"
        password = "password"

        nonces = set()
        for _ in range(5):
            _, _, _, nonce, _, _, _ = encrypt_file_bytes(data, password, None, None)
            assert nonce not in nonces, f"CRITICAL: Nonce reused! {nonce.hex()}"
            nonces.add(nonce)

    def test_invariant_aad_modification_rejected(self):
        """
        INVARIANT: AAD tampering MUST be detected.

        Critical: AAD protects metadata integrity.
        """
        data = b"Data"
        password = "password"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(data) + 1,  # TAMPERED
                comp_len=len(comp),
                sha256=sha,
            )

    def test_invariant_partial_data_rejected(self, tmp_path):
        """
        INVARIANT: Incomplete fountain decode MUST fail.

        Critical: Prevents returning partial/corrupted data.
        """
        from meow_decoder.fountain import FountainEncoder, FountainDecoder

        data = b"Important data" * 100
        block_size = 32
        k_blocks = (len(data) + block_size - 1) // block_size

        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, len(data))

        for _ in range(k_blocks // 2):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)

        assert not decoder.is_complete()

        with pytest.raises(RuntimeError, match="Decoding incomplete"):
            decoder.get_data()

    def test_invariant_roundtrip_preserves_data(self, tmp_path):
        """
        INVARIANT: Roundtrip MUST preserve data exactly.

        Critical: Data corruption is unacceptable.
        """
        pytest.importorskip("cv2")
        test_cases = [
            b"",
            b"X",
            b"Hello, World!",
            secrets.token_bytes(200),
            b"\x00" * 100,
            b"\xff" * 100,
        ]

        for i, original_data in enumerate(test_cases):
            if len(original_data) == 0:
                continue

            input_file = tmp_path / f"test_{i}.dat"
            input_file.write_bytes(original_data)

            gif_file = tmp_path / f"test_{i}.gif"
            output_file = tmp_path / f"output_{i}.dat"

            config = EncodingConfig(block_size=512, redundancy=10.0)
            encode_file(input_file, gif_file, "password", config=config)
            decode_gif(gif_file, output_file, "password")

            recovered_data = output_file.read_bytes()
            assert (
                recovered_data == original_data
            ), f"Data corruption in test case {i}: {len(original_data)} bytes"
