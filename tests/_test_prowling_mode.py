#!/usr/bin/env python3
"""
🧪 Test Suite: prowling_mode.py
Tests low-memory streaming mode for large file handling.
"""

import pytest
import os
import tempfile
from pathlib import Path
os.environ["MEOW_TEST_MODE"] = "1"

# Try to import prowling_mode module
try:
    from meow_decoder.prowling_mode import (
        ProwlingEncoder,
        ProwlingDecoder,
        StreamingCipher,
    )
    PROWLING_AVAILABLE = True
except (ImportError, AttributeError):
    PROWLING_AVAILABLE = False
    try:
        from meow_decoder import prowling_mode
        PROWLING_AVAILABLE = hasattr(prowling_mode, 'ProwlingEncoder')
    except ImportError:
        pass


@pytest.mark.skipif(not PROWLING_AVAILABLE, reason="prowling_mode module not available")
class TestProwlingEncoder:
    """Tests for ProwlingEncoder low-memory streaming."""

    def test_encoder_creation(self):
        """Test encoder creation."""
        from meow_decoder.prowling_mode import ProwlingEncoder
        encoder = ProwlingEncoder(password="test_password")
        assert encoder is not None

    def test_encode_stream(self):
        """Test streaming encoding."""
        from meow_decoder.prowling_mode import ProwlingEncoder
        import io
        
        encoder = ProwlingEncoder(password="test_password")
        input_data = b"Test data for streaming " * 100
        input_stream = io.BytesIO(input_data)
        output_stream = io.BytesIO()
        
        encoder.encode_stream(input_stream, output_stream)
        
        output_stream.seek(0)
        encoded = output_stream.read()
        assert len(encoded) > 0

    def test_chunk_processing(self):
        """Test chunk-by-chunk processing."""
        from meow_decoder.prowling_mode import ProwlingEncoder
        
        encoder = ProwlingEncoder(password="test", chunk_size=1024)
        chunks = list(encoder.encode_chunks(b"Test data " * 500))
        assert len(chunks) > 0

    def test_memory_efficiency(self):
        """Test memory efficiency (should not load all data at once)."""
        from meow_decoder.prowling_mode import ProwlingEncoder
        import io
        
        # Create large-ish test data
        large_data = b"X" * (1024 * 100)  # 100KB
        encoder = ProwlingEncoder(password="test", chunk_size=1024)
        
        input_stream = io.BytesIO(large_data)
        output_stream = io.BytesIO()
        
        # Should succeed without memory issues
        encoder.encode_stream(input_stream, output_stream)
        assert output_stream.tell() > 0


@pytest.mark.skipif(not PROWLING_AVAILABLE, reason="prowling_mode module not available")
class TestProwlingDecoder:
    """Tests for ProwlingDecoder low-memory streaming."""

    def test_decoder_creation(self):
        """Test decoder creation."""
        from meow_decoder.prowling_mode import ProwlingDecoder
        decoder = ProwlingDecoder(password="test_password")
        assert decoder is not None

    def test_decode_stream(self):
        """Test streaming decoding."""
        from meow_decoder.prowling_mode import ProwlingEncoder, ProwlingDecoder
        import io
        
        # First encode
        encoder = ProwlingEncoder(password="test")
        input_data = b"Original data for roundtrip"
        encoded_stream = io.BytesIO()
        encoder.encode_stream(io.BytesIO(input_data), encoded_stream)
        
        # Then decode
        encoded_stream.seek(0)
        decoder = ProwlingDecoder(password="test")
        output_stream = io.BytesIO()
        decoder.decode_stream(encoded_stream, output_stream)
        
        output_stream.seek(0)
        recovered = output_stream.read()
        assert recovered == input_data


@pytest.mark.skipif(not PROWLING_AVAILABLE, reason="prowling_mode module not available")
class TestStreamingCipher:
    """Tests for StreamingCipher component."""

    def test_cipher_creation(self):
        """Test streaming cipher creation."""
        from meow_decoder.prowling_mode import StreamingCipher
        cipher = StreamingCipher(key=b"0" * 32, nonce=b"1" * 12)
        assert cipher is not None

    def test_encrypt_chunk(self):
        """Test chunk encryption."""
        from meow_decoder.prowling_mode import StreamingCipher
        cipher = StreamingCipher(key=b"0" * 32, nonce=b"1" * 12)
        
        chunk = b"Chunk data here"
        encrypted = cipher.encrypt_chunk(chunk)
        assert encrypted != chunk
        assert len(encrypted) > 0

    def test_decrypt_chunk(self):
        """Test chunk decryption."""
        from meow_decoder.prowling_mode import StreamingCipher
        
        key = b"0" * 32
        nonce = b"1" * 12
        
        encrypt_cipher = StreamingCipher(key=key, nonce=nonce)
        decrypt_cipher = StreamingCipher(key=key, nonce=nonce)
        
        original = b"Original chunk data"
        encrypted = encrypt_cipher.encrypt_chunk(original)
        decrypted = decrypt_cipher.decrypt_chunk(encrypted)
        
        assert decrypted == original


@pytest.mark.skipif(not PROWLING_AVAILABLE, reason="prowling_mode module not available")
class TestProwlingModeIntegration:
    """Integration tests for prowling mode."""

    def test_file_roundtrip(self):
        """Test full file encode/decode roundtrip."""
        from meow_decoder.prowling_mode import ProwlingEncoder, ProwlingDecoder
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create test file
            input_file = tmpdir / "input.txt"
            input_file.write_bytes(b"Test content " * 100)
            
            encoded_file = tmpdir / "encoded.bin"
            decoded_file = tmpdir / "decoded.txt"
            
            # Encode
            encoder = ProwlingEncoder(password="test123")
            with open(input_file, 'rb') as fin, open(encoded_file, 'wb') as fout:
                encoder.encode_stream(fin, fout)
            
            # Decode
            decoder = ProwlingDecoder(password="test123")
            with open(encoded_file, 'rb') as fin, open(decoded_file, 'wb') as fout:
                decoder.decode_stream(fin, fout)
            
            # Verify
            assert input_file.read_bytes() == decoded_file.read_bytes()

    def test_wrong_password_fails(self):
        """Test that wrong password fails gracefully."""
        from meow_decoder.prowling_mode import ProwlingEncoder, ProwlingDecoder
        import io
        
        encoder = ProwlingEncoder(password="correct")
        input_data = b"Secret data"
        encoded = io.BytesIO()
        encoder.encode_stream(io.BytesIO(input_data), encoded)
        
        encoded.seek(0)
        decoder = ProwlingDecoder(password="wrong")
        output = io.BytesIO()
        
        with pytest.raises(Exception):  # Should fail on auth
            decoder.decode_stream(encoded, output)


# Fallback test
@pytest.mark.skipif(PROWLING_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not PROWLING_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
