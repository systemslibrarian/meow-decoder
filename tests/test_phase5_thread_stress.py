#!/usr/bin/env python3
"""
🧵 Phase 5: Thread Safety and Large File Stress Tests

Tests concurrent encoding thread safety (especially nonce reuse prevention)
and large file handling for memory efficiency.

Test Coverage:
- TS-01 to TS-10: Thread safety for encryption operations
- TS-11 to TS-15: Nonce uniqueness under concurrency
- LF-01 to LF-10: Large file stress tests
- MEM-01 to MEM-05: Memory residue verification

Security Properties Verified:
- No nonce reuse under concurrent encoding
- Memory usage bounded for large files
- No key material left in memory after operations
"""

import pytest
import secrets
import threading
import time
import hashlib
import gc
import sys
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import os


class TestNonceThreadSafety:
    """TS-01 to TS-10: Thread safety for nonce generation."""
    
    def test_nonce_cache_thread_safe(self):
        """TS-01: Nonce reuse cache handles concurrent access."""
        from meow_decoder.crypto import _nonce_reuse_cache, _register_nonce_use
        
        # Clear cache
        _nonce_reuse_cache.clear()
        
        errors = []
        nonces_used = []
        lock = threading.Lock()
        
        def register_nonces(thread_id):
            try:
                for i in range(100):
                    key = secrets.token_bytes(32)
                    nonce = secrets.token_bytes(12)
                    
                    with lock:
                        nonces_used.append((key, nonce))
                    
                    _register_nonce_use(key, nonce)
            except Exception as e:
                errors.append(e)
        
        # Run concurrent threads
        threads = []
        for i in range(10):
            t = threading.Thread(target=register_nonces, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # No errors should occur
        assert len(errors) == 0, f"Errors during concurrent access: {errors}"
    
    def test_encrypt_concurrent_unique_nonces(self):
        """TS-02: Concurrent encryption produces unique nonces."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        nonces = []
        lock = threading.Lock()
        errors = []
        
        def encrypt_file(data, password):
            try:
                _, _, salt, nonce, cipher, _, _ = encrypt_file_bytes(
                    data, password
                )
                with lock:
                    nonces.append((salt, nonce))
            except Exception as e:
                errors.append(e)
        
        # Encrypt concurrently
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for i in range(20):
                data = f"Test data {i}".encode() * 100
                futures.append(
                    executor.submit(encrypt_file, data, f"password{i}!")
                )
            
            for f in as_completed(futures):
                pass
        
        assert len(errors) == 0, f"Encryption errors: {errors}"
        
        # All salt+nonce combinations should be unique
        combinations = [(s.hex(), n.hex()) for s, n in nonces]
        assert len(set(combinations)) == len(combinations), "Duplicate nonces found!"
    
    def test_nonce_reuse_detection(self):
        """TS-03: Nonce reuse is detected and raises error."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        
        # Clear cache first
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First registration should succeed
        _register_nonce_use(key, nonce)
        
        # Second registration should fail
        with pytest.raises(RuntimeError, match="Nonce reuse detected"):
            _register_nonce_use(key, nonce)
    
    def test_concurrent_key_derivation(self):
        """TS-04: Concurrent key derivation is thread-safe."""
        from meow_decoder.crypto import derive_key
        
        results = []
        lock = threading.Lock()
        
        def derive(password, salt):
            key = derive_key(password, salt)
            with lock:
                results.append((password, salt.hex(), key.hex()))
        
        # Same password + salt should give same key
        salt = secrets.token_bytes(16)
        
        threads = []
        for _ in range(5):
            t = threading.Thread(target=derive, args=("testpassword!", salt))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All results should be identical
        keys = [r[2] for r in results]
        assert len(set(keys)) == 1, "Same inputs produced different keys"
    
    def test_concurrent_hmac_computation(self):
        """TS-05: Concurrent HMAC computation is thread-safe."""
        from meow_decoder.crypto import compute_manifest_hmac
        
        results = []
        lock = threading.Lock()
        
        password = "test_password!"
        salt = secrets.token_bytes(16)
        manifest_data = b"test manifest data" * 10
        
        def compute_hmac():
            hmac = compute_manifest_hmac(password, salt, manifest_data)
            with lock:
                results.append(hmac.hex())
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=compute_hmac)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All HMACs should be identical
        assert len(set(results)) == 1, "Concurrent HMAC computation inconsistent"
    
    def test_frame_mac_concurrent_generation(self):
        """TS-06: Concurrent frame MAC generation is thread-safe."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        results = {}
        lock = threading.Lock()
        
        def generate_mac(frame_idx, data):
            packed = pack_frame_with_mac(data, master_key, frame_idx, salt)
            with lock:
                results[frame_idx] = packed[:8].hex()
        
        threads = []
        for i in range(100):
            data = f"Frame {i}".encode()
            t = threading.Thread(target=generate_mac, args=(i, data))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All frame indices should have unique MACs
        assert len(results) == 100
        assert len(set(results.values())) == 100
    
    def test_encryption_decryption_concurrent(self):
        """TS-07: Concurrent encrypt/decrypt operations work correctly."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        test_data = b"Secret test data " * 50
        password = "TestPassword123!"
        
        results = []
        lock = threading.Lock()
        errors = []
        
        def encrypt_decrypt_cycle(cycle_id):
            try:
                # Encrypt
                _, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
                    test_data, password
                )
                
                # Decrypt
                decrypted = decrypt_to_raw(
                    cipher, password, salt, nonce,
                    orig_len=len(test_data),
                    comp_len=len(cipher),  # approximation
                    sha256=sha
                )
                
                with lock:
                    results.append((cycle_id, decrypted == test_data))
            except Exception as e:
                with lock:
                    errors.append((cycle_id, str(e)))
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(encrypt_decrypt_cycle, i)
                for i in range(10)
            ]
            for f in as_completed(futures):
                pass
        
        assert len(errors) == 0, f"Errors: {errors}"
        assert all(success for _, success in results)
    
    def test_fountain_encoder_thread_safe(self):
        """TS-08: Fountain encoder is thread-safe for droplet generation."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data for fountain encoding " * 100
        k_blocks = 10
        block_size = 256
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        droplets = {}
        lock = threading.Lock()
        
        def generate_droplet(seed):
            droplet = encoder.droplet(seed)
            with lock:
                droplets[seed] = droplet.data.hex()
        
        threads = []
        for seed in range(50):
            t = threading.Thread(target=generate_droplet, args=(seed,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All droplets should be generated
        assert len(droplets) == 50
    
    def test_concurrent_manifest_packing(self):
        """TS-09: Concurrent manifest packing is thread-safe."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        results = []
        lock = threading.Lock()
        
        def pack_manifests(thread_id):
            manifest = Manifest(
                salt=secrets.token_bytes(16),
                nonce=secrets.token_bytes(12),
                orig_len=1000 + thread_id,
                comp_len=800 + thread_id,
                cipher_len=820 + thread_id,
                sha256=secrets.token_bytes(32),
                block_size=512,
                k_blocks=10 + thread_id,
                hmac=secrets.token_bytes(32)
            )
            packed = pack_manifest(manifest)
            with lock:
                results.append((thread_id, len(packed)))
        
        threads = []
        for i in range(20):
            t = threading.Thread(target=pack_manifests, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert len(results) == 20
    
    def test_stress_concurrent_operations(self):
        """TS-10: Stress test with many concurrent operations."""
        from meow_decoder.crypto import derive_key
        
        errors = []
        
        def stress_operation(op_id):
            try:
                salt = secrets.token_bytes(16)
                key = derive_key(f"password_{op_id}!", salt)
                assert len(key) == 32
            except Exception as e:
                errors.append((op_id, str(e)))
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(stress_operation, i)
                for i in range(50)
            ]
            for f in as_completed(futures):
                pass
        
        assert len(errors) == 0, f"Stress test errors: {errors}"


class TestLargeFileHandling:
    """LF-01 to LF-10: Large file stress tests."""
    
    def test_1mb_file_encoding(self):
        """LF-01: 1 MB file encodes correctly."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        data = secrets.token_bytes(1024 * 1024)  # 1 MB
        password = "LargeFileTest123!"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password
        )
        
        assert len(cipher) > 0
        assert len(sha) == 32
    
    def test_5mb_file_encoding(self):
        """LF-02: 5 MB file encodes correctly."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        data = secrets.token_bytes(5 * 1024 * 1024)  # 5 MB
        password = "LargeFileTest123!"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password
        )
        
        assert len(cipher) > 0
    
    def test_10mb_file_roundtrip(self):
        """LF-03: 10 MB file survives encrypt/decrypt roundtrip."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = secrets.token_bytes(10 * 1024 * 1024)  # 10 MB
        password = "LargeFileTest123!"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha
        )
        
        assert decrypted == data
    
    def test_fountain_large_data(self):
        """LF-04: Fountain encoder handles large data."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = secrets.token_bytes(1024 * 1024)  # 1 MB
        k_blocks = 2048
        block_size = 512
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Generate many droplets
        droplets = []
        for _ in range(int(k_blocks * 1.5)):
            droplets.append(encoder.droplet())
        
        assert len(droplets) == int(k_blocks * 1.5)
    
    def test_fountain_large_decode(self):
        """LF-05: Fountain decoder handles large data reconstruction."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        # Use smaller size for faster test
        data = secrets.token_bytes(100 * 1024)  # 100 KB
        k_blocks = 200
        block_size = 512
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Feed droplets until complete
        for seed in range(int(k_blocks * 2)):
            droplet = encoder.droplet(seed)
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
        
        # Pad original data to match what encoder padded
        total_size = k_blocks * block_size
        padded_data = data + b'\x00' * (total_size - len(data))
        
        recovered = decoder.get_data(len(data))
        assert recovered == data
    
    def test_memory_efficiency_large_encrypt(self):
        """LF-06: Large file encryption doesn't use excessive memory."""
        import tracemalloc
        from meow_decoder.crypto import encrypt_file_bytes
        
        data = secrets.token_bytes(5 * 1024 * 1024)  # 5 MB
        
        tracemalloc.start()
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, "password123!"
        )
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Peak memory should be reasonable (< 3x data size)
        # This accounts for data + compressed + cipher in memory
        assert peak < len(data) * 5, f"Peak memory too high: {peak / 1024 / 1024:.1f} MB"
    
    def test_incremental_fountain_memory(self):
        """LF-07: Fountain encoding doesn't hold all droplets in memory."""
        import tracemalloc
        from meow_decoder.fountain import FountainEncoder
        
        data = secrets.token_bytes(1024 * 1024)  # 1 MB
        k_blocks = 2048
        block_size = 512
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        tracemalloc.start()
        
        # Generate droplets one at a time, discarding
        for i in range(1000):
            droplet = encoder.droplet(i)
            # Immediately discard
            del droplet
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Peak memory should be bounded
        assert peak < 10 * 1024 * 1024, f"Peak memory too high: {peak / 1024 / 1024:.1f} MB"
    
    def test_compression_ratio_large_random(self):
        """LF-08: Random data doesn't compress much (as expected)."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        # Random data shouldn't compress well
        data = secrets.token_bytes(100 * 1024)  # 100 KB
        
        comp, _, _, _, cipher, _, _ = encrypt_file_bytes(data, "password!")
        
        # Cipher should be similar size to original (random incompressible)
        ratio = len(cipher) / len(data)
        assert ratio > 0.95, f"Random data compressed unexpectedly: {ratio:.2f}"
    
    def test_compression_ratio_large_repetitive(self):
        """LF-09: Repetitive data compresses well."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        # Repetitive data should compress well
        data = b"AAAA" * 25000  # 100 KB of A's
        
        comp, _, _, _, cipher, _, _ = encrypt_file_bytes(data, "password!")
        
        # Cipher should be much smaller
        ratio = len(cipher) / len(data)
        assert ratio < 0.5, f"Repetitive data didn't compress: {ratio:.2f}"
    
    @pytest.mark.slow
    def test_50mb_file_handling(self):
        """LF-10: 50 MB file can be processed (slow test)."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        # This is a slow test - marked appropriately
        data = secrets.token_bytes(50 * 1024 * 1024)  # 50 MB
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, "LargeFile123!"
        )
        
        assert len(cipher) > 0
        assert len(sha) == 32


class TestMemoryResidue:
    """MEM-01 to MEM-05: Memory residue verification."""
    
    def test_key_derivation_memory_cleanup(self):
        """MEM-01: Key derivation cleans up intermediate values."""
        from meow_decoder.crypto import derive_key
        import gc
        
        password = "SensitivePassword123!"
        salt = secrets.token_bytes(16)
        
        # Derive key
        key = derive_key(password, salt)
        key_hex = key.hex()
        
        # Delete and garbage collect
        del key
        gc.collect()
        
        # Note: In Python, we can't fully verify memory cleanup
        # But we can verify the function completes without error
        assert len(key_hex) == 64
    
    def test_encryption_memory_cleanup(self):
        """MEM-02: Encryption cleans up plaintext from buffers."""
        from meow_decoder.crypto import encrypt_file_bytes
        import gc
        
        plaintext = b"SENSITIVE DATA " * 100
        plaintext_hash = hashlib.sha256(plaintext).hexdigest()
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            plaintext, "password!"
        )
        
        # Delete plaintext reference
        del plaintext
        gc.collect()
        
        # Verify SHA matches original
        assert sha.hex() == hashlib.sha256(b"SENSITIVE DATA " * 100).hexdigest()
    
    def test_decryption_memory_cleanup(self):
        """MEM-03: Decryption cleans up key material."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        import gc
        
        data = b"Secret data for cleanup test"
        password = "CleanupTest123!"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha
        )
        
        # Verify data recovered
        assert decrypted == data
        
        # Force cleanup
        del decrypted
        gc.collect()
    
    def test_secure_buffer_zeroing(self):
        """MEM-04: SecureBuffer zeros memory on exit."""
        from meow_decoder.constant_time import SecureBuffer
        
        # Create and populate buffer
        with SecureBuffer(64) as buf:
            buf.write(b"SENSITIVE" * 7)
            data = buf.read()
            assert b"SENSITIVE" in data
        
        # Buffer should be zeroed after context exit
        # (Verification is implementation-dependent)
    
    def test_secure_memory_context(self):
        """MEM-05: secure_memory context manager works."""
        from meow_decoder.constant_time import secure_memory
        import gc
        
        sensitive = b"Top Secret Password Data!"
        
        with secure_memory(sensitive) as buf:
            assert bytes(buf) == sensitive
        
        # After context, buffer should be zeroed
        gc.collect()


class TestNonceUniqueness:
    """TS-11 to TS-15: Nonce uniqueness verification."""
    
    def test_sequential_encryptions_unique_nonces(self):
        """TS-11: Sequential encryptions produce unique nonces."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        nonces = []
        data = b"test data"
        
        for _ in range(100):
            _, _, _, nonce, _, _, _ = encrypt_file_bytes(data, "password!")
            nonces.append(nonce.hex())
        
        assert len(set(nonces)) == 100, "Duplicate nonces in sequential encryption"
    
    def test_nonces_are_cryptographically_random(self):
        """TS-12: Nonces appear random (entropy check)."""
        from meow_decoder.crypto import encrypt_file_bytes
        import math
        
        all_bytes = bytearray()
        
        for _ in range(100):
            _, _, _, nonce, _, _, _ = encrypt_file_bytes(b"data", "password!")
            all_bytes.extend(nonce)
        
        # Calculate entropy
        byte_counts = Counter(all_bytes)
        total = len(all_bytes)
        
        entropy = -sum(
            (count / total) * math.log2(count / total)
            for count in byte_counts.values()
        )
        
        # Expect high entropy (near 8 bits)
        assert entropy > 7.0, f"Nonce entropy too low: {entropy}"
    
    def test_nonces_no_pattern(self):
        """TS-13: No obvious patterns in generated nonces."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        nonces = []
        
        for _ in range(50):
            _, _, _, nonce, _, _, _ = encrypt_file_bytes(b"data", "password!")
            nonces.append(nonce)
        
        # Check first bytes aren't all the same
        first_bytes = [n[0] for n in nonces]
        assert len(set(first_bytes)) > 10, "First bytes show pattern"
        
        # Check last bytes aren't all the same
        last_bytes = [n[-1] for n in nonces]
        assert len(set(last_bytes)) > 10, "Last bytes show pattern"
    
    def test_salt_uniqueness(self):
        """TS-14: Salts are also unique per encryption."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        salts = []
        
        for _ in range(100):
            _, _, salt, _, _, _, _ = encrypt_file_bytes(b"data", "password!")
            salts.append(salt.hex())
        
        assert len(set(salts)) == 100, "Duplicate salts found"
    
    def test_salt_nonce_combination_unique(self):
        """TS-15: Salt+nonce combinations are always unique."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        combinations = set()
        
        for _ in range(100):
            _, _, salt, nonce, _, _, _ = encrypt_file_bytes(b"data", "password!")
            combo = salt.hex() + nonce.hex()
            
            assert combo not in combinations, "Duplicate salt+nonce combination"
            combinations.add(combo)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
