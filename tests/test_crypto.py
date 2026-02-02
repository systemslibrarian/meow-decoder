"""
Comprehensive Test Suite for crypto.py

Target: 95-100% branch coverage
Covers: AES-256-GCM encryption, Argon2id KDF, manifest handling, duress mode, 
        forward secrecy support, keyfile validation, nonce reuse guard.

Run with: MEOW_TEST_MODE=1 pytest tests/test_crypto.py -v --cov=meow_decoder.crypto --cov-branch
"""

import pytest
import secrets
import hashlib
import struct
import os

# Import module under test
from meow_decoder.crypto import (
    # Core functions
    derive_key,
    encrypt_file_bytes,
    decrypt_to_raw,
    # Manifest functions
    pack_manifest,
    unpack_manifest,
    pack_manifest_core,
    Manifest,
    # HMAC functions
    compute_manifest_hmac,
    verify_manifest_hmac,
    # Duress functions
    compute_duress_hash,
    compute_duress_tag,
    check_duress_password,
    # Key derivation
    derive_encryption_key_for_manifest,
    # Keyfile
    verify_keyfile,
    # Nonce reuse
    _register_nonce_use,
    _nonce_reuse_cache,
    # Constants
    MAGIC,
    MIN_PASSWORD_LENGTH,
    ARGON2_MEMORY,
    ARGON2_ITERATIONS,
)


# ==============================================================================
# Test Fixtures
# ==============================================================================

@pytest.fixture
def valid_password():
    """Return a valid password meeting minimum length."""
    return "SecureTestPassword123!"


@pytest.fixture
def short_password():
    """Return password shorter than minimum."""
    return "Short1!"  # 7 chars, minimum is 8


@pytest.fixture
def test_data():
    """Return test plaintext data."""
    return b"Secret cat message! " * 50


@pytest.fixture
def salt():
    """Return 16-byte random salt."""
    return secrets.token_bytes(16)


@pytest.fixture
def nonce():
    """Return 12-byte random nonce."""
    return secrets.token_bytes(12)


@pytest.fixture
def sample_manifest(salt, nonce):
    """Create a sample manifest for testing."""
    return Manifest(
        salt=salt,
        nonce=nonce,
        orig_len=12345,
        comp_len=10000,
        cipher_len=10016,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=25,
        hmac=secrets.token_bytes(32),
        ephemeral_public_key=None,
        pq_ciphertext=None,
        duress_tag=None
    )


# ==============================================================================
# Test Key Derivation (derive_key)
# ==============================================================================

class TestDeriveKey:
    """Tests for Argon2id key derivation."""
    
    def test_derive_key_returns_32_bytes(self, valid_password, salt):
        """Key derivation returns 32-byte key."""
        key = derive_key(valid_password, salt)
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_derive_key_deterministic(self, valid_password, salt):
        """Same password + salt = same key."""
        key1 = derive_key(valid_password, salt)
        key2 = derive_key(valid_password, salt)
        assert key1 == key2
    
    def test_derive_key_different_salt_different_key(self, valid_password):
        """Different salts produce different keys."""
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        key1 = derive_key(valid_password, salt1)
        key2 = derive_key(valid_password, salt2)
        assert key1 != key2
    
    def test_derive_key_different_password_different_key(self, salt):
        """Different passwords produce different keys."""
        key1 = derive_key("PasswordOne123!", salt)
        key2 = derive_key("PasswordTwo456!", salt)
        assert key1 != key2
    
    def test_derive_key_empty_password_rejected(self, salt):
        """Empty password raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            derive_key("", salt)
    
    def test_derive_key_short_password_rejected(self, short_password, salt):
        """Password shorter than MIN_PASSWORD_LENGTH raises ValueError."""
        with pytest.raises(ValueError, match=f"at least {MIN_PASSWORD_LENGTH}"):
            derive_key(short_password, salt)
    
    def test_derive_key_minimum_length_password_accepted(self, salt):
        """Password at minimum length is accepted."""
        min_password = "A" * MIN_PASSWORD_LENGTH
        key = derive_key(min_password, salt)
        assert len(key) == 32
    
    def test_derive_key_wrong_salt_length_rejected(self, valid_password):
        """Salt not 16 bytes raises ValueError."""
        with pytest.raises(ValueError, match="must be 16 bytes"):
            derive_key(valid_password, b"short")
        
        with pytest.raises(ValueError, match="must be 16 bytes"):
            derive_key(valid_password, secrets.token_bytes(32))
    
    def test_derive_key_with_keyfile(self, valid_password, salt):
        """Keyfile changes derived key."""
        keyfile = secrets.token_bytes(64)
        key_without = derive_key(valid_password, salt)
        key_with = derive_key(valid_password, salt, keyfile=keyfile)
        assert key_without != key_with
    
    def test_derive_key_different_keyfile_different_key(self, valid_password, salt):
        """Different keyfiles produce different keys."""
        keyfile1 = secrets.token_bytes(64)
        keyfile2 = secrets.token_bytes(64)
        key1 = derive_key(valid_password, salt, keyfile=keyfile1)
        key2 = derive_key(valid_password, salt, keyfile=keyfile2)
        assert key1 != key2


# ==============================================================================
# Test Encryption/Decryption Roundtrip
# ==============================================================================

class TestEncryptDecryptRoundtrip:
    """Tests for encrypt_file_bytes and decrypt_to_raw roundtrip."""
    
    def test_roundtrip_basic(self, valid_password, test_data):
        """Basic encryption/decryption roundtrip."""
        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(
            test_data, valid_password
        )
        
        decrypted = decrypt_to_raw(
            cipher, valid_password, salt, nonce,
            orig_len=len(test_data), comp_len=len(comp), sha256=sha
        )
        
        assert decrypted == test_data
    
    def test_roundtrip_binary_data(self, valid_password):
        """Roundtrip with binary data including null bytes."""
        binary_data = bytes(range(256)) * 10
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            binary_data, valid_password
        )
        
        decrypted = decrypt_to_raw(
            cipher, valid_password, salt, nonce,
            orig_len=len(binary_data), comp_len=len(comp), sha256=sha
        )
        
        assert decrypted == binary_data
    
    def test_roundtrip_empty_data(self, valid_password):
        """Roundtrip with empty data."""
        empty_data = b""
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            empty_data, valid_password
        )
        
        decrypted = decrypt_to_raw(
            cipher, valid_password, salt, nonce,
            orig_len=0, comp_len=len(comp), sha256=sha
        )
        
        assert decrypted == empty_data
    
    def test_roundtrip_large_data(self, valid_password):
        """Roundtrip with large data (1 MB)."""
        large_data = secrets.token_bytes(1024 * 1024)
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            large_data, valid_password
        )
        
        decrypted = decrypt_to_raw(
            cipher, valid_password, salt, nonce,
            orig_len=len(large_data), comp_len=len(comp), sha256=sha
        )
        
        assert decrypted == large_data
    
    def test_roundtrip_with_keyfile(self, valid_password, test_data):
        """Roundtrip with keyfile."""
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password, keyfile=keyfile
        )
        
        decrypted = decrypt_to_raw(
            cipher, valid_password, salt, nonce, keyfile=keyfile,
            orig_len=len(test_data), comp_len=len(comp), sha256=sha
        )
        
        assert decrypted == test_data
    
    def test_roundtrip_without_padding(self, valid_password, test_data):
        """Roundtrip without length padding."""
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password, use_length_padding=False
        )
        
        decrypted = decrypt_to_raw(
            cipher, valid_password, salt, nonce,
            orig_len=len(test_data), comp_len=len(comp), sha256=sha
        )
        
        assert decrypted == test_data
    
    def test_roundtrip_with_precomputed_key(self, valid_password, test_data):
        """Roundtrip with precomputed hardware key."""
        precomputed_key = secrets.token_bytes(32)
        precomputed_salt = secrets.token_bytes(16)
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password,
            precomputed_key=precomputed_key,
            precomputed_salt=precomputed_salt
        )
        
        decrypted = decrypt_to_raw(
            cipher, valid_password, salt, nonce,
            orig_len=len(test_data), comp_len=len(comp), sha256=sha,
            precomputed_key=precomputed_key
        )
        
        assert decrypted == test_data


# ==============================================================================
# Test Wrong Password/Key Rejection
# ==============================================================================

class TestWrongKeyRejection:
    """Tests for wrong password/key rejection."""
    
    def test_wrong_password_rejected(self, valid_password, test_data):
        """Wrong password fails decryption."""
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password
        )
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                cipher, "WrongPassword!23", salt, nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )
    
    def test_similar_password_rejected(self, test_data):
        """Similar password (off by one char) fails."""
        password = "CorrectPassword1"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, password
        )
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                cipher, "CorrectPassword2", salt, nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )
    
    def test_case_sensitive_password(self, test_data):
        """Password comparison is case-sensitive."""
        password = "MyPassword123!"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, password
        )
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, "mypassword123!", salt, nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )
    
    def test_missing_keyfile_rejected(self, valid_password, test_data):
        """Decryption without required keyfile fails."""
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password, keyfile=keyfile
        )
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, valid_password, salt, nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
                # No keyfile!
            )
    
    def test_wrong_keyfile_rejected(self, valid_password, test_data):
        """Wrong keyfile fails decryption."""
        keyfile1 = secrets.token_bytes(64)
        keyfile2 = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password, keyfile=keyfile1
        )
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, valid_password, salt, nonce, keyfile=keyfile2,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )


# ==============================================================================
# Test Ciphertext Tampering Detection
# ==============================================================================

class TestCiphertextTampering:
    """Tests for tampering detection."""
    
    def test_bit_flip_detected(self, valid_password, test_data):
        """Single bit flip in ciphertext is detected."""
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password
        )
        
        # Flip a bit
        tampered = bytearray(cipher)
        tampered[len(tampered) // 2] ^= 0x01
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                bytes(tampered), valid_password, salt, nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )
    
    def test_truncated_ciphertext_detected(self, valid_password, test_data):
        """Truncated ciphertext is detected."""
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password
        )
        
        truncated = cipher[:-10]
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                truncated, valid_password, salt, nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )
    
    def test_extended_ciphertext_detected(self, valid_password, test_data):
        """Extended ciphertext is detected."""
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password
        )
        
        extended = cipher + b"\x00" * 10
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                extended, valid_password, salt, nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )


# ==============================================================================
# Test Nonce Handling
# ==============================================================================

class TestNonceHandling:
    """Tests for nonce uniqueness and handling."""
    
    def test_nonces_are_unique(self, valid_password, test_data):
        """Each encryption produces unique nonce."""
        _, _, _, nonce1, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        _, _, _, nonce2, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        assert nonce1 != nonce2
    
    def test_nonce_is_12_bytes(self, valid_password, test_data):
        """Nonce is exactly 12 bytes."""
        _, _, _, nonce, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        assert len(nonce) == 12
    
    def test_wrong_nonce_rejected(self, valid_password, test_data):
        """Wrong nonce fails decryption."""
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password
        )
        
        wrong_nonce = secrets.token_bytes(12)
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, valid_password, salt, wrong_nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )
    
    def test_nonce_reuse_guard(self):
        """Nonce reuse with same key is detected."""
        # Clear cache first
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First use OK
        _register_nonce_use(key, nonce)
        
        # Second use with same key/nonce raises
        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(key, nonce)
    
    def test_different_nonce_allowed(self):
        """Different nonces with same key is allowed."""
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(12)
        nonce2 = secrets.token_bytes(12)
        
        _register_nonce_use(key, nonce1)
        _register_nonce_use(key, nonce2)  # Should not raise
    
    def test_same_nonce_different_key_allowed(self):
        """Same nonce with different key is allowed."""
        _nonce_reuse_cache.clear()
        
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        _register_nonce_use(key1, nonce)
        _register_nonce_use(key2, nonce)  # Should not raise


# ==============================================================================
# Test Salt Handling
# ==============================================================================

class TestSaltHandling:
    """Tests for salt generation and handling."""
    
    def test_salts_are_unique(self, valid_password, test_data):
        """Each encryption produces unique salt."""
        _, _, salt1, _, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        _, _, salt2, _, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        assert salt1 != salt2
    
    def test_salt_is_16_bytes(self, valid_password, test_data):
        """Salt is exactly 16 bytes."""
        _, _, salt, _, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        assert len(salt) == 16
    
    def test_precomputed_salt_used(self, valid_password, test_data):
        """Precomputed salt is used instead of generating new one."""
        precomputed_salt = secrets.token_bytes(16)
        precomputed_key = secrets.token_bytes(32)
        
        _, _, salt, _, _, _, _ = encrypt_file_bytes(
            test_data, valid_password,
            precomputed_key=precomputed_key,
            precomputed_salt=precomputed_salt
        )
        
        assert salt == precomputed_salt


# ==============================================================================
# Test SHA256 Hash Verification
# ==============================================================================

class TestSHA256Verification:
    """Tests for SHA256 integrity verification."""
    
    def test_sha256_computed_from_original(self, valid_password, test_data):
        """SHA256 is computed from original (uncompressed) data."""
        _, sha, _, _, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        expected = hashlib.sha256(test_data).digest()
        assert sha == expected
    
    def test_sha256_is_32_bytes(self, valid_password, test_data):
        """SHA256 hash is 32 bytes."""
        _, sha, _, _, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        assert len(sha) == 32


# ==============================================================================
# Test Manifest Packing/Unpacking
# ==============================================================================

class TestManifestPackingUnpacking:
    """Tests for manifest serialization."""
    
    def test_manifest_roundtrip_password_only(self, sample_manifest):
        """Password-only manifest roundtrip (115 bytes)."""
        packed = pack_manifest(sample_manifest)
        assert len(packed) == 115
        
        unpacked = unpack_manifest(packed)
        
        assert unpacked.salt == sample_manifest.salt
        assert unpacked.nonce == sample_manifest.nonce
        assert unpacked.orig_len == sample_manifest.orig_len
        assert unpacked.comp_len == sample_manifest.comp_len
        assert unpacked.cipher_len == sample_manifest.cipher_len
        assert unpacked.sha256 == sample_manifest.sha256
        assert unpacked.block_size == sample_manifest.block_size
        assert unpacked.k_blocks == sample_manifest.k_blocks
        assert unpacked.hmac == sample_manifest.hmac
        assert unpacked.ephemeral_public_key is None
        assert unpacked.pq_ciphertext is None
        assert unpacked.duress_tag is None
    
    def test_manifest_roundtrip_forward_secrecy(self, sample_manifest):
        """Forward secrecy manifest roundtrip (147 bytes)."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(32)
        
        packed = pack_manifest(sample_manifest)
        assert len(packed) == 147
        
        unpacked = unpack_manifest(packed)
        assert unpacked.ephemeral_public_key == sample_manifest.ephemeral_public_key
    
    def test_manifest_roundtrip_fs_with_duress(self, sample_manifest):
        """FS + duress manifest roundtrip (179 bytes)."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(32)
        sample_manifest.duress_tag = secrets.token_bytes(32)
        
        packed = pack_manifest(sample_manifest)
        assert len(packed) == 179
        
        unpacked = unpack_manifest(packed)
        assert unpacked.ephemeral_public_key == sample_manifest.ephemeral_public_key
        assert unpacked.duress_tag == sample_manifest.duress_tag
    
    def test_manifest_roundtrip_pq_hybrid(self, sample_manifest):
        """PQ hybrid manifest roundtrip (1235 bytes)."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(32)
        sample_manifest.pq_ciphertext = secrets.token_bytes(1088)
        
        packed = pack_manifest(sample_manifest)
        assert len(packed) == 1235
        
        unpacked = unpack_manifest(packed)
        assert unpacked.pq_ciphertext == sample_manifest.pq_ciphertext
    
    def test_manifest_roundtrip_pq_with_duress(self, sample_manifest):
        """PQ + duress manifest roundtrip (1267 bytes)."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(32)
        sample_manifest.pq_ciphertext = secrets.token_bytes(1088)
        sample_manifest.duress_tag = secrets.token_bytes(32)
        
        packed = pack_manifest(sample_manifest)
        assert len(packed) == 1267
        
        unpacked = unpack_manifest(packed)
        assert unpacked.duress_tag == sample_manifest.duress_tag
    
    def test_manifest_invalid_magic_rejected(self):
        """Invalid magic bytes rejected."""
        packed = b"XXXX" + b"\x00" * 111
        
        with pytest.raises(ValueError, match="Invalid MAGIC"):
            unpack_manifest(packed)
    
    def test_manifest_truncated_rejected(self):
        """Truncated manifest rejected."""
        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(b"MEOW3" + b"\x00" * 50)
    
    def test_manifest_invalid_length_rejected(self, sample_manifest):
        """Invalid manifest length rejected."""
        packed = pack_manifest(sample_manifest)
        # Add random extra bytes to make invalid length
        invalid = packed + b"\x00" * 5
        
        with pytest.raises(ValueError, match="length invalid"):
            unpack_manifest(invalid)
    
    def test_manifest_meow2_backward_compat(self, sample_manifest):
        """MEOW2 magic is accepted for backward compatibility."""
        packed = pack_manifest(sample_manifest)
        # Replace MEOW3 with MEOW2
        packed = b"MEOW2" + packed[5:]
        
        unpacked = unpack_manifest(packed)
        assert unpacked.orig_len == sample_manifest.orig_len
    
    def test_manifest_ephemeral_key_wrong_length_rejected(self, sample_manifest):
        """Ephemeral key wrong length raises ValueError."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(16)  # Should be 32
        
        with pytest.raises(ValueError, match="32 bytes"):
            pack_manifest(sample_manifest)
    
    def test_manifest_pq_ciphertext_wrong_length_rejected(self, sample_manifest):
        """PQ ciphertext wrong length raises ValueError."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(32)
        sample_manifest.pq_ciphertext = secrets.token_bytes(1000)  # Should be 1088
        
        with pytest.raises(ValueError, match="1088 bytes"):
            pack_manifest(sample_manifest)
    
    def test_manifest_duress_tag_wrong_length_rejected(self, sample_manifest):
        """Duress tag wrong length raises ValueError."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(32)
        sample_manifest.duress_tag = secrets.token_bytes(16)  # Should be 32
        
        with pytest.raises(ValueError, match="32 bytes"):
            pack_manifest(sample_manifest)


# ==============================================================================
# Test Manifest HMAC
# ==============================================================================

class TestManifestHMAC:
    """Tests for manifest HMAC computation and verification."""
    
    def test_hmac_roundtrip(self, valid_password, sample_manifest):
        """HMAC computed and verified correctly."""
        # Clear the placeholder HMAC
        sample_manifest.hmac = b'\x00' * 32
        
        # Pack without HMAC to compute
        packed_core = pack_manifest_core(sample_manifest, include_duress_tag=False)
        
        # Derive key first
        enc_key = derive_key(valid_password, sample_manifest.salt)
        
        # Compute HMAC
        sample_manifest.hmac = compute_manifest_hmac(
            valid_password, sample_manifest.salt, packed_core, encryption_key=enc_key
        )
        
        # Verify HMAC
        assert verify_manifest_hmac(valid_password, sample_manifest)
    
    def test_hmac_wrong_password_rejected(self, valid_password, sample_manifest):
        """Wrong password fails HMAC verification."""
        sample_manifest.hmac = b'\x00' * 32
        packed_core = pack_manifest_core(sample_manifest, include_duress_tag=False)
        enc_key = derive_key(valid_password, sample_manifest.salt)
        sample_manifest.hmac = compute_manifest_hmac(
            valid_password, sample_manifest.salt, packed_core, encryption_key=enc_key
        )
        
        assert not verify_manifest_hmac("WrongPassword!23", sample_manifest)
    
    def test_hmac_tampered_field_rejected(self, valid_password, sample_manifest):
        """Tampered manifest field fails HMAC verification."""
        sample_manifest.hmac = b'\x00' * 32
        packed_core = pack_manifest_core(sample_manifest, include_duress_tag=False)
        enc_key = derive_key(valid_password, sample_manifest.salt)
        sample_manifest.hmac = compute_manifest_hmac(
            valid_password, sample_manifest.salt, packed_core, encryption_key=enc_key
        )
        
        # Tamper with a field
        sample_manifest.orig_len = 99999
        
        assert not verify_manifest_hmac(valid_password, sample_manifest)
    
    def test_hmac_is_32_bytes(self, valid_password, salt):
        """HMAC output is 32 bytes."""
        hmac_val = compute_manifest_hmac(
            valid_password, salt, b"test manifest data",
            encryption_key=secrets.token_bytes(32)
        )
        assert len(hmac_val) == 32
    
    def test_hmac_with_precomputed_key(self, valid_password, sample_manifest):
        """HMAC verification works with precomputed key."""
        precomputed = secrets.token_bytes(32)
        sample_manifest.hmac = b'\x00' * 32
        packed_core = pack_manifest_core(sample_manifest, include_duress_tag=False)
        
        sample_manifest.hmac = compute_manifest_hmac(
            valid_password, sample_manifest.salt, packed_core,
            encryption_key=precomputed
        )
        
        assert verify_manifest_hmac(
            valid_password, sample_manifest, precomputed_key=precomputed
        )


# ==============================================================================
# Test Duress Functions
# ==============================================================================

class TestDuressFunctions:
    """Tests for duress password functions."""
    
    def test_compute_duress_hash_returns_32_bytes(self, salt):
        """Duress hash is 32 bytes."""
        hash_val = compute_duress_hash("DuressPassword!", salt)
        assert len(hash_val) == 32
    
    def test_compute_duress_hash_deterministic(self, salt):
        """Same password + salt = same hash."""
        hash1 = compute_duress_hash("DuressPassword!", salt)
        hash2 = compute_duress_hash("DuressPassword!", salt)
        assert hash1 == hash2
    
    def test_compute_duress_hash_different_password(self, salt):
        """Different passwords produce different hashes."""
        hash1 = compute_duress_hash("DuressPassword1", salt)
        hash2 = compute_duress_hash("DuressPassword2", salt)
        assert hash1 != hash2
    
    def test_compute_duress_tag_returns_32_bytes(self, salt):
        """Duress tag is 32 bytes."""
        manifest_core = b"manifest data " * 10
        tag = compute_duress_tag("DuressPassword!", salt, manifest_core)
        assert len(tag) == 32
    
    def test_compute_duress_tag_deterministic(self, salt):
        """Same inputs = same tag."""
        manifest_core = b"manifest data " * 10
        tag1 = compute_duress_tag("DuressPassword!", salt, manifest_core)
        tag2 = compute_duress_tag("DuressPassword!", salt, manifest_core)
        assert tag1 == tag2
    
    def test_check_duress_password_correct(self, salt):
        """Correct duress password is detected."""
        manifest_core = b"manifest data " * 10
        tag = compute_duress_tag("DuressPassword!", salt, manifest_core)
        
        assert check_duress_password("DuressPassword!", salt, tag, manifest_core)
    
    def test_check_duress_password_wrong(self, salt):
        """Wrong duress password is rejected."""
        manifest_core = b"manifest data " * 10
        tag = compute_duress_tag("DuressPassword!", salt, manifest_core)
        
        assert not check_duress_password("WrongPassword!!", salt, tag, manifest_core)
    
    def test_duress_tag_different_from_different_manifest(self, salt):
        """Different manifest core produces different tag."""
        tag1 = compute_duress_tag("DuressPassword!", salt, b"manifest 1")
        tag2 = compute_duress_tag("DuressPassword!", salt, b"manifest 2")
        assert tag1 != tag2


# ==============================================================================
# Test Keyfile Functions
# ==============================================================================

class TestKeyfileFunctions:
    """Tests for keyfile validation."""
    
    def test_verify_keyfile_valid(self, tmp_path):
        """Valid keyfile is accepted."""
        keyfile_path = tmp_path / "keyfile.key"
        keyfile_path.write_bytes(secrets.token_bytes(64))
        
        content = verify_keyfile(str(keyfile_path))
        assert len(content) == 64
    
    def test_verify_keyfile_not_found(self):
        """Missing keyfile raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="not found"):
            verify_keyfile("/nonexistent/keyfile.key")
    
    def test_verify_keyfile_too_small(self, tmp_path):
        """Keyfile < 32 bytes is rejected."""
        keyfile_path = tmp_path / "small.key"
        keyfile_path.write_bytes(b"tiny")
        
        with pytest.raises(ValueError, match="too small"):
            verify_keyfile(str(keyfile_path))
    
    def test_verify_keyfile_too_large(self, tmp_path):
        """Keyfile > 1 MB is rejected."""
        keyfile_path = tmp_path / "large.key"
        keyfile_path.write_bytes(secrets.token_bytes(2 * 1024 * 1024))
        
        with pytest.raises(ValueError, match="too large"):
            verify_keyfile(str(keyfile_path))
    
    def test_verify_keyfile_exactly_32_bytes(self, tmp_path):
        """Keyfile at minimum size (32 bytes) is accepted."""
        keyfile_path = tmp_path / "min.key"
        keyfile_path.write_bytes(secrets.token_bytes(32))
        
        content = verify_keyfile(str(keyfile_path))
        assert len(content) == 32
    
    def test_verify_keyfile_at_max_size(self, tmp_path):
        """Keyfile at max size (1 MB) is accepted."""
        keyfile_path = tmp_path / "max.key"
        keyfile_path.write_bytes(secrets.token_bytes(1024 * 1024))
        
        content = verify_keyfile(str(keyfile_path))
        assert len(content) == 1024 * 1024


# ==============================================================================
# Test derive_encryption_key_for_manifest
# ==============================================================================

class TestDeriveEncryptionKeyForManifest:
    """Tests for centralized key derivation helper."""
    
    def test_derive_key_password_only(self, valid_password, salt):
        """Password-only mode returns 32-byte key."""
        key = derive_encryption_key_for_manifest(valid_password, salt)
        assert len(key) == 32
    
    def test_derive_key_with_keyfile(self, valid_password, salt):
        """Keyfile mode returns different key."""
        keyfile = secrets.token_bytes(64)
        key1 = derive_encryption_key_for_manifest(valid_password, salt)
        key2 = derive_encryption_key_for_manifest(
            valid_password, salt, keyfile=keyfile
        )
        assert key1 != key2
    
    def test_derive_key_precomputed_passthrough(self, valid_password, salt):
        """Precomputed key is returned directly."""
        precomputed = secrets.token_bytes(32)
        key = derive_encryption_key_for_manifest(
            valid_password, salt, precomputed_key=precomputed
        )
        assert key == precomputed
    
    def test_derive_key_precomputed_wrong_size(self, valid_password, salt):
        """Wrong size precomputed key is rejected."""
        with pytest.raises(ValueError, match="32 bytes"):
            derive_encryption_key_for_manifest(
                valid_password, salt, precomputed_key=secrets.token_bytes(16)
            )
    
    def test_forward_secrecy_requires_receiver_key(self, valid_password, salt):
        """Forward secrecy mode requires receiver private key."""
        ephemeral_pubkey = secrets.token_bytes(32)
        
        with pytest.raises(ValueError, match="requires receiver private key"):
            derive_encryption_key_for_manifest(
                valid_password, salt, ephemeral_public_key=ephemeral_pubkey
            )


# ==============================================================================
# Test Error Message Safety
# ==============================================================================

class TestErrorMessageSafety:
    """Tests that error messages don't leak sensitive info."""
    
    def test_decryption_error_is_generic(self, valid_password, test_data):
        """Decryption error doesn't reveal which check failed."""
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            test_data, valid_password
        )
        
        try:
            decrypt_to_raw(
                cipher, "WrongPassword!23", salt, nonce,
                orig_len=len(test_data), comp_len=len(comp), sha256=sha
            )
            pytest.fail("Should have raised RuntimeError")
        except RuntimeError as e:
            # Should not reveal whether password was wrong vs ciphertext tampered
            assert "Decryption failed" in str(e)
            # Should not contain the actual password
            assert valid_password not in str(e)
            assert "WrongPassword" not in str(e)


# ==============================================================================
# Test Encryption Output Structure
# ==============================================================================

class TestEncryptionOutputStructure:
    """Tests for encrypt_file_bytes output format."""
    
    def test_encrypt_returns_seven_values(self, valid_password, test_data):
        """encrypt_file_bytes returns 7 values."""
        result = encrypt_file_bytes(test_data, valid_password)
        assert len(result) == 7
        
        comp, sha, salt, nonce, cipher, ephemeral, enc_key = result
        
        assert isinstance(comp, bytes)
        assert isinstance(sha, bytes)
        assert isinstance(salt, bytes)
        assert isinstance(nonce, bytes)
        assert isinstance(cipher, bytes)
        # ephemeral can be None or bytes
        assert ephemeral is None or isinstance(ephemeral, bytes)
        assert isinstance(enc_key, bytes)
    
    def test_sha256_matches_original(self, valid_password, test_data):
        """SHA256 in output matches original data hash."""
        _, sha, _, _, _, _, _ = encrypt_file_bytes(test_data, valid_password)
        assert sha == hashlib.sha256(test_data).digest()
    
    def test_encryption_key_returned(self, valid_password, test_data):
        """Encryption key is returned for HMAC computation."""
        _, _, _, _, _, _, enc_key = encrypt_file_bytes(test_data, valid_password)
        assert len(enc_key) == 32
    
    def test_ephemeral_key_none_password_only(self, valid_password, test_data):
        """Ephemeral key is None in password-only mode."""
        _, _, _, _, _, ephemeral, _ = encrypt_file_bytes(test_data, valid_password)
        assert ephemeral is None


# ==============================================================================
# Test pack_manifest_core
# ==============================================================================

class TestPackManifestCore:
    """Tests for manifest core packing."""
    
    def test_pack_manifest_core_without_duress(self, sample_manifest):
        """Pack core without duress tag."""
        core = pack_manifest_core(sample_manifest, include_duress_tag=False)
        assert isinstance(core, bytes)
        assert MAGIC in core
    
    def test_pack_manifest_core_with_duress(self, sample_manifest):
        """Pack core with duress tag included."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(32)
        sample_manifest.duress_tag = secrets.token_bytes(32)
        
        core_without = pack_manifest_core(sample_manifest, include_duress_tag=False)
        core_with = pack_manifest_core(sample_manifest, include_duress_tag=True)
        
        # With duress tag should be 32 bytes longer
        assert len(core_with) == len(core_without) + 32
    
    def test_pack_manifest_core_includes_ephemeral_key(self, sample_manifest):
        """Ephemeral key is included in core."""
        sample_manifest.ephemeral_public_key = secrets.token_bytes(32)
        
        core = pack_manifest_core(sample_manifest)
        assert sample_manifest.ephemeral_public_key in core


# ==============================================================================
# Test Compression
# ==============================================================================

class TestCompression:
    """Tests for compression in encryption pipeline."""
    
    def test_compressible_data_gets_smaller(self, valid_password):
        """Highly repetitive data compresses well."""
        # Highly repetitive data
        data = b"AAAA" * 10000
        
        comp, _, _, _, _, _, _ = encrypt_file_bytes(data, valid_password)
        
        # Compressed data should be much smaller than original
        # (After adding padding, it might be larger than compression output,
        # but should still be smaller than 40K of AAAA)
        assert len(comp) < len(data)
    
    def test_random_data_compression(self, valid_password):
        """Random data doesn't compress much (might even expand)."""
        data = secrets.token_bytes(10000)
        
        comp, _, _, _, _, _, _ = encrypt_file_bytes(data, valid_password)
        
        # Random data + padding - might be similar size or slightly larger
        # Just verify it's reasonable (within 2x)
        assert len(comp) < len(data) * 2


# ==============================================================================
# Test Test Mode Parameters
# ==============================================================================

class TestTestModeParameters:
    """Tests that MEOW_TEST_MODE affects Argon2 parameters."""
    
    def test_test_mode_has_fast_parameters(self):
        """Verify test mode uses fast parameters."""
        # MEOW_TEST_MODE=1 should be set in test environment
        # This test verifies the parameters are indeed fast
        
        # In test mode: 32 MiB, 1 iteration
        # In production: 512 MiB, 20 iterations
        
        # If MEOW_TEST_MODE is set, parameters should be fast
        import os
        if os.environ.get("MEOW_TEST_MODE", "").lower() in ("1", "true", "yes"):
            assert ARGON2_MEMORY == 32768  # 32 MiB
            assert ARGON2_ITERATIONS == 1
        else:
            # In production, parameters are hardened
            assert ARGON2_MEMORY >= 65536  # At least 64 MiB


# ==============================================================================
# Property-Based Tests (Hypothesis)
# ==============================================================================

pytest.importorskip("hypothesis")

from hypothesis import given, strategies as st, settings

class TestHypothesis:
    """Property-based tests using Hypothesis."""
    
    @given(st.binary(min_size=0, max_size=10000))
    @settings(max_examples=20, deadline=None)
    def test_roundtrip_arbitrary_data(self, data):
        """Roundtrip works for arbitrary binary data."""
        password = "HypothesisTestPwd!"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, use_length_padding=False  # Disable padding for speed
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data), comp_len=len(comp), sha256=sha
        )
        
        assert decrypted == data
    
    @given(st.text(min_size=MIN_PASSWORD_LENGTH, max_size=100))
    @settings(max_examples=10, deadline=None)
    def test_password_roundtrip(self, password):
        """Roundtrip works for arbitrary passwords."""
        data = b"Test data for password hypothesis"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password)
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data), comp_len=len(comp), sha256=sha
        )
        
        assert decrypted == data


# ==============================================================================
# Main entry point
# ==============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
