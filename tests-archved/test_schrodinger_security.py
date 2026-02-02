"""
🧪 Security Tests for Schrödinger Mode
Verifies cryptographic safety, tamper-resistance, and key separation.
"""

import struct
import tempfile
import hashlib
from pathlib import Path
import sys
import os
import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.schrodinger_encode import schrodinger_encode_data, SchrodingerManifest
from meow_decoder.crypto import derive_key
from meow_decoder.quantum_mixer import collapse_to_reality

# This is a placeholder for the new decode function we will create
def schrodinger_decode_data_placeholder(manifest: SchrodingerManifest, password: str, superposition: bytes):
    """A placeholder decoder to test manifest verification."""
    # This will be replaced with the full decoder implementation
    # For now, it just verifies the manifest for testing purposes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    import hmac
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Determine which reality to try based on HMAC
    # In a real decoder, we'd try both. For the test, we assume we know.
    is_a = True # Assume we're testing password A

    if is_a:
        salt = manifest.salt_a
        nonce = manifest.nonce_a
        expected_hmac = manifest.reality_a_hmac
        metadata_enc = manifest.metadata_a
    else: # pragma: no cover
        salt = manifest.salt_b
        nonce = manifest.nonce_b
        expected_hmac = manifest.reality_b_hmac
        metadata_enc = manifest.metadata_b

    # --- Task B & C: Strengthened Key Derivation ---
    # 1. Derive master metadata key with Argon2id
    master_meta_key = derive_key(password, salt) # Using crypto.py's Argon2id

    # 2. Derive separate keys for HMAC and encryption with HKDF
    hkdf_hmac = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"schrodinger_hmac_key_v1")
    hmac_key = hkdf_hmac.derive(master_meta_key)

    hkdf_enc = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"schrodinger_enc_key_v1")
    enc_key = hkdf_enc.derive(master_meta_key)

    # --- Task A: Authentication Verification ---
    # Pack the manifest core for HMAC verification
    # This MUST include all fields that need to be authenticated
    manifest_core = manifest.pack_core_for_auth()

    # Verify HMAC
    computed_hmac = hmac.new(hmac_key, manifest_core, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_hmac, computed_hmac):
        raise ValueError("Manifest HMAC verification failed!")

    # If HMAC is valid, decrypt metadata
    aesgcm = AESGCM(enc_key)
    try:
        metadata_plain = aesgcm.decrypt(nonce, metadata_enc, None)
    except Exception as e:
        raise ValueError(f"Metadata decryption failed: {e}")

    # Unpack metadata and return for verification
    orig_len, comp_len, cipher_len = struct.unpack('>QQQ', metadata_plain[:24])
    salt_enc = metadata_plain[24:40]
    nonce_enc = metadata_plain[40:52]
    sha_hash = metadata_plain[52:84]

    # In a real decoder, we would now use these params to decrypt the payload
    return {
        "orig_len": orig_len,
        "sha256": sha_hash
    }

# --- Test Cases ---

@pytest.fixture
def encoded_realities():
    """Fixture to provide encoded data for tests."""
    real_data = b"This is the real secret." * 10
    decoy_data = b"This is a plausible decoy." * 10
    real_pw = "RealPassword123"
    decoy_pw = "DecoyPassword456"

    superposition, manifest = schrodinger_encode_data(
        real_data, decoy_data, real_pw, decoy_pw, block_size=128
    )
    return {
        "superposition": superposition,
        "manifest": manifest,
        "real_pw": real_pw,
        "decoy_pw": decoy_pw,
        "real_data": real_data,
    }

def test_tamper_proof_manifest_version(encoded_realities):
    """Verify that changing the version byte invalidates the manifest."""
    manifest = encoded_realities["manifest"]
    real_pw = encoded_realities["real_pw"]
    superposition = encoded_realities["superposition"]

    # Tamper with the version
    manifest.version = 0x99 # Change from 0x07

    with pytest.raises(ValueError, match="Manifest HMAC verification failed"):
        schrodinger_decode_data_placeholder(manifest, real_pw, superposition)
    print("✅ Tampering with 'version' field correctly caused HMAC failure.")

def test_tamper_proof_manifest_block_size(encoded_realities):
    """Verify that changing the block_size field invalidates the manifest."""
    manifest = encoded_realities["manifest"]
    real_pw = encoded_realities["real_pw"]
    superposition = encoded_realities["superposition"]

    # Tamper with block_size
    manifest.block_size += 1

    with pytest.raises(ValueError, match="Manifest HMAC verification failed"):
        schrodinger_decode_data_placeholder(manifest, real_pw, superposition)
    print("✅ Tampering with 'block_size' field correctly caused HMAC failure.")

def test_tamper_proof_manifest_superposition_len(encoded_realities):
    """Verify that changing the superposition_len field invalidates the manifest."""
    manifest = encoded_realities["manifest"]
    real_pw = encoded_realities["real_pw"]
    superposition = encoded_realities["superposition"]

    # Tamper with superposition_len
    manifest.superposition_len -= 10

    with pytest.raises(ValueError, match="Manifest HMAC verification failed"):
        schrodinger_decode_data_placeholder(manifest, real_pw, superposition)
    print("✅ Tampering with 'superposition_len' field correctly caused HMAC failure.")

def test_tamper_proof_manifest_reserved_bytes(encoded_realities):
    """Verify that changing the reserved bytes invalidates the manifest."""
    manifest = encoded_realities["manifest"]
    real_pw = encoded_realities["real_pw"]
    superposition = encoded_realities["superposition"]

    # Tamper with reserved bytes
    manifest.reserved = b'\xDE\xAD\xBE\xEF' * 8

    with pytest.raises(ValueError, match="Manifest HMAC verification failed"):
        schrodinger_decode_data_placeholder(manifest, real_pw, superposition)
    print("✅ Tampering with 'reserved' field correctly caused HMAC failure.")

def test_successful_verification_with_correct_password(encoded_realities):
    """Verify that the correct password passes all checks."""
    manifest = encoded_realities["manifest"]
    real_pw = encoded_realities["real_pw"]
    superposition = encoded_realities["superposition"]
    real_data = encoded_realities["real_data"]

    # This should succeed without raising an exception
    decoded_meta = schrodinger_decode_data_placeholder(manifest, real_pw, superposition)

    assert decoded_meta["orig_len"] == len(real_data)
    assert decoded_meta["sha256"] == hashlib.sha256(real_data).digest()
    print("✅ Correct password successfully verified manifest and decrypted metadata.")

def test_verification_fails_with_wrong_password(encoded_realities):
    """Verify that the wrong password fails HMAC check."""
    manifest = encoded_realities["manifest"]
    superposition = encoded_realities["superposition"]

    with pytest.raises(ValueError, match="Manifest HMAC verification failed"):
        schrodinger_decode_data_placeholder(manifest, "ThisIsTheWrongPassword", superposition)
    print("✅ Wrong password correctly failed HMAC verification.")
