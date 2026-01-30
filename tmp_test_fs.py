
import secrets
import sys
sys.path.insert(0, "/workspaces/meow-decoder")

from meow_decoder.forward_secrecy import (
    ForwardSecrecyManager, 
    RatchetState,
    pack_forward_secrecy_extension,
    unpack_forward_secrecy_extension,
    create_forward_secrecy_encoder,
    create_forward_secrecy_decoder
)

# Test basic manager
master_key = secrets.token_bytes(32)
salt = secrets.token_bytes(16)
mgr = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
key = mgr.derive_block_key(0)
print(f"Block key derived: {len(key)} bytes")

# Test encryption/decryption
data = b"Test data"
nonce, ct = mgr.encrypt_block(data, 0)
pt = mgr.decrypt_block(ct, nonce, 0)
assert pt == data
print("Encrypt/decrypt OK")

# Test with ratchet
mgr2 = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=10)
k1 = mgr2.derive_block_key(0)
k2 = mgr2.derive_block_key(10)  # Should trigger ratchet
k3 = mgr2.derive_block_key(20)  # Should trigger ratchet again
print(f"Ratchet keys derived: {mgr2.ratchet_state.counter} ratchets")

# Test extension packing
ext = pack_forward_secrecy_extension(mgr2)
print(f"Extension packed: {len(ext)} bytes")

# Unpack extension
ratchet_enabled, interval, state = unpack_forward_secrecy_extension(ext[3:])
print(f"Unpacked: ratchet={ratchet_enabled}, interval={interval}")

# Test factory functions
encoder_mgr = create_forward_secrecy_encoder(master_key, salt, enable_ratchet=True)
print(f"Encoder manager created: ratchet={encoder_mgr.enable_ratchet}")

# Test cleanup
mgr.cleanup()
mgr2.cleanup()
print("Cleanup OK")

print("All forward_secrecy tests passed!")
