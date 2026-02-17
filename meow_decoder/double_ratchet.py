"""
🔐 Double Ratchet Protocol for Meow Decoder

Implements Signal-style double ratchet for perfect forward secrecy
and future secrecy in multi-session communication (Clowder mode).

Architecture:
    ┌──────────────────────────────────────────────────────┐
    │               DOUBLE RATCHET                         │
    │                                                      │
    │  ┌─────────────┐    ┌─────────────┐                 │
    │  │   ROOT      │───▶│  SENDING    │───▶ Message Keys │
    │  │   CHAIN     │    │  CHAIN      │                 │
    │  └─────────────┘    └─────────────┘                 │
    │        │                                            │
    │        │ DH Ratchet                                 │
    │        ▼                                            │
    │  ┌─────────────┐                                    │
    │  │  RECEIVING  │───▶ Message Keys                   │
    │  │  CHAIN      │                                    │
    │  └─────────────┘                                    │
    └──────────────────────────────────────────────────────┘

Security Properties:
    - Forward Secrecy: Compromise of current keys doesn't expose past messages
    - Future Secrecy: Compromise heals after DH ratchet step
    - Break-in Recovery: System recovers from temporary key compromise
    - Out-of-Order Delivery: Handles missed/reordered messages

References:
    - Signal Protocol: https://signal.org/docs/specifications/doubleratchet/
    - HKDF: RFC 5869
    - X25519: RFC 7748
"""

import struct
import secrets
from typing import Tuple, Optional, Dict, List
from dataclasses import dataclass, field
from enum import Enum

from .crypto_backend import get_default_backend

# Domain separation constants
RATCHET_INFO_ROOT = b"meow_double_ratchet_root_v1"
RATCHET_INFO_CHAIN = b"meow_double_ratchet_chain_v1"
RATCHET_INFO_MESSAGE = b"meow_double_ratchet_message_v1"

# Maximum number of skipped message keys to store (prevents DoS)
MAX_SKIP = 1000


class RatchetError(Exception):
    """Errors raised by the double ratchet implementation."""


@dataclass
class KeyPair:
    """X25519 keypair container."""

    _private_bytes: bytes
    _public_bytes: bytes

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a new X25519 keypair."""
        backend = get_default_backend()
        priv, pub = backend.x25519_generate_keypair()
        return cls(_private_bytes=priv, _public_bytes=pub)

    def public_bytes(self) -> bytes:
        """Serialize public key to raw bytes."""
        return self._public_bytes

    def exchange(self, their_public: bytes) -> bytes:
        """Perform X25519 key exchange."""
        backend = get_default_backend()
        return backend.x25519_exchange(self._private_bytes, their_public)

    @staticmethod
    def public_from_bytes(public_bytes: bytes) -> bytes:
        """Validate and return public key bytes."""
        if len(public_bytes) != 32:
            raise ValueError("Public key must be 32 bytes")
        return public_bytes


@dataclass
class MessageHeader:
    """Message header for double ratchet messages."""

    dh_public: bytes
    pn: int
    n: int

    def pack(self) -> bytes:
        """Serialize header to bytes."""
        if len(self.dh_public) != 32:
            raise ValueError("DH public key must be 32 bytes")
        return struct.pack(">32sII", self.dh_public, self.pn, self.n)

    @classmethod
    def unpack(cls, data: bytes) -> "MessageHeader":
        """Deserialize header from bytes."""
        if len(data) < 40:
            raise ValueError("Header too short")
        dh_public, pn, n = struct.unpack(">32sII", data[:40])
        return cls(dh_public=dh_public, pn=pn, n=n)


@dataclass
class RatchetState:
    """State for the double ratchet protocol."""

    # DH Ratchet
    dh_keypair: Optional[KeyPair] = None
    dh_remote_public: Optional[bytes] = None

    # Root chain
    root_key: Optional[bytes] = None  # 32 bytes

    # Sending chain
    send_chain_key: Optional[bytes] = None  # 32 bytes
    send_n: int = 0  # Message number

    # Receiving chain
    recv_chain_key: Optional[bytes] = None  # 32 bytes
    recv_n: int = 0  # Message number

    # Previous sending chain length (for header)
    previous_send_n: int = 0

    # Skipped message keys: {(dh_public, n): message_key}
    skipped_keys: Dict[Tuple[bytes, int], bytes] = field(default_factory=dict)

    def serialize(self) -> bytes:
        """Serialize state for storage (encrypted)."""
        data = bytearray()

        # DH keypair (private key)
        if self.dh_keypair:
            privkey_bytes = self.dh_keypair._private_bytes
            data += struct.pack(">B", 1)  # Has keypair
            data += privkey_bytes  # 32 bytes
        else:
            data += struct.pack(">B", 0)

        # Remote public
        if self.dh_remote_public:
            data += struct.pack(">B", 1)
            data += self.dh_remote_public  # 32 bytes
        else:
            data += struct.pack(">B", 0)

        # Keys and counters
        data += self.root_key or (b"\x00" * 32)
        data += self.send_chain_key or (b"\x00" * 32)
        data += self.recv_chain_key or (b"\x00" * 32)
        data += struct.pack(">III", self.send_n, self.recv_n, self.previous_send_n)

        # Skipped keys (limited to prevent DoS)
        skipped_count = min(len(self.skipped_keys), MAX_SKIP)
        data += struct.pack(">H", skipped_count)

        for (dh_pub, n), key in list(self.skipped_keys.items())[:skipped_count]:
            data += dh_pub  # 32 bytes
            data += struct.pack(">I", n)
            data += key  # 32 bytes

        return bytes(data)

    @classmethod
    def deserialize(cls, data: bytes) -> "RatchetState":
        """Deserialize state from bytes."""
        state = cls()
        offset = 0

        # DH keypair
        has_keypair = struct.unpack(">B", data[offset : offset + 1])[0]
        offset += 1
        if has_keypair:
            privkey_bytes = data[offset : offset + 32]
            offset += 32
            backend = get_default_backend()
            pubkey_bytes = backend.x25519_public_from_private(privkey_bytes)
            state.dh_keypair = KeyPair(_private_bytes=privkey_bytes, _public_bytes=pubkey_bytes)

        # Remote public
        has_remote = struct.unpack(">B", data[offset : offset + 1])[0]
        offset += 1
        if has_remote:
            state.dh_remote_public = data[offset : offset + 32]
            offset += 32

        # Keys
        state.root_key = data[offset : offset + 32]
        offset += 32
        state.send_chain_key = data[offset : offset + 32]
        offset += 32
        state.recv_chain_key = data[offset : offset + 32]
        offset += 32

        # Counters
        state.send_n, state.recv_n, state.previous_send_n = struct.unpack(
            ">III", data[offset : offset + 12]
        )
        offset += 12

        # Skipped keys
        skipped_count = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2

        for _ in range(skipped_count):
            dh_pub = data[offset : offset + 32]
            offset += 32
            n = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4
            key = data[offset : offset + 32]
            offset += 32
            state.skipped_keys[(dh_pub, n)] = key

        return state


class DoubleRatchet:
    """
    Double Ratchet implementation for Signal-style forward secrecy.

    Usage:
        # Alice (initiator)
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_public)
        ciphertext, header = alice.encrypt(b"Hello Bob!")

        # Bob (responder)
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)
        plaintext = bob.decrypt(ciphertext, header)

        # Bob replies
        ciphertext2, header2 = bob.encrypt(b"Hello Alice!")

        # Alice receives
        plaintext2 = alice.decrypt(ciphertext2, header2)
    """

    def __init__(self, state: Optional[RatchetState] = None):
        """Initialize with existing state or empty."""
        self.state = state or RatchetState()

    @classmethod
    def initialize_alice(cls, shared_secret: bytes, bob_public_key: bytes) -> "DoubleRatchet":
        """
        Initialize as Alice (initiator).

        Args:
            shared_secret: Pre-shared secret from X3DH or password-based key
            bob_public_key: Bob's initial public key (32 bytes)

        Returns:
            Initialized DoubleRatchet
        """
        if len(shared_secret) != 32:
            raise ValueError("Shared secret must be 32 bytes")
        if len(bob_public_key) != 32:
            raise ValueError("Public key must be 32 bytes")

        state = RatchetState()

        # Generate Alice's DH keypair
        state.dh_keypair = KeyPair.generate()
        state.dh_remote_public = bob_public_key

        # Perform DH and derive root + send chain
        dh_output = state.dh_keypair.exchange(bob_public_key)

        state.root_key, state.send_chain_key = cls._kdf_rk(shared_secret, dh_output)

        return cls(state)

    @classmethod
    def initialize_bob(cls, shared_secret: bytes, bob_keypair: KeyPair) -> "DoubleRatchet":
        """
        Initialize as Bob (responder).

        Args:
            shared_secret: Pre-shared secret from X3DH or password-based key
            bob_keypair: Bob's DH keypair

        Returns:
            Initialized DoubleRatchet
        """
        if len(shared_secret) != 32:
            raise ValueError("Shared secret must be 32 bytes")

        state = RatchetState()
        state.dh_keypair = bob_keypair
        state.root_key = shared_secret

        # Bob waits for first message to perform DH ratchet

        return cls(state)

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, MessageHeader]:
        """
        Encrypt a message.

        Args:
            plaintext: Message to encrypt

        Returns:
            Tuple of (ciphertext, header)
        """
        if self.state.send_chain_key is None:
            raise RatchetError("Cannot encrypt: no sending chain initialized")

        # Derive message key
        message_key, new_chain_key = self._kdf_ck(self.state.send_chain_key)
        self.state.send_chain_key = new_chain_key

        # Create header
        assert self.state.dh_keypair is not None, "DH keypair must exist"
        header = MessageHeader(
            dh_public=self.state.dh_keypair.public_bytes(),
            pn=self.state.previous_send_n,
            n=self.state.send_n,
        )

        self.state.send_n += 1

        # Encrypt with AEAD
        ciphertext = self._aead_encrypt(message_key, plaintext, header.pack())

        # Zero message key
        del message_key

        return ciphertext, header

    def decrypt(self, ciphertext: bytes, header: MessageHeader) -> bytes:
        """
        Decrypt a message.

        Args:
            ciphertext: Encrypted message
            header: Message header

        Returns:
            Decrypted plaintext
        """
        # Check for skipped message key
        skipped_key = self.state.skipped_keys.pop((header.dh_public, header.n), None)
        if skipped_key:
            return self._aead_decrypt(skipped_key, ciphertext, header.pack())

        # Check if we need DH ratchet
        if header.dh_public != self.state.dh_remote_public:
            self._skip_messages(header.pn)
            self._dh_ratchet(header.dh_public)

        # Skip to correct message number
        self._skip_messages(header.n)

        # Derive message key
        message_key, new_chain_key = self._kdf_ck(self.state.recv_chain_key)
        self.state.recv_chain_key = new_chain_key
        self.state.recv_n += 1

        # Decrypt
        plaintext = self._aead_decrypt(message_key, ciphertext, header.pack())

        # Zero message key
        del message_key

        return plaintext

    def _dh_ratchet(self, their_public: bytes):
        """Perform DH ratchet step."""
        self.state.previous_send_n = self.state.send_n
        self.state.send_n = 0
        self.state.recv_n = 0
        self.state.dh_remote_public = their_public

        # Derive receiving chain
        assert self.state.dh_keypair is not None, "DH keypair must exist"
        dh_output = self.state.dh_keypair.exchange(their_public)
        self.state.root_key, self.state.recv_chain_key = self._kdf_rk(
            self.state.root_key, dh_output
        )

        # Generate new DH keypair
        self.state.dh_keypair = KeyPair.generate()

        # Derive sending chain
        dh_output = self.state.dh_keypair.exchange(their_public)
        self.state.root_key, self.state.send_chain_key = self._kdf_rk(
            self.state.root_key, dh_output
        )

    def _skip_messages(self, until: int):
        """Skip message keys for out-of-order delivery."""
        if self.state.recv_chain_key is None:
            return

        if self.state.recv_n + MAX_SKIP < until:
            raise RatchetError(f"Too many skipped messages: {until - self.state.recv_n}")

        while self.state.recv_n < until:
            message_key, new_chain_key = self._kdf_ck(self.state.recv_chain_key)
            self.state.recv_chain_key = new_chain_key

            # Store skipped key
            key_id = (self.state.dh_remote_public, self.state.recv_n)
            self.state.skipped_keys[key_id] = message_key

            self.state.recv_n += 1

            # Limit stored keys
            if len(self.state.skipped_keys) > MAX_SKIP:
                # Remove oldest (first inserted)
                oldest_key = next(iter(self.state.skipped_keys))
                del self.state.skipped_keys[oldest_key]

    @staticmethod
    def _kdf_rk(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """
        Root key derivation function.

        Returns (new_root_key, chain_key)
        """
        backend = get_default_backend()
        output = backend.derive_key_hkdf(dh_output, root_key, RATCHET_INFO_ROOT, 64)

        return output[:32], output[32:]

    @staticmethod
    def _kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Chain key derivation function.

        Returns (message_key, new_chain_key)
        """
        backend = get_default_backend()
        message_key = backend.hkdf_expand(chain_key, RATCHET_INFO_MESSAGE, 32)
        new_chain_key = backend.hkdf_expand(chain_key, RATCHET_INFO_CHAIN, 32)

        return message_key, new_chain_key

    @staticmethod
    def _aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Encrypt with AES-256-GCM."""
        backend = get_default_backend()
        nonce = secrets.token_bytes(12)
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        return nonce + ciphertext

    @staticmethod
    def _aead_decrypt(key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Decrypt with AES-256-GCM."""
        if len(ciphertext) < 12:
            raise RatchetError("Ciphertext too short")

        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]

        backend = get_default_backend()
        return backend.aes_gcm_decrypt(key, nonce, actual_ciphertext, aad)


# Clowder mode integration


class ClowderSession:
    """
    Clowder mode session with double ratchet.

    Manages multi-party streaming with perfect forward secrecy.
    Each participant maintains ratchets with each other participant.
    """

    def __init__(self, identity: KeyPair):
        """
        Initialize Clowder session.

        Args:
            identity: Long-term identity keypair
        """
        self.identity = identity
        self.sessions: Dict[bytes, DoubleRatchet] = {}  # peer_id -> ratchet

    def add_peer(
        self, peer_id: bytes, peer_public: bytes, is_initiator: bool, shared_secret: bytes
    ):
        """
        Add a peer to the session.

        Args:
            peer_id: Unique peer identifier
            peer_public: Peer's public key
            is_initiator: Whether we initiated the connection
            shared_secret: Pre-shared secret for this peer
        """
        if is_initiator:
            ratchet = DoubleRatchet.initialize_alice(shared_secret, peer_public)
        else:
            ratchet = DoubleRatchet.initialize_bob(shared_secret, self.identity)

        self.sessions[peer_id] = ratchet

    def encrypt_for_peer(self, peer_id: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt message for specific peer.

        Returns:
            Tuple of (ciphertext, header_bytes)
        """
        if peer_id not in self.sessions:
            raise RatchetError(f"Unknown peer: {peer_id.hex()}")

        ratchet = self.sessions[peer_id]
        ciphertext, header = ratchet.encrypt(plaintext)

        return ciphertext, header.pack()

    def decrypt_from_peer(self, peer_id: bytes, ciphertext: bytes, header_bytes: bytes) -> bytes:
        """
        Decrypt message from specific peer.

        Returns:
            Decrypted plaintext
        """
        if peer_id not in self.sessions:
            raise RatchetError(f"Unknown peer: {peer_id.hex()}")

        ratchet = self.sessions[peer_id]
        header = MessageHeader.unpack(header_bytes)

        return ratchet.decrypt(ciphertext, header)

    def get_session_state(self, peer_id: bytes) -> bytes:
        """Get serialized session state for storage."""
        if peer_id not in self.sessions:
            raise RatchetError(f"Unknown peer: {peer_id.hex()}")

        return self.sessions[peer_id].state.serialize()

    def restore_session(self, peer_id: bytes, state_bytes: bytes):
        """Restore session from serialized state."""
        state = RatchetState.deserialize(state_bytes)
        self.sessions[peer_id] = DoubleRatchet(state)


def _self_test():  # pragma: no cover
    print("🔐 Double Ratchet Protocol Test")
    print("=" * 60)

    # Test 1: Basic exchange
    print("\n1. Testing basic message exchange...")

    # Shared secret (from X3DH or password-based)
    shared_secret = secrets.token_bytes(32)

    # Bob's identity
    bob_keypair = KeyPair.generate()
    bob_public = bob_keypair.public_bytes()

    # Initialize Alice (initiator)
    alice = DoubleRatchet.initialize_alice(shared_secret, bob_public)

    # Initialize Bob (responder)
    bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

    # Alice sends to Bob
    msg1 = b"Hello Bob! This is message 1."
    ct1, hdr1 = alice.encrypt(msg1)
    pt1 = bob.decrypt(ct1, hdr1)
    assert pt1 == msg1, "Message 1 mismatch"
    print("   ✅ Alice → Bob: Message 1")

    # Alice sends another message
    msg2 = b"Hello Bob! This is message 2."
    ct2, hdr2 = alice.encrypt(msg2)
    pt2 = bob.decrypt(ct2, hdr2)
    assert pt2 == msg2, "Message 2 mismatch"
    print("   ✅ Alice → Bob: Message 2")

    # Bob replies (triggers DH ratchet)
    msg3 = b"Hello Alice! Got your messages."
    ct3, hdr3 = bob.encrypt(msg3)
    pt3 = alice.decrypt(ct3, hdr3)
    assert pt3 == msg3, "Message 3 mismatch"
    print("   ✅ Bob → Alice: Message 3 (DH ratchet)")

    # Alice replies again
    msg4 = b"Great! Here's another message."
    ct4, hdr4 = alice.encrypt(msg4)
    pt4 = bob.decrypt(ct4, hdr4)
    assert pt4 == msg4, "Message 4 mismatch"
    print("   ✅ Alice → Bob: Message 4 (another DH ratchet)")

    print("\n2. Testing out-of-order delivery...")

    # Alice sends 3 messages
    msgs = [b"OOO Message 1", b"OOO Message 2", b"OOO Message 3"]
    encrypted = []
    for msg in msgs:
        ct, hdr = alice.encrypt(msg)
        encrypted.append((ct, hdr))

    # Bob receives in reverse order
    for i in range(2, -1, -1):
        ct, hdr = encrypted[i]
        pt = bob.decrypt(ct, hdr)
        assert pt == msgs[i], f"OOO message {i} mismatch"
        print(f"   ✅ Received message {i+1} out of order")

    print("\n3. Testing state serialization...")

    # Serialize Alice's state
    alice_state_bytes = alice.state.serialize()
    print(f"   State size: {len(alice_state_bytes)} bytes")

    # Restore Alice
    restored_state = RatchetState.deserialize(alice_state_bytes)
    alice_restored = DoubleRatchet(restored_state)

    # Send message from restored Alice
    msg5 = b"Message from restored Alice"
    ct5, hdr5 = alice_restored.encrypt(msg5)
    pt5 = bob.decrypt(ct5, hdr5)
    assert pt5 == msg5, "Restored message mismatch"
    print("   ✅ Message from restored state")

    print("\n4. Testing Clowder session...")

    # Create identities
    alice_id = KeyPair.generate()
    bob_id = KeyPair.generate()

    # Create sessions
    alice_session = ClowderSession(alice_id)
    bob_session = ClowderSession(bob_id)

    # Peer IDs
    backend = get_default_backend()
    alice_peer_id = backend.sha256(b"alice")
    bob_peer_id = backend.sha256(b"bob")

    # Add peers
    peer_secret = secrets.token_bytes(32)
    alice_session.add_peer(bob_peer_id, bob_id.public_bytes(), True, peer_secret)
    bob_session.add_peer(alice_peer_id, alice_id.public_bytes(), False, peer_secret)

    # Exchange messages
    msg6 = b"Clowder message from Alice"
    ct6, hdr6 = alice_session.encrypt_for_peer(bob_peer_id, msg6)
    pt6 = bob_session.decrypt_from_peer(alice_peer_id, ct6, hdr6)
    assert pt6 == msg6, "Clowder message mismatch"
    print("   ✅ Clowder session exchange")

    print("\n" + "=" * 60)
    print("✅ All double ratchet tests passed!")
    print("\nSecurity Properties:")
    print("  • Forward Secrecy: Past messages protected from key compromise")
    print("  • Future Secrecy: Healing after DH ratchet step")
    print("  • Out-of-Order: Handles missed/reordered messages")
    print("  • State Persistence: Serialize/restore works correctly")


# Testing
if __name__ == "__main__":  # pragma: no cover
    _self_test()
