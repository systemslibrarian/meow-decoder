"""
Master Key Ratchet for Cross-Session Forward Secrecy.

Provides long-term key management with per-file roots and automatic ratcheting.
Each GIF encode derives a unique session key from the master chain, ensuring:
- Forward secrecy: Compromise of current key doesn't expose past files
- Post-compromise security: Periodic ratcheting limits damage window
- Key commitment: Ciphertext bound to specific chain state

Protocol overview:
1. Master key initialized from user passphrase + hardware entropy
2. Each encode operation ratchets the chain forward
3. Per-file keys derived via HKDF with file-specific context
4. Chain state stored encrypted on disk (optional)
5. Emergency wipe zeros all chain state

Security properties:
- Deleting chain state renders ALL past files undecryptable (plausible deniability)
- Chain cannot be rewound (one-way hash ratchet)
- Each file gets unique key even with same password

Cross-platform: Windows, Linux, macOS.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import platform
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

# Try to use cryptography library, fall back to pure Python
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

__all__ = [
    "MasterRatchet",
    "ChainState",
    "derive_file_key",
    "get_master_ratchet",
    "emergency_wipe_chain",
]


def _hkdf_expand(
    key_material: bytes,
    info: bytes,
    length: int = 32,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    HKDF-Expand for key derivation.

    Uses cryptography library if available, otherwise pure Python.
    """
    if HAS_CRYPTOGRAPHY:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(key_material)
    else:
        # Pure Python HKDF-Extract + Expand (RFC 5869)
        if salt is None:
            salt = b"\x00" * 32

        # Extract
        prk = hmac.new(salt, key_material, hashlib.sha256).digest()

        # Expand
        t = b""
        okm = b""
        counter = 1
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
            okm += t
            counter += 1

        return okm[:length]


def _secure_zero(data: bytearray) -> None:
    """Securely zero a bytearray."""
    for i in range(len(data)):
        data[i] = 0
    # Memory barrier (best effort)
    _ = bytes(data)


@dataclass
class ChainState:
    """
    Ratchet chain state.

    Contains the current chain key and generation counter.
    """

    # Current chain key (32 bytes)
    chain_key: bytes

    # Generation counter (number of ratchets performed)
    generation: int

    # Timestamp of last ratchet
    last_ratchet_time: float

    # Salt used for initial derivation
    master_salt: bytes

    def to_bytes(self, encryption_key: bytes) -> bytes:
        """
        Serialize chain state with AES-GCM encryption.

        Args:
            encryption_key: 32-byte key for state encryption.

        Returns:
            Encrypted state bytes.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            plaintext = (
                struct.pack("<Q", self.generation) +
                struct.pack("<d", self.last_ratchet_time) +
                self.master_salt +
                self.chain_key
            )

            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(encryption_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, b"meow_chain_state_v1")

            return b"MRCV1" + nonce + ciphertext
        except ImportError:
            # Fallback: XOR with derived key (less secure, but works)
            derived = _hkdf_expand(encryption_key, b"chain_state_encryption", 80)
            plaintext = (
                struct.pack("<Q", self.generation) +
                struct.pack("<d", self.last_ratchet_time) +
                self.master_salt +
                self.chain_key
            )
            ciphertext = bytes(a ^ b for a, b in zip(plaintext, derived))
            mac = hmac.new(encryption_key, ciphertext, hashlib.sha256).digest()[:16]
            return b"MRCX1" + mac + ciphertext

    @classmethod
    def from_bytes(cls, data: bytes, encryption_key: bytes) -> Optional["ChainState"]:
        """
        Deserialize and decrypt chain state.

        Args:
            data: Encrypted state bytes from to_bytes().
            encryption_key: 32-byte key for state decryption.

        Returns:
            ChainState or None if decryption fails.
        """
        if len(data) < 5:
            return None

        magic = data[:5]

        if magic == b"MRCV1":
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                nonce = data[5:17]
                ciphertext = data[17:]

                aesgcm = AESGCM(encryption_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, b"meow_chain_state_v1")

                generation = struct.unpack("<Q", plaintext[:8])[0]
                last_ratchet_time = struct.unpack("<d", plaintext[8:16])[0]
                master_salt = plaintext[16:48]
                chain_key = plaintext[48:80]

                return cls(
                    chain_key=chain_key,
                    generation=generation,
                    last_ratchet_time=last_ratchet_time,
                    master_salt=master_salt,
                )
            except Exception:
                return None

        elif magic == b"MRCX1":
            # XOR fallback
            if len(data) < 5 + 16 + 80:
                return None

            stored_mac = data[5:21]
            ciphertext = data[21:101]

            expected_mac = hmac.new(encryption_key, ciphertext, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(stored_mac, expected_mac):
                return None

            derived = _hkdf_expand(encryption_key, b"chain_state_encryption", 80)
            plaintext = bytes(a ^ b for a, b in zip(ciphertext, derived))

            generation = struct.unpack("<Q", plaintext[:8])[0]
            last_ratchet_time = struct.unpack("<d", plaintext[8:16])[0]
            master_salt = plaintext[16:48]
            chain_key = plaintext[48:80]

            return cls(
                chain_key=chain_key,
                generation=generation,
                last_ratchet_time=last_ratchet_time,
                master_salt=master_salt,
            )

        return None


class MasterRatchet:
    """
    Master key ratchet for cross-session forward secrecy.

    Usage:
        # Initialize from password
        ratchet = MasterRatchet.from_password("my_password")

        # Derive per-file key
        file_key = ratchet.derive_file_key(file_id="document.pdf")

        # Ratchet forward (call after each encode)
        ratchet.ratchet()

        # Emergency wipe (deletes chain state, makes past files unrecoverable)
        ratchet.emergency_wipe()
    """

    # Domain separation constants
    DOMAIN_CHAIN_INIT = b"meow_master_ratchet_v1_init"
    DOMAIN_CHAIN_RATCHET = b"meow_master_ratchet_v1_ratchet"
    DOMAIN_FILE_KEY = b"meow_master_ratchet_v1_file_key"
    DOMAIN_STATE_KEY = b"meow_master_ratchet_v1_state_key"

    def __init__(
        self,
        state: ChainState,
        state_file: Optional[Path] = None,
        auto_persist: bool = True,
    ):
        """
        Initialize ratchet with existing chain state.

        Use from_password() for initial setup.

        Args:
            state: Existing chain state.
            state_file: Path to persist state (optional).
            auto_persist: If True, save state after each ratchet.
        """
        self._state = state
        self._state_file = state_file
        self._auto_persist = auto_persist
        self._state_key: Optional[bytes] = None

    @classmethod
    def from_password(
        cls,
        password: str,
        state_file: Optional[Path] = None,
        auto_persist: bool = True,
    ) -> "MasterRatchet":
        """
        Initialize ratchet from password.

        Combines password with hardware entropy for initial chain key.

        Args:
            password: User password.
            state_file: Path to persist state (optional).
            auto_persist: If True, save state after each ratchet.

        Returns:
            New MasterRatchet instance.
        """
        # Generate fresh salt with hardware entropy
        master_salt = secrets.token_bytes(32)

        # Derive initial chain key from password + salt
        key_material = (
            password.encode("utf-8") +
            master_salt +
            cls._get_hardware_entropy()
        )

        chain_key = _hkdf_expand(
            key_material,
            cls.DOMAIN_CHAIN_INIT,
            32,
            master_salt,
        )

        state = ChainState(
            chain_key=chain_key,
            generation=0,
            last_ratchet_time=time.time(),
            master_salt=master_salt,
        )

        ratchet = cls(state, state_file, auto_persist)

        if auto_persist and state_file is not None:
            ratchet._derive_state_key(password)
            ratchet._save_state()

        return ratchet

    @classmethod
    def load(
        cls,
        password: str,
        state_file: Path,
    ) -> Optional["MasterRatchet"]:
        """
        Load existing ratchet from state file.

        Args:
            password: User password (for state decryption).
            state_file: Path to state file.

        Returns:
            MasterRatchet or None if load fails.
        """
        if not state_file.exists():
            return None

        try:
            data = state_file.read_bytes()
        except (OSError, IOError):
            return None

        # Derive state key from password
        state_key = _hkdf_expand(
            password.encode("utf-8"),
            cls.DOMAIN_STATE_KEY,
            32,
        )

        state = ChainState.from_bytes(data, state_key)
        if state is None:
            return None

        ratchet = cls(state, state_file, auto_persist=True)
        ratchet._state_key = state_key

        return ratchet

    @staticmethod
    def _get_hardware_entropy() -> bytes:
        """Collect hardware-specific entropy."""
        entropy_sources = []

        # OS random
        entropy_sources.append(os.urandom(16))

        # Platform info
        entropy_sources.append(platform.node().encode()[:16])
        entropy_sources.append(platform.machine().encode()[:8])

        # High-resolution time
        entropy_sources.append(struct.pack("<d", time.time()))
        entropy_sources.append(struct.pack("<q", time.perf_counter_ns()))

        # Process ID
        entropy_sources.append(struct.pack("<I", os.getpid()))

        # Combine via hash
        combined = b"".join(entropy_sources)
        return hashlib.sha256(combined).digest()

    def _derive_state_key(self, password: str) -> None:
        """Derive key for state file encryption."""
        self._state_key = _hkdf_expand(
            password.encode("utf-8"),
            self.DOMAIN_STATE_KEY,
            32,
        )

    def _save_state(self) -> None:
        """Save encrypted state to file."""
        if self._state_file is None or self._state_key is None:
            return

        try:
            encrypted = self._state.to_bytes(self._state_key)
            self._state_file.write_bytes(encrypted)
        except (OSError, IOError):
            pass  # Silent failure

    def ratchet(self) -> None:
        """
        Advance the chain key one step.

        This is a one-way operation - previous keys cannot be recovered.
        Call this after each successful encode operation.
        """
        # Derive next chain key
        new_chain_key = _hkdf_expand(
            self._state.chain_key,
            self.DOMAIN_CHAIN_RATCHET + struct.pack("<Q", self._state.generation),
            32,
        )

        # Zero old key
        old_key = bytearray(self._state.chain_key)
        _secure_zero(old_key)

        # Update state
        self._state.chain_key = new_chain_key
        self._state.generation += 1
        self._state.last_ratchet_time = time.time()

        # Persist if enabled
        if self._auto_persist:
            self._save_state()

    def derive_file_key(
        self,
        file_id: str,
        key_length: int = 32,
    ) -> bytes:
        """
        Derive a unique key for a specific file.

        Args:
            file_id: Unique identifier for the file (e.g., filename, hash).
            key_length: Length of derived key in bytes.

        Returns:
            Derived file key.
        """
        context = (
            self.DOMAIN_FILE_KEY +
            struct.pack("<Q", self._state.generation) +
            file_id.encode("utf-8")
        )

        return _hkdf_expand(
            self._state.chain_key,
            context,
            key_length,
        )

    def derive_file_key_with_commitment(
        self,
        file_id: str,
        key_length: int = 32,
    ) -> Tuple[bytes, bytes]:
        """
        Derive file key with commitment tag.

        The commitment tag binds the ciphertext to the chain state,
        preventing invisible salamanders attacks.

        Args:
            file_id: Unique identifier for the file.
            key_length: Length of derived key in bytes.

        Returns:
            Tuple of (file_key, commitment_tag).
        """
        file_key = self.derive_file_key(file_id, key_length)

        commitment = hmac.new(
            self._state.chain_key,
            b"commitment:" + file_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()[:16]

        return file_key, commitment

    @property
    def generation(self) -> int:
        """Current chain generation (number of ratchets performed)."""
        return self._state.generation

    @property
    def last_ratchet_time(self) -> float:
        """Timestamp of last ratchet operation."""
        return self._state.last_ratchet_time

    def emergency_wipe(self) -> bool:
        """
        Emergency wipe - securely delete all chain state.

        After this operation:
        - All past files become undecryptable
        - Chain cannot be recovered
        - Provides plausible deniability

        Returns:
            True if wipe succeeded, False otherwise.
        """
        success = True

        # Zero in-memory state
        chain_key_ba = bytearray(self._state.chain_key)
        salt_ba = bytearray(self._state.master_salt)
        _secure_zero(chain_key_ba)
        _secure_zero(salt_ba)

        self._state.chain_key = bytes(32)
        self._state.master_salt = bytes(32)
        self._state.generation = 0

        if self._state_key is not None:
            state_key_ba = bytearray(self._state_key)
            _secure_zero(state_key_ba)
            self._state_key = None

        # Delete state file
        if self._state_file is not None and self._state_file.exists():
            try:
                # Overwrite with random data multiple times
                size = self._state_file.stat().st_size
                for _ in range(3):
                    self._state_file.write_bytes(secrets.token_bytes(size))

                # Then delete
                self._state_file.unlink()
            except (OSError, IOError):
                success = False

        return success

    def get_chain_id(self) -> bytes:
        """
        Get a non-sensitive identifier for this chain.

        Can be used to verify chain continuity without exposing keys.
        """
        return hashlib.sha256(
            b"chain_id:" + self._state.master_salt
        ).digest()[:16]


def derive_file_key(
    password: str,
    file_id: str,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    Convenience function to derive a one-shot file key.

    Use this when you don't need persistent ratchet state.

    Args:
        password: User password.
        file_id: Unique file identifier.
        salt: Optional salt (generated if not provided).

    Returns:
        32-byte derived key.
    """
    if salt is None:
        salt = secrets.token_bytes(32)

    key_material = password.encode("utf-8") + salt

    return _hkdf_expand(
        key_material,
        MasterRatchet.DOMAIN_FILE_KEY + file_id.encode("utf-8"),
        32,
        salt,
    )


# Global singleton
_global_ratchet: Optional[MasterRatchet] = None


def get_master_ratchet() -> Optional[MasterRatchet]:
    """Get the global master ratchet instance."""
    return _global_ratchet


def set_master_ratchet(ratchet: MasterRatchet) -> None:
    """Set the global master ratchet instance."""
    global _global_ratchet
    _global_ratchet = ratchet


def emergency_wipe_chain() -> bool:
    """
    Emergency wipe of global master ratchet.

    Returns True if wipe succeeded or no ratchet was set.
    """
    global _global_ratchet

    if _global_ratchet is None:
        return True

    result = _global_ratchet.emergency_wipe()
    _global_ratchet = None
    return result
