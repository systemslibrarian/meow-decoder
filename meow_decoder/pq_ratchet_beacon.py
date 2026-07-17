"""
Post-Quantum Ratchet Beacon using ML-KEM-1024.

Replaces classical X25519 rekey beacons with ML-KEM-1024 (FIPS 203)
for quantum-resistant post-compromise security in the symmetric ratchet.

Protocol:
1. Sender encapsulates to receiver's ML-KEM public key
2. Ciphertext (1568 bytes) embedded in frame header
3. Shared secret mixed into chain key via HKDF
4. Receiver decapsulates to recover shared secret

Security Properties:
- Post-quantum KEM (NIST Level 5 security)
- Transcript binding: ciphertext bound in AAD
- Forward secrecy: even with chain_key[N], cannot derive enhanced keys
  without receiver's ML-KEM private key
- Compatible with MSR v1.2 ratchet protocol

Integration:
    from meow_decoder.pq_ratchet_beacon import PQRatchetBeacon

    beacon = PQRatchetBeacon(receiver_pk)
    ciphertext, enhanced_key = beacon.encapsulate(message_key)

    # On receiver:
    enhanced_key = beacon.decapsulate(ciphertext, message_key)

Cross-platform: Windows, Linux, macOS
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "PQRatchetBeacon",
    "PQBeaconKeyPair",
    "generate_beacon_keypair",
    "MLKEM1024_CIPHERTEXT_SIZE",
    "MLKEM1024_PUBLIC_KEY_SIZE",
]

# ML-KEM-1024 sizes (FIPS 203 / Kyber1024)
MLKEM1024_CIPHERTEXT_SIZE = 1568
MLKEM1024_PUBLIC_KEY_SIZE = 1568
MLKEM1024_SECRET_KEY_SIZE = 3168
MLKEM1024_SHARED_SECRET_SIZE = 32

# Domain separation
BEACON_MIX_DOMAIN = b"meow_pq_beacon_mix_v1"
BEACON_DERIVE_DOMAIN = b"meow_pq_beacon_derive_v1"

# Check for Rust backend
_RUST_MLKEM_AVAILABLE = False
try:
    import meow_crypto_rs as _rs

    _RUST_MLKEM_AVAILABLE = hasattr(_rs, "mlkem1024_keygen")
except ImportError:
    pass

# Check for pqcrypto or ml-kem pure Python
_MLKEM_PURE_AVAILABLE = False
try:
    from ml_kem import ML_KEM_1024  # type: ignore

    _MLKEM_PURE_AVAILABLE = True
except ImportError:
    pass

# Check for oqs backend
_OQS_AVAILABLE = False
try:
    import oqs  # type: ignore[import-not-found]

    _OQS_AVAILABLE = "Kyber1024" in oqs.get_enabled_kem_mechanisms()
except (ImportError, AttributeError):
    pass


@dataclass
class PQBeaconKeyPair:
    """ML-KEM-1024 keypair for PQ ratchet beacons."""

    secret_key: bytes  # 3168 bytes
    public_key: bytes  # 1568 bytes

    def export_public_key(self) -> bytes:
        """Export public key for distribution."""
        return self.public_key

    def __del__(self):
        """Best-effort secret zeroization on collection.

        bytes are immutable; we copy into a bytearray and zero that
        as a defensive overwrite on the duplicated copy. The original
        immutable secret_key bytes object will be GC'd normally.
        """
        sk = getattr(self, "secret_key", None)
        if sk:
            try:
                from .crypto_backend import secure_zero_memory

                secure_zero_memory(bytearray(sk))
            except Exception:
                pass
            self.secret_key = b""


def _mlkem1024_keygen() -> Tuple[bytes, bytes]:
    """Generate ML-KEM-1024 keypair."""
    if _RUST_MLKEM_AVAILABLE:
        import meow_crypto_rs as rs

        return rs.mlkem1024_keygen()

    if _MLKEM_PURE_AVAILABLE:
        kem = ML_KEM_1024()
        pk, sk = kem.keygen()
        return sk, pk

    if _OQS_AVAILABLE:
        with oqs.KeyEncapsulation("Kyber1024") as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return sk, pk

    raise RuntimeError(
        "No secure ML-KEM-1024 implementation available (Rust, ml-kem, or OQS). "
        "Insecure stubs are permanently disabled."
    )


def _mlkem1024_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate to ML-KEM-1024 public key."""
    if _RUST_MLKEM_AVAILABLE:
        import meow_crypto_rs as rs

        # Rust returns (ss, ct); normalise to (ct, ss) to match other backends.
        ss, ct = rs.mlkem1024_encapsulate(pk)
        return ct, ss

    if _MLKEM_PURE_AVAILABLE:
        kem = ML_KEM_1024()
        ct, ss = kem.encaps(pk)
        return ct, ss

    if _OQS_AVAILABLE:
        with oqs.KeyEncapsulation("Kyber1024") as kem:
            ct, ss = kem.encap_secret(pk)
        return ct, ss

    raise RuntimeError(
        "No secure ML-KEM-1024 implementation available (Rust, ml-kem, or OQS). "
        "Insecure stubs are permanently disabled."
    )


def _mlkem1024_decapsulate(sk: bytes, ct: bytes) -> bytes:
    """Decapsulate ML-KEM-1024 ciphertext."""
    if _RUST_MLKEM_AVAILABLE:
        import meow_crypto_rs as rs

        return rs.mlkem1024_decapsulate(sk, ct)

    if _MLKEM_PURE_AVAILABLE:
        kem = ML_KEM_1024()
        return kem.decaps(sk, ct)

    if _OQS_AVAILABLE:
        # SECURITY (M8): liboqs-python stores the decapsulation key in
        # ``self.secret_key`` (settable only via the constructor). The prior
        # ``kem._secret_key = sk`` assignment left ``self.secret_key`` unset,
        # so ``decap_secret`` raised AttributeError and OQS-only installs could
        # never decode. Pass the key through the constructor to match the
        # keygen/encapsulate paths above.
        with oqs.KeyEncapsulation("Kyber1024", secret_key=sk) as kem:
            return kem.decap_secret(ct)

    raise RuntimeError(
        "No secure ML-KEM-1024 implementation available (Rust, ml-kem, or OQS). "
        "Insecure stubs are permanently disabled."
    )


def generate_beacon_keypair() -> PQBeaconKeyPair:
    """
    Generate ML-KEM-1024 keypair for PQ ratchet beacons.

    Returns:
        PQBeaconKeyPair with secret and public keys.
    """
    sk, pk = _mlkem1024_keygen()
    return PQBeaconKeyPair(secret_key=sk, public_key=pk)


class PQRatchetBeacon:
    """
    Post-Quantum ratchet beacon using ML-KEM-1024.

    Provides quantum-resistant post-compromise security for the
    symmetric ratchet by periodically injecting fresh entropy
    that requires the receiver's ML-KEM private key to recover.
    """

    def __init__(
        self,
        receiver_public_key: Optional[bytes] = None,
        receiver_keypair: Optional[PQBeaconKeyPair] = None,
    ):
        """
        Initialize PQ ratchet beacon.

        Args:
            receiver_public_key: Receiver's ML-KEM-1024 public key (for sender).
            receiver_keypair: Receiver's ML-KEM-1024 keypair (for receiver).

        Either receiver_public_key OR receiver_keypair must be provided.
        """
        self.receiver_public_key = receiver_public_key
        self.receiver_keypair = receiver_keypair

        if receiver_public_key is None and receiver_keypair is None:
            raise ValueError("Either receiver_public_key or receiver_keypair must be provided")

        if receiver_keypair is not None:
            self.receiver_public_key = receiver_keypair.public_key

    def encapsulate(
        self,
        message_key: bytes,
        salt: bytes = b"",
    ) -> Tuple[bytes, bytes]:
        """
        Encapsulate fresh entropy and mix into message key.

        Used by SENDER to generate PQ beacon.

        Args:
            message_key: Current message key (32 bytes).
            salt: Optional salt for HKDF mixing.

        Returns:
            Tuple of (ciphertext, enhanced_message_key):
            - ciphertext: ML-KEM ciphertext (1568 bytes) to embed in frame
            - enhanced_message_key: message_key mixed with PQ shared secret
        """
        if self.receiver_public_key is None:
            raise ValueError("Receiver public key required for encapsulation")

        # Encapsulate to receiver's public key
        ciphertext, shared_secret = _mlkem1024_encapsulate(self.receiver_public_key)

        # Mix shared secret into message key
        enhanced_key = self._mix_beacon(message_key, shared_secret, salt)

        return ciphertext, enhanced_key

    def decapsulate(
        self,
        ciphertext: bytes,
        message_key: bytes,
        salt: bytes = b"",
    ) -> bytes:
        """
        Decapsulate beacon and mix into message key.

        Used by RECEIVER to recover enhanced message key.

        Args:
            ciphertext: ML-KEM ciphertext from frame (1568 bytes).
            message_key: Current message key (32 bytes).
            salt: Optional salt for HKDF mixing (must match sender).

        Returns:
            Enhanced message key.

        Raises:
            ValueError: If decapsulation fails.
        """
        if self.receiver_keypair is None:
            raise ValueError("Receiver keypair required for decapsulation")

        if len(ciphertext) != MLKEM1024_CIPHERTEXT_SIZE:
            raise ValueError(
                f"Invalid ciphertext size: {len(ciphertext)}, "
                f"expected {MLKEM1024_CIPHERTEXT_SIZE}"
            )

        # Decapsulate
        shared_secret = _mlkem1024_decapsulate(self.receiver_keypair.secret_key, ciphertext)

        # Mix shared secret into message key
        enhanced_key = self._mix_beacon(message_key, shared_secret, salt)

        return enhanced_key

    def _mix_beacon(
        self,
        message_key: bytes,
        shared_secret: bytes,
        salt: bytes,
    ) -> bytes:
        """
        Mix PQ shared secret into message key via HKDF.

        All secret material (message_key, shared_secret) is imported into
        Rust handles immediately. The HKDF computation happens entirely
        in the Rust backend — secrets never flow through Python's hmac
        module, preventing GC/swap exposure.

        Args:
            message_key: Current message key (32 bytes).
            shared_secret: ML-KEM shared secret (32 bytes).
            salt: Optional additional salt.

        Returns:
            Enhanced message key (32 bytes).

        Raises:
            RuntimeError: If the Rust crypto backend is unavailable.
        """
        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        effective_salt = salt or b"\x00" * 32

        # Import message_key into a Rust handle — key bytes leave Python
        # immediately and are protected by guard pages + zeroize-on-drop.
        mk_handle = hb.import_key(message_key)
        try:
            # HKDF mixing entirely in Rust:
            #   IKM  = message_key (handle) || shared_secret (extra_ikm)
            #   salt = effective_salt
            #   info = BEACON_MIX_DOMAIN
            # The shared_secret bytes cross the FFI boundary but are
            # never processed by Python's hmac/hashlib.
            enhanced_handle = hb.mix_hkdf(
                mk_handle, shared_secret, effective_salt, BEACON_MIX_DOMAIN, 32
            )
            try:
                # Derive the final enhanced key bytes via a second HKDF
                # pass to maintain domain separation parity with the
                # original two-step Extract-then-Expand construction.
                result = hb.derive_key_hkdf_bytes(
                    enhanced_handle, effective_salt, BEACON_DERIVE_DOMAIN, 32
                )
                return result
            finally:
                hb.drop(enhanced_handle)
        finally:
            hb.drop(mk_handle)

    def _mix_beacon_handle(
        self,
        message_key_handle: int,
        shared_secret: bytes,
        salt: bytes,
    ) -> int:
        """
        Handle-based variant — both input and output stay in Rust.

        Use this when the caller already has a handle (e.g. from the
        symmetric ratchet).  Returns a new handle; caller MUST drop
        the old message_key_handle.

        Args:
            message_key_handle: Rust handle for the current message key.
            shared_secret: ML-KEM shared secret (32 bytes).
            salt: Optional additional salt.

        Returns:
            Handle to enhanced message key (stays in Rust).
        """
        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        effective_salt = salt or b"\x00" * 32
        return hb.mix_hkdf(message_key_handle, shared_secret, effective_salt, BEACON_MIX_DOMAIN, 32)


@dataclass
class PQBeaconFrame:
    """
    Frame header extension for PQ beacon.

    Embedded in frame when beacon is active.
    """

    # Magic identifier
    MAGIC = b"PQBCN"

    # ML-KEM-1024 ciphertext
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """Serialize beacon frame."""
        return self.MAGIC + struct.pack(">H", len(self.ciphertext)) + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["PQBeaconFrame"]:
        """Deserialize beacon frame, or None if not a beacon."""
        if len(data) < 7:  # MAGIC(5) + len(2)
            return None

        if data[:5] != cls.MAGIC:
            return None

        ct_len = struct.unpack(">H", data[5:7])[0]
        if ct_len == 0:
            return None
        if len(data) < 7 + ct_len:
            return None

        ciphertext = data[7 : 7 + ct_len]
        return cls(ciphertext=ciphertext)

    @classmethod
    def header_size(cls) -> int:
        """Return fixed header size (before ciphertext)."""
        return 5 + 2  # MAGIC + length

    @classmethod
    def total_size(cls) -> int:
        """Return total size with ML-KEM-1024 ciphertext."""
        return cls.header_size() + MLKEM1024_CIPHERTEXT_SIZE


def integrate_with_ratchet(
    chain_key: bytes,
    receiver_pk: bytes,
    frame_index: int,
    rekey_interval: int = 32,
) -> Tuple[bytes, Optional[bytes]]:
    """
    Helper to integrate PQ beacon with existing ratchet.

    Args:
        chain_key: Current chain key.
        receiver_pk: Receiver's ML-KEM-1024 public key.
        frame_index: Current frame index.
        rekey_interval: How often to inject beacon (default: every 32 frames).

    Returns:
        Tuple of (enhanced_chain_key, beacon_ciphertext_or_none).
    """
    if rekey_interval == 0 or frame_index % rekey_interval != 0:
        # No beacon this frame
        return chain_key, None

    beacon = PQRatchetBeacon(receiver_public_key=receiver_pk)
    ciphertext, enhanced_key = beacon.encapsulate(
        chain_key,
        salt=struct.pack(">I", frame_index),
    )

    return enhanced_key, ciphertext
