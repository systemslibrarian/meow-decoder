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
- The in-memory chain key is one-way: a compromise of the *current* key
  cannot recover past keys (forward secrecy). NOTE: the *on-disk* state
  file can be replaced with an older authentic copy to rewind the chain
  (reusing past file keys) unless rollback protection is used. `load()`
  tracks the highest generation ever observed for a state file in a
  sidecar watermark and emits a loud warning (or refuses the load, with
  `reject_rollback=True`) when a lower generation is presented. Superseded
  state-file copies must still be destroyed to fully preserve the property.
- Each file gets unique key even with same password

Implementation note (gemini #1, 2026-05-04; updated 2026-07-05):
The chain key never leaves Rust. `ChainState.chain_handle` is an opaque
HandleBackend handle; HKDF derivations and AES-GCM sealing for at-rest
persistence happen entirely in Rust. The current on-disk format is
`MRCV3`, whose at-rest key-encryption key is stretched with Argon2id
(salted by the per-chain `master_salt`) rather than a single unsalted
HKDF (see SECURITY H2). Legacy `MRCV2` files (unsalted/unstretched KEK)
are still *readable* and are transparently migrated to `MRCV3` on their
next persist. The older `MRCV1`/`MRCX1` formats cannot be loaded.

Cross-platform: Windows, Linux, macOS.
"""

from __future__ import annotations

import hashlib
import os
import platform
import secrets
import struct
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from meow_decoder.argon2_presets import get_preset
from meow_decoder.crypto_backend import HandleBackend, get_handle_backend

__all__ = [
    "MasterRatchet",
    "ChainState",
    "derive_file_key",
    "get_master_ratchet",
    "set_master_ratchet",
    "emergency_wipe_chain",
]


# ─── On-disk format constants ───────────────────────────────────────────────

# SECURITY (H2): MRCV3 seals the on-disk chain key under an Argon2id-stretched
# KEK (salted by master_salt). MRCV2 is the legacy unsalted-HKDF format — kept
# read-only for backward compatibility and migrated to MRCV3 on next persist.
_FORMAT_MAGIC_V2 = b"MRCV2"  # legacy: unsalted, unstretched HKDF KEK (read-only)
_FORMAT_MAGIC_V3 = b"MRCV3"  # current: Argon2id(master_salt) → HKDF KEK
_FORMAT_MAGIC = _FORMAT_MAGIC_V3  # magic written for all new state files
_FORMAT_AAD = b"meow_chain_state_v2"
_SEAL_AAD = b"meow_chain_seal_v2"

# Layout: magic(5) || generation(8 LE) || timestamp(8 LE double) ||
#         master_salt(32) || seal_nonce(12) || sealed_chain_key(48)
_HEADER_LEN = 5 + 8 + 8 + 32 + 12 + 48  # = 113


def _zero_bytearray(data: bytearray) -> None:
    """Best-effort zero of a bytearray (CPython only — bytes objects are immutable)."""
    for i in range(len(data)):
        data[i] = 0


@dataclass
class ChainState:
    """
    Ratchet chain state.

    `chain_handle` is an opaque HandleBackend handle ID; the actual chain
    key bytes never enter Python. `master_salt` is non-secret (per-file
    randomness used for KDF domain separation) and lives in Python as bytes.
    """

    chain_handle: Optional[int]
    generation: int
    last_ratchet_time: float
    master_salt: bytes


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
        backend: Optional[HandleBackend] = None,
    ):
        """
        Initialize ratchet with existing chain state.

        Use from_password() for initial setup.

        Args:
            state: Existing chain state.
            state_file: Path to persist state (optional).
            auto_persist: If True, save state after each ratchet.
            backend: HandleBackend instance (defaults to global singleton).
        """
        self._state = state
        self._state_file = state_file
        self._auto_persist = auto_persist
        self._state_key_handle: Optional[int] = None
        self._hb: HandleBackend = backend if backend is not None else get_handle_backend()

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
        The password and IKM bytes briefly live in Python (they originate
        from user input / OS entropy); the derived chain key is imported
        directly into a Rust handle and never re-exported.
        """
        hb = get_handle_backend()

        master_salt = secrets.token_bytes(32)

        # IKM = password || salt || hardware_entropy. Hold in a bytearray
        # so we can overwrite after the derive.
        password_bytes = password.encode("utf-8")
        ikm = bytearray(password_bytes)
        ikm.extend(master_salt)
        ikm.extend(cls._get_hardware_entropy())

        try:
            chain_handle = hb.derive_key_hkdf_raw(
                bytes(ikm), master_salt, cls.DOMAIN_CHAIN_INIT, 32
            )
        finally:
            _zero_bytearray(ikm)

        state = ChainState(
            chain_handle=chain_handle,
            generation=0,
            last_ratchet_time=time.time(),
            master_salt=master_salt,
        )

        ratchet = cls(state, state_file, auto_persist, backend=hb)

        if auto_persist and state_file is not None:
            ratchet._derive_state_key(password)
            ratchet._save_state()

        return ratchet

    @classmethod
    def load(
        cls,
        password: str,
        state_file: Path,
        *,
        reject_rollback: bool = False,
    ) -> Optional["MasterRatchet"]:
        """
        Load existing ratchet from state file.

        Returns None on any failure (missing file, IO error, decryption
        failure, format mismatch).

        Backward compatibility (SECURITY H2): both MRCV3 files (Argon2id-
        stretched KEK) and legacy MRCV2 files (unsalted HKDF KEK) are
        readable. A loaded MRCV2 file is transparently migrated to MRCV3 on
        its next persist.

        Rollback protection (SECURITY L15): the highest generation ever
        observed for this state file is tracked in a sidecar watermark. If
        the loaded generation is lower than that watermark, the state file
        may have been replaced with an older authentic copy (rewinding the
        chain and reusing past file keys). This always emits a loud warning;
        with ``reject_rollback=True`` the load is refused (returns None).
        """
        if not state_file.exists():
            return None

        try:
            data = state_file.read_bytes()
        except (OSError, IOError):
            return None

        # Detect on-disk format by magic before choosing the KEK derivation.
        if len(data) != _HEADER_LEN:
            return None
        magic = data[:5]
        if magic == _FORMAT_MAGIC_V3:
            legacy_v2 = False
        elif magic == _FORMAT_MAGIC_V2:
            legacy_v2 = True
        else:
            return None

        # master_salt lives in the header (offset 21:53) and salts the KEK.
        master_salt = data[21:53]

        hb = get_handle_backend()

        # Derive the state KEK as a handle (Argon2id for V3, legacy HKDF for V2).
        state_key_handle = cls._derive_state_key_handle(
            hb, password, master_salt, legacy_v2=legacy_v2
        )

        try:
            state = _decode_chain_state(data, state_key_handle, hb)
        except (ValueError, RuntimeError):
            hb.drop(state_key_handle)
            return None

        if state is None:
            hb.drop(state_key_handle)
            return None

        # SECURITY (L15): compare the loaded generation against the highest
        # generation ever seen for this file (persisted out-of-band in a
        # sidecar). A lower generation means the state file was rewound.
        watermark = _read_generation_watermark(state_file)
        if watermark is not None and state.generation < watermark:
            warnings.warn(
                "Master ratchet rollback detected: loaded generation "
                f"{state.generation} is lower than the highest previously "
                f"observed generation {watermark}. The state file may have "
                "been replaced with an older copy, rewinding the chain and "
                "reusing past file keys (forward-secrecy violation).",
                stacklevel=2,
            )
            if reject_rollback:
                if state.chain_handle is not None:
                    hb.drop(state.chain_handle)
                hb.drop(state_key_handle)
                return None

        ratchet = cls(state, state_file, auto_persist=True, backend=hb)
        ratchet._state_key_handle = state_key_handle

        # Record the highest generation observed (monotonic watermark).
        _update_generation_watermark(state_file, state.generation)

        if legacy_v2:
            # SECURITY (H2): migrate the KEK to the Argon2id-stretched MRCV3
            # scheme so the next persist re-seals under the stronger KDF.
            ratchet._derive_state_key(password)

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

    @staticmethod
    def _derive_state_key_handle(
        hb: HandleBackend,
        password: str,
        master_salt: bytes,
        *,
        legacy_v2: bool = False,
    ) -> int:
        """Derive the at-rest KEK handle from the password.

        SECURITY (H2): the sealed on-disk state file (MRCV3) is a per-guess
        offline oracle (GCM tag), so its key-encryption key must be memory-
        hard. The KEK is now derived as
        ``HKDF(Argon2id(password, salt=master_salt), DOMAIN_STATE_KEY)`` —
        the per-chain ``master_salt`` (already stored in the file header)
        salts the Argon2id stretch, defeating precomputation and slowing
        each brute-force guess to one Argon2id evaluation.

        MRCV2 (legacy, read-only): the original unsalted/unstretched
        ``HKDF-SHA256(password, salt=b"", DOMAIN_STATE_KEY)``. Retained only
        so pre-existing state files can still be loaded; such files are
        migrated to MRCV3 on the next persist.
        """
        password_bytes = bytearray(password.encode("utf-8"))
        try:
            if legacy_v2:
                # Legacy MRCV2 derivation — read-only compatibility path.
                return hb.derive_key_hkdf_raw(
                    bytes(password_bytes), b"", MasterRatchet.DOMAIN_STATE_KEY, 32
                )
            preset = get_preset()
            # Argon2id requires a 16-byte salt; the per-chain master_salt is
            # 32 bytes, so use its first 16 bytes (deterministic on save/load).
            argon_handle = hb.derive_key_argon2id(
                bytes(password_bytes),
                master_salt[:16],
                memory_kib=preset.memory_kib,
                iterations=preset.iterations,
                parallelism=preset.parallelism,
            )
            try:
                # HKDF-expand the Argon2id output with DOMAIN_STATE_KEY.
                return hb.derive_key_hkdf(argon_handle, b"", MasterRatchet.DOMAIN_STATE_KEY, 32)
            finally:
                hb.drop(argon_handle)
        finally:
            _zero_bytearray(password_bytes)

    def _derive_state_key(self, password: str) -> None:
        """Derive (or re-derive) the at-rest KEK handle for this ratchet (MRCV3)."""
        if self._state_key_handle is not None:
            self._hb.drop(self._state_key_handle)
            self._state_key_handle = None
        self._state_key_handle = self._derive_state_key_handle(
            self._hb, password, self._state.master_salt
        )

    def _save_state(self) -> None:
        """Save encrypted state to file. Silent on IO errors (best-effort)."""
        if self._state_file is None or self._state_key_handle is None:
            return
        if self._state.chain_handle is None:
            return

        seal_nonce = secrets.token_bytes(12)

        # AAD binds the on-disk metadata to the sealed chain key. Tampering
        # with generation/timestamp/master_salt invalidates the seal.
        meta = (
            _FORMAT_MAGIC
            + struct.pack("<Q", self._state.generation)
            + struct.pack("<d", self._state.last_ratchet_time)
            + self._state.master_salt
        )
        sealed = self._hb.seal_key(
            self._state.chain_handle,
            self._state_key_handle,
            seal_nonce,
            aad=meta + _SEAL_AAD,
        )

        blob = meta + seal_nonce + sealed
        try:
            self._state_file.write_bytes(blob)
            # SECURITY (L15): advance the rollback watermark on every persist.
            _update_generation_watermark(self._state_file, self._state.generation)
        except (OSError, IOError):
            pass

    def ratchet(self) -> None:
        """
        Advance the chain key one step.

        This is a one-way operation - previous keys cannot be recovered.
        Call this after each successful encode operation.
        """
        if self._state.chain_handle is None:
            raise RuntimeError("Cannot ratchet a wiped chain")

        info = self.DOMAIN_CHAIN_RATCHET + struct.pack("<Q", self._state.generation)
        new_handle = self._hb.derive_key_hkdf(self._state.chain_handle, b"", info, 32)

        old = self._state.chain_handle
        self._state.chain_handle = new_handle
        self._state.generation += 1
        self._state.last_ratchet_time = time.time()
        self._hb.drop(old)

        if self._auto_persist:
            self._save_state()

    def derive_file_key(
        self,
        file_id: str,
        key_length: int = 32,
    ) -> bytes:
        """
        Derive a unique key for a specific file.

        Returns raw bytes — file keys are consumed by callers that need
        bytes (e.g. shamir_split, downstream AES setup). The chain key
        itself is never exported.
        """
        if self._state.chain_handle is None:
            raise RuntimeError("Cannot derive from a wiped chain")

        info = (
            self.DOMAIN_FILE_KEY
            + struct.pack("<Q", self._state.generation)
            + file_id.encode("utf-8")
        )
        return self._hb.derive_key_hkdf_bytes(self._state.chain_handle, b"", info, key_length)

    def derive_file_key_with_commitment(
        self,
        file_id: str,
        key_length: int = 32,
    ) -> Tuple[bytes, bytes]:
        """
        Derive file key with a commitment tag.

        Commitment binds the ciphertext to the chain state, preventing
        invisible-salamander attacks. Computed via HMAC-SHA256(chain_handle,
        "commitment:" || file_id) inside Rust.
        """
        if self._state.chain_handle is None:
            raise RuntimeError("Cannot derive from a wiped chain")

        file_key = self.derive_file_key(file_id, key_length)
        tag = self._hb.hmac_sha256(
            self._state.chain_handle,
            b"commitment:" + file_id.encode("utf-8"),
        )
        return file_key, tag[:16]

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
        Emergency wipe — securely delete all chain state.

        After this:
        - Chain handle dropped (Rust zeroizes via Zeroize impl on Drop)
        - State file overwritten with random data 3x then unlinked
        - Future calls to ratchet/derive_file_key raise RuntimeError
        """
        success = True

        # Drop the chain handle — Rust zeroizes the SecretKey on Drop.
        if self._state.chain_handle is not None:
            try:
                self._hb.drop(self._state.chain_handle)
            except Exception:
                success = False
            self._state.chain_handle = None

        if self._state_key_handle is not None:
            try:
                self._hb.drop(self._state_key_handle)
            except Exception:
                success = False
            self._state_key_handle = None

        # Zero the non-secret salt as defence-in-depth.
        salt_ba = bytearray(self._state.master_salt)
        _zero_bytearray(salt_ba)
        self._state.master_salt = bytes(32)
        self._state.generation = 0

        # Delete state file.
        if self._state_file is not None and self._state_file.exists():
            try:
                size = self._state_file.stat().st_size
                for _ in range(3):
                    self._state_file.write_bytes(secrets.token_bytes(size))
                self._state_file.unlink()
            except (OSError, IOError):
                success = False

        # SECURITY (L15): remove the rollback watermark sidecar as well, so a
        # fresh chain created later does not falsely trip the regression check.
        if self._state_file is not None:
            wm = _watermark_path(self._state_file)
            if wm.exists():
                try:
                    wm.unlink()
                except (OSError, IOError):
                    success = False

        return success

    def get_chain_id(self) -> bytes:
        """
        Get a non-sensitive identifier for this chain.

        Can be used to verify chain continuity without exposing keys.
        """
        return hashlib.sha256(b"chain_id:" + self._state.master_salt).digest()[:16]

    def __del__(self) -> None:
        # Best-effort handle cleanup on GC. Production code should call
        # emergency_wipe() explicitly for deterministic teardown.
        try:
            if self._state.chain_handle is not None:
                self._hb.drop(self._state.chain_handle)
                self._state.chain_handle = None
            if self._state_key_handle is not None:
                self._hb.drop(self._state_key_handle)
                self._state_key_handle = None
        except Exception:
            pass


# ─── Rollback watermark sidecar (SECURITY L15) ──────────────────────────────
# The AEAD seal authenticates the state file's contents but cannot stop a
# wholesale replay of an *earlier authentic* blob. We record the highest
# generation ever observed for a given state file in a small sidecar so a
# subsequent load presenting a lower generation can be detected (warn/reject).


def _watermark_path(state_file: Path) -> Path:
    """Path of the highest-generation-observed sidecar for a state file."""
    return state_file.with_name(state_file.name + ".maxgen")


def _read_generation_watermark(state_file: Path) -> Optional[int]:
    """Read the highest generation observed for this state file, or None."""
    try:
        raw = _watermark_path(state_file).read_bytes()
    except (OSError, IOError):
        return None
    if len(raw) < 8:
        return None
    try:
        return int(struct.unpack("<Q", raw[:8])[0])
    except struct.error:
        return None


def _update_generation_watermark(state_file: Path, generation: int) -> None:
    """Persist max(existing watermark, generation). Best-effort, monotonic."""
    current = _read_generation_watermark(state_file)
    if current is not None and current >= generation:
        return
    try:
        _watermark_path(state_file).write_bytes(struct.pack("<Q", generation))
    except (OSError, IOError):
        pass


def _decode_chain_state(
    data: bytes, state_key_handle: int, hb: HandleBackend
) -> Optional[ChainState]:
    """Parse and verify an MRCV2/MRCV3 blob, return ChainState or None."""
    if len(data) != _HEADER_LEN:
        return None
    if data[:5] not in (_FORMAT_MAGIC_V2, _FORMAT_MAGIC_V3):
        return None

    generation = struct.unpack("<Q", data[5:13])[0]
    last_ratchet_time = struct.unpack("<d", data[13:21])[0]
    master_salt = data[21:53]
    seal_nonce = data[53:65]
    sealed = data[65:113]

    meta = data[:53]  # magic || generation || timestamp || master_salt

    try:
        chain_handle = hb.unseal_key(sealed, state_key_handle, seal_nonce, aad=meta + _SEAL_AAD)
    except Exception:
        return None

    return ChainState(
        chain_handle=chain_handle,
        generation=generation,
        last_ratchet_time=last_ratchet_time,
        master_salt=master_salt,
    )


def derive_file_key(
    password: str,
    file_id: str,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    Convenience function to derive a one-shot file key.

    Use this when you don't need persistent ratchet state. Goes through
    the Rust handle backend (no Python-side HKDF).
    """
    if salt is None:
        salt = secrets.token_bytes(32)

    hb = get_handle_backend()
    password_bytes = bytearray(password.encode("utf-8"))
    try:
        ikm = bytearray(password_bytes)
        ikm.extend(salt)
        try:
            transient = hb.derive_key_hkdf_raw(bytes(ikm), salt, b"meow_oneshot_seed", 32)
        finally:
            _zero_bytearray(ikm)
    finally:
        _zero_bytearray(password_bytes)

    try:
        return hb.derive_key_hkdf_bytes(
            transient,
            b"",
            MasterRatchet.DOMAIN_FILE_KEY + file_id.encode("utf-8"),
            32,
        )
    finally:
        hb.drop(transient)


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
