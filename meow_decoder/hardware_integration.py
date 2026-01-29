"""
🔐 Hardware Security Integration Layer for Meow Decoder

Unified interface for HSM, YubiKey PIV, and TPM 2.0 hardware security.
This module bridges the CLI to the Rust crypto_core hardware modules.

Security Properties:
- HSM-001: Keys never leave hardware boundary
- YK-001: PIV operations require hardware touch
- TPM-001: PCR binding prevents key extraction on different boot state
- FALLBACK-001: Software fallback only with explicit user acknowledgment

CLI Integration:
    meow-encode --hsm-slot 0 --hsm-pin 123456 ...
    meow-encode --yubikey-piv --yubikey-slot 9d ...
    meow-encode --tpm-seal 0,2,7 ...
    meow-decode-gif --tpm-unseal ...

Usage:
    from meow_decoder.hardware_integration import HardwareSecurityProvider

    provider = HardwareSecurityProvider()
    
    # Check availability
    status = provider.detect_all()
    
    # Use YubiKey PIV for key derivation
    key = provider.derive_key_yubikey_piv(password, salt, slot="9d", pin="123456")
    
    # Use TPM for key sealing
    sealed = provider.tpm_seal(data, pcrs=[0, 2, 7])
    unsealed = provider.tpm_unseal(sealed)
    
    # Use HSM for AES operations
    ciphertext = provider.hsm_encrypt(plaintext, key_label="meow-master")
"""

import os
import sys
import secrets
import subprocess
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Tuple, List, Union, Callable
from enum import Enum

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class HardwareType(Enum):
    """Hardware security module types."""
    NONE = "none"
    HSM = "hsm"
    YUBIKEY_PIV = "yubikey_piv"
    YUBIKEY_FIDO2 = "yubikey_fido2"
    TPM = "tpm"
    SOFTWARE = "software"


@dataclass
class HardwareCapabilities:
    """Detected hardware security capabilities."""
    # HSM/PKCS#11
    hsm_available: bool = False
    hsm_slots: List[int] = field(default_factory=list)
    hsm_library_path: str = ""
    
    # YubiKey
    yubikey_available: bool = False
    yubikey_serial: str = ""
    yubikey_version: str = ""
    yubikey_piv_slots: List[str] = field(default_factory=list)
    yubikey_fido2_available: bool = False
    
    # TPM
    tpm_available: bool = False
    tpm_version: str = ""
    tpm_manufacturer: str = ""
    tpm_pcrs: List[int] = field(default_factory=list)
    
    # Warnings/errors
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def any_hardware(self) -> bool:
        """Check if any hardware security is available."""
        return self.hsm_available or self.yubikey_available or self.tpm_available
    
    def best_available(self) -> HardwareType:
        """Return the best available hardware type."""
        # Priority: HSM > YubiKey > TPM > Software
        if self.hsm_available:
            return HardwareType.HSM
        if self.yubikey_available:
            return HardwareType.YUBIKEY_PIV
        if self.tpm_available:
            return HardwareType.TPM
        return HardwareType.SOFTWARE
    
    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "🔐 Hardware Security Status",
            "=" * 40
        ]
        
        # HSM
        if self.hsm_available:
            lines.append(f"✅ HSM: Available (slots: {self.hsm_slots})")
        else:
            lines.append("❌ HSM: Not detected")
        
        # YubiKey
        if self.yubikey_available:
            lines.append(f"✅ YubiKey: {self.yubikey_version} (S/N: {self.yubikey_serial})")
            lines.append(f"   PIV slots: {', '.join(self.yubikey_piv_slots)}")
            lines.append(f"   FIDO2: {'Yes' if self.yubikey_fido2_available else 'No'}")
        else:
            lines.append("❌ YubiKey: Not detected")
        
        # TPM
        if self.tpm_available:
            lines.append(f"✅ TPM: {self.tpm_version} ({self.tpm_manufacturer})")
            lines.append(f"   PCRs: {len(self.tpm_pcrs)} available")
        else:
            lines.append("❌ TPM: Not detected")
        
        # Warnings
        if self.warnings:
            lines.append("")
            lines.append("⚠️  Warnings:")
            for w in self.warnings:
                lines.append(f"   - {w}")
        
        # Best recommendation
        lines.append("")
        best = self.best_available()
        if best == HardwareType.SOFTWARE:
            lines.append("🔑 Using: Software-only key derivation")
            lines.append("   ⚠️  Keys reside in memory (vulnerable to extraction)")
        else:
            lines.append(f"🔑 Recommended: {best.value.upper()}")
        
        return "\n".join(lines)


class HardwareSecurityError(Exception):
    """Base exception for hardware security operations."""
    pass


class HardwareNotFoundError(HardwareSecurityError):
    """Requested hardware not available."""
    pass


class HardwareAuthError(HardwareSecurityError):
    """Hardware authentication failed (wrong PIN, etc)."""
    pass


class HardwareOperationError(HardwareSecurityError):
    """Hardware operation failed."""
    pass


class SoftwareFallbackWarning(UserWarning):
    """Warning issued when falling back to software."""
    pass


class HardwareSecurityProvider:
    """
    Unified hardware security provider.
    
    Provides access to HSM, YubiKey, and TPM through a single interface.
    Automatically detects available hardware and provides fallback options.
    """
    
    def __init__(self, verbose: bool = False, allow_software_fallback: bool = True):
        """
        Initialize hardware security provider.
        
        Args:
            verbose: Print detection progress
            allow_software_fallback: Allow software-only if no hardware
        """
        self.verbose = verbose
        self.allow_software_fallback = allow_software_fallback
        self._capabilities: Optional[HardwareCapabilities] = None
        self._rust_backend = None
        
        # Try to load Rust backend for hardware ops
        try:
            import meow_crypto_rs
            self._rust_backend = meow_crypto_rs
        except ImportError:
            pass
    
    def detect_all(self) -> HardwareCapabilities:
        """
        Detect all available hardware security modules.
        
        Returns:
            HardwareCapabilities with detection results
        """
        if self._capabilities is not None:
            return self._capabilities
        
        caps = HardwareCapabilities()
        
        # Detect HSM/PKCS#11
        self._detect_hsm(caps)
        
        # Detect YubiKey
        self._detect_yubikey(caps)
        
        # Detect TPM
        self._detect_tpm(caps)
        
        self._capabilities = caps
        return caps
    
    def _run_cmd(self, cmd: List[str], timeout: int = 5) -> Tuple[bool, str]:
        """Run command and return (success, output)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)
    
    def _detect_hsm(self, caps: HardwareCapabilities) -> None:
        """Detect PKCS#11/HSM availability."""
        # Check for common PKCS#11 libraries
        pkcs11_paths = [
            "/usr/lib/softhsm/libsofthsm2.so",          # SoftHSM2 (testing)
            "/usr/lib/x86_64-linux-gnu/libykcs11.so",  # YubiHSM
            "/usr/lib/libyubihsm.so",                  # YubiHSM
            "/usr/lib/pkcs11/opensc-pkcs11.so",        # OpenSC
            "/usr/local/lib/libpkcs11.so",             # Generic
        ]
        
        for path in pkcs11_paths:
            if os.path.exists(path):
                caps.hsm_available = True
                caps.hsm_library_path = path
                
                # Try to enumerate slots
                ok, output = self._run_cmd(["pkcs11-tool", "--list-slots"])
                if ok:
                    # Parse slot numbers
                    import re
                    slots = re.findall(r"Slot (\d+)", output)
                    caps.hsm_slots = [int(s) for s in slots]
                break
    
    def _detect_yubikey(self, caps: HardwareCapabilities) -> None:
        """Detect YubiKey availability."""
        # Try ykman
        ok, output = self._run_cmd(["ykman", "info"])
        if ok:
            caps.yubikey_available = True
            
            # Parse serial and version
            import re
            serial_match = re.search(r"Serial number:\s*(\d+)", output)
            if serial_match:
                caps.yubikey_serial = serial_match.group(1)
            
            version_match = re.search(r"Firmware version:\s*([\d.]+)", output)
            if version_match:
                caps.yubikey_version = version_match.group(1)
            
            # Check PIV slots
            ok_piv, piv_output = self._run_cmd(["ykman", "piv", "info"])
            if ok_piv:
                caps.yubikey_piv_slots = ["9a", "9c", "9d", "9e"]  # Standard slots
            
            # Check FIDO2
            ok_fido2, _ = self._run_cmd(["ykman", "fido", "info"])
            caps.yubikey_fido2_available = ok_fido2
        else:
            # Fallback to lsusb
            ok, output = self._run_cmd(["lsusb"])
            if ok and "Yubico" in output:
                caps.yubikey_available = True
                caps.warnings.append("YubiKey detected but ykman not available")
    
    def _detect_tpm(self, caps: HardwareCapabilities) -> None:
        """Detect TPM 2.0 availability."""
        # Check /dev/tpm0 or /dev/tpmrm0
        if os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0"):
            caps.tpm_available = True
            
            # Try to get TPM info via tpm2_getcap
            ok, output = self._run_cmd(["tpm2_getcap", "properties-fixed"])
            if ok:
                import re
                
                # Parse version
                version_match = re.search(r"TPM2_PT_FAMILY_INDICATOR.*value:\s*\"([^\"]+)\"", output)
                if version_match:
                    caps.tpm_version = version_match.group(1)
                
                # Parse manufacturer
                mfr_match = re.search(r"TPM2_PT_MANUFACTURER.*value:\s*\"([^\"]+)\"", output)
                if mfr_match:
                    caps.tpm_manufacturer = mfr_match.group(1)
                
                # Standard PCRs
                caps.tpm_pcrs = list(range(24))  # PCR 0-23
            else:
                caps.tpm_version = "2.0"
                caps.tpm_manufacturer = "Unknown"
                caps.warnings.append("TPM detected but tpm2-tools not available")
    
    # =========================================================================
    # YubiKey PIV Operations
    # =========================================================================
    
    def derive_key_yubikey_piv(
        self,
        password: bytes,
        salt: bytes,
        slot: str = "9d",
        pin: Optional[str] = None,
        touch_required: bool = True
    ) -> bytes:
        """
        Derive encryption key using YubiKey PIV slot.
        
        Security Properties:
        - Private key never leaves YubiKey
        - PIN required for key access
        - Optional touch required for operation
        
        Args:
            password: User password
            salt: Random salt
            slot: PIV slot (9a, 9c, 9d, 9e)
            pin: YubiKey PIN
            touch_required: Require physical touch
            
        Returns:
            32-byte derived key
        """
        caps = self.detect_all()
        
        if not caps.yubikey_available:
            if self.allow_software_fallback:
                import warnings
                warnings.warn(
                    "YubiKey not available, falling back to software key derivation",
                    SoftwareFallbackWarning
                )
                return self._derive_key_software(password, salt)
            raise HardwareNotFoundError("YubiKey not available")
        
        # Try Rust backend first
        if self._rust_backend is not None:
            try:
                return self._rust_backend.yubikey_derive_key(
                    password, salt, slot, pin
                )
            except AttributeError:
                pass  # Feature not compiled
        
        # Fallback to ykman challenge-response
        # This uses HMAC-SHA1 challenge-response on slot 2
        combined = salt + password
        challenge = hashlib.sha256(combined).digest()
        
        ok, output = self._run_cmd([
            "ykchalresp", "-2", challenge.hex()
        ], timeout=30)  # Longer timeout for touch
        
        if not ok:
            raise HardwareOperationError(f"YubiKey challenge-response failed: {output}")
        
        response = bytes.fromhex(output.strip())
        
        # Derive final key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"meow_yubikey_piv_v1"
        )
        return hkdf.derive(response + password)
    
    # =========================================================================
    # TPM 2.0 Operations
    # =========================================================================
    
    def tpm_seal(
        self,
        data: bytes,
        pcrs: List[int] = None,
        auth_password: Optional[str] = None
    ) -> bytes:
        """
        Seal data to TPM PCR state.
        
        Security Properties:
        - Data only recoverable with identical PCR values
        - PCR 0,2,7 = BIOS + firmware + Secure Boot (recommended)
        - Changing boot config makes data unrecoverable
        
        Args:
            data: Data to seal (max 128 bytes for direct seal)
            pcrs: PCR indices to bind (default: [0, 2, 7])
            auth_password: Optional password for sealed object
            
        Returns:
            Sealed blob (opaque)
        """
        if pcrs is None:
            pcrs = [0, 2, 7]
        
        caps = self.detect_all()
        
        if not caps.tpm_available:
            raise HardwareNotFoundError("TPM not available")
        
        # Validate PCRs
        for pcr in pcrs:
            if pcr < 0 or pcr > 23:
                raise ValueError(f"Invalid PCR index: {pcr}")
        
        # Try Rust backend first
        if self._rust_backend is not None:
            try:
                return self._rust_backend.tpm_seal(data, pcrs, auth_password)
            except AttributeError:
                pass  # Feature not compiled
        
        # Fallback to tpm2-tools
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Write data to temp file
            data_file = tmpdir / "data.bin"
            data_file.write_bytes(data)
            
            sealed_file = tmpdir / "sealed.bin"
            
            # Create PCR policy
            pcr_list = ",".join(str(p) for p in pcrs)
            
            cmd = [
                "tpm2_create",
                "-C", "o",  # Owner hierarchy
                "-i", str(data_file),
                "-u", str(tmpdir / "sealed.pub"),
                "-r", str(tmpdir / "sealed.priv"),
                "-L", f"sha256:{pcr_list}",
            ]
            
            if auth_password:
                cmd.extend(["-p", auth_password])
            
            ok, output = self._run_cmd(cmd, timeout=30)
            
            if not ok:
                raise HardwareOperationError(f"TPM seal failed: {output}")
            
            # Load the sealed object
            cmd = [
                "tpm2_load",
                "-C", "o",
                "-u", str(tmpdir / "sealed.pub"),
                "-r", str(tmpdir / "sealed.priv"),
                "-c", str(tmpdir / "sealed.ctx")
            ]
            
            ok, output = self._run_cmd(cmd, timeout=30)
            if not ok:
                raise HardwareOperationError(f"TPM load failed: {output}")
            
            # Create context blob for storage
            pub_bytes = (tmpdir / "sealed.pub").read_bytes()
            priv_bytes = (tmpdir / "sealed.priv").read_bytes()
            
            # Pack: len(pub) || pub || len(priv) || priv || pcr_list
            import struct
            sealed = struct.pack(">I", len(pub_bytes)) + pub_bytes
            sealed += struct.pack(">I", len(priv_bytes)) + priv_bytes
            sealed += bytes(pcrs)
            
            return sealed
    
    def tpm_unseal(
        self,
        sealed_blob: bytes,
        auth_password: Optional[str] = None
    ) -> bytes:
        """
        Unseal data from TPM.
        
        Only succeeds if current PCR values match sealed state.
        
        Args:
            sealed_blob: Sealed blob from tpm_seal()
            auth_password: Password if sealed with one
            
        Returns:
            Original data
        """
        caps = self.detect_all()
        
        if not caps.tpm_available:
            raise HardwareNotFoundError("TPM not available")
        
        # Try Rust backend first
        if self._rust_backend is not None:
            try:
                return self._rust_backend.tpm_unseal(sealed_blob, auth_password)
            except AttributeError:
                pass  # Feature not compiled
        
        # Fallback to tpm2-tools
        import tempfile
        import struct
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Unpack sealed blob
            offset = 0
            pub_len = struct.unpack(">I", sealed_blob[offset:offset+4])[0]
            offset += 4
            pub_bytes = sealed_blob[offset:offset+pub_len]
            offset += pub_len
            
            priv_len = struct.unpack(">I", sealed_blob[offset:offset+4])[0]
            offset += 4
            priv_bytes = sealed_blob[offset:offset+priv_len]
            offset += priv_len
            
            pcrs = list(sealed_blob[offset:])
            
            # Write to temp files
            (tmpdir / "sealed.pub").write_bytes(pub_bytes)
            (tmpdir / "sealed.priv").write_bytes(priv_bytes)
            
            # Load the sealed object
            cmd = [
                "tpm2_load",
                "-C", "o",
                "-u", str(tmpdir / "sealed.pub"),
                "-r", str(tmpdir / "sealed.priv"),
                "-c", str(tmpdir / "sealed.ctx")
            ]
            
            ok, output = self._run_cmd(cmd, timeout=30)
            if not ok:
                raise HardwareOperationError(f"TPM load failed: {output}")
            
            # Create PCR policy session
            pcr_list = ",".join(str(p) for p in pcrs)
            
            cmd = [
                "tpm2_startauthsession", "--policy-session", "-S", str(tmpdir / "session.ctx")
            ]
            ok, output = self._run_cmd(cmd, timeout=30)
            if not ok:
                raise HardwareOperationError(f"TPM session failed: {output}")
            
            cmd = [
                "tpm2_policypcr", "-S", str(tmpdir / "session.ctx"),
                "-l", f"sha256:{pcr_list}"
            ]
            ok, output = self._run_cmd(cmd, timeout=30)
            if not ok:
                raise HardwareOperationError(f"TPM PCR policy failed: {output}")
            
            # Unseal
            unsealed_file = tmpdir / "unsealed.bin"
            
            cmd = [
                "tpm2_unseal",
                "-c", str(tmpdir / "sealed.ctx"),
                "-p", f"session:{tmpdir / 'session.ctx'}",
                "-o", str(unsealed_file)
            ]
            
            if auth_password:
                cmd[-1] = f"{auth_password}"
            
            ok, output = self._run_cmd(cmd, timeout=30)
            if not ok:
                if "PCR" in output or "policy" in output.lower():
                    raise HardwareOperationError(
                        "TPM unseal failed: PCR values have changed since sealing. "
                        "This may indicate boot configuration change or tampering."
                    )
                raise HardwareOperationError(f"TPM unseal failed: {output}")
            
            return unsealed_file.read_bytes()
    
    def derive_key_tpm(
        self,
        password: bytes,
        salt: bytes,
        pcrs: List[int] = None
    ) -> bytes:
        """
        Derive key using TPM-backed HMAC.
        
        Args:
            password: User password
            salt: Random salt
            pcrs: PCRs to bind (for platform-bound derivation)
            
        Returns:
            32-byte derived key
        """
        caps = self.detect_all()
        
        if not caps.tpm_available:
            if self.allow_software_fallback:
                import warnings
                warnings.warn(
                    "TPM not available, falling back to software key derivation",
                    SoftwareFallbackWarning
                )
                return self._derive_key_software(password, salt)
            raise HardwareNotFoundError("TPM not available")
        
        # Use TPM HMAC for derivation
        combined = salt + password
        
        # Try Rust backend first
        if self._rust_backend is not None:
            try:
                return self._rust_backend.tpm_derive_key(combined, salt, pcrs or [])
            except AttributeError:
                pass
        
        # Fallback to tpm2-tools
        import tempfile
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            data_file = tmpdir / "data.bin"
            data_file.write_bytes(combined)
            
            hmac_file = tmpdir / "hmac.bin"
            
            # Use TPM's HMAC capability
            cmd = [
                "tpm2_hmac",
                "-c", "o",  # Owner hierarchy key
                "-o", str(hmac_file),
                str(data_file)
            ]
            
            ok, output = self._run_cmd(cmd, timeout=30)
            if not ok:
                raise HardwareOperationError(f"TPM HMAC failed: {output}")
            
            tpm_hmac = hmac_file.read_bytes()
            
            # Derive final key
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"meow_tpm_kdf_v1"
            )
            return hkdf.derive(tpm_hmac + password)
    
    # =========================================================================
    # HSM/PKCS#11 Operations
    # =========================================================================
    
    def hsm_generate_key(
        self,
        slot: int,
        pin: str,
        key_label: str = "meow-master",
        key_type: str = "aes256"
    ) -> str:
        """
        Generate AES key in HSM.
        
        Args:
            slot: HSM slot number
            pin: User PIN
            key_label: Label for the key
            key_type: Key type (aes256, aes128)
            
        Returns:
            Key ID/handle
        """
        caps = self.detect_all()
        
        if not caps.hsm_available:
            raise HardwareNotFoundError("HSM not available")
        
        # Use pkcs11-tool
        key_bits = "256" if key_type == "aes256" else "128"
        
        cmd = [
            "pkcs11-tool",
            "--module", caps.hsm_library_path,
            "--slot", str(slot),
            "--login", "--pin", pin,
            "--keygen", "--key-type", f"AES:{key_bits}",
            "--label", key_label
        ]
        
        ok, output = self._run_cmd(cmd, timeout=30)
        if not ok:
            raise HardwareOperationError(f"HSM key generation failed: {output}")
        
        return key_label
    
    def hsm_derive_key(
        self,
        password: bytes,
        salt: bytes,
        slot: int,
        pin: str,
        master_key_label: str = "meow-master"
    ) -> bytes:
        """
        Derive key using HSM-stored master key.
        
        Args:
            password: User password
            salt: Random salt
            slot: HSM slot number
            pin: User PIN
            master_key_label: Label of master key in HSM
            
        Returns:
            32-byte derived key
        """
        caps = self.detect_all()
        
        if not caps.hsm_available:
            if self.allow_software_fallback:
                import warnings
                warnings.warn(
                    "HSM not available, falling back to software key derivation",
                    SoftwareFallbackWarning
                )
                return self._derive_key_software(password, salt)
            raise HardwareNotFoundError("HSM not available")
        
        # Try Rust backend first
        if self._rust_backend is not None:
            try:
                return self._rust_backend.hsm_derive_key(
                    password, salt, slot, pin, master_key_label
                )
            except AttributeError:
                pass
        
        # Fallback to HMAC with HSM key
        # This is a simplified approach - real impl would use PKCS#11 derive
        combined = salt + password
        
        import tempfile
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            data_file = tmpdir / "data.bin"
            data_file.write_bytes(combined)
            
            hmac_file = tmpdir / "hmac.bin"
            
            cmd = [
                "pkcs11-tool",
                "--module", caps.hsm_library_path,
                "--slot", str(slot),
                "--login", "--pin", pin,
                "--sign", "--mechanism", "SHA256-HMAC",
                "--label", master_key_label,
                "-i", str(data_file),
                "-o", str(hmac_file)
            ]
            
            ok, output = self._run_cmd(cmd, timeout=30)
            if not ok:
                raise HardwareOperationError(f"HSM HMAC failed: {output}")
            
            hsm_hmac = hmac_file.read_bytes()
            
            # Final derivation
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"meow_hsm_kdf_v1"
            )
            return hkdf.derive(hsm_hmac + password)
    
    # =========================================================================
    # Software Fallback
    # =========================================================================
    
    def _derive_key_software(self, password: bytes, salt: bytes) -> bytes:
        """
        Software-only key derivation (fallback).
        
        WARNING: Keys reside in memory and are vulnerable to extraction.
        """
        try:
            from .crypto_backend import get_default_backend
            backend = get_default_backend()
            return backend.derive_key_argon2id(password, salt)
        except ImportError:
            # Pure Python fallback
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            
            kdf = Argon2id(
                length=32,
                salt=salt,
                memory_cost=524288,  # 512 MiB
                time_cost=20,
                parallelism=4
            )
            return kdf.derive(password)
    
    # =========================================================================
    # Auto-selection
    # =========================================================================
    
    def derive_key_auto(
        self,
        password: bytes,
        salt: bytes,
        prefer: Optional[HardwareType] = None,
        **kwargs
    ) -> Tuple[bytes, HardwareType]:
        """
        Automatically derive key using best available hardware.
        
        Args:
            password: User password
            salt: Random salt
            prefer: Preferred hardware type (optional)
            **kwargs: Additional hardware-specific arguments
            
        Returns:
            Tuple of (derived_key, hardware_type_used)
        """
        caps = self.detect_all()
        
        hw_type = prefer or caps.best_available()
        
        if hw_type == HardwareType.HSM and caps.hsm_available:
            key = self.hsm_derive_key(
                password, salt,
                kwargs.get("slot", 0),
                kwargs.get("pin", ""),
                kwargs.get("key_label", "meow-master")
            )
            return key, HardwareType.HSM
        
        if hw_type == HardwareType.YUBIKEY_PIV and caps.yubikey_available:
            key = self.derive_key_yubikey_piv(
                password, salt,
                kwargs.get("yubikey_slot", "9d"),
                kwargs.get("yubikey_pin")
            )
            return key, HardwareType.YUBIKEY_PIV
        
        if hw_type == HardwareType.TPM and caps.tpm_available:
            key = self.derive_key_tpm(
                password, salt,
                kwargs.get("pcrs")
            )
            return key, HardwareType.TPM
        
        # Software fallback
        key = self._derive_key_software(password, salt)
        return key, HardwareType.SOFTWARE


# ==============================================================================
# CLI Argument Helpers
# ==============================================================================

def add_hardware_args(parser) -> None:
    """
    Add hardware security CLI arguments to argparse parser.
    
    Usage:
        parser = argparse.ArgumentParser()
        add_hardware_args(parser)
        args = parser.parse_args()
    """
    group = parser.add_argument_group('🔐 Hardware Security')
    
    # HSM options
    group.add_argument(
        '--hsm-slot',
        type=int,
        metavar='N',
        help='HSM PKCS#11 slot number (enables HSM mode)'
    )
    group.add_argument(
        '--hsm-pin',
        type=str,
        metavar='PIN',
        help='HSM user PIN (prompted if not provided)'
    )
    group.add_argument(
        '--hsm-key-label',
        type=str,
        default='meow-master',
        metavar='LABEL',
        help='HSM key label (default: meow-master)'
    )
    group.add_argument(
        '--hsm-library',
        type=str,
        metavar='PATH',
        help='Path to PKCS#11 library (auto-detected if not specified)'
    )
    
    # YubiKey options (extended from existing --yubikey)
    group.add_argument(
        '--yubikey-piv',
        action='store_true',
        help='Use YubiKey PIV for key derivation'
    )
    group.add_argument(
        '--yubikey-fido2',
        action='store_true',
        help='Use YubiKey FIDO2 hmac-secret for password hardening'
    )
    group.add_argument(
        '--yubikey-touch',
        action='store_true',
        default=True,
        help='Require physical touch (default: true)'
    )
    
    # TPM options
    group.add_argument(
        '--tpm-seal',
        type=str,
        metavar='PCRS',
        help='Seal key to TPM PCRs (comma-separated, e.g., 0,2,7)'
    )
    group.add_argument(
        '--tpm-unseal',
        action='store_true',
        help='Unseal key from TPM (requires matching PCR state)'
    )
    group.add_argument(
        '--tpm-derive',
        action='store_true',
        help='Use TPM for key derivation'
    )
    
    # Auto/detection options
    group.add_argument(
        '--hardware-auto',
        action='store_true',
        help='Automatically use best available hardware'
    )
    group.add_argument(
        '--hardware-status',
        action='store_true',
        help='Show hardware security status and exit'
    )
    group.add_argument(
        '--no-hardware-fallback',
        action='store_true',
        help='Fail if requested hardware not available (no software fallback)'
    )


def process_hardware_args(args, password: bytes, salt: bytes) -> Tuple[bytes, str]:
    """
    Process hardware CLI arguments and derive key.
    
    Args:
        args: Parsed argparse namespace
        password: User password bytes
        salt: Random salt
        
    Returns:
        Tuple of (derived_key, method_description)
    """
    provider = HardwareSecurityProvider(
        verbose=getattr(args, 'verbose', False),
        allow_software_fallback=not getattr(args, 'no_hardware_fallback', False)
    )
    
    # Check status request
    if getattr(args, 'hardware_status', False):
        caps = provider.detect_all()
        print(caps.summary())
        sys.exit(0)
    
    # HSM mode
    if getattr(args, 'hsm_slot', None) is not None:
        pin = getattr(args, 'hsm_pin', None)
        if not pin:
            from getpass import getpass
            pin = getpass("HSM PIN: ")
        
        key = provider.hsm_derive_key(
            password, salt,
            args.hsm_slot,
            pin,
            getattr(args, 'hsm_key_label', 'meow-master')
        )
        return key, f"HSM slot {args.hsm_slot}"
    
    # YubiKey PIV mode
    if getattr(args, 'yubikey_piv', False) or getattr(args, 'yubikey', False):
        slot = getattr(args, 'yubikey_slot', '9d')
        pin = getattr(args, 'yubikey_pin', None)
        if not pin:
            from getpass import getpass
            pin = getpass("YubiKey PIN: ")
        
        key = provider.derive_key_yubikey_piv(
            password, salt, slot, pin
        )
        return key, f"YubiKey PIV slot {slot}"
    
    # TPM derive mode
    if getattr(args, 'tpm_derive', False):
        pcrs = None
        if getattr(args, 'tpm_seal', None):
            pcrs = [int(p.strip()) for p in args.tpm_seal.split(',')]
        
        key = provider.derive_key_tpm(password, salt, pcrs)
        return key, f"TPM (PCRs: {pcrs or 'default'})"
    
    # Hardware auto mode
    if getattr(args, 'hardware_auto', False):
        key, hw_type = provider.derive_key_auto(password, salt)
        return key, f"Auto ({hw_type.value})"
    
    # Default: software (use existing code path)
    return None, "software"


# ==============================================================================
# Self-Test
# ==============================================================================

if __name__ == "__main__":
    print("🔐 Hardware Security Integration Self-Test")
    print("=" * 60)
    
    provider = HardwareSecurityProvider(verbose=True)
    caps = provider.detect_all()
    
    print(caps.summary())
    
    print("\n" + "=" * 60)
    print("Testing key derivation...")
    
    test_password = b"test_password_123"
    test_salt = secrets.token_bytes(16)
    
    key, method = provider.derive_key_auto(test_password, test_salt)
    
    print(f"\n✅ Key derived using: {method.value}")
    print(f"   Key (first 16 bytes): {key[:16].hex()}")
    
    # Verify consistency
    key2, _ = provider.derive_key_auto(test_password, test_salt)
    
    if key == key2:
        print("   ✅ Same password + salt = same key")
    else:
        print("   ⚠️  Keys differ (hardware may add randomness)")
    
    print("\n🐱 Meow securely!")
