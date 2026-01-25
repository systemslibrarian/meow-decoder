"""
Meow Decoder Configuration Module
Centralized configuration management for all Meow Decoder operations
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import json


@dataclass
class EncodingConfig:
    """Configuration for encoding operations."""
    block_size: int = 512                    # Fountain code block size
    redundancy: float = 1.5                  # Redundancy factor (1.5 = 150% of k_blocks)
    qr_error_correction: str = "H"           # QR error correction (L/M/Q/H) - H for GIF
    qr_box_size: int = 14                    # QR box size in pixels - 14 for GIF readability
    qr_border: int = 4                       # QR border size
    fps: int = 10                            # GIF frames per second
    
    # Security options (🐱 NINE LIVES MODE - NOW DEFAULT!)
    enable_forward_secrecy: bool = True      # ✅ Enable per-block keys (RECOMMENDED)
    ratchet_interval: int = 100              # Blocks between ratchet steps
    enable_stego: bool = False               # Enable steganography
    stealth_level: int = 2                   # Stealth level (1-4)
    enable_animation: bool = False           # Animated carriers
    enable_low_memory: bool = False          # Low-memory streaming mode
    enable_pq: bool = True                   # ✅ Post-quantum crypto (ML-KEM-1024 + X25519 hybrid) - DEFAULT ON
    
    # Enhanced security features
    enable_duress: bool = False              # Duress password support
    enable_hardware_keys: bool = True        # Auto-detect hardware security (TPM/YubiKey)
    enable_enhanced_entropy: bool = True     # Multi-source entropy collection
    enable_chaff_frames: bool = False        # Add dummy frames to GIF
    
    # Backend selection (SECURITY: Rust is REQUIRED unless explicitly allowed)
    require_rust: bool = True                # SECURITY: Fail if Rust unavailable (default)
    allow_python_fallback: bool = False      # Allow Python backend with explicit flag
    
    # Performance
    enable_profiling: bool = False           # Enable performance profiling


@dataclass
class DecodingConfig:
    """Configuration for decoding operations."""
    webcam_device: int = 0                   # Webcam device index
    frame_skip: int = 0                      # Skip frames for performance
    preprocessing: str = "normal"            # Preprocessing mode (normal/aggressive)
    
    # Security options
    enable_resume: bool = True               # Enable resume functionality
    resume_password: Optional[str] = None    # Password for encrypted resume
    save_interval: int = 10                  # Save resume every N droplets
    
    # Steganography
    enable_stego: bool = False               # Decode from steganography
    aggressive_stego: bool = False           # Aggressive stego preprocessing
    
    # Performance
    max_memory_mb: int = 500                 # Maximum memory usage


@dataclass
class CryptoConfig:
    """
    Configuration for cryptography operations.
    
    Security Note:
        Defaults are set to OWASP-recommended minimums for Argon2id.
        ~500-800ms on modern hardware (acceptable for high-security use).
        
        For faster operation (e.g., testing), reduce:
        - argon2_memory to 32768 (32 MB)
        - argon2_iterations to 2
        
        For maximum security, increase:
        - argon2_memory to 131072 (128 MB) or 262144 (256 MB)
        - argon2_iterations to 4 or 5
    """
    key_derivation: str = "argon2id"         # Key derivation function
    argon2_memory: int = 524288              # 512 MiB (8x OWASP minimum) - ULTRA HARDENED
    argon2_iterations: int = 20              # 20 passes (~5-10 sec delay)
    argon2_parallelism: int = 4              # 4 threads
    
    # Ultra-hardened mode (when lives depend on it)
    ultra_hardened: bool = False             # 1 GiB / 40 iterations (~20-30 sec)
    
    cipher: str = "aes-256-gcm"              # Cipher algorithm
    
    # Backend selection (SECURITY: Rust is REQUIRED unless explicitly allowed)
    require_rust: bool = True                # SECURITY: Fail if Rust unavailable (default)
    allow_python_fallback: bool = False      # Allow Python backend with explicit flag
    
    # Forward secrecy
    enable_forward_secrecy: bool = True      # Enabled by default
    ratchet_interval: int = 50               # Ratchet every 50 blocks
    
    # Post-quantum (DEFAULT ON for quantum resilience)
    enable_pq: bool = True                   # ✅ ENABLED by default (ML-KEM-1024 + X25519 hybrid)
    kyber_variant: str = "kyber1024"         # ML-KEM-1024 (NIST FIPS 203 - highest security)


@dataclass
class PathConfig:
    """Configuration for file paths."""
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "meowdecoder")
    resume_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "meowdecoder" / "resume")
    temp_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "meowdecoder" / "temp")
    
    def __post_init__(self):
        """Ensure directories exist."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.resume_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class MeowConfig:
    """Master configuration for Meow Decoder."""
    encoding: EncodingConfig = field(default_factory=EncodingConfig)
    decoding: DecodingConfig = field(default_factory=DecodingConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    paths: PathConfig = field(default_factory=PathConfig)
    
    # Global options
    verbose: bool = False
    debug: bool = False
    
    def save(self, path: Path):
        """Save configuration to JSON file."""
        config_dict = {
            'encoding': self.encoding.__dict__,
            'decoding': self.decoding.__dict__,
            'crypto': self.crypto.__dict__,
            'paths': {
                'cache_dir': str(self.paths.cache_dir),
                'resume_dir': str(self.paths.resume_dir),
                'temp_dir': str(self.paths.temp_dir)
            },
            'verbose': self.verbose,
            'debug': self.debug
        }
        
        with open(path, 'w') as f:
            json.dump(config_dict, f, indent=2)
    
    @classmethod
    def load(cls, path: Path) -> 'MeowConfig':
        """Load configuration from JSON file."""
        with open(path, 'r') as f:
            config_dict = json.load(f)
        
        config = cls()
        
        # Load encoding config
        if 'encoding' in config_dict:
            for key, value in config_dict['encoding'].items():
                setattr(config.encoding, key, value)
        
        # Load decoding config
        if 'decoding' in config_dict:
            for key, value in config_dict['decoding'].items():
                setattr(config.decoding, key, value)
        
        # Load crypto config
        if 'crypto' in config_dict:
            for key, value in config_dict['crypto'].items():
                setattr(config.crypto, key, value)
        
        # Load paths
        if 'paths' in config_dict:
            config.paths = PathConfig(
                cache_dir=Path(config_dict['paths']['cache_dir']),
                resume_dir=Path(config_dict['paths']['resume_dir']),
                temp_dir=Path(config_dict['paths']['temp_dir'])
            )
        
        # Load global options
        config.verbose = config_dict.get('verbose', False)
        config.debug = config_dict.get('debug', False)
        
        return config


# Default configuration instance
DEFAULT_CONFIG = MeowConfig()


def get_config() -> MeowConfig:
    """
    Get configuration, loading from file if it exists.
    
    Returns:
        MeowConfig instance
    """
    config_path = Path.home() / ".config" / "meowdecoder" / "config.json"
    
    if config_path.exists():
        try:
            return MeowConfig.load(config_path)
        except Exception as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")
            print("Using default configuration.")
    
    return MeowConfig()


def save_config(config: MeowConfig):
    """
    Save configuration to default location.
    
    Args:
        config: MeowConfig to save
    """
    config_dir = Path.home() / ".config" / "meowdecoder"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_path = config_dir / "config.json"
    config.save(config_path)


# Testing
if __name__ == "__main__":
    print("Testing Meow Decoder Configuration...\n")
    
    # Test 1: Create default config
    print("1. Creating default configuration...")
    config = MeowConfig()
    print(f"   Block size: {config.encoding.block_size}")
    print(f"   Redundancy: {config.encoding.redundancy}")
    print(f"   Cache dir: {config.paths.cache_dir}")
    print("   ✓ Default config created")
    
    # Test 2: Modify config
    print("\n2. Modifying configuration...")
    config.encoding.enable_forward_secrecy = True
    config.encoding.enable_stego = True
    config.encoding.stealth_level = 4
    print(f"   Forward secrecy: {config.encoding.enable_forward_secrecy}")
    print(f"   Stealth level: {config.encoding.stealth_level}")
    print("   ✓ Config modified")
    
    # Test 3: Save/load config
    print("\n3. Testing save/load...")
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = Path(f.name)
    
    try:
        config.save(config_path)
        loaded_config = MeowConfig.load(config_path)
        
        assert loaded_config.encoding.enable_forward_secrecy == True
        assert loaded_config.encoding.stealth_level == 4
        print("   ✓ Save/load working")
    finally:
        config_path.unlink()
    
    print("\n✅ All configuration tests passed!")
