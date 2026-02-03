"""
Resume Capability for Meow Decoder - SECURED VERSION v2
Save and resume partial decoding operations with encrypted state files
SECURITY: State files are now encrypted using Fernet (AES-128)
"""

import os
import json
import base64
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from meow_decoder.fountain import FountainDecoder
from meow_decoder.crypto import Manifest


STATE_VERSION = 1  # For future migrations


@dataclass
class DecoderState:
    """Serializable decoder state for resume capability."""
    version: int  # State format version
    session_id: str
    manifest: dict  # Manifest as dict
    solved_blocks: list  # List of (index, block_bytes_hex) tuples
    pending_droplets: list  # List of (block_indices, data_hex) tuples
    droplets_seen: int
    timestamp: str
    input_source: str  # "gif" or "webcam"
    seed: int
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'DecoderState':
        # Handle legacy states without version field
        if 'version' not in data:
            data['version'] = 0
        return cls(**data)


class ResumeManager:
    """
    Manages saving and loading decoder state for resume capability.
    Now with encrypted state files for security.
    """
    
    def __init__(
        self,
        state_dir: Optional[str] = None,
        config=None,
        encrypt_state: Optional[bool] = None,
        cleanup_days: Optional[int] = None,
        auto_save_interval: Optional[int] = None
    ):
        """
        Initialize resume manager.
        
        Args:
            state_dir: Directory for state files (default: ~/.cache/meowdecoder/resume/)
            config: Optional configuration object with resume settings
        """
        if state_dir is None:
            home = Path.home()
            state_dir = home / '.cache' / 'meowdecoder' / 'resume'
        
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        # Load config or use defaults
        if config and hasattr(config, 'resume'):
            self.auto_save_interval = config.resume.auto_save_interval
            self.cleanup_days = config.resume.cleanup_days
            self.encrypt_state = config.resume.encrypt_state
        else:
            self.auto_save_interval = 50
            self.cleanup_days = 7
            self.encrypt_state = True  # Default to encrypted

        # Allow explicit overrides for compatibility
        if auto_save_interval is not None:
            self.auto_save_interval = auto_save_interval
        if cleanup_days is not None:
            self.cleanup_days = cleanup_days
        if encrypt_state is not None:
            self.encrypt_state = encrypt_state

    def _get_state_file_path(self, session_id: str) -> Path:
        """Return canonical state file path (.meow)."""
        return self.state_dir / f"{session_id}.meow"
    
    def _derive_state_key(self, password: str, manifest: Manifest) -> bytes:
        """
        Derive encryption key for state file from password and manifest salt.
        
        Args:
            password: User password
            manifest: File manifest (provides salt)
            
        Returns:
            32-byte key suitable for Fernet
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=manifest.salt,  # Use manifest salt for domain separation
            iterations=100000,   # OWASP recommended minimum
        )
        return kdf.derive(password.encode())
    
    def generate_session_id(self, manifest: Manifest) -> str:
        """
        Generate unique session ID based on manifest.
        
        Args:
            manifest: File manifest
            
        Returns:
            Unique session ID
        """
        # Hash of salt + sha256 creates unique identifier
        session_data = manifest.salt + manifest.sha256
        session_hash = hashlib.sha256(session_data).hexdigest()[:16]
        return f"session_{session_hash}"
    
    def save_state(
        self,
        decoder: FountainDecoder,
        manifest: Manifest,
        password: Optional[str] = None,
        droplets_seen: int = 0,
        session_id: Optional[str] = None,
        input_source: str = "webcam",
        seed: int = 42069
    ) -> str:
        """
        Save current decoder state to disk (encrypted).
        
        Args:
            decoder: FountainDecoder instance
            manifest: File manifest
            password: Password for state encryption
            droplets_seen: Number of droplets processed
            session_id: Optional session ID (auto-generated if None)
            input_source: Source type ("gif" or "webcam")
            seed: Random seed used
            
        Returns:
            Path to saved state file
        """
        if session_id is None:
            session_id = self.generate_session_id(manifest)
        
        # Convert solved blocks to serializable format
        solved_blocks = [
            (i, block.hex())
            for i, block in enumerate(decoder.blocks)
            if block is not None
        ]
        
        # Convert pending droplets to serializable format
        # Note: pending_droplets contains Droplet objects with block_indices and data
        pending_droplets = [
            (sorted(droplet.block_indices), droplet.data.hex())
            for droplet in decoder.pending_droplets
        ]
        
        # Convert manifest to dict
        manifest_dict = {
            'salt': manifest.salt.hex(),
            'nonce': manifest.nonce.hex(),
            'orig_len': manifest.orig_len,
            'comp_len': manifest.comp_len,
            'cipher_len': manifest.cipher_len,
            'sha256': manifest.sha256.hex(),
            'block_size': manifest.block_size,
            'k_blocks': manifest.k_blocks,
            'hmac': manifest.hmac.hex()
        }
        
        state = DecoderState(
            version=STATE_VERSION,
            session_id=session_id,
            manifest=manifest_dict,
            solved_blocks=solved_blocks,
            pending_droplets=pending_droplets,
            droplets_seen=droplets_seen,
            timestamp=datetime.now().isoformat(),
            input_source=input_source,
            seed=seed
        )
        
        # Serialize state
        state_json = json.dumps(state.to_dict())
        
        # Encrypt if enabled
        if self.encrypt_state:
            if not password:
                raise ValueError("Password required to encrypt state")
            try:
                key = self._derive_state_key(password, manifest)
                fernet = Fernet(base64.urlsafe_b64encode(key))
                encrypted_data = fernet.encrypt(state_json.encode())
                
                # Save encrypted
                state_path = self._get_state_file_path(session_id)
                with open(state_path, 'wb') as f:
                    f.write(encrypted_data)
            except Exception as e:
                raise RuntimeError(f"Failed to encrypt state: {e}")
        else:
            # Save unencrypted (for debugging only)
            state_path = self._get_state_file_path(session_id)
            with open(state_path, 'w') as f:
                json.dump(state.to_dict(), f, indent=2)
        
        return str(state_path)
    
    def load_state(
        self,
        session_id: str,
        password: Optional[str] = None,
        manifest: Optional[Manifest] = None
    ) -> Optional[DecoderState]:
        """
        Load decoder state from disk (encrypted).
        
        Args:
            session_id: Session ID to load
            password: Password for decryption (required if encrypted)
            
        Returns:
            DecoderState or None if not found
            
        Raises:
            ValueError: If password is missing for encrypted state
            InvalidToken: If password is incorrect
        """
        # Prefer canonical .meow path, with legacy fallbacks
        state_path = self._get_state_file_path(session_id)
        legacy_paths = [
            state_path,
            self.state_dir / f"{session_id}.enc",
            self.state_dir / f"{session_id}.json"
        ]

        for candidate in legacy_paths:
            if not candidate.exists():
                continue

            try:
                if self.encrypt_state:
                    if password is None or manifest is None:
                        return None

                    with open(candidate, 'rb') as f:
                        encrypted_data = f.read()

                    key = self._derive_state_key(password, manifest)
                    fernet = Fernet(base64.urlsafe_b64encode(key))
                    decrypted_data = fernet.decrypt(encrypted_data)

                    data = json.loads(decrypted_data.decode())
                    return DecoderState.from_dict(data)

                with open(candidate, 'r') as f:
                    data = json.load(f)

                return DecoderState.from_dict(data)
            except InvalidToken:
                return None
            except json.JSONDecodeError as e:
                print(f"Warning: Corrupted state file {session_id}: {e}")
                return None
            except Exception as e:
                print(f"Error loading state {session_id}: {e}")
                return None

        return None
    
    def load_state_with_manifest(
        self,
        session_id: str,
        manifest: Manifest,
        password: str
    ) -> Optional[DecoderState]:
        """
        Load decoder state with manifest for decryption.
        
        Args:
            session_id: Session ID to load
            manifest: Manifest for key derivation
            password: Password for decryption
            
        Returns:
            DecoderState or None if not found
        """
        state_path = self._get_state_file_path(session_id)
        
        if state_path.exists():
            try:
                with open(state_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # Derive key and decrypt
                key = self._derive_state_key(password, manifest)
                fernet = Fernet(base64.urlsafe_b64encode(key))
                decrypted_data = fernet.decrypt(encrypted_data)
                
                # Parse JSON
                data = json.loads(decrypted_data.decode())
                return DecoderState.from_dict(data)
                
            except InvalidToken:
                print(f"Error: Incorrect password for encrypted state")
                return None
            except Exception as e:
                print(f"Warning: Failed to load encrypted state {session_id}: {e}")
                return None
        
        # Fall back to unencrypted
        return self.load_state(session_id)
    
    def restore_decoder(self, state: DecoderState, return_tuple: bool = False):
        """
        Restore FountainDecoder from saved state.
        
        Args:
            state: DecoderState to restore
            
        Returns:
            Tuple of (decoder, manifest, droplets_seen)
        """
        # Restore manifest
        manifest_dict = state.manifest
        manifest = Manifest(
            salt=bytes.fromhex(manifest_dict['salt']),
            nonce=bytes.fromhex(manifest_dict['nonce']),
            orig_len=manifest_dict['orig_len'],
            comp_len=manifest_dict['comp_len'],
            cipher_len=manifest_dict['cipher_len'],
            sha256=bytes.fromhex(manifest_dict['sha256']),
            block_size=manifest_dict['block_size'],
            k_blocks=manifest_dict['k_blocks'],
            hmac=bytes.fromhex(manifest_dict['hmac'])
        )
        
        # Create decoder
        decoder = FountainDecoder(
            k_blocks=manifest.k_blocks,
            block_size=manifest.block_size
        )
        
        # Restore solved blocks
        for i, block_hex in state.solved_blocks:
            if block_hex is not None:
                decoder.blocks[i] = bytes.fromhex(block_hex)
                decoder.decoded[i] = True
                decoder.decoded_count += 1
        
        # Note: pending_droplets are lost on restore (cannot easily reconstruct Droplet objects)
        # This is acceptable as fountain codes are redundant - we'll receive more droplets
        
        if return_tuple:
            return decoder, manifest, state.droplets_seen
        return decoder
    
    def list_sessions(self, detailed: bool = False) -> list:
        """
        List all saved sessions.
        
        Returns:
            List of session info dicts
        """
        sessions = []

        for state_file in self.state_dir.glob("session_*.meow"):
            try:
                session_id = state_file.stem
                if not detailed:
                    sessions.append(session_id)
                    continue

                mtime = datetime.fromtimestamp(state_file.stat().st_mtime)
                try:
                    state = self.load_state(session_id)
                    if state:
                        solved_count = sum(
                            1 for _, block in state.solved_blocks
                            if block is not None
                        )
                        total_blocks = state.manifest['k_blocks']
                        progress = (solved_count / total_blocks * 100) if total_blocks > 0 else 0

                        sessions.append({
                            'session_id': state.session_id,
                            'timestamp': state.timestamp,
                            'progress': progress,
                            'source': state.input_source,
                            'droplets': state.droplets_seen,
                            'blocks_solved': f"{solved_count}/{total_blocks}",
                            'encrypted': False
                        })
                    else:
                        sessions.append({
                            'session_id': session_id,
                            'timestamp': mtime.isoformat(),
                            'progress': None,
                            'source': 'unknown',
                            'droplets': None,
                            'blocks_solved': 'unknown',
                            'encrypted': True
                        })
                except Exception:
                    sessions.append({
                        'session_id': session_id,
                        'timestamp': mtime.isoformat(),
                        'progress': None,
                        'source': 'unknown',
                        'droplets': None,
                        'blocks_solved': 'unknown',
                        'encrypted': True
                    })
            except Exception:
                continue

        if detailed:
            sessions.sort(key=lambda x: x['timestamp'], reverse=True)
        return sessions
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete saved session (both encrypted and unencrypted).
        
        Args:
            session_id: Session to delete
            
        Returns:
            True if deleted successfully
        """
        deleted = False
        
        for ext in ['.meow', '.enc', '.json']:
            state_path = self.state_dir / f"{session_id}{ext}"
            if state_path.exists():
                state_path.unlink()
                deleted = True
        
        return deleted
    
    def cleanup_old_sessions(self, days: int = None) -> int:
        """
        Delete sessions older than specified days.
        
        Args:
            days: Age threshold in days (uses config default if None)
            
        Returns:
            Number of sessions deleted
        """
        if days is None:
            days = self.cleanup_days
        
        cutoff = datetime.now() - timedelta(days=days)
        deleted = 0
        
        for state_file in self.state_dir.glob("session_*.*"):
            try:
                # Use file modification time
                mtime = datetime.fromtimestamp(state_file.stat().st_mtime)
                
                if mtime < cutoff:
                    state_file.unlink()
                    deleted += 1
            except Exception:
                continue
        
        return deleted

    def cleanup_old_states(self, days: int = None) -> int:
        """Backward-compatible alias for cleanup_old_sessions."""
        return self.cleanup_old_sessions(days)
    
    def check_for_existing_session(self, manifest: Manifest) -> Optional[str]:
        """
        Check if a resume session exists for this manifest.
        
        Args:
            manifest: File manifest
            
        Returns:
            Session ID if found, None otherwise
        """
        session_id = self.generate_session_id(manifest)
        
        # Check if file exists
        for ext in ['.meow', '.enc', '.json']:
            state_path = self.state_dir / f"{session_id}{ext}"
            if state_path.exists():
                return session_id
        
        return None


class AutoSaveDecoder:
    """
    Wrapper around FountainDecoder with automatic state saving.
    """
    
    def __init__(
        self,
        decoder: FountainDecoder,
        manifest: Manifest,
        password: Optional[str] = None,
        resume_manager: ResumeManager,
        session_id: Optional[str] = None,
        auto_save_interval: int = None,
        save_interval: Optional[int] = None,
        input_source: str = "webcam",
        seed: int = 42069
    ):
        """
        Initialize auto-save decoder.
        
        Args:
            decoder: FountainDecoder instance
            manifest: File manifest
            password: Password for state encryption
            resume_manager: ResumeManager instance
            session_id: Optional session ID
            auto_save_interval: Save every N droplets (uses config default if None)
            input_source: Source type
            seed: Random seed
        """
        self.decoder = decoder
        self.manifest = manifest
        if resume_manager.encrypt_state and not password:
            raise ValueError("Password required for encrypted resume state")

        self.password = password or ""
        self.resume_manager = resume_manager
        self.session_id = session_id or resume_manager.generate_session_id(manifest)
        if auto_save_interval is None and save_interval is not None:
            auto_save_interval = save_interval
        self.auto_save_interval = auto_save_interval or resume_manager.auto_save_interval
        self.input_source = input_source
        self.seed = seed
        self.droplets_seen = 0
        self.droplets_since_save = 0
    
    def add_droplet(self, droplet) -> bool:
        """
        Add droplet with automatic saving.
        
        Args:
            droplet: Droplet object to add
            
        Returns:
            True if decoding is complete
        """
        result = self.decoder.add_droplet(droplet)
        self.droplets_seen += 1
        self.droplets_since_save += 1
        
        # Auto-save if interval reached
        if self.droplets_since_save >= self.auto_save_interval:
            try:
                self.save()
                self.droplets_since_save = 0
            except Exception as e:
                # Don't fail decode if save fails
                print(f"Warning: Auto-save failed: {e}")
        
        return result
    
    def save(self) -> str:
        """
        Manually trigger save.
        
        Returns:
            Path to state file
        """
        return self.resume_manager.save_state(
            self.decoder,
            self.manifest,
            self.password,
            self.droplets_seen,
            self.session_id,
            self.input_source,
            self.seed
        )
    
    def is_complete(self) -> bool:
        """Check if decoding complete."""
        return self.decoder.is_complete()
    
    def get_data(self, orig_len: int = None) -> bytes:
        """Get reconstructed data (same as FountainDecoder)."""
        return self.decoder.get_data(orig_len)


# Convenience functions

def resume_from_session(
    session_id: str,
    manifest: Optional[Manifest] = None,
    password: Optional[str] = None,
    resume_manager: Optional[ResumeManager] = None
) -> Optional[Tuple[FountainDecoder, Manifest, int]]:
    """
    Resume decoding from saved session.
    
    Args:
        session_id: Session to resume
        manifest: Manifest for decryption
        password: Password for state decryption
        resume_manager: Optional ResumeManager (creates default if None)
        
    Returns:
        Tuple of (decoder, manifest, droplets_seen) or None if not found
    """
    if resume_manager is None:
        resume_manager = ResumeManager()
    
    if manifest is not None and password is not None:
        state = resume_manager.load_state_with_manifest(session_id, manifest, password)
    else:
        state = resume_manager.load_state(session_id)
    if state is None:
        return None
    
    return resume_manager.restore_decoder(state)


def create_resumable_decoder(
    manifest: Manifest,
    password: Optional[str] = None,
    auto_save_interval: int = 50,
    input_source: str = "webcam",
    seed: int = 42069,
    resume_manager: Optional[ResumeManager] = None
) -> AutoSaveDecoder:
    """
    Create decoder with auto-save capability.
    
    Args:
        manifest: File manifest
        password: Password for state encryption
        auto_save_interval: Save every N droplets
        input_source: Source type
        seed: Random seed
        resume_manager: Optional ResumeManager
        
    Returns:
        AutoSaveDecoder instance
    """
    if resume_manager is None:
        resume_manager = ResumeManager()
    
    decoder = FountainDecoder(
        k_blocks=manifest.k_blocks,
        block_size=manifest.block_size
    )
    
    return AutoSaveDecoder(
        decoder,
        manifest,
        password,
        resume_manager,
        auto_save_interval=auto_save_interval,
        input_source=input_source,
        seed=seed
    )


# CLI for managing sessions
if __name__ == "__main__":
    import sys
    from colorama import Fore, Style, init
    init()
    
    manager = ResumeManager()
    
    if len(sys.argv) < 2:
        print(f"\n{Fore.CYAN}Resume Session Manager{Style.RESET_ALL}\n")
        print("Commands:")
        print("  list         - List all saved sessions")
        print("  show <id>    - Show session details")
        print("  delete <id>  - Delete session")
        print("  cleanup [days] - Delete sessions older than N days (default: 7)")
        sys.exit(0)
    
    command = sys.argv[1]
    
    if command == "list":
        sessions = manager.list_sessions(detailed=True)
        
        if not sessions:
            print(f"{Fore.YELLOW}No saved sessions found.{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.CYAN}Saved Sessions:{Style.RESET_ALL}\n")
            for s in sessions:
                encrypted_badge = f"{Fore.GREEN}🔒{Style.RESET_ALL}" if s['encrypted'] else ""
                print(f"  {Fore.GREEN}{s['session_id']}{Style.RESET_ALL} {encrypted_badge}")
                print(f"    Time:     {s['timestamp']}")
                if s['progress'] is not None:
                    print(f"    Progress: {s['progress']:.1f}% ({s['blocks_solved']} blocks)")
                    print(f"    Source:   {s['source']}")
                    print(f"    Droplets: {s['droplets']}")
                else:
                    print(f"    {Fore.YELLOW}(Encrypted - details require password){Style.RESET_ALL}")
                print()
    
    elif command == "delete" and len(sys.argv) > 2:
        session_id = sys.argv[2]
        if manager.delete_session(session_id):
            print(f"{Fore.GREEN}✓ Deleted session: {session_id}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Session not found: {session_id}{Style.RESET_ALL}")
    
    elif command == "cleanup":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 7
        deleted = manager.cleanup_old_sessions(days)
        print(f"{Fore.GREEN}✓ Deleted {deleted} sessions older than {days} days{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.RED}Unknown command: {command}{Style.RESET_ALL}")
        sys.exit(1)
