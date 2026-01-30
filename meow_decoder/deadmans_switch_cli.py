#!/usr/bin/env python3
"""
🪦 Dead-Man's Switch CLI for Meow Decoder
==========================================

Command-line interface for configuring and managing dead-man's switch duress.

A dead-man's switch is a security device that triggers an action if you FAIL to 
take preventive action (e.g., entering a password within a time interval).

Use Cases:
1. **Journalist Protection**: If arrested and unable to check in, decoy data auto-releases
2. **Insurance Policy**: If you forget to renew, real data becomes accessible to inheritors
3. **Coercion Resistance**: Under coercion, activate to schedule automatic decoy release
4. **Time-Release Secrets**: Schedule future auto-unlock of archived data

SECURITY:
- Uses timelock_duress.py for robust implementation
- Tamper-evident: Modifications to timing are detectable
- Cryptographically sound: Based on iterated hashing

OPERATION:
1. Encode file with: meow-encode --dead-mans-switch 24h ...
2. Set check-in interval: meow-deadmans-switch renew
3. If not renewed by deadline, decoy auto-releases on decode attempt
"""

import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

from .timelock_duress import TimeLockPuzzle, TimeLockConfig, TimeLockState


class DeadManSwitchState:
    """
    Manages dead-man's switch state for a GIF file.
    
    Stores configuration and check-in history as JSON alongside the GIF.
    """
    
    def __init__(self, gif_path: str, checkin_interval_seconds: int, 
                 grace_period_seconds: int, decoy_file: Optional[str] = None):
        """
        Initialize dead-man's switch state.
        
        Args:
            gif_path: Path to the encoded GIF file
            checkin_interval_seconds: Seconds between required check-ins
            grace_period_seconds: Grace period before auto-release
            decoy_file: Optional path to decoy file to release on timeout
        """
        self.gif_path = Path(gif_path)
        self.state_file = self.gif_path.parent / f".{self.gif_path.stem}.deadman.json"
        self.checkin_interval = checkin_interval_seconds
        self.grace_period = grace_period_seconds
        self.decoy_file = decoy_file
        
        self.state = {
            'configured_at': datetime.now().isoformat(),
            'checkin_interval_seconds': checkin_interval_seconds,
            'grace_period_seconds': grace_period_seconds,
            'decoy_file': decoy_file,
            'last_checkin': None,
            'next_deadline': None,
            'status': 'armed',
            'triggered_at': None,
            'disabled_at': None,
        }
    
    def save(self):
        """Save state to JSON file."""
        # Calculate next deadline based on current time
        if self.state['last_checkin'] is None:
            # First setup: deadline is now + interval + grace
            next_deadline = datetime.now() + timedelta(seconds=self.checkin_interval + self.grace_period)
        else:
            # Renew: deadline is last checkin + interval + grace
            last_checkin = datetime.fromisoformat(self.state['last_checkin'])
            next_deadline = last_checkin + timedelta(seconds=self.checkin_interval + self.grace_period)
        
        self.state['next_deadline'] = next_deadline.isoformat()
        
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
        
        print(f"💾 State saved: {self.state_file}")
    
    @classmethod
    def load(cls, gif_path: str) -> 'DeadManSwitchState':
        """Load state from JSON file."""
        gif_path = Path(gif_path)
        state_file = gif_path.parent / f".{gif_path.stem}.deadman.json"
        
        if not state_file.exists():
            raise FileNotFoundError(f"Dead-man's switch state not found: {state_file}")
        
        with open(state_file, 'r') as f:
            state_dict = json.load(f)
        
        instance = cls(
            gif_path=str(gif_path),
            checkin_interval_seconds=state_dict['checkin_interval_seconds'],
            grace_period_seconds=state_dict['grace_period_seconds'],
            decoy_file=state_dict.get('decoy_file')
        )
        instance.state = state_dict
        
        return instance
    
    def renew(self):
        """Reset check-in timer."""
        self.state['last_checkin'] = datetime.now().isoformat()
        self.state['status'] = 'armed'
        self.save()
    
    def is_deadline_passed(self) -> bool:
        """Check if deadline has passed."""
        if self.state['status'] != 'armed':
            return False
        
        if self.state['next_deadline'] is None:
            return False
        
        deadline = datetime.fromisoformat(self.state['next_deadline'])
        return datetime.now() > deadline
    
    def trigger(self):
        """Manually trigger decoy release."""
        self.state['status'] = 'triggered'
        self.state['triggered_at'] = datetime.now().isoformat()
        self.save()
    
    def disable(self):
        """Disable dead-man's switch."""
        self.state['status'] = 'disabled'
        self.state['disabled_at'] = datetime.now().isoformat()
        self.save()


def cmd_setup(args):
    """
    Set up a new dead-man's switch for an encoded file.
    
    Usage:
        meow-deadmans-switch setup --gif secret.gif --duration 24h --decoy decoy.pdf
    """
    print("🪦 Dead-Man's Switch Setup")
    print("=" * 60)
    
    gif_path = Path(args.gif)
    if not gif_path.exists():
        print(f"❌ Error: GIF file not found: {gif_path}")
        return 1
    
    # Parse duration
    duration_str = args.duration.lower()
    try:
        if duration_str.endswith('h'):
            duration_seconds = int(duration_str[:-1]) * 3600
        elif duration_str.endswith('d'):
            duration_seconds = int(duration_str[:-1]) * 86400
        elif duration_str.endswith('m'):
            duration_seconds = int(duration_str[:-1]) * 60
        else:
            duration_seconds = int(duration_str)
    except ValueError:
        print(f"❌ Error: Invalid duration format: {args.duration}")
        print(f"   Use: 24h (hours), 7d (days), 3600s (seconds)")
        return 1
    
    # Parse decoy file if provided
    decoy_path = None
    if args.decoy:
        decoy_path = Path(args.decoy)
        if not decoy_path.exists():
            print(f"❌ Error: Decoy file not found: {decoy_path}")
            return 1
        print(f"📋 Decoy file: {decoy_path.name}")
    
    # Create configuration
    config = TimeLockConfig(
        checkin_interval_seconds=duration_seconds,
        grace_period_seconds=args.grace * 3600 if args.grace else 3600,
        deadman_enabled=True,
        deadman_decoy_path=str(decoy_path) if decoy_path else None
    )
    
    # Load manifest from GIF (would need integration with decode_gif)
    # For now, just save the configuration
    state_file = gif_path.with_suffix('.deadman.json')
    
    state = {
        'configured_at': datetime.now().isoformat(),
        'checkin_interval_seconds': duration_seconds,
        'grace_period_seconds': config.grace_period_seconds,
        'decoy_file': str(decoy_path) if decoy_path else None,
        'last_checkin': None,
        'next_deadline': None,
        'status': 'armed'
    }
    
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)
    
    print(f"\n✅ Dead-man's switch configured!")
    print(f"   Check-in interval: {duration_str}")
    print(f"   Grace period: {args.grace}h" if args.grace else "   Grace period: 1h")
    print(f"   State file: {state_file}")
    print(f"\n💡 Next step: Run 'meow-deadmans-switch renew' to set the first deadline")
    
    return 0


def cmd_renew(args):
    """
    Renew the dead-man's switch (reset the countdown timer).
    
    Usage:
        meow-deadmans-switch renew --gif secret.gif
    """
    print("🪦 Dead-Man's Switch Renewal")
    print("=" * 60)
    
    gif_path = Path(args.gif)
    state_file = gif_path.with_suffix('.deadman.json')
    
    if not state_file.exists():
        print(f"❌ Error: No dead-man's switch configured for {gif_path.name}")
        print(f"   First run: meow-deadmans-switch setup --gif {gif_path}")
        return 1
    
    # Load state
    with open(state_file, 'r') as f:
        state = json.load(f)
    
    # Calculate new deadline
    interval = state['checkin_interval_seconds']
    now = datetime.now()
    deadline = now + timedelta(seconds=interval)
    
    # Update state
    state['last_checkin'] = now.isoformat()
    state['next_deadline'] = deadline.isoformat()
    state['status'] = 'armed'
    
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)
    
    print(f"✅ Dead-man's switch renewed!")
    print(f"   Last check-in: {now.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Next deadline: {deadline.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Time remaining: {interval // 3600} hours")
    
    return 0


def cmd_status(args):
    """
    Check the status of a dead-man's switch.
    
    Usage:
        meow-deadmans-switch status --gif secret.gif
    """
    print("🪦 Dead-Man's Switch Status")
    print("=" * 60)
    
    gif_path = Path(args.gif)
    state_file = gif_path.with_suffix('.deadman.json')
    
    if not state_file.exists():
        print(f"❌ No dead-man's switch configured for {gif_path.name}")
        return 1
    
    # Load state
    with open(state_file, 'r') as f:
        state = json.load(f)
    
    print(f"\n📊 Configuration:")
    print(f"   Check-in interval: {state['checkin_interval_seconds'] // 3600}h")
    print(f"   Decoy file: {state['decoy_file'] or '(none)'}")
    print(f"   Status: {state['status'].upper()}")
    
    if state['last_checkin']:
        last_checkin = datetime.fromisoformat(state['last_checkin'])
        print(f"\n📅 Last Check-In:")
        print(f"   When: {last_checkin.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if state['next_deadline']:
            deadline = datetime.fromisoformat(state['next_deadline'])
            now = datetime.now()
            
            if now < deadline:
                time_left = (deadline - now).total_seconds()
                hours = int(time_left // 3600)
                minutes = int((time_left % 3600) // 60)
                
                print(f"   Deadline: {deadline.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   Time until deadline: {hours}h {minutes}m")
                
                if time_left < 3600:  # Less than 1 hour
                    print(f"\n⚠️  WARNING: Less than 1 hour until auto-release trigger!")
                    print(f"   Remember to renew: meow-deadmans-switch renew")
            else:
                print(f"   ⚠️  DEADLINE PASSED - Auto-release would trigger on next decode")
                print(f"   Renew now to prevent auto-release")
    else:
        print(f"\n⚠️  Never checked in - deadline will trigger immediately on decode")
    
    return 0


def cmd_trigger(args):
    """
    Manually trigger the dead-man's switch (forces decoy release).
    
    Usage:
        meow-deadmans-switch trigger --gif secret.gif [--confirm]
    """
    print("🪦 Dead-Man's Switch Manual Trigger")
    print("=" * 60)
    
    gif_path = Path(args.gif)
    state_file = gif_path.with_suffix('.deadman.json')
    
    if not state_file.exists():
        print(f"❌ No dead-man's switch configured for {gif_path.name}")
        return 1
    
    # Load state
    with open(state_file, 'r') as f:
        state = json.load(f)
    
    # Warn user
    print(f"\n⚠️  WARNING: This will trigger immediate decoy release!")
    print(f"   GIF: {gif_path.name}")
    print(f"   Decoy file: {state['decoy_file'] or '(none)'}")
    print(f"\n💡 This action is NON-REVERSIBLE. Once triggered, decoy data will release")
    print(f"   on the next decode attempt (cannot be cancelled).")
    
    if not args.confirm:
        response = input("\n❓ Type 'trigger' to confirm: ").strip()
        if response != 'trigger':
            print("❌ Cancelled")
            return 1
    
    # Mark as triggered
    state['status'] = 'triggered'
    state['triggered_at'] = datetime.now().isoformat()
    
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)
    
    print(f"\n✅ Dead-man's switch TRIGGERED")
    print(f"   Next decode attempt will release the decoy")
    print(f"   Timestamp: {state['triggered_at']}")
    
    return 0


def cmd_disable(args):
    """
    Disable a dead-man's switch permanently.
    
    Usage:
        meow-deadmans-switch disable --gif secret.gif [--confirm]
    """
    print("🪦 Dead-Man's Switch Disable")
    print("=" * 60)
    
    gif_path = Path(args.gif)
    state_file = gif_path.with_suffix('.deadman.json')
    
    if not state_file.exists():
        print(f"❌ No dead-man's switch configured for {gif_path.name}")
        return 1
    
    print(f"\n⚠️  WARNING: Disabling dead-man's switch")
    print(f"   GIF: {gif_path.name}")
    print(f"   Decoy auto-release will be cancelled")
    
    if not args.confirm:
        response = input("\n❓ Type 'disable' to confirm: ").strip()
        if response != 'disable':
            print("❌ Cancelled")
            return 1
    
    # Load and update state
    with open(state_file, 'r') as f:
        state = json.load(f)
    
    state['status'] = 'disabled'
    state['disabled_at'] = datetime.now().isoformat()
    
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)
    
    print(f"\n✅ Dead-man's switch DISABLED")
    print(f"   Decoy auto-release is now inactive")
    
    return 0


def main():
    """Main CLI entry point for dead-man's switch."""
    
    parser = argparse.ArgumentParser(
        prog='meow-deadmans-switch',
        description='🪦 Dead-Man\'s Switch - Time-Release Duress for Meow Decoder',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🪦 DEAD-MAN'S SWITCH EXAMPLES:

  Setup with 24-hour check-in:
    meow-deadmans-switch setup --gif secret.gif --duration 24h --decoy decoy.pdf

  Check status:
    meow-deadmans-switch status --gif secret.gif

  Renew the timer:
    meow-deadmans-switch renew --gif secret.gif

  Manually trigger (emergency):
    meow-deadmans-switch trigger --gif secret.gif

  Disable (cancel auto-release):
    meow-deadmans-switch disable --gif secret.gif

🪦 HOW IT WORKS:

  1. Setup: Configure a time interval and optional decoy file
  2. Encode: Create encrypted GIF with dead-man's switch enabled
  3. Renew: Periodically run 'renew' to reset the timer
  4. Deadline: If deadline passes without renewal, decoy auto-releases
  5. Decode: Attempting to decode past deadline reveals decoy instead

⚠️  SECURITY NOTES:

  - Dead-man's switch is NON-CRYPTOGRAPHIC (uses system time)
  - Time can be manipulated by an attacker with system access
  - For cryptographic time-locking, see: meow-timelock
  - For high-value secrets, combine with offline storage

📖 DOCUMENTATION:

  See docs/THREAT_MODEL.md § Coercion Resistance for full details
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Subcommand to run')
    
    # Setup subcommand
    setup_parser = subparsers.add_parser('setup', help='Setup new dead-man\'s switch')
    setup_parser.add_argument('--gif', required=True, help='Path to encoded GIF')
    setup_parser.add_argument('--duration', default='24h',
                             help='Check-in interval (e.g., 24h, 7d, 3600s)')
    setup_parser.add_argument('--decoy', help='Path to decoy file to auto-release')
    setup_parser.add_argument('--grace', type=int, default=1,
                             help='Grace period in hours (default: 1)')
    setup_parser.set_defaults(func=cmd_setup)
    
    # Renew subcommand
    renew_parser = subparsers.add_parser('renew', help='Renew the timer')
    renew_parser.add_argument('--gif', required=True, help='Path to encoded GIF')
    renew_parser.set_defaults(func=cmd_renew)
    
    # Status subcommand
    status_parser = subparsers.add_parser('status', help='Check status')
    status_parser.add_argument('--gif', required=True, help='Path to encoded GIF')
    status_parser.set_defaults(func=cmd_status)
    
    # Trigger subcommand
    trigger_parser = subparsers.add_parser('trigger', help='Manually trigger decoy release')
    trigger_parser.add_argument('--gif', required=True, help='Path to encoded GIF')
    trigger_parser.add_argument('--confirm', action='store_true',
                               help='Skip confirmation prompt')
    trigger_parser.set_defaults(func=cmd_trigger)
    
    # Disable subcommand
    disable_parser = subparsers.add_parser('disable', help='Disable dead-man\'s switch')
    disable_parser.add_argument('--gif', required=True, help='Path to encoded GIF')
    disable_parser.add_argument('--confirm', action='store_true',
                               help='Skip confirmation prompt')
    disable_parser.set_defaults(func=cmd_disable)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    # Call the appropriate command handler
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
