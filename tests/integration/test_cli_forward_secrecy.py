#!/usr/bin/env python3
"""
End-to-End CLI Test for Forward Secrecy
Tests the complete encode/decode flow with X25519 ephemeral keys

DEPRECATED: Merged into test_forward_secrecy_integration.py
This file is kept for reference but tests are skipped.
"""

import pytest
pytestmark = pytest.mark.skip(reason="DEPRECATED: Merged into test_forward_secrecy_integration.py")

import sys
import os
import subprocess
import tempfile
from pathlib import Path

def run_command(cmd, **kwargs):
    """Run command and return result."""
    print(f"\n💻 Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if result.stdout:
        print(f"📤 Output:\n{result.stdout}")
    if result.stderr:
        print(f"⚠️  Stderr:\n{result.stderr}")
    return result

def test_key_generation():
    """Test generating receiver keypair."""
    print("\n" + "=" * 60)
    print("TEST 1: Generate Receiver Keypair")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Generate keys
        result = run_command([
            sys.executable, "-m", "meow_decoder.encode",
            "--generate-keys",
            "--key-output-dir", str(tmpdir)
        ], input="test_password\ntest_password\n")
        
        if result.returncode != 0:
            print(f"❌ Key generation failed!")
            return False
        
        # Check files exist
        privkey = tmpdir / "receiver_private.pem"
        pubkey = tmpdir / "receiver_public.key"
        
        if not privkey.exists():
            print(f"❌ Private key not generated: {privkey}")
            return False
        
        if not pubkey.exists():
            print(f"❌ Public key not generated: {pubkey}")
            return False
        
        # Check public key size
        pubkey_data = pubkey.read_bytes()
        if len(pubkey_data) != 32:
            print(f"❌ Public key wrong size: {len(pubkey_data)} (expected 32)")
            return False
        
        print(f"✅ Keys generated successfully!")
        print(f"   Private: {privkey}")
        print(f"   Public: {pubkey} ({len(pubkey_data)} bytes)")
        return True

def test_encode_decode_with_fs():
    """Test complete encode/decode flow with forward secrecy."""
    print("\n" + "=" * 60)
    print("TEST 2: Encode/Decode with Forward Secrecy")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Test data
        test_file = tmpdir / "test_input.txt"
        test_file.write_text("Secret message with forward secrecy! 🔐")
        
        gif_file = tmpdir / "test.gif"
        output_file = tmpdir / "test_output.txt"
        
        # Generate keys
        print("\n📋 Step 1: Generating keys...")
        result = run_command([
            sys.executable, "-m", "meow_decoder.encode",
            "--generate-keys",
            "--key-output-dir", str(tmpdir)
        ], input="keypass123\nkeypass123\n")
        
        if result.returncode != 0:
            print("❌ Key generation failed!")
            return False
        
        privkey = tmpdir / "receiver_private.pem"
        pubkey = tmpdir / "receiver_public.key"
        
        # Encode with forward secrecy
        print("\n📋 Step 2: Encoding with forward secrecy...")
        result = run_command([
            sys.executable, "-m", "meow_decoder.encode",
            "-i", str(test_file),
            "-o", str(gif_file),
            "-p", "test_password_123",
            "--receiver-pubkey", str(pubkey),
            "--verbose"
        ])
        
        if result.returncode != 0:
            print("❌ Encoding failed!")
            return False
        
        if not gif_file.exists():
            print(f"❌ GIF not created: {gif_file}")
            return False
        
        print(f"✅ Encoding successful! GIF size: {gif_file.stat().st_size} bytes")
        
        # Decode with forward secrecy
        print("\n📋 Step 3: Decoding with forward secrecy...")
        result = run_command([
            sys.executable, "-m", "meow_decoder.decode_gif",
            "-i", str(gif_file),
            "-o", str(output_file),
            "-p", "test_password_123",
            "--receiver-privkey", str(privkey),
            "--receiver-privkey-password", "keypass123",
            "--verbose"
        ])
        
        if result.returncode != 0:
            print("❌ Decoding failed!")
            return False
        
        if not output_file.exists():
            print(f"❌ Output not created: {output_file}")
            return False
        
        # Verify content
        original = test_file.read_text()
        decoded = output_file.read_text()
        
        if original != decoded:
            print(f"❌ Content mismatch!")
            print(f"   Original: {original}")
            print(f"   Decoded:  {decoded}")
            return False
        
        print(f"✅ Decoding successful! Content matches.")
        print(f"✅ Forward secrecy working end-to-end!")
        return True

def test_password_only_mode():
    """Test backward-compatible password-only mode."""
    print("\n" + "=" * 60)
    print("TEST 3: Password-Only Mode (No Forward Secrecy)")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Test data
        test_file = tmpdir / "test_input.txt"
        test_file.write_text("Secret without forward secrecy")
        
        gif_file = tmpdir / "test.gif"
        output_file = tmpdir / "test_output.txt"
        
        # Encode without receiver pubkey (password-only)
        print("\n📋 Step 1: Encoding (password-only)...")
        result = run_command([
            sys.executable, "-m", "meow_decoder.encode",
            "-i", str(test_file),
            "-o", str(gif_file),
            "-p", "test_password_456",
            "--verbose"
        ])
        
        if result.returncode != 0:
            print("❌ Encoding failed!")
            return False
        
        # Decode without receiver privkey (password-only)
        print("\n📋 Step 2: Decoding (password-only)...")
        result = run_command([
            sys.executable, "-m", "meow_decoder.decode_gif",
            "-i", str(gif_file),
            "-o", str(output_file),
            "-p", "test_password_456",
            "--verbose"
        ])
        
        if result.returncode != 0:
            print("❌ Decoding failed!")
            return False
        
        # Verify
        original = test_file.read_text()
        decoded = output_file.read_text()
        
        if original != decoded:
            print(f"❌ Content mismatch!")
            return False
        
        print(f"✅ Password-only mode working!")
        return True

def main():
    """Run all CLI tests."""
    print("\n🔐 FORWARD SECRECY CLI INTEGRATION TESTS")
    print("=" * 60)
    
    tests = [
        ("Key Generation", test_key_generation),
        ("Encode/Decode with FS", test_encode_decode_with_fs),
        ("Password-Only Mode", test_password_only_mode)
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"\n✅ {name}: PASSED")
            else:
                failed += 1
                print(f"\n❌ {name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"\n❌ {name}: EXCEPTION - {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{len(tests)} passed")
    print("=" * 60)
    
    if failed == 0:
        print("\n🎉 ALL CLI TESTS PASSED!")
        print("   Forward secrecy is fully integrated into CLI!")
        return 0
    else:
        print(f"\n❌ {failed} TEST(S) FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
