#!/usr/bin/env python3
"""
Simple test for fountain encoding fix
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from meow_decoder.fountain import RobustSolitonDistribution, FountainEncoder
import secrets

def test_small_k():
    """Test fountain encoding with small k values that previously failed."""
    print("🧪 Testing Fountain Encoding with Small K Values")
    print("=" * 60)
    
    test_cases = [1, 2, 3, 5, 10, 20, 50, 100]
    
    for k in test_cases:
        try:
            # Create distribution (this previously failed for small k)
            dist = RobustSolitonDistribution(k)
            print(f"✅ k={k:3d}: Distribution created")
            
            # Test encoding
            data = secrets.token_bytes(k * 32)  # Some random data
            encoder = FountainEncoder(data, k, block_size=32)
            
            # Generate a few droplets
            for i in range(5):
                droplet = encoder.droplet()
                assert droplet is not None
                assert len(droplet.data) > 0
            
            print(f"   ✅ Encoding works, droplets generated")
            
        except Exception as e:
            print(f"❌ k={k:3d}: FAILED - {e}")
            import traceback
            traceback.print_exc()
            return False
    
    print("\n" + "=" * 60)
    print("🎉 ALL TESTS PASSED!")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = test_small_k()
    sys.exit(0 if success else 1)
