#!/bin/bash
#
# Test File Cleanup Script
# Created during test consolidation effort
#
# Files to DELETE (merged or deprecated):
#

set -e

echo "🧹 Cleaning up redundant test files..."

# Step 1: Delete deprecated file
if [ -f "tests/test_coverage_final_70.py" ]; then
    rm tests/test_coverage_final_70.py
    echo "✅ Deleted: test_coverage_final_70.py (deprecated placeholder)"
fi

# Step 2: Delete frame_mac duplicate (merged into test_frame_mac.py)
if [ -f "tests/test_core_frame_mac.py" ]; then
    rm tests/test_core_frame_mac.py
    echo "✅ Deleted: test_core_frame_mac.py (merged into test_frame_mac.py)"
fi

# Step 3: Delete metadata_obfuscation duplicates (merged into test_metadata_obfuscation.py)
if [ -f "tests/test_core_metadata_obfuscation.py" ]; then
    rm tests/test_core_metadata_obfuscation.py
    echo "✅ Deleted: test_core_metadata_obfuscation.py (merged)"
fi

if [ -f "tests/test_core_metadata_obfuscation_more.py" ]; then
    rm tests/test_core_metadata_obfuscation_more.py
    echo "✅ Deleted: test_core_metadata_obfuscation_more.py (merged)"
fi

# Step 4: Delete test_coverage.py (overlaps with test_coverage_boost.py)
if [ -f "tests/test_coverage.py" ]; then
    rm tests/test_coverage.py
    echo "✅ Deleted: test_coverage.py (overlaps with test_coverage_boost.py)"
fi

echo ""
echo "🎉 Cleanup complete!"
echo ""
echo "Files remaining in tests/test_coverage*.py:"
ls -la tests/test_coverage*.py 2>/dev/null || echo "(none found)"
echo ""
echo "Run 'pytest tests/ -v' to verify all tests still pass."
