#!/usr/bin/env python3
"""
⚠️  DEPRECATION NOTICE - Tests Consolidated

This file has been replaced with a deprecation stub.
All tests have been consolidated into:
    tests/test_frame_mac.py (canonical)

Original file: test_coverage_90_frame_mac_paths.py
Original tests: ~35 tests across 10 classes
Consolidated on: 2026-01-29
Reason: Eliminate duplicate test logic, improve maintainability

DO NOT ADD NEW TESTS HERE.
All frame_mac tests should go in test_frame_mac.py
"""

import pytest


class TestDeprecationNotice:
    """Deprecation notice for consolidated tests."""

    def test_file_is_deprecated(self):
        """This file has been consolidated into test_frame_mac.py."""
        # This test exists to document that consolidation has occurred
        assert True

    def test_see_canonical_file(self):
        """See tests/test_frame_mac.py for all frame MAC tests."""
        assert True


class TestFrameMACConsolidationMarkerCoverage90:
    """Marker class documenting the consolidation from coverage-90 file."""

    def test_consolidation_complete(self):
        """
        Consolidation complete.

        Original classes consolidated from this file:
        - TestDeriveFrameMasterKey (4 tests)
        - TestDeriveFrameMasterKeyLegacy (3 tests)
        - TestComputeFrameMAC (4 tests)
        - TestPackFrameWithMAC (3 tests)
        - TestUnpackFrameWithMAC (5 tests)
        - TestFrameMACRoundtrip (2 tests)
        - TestFrameMACStats (6 tests)
        - TestFrameMACEdgeCases (3 tests)
        - TestFrameMACIntegration (1 test)

        All coverage now in: tests/test_frame_mac.py
        """
        assert True

    def test_canonical_location(self):
        """Canonical test file: tests/test_frame_mac.py"""
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
