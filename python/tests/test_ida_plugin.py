"""
Test suite for BinDiff IDA plugin.

Tests that the plugin can be imported and basic functionality works within IDA Pro.
"""
import sys
import unittest


class TestBinDiffIDAPlugin(unittest.TestCase):
    """Test BinDiff IDA plugin imports and basic functionality."""

    def test_import_ida_plugin(self):
        """Test that the IDA plugin module can be imported."""
        try:
            from bindiff.ida_plugin import BindiffResults, Match, PortCommentsKind
            self.assertIsNotNone(BindiffResults)
            self.assertIsNotNone(Match)
            self.assertIsNotNone(PortCommentsKind)
        except ImportError as e:
            self.fail(f"Failed to import bindiff.ida_plugin: {e}")

    def test_create_results_wrapper(self):
        """Test that ResultsWrapper can be instantiated."""
        from bindiff.ida_plugin import BindiffResults
        
        # Create a results wrapper instance
        results = BindiffResults()
        self.assertIsNotNone(results)
        
        # Should start with no matches
        self.assertEqual(results.num_matches(), 0)

    def test_port_comments_enum(self):
        """Test that PortCommentsKind enum values are accessible."""
        from bindiff.ida_plugin import PortCommentsKind
        
        # Verify enum values exist
        self.assertTrue(hasattr(PortCommentsKind, '__members__'))


if __name__ == '__main__':
    unittest.main()
