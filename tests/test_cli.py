"""Tests for CLI module."""

import os
import sys
from unittest.mock import patch

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.cli import (
    _display_scan_results,
    configure,
    demo,
    list_rules,
    main,
    reset,
    rule_details,
    scan,
    status,
)
from adversary_mcp_server.threat_engine import Category, Severity, ThreatMatch


class TestCLI:
    """Test cases for CLI functions."""

    def test_main_function_exists(self):
        """Test main function exists."""
        assert main is not None

    def test_configure_function_exists(self):
        """Test configure function exists."""
        assert configure is not None

    def test_cli_functions_exist(self):
        """Test that CLI functions can be imported."""
        # Since these are typer commands, we mainly test they can be imported
        assert status is not None
        assert scan is not None
        assert list_rules is not None
        assert rule_details is not None
        assert demo is not None
        assert reset is not None

    def test_display_scan_results_empty(self):
        """Test _display_scan_results with empty results."""
        with patch("adversary_mcp_server.cli.console") as mock_console:
            _display_scan_results([], "test.py")
            mock_console.print.assert_called()

    def test_display_scan_results_with_threats(self):
        """Test _display_scan_results with threats."""
        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            code_snippet="test code",
            exploit_examples=["test exploit"],
            remediation="Fix it",
        )

        with patch("adversary_mcp_server.cli.console") as mock_console:
            _display_scan_results([threat], "test.py")
            mock_console.print.assert_called()


class TestCLIIntegration:
    """Integration tests for CLI."""

    def test_cli_import_integration(self):
        """Test that CLI components can be integrated."""
        # Test that we can import all the CLI functions
        assert main is not None
        assert configure is not None
        assert status is not None

        # Test basic CLI structure exists
        from adversary_mcp_server import cli

        assert hasattr(cli, "cli")  # Main typer app
