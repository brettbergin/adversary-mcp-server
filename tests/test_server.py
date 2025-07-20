"""Tests for MCP server module."""

import os
import sys

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.server import AdversaryMCPServer
from adversary_mcp_server.threat_engine import Category, Severity, ThreatMatch


class TestAdversaryMCPServer:
    """Test cases for AdversaryMCPServer class."""

    def test_init(self):
        """Test server initialization."""
        server = AdversaryMCPServer()
        assert server.threat_engine is not None
        assert server.ast_scanner is not None
        assert server.credential_manager is not None
        assert server.exploit_generator is not None

    def test_server_filtering_methods(self):
        """Test server utility methods."""
        server = AdversaryMCPServer()

        # Test severity filtering
        threats = [
            ThreatMatch(
                rule_id="test1",
                rule_name="Test 1",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
            ),
            ThreatMatch(
                rule_id="test2",
                rule_name="Test 2",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=2,
            ),
        ]

        filtered = server._filter_threats_by_severity(threats, Severity.MEDIUM)
        assert len(filtered) == 1  # Only HIGH severity should remain

    def test_format_scan_results(self):
        """Test scan results formatting."""
        server = AdversaryMCPServer()

        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
        )

        result = server._format_scan_results([threat], "test.py")
        assert "Test Rule" in result
        assert "test.py" in result


class TestServerIntegration:
    """Integration tests for server functionality."""

    def test_server_startup(self):
        """Test server can be created and initialized."""
        server = AdversaryMCPServer()
        assert server is not None
        assert hasattr(server, "threat_engine")
        assert hasattr(server, "ast_scanner")
        assert hasattr(server, "exploit_generator")
        assert hasattr(server, "credential_manager")


class TestServerUtilities:
    """Test server utility functions."""

    def test_format_threat_output(self):
        """Test threat formatting."""
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
            cwe_id="CWE-89",
        )

        # Test that threat can be converted to string representation
        threat_str = str(threat)
        assert isinstance(threat_str, str)
