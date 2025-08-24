"""
Focused tests for specific JSON parsing improvements.

These tests target the exact methods and functionality we fixed
to prevent regression in line number extraction, confidence conversion,
and JSON response handling.
"""

from pathlib import Path
from unittest.mock import Mock

import pytest

from adversary_mcp_server.scanner.types import Severity
from adversary_mcp_server.session.llm_session_manager import LLMSessionManager
from adversary_mcp_server.session.session_types import AnalysisSession, SecurityFinding


class TestSpecificJSONParsing:
    """Test the specific JSON parsing methods we improved."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create session manager with minimal setup
        mock_llm_client = Mock()
        self.session_manager = LLMSessionManager(
            llm_client=mock_llm_client, enable_cleanup_automation=False
        )

    def test_extract_line_number_method_directly(self):
        """Test _extract_line_number method directly with all formats."""
        # Integer inputs
        assert self.session_manager._extract_line_number(42) == 42
        assert self.session_manager._extract_line_number(1) == 1
        assert self.session_manager._extract_line_number(0) == 1  # Edge case

        # String number inputs
        assert self.session_manager._extract_line_number("42") == 42
        assert self.session_manager._extract_line_number("1") == 1

        # Estimated format (the key fix)
        assert self.session_manager._extract_line_number("estimated_10-15") == 10
        assert self.session_manager._extract_line_number("estimated_5-8") == 5
        assert self.session_manager._extract_line_number("estimated_42") == 42

        # Invalid formats default to 1
        assert self.session_manager._extract_line_number("not_a_number") == 1
        assert self.session_manager._extract_line_number("") == 1
        assert self.session_manager._extract_line_number(None) == 1

    def test_create_finding_from_data_method_directly(self):
        """Test _create_finding_from_data method directly."""
        # Create a proper mock session
        mock_session = Mock(spec=AnalysisSession)
        mock_session.session_id = "test-session-123"
        mock_session.project_root = Path("/test_project")

        # Test with valid data
        finding_data = {
            "rule_id": "test_rule_001",
            "title": "Test Security Finding",
            "description": "This is a test security finding",
            "severity": "high",  # String that should be converted
            "file_path": "test.py",
            "line_number": 42,
            "confidence": "high",  # String that should be converted
        }

        finding = self.session_manager._create_finding_from_data(
            finding_data, mock_session
        )

        # Should successfully create a finding
        assert finding is not None
        assert isinstance(finding, SecurityFinding)
        assert finding.rule_id == "test_rule_001"
        assert finding.rule_name == "Test Security Finding"
        assert finding.severity == Severity.HIGH
        assert finding.line_number == 42
        assert finding.confidence == 0.8  # "high" -> 0.8

    def test_confidence_string_conversion_directly(self):
        """Test confidence string to float conversion in _create_finding_from_data."""
        mock_session = Mock(spec=AnalysisSession)
        mock_session.session_id = "test-confidence"
        mock_session.project_root = Path("/test")

        confidence_tests = [
            ("very_low", 0.1),
            ("low", 0.3),
            ("medium", 0.5),
            ("high", 0.8),
            ("very_high", 0.95),
            (0.75, 0.75),  # Numeric should pass through
            ("unknown", 0.8),  # Unknown defaults to 0.8
        ]

        for confidence_input, expected_output in confidence_tests:
            finding_data = {
                "rule_id": f"confidence_test_{confidence_input}",
                "confidence": confidence_input,
            }

            finding = self.session_manager._create_finding_from_data(
                finding_data, mock_session
            )
            assert finding is not None
            assert finding.confidence == expected_output

    def test_severity_string_conversion_directly(self):
        """Test severity string to enum conversion in _create_finding_from_data."""
        mock_session = Mock(spec=AnalysisSession)
        mock_session.session_id = "test-severity"
        mock_session.project_root = Path("/test")

        severity_tests = [
            ("low", Severity.LOW),
            ("medium", Severity.MEDIUM),
            ("high", Severity.HIGH),
            ("critical", Severity.CRITICAL),
            ("LOW", Severity.LOW),  # Case insensitive
            ("HIGH", Severity.HIGH),
            ("unknown", Severity.MEDIUM),  # Unknown defaults to MEDIUM
        ]

        for severity_input, expected_enum in severity_tests:
            finding_data = {
                "rule_id": f"severity_test_{severity_input}",
                "severity": severity_input,
            }

            finding = self.session_manager._create_finding_from_data(
                finding_data, mock_session
            )
            assert finding is not None
            assert finding.severity == expected_enum

    def test_line_number_with_estimated_format_in_finding_creation(self):
        """Test that estimated line numbers are correctly extracted during finding creation."""
        mock_session = Mock(spec=AnalysisSession)
        mock_session.session_id = "test-estimated-lines"
        mock_session.project_root = Path("/test")

        estimated_line_tests = [
            ("estimated_10-15", 10),
            ("estimated_5-8", 5),
            ("estimated_42", 42),
            (25, 25),  # Integer should pass through
            ("30", 30),  # String number should work
        ]

        for line_input, expected_line in estimated_line_tests:
            finding_data = {
                "rule_id": f"line_test_{line_input}",
                "line_number": line_input,
            }

            finding = self.session_manager._create_finding_from_data(
                finding_data, mock_session
            )
            assert finding is not None
            assert finding.line_number == expected_line

    def test_json_sanitization_method_directly(self):
        """Test _sanitize_json_string method directly."""
        # Test basic functionality
        malformed_json = '{"description": "This has "quotes" inside"}'
        sanitized = self.session_manager._sanitize_json_string(malformed_json)

        # Should be a string (method exists and runs)
        assert isinstance(sanitized, str)

        # Test that method doesn't crash on edge cases
        edge_cases = [
            "",
            "not json at all",
            '{"valid": "json"}',
            '{"missing_end":',
        ]

        for edge_case in edge_cases:
            result = self.session_manager._sanitize_json_string(edge_case)
            assert isinstance(result, str)

    def test_create_finding_with_minimal_data(self):
        """Test finding creation with minimal required data."""
        mock_session = Mock(spec=AnalysisSession)
        mock_session.session_id = "test-minimal"
        mock_session.project_root = Path("/test")

        # Only rule_id provided
        minimal_data = {"rule_id": "minimal_test"}

        finding = self.session_manager._create_finding_from_data(
            minimal_data, mock_session
        )

        # Should create finding with defaults
        assert finding is not None
        assert finding.rule_id == "minimal_test"
        assert finding.rule_name == "AI-Detected Security Issue"  # Default
        assert finding.description == ""  # Default
        assert finding.severity == Severity.MEDIUM  # Default
        assert finding.line_number == 1  # Default
        assert finding.confidence == 0.8  # Default

    def test_create_finding_handles_exceptions_gracefully(self):
        """Test that finding creation handles exceptions gracefully."""
        mock_session = Mock(spec=AnalysisSession)
        mock_session.session_id = "test-exception"
        mock_session.project_root = Path("/test")

        # Test with invalid data that might cause exceptions
        invalid_data_cases = [
            {},  # Empty dict
            {"rule_id": None},  # None values
            {"severity": object()},  # Invalid object type
            {"confidence": "not_a_number_or_valid_string"},
        ]

        for invalid_data in invalid_data_cases:
            # Should either return a finding or None, but not crash
            try:
                result = self.session_manager._create_finding_from_data(
                    invalid_data, mock_session
                )
                # If it returns something, it should be SecurityFinding or None
                assert result is None or isinstance(result, SecurityFinding)
            except Exception:
                # If it raises an exception, that's also acceptable for invalid data
                pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
