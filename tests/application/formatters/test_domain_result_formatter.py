"""Comprehensive tests for DomainScanResultFormatter."""

import json
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from adversary_mcp_server.application.formatters.domain_result_formatter import (
    DomainScanResultFormatter,
)
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class TestDomainScanResultFormatter:
    """Test DomainScanResultFormatter functionality."""

    @pytest.fixture
    def sample_threat(self):
        """Create a sample threat for testing."""
        return ThreatMatch(
            uuid=str(uuid.uuid4()),
            rule_id="test-rule-001",
            rule_name="SQL Injection",
            description="Potential SQL injection vulnerability detected",
            category="security",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceScore(0.85),
            file_path=FilePath.from_string("/test/file.py"),
            line_number=42,
            column_number=15,
            code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
            source_scanner="semgrep",
            remediation="Use parameterized queries to prevent SQL injection",
            exploit_examples=["'; DROP TABLE users; --"],
        )

    @pytest.fixture
    def sample_scan_result(self, sample_threat):
        """Create a sample scan result for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_path = f.name

        try:
            # Create proper domain objects
            context = ScanContext.for_file(
                file_path=temp_path,
                requester="test_user",
                language="python",
                timeout_seconds=120,
                enable_semgrep=True,
                enable_llm=False,
                enable_validation=False,
            )

            request = ScanRequest(
                context=context,
                enable_semgrep=True,
                enable_llm=False,
                enable_validation=False,
                severity_threshold=SeverityLevel.MEDIUM,
            )

            result = ScanResult.create_from_threats(
                request=request,
                threats=[sample_threat],
                scan_metadata={"scan_duration_ms": 1500, "lines_analyzed": 100},
                validation_applied=False,
            )

            yield result
        finally:
            # Cleanup
            Path(temp_path).unlink(missing_ok=True)

    @pytest.fixture
    def empty_scan_result(self):
        """Create an empty scan result for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_path = f.name

        try:
            context = ScanContext.for_file(
                file_path=temp_path,
                requester="test_user",
                language="python",
                enable_semgrep=True,
                enable_llm=False,
                enable_validation=False,
            )

            request = ScanRequest(
                context=context,
                enable_semgrep=True,
                enable_llm=False,
                enable_validation=False,
            )

            result = ScanResult.create_empty(request)
            yield result
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_formatter_initialization_default(self):
        """Test formatter initialization with default parameters."""
        formatter = DomainScanResultFormatter()
        assert formatter.include_metadata is True
        assert formatter.include_exploits is False

    def test_formatter_initialization_custom(self):
        """Test formatter initialization with custom parameters."""
        formatter = DomainScanResultFormatter(
            include_metadata=False, include_exploits=True
        )
        assert formatter.include_metadata is False
        assert formatter.include_exploits is True

    def test_format_json_with_threats(self, sample_scan_result):
        """Test JSON formatting with threats."""
        formatter = DomainScanResultFormatter()
        json_output = formatter.format_json(sample_scan_result)

        # Verify it's valid JSON
        data = json.loads(json_output)
        assert "scan_metadata" in data
        assert "summary" in data
        assert "statistics" in data
        assert "threats" in data
        assert len(data["threats"]) == 1

        # Check threat structure
        threat = data["threats"][0]
        assert threat["rule_name"] == "SQL Injection"
        assert threat["severity"] == "high"
        assert threat["confidence"]["percentage"] == 85.0

    def test_format_json_empty_result(self, empty_scan_result):
        """Test JSON formatting with empty result."""
        formatter = DomainScanResultFormatter()
        json_output = formatter.format_json(empty_scan_result)

        data = json.loads(json_output)
        assert data["summary"]["total_threats"] == 0
        assert data["threats"] == []
        assert data["summary"]["is_empty"] is True

    def test_format_dict(self, sample_scan_result):
        """Test dictionary formatting."""
        formatter = DomainScanResultFormatter()
        data = formatter.format_dict(sample_scan_result)

        assert isinstance(data, dict)
        assert "scan_metadata" in data
        assert "summary" in data
        assert "statistics" in data
        assert "threats" in data
        assert "validation_info" in data
        assert "scanner_execution_summary" in data

    def test_format_markdown_with_threats(self, sample_scan_result):
        """Test Markdown formatting with threats."""
        formatter = DomainScanResultFormatter()
        markdown_output = formatter.format_markdown(sample_scan_result)

        assert "# Security Scan Report" in markdown_output
        assert "## Scan Information" in markdown_output
        assert "## Summary" in markdown_output
        assert "## Threats Found" in markdown_output
        assert "### 1. SQL Injection" in markdown_output
        assert "- **Severity**: high" in markdown_output

    def test_format_markdown_empty_result(self, empty_scan_result):
        """Test Markdown formatting with empty result."""
        formatter = DomainScanResultFormatter()
        markdown_output = formatter.format_markdown(empty_scan_result)

        assert "# Security Scan Report" in markdown_output
        assert "## No Threats Found" in markdown_output
        assert "No security vulnerabilities were detected" in markdown_output

    def test_format_csv_with_threats(self, sample_scan_result):
        """Test CSV formatting with threats."""
        formatter = DomainScanResultFormatter()
        csv_output = formatter.format_csv(sample_scan_result)

        lines = csv_output.split("\n")
        assert len(lines) >= 2  # Header + at least one threat

        # Check header
        header = lines[0]
        assert "rule_id" in header
        assert "severity" in header
        assert "confidence" in header

        # Check threat data
        threat_line = lines[1]
        assert "test-rule-001" in threat_line
        assert "high" in threat_line
        assert "85.0%" in threat_line

    def test_format_csv_empty_result(self, empty_scan_result):
        """Test CSV formatting with empty result."""
        formatter = DomainScanResultFormatter()
        csv_output = formatter.format_csv(empty_scan_result)

        lines = csv_output.split("\n")
        assert len(lines) == 1  # Only header
        assert "rule_id" in lines[0]

    def test_json_serializer_datetime(self):
        """Test JSON serializer with datetime objects."""
        formatter = DomainScanResultFormatter()
        test_datetime = datetime(2023, 12, 25, 12, 30, 45)
        result = formatter._json_serializer(test_datetime)
        assert result == "2023-12-25T12:30:45"

    def test_json_serializer_path(self):
        """Test JSON serializer with Path objects."""
        formatter = DomainScanResultFormatter()
        test_path = Path("/test/path.py")
        result = formatter._json_serializer(test_path)
        assert result == "/test/path.py"

    def test_json_serializer_with_to_dict(self):
        """Test JSON serializer with objects that have to_dict method."""
        formatter = DomainScanResultFormatter()

        class MockObject:
            def to_dict(self):
                return {"test": "value"}

        obj = MockObject()
        result = formatter._json_serializer(obj)
        assert result == {"test": "value"}

    def test_json_serializer_with_str_method(self):
        """Test JSON serializer with objects that have __str__ method."""
        formatter = DomainScanResultFormatter()

        class MockObject:
            def __str__(self):
                return "test string with control\x01char"

        obj = MockObject()
        result = formatter._json_serializer(obj)
        assert result == "test string with controlchar"  # Control character removed

    def test_json_serializer_with_str_fallback(self):
        """Test JSON serializer falls back to __str__ for unknown objects."""
        formatter = DomainScanResultFormatter()

        # object() has __str__, so it should work
        result = formatter._json_serializer(object())
        assert isinstance(result, str)
        assert result.startswith("<object object at")

    def test_sanitize_for_json(self):
        """Test JSON sanitization function."""
        formatter = DomainScanResultFormatter()

        # Test with control characters
        dirty_text = "Hello\x01\x02\x03World\t\n\r"
        clean_text = formatter._sanitize_for_json(dirty_text)
        assert (
            clean_text == "HelloWorld\t\n\r"
        )  # Control chars removed, whitespace preserved

        # Test with non-string input
        result = formatter._sanitize_for_json(123)
        assert result == "123"

    def test_format_scan_metadata_full(self, sample_scan_result):
        """Test scan metadata formatting with full metadata."""
        formatter = DomainScanResultFormatter(include_metadata=True)
        metadata = formatter._format_scan_metadata(sample_scan_result)

        assert "scan_id" in metadata
        assert "scan_type" in metadata
        assert "timestamp" in metadata
        assert "requester" in metadata
        assert "target_path" in metadata
        assert "scanners_enabled" in metadata
        assert "scanners_used" in metadata
        assert "timeout_seconds" in metadata
        assert "additional_metadata" in metadata

    def test_format_scan_metadata_minimal(self, sample_scan_result):
        """Test scan metadata formatting without full metadata."""
        formatter = DomainScanResultFormatter(include_metadata=False)
        metadata = formatter._format_scan_metadata(sample_scan_result)

        assert "scan_id" in metadata
        assert "scanners_enabled" in metadata
        assert "timeout_seconds" not in metadata
        assert "additional_metadata" not in metadata

    def test_format_summary(self, sample_scan_result):
        """Test summary formatting."""
        formatter = DomainScanResultFormatter()
        summary = formatter._format_summary(sample_scan_result)

        assert summary["total_threats"] == 1
        assert "threat_count_by_severity" in summary
        # The method get_threats_by_severity with string expects exact string match
        # Our threat has severity SeverityLevel.HIGH which should match "high"
        # NOTE: Due to duplicate method definitions in ScanResult, the string version
        # of get_threats_by_severity doesn't work as expected - it's overridden by the SeverityLevel version
        assert summary["threat_count_by_severity"]["high"] == 1
        assert summary["has_critical_threats"] is False
        assert summary["is_empty"] is False
        assert "high_confidence_threats" in summary
        assert "validated_threats" in summary

    def test_format_statistics(self, sample_scan_result):
        """Test statistics formatting."""
        formatter = DomainScanResultFormatter()
        stats = formatter._format_statistics(sample_scan_result)

        assert "total_threats" in stats
        assert "by_scanner" in stats
        assert "semgrep" in stats["by_scanner"]
        assert stats["by_scanner"]["semgrep"]["threats_found"] == 1
        assert "avg_confidence" in stats["by_scanner"]["semgrep"]

    def test_format_threats_with_exploits(self, sample_scan_result):
        """Test threat formatting with exploits enabled."""
        formatter = DomainScanResultFormatter(include_exploits=True)
        threats = formatter._format_threats(sample_scan_result.threats)

        assert len(threats) == 1
        threat = threats[0]
        assert "exploit_examples" in threat
        assert threat["exploit_examples"] == ["'; DROP TABLE users; --"]

    def test_format_threats_without_exploits(self, sample_scan_result):
        """Test threat formatting with exploits disabled."""
        formatter = DomainScanResultFormatter(include_exploits=False)
        threats = formatter._format_threats(sample_scan_result.threats)

        assert len(threats) == 1
        threat = threats[0]
        assert "exploit_examples" not in threat

    def test_format_threats_with_metadata(self, sample_scan_result):
        """Test threat formatting with metadata enabled."""
        formatter = DomainScanResultFormatter(include_metadata=True)
        threats = formatter._format_threats(sample_scan_result.threats)

        threat = threats[0]
        assert "metadata" in threat

    def test_format_threats_without_metadata(self, sample_scan_result):
        """Test threat formatting with metadata disabled."""
        formatter = DomainScanResultFormatter(include_metadata=False)
        threats = formatter._format_threats(sample_scan_result.threats)

        threat = threats[0]
        assert "metadata" not in threat

    def test_format_validation_info_with_validation(self):
        """Test validation info formatting with validated threats."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_path = f.name

        try:
            context = ScanContext.for_file(
                file_path=temp_path,
                requester="test_user",
                enable_validation=True,
            )

            request = ScanRequest(
                context=context,
                enable_validation=True,
            )

            # Create threat with valid scanner name but mock the source_scanner property
            threat = ThreatMatch(
                uuid=str(uuid.uuid4()),
                rule_id="val-001",
                rule_name="Validation Test",
                description="Test",
                category="test",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceScore(0.7),
                file_path=FilePath.from_string(temp_path),
                line_number=1,
                source_scanner="llm",  # Use valid scanner name
                is_false_positive=True,
            )

            # Mock the source_scanner property to include "validation"
            with patch.object(threat, "source_scanner", "llm_validation"):
                result = ScanResult.create_from_threats(request, [threat])

                formatter = DomainScanResultFormatter()
                validation_info = formatter._format_validation_info(result)

                assert validation_info is not None
                assert validation_info["validation_enabled"] is True
                assert validation_info["total_threats_validated"] == 1
                assert validation_info["false_positives_detected"] == 1
                assert validation_info["false_positive_rate"] == 1.0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_format_validation_info_without_validation(self, sample_scan_result):
        """Test validation info formatting without validated threats."""
        formatter = DomainScanResultFormatter()
        validation_info = formatter._format_validation_info(sample_scan_result)

        assert validation_info is None

    def test_format_scanner_execution_summary(self, sample_scan_result):
        """Test scanner execution summary formatting."""
        formatter = DomainScanResultFormatter()
        summary = formatter._format_scanner_execution_summary(sample_scan_result)

        assert summary["total_scanners_used"] == 1
        assert "scanners" in summary
        assert "semgrep" in summary["scanners"]
        assert summary["scanners"]["semgrep"]["status"] == "completed"
        assert summary["scanners"]["semgrep"]["threats_found"] == 1

    def test_escape_csv_simple(self):
        """Test CSV escaping with simple values."""
        formatter = DomainScanResultFormatter()

        assert formatter._escape_csv("simple") == "simple"
        assert formatter._escape_csv("with space") == "with space"

    def test_escape_csv_with_quotes(self):
        """Test CSV escaping with quotes."""
        formatter = DomainScanResultFormatter()

        result = formatter._escape_csv('has "quotes" inside')
        assert result == '"has ""quotes"" inside"'

    def test_escape_csv_with_commas(self):
        """Test CSV escaping with commas."""
        formatter = DomainScanResultFormatter()

        result = formatter._escape_csv("has,commas,inside")
        assert result == '"has,commas,inside"'

    def test_escape_csv_with_newlines(self):
        """Test CSV escaping with newlines."""
        formatter = DomainScanResultFormatter()

        result = formatter._escape_csv("has\nnewlines\ninside")
        assert result == '"has\nnewlines\ninside"'

    def test_markdown_with_remediation_advice(self):
        """Test Markdown formatting with remediation advice."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_path = f.name

        try:
            context = ScanContext.for_file(file_path=temp_path, requester="test")
            request = ScanRequest(context=context)

            # Create threat with remediation advice
            threat = ThreatMatch(
                uuid=str(uuid.uuid4()),
                rule_id="test-001",
                rule_name="Test Threat",
                description="Test description",
                category="test",
                severity=SeverityLevel.LOW,
                confidence=ConfidenceScore(0.5),
                file_path=FilePath.from_string(temp_path),
                line_number=1,
                source_scanner="semgrep",
            )

            # Mock remediation advice attribute
            threat.remediation_advice = [
                "Use secure coding practices",
                "Validate all inputs",
            ]

            result = ScanResult.create_from_threats(request, [threat])

            formatter = DomainScanResultFormatter()
            markdown_output = formatter.format_markdown(result)

            assert "- **Remediation**:" in markdown_output
            assert "  - Use secure coding practices" in markdown_output
            assert "  - Validate all inputs" in markdown_output
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_format_with_code_snippet(self, sample_scan_result):
        """Test formatting with code snippet in threat."""
        formatter = DomainScanResultFormatter()
        markdown_output = formatter.format_markdown(sample_scan_result)

        assert "- **Code**:" in markdown_output
        assert "```" in markdown_output
        assert "SELECT * FROM users" in markdown_output

    def test_threat_categories_in_summary(self, sample_scan_result):
        """Test that threat categories are included in summary."""
        formatter = DomainScanResultFormatter()
        summary = formatter._format_summary(sample_scan_result)

        assert "threat_categories" in summary
        assert "security" in summary["threat_categories"]

    def test_empty_scanner_stats(self, empty_scan_result):
        """Test statistics formatting with no active scanners."""
        formatter = DomainScanResultFormatter()
        stats = formatter._format_statistics(empty_scan_result)

        assert "by_scanner" in stats
        # Should be empty since no threats means no active scanners
        assert stats["by_scanner"] == {}
