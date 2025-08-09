"""Tests for result_formatter.py with comprehensive coverage."""

import json
import tempfile
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.scanner.result_formatter import ScanResultFormatter
from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


@pytest.fixture
def mock_threat():
    """Create a mock threat for testing."""
    threat = ThreatMatch(
        rule_id="test-rule",
        rule_name="Test Rule",
        description="Test vulnerability",
        category=Category.INJECTION,
        severity=Severity.HIGH,
        file_path="/test/file.py",
        line_number=10,
        uuid="test-uuid-123",
        code_snippet="vulnerable_code()",
        confidence=0.9,
        source="semgrep",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        remediation="Fix the vulnerability",
        references=["https://example.com"],
        exploit_examples=["exploit code"],
    )
    return threat


@pytest.fixture
def mock_scan_result(mock_threat):
    """Create a mock scan result for testing."""
    result = Mock(spec=EnhancedScanResult)
    result.file_path = "/test/file.py"
    result.language = "python"
    result.all_threats = [mock_threat]
    result.scan_metadata = {
        "semgrep_scan_success": True,
        "llm_scan_success": True,
        "llm_validation_success": False,
    }
    result.stats = {"semgrep_threats": 1, "llm_threats": 0}
    result.validation_results = {}
    return result


@pytest.fixture
def formatter():
    """Create a formatter instance."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield ScanResultFormatter(working_directory=temp_dir)


class TestScanResultFormatter:
    """Test cases for ScanResultFormatter."""

    def test_init(self):
        """Test formatter initialization."""
        formatter = ScanResultFormatter("/test/dir")
        assert formatter.working_directory == "/test/dir"

        formatter_default = ScanResultFormatter()
        assert formatter_default.working_directory == "."

    def test_format_directory_results_json_basic(self, formatter, mock_scan_result):
        """Test basic directory results JSON formatting."""
        result_json = formatter.format_directory_results_json(
            [mock_scan_result], "/test/target"
        )

        data = json.loads(result_json)
        assert data["scan_metadata"]["target"] == "/test/target"
        assert data["scan_metadata"]["scan_type"] == "directory"
        assert data["scan_metadata"]["total_threats"] == 1
        assert len(data["threats"]) == 1
        assert data["threats"][0]["rule_id"] == "test-rule"

    def test_format_directory_results_json_exception_handling(self, formatter):
        """Test exception handling in directory results formatting."""
        # Create a mock with problematic attributes to trigger exception paths
        mock_result = Mock()

        # Test file_path exception handling (lines 60-61)
        mock_result.file_path = Mock()
        mock_result.file_path.__str__ = Mock(side_effect=Exception("str failed"))
        mock_result.language = "python"
        mock_result.all_threats = []
        mock_result.scan_metadata = {}
        mock_result.stats = {}
        mock_result.validation_results = {}

        result_json = formatter.format_directory_results_json([mock_result], "/test")
        data = json.loads(result_json)

        # Should default to empty string when str() fails
        assert data["files_scanned"][0]["file_path"] == ""

    def test_format_directory_results_json_language_exception(self, formatter):
        """Test language exception handling (lines 66-67)."""
        mock_result = Mock()
        mock_result.file_path = "/test/file.py"

        # Test language exception handling (lines 66-67)
        mock_result.language = Mock()
        mock_result.language.__str__ = Mock(side_effect=Exception("str failed"))
        mock_result.all_threats = []
        mock_result.scan_metadata = {}
        mock_result.stats = {}
        mock_result.validation_results = {}

        result_json = formatter.format_directory_results_json([mock_result], "/test")
        data = json.loads(result_json)

        # Should default to "generic" when str() fails
        assert data["files_scanned"][0]["language"] == "generic"

    def test_format_directory_results_json_threats_exception(self, formatter):
        """Test threats exception handling (lines 74-75)."""
        mock_result = Mock()
        mock_result.file_path = "/test/file.py"
        mock_result.language = "python"

        # Test all_threats exception handling (lines 74-75)
        mock_result.all_threats = Mock(side_effect=Exception("threats failed"))
        mock_result.scan_metadata = {}
        mock_result.stats = {}
        mock_result.validation_results = {}

        result_json = formatter.format_directory_results_json([mock_result], "/test")
        data = json.loads(result_json)

        # Should default to empty list when accessing threats fails
        assert data["files_scanned"][0]["threat_count"] == 0

    def test_format_directory_results_json_validation_result_filtering(
        self, formatter, mock_threat
    ):
        """Test ValidationResult class name filtering (line 109)."""
        mock_result = Mock(spec=EnhancedScanResult)
        mock_result.file_path = "/test/file.py"
        mock_result.language = "python"
        mock_result.all_threats = [mock_threat]
        mock_result.scan_metadata = {}
        mock_result.stats = {}

        # Create a mock validation result that's not a ValidationResult
        mock_validation = Mock()
        mock_validation.__class__.__name__ = "MockObject"  # Not "ValidationResult"
        mock_result.validation_results = {"test-uuid-123": mock_validation}

        result_json = formatter.format_directory_results_json([mock_result], "/test")
        data = json.loads(result_json)

        # Should treat non-ValidationResult as None
        threat_data = data["threats"][0]
        assert threat_data["validation"]["was_validated"] is False
        assert threat_data["validation"]["validation_status"] == "not_validated"

    def test_format_single_file_results_json(self, formatter, mock_scan_result):
        """Test single file results JSON formatting."""
        result_json = formatter.format_single_file_results_json(
            mock_scan_result, "/test/file.py"
        )

        data = json.loads(result_json)
        assert data["scan_metadata"]["target"] == "/test/file.py"
        assert data["scan_metadata"]["scan_type"] == "file"

    def test_format_diff_results_json(self, formatter, mock_scan_result):
        """Test diff results JSON formatting."""
        scan_results = {"/test/file1.py": [mock_scan_result]}
        diff_summary = {"source_branch": "main", "target_branch": "feature"}

        result_json = formatter.format_diff_results_json(
            scan_results, diff_summary, "main...feature"
        )

        data = json.loads(result_json)
        assert data["scan_metadata"]["scan_type"] == "diff"
        assert data["diff_summary"] == diff_summary
        assert data["scan_metadata"]["files_changed"] == 1

    def test_format_directory_results_markdown_with_threats(
        self, formatter, mock_scan_result, mock_threat
    ):
        """Test markdown formatting with threats."""
        # Clear code_snippet and add matched_content to test fallback behavior
        mock_threat.code_snippet = ""
        mock_threat.matched_content = "vulnerable_code_snippet"

        result_md = formatter.format_directory_results_markdown(
            [mock_scan_result], "/test/target"
        )

        assert "# Adversary Security Scan Report" in result_md
        assert "**Files Scanned:** 1" in result_md
        assert "**Total Threats Found:** 1" in result_md
        assert "HIGH" in result_md
        assert "vulnerable_code_snippet" in result_md  # Line 415-419 coverage

    def test_format_directory_results_markdown_with_remediation(
        self, formatter, mock_scan_result, mock_threat
    ):
        """Test markdown formatting with remediation (lines 423-425)."""
        # Ensure threat has remediation
        mock_threat.remediation = "Fix this vulnerability by using prepared statements"

        result_md = formatter.format_directory_results_markdown(
            [mock_scan_result], "/test/target"
        )

        assert "**Remediation:**" in result_md
        assert "Fix this vulnerability by using prepared statements" in result_md

    def test_format_directory_results_markdown_no_threats(self, formatter):
        """Test markdown formatting with no threats (lines 431-434)."""
        mock_result = Mock(spec=EnhancedScanResult)
        mock_result.file_path = "/test/file.py"
        mock_result.language = "python"
        mock_result.all_threats = []  # No threats

        result_md = formatter.format_directory_results_markdown(
            [mock_result], "/test/target"
        )

        assert "## ✅ No Security Threats Detected" in result_md
        assert (
            "The scan completed successfully with no security vulnerabilities found."
            in result_md
        )

    def test_format_directory_results_markdown_with_validation(self, formatter):
        """Test markdown formatting with validation summary (lines 439-447)."""
        # Create a scan result with validation enabled
        mock_result = Mock(spec=EnhancedScanResult)
        mock_result.file_path = "/test/file.py"
        mock_result.language = "python"
        mock_result.all_threats = []
        mock_result.scan_metadata = {"llm_validation_success": True}

        # Mock validation results
        mock_validation = Mock()
        mock_validation.is_legitimate = True
        mock_validation.confidence = 0.85
        mock_result.validation_results = {"test-uuid": mock_validation}

        result_md = formatter.format_directory_results_markdown(
            [mock_result], "/test/target"
        )

        assert "## Validation Summary" in result_md
        assert "**Findings Reviewed:**" in result_md
        assert "**False Positive Rate:**" in result_md
        assert "**Average Confidence:**" in result_md

    def test_format_single_file_results_markdown(self, formatter, mock_scan_result):
        """Test single file markdown formatting."""
        result_md = formatter.format_single_file_results_markdown(
            mock_scan_result, "/test/file.py"
        )

        assert "# Adversary Security Scan Report" in result_md
        assert "/test/file.py" in result_md

    def test_format_diff_results_markdown(self, formatter, mock_scan_result):
        """Test diff results markdown formatting."""
        scan_results = {"/test/file1.py": [mock_scan_result]}
        diff_summary = {"source_branch": "main", "target_branch": "feature"}

        result_md = formatter.format_diff_results_markdown(
            scan_results, diff_summary, "main...feature"
        )

        assert "### Git Diff Information" in result_md
        assert "**Source Branch:** `main`" in result_md
        assert "**Target Branch:** `feature`" in result_md

    def test_format_code_results_markdown(self, formatter, mock_scan_result):
        """Test code results markdown formatting."""
        result_md = formatter.format_code_results_markdown(
            mock_scan_result, "test-code"
        )

        assert "# Adversary Security Scan Report" in result_md
        assert "test-code" in result_md

    def test_aggregate_validation_stats_no_results(self, formatter):
        """Test validation stats aggregation with no results."""
        stats = formatter._aggregate_validation_stats([])

        assert stats["enabled"] is False
        assert stats["status"] == "no_results"
        assert stats["total_findings_reviewed"] == 0

    def test_aggregate_validation_stats_disabled(self, formatter):
        """Test validation stats aggregation when disabled (lines 550-553)."""
        # Create mock results with no validation
        mock_result = Mock()
        mock_result.scan_metadata = {"llm_validation_success": False}

        # Test exception handling in validation check (lines 552-553)
        mock_result_exception = Mock()
        mock_result_exception.scan_metadata = Mock(
            side_effect=Exception("metadata failed")
        )

        stats = formatter._aggregate_validation_stats(
            [mock_result, mock_result_exception]
        )

        assert stats["enabled"] is False
        assert stats["status"] == "disabled"

    def test_aggregate_validation_stats_unknown_reason(self, formatter):
        """Test validation stats with unknown reason (lines 565-566)."""
        # Create mock results with problematic scan_metadata access
        mock_result = Mock()
        mock_result.scan_metadata = Mock(side_effect=Exception("metadata failed"))

        stats = formatter._aggregate_validation_stats([mock_result])

        assert stats["enabled"] is False
        assert stats["reason"] == "unknown"

    def test_aggregate_validation_stats_enabled(self, formatter):
        """Test validation stats aggregation when enabled (lines 584-619)."""
        # Create mock results with validation enabled
        mock_result = Mock()
        mock_result.scan_metadata = {
            "llm_validation_success": True,
            "validation_errors": 2,
        }

        # Mock validation results
        mock_validation_legit = Mock()
        mock_validation_legit.is_legitimate = True
        mock_validation_legit.confidence = 0.9

        mock_validation_false = Mock()
        mock_validation_false.is_legitimate = False
        mock_validation_false.confidence = 0.3

        mock_result.validation_results = {
            "uuid1": mock_validation_legit,
            "uuid2": mock_validation_false,
        }

        stats = formatter._aggregate_validation_stats([mock_result])

        assert stats["enabled"] is True
        assert stats["total_findings_reviewed"] == 2
        assert stats["legitimate_findings"] == 1
        assert stats["false_positives_filtered"] == 1
        assert stats["false_positive_rate"] == 0.5
        assert stats["average_confidence"] == 0.6
        assert stats["validation_errors"] == 2
        assert stats["status"] == "completed"

    def test_aggregate_validation_stats_non_dict_validation_results(self, formatter):
        """Test validation stats with non-dict validation results."""
        mock_result = Mock()
        mock_result.scan_metadata = {"llm_validation_success": True}
        mock_result.validation_results = "not a dict"  # Non-dict validation results

        stats = formatter._aggregate_validation_stats([mock_result])

        assert stats["enabled"] is True
        assert stats["total_findings_reviewed"] == 0

    def test_get_semgrep_summary(self, formatter):
        """Test Semgrep summary generation."""
        # Create mock results with different states
        mock_result_success = Mock()
        mock_result_success.scan_metadata = {"semgrep_scan_success": True}
        mock_result_success.stats = {"semgrep_threats": 3}

        mock_result_failed = Mock()
        mock_result_failed.scan_metadata = {
            "semgrep_scan_success": False,
            "semgrep_scan_reason": "error",
        }
        mock_result_failed.stats = {"semgrep_threats": 0}

        mock_result_disabled = Mock()
        mock_result_disabled.scan_metadata = {
            "semgrep_scan_success": False,
            "semgrep_scan_reason": "disabled",
        }
        mock_result_disabled.stats = {"semgrep_threats": 0}

        summary = formatter._get_semgrep_summary(
            [mock_result_success, mock_result_failed, mock_result_disabled]
        )

        assert summary["files_processed"] == 1
        assert summary["files_failed"] == 1  # Only the "error" one, not "disabled"
        assert summary["total_threats"] == 3

    @patch("adversary_mcp_server.scanner.result_formatter.FalsePositiveManager")
    def test_false_positive_integration(
        self, mock_fp_manager, formatter, mock_scan_result
    ):
        """Test false positive manager integration."""
        # Mock false positive manager
        mock_fp_instance = Mock()
        mock_fp_instance.get_false_positive_details.return_value = {
            "reviewer": "test@example.com",
            "timestamp": "2023-01-01T00:00:00Z",
        }
        mock_fp_manager.return_value = mock_fp_instance

        result_json = formatter.format_directory_results_json(
            [mock_scan_result], "/test"
        )
        data = json.loads(result_json)

        # Should include false positive metadata
        threat_data = data["threats"][0]
        assert threat_data["is_false_positive"] is True
        assert threat_data["false_positive_metadata"]["reviewer"] == "test@example.com"

    def test_comprehensive_json_structure(
        self, formatter, mock_scan_result, mock_threat
    ):
        """Test complete JSON structure with all fields."""
        result_json = formatter.format_directory_results_json(
            [mock_scan_result], "/test"
        )
        data = json.loads(result_json)

        # Verify all main sections exist
        assert "scan_metadata" in data
        assert "validation_summary" in data
        assert "scanner_execution_summary" in data
        assert "statistics" in data
        assert "files_scanned" in data
        assert "threats" in data

        # Verify threat structure
        threat_data = data["threats"][0]
        expected_fields = [
            "uuid",
            "rule_id",
            "rule_name",
            "description",
            "category",
            "severity",
            "file_path",
            "line_number",
            "end_line_number",
            "code_snippet",
            "confidence",
            "source",
            "cwe_id",
            "owasp_category",
            "remediation",
            "references",
            "exploit_examples",
            "is_false_positive",
            "false_positive_metadata",
            "validation",
        ]
        for field in expected_fields:
            assert field in threat_data

    def test_markdown_severity_emojis(self, formatter):
        """Test markdown severity emoji assignment."""
        # Create threats with different severities
        threats = []
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]:
            threat = ThreatMatch(
                rule_id=f"rule-{severity}",
                rule_name=f"Rule {severity}",
                description="Test",
                category=Category.INJECTION,
                severity=severity,
                file_path="/test.py",
                line_number=1,
            )
            threats.append(threat)

        mock_result = Mock(spec=EnhancedScanResult)
        mock_result.file_path = "/test.py"
        mock_result.all_threats = threats

        result_md = formatter.format_directory_results_markdown([mock_result], "/test")

        # Check that severity emojis are included
        assert "🔴" in result_md  # Critical
        assert "🟠" in result_md  # High
        assert "🟡" in result_md  # Medium
        assert "🔵" in result_md  # Low

    def test_format_directory_results_json_hasattr_false(self, formatter):
        """Test when hasattr returns False for all_threats (lines 74-75)."""
        mock_result = Mock()
        mock_result.file_path = "/test/file.py"
        mock_result.language = "python"
        # Remove all_threats attribute entirely
        del mock_result.all_threats
        mock_result.scan_metadata = {}
        mock_result.stats = {}
        mock_result.validation_results = {}

        result_json = formatter.format_directory_results_json([mock_result], "/test")
        data = json.loads(result_json)

        # Should default to empty list when all_threats attribute doesn't exist
        assert data["files_scanned"][0]["threat_count"] == 0

    def test_format_directory_results_json_non_list_all_threats(self, formatter):
        """Test when all_threats is not a list (line 105)."""
        mock_result = Mock()
        mock_result.file_path = "/test/file.py"
        mock_result.language = "python"
        mock_result.all_threats = "not a list"  # Not a list
        mock_result.scan_metadata = {}
        mock_result.stats = {}
        mock_result.validation_results = {}

        result_json = formatter.format_directory_results_json([mock_result], "/test")
        data = json.loads(result_json)

        # Should default to empty list when all_threats is not a list
        assert data["files_scanned"][0]["threat_count"] == 0

    def test_aggregate_validation_stats_enabled_exception_handling(self, formatter):
        """Test exception handling in enabled validation stats (lines 552-553, 565-566, 610-611)."""
        mock_result = Mock()
        mock_result.scan_metadata = {
            "llm_validation_success": True,
            "validation_errors": 1,
        }

        # Mock validation results with proper attributes but no confidence to test None handling
        mock_validation = Mock()
        mock_validation.is_legitimate = True
        mock_validation.confidence = None  # This should be handled gracefully

        mock_result.validation_results = {"uuid1": mock_validation}

        # Create another result that will cause exception in validation_errors access
        mock_result2 = Mock()
        mock_result2.scan_metadata = {"llm_validation_success": True}
        # Make scan_metadata.get raise an exception for validation_errors
        mock_result2.scan_metadata = Mock(spec=dict)
        mock_result2.scan_metadata.get = Mock(
            side_effect=Exception("metadata get failed")
        )
        mock_result2.validation_results = {}

        stats = formatter._aggregate_validation_stats([mock_result, mock_result2])

        assert stats["enabled"] is True
        # Should handle exceptions gracefully
        assert stats["total_findings_reviewed"] == 1
        assert (
            stats["validation_errors"] == 1
        )  # Only first result contributes due to exception in second
