"""Comprehensive tests for result_formatter.py to increase coverage."""

import json
from unittest.mock import Mock, patch

from adversary_mcp_server.scanner.result_formatter import ScanResultFormatter
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestScanResultFormatter:
    """Tests for ScanResultFormatter class."""

    def test_init_minimal(self):
        """Test ScanResultFormatter initialization with minimal configuration."""
        with (
            patch(
                "adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"
            ) as mock_db,
            patch(
                "adversary_mcp_server.scanner.result_formatter.TelemetryService"
            ) as mock_telemetry,
        ):

            mock_db_instance = Mock()
            mock_db.return_value = mock_db_instance

            mock_telemetry_instance = Mock()
            mock_telemetry.return_value = mock_telemetry_instance

            formatter = ScanResultFormatter()

            assert formatter.working_directory == "."
            assert formatter.telemetry_service == mock_telemetry_instance

    def test_init_with_custom_directory(self):
        """Test ScanResultFormatter initialization with custom directory."""
        with (
            patch(
                "adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"
            ) as mock_db,
            patch(
                "adversary_mcp_server.scanner.result_formatter.TelemetryService"
            ) as mock_telemetry,
        ):

            mock_db_instance = Mock()
            mock_db.return_value = mock_db_instance

            mock_telemetry_instance = Mock()
            mock_telemetry.return_value = mock_telemetry_instance

            formatter = ScanResultFormatter(working_directory="/custom/path")

            assert formatter.working_directory == "/custom/path"
            assert formatter.telemetry_service == mock_telemetry_instance

    def test_init_with_custom_telemetry(self):
        """Test ScanResultFormatter initialization with custom telemetry service."""
        custom_telemetry = Mock()

        formatter = ScanResultFormatter(telemetry_service=custom_telemetry)

        assert formatter.telemetry_service == custom_telemetry

    def test_create_telemetry_service_success(self):
        """Test successful telemetry service creation."""
        with (
            patch(
                "adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"
            ) as mock_db,
            patch(
                "adversary_mcp_server.scanner.result_formatter.TelemetryService"
            ) as mock_telemetry,
        ):

            mock_db_instance = Mock()
            mock_db.return_value = mock_db_instance

            mock_telemetry_instance = Mock()
            mock_telemetry.return_value = mock_telemetry_instance

            formatter = ScanResultFormatter()
            service = formatter._create_telemetry_service()

            assert service == mock_telemetry_instance
            # Database may be called multiple times during initialization
            assert mock_db.call_count >= 1
            mock_telemetry.assert_called_with(mock_db_instance)

    def test_create_telemetry_service_failure(self):
        """Test telemetry service creation failure."""
        with patch(
            "adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"
        ) as mock_db:

            mock_db.side_effect = Exception("Database connection failed")

            formatter = ScanResultFormatter()
            service = formatter._create_telemetry_service()

            assert service is None

    def test_format_directory_results_json_empty(self):
        """Test formatting empty directory results."""
        with patch("adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"):
            formatter = ScanResultFormatter()

            result = formatter.format_directory_results_json([], "/test/dir")
            result_data = json.loads(result)

            assert result_data["scan_metadata"]["target"] == "/test/dir"
            assert result_data["scan_metadata"]["scan_type"] == "directory"
            assert result_data["threats"] == []
            assert result_data["files_scanned"] == []
            assert result_data["statistics"]["total_threats"] == 0

    def test_format_directory_results_json_with_threats(self):
        """Test formatting directory results with threats."""
        with (
            patch("adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"),
            patch(
                "adversary_mcp_server.scanner.result_formatter.FalsePositiveManager"
            ) as mock_fp,
        ):

            # Mock false positive manager
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = {
                "is_false_positive": False,
                "marked_by": None,
                "marked_at": None,
                "reason": None,
            }
            mock_fp.return_value = mock_fp_instance

            # Create mock threat
            mock_threat = ThreatMatch(
                rule_id="test-1",
                rule_name="Test Threat",
                description="Test threat description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                column_number=5,
                code_snippet="vulnerable code",
                confidence=0.8,
            )
            mock_threat.uuid = "test-uuid-123"

            # Create mock scan result
            mock_scan_result = Mock()
            mock_scan_result.file_path = "test.py"
            mock_scan_result.language = "python"
            mock_scan_result.all_threats = [mock_threat]
            mock_scan_result.validation_results = {}
            mock_scan_result.scan_metadata = {
                "scan_duration": 2.5,
                "scan_id": "scan-123",
            }
            mock_scan_result.stats = {
                "total_threats": 1,
                "severity_counts": {"high": 1, "medium": 0, "low": 0, "critical": 0},
            }

            formatter = ScanResultFormatter()

            result = formatter.format_directory_results_json(
                [mock_scan_result], "/test/dir"
            )
            result_data = json.loads(result)

            assert result_data["scan_metadata"]["target"] == "/test/dir"
            assert result_data["scan_metadata"]["scan_type"] == "directory"
            assert len(result_data["threats"]) == 1
            assert result_data["threats"][0]["rule_id"] == "test-1"
            assert result_data["statistics"]["total_threats"] == 1

    def test_format_directory_results_json_with_validation(self):
        """Test formatting directory results with LLM validation."""
        with (
            patch("adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"),
            patch(
                "adversary_mcp_server.scanner.result_formatter.FalsePositiveManager"
            ) as mock_fp,
        ):

            # Mock false positive manager
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = {
                "is_false_positive": False,
                "marked_by": None,
                "marked_at": None,
                "reason": None,
            }
            mock_fp.return_value = mock_fp_instance

            # Create mock threat
            mock_threat = ThreatMatch(
                rule_id="test-1",
                rule_name="Test Threat",
                description="Test threat description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                column_number=5,
                code_snippet="vulnerable code",
                confidence=0.8,
            )
            mock_threat.uuid = "test-uuid-123"

            # Create mock validation result
            mock_validation_result = Mock()
            mock_validation_result.__class__.__name__ = "ValidationResult"
            mock_validation_result.confidence = 0.9
            mock_validation_result.reasoning = "High confidence vulnerability"
            mock_validation_result.is_legitimate = True
            mock_validation_result.exploitation_vector = "SQL injection attack"

            # Create mock scan result with validation
            mock_scan_result = Mock()
            mock_scan_result.file_path = "test.py"
            mock_scan_result.language = "python"
            mock_scan_result.all_threats = [mock_threat]
            mock_scan_result.validation_results = {
                "test-uuid-123": mock_validation_result
            }
            mock_scan_result.scan_metadata = {
                "scan_duration": 2.5,
                "scan_id": "scan-123",
            }
            mock_scan_result.stats = {
                "total_threats": 1,
                "severity_counts": {"high": 1, "medium": 0, "low": 0, "critical": 0},
            }

            formatter = ScanResultFormatter()

            result = formatter.format_directory_results_json(
                [mock_scan_result], "/test/dir"
            )
            result_data = json.loads(result)

            assert result_data["threats"][0]["validation"]["was_validated"] is True
            assert (
                result_data["threats"][0]["validation"]["validation_confidence"] == 0.9
            )
            assert (
                result_data["threats"][0]["validation"]["validation_status"]
                == "legitimate"
            )

    def test_format_directory_results_json_with_false_positive(self):
        """Test formatting directory results with false positive."""
        with (
            patch("adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"),
            patch(
                "adversary_mcp_server.scanner.result_formatter.FalsePositiveManager"
            ) as mock_fp,
        ):

            # Mock false positive manager with false positive result
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = {
                "is_false_positive": True,
                "marked_by": "test-user",
                "marked_at": "2025-01-01T00:00:00Z",
                "reason": "Not a real vulnerability",
            }
            mock_fp.return_value = mock_fp_instance

            # Create mock threat
            mock_threat = ThreatMatch(
                rule_id="test-1",
                rule_name="Test Threat",
                description="Test threat description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                column_number=5,
                code_snippet="vulnerable code",
                confidence=0.8,
            )
            mock_threat.uuid = "test-uuid-123"

            # Create mock scan result
            mock_scan_result = Mock()
            mock_scan_result.file_path = "test.py"
            mock_scan_result.language = "python"
            mock_scan_result.all_threats = [mock_threat]
            mock_scan_result.validation_results = {}
            mock_scan_result.scan_metadata = {
                "scan_duration": 2.5,
                "scan_id": "scan-123",
            }
            mock_scan_result.stats = {
                "total_threats": 1,
                "severity_counts": {"high": 1, "medium": 0, "low": 0, "critical": 0},
            }

            formatter = ScanResultFormatter()

            result = formatter.format_directory_results_json(
                [mock_scan_result], "/test/dir"
            )
            result_data = json.loads(result)

            assert (
                result_data["threats"][0]["false_positive_metadata"][
                    "is_false_positive"
                ]
                is True
            )
            assert (
                result_data["threats"][0]["false_positive_metadata"]["marked_by"]
                == "test-user"
            )
            assert (
                result_data["threats"][0]["false_positive_metadata"]["reason"]
                == "Not a real vulnerability"
            )

    def test_format_directory_results_json_with_directory_metadata(self):
        """Test formatting directory results with directory scan metadata."""
        with (
            patch("adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"),
            patch(
                "adversary_mcp_server.scanner.result_formatter.FalsePositiveManager"
            ) as mock_fp,
        ):

            # Mock false positive manager
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = {
                "is_false_positive": False,
                "marked_by": None,
                "marked_at": None,
                "reason": None,
            }
            mock_fp.return_value = mock_fp_instance

            # Create mock threat
            mock_threat = ThreatMatch(
                rule_id="test-1",
                rule_name="Test Threat",
                description="Test threat description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                column_number=5,
                code_snippet="vulnerable code",
                confidence=0.8,
            )
            mock_threat.uuid = "test-uuid-123"

            # Create mock scan result with directory metadata
            mock_scan_result = Mock()
            mock_scan_result.file_path = "/test/dir"
            mock_scan_result.language = "mixed"
            mock_scan_result.all_threats = [mock_threat]
            mock_scan_result.validation_results = {}
            mock_scan_result.scan_metadata = {
                "directory_scan": True,
                "directory_files_info": [
                    {
                        "file_path": "test.py",
                        "language": "python",
                        "threat_count": 1,
                        "issues_identified": True,
                    },
                    {
                        "file_path": "clean.js",
                        "language": "javascript",
                        "threat_count": 0,
                        "issues_identified": False,
                    },
                ],
                "scan_duration": 5.2,
                "scan_id": "scan-456",
            }
            mock_scan_result.stats = {
                "total_threats": 1,
                "severity_counts": {"high": 1, "medium": 0, "low": 0, "critical": 0},
            }

            formatter = ScanResultFormatter()

            result = formatter.format_directory_results_json(
                [mock_scan_result], "/test/dir"
            )
            result_data = json.loads(result)

            assert len(result_data["files_scanned"]) == 2
            assert result_data["files_scanned"][0]["file_path"] == "test.py"
            assert result_data["files_scanned"][0]["issues_identified"] is True
            assert result_data["files_scanned"][1]["file_path"] == "clean.js"
            assert result_data["files_scanned"][1]["issues_identified"] is False

    def test_format_directory_results_json_error_handling(self):
        """Test error handling in directory results formatting."""
        with (
            patch("adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"),
            patch(
                "adversary_mcp_server.scanner.result_formatter.FalsePositiveManager"
            ) as mock_fp,
        ):

            # Mock false positive manager
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = {
                "is_false_positive": False,
                "marked_by": None,
                "marked_at": None,
                "reason": None,
            }
            mock_fp.return_value = mock_fp_instance

            # Create problematic mock scan result (missing attributes)
            mock_scan_result = Mock()
            # Missing file_path attribute
            del mock_scan_result.file_path
            mock_scan_result.language = 123  # Invalid type
            mock_scan_result.all_threats = "not a list"  # Invalid type
            mock_scan_result.validation_results = {}
            mock_scan_result.scan_metadata = {}
            mock_scan_result.stats = {}

            formatter = ScanResultFormatter()

            # Should not crash and return valid JSON
            result = formatter.format_directory_results_json(
                [mock_scan_result], "/test/dir"
            )
            result_data = json.loads(result)

            assert result_data["scan_metadata"]["target"] == "/test/dir"
            assert isinstance(result_data["threats"], list)
            assert isinstance(result_data["files_scanned"], list)

    def test_format_directory_results_json_mixed_scan_types(self):
        """Test formatting with mixed scan result types."""
        with (
            patch("adversary_mcp_server.scanner.result_formatter.AdversaryDatabase"),
            patch(
                "adversary_mcp_server.scanner.result_formatter.FalsePositiveManager"
            ) as mock_fp,
        ):

            # Mock false positive manager
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = {
                "is_false_positive": False,
                "marked_by": None,
                "marked_at": None,
                "reason": None,
            }
            mock_fp.return_value = mock_fp_instance

            # Create mixed scan results
            scan_results = []

            # Individual file scan result
            mock_threat1 = ThreatMatch(
                rule_id="file-threat",
                rule_name="File Threat",
                description="File threat description",
                category=Category.DISCLOSURE,
                severity=Severity.MEDIUM,
                file_path="individual.py",
                line_number=5,
                column_number=1,
                code_snippet="sensitive data",
                confidence=0.7,
            )
            mock_threat1.uuid = "file-uuid"

            file_scan_result = Mock()
            file_scan_result.file_path = "individual.py"
            file_scan_result.language = "python"
            file_scan_result.all_threats = [mock_threat1]
            file_scan_result.validation_results = {}
            file_scan_result.scan_metadata = {"scan_type": "file"}
            file_scan_result.stats = {"total_threats": 1}

            # Directory scan result
            mock_threat2 = ThreatMatch(
                rule_id="dir-threat",
                rule_name="Directory Threat",
                description="Directory threat description",
                category=Category.XSS,
                severity=Severity.CRITICAL,
                file_path="subdir/script.js",
                line_number=15,
                column_number=10,
                code_snippet="innerHTML = userInput",
                confidence=0.9,
            )
            mock_threat2.uuid = "dir-uuid"

            dir_scan_result = Mock()
            dir_scan_result.file_path = "/test/dir"
            dir_scan_result.language = "mixed"
            dir_scan_result.all_threats = [mock_threat2]
            dir_scan_result.validation_results = {}
            dir_scan_result.scan_metadata = {
                "directory_scan": True,
                "directory_files_info": [
                    {
                        "file_path": "subdir/script.js",
                        "language": "javascript",
                        "threat_count": 1,
                        "issues_identified": True,
                    }
                ],
            }
            dir_scan_result.stats = {"total_threats": 1}

            scan_results = [file_scan_result, dir_scan_result]

            formatter = ScanResultFormatter()

            result = formatter.format_directory_results_json(
                scan_results, "/test/dir", "mixed"
            )
            result_data = json.loads(result)

            assert result_data["scan_metadata"]["scan_type"] == "mixed"
            assert len(result_data["threats"]) == 2
            assert (
                len(result_data["files_scanned"]) == 2
            )  # One from individual scan, one from directory info
