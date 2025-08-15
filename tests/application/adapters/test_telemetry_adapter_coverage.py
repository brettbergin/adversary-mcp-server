"""Comprehensive tests for telemetry_adapter.py to increase coverage."""

from datetime import datetime
from unittest.mock import Mock, patch

from adversary_mcp_server.application.adapters.telemetry_adapter import TelemetryAdapter
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class TestTelemetryAdapter:
    """Tests for TelemetryAdapter class."""

    def test_init_without_telemetry_service(self):
        """Test TelemetryAdapter initialization without telemetry service."""
        adapter = TelemetryAdapter()

        assert adapter._telemetry_service is None

    def test_init_with_telemetry_service(self):
        """Test TelemetryAdapter initialization with telemetry service."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        assert adapter._telemetry_service == mock_service

    def test_record_scan_completion_no_telemetry_service(self):
        """Test record_scan_completion when no telemetry service is available."""
        adapter = TelemetryAdapter()
        mock_scan_result = Mock()

        # Should not crash and return early
        adapter.record_scan_completion(mock_scan_result)

        # No assertion needed - just ensuring it doesn't crash

    def test_record_scan_completion_success(self):
        """Test successful scan completion recording."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        # Create mock threat
        mock_threat = Mock()
        mock_threat.rule_id = "test-rule"
        mock_threat.rule_name = "Test Rule"
        mock_threat.category = "injection"
        mock_threat.severity = SeverityLevel.HIGH
        mock_threat.file_path = "test.py"
        mock_threat.line_number = 10
        mock_threat.confidence = Mock()
        mock_threat.confidence.get_value.return_value = 0.8
        mock_threat.source_scanner = "semgrep"
        mock_threat.is_false_positive = False

        # Create mock scan result
        mock_scan_result = Mock()
        mock_scan_result.scan_id = "scan-123"
        mock_scan_result.threats = [mock_threat]
        mock_scan_result.metadata = {
            "scan_type": "file",
            "target_info": {"path": "/test/file.py", "language": "python"},
            "execution_stats": {"total_duration_ms": 1500},
        }

        with patch(
            "adversary_mcp_server.application.adapters.telemetry_adapter.safe_convert_to_input_model"
        ) as mock_convert:
            mock_metadata_input = Mock()
            mock_metadata_input.scan_type = "file"
            mock_metadata_input.target_info = {
                "path": "/test/file.py",
                "language": "python",
            }
            mock_metadata_input.execution_stats = {"total_duration_ms": 1500}
            mock_convert.return_value = mock_metadata_input

            adapter.record_scan_completion(mock_scan_result)

            # Verify scan event was recorded
            mock_service.record_scan_event.assert_called_once_with(
                scan_id="scan-123",
                scan_type="file",
                target_path="/test/file.py",
                language="python",
                threats_found=1,
                duration_ms=1500,
                success=True,
            )

            # Verify threat detection was recorded
            mock_service.record_threat_detection.assert_called_once()

    def test_record_scan_completion_no_scan_id(self):
        """Test scan completion recording with no scan ID."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        # Create mock scan result without scan_id
        mock_scan_result = Mock()
        mock_scan_result.scan_id = None
        mock_scan_result.threats = []
        mock_scan_result.metadata = {}

        with patch(
            "adversary_mcp_server.application.adapters.telemetry_adapter.safe_convert_to_input_model"
        ) as mock_convert:
            mock_metadata_input = Mock()
            mock_metadata_input.scan_type = "unknown"
            mock_metadata_input.target_info = {}
            mock_metadata_input.execution_stats = {}
            mock_convert.return_value = mock_metadata_input

            adapter.record_scan_completion(mock_scan_result)

            # Should use "unknown" as scan_id
            mock_service.record_scan_event.assert_called_once()
            args, kwargs = mock_service.record_scan_event.call_args
            assert kwargs["scan_id"] == "unknown"

    def test_record_scan_completion_no_metadata(self):
        """Test scan completion recording with no metadata."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        # Create mock scan result without metadata
        mock_scan_result = Mock()
        mock_scan_result.scan_id = "scan-123"
        mock_scan_result.threats = []
        mock_scan_result.metadata = None

        with (
            patch(
                "adversary_mcp_server.application.adapters.telemetry_adapter.safe_convert_to_input_model"
            ) as mock_convert,
            patch(
                "adversary_mcp_server.application.adapters.telemetry_adapter.MetadataInput"
            ) as mock_metadata_class,
        ):

            mock_metadata_input = Mock()
            mock_metadata_input.scan_type = "unknown"
            mock_metadata_input.target_info = {}
            mock_metadata_input.execution_stats = {}
            mock_metadata_class.return_value = mock_metadata_input

            adapter.record_scan_completion(mock_scan_result)

            # Should create default MetadataInput
            mock_metadata_class.assert_called_once()
            mock_service.record_scan_event.assert_called_once()

    def test_record_scan_completion_exception_handling(self):
        """Test exception handling in record_scan_completion."""
        mock_service = Mock()
        mock_service.record_scan_event.side_effect = Exception("Service error")

        adapter = TelemetryAdapter(telemetry_service=mock_service)

        mock_scan_result = Mock()
        mock_scan_result.scan_id = "scan-123"
        mock_scan_result.threats = []
        mock_scan_result.metadata = {}

        with patch(
            "adversary_mcp_server.application.adapters.telemetry_adapter.safe_convert_to_input_model"
        ):
            # Should not crash despite exception
            adapter.record_scan_completion(mock_scan_result)

    def test_record_threat_detection_no_telemetry_service(self):
        """Test record_threat_detection when no telemetry service is available."""
        adapter = TelemetryAdapter()
        mock_threat = Mock()

        # Should not crash and return early
        adapter.record_threat_detection(mock_threat, "scan-123")

    def test_record_threat_detection_no_threat(self):
        """Test record_threat_detection with None threat."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        # Should not crash and return early
        adapter.record_threat_detection(None, "scan-123")

        mock_service.record_threat_detection.assert_not_called()

    def test_record_threat_detection_success(self):
        """Test successful threat detection recording."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        # Create mock threat
        mock_threat = Mock()
        mock_threat.rule_id = "test-rule"
        mock_threat.rule_name = "Test Rule"
        mock_threat.category = "injection"
        mock_threat.severity = SeverityLevel.HIGH
        mock_threat.file_path = "test.py"
        mock_threat.line_number = 10
        mock_threat.confidence = Mock()
        mock_threat.confidence.get_value.return_value = 0.8
        mock_threat.source_scanner = "semgrep"
        mock_threat.is_false_positive = False

        adapter.record_threat_detection(mock_threat, "scan-123")

        mock_service.record_threat_detection.assert_called_once_with(
            scan_id="scan-123",
            rule_id="test-rule",
            rule_name="Test Rule",
            category="injection",
            severity="high",
            file_path="test.py",
            line_number=10,
            confidence=0.8,
            scanner="semgrep",
            is_false_positive=False,
        )

    def test_record_threat_detection_exception_handling(self):
        """Test exception handling in record_threat_detection."""
        mock_service = Mock()
        mock_service.record_threat_detection.side_effect = Exception("Service error")

        adapter = TelemetryAdapter(telemetry_service=mock_service)

        mock_threat = Mock()
        mock_threat.rule_id = "test-rule"
        mock_threat.rule_name = "Test Rule"
        mock_threat.category = "injection"
        mock_threat.severity = SeverityLevel.HIGH
        mock_threat.file_path = "test.py"
        mock_threat.line_number = 10
        mock_threat.confidence = Mock()
        mock_threat.confidence.get_value.return_value = 0.8
        mock_threat.source_scanner = "semgrep"
        mock_threat.is_false_positive = False

        # Should not crash despite exception
        adapter.record_threat_detection(mock_threat, "scan-123")

    def test_record_scan_performance_no_telemetry_service(self):
        """Test record_scan_performance when no telemetry service is available."""
        adapter = TelemetryAdapter()
        mock_scan_result = Mock()

        # Should not crash and return early
        adapter.record_scan_performance(mock_scan_result)

    def test_record_scan_performance_no_metadata(self):
        """Test record_scan_performance with no metadata."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        mock_scan_result = Mock()
        mock_scan_result.metadata = None

        # Should return early without calling service
        adapter.record_scan_performance(mock_scan_result)

        mock_service.record_performance_metrics.assert_not_called()

    def test_record_scan_performance_success(self):
        """Test successful scan performance recording."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        mock_scan_result = Mock()
        mock_scan_result.scan_id = "test-scan-123"
        mock_scan_result.threats = []
        mock_scan_result.metadata = {
            "execution_stats": {
                "total_duration_ms": 2500,
                "semgrep_duration_ms": 1000,
                "llm_duration_ms": 1500,
            },
            "target_info": {"size": 1024},
        }

        with patch(
            "adversary_mcp_server.application.adapters.telemetry_adapter.safe_convert_to_input_model"
        ) as mock_convert:
            mock_metadata_input = Mock()
            mock_metadata_input.execution_stats = {
                "total_duration_ms": 2500,
                "semgrep_duration_ms": 1000,
                "llm_duration_ms": 1500,
            }
            mock_metadata_input.target_info = {"size": 1024}
            mock_convert.return_value = mock_metadata_input

            adapter.record_scan_performance(mock_scan_result)

            mock_service.record_performance_metrics.assert_called_once_with(
                scan_id="test-scan-123",
                total_duration_ms=2500,
                component_timings={
                    "total_duration_ms": 2500,
                    "semgrep_duration_ms": 1000,
                    "llm_duration_ms": 1500,
                },
                file_size_bytes=1024,
                threat_count=0,
            )

    def test_record_scan_performance_exception_handling(self):
        """Test exception handling in record_scan_performance."""
        mock_service = Mock()
        mock_service.record_performance_metrics.side_effect = Exception("Service error")

        adapter = TelemetryAdapter(telemetry_service=mock_service)

        mock_scan_result = Mock()
        mock_scan_result.metadata = {"execution_stats": {}}

        with patch(
            "adversary_mcp_server.application.adapters.telemetry_adapter.safe_convert_to_input_model"
        ):
            # Should not crash despite exception
            adapter.record_scan_performance(mock_scan_result)

    def test_record_validation_results_no_telemetry_service(self):
        """Test record_validation_results when no telemetry service is available."""
        adapter = TelemetryAdapter()

        # Should not crash and return early
        adapter.record_validation_results([], [], "scan-123")

    def test_record_validation_results_empty_threats(self):
        """Test record_validation_results with empty threat lists."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        # Should return early without calling service
        adapter.record_validation_results([], [], "scan-123")

        mock_service.record_validation_event.assert_not_called()

    def test_record_validation_results_success(self):
        """Test successful validation results recording."""
        mock_service = Mock()
        adapter = TelemetryAdapter(telemetry_service=mock_service)

        # Create original threats
        original_threat1 = Mock()
        original_threat1.rule_id = "rule-1"
        original_threat1.confidence = Mock()
        original_threat1.confidence.get_value.return_value = 0.6
        original_threat1.severity = SeverityLevel.HIGH

        original_threat2 = Mock()
        original_threat2.rule_id = "rule-2"
        original_threat2.confidence = Mock()
        original_threat2.confidence.get_value.return_value = 0.7
        original_threat2.severity = SeverityLevel.MEDIUM

        # Create validated threats (one is filtered out as false positive)
        validated_threat = Mock()
        validated_threat.rule_id = "rule-1"
        validated_threat.confidence = Mock()
        validated_threat.confidence.get_value.return_value = 0.9  # Improved confidence
        validated_threat.severity = SeverityLevel.CRITICAL  # Adjusted severity

        adapter.record_validation_results(
            [original_threat1, original_threat2], [validated_threat], "scan-123"
        )

        mock_service.record_validation_event.assert_called_once_with(
            scan_id="scan-123",
            original_threat_count=2,
            validated_threat_count=1,
            false_positive_count=1,
            confidence_improvements=1,
            severity_adjustments=1,
        )

    def test_record_validation_results_exception_handling(self):
        """Test exception handling in record_validation_results."""
        mock_service = Mock()
        mock_service.record_validation_event.side_effect = Exception("Service error")

        adapter = TelemetryAdapter(telemetry_service=mock_service)

        mock_threat = Mock()
        mock_threat.rule_id = "test"
        mock_threat.confidence = Mock()
        mock_threat.confidence.get_value.return_value = 0.5
        mock_threat.severity = SeverityLevel.LOW

        # Should not crash despite exception
        adapter.record_validation_results([mock_threat], [mock_threat], "scan-123")


class TestDomainTelemetryAdapter:
    """Tests for DomainTelemetryAdapter class."""

    def test_extract_scan_metrics_basic(self):
        """Test basic scan metrics extraction."""
        from adversary_mcp_server.application.adapters.telemetry_adapter import (
            DomainTelemetryAdapter,
        )

        adapter = DomainTelemetryAdapter()

        # Create mock scan result
        mock_scan_result = Mock()
        mock_scan_result.scan_request = Mock()
        mock_scan_result.scan_request.context = Mock()
        mock_scan_result.scan_request.context.metadata = Mock()
        mock_scan_result.scan_request.context.metadata.scan_id = "scan-123"
        mock_scan_result.scan_request.context.metadata.scan_type = "file"
        mock_scan_result.scan_request.context.metadata.timestamp = datetime.now()
        mock_scan_result.scan_request.context.metadata.requester = "test-user"
        mock_scan_result.scan_request.context.metadata.timeout_seconds = 30
        mock_scan_result.scan_request.context.target_path = "test.py"
        mock_scan_result.scan_request.context.language = "python"
        mock_scan_result.scan_request.enable_semgrep = True
        mock_scan_result.scan_request.enable_llm = False
        mock_scan_result.scan_request.enable_validation = True
        mock_scan_result.scan_request.severity_threshold = SeverityLevel.MEDIUM

        mock_scan_result.get_statistics.return_value = {
            "total_threats": 3,
            "by_severity": {"high": 1, "medium": 2},
            "by_category": {"injection": 2, "xss": 1},
        }
        mock_scan_result.get_active_scanners.return_value = ["semgrep"]
        mock_scan_result.has_critical_threats.return_value = False
        mock_scan_result.filter_by_confidence.return_value = Mock(threats=[])
        mock_scan_result.threats = []
        mock_scan_result.scan_metadata = {"scan_duration_ms": 1500}

        with (
            patch.object(adapter, "_get_file_size", return_value=1024),
            patch.object(adapter, "_extract_scanner_metrics", return_value={}),
            patch.object(adapter, "_extract_validation_metrics", return_value=None),
        ):

            metrics = adapter.extract_scan_metrics(mock_scan_result)

            assert metrics["scan_id"] == "scan-123"
            assert metrics["scan_type"] == "file"
            assert metrics["requester"] == "test-user"
            assert metrics["total_threats"] == 3
            assert metrics["file_size_bytes"] == 1024

    def test_extract_threat_metrics_basic(self):
        """Test basic threat metrics extraction."""
        from adversary_mcp_server.application.adapters.telemetry_adapter import (
            DomainTelemetryAdapter,
        )

        adapter = DomainTelemetryAdapter()

        # Create mock threat
        mock_threat = Mock()
        mock_threat.rule_id = "test-rule"
        mock_threat.rule_name = "Test Rule"
        mock_threat.get_fingerprint.return_value = "fingerprint-123"
        mock_threat.severity = (
            SeverityLevel.HIGH
        )  # Use actual SeverityLevel instead of Mock
        mock_threat.category = "injection"
        mock_threat.confidence = Mock()
        mock_threat.confidence.get_decimal.return_value = 0.8
        mock_threat.confidence.get_quality_level.return_value = "high"
        mock_threat.file_path = "test.py"
        mock_threat.line_number = 10
        mock_threat.column_number = 5
        mock_threat.source_scanner = "semgrep"
        mock_threat.metadata = {}
        mock_threat.is_false_positive = False
        mock_threat.exploit_examples = []
        mock_threat.remediation_advice = "Fix this issue"
        mock_threat.code_snippet = "vulnerable code"

        with patch.object(
            adapter,
            "_extract_semgrep_threat_metrics",
            return_value={"semgrep_rule": "test"},
        ):
            metrics = adapter.extract_threat_metrics([mock_threat])

            assert len(metrics) == 1
            threat_metric = metrics[0]
            assert threat_metric["rule_id"] == "test-rule"
            assert threat_metric["severity"] == "high"
            assert threat_metric["confidence"] == 0.8
            assert threat_metric["source_scanner"] == "semgrep"

    def test_extract_performance_metrics_basic(self):
        """Test basic performance metrics extraction."""
        from adversary_mcp_server.application.adapters.telemetry_adapter import (
            DomainTelemetryAdapter,
        )

        adapter = DomainTelemetryAdapter()

        # Create mock scan result
        mock_scan_result = Mock()
        mock_scan_result.scan_metadata = {
            "scan_duration_ms": 2000,
            "semgrep_duration_ms": 800,
            "llm_duration_ms": 1200,
            "validation_duration_ms": 300,
        }
        mock_scan_result.scan_request = Mock()
        mock_scan_result.scan_request.enable_semgrep = True
        mock_scan_result.scan_request.enable_llm = True
        mock_scan_result.scan_request.enable_validation = True
        mock_scan_result.threats = []

        with (
            patch.object(adapter, "_calculate_throughput", return_value=1.5),
            patch.object(adapter, "_estimate_lines_scanned", return_value=100),
            patch.object(adapter, "_count_files_processed", return_value=1),
        ):

            metrics = adapter.extract_performance_metrics(mock_scan_result)

            assert metrics["total_scan_time_ms"] == 2000
            assert metrics["scanner_performance"]["semgrep"]["duration_ms"] == 800
            assert metrics["scanner_performance"]["llm"]["duration_ms"] == 1200
            assert metrics["validation_performance"]["duration_ms"] == 300
            assert metrics["throughput"]["threats_per_second"] == 1.5

    def test_extract_quality_metrics_no_threats(self):
        """Test quality metrics extraction with no threats."""
        from adversary_mcp_server.application.adapters.telemetry_adapter import (
            DomainTelemetryAdapter,
        )

        adapter = DomainTelemetryAdapter()

        # Create mock scan result with no threats
        mock_scan_result = Mock()
        mock_scan_result.threats = []

        metrics = adapter.extract_quality_metrics(mock_scan_result)

        assert metrics["security_score"] == 100.0
        assert metrics["quality_rating"] == "A"
        assert metrics["risk_level"] == "low"

    def test_extract_quality_metrics_with_threats(self):
        """Test quality metrics extraction with threats."""
        from adversary_mcp_server.application.adapters.telemetry_adapter import (
            DomainTelemetryAdapter,
        )

        adapter = DomainTelemetryAdapter()

        # Create mock threats
        critical_threat = Mock()
        critical_threat.confidence = Mock()
        critical_threat.confidence.get_decimal.return_value = 0.9
        critical_threat.confidence.is_very_low.return_value = False
        critical_threat.confidence.is_low.return_value = False
        critical_threat.confidence.is_medium.return_value = False
        critical_threat.confidence.is_high.return_value = True
        critical_threat.confidence.is_very_high.return_value = False
        critical_threat.confidence.is_actionable.return_value = True

        high_threat = Mock()
        high_threat.confidence = Mock()
        high_threat.confidence.get_decimal.return_value = 0.8
        high_threat.confidence.is_very_low.return_value = False
        high_threat.confidence.is_low.return_value = False
        high_threat.confidence.is_medium.return_value = False
        high_threat.confidence.is_high.return_value = True
        high_threat.confidence.is_very_high.return_value = False
        high_threat.confidence.is_actionable.return_value = True

        # Create mock scan result
        mock_scan_result = Mock()
        mock_scan_result.threats = [critical_threat, high_threat]
        mock_scan_result.get_threats_by_severity.side_effect = lambda severity: {
            "critical": [critical_threat] if severity == "critical" else [],
            "high": [high_threat] if severity == "high" else [],
            "medium": [],
            "low": [],
        }[severity]

        metrics = adapter.extract_quality_metrics(mock_scan_result)

        assert metrics["security_score"] == 60  # 100 - (1*25 + 1*15) = 60
        assert metrics["quality_rating"] == "D"
        assert metrics["risk_level"] == "critical"
        assert abs(metrics["average_confidence"] - 0.85) < 0.01  # (0.9 + 0.8) / 2
        assert metrics["actionable_threats"] == 2

    def test_private_helper_methods(self):
        """Test private helper methods."""
        from adversary_mcp_server.application.adapters.telemetry_adapter import (
            DomainTelemetryAdapter,
        )

        adapter = DomainTelemetryAdapter()

        # Test _get_category_breakdown
        mock_threat1 = Mock()
        mock_threat1.category = "injection"
        mock_threat2 = Mock()
        mock_threat2.category = "injection"
        mock_threat3 = Mock()
        mock_threat3.category = "xss"

        breakdown = adapter._get_category_breakdown(
            [mock_threat1, mock_threat2, mock_threat3]
        )
        assert breakdown["injection"] == 2
        assert breakdown["xss"] == 1

    def test_file_size_with_content(self):
        """Test _get_file_size with content."""
        from adversary_mcp_server.application.adapters.telemetry_adapter import (
            DomainTelemetryAdapter,
        )

        adapter = DomainTelemetryAdapter()

        mock_scan_result = Mock()
        mock_scan_result.scan_request = Mock()
        mock_scan_result.scan_request.context = Mock()
        mock_scan_result.scan_request.context.content = "test content"

        size = adapter._get_file_size(mock_scan_result)
        assert size == len(b"test content")

    def test_file_size_with_file_path(self):
        """Test _get_file_size with file path."""
        from adversary_mcp_server.application.adapters.telemetry_adapter import (
            DomainTelemetryAdapter,
        )

        adapter = DomainTelemetryAdapter()

        mock_scan_result = Mock()
        mock_scan_result.scan_request = Mock()
        mock_scan_result.scan_request.context = Mock()
        mock_scan_result.scan_request.context.content = None
        mock_scan_result.scan_request.context.target_path = Mock()
        mock_scan_result.scan_request.context.target_path.exists.return_value = True
        mock_scan_result.scan_request.context.target_path.is_file.return_value = True
        mock_scan_result.scan_request.context.target_path.get_size_bytes.return_value = (
            2048
        )

        size = adapter._get_file_size(mock_scan_result)
        assert size == 2048
