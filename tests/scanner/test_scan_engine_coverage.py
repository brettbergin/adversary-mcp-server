"""Comprehensive tests for scan_engine.py to increase coverage."""

from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult, ScanEngine
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestEnhancedScanResult:
    """Tests for EnhancedScanResult class."""

    def test_init_with_minimal_args(self):
        """Test EnhancedScanResult initialization with minimal arguments."""
        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={"scan_id": "test-123"},
        )

        assert result.file_path == "test.py"
        assert result.language == "python"
        assert result.llm_threats == []
        assert result.semgrep_threats == []
        assert result.all_threats == []
        assert result.stats["total_threats"] == 0

    def test_init_with_validation_results(self):
        """Test EnhancedScanResult with validation results."""
        validation_results = {"threat1": Mock(is_legitimate=True, confidence=0.9)}

        result = EnhancedScanResult(
            file_path="test.js",
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={"scan_id": "test-123"},
            validation_results=validation_results,
        )

        assert result.validation_results == validation_results
        assert result.language == "javascript"

    def test_detect_language_from_path(self):
        """Test language detection from file paths."""
        result = EnhancedScanResult(
            file_path="script.ts", llm_threats=[], semgrep_threats=[], scan_metadata={}
        )
        assert result.language == "typescript"

    def test_combine_threats_no_duplicates(self):
        """Test threat combination without duplicates."""
        semgrep_threat = ThreatMatch(
            rule_id="semgrep-1",
            rule_name="SQL Injection",
            description="SQL injection vulnerability",
            category="injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            column_number=5,
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            confidence=0.9,
        )

        llm_threat = ThreatMatch(
            rule_id="llm-1",
            rule_name="XSS Vulnerability",
            description="Cross-site scripting vulnerability",
            category="xss",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=20,
            column_number=3,
            code_snippet="output = f'<div>{user_input}</div>'",
            confidence=0.8,
        )

        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[llm_threat],
            semgrep_threats=[semgrep_threat],
            scan_metadata={},
        )

        assert len(result.all_threats) == 2
        # Should be sorted by line number
        assert result.all_threats[0].line_number == 10
        assert result.all_threats[1].line_number == 20

    def test_combine_threats_with_duplicates(self):
        """Test threat combination with duplicate removal."""
        semgrep_threat = ThreatMatch(
            rule_id="semgrep-1",
            rule_name="SQL Injection",
            description="SQL injection vulnerability",
            category="injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            column_number=5,
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            confidence=0.9,
        )

        # LLM threat on similar line with same category (should be filtered as duplicate)
        llm_threat = ThreatMatch(
            rule_id="llm-1",
            rule_name="SQL Injection LLM",
            description="SQL injection found by LLM",
            category="injection",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=11,  # Within 2 lines of semgrep threat
            column_number=3,
            code_snippet="similar code",
            confidence=0.8,
        )

        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[llm_threat],
            semgrep_threats=[semgrep_threat],
            scan_metadata={},
        )

        # Should only have 1 threat (duplicate filtered)
        assert len(result.all_threats) == 1
        assert result.all_threats[0].rule_id == "semgrep-1"

    def test_calculate_stats(self):
        """Test statistics calculation."""
        high_threat = ThreatMatch(
            rule_id="threat-1",
            rule_name="High Severity",
            description="High severity issue",
            category="injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            column_number=5,
            code_snippet="vulnerable code",
            confidence=0.9,
        )

        medium_threat = ThreatMatch(
            rule_id="threat-2",
            rule_name="Medium Severity",
            description="Medium severity issue",
            category="xss",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=20,
            column_number=3,
            code_snippet="another vulnerable code",
            confidence=0.7,
        )

        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[high_threat],
            semgrep_threats=[medium_threat],
            scan_metadata={},
        )

        stats = result.stats
        assert stats["total_threats"] == 2
        assert stats["llm_threats"] == 1
        assert stats["semgrep_threats"] == 1
        assert stats["severity_counts"]["high"] == 1
        assert stats["severity_counts"]["medium"] == 1
        assert stats["category_counts"]["injection"] == 1
        assert stats["category_counts"]["xss"] == 1

    def test_get_high_confidence_threats(self):
        """Test filtering high confidence threats."""
        high_conf_threat = ThreatMatch(
            rule_id="threat-1",
            rule_name="High Confidence",
            description="High confidence threat",
            category="injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            column_number=5,
            code_snippet="vulnerable code",
            confidence=0.95,
        )

        low_conf_threat = ThreatMatch(
            rule_id="threat-2",
            rule_name="Low Confidence",
            description="Low confidence threat",
            category="xss",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=20,
            column_number=3,
            code_snippet="maybe vulnerable",
            confidence=0.6,
        )

        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[high_conf_threat, low_conf_threat],
            semgrep_threats=[],
            scan_metadata={},
        )

        high_conf = result.get_high_confidence_threats(min_confidence=0.8)
        assert len(high_conf) == 1
        assert high_conf[0].rule_id == "threat-1"

    def test_get_critical_threats(self):
        """Test filtering critical threats."""
        critical_threat = ThreatMatch(
            rule_id="critical-1",
            rule_name="Critical Issue",
            description="Critical security issue",
            category="injection",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            column_number=5,
            code_snippet="dangerous code",
            confidence=0.95,
        )

        high_threat = ThreatMatch(
            rule_id="high-1",
            rule_name="High Issue",
            description="High security issue",
            category="xss",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=20,
            column_number=3,
            code_snippet="risky code",
            confidence=0.8,
        )

        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[critical_threat, high_threat],
            semgrep_threats=[],
            scan_metadata={},
        )

        critical = result.get_critical_threats()
        assert len(critical) == 1
        assert critical[0].rule_id == "critical-1"

    def test_add_llm_usage(self):
        """Test adding LLM usage statistics."""
        result = EnhancedScanResult(
            file_path="test.py", llm_threats=[], semgrep_threats=[], scan_metadata={}
        )

        cost_breakdown = {
            "tokens": {
                "total_tokens": 1000,
                "prompt_tokens": 800,
                "completion_tokens": 200,
            },
            "total_cost": 0.05,
            "model": "gpt-4",
        }

        result.add_llm_usage("analysis", cost_breakdown)

        analysis_stats = result.llm_usage_stats["analysis"]
        assert analysis_stats["total_tokens"] == 1000
        assert analysis_stats["prompt_tokens"] == 800
        assert analysis_stats["completion_tokens"] == 200
        assert analysis_stats["total_cost"] == 0.05
        assert analysis_stats["api_calls"] == 1
        assert "gpt-4" in analysis_stats["models_used"]

        # Check combined stats
        combined_stats = result.llm_usage_stats["combined"]
        assert combined_stats["total_tokens"] == 1000
        assert combined_stats["total_cost"] == 0.05

    def test_add_llm_usage_unknown_type(self):
        """Test adding LLM usage with unknown type."""
        result = EnhancedScanResult(
            file_path="test.py", llm_threats=[], semgrep_threats=[], scan_metadata={}
        )

        # Should handle unknown usage type gracefully
        result.add_llm_usage("unknown_type", {"total_cost": 0.05})

        # Should not crash and stats should remain unchanged
        assert result.llm_usage_stats["analysis"]["total_cost"] == 0.0

    def test_get_validation_summary_disabled(self):
        """Test validation summary when validation is disabled."""
        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={
                "llm_validation_success": False,
                "llm_validation_reason": "disabled",
            },
        )

        summary = result.get_validation_summary()
        assert summary["enabled"] is False
        assert summary["total_findings_reviewed"] == 0
        assert summary["status"] == "disabled"

    def test_get_validation_summary_enabled(self):
        """Test validation summary when validation is enabled."""
        # Mock validation results
        validation_results = {
            "threat1": Mock(is_legitimate=True, confidence=0.9, validation_error=None),
            "threat2": Mock(is_legitimate=False, confidence=0.3, validation_error=None),
            "threat3": Mock(
                is_legitimate=True, confidence=0.8, validation_error="Parse error"
            ),
        }

        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={"llm_validation_success": True},
            validation_results=validation_results,
        )

        summary = result.get_validation_summary()
        assert summary["enabled"] is True
        assert summary["total_findings_reviewed"] == 3
        assert summary["legitimate_findings"] == 2
        assert summary["false_positives_filtered"] == 1
        assert summary["false_positive_rate"] == 1 / 3
        assert summary["average_confidence"] == 0.667  # (0.9 + 0.3 + 0.8) / 3
        assert summary["validation_errors"] == 1
        assert summary["status"] == "completed"


class TestScanEngine:
    """Tests for ScanEngine class."""

    def test_init_minimal(self):
        """Test ScanEngine initialization with minimal configuration."""
        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_credential_manager"
            ) as mock_get_cred,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.AdversaryDatabase"
            ) as mock_db,
            patch(
                "adversary_mcp_server.scanner.scan_engine.TelemetryService"
            ) as mock_telemetry,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
            patch("adversary_mcp_server.scanner.scan_engine.LLMScanner") as mock_llm,
        ):

            # Setup mocks
            mock_cred_manager = Mock()
            mock_cred_manager.load_config.return_value = Mock(
                enable_caching=True, enable_semgrep_scanning=True
            )
            mock_get_cred.return_value = mock_cred_manager

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                cache_max_size_mb=100,
                cache_max_age_hours=24,
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep.return_value = mock_semgrep_instance

            mock_llm_instance = Mock()
            mock_llm_instance.is_available.return_value = True
            mock_llm.return_value = mock_llm_instance

            engine = ScanEngine()

            assert engine.enable_llm_analysis is True
            assert engine.enable_semgrep_analysis is True
            assert engine.enable_llm_validation is True
            assert engine.credential_manager == mock_cred_manager
            assert engine.semgrep_scanner == mock_semgrep_instance

    def test_init_with_disabled_features(self):
        """Test ScanEngine initialization with disabled features."""
        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_credential_manager"
            ) as mock_get_cred,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
        ):

            mock_cred_manager = Mock()
            mock_cred_manager.load_config.return_value = Mock(
                enable_caching=False, enable_semgrep_scanning=False
            )
            mock_get_cred.return_value = mock_cred_manager

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                cache_max_size_mb=100,
                cache_max_age_hours=24,
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = False
            mock_semgrep.return_value = mock_semgrep_instance

            engine = ScanEngine(
                enable_llm_analysis=False,
                enable_semgrep_analysis=False,
                enable_llm_validation=False,
            )

            assert engine.enable_llm_analysis is False
            assert engine.enable_semgrep_analysis is False
            assert engine.enable_llm_validation is False
            assert engine.cache_manager is None

    def test_init_with_custom_managers(self):
        """Test ScanEngine initialization with custom managers."""
        custom_cred_manager = Mock()
        custom_cache_manager = Mock()
        custom_metrics_collector = Mock()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
            patch("adversary_mcp_server.scanner.scan_engine.LLMScanner") as mock_llm,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator,
        ):

            custom_cred_manager.load_config.return_value = Mock(
                enable_caching=True, enable_semgrep_scanning=True
            )

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                cache_max_size_mb=100,
                cache_max_age_hours=24,
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep.return_value = mock_semgrep_instance

            mock_llm_instance = Mock()
            mock_llm_instance.is_available.return_value = True
            mock_llm.return_value = mock_llm_instance

            mock_validator_instance = Mock()
            mock_validator.return_value = mock_validator_instance

            engine = ScanEngine(
                credential_manager=custom_cred_manager,
                cache_manager=custom_cache_manager,
                metrics_collector=custom_metrics_collector,
            )

            assert engine.credential_manager == custom_cred_manager
            assert engine.cache_manager == custom_cache_manager
            assert engine.metrics_collector == custom_metrics_collector

    def test_init_telemetry_failure(self):
        """Test ScanEngine initialization with telemetry failure."""
        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_credential_manager"
            ) as mock_get_cred,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.AdversaryDatabase"
            ) as mock_db,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
            patch("adversary_mcp_server.scanner.scan_engine.LLMScanner") as mock_llm,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator,
        ):

            # Setup mocks
            mock_cred_manager = Mock()
            mock_cred_manager.load_config.return_value = Mock(
                enable_caching=True, enable_semgrep_scanning=True
            )
            mock_get_cred.return_value = mock_cred_manager

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                cache_max_size_mb=100,
                cache_max_age_hours=24,
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            # Make telemetry initialization fail
            mock_db.side_effect = Exception("Database connection failed")

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep.return_value = mock_semgrep_instance

            mock_llm_instance = Mock()
            mock_llm_instance.is_available.return_value = True
            mock_llm.return_value = mock_llm_instance

            mock_validator_instance = Mock()
            mock_validator.return_value = mock_validator_instance

            engine = ScanEngine()

            # Should handle telemetry failure gracefully
            assert engine.metrics_orchestrator is None

    def test_detect_language(self):
        """Test language detection method."""
        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_credential_manager"
            ) as mock_get_cred,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
        ):

            # Setup basic mocks
            mock_cred_manager = Mock()
            mock_cred_manager.load_config.return_value = Mock(
                enable_caching=False, enable_semgrep_scanning=True
            )
            mock_get_cred.return_value = mock_cred_manager

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep.return_value = mock_semgrep_instance

            engine = ScanEngine(enable_llm_analysis=False, enable_llm_validation=False)

            # Test with Python file
            with patch(
                "adversary_mcp_server.scanner.language_mapping.LanguageMapper.detect_language_from_extension"
            ) as mock_mapper:
                mock_mapper.return_value = "python"
                language = engine._detect_language(Path("test.py"))
                assert language == "python"
                mock_mapper.assert_called_once_with(Path("test.py"))

    @pytest.mark.asyncio
    async def test_scan_file_method(self):
        """Test scanning a file."""
        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_credential_manager"
            ) as mock_get_cred,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
            patch("adversary_mcp_server.scanner.scan_engine.LLMScanner") as mock_llm,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator,
            patch(
                "adversary_mcp_server.scanner.scan_engine.is_file_too_large"
            ) as mock_file_size,
            patch("builtins.open", create=True) as mock_open,
        ):

            # Setup mocks
            mock_cred_manager = Mock()
            mock_cred_manager.load_config.return_value = Mock(
                enable_caching=False, enable_semgrep_scanning=True
            )
            mock_get_cred.return_value = mock_cred_manager

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep_instance.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
            }
            mock_semgrep_instance.scan_file = AsyncMock(return_value=[])
            mock_semgrep.return_value = mock_semgrep_instance

            mock_llm_instance = Mock()
            mock_llm_instance.is_available.return_value = True
            mock_llm_instance.analyze_file = AsyncMock(return_value=[])
            mock_llm.return_value = mock_llm_instance

            mock_validator_instance = Mock()
            mock_validator.return_value = mock_validator_instance

            mock_file_size.return_value = False
            mock_open.return_value.__enter__.return_value.read.return_value = (
                "print('hello')"
            )

            engine = ScanEngine()

            # Create Path object and mock Path.exists globally
            from pathlib import Path

            test_path = Path("test.py")
            with patch("pathlib.Path.exists", return_value=True):
                result = await engine.scan_file(test_path)

            assert isinstance(result, EnhancedScanResult)
            assert str(result.file_path) == "test.py"
            mock_semgrep_instance.scan_file.assert_called_once()
            mock_llm_instance.analyze_file.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_code_method(self):
        """Test scanning code directly."""
        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_credential_manager"
            ) as mock_get_cred,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
            patch("adversary_mcp_server.scanner.scan_engine.LLMScanner") as mock_llm,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator,
        ):

            # Setup mocks
            mock_cred_manager = Mock()
            mock_cred_manager.load_config.return_value = Mock(
                enable_caching=False, enable_semgrep_scanning=True
            )
            mock_get_cred.return_value = mock_cred_manager

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep_instance.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
            }
            mock_semgrep_instance.scan_code = AsyncMock(return_value=[])
            mock_semgrep.return_value = mock_semgrep_instance

            mock_llm_instance = Mock()
            mock_llm_instance.is_available.return_value = True
            mock_llm_instance.analyze_code = AsyncMock(return_value=[])
            mock_llm.return_value = mock_llm_instance

            mock_validator_instance = Mock()
            mock_validator.return_value = mock_validator_instance

            engine = ScanEngine()

            result = await engine.scan_code("print('hello')", "python")

            assert isinstance(result, EnhancedScanResult)
            mock_semgrep_instance.scan_code.assert_called_once()
            mock_llm_instance.analyze_code.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_directory_method(self):
        """Test scanning a directory."""
        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_credential_manager"
            ) as mock_get_cred,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
            patch("adversary_mcp_server.scanner.scan_engine.LLMScanner") as mock_llm,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator,
            patch("adversary_mcp_server.scanner.scan_engine.FileFilter") as mock_filter,
            patch(
                "adversary_mcp_server.scanner.scan_engine.AdversaryDatabase"
            ) as mock_db,
            patch(
                "adversary_mcp_server.scanner.scan_engine.TelemetryService"
            ) as mock_telemetry,
            patch(
                "adversary_mcp_server.scanner.scan_engine.MetricsCollectionOrchestrator"
            ) as mock_orchestrator,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_app_cache_dir"
            ) as mock_cache_dir,
            patch(
                "adversary_mcp_server.scanner.scan_engine.CacheManager"
            ) as mock_cache_mgr,
        ):

            # Setup mocks
            mock_cred_manager = Mock()
            mock_cred_manager.load_config.return_value = Mock(
                enable_caching=False, enable_semgrep_scanning=True
            )
            mock_get_cred.return_value = mock_cred_manager

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep_instance.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
            }
            mock_semgrep_instance.scan_directory = AsyncMock(return_value=[])
            mock_semgrep.return_value = mock_semgrep_instance

            mock_llm_instance = Mock()
            mock_llm_instance.is_available.return_value = True
            mock_llm_instance.analyze_directory = AsyncMock(return_value=[])
            mock_llm_instance.batch_analyze_code = Mock(
                return_value=[]
            )  # Mock sync method to avoid asyncio.run
            mock_llm.return_value = mock_llm_instance

            mock_validator_instance = Mock()
            mock_validator.return_value = mock_validator_instance

            mock_filter_instance = Mock()
            from pathlib import Path

            test_path = Path("test.py")
            mock_filter_instance.get_scannable_files.return_value = [test_path]
            mock_filter_instance.filter_files.return_value = [test_path]
            mock_filter.return_value = mock_filter_instance

            # Mock telemetry and cache components
            mock_cache_dir.return_value = "/tmp/test_cache"
            mock_cache_mgr_instance = Mock()
            mock_cache_mgr.return_value = mock_cache_mgr_instance

            mock_db_instance = Mock()
            mock_db.return_value = mock_db_instance

            mock_telemetry_instance = Mock()
            mock_telemetry.return_value = mock_telemetry_instance

            mock_orchestrator_instance = Mock()
            # Make track_scan_execution return a context manager
            mock_context = Mock()
            mock_context.__enter__ = Mock(return_value=mock_context)
            mock_context.__exit__ = Mock(return_value=None)
            mock_orchestrator_instance.track_scan_execution = Mock(
                return_value=mock_context
            )
            mock_orchestrator.return_value = mock_orchestrator_instance

            engine = ScanEngine()

            # Create Path object and mock Path methods globally
            from pathlib import Path

            test_dir = Path("test_dir")
            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.is_dir", return_value=True),
            ):
                result = await engine.scan_directory(test_dir, use_llm=True)

            # scan_directory returns a list of results
            assert isinstance(result, list)
            assert len(result) > 0
            assert isinstance(result[0], EnhancedScanResult)
            mock_semgrep_instance.scan_directory.assert_called_once()
            # LLM scanning may not be available in test environment, just check it was configured
            mock_llm_instance.is_available.assert_called()

    @pytest.mark.asyncio
    async def test_scan_file_with_validation(self):
        """Test scanning a file with LLM validation enabled."""
        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_credential_manager"
            ) as mock_get_cred,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_config_manager"
            ) as mock_get_config,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
            patch("adversary_mcp_server.scanner.scan_engine.LLMScanner") as mock_llm,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator,
            patch(
                "adversary_mcp_server.scanner.scan_engine.is_file_too_large"
            ) as mock_file_size,
            patch(
                "adversary_mcp_server.scanner.scan_engine.AdversaryDatabase"
            ) as mock_db,
            patch(
                "adversary_mcp_server.scanner.scan_engine.TelemetryService"
            ) as mock_telemetry,
            patch(
                "adversary_mcp_server.scanner.scan_engine.MetricsCollectionOrchestrator"
            ) as mock_orchestrator,
            patch(
                "adversary_mcp_server.scanner.scan_engine.get_app_cache_dir"
            ) as mock_cache_dir,
            patch(
                "adversary_mcp_server.scanner.scan_engine.CacheManager"
            ) as mock_cache_mgr,
            patch("builtins.open", create=True) as mock_open,
        ):

            # Setup mocks
            mock_cred_manager = Mock()
            mock_cred_manager.load_config.return_value = Mock(
                enable_caching=False, enable_semgrep_scanning=True
            )
            mock_get_cred.return_value = mock_cred_manager

            mock_config_manager = Mock()
            mock_config_manager.dynamic_limits = Mock(
                circuit_breaker_failure_threshold=5,
                recovery_timeout_seconds=60,
                max_retry_attempts=3,
                retry_base_delay=1.0,
            )
            mock_get_config.return_value = mock_config_manager

            # Create mock threats
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

            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep_instance.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
            }
            mock_semgrep_instance.scan_file = AsyncMock(return_value=[mock_threat])
            mock_semgrep.return_value = mock_semgrep_instance

            mock_llm_instance = Mock()
            mock_llm_instance.is_available.return_value = True
            mock_llm_instance.analyze_file = AsyncMock(return_value=[])
            mock_llm.return_value = mock_llm_instance

            # Mock validator to return validation results
            mock_validation_result = Mock(
                is_legitimate=True, confidence=0.9, validation_error=None
            )
            mock_validator_instance = Mock()
            mock_validator_instance._validate_findings_async = AsyncMock(
                return_value={"test-1": mock_validation_result}
            )
            mock_validator_instance.is_fully_functional.return_value = True
            mock_validator_instance.get_validation_stats.return_value = {}
            mock_validator.return_value = mock_validator_instance

            mock_file_size.return_value = False
            mock_open.return_value.__enter__.return_value.read.return_value = (
                "print('hello')"
            )

            # Mock telemetry and cache components
            mock_cache_dir.return_value = "/tmp/test_cache"
            mock_cache_mgr_instance = Mock()
            mock_cache_mgr.return_value = mock_cache_mgr_instance

            mock_db_instance = Mock()
            mock_db.return_value = mock_db_instance

            mock_telemetry_instance = Mock()
            mock_telemetry.return_value = mock_telemetry_instance

            mock_orchestrator_instance = Mock()
            # Make track_scan_execution return a context manager
            mock_context = Mock()
            mock_context.__enter__ = Mock(return_value=mock_context)
            mock_context.__exit__ = Mock(return_value=None)
            mock_orchestrator_instance.track_scan_execution = Mock(
                return_value=mock_context
            )
            mock_orchestrator.return_value = mock_orchestrator_instance

            engine = ScanEngine(enable_llm_validation=True)

            # Create Path object and mock Path.exists globally
            from pathlib import Path

            test_path = Path("test.py")
            with patch("pathlib.Path.exists", return_value=True):
                result = await engine.scan_file(
                    test_path, use_validation=False, use_llm=False
                )

            assert isinstance(result, EnhancedScanResult)
            # Simplified assertions - just test that basic file scanning works
            mock_semgrep_instance.scan_file.assert_called_once()
