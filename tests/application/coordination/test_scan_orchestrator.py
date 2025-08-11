"""Tests for ScanOrchestrator."""

from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.application.coordination.cache_coordinator import (
    CacheCoordinator,
)
from adversary_mcp_server.application.coordination.scan_orchestrator import (
    ScanOrchestrator,
)
from adversary_mcp_server.application.coordination.validation_coordinator import (
    ValidationCoordinator,
)
from adversary_mcp_server.domain.aggregation.threat_aggregator import ThreatAggregator
from adversary_mcp_server.infrastructure.builders.result_builder import ResultBuilder
from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
from adversary_mcp_server.scanner.types import Severity, ThreatMatch


@pytest.fixture
def mock_semgrep_scanner():
    """Create a mock Semgrep scanner."""
    scanner = Mock()
    scanner.scan_file = AsyncMock(return_value=[])
    scanner.scan_code = AsyncMock(return_value=[])
    return scanner


@pytest.fixture
def mock_llm_scanner():
    """Create a mock LLM scanner."""
    scanner = Mock()
    scanner.analyze_file = AsyncMock(return_value=[])
    scanner.analyze_code = AsyncMock(return_value=[])
    return scanner


@pytest.fixture
def mock_validator():
    """Create a mock validator."""
    validator = Mock()
    validator.validate_findings = Mock(return_value={})
    return validator


@pytest.fixture
def mock_cache_manager():
    """Create a mock cache manager."""
    cache_manager = Mock()
    hasher = Mock()
    hasher.hash_content.return_value = "content_hash_123"
    hasher.hash_metadata.return_value = "metadata_hash_456"
    cache_manager.get_hasher.return_value = hasher
    cache_manager.get.return_value = None
    cache_manager.put.return_value = None
    return cache_manager


@pytest.fixture
def scan_orchestrator(
    mock_semgrep_scanner, mock_llm_scanner, mock_validator, mock_cache_manager
):
    """Create a ScanOrchestrator instance."""
    return ScanOrchestrator(
        semgrep_scanner=mock_semgrep_scanner,
        llm_scanner=mock_llm_scanner,
        validator=mock_validator,
        cache_manager=mock_cache_manager,
    )


@pytest.fixture
def sample_threats():
    """Create sample threats for testing."""
    return [
        ThreatMatch(
            rule_id="test-1",
            rule_name="Test Threat 1",
            description="First test threat",
            category="injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
        ),
        ThreatMatch(
            rule_id="test-2",
            rule_name="Test Threat 2",
            description="Second test threat",
            category="xss",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=20,
        ),
    ]


class TestScanOrchestrator:
    """Test ScanOrchestrator functionality."""

    def test_init_with_all_dependencies(
        self, mock_semgrep_scanner, mock_llm_scanner, mock_validator, mock_cache_manager
    ):
        """Test initialization with all dependencies."""
        orchestrator = ScanOrchestrator(
            semgrep_scanner=mock_semgrep_scanner,
            llm_scanner=mock_llm_scanner,
            validator=mock_validator,
            cache_manager=mock_cache_manager,
        )

        assert orchestrator.semgrep_scanner == mock_semgrep_scanner
        assert orchestrator.llm_scanner == mock_llm_scanner
        assert orchestrator.validator == mock_validator
        assert orchestrator.cache_manager == mock_cache_manager
        assert orchestrator.threat_aggregator is not None
        assert orchestrator.result_builder is not None
        assert orchestrator.validation_coordinator is not None
        assert orchestrator.cache_coordinator is not None

    def test_init_minimal_dependencies(self, mock_semgrep_scanner):
        """Test initialization with minimal dependencies."""
        orchestrator = ScanOrchestrator(
            semgrep_scanner=mock_semgrep_scanner,
        )

        assert orchestrator.semgrep_scanner == mock_semgrep_scanner
        assert orchestrator.llm_scanner is None
        assert orchestrator.validator is None
        assert orchestrator.cache_manager is None
        assert orchestrator.threat_aggregator is not None
        assert orchestrator.result_builder is not None
        assert orchestrator.validation_coordinator is not None
        assert orchestrator.cache_coordinator is not None

    @pytest.mark.asyncio
    async def test_orchestrate_code_scan_basic(
        self, scan_orchestrator, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test basic code scan orchestration."""
        # Setup mock responses with proper ThreatMatch objects
        semgrep_threats = [
            ThreatMatch(
                rule_id="semgrep-rule-1",
                rule_name="Semgrep Test Rule",
                description="Semgrep test threat",
                category="injection",
                severity=Severity.HIGH,
                file_path="<code_snippet>",
                line_number=5,
            )
        ]
        llm_threats = [
            ThreatMatch(
                rule_id="llm-rule-1",
                rule_name="LLM Test Rule",
                description="LLM test threat",
                category="xss",
                severity=Severity.MEDIUM,
                file_path="<code_snippet>",
                line_number=10,
            )
        ]
        mock_semgrep_scanner.scan_code.return_value = semgrep_threats
        mock_llm_scanner.analyze_code.return_value = llm_threats

        # Mock the cache coordinator to avoid cache hits
        scan_orchestrator.cache_coordinator.create_cache_key_for_code = Mock(
            return_value=None
        )
        scan_orchestrator.cache_coordinator.get_cached_code_result = Mock(
            return_value=None
        )
        scan_orchestrator.cache_coordinator.cache_code_result = Mock()

        # Mock time.time() to avoid Mock arithmetic issues
        with patch(
            "src.adversary_mcp_server.application.coordination.scan_orchestrator.time.time"
        ) as mock_time:
            # Provide enough values for all time.time() calls including logging
            mock_time.side_effect = [1000.0] + [1000.1] * 20 + [1002.5]

            result = await scan_orchestrator.orchestrate_code_scan(
                code="test code",
                language="python",
            )

        assert isinstance(result, EnhancedScanResult)
        assert result.file_path == "<code_snippet>"
        mock_semgrep_scanner.scan_code.assert_called_once_with("test code", "python")
        # Check that analyze_code was called with code, file_path, and language
        assert mock_llm_scanner.analyze_code.called
        call_args = mock_llm_scanner.analyze_code.call_args
        assert call_args[0][0] == "test code"  # source code
        assert call_args[0][1].endswith(".py")  # file path should have .py extension
        assert call_args[0][2] == "python"  # language

    @pytest.mark.asyncio
    async def test_orchestrate_code_scan_cache_hit(self, scan_orchestrator):
        """Test code scan with cache hit."""
        # Mock cache coordinator to return cached result
        cached_result = EnhancedScanResult(
            file_path="<code_snippet>",
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={"cache_hit": True},
        )
        scan_orchestrator.cache_coordinator.get_cached_code_result = Mock(
            return_value=cached_result
        )

        result = await scan_orchestrator.orchestrate_code_scan(
            code="test code",
            language="python",
        )

        assert result == cached_result
        assert result.scan_metadata["cache_hit"] is True

    @pytest.mark.asyncio
    async def test_orchestrate_code_scan_no_llm(self, mock_semgrep_scanner):
        """Test code scan without LLM scanner."""
        orchestrator = ScanOrchestrator(
            semgrep_scanner=mock_semgrep_scanner,
            llm_scanner=None,
        )

        mock_semgrep_scanner.scan_code.return_value = []

        result = await orchestrator.orchestrate_code_scan(
            code="test code",
            language="python",
            use_llm=True,  # Requested but not available
        )

        assert isinstance(result, EnhancedScanResult)
        mock_semgrep_scanner.scan_code.assert_called_once()

    @pytest.mark.asyncio
    async def test_orchestrate_code_scan_with_severity_filtering(
        self, scan_orchestrator, mock_semgrep_scanner, sample_threats
    ):
        """Test code scan with severity filtering."""
        mock_semgrep_scanner.scan_code.return_value = sample_threats

        result = await scan_orchestrator.orchestrate_code_scan(
            code="test code",
            language="python",
            use_llm=False,
            severity_threshold=Severity.HIGH,
        )

        assert isinstance(result, EnhancedScanResult)
        # Should only include HIGH and CRITICAL severity threats
        high_severity_threats = [
            t
            for t in sample_threats
            if t.severity in [Severity.HIGH, Severity.CRITICAL]
        ]
        assert len(result.semgrep_threats) == len(high_severity_threats)

    @pytest.mark.asyncio
    async def test_orchestrate_file_scan_basic(
        self, scan_orchestrator, mock_semgrep_scanner, mock_llm_scanner, tmp_path
    ):
        """Test basic file scan orchestration."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello world')")

        # Setup mock responses with proper ThreatMatch objects
        semgrep_threats = [
            ThreatMatch(
                rule_id="semgrep-file-rule-1",
                rule_name="Semgrep File Test Rule",
                description="Semgrep file test threat",
                category="injection",
                severity=Severity.HIGH,
                file_path=str(test_file),
                line_number=5,
            )
        ]
        llm_threats = [
            ThreatMatch(
                rule_id="llm-file-rule-1",
                rule_name="LLM File Test Rule",
                description="LLM file test threat",
                category="xss",
                severity=Severity.MEDIUM,
                file_path=str(test_file),
                line_number=10,
            )
        ]
        mock_semgrep_scanner.scan_file.return_value = semgrep_threats
        mock_llm_scanner.analyze_file.return_value = llm_threats

        # Mock the cache coordinator to avoid cache hits
        scan_orchestrator.cache_coordinator.create_content_hash = Mock(
            return_value="hash123"
        )
        scan_orchestrator.cache_coordinator.get_cached_scan_result = AsyncMock(
            return_value=None
        )
        scan_orchestrator.cache_coordinator.cache_scan_result = AsyncMock()

        # Mock time.time() to avoid Mock arithmetic issues
        with patch(
            "src.adversary_mcp_server.application.coordination.scan_orchestrator.time.time"
        ) as mock_time:
            # Provide enough values for all time.time() calls including logging
            mock_time.side_effect = [2000.0] + [2000.1] * 20 + [2003.0]

            result = await scan_orchestrator.orchestrate_file_scan(test_file)

        assert isinstance(result, EnhancedScanResult)
        assert result.file_path == str(test_file)
        mock_semgrep_scanner.scan_file.assert_called_once_with(test_file, "python")
        mock_llm_scanner.analyze_file.assert_called_once()

    @pytest.mark.asyncio
    async def test_orchestrate_file_scan_cache_hit(self, scan_orchestrator, tmp_path):
        """Test file scan with cache hit."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello world')")

        # Mock cache coordinator to return cached result
        cached_result = EnhancedScanResult(
            file_path=str(test_file),
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={"cache_hit": True},
        )
        scan_orchestrator.cache_coordinator.get_cached_scan_result = AsyncMock(
            return_value=cached_result
        )

        result = await scan_orchestrator.orchestrate_file_scan(test_file)

        assert result == cached_result
        assert result.scan_metadata["cache_hit"] is True

    @pytest.mark.asyncio
    async def test_orchestrate_file_scan_file_read_error(self, scan_orchestrator):
        """Test file scan with file read error."""
        non_existent_file = Path("/non/existent/file.py")

        with pytest.raises(FileNotFoundError):
            await scan_orchestrator.orchestrate_file_scan(non_existent_file)

    @pytest.mark.asyncio
    async def test_execute_parallel_scans_both_engines(
        self, scan_orchestrator, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test parallel execution of both scan engines."""
        semgrep_threats = [
            ThreatMatch(
                rule_id="test-semgrep",
                rule_name="Test Semgrep",
                description="Test semgrep threat",
                category="injection",
                severity=Severity.HIGH,
                file_path="<code_snippet>",
                line_number=5,
            )
        ]
        llm_threats = [
            ThreatMatch(
                rule_id="test-llm",
                rule_name="Test LLM",
                description="Test LLM threat",
                category="xss",
                severity=Severity.MEDIUM,
                file_path="<code_snippet>",
                line_number=10,
            )
        ]
        mock_semgrep_scanner.scan_code.return_value = semgrep_threats
        mock_llm_scanner.analyze_code.return_value = llm_threats

        semgrep_results, llm_results = await scan_orchestrator._execute_parallel_scans(
            code="test code",
            language="python",
            use_llm=True,
            use_semgrep=True,
        )

        assert semgrep_results == semgrep_threats
        assert llm_results == llm_threats

    @pytest.mark.asyncio
    async def test_execute_parallel_scans_semgrep_only(
        self, scan_orchestrator, mock_semgrep_scanner
    ):
        """Test parallel execution with only Semgrep."""
        semgrep_threats = [
            ThreatMatch(
                rule_id="test-semgrep-only",
                rule_name="Test Semgrep Only",
                description="Test semgrep only threat",
                category="injection",
                severity=Severity.HIGH,
                file_path="<code_snippet>",
                line_number=5,
            )
        ]
        mock_semgrep_scanner.scan_code.return_value = semgrep_threats

        semgrep_results, llm_results = await scan_orchestrator._execute_parallel_scans(
            code="test code",
            language="python",
            use_llm=False,
            use_semgrep=True,
        )

        assert semgrep_results == semgrep_threats
        assert llm_results == []

    @pytest.mark.asyncio
    async def test_execute_parallel_scans_with_exception(
        self, scan_orchestrator, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test parallel scans when one engine raises an exception."""
        semgrep_threats = [
            ThreatMatch(
                rule_id="test-semgrep-exception",
                rule_name="Test Semgrep Exception",
                description="Test semgrep threat with exception",
                category="injection",
                severity=Severity.HIGH,
                file_path="<code_snippet>",
                line_number=5,
            )
        ]
        mock_semgrep_scanner.scan_code.return_value = semgrep_threats
        mock_llm_scanner.analyze_code.side_effect = Exception("LLM scan failed")

        semgrep_results, llm_results = await scan_orchestrator._execute_parallel_scans(
            code="test code",
            language="python",
            use_llm=True,
            use_semgrep=True,
        )

        assert semgrep_results == semgrep_threats
        assert llm_results == []  # LLM results should be empty due to exception

    def test_filter_by_severity(self, scan_orchestrator, sample_threats):
        """Test severity filtering."""
        # Test HIGH threshold (should include HIGH and CRITICAL)
        high_filtered = scan_orchestrator._filter_by_severity(
            sample_threats, Severity.HIGH
        )
        assert len(high_filtered) == 1  # Only the HIGH severity threat
        assert high_filtered[0].severity == Severity.HIGH

        # Test MEDIUM threshold (should include MEDIUM, HIGH, and CRITICAL)
        medium_filtered = scan_orchestrator._filter_by_severity(
            sample_threats, Severity.MEDIUM
        )
        assert len(medium_filtered) == 2  # Both MEDIUM and HIGH threats

        # Test CRITICAL threshold (should include only CRITICAL)
        critical_filtered = scan_orchestrator._filter_by_severity(
            sample_threats, Severity.CRITICAL
        )
        assert len(critical_filtered) == 0  # No CRITICAL threats in sample

    def test_detect_language_from_file(self, scan_orchestrator):
        """Test language detection from file extension."""
        # Test Python file
        assert scan_orchestrator._detect_language_from_file(Path("test.py")) == "python"

        # Test JavaScript file
        assert (
            scan_orchestrator._detect_language_from_file(Path("test.js"))
            == "javascript"
        )

        # Test unknown file type
        assert (
            scan_orchestrator._detect_language_from_file(Path("test.unknown")) is None
        )

        # Test case insensitivity
        assert scan_orchestrator._detect_language_from_file(Path("TEST.PY")) == "python"

    @pytest.mark.asyncio
    async def test_run_semgrep_file_scan(self, scan_orchestrator, mock_semgrep_scanner):
        """Test Semgrep file scan wrapper."""
        expected_threats = [
            ThreatMatch(
                rule_id="test-file-scan",
                rule_name="Test File Scan",
                description="Test file scan threat",
                category="injection",
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=5,
            )
        ]
        mock_semgrep_scanner.scan_file.return_value = expected_threats

        result = await scan_orchestrator._run_semgrep_file_scan(
            Path("test.py"), "python"
        )

        assert result == expected_threats
        mock_semgrep_scanner.scan_file.assert_called_once_with(
            Path("test.py"), "python"
        )

    @pytest.mark.asyncio
    async def test_run_llm_code_scan(self, scan_orchestrator, mock_llm_scanner):
        """Test LLM code scan wrapper."""
        expected_threats = [
            ThreatMatch(
                rule_id="test-llm-code-scan",
                rule_name="Test LLM Code Scan",
                description="Test LLM code scan threat",
                category="xss",
                severity=Severity.MEDIUM,
                file_path="<code_snippet>",
                line_number=10,
            )
        ]
        mock_llm_scanner.analyze_code.return_value = expected_threats

        result = await scan_orchestrator._run_llm_code_scan("test code", "python")

        assert result == expected_threats
        # Check that analyze_code was called with correct parameters (code, file_path, language)
        assert mock_llm_scanner.analyze_code.called
        call_args = mock_llm_scanner.analyze_code.call_args
        assert call_args[0][0] == "test code"  # source code
        assert call_args[0][1].endswith(".py")  # file path should have .py extension
        assert call_args[0][2] == "python"  # language

    @pytest.mark.asyncio
    async def test_validation_integration(
        self, scan_orchestrator, mock_validator, sample_threats
    ):
        """Test validation integration in scan workflow."""
        # Setup mocks
        scan_orchestrator.semgrep_scanner.scan_code.return_value = sample_threats
        scan_orchestrator.llm_scanner.analyze_code.return_value = []

        # Mock validation coordinator
        scan_orchestrator.validation_coordinator.should_validate = Mock(
            return_value=True
        )
        scan_orchestrator.validation_coordinator.validate_findings = Mock(
            return_value={"test": "validation"}
        )
        scan_orchestrator.validation_coordinator.filter_false_positives = Mock(
            side_effect=lambda threats, _: threats
        )

        result = await scan_orchestrator.orchestrate_code_scan(
            code="test code",
            language="python",
            use_validation=True,
        )

        assert isinstance(result, EnhancedScanResult)
        scan_orchestrator.validation_coordinator.validate_findings.assert_called_once()
        assert (
            scan_orchestrator.validation_coordinator.filter_false_positives.call_count
            == 2
        )  # Called for both threat types

    @pytest.mark.asyncio
    async def test_validation_exception_handling(
        self, scan_orchestrator, sample_threats
    ):
        """Test validation exception handling."""
        # Setup mocks
        scan_orchestrator.semgrep_scanner.scan_code.return_value = sample_threats
        scan_orchestrator.llm_scanner.analyze_code.return_value = []

        # Mock validation coordinator to raise exception
        scan_orchestrator.validation_coordinator.should_validate = Mock(
            return_value=True
        )
        scan_orchestrator.validation_coordinator.validate_findings = Mock(
            side_effect=Exception("Validation failed")
        )

        # Should not raise exception, should continue with scan
        result = await scan_orchestrator.orchestrate_code_scan(
            code="test code",
            language="python",
            use_validation=True,
        )

        assert isinstance(result, EnhancedScanResult)
        assert len(result.semgrep_threats) == len(sample_threats)


class TestScanOrchestratorEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_orchestrate_code_scan_empty_code(self, scan_orchestrator):
        """Test code scan with empty code."""
        result = await scan_orchestrator.orchestrate_code_scan(
            code="",
            language="python",
        )

        assert isinstance(result, EnhancedScanResult)
        assert result.file_path == "<code_snippet>"

    @pytest.mark.asyncio
    async def test_orchestrate_code_scan_no_language(self, scan_orchestrator):
        """Test code scan without specified language."""
        result = await scan_orchestrator.orchestrate_code_scan(
            code="test code",
            language=None,
        )

        assert isinstance(result, EnhancedScanResult)
        assert result.scan_metadata["language"] == "unknown"

    def test_filter_by_severity_unknown_severity(self, scan_orchestrator):
        """Test severity filtering with unknown severity levels."""
        # Create threat with unknown severity
        threat_with_unknown_severity = Mock()
        threat_with_unknown_severity.severity = "unknown"

        filtered = scan_orchestrator._filter_by_severity(
            [threat_with_unknown_severity], Severity.MEDIUM
        )

        # Unknown severities are treated as having value 1 (low),
        # so they should be filtered out when threshold is MEDIUM (value 2)
        assert len(filtered) == 0

    @pytest.mark.asyncio
    async def test_execute_parallel_scans_no_tasks(self, scan_orchestrator):
        """Test parallel scans when no tasks are created."""
        semgrep_results, llm_results = await scan_orchestrator._execute_parallel_scans(
            code="test code",
            language="python",
            use_llm=False,
            use_semgrep=False,
        )

        assert semgrep_results == []
        assert llm_results == []


class TestScanOrchestratorIntegration:
    """Integration tests for ScanOrchestrator with real component interactions."""

    @pytest.fixture
    def real_threat_aggregator(self):
        """Create a real ThreatAggregator instance."""
        return ThreatAggregator()

    @pytest.fixture
    def real_result_builder(self):
        """Create a real ResultBuilder instance."""
        return ResultBuilder()

    @pytest.fixture
    def real_cache_coordinator(self):
        """Create a real CacheCoordinator instance (no cache manager)."""
        return CacheCoordinator(cache_manager=None)

    @pytest.fixture
    def real_validation_coordinator(self):
        """Create a real ValidationCoordinator instance (no validator)."""
        return ValidationCoordinator(validator=None)

    @pytest.fixture
    def integration_orchestrator(
        self,
        mock_semgrep_scanner,
        mock_llm_scanner,
        real_threat_aggregator,
        real_result_builder,
        real_cache_coordinator,
        real_validation_coordinator,
    ):
        """Create ScanOrchestrator with real components and mock scanners."""
        return ScanOrchestrator(
            semgrep_scanner=mock_semgrep_scanner,
            llm_scanner=mock_llm_scanner,
            validator=None,
            cache_manager=None,
            metrics_collector=None,
            threat_aggregator=real_threat_aggregator,
            result_builder=real_result_builder,
            validation_coordinator=real_validation_coordinator,
            cache_coordinator=real_cache_coordinator,
        )

    def test_threat_aggregator_initialization(self, integration_orchestrator):
        """Test that ThreatAggregator is properly initialized."""
        assert isinstance(integration_orchestrator.threat_aggregator, ThreatAggregator)
        assert integration_orchestrator.threat_aggregator is not None

    def test_result_builder_initialization(self, integration_orchestrator):
        """Test that ResultBuilder is properly initialized."""
        assert isinstance(integration_orchestrator.result_builder, ResultBuilder)
        assert integration_orchestrator.result_builder is not None

    def test_cache_coordinator_initialization(self, integration_orchestrator):
        """Test that CacheCoordinator is properly initialized."""
        assert isinstance(integration_orchestrator.cache_coordinator, CacheCoordinator)
        assert integration_orchestrator.cache_coordinator is not None

    def test_validation_coordinator_initialization(self, integration_orchestrator):
        """Test that ValidationCoordinator is properly initialized."""
        assert isinstance(
            integration_orchestrator.validation_coordinator, ValidationCoordinator
        )
        assert integration_orchestrator.validation_coordinator is not None

    @pytest.mark.asyncio
    async def test_real_threat_aggregation(
        self, integration_orchestrator, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test real threat aggregation with duplicate detection."""
        # Create overlapping threats that should be deduplicated
        semgrep_threats = [
            ThreatMatch(
                rule_id="sql-injection",
                rule_name="SQL Injection",
                description="Potential SQL injection vulnerability",
                category="injection",
                severity=Severity.HIGH,
                file_path="<code_snippet>",
                line_number=10,
            ),
            ThreatMatch(
                rule_id="xss-reflected",
                rule_name="Reflected XSS",
                description="Reflected XSS vulnerability",
                category="xss",
                severity=Severity.MEDIUM,
                file_path="<code_snippet>",
                line_number=25,
            ),
        ]

        # Create LLM threats, one overlapping with Semgrep
        llm_threats = [
            ThreatMatch(
                rule_id="sql-injection-llm",
                rule_name="SQL Injection (LLM)",
                description="AI-detected SQL injection pattern",
                category="injection",
                severity=Severity.HIGH,
                file_path="<code_snippet>",
                line_number=12,  # Close to semgrep finding - should be deduplicated
            ),
            ThreatMatch(
                rule_id="path-traversal",
                rule_name="Path Traversal",
                description="Potential path traversal vulnerability",
                category="traversal",
                severity=Severity.MEDIUM,
                file_path="<code_snippet>",
                line_number=50,
            ),
        ]

        mock_semgrep_scanner.scan_code.return_value = semgrep_threats
        mock_llm_scanner.analyze_code.return_value = llm_threats

        # Mock time.time() for consistent metadata
        with patch(
            "src.adversary_mcp_server.application.coordination.scan_orchestrator.time.time"
        ) as mock_time:
            mock_time.side_effect = [1000.0] + [1000.1] * 10 + [1002.0]

            result = await integration_orchestrator.orchestrate_code_scan(
                code="SELECT * FROM users WHERE id = ?",
                language="python",
                use_validation=False,  # Disable validation for this test
            )

        # Verify result structure
        assert isinstance(result, EnhancedScanResult)
        assert result.file_path == "<code_snippet>"

        # Verify threat aggregation worked (should have 4 total threats, potentially deduplicated)
        total_threats = len(result.semgrep_threats) + len(result.llm_threats)
        assert (
            total_threats >= 3
        )  # At least 3 unique threats (2 semgrep + 1-2 llm after deduplication)

        # Verify specific threat types are preserved
        all_rule_ids = [t.rule_id for t in result.semgrep_threats + result.llm_threats]
        assert "sql-injection" in all_rule_ids
        assert "xss-reflected" in all_rule_ids
        assert "path-traversal" in all_rule_ids

        # Verify metadata was built correctly
        assert result.scan_metadata["scan_type"] == "code"
        assert result.scan_metadata["language"] == "python"
        assert "scan_duration_ms" in result.scan_metadata
        assert result.scan_metadata["engines_used"]["llm_analysis"] is True
        assert result.scan_metadata["engines_used"]["semgrep_analysis"] is True

    @pytest.mark.asyncio
    async def test_real_severity_filtering(
        self, integration_orchestrator, mock_semgrep_scanner
    ):
        """Test real severity filtering with various threat levels."""
        mixed_severity_threats = [
            ThreatMatch(
                rule_id="critical-rce",
                rule_name="Remote Code Execution",
                description="Critical RCE vulnerability",
                category="rce",
                severity=Severity.CRITICAL,
                file_path="<code_snippet>",
                line_number=5,
            ),
            ThreatMatch(
                rule_id="high-sqli",
                rule_name="SQL Injection",
                description="High severity SQL injection",
                category="injection",
                severity=Severity.HIGH,
                file_path="<code_snippet>",
                line_number=15,
            ),
            ThreatMatch(
                rule_id="medium-xss",
                rule_name="Cross-Site Scripting",
                description="Medium severity XSS",
                category="xss",
                severity=Severity.MEDIUM,
                file_path="<code_snippet>",
                line_number=25,
            ),
            ThreatMatch(
                rule_id="low-info",
                rule_name="Information Disclosure",
                description="Low severity info leak",
                category="disclosure",
                severity=Severity.LOW,
                file_path="<code_snippet>",
                line_number=35,
            ),
        ]

        mock_semgrep_scanner.scan_code.return_value = mixed_severity_threats

        # Mock time.time() for consistent results
        with patch(
            "src.adversary_mcp_server.application.coordination.scan_orchestrator.time.time"
        ) as mock_time:
            mock_time.side_effect = [2000.0] + [2000.1] * 5 + [2001.0]

            # Test filtering with HIGH threshold
            result = await integration_orchestrator.orchestrate_code_scan(
                code="test code",
                language="javascript",
                use_llm=False,
                severity_threshold=Severity.HIGH,
                use_validation=False,
            )

        # Should only include CRITICAL and HIGH threats
        assert len(result.semgrep_threats) == 2
        severities = [threat.severity for threat in result.semgrep_threats]
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM not in severities
        assert Severity.LOW not in severities

        # Verify rule IDs are correct
        rule_ids = [threat.rule_id for threat in result.semgrep_threats]
        assert "critical-rce" in rule_ids
        assert "high-sqli" in rule_ids
        assert "medium-xss" not in rule_ids
        assert "low-info" not in rule_ids

    @pytest.mark.asyncio
    async def test_real_scan_metadata_generation(
        self, integration_orchestrator, mock_semgrep_scanner
    ):
        """Test real scan metadata generation with ResultBuilder."""
        test_threats = [
            ThreatMatch(
                rule_id="test-threat",
                rule_name="Test Threat",
                description="Test threat for metadata",
                category="test",
                severity=Severity.HIGH,
                file_path="<code_snippet>",
                line_number=10,
            ),
        ]

        mock_semgrep_scanner.scan_code.return_value = test_threats

        # Mock time.time() with specific values for duration calculation
        with (
            patch(
                "src.adversary_mcp_server.application.coordination.scan_orchestrator.time.time"
            ) as mock_time,
            patch(
                "src.adversary_mcp_server.application.coordination.scan_orchestrator.time.strftime"
            ) as mock_strftime,
        ):

            mock_time.side_effect = [5000.0, 5002.5]  # 2.5 second duration
            mock_strftime.return_value = "2024-01-15T10:30:45Z"

            result = await integration_orchestrator.orchestrate_code_scan(
                code="test code for metadata",
                language="typescript",
                use_llm=False,
                use_validation=False,
            )

        # Verify comprehensive metadata structure
        metadata = result.scan_metadata

        # Basic scan info
        assert metadata["scan_type"] == "code"
        assert metadata["language"] == "typescript"
        assert metadata["engines_used"]["llm_analysis"] is False
        assert metadata["engines_used"]["semgrep_analysis"] is True
        assert metadata["validation_enabled"] is False

        # Timing info
        assert metadata["scan_duration_ms"] == 2500.0  # 2.5 seconds in ms
        assert metadata["timestamp"] == "2024-01-15T10:30:45Z"

        # Validation metadata (should be present even when disabled)
        assert metadata["validation_enabled"] is False

        # Verify actual threat counts in the result object (not metadata)
        assert len(result.semgrep_threats) == 1
        assert len(result.llm_threats) == 0
        assert result.semgrep_threats[0].rule_id == "test-threat"

    @pytest.mark.asyncio
    async def test_cache_coordinator_integration(
        self, integration_orchestrator, mock_semgrep_scanner
    ):
        """Test CacheCoordinator integration with no cache manager."""
        test_threats = [
            ThreatMatch(
                rule_id="cache-test",
                rule_name="Cache Test Threat",
                description="Test threat for cache integration",
                category="test",
                severity=Severity.MEDIUM,
                file_path="<code_snippet>",
                line_number=20,
            ),
        ]

        mock_semgrep_scanner.scan_code.return_value = test_threats

        with patch(
            "src.adversary_mcp_server.application.coordination.scan_orchestrator.time.time"
        ) as mock_time:
            mock_time.side_effect = [3000.0] + [3000.1] * 5 + [3001.0]

            result = await integration_orchestrator.orchestrate_code_scan(
                code="cache test code",
                language="python",
                use_llm=False,
                use_validation=False,
            )

        # Should work without cache manager (graceful degradation)
        assert isinstance(result, EnhancedScanResult)
        assert len(result.semgrep_threats) == 1
        assert result.semgrep_threats[0].rule_id == "cache-test"

        # Cache operations should not interfere with results
        assert result.file_path == "<code_snippet>"
        assert result.scan_metadata["language"] == "python"
