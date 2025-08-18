"""Tests for SemgrepScanStrategy adapter implementation."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.application.adapters.semgrep_adapter import (
    SemgrepScanStrategy,
)
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.threat_match import (
    ThreatMatch as DomainThreatMatch,
)
from adversary_mcp_server.domain.interfaces import ScanError
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel
from adversary_mcp_server.scanner.types import Severity
from adversary_mcp_server.scanner.types import ThreatMatch as InfraThreatMatch


class TestSemgrepScanStrategy:
    """Test the SemgrepScanStrategy adapter."""

    @pytest.fixture
    def mock_semgrep_scanner(self):
        """Create a mock SemgrepScanner for testing."""
        scanner = Mock()
        scanner.scan_file = AsyncMock()
        scanner.scan_directory = AsyncMock()
        scanner.scan_code = AsyncMock()
        scanner.config = "p/security-audit"
        scanner._rules_count = 100
        scanner._version = "1.0.0"
        return scanner

    @pytest.fixture
    def semgrep_strategy(self, mock_semgrep_scanner):
        """Create SemgrepScanStrategy with mocked scanner."""
        return SemgrepScanStrategy(semgrep_scanner=mock_semgrep_scanner)

    @pytest.fixture
    def sample_scan_request(self):
        """Create a sample scan request for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('hello world')\n")
            f.flush()

            request = ScanRequest.for_file_scan(
                file_path=f.name,
                requester="test",
                enable_semgrep=True,
                enable_llm=False,
                enable_validation=False,
                severity_threshold="medium",
            )

            yield request

            # Cleanup
            Path(f.name).unlink(missing_ok=True)

    @pytest.fixture
    def sample_infra_threat(self):
        """Create a sample infrastructure threat match."""
        threat = Mock(spec=InfraThreatMatch)
        threat.rule_id = "test-rule-id"
        threat.rule_name = "Test Rule"
        threat.description = "Test vulnerability"
        threat.category = Mock()
        threat.category.value = "security"
        threat.severity = Severity.HIGH
        threat.file_path = "/test/file.py"
        threat.line_number = 10
        threat.column_number = 5
        threat.code_snippet = "test code"
        threat.confidence = 0.9
        threat.cwe_id = "CWE-89"
        threat.owasp_category = "A03"
        threat.references = ["https://example.com"]
        threat.function_name = "test_function"
        threat.exploit_examples = ["example exploit"]
        threat.remediation = "Fix the vulnerability"
        threat.is_false_positive = False
        return threat

    def test_initialization_with_scanner(self, mock_semgrep_scanner):
        """Test initialization with provided scanner."""
        strategy = SemgrepScanStrategy(semgrep_scanner=mock_semgrep_scanner)
        assert strategy._scanner == mock_semgrep_scanner

    def test_initialization_with_api_key(self):
        """Test initialization with Semgrep API key."""
        mock_credential_manager = Mock()
        mock_credential_manager.get_semgrep_api_key.return_value = "test-api-key"

        with (
            patch(
                "adversary_mcp_server.application.adapters.semgrep_adapter.get_credential_manager",
                return_value=mock_credential_manager,
            ),
            patch(
                "adversary_mcp_server.application.adapters.semgrep_adapter.SemgrepScanner"
            ) as mock_scanner_class,
        ):

            strategy = SemgrepScanStrategy()
            mock_scanner_class.assert_called_once_with(config="auto")

    def test_initialization_without_api_key(self):
        """Test initialization without Semgrep API key."""
        mock_credential_manager = Mock()
        mock_credential_manager.get_semgrep_api_key.return_value = None

        with (
            patch(
                "adversary_mcp_server.application.adapters.semgrep_adapter.get_credential_manager",
                return_value=mock_credential_manager,
            ),
            patch(
                "adversary_mcp_server.application.adapters.semgrep_adapter.SemgrepScanner"
            ) as mock_scanner_class,
        ):

            strategy = SemgrepScanStrategy()
            mock_scanner_class.assert_called_once_with(config="p/security-audit")

    def test_initialization_credential_error(self):
        """Test initialization when credential detection fails."""
        with (
            patch(
                "adversary_mcp_server.application.adapters.semgrep_adapter.get_credential_manager",
                side_effect=Exception("Credential error"),
            ),
            patch(
                "adversary_mcp_server.application.adapters.semgrep_adapter.SemgrepScanner"
            ) as mock_scanner_class,
        ):

            strategy = SemgrepScanStrategy()
            mock_scanner_class.assert_called_once_with(config="p/security-audit")

    def test_get_strategy_name(self, semgrep_strategy):
        """Test getting strategy name."""
        assert semgrep_strategy.get_strategy_name() == "semgrep_static_analysis"

    def test_can_scan_file(self, semgrep_strategy):
        """Test can_scan for file context."""
        context = Mock()
        context.metadata.scan_type = "file"
        assert semgrep_strategy.can_scan(context) is True

    def test_can_scan_directory(self, semgrep_strategy):
        """Test can_scan for directory context."""
        context = Mock()
        context.metadata.scan_type = "directory"
        assert semgrep_strategy.can_scan(context) is True

    def test_can_scan_code(self, semgrep_strategy):
        """Test can_scan for code context."""
        context = Mock()
        context.metadata.scan_type = "code"
        assert semgrep_strategy.can_scan(context) is True

    def test_can_scan_diff(self, semgrep_strategy):
        """Test can_scan for diff context."""
        context = Mock()
        context.metadata.scan_type = "diff"
        assert semgrep_strategy.can_scan(context) is True

    def test_can_scan_unsupported(self, semgrep_strategy):
        """Test can_scan for unsupported context."""
        context = Mock()
        context.metadata.scan_type = "unknown"
        assert semgrep_strategy.can_scan(context) is False

    def test_get_supported_languages(self, semgrep_strategy):
        """Test getting supported languages."""
        with patch(
            "adversary_mcp_server.application.adapters.semgrep_adapter.LanguageMapper.get_supported_languages",
            return_value=["python", "javascript", "java"],
        ):
            languages = semgrep_strategy.get_supported_languages()
            assert "python" in languages
            assert "javascript" in languages
            assert "java" in languages

    @pytest.mark.asyncio
    async def test_execute_scan_file(
        self, semgrep_strategy, sample_scan_request, sample_infra_threat
    ):
        """Test executing file scan."""
        # Setup mocks
        semgrep_strategy._scanner.scan_file.return_value = [sample_infra_threat]

        with (
            patch.object(semgrep_strategy, "_count_lines_in_file", return_value=100),
            patch.object(
                semgrep_strategy, "_get_semgrep_version", return_value="1.0.0"
            ),
            patch.object(semgrep_strategy, "_get_rules_count", return_value=50),
            patch(
                "adversary_mcp_server.application.adapters.semgrep_adapter.LanguageMapper.detect_language_from_extension",
                return_value="python",
            ),
        ):

            result = await semgrep_strategy.execute_scan(sample_scan_request)

            assert len(result.threats) == 1
            assert result.threats[0].rule_id == "test-rule-id"
            assert result.scan_metadata["scanner"] == "semgrep_static_analysis"
            assert result.scan_metadata["lines_analyzed"] == 100

    @pytest.mark.asyncio
    async def test_execute_scan_directory(self, semgrep_strategy, sample_infra_threat):
        """Test executing directory scan."""
        # Create directory scan request
        with tempfile.TemporaryDirectory() as temp_dir:
            request = ScanRequest.for_directory_scan(
                directory_path=temp_dir, requester="test"
            )

            # Setup mocks
            semgrep_strategy._scanner.scan_directory.return_value = [
                sample_infra_threat
            ]

            with (
                patch.object(
                    semgrep_strategy, "_count_lines_in_directory", return_value=500
                ),
                patch.object(
                    semgrep_strategy, "_get_semgrep_version", return_value="1.0.0"
                ),
                patch.object(semgrep_strategy, "_get_rules_count", return_value=50),
            ):

                result = await semgrep_strategy.execute_scan(request)

                assert len(result.threats) == 1
                assert result.scan_metadata["lines_analyzed"] == 500

    @pytest.mark.asyncio
    async def test_execute_scan_code(self, semgrep_strategy, sample_infra_threat):
        """Test executing code scan."""
        # Create code scan request
        request = ScanRequest.for_code_scan(
            code="print('hello')", language="python", requester="test"
        )

        # Setup mocks
        semgrep_strategy._scanner.scan_code.return_value = [sample_infra_threat]

        with (
            patch.object(
                semgrep_strategy, "_get_semgrep_version", return_value="1.0.0"
            ),
            patch.object(semgrep_strategy, "_get_rules_count", return_value=50),
        ):

            result = await semgrep_strategy.execute_scan(request)

            assert len(result.threats) == 1
            assert result.scan_metadata["lines_analyzed"] == 1  # One line of code

    @pytest.mark.asyncio
    async def test_execute_scan_diff(
        self, semgrep_strategy, sample_scan_request, sample_infra_threat
    ):
        """Test executing diff scan."""
        # Create diff scan request
        with tempfile.TemporaryDirectory() as temp_dir:
            request = ScanRequest.for_diff_scan(
                source_branch="main",
                target_branch="feature",
                working_directory=temp_dir,
                requester="test",
            )

            # Setup mocks
            semgrep_strategy._scanner.scan_file.return_value = [sample_infra_threat]

            with (
                patch.object(
                    semgrep_strategy, "_count_lines_in_file", return_value=100
                ),
                patch.object(
                    semgrep_strategy, "_get_semgrep_version", return_value="1.0.0"
                ),
                patch.object(semgrep_strategy, "_get_rules_count", return_value=50),
                patch(
                    "adversary_mcp_server.application.adapters.semgrep_adapter.LanguageMapper.detect_language_from_extension",
                    return_value="python",
                ),
            ):

                result = await semgrep_strategy.execute_scan(request)

                # Diff scan may not find threats in empty directory, just verify it completed
                assert result.scan_metadata["scanner"] == "semgrep_static_analysis"

    @pytest.mark.asyncio
    async def test_execute_scan_error(self, semgrep_strategy, sample_scan_request):
        """Test scan execution with error."""
        # Setup scanner to raise exception
        semgrep_strategy._scanner.scan_file.side_effect = Exception("Scanner error")

        with pytest.raises(ScanError, match="Semgrep scan failed"):
            await semgrep_strategy.execute_scan(sample_scan_request)

    def test_convert_to_domain_threats(
        self, semgrep_strategy, sample_scan_request, sample_infra_threat
    ):
        """Test conversion of infrastructure threats to domain threats."""
        threats = [sample_infra_threat]
        domain_threats = semgrep_strategy._convert_to_domain_threats(
            threats, sample_scan_request
        )

        assert len(domain_threats) == 1
        domain_threat = domain_threats[0]
        assert isinstance(domain_threat, DomainThreatMatch)
        assert domain_threat.rule_id == "test-rule-id"
        assert domain_threat.rule_name == "Test Rule"
        assert domain_threat.description == "Test vulnerability"
        assert domain_threat.source_scanner == "semgrep"

    def test_convert_to_domain_threats_conversion_error(
        self, semgrep_strategy, sample_scan_request
    ):
        """Test handling conversion error."""
        # Create a threat that will cause conversion error
        bad_threat = Mock()
        bad_threat.rule_id = None  # This will cause error

        domain_threats = semgrep_strategy._convert_to_domain_threats(
            [bad_threat], sample_scan_request
        )

        # Should continue processing and return empty list
        assert len(domain_threats) == 0

    def test_map_infrastructure_severity_to_domain(self, semgrep_strategy):
        """Test severity mapping from infrastructure to domain."""
        # Test enum-like severity
        mock_severity = Mock()
        mock_severity.value = "critical"
        result = semgrep_strategy._map_infrastructure_severity_to_domain(mock_severity)
        assert result == SeverityLevel.from_string("critical")

        # Test string severity
        result = semgrep_strategy._map_infrastructure_severity_to_domain("high")
        assert result == SeverityLevel.from_string("high")

        # Test unknown severity
        result = semgrep_strategy._map_infrastructure_severity_to_domain("unknown")
        assert result == SeverityLevel.from_string("medium")

    def test_map_severity(self, semgrep_strategy):
        """Test Semgrep severity mapping."""
        assert semgrep_strategy._map_severity("error") == SeverityLevel.from_string(
            "critical"
        )
        assert semgrep_strategy._map_severity("warning") == SeverityLevel.from_string(
            "high"
        )
        assert semgrep_strategy._map_severity("info") == SeverityLevel.from_string(
            "medium"
        )
        assert semgrep_strategy._map_severity("note") == SeverityLevel.from_string(
            "low"
        )
        assert semgrep_strategy._map_severity("unknown") == SeverityLevel.from_string(
            "medium"
        )

    def test_map_scanner_severity(self, semgrep_strategy):
        """Test scanner severity mapping."""
        result = semgrep_strategy._map_scanner_severity("severity.critical")
        assert result == SeverityLevel.from_string("critical")

        result = semgrep_strategy._map_scanner_severity("high")
        assert result == SeverityLevel.from_string("high")

    def test_determine_category(self, semgrep_strategy):
        """Test threat category determination."""
        assert (
            semgrep_strategy._determine_category({"check_id": "test-injection"})
            == "injection"
        )
        assert semgrep_strategy._determine_category({"check_id": "test-xss"}) == "xss"
        assert (
            semgrep_strategy._determine_category({"check_id": "test-crypto"})
            == "cryptography"
        )
        assert (
            semgrep_strategy._determine_category({"check_id": "test-auth"})
            == "authentication"
        )
        assert (
            semgrep_strategy._determine_category({"check_id": "test-path"})
            == "path_traversal"
        )
        assert (
            semgrep_strategy._determine_category({"check_id": "test-disclosure"})
            == "information_disclosure"
        )
        assert (
            semgrep_strategy._determine_category({"check_id": "test-other"})
            == "security"
        )

    def test_apply_severity_filter(self, semgrep_strategy):
        """Test severity filtering."""
        # Create mock threats with severity that meets/doesn't meet threshold
        high_threat = Mock()
        high_threat.severity.meets_threshold.return_value = True

        low_threat = Mock()
        low_threat.severity.meets_threshold.return_value = False

        threats = [high_threat, low_threat]
        threshold = SeverityLevel.from_string("medium")

        filtered = semgrep_strategy._apply_severity_filter(threats, threshold)
        assert len(filtered) == 1
        assert filtered[0] == high_threat

    def test_apply_severity_filter_no_threshold(self, semgrep_strategy):
        """Test severity filtering with no threshold."""
        threats = [Mock(), Mock()]
        filtered = semgrep_strategy._apply_severity_filter(threats, None)
        assert len(filtered) == 2

    def test_count_lines_in_file(self, semgrep_strategy):
        """Test counting lines in a file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("line 1\nline 2\nline 3\n")
            f.flush()

            count = semgrep_strategy._count_lines_in_file(f.name)
            assert count == 3

    def test_count_lines_in_file_error(self, semgrep_strategy):
        """Test counting lines with file error."""
        count = semgrep_strategy._count_lines_in_file("/nonexistent/file.py")
        assert count == 0

    def test_count_lines_in_directory(self, semgrep_strategy):
        """Test counting lines in a directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            (Path(temp_dir) / "test1.py").write_text("line 1\nline 2\n")
            (Path(temp_dir) / "test2.js").write_text("line 1\n")
            (Path(temp_dir) / "README.txt").write_text(
                "ignore this"
            )  # Non-supported extension

            with patch(
                "adversary_mcp_server.application.adapters.semgrep_adapter.LanguageMapper.get_supported_extensions",
                return_value=[".py", ".js"],
            ):
                count = semgrep_strategy._count_lines_in_directory(temp_dir)
                assert count == 3  # 2 from .py + 1 from .js

    def test_count_lines_in_directory_error(self, semgrep_strategy):
        """Test counting lines in directory with error."""
        count = semgrep_strategy._count_lines_in_directory("/nonexistent/dir")
        assert count == 0

    @pytest.mark.asyncio
    async def test_get_semgrep_version_success(self, semgrep_strategy):
        """Test getting Semgrep version successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "semgrep 1.2.3"

        with patch("subprocess.run", return_value=mock_result):
            version = await semgrep_strategy._get_semgrep_version()
            assert version == "semgrep 1.2.3"

    @pytest.mark.asyncio
    async def test_get_semgrep_version_failure(self, semgrep_strategy):
        """Test getting Semgrep version with failure."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            version = await semgrep_strategy._get_semgrep_version()
            assert version == "unknown"

    @pytest.mark.asyncio
    async def test_get_semgrep_version_exception(self, semgrep_strategy):
        """Test getting Semgrep version with exception."""
        # Mock scanner's _version attribute to avoid recursion
        semgrep_strategy._scanner._version = "unknown"

        with patch("subprocess.run", side_effect=FileNotFoundError):
            version = await semgrep_strategy._get_semgrep_version()
            assert version == "unknown"

    @pytest.mark.asyncio
    async def test_get_rules_count_pro_status(self, semgrep_strategy):
        """Test getting rules count from pro status."""
        # Mock the pro_status properly
        semgrep_strategy._scanner._pro_status = {"rules_available": 1500}

        # Ensure hasattr returns True for _pro_status
        with patch("builtins.hasattr", return_value=True):
            count = await semgrep_strategy._get_rules_count()
            assert count == 1500

    @pytest.mark.asyncio
    async def test_get_rules_count_dump_config(self, semgrep_strategy):
        """Test getting rules count from dump config."""
        # Set pro_status to None so it falls back to dump config
        semgrep_strategy._scanner._pro_status = None

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"rules": [{"id": "rule1"}, {"id": "rule2"}]})

        with patch("subprocess.run", return_value=mock_result):
            count = await semgrep_strategy._get_rules_count()
            assert count == 2

    @pytest.mark.asyncio
    async def test_get_rules_count_fallback(self, semgrep_strategy):
        """Test getting rules count fallback."""
        # Set pro_status to None and make subprocess fail
        semgrep_strategy._scanner._pro_status = None

        with patch("subprocess.run", side_effect=FileNotFoundError):
            count = await semgrep_strategy._get_rules_count()
            assert count == 100  # From mock scanner _rules_count

    def test_validate_scan_metadata_success(self, semgrep_strategy):
        """Test successful metadata validation."""
        metadata = {
            "semgrep_version": "1.0.0",
            "rules_count": 100,
            "scan_duration_ms": 5000,
            "lines_analyzed": 500,
        }

        # Should not raise any exception
        semgrep_strategy._validate_scan_metadata(metadata)

    def test_validate_scan_metadata_warnings(self, semgrep_strategy):
        """Test metadata validation with warnings."""
        metadata = {
            "semgrep_version": "unknown",
            "rules_count": 0,
            "scan_duration_ms": 0,
            "lines_analyzed": 0,
        }

        with patch(
            "adversary_mcp_server.application.adapters.semgrep_adapter.get_logger"
        ) as mock_logger:
            semgrep_strategy._validate_scan_metadata(metadata)
            # Should have logged warnings
            assert mock_logger.return_value.warning.call_count >= 2

    def test_validate_scan_metadata_long_duration(self, semgrep_strategy):
        """Test metadata validation with long duration."""
        metadata = {
            "semgrep_version": "1.0.0",
            "rules_count": 100,
            "scan_duration_ms": 400000,  # Over 5 minutes
            "lines_analyzed": 500,
        }

        with patch(
            "adversary_mcp_server.application.adapters.semgrep_adapter.get_logger"
        ) as mock_logger:
            semgrep_strategy._validate_scan_metadata(metadata)
            mock_logger.return_value.warning.assert_called()

    @pytest.mark.asyncio
    async def test_scan_file_delegation(self, semgrep_strategy):
        """Test scan file delegation to underlying scanner."""
        semgrep_strategy._scanner.scan_file.return_value = []

        result = await semgrep_strategy._scan_file("/test/file.py", "python")

        semgrep_strategy._scanner.scan_file.assert_called_once_with(
            "/test/file.py", "python"
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_directory_delegation(self, semgrep_strategy):
        """Test scan directory delegation to underlying scanner."""
        semgrep_strategy._scanner.scan_directory.return_value = []

        result = await semgrep_strategy._scan_directory("/test/dir")

        semgrep_strategy._scanner.scan_directory.assert_called_once_with("/test/dir")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_code_delegation(self, semgrep_strategy):
        """Test scan code delegation to underlying scanner."""
        semgrep_strategy._scanner.scan_code.return_value = []

        result = await semgrep_strategy._scan_code("print('hello')", "python")

        semgrep_strategy._scanner.scan_code.assert_called_once_with(
            "print('hello')", "python"
        )
        assert result == []
