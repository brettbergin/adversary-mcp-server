"""Comprehensive tests for ScanApplicationService."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.application.services.scan_application_service import (
    ScanApplicationService,
)
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class TestScanApplicationService:
    """Test ScanApplicationService functionality."""

    @pytest.fixture
    def mock_orchestrator(self):
        """Create a mock scan orchestrator."""
        mock = Mock()
        mock.register_scan_strategy = Mock()
        mock.register_validation_strategy = Mock()
        mock.set_threat_aggregator = Mock()
        mock.execute_scan = AsyncMock()
        mock.get_registered_strategies = Mock(
            return_value={
                "scan_strategies": ["semgrep", "llm"],
                "validation_strategies": ["llm_validation"],
                "threat_aggregator": "default",
            }
        )
        return mock

    @pytest.fixture
    def mock_threat_aggregator(self):
        """Create a mock threat aggregator."""
        return Mock()

    @pytest.fixture
    def mock_validation_service(self):
        """Create a mock validation service."""
        mock = Mock()
        mock.validate_scan_request = Mock()
        mock.enforce_security_constraints = Mock()
        mock.get_security_constraints = Mock(
            return_value={
                "max_file_size": 10485760,
                "allowed_extensions": [".py", ".js", ".ts"],
                "blocked_paths": ["/etc", "/var"],
            }
        )
        mock.update_security_constraints = Mock()
        return mock

    @pytest.fixture
    def mock_strategies(self):
        """Create mock scan strategies."""
        semgrep_strategy = Mock()
        semgrep_strategy.get_strategy_name.return_value = "semgrep"

        llm_strategy = Mock()
        llm_strategy.get_strategy_name.return_value = "llm"

        validation_strategy = Mock()
        validation_strategy.get_strategy_name.return_value = "llm_validation"

        return {
            "semgrep": semgrep_strategy,
            "llm": llm_strategy,
            "validation": validation_strategy,
        }

    @pytest.fixture
    def mock_scan_result(self):
        """Create a mock scan result."""
        mock_request = Mock()
        mock_context = Mock()
        mock_metadata = Mock()
        mock_metadata.scan_id = "test-scan-id"
        mock_context.metadata = mock_metadata
        mock_request.context = mock_context
        return ScanResult.create_empty(mock_request)

    @pytest.fixture
    def temp_file(self):
        """Create a temporary file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_path = f.name
        yield temp_path
        # Cleanup
        Path(temp_path).unlink(missing_ok=True)

    @pytest.fixture
    def temp_directory(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def service(
        self,
        mock_orchestrator,
        mock_threat_aggregator,
        mock_validation_service,
        mock_strategies,
        mock_scan_result,
    ):
        """Create a ScanApplicationService with mocked dependencies."""
        with (
            patch(
                "adversary_mcp_server.application.services.scan_application_service.ScanOrchestrator",
                return_value=mock_orchestrator,
            ),
            patch(
                "adversary_mcp_server.application.services.scan_application_service.ThreatAggregator",
                return_value=mock_threat_aggregator,
            ),
            patch(
                "adversary_mcp_server.application.services.scan_application_service.ValidationService",
                return_value=mock_validation_service,
            ),
            patch(
                "adversary_mcp_server.application.services.scan_application_service.SemgrepScanStrategy",
                return_value=mock_strategies["semgrep"],
            ),
            patch(
                "adversary_mcp_server.application.services.scan_application_service.LLMScanStrategy",
                return_value=mock_strategies["llm"],
            ),
            patch(
                "adversary_mcp_server.application.services.scan_application_service.LLMValidationStrategy",
                return_value=mock_strategies["validation"],
            ),
        ):
            service = ScanApplicationService()
            service._scan_orchestrator = mock_orchestrator
            service._threat_aggregator = mock_threat_aggregator
            service._validation_service = mock_validation_service
            # Set up default return value
            service._scan_orchestrator.execute_scan.return_value = mock_scan_result
            yield service

    def test_initialization(self, service):
        """Test service initialization and strategy registration."""
        # Verify orchestrator setup calls
        service._scan_orchestrator.register_scan_strategy.assert_any_call(
            service._semgrep_strategy
        )
        service._scan_orchestrator.register_scan_strategy.assert_any_call(
            service._llm_strategy
        )
        service._scan_orchestrator.register_validation_strategy.assert_called_once_with(
            service._llm_validation_strategy
        )
        service._scan_orchestrator.set_threat_aggregator.assert_called_once_with(
            service._threat_aggregator
        )

    @pytest.mark.asyncio
    async def test_scan_file_success(self, service, temp_file):
        """Test successful file scanning."""
        # Execute
        result = await service.scan_file(
            temp_file,
            requester="test_user",
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=True,
            severity_threshold="high",
            timeout_seconds=120,
            language="python",
        )

        # Verify
        assert result is not None
        service._validation_service.validate_scan_request.assert_called_once()
        service._validation_service.enforce_security_constraints.assert_called_once()
        service._scan_orchestrator.execute_scan.assert_called_once()

        # Check request structure
        call_args = service._scan_orchestrator.execute_scan.call_args[0][0]
        assert isinstance(call_args, ScanRequest)
        assert call_args.enable_semgrep is True
        assert call_args.enable_llm is True
        assert call_args.enable_validation is True
        assert call_args.severity_threshold == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_scan_file_minimal_parameters(self, service, temp_file):
        """Test file scanning with minimal parameters."""
        # Execute with minimal parameters
        result = await service.scan_file(temp_file)

        # Verify
        assert result is not None
        service._validation_service.validate_scan_request.assert_called_once()
        service._validation_service.enforce_security_constraints.assert_called_once()
        service._scan_orchestrator.execute_scan.assert_called_once()

        # Check defaults
        call_args = service._scan_orchestrator.execute_scan.call_args[0][0]
        assert call_args.enable_semgrep is True
        assert call_args.enable_llm is False
        assert call_args.enable_validation is False
        assert call_args.severity_threshold is None

    @pytest.mark.asyncio
    async def test_scan_file_with_severity_threshold(self, service, temp_file):
        """Test file scanning with severity threshold."""
        # Test different severity levels
        for severity_str, expected_level in [
            ("low", SeverityLevel.LOW),
            ("medium", SeverityLevel.MEDIUM),
            ("high", SeverityLevel.HIGH),
            ("critical", SeverityLevel.CRITICAL),
        ]:
            service._scan_orchestrator.execute_scan.reset_mock()

            result = await service.scan_file(temp_file, severity_threshold=severity_str)

            call_args = service._scan_orchestrator.execute_scan.call_args[0][0]
            assert call_args.severity_threshold == expected_level

    @pytest.mark.asyncio
    async def test_scan_directory_success(self, service, temp_directory):
        """Test successful directory scanning."""
        # Execute
        result = await service.scan_directory(
            temp_directory,
            requester="test_user",
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=True,
            severity_threshold="medium",
            timeout_seconds=300,
            recursive=True,
        )

        # Verify
        assert result is not None
        service._validation_service.validate_scan_request.assert_called_once()
        service._validation_service.enforce_security_constraints.assert_called_once()
        service._scan_orchestrator.execute_scan.assert_called_once()

        # Check request structure
        call_args = service._scan_orchestrator.execute_scan.call_args[0][0]
        assert isinstance(call_args, ScanRequest)
        assert call_args.context.metadata.scan_type == "directory"

    @pytest.mark.asyncio
    async def test_scan_directory_minimal_parameters(self, service, temp_directory):
        """Test directory scanning with minimal parameters."""
        # Execute with minimal parameters
        result = await service.scan_directory(temp_directory)

        # Verify
        assert result is not None

        # Check defaults
        call_args = service._scan_orchestrator.execute_scan.call_args[0][0]
        assert call_args.enable_semgrep is True
        assert call_args.enable_llm is False

    @pytest.mark.asyncio
    async def test_scan_code_success(self, service):
        """Test successful code scanning."""
        code_content = "print('Hello, world!')"
        language = "python"

        # Execute
        result = await service.scan_code(
            code_content,
            language,
            requester="test_user",
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=True,
            severity_threshold="low",
        )

        # Verify
        assert result is not None
        service._validation_service.validate_scan_request.assert_called_once()
        service._validation_service.enforce_security_constraints.assert_called_once()
        service._scan_orchestrator.execute_scan.assert_called_once()

        # Check request structure
        call_args = service._scan_orchestrator.execute_scan.call_args[0][0]
        assert isinstance(call_args, ScanRequest)
        assert call_args.context.metadata.scan_type == "code"
        assert call_args.context.metadata.language == language
        assert call_args.context.content == code_content

    @pytest.mark.asyncio
    async def test_scan_code_minimal_parameters(self, service):
        """Test code scanning with minimal parameters."""
        code_content = "console.log('test');"
        language = "javascript"

        # Execute with minimal parameters
        result = await service.scan_code(code_content, language)

        # Verify
        assert result is not None

        # Check defaults for code scanning
        call_args = service._scan_orchestrator.execute_scan.call_args[0][0]
        assert call_args.enable_semgrep is True
        assert call_args.enable_llm is True  # Default True for code scanning
        assert call_args.enable_validation is False

    @pytest.mark.asyncio
    async def test_scan_code_virtual_file_path(self, service):
        """Test that code scanning creates proper virtual file path."""
        code_content = "const x = 1;"
        language = "typescript"

        with patch.object(service, "_get_extension_for_language", return_value="ts"):
            await service.scan_code(code_content, language)

        call_args = service._scan_orchestrator.execute_scan.call_args[0][0]
        assert "/virtual/code.ts" in str(call_args.context.target_path)

    def test_get_scan_capabilities(self, service):
        """Test getting scan capabilities."""
        capabilities = service.get_scan_capabilities()

        assert "scan_strategies" in capabilities
        assert "validation_strategies" in capabilities
        assert "threat_aggregator" in capabilities
        assert "supported_scan_types" in capabilities
        assert "supported_languages" in capabilities
        assert "severity_levels" in capabilities
        assert "default_timeouts" in capabilities

        # Check specific values
        assert capabilities["supported_scan_types"] == ["file", "directory", "code"]
        assert capabilities["severity_levels"] == ["low", "medium", "high", "critical"]
        assert capabilities["default_timeouts"]["file"] == 120
        assert capabilities["default_timeouts"]["directory"] == 600
        assert capabilities["default_timeouts"]["code"] == 60

    def test_get_security_constraints(self, service):
        """Test getting security constraints."""
        constraints = service.get_security_constraints()

        service._validation_service.get_security_constraints.assert_called_once()
        assert constraints == {
            "max_file_size": 10485760,
            "allowed_extensions": [".py", ".js", ".ts"],
            "blocked_paths": ["/etc", "/var"],
        }

    def test_update_security_constraints(self, service):
        """Test updating security constraints."""
        new_constraints = {
            "max_file_size": 5242880,
            "allowed_extensions": [".py"],
        }

        service.update_security_constraints(**new_constraints)

        service._validation_service.update_security_constraints.assert_called_once_with(
            **new_constraints
        )

    @patch(
        "adversary_mcp_server.application.services.scan_application_service.LanguageMapper"
    )
    def test_get_extension_for_language(self, mock_language_mapper, service):
        """Test getting file extension for language."""
        mock_language_mapper.get_extension_for_language.return_value = "py"

        result = service._get_extension_for_language("python")

        assert result == "py"
        mock_language_mapper.get_extension_for_language.assert_called_once_with(
            "python"
        )

    @patch(
        "adversary_mcp_server.application.services.scan_application_service.LanguageMapper"
    )
    def test_get_supported_languages(self, mock_language_mapper, service):
        """Test getting supported languages."""
        expected_languages = ["python", "javascript", "typescript", "java"]
        mock_language_mapper.get_supported_languages.return_value = expected_languages

        result = service._get_supported_languages()

        assert result == expected_languages
        mock_language_mapper.get_supported_languages.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_file_validation_error(self, service, temp_file):
        """Test file scanning with validation error."""
        from adversary_mcp_server.domain.interfaces import ValidationError

        service._validation_service.validate_scan_request.side_effect = ValidationError(
            "Invalid request"
        )

        with pytest.raises(ValidationError, match="Invalid request"):
            await service.scan_file(temp_file)

    @pytest.mark.asyncio
    async def test_scan_file_security_error(self, service, temp_file):
        """Test file scanning with security error."""
        from adversary_mcp_server.domain.interfaces import SecurityError

        service._validation_service.enforce_security_constraints.side_effect = (
            SecurityError("Access denied")
        )

        with pytest.raises(SecurityError, match="Access denied"):
            await service.scan_file(temp_file)
