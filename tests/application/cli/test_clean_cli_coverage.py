"""Comprehensive tests for clean_cli.py to increase coverage."""

from unittest.mock import AsyncMock, Mock, call, patch

import pytest

from adversary_mcp_server.application.cli.clean_cli import CleanCLI
from adversary_mcp_server.domain.interfaces import SecurityError


@pytest.fixture
def mock_input_validator():
    """Fixture to mock InputValidator for all CLI tests."""
    with patch(
        "adversary_mcp_server.application.cli.clean_cli.InputValidator"
    ) as mock_validator_class:
        mock_validator = Mock()
        mock_validator.validate_mcp_arguments.return_value = {
            "path": "test.py",
            "use_semgrep": True,
            "use_llm": False,
            "use_validation": False,
            "severity_threshold": "medium",
            "output_format": "json",
            "verbose": False,
        }
        mock_validator_class.return_value = mock_validator
        yield mock_validator


class TestCleanCLI:
    """Tests for CleanCLI class."""

    def test_init(self):
        """Test CleanCLI initialization."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter,
        ):

            cli = CleanCLI()

            assert cli._scan_service is not None
            assert cli._formatter is not None
            mock_service.assert_called_once()
            mock_formatter.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_file_basic(self, mock_input_validator):
        """Test basic file scanning."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
        ):

            # Setup mocks
            mock_service = AsyncMock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            mock_result = Mock()
            mock_service.scan_file.return_value = mock_result

            cli = CleanCLI()

            with patch.object(
                cli, "_output_results", new_callable=AsyncMock
            ) as mock_output:
                await cli.scan_file("test.py")

                mock_service.scan_file.assert_called_once_with(
                    file_path="test.py",
                    requester="cli",
                    enable_semgrep=True,
                    enable_llm=False,
                    enable_validation=False,
                    severity_threshold="medium",
                )
                mock_output.assert_called_once_with(mock_result, "json", None, False)

    @pytest.mark.asyncio
    async def test_scan_file_verbose(self):
        """Test file scanning with verbose output."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.InputValidator"
            ) as mock_validator_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
        ):

            # Setup mocks
            mock_service = AsyncMock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            # Mock input validator to return verbose=True arguments
            mock_validator = Mock()
            mock_validator.validate_mcp_arguments.return_value = {
                "path": "test.py",
                "use_semgrep": True,
                "use_llm": True,
                "use_validation": True,
                "severity_threshold": "medium",
                "output_format": "json",
                "verbose": True,
            }
            mock_validator_class.return_value = mock_validator

            mock_result = Mock()
            mock_service.scan_file.return_value = mock_result

            cli = CleanCLI()

            with patch.object(
                cli, "_output_results", new_callable=AsyncMock
            ) as mock_output:
                await cli.scan_file(
                    "test.py", verbose=True, use_llm=True, use_validation=True
                )

                # Should print verbose output (2 print statements for verbose info)
                assert mock_console.print.call_count >= 2
                mock_output.assert_called_once_with(mock_result, "json", None, True)

    @pytest.mark.asyncio
    async def test_scan_file_validation_error(self):
        """Test file scanning with validation error."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.InputValidator"
            ) as mock_validator_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
            patch("sys.exit") as mock_exit,
        ):

            # Setup mocks
            mock_service = AsyncMock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            # Mock input validator to raise ValueError during validation
            mock_validator = Mock()
            mock_validator.validate_mcp_arguments.side_effect = ValueError(
                "Invalid file"
            )
            mock_validator_class.return_value = mock_validator

            cli = CleanCLI()

            await cli.scan_file("test.py")

            # Check that the first call was the validation error message
            assert len(mock_console.print.call_args_list) >= 1
            first_call = mock_console.print.call_args_list[0]
            assert first_call == call(
                "[red]Input validation failed:[/red] Invalid file"
            )

            # sys.exit should have been called to stop execution
            mock_exit.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_scan_file_security_error(self):
        """Test file scanning with security error."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.InputValidator"
            ) as mock_validator_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
            patch("sys.exit") as mock_exit,
        ):

            # Setup mocks
            mock_service = AsyncMock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            # Mock input validator to succeed
            mock_validator = Mock()
            mock_validator.validate_mcp_arguments.return_value = {
                "path": "test.py",
                "use_semgrep": True,
                "use_llm": False,
                "use_validation": False,
                "severity_threshold": "medium",
                "output_format": "json",
                "verbose": False,
            }
            mock_validator_class.return_value = mock_validator

            mock_service.scan_file.side_effect = SecurityError("Security violation")

            cli = CleanCLI()

            await cli.scan_file("test.py")

            mock_console.print.assert_called_with(
                "[red]Scan failed:[/red] Security violation"
            )
            mock_exit.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_scan_file_unexpected_error(self):
        """Test file scanning with unexpected error."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.InputValidator"
            ) as mock_validator_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.logger"
            ) as mock_logger,
            patch("sys.exit") as mock_exit,
        ):

            # Setup mocks
            mock_service = AsyncMock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            # Mock input validator to succeed
            mock_validator = Mock()
            mock_validator.validate_mcp_arguments.return_value = {
                "path": "test.py",
                "use_semgrep": True,
                "use_llm": False,
                "use_validation": False,
                "severity_threshold": "medium",
                "output_format": "json",
                "verbose": False,
            }
            mock_validator_class.return_value = mock_validator

            mock_service.scan_file.side_effect = Exception("Unexpected error")

            cli = CleanCLI()

            await cli.scan_file("test.py")

            mock_logger.error.assert_called()
            mock_exit.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_scan_directory_basic(self):
        """Test basic directory scanning."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.InputValidator"
            ) as mock_validator_class,
        ):

            # Setup mocks
            mock_service = AsyncMock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            # Mock input validator for directory scan
            mock_validator = Mock()
            mock_validator.validate_mcp_arguments.return_value = {
                "path": "/test/dir",
                "use_semgrep": True,
                "use_llm": False,
                "use_validation": False,
                "severity_threshold": "medium",
                "output_format": "json",
                "verbose": False,
            }
            mock_validator_class.return_value = mock_validator

            mock_result = Mock()
            mock_service.scan_directory.return_value = mock_result

            cli = CleanCLI()

            with patch.object(
                cli, "_output_results", new_callable=AsyncMock
            ) as mock_output:
                await cli.scan_directory("/test/dir")

                mock_service.scan_directory.assert_called_once_with(
                    directory_path="/test/dir",
                    requester="cli",
                    enable_semgrep=True,
                    enable_llm=False,
                    enable_validation=False,
                    severity_threshold="medium",
                )
                mock_output.assert_called_once_with(mock_result, "json", None, False)

    @pytest.mark.asyncio
    async def test_scan_code_basic(self):
        """Test basic code scanning."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.InputValidator"
            ) as mock_validator_class,
        ):

            # Setup mocks
            mock_service = AsyncMock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            # Mock input validator for code scan
            mock_validator = Mock()
            mock_validator.validate_mcp_arguments.return_value = {
                "content": "print('hello')",
                "language": "python",
                "use_semgrep": True,
                "use_llm": False,
                "use_validation": False,
                "severity_threshold": "medium",
                "output_format": "json",
                "verbose": False,
            }
            mock_validator_class.return_value = mock_validator

            mock_result = Mock()
            mock_service.scan_code.return_value = mock_result

            cli = CleanCLI()

            with patch.object(
                cli, "_output_results", new_callable=AsyncMock
            ) as mock_output:
                await cli.scan_code("print('hello')", "python")

                mock_service.scan_code.assert_called_once_with(
                    code_content="print('hello')",
                    language="python",
                    requester="cli",
                    enable_semgrep=True,
                    enable_llm=False,
                    enable_validation=False,
                    severity_threshold="medium",
                )
                mock_output.assert_called_once_with(mock_result, "json", None, False)

    @pytest.mark.asyncio
    async def test_output_results_json_stdout(self):
        """Test output results in JSON format to stdout."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
            patch("builtins.print") as mock_print,
        ):

            # Setup mocks
            mock_service = Mock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter.format_json.return_value = '{"test": "result"}'
            mock_formatter_class.return_value = mock_formatter

            cli = CleanCLI()
            mock_result = Mock()

            await cli._output_results(mock_result, "json", None, False)

            mock_formatter.format_json.assert_called_once_with(mock_result)
            # JSON output to stdout now uses plain print() instead of console.print()
            mock_print.assert_called_with('{"test": "result"}')

    @pytest.mark.asyncio
    async def test_output_results_json_to_file(self):
        """Test output results in JSON format to file."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
            patch("adversary_mcp_server.application.cli.clean_cli.Path") as mock_path,
        ):

            # Setup mocks
            mock_service = Mock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter.format_json.return_value = '{"test": "result"}'
            mock_formatter_class.return_value = mock_formatter

            # Mock Path and its methods
            mock_path_instance = Mock()
            mock_path_instance.resolve.return_value = mock_path_instance
            mock_path_instance.parent.mkdir = Mock()
            mock_path_instance.write_text = Mock()
            mock_path_instance.__str__ = Mock(return_value="/resolved/output.json")
            mock_path.return_value = mock_path_instance

            cli = CleanCLI()
            mock_result = Mock()

            await cli._output_results(mock_result, "json", "output.json", False)

            mock_formatter.format_json.assert_called_once_with(mock_result)
            mock_path.assert_called_once_with("output.json")
            mock_path_instance.resolve.assert_called_once()
            mock_path_instance.parent.mkdir.assert_called_once_with(
                parents=True, exist_ok=True
            )
            mock_path_instance.write_text.assert_called_once_with('{"test": "result"}')
            mock_console.print.assert_called_with(
                "[green]Results written to:[/green] /resolved/output.json"
            )

    @pytest.mark.asyncio
    async def test_output_results_table_format(self):
        """Test output results in table format."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
        ):

            # Setup mocks
            mock_service = Mock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter.format_markdown.return_value = "table_content"
            mock_formatter_class.return_value = mock_formatter

            cli = CleanCLI()
            mock_result = Mock()

            await cli._output_results(mock_result, "markdown", None, False)

            mock_formatter.format_markdown.assert_called_once_with(mock_result)
            mock_console.print.assert_called_with("table_content")

    @pytest.mark.asyncio
    async def test_output_results_verbose_summary(self):
        """Test output results with verbose summary."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
        ):

            # Setup mocks
            mock_service = Mock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter.format_json.return_value = '{"test": "result"}'
            mock_formatter_class.return_value = mock_formatter

            cli = CleanCLI()
            mock_result = Mock()
            mock_result.threats = []
            mock_result.scan_metadata = {"scan_duration_ms": 1500}
            mock_result.get_statistics.return_value = {
                "total_threats": 3,
                "by_severity": {"high": 1, "medium": 2},
            }

            with patch.object(cli, "_print_summary") as mock_verbose:
                await cli._output_results(mock_result, "json", None, True)

                mock_verbose.assert_called_once_with(mock_result)

    def test_print_summary_with_threats(self):
        """Test print summary with threats."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
            patch("adversary_mcp_server.application.cli.clean_cli.Panel") as mock_panel,
            patch("adversary_mcp_server.application.cli.clean_cli.Table") as mock_table,
        ):

            # Setup mocks
            mock_service = Mock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            # Create mock threat
            mock_threat = Mock()
            mock_threat.severity = Mock()
            mock_threat.severity.__str__ = Mock(return_value="high")
            mock_threat.confidence = Mock()
            mock_threat.confidence.get_percentage = Mock(return_value=85.0)
            mock_threat.rule_name = "SQL Injection"
            mock_threat.file_path = "test.py"
            mock_threat.line_number = 10

            cli = CleanCLI()
            mock_result = Mock()
            mock_result.threats = [mock_threat]
            mock_result.get_statistics.return_value = {
                "total_threats": 1,
                "by_severity": {"high": 1, "medium": 0, "low": 0, "critical": 0},
            }
            mock_result.get_active_scanners.return_value = ["semgrep"]

            mock_table_instance = Mock()
            mock_table.return_value = mock_table_instance

            cli._print_summary(mock_result)

            # Should create and display summary
            mock_panel.assert_called()
            mock_console.print.assert_called()

    def test_print_summary_no_threats(self):
        """Test print summary with no threats."""
        with (
            patch(
                "adversary_mcp_server.application.cli.clean_cli.ScanApplicationService"
            ) as mock_service_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.DomainScanResultFormatter"
            ) as mock_formatter_class,
            patch(
                "adversary_mcp_server.application.cli.clean_cli.console"
            ) as mock_console,
            patch("adversary_mcp_server.application.cli.clean_cli.Panel") as mock_panel,
        ):

            # Setup mocks
            mock_service = Mock()
            mock_service_class.return_value = mock_service

            mock_formatter = Mock()
            mock_formatter_class.return_value = mock_formatter

            cli = CleanCLI()
            mock_result = Mock()
            mock_result.threats = []
            mock_result.get_statistics.return_value = {
                "total_threats": 0,
                "by_severity": {"high": 0, "medium": 0, "low": 0, "critical": 0},
            }
            mock_result.get_active_scanners.return_value = ["semgrep"]

            cli._print_summary(mock_result)

            # Should print summary
            mock_panel.assert_called()
            mock_console.print.assert_called()
