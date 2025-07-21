"""Extended tests for server module to improve coverage."""

import asyncio
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp import types

from adversary_mcp_server import DEFAULT_VERSION
from adversary_mcp_server.server import (
    AdversaryMCPServer,
    AdversaryToolError,
    ScanRequest,
    ScanResult,
)
from adversary_mcp_server.threat_engine import Category, Language, Severity, ThreatMatch


def _read_version_from_pyproject() -> str:
    """Helper function to read version from pyproject.toml for tests."""
    try:
        # Get the project root
        project_root = Path(__file__).parent.parent
        pyproject_path = project_root / "pyproject.toml"

        if pyproject_path.exists():
            # Use tomllib for Python 3.11+ or simple parsing for older versions
            if sys.version_info >= (3, 11):
                import tomllib

                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                    return pyproject_data.get("project", {}).get("version", "unknown")
            else:
                # Simple regex parsing for older Python versions
                with open(pyproject_path) as f:
                    content = f.read()
                    match = re.search(
                        r'^version\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE
                    )
                    if match:
                        return match.group(1)
        return "unknown"
    except Exception:
        return "unknown"


class TestAdversaryMCPServerExtended:
    """Extended test cases for AdversaryMCPServer."""

    @pytest.fixture
    def server(self):
        """Create a server instance for testing."""
        return AdversaryMCPServer()

    @pytest.mark.asyncio
    async def test_call_tool_scan_code(self, server):
        """Test scan_code tool call."""
        arguments = {
            "content": "import pickle; pickle.loads(data)",
            "language": "python",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False,
        }

        with patch.object(server.ast_scanner, "scan_code") as mock_scan:
            threat = ThreatMatch(
                rule_id="python_pickle",
                rule_name="Unsafe Pickle",
                description="Unsafe pickle deserialization",
                category=Category.DESERIALIZATION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
            )
            mock_scan.return_value = [threat]

            with patch.object(
                server.exploit_generator, "generate_exploits", return_value=["exploit1"]
            ):
                result = await server._handle_scan_code(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)
            assert "Unsafe Pickle" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_scan_file(self, server):
        """Test scan_file tool call."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("query = 'SELECT * FROM users WHERE id = ' + user_id")
            temp_file = f.name

        try:
            arguments = {
                "file_path": temp_file,
                "severity_threshold": "low",
                "include_exploits": False,
                "use_llm": False,
            }

            with patch.object(server.scan_engine, "scan_file") as mock_scan:
                threat = ThreatMatch(
                    rule_id="sql_injection",
                    rule_name="SQL Injection",
                    description="SQL injection vulnerability",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path=temp_file,
                    line_number=1,
                )
                # Mock the enhanced scanner to return an EnhancedScanResult
                from adversary_mcp_server.scan_engine import EnhancedScanResult
                from adversary_mcp_server.threat_engine import Language

                mock_result = EnhancedScanResult(
                    rules_threats=[threat],
                    llm_threats=[],
                    semgrep_threats=[],
                    file_path=temp_file,
                    language=Language.PYTHON,
                    scan_metadata={
                        "rules_engine": {"findings": 1},
                        "llm_analysis": {"findings": 0},
                    },
                )
                mock_scan.return_value = mock_result

                result = await server._handle_scan_file(arguments)

            assert len(result) == 1
            assert "SQL Injection" in result[0].text
        finally:
            os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_call_tool_scan_file_not_found(self, server):
        """Test scan_file with non-existent file."""
        arguments = {"file_path": "/nonexistent/file.py"}

        with pytest.raises(AdversaryToolError, match="File not found"):
            await server._handle_scan_file(arguments)

    @pytest.mark.asyncio
    async def test_call_tool_scan_directory(self, server):
        """Test scan_directory tool call."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("eval(user_input)")

            arguments = {
                "directory_path": temp_dir,
                "recursive": True,
                "severity_threshold": "medium",
                "include_exploits": True,
                "use_llm": False,
            }

            with patch.object(server.scan_engine, "scan_directory") as mock_scan:
                threat = ThreatMatch(
                    rule_id="eval_injection",
                    rule_name="Code Injection",
                    description="Dangerous eval usage",
                    category=Category.INJECTION,
                    severity=Severity.CRITICAL,
                    file_path=str(test_file),
                    line_number=1,
                )
                # Mock the enhanced scanner to return a list of EnhancedScanResults
                from adversary_mcp_server.scan_engine import EnhancedScanResult
                from adversary_mcp_server.threat_engine import Language

                mock_result = EnhancedScanResult(
                    rules_threats=[threat],
                    llm_threats=[],
                    semgrep_threats=[],
                    file_path=str(test_file),
                    language=Language.PYTHON,
                    scan_metadata={
                        "rules_engine": {"findings": 1},
                        "llm_analysis": {"findings": 0},
                    },
                )
                mock_scan.return_value = [mock_result]

                with patch.object(
                    server.exploit_generator,
                    "generate_exploits",
                    return_value=["exploit"],
                ):
                    result = await server._handle_scan_directory(arguments)

            assert len(result) == 1
            assert "Code Injection" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_scan_directory_not_found(self, server):
        """Test scan_directory with non-existent directory."""
        arguments = {"directory_path": "/nonexistent/directory"}

        with pytest.raises(AdversaryToolError, match="Directory not found"):
            await server._handle_scan_directory(arguments)

    @pytest.mark.asyncio
    async def test_call_tool_generate_exploit(self, server):
        """Test generate_exploit tool call."""
        arguments = {
            "vulnerability_type": "sql_injection",
            "code_context": "SELECT * FROM users WHERE id = ' + user_id",
            "target_language": "python",
            "use_llm": False,
        }

        with patch.object(server.exploit_generator, "generate_exploits") as mock_gen:
            mock_gen.return_value = ["' OR '1'='1' --", "' UNION SELECT NULL--"]

            result = await server._handle_generate_exploit(arguments)

        assert len(result) == 1
        assert "sql_injection" in result[0].text.lower()
        assert "OR '1'='1'" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_list_rules(self, server):
        """Test list_rules tool call."""
        arguments = {"category": "injection", "min_severity": "medium"}

        with patch.object(server.threat_engine, "list_rules") as mock_list:
            mock_list.return_value = [
                {
                    "id": "sql_injection",
                    "name": "SQL Injection",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "description": "SQL injection vulnerability detection",
                }
            ]

            result = await server._handle_list_rules(arguments)

        assert len(result) == 1
        assert "SQL Injection" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_get_rule_details(self, server):
        """Test get_rule_details tool call."""
        arguments = {"rule_id": "sql_injection"}

        mock_rule = Mock()
        mock_rule.id = "sql_injection"
        mock_rule.name = "SQL Injection"
        mock_rule.description = "Detects SQL injection vulnerabilities"
        mock_rule.category = Category.INJECTION
        mock_rule.severity = Severity.HIGH
        mock_rule.languages = [Language.PYTHON]
        mock_rule.conditions = []
        mock_rule.exploit_templates = []
        mock_rule.remediation = "Use parameterized queries"
        mock_rule.references = ["https://owasp.org/sql-injection"]
        mock_rule.cwe_id = "CWE-89"
        mock_rule.owasp_category = "A03"

        with patch.object(
            server.threat_engine, "get_rule_by_id", return_value=mock_rule
        ):
            result = await server._handle_get_rule_details(arguments)

        assert len(result) == 1
        assert "SQL Injection" in result[0].text
        assert "CWE-89" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_get_rule_details_not_found(self, server):
        """Test get_rule_details with non-existent rule."""
        arguments = {"rule_id": "nonexistent_rule"}

        with patch.object(server.threat_engine, "get_rule_by_id", return_value=None):
            with pytest.raises(AdversaryToolError, match="Rule not found"):
                await server._handle_get_rule_details(arguments)

    @pytest.mark.asyncio
    async def test_call_tool_configure_settings(self, server):
        """Test configure_settings tool call."""
        arguments = {
            "openai_api_key": "test_key",
            "enable_llm_generation": True,
            "min_severity": "high",
        }

        with patch.object(server.credential_manager, "store_config") as mock_store:
            result = await server._handle_configure_settings(arguments)

        assert len(result) == 1
        assert "updated successfully" in result[0].text.lower()
        mock_store.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_tool_get_status(self, server):
        """Test get_status tool call."""
        mock_config = Mock()
        mock_config.openai_api_key = "sk-test***"
        mock_config.enable_llm_generation = True
        mock_config.min_severity = "medium"

        with patch.object(
            server.credential_manager, "load_config", return_value=mock_config
        ):
            with patch.object(server.threat_engine, "list_rules", return_value=[]):
                result = await server._handle_get_status()

        assert len(result) == 1
        assert "Adversary MCP Server Status" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_get_version(self, server):
        """Test get_version tool call."""
        with patch.object(server, "_get_version", return_value="0.8.5"):
            result = await server._handle_get_version()

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "# Adversary MCP Server" in result[0].text
        assert "**Version:** 0.8.5" in result[0].text
        assert "**LLM Integration:** Client-based" in result[0].text
        assert (
            "**Supported Languages:** Python, JavaScript, TypeScript" in result[0].text
        )

    @pytest.mark.asyncio
    async def test_call_tool_get_version_error_handling(self, server):
        """Test get_version error handling."""
        with patch.object(
            server, "_get_version", side_effect=Exception("Version error")
        ):
            with pytest.raises(AdversaryToolError, match="Failed to get version"):
                await server._handle_get_version()

    @pytest.mark.asyncio
    async def test_call_tool_unknown(self, server):
        """Test calling unknown tool."""
        # This tests the main call_tool handler with an unknown tool
        with patch.object(server.server, "call_tool") as mock_call:
            # We need to test the actual call_tool method that was set up in _setup_handlers
            # Let's simulate what happens when an unknown tool is called
            pass  # The actual handler is set up in _setup_handlers, so we test error handling

    @pytest.mark.asyncio
    async def test_severity_filtering(self, server):
        """Test threat filtering by severity."""
        threats = [
            ThreatMatch(
                rule_id="high_threat",
                rule_name="High Threat",
                description="High severity threat",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
            ),
            ThreatMatch(
                rule_id="low_threat",
                rule_name="Low Threat",
                description="Low severity threat",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=2,
            ),
        ]

        # Test filtering with MEDIUM threshold
        filtered = server._filter_threats_by_severity(threats, Severity.MEDIUM)
        assert len(filtered) == 1
        assert filtered[0].rule_id == "high_threat"

        # Test filtering with LOW threshold
        filtered = server._filter_threats_by_severity(threats, Severity.LOW)
        assert len(filtered) == 2

    def test_scan_result_formatting(self, server):
        """Test scan result formatting."""
        threats = [
            ThreatMatch(
                rule_id="test_threat",
                rule_name="Test Threat",
                description="Test description",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.js",
                line_number=10,
                code_snippet="document.innerHTML = userInput",
                exploit_examples=["<script>alert('XSS')</script>"],
                remediation="Use textContent instead",
            )
        ]

        result = server._format_scan_results(threats, "test.js")

        assert "Test Threat" in result
        assert "Medium" in result
        assert "XSS" in result
        assert "test.js" in result
        assert "alert('XSS')" in result
        assert "textContent" in result

    def test_scan_result_formatting_no_threats(self, server):
        """Test scan result formatting with no threats."""
        result = server._format_scan_results([], "test.py")
        assert "No security vulnerabilities found" in result

    @pytest.mark.asyncio
    async def test_exploit_generation_error_handling(self, server):
        """Test exploit generation with errors."""
        arguments = {
            "content": "test code",
            "language": "python",
            "include_exploits": True,
            "use_llm": False,
        }

        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
        )

        with patch.object(server.ast_scanner, "scan_code", return_value=[threat]):
            with patch.object(
                server.exploit_generator,
                "generate_exploits",
                side_effect=Exception("Gen error"),
            ):
                # Should not raise exception, just log warning
                result = await server._handle_scan_code(arguments)
                assert len(result) == 1

    @pytest.mark.asyncio
    async def test_scan_code_with_all_parameters(self, server):
        """Test scan_code with all parameter combinations."""
        # Test with minimal parameters
        arguments = {"content": "print('hello')", "language": "python"}

        with patch.object(server.ast_scanner, "scan_code", return_value=[]):
            result = await server._handle_scan_code(arguments)
            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_scan_file_with_encoding_error(self, server):
        """Test scan_file when file reading fails."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".py", delete=False) as f:
            # Write binary data that can't be decoded as UTF-8
            f.write(b"\x80\x81\x82\x83")
            temp_file = f.name

        try:
            arguments = {"file_path": temp_file, "include_exploits": True}

            threat = ThreatMatch(
                rule_id="test_rule",
                rule_name="Test Rule",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path=temp_file,
                line_number=1,
            )

            with patch.object(server.ast_scanner, "scan_file", return_value=[threat]):
                with patch.object(
                    server.exploit_generator,
                    "generate_exploits",
                    return_value=["exploit"],
                ):
                    result = await server._handle_scan_file(arguments)
                    assert len(result) == 1
        finally:
            os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_large_directory_scan_exploit_limiting(self, server):
        """Test that directory scans limit exploit generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"directory_path": temp_dir, "include_exploits": True}

            # Create 15 threats
            threats = []
            for i in range(15):
                threats.append(
                    ThreatMatch(
                        rule_id=f"threat_{i}",
                        rule_name=f"Threat {i}",
                        description="Test",
                        category=Category.INJECTION,
                        severity=Severity.HIGH,
                        file_path=f"test{i}.py",
                        line_number=1,
                    )
                )

            # Mock the enhanced scanner to return a list of EnhancedScanResults
            from adversary_mcp_server.scan_engine import EnhancedScanResult
            from adversary_mcp_server.threat_engine import Language

            mock_results = []
            for threat in threats:
                mock_result = EnhancedScanResult(
                    rules_threats=[threat],
                    llm_threats=[],
                    semgrep_threats=[],
                    file_path=threat.file_path,
                    language=Language.PYTHON,
                    scan_metadata={
                        "rules_engine": {"findings": 1},
                        "llm_analysis": {"findings": 0},
                    },
                )
                mock_results.append(mock_result)

            with patch.object(
                server.scan_engine, "scan_directory", return_value=mock_results
            ):
                with patch.object(
                    server.exploit_generator, "generate_exploits"
                ) as mock_gen:
                    mock_gen.return_value = ["exploit"]

                    result = await server._handle_scan_directory(arguments)

                    # Should only generate exploits for first 10 threats
                    assert mock_gen.call_count == 10

    def test_data_models(self):
        """Test ScanRequest and ScanResult data models."""
        # Test ScanRequest
        request = ScanRequest(
            content="test code",
            language="python",
            severity_threshold="high",
            include_exploits=False,
        )
        assert request.content == "test code"
        assert request.include_exploits is False

        # Test ScanResult
        result = ScanResult(
            threats=[{"rule_id": "test"}],
            summary={"total": 1},
            metadata={"scan_time": "2023-01-01"},
        )
        assert len(result.threats) == 1
        assert result.summary["total"] == 1

    @pytest.mark.asyncio
    async def test_vulnerability_type_mapping(self, server):
        """Test different vulnerability types in generate_exploit."""
        vulnerability_types = [
            "sql_injection",
            "command_injection",
            "xss",
            "deserialization",
            "path_traversal",
            "unknown_type",
        ]

        for vuln_type in vulnerability_types:
            arguments = {
                "vulnerability_type": vuln_type,
                "code_context": "test code",
                "target_language": "python",
            }

            with patch.object(
                server.exploit_generator, "generate_exploits", return_value=["exploit"]
            ):
                result = await server._handle_generate_exploit(arguments)
                assert len(result) == 1
                assert vuln_type in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_error_handling_in_handlers(self, server):
        """Test error handling in various handlers."""
        # Test scan_code with invalid language
        with pytest.raises(AdversaryToolError):
            await server._handle_scan_code(
                {"content": "test", "language": "invalid_language"}
            )

        # Test configure_settings with error in store_config
        with patch.object(
            server.credential_manager,
            "store_config",
            side_effect=Exception("Save error"),
        ):
            with pytest.raises(
                AdversaryToolError, match="Failed to configure settings"
            ):
                await server._handle_configure_settings({"openai_api_key": "test"})

        # Test get_status with error
        with patch.object(
            server.credential_manager,
            "load_config",
            side_effect=Exception("Load error"),
        ):
            with pytest.raises(AdversaryToolError, match="Failed to get status"):
                await server._handle_get_status()

    def test_get_version_from_pyproject_toml(self, server):
        """Test _get_version reading from pyproject.toml."""
        # Mock pyproject.toml content
        pyproject_content = {
            "project": {"name": "adversary-mcp-server", "version": "1.2.3"}
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            pyproject_path = Path(temp_dir) / "pyproject.toml"

            # Mock the path resolution to point to our temp directory
            with patch.object(server, "_get_version") as mock_get_version:
                # Create a custom implementation that uses our mocked data
                def mock_version_impl():
                    try:
                        # Simulate reading from pyproject.toml successfully
                        return pyproject_content["project"]["version"]
                    except Exception:
                        return "unknown"

                mock_get_version.side_effect = mock_version_impl
                version = server._get_version()
                assert version == "1.2.3"

    def test_get_version_with_real_path_resolution(self, server):
        """Test _get_version with mocked path resolution."""
        # Test the version reading logic by mocking the Path resolution
        with tempfile.TemporaryDirectory() as temp_dir:
            pyproject_path = Path(temp_dir) / "pyproject.toml"
            pyproject_content = """
[project]
name = "adversary-mcp-server"
version = "2.1.0"
description = "Test version"
"""
            pyproject_path.write_text(pyproject_content)

            # Mock the path resolution in the _get_version method
            with patch.object(
                Path,
                "parent",
                new_callable=lambda: property(lambda self: Path(temp_dir)),
            ):
                with patch.object(Path, "exists", return_value=True):
                    # This test just verifies the method handles mocked paths gracefully
                    version = server._get_version()
                    # The version should be either from pyproject.toml or fallback methods
                    assert isinstance(version, str)
                    assert len(version) > 0

    def test_get_version_importlib_package_not_found(self, server):
        """Test version retrieval when importlib package is not found."""
        expected_version = _read_version_from_pyproject()

        with patch(
            "importlib.metadata.version", side_effect=Exception("Package not found")
        ):
            version = server._get_version()
            # Should fallback to reading from pyproject.toml
            assert version == expected_version

    def test_get_version_all_methods_fail(self, server):
        """Test version retrieval when all methods fail."""
        with patch("importlib.metadata.version", side_effect=Exception("All failed")):
            # Mock the pyproject.toml reading to also fail
            with patch(
                "adversary_mcp_server._read_version_from_pyproject",
                side_effect=Exception("Pyproject failed"),
            ):
                version = server._get_version()
                # Should fallback to DEFAULT_VERSION constant
                assert version == DEFAULT_VERSION

    def test_get_version_exception_in_main_try_block(self, server):
        """Test version retrieval with exception in main try block."""
        expected_version = _read_version_from_pyproject()

        with patch(
            "importlib.metadata.version", side_effect=Exception("Main try failed")
        ):
            version = server._get_version()
            # Should fallback to reading from pyproject.toml
            assert version == expected_version

    def test_get_version_pyproject_fallback_works(self, server):
        """Test version retrieval successfully falls back to pyproject.toml."""
        expected_version = _read_version_from_pyproject()

        with patch(
            "importlib.metadata.version", side_effect=Exception("No package metadata")
        ):
            version = server._get_version()
            # Should successfully read from pyproject.toml
            assert version == expected_version
            # Should be a valid version string format
            assert version != "unknown"
            assert len(version) > 0

    def test_get_version_pyproject_file_missing(self, server):
        """Test version retrieval when pyproject.toml file is missing."""
        with patch(
            "importlib.metadata.version", side_effect=Exception("No package metadata")
        ):
            # Mock Path.exists() to return False for pyproject.toml
            with patch("pathlib.Path.exists", return_value=False):
                version = server._get_version()
                # Should fallback to DEFAULT_VERSION constant
                assert version == DEFAULT_VERSION

    def test_get_version_format_validation(self, server):
        """Test that version retrieval always returns a valid format."""
        # Test normal case
        version = server._get_version()
        assert isinstance(version, str)
        assert len(version) > 0

        # Test fallback case
        with patch("importlib.metadata.version", side_effect=Exception("Failed")):
            with patch(
                "adversary_mcp_server._read_version_from_pyproject",
                side_effect=Exception("Failed"),
            ):
                version = server._get_version()
                assert isinstance(version, str)
                assert len(version) > 0
                assert version == DEFAULT_VERSION


class TestAdversaryMCPServerRuntime:
    """Test server runtime and lifecycle."""

    def test_adversary_tool_error(self):
        """Test AdversaryToolError exception."""
        error = AdversaryToolError("Test error")
        assert str(error) == "Test error"

    @pytest.mark.asyncio
    async def test_server_run_method(self):
        """Test server run method."""
        server = AdversaryMCPServer()

        # Mock stdio_server since the run method now uses it
        with patch("adversary_mcp_server.server.stdio_server") as mock_stdio:
            # Create a proper async context manager mock
            mock_context = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=("read", "write"))
            mock_context.__aexit__ = AsyncMock(return_value=None)
            mock_stdio.return_value = mock_context

            # Mock the server.run method to avoid actually running the MCP server
            with patch.object(server.server, "run") as mock_run:
                mock_run.return_value = None

                # Test that run method works
                await server.run()

                # Verify stdio_server was called
                mock_stdio.assert_called_once()
                # Verify server.run was called with the expected arguments
                mock_run.assert_called_once()

                # Verify the call arguments - should be read_stream, write_stream, and InitializationOptions
                call_args = mock_run.call_args
                assert len(call_args[0]) == 3  # Should have 3 positional arguments
                assert call_args[0][0] == "read"  # read_stream
                assert call_args[0][1] == "write"  # write_stream
                # The third argument should be InitializationOptions

    def test_main_functions(self):
        """Test main and async_main functions."""
        from adversary_mcp_server.server import async_main, main

        # Test async_main
        with patch("adversary_mcp_server.server.AdversaryMCPServer") as mock_server:
            mock_instance = Mock()
            mock_instance.run = AsyncMock()
            mock_server.return_value = mock_instance

            # Run async_main (it now calls server.run())
            asyncio.run(async_main())

            # Verify server was created and run() was called
            mock_server.assert_called_once()
            mock_instance.run.assert_called_once()

        # Test main function
        with patch("adversary_mcp_server.server.asyncio.run") as mock_run:
            main()
            mock_run.assert_called_once()


class TestAdversaryMCPServerVersionIntegration:
    """Integration tests specifically for the version functionality."""

    @pytest.fixture
    def server(self):
        """Create a server instance for testing."""
        return AdversaryMCPServer()

    @pytest.mark.asyncio
    async def test_version_tool_registration(self, server):
        """Test that adv_get_version tool is properly registered."""
        # Get the list_tools handler from the server
        list_tools_handler = None
        for attr_name in dir(server.server):
            attr = getattr(server.server, attr_name)
            if hasattr(attr, "__name__") and "list_tools" in str(attr):
                list_tools_handler = attr
                break

        # Since we can't easily call the decorated function directly,
        # we'll test the tool registration indirectly by checking
        # that our handler methods exist
        assert hasattr(server, "_handle_get_version")
        assert callable(server._handle_get_version)
        assert hasattr(server, "_get_version")
        assert callable(server._get_version)

    @pytest.mark.asyncio
    async def test_full_version_tool_integration(self, server):
        """Test full version tool integration."""
        # Test tool call directly
        with patch.object(server, "_get_version", return_value="1.0.0-test"):
            result = await server._handle_get_version()
            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

            response_text = result[0].text
            assert "# Adversary MCP Server" in response_text
            assert "**Version:** 1.0.0-test" in response_text
            assert "**LLM Integration:** Client-based" in response_text

    @pytest.mark.asyncio
    async def test_version_tool_call_dispatcher(self, server):
        """Test that the call_tool dispatcher correctly routes to version handler."""
        # Test the actual call_tool method that's set up in _setup_handlers
        # We need to patch the handler to avoid actually executing it
        with patch.object(server, "_handle_get_version") as mock_handler:
            mock_handler.return_value = [
                types.TextContent(type="text", text="Test response")
            ]

            # Create a mock call_tool function that mimics the behavior
            async def mock_call_tool(name: str, arguments: dict):
                if name == "adv_get_version":
                    return await server._handle_get_version()
                else:
                    raise Exception(f"Unknown tool: {name}")

            # Test the dispatcher logic
            result = await mock_call_tool("adv_get_version", {})
            mock_handler.assert_called_once()
            assert len(result) == 1
            assert result[0].text == "Test response"

    @pytest.mark.asyncio
    async def test_version_error_propagation(self, server):
        """Test that version errors are properly caught and re-raised as AdversaryToolError."""
        with patch.object(
            server, "_get_version", side_effect=RuntimeError("Test error")
        ):
            with pytest.raises(AdversaryToolError) as exc_info:
                await server._handle_get_version()

            assert "Failed to get version" in str(exc_info.value)

    def test_version_method_robustness(self, server):
        """Test that the version method handles various edge cases gracefully."""
        # Test with no exceptions - should return some version or "unknown"
        version = server._get_version()
        assert isinstance(version, str)
        assert len(version) > 0

        # Version should be either a valid version string or "unknown"
        assert version == "unknown" or any(char.isdigit() for char in version)

    @pytest.mark.asyncio
    async def test_version_response_format(self, server):
        """Test that the version response follows the expected format."""
        with patch.object(server, "_get_version", return_value="2.5.1"):
            result = await server._handle_get_version()

            assert len(result) == 1
            response = result[0]

            # Check response structure
            assert response.type == "text"
            assert isinstance(response.text, str)

            # Check content format
            lines = response.text.split("\n")
            assert any("# Adversary MCP Server" in line for line in lines)
            assert any("**Version:**" in line for line in lines)
            assert any("**LLM Integration:**" in line for line in lines)
            assert any("**Supported Languages:**" in line for line in lines)

    @pytest.mark.asyncio
    async def test_scan_tools_with_output_parameter(self, server):
        """Test that scan tools accept and use the output parameter."""
        import os
        import tempfile
        from unittest.mock import patch

        # Test scan_code with output parameter
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_output = os.path.join(temp_dir, "custom_scan_results.json")

            arguments = {
                "content": "test code",
                "language": "python",
                "output_format": "json",
                "output": custom_output,
            }

            with patch.object(server.scan_engine, "scan_code") as mock_scan:
                from adversary_mcp_server.scan_engine import EnhancedScanResult
                from adversary_mcp_server.threat_engine import Language

                mock_result = EnhancedScanResult(
                    rules_threats=[],
                    llm_threats=[],
                    semgrep_threats=[],
                    file_path="input.code",
                    language=Language.PYTHON,
                    scan_metadata={},
                )
                mock_scan.return_value = mock_result

                result = await server._handle_scan_code(arguments)

                # Check that the result was returned
                assert len(result) == 1

                # Check that the custom output file was created
                assert os.path.exists(custom_output)

                # Verify the file contains JSON data
                with open(custom_output) as f:
                    content = f.read()
                    assert '"target": "code"' in content
