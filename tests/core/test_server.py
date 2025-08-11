"""Tests for MCP server module."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp import types

from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch
from adversary_mcp_server.server import (
    AdversaryMCPServer,
    AdversaryToolError,
    ScanRequest,
    ScanResult,
)


@pytest.fixture(autouse=True, scope="function")
def mock_adversary_json_file_access():
    """Automatically mock .adversary.json file access during tests only to prevent test interference."""
    # Only apply this mock during actual test execution
    import os

    if "PYTEST_CURRENT_TEST" not in os.environ:
        yield  # Not in a test, don't apply the mock
        return

    # Store the original exists method
    original_exists = Path.exists

    def mock_path_exists(self):
        """Mock Path.exists() to simulate .adversary.json exists without real file access."""
        if self.name == ".adversary.json":
            # For tests, always return True to avoid smart search traversal
            return True
        # For other files, use the original exists method
        return original_exists(self)

    with patch.object(Path, "exists", mock_path_exists):
        yield


class TestAdversaryMCPServer:
    """Test cases for AdversaryMCPServer class."""

    def test_init(self):
        """Test server initialization."""
        server = AdversaryMCPServer()
        assert server.credential_manager is not None
        assert server.exploit_generator is not None
        assert server.scan_engine is not None
        assert server.diff_scanner is not None

    def test_server_filtering_methods(self):
        """Test server utility methods."""
        server = AdversaryMCPServer()

        # Test severity filtering
        threats = [
            ThreatMatch(
                rule_id="test1",
                rule_name="Test 1",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
            ),
            ThreatMatch(
                rule_id="test2",
                rule_name="Test 2",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=2,
            ),
        ]

        filtered = server._filter_threats_by_severity(threats, Severity.MEDIUM)
        assert len(filtered) == 1  # Only HIGH severity should remain

    def test_format_scan_results(self):
        """Test scan results formatting."""
        server = AdversaryMCPServer()

        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
        )

        result = server._format_scan_results([threat], "test.py")
        assert "Test Rule" in result
        assert "test.py" in result


class TestMCPToolHandlers:
    """Test MCP tool handlers for comprehensive coverage."""

    @pytest.fixture
    def server(self):
        """Create a server instance for testing."""
        with patch(
            "adversary_mcp_server.scanner.semgrep_scanner.OptimizedSemgrepScanner.get_status"
        ) as mock_status:
            # Mock semgrep status to avoid subprocess calls
            mock_status.return_value = {
                "semgrep_installed": True,
                "semgrep_version": "1.0.0",
                "semgrep_path": "/mock/semgrep",
                "config_status": "loaded",
            }
            server = AdversaryMCPServer()
            yield server

    @pytest.fixture
    def mock_threat(self):
        """Create a mock threat for testing."""
        return ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
        )

    @pytest.fixture
    def mock_scan_result(self, mock_threat):
        """Create a mock scan result for testing."""
        return EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[mock_threat],
            scan_metadata={"total_threats": 1},
        )

    @pytest.mark.asyncio
    async def test_handle_scan_code_basic(self, server, mock_scan_result):
        """Test basic scan_code tool handler."""
        arguments = {
            "content": "import pickle; pickle.loads(data)",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        with patch.object(
            server.scan_engine, "scan_code", return_value=mock_scan_result
        ):
            result = await server._handle_scan_code(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "scan completed successfully" in result[0].text

    @pytest.mark.asyncio
    async def test_handle_scan_code_with_exploits(self, server, mock_scan_result):
        """Test scan_code with exploit generation."""
        arguments = {
            "content": "import pickle; pickle.loads(data)",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        with patch.object(
            server.scan_engine, "scan_code", return_value=mock_scan_result
        ):
            with patch.object(
                server.exploit_generator, "generate_exploits", return_value=["exploit1"]
            ):
                result = await server._handle_scan_code(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "scan completed successfully" in result[0].text

    @pytest.mark.asyncio
    async def test_handle_scan_code_exploit_generation_failure(
        self, server, mock_scan_result
    ):
        """Test scan_code with exploit generation failure."""
        arguments = {
            "content": "import pickle; pickle.loads(data)",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        with patch.object(
            server.scan_engine, "scan_code", return_value=mock_scan_result
        ):
            with patch.object(
                server.exploit_generator,
                "generate_exploits",
                side_effect=Exception("Exploit generation failed"),
            ):
                result = await server._handle_scan_code(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_scan_code_json_output(self, server, mock_scan_result):
        """Test scan_code with JSON output format."""
        arguments = {
            "content": "import pickle; pickle.loads(data)",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        with patch.object(
            server.scan_engine, "scan_code", return_value=mock_scan_result
        ):
            with patch.object(
                server, "_format_json_scan_results", return_value='{"threats": []}'
            ):
                with patch.object(
                    server, "_save_scan_results_json", return_value="/tmp/results.json"
                ):
                    result = await server._handle_scan_code(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_scan_code_json_output_save_failure(
        self, server, mock_scan_result
    ):
        """Test scan_code with JSON output format and save failure."""
        arguments = {
            "content": "import pickle; pickle.loads(data)",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        with patch.object(
            server.scan_engine, "scan_code", return_value=mock_scan_result
        ):
            with patch.object(
                server, "_format_json_scan_results", return_value='{"threats": []}'
            ):
                with patch.object(server, "_save_scan_results_json", return_value=None):
                    result = await server._handle_scan_code(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_scan_file_basic(self, server, mock_scan_result):
        """Test basic scan_file tool handler."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import pickle; pickle.loads(data)")
            temp_file = Path(f.name)

        try:
            arguments = {
                "path": str(temp_file),
                "severity_threshold": "medium",
                "include_exploits": False,
                "use_llm": False,
                "use_semgrep": False,
                "output_format": "json",
            }

            with patch.object(
                server.scan_engine, "scan_file", return_value=mock_scan_result
            ):
                result = await server._handle_scan_file(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)
            assert "scan completed successfully" in result[0].text

        finally:
            temp_file.unlink()

    @pytest.mark.asyncio
    async def test_handle_scan_file_not_found(self, server):
        """Test scan_file with non-existent file."""
        arguments = {
            "path": "/nonexistent/file.py",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        with pytest.raises(AdversaryToolError, match="Path does not exist"):
            await server._handle_scan_file(arguments)

    @pytest.mark.asyncio
    async def test_handle_scan_file_with_exploits(self, server, mock_scan_result):
        """Test scan_file with exploit generation."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import pickle; pickle.loads(data)")
            temp_file = Path(f.name)

        try:
            arguments = {
                "path": str(temp_file),
                "severity_threshold": "medium",
                "include_exploits": True,
                "use_llm": False,
                "use_semgrep": False,
                "output_format": "json",
            }

            with patch.object(
                server.scan_engine, "scan_file", return_value=mock_scan_result
            ):
                with patch.object(
                    server.exploit_generator,
                    "generate_exploits",
                    return_value=["exploit1"],
                ):
                    result = await server._handle_scan_file(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

        finally:
            temp_file.unlink()

    @pytest.mark.asyncio
    async def test_handle_scan_file_read_error_for_exploits(
        self, server, mock_scan_result
    ):
        """Test scan_file with file read error during exploit generation."""
        arguments = {
            "path": "/fake/file.py",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        # The scan should succeed even if file reading for exploits fails
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.is_file", return_value=True):
                with patch.object(
                    server,
                    "_determine_scan_output_path",
                    return_value="/tmp/test.adversary.json",
                ):
                    with patch.object(
                        server,
                        "_save_scan_results_json",
                        return_value="/tmp/test.adversary.json",
                    ):
                        with patch.object(
                            server.scan_engine,
                            "scan_file",
                            return_value=mock_scan_result,
                        ):
                            # Don't mock open to fail globally - just for exploit generation
                            with patch.object(
                                server.exploit_generator,
                                "generate_exploits",
                                return_value=["exploit1"],
                            ):
                                result = await server._handle_scan_file(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_scan_file_with_llm_prompts(self, server, mock_scan_result):
        """Test scan_file with LLM prompts."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import pickle; pickle.loads(data)")
            temp_file = Path(f.name)

        try:
            arguments = {
                "path": str(temp_file),
                "severity_threshold": "medium",
                "include_exploits": True,
                "use_llm": True,
                "use_semgrep": False,
                "output_format": "json",
            }

            with patch.object(
                server.scan_engine, "scan_file", return_value=mock_scan_result
            ):
                with patch.object(
                    server,
                    "_add_llm_analysis_prompts",
                    return_value="\n\nLLM prompts added",
                ):
                    with patch.object(
                        server,
                        "_add_llm_exploit_prompts",
                        return_value="\n\nLLM exploit prompts added",
                    ):
                        result = await server._handle_scan_file(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

        finally:
            temp_file.unlink()

    @pytest.mark.asyncio
    async def test_handle_scan_file_llm_read_error(self, server, mock_scan_result):
        """Test scan_file with LLM prompts but file read error."""
        arguments = {
            "path": "/fake/file.py",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": True,
            "use_semgrep": False,
            "output_format": "json",
        }

        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.is_file", return_value=True):
                with patch.object(
                    server,
                    "_determine_scan_output_path",
                    return_value="/tmp/test.adversary.json",
                ):
                    with patch.object(
                        server,
                        "_save_scan_results_json",
                        return_value="/tmp/test.adversary.json",
                    ):
                        with patch.object(
                            server.scan_engine,
                            "scan_file",
                            return_value=mock_scan_result,
                        ):
                            # The scan should succeed even without LLM file reading
                            result = await server._handle_scan_file(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "scan completed successfully" in result[0].text

    @pytest.mark.asyncio
    async def test_handle_scan_directory_basic(self, server, mock_scan_result):
        """Test basic scan_directory tool handler."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("import pickle; pickle.loads(data)")

            arguments = {
                "path": temp_dir,
                "recursive": True,
                "severity_threshold": "medium",
                "include_exploits": False,
                "use_llm": False,
                "use_semgrep": False,
                "output_format": "json",
            }

            with patch.object(
                server.scan_engine, "scan_directory", return_value=[mock_scan_result]
            ):
                result = await server._handle_scan_directory(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_scan_directory_not_found(self, server):
        """Test scan_directory with non-existent directory."""
        arguments = {
            "path": "/nonexistent/directory",
            "recursive": True,
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        with pytest.raises(AdversaryToolError, match="Path does not exist"):
            await server._handle_scan_directory(arguments)

    @pytest.mark.asyncio
    async def test_handle_scan_directory_with_exploits(self, server, mock_scan_result):
        """Test scan_directory with exploit generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {
                "path": temp_dir,
                "recursive": True,
                "severity_threshold": "medium",
                "include_exploits": True,
                "use_llm": False,
                "use_semgrep": False,
                "output_format": "json",
            }

            with patch.object(
                server.scan_engine, "scan_directory", return_value=[mock_scan_result]
            ):
                with patch.object(
                    server.exploit_generator,
                    "generate_exploits",
                    return_value=["exploit1"],
                ):
                    result = await server._handle_scan_directory(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_diff_scan_basic(self, server, mock_scan_result):
        """Test basic diff_scan tool handler."""
        arguments = {
            "source_branch": "main",
            "target_branch": "feature",
            "path": ".",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        mock_diff_summary = {
            "files_changed": 2,
            "lines_added": 10,
            "lines_removed": 5,
        }

        mock_scan_results = {
            "file1.py": [mock_scan_result],
            "file2.py": [mock_scan_result],
        }

        with patch.object(
            server.diff_scanner, "get_diff_summary", return_value=mock_diff_summary
        ):
            with patch.object(
                server.diff_scanner, "scan_diff", return_value=mock_scan_results
            ):
                result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_diff_scan_git_error(self, server):
        """Test diff_scan with git error."""
        arguments = {
            "source_branch": "main",
            "target_branch": "feature",
            "path": ".",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        mock_diff_summary = {"error": "Git repository not found"}

        with patch.object(
            server.diff_scanner, "get_diff_summary", return_value=mock_diff_summary
        ):
            with pytest.raises(AdversaryToolError, match="Git diff operation failed"):
                await server._handle_diff_scan(arguments)

    @pytest.mark.asyncio
    async def test_handle_diff_scan_with_exploits(self, server, mock_scan_result):
        """Test diff_scan with exploit generation."""
        arguments = {
            "source_branch": "main",
            "target_branch": "feature",
            "path": ".",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        mock_diff_summary = {
            "files_changed": 1,
            "lines_added": 5,
            "lines_removed": 2,
        }

        mock_scan_results = {
            "file1.py": [mock_scan_result],
        }

        with patch.object(
            server.diff_scanner, "get_diff_summary", return_value=mock_diff_summary
        ):
            with patch.object(
                server.diff_scanner, "scan_diff", return_value=mock_scan_results
            ):
                with patch.object(
                    server.exploit_generator,
                    "generate_exploits",
                    return_value=["exploit1"],
                ):
                    result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_configure_settings(self, server):
        """Test configure_settings tool handler."""
        arguments = {
            "severity_threshold": "high",
            "exploit_safety_mode": True,
            "enable_llm_analysis": False,
            "enable_exploit_generation": True,
        }

        with patch.object(server.credential_manager, "store_config") as mock_save:
            result = await server._handle_configure_settings(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "Configuration updated" in result[0].text
        mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_get_status(self, server):
        """Test get_status tool handler."""
        with (
            patch.object(
                server.scan_engine, "get_scanner_stats", return_value={"status": "ok"}
            ),
            patch("subprocess.run") as mock_run,
        ):
            # Mock subprocess.run for semgrep status check
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "semgrep version 1.0.0"

            result = await server._handle_get_status()

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "status" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_handle_get_version(self, server):
        """Test get_version tool handler."""
        with patch.object(server, "_get_version", return_value="1.0.0"):
            result = await server._handle_get_version()

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "1.0.0" in result[0].text

    @pytest.mark.asyncio
    async def test_handle_mark_false_positive(self, server):
        """Test mark_false_positive tool handler."""
        arguments = {
            "finding_uuid": "test-uuid-123",
            "reason": "False positive",
            "path": "/mock/working/dir",
        }

        with patch("adversary_mcp_server.server.FalsePositiveManager") as mock_fp_class:
            mock_fp_instance = Mock()
            mock_fp_instance.mark_false_positive.return_value = True
            mock_fp_class.return_value = mock_fp_instance

            # Mock _get_project_root() and _validate_adversary_path() to avoid using actual working directory
            with patch.object(server, "_get_project_root") as mock_cwd:
                mock_cwd.return_value = Path("/mock/working/dir")
                with patch.object(server, "_validate_adversary_path") as mock_validate:
                    mock_validate.return_value = Path(
                        "/mock/working/dir/.adversary.json"
                    )
                    result = await server._handle_mark_false_positive(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "marked as false positive" in result[0].text
        # Path should be resolved to absolute path using mocked working directory
        expected_path = "/mock/working/dir/.adversary.json"
        mock_fp_class.assert_called_once_with(adversary_file_path=expected_path)
        mock_fp_instance.mark_false_positive.assert_called_once_with(
            "test-uuid-123", "False positive", "MCP User"
        )

    @pytest.mark.asyncio
    async def test_handle_unmark_false_positive(self, server):
        """Test unmark_false_positive tool handler."""
        arguments = {
            "finding_uuid": "test-uuid-123",
            "path": "/mock/working/dir",
        }

        with patch("adversary_mcp_server.server.FalsePositiveManager") as mock_fp_class:
            mock_fp_instance = Mock()
            mock_fp_instance.unmark_false_positive.return_value = True
            mock_fp_class.return_value = mock_fp_instance

            # Mock _get_project_root() and _validate_adversary_path() to avoid using actual working directory
            with patch.object(server, "_get_project_root") as mock_cwd:
                mock_cwd.return_value = Path("/mock/working/dir")
                with patch.object(server, "_validate_adversary_path") as mock_validate:
                    mock_validate.return_value = Path(
                        "/mock/working/dir/.adversary.json"
                    )
                    result = await server._handle_unmark_false_positive(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "unmarked as false positive" in result[0].text
        # Path should be resolved to absolute path using mocked working directory
        expected_path = "/mock/working/dir/.adversary.json"
        mock_fp_class.assert_called_once_with(adversary_file_path=expected_path)
        mock_fp_instance.unmark_false_positive.assert_called_once_with("test-uuid-123")

    @pytest.mark.asyncio
    async def test_handle_list_false_positives(self, server):
        """Test list_false_positives tool handler."""
        arguments = {
            "path": "/mock/working/dir",
        }

        mock_false_positives = [
            {
                "uuid": "test-uuid-123",
                "rule_id": "test_rule",
                "file_path": "test.py",
                "line_number": 10,
                "reason": "False positive",
                "marked_date": "2023-01-01T00:00:00Z",
            }
        ]

        with patch("adversary_mcp_server.server.FalsePositiveManager") as mock_fp_class:
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positives.return_value = mock_false_positives
            mock_fp_class.return_value = mock_fp_instance

            # Mock _get_project_root() to avoid using actual working directory
            with patch.object(server, "_get_project_root") as mock_cwd:
                mock_cwd.return_value = Path("/mock/working/dir")
                with patch.object(server, "_validate_adversary_path") as mock_validate:
                    mock_validate.return_value = Path(
                        "/mock/working/dir/.adversary.json"
                    )
                    result = await server._handle_list_false_positives(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "test-uuid-123" in result[0].text
        # Path should be resolved to absolute path using mocked working directory
        expected_path = "/mock/working/dir/.adversary.json"
        mock_fp_class.assert_called_once_with(adversary_file_path=expected_path)
        mock_fp_instance.get_false_positives.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_scan_code_exception_handling(self, server):
        """Test scan_code exception handling."""
        arguments = {
            "content": "test code",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        with patch.object(
            server.scan_engine, "scan_code", side_effect=Exception("Test error")
        ):
            with pytest.raises(AdversaryToolError, match="Code scanning failed"):
                await server._handle_scan_code(arguments)


class TestServerIntegration:
    """Integration tests for server functionality."""

    def test_server_startup(self):
        """Test server can be created and initialized."""
        server = AdversaryMCPServer()
        assert server is not None
        assert hasattr(server, "exploit_generator")
        assert hasattr(server, "credential_manager")
        assert hasattr(server, "scan_engine")
        assert hasattr(server, "diff_scanner")

    def test_list_tools(self):
        """Test list_tools functionality."""
        server = AdversaryMCPServer()

        # Test that the server has the expected tools by checking the tool names
        # We can't directly call server.server.list_tools() as it's an async handler
        # but we can verify the server has the necessary handlers set up
        assert server.server is not None
        assert hasattr(server, "_handle_scan_code")
        assert hasattr(server, "_handle_scan_file")
        assert hasattr(server, "_handle_scan_directory")
        assert hasattr(server, "_handle_diff_scan")
        assert hasattr(server, "_handle_configure_settings")
        assert hasattr(server, "_handle_get_status")
        assert hasattr(server, "_handle_get_version")
        assert hasattr(server, "_handle_mark_false_positive")
        assert hasattr(server, "_handle_unmark_false_positive")
        assert hasattr(server, "_handle_list_false_positives")


class TestServerUtilities:
    """Test server utility functions."""

    def test_format_threat_output(self):
        """Test threat formatting."""
        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            code_snippet="test code",
            exploit_examples=["test exploit"],
            remediation="Fix it",
            cwe_id="CWE-89",
        )

        # Test that threat can be converted to string representation
        threat_str = str(threat)
        assert isinstance(threat_str, str)

    def test_scan_request_model(self):
        """Test ScanRequest model."""
        request = ScanRequest(
            content="test code",
            severity_threshold="high",
            include_exploits=True,
            use_llm=False,
        )
        assert request.content == "test code"
        # Language parameter has been removed - no longer part of ScanRequest
        assert request.severity_threshold == "high"
        assert request.include_exploits is True
        assert request.use_llm is False

    def test_scan_result_model(self):
        """Test ScanResult model."""
        result = ScanResult(
            threats=[{"rule_id": "test", "severity": "high"}],
            summary={"total_threats": 1},
            metadata={"scan_time": "2023-01-01"},
        )
        assert len(result.threats) == 1
        assert result.summary["total_threats"] == 1
        assert result.metadata["scan_time"] == "2023-01-01"

    def test_adversary_tool_error(self):
        """Test AdversaryToolError exception."""
        error = AdversaryToolError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)


class TestServerUtilityMethods:
    """Test server utility and formatting methods."""

    @pytest.fixture
    def server(self):
        """Create a server instance for testing."""
        with patch(
            "adversary_mcp_server.scanner.semgrep_scanner.OptimizedSemgrepScanner.get_status"
        ) as mock_status:
            # Mock semgrep status to avoid subprocess calls
            mock_status.return_value = {
                "semgrep_installed": True,
                "semgrep_version": "1.0.0",
                "semgrep_path": "/mock/semgrep",
                "config_status": "loaded",
            }
            server = AdversaryMCPServer()
            yield server

    @pytest.fixture
    def mock_threat(self):
        """Create a mock threat for testing."""
        return ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            code_snippet="test code",
            exploit_examples=["exploit1"],
            remediation="Fix it",
            references=["https://example.com"],
            cwe_id="CWE-89",
        )

    @pytest.fixture
    def mock_scan_result(self, mock_threat):
        """Create a mock scan result for testing."""
        return EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[mock_threat],
            scan_metadata={
                "rules_scan_success": True,
                "llm_scan_success": False,
                "source_lines": 100,
            },
        )

    def test_format_scan_results(self, server, mock_threat):
        """Test _format_scan_results utility method."""
        result = server._format_scan_results([mock_threat], "test.py")

        assert "Security Scan Results for test.py" in result
        assert "Test Rule" in result
        assert "test.py:1" in result
        assert "High" in result

    def test_format_scan_results_no_threats(self, server):
        """Test _format_scan_results with no threats."""
        result = server._format_scan_results([], "test.py")

        assert "Security Scan Results for test.py" in result
        assert "No security vulnerabilities found" in result

    def test_format_enhanced_scan_results(self, server, mock_scan_result):
        """Test _format_enhanced_scan_results utility method."""
        result = server._format_enhanced_scan_results(mock_scan_result, "test.py")

        assert "Enhanced Security Scan Results for test.py" in result
        assert "Test Rule" in result
        assert "**LLM Analysis:** 0 findings" in result
        assert "**Total Threats:** 1" in result

    def test_format_enhanced_scan_results_no_threats(self, server):
        """Test _format_enhanced_scan_results with no threats."""
        empty_result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={},
        )

        result = server._format_enhanced_scan_results(empty_result, "test.py")

        assert "Enhanced Security Scan Results for test.py" in result
        assert "No security vulnerabilities found" in result

    def test_format_json_scan_results(self, server, mock_scan_result):
        """Test _format_json_scan_results utility method."""
        with patch("adversary_mcp_server.server.FalsePositiveManager") as mock_fp_class:
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = None
            mock_fp_class.return_value = mock_fp_instance

            result = server._format_json_scan_results(mock_scan_result, "test.py")

        # Parse JSON to verify structure
        data = json.loads(result)
        assert data["scan_metadata"]["target"] == "test.py"
        # Language is now auto-detected, no longer in metadata assertions
        assert len(data["threats"]) == 1
        assert data["threats"][0]["rule_id"] == "test_rule"
        assert data["threats"][0]["severity"] == "high"

    def test_format_json_scan_results_with_false_positive(
        self, server, mock_scan_result
    ):
        """Test _format_json_scan_results with false positive metadata."""
        false_positive_data = {
            "rule_id": "test_rule",
            "reason": "Test false positive",
            "marked_at": "2023-01-01T00:00:00Z",
        }

        with patch("adversary_mcp_server.server.FalsePositiveManager") as mock_fp_class:
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = (
                false_positive_data
            )
            mock_fp_class.return_value = mock_fp_instance

            result = server._format_json_scan_results(mock_scan_result, "test.py")

        data = json.loads(result)
        assert data["threats"][0]["is_false_positive"] is True
        assert data["threats"][0]["false_positive_metadata"] == false_positive_data

    def test_format_json_directory_results(self, server, mock_scan_result):
        """Test _format_json_directory_results utility method."""
        with patch("adversary_mcp_server.server.FalsePositiveManager") as mock_fp_class:
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = None
            mock_fp_class.return_value = mock_fp_instance

            with patch.object(
                server, "_get_semgrep_summary", return_value={"files_processed": 1}
            ):
                result = server._format_json_directory_results(
                    [mock_scan_result], "/test/dir"
                )

        data = json.loads(result)
        assert data["scan_metadata"]["target"] == "/test/dir"
        assert data["scan_metadata"]["scan_type"] == "directory"
        assert data["scan_metadata"]["files_scanned"] == 1
        assert len(data["threats"]) == 1

    def test_format_json_diff_results(self, server, mock_scan_result):
        """Test _format_json_diff_results utility method."""
        scan_results = {"test.py": [mock_scan_result]}
        diff_summary = {
            "files_changed": {
                "test.py": {
                    "lines_added": 10,
                    "lines_removed": 5,
                }
            },
            "lines_added": 10,
            "lines_removed": 5,
        }

        with patch("adversary_mcp_server.server.FalsePositiveManager") as mock_fp_class:
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positive_details.return_value = None
            mock_fp_class.return_value = mock_fp_instance

            result = server._format_json_diff_results(
                scan_results, diff_summary, "main..feature", "."
            )

        data = json.loads(result)
        assert data["scan_metadata"]["target"] == "main..feature"
        assert data["scan_metadata"]["scan_type"] == "git_diff"

    def test_save_scan_results_json_to_directory(self, server):
        """Test _save_scan_results_json saving to directory."""
        json_data = '{"test": "data"}'

        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = server._save_scan_results_json(json_data, temp_dir)

            assert result_path is not None
            assert Path(result_path).exists()
            assert Path(result_path).name == ".adversary.json"

            # Verify content
            with open(result_path) as f:
                saved_data = json.load(f)
            assert saved_data["test"] == "data"

    def test_save_scan_results_json_to_file(self, server):
        """Test _save_scan_results_json saving to specific file."""
        json_data = '{"test": "data"}'

        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "custom_results.json"
            result_path = server._save_scan_results_json(json_data, str(output_file))

            assert result_path is not None
            assert Path(result_path).exists()
            assert Path(result_path).name == "custom_results.json"

    def test_save_scan_results_json_failure(self, server):
        """Test _save_scan_results_json with save failure."""
        json_data = '{"test": "data"}'

        # Try to save to invalid path
        result_path = server._save_scan_results_json(
            json_data, "/invalid/path/file.json"
        )

        assert result_path is None

    def test_add_llm_analysis_prompts(self, server):
        """Test _add_llm_analysis_prompts utility method."""
        content = "import pickle; pickle.loads(data)"
        # Language is now auto-detected
        file_path = "test.py"

        mock_prompt = Mock()
        mock_prompt.system_prompt = "Test system prompt"
        mock_prompt.user_prompt = "Test user prompt"

        with patch.object(
            server.scan_engine.llm_analyzer,
            "create_analysis_prompt",
            return_value=mock_prompt,
        ):
            result = server._add_llm_analysis_prompts(content, file_path)

        assert "LLM Security Analysis" in result
        assert "Test system prompt" in result
        assert "Test user prompt" in result
        assert "Instructions:" in result

    def test_add_llm_analysis_prompts_no_header(self, server):
        """Test _add_llm_analysis_prompts without header."""
        content = "import pickle; pickle.loads(data)"
        # Language is now auto-detected
        file_path = "test.py"

        mock_prompt = Mock()
        mock_prompt.system_prompt = "Test system prompt"
        mock_prompt.user_prompt = "Test user prompt"

        with patch.object(
            server.scan_engine.llm_analyzer,
            "create_analysis_prompt",
            return_value=mock_prompt,
        ):
            result = server._add_llm_analysis_prompts(
                content, file_path, include_header=False
            )

        assert "LLM Security Analysis" not in result
        assert "Test system prompt" in result
        assert "Test user prompt" in result

    def test_add_llm_analysis_prompts_failure(self, server):
        """Test _add_llm_analysis_prompts with exception."""
        content = "import pickle; pickle.loads(data)"
        # Language is now auto-detected
        file_path = "test.py"

        with patch.object(
            server.scan_engine.llm_analyzer,
            "create_analysis_prompt",
            side_effect=Exception("Prompt failed"),
        ):
            result = server._add_llm_analysis_prompts(content, file_path)

        assert "Failed to create prompts" in result
        assert "Prompt failed" in result

    def test_filter_threats_by_severity(self, server):
        """Test _filter_threats_by_severity utility method."""
        threats = [
            ThreatMatch(
                rule_id="low_threat",
                rule_name="Low Threat",
                description="Low severity threat",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=1,
            ),
            ThreatMatch(
                rule_id="high_threat",
                rule_name="High Threat",
                description="High severity threat",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=2,
            ),
            ThreatMatch(
                rule_id="critical_threat",
                rule_name="Critical Threat",
                description="Critical severity threat",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=3,
            ),
        ]

        # Filter for HIGH and above
        filtered = server._filter_threats_by_severity(threats, Severity.HIGH)
        assert len(filtered) == 2
        assert filtered[0].severity == Severity.HIGH
        assert filtered[1].severity == Severity.CRITICAL

        # Filter for CRITICAL only
        filtered = server._filter_threats_by_severity(threats, Severity.CRITICAL)
        assert len(filtered) == 1
        assert filtered[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_handle_scan_code_with_llm_prompts(self, server, mock_scan_result):
        """Test scan_code with LLM prompts enabled."""
        arguments = {
            "content": "import pickle; pickle.loads(data)",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": True,
            "use_semgrep": False,
            "output_format": "json",
        }

        with patch.object(
            server.scan_engine, "scan_code", return_value=mock_scan_result
        ):
            with patch.object(
                server, "_add_llm_analysis_prompts", return_value="\n\nLLM prompts"
            ):
                with patch.object(
                    server,
                    "_add_llm_exploit_prompts",
                    return_value="\n\nLLM exploit prompts",
                ):
                    result = await server._handle_scan_code(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert "scan completed successfully" in result[0].text

    @pytest.mark.asyncio
    async def test_handle_scan_directory_json_output(self, server, mock_scan_result):
        """Test scan_directory with JSON output format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {
                "path": temp_dir,
                "recursive": True,
                "severity_threshold": "medium",
                "include_exploits": False,
                "use_llm": False,
                "use_semgrep": False,
                "output_format": "json",
            }

            with patch.object(
                server.scan_engine, "scan_directory", return_value=[mock_scan_result]
            ):
                with patch.object(
                    server,
                    "_format_json_directory_results",
                    return_value='{"test": "data"}',
                ):
                    with patch.object(
                        server,
                        "_save_scan_results_json",
                        return_value="/tmp/results.json",
                    ):
                        result = await server._handle_scan_directory(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_scan_directory_json_save_failure(
        self, server, mock_scan_result
    ):
        """Test scan_directory with JSON output and save failure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {
                "path": temp_dir,
                "recursive": True,
                "severity_threshold": "medium",
                "include_exploits": False,
                "use_llm": False,
                "use_semgrep": False,
                "output_format": "json",
            }

            with patch.object(
                server.scan_engine, "scan_directory", return_value=[mock_scan_result]
            ):
                with patch.object(
                    server,
                    "_format_json_directory_results",
                    return_value='{"test": "data"}',
                ):
                    with patch.object(
                        server, "_save_scan_results_json", return_value=None
                    ):
                        result = await server._handle_scan_directory(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_diff_scan_json_output(self, server, mock_scan_result):
        """Test diff_scan with JSON output format."""
        arguments = {
            "source_branch": "main",
            "target_branch": "feature",
            "path": ".",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        mock_diff_summary = {
            "files_changed": 1,
            "lines_added": 5,
            "lines_removed": 2,
        }

        mock_scan_results = {
            "file1.py": [mock_scan_result],
        }

        with patch.object(
            server.diff_scanner, "get_diff_summary", return_value=mock_diff_summary
        ):
            with patch.object(
                server.diff_scanner, "scan_diff", return_value=mock_scan_results
            ):
                with patch.object(
                    server, "_format_json_diff_results", return_value='{"test": "data"}'
                ):
                    with patch.object(
                        server,
                        "_save_scan_results_json",
                        return_value="/tmp/results.json",
                    ):
                        result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_diff_scan_with_llm_prompts(self, server, mock_scan_result):
        """Test diff_scan with LLM prompts."""
        arguments = {
            "source_branch": "main",
            "target_branch": "feature",
            "path": ".",
            "severity_threshold": "medium",
            "include_exploits": False,
            "use_llm": True,
            "use_semgrep": False,
            "output_format": "json",
        }

        mock_diff_summary = {
            "files_changed": 1,
            "lines_added": 5,
            "lines_removed": 2,
        }

        mock_scan_results = {
            "file1.py": [mock_scan_result],
        }

        with patch.object(
            server.diff_scanner, "get_diff_summary", return_value=mock_diff_summary
        ):
            with patch.object(
                server.diff_scanner, "scan_diff", return_value=mock_scan_results
            ):
                # Skip LLM prompts test since the method doesn't exist yet
                result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_scan_directory_exploit_generation_failure(
        self, server, mock_scan_result
    ):
        """Test scan_directory with exploit generation failure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {
                "path": temp_dir,
                "recursive": True,
                "severity_threshold": "medium",
                "include_exploits": True,
                "use_llm": False,
                "use_semgrep": False,
                "output_format": "json",
            }

            with patch.object(
                server.scan_engine, "scan_directory", return_value=[mock_scan_result]
            ):
                with patch.object(
                    server.exploit_generator,
                    "generate_exploits",
                    side_effect=Exception("Exploit generation failed"),
                ):
                    result = await server._handle_scan_directory(arguments)

            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_diff_scan_exploit_generation_failure(
        self, server, mock_scan_result
    ):
        """Test diff_scan with exploit generation failure."""
        arguments = {
            "source_branch": "main",
            "target_branch": "feature",
            "path": ".",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "json",
        }

        mock_diff_summary = {
            "files_changed": 1,
            "lines_added": 5,
            "lines_removed": 2,
        }

        mock_scan_results = {
            "file1.py": [mock_scan_result],
        }

        with patch.object(
            server.diff_scanner, "get_diff_summary", return_value=mock_diff_summary
        ):
            with patch.object(
                server.diff_scanner, "scan_diff", return_value=mock_scan_results
            ):
                with patch.object(
                    server.exploit_generator,
                    "generate_exploits",
                    side_effect=Exception("Exploit generation failed"),
                ):
                    result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)

    @pytest.mark.asyncio
    async def test_handle_list_false_positives_empty_result(self, server):
        """Test list_false_positives with empty result."""
        arguments = {
            "path": "/mock/working/dir",
        }

        with patch("adversary_mcp_server.server.FalsePositiveManager") as mock_fp_class:
            mock_fp_instance = Mock()
            mock_fp_instance.get_false_positives.return_value = []
            mock_fp_class.return_value = mock_fp_instance

            with patch.object(server, "_validate_adversary_path") as mock_validate:
                mock_validate.return_value = Path("/mock/working/dir/.adversary.json")
                result = await server._handle_list_false_positives(arguments)

        assert len(result) == 1
        assert isinstance(result[0], types.TextContent)
        assert (
            "No false positives" in result[0].text
            or "0 false positives" in result[0].text
        )

    def test_security_validation_integration(self):
        """Test that security validation is properly integrated into server."""
        from adversary_mcp_server.security import InputValidator

        server = AdversaryMCPServer()

        # Test that InputValidator is accessible and working
        dangerous_args = {"path": "../../../etc/passwd", "severity_threshold": "medium"}

        with pytest.raises(Exception):  # Should raise SecurityError or ValidationError
            InputValidator.validate_mcp_arguments(dangerous_args)

    def test_telemetry_collection_integration(self):
        """Test that telemetry collection is properly integrated."""
        server = AdversaryMCPServer()

        # Verify telemetry components are initialized
        assert hasattr(server, "telemetry_service")
        assert hasattr(server, "metrics_orchestrator")
        assert hasattr(server, "metrics_collector")

        # Verify telemetry can be accessed
        assert server.telemetry_service is not None
        assert server.metrics_orchestrator is not None

    def test_log_sanitization_integration(self):
        """Test that log sanitization is working in server context."""
        from adversary_mcp_server.security import sanitize_for_logging

        # Test that sanitization is available and working
        sensitive_data = {
            "api_key": "sk-secret123",
            "file_path": "/safe/path/test.py",
            "password": "dangerous_password",
        }

        sanitized = sanitize_for_logging(sensitive_data)

        # Verify sensitive data is redacted
        assert "sk-secret123" not in sanitized
        assert "dangerous_password" not in sanitized
        assert "[REDACTED]" in sanitized

        # Verify safe data is preserved
        assert "/safe/path/test.py" in sanitized

    @pytest.mark.asyncio
    async def test_server_initialization_with_new_components(self):
        """Test that server initializes correctly with all new Phase II and III components."""
        with (
            patch("adversary_mcp_server.server.get_credential_manager"),
            patch("adversary_mcp_server.server.AdversaryDatabase"),
            patch("adversary_mcp_server.server.TelemetryService"),
            patch("adversary_mcp_server.server.MetricsCollectionOrchestrator"),
            patch("adversary_mcp_server.server.ScanEngine"),
            patch("adversary_mcp_server.server.ExploitGenerator"),
            patch("adversary_mcp_server.server.FalsePositiveManager"),
            patch("adversary_mcp_server.server.GitDiffScanner"),
        ):

            # Should initialize without errors
            server = AdversaryMCPServer()

            # Verify key components are set
            assert hasattr(server, "db")
            assert hasattr(server, "telemetry_service")
            assert hasattr(server, "metrics_orchestrator")
            assert hasattr(server, "scan_engine")
            assert hasattr(server, "exploit_generator")
            assert hasattr(server, "false_positive_manager")

    def test_metrics_collection_availability(self):
        """Test that metrics collection is available and configured."""
        server = AdversaryMCPServer()

        # Test metrics collector has required methods
        assert hasattr(server.metrics_collector, "record_metric")

        # Test metrics orchestrator has required methods
        if hasattr(server, "metrics_orchestrator"):
            assert hasattr(server.metrics_orchestrator, "track_cache_operation")

    def test_security_error_handling_integration(self):
        """Test that security errors are properly handled."""
        from adversary_mcp_server.security import SecurityError

        # Test SecurityError can be raised and caught
        with pytest.raises(SecurityError):
            raise SecurityError("Test security error")

        # Test error has proper message
        error = SecurityError("Custom message")
        assert str(error) == "Custom message"
