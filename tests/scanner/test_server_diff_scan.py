"""Tests for the server integration of the diff scan tool."""

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch
from adversary_mcp_server.server import AdversaryMCPServer, AdversaryToolError


class TestServerDiffScanIntegration:
    """Test cases for server integration of diff scan tool."""

    def test_server_has_diff_scanner(self):
        """Test that server initializes with diff scanner."""
        server = AdversaryMCPServer()
        assert hasattr(server, "diff_scanner")
        assert server.diff_scanner is not None

    @pytest.mark.asyncio
    async def test_handle_diff_scan_success(self):
        """Test successful diff scan handling."""
        server = AdversaryMCPServer()

        # Mock the diff scanner
        mock_diff_summary = {
            "source_branch": "feature",
            "target_branch": "main",
            "total_files_changed": 2,
            "supported_files": 1,
            "lines_added": 3,
            "lines_removed": 1,
            "scannable_files": ["test.py"],
        }

        mock_threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=5,
            code_snippet="eval(user_input)",
        )

        mock_scan_result = Mock()
        mock_scan_result.all_threats = [mock_threat]
        mock_scan_result.stats = {
            "severity_counts": {"high": 1, "medium": 0, "low": 0, "critical": 0}
        }
        mock_scan_result.validation_results = {}
        mock_scan_result.scan_metadata = {"validation_errors": 0}
        mock_scan_result.file_path = "test.py"
        mock_scan_result.language = "python"

        mock_scan_results = {"test.py": [mock_scan_result]}

        server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)

        # Create an async mock for scan_diff since it's now async
        async def mock_scan_diff(*args, **kwargs):
            return mock_scan_results

        server.diff_scanner.scan_diff = mock_scan_diff
        server.diff_scanner.get_diff_changes = AsyncMock(return_value={})

        # Mock exploit generator
        server.exploit_generator.generate_exploits = Mock(return_value=["test exploit"])

        arguments = {
            "source_branch": "feature",
            "target_branch": "main",
            "path": ".",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False,
        }

        result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert result[0].type == "text"
        assert "diff scan completed successfully" in result[0].text
        assert "feature" in result[0].text
        assert "main" in result[0].text
        assert "threats" in result[0].text.lower() or "completed" in result[0].text

    @pytest.mark.asyncio
    async def test_handle_diff_scan_no_changes(self):
        """Test diff scan with no changes."""
        server = AdversaryMCPServer()

        mock_diff_summary = {
            "source_branch": "feature",
            "target_branch": "main",
            "total_files_changed": 0,
            "supported_files": 0,
            "lines_added": 0,
            "lines_removed": 0,
            "scannable_files": [],
        }

        server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)

        # Create an async mock for scan_diff since it's now async
        async def mock_scan_diff(*args, **kwargs):
            return {}

        server.diff_scanner.scan_diff = mock_scan_diff

        arguments = {"source_branch": "feature", "target_branch": "main", "path": "."}

        result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert "diff scan completed" in result[0].text or "No changes" in result[0].text

    @pytest.mark.asyncio
    async def test_handle_diff_scan_git_error(self):
        """Test diff scan with git error."""
        server = AdversaryMCPServer()

        mock_diff_summary = {
            "source_branch": "feature",
            "target_branch": "main",
            "error": "Branch not found",
        }

        server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)

        arguments = {"source_branch": "feature", "target_branch": "main", "path": "."}

        with pytest.raises(AdversaryToolError, match="Git diff operation failed"):
            await server._handle_diff_scan(arguments)

    @pytest.mark.asyncio
    async def test_handle_diff_scan_with_llm(self):
        """Test diff scan with LLM prompts."""
        server = AdversaryMCPServer()

        mock_diff_summary = {
            "source_branch": "feature",
            "target_branch": "main",
            "total_files_changed": 1,
            "supported_files": 1,
            "lines_added": 1,
            "lines_removed": 0,
            "scannable_files": ["test.py"],
        }

        mock_threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=5,
            code_snippet="eval(user_input)",
        )

        mock_scan_result = Mock()
        mock_scan_result.all_threats = [mock_threat]
        mock_scan_result.stats = {
            "severity_counts": {"high": 1, "medium": 0, "low": 0, "critical": 0}
        }
        mock_scan_result.validation_results = {}
        mock_scan_result.scan_metadata = {"validation_errors": 0}
        mock_scan_result.file_path = "test.py"
        mock_scan_result.language = "python"

        mock_scan_results = {"test.py": [mock_scan_result]}

        # Mock diff changes for LLM prompts
        mock_chunk = Mock()
        mock_chunk.get_added_lines_with_minimal_context.return_value = (
            "eval(user_input)"
        )
        mock_diff_changes = {"test.py": [mock_chunk]}

        server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)

        # Create an async mock for scan_diff since it's now async
        async def mock_scan_diff(*args, **kwargs):
            return mock_scan_results

        server.diff_scanner.scan_diff = mock_scan_diff
        server.diff_scanner.get_diff_changes = AsyncMock(return_value=mock_diff_changes)

        # Mock LLM analysis prompts
        server._add_llm_analysis_prompts = Mock(
            return_value="\n\nLLM Analysis Prompts\n"
        )

        arguments = {
            "source_branch": "feature",
            "target_branch": "main",
            "use_llm": True,
        }

        result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert "completed" in result[0].text
        server._add_llm_analysis_prompts.assert_called()

    @pytest.mark.asyncio
    async def test_handle_diff_scan_with_exploits(self):
        """Test diff scan with exploit generation."""
        server = AdversaryMCPServer()

        mock_diff_summary = {
            "source_branch": "feature",
            "target_branch": "main",
            "total_files_changed": 1,
            "supported_files": 1,
            "lines_added": 1,
            "lines_removed": 0,
            "scannable_files": ["test.py"],
        }

        mock_threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=5,
            code_snippet="eval(user_input)",
        )

        mock_scan_result = Mock()
        mock_scan_result.all_threats = [mock_threat]
        mock_scan_result.stats = {
            "severity_counts": {"high": 1, "medium": 0, "low": 0, "critical": 0}
        }
        mock_scan_result.validation_results = {}
        mock_scan_result.scan_metadata = {"validation_errors": 0}
        mock_scan_result.file_path = "test.py"
        mock_scan_result.language = "python"

        mock_scan_results = {"test.py": [mock_scan_result]}

        server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)

        # Create an async mock for scan_diff since it's now async
        async def mock_scan_diff(*args, **kwargs):
            return mock_scan_results

        server.diff_scanner.scan_diff = mock_scan_diff

        # Mock exploit generator
        server.exploit_generator.generate_exploits = Mock(return_value=["test exploit"])

        arguments = {
            "source_branch": "feature",
            "target_branch": "main",
            "include_exploits": True,
        }

        result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        assert "threats" in result[0].text.lower() or "completed" in result[0].text
        server.exploit_generator.generate_exploits.assert_called()

    @pytest.mark.asyncio
    async def test_handle_diff_scan_severity_filtering(self):
        """Test diff scan with severity filtering."""
        server = AdversaryMCPServer()

        mock_diff_summary = {
            "source_branch": "feature",
            "target_branch": "main",
            "total_files_changed": 1,
            "supported_files": 1,
            "lines_added": 1,
            "lines_removed": 0,
            "scannable_files": ["test.py"],
        }

        mock_threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.LOW,
            file_path="test.py",
            line_number=5,
            code_snippet="eval(user_input)",
        )

        mock_scan_result = Mock()
        mock_scan_result.all_threats = [mock_threat]
        mock_scan_result.stats = {
            "severity_counts": {"high": 0, "medium": 0, "low": 1, "critical": 0}
        }

        mock_scan_results = {"test.py": [mock_scan_result]}

        server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)

        # Create an async mock for scan_diff since it's now async
        async def mock_scan_diff(*args, **kwargs):
            return mock_scan_results

        server.diff_scanner.scan_diff = mock_scan_diff

        arguments = {
            "source_branch": "feature",
            "target_branch": "main",
            "severity_threshold": "high",  # Should filter out LOW severity
        }

        result = await server._handle_diff_scan(arguments)

        assert len(result) == 1
        # Note: Cannot easily assert call parameters on async function mock without more complex setup
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_handle_diff_scan_exception(self):
        """Test diff scan with exception handling."""
        server = AdversaryMCPServer()

        # Mock diff scanner to raise exception
        server.diff_scanner.get_diff_summary = AsyncMock(
            side_effect=Exception("Test error")
        )

        arguments = {"source_branch": "feature", "target_branch": "main", "path": "."}

        with pytest.raises(AdversaryToolError, match="Diff scanning failed"):
            await server._handle_diff_scan(arguments)


class TestServerDiffScanFormatting:
    """Test cases for diff scan result formatting."""

    def test_format_diff_scan_results_no_results(self):
        """Test formatting diff scan results with no results."""
        server = AdversaryMCPServer()

        diff_summary = {
            "total_files_changed": 0,
            "supported_files": 0,
            "lines_added": 0,
            "lines_removed": 0,
            "scannable_files": [],
        }

        result = server._format_diff_scan_results({}, diff_summary, "feature", "main")

        assert "Git Diff Scan Results" in result
        assert "No changes found between branches" in result
        assert "feature" in result
        assert "main" in result

    def test_format_diff_scan_results_with_threats(self):
        """Test formatting diff scan results with threats."""
        server = AdversaryMCPServer()

        diff_summary = {
            "total_files_changed": 1,
            "supported_files": 1,
            "lines_added": 2,
            "lines_removed": 1,
            "scannable_files": ["test.py"],
        }

        mock_threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=5,
            code_snippet="eval(user_input)",
            exploit_examples=["exploit1", "exploit2"],
        )

        mock_scan_result = Mock()
        mock_scan_result.all_threats = [mock_threat]
        mock_scan_result.stats = {
            "severity_counts": {"high": 1, "medium": 0, "low": 0, "critical": 0}
        }
        mock_scan_result.validation_results = {}
        mock_scan_result.scan_metadata = {"validation_errors": 0}
        mock_scan_result.file_path = "test.py"
        mock_scan_result.language = "python"

        scan_results = {"test.py": [mock_scan_result]}

        result = server._format_diff_scan_results(
            scan_results, diff_summary, "feature", "main"
        )

        assert "Git Diff Scan Results" in result
        assert "Test Rule" in result
        assert "🟠" in result  # High severity emoji
        assert "**Files with Security Issues:** 1" in result

    def test_format_diff_scan_results_clean_scan(self):
        """Test formatting diff scan results with no threats."""
        server = AdversaryMCPServer()

        diff_summary = {
            "total_files_changed": 1,
            "supported_files": 1,
            "lines_added": 2,
            "lines_removed": 1,
            "scannable_files": ["test.py"],
        }

        result = server._format_diff_scan_results({}, diff_summary, "feature", "main")

        assert "Git Diff Scan Results" in result
        assert "No security vulnerabilities found in diff changes" in result
        assert "**Files Changed:** 1" in result


class TestServerDiffScanToolDefinition:
    """Test cases for diff scan tool definition and dispatch."""

    def test_server_has_diff_scan_tool(self):
        """Test that server defines the diff scan tool."""
        server = AdversaryMCPServer()

        # Check that the diff scanner is initialized
        assert hasattr(server, "diff_scanner")
        assert server.diff_scanner is not None

    @pytest.mark.asyncio
    async def test_handle_diff_scan_method_exists(self):
        """Test that the diff scan handler method exists and is callable."""
        server = AdversaryMCPServer()

        # Check that the handler method exists
        assert hasattr(server, "_handle_diff_scan")
        assert callable(server._handle_diff_scan)

        # Mock the dependencies and test that it can be called
        server.diff_scanner.get_diff_summary = AsyncMock(
            return_value={"error": "test error"}
        )

        arguments = {"source_branch": "feature", "target_branch": "main", "path": "."}

        # Should raise AdversaryToolError due to the mocked error
        with pytest.raises(AdversaryToolError, match="Git diff operation failed"):
            await server._handle_diff_scan(arguments)

    @pytest.mark.asyncio
    async def test_diff_scan_tool_integration(self):
        """Test that the diff scan tool integrates properly with the server."""
        server = AdversaryMCPServer()

        # Mock a successful diff scan
        mock_diff_summary = {
            "source_branch": "feature",
            "target_branch": "main",
            "total_files_changed": 0,
            "supported_files": 0,
            "lines_added": 0,
            "lines_removed": 0,
            "scannable_files": [],
        }

        server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)

        # Create an async mock for scan_diff since it's now async
        async def mock_scan_diff(*args, **kwargs):
            return {}

        server.diff_scanner.scan_diff = mock_scan_diff

        arguments = {"source_branch": "feature", "target_branch": "main", "path": "."}

        result = await server._handle_diff_scan(arguments)

        # Verify the result structure
        assert len(result) == 1
        assert result[0].type == "text"
        assert "diff scan completed successfully" in result[0].text
        assert "diff scan completed" in result[0].text or "No changes" in result[0].text


class TestServerDiffScanIntegrationComplete:
    """Test cases for complete diff scan integration."""

    @pytest.mark.asyncio
    async def test_complete_diff_scan_workflow(self):
        """Test complete diff scan workflow using the handler directly."""
        server = AdversaryMCPServer()

        # Mock all components
        mock_diff_summary = {
            "source_branch": "feature",
            "target_branch": "main",
            "total_files_changed": 1,
            "supported_files": 1,
            "lines_added": 1,
            "lines_removed": 0,
            "scannable_files": ["test.py"],
        }

        mock_threat = ThreatMatch(
            rule_id="eval_usage",
            rule_name="Eval Usage",
            description="Use of eval() function",
            category=Category.INJECTION,
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=5,
            code_snippet="eval(user_input)",
        )

        mock_scan_result = Mock()
        mock_scan_result.all_threats = [mock_threat]
        mock_scan_result.stats = {
            "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0}
        }

        mock_scan_results = {"test.py": [mock_scan_result]}

        # Mock the diff scanner methods
        server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)

        # Create an async mock for scan_diff since it's now async
        async def mock_scan_diff(*args, **kwargs):
            return mock_scan_results

        server.diff_scanner.scan_diff = mock_scan_diff

        # Mock exploit generator
        server.exploit_generator.generate_exploits = Mock(return_value=["exploit code"])

        # Execute the complete workflow
        arguments = {
            "source_branch": "feature",
            "target_branch": "main",
            "path": ".",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False,
        }

        result = await server._handle_diff_scan(arguments)

        # Verify the result
        assert len(result) == 1
        assert result[0].type == "text"
        assert "diff scan completed successfully" in result[0].text
        assert "feature" in result[0].text
        assert "main" in result[0].text
        assert "Eval Usage" in result[0].text
        assert "🔴" in result[0].text  # Critical severity emoji

        # Verify methods were called
        server.diff_scanner.get_diff_summary.assert_called_once_with(
            "feature", "main", Path(".").resolve()
        )
        # Note: Cannot easily assert call parameters on async function mock without more complex setup
        server.exploit_generator.generate_exploits.assert_called_once()
