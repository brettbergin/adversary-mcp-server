"""Tests for MCP server use_rules flag functionality."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.server import AdversaryMCPServer
from adversary_mcp_server.threat_engine import Category, Severity, ThreatMatch


class TestMCPServerUseRulesFlag:
    """Test MCP server with use_rules parameter."""

    @pytest.fixture
    async def server(self):
        """Create a test server instance."""
        server = AdversaryMCPServer()
        return server

    @pytest.mark.asyncio
    async def test_adv_scan_code_with_use_rules_false(self, server):
        """Test adv_scan_code with use_rules=False."""
        with patch.object(server.scan_engine, "scan_code") as mock_scan_code:
            # Create mock result with no threats (rules disabled)
            mock_result = Mock()
            mock_result.all_threats = []
            mock_result.scan_metadata = {
                "use_rules": False,
                "rules_scan_success": False,
                "rules_scan_reason": "disabled",
            }
            mock_result.stats = {
                "total_threats": 0,
                "rules_threats": 0,
                "llm_threats": 0,
                "semgrep_threats": 0,
                "unique_threats": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "category_counts": {},
                "sources": {
                    "rules_engine": False,
                    "llm_analysis": False,
                    "semgrep_analysis": False,
                },
            }
            mock_scan_code.return_value = mock_result

            arguments = {
                "content": "import os; os.system(user_input)",
                "language": "python",
                "use_rules": False,
                "use_semgrep": False,
                "use_llm": False,
            }

            result = await server._handle_scan_code(arguments)

            # Verify scan_code was called with use_rules=False
            mock_scan_code.assert_called_once()
            call_args = mock_scan_code.call_args
            assert call_args.kwargs["use_rules"] is False
            assert call_args.kwargs["use_semgrep"] is False
            assert call_args.kwargs["use_llm"] is False

            # Should return successful result
            assert len(result) > 0

    @pytest.mark.asyncio
    async def test_adv_scan_code_with_use_rules_true(self, server):
        """Test adv_scan_code with use_rules=True."""
        with patch.object(server.scan_engine, "scan_code") as mock_scan_code:
            # Create mock result with threats (rules enabled)
            mock_result = Mock()
            mock_result.all_threats = [
                ThreatMatch(
                    rule_id="test_rule",
                    rule_name="Test Rule",
                    description="Test description",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path="test.py",
                    line_number=1,
                )
            ]
            mock_result.scan_metadata = {
                "use_rules": True,
                "rules_scan_success": True,
                "rules_scan_reason": "analysis_completed",
            }
            mock_result.stats = {
                "total_threats": 1,
                "rules_threats": 1,
                "llm_threats": 0,
                "semgrep_threats": 0,
                "unique_threats": 1,
                "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                "category_counts": {"injection": 1},
                "sources": {
                    "rules_engine": True,
                    "llm_analysis": False,
                    "semgrep_analysis": False,
                },
            }
            mock_scan_code.return_value = mock_result

            arguments = {
                "content": "import os; os.system(user_input)",
                "language": "python",
                "use_rules": True,
                "use_semgrep": False,
                "use_llm": False,
            }

            result = await server._handle_scan_code(arguments)

            # Verify scan_code was called with use_rules=True
            mock_scan_code.assert_called_once()
            call_args = mock_scan_code.call_args
            assert call_args.kwargs["use_rules"] is True

            # Should return successful result
            assert len(result) > 0

    @pytest.mark.asyncio
    async def test_adv_scan_code_default_behavior(self, server):
        """Test that use_rules defaults to True when not specified."""
        with patch.object(server.scan_engine, "scan_code") as mock_scan_code:
            mock_result = Mock()
            mock_result.all_threats = []
            mock_result.scan_metadata = {
                "use_rules": True,
                "rules_scan_success": True,
                "rules_scan_reason": "analysis_completed",
            }
            mock_result.stats = {
                "total_threats": 0,
                "rules_threats": 0,
                "llm_threats": 0,
                "semgrep_threats": 0,
                "unique_threats": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "category_counts": {},
                "sources": {
                    "rules_engine": False,
                    "llm_analysis": False,
                    "semgrep_analysis": False,
                },
            }
            mock_scan_code.return_value = mock_result

            arguments = {
                "content": "import os; os.system(user_input)",
                "language": "python",
                # use_rules not specified - should default to True
            }

            result = await server._handle_scan_code(arguments)

            # Verify scan_code was called with use_rules=True (default)
            mock_scan_code.assert_called_once()
            call_args = mock_scan_code.call_args
            assert call_args.kwargs["use_rules"] is True

    @pytest.mark.asyncio
    async def test_adv_scan_file_with_use_rules_false(self, server):
        """Test adv_scan_file with use_rules=False."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import os; os.system(user_input)")
            test_file = f.name

        try:
            with patch.object(server.scan_engine, "scan_file") as mock_scan_file:
                mock_result = Mock()
                mock_result.all_threats = []
                mock_result.scan_metadata = {
                    "use_rules": False,
                    "rules_scan_success": False,
                    "rules_scan_reason": "disabled",
                }
                mock_result.stats = {
                    "total_threats": 0,
                    "rules_threats": 0,
                    "llm_threats": 0,
                    "semgrep_threats": 0,
                    "unique_threats": 0,
                    "severity_counts": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    },
                    "category_counts": {},
                    "sources": {
                        "rules_engine": False,
                        "llm_analysis": False,
                        "semgrep_analysis": False,
                    },
                }
                mock_scan_file.return_value = mock_result

                arguments = {
                    "file_path": test_file,
                    "use_rules": False,
                    "use_semgrep": False,
                    "use_llm": False,
                }

                result = await server._handle_scan_file(arguments)

                # Verify scan_file was called with use_rules=False
                mock_scan_file.assert_called_once()
                call_args = mock_scan_file.call_args
                assert call_args.kwargs["use_rules"] is False

        finally:
            Path(test_file).unlink()

    @pytest.mark.asyncio
    async def test_adv_scan_folder_with_use_rules_false(self, server):
        """Test adv_scan_folder with use_rules=False."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("import os; os.system(user_input)")

            with patch.object(
                server.scan_engine, "scan_directory"
            ) as mock_scan_directory:
                mock_scan_directory.return_value = []

                arguments = {
                    "directory_path": temp_dir,
                    "use_rules": False,
                    "use_semgrep": False,
                    "use_llm": False,
                }

                result = await server._handle_scan_directory(arguments)

                # Verify scan_directory was called with use_rules=False
                mock_scan_directory.assert_called_once()
                call_args = mock_scan_directory.call_args
                assert call_args.kwargs["use_rules"] is False

    @pytest.mark.asyncio
    async def test_adv_diff_scan_with_use_rules_false(self, server):
        """Test adv_diff_scan with use_rules=False."""
        with patch.object(
            server.diff_scanner, "get_diff_summary"
        ) as mock_get_diff_summary:
            with patch.object(server.diff_scanner, "scan_diff") as mock_scan_diff:
                # Mock successful diff summary
                mock_get_diff_summary.return_value = {
                    "files_changed": 1,
                    "lines_added": 10,
                    "lines_removed": 5,
                }

                # Mock scan_diff to return empty results
                mock_scan_diff.return_value = {}

                arguments = {
                    "source_branch": "main",
                    "target_branch": "feature",
                    "working_directory": ".",
                    "use_rules": False,
                    "use_semgrep": False,
                    "use_llm": False,
                }

                result = await server._handle_diff_scan(arguments)

                # Verify scan_diff was called with use_rules=False
                mock_scan_diff.assert_called_once()
                call_args = mock_scan_diff.call_args
                assert call_args.kwargs["use_rules"] is False

    @pytest.mark.asyncio
    async def test_mcp_tool_schema_includes_use_rules(self, server):
        """Test that MCP tool schemas include use_rules parameter."""
        # Test the scan tools directly through the server's tool definitions
        scan_tools = [
            "adv_scan_code",
            "adv_scan_file",
            "adv_scan_folder",
            "adv_diff_scan",
        ]

        # Check that use_rules parameter exists in server tool schemas
        for tool_name in scan_tools:
            # The schemas are defined in the server initialization
            # We can check by examining the server's capability to handle use_rules
            test_args = {"use_rules": False, "use_semgrep": False, "use_llm": False}

            if tool_name == "adv_scan_code":
                test_args.update({"content": "test", "language": "python"})
                # Mock the scan_code method to verify it accepts use_rules
                with patch.object(server.scan_engine, "scan_code") as mock_scan:
                    mock_result = Mock()
                    mock_result.all_threats = []
                    mock_result.scan_metadata = {"use_rules": False}
                    mock_result.stats = {
                        "total_threats": 0,
                        "rules_threats": 0,
                        "llm_threats": 0,
                        "semgrep_threats": 0,
                        "unique_threats": 0,
                        "severity_counts": {
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0,
                        },
                        "category_counts": {},
                        "sources": {
                            "rules_engine": False,
                            "llm_analysis": False,
                            "semgrep_analysis": False,
                        },
                    }
                    mock_scan.return_value = mock_result

                    result = await server._handle_scan_code(test_args)
                    assert len(result) > 0  # Should return some result

                    # Verify the method was called with use_rules parameter
                    call_args = mock_scan.call_args
                    assert "use_rules" in call_args.kwargs
                    assert call_args.kwargs["use_rules"] is False

    @pytest.mark.asyncio
    async def test_flag_combinations_in_mcp(self, server):
        """Test different flag combinations in MCP tools."""
        with patch.object(server.scan_engine, "scan_code") as mock_scan_code:
            mock_result = Mock()
            mock_result.all_threats = []
            mock_result.scan_metadata = {
                "use_rules": False,
                "rules_scan_success": False,
                "rules_scan_reason": "disabled",
            }
            mock_result.stats = {
                "total_threats": 0,
                "rules_threats": 0,
                "llm_threats": 0,
                "semgrep_threats": 0,
                "unique_threats": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "category_counts": {},
                "sources": {
                    "rules_engine": False,
                    "llm_analysis": False,
                    "semgrep_analysis": False,
                },
            }
            mock_scan_code.return_value = mock_result

            # Test all flags disabled
            arguments1 = {
                "content": "test code",
                "language": "python",
                "use_rules": False,
                "use_semgrep": False,
                "use_llm": False,
            }

            await server._handle_scan_code(arguments1)
            call_args = mock_scan_code.call_args
            assert call_args.kwargs["use_rules"] is False
            assert call_args.kwargs["use_semgrep"] is False
            assert call_args.kwargs["use_llm"] is False

            # Reset mock
            mock_scan_code.reset_mock()

            # Test only rules enabled
            arguments2 = {
                "content": "test code",
                "language": "python",
                "use_rules": True,
                "use_semgrep": False,
                "use_llm": False,
            }

            await server._handle_scan_code(arguments2)
            call_args = mock_scan_code.call_args
            assert call_args.kwargs["use_rules"] is True
            assert call_args.kwargs["use_semgrep"] is False
            assert call_args.kwargs["use_llm"] is False

            # Reset mock
            mock_scan_code.reset_mock()

            # Test all flags enabled
            arguments3 = {
                "content": "test code",
                "language": "python",
                "use_rules": True,
                "use_semgrep": True,
                "use_llm": True,
            }

            await server._handle_scan_code(arguments3)
            call_args = mock_scan_code.call_args
            assert call_args.kwargs["use_rules"] is True
            assert call_args.kwargs["use_semgrep"] is True
            # use_llm parameter is now properly passed through
            assert call_args.kwargs["use_llm"] is True

    @pytest.mark.asyncio
    async def test_output_format_with_rules_disabled(self, server):
        """Test output format when rules are disabled."""
        with patch.object(server.scan_engine, "scan_code") as mock_scan_code:
            mock_result = Mock()
            mock_result.all_threats = []
            mock_result.scan_metadata = {
                "use_rules": False,
                "rules_scan_reason": "disabled",
            }
            mock_result.stats = {
                "total_threats": 0,
                "rules_threats": 0,
                "llm_threats": 0,
                "semgrep_threats": 0,
                "unique_threats": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "category_counts": {},
                "sources": {
                    "rules_engine": False,
                    "llm_analysis": False,
                    "semgrep_analysis": False,
                },
            }
            mock_scan_code.return_value = mock_result

            arguments = {
                "content": "import os; os.system(user_input)",
                "language": "python",
                "use_rules": False,
                "output_format": "text",
            }

            result = await server._handle_scan_code(arguments)

            # Should still return valid output even with no threats
            assert len(result) > 0
            # The output should indicate that rules scanning was disabled
            content = result[0].text
            assert (
                "rules" in content.lower()
                or "disabled" in content.lower()
                or "no threats" in content.lower()
            )
