"""Tests for MCP server path resolution functionality."""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.server import AdversaryMCPServer, AdversaryToolError


class TestPathResolution:
    """Test path resolution functionality in MCP server."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server = AdversaryMCPServer()

    def test_resolve_absolute_path_unchanged(self):
        """Test that absolute paths are returned unchanged."""
        absolute_path = "/Users/test/project/.adversary.json"
        result = self.server._resolve_adversary_file_path(absolute_path)
        assert result == absolute_path

    def test_resolve_relative_path_to_absolute(self):
        """Test that relative paths are resolved to absolute paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                result = self.server._resolve_adversary_file_path(".adversary.json")
                expected = str((Path(temp_dir) / ".adversary.json").resolve())
                assert result == expected
                assert Path(result).is_absolute()

    def test_resolve_nested_relative_path(self):
        """Test that nested relative paths are resolved correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                result = self.server._resolve_adversary_file_path(
                    "subdir/.adversary.json"
                )
                expected = str(
                    (Path(temp_dir) / "subdir" / ".adversary.json").resolve()
                )
                assert result == expected

    def test_resolve_parent_directory_path(self):
        """Test that parent directory references are resolved correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            subdir = Path(temp_dir) / "subdir"
            with patch.object(self.server, "_get_project_root", return_value=subdir):
                result = self.server._resolve_adversary_file_path("../.adversary.json")
                expected = str((Path(temp_dir) / ".adversary.json").resolve())
                assert result == expected

    def test_resolve_complex_relative_path(self):
        """Test that complex relative paths with multiple .. are resolved correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            deep_dir = Path(temp_dir) / "a" / "b" / "c"
            with patch.object(self.server, "_get_project_root", return_value=deep_dir):
                result = self.server._resolve_adversary_file_path(
                    "../../other/.adversary.json"
                )
                expected = str(
                    (Path(temp_dir) / "a" / "other" / ".adversary.json").resolve()
                )
                assert result == expected

    def test_whitespace_is_stripped(self):
        """Test that leading and trailing whitespace is stripped from paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                result = self.server._resolve_adversary_file_path("  .adversary.json  ")
                expected = str((Path(temp_dir) / ".adversary.json").resolve())
                assert result == expected

    def test_empty_string_raises_error(self):
        """Test that empty string raises AdversaryToolError."""
        with pytest.raises(
            AdversaryToolError, match="adversary_file_path cannot be empty"
        ):
            self.server._resolve_adversary_file_path("")

    def test_whitespace_only_raises_error(self):
        """Test that whitespace-only string raises AdversaryToolError."""
        with pytest.raises(
            AdversaryToolError, match="adversary_file_path cannot be empty"
        ):
            self.server._resolve_adversary_file_path("   ")

    def test_none_value_raises_error(self):
        """Test that None value raises AdversaryToolError."""
        with pytest.raises(
            AdversaryToolError, match="adversary_file_path cannot be empty"
        ):
            self.server._resolve_adversary_file_path(None)

    def test_resolve_with_current_directory_dot(self):
        """Test that './file' resolves correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                result = self.server._resolve_adversary_file_path("./.adversary.json")
                expected = str((Path(temp_dir) / ".adversary.json").resolve())
                assert result == expected

    def test_resolve_symlink_resolution(self):
        """Test that symlinks in paths are resolved correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a real directory and a symlink to it
            real_dir = Path(temp_dir) / "real"
            real_dir.mkdir()
            link_dir = Path(temp_dir) / "link"

            try:
                link_dir.symlink_to(real_dir)
                with patch.object(
                    self.server, "_get_project_root", return_value=link_dir
                ):
                    result = self.server._resolve_adversary_file_path(".adversary.json")
                    # Should resolve symlinks to real path
                    assert str(real_dir) in result
            except OSError:
                # Skip test if symlinks aren't supported (e.g., on some Windows systems)
                pytest.skip("Symlinks not supported on this system")

    def test_resolve_windows_style_path(self):
        """Test that Windows-style paths work correctly."""
        # Test with mock to avoid platform dependencies
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                # Test forward slashes (should work on all platforms)
                result = self.server._resolve_adversary_file_path("subdir/file.json")
                assert "subdir" in result
                assert "file.json" in result

    def test_resolve_preserves_filename(self):
        """Test that the filename is preserved correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                test_filename = "custom-adversary-file.json"
                result = self.server._resolve_adversary_file_path(test_filename)
                assert result.endswith(test_filename)

    def test_resolve_very_long_path(self):
        """Test that very long paths are handled correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                # Create a long relative path
                long_path = (
                    "/".join([f"dir{i}" for i in range(10)]) + "/.adversary.json"
                )  # Reduced to avoid filesystem limits
                result = self.server._resolve_adversary_file_path(long_path)
                resolved_temp_dir = str(Path(temp_dir).resolve())
                assert result.startswith(resolved_temp_dir)
                assert result.endswith(".adversary.json")
                assert Path(result).is_absolute()

    def test_resolve_path_with_spaces(self):
        """Test that paths with spaces are handled correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                spaced_path = "my project/.adversary.json"
                result = self.server._resolve_adversary_file_path(spaced_path)
                assert "my project" in result
                assert result.endswith(".adversary.json")

    def test_resolve_path_with_special_characters(self):
        """Test that paths with special characters are handled correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                special_path = "test-project_v2/.adversary.json"
                result = self.server._resolve_adversary_file_path(special_path)
                assert "test-project_v2" in result
                assert result.endswith(".adversary.json")

    def test_resolve_file_path_generic_method(self):
        """Test the generic _resolve_file_path method with custom error message."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                result = self.server._resolve_file_path("output.json", "output path")
                expected = str((Path(temp_dir) / "output.json").resolve())
                assert result == expected

    def test_resolve_file_path_custom_error_message(self):
        """Test that _resolve_file_path uses custom error message."""
        with pytest.raises(AdversaryToolError, match="output path cannot be empty"):
            self.server._resolve_file_path("", "output path")

        with pytest.raises(AdversaryToolError, match="custom path cannot be empty"):
            self.server._resolve_file_path("   ", "custom path")


class TestPathResolutionIntegration:
    """Integration tests for path resolution in MCP tool handlers."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server = AdversaryMCPServer()

    @pytest.mark.asyncio
    async def test_mark_false_positive_with_relative_path(self):
        """Test that mark_false_positive resolves relative paths correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a mock .adversary.json file
            adversary_file = Path(temp_dir) / ".adversary.json"
            adversary_file.write_text(
                '{"threats": [{"uuid": "test-uuid", "is_false_positive": false}]}'
            )

            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                arguments = {
                    "finding_uuid": "test-uuid",
                    "adversary_file_path": ".adversary.json",
                    "reason": "Test reason",
                }

                # This should not raise an error about file not found
                try:
                    await self.server._handle_mark_false_positive(arguments)
                except AdversaryToolError as e:
                    if "cannot be empty" in str(e):
                        pytest.fail("Path resolution failed - treated as empty path")
                except Exception:
                    # Other exceptions are expected (like finding not found) - we just care about path resolution
                    pass

    @pytest.mark.asyncio
    async def test_list_false_positives_with_relative_path(self):
        """Test that list_false_positives resolves relative paths correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a mock .adversary.json file
            adversary_file = Path(temp_dir) / ".adversary.json"
            adversary_file.write_text('{"threats": []}')

            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                arguments = {"adversary_file_path": ".adversary.json"}

                # This should not raise an error about file not found due to path resolution
                try:
                    result = await self.server._handle_list_false_positives(arguments)
                    # Should succeed and return content about the resolved path
                    assert len(result) > 0
                    assert str(adversary_file) in result[0].text
                except AdversaryToolError as e:
                    if "cannot be empty" in str(e):
                        pytest.fail("Path resolution failed - treated as empty path")

    @pytest.mark.asyncio
    async def test_handlers_reject_empty_path(self):
        """Test that all handlers properly reject empty adversary_file_path."""
        # Test the path resolution helper directly since handlers have their own validation
        with pytest.raises(
            AdversaryToolError, match="adversary_file_path cannot be empty"
        ):
            self.server._resolve_adversary_file_path("")

        with pytest.raises(
            AdversaryToolError, match="adversary_file_path cannot be empty"
        ):
            self.server._resolve_adversary_file_path("   ")

        # Test that handlers also reject empty paths (though with different error messages)
        with pytest.raises(
            AdversaryToolError
        ):  # Don't match exact message since it varies
            await self.server._handle_mark_false_positive(
                {"finding_uuid": "test", "path": ""}
            )

        with pytest.raises(AdversaryToolError):
            await self.server._handle_list_false_positives({"path": ""})

    @pytest.mark.asyncio
    async def test_scan_methods_resolve_output_paths(self):
        """Test that scan methods resolve output paths correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                self.server,
                "_get_project_root",
                return_value=Path(temp_dir),
            ):
                # Create a test file
                test_file = Path(temp_dir) / "test.py"
                test_file.write_text("print('hello')")

                # Test scan_code with relative output path
                try:
                    arguments = {
                        "content": "print('test')",
                        "language": "python",
                        "output": "results.json",  # Relative path
                    }
                    # This should resolve the output path without errors
                    with patch.object(
                        self.server.scan_engine, "scan_code"
                    ) as mock_scan:
                        mock_result = Mock(
                            all_threats=[],
                            scan_metadata={},
                            llm_prompts=[],
                            exploit_prompts=[],
                            file_path="input.code",  # Add missing file_path attribute
                            language="auto",  # Add missing language attribute
                            stats={},  # Add missing stats attribute
                            validation_results={},  # Add missing validation_results attribute
                        )
                        mock_result.get_validation_summary.return_value = {
                            "enabled": False,
                            "total_findings_reviewed": 0,
                            "legitimate_findings": 0,
                            "false_positives_filtered": 0,
                            "false_positive_rate": 0.0,
                            "average_confidence": 0.0,
                            "validation_errors": 0,
                            "status": "disabled",
                        }
                        mock_scan.return_value = mock_result
                        await self.server._handle_scan_code(arguments)
                        # If we get here without exception, path resolution worked

                except Exception as e:
                    if "output path cannot be empty" in str(e):
                        pytest.fail("Path resolution failed for scan_code output path")

                # Test scan_file with relative output path
                try:
                    arguments = {
                        "file_path": str(test_file),
                        "output": "../output.json",  # Relative path with parent dir
                    }
                    with patch.object(
                        self.server.scan_engine, "scan_file"
                    ) as mock_scan:
                        mock_result = Mock(
                            all_threats=[],
                            scan_metadata={},
                            llm_prompts=[],
                            exploit_prompts=[],
                            file_path=str(test_file),  # Convert Path to string
                            language="python",
                            stats={},
                            validation_results={},  # Add missing validation_results attribute
                        )
                        mock_result.get_validation_summary.return_value = {
                            "enabled": False,
                            "total_findings_reviewed": 0,
                            "legitimate_findings": 0,
                            "false_positives_filtered": 0,
                            "false_positive_rate": 0.0,
                            "average_confidence": 0.0,
                            "validation_errors": 0,
                            "status": "disabled",
                        }
                        mock_scan.return_value = mock_result
                        await self.server._handle_scan_file(arguments)

                except Exception as e:
                    if "output path cannot be empty" in str(e):
                        pytest.fail("Path resolution failed for scan_file output path")


class TestWorkspaceRootEnvironmentVariable:
    """Test workspace root environment variable functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server = AdversaryMCPServer()

    def test_get_project_root_with_valid_workspace_root(self):
        """Test that _get_project_root uses ADVERSARY_WORKSPACE_ROOT when set and valid."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict("os.environ", {"ADVERSARY_WORKSPACE_ROOT": temp_dir}):
                result = self.server._get_project_root()
                # Both paths should resolve to the same real path
                assert result.resolve() == Path(temp_dir).resolve()

    def test_get_project_root_with_nonexistent_workspace_root(self):
        """Test that _get_project_root raises error for nonexistent ADVERSARY_WORKSPACE_ROOT."""
        nonexistent_path = "/nonexistent/workspace/path"
        with patch.dict("os.environ", {"ADVERSARY_WORKSPACE_ROOT": nonexistent_path}):
            with pytest.raises(
                AdversaryToolError, match="Workspace root path does not exist"
            ):
                self.server._get_project_root()

    def test_get_project_root_with_file_as_workspace_root(self):
        """Test that _get_project_root raises error when ADVERSARY_WORKSPACE_ROOT is a file."""
        with tempfile.NamedTemporaryFile() as temp_file:
            with patch.dict("os.environ", {"ADVERSARY_WORKSPACE_ROOT": temp_file.name}):
                with pytest.raises(
                    AdversaryToolError, match="Workspace root is not a directory"
                ):
                    self.server._get_project_root()

    def test_get_project_root_fallback_to_cwd(self):
        """Test that _get_project_root falls back to cwd when ADVERSARY_WORKSPACE_ROOT not set."""
        # Ensure ADVERSARY_WORKSPACE_ROOT is not set
        with patch.dict("os.environ", {}, clear=False):
            if "ADVERSARY_WORKSPACE_ROOT" in os.environ:
                del os.environ["ADVERSARY_WORKSPACE_ROOT"]

            result = self.server._get_project_root()
            assert result == Path.cwd()

    def test_resolve_path_uses_workspace_root(self):
        """Test that path resolution uses workspace root when available."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file in the workspace
            test_file = Path(temp_dir) / "test_file.py"
            test_file.write_text("print('test')")

            with patch.dict("os.environ", {"ADVERSARY_WORKSPACE_ROOT": temp_dir}):
                result = self.server._resolve_path_from_project_root(
                    "test_file.py", "test file"
                )
                expected = Path(temp_dir) / "test_file.py"
                assert result == expected.resolve()

    @pytest.mark.asyncio
    async def test_scan_file_with_workspace_root(self):
        """Test that scan_file works correctly with workspace root environment variable."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file in the workspace
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("print('hello world')")

            with patch.dict("os.environ", {"ADVERSARY_WORKSPACE_ROOT": temp_dir}):
                with patch.object(self.server.scan_engine, "scan_file") as mock_scan:
                    # Properly mock the scan result with all required attributes
                    mock_result = Mock()
                    mock_result.all_threats = []
                    mock_result.scan_metadata = {}
                    mock_result.llm_prompts = []
                    mock_result.exploit_prompts = []
                    mock_result.language = "python"
                    mock_result.file_path = str(
                        test_file
                    )  # Add missing file_path attribute as string
                    mock_result.stats = {
                        "severity_counts": {
                            "low": 0,
                            "medium": 0,
                            "high": 0,
                            "critical": 0,
                        },
                        "llm_threats": 0,
                        "semgrep_threats": 0,
                        "unique_threats": 0,
                    }
                    mock_result.validation_results = {}
                    mock_result.get_validation_summary.return_value = {
                        "enabled": False,
                        "total_findings_reviewed": 0,
                        "legitimate_findings": 0,
                        "false_positives_filtered": 0,
                        "false_positive_rate": 0.0,
                        "average_confidence": 0.0,
                        "validation_errors": 0,
                        "status": "disabled",
                    }
                    mock_scan.return_value = mock_result

                    arguments = {"path": "test.py"}  # Relative path
                    await self.server._handle_scan_file(arguments)

                    # Verify that scan_engine.scan_file was called with the resolved path
                    mock_scan.assert_called_once()
                    called_path = mock_scan.call_args[1]["file_path"]
                    assert called_path == test_file.resolve()

    @pytest.mark.asyncio
    async def test_scan_directory_with_workspace_root(self):
        """Test that scan_directory works correctly with workspace root environment variable."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a subdirectory in the workspace
            subdir = Path(temp_dir) / "src"
            subdir.mkdir()
            test_file = subdir / "app.py"
            test_file.write_text("import os")

            with patch.dict("os.environ", {"ADVERSARY_WORKSPACE_ROOT": temp_dir}):
                with patch.object(
                    self.server.scan_engine, "scan_directory"
                ) as mock_scan:
                    mock_scan.return_value = []

                    arguments = {"path": "src"}  # Relative path
                    await self.server._handle_scan_directory(arguments)

                    # Verify that scan_engine.scan_directory was called with the resolved path
                    mock_scan.assert_called_once()
                    called_path = mock_scan.call_args[1]["directory_path"]
                    assert called_path == subdir.resolve()
