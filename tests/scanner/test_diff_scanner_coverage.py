"""Comprehensive tests for diff_scanner.py to improve coverage."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.scanner.diff_scanner import (
    DiffChunk,
    GitDiffError,
    GitDiffParser,
    GitDiffScanner,
)
from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult, ScanEngine
from adversary_mcp_server.scanner.types import Severity


class TestGitDiffError:
    """Tests for GitDiffError exception."""

    def test_git_diff_error_creation(self):
        """Test GitDiffError exception creation."""
        error = GitDiffError("test error message")
        assert str(error) == "test error message"
        assert isinstance(error, Exception)

    def test_git_diff_error_inheritance(self):
        """Test GitDiffError inherits from Exception."""
        error = GitDiffError("test")
        assert isinstance(error, Exception)
        assert isinstance(error, GitDiffError)


class TestDiffChunk:
    """Tests for DiffChunk class."""

    def test_diff_chunk_initialization(self):
        """Test DiffChunk initialization."""
        chunk = DiffChunk("test.py", 10, 5, 15, 3)

        assert chunk.file_path == "test.py"
        assert chunk.old_start == 10
        assert chunk.old_count == 5
        assert chunk.new_start == 15
        assert chunk.new_count == 3
        assert chunk.added_lines == []
        assert chunk.removed_lines == []
        assert chunk.context_lines == []

    def test_diff_chunk_add_line_added(self):
        """Test adding a line with '+' type."""
        chunk = DiffChunk("test.py", 1, 1, 1, 1)
        chunk.add_line("+", 10, "new code line")

        assert len(chunk.added_lines) == 1
        assert chunk.added_lines[0] == (10, "new code line")
        assert len(chunk.removed_lines) == 0
        assert len(chunk.context_lines) == 0

    def test_diff_chunk_add_line_removed(self):
        """Test adding a line with '-' type."""
        chunk = DiffChunk("test.py", 1, 1, 1, 1)
        chunk.add_line("-", 5, "old code line")

        assert len(chunk.removed_lines) == 1
        assert chunk.removed_lines[0] == (5, "old code line")
        assert len(chunk.added_lines) == 0
        assert len(chunk.context_lines) == 0

    def test_diff_chunk_add_line_context(self):
        """Test adding a context line."""
        chunk = DiffChunk("test.py", 1, 1, 1, 1)
        chunk.add_line(" ", 8, "context line")

        assert len(chunk.context_lines) == 1
        assert chunk.context_lines[0] == (8, "context line")
        assert len(chunk.added_lines) == 0
        assert len(chunk.removed_lines) == 0

    def test_diff_chunk_get_changed_code(self):
        """Test getting changed code from chunk."""
        chunk = DiffChunk("test.py", 1, 3, 1, 3)
        chunk.add_line(" ", 1, "context line 1")
        chunk.add_line(" ", 2, "context line 2")
        chunk.add_line("+", 3, "new code line")
        chunk.add_line("+", 4, "another new line")

        changed_code = chunk.get_changed_code()
        expected = "context line 1\ncontext line 2\nnew code line\nanother new line"
        assert changed_code == expected

    def test_diff_chunk_get_changed_code_empty(self):
        """Test getting changed code from empty chunk."""
        chunk = DiffChunk("test.py", 1, 1, 1, 1)
        changed_code = chunk.get_changed_code()
        assert changed_code == ""

    def test_diff_chunk_get_added_lines_with_minimal_context(self):
        """Test getting added lines with minimal context."""
        chunk = DiffChunk("test.py", 1, 5, 1, 5)
        chunk.add_line(" ", 1, "context 1")
        chunk.add_line(" ", 2, "context 2")
        chunk.add_line(" ", 3, "context 3")
        chunk.add_line("+", 4, "new line 1")
        chunk.add_line("+", 5, "new line 2")

        result = chunk.get_added_lines_with_minimal_context()
        lines = result.split("\n")

        # Should include max 2 context lines with CONTEXT prefix
        assert "// CONTEXT: context 1" in lines
        assert "// CONTEXT: context 2" in lines
        assert "context 3" not in result or "// CONTEXT: context 3" not in lines
        assert "new line 1" in lines
        assert "new line 2" in lines

    def test_diff_chunk_get_added_lines_with_minimal_context_no_context(self):
        """Test getting added lines with no context available."""
        chunk = DiffChunk("test.py", 1, 2, 1, 2)
        chunk.add_line("+", 1, "new line only")

        result = chunk.get_added_lines_with_minimal_context()
        assert result == "new line only"
        assert "CONTEXT" not in result

    def test_diff_chunk_get_added_lines_only(self):
        """Test getting only added lines."""
        chunk = DiffChunk("test.py", 1, 3, 1, 3)
        chunk.add_line(" ", 1, "context line")
        chunk.add_line("+", 2, "added line 1")
        chunk.add_line("-", 3, "removed line")
        chunk.add_line("+", 4, "added line 2")

        result = chunk.get_added_lines_only()
        assert result == "added line 1\nadded line 2"
        assert "context line" not in result
        assert "removed line" not in result

    def test_diff_chunk_get_added_lines_only_empty(self):
        """Test getting added lines when none exist."""
        chunk = DiffChunk("test.py", 1, 2, 1, 1)
        chunk.add_line(" ", 1, "context line")
        chunk.add_line("-", 2, "removed line")

        result = chunk.get_added_lines_only()
        assert result == ""


class TestGitDiffParser:
    """Tests for GitDiffParser class."""

    def test_git_diff_parser_initialization(self):
        """Test GitDiffParser initialization."""
        parser = GitDiffParser()

        assert hasattr(parser, "diff_header_pattern")
        assert hasattr(parser, "chunk_header_pattern")
        assert hasattr(parser, "file_header_pattern")

    def test_git_diff_parser_regex_patterns(self):
        """Test regex patterns work correctly."""
        parser = GitDiffParser()

        # Test diff header pattern
        diff_match = parser.diff_header_pattern.match("diff --git a/old.py b/new.py")
        assert diff_match is not None
        assert diff_match.group(1) == "old.py"
        assert diff_match.group(2) == "new.py"

        # Test chunk header pattern
        chunk_match = parser.chunk_header_pattern.match("@@ -10,5 +15,3 @@")
        assert chunk_match is not None
        assert chunk_match.group(1) == "10"
        assert chunk_match.group(2) == "5"
        assert chunk_match.group(3) == "15"
        assert chunk_match.group(4) == "3"

        # Test chunk header pattern with optional counts
        chunk_match_simple = parser.chunk_header_pattern.match("@@ -10 +15 @@")
        assert chunk_match_simple is not None
        assert chunk_match_simple.group(1) == "10"
        assert chunk_match_simple.group(2) is None
        assert chunk_match_simple.group(3) == "15"
        assert chunk_match_simple.group(4) is None

    def test_parse_diff_simple(self):
        """Test parsing a simple diff."""
        parser = GitDiffParser()
        diff_output = """diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
 line 1
-old line 2
+new line 2
+added line 3
 line 4"""

        result = parser.parse_diff(diff_output)

        assert "test.py" in result
        assert len(result["test.py"]) == 1

        chunk = result["test.py"][0]
        assert chunk.file_path == "test.py"
        assert chunk.old_start == 1
        assert chunk.old_count == 3
        assert chunk.new_start == 1
        assert chunk.new_count == 4

        # Check that lines were parsed correctly
        assert len(chunk.context_lines) >= 1
        assert len(chunk.added_lines) >= 1
        assert len(chunk.removed_lines) >= 1

    def test_parse_diff_empty(self):
        """Test parsing empty diff."""
        parser = GitDiffParser()
        result = parser.parse_diff("")
        assert result == {}

    def test_parse_diff_no_changes(self):
        """Test parsing diff with no actual changes."""
        parser = GitDiffParser()
        diff_output = """diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py"""

        result = parser.parse_diff(diff_output)
        assert "test.py" in result
        assert len(result["test.py"]) == 0

    def test_parse_diff_multiple_files(self):
        """Test parsing diff with multiple files."""
        parser = GitDiffParser()
        diff_output = """diff --git a/file1.py b/file1.py
index 1234567..abcdefg 100644
--- a/file1.py
+++ b/file1.py
@@ -1,2 +1,3 @@
 line 1
+added in file1
 line 2
diff --git a/file2.js b/file2.js
index 7890abc..defghij 100644
--- a/file2.js
+++ b/file2.js
@@ -5,3 +5,4 @@
 line 5
+added in file2
 line 6"""

        result = parser.parse_diff(diff_output)

        assert "file1.py" in result
        assert "file2.js" in result
        assert len(result["file1.py"]) == 1
        assert len(result["file2.js"]) == 1

    def test_parse_diff_multiple_chunks_same_file(self):
        """Test parsing diff with multiple chunks in same file."""
        parser = GitDiffParser()
        diff_output = """diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,2 +1,3 @@
 line 1
+added line 2
 line 3
@@ -10,2 +11,3 @@
 line 10
+added line 11
 line 12"""

        result = parser.parse_diff(diff_output)

        assert "test.py" in result
        assert len(result["test.py"]) == 2

        # Check both chunks
        chunk1 = result["test.py"][0]
        chunk2 = result["test.py"][1]

        assert chunk1.new_start == 1
        assert chunk2.new_start == 11

    def test_parse_diff_skip_file_headers(self):
        """Test that file headers (+++ and ---) are properly skipped."""
        parser = GitDiffParser()
        diff_output = """diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,2 +1,3 @@
 line 1
+added line
 line 2"""

        result = parser.parse_diff(diff_output)

        # Make sure the +++ and --- lines didn't get parsed as content
        chunk = result["test.py"][0]
        added_content = [content for _, content in chunk.added_lines]
        assert "a/test.py" not in added_content
        assert "b/test.py" not in added_content


class TestGitDiffScanner:
    """Tests for GitDiffScanner class."""

    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    def test_git_diff_scanner_initialization_default(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test GitDiffScanner initialization with defaults."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        assert scanner.scan_engine is not None
        assert scanner.working_dir == Path.cwd()
        assert scanner.parser is not None
        assert scanner.config_manager is not None
        assert scanner.error_handler is not None

    def test_git_diff_scanner_initialization_with_params(self):
        """Test GitDiffScanner initialization with custom parameters."""
        mock_scan_engine = Mock(spec=ScanEngine)
        test_dir = Path("/tmp/test")
        mock_metrics = Mock()

        scanner = GitDiffScanner(
            scan_engine=mock_scan_engine,
            working_dir=test_dir,
            metrics_collector=mock_metrics,
        )

        assert scanner.scan_engine == mock_scan_engine
        assert scanner.working_dir == test_dir
        assert scanner.metrics_collector == mock_metrics

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_run_git_command_success(self, mock_config_manager, mock_scan_engine):
        """Test successful git command execution."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = (b"git output", b"")
            mock_exec.return_value = mock_proc

            result = await scanner._run_git_command(["status"])

            assert result == "git output"
            mock_exec.assert_called_once()

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_run_git_command_failure(self, mock_config_manager, mock_scan_engine):
        """Test git command execution failure."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 1
            mock_proc.communicate.return_value = (b"", b"error message")
            mock_exec.return_value = mock_proc

            with pytest.raises(GitDiffError, match="Git command failed"):
                await scanner._run_git_command(["status"])

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_run_git_command_not_found(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test git command not found error."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            with pytest.raises(GitDiffError):
                await scanner._run_git_command(["status"])

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_run_git_command_timeout(self, mock_config_manager, mock_scan_engine):
        """Test git command timeout handling."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.side_effect = TimeoutError()
            mock_proc.returncode = None
            mock_exec.return_value = mock_proc

            # The error handler will catch the timeout and potentially retry
            with pytest.raises((GitDiffError, asyncio.TimeoutError)):
                await scanner._run_git_command(["status"])

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_run_git_command_with_metrics(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test git command execution with metrics collection."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        mock_metrics = Mock()
        scanner = GitDiffScanner(metrics_collector=mock_metrics)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = (b"git output", b"")
            mock_exec.return_value = mock_proc

            result = await scanner._run_git_command(["status"])

            assert result == "git output"
            # Should record metrics for git operations
            assert mock_metrics.record_metric.called
            assert mock_metrics.record_histogram.called

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_validate_branches_success(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test successful branch validation."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch.object(
            scanner, "_run_git_command", new_callable=AsyncMock
        ) as mock_git:
            mock_git.return_value = "commit_hash"

            # Should not raise an exception
            await scanner._validate_branches("feature", "main")

            # Should call git rev-parse for both branches
            assert mock_git.call_count == 2

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_validate_branches_failure(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test branch validation failure."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch.object(
            scanner, "_run_git_command", new_callable=AsyncMock
        ) as mock_git:
            mock_git.side_effect = GitDiffError("branch not found")

            with pytest.raises(GitDiffError, match="Branch validation failed"):
                await scanner._validate_branches("nonexistent", "main")

    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    def test_detect_language_from_path(self, mock_config_manager, mock_scan_engine):
        """Test language detection from file path."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        # Test with various file extensions - patch at module level where it's imported
        with patch(
            "adversary_mcp_server.scanner.language_mapping.LanguageMapper.detect_language_from_extension"
        ) as mock_detect:
            mock_detect.return_value = "python"

            language = scanner._detect_language_from_path("test.py")
            assert language == "python"
            mock_detect.assert_called_once_with("test.py")

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_get_diff_changes_success(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test successful diff changes retrieval."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        mock_diff_output = """diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,2 +1,3 @@
 line 1
+added line
 line 2"""

        with patch.object(
            scanner, "_validate_branches", new_callable=AsyncMock
        ) as mock_validate:
            with patch.object(
                scanner, "_run_git_command", new_callable=AsyncMock
            ) as mock_git:
                mock_git.return_value = mock_diff_output

                result = await scanner.get_diff_changes("feature", "main")

                assert "test.py" in result
                assert len(result["test.py"]) == 1
                mock_validate.assert_called_once_with("feature", "main", None)

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_get_diff_changes_no_differences(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test diff changes when no differences exist."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch.object(scanner, "_validate_branches", new_callable=AsyncMock):
            with patch.object(
                scanner, "_run_git_command", new_callable=AsyncMock
            ) as mock_git:
                mock_git.return_value = ""

                result = await scanner.get_diff_changes("feature", "main")

                assert result == {}

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_get_diff_changes_with_metrics(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test diff changes retrieval with metrics collection."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        mock_metrics = Mock()
        scanner = GitDiffScanner(metrics_collector=mock_metrics)

        with patch.object(scanner, "_validate_branches", new_callable=AsyncMock):
            with patch.object(
                scanner, "_run_git_command", new_callable=AsyncMock
            ) as mock_git:
                mock_git.return_value = ""

                await scanner.get_diff_changes("feature", "main")

                # Should record metrics for diff analysis
                assert mock_metrics.record_metric.called
                assert mock_metrics.record_histogram.called

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_scan_diff_no_changes(self, mock_config_manager, mock_scan_engine):
        """Test diff scanning when no changes exist."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_changes:
            mock_changes.return_value = {}

            result = await scanner.scan_diff("feature", "main")

            assert result == {}

    @pytest.mark.asyncio
    async def test_scan_diff_with_changes(self):
        """Test diff scanning with actual changes."""
        mock_scan_engine = AsyncMock(spec=ScanEngine)
        mock_scan_result = Mock(spec=EnhancedScanResult)
        mock_scan_result.all_threats = []
        mock_scan_engine.scan_code.return_value = mock_scan_result

        scanner = GitDiffScanner(scan_engine=mock_scan_engine)

        # Create mock diff changes
        mock_chunk = Mock(spec=DiffChunk)
        mock_chunk.added_lines = [(1, "test code line")]
        mock_chunk.get_added_lines_only.return_value = "test code line"

        mock_changes = {"test.py": [mock_chunk]}

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            with patch.object(scanner, "_detect_language_from_path") as mock_detect:
                mock_get_changes.return_value = mock_changes
                mock_detect.return_value = "python"

                result = await scanner.scan_diff("feature", "main")

                assert "test.py" in result
                assert len(result["test.py"]) == 1
                mock_scan_engine.scan_code.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_diff_with_threat_line_mapping(self):
        """Test diff scanning with threat line number remapping."""
        mock_scan_engine = AsyncMock(spec=ScanEngine)
        mock_scan_result = Mock(spec=EnhancedScanResult)

        # Create a mock threat with line number
        mock_threat = Mock()
        mock_threat.line_number = 1
        mock_scan_result.all_threats = [mock_threat]
        mock_scan_engine.scan_code.return_value = mock_scan_result

        scanner = GitDiffScanner(scan_engine=mock_scan_engine)

        # Create mock diff chunk with line mapping
        mock_chunk = Mock(spec=DiffChunk)
        mock_chunk.added_lines = [(10, "test code line")]  # Original line 10
        mock_chunk.get_added_lines_only.return_value = "test code line"

        mock_changes = {"test.py": [mock_chunk]}

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            with patch.object(scanner, "_detect_language_from_path") as mock_detect:
                mock_get_changes.return_value = mock_changes
                mock_detect.return_value = "python"

                result = await scanner.scan_diff("feature", "main")

                # Threat line number should be remapped from 1 to 10
                assert mock_threat.line_number == 10

    @pytest.mark.asyncio
    async def test_scan_diff_scan_failure(self):
        """Test diff scanning when scan engine fails."""
        mock_scan_engine = AsyncMock(spec=ScanEngine)
        mock_scan_engine.scan_code.side_effect = Exception("Scan failed")

        scanner = GitDiffScanner(scan_engine=mock_scan_engine)

        # Create mock diff changes
        mock_chunk = Mock(spec=DiffChunk)
        mock_chunk.added_lines = [(1, "test code line")]
        mock_chunk.get_added_lines_only.return_value = "test code line"

        mock_changes = {"test.py": [mock_chunk]}

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            with patch.object(scanner, "_detect_language_from_path") as mock_detect:
                mock_get_changes.return_value = mock_changes
                mock_detect.return_value = "python"

                result = await scanner.scan_diff("feature", "main")

                # Should return empty result for failed file, but not crash
                assert result == {}

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_scan_diff_skip_files_no_added_code(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test diff scanning skips files with no added code."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        # Create mock diff chunk with no added lines
        mock_chunk = Mock(spec=DiffChunk)
        mock_chunk.added_lines = []
        mock_chunk.get_added_lines_only.return_value = ""

        mock_changes = {"test.py": [mock_chunk]}

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            mock_get_changes.return_value = mock_changes

            result = await scanner.scan_diff("feature", "main")

            # Should return empty result since no code to scan
            assert result == {}

    @pytest.mark.asyncio
    async def test_scan_diff_with_all_scan_options(self):
        """Test diff scanning with all scan options enabled."""
        mock_scan_engine = AsyncMock(spec=ScanEngine)
        mock_scan_result = Mock(spec=EnhancedScanResult)
        mock_scan_result.all_threats = []
        mock_scan_engine.scan_code.return_value = mock_scan_result

        scanner = GitDiffScanner(scan_engine=mock_scan_engine)

        # Create mock diff changes
        mock_chunk = Mock(spec=DiffChunk)
        mock_chunk.added_lines = [(1, "test code line")]
        mock_chunk.get_added_lines_only.return_value = "test code line"

        mock_changes = {"test.py": [mock_chunk]}

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            with patch.object(scanner, "_detect_language_from_path") as mock_detect:
                mock_get_changes.return_value = mock_changes
                mock_detect.return_value = "python"

                result = await scanner.scan_diff(
                    "feature",
                    "main",
                    use_llm=True,
                    use_semgrep=True,
                    use_validation=True,
                    use_rules=True,
                    severity_threshold=Severity.MEDIUM,
                )

                # Verify scan_code was called with correct parameters
                mock_scan_engine.scan_code.assert_called_once()
                call_args = mock_scan_engine.scan_code.call_args
                assert call_args.kwargs["use_llm"] is True
                assert call_args.kwargs["use_semgrep"] is True
                assert call_args.kwargs["use_validation"] is True
                assert call_args.kwargs["severity_threshold"] == Severity.MEDIUM

    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    def test_scan_diff_sync(self, mock_config_manager, mock_scan_engine):
        """Test synchronous wrapper for scan_diff."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch.object(scanner, "scan_diff", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = {"test.py": []}

            result = scanner.scan_diff_sync("feature", "main")

            assert result == {"test.py": []}
            mock_scan.assert_called_once()

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_get_diff_summary_success(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test successful diff summary generation."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        # Create mock diff changes
        mock_chunk1 = Mock(spec=DiffChunk)
        mock_chunk1.added_lines = [(1, "line1"), (2, "line2")]
        mock_chunk1.removed_lines = [(1, "old_line")]

        mock_chunk2 = Mock(spec=DiffChunk)
        mock_chunk2.added_lines = [(3, "line3")]
        mock_chunk2.removed_lines = []

        mock_changes = {"file1.py": [mock_chunk1], "file2.js": [mock_chunk2]}

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            mock_get_changes.return_value = mock_changes

            summary = await scanner.get_diff_summary("feature", "main")

            assert summary["source_branch"] == "feature"
            assert summary["target_branch"] == "main"
            assert summary["total_files_changed"] == 2
            assert summary["supported_files"] == 2
            assert summary["total_chunks"] == 2
            assert summary["lines_added"] == 3  # 2 + 1
            assert summary["lines_removed"] == 1
            assert "file1.py" in summary["scannable_files"]
            assert "file2.js" in summary["scannable_files"]

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_get_diff_summary_failure(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test diff summary generation failure."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            mock_get_changes.side_effect = GitDiffError("Git error")

            summary = await scanner.get_diff_summary("feature", "main")

            assert summary["source_branch"] == "feature"
            assert summary["target_branch"] == "main"
            assert "error" in summary
            assert summary["error"] == "Failed to get diff summary"

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.ScanEngine")
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_get_diff_summary_no_changes(
        self, mock_config_manager, mock_scan_engine
    ):
        """Test diff summary with no changes."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )
        mock_scan_engine.return_value = Mock()

        scanner = GitDiffScanner()

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            mock_get_changes.return_value = {}

            summary = await scanner.get_diff_summary("feature", "main")

            assert summary["total_files_changed"] == 0
            assert summary["supported_files"] == 0
            assert summary["total_chunks"] == 0
            assert summary["lines_added"] == 0
            assert summary["lines_removed"] == 0
            assert summary["scannable_files"] == []

    @pytest.mark.asyncio
    async def test_scan_diff_with_metrics_collection(self):
        """Test diff scanning with comprehensive metrics collection."""
        mock_metrics = Mock()
        mock_scan_engine = AsyncMock(spec=ScanEngine)
        mock_scan_result = Mock(spec=EnhancedScanResult)
        mock_scan_result.all_threats = []
        mock_scan_engine.scan_code.return_value = mock_scan_result

        scanner = GitDiffScanner(
            scan_engine=mock_scan_engine, metrics_collector=mock_metrics
        )

        # Create mock diff changes
        mock_chunk = Mock(spec=DiffChunk)
        mock_chunk.added_lines = [(1, "test code line")]
        mock_chunk.get_added_lines_only.return_value = "test code line"

        mock_changes = {"test.py": [mock_chunk]}

        with patch.object(
            scanner, "get_diff_changes", new_callable=AsyncMock
        ) as mock_get_changes:
            with patch.object(scanner, "_detect_language_from_path") as mock_detect:
                mock_get_changes.return_value = mock_changes
                mock_detect.return_value = "python"

                await scanner.scan_diff("feature", "main")

                # Should record various metrics
                metric_calls = mock_metrics.record_metric.call_args_list
                histogram_calls = mock_metrics.record_histogram.call_args_list

                # Should have recorded scan operation metrics
                metric_names = [call[0][0] for call in metric_calls]
                assert "diff_scan_operations_total" in metric_names
                assert "diff_scan_files_processed" in metric_names


class TestDiffScannerIntegration:
    """Integration tests for DiffScanner components."""

    def test_integration_diff_chunk_and_parser(self):
        """Test integration between DiffChunk and GitDiffParser."""
        parser = GitDiffParser()

        diff_output = """diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
 unchanged line
-removed line
+added line 1
+added line 2
 another unchanged line"""

        chunks = parser.parse_diff(diff_output)

        assert "test.py" in chunks
        chunk = chunks["test.py"][0]

        # Test chunk methods work correctly
        changed_code = chunk.get_changed_code()
        added_only = chunk.get_added_lines_only()
        minimal_context = chunk.get_added_lines_with_minimal_context()

        assert "added line 1" in changed_code
        assert "added line 2" in changed_code
        assert "unchanged line" in changed_code

        assert "added line 1" in added_only
        assert "added line 2" in added_only
        assert "removed line" not in added_only
        assert "unchanged line" not in added_only

        assert "added line 1" in minimal_context
        assert "added line 2" in minimal_context

    @pytest.mark.asyncio
    @patch("adversary_mcp_server.scanner.diff_scanner.get_config_manager")
    async def test_integration_scanner_with_real_diff_parsing(
        self, mock_config_manager
    ):
        """Test GitDiffScanner integration with real diff parsing."""
        mock_config_manager.return_value = Mock()
        mock_config_manager.return_value.dynamic_limits = Mock(
            circuit_breaker_failure_threshold=5,
            circuit_breaker_recovery_timeout=60,
            max_retry_attempts=3,
            retry_base_delay=1.0,
            scan_timeout_seconds=30,
        )

        mock_scan_engine = AsyncMock(spec=ScanEngine)
        mock_scan_result = Mock(spec=EnhancedScanResult)
        mock_scan_result.all_threats = []
        mock_scan_engine.scan_code.return_value = mock_scan_result

        scanner = GitDiffScanner(scan_engine=mock_scan_engine)

        # Mock git commands to return a realistic diff
        diff_output = """diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,2 +1,3 @@
 existing_line = "hello"
+new_risky_code = eval(user_input)
 print("done")"""

        with patch.object(scanner, "_validate_branches", new_callable=AsyncMock):
            with patch.object(
                scanner, "_run_git_command", new_callable=AsyncMock
            ) as mock_git:
                with patch.object(scanner, "_detect_language_from_path") as mock_detect:
                    mock_git.return_value = diff_output
                    mock_detect.return_value = "python"

                    result = await scanner.scan_diff("feature", "main")

                    # Should have processed the file and called scan_code
                    assert "test.py" in result
                    mock_scan_engine.scan_code.assert_called_once()

                    # Check the code passed to scan_code contains only the new line
                    call_args = mock_scan_engine.scan_code.call_args
                    scanned_code = call_args.kwargs["source_code"]
                    assert "new_risky_code = eval(user_input)" in scanned_code
                    assert 'existing_line = "hello"' not in scanned_code
                    assert 'print("done")' not in scanned_code
