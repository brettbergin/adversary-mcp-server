"""Additional tests for incremental_utils.py to improve coverage."""

from pathlib import Path
from unittest.mock import Mock, patch

from adversary_mcp_server.session.incremental_utils import (
    GitChangeDetector,
    create_incremental_scan_context,
    filter_security_relevant_changes,
)


class TestGitChangeDetectorCoverage:
    """Additional tests to improve coverage of GitChangeDetector."""

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_with_empty_lines(self, mock_run, tmp_path):
        """Test git diff handling empty lines correctly."""
        # Create test files
        file1 = tmp_path / "file1.py"
        file1.write_text("content")

        # Mock git command output with empty lines
        mock_result = Mock()
        mock_result.stdout = "file1.py\n\n\nfile2.js\n\n"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_since_commit("abc123")

        # Should only return existing files, filtering out empty lines
        assert len(changed_files) == 1
        assert file1 in changed_files

    @patch("subprocess.run")
    def test_get_changed_files_in_working_directory_with_empty_lines(
        self, mock_run, tmp_path
    ):
        """Test working directory detection with empty lines."""
        # Create test files
        file1 = tmp_path / "modified.py"
        file1.write_text("content")

        # Mock git command output with empty lines
        mock_result = Mock()
        mock_result.stdout = "\n\nmodified.py\n\n"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_in_working_directory()

        # Should only return existing files, filtering out empty lines
        assert len(changed_files) == 1
        assert file1 in changed_files

    @patch("subprocess.run")
    def test_get_commit_info_with_complex_message(self, mock_run, tmp_path):
        """Test commit info with complex multi-line message."""
        mock_result = Mock()
        # Format: hash|author|email|subject|full_message
        # The git parsing only uses the first line, so multiline messages get truncated
        mock_result.stdout = "abc123|John Doe|john@example.com|Fix bug|Fix critical security bug\n\nThis is a detailed description\nwith multiple lines"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        commit_info = detector.get_commit_info("abc123")

        # The implementation only processes the first line of output
        expected = {
            "hash": "abc123",
            "author": "John Doe",
            "email": "john@example.com",
            "subject": "Fix bug",
            "message": "Fix critical security bug",  # Only first line is processed
        }
        assert commit_info == expected

    def test_project_root_resolution(self, tmp_path):
        """Test that project root is properly resolved."""
        # Create a subdirectory
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        # Test with relative path
        detector = GitChangeDetector(Path("./") / tmp_path.name / "subdir")
        # Should resolve to absolute path
        assert detector.project_root.is_absolute()
        assert detector.project_root.name == "subdir"


class TestCreateIncrementalScanContextCoverage:
    """Additional tests to improve coverage of create_incremental_scan_context."""

    def test_create_context_with_none_commit_info(self, tmp_path):
        """Test creating context with None commit info."""
        changed_files = [tmp_path / "file1.py"]

        # Explicitly pass None for commit_info
        context = create_incremental_scan_context(changed_files, commit_info=None)

        expected = {
            "changed_files": [str(tmp_path / "file1.py")],
            "change_count": 1,
            "analysis_type": "incremental",
        }
        assert context == expected

    def test_create_context_with_empty_commit_info(self, tmp_path):
        """Test creating context with empty commit info dict."""
        changed_files = [tmp_path / "file1.py"]
        commit_info = {}  # Empty dict - falsy, so commit info won't be added

        context = create_incremental_scan_context(changed_files, commit_info)

        # Empty dict is falsy, so no commit fields are added
        expected = {
            "changed_files": [str(tmp_path / "file1.py")],
            "change_count": 1,
            "analysis_type": "incremental",
        }
        assert context == expected

    def test_create_context_with_none_diff_info(self, tmp_path):
        """Test creating context with None diff info."""
        changed_files = [tmp_path / "file1.py"]

        # Explicitly pass None for diff_info
        context = create_incremental_scan_context(changed_files, diff_info=None)

        expected = {
            "changed_files": [str(tmp_path / "file1.py")],
            "change_count": 1,
            "analysis_type": "incremental",
        }
        assert context == expected

    def test_create_context_with_empty_string_diff_info(self, tmp_path):
        """Test creating context with empty string diff info."""
        changed_files = [tmp_path / "file1.py"]
        diff_info = ""  # Empty string is falsy, so diff_info won't be added

        context = create_incremental_scan_context(changed_files, diff_info=diff_info)

        # Empty string is falsy, so diff_info won't be added
        expected = {
            "changed_files": [str(tmp_path / "file1.py")],
            "change_count": 1,
            "analysis_type": "incremental",
        }
        assert context == expected


class TestFilterSecurityRelevantChangesCoverage:
    """Additional tests to improve coverage of filter_security_relevant_changes."""

    def test_filter_with_continue_logic_extension_first(self):
        """Test that extension matching hits continue statement."""
        files = [
            Path("/home/project/app.py"),  # Should match extension and continue
            Path("/home/project/test.txt"),  # Should not match and go to pattern check
        ]

        result = filter_security_relevant_changes(files)

        # Only the .py file should be included
        assert result == [Path("/home/project/app.py")]

    def test_filter_with_continue_logic_pattern_second(self):
        """Test that pattern matching hits continue statement."""
        files = [
            Path("/home/project/auth_module.txt"),  # Should match pattern and continue
            Path("/home/project/readme.txt"),  # Should not match anything
        ]

        result = filter_security_relevant_changes(files)

        # Only the auth file should be included
        assert result == [Path("/home/project/auth_module.txt")]

    def test_filter_logs_message(self):
        """Test that the logging message is triggered."""
        files = [
            Path("/home/project/app.py"),
            Path("/home/project/test.txt"),
        ]

        with patch(
            "adversary_mcp_server.session.incremental_utils.logger"
        ) as mock_logger:
            result = filter_security_relevant_changes(files)

            # Verify logging was called
            mock_logger.info.assert_called_once()
            call_args = mock_logger.info.call_args[0][0]
            assert "Filtered 2 files to 1 security-relevant files" in call_args

    def test_filter_comprehensive_pattern_coverage(self):
        """Test filtering to ensure all pattern matching paths are covered."""
        # Test files that match different parts of the security patterns
        pattern_test_files = [
            # Files that should match patterns
            Path("/home/project/authentication.txt"),
            Path("/home/project/user_login.txt"),
            Path("/home/project/jwt_token.txt"),
            Path("/home/project/admin_session.txt"),
            Path("/home/project/crypto_hash.txt"),
            Path("/home/project/sql_database.txt"),
            Path("/home/project/api_controller.txt"),
            # Files that should NOT match
            Path("/home/project/normal_file.txt"),
            Path("/home/docs/documentation.txt"),
        ]

        result = filter_security_relevant_changes(pattern_test_files)

        # Should include all files except the last two
        assert len(result) == 7
        assert Path("/home/project/normal_file.txt") not in result
        assert Path("/home/docs/documentation.txt") not in result

    def test_filter_edge_case_extensions(self):
        """Test filtering with edge case file extensions."""
        files = [
            Path("/home/project/script.PS1"),  # Uppercase extension
            Path("/home/project/config.YML"),  # Uppercase extension
            Path("/home/project/data.JSON"),  # Uppercase extension
            Path("/home/project/file.TXT"),  # Not security-relevant
        ]

        result = filter_security_relevant_changes(files)

        # First three should be included (case insensitive), last should not
        assert len(result) == 3
        assert Path("/home/project/file.TXT") not in result

    def test_filter_complex_paths_with_multiple_patterns(self):
        """Test files that might match multiple patterns."""
        files = [
            Path(
                "/home/project/auth/user_login.py"
            ),  # Matches both 'auth' and 'user' and '.py'
            Path(
                "/home/project/api/jwt_token.js"
            ),  # Matches 'api', 'jwt', 'token' and '.js'
            Path("/home/project/normal/file.py"),  # Only matches '.py'
        ]

        result = filter_security_relevant_changes(files)

        # All should be included
        assert len(result) == 3
        assert all(f in result for f in files)

    def test_filter_suffix_method_coverage(self):
        """Test that the suffix method is properly called and covers different cases."""
        files = [
            Path("/home/project/file.py"),  # Normal extension
            Path("/home/project/file"),  # No extension
            Path("/home/project/file.PY"),  # Uppercase extension
            Path("/home/project/.hidden.py"),  # Hidden file with extension
        ]

        result = filter_security_relevant_changes(files)

        # Should include files with .py extension (case insensitive)
        expected = [
            Path("/home/project/file.py"),
            Path("/home/project/file.PY"),
            Path("/home/project/.hidden.py"),
        ]
        assert result == expected
