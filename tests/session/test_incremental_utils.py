"""Tests for incremental analysis utility functions."""

import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

from adversary_mcp_server.session.incremental_utils import (
    GitChangeDetector,
    create_incremental_scan_context,
    filter_security_relevant_changes,
)


class TestGitChangeDetector:
    """Test GitChangeDetector class."""

    def test_init(self, tmp_path):
        """Test GitChangeDetector initialization."""
        detector = GitChangeDetector(tmp_path)
        assert detector.project_root == tmp_path.resolve()

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_success(self, mock_run, tmp_path):
        """Test successful git diff operation."""
        # Create test files
        file1 = tmp_path / "file1.py"
        file2 = tmp_path / "file2.js"
        file1.write_text("content")
        file2.write_text("content")

        # Mock git command output
        mock_result = Mock()
        mock_result.stdout = "file1.py\nfile2.js\n"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_since_commit("abc123")

        # Verify git command was called correctly
        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "abc123..HEAD"],
            cwd=tmp_path.resolve(),
            capture_output=True,
            text=True,
            check=True,
        )

        # Verify results
        assert len(changed_files) == 2
        assert file1 in changed_files
        assert file2 in changed_files

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_nonexistent_files(self, mock_run, tmp_path):
        """Test git diff with non-existent files filtered out."""
        # Mock git command output with non-existent file
        mock_result = Mock()
        mock_result.stdout = "file1.py\nnonexistent.js\n"
        mock_run.return_value = mock_result

        # Only create one file
        file1 = tmp_path / "file1.py"
        file1.write_text("content")

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_since_commit("abc123")

        # Should only return existing files
        assert len(changed_files) == 1
        assert file1 in changed_files

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_empty_output(self, mock_run, tmp_path):
        """Test git diff with empty output."""
        mock_result = Mock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_since_commit("abc123")

        assert changed_files == []

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_git_error(self, mock_run, tmp_path):
        """Test git diff command failure."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_since_commit("abc123")

        assert changed_files == []

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_general_error(self, mock_run, tmp_path):
        """Test general exception handling."""
        mock_run.side_effect = Exception("General error")

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_since_commit("abc123")

        assert changed_files == []

    @patch("subprocess.run")
    def test_get_changed_files_in_working_directory_success(self, mock_run, tmp_path):
        """Test successful working directory changes detection."""
        # Create test files
        file1 = tmp_path / "modified.py"
        file2 = tmp_path / "added.js"
        file1.write_text("content")
        file2.write_text("content")

        # Mock git command output
        mock_result = Mock()
        mock_result.stdout = "modified.py\nadded.js\n"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_in_working_directory()

        # Verify git command was called correctly
        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=tmp_path.resolve(),
            capture_output=True,
            text=True,
            check=True,
        )

        # Verify results
        assert len(changed_files) == 2
        assert file1 in changed_files
        assert file2 in changed_files

    @patch("subprocess.run")
    def test_get_changed_files_in_working_directory_git_error(self, mock_run, tmp_path):
        """Test working directory detection with git error."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_in_working_directory()

        assert changed_files == []

    @patch("subprocess.run")
    def test_get_changed_files_in_working_directory_general_error(
        self, mock_run, tmp_path
    ):
        """Test working directory detection with general error."""
        mock_run.side_effect = Exception("General error")

        detector = GitChangeDetector(tmp_path)
        changed_files = detector.get_changed_files_in_working_directory()

        assert changed_files == []

    @patch("subprocess.run")
    def test_get_commit_info_success_with_commit_hash(self, mock_run, tmp_path):
        """Test successful commit info retrieval with specific commit."""
        mock_result = Mock()
        mock_result.stdout = "abc123|John Doe|john@example.com|Fix bug|Fix critical security bug in authentication\n"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        commit_info = detector.get_commit_info("abc123")

        # Verify git command was called correctly
        mock_run.assert_called_once_with(
            ["git", "show", "--format=%H|%an|%ae|%s|%B", "--no-patch", "abc123"],
            cwd=tmp_path.resolve(),
            capture_output=True,
            text=True,
            check=True,
        )

        # Verify results
        expected = {
            "hash": "abc123",
            "author": "John Doe",
            "email": "john@example.com",
            "subject": "Fix bug",
            "message": "Fix critical security bug in authentication",
        }
        assert commit_info == expected

    @patch("subprocess.run")
    def test_get_commit_info_success_without_commit_hash(self, mock_run, tmp_path):
        """Test commit info retrieval defaults to HEAD."""
        mock_result = Mock()
        mock_result.stdout = "def456|Jane Smith|jane@example.com|Add feature|Add new authentication feature\n"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        commit_info = detector.get_commit_info()

        # Should default to HEAD
        mock_run.assert_called_once_with(
            ["git", "show", "--format=%H|%an|%ae|%s|%B", "--no-patch", "HEAD"],
            cwd=tmp_path.resolve(),
            capture_output=True,
            text=True,
            check=True,
        )

        expected = {
            "hash": "def456",
            "author": "Jane Smith",
            "email": "jane@example.com",
            "subject": "Add feature",
            "message": "Add new authentication feature",
        }
        assert commit_info == expected

    @patch("subprocess.run")
    def test_get_commit_info_success_minimal_parts(self, mock_run, tmp_path):
        """Test commit info with minimal parts (no message body)."""
        mock_result = Mock()
        mock_result.stdout = "abc123|John Doe|john@example.com|Fix bug\n"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        commit_info = detector.get_commit_info("abc123")

        expected = {
            "hash": "abc123",
            "author": "John Doe",
            "email": "john@example.com",
            "subject": "Fix bug",
            "message": "Fix bug",  # message defaults to subject when not provided
        }
        assert commit_info == expected

    @patch("subprocess.run")
    def test_get_commit_info_malformed_output(self, mock_run, tmp_path):
        """Test commit info with malformed git output."""
        mock_result = Mock()
        mock_result.stdout = "invalid|output\n"
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        commit_info = detector.get_commit_info("abc123")

        assert commit_info == {}

    @patch("subprocess.run")
    def test_get_commit_info_empty_output(self, mock_run, tmp_path):
        """Test commit info with empty git output."""
        mock_result = Mock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        detector = GitChangeDetector(tmp_path)
        commit_info = detector.get_commit_info("abc123")

        assert commit_info == {}

    @patch("subprocess.run")
    def test_get_commit_info_git_error(self, mock_run, tmp_path):
        """Test commit info with git command error."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")

        detector = GitChangeDetector(tmp_path)
        commit_info = detector.get_commit_info("abc123")

        assert commit_info == {}

    @patch("subprocess.run")
    def test_get_commit_info_general_error(self, mock_run, tmp_path):
        """Test commit info with general error."""
        mock_run.side_effect = Exception("General error")

        detector = GitChangeDetector(tmp_path)
        commit_info = detector.get_commit_info("abc123")

        assert commit_info == {}


class TestCreateIncrementalScanContext:
    """Test create_incremental_scan_context function."""

    def test_create_context_minimal(self, tmp_path):
        """Test creating context with minimal data."""
        changed_files = [tmp_path / "file1.py", tmp_path / "file2.js"]

        context = create_incremental_scan_context(changed_files)

        expected = {
            "changed_files": [str(tmp_path / "file1.py"), str(tmp_path / "file2.js")],
            "change_count": 2,
            "analysis_type": "incremental",
        }
        assert context == expected

    def test_create_context_with_commit_info(self, tmp_path):
        """Test creating context with commit information."""
        changed_files = [tmp_path / "file1.py"]
        commit_info = {
            "hash": "abc123",
            "author": "John Doe",
            "message": "Fix security issue",
            "email": "john@example.com",  # Extra field should be ignored
        }

        context = create_incremental_scan_context(changed_files, commit_info)

        expected = {
            "changed_files": [str(tmp_path / "file1.py")],
            "change_count": 1,
            "analysis_type": "incremental",
            "commit_hash": "abc123",
            "author": "John Doe",
            "message": "Fix security issue",
        }
        assert context == expected

    def test_create_context_with_diff_info(self, tmp_path):
        """Test creating context with diff information."""
        changed_files = [tmp_path / "file1.py"]
        diff_info = "diff --git a/file1.py b/file1.py\n+added line"

        context = create_incremental_scan_context(changed_files, diff_info=diff_info)

        expected = {
            "changed_files": [str(tmp_path / "file1.py")],
            "change_count": 1,
            "analysis_type": "incremental",
            "diff_info": "diff --git a/file1.py b/file1.py\n+added line",
        }
        assert context == expected

    def test_create_context_with_all_data(self, tmp_path):
        """Test creating context with all optional data."""
        changed_files = [tmp_path / "file1.py", tmp_path / "file2.js"]
        commit_info = {
            "hash": "def456",
            "author": "Jane Smith",
            "message": "Add new feature",
        }
        diff_info = "diff --git a/file1.py b/file1.py\n+new feature"

        context = create_incremental_scan_context(changed_files, commit_info, diff_info)

        expected = {
            "changed_files": [str(tmp_path / "file1.py"), str(tmp_path / "file2.js")],
            "change_count": 2,
            "analysis_type": "incremental",
            "commit_hash": "def456",
            "author": "Jane Smith",
            "message": "Add new feature",
            "diff_info": "diff --git a/file1.py b/file1.py\n+new feature",
        }
        assert context == expected

    def test_create_context_empty_files(self):
        """Test creating context with empty file list."""
        context = create_incremental_scan_context([])

        expected = {
            "changed_files": [],
            "change_count": 0,
            "analysis_type": "incremental",
        }
        assert context == expected

    def test_create_context_partial_commit_info(self, tmp_path):
        """Test creating context with partial commit info."""
        changed_files = [tmp_path / "file1.py"]
        commit_info = {"hash": "abc123"}  # Missing other fields

        context = create_incremental_scan_context(changed_files, commit_info)

        expected = {
            "changed_files": [str(tmp_path / "file1.py")],
            "change_count": 1,
            "analysis_type": "incremental",
            "commit_hash": "abc123",
            "author": None,  # Missing fields become None
            "message": None,
        }
        assert context == expected


class TestFilterSecurityRelevantChanges:
    """Test filter_security_relevant_changes function."""

    def test_filter_by_extension(self):
        """Test filtering by security-relevant file extensions."""
        # Use absolute paths that don't contain security-related patterns
        files = [
            Path("/home/project/app.py"),  # Should be included
            Path("/home/project/script.js"),  # Should be included
            Path("/home/project/config.yaml"),  # Should be included
            Path("/home/docs/readme.md"),  # Should be excluded
            Path("/home/media/image.png"),  # Should be excluded
            Path("/home/data/export.csv"),  # Should be excluded
        ]

        result = filter_security_relevant_changes(files)

        expected = [
            Path("/home/project/app.py"),
            Path("/home/project/script.js"),
            Path("/home/project/config.yaml"),
        ]
        assert result == expected

    def test_filter_by_path_patterns(self):
        """Test filtering by security-relevant path patterns."""
        files = [
            Path("/home/project/auth/login.txt"),  # Should be included (auth pattern)
            Path("/home/project/user/profile.txt"),  # Should be included (user pattern)
            Path("/home/project/api/endpoint.txt"),  # Should be included (api pattern)
            Path("/home/docs/readme.txt"),  # Should be excluded
            Path("/home/content/unit.txt"),  # Should be excluded
        ]

        result = filter_security_relevant_changes(files)

        expected = [
            Path("/home/project/auth/login.txt"),
            Path("/home/project/user/profile.txt"),
            Path("/home/project/api/endpoint.txt"),
        ]
        assert result == expected

    def test_filter_mixed_criteria(self):
        """Test filtering with both extension and pattern criteria."""
        files = [
            Path("/home/project/auth.py"),  # Included by extension
            Path("/home/project/password.txt"),  # Included by pattern
            Path("/home/project/security/file.log"),  # Included by pattern
            Path("/home/docs/normal.txt"),  # Excluded
            Path("/home/project/example.py"),  # Included by extension
        ]

        result = filter_security_relevant_changes(files)

        expected = [
            Path("/home/project/auth.py"),
            Path("/home/project/password.txt"),
            Path("/home/project/security/file.log"),
            Path("/home/project/example.py"),
        ]
        assert result == expected

    def test_filter_case_insensitive_patterns(self):
        """Test that pattern matching is case insensitive."""
        files = [
            Path("/home/project/AUTH/file.txt"),  # Should match 'auth' pattern
            Path("/home/project/Password.txt"),  # Should match 'password' pattern
            Path("/home/project/API_endpoint.txt"),  # Should match 'api' pattern
            Path("/home/content/Normal.txt"),  # Should be excluded
        ]

        result = filter_security_relevant_changes(files)

        expected = [
            Path("/home/project/AUTH/file.txt"),
            Path("/home/project/Password.txt"),
            Path("/home/project/API_endpoint.txt"),
        ]
        assert result == expected

    def test_filter_extension_case_insensitive(self):
        """Test that extension matching is case insensitive."""
        files = [
            Path("/home/project/app.PY"),  # Should match '.py' extension
            Path("/home/project/script.JS"),  # Should match '.js' extension
            Path("/home/project/config.YAML"),  # Should match '.yaml' extension
            Path("/home/docs/readme.MD"),  # Should be excluded
        ]

        result = filter_security_relevant_changes(files)

        expected = [
            Path("/home/project/app.PY"),
            Path("/home/project/script.JS"),
            Path("/home/project/config.YAML"),
        ]
        assert result == expected

    def test_filter_empty_list(self):
        """Test filtering empty file list."""
        result = filter_security_relevant_changes([])
        assert result == []

    def test_exclude_non_code_files(self):
        """Test filtering when no files match criteria."""
        # Use absolute paths that don't contain security-related patterns
        files = [
            Path("/home/docs/readme.md"),
            Path("/home/media/image.png"),
            Path("/home/data/export.csv"),
        ]

        result = filter_security_relevant_changes(files)
        assert result == []

    def test_filter_all_match(self):
        """Test filtering when all files match criteria."""
        files = [
            Path("/home/project/app.py"),
            Path("/home/project/auth.js"),
            Path("/home/project/config.yaml"),
        ]

        result = filter_security_relevant_changes(files)
        assert result == files

    def test_filter_comprehensive_extensions(self):
        """Test filtering with comprehensive list of security-relevant extensions."""
        files = [
            Path("/home/project/app.py"),  # Python
            Path("/home/project/script.js"),  # JavaScript
            Path("/home/project/app.ts"),  # TypeScript
            Path("/home/project/Main.java"),  # Java
            Path("/home/project/main.go"),  # Go
            Path("/home/project/lib.rs"),  # Rust
            Path("/home/project/program.c"),  # C
            Path("/home/project/program.cpp"),  # C++
            Path("/home/project/header.h"),  # C header
            Path("/home/project/header.hpp"),  # C++ header
            Path("/home/project/web.php"),  # PHP
            Path("/home/project/script.rb"),  # Ruby
            Path("/home/project/app.cs"),  # C#
            Path("/home/project/app.swift"),  # Swift
            Path("/home/project/app.kt"),  # Kotlin
            Path("/home/project/app.scala"),  # Scala
            Path("/home/project/script.pl"),  # Perl
            Path("/home/project/script.sh"),  # Shell
            Path("/home/project/script.ps1"),  # PowerShell
            Path("/home/project/query.sql"),  # SQL
            Path("/home/project/config.yaml"),  # YAML
            Path("/home/project/config.yml"),  # YAML alternative
            Path("/home/project/data.json"),  # JSON
            Path("/home/project/config.xml"),  # XML
            Path("/home/project/app.conf"),  # Config
            Path("/home/project/app.config"),  # Config alternative
            Path("/home/project/secrets.env"),  # Environment
        ]

        result = filter_security_relevant_changes(files)

        # All files should be included as they all have security-relevant extensions
        assert result == files

    def test_filter_comprehensive_patterns(self):
        """Test filtering with comprehensive list of security-relevant patterns."""
        pattern_files = [
            Path("/home/project/auth_service.txt"),
            Path("/home/project/login_handler.txt"),
            Path("/home/project/password_utils.txt"),
            Path("/home/project/token_manager.txt"),
            Path("/home/project/jwt_service.txt"),
            Path("/home/project/session_store.txt"),
            Path("/home/project/permission_check.txt"),
            Path("/home/project/role_manager.txt"),
            Path("/home/project/admin_panel.txt"),
            Path("/home/project/user_service.txt"),
            Path("/home/project/security_config.txt"),
            Path("/home/project/crypto_utils.txt"),
            Path("/home/project/hash_function.txt"),
            Path("/home/project/encrypt_data.txt"),
            Path("/home/project/decrypt_data.txt"),
            Path("/home/project/validate_input.txt"),
            Path("/home/project/sanitize_data.txt"),
            Path("/home/project/escape_html.txt"),
            Path("/home/project/sql_query.txt"),
            Path("/home/project/query_builder.txt"),
            Path("/home/project/database_config.txt"),
            Path("/home/project/db_connection.txt"),
            Path("/home/project/api_gateway.txt"),
            Path("/home/project/endpoint_handler.txt"),
            Path("/home/project/route_config.txt"),
            Path("/home/project/controller_base.txt"),
            Path("/home/project/middleware_auth.txt"),
            Path("/home/project/components/security.txt"),
            Path("/home/project/interceptor_cors.txt"),
        ]

        result = filter_security_relevant_changes(pattern_files)

        # All files should be included as they all contain security-relevant patterns
        assert result == pattern_files
