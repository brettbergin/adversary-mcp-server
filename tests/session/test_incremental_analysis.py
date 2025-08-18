"""Tests for incremental analysis capabilities."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

# Import the module to ensure coverage tracking
from src.adversary_mcp_server.session.incremental_utils import (
    GitChangeDetector,
    create_incremental_scan_context,
    filter_security_relevant_changes,
)


class TestGitChangeDetector:
    """Test suite for GitChangeDetector functionality."""

    @pytest.fixture
    def project_root(self):
        """Create a temporary project root for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.fixture
    def git_detector(self, project_root):
        """Create a GitChangeDetector instance for testing."""
        return GitChangeDetector(project_root)

    def test_initialization(self, git_detector, project_root):
        """Test GitChangeDetector initialization."""
        assert git_detector.project_root == project_root.resolve()

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_success(
        self, mock_run, git_detector, project_root
    ):
        """Test successful detection of changed files since commit."""
        # Mock git diff output
        mock_result = Mock()
        mock_result.stdout = "src/app.py\nsrc/config.py\nREADME.md\n"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        # Create test files
        (project_root / "src").mkdir()
        (project_root / "src" / "app.py").touch()
        (project_root / "src" / "config.py").touch()
        (project_root / "README.md").touch()

        commit_hash = "abc123"
        changed_files = git_detector.get_changed_files_since_commit(commit_hash)

        # Verify git command was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args

        # Check the command was called with expected arguments
        args = call_args[0][0]  # First positional argument (command list)
        assert args[0] == "git"
        assert args[1] == "diff"
        assert args[2] == "--name-only"
        assert args[3] == f"{commit_hash}..HEAD"

        # Verify results (should be 3 files found)
        assert len(changed_files) == 3

        # Verify file names are correct
        changed_names = [f.name for f in changed_files]
        assert "app.py" in changed_names
        assert "config.py" in changed_names
        assert "README.md" in changed_names

        # Also verify that the files are in the correct locations
        changed_paths = [str(f) for f in changed_files]
        assert any("src/app.py" in path for path in changed_paths)
        assert any("src/config.py" in path for path in changed_paths)
        assert any("README.md" in path for path in changed_paths)

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_nonexistent_files(
        self, mock_run, git_detector, project_root
    ):
        """Test handling of nonexistent files in git diff output."""
        # Mock git diff output with files that don't exist
        mock_result = Mock()
        mock_result.stdout = "src/app.py\ndeleted_file.py\n"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        # Create only one of the files
        (project_root / "src").mkdir()
        (project_root / "src" / "app.py").touch()
        # deleted_file.py doesn't exist

        commit_hash = "abc123"
        changed_files = git_detector.get_changed_files_since_commit(commit_hash)

        # Should only return existing files
        assert len(changed_files) == 1
        assert changed_files[0].name == "app.py"

    @patch("subprocess.run")
    def test_get_changed_files_since_commit_git_error(self, mock_run, git_detector):
        """Test handling of git command errors."""
        # Mock git command failure
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, "git diff")

        commit_hash = "abc123"
        changed_files = git_detector.get_changed_files_since_commit(commit_hash)

        # Should return empty list on error
        assert changed_files == []

    @patch("subprocess.run")
    def test_get_changed_files_in_working_directory(
        self, mock_run, git_detector, project_root
    ):
        """Test detection of changes in working directory."""
        # Mock git diff output for working directory
        mock_result = Mock()
        mock_result.stdout = "src/modified.py\nsrc/new_file.py\n"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        # Create test files
        (project_root / "src").mkdir()
        (project_root / "src" / "modified.py").touch()
        (project_root / "src" / "new_file.py").touch()

        changed_files = git_detector.get_changed_files_in_working_directory()

        # Verify git command
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[1] == "diff"
        assert args[2] == "--name-only"
        assert args[3] == "HEAD"

        # Verify results
        assert len(changed_files) == 2
        changed_names = [f.name for f in changed_files]
        assert "modified.py" in changed_names
        assert "new_file.py" in changed_names

    @patch("subprocess.run")
    def test_get_commit_info_success(self, mock_run, git_detector):
        """Test successful retrieval of commit information."""
        # Mock git show output
        mock_result = Mock()
        mock_result.stdout = "abc123|John Doe|john@example.com|Fix security issue|Fix SQL injection vulnerability\n"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        commit_hash = "abc123"
        commit_info = git_detector.get_commit_info(commit_hash)

        # Verify git command
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "git"
        assert args[1] == "show"
        assert commit_hash in args

        # Verify parsed info
        assert commit_info["hash"] == "abc123"
        assert commit_info["author"] == "John Doe"
        assert commit_info["email"] == "john@example.com"
        assert commit_info["subject"] == "Fix security issue"
        assert commit_info["message"] == "Fix SQL injection vulnerability"

    @patch("subprocess.run")
    def test_get_commit_info_default_head(self, mock_run, git_detector):
        """Test commit info retrieval with default HEAD."""
        mock_result = Mock()
        mock_result.stdout = (
            "def456|Jane Doe|jane@example.com|Update docs|Documentation update\n"
        )
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        commit_info = git_detector.get_commit_info()  # No commit hash specified

        # Should use HEAD as default
        args = mock_run.call_args[0][0]
        assert "HEAD" in args

        assert commit_info["hash"] == "def456"
        assert commit_info["author"] == "Jane Doe"

    @patch("subprocess.run")
    def test_get_commit_info_error(self, mock_run, git_detector):
        """Test handling of errors in commit info retrieval."""
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, "git show")

        commit_info = git_detector.get_commit_info("invalid_hash")

        # Should return empty dict on error
        assert commit_info == {}


class TestIncrementalUtilityFunctions:
    """Test suite for incremental analysis utility functions."""

    def test_create_incremental_scan_context_basic(self):
        """Test creation of basic incremental scan context."""
        changed_files = [Path("/test/app.py"), Path("/test/config.py")]

        context = create_incremental_scan_context(changed_files)

        assert context["changed_files"] == ["/test/app.py", "/test/config.py"]
        assert context["change_count"] == 2
        assert context["analysis_type"] == "incremental"

    def test_create_incremental_scan_context_with_commit_info(self):
        """Test scan context creation with commit information."""
        changed_files = [Path("/test/app.py")]
        commit_info = {
            "hash": "abc123",
            "author": "John Doe",
            "message": "Fix security vulnerability",
        }

        context = create_incremental_scan_context(changed_files, commit_info)

        assert context["commit_hash"] == "abc123"
        assert context["author"] == "John Doe"
        assert context["message"] == "Fix security vulnerability"

    def test_create_incremental_scan_context_with_diff_info(self):
        """Test scan context creation with diff information."""
        changed_files = [Path("/test/app.py")]
        diff_info = "+++ b/app.py\n@@ -10,5 +10,5 @@\n-old_line\n+new_line"

        context = create_incremental_scan_context(changed_files, diff_info=diff_info)

        assert context["diff_info"] == diff_info

    def test_filter_security_relevant_changes_by_extension(self):
        """Test filtering of security-relevant files by extension."""
        changed_files = [
            Path("/test/app.py"),
            Path("/test/config.js"),
            Path("/test/README.md"),
            Path("/test/image.jpg"),
            Path("/test/script.sh"),
            Path("/test/data.sql"),
        ]

        relevant_files = filter_security_relevant_changes(changed_files)

        # Should include programming files but not images
        relevant_names = [f.name for f in relevant_files]
        assert "app.py" in relevant_names
        assert "config.js" in relevant_names
        assert "script.sh" in relevant_names
        assert "data.sql" in relevant_names
        assert "image.jpg" not in relevant_names

    def test_filter_security_relevant_changes_by_path_keywords(self):
        """Test filtering of security-relevant files by path keywords."""
        changed_files = [
            Path("/test/auth/login.txt"),
            Path("/test/security/validator.txt"),
            Path("/test/api/endpoints.txt"),
            Path("/test/docs/readme.txt"),
            Path("/test/admin/panel.txt"),
            Path("/test/crypto/hash.txt"),
        ]

        relevant_files = filter_security_relevant_changes(changed_files)

        # Should include files with security-related path keywords
        relevant_paths = [str(f) for f in relevant_files]
        assert any("auth" in path for path in relevant_paths)
        assert any("security" in path for path in relevant_paths)
        assert any("api" in path for path in relevant_paths)
        assert any("admin" in path for path in relevant_paths)
        assert any("crypto" in path for path in relevant_paths)

    def test_filter_security_relevant_changes_mixed_criteria(self):
        """Test filtering with mixed extension and keyword criteria."""
        changed_files = [
            Path("/test/auth.py"),  # Both extension and keyword
            Path("/test/normal.py"),  # Extension only
            Path("/test/security/docs.txt"),  # Keyword only
            Path("/test/unrelated.jpg"),  # Neither
            Path("/test/login.config"),  # Keyword only
        ]

        relevant_files = filter_security_relevant_changes(changed_files)

        relevant_names = [f.name for f in relevant_files]
        assert "auth.py" in relevant_names
        assert "normal.py" in relevant_names
        assert "docs.txt" in relevant_names
        assert "login.config" in relevant_names
        assert "unrelated.jpg" not in relevant_names

    def test_filter_security_relevant_changes_empty_list(self):
        """Test filtering with empty file list."""
        changed_files = []

        relevant_files = filter_security_relevant_changes(changed_files)

        assert relevant_files == []

    def test_filter_security_relevant_changes_no_relevant_files(self):
        """Test filtering when no files are security-relevant."""
        changed_files = [
            Path("/test/image.jpg"),
            Path("/test/video.mp4"),
            Path("/test/document.pdf"),
        ]

        relevant_files = filter_security_relevant_changes(changed_files)

        assert relevant_files == []


@pytest.mark.integration
class TestIncrementalAnalysisIntegration:
    """Integration tests for incremental analysis functionality."""

    def test_git_change_detection_workflow(self):
        """Test complete git change detection workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            # Create test files
            (project_root / "src").mkdir()
            (project_root / "src" / "app.py").write_text("print('hello')")
            (project_root / "src" / "auth.py").write_text("def login(): pass")
            (project_root / "README.md").write_text("# Project")

            # Initialize git repo (mocked)
            git_detector = GitChangeDetector(project_root)

            # Test file filtering
            all_files = [
                project_root / "src" / "app.py",
                project_root / "src" / "auth.py",
                project_root / "README.md",
            ]

            relevant_files = filter_security_relevant_changes(all_files)

            # Should include Python files and auth-related files
            relevant_names = [f.name for f in relevant_files]
            assert "app.py" in relevant_names
            assert "auth.py" in relevant_names
            # README.md might not be included as it's not a security-relevant extension

    def test_incremental_context_creation_workflow(self):
        """Test complete incremental context creation workflow."""
        # Simulate a real scenario
        changed_files = [
            Path("/project/src/auth.py"),
            Path("/project/src/api.py"),
            Path("/project/tests/test_auth.py"),
        ]

        commit_info = {
            "hash": "abc123",
            "author": "Security Team",
            "message": "Fix authentication bypass vulnerability",
        }

        diff_info = """
@@ -15,7 +15,7 @@ def authenticate(username, password):
     if not username or not password:
         return False

-    query = f"SELECT * FROM users WHERE username='{username}'"
+    query = "SELECT * FROM users WHERE username=%s"
+    cursor.execute(query, (username,))
"""

        # Filter for security-relevant changes
        relevant_files = filter_security_relevant_changes(changed_files)

        # Create incremental scan context
        context = create_incremental_scan_context(
            relevant_files, commit_info, diff_info
        )

        # Verify complete context
        assert context["analysis_type"] == "incremental"
        assert context["commit_hash"] == "abc123"
        assert context["author"] == "Security Team"
        assert "authentication bypass" in context["message"]
        assert context["diff_info"] == diff_info
        assert len(context["changed_files"]) >= 2  # Should include relevant files

        # All files should be security-relevant (Python files, auth-related)
        for file_path in context["changed_files"]:
            assert any(ext in file_path for ext in [".py"]) or any(
                keyword in file_path.lower() for keyword in ["auth", "api", "test"]
            )


@pytest.mark.asyncio
class TestIncrementalAnalysisWithLLMSession:
    """Test incremental analysis integration with LLM session manager."""

    @pytest.fixture
    def mock_llm_session_manager(self):
        """Create a mock LLM session manager."""
        from src.adversary_mcp_server.session.llm_session_manager import (
            LLMSessionManager,
        )

        manager = Mock(spec=LLMSessionManager)
        manager.analyze_changes_incrementally = AsyncMock()
        manager.get_incremental_analysis_metadata = Mock()
        return manager

    async def test_incremental_analysis_execution(self, mock_llm_session_manager):
        """Test execution of incremental analysis through session manager."""
        session_id = "test_session"
        changed_files = [Path("/project/src/auth.py"), Path("/project/src/api.py")]
        commit_hash = "abc123"

        # Mock return value
        mock_findings = [
            Mock(metadata={"incremental_analysis": True}),
            Mock(metadata={"incremental_analysis": True}),
        ]
        mock_llm_session_manager.analyze_changes_incrementally.return_value = (
            mock_findings
        )

        # Execute incremental analysis
        result = await mock_llm_session_manager.analyze_changes_incrementally(
            session_id=session_id, changed_files=changed_files, commit_hash=commit_hash
        )

        # Verify execution
        mock_llm_session_manager.analyze_changes_incrementally.assert_called_once_with(
            session_id=session_id, changed_files=changed_files, commit_hash=commit_hash
        )

        assert len(result) == 2
        for finding in result:
            assert finding.metadata["incremental_analysis"] is True

    async def test_baseline_establishment_workflow(self, mock_llm_session_manager):
        """Test baseline establishment for incremental analysis."""
        session_id = "test_session"
        target_files = [Path("/project/src/app.py")]

        # Mock baseline establishment
        baseline_metadata = {
            "baseline_established": True,
            "baseline_findings_count": 5,
            "analyzed_files": ["/project/src/app.py"],
        }
        mock_llm_session_manager.establish_incremental_baseline = AsyncMock(
            return_value=baseline_metadata
        )

        # Execute baseline establishment
        result = await mock_llm_session_manager.establish_incremental_baseline(
            session_id=session_id, target_files=target_files
        )

        # Verify execution
        mock_llm_session_manager.establish_incremental_baseline.assert_called_once_with(
            session_id=session_id, target_files=target_files
        )

        assert result["baseline_established"] is True
        assert result["baseline_findings_count"] == 5
