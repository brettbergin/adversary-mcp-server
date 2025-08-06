"""Tests for content hasher."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from adversary_mcp_server.cache.content_hasher import ContentHasher


class TestContentHasher:
    """Test ContentHasher class."""

    @pytest.fixture
    def hasher(self):
        """Create content hasher instance."""
        return ContentHasher()

    @pytest.fixture
    def temp_file(self):
        """Create temporary file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".py") as f:
            f.write("print('hello world')\n")
            temp_path = Path(f.name)

        yield temp_path

        # Cleanup
        temp_path.unlink(missing_ok=True)

    def test_initialization_default(self):
        """Test hasher initialization with default algorithm."""
        hasher = ContentHasher()
        assert hasher.algorithm == "sha256"

    def test_initialization_custom_algorithm(self):
        """Test hasher initialization with custom algorithm."""
        hasher = ContentHasher(algorithm="md5")
        assert hasher.algorithm == "md5"

    def test_hash_content_basic(self, hasher):
        """Test basic content hashing."""
        content = "Hello, World!"
        hash_result = hasher.hash_content(content)

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64  # SHA256 hex digest length

        # Same content should produce same hash
        hash_result2 = hasher.hash_content(content)
        assert hash_result == hash_result2

    def test_hash_content_different_inputs(self, hasher):
        """Test that different content produces different hashes."""
        hash1 = hasher.hash_content("content1")
        hash2 = hasher.hash_content("content2")

        assert hash1 != hash2

    def test_hash_content_empty_string(self, hasher):
        """Test hashing empty string."""
        hash_result = hasher.hash_content("")

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_content_unicode(self, hasher):
        """Test hashing unicode content."""
        content = "Hello 世界 🌍"
        hash_result = hasher.hash_content(content)

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_file_success(self, hasher, temp_file):
        """Test successful file hashing."""
        hash_result = hasher.hash_file(temp_file)

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_file_nonexistent(self, hasher):
        """Test hashing non-existent file raises exception."""
        nonexistent_file = Path("/nonexistent/file.txt")

        with pytest.raises(Exception):
            hasher.hash_file(nonexistent_file)

    def test_hash_file_consistent_results(self, hasher, temp_file):
        """Test that file hashing produces consistent results."""
        hash1 = hasher.hash_file(temp_file)
        hash2 = hasher.hash_file(temp_file)

        assert hash1 == hash2

    def test_hash_metadata_basic(self, hasher):
        """Test basic metadata hashing."""
        metadata = {
            "language": "python",
            "rules": ["security", "performance"],
            "version": "1.0",
        }

        hash_result = hasher.hash_metadata(metadata)

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_metadata_order_independence(self, hasher):
        """Test that metadata hash is independent of key order."""
        metadata1 = {"b": 2, "a": 1, "c": 3}
        metadata2 = {"a": 1, "c": 3, "b": 2}

        hash1 = hasher.hash_metadata(metadata1)
        hash2 = hasher.hash_metadata(metadata2)

        assert hash1 == hash2

    def test_hash_metadata_empty_dict(self, hasher):
        """Test hashing empty metadata dictionary."""
        hash_result = hasher.hash_metadata({})

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_metadata_nested_dict(self, hasher):
        """Test hashing nested metadata dictionary."""
        metadata = {"config": {"nested": {"value": 42}}, "list": [1, 2, 3]}

        hash_result = hasher.hash_metadata(metadata)

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_llm_context_basic(self, hasher):
        """Test basic LLM context hashing."""
        hash_result = hasher.hash_llm_context(
            content="def test(): pass",
            model="gpt-4",
            system_prompt="You are a security analyzer",
            user_prompt="Analyze this code",
            temperature=0.0,
            max_tokens=1000,
        )

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_llm_context_default_values(self, hasher):
        """Test LLM context hashing with default values."""
        hash_result = hasher.hash_llm_context(
            content="test content",
            model="claude-3",
            system_prompt="system",
            user_prompt="user",
        )

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_llm_context_different_params(self, hasher):
        """Test that different LLM parameters produce different hashes."""
        base_params = {
            "content": "def test(): pass",
            "model": "gpt-4",
            "system_prompt": "You are a security analyzer",
            "user_prompt": "Analyze this code",
        }

        hash1 = hasher.hash_llm_context(**base_params)

        # Change temperature
        hash2 = hasher.hash_llm_context(**base_params, temperature=0.5)
        assert hash1 != hash2

        # Change model
        hash3 = hasher.hash_llm_context(**{**base_params, "model": "claude-3"})
        assert hash1 != hash3

    def test_hash_semgrep_context_basic(self, hasher):
        """Test basic Semgrep context hashing."""
        hash_result = hasher.hash_semgrep_context(
            content="print('hello')",
            language="python",
            rules=["security.py", "performance.py"],
            config_path="/path/to/config",
        )

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_semgrep_context_no_rules(self, hasher):
        """Test Semgrep context hashing without rules."""
        hash_result = hasher.hash_semgrep_context(
            content="console.log('hello');", language="javascript"
        )

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_semgrep_context_rules_sorted(self, hasher):
        """Test that Semgrep rules are sorted for consistent hashing."""
        hash1 = hasher.hash_semgrep_context(
            content="test", language="python", rules=["rule3", "rule1", "rule2"]
        )

        hash2 = hasher.hash_semgrep_context(
            content="test", language="python", rules=["rule1", "rule2", "rule3"]
        )

        assert hash1 == hash2

    def test_hash_validation_context_basic(self, hasher):
        """Test basic validation context hashing."""

        # Mock findings with to_dict method
        class MockFinding:
            def to_dict(self):
                return {
                    "type": "vulnerability",
                    "severity": "high",
                    "description": "SQL injection",
                    "uuid": "should-be-removed",
                    "created_at": "should-be-removed",
                }

        findings = [MockFinding(), MockFinding()]

        hash_result = hasher.hash_validation_context(
            findings=findings,
            validator_model="gpt-4",
            confidence_threshold=0.7,
            additional_context={"test": "context"},
        )

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_validation_context_string_findings(self, hasher):
        """Test validation context hashing with string findings."""
        findings = ["finding1", "finding2", "finding3"]

        hash_result = hasher.hash_validation_context(
            findings=findings, validator_model="claude-3", confidence_threshold=0.8
        )

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_validation_context_no_additional_context(self, hasher):
        """Test validation context hashing without additional context."""
        findings = ["test finding"]

        hash_result = hasher.hash_validation_context(
            findings=findings, validator_model="gpt-4", confidence_threshold=0.5
        )

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    @patch("subprocess.run")
    def test_compute_git_hash_success(self, mock_run, hasher, temp_file):
        """Test successful git hash computation."""
        mock_run.return_value.stdout = "abc123def456\n"
        mock_run.return_value.returncode = 0

        repo_path = Path("/fake/repo")
        git_hash = hasher.compute_git_hash(repo_path, temp_file)

        assert git_hash == "abc123def456"
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_compute_git_hash_failure(self, mock_run, hasher, temp_file):
        """Test git hash computation failure."""
        mock_run.side_effect = FileNotFoundError("git not found")

        repo_path = Path("/fake/repo")
        git_hash = hasher.compute_git_hash(repo_path, temp_file)

        assert git_hash is None

    @patch("subprocess.run")
    def test_compute_git_hash_command_error(self, mock_run, hasher, temp_file):
        """Test git hash computation with command error."""
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, "git")

        repo_path = Path("/fake/repo")
        git_hash = hasher.compute_git_hash(repo_path, temp_file)

        assert git_hash is None

    @patch.object(ContentHasher, "compute_git_hash")
    @patch.object(ContentHasher, "hash_file")
    def test_compute_hybrid_hash_with_git(
        self, mock_hash_file, mock_git_hash, hasher, temp_file
    ):
        """Test hybrid hash computation with git available."""
        mock_git_hash.return_value = "git_hash_123"

        repo_path = Path("/fake/repo")
        result = hasher.compute_hybrid_hash(temp_file, repo_path)

        assert result == "git:git_hash_123"
        mock_git_hash.assert_called_once_with(repo_path, temp_file)
        mock_hash_file.assert_not_called()

    @patch.object(ContentHasher, "compute_git_hash")
    @patch.object(ContentHasher, "hash_file")
    def test_compute_hybrid_hash_fallback_to_content(
        self, mock_hash_file, mock_git_hash, hasher, temp_file
    ):
        """Test hybrid hash computation fallback to content hash."""
        mock_git_hash.return_value = None
        mock_hash_file.return_value = "content_hash_456"

        repo_path = Path("/fake/repo")
        result = hasher.compute_hybrid_hash(temp_file, repo_path)

        assert result == "content:content_hash_456"
        mock_git_hash.assert_called_once_with(repo_path, temp_file)
        mock_hash_file.assert_called_once_with(temp_file)

    @patch.object(ContentHasher, "hash_file")
    def test_compute_hybrid_hash_no_repo(self, mock_hash_file, hasher, temp_file):
        """Test hybrid hash computation without repository."""
        mock_hash_file.return_value = "content_hash_789"

        result = hasher.compute_hybrid_hash(temp_file)

        assert result == "content:content_hash_789"
        mock_hash_file.assert_called_once_with(temp_file)

    def test_hash_file_with_different_algorithms(self, temp_file):
        """Test file hashing with different algorithms."""
        hasher_sha256 = ContentHasher("sha256")
        hasher_md5 = ContentHasher("md5")

        hash_sha256 = hasher_sha256.hash_file(temp_file)
        hash_md5 = hasher_md5.hash_file(temp_file)

        # Different algorithms should produce different hash lengths
        assert len(hash_sha256) == 64  # SHA256
        assert len(hash_md5) == 32  # MD5
        assert hash_sha256 != hash_md5

    @patch("adversary_mcp_server.cache.content_hasher.logger")
    def test_hash_file_error_logging(self, mock_logger, hasher):
        """Test that file hashing errors are logged."""
        nonexistent_file = Path("/definitely/does/not/exist.txt")

        with pytest.raises(Exception):
            hasher.hash_file(nonexistent_file)

        mock_logger.error.assert_called_once()
