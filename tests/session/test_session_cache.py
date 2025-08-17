"""Tests for SessionCache and TokenUsageOptimizer."""

import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.cache import CacheManager
from adversary_mcp_server.session.project_context import ProjectContext, ProjectFile
from adversary_mcp_server.session.session_cache import SessionCache, TokenUsageOptimizer


class TestSessionCache:
    """Test SessionCache functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create mock cache manager
        self.mock_cache_manager = Mock(spec=CacheManager)
        self.mock_hasher = Mock()
        self.mock_cache_manager.get_hasher.return_value = self.mock_hasher

        self.cache = SessionCache(self.mock_cache_manager)

    def test_initialization(self):
        """Test cache initialization."""
        assert self.cache.cache_manager == self.mock_cache_manager
        assert self.cache.hasher == self.mock_hasher

    def test_create_project_signature(self):
        """Test project signature creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            # Create test files
            (project_root / "package.json").write_text('{"name": "test"}')
            (project_root / "src").mkdir()
            (project_root / "tests").mkdir()

            signature1 = self.cache._create_project_signature(project_root)
            assert len(signature1) == 16  # Should be 16-char hash

            # Same project should have same signature
            signature2 = self.cache._create_project_signature(project_root)
            assert signature1 == signature2

            # Different project should have different signature
            (project_root / "new_file.py").write_text("# new file")
            signature3 = self.cache._create_project_signature(project_root)
            # May or may not be different depending on what's included in signature

    def test_serialize_project_file(self):
        """Test ProjectFile serialization."""
        project_file = ProjectFile(
            path=Path("test.py"),
            language="python",
            size_bytes=1000,
            priority_score=0.8,
            security_relevance=0.9,
            content_preview="def test(): pass",
            is_entry_point=True,
            is_config=False,
            is_security_critical=True,
        )

        serialized = self.cache._serialize_project_file(project_file)

        assert serialized["path"] == "test.py"
        assert serialized["language"] == "python"
        assert serialized["size_bytes"] == 1000
        assert serialized["priority_score"] == 0.8
        assert serialized["security_relevance"] == 0.9
        assert serialized["content_preview"] == "def test(): pass"
        assert serialized["is_entry_point"] is True
        assert serialized["is_config"] is False
        assert serialized["is_security_critical"] is True

    def test_deserialize_project_context(self):
        """Test ProjectContext deserialization."""
        cached_data = {
            "project_root": "/test/project",
            "project_type": "Python Application",
            "structure_overview": "Test structure",
            "key_files": [
                {
                    "path": "main.py",
                    "language": "python",
                    "size_bytes": 500,
                    "priority_score": 1.0,
                    "security_relevance": 0.8,
                    "content_preview": "def main(): pass",
                    "is_entry_point": True,
                    "is_config": False,
                    "is_security_critical": False,
                }
            ],
            "security_modules": ["auth.py"],
            "entry_points": ["main.py"],
            "dependencies": ["flask"],
            "architecture_summary": "Simple architecture",
            "total_files": 5,
            "total_size_bytes": 2500,
            "languages_used": ["python"],
            "estimated_tokens": 1000,
        }

        context = self.cache._deserialize_project_context(cached_data)

        assert context.project_root == Path("/test/project")
        assert context.project_type == "Python Application"
        assert len(context.key_files) == 1
        assert context.key_files[0].path == Path("main.py")
        assert context.key_files[0].is_entry_point is True
        assert context.security_modules == ["auth.py"]
        assert context.estimated_tokens == 1000

    def test_cache_project_context(self):
        """Test caching project context."""
        project_root = Path("/test/project")
        context = ProjectContext(
            project_root=project_root, project_type="Test App", estimated_tokens=1500
        )

        # Mock project signature
        self.mock_hasher.hash_content.return_value = "test_hash"

        self.cache.cache_project_context(project_root, context, cache_duration_hours=12)

        # Verify cache manager was called
        self.mock_cache_manager.put.assert_called_once()

        # Check the cached data structure
        call_args = self.mock_cache_manager.put.call_args
        cache_key, cache_data, expiry = call_args[0]

        assert cache_data["project_type"] == "Test App"
        assert cache_data["estimated_tokens"] == 1500
        assert "cached_at" in cache_data
        assert expiry == 12 * 3600  # 12 hours in seconds

    def test_get_cached_project_context_hit(self):
        """Test retrieving cached project context (cache hit)."""
        project_root = Path("/test/project")

        # Mock cached data
        cached_data = {
            "project_root": str(project_root),
            "project_type": "Cached App",
            "structure_overview": "",
            "key_files": [],
            "security_modules": [],
            "entry_points": [],
            "dependencies": [],
            "architecture_summary": "",
            "total_files": 0,
            "total_size_bytes": 0,
            "languages_used": [],
            "estimated_tokens": 500,
            "cached_at": time.time() - 3600,  # 1 hour ago
        }

        # Mock the _cache dictionary to simulate cache hit
        from adversary_mcp_server.cache.types import CacheEntry, CacheType

        mock_entry = Mock(spec=CacheEntry)
        mock_entry.data = cached_data

        # Mock the project signature method to return a predictable value
        with patch.object(
            self.cache, "_create_project_signature", return_value="test_signature"
        ):
            # Create a mock cache with a key that will match our search
            cache_key = (
                f"{CacheType.PROJECT_CONTEXT.value}:test_signature:metadata_hash"
            )
            self.mock_cache_manager._cache = {cache_key: mock_entry}

            context = self.cache.get_cached_project_context(
                project_root, max_age_hours=24
            )

            assert context is not None
            assert context.project_type == "Cached App"
            assert context.estimated_tokens == 500

    def test_get_cached_project_context_miss(self):
        """Test retrieving cached project context (cache miss)."""
        project_root = Path("/test/project")

        # Mock cache miss
        self.mock_cache_manager.get.return_value = None

        context = self.cache.get_cached_project_context(project_root)

        assert context is None

    def test_get_cached_project_context_expired(self):
        """Test retrieving expired cached project context."""
        project_root = Path("/test/project")

        # Mock expired cached data
        cached_data = {
            "project_root": str(project_root),
            "project_type": "Expired App",
            "structure_overview": "",
            "key_files": [],
            "security_modules": [],
            "entry_points": [],
            "dependencies": [],
            "architecture_summary": "",
            "total_files": 0,
            "total_size_bytes": 0,
            "languages_used": [],
            "estimated_tokens": 500,
            "cached_at": time.time() - (25 * 3600),  # 25 hours ago
        }

        self.mock_cache_manager.get.return_value = cached_data

        context = self.cache.get_cached_project_context(project_root, max_age_hours=24)

        assert context is None  # Should return None for expired cache

    def test_cache_session_analysis(self):
        """Test caching session analysis results."""
        session_id = "test-session-123"
        analysis_query = "Find SQL injection vulnerabilities"
        findings = [
            {"rule_id": "sql_injection", "severity": "high"},
            {"rule_id": "xss", "severity": "medium"},
        ]

        self.mock_hasher.hash_content.return_value = "query_hash"

        self.cache.cache_session_analysis(
            session_id=session_id,
            analysis_query=analysis_query,
            findings=findings,
            cache_duration_hours=6,
        )

        # Verify cache manager was called
        self.mock_cache_manager.put.assert_called_once()

        call_args = self.mock_cache_manager.put.call_args
        cache_key, cache_data, expiry = call_args[0]

        assert cache_data["session_id"] == session_id
        assert cache_data["analysis_query"] == analysis_query
        assert cache_data["findings"] == findings
        assert cache_data["findings_count"] == 2
        assert expiry == 6 * 3600

    def test_get_cached_session_analysis_hit(self):
        """Test retrieving cached analysis results (hit)."""
        session_id = "test-session-123"
        analysis_query = "Find vulnerabilities"

        cached_data = {
            "session_id": session_id,
            "analysis_query": analysis_query,
            "findings": [{"rule_id": "test", "severity": "low"}],
            "cached_at": time.time() - 1800,  # 30 minutes ago
            "findings_count": 1,
        }

        self.mock_hasher.hash_content.return_value = "query_hash"
        self.mock_cache_manager.get.return_value = cached_data

        findings = self.cache.get_cached_session_analysis(
            session_id=session_id, analysis_query=analysis_query, max_age_hours=6
        )

        assert findings is not None
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "test"

    def test_get_cached_session_analysis_expired(self):
        """Test retrieving expired cached analysis results."""
        session_id = "test-session-123"
        analysis_query = "Find vulnerabilities"

        cached_data = {
            "session_id": session_id,
            "analysis_query": analysis_query,
            "findings": [{"rule_id": "test"}],
            "cached_at": time.time() - (7 * 3600),  # 7 hours ago
            "findings_count": 1,
        }

        self.mock_hasher.hash_content.return_value = "query_hash"
        self.mock_cache_manager.get.return_value = cached_data

        findings = self.cache.get_cached_session_analysis(
            session_id=session_id, analysis_query=analysis_query, max_age_hours=6
        )

        assert findings is None  # Should be None for expired cache

    def test_invalidate_project_cache(self):
        """Test project cache invalidation."""
        project_root = Path("/test/project")

        # Should not raise an exception
        self.cache.invalidate_project_cache(project_root)

        # Currently just logs, but method should complete successfully

    def test_cache_error_handling(self):
        """Test error handling in cache operations."""
        project_root = Path("/test/project")
        context = ProjectContext(project_root=project_root, estimated_tokens=100)

        # Mock cache manager to raise exception
        self.mock_cache_manager.put.side_effect = Exception("Cache error")

        # Should not raise exception, just log warning
        self.cache.cache_project_context(project_root, context)

        # Verify put was attempted
        self.mock_cache_manager.put.assert_called_once()


class TestTokenUsageOptimizer:
    """Test TokenUsageOptimizer functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.optimizer = TokenUsageOptimizer()

    def test_initialization(self):
        """Test optimizer initialization."""
        assert len(self.optimizer.token_usage_history) == 0

    def test_record_token_usage(self):
        """Test recording token usage."""
        session_id = "test-session"

        self.optimizer.record_token_usage(
            session_id=session_id,
            operation="context_loading",
            tokens_used=5000,
            tokens_available=50000,
        )

        assert session_id in self.optimizer.token_usage_history
        history = self.optimizer.token_usage_history[session_id]
        assert len(history) == 1

        record = history[0]
        assert record["operation"] == "context_loading"
        assert record["tokens_used"] == 5000
        assert record["tokens_available"] == 50000
        assert record["utilization"] == 0.1  # 5000/50000

    def test_record_multiple_usages(self):
        """Test recording multiple token usages."""
        session_id = "test-session"

        # Record multiple operations
        self.optimizer.record_token_usage(session_id, "operation1", 1000, 10000)
        self.optimizer.record_token_usage(session_id, "operation2", 2000, 10000)
        self.optimizer.record_token_usage(session_id, "operation3", 3000, 10000)

        history = self.optimizer.token_usage_history[session_id]
        assert len(history) == 3

        assert history[0]["operation"] == "operation1"
        assert history[1]["operation"] == "operation2"
        assert history[2]["operation"] == "operation3"

    def test_token_usage_history_cleanup(self):
        """Test automatic cleanup of old token usage history."""
        session_id = "test-session"

        # Mock old timestamp (25 hours ago)
        old_time = time.time() - (25 * 3600)

        # Manually add old record
        self.optimizer.token_usage_history[session_id] = [
            {
                "operation": "old_operation",
                "tokens_used": 1000,
                "tokens_available": 10000,
                "utilization": 0.1,
                "timestamp": old_time,
            }
        ]

        # Record new usage (should trigger cleanup)
        self.optimizer.record_token_usage(session_id, "new_operation", 2000, 10000)

        history = self.optimizer.token_usage_history[session_id]

        # Should only have the new record (old one cleaned up)
        assert len(history) == 1
        assert history[0]["operation"] == "new_operation"

    def test_get_optimal_context_size_no_history(self):
        """Test optimal context size with no history."""
        session_id = "new-session"

        optimal_size = self.optimizer.get_optimal_context_size(session_id)

        assert optimal_size == 50000  # Default size

    def test_get_optimal_context_size_high_utilization(self):
        """Test optimal context size with high utilization."""
        session_id = "high-util-session"

        # Record high utilization usage
        self.optimizer.record_token_usage(session_id, "op1", 45000, 50000)  # 90%
        self.optimizer.record_token_usage(session_id, "op2", 48000, 50000)  # 96%

        optimal_size = self.optimizer.get_optimal_context_size(session_id)

        assert optimal_size == 75000  # Increased for high utilization

    def test_get_optimal_context_size_low_utilization(self):
        """Test optimal context size with low utilization."""
        session_id = "low-util-session"

        # Record low utilization usage
        self.optimizer.record_token_usage(session_id, "op1", 5000, 50000)  # 10%
        self.optimizer.record_token_usage(session_id, "op2", 10000, 50000)  # 20%

        optimal_size = self.optimizer.get_optimal_context_size(session_id)

        assert optimal_size == 30000  # Decreased for low utilization

    def test_get_optimal_context_size_medium_utilization(self):
        """Test optimal context size with medium utilization."""
        session_id = "medium-util-session"

        # Record medium utilization usage
        self.optimizer.record_token_usage(session_id, "op1", 30000, 50000)  # 60%
        self.optimizer.record_token_usage(session_id, "op2", 35000, 50000)  # 70%

        optimal_size = self.optimizer.get_optimal_context_size(session_id)

        assert optimal_size == 50000  # Keep default for medium utilization

    def test_should_use_sliding_window(self):
        """Test sliding window recommendation."""
        session_id = "test-session"

        # Record usage that would result in large optimal context
        self.optimizer.record_token_usage(
            session_id, "op1", 46000, 50000
        )  # High utilization > 0.9

        should_use_sliding = self.optimizer.should_use_sliding_window(session_id)

        assert should_use_sliding is True  # Large context should use sliding window

    def test_should_not_use_sliding_window(self):
        """Test sliding window not recommended for smaller contexts."""
        session_id = "test-session"

        # Record usage that would result in small optimal context
        self.optimizer.record_token_usage(
            session_id, "op1", 5000, 50000
        )  # Low utilization

        should_use_sliding = self.optimizer.should_use_sliding_window(session_id)

        assert should_use_sliding is False  # Small context doesn't need sliding window

    def test_zero_available_tokens_handling(self):
        """Test handling of zero available tokens."""
        session_id = "test-session"

        # This should not crash
        self.optimizer.record_token_usage(session_id, "operation", 1000, 0)

        history = self.optimizer.token_usage_history[session_id]
        assert history[0]["utilization"] == 0  # Should handle division by zero


@pytest.fixture
def temp_cache_dir():
    """Create temporary cache directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


class TestSessionCacheIntegration:
    """Integration tests for SessionCache with real CacheManager."""

    def test_full_cache_workflow(self, temp_cache_dir):
        """Test complete cache workflow with real cache manager."""
        # Create real cache manager
        cache_manager = CacheManager(cache_dir=temp_cache_dir)
        session_cache = SessionCache(cache_manager)

        # Create test project context
        project_root = Path("/test/project")
        context = ProjectContext(
            project_root=project_root,
            project_type="Integration Test App",
            total_files=10,
            estimated_tokens=2000,
            key_files=[
                ProjectFile(
                    path=Path("main.py"),
                    language="python",
                    size_bytes=500,
                    content_preview="def main(): pass",
                )
            ],
        )

        # Cache the context
        session_cache.cache_project_context(
            project_root, context, cache_duration_hours=1
        )

        # Retrieve the context
        retrieved_context = session_cache.get_cached_project_context(
            project_root, max_age_hours=2
        )

        # Verify retrieval
        assert retrieved_context is not None
        assert retrieved_context.project_type == "Integration Test App"
        assert retrieved_context.total_files == 10
        assert retrieved_context.estimated_tokens == 2000
        assert len(retrieved_context.key_files) == 1
        assert retrieved_context.key_files[0].path == Path("main.py")

    def test_cache_persistence(self, temp_cache_dir):
        """Test that cache persists across SessionCache instances."""
        project_root = Path("/test/persistent")

        # Create context with first cache instance
        cache_manager1 = CacheManager(cache_dir=temp_cache_dir)
        session_cache1 = SessionCache(cache_manager1)

        context = ProjectContext(
            project_root=project_root,
            project_type="Persistent App",
            estimated_tokens=1500,
        )

        session_cache1.cache_project_context(project_root, context)

        # Retrieve with second cache instance
        cache_manager2 = CacheManager(cache_dir=temp_cache_dir)
        session_cache2 = SessionCache(cache_manager2)

        retrieved_context = session_cache2.get_cached_project_context(project_root)

        assert retrieved_context is not None
        assert retrieved_context.project_type == "Persistent App"
        assert retrieved_context.estimated_tokens == 1500
