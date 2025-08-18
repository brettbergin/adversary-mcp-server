"""Comprehensive tests for session cache functionality."""

import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.adversary_mcp_server.cache import CacheKey, CacheManager, CacheType
from src.adversary_mcp_server.session.project_context import ProjectContext, ProjectFile
from src.adversary_mcp_server.session.session_cache import (
    SessionCache,
    TokenUsageOptimizer,
)


class TestSessionCache:
    """Test SessionCache functionality."""

    @pytest.fixture
    def mock_cache_manager(self):
        """Create a mock cache manager."""
        mock_manager = Mock(spec=CacheManager)
        mock_hasher = Mock()
        mock_hasher.hash_content.side_effect = lambda x: f"hash_{hash(x)}"
        mock_manager.get_hasher.return_value = mock_hasher
        mock_manager._cache = {}
        return mock_manager

    @pytest.fixture
    def session_cache(self, mock_cache_manager):
        """Create a SessionCache instance."""
        return SessionCache(mock_cache_manager)

    @pytest.fixture
    def sample_project_context(self):
        """Create a sample project context."""
        project_file = ProjectFile(
            path=Path("test_file.py"),
            language="python",
            size_bytes=1000,
            priority_score=0.8,
            security_relevance="high",
            content_preview="def test(): pass",
            is_entry_point=True,
            is_config=False,
            is_security_critical=True,
        )

        return ProjectContext(
            project_root=Path("/test/project"),
            project_type="python",
            structure_overview="Test project",
            key_files=[project_file],
            security_modules=["auth", "crypto"],
            entry_points=["main.py"],
            dependencies=["requests", "flask"],
            architecture_summary="Web application",
            total_files=10,
            total_size_bytes=50000,
            languages_used={"python", "javascript"},
            estimated_tokens=1500,
        )

    def test_initialization(self, mock_cache_manager):
        """Test SessionCache initialization."""
        cache = SessionCache(mock_cache_manager)

        assert cache.cache_manager == mock_cache_manager
        assert cache.hasher is not None
        assert cache._context_cache_hits == 0
        assert cache._context_cache_misses == 0
        assert cache._analysis_cache_hits == 0
        assert cache._analysis_cache_misses == 0

    def test_cache_project_context_success(self, session_cache, sample_project_context):
        """Test successful project context caching."""
        session_cache.cache_project_context(
            sample_project_context.project_root,
            sample_project_context,
            cache_duration_hours=12,
        )

        # Verify cache manager was called
        session_cache.cache_manager.put.assert_called_once()
        call_args = session_cache.cache_manager.put.call_args

        # Check cache key
        cache_key = call_args[0][0]
        assert isinstance(cache_key, CacheKey)
        assert cache_key.cache_type == CacheType.PROJECT_CONTEXT

        # Check cache data structure
        cached_data = call_args[0][1]
        assert cached_data["project_root"] == str(sample_project_context.project_root)
        assert cached_data["project_type"] == sample_project_context.project_type
        assert cached_data["total_files"] == sample_project_context.total_files
        assert "cached_at" in cached_data

        # Check expiry
        expiry = call_args[0][2]
        assert expiry == 12 * 3600

    def test_cache_project_context_exception_handling(
        self, session_cache, sample_project_context
    ):
        """Test project context caching with exception."""
        session_cache.cache_manager.put.side_effect = Exception("Cache error")

        # Should not raise exception
        session_cache.cache_project_context(
            sample_project_context.project_root, sample_project_context
        )

    def test_get_cached_project_context_found(self, session_cache):
        """Test retrieving cached project context when found."""
        # Setup mock cache data
        cached_data = {
            "project_root": "/test/project",
            "project_type": "python",
            "structure_overview": "Test project",
            "key_files": [],
            "security_modules": ["auth"],
            "entry_points": ["main.py"],
            "dependencies": ["requests"],
            "architecture_summary": "Web app",
            "total_files": 5,
            "total_size_bytes": 25000,
            "languages_used": ["python"],
            "estimated_tokens": 1000,
            "cached_at": time.time() - 1000,  # 1000 seconds ago
        }

        # Mock cache lookup
        session_cache.cache_manager._cache = {
            "project_context:test_hash:meta_hash": Mock(data=cached_data)
        }

        with patch.object(
            session_cache, "_create_project_signature", return_value="test_hash"
        ):
            result = session_cache.get_cached_project_context(Path("/test/project"))

        assert result is not None
        assert result.project_type == "python"
        assert result.total_files == 5

    def test_get_cached_project_context_expired(self, session_cache):
        """Test retrieving expired cached project context."""
        # Setup expired cache data
        cached_data = {
            "project_root": "/test/project",
            "project_type": "python",
            "structure_overview": "Test project",
            "key_files": [],
            "security_modules": ["auth"],
            "entry_points": ["main.py"],
            "dependencies": ["requests"],
            "architecture_summary": "Web app",
            "total_files": 5,
            "total_size_bytes": 25000,
            "languages_used": ["python"],
            "estimated_tokens": 1000,
            "cached_at": time.time() - 48 * 3600,  # 48 hours ago
        }

        session_cache.cache_manager._cache = {
            "project_context:test_hash:meta_hash": Mock(data=cached_data)
        }

        with patch.object(
            session_cache, "_create_project_signature", return_value="test_hash"
        ):
            result = session_cache.get_cached_project_context(
                Path("/test/project"), max_age_hours=24
            )

        assert result is None

    def test_get_cached_project_context_not_found(self, session_cache):
        """Test retrieving cached project context when not found."""
        session_cache.cache_manager._cache = {}

        with patch.object(
            session_cache, "_create_project_signature", return_value="test_hash"
        ):
            result = session_cache.get_cached_project_context(Path("/test/project"))

        assert result is None

    def test_get_cached_project_context_exception(self, session_cache):
        """Test exception handling in get_cached_project_context."""
        with patch.object(
            session_cache, "_create_project_signature", side_effect=Exception("Error")
        ):
            result = session_cache.get_cached_project_context(Path("/test/project"))

        assert result is None

    def test_cache_session_analysis_success(self, session_cache):
        """Test successful session analysis caching."""
        session_id = "test_session_123"
        analysis_query = "Find vulnerabilities"
        findings = [{"rule": "test", "severity": "high"}]

        session_cache.cache_session_analysis(
            session_id, analysis_query, findings, cache_duration_hours=8
        )

        session_cache.cache_manager.put.assert_called_once()
        call_args = session_cache.cache_manager.put.call_args

        # Check cache key
        cache_key = call_args[0][0]
        assert cache_key.cache_type == CacheType.ANALYSIS_RESULT
        assert cache_key.content_hash == session_id

        # Check cached data
        cached_data = call_args[0][1]
        assert cached_data["session_id"] == session_id
        assert cached_data["analysis_query"] == analysis_query
        assert cached_data["findings"] == findings
        assert cached_data["findings_count"] == 1

    def test_cache_session_analysis_exception(self, session_cache):
        """Test session analysis caching with exception."""
        session_cache.cache_manager.put.side_effect = Exception("Cache error")

        # Should not raise exception
        session_cache.cache_session_analysis("session", "query", [])

    def test_get_cached_session_analysis_found(self, session_cache):
        """Test retrieving cached session analysis when found."""
        cached_data = {
            "session_id": "test_session",
            "analysis_query": "test query",
            "findings": [{"rule": "test"}],
            "cached_at": time.time() - 1000,
            "findings_count": 1,
        }

        session_cache.cache_manager.get.return_value = cached_data

        result = session_cache.get_cached_session_analysis("test_session", "test query")

        assert result == [{"rule": "test"}]

    def test_get_cached_session_analysis_expired(self, session_cache):
        """Test retrieving expired cached session analysis."""
        cached_data = {
            "session_id": "test_session",
            "analysis_query": "test query",
            "findings": [{"rule": "test"}],
            "cached_at": time.time() - 24 * 3600,  # 24 hours ago
            "findings_count": 1,
        }

        session_cache.cache_manager.get.return_value = cached_data

        result = session_cache.get_cached_session_analysis(
            "test_session", "test query", max_age_hours=6
        )

        assert result is None

    def test_get_cached_session_analysis_not_found(self, session_cache):
        """Test retrieving cached session analysis when not found."""
        session_cache.cache_manager.get.return_value = None

        result = session_cache.get_cached_session_analysis("test_session", "test query")

        assert result is None

    def test_get_cached_session_analysis_exception(self, session_cache):
        """Test exception handling in get_cached_session_analysis."""
        session_cache.cache_manager.get.side_effect = Exception("Cache error")

        result = session_cache.get_cached_session_analysis("test_session", "test query")

        assert result is None

    def test_invalidate_project_cache(self, session_cache):
        """Test project cache invalidation."""
        project_root = Path("/test/project")

        with patch.object(
            session_cache, "_create_project_signature", return_value="test_hash"
        ):
            # Should not raise exception
            session_cache.invalidate_project_cache(project_root)

    def test_invalidate_project_cache_exception(self, session_cache):
        """Test project cache invalidation with exception."""
        with patch.object(
            session_cache, "_create_project_signature", side_effect=Exception("Error")
        ):
            # Should not raise exception
            session_cache.invalidate_project_cache(Path("/test/project"))

    def test_create_project_signature_basic(self, session_cache):
        """Test basic project signature creation."""
        project_root = Path("/test/project")

        with (
            patch("pathlib.Path.exists", return_value=False),
            patch("pathlib.Path.iterdir", return_value=[]),
            patch("pathlib.Path.is_dir", return_value=True),
        ):

            signature = session_cache._create_project_signature(project_root)

            assert isinstance(signature, str)
            assert len(signature) == 16  # Hash truncated to 16 chars

    def test_create_project_signature_with_files(self, session_cache):
        """Test project signature creation with existing files."""
        project_root = Path("/test/project")

        # Mock file exists and stats
        mock_file = Mock()
        mock_file.exists.return_value = True
        mock_file.stat.return_value = Mock(st_mtime=1234567890)

        # Mock directory structure
        mock_dir = Mock()
        mock_dir.name = "src"
        mock_dir.is_dir.return_value = True

        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.stat", return_value=Mock(st_mtime=1234567890)),
            patch("pathlib.Path.iterdir", return_value=[mock_dir]),
        ):

            signature = session_cache._create_project_signature(project_root)

            assert isinstance(signature, str)
            assert len(signature) == 16

    def test_create_project_signature_exception(self, session_cache):
        """Test project signature creation with exception."""
        project_root = Path("/test/project")

        with patch("pathlib.Path.iterdir", side_effect=Exception("Directory error")):
            signature = session_cache._create_project_signature(project_root)

            # Should still return a hash based on path only
            assert isinstance(signature, str)
            assert len(signature) == 16

    def test_serialize_project_file(self, session_cache):
        """Test project file serialization."""
        project_file = ProjectFile(
            path=Path("test.py"),
            language="python",
            size_bytes=1000,
            priority_score=0.8,
            security_relevance="high",
            content_preview="test code",
            is_entry_point=True,
            is_config=False,
            is_security_critical=True,
        )

        serialized = session_cache._serialize_project_file(project_file)

        assert serialized["path"] == "test.py"
        assert serialized["language"] == "python"
        assert serialized["size_bytes"] == 1000
        assert serialized["priority_score"] == 0.8
        assert serialized["security_relevance"] == "high"
        assert serialized["content_preview"] == "test code"
        assert serialized["is_entry_point"] is True
        assert serialized["is_config"] is False
        assert serialized["is_security_critical"] is True

    def test_deserialize_project_context(self, session_cache):
        """Test project context deserialization."""
        cached_data = {
            "project_root": "/test/project",
            "project_type": "python",
            "structure_overview": "Test project",
            "key_files": [
                {
                    "path": "test.py",
                    "language": "python",
                    "size_bytes": 1000,
                    "priority_score": 0.8,
                    "security_relevance": "high",
                    "content_preview": "test code",
                    "is_entry_point": True,
                    "is_config": False,
                    "is_security_critical": True,
                }
            ],
            "security_modules": ["auth"],
            "entry_points": ["main.py"],
            "dependencies": ["requests"],
            "architecture_summary": "Web app",
            "total_files": 5,
            "total_size_bytes": 25000,
            "languages_used": ["python"],
            "estimated_tokens": 1000,
        }

        context = session_cache._deserialize_project_context(cached_data)

        assert isinstance(context, ProjectContext)
        assert context.project_root == Path("/test/project")
        assert context.project_type == "python"
        assert len(context.key_files) == 1
        assert context.key_files[0].path == Path("test.py")
        assert context.languages_used == {"python"}

    def test_cache_analysis_result_success(self, session_cache, sample_project_context):
        """Test successful analysis result caching."""
        analysis_query = "Find SQL injection"
        analysis_result = [{"vulnerability": "sql_injection"}]

        session_cache.cache_analysis_result(
            analysis_query,
            sample_project_context,
            analysis_result,
            cache_duration_hours=10,
        )

        session_cache.cache_manager.put.assert_called_once()
        call_args = session_cache.cache_manager.put.call_args

        # Check cache key
        cache_key = call_args[0][0]
        assert cache_key.cache_type == CacheType.LLM_RESPONSE

        # Check cached data
        cached_data = call_args[0][1]
        assert cached_data["analysis_result"] == analysis_result
        assert cached_data["query"] == analysis_query
        assert "cached_at" in cached_data

    def test_cache_analysis_result_exception(
        self, session_cache, sample_project_context
    ):
        """Test analysis result caching with exception."""
        session_cache.cache_manager.put.side_effect = Exception("Cache error")

        # Should not raise exception
        session_cache.cache_analysis_result("query", sample_project_context, [])

    def test_get_cached_analysis_result_found(
        self, session_cache, sample_project_context
    ):
        """Test retrieving cached analysis result when found."""
        cached_data = {
            "analysis_result": [{"vuln": "test"}],
            "query": "test query",
            "project_root": str(sample_project_context.project_root),
            "cached_at": time.time() - 1000,
        }

        session_cache.cache_manager.get.return_value = cached_data

        result = session_cache.get_cached_analysis_result(
            "test query", sample_project_context
        )

        assert result == [{"vuln": "test"}]
        assert session_cache._analysis_cache_hits == 1

    def test_get_cached_analysis_result_expired(
        self, session_cache, sample_project_context
    ):
        """Test retrieving expired cached analysis result."""
        cached_data = {
            "analysis_result": [{"vuln": "test"}],
            "query": "test query",
            "project_root": str(sample_project_context.project_root),
            "cached_at": time.time() - 48 * 3600,  # 48 hours ago
        }

        session_cache.cache_manager.get.return_value = cached_data

        result = session_cache.get_cached_analysis_result(
            "test query", sample_project_context, max_age_hours=12
        )

        assert result is None
        assert session_cache._analysis_cache_misses == 1

    def test_get_cached_analysis_result_not_found(
        self, session_cache, sample_project_context
    ):
        """Test retrieving cached analysis result when not found."""
        session_cache.cache_manager.get.return_value = None

        result = session_cache.get_cached_analysis_result(
            "test query", sample_project_context
        )

        assert result is None
        assert session_cache._analysis_cache_misses == 1

    def test_get_cached_analysis_result_exception(
        self, session_cache, sample_project_context
    ):
        """Test exception handling in get_cached_analysis_result."""
        session_cache.cache_manager.get.side_effect = Exception("Cache error")

        result = session_cache.get_cached_analysis_result(
            "test query", sample_project_context
        )

        assert result is None
        assert session_cache._analysis_cache_misses == 1

    def test_warm_project_cache_already_cached(self, session_cache):
        """Test warming project cache when already cached."""
        project_root = Path("/test/project")

        with patch.object(
            session_cache, "get_cached_project_context", return_value=Mock()
        ):
            result = session_cache.warm_project_cache(project_root)

            assert result is True

    def test_warm_project_cache_success(self, session_cache, sample_project_context):
        """Test successful project cache warming."""
        project_root = Path("/test/project")

        mock_builder = Mock()
        mock_builder.build_context.return_value = sample_project_context

        with (
            patch.object(
                session_cache, "get_cached_project_context", return_value=None
            ),
            patch(
                "src.adversary_mcp_server.session.project_context.ProjectContextBuilder",
                return_value=mock_builder,
            ),
            patch.object(session_cache, "cache_project_context") as mock_cache,
        ):

            result = session_cache.warm_project_cache(project_root)

            assert result is True
            mock_cache.assert_called_once_with(project_root, sample_project_context)

    def test_warm_project_cache_exception(self, session_cache):
        """Test project cache warming with exception."""
        project_root = Path("/test/project")

        with patch.object(
            session_cache, "get_cached_project_context", side_effect=Exception("Error")
        ):
            result = session_cache.warm_project_cache(project_root)

            assert result is False

    def test_get_cache_statistics(self, session_cache):
        """Test cache statistics retrieval."""
        # Set some cache hit/miss counts
        session_cache._context_cache_hits = 5
        session_cache._context_cache_misses = 2
        session_cache._analysis_cache_hits = 10
        session_cache._analysis_cache_misses = 3

        # Mock cache manager stats
        session_cache.cache_manager.get_stats = Mock(return_value={"total_size": 1024})

        stats = session_cache.get_cache_statistics()

        assert stats["context_cache"]["hits"] == 5
        assert stats["context_cache"]["misses"] == 2
        assert stats["context_cache"]["hit_rate"] == 5 / 7  # 5/(5+2)

        assert stats["analysis_cache"]["hits"] == 10
        assert stats["analysis_cache"]["misses"] == 3
        assert stats["analysis_cache"]["hit_rate"] == 10 / 13  # 10/(10+3)

        assert stats["cache_manager_stats"]["total_size"] == 1024

    def test_get_cache_statistics_no_requests(self, session_cache):
        """Test cache statistics with no cache requests."""
        stats = session_cache.get_cache_statistics()

        assert stats["context_cache"]["hit_rate"] == 0
        assert stats["analysis_cache"]["hit_rate"] == 0

    def test_optimize_cache_usage(self, session_cache):
        """Test cache usage optimization."""
        # Mock statistics
        mock_stats = {
            "context_cache": {"hit_rate": 0.2},  # Low hit rate
            "analysis_cache": {"hit_rate": 0.1},  # Very low hit rate
        }

        with patch.object(
            session_cache, "get_cache_statistics", return_value=mock_stats
        ):
            # Should not raise exception
            session_cache.optimize_cache_usage()

    def test_optimize_cache_usage_exception(self, session_cache):
        """Test cache usage optimization with exception."""
        with patch.object(
            session_cache, "get_cache_statistics", side_effect=Exception("Error")
        ):
            # Should not raise exception
            session_cache.optimize_cache_usage()


class TestTokenUsageOptimizer:
    """Test TokenUsageOptimizer functionality."""

    @pytest.fixture
    def optimizer(self):
        """Create a TokenUsageOptimizer instance."""
        return TokenUsageOptimizer()

    def test_initialization(self, optimizer):
        """Test TokenUsageOptimizer initialization."""
        assert optimizer.token_usage_history == {}

    def test_record_token_usage(self, optimizer):
        """Test recording token usage."""
        session_id = "test_session"

        optimizer.record_token_usage(session_id, "analysis", 1000, 4000)

        assert session_id in optimizer.token_usage_history
        assert len(optimizer.token_usage_history[session_id]) == 1

        record = optimizer.token_usage_history[session_id][0]
        assert record["operation"] == "analysis"
        assert record["tokens_used"] == 1000
        assert record["tokens_available"] == 4000
        assert record["utilization"] == 0.25  # 1000/4000

    def test_record_token_usage_zero_available(self, optimizer):
        """Test recording token usage with zero available tokens."""
        optimizer.record_token_usage("session", "test", 100, 0)

        record = optimizer.token_usage_history["session"][0]
        assert record["utilization"] == 0

    def test_record_token_usage_cleanup_old_records(self, optimizer):
        """Test that old token usage records are cleaned up."""
        session_id = "test_session"

        # Add an old record
        old_time = time.time() - (25 * 3600)  # 25 hours ago
        optimizer.token_usage_history[session_id] = [
            {
                "operation": "old_op",
                "tokens_used": 500,
                "tokens_available": 2000,
                "utilization": 0.25,
                "timestamp": old_time,
            }
        ]

        # Add a new record
        optimizer.record_token_usage(session_id, "new_op", 1000, 4000)

        # Old record should be removed
        assert len(optimizer.token_usage_history[session_id]) == 1
        assert optimizer.token_usage_history[session_id][0]["operation"] == "new_op"

    def test_get_optimal_context_size_no_history(self, optimizer):
        """Test getting optimal context size with no history."""
        result = optimizer.get_optimal_context_size("unknown_session")
        assert result == 50000  # Default

    def test_get_optimal_context_size_empty_history(self, optimizer):
        """Test getting optimal context size with empty history."""
        optimizer.token_usage_history["session"] = []
        result = optimizer.get_optimal_context_size("session")
        assert result == 50000  # Default

    def test_get_optimal_context_size_high_utilization(self, optimizer):
        """Test optimal context size with high utilization."""
        session_id = "test_session"
        optimizer.token_usage_history[session_id] = [
            {"utilization": 0.95, "timestamp": time.time()},
            {"utilization": 0.92, "timestamp": time.time()},
        ]

        result = optimizer.get_optimal_context_size(session_id)
        assert result == 75000  # Increased for high utilization

    def test_get_optimal_context_size_low_utilization(self, optimizer):
        """Test optimal context size with low utilization."""
        session_id = "test_session"
        optimizer.token_usage_history[session_id] = [
            {"utilization": 0.3, "timestamp": time.time()},
            {"utilization": 0.4, "timestamp": time.time()},
        ]

        result = optimizer.get_optimal_context_size(session_id)
        assert result == 30000  # Decreased for low utilization

    def test_get_optimal_context_size_medium_utilization(self, optimizer):
        """Test optimal context size with medium utilization."""
        session_id = "test_session"
        optimizer.token_usage_history[session_id] = [
            {"utilization": 0.6, "timestamp": time.time()},
            {"utilization": 0.7, "timestamp": time.time()},
        ]

        result = optimizer.get_optimal_context_size(session_id)
        assert result == 50000  # Default for medium utilization

    def test_should_use_sliding_window(self, optimizer):
        """Test sliding window usage decision."""
        session_id = "test_session"

        # Mock high optimal size
        with patch.object(optimizer, "get_optimal_context_size", return_value=70000):
            assert optimizer.should_use_sliding_window(session_id) is True

        # Mock low optimal size
        with patch.object(optimizer, "get_optimal_context_size", return_value=50000):
            assert optimizer.should_use_sliding_window(session_id) is False

    def test_create_sliding_window_empty_history(self, optimizer):
        """Test creating sliding window with empty conversation history."""
        result = optimizer.create_sliding_window([], 10000)
        assert result == []

    def test_create_sliding_window_basic(self, optimizer):
        """Test creating sliding window with basic conversation."""
        conversation = [
            {"role": "system", "content": "System message"},
            {"role": "user", "content": "User question"},
            {"role": "assistant", "content": "Assistant response"},
        ]

        result = optimizer.create_sliding_window(conversation, 1000)

        # Should include all messages as they fit in budget
        assert len(result) == 3
        assert result[0]["role"] == "system"

    def test_create_sliding_window_large_conversation(self, optimizer):
        """Test creating sliding window with large conversation that needs truncation."""
        # Create a large conversation
        conversation = []
        for i in range(20):
            conversation.append(
                {
                    "role": "user" if i % 2 == 0 else "assistant",
                    "content": "x" * 1000,  # Large content
                }
            )

        result = optimizer.create_sliding_window(conversation, 5000)  # Small budget

        # Should be truncated but include recent messages
        assert len(result) < len(conversation)
        assert len(result) >= 3  # Emergency fallback ensures at least 3

    def test_create_sliding_window_emergency_fallback(self, optimizer):
        """Test sliding window emergency fallback."""
        conversation = [
            {"role": "system", "content": "x" * 10000},  # Very large
            {"role": "user", "content": "x" * 10000},  # Very large
            {"role": "assistant", "content": "x" * 10000},  # Very large
        ]

        result = optimizer.create_sliding_window(conversation, 100)  # Very small budget

        # Emergency fallback should keep last 3 messages
        assert len(result) == 3

    def test_optimize_context_for_sliding_window(self, optimizer):
        """Test context optimization for sliding window."""
        # Create mock project context
        mock_context = Mock()
        mock_context.project_root = Path("/test/project")
        mock_context.project_type = "python"
        mock_context.architecture_summary = "Web app"
        mock_context.total_files = 10
        mock_context.languages_used = {"python", "javascript"}

        # Create mock files
        mock_file1 = Mock()
        mock_file1.path = Path("main.py")
        mock_file1.priority_score = 0.9
        mock_file1.content_preview = "def main():\n    pass"
        mock_file1.language = "python"
        mock_file1.security_relevance = "high"
        mock_file1.is_security_critical = True

        mock_file2 = Mock()
        mock_file2.path = Path("utils.py")
        mock_file2.priority_score = 0.5
        mock_file2.content_preview = "def util():\n    pass"
        mock_file2.language = "python"
        mock_file2.security_relevance = "medium"
        mock_file2.is_security_critical = False

        mock_context.key_files = [mock_file1, mock_file2]

        result = optimizer.optimize_context_for_sliding_window(
            mock_context, "main.py", 1000
        )

        assert result["project_root"] == "/test/project"
        assert result["project_type"] == "python"
        assert result["optimization_applied"] is True
        assert result["focus_context"] == "main.py"
        assert "key_files" in result

    def test_get_incremental_analysis_metadata_no_history(self, optimizer):
        """Test getting incremental analysis metadata with no history."""
        result = optimizer.get_incremental_analysis_metadata("unknown_session")

        assert result["last_analysis_timestamp"] is None
        assert result["analyzed_files"] == set()
        assert result["analyzed_commit_hash"] is None
        assert result["baseline_established"] is False

    def test_get_incremental_analysis_metadata_no_incremental_ops(self, optimizer):
        """Test getting incremental analysis metadata with no incremental operations."""
        session_id = "test_session"
        optimizer.token_usage_history[session_id] = [
            {"operation": "regular_analysis", "timestamp": time.time()}
        ]

        result = optimizer.get_incremental_analysis_metadata(session_id)

        assert result["last_analysis_timestamp"] is None
        assert result["analyzed_files"] == set()
        assert result["baseline_established"] is False

    def test_get_incremental_analysis_metadata_with_incremental_ops(self, optimizer):
        """Test getting incremental analysis metadata with incremental operations."""
        session_id = "test_session"
        timestamp = time.time()
        optimizer.token_usage_history[session_id] = [
            {
                "operation": "incremental_scan",
                "timestamp": timestamp,
                "metadata": {
                    "last_analysis_timestamp": timestamp,
                    "analyzed_files": {"file1.py", "file2.py"},
                    "analyzed_commit_hash": "abc123",
                    "baseline_established": True,
                },
            }
        ]

        result = optimizer.get_incremental_analysis_metadata(session_id)

        assert result["last_analysis_timestamp"] == timestamp
        assert result["analyzed_files"] == {"file1.py", "file2.py"}
        assert result["analyzed_commit_hash"] == "abc123"
        assert result["baseline_established"] is True

    def test_record_incremental_analysis(self, optimizer):
        """Test recording incremental analysis operation."""
        session_id = "test_session"
        analyzed_files = ["file1.py", "file2.py"]

        optimizer.record_incremental_analysis(
            session_id,
            "git_diff",
            analyzed_files,
            commit_hash="abc123",
            findings_count=5,
            tokens_used=2000,
        )

        assert session_id in optimizer.token_usage_history
        record = optimizer.token_usage_history[session_id][0]

        assert record["operation"] == "incremental_git_diff"
        assert record["tokens_used"] == 2000
        assert "metadata" in record

        metadata = record["metadata"]
        assert metadata["analyzed_files"] == set(analyzed_files)
        assert metadata["analyzed_commit_hash"] == "abc123"
        assert metadata["findings_count"] == 5
        assert metadata["file_count"] == 2
        assert metadata["baseline_established"] is True

    def test_record_incremental_analysis_cleanup(self, optimizer):
        """Test that incremental analysis recording cleans up old records."""
        session_id = "test_session"

        # Add old record
        old_time = time.time() - (25 * 3600)  # 25 hours ago
        optimizer.token_usage_history[session_id] = [
            {
                "operation": "incremental_old",
                "timestamp": old_time,
                "utilization": 0.5,  # Required field for get_optimal_context_size
            }
        ]

        # Record new incremental analysis
        optimizer.record_incremental_analysis(session_id, "new_scan", ["file.py"])

        # Old record should be removed
        assert len(optimizer.token_usage_history[session_id]) == 1
        assert (
            optimizer.token_usage_history[session_id][0]["operation"]
            == "incremental_new_scan"
        )
