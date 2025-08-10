"""Tests for CacheCoordinator."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from adversary_mcp_server.application.coordination.cache_coordinator import (
    CacheCoordinator,
)
from adversary_mcp_server.cache import CacheKey, CacheType
from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
from adversary_mcp_server.scanner.types import Severity, ThreatMatch


@pytest.fixture
def mock_cache_manager():
    """Create a mock cache manager."""
    cache_manager = Mock()
    hasher = Mock()
    hasher.hash_content.return_value = "content_hash_123"
    hasher.hash_metadata.return_value = "metadata_hash_456"
    cache_manager.get_hasher.return_value = hasher
    cache_manager.get.return_value = None
    cache_manager.put.return_value = None
    return cache_manager


@pytest.fixture
def cache_coordinator(mock_cache_manager):
    """Create a CacheCoordinator instance."""
    return CacheCoordinator(cache_manager=mock_cache_manager)


@pytest.fixture
def sample_enhanced_result():
    """Create a sample EnhancedScanResult."""
    llm_threats = [
        ThreatMatch(
            rule_id="llm-1",
            rule_name="LLM Threat",
            description="LLM detected threat",
            category="injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
        )
    ]

    semgrep_threats = [
        ThreatMatch(
            rule_id="semgrep-1",
            rule_name="Semgrep Threat",
            description="Semgrep detected threat",
            category="xss",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=20,
        )
    ]

    return EnhancedScanResult(
        file_path="test.py",
        llm_threats=llm_threats,
        semgrep_threats=semgrep_threats,
        scan_metadata={"test": "metadata"},
        validation_results={"test": "validation"},
        llm_usage_stats={"test": "stats"},
    )


@pytest.fixture
def scan_parameters():
    """Create sample scan parameters."""
    return {
        "use_llm": True,
        "use_semgrep": True,
        "use_validation": True,
        "language": "python",
        "severity_threshold": "medium",
    }


class TestCacheCoordinator:
    """Test CacheCoordinator functionality."""

    def test_init_with_cache_manager(self, mock_cache_manager):
        """Test initialization with cache manager."""
        coordinator = CacheCoordinator(cache_manager=mock_cache_manager)
        assert coordinator.cache_manager == mock_cache_manager

    def test_init_without_cache_manager(self):
        """Test initialization without cache manager."""
        coordinator = CacheCoordinator()
        assert coordinator.cache_manager is None

    def test_is_cache_available_true(self, cache_coordinator):
        """Test is_cache_available when cache manager is present."""
        assert cache_coordinator.is_cache_available() is True

    def test_is_cache_available_false(self):
        """Test is_cache_available when cache manager is absent."""
        coordinator = CacheCoordinator(cache_manager=None)
        assert coordinator.is_cache_available() is False

    @pytest.mark.asyncio
    async def test_get_cached_scan_result_no_cache_manager(self):
        """Test get_cached_scan_result without cache manager."""
        coordinator = CacheCoordinator(cache_manager=None)

        result = await coordinator.get_cached_scan_result(
            file_path=Path("test.py"),
            content_hash="hash123",
            scan_parameters={},
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_get_cached_scan_result_cache_miss(
        self, cache_coordinator, scan_parameters, mock_cache_manager
    ):
        """Test get_cached_scan_result with cache miss."""
        mock_cache_manager.get.return_value = None

        result = await cache_coordinator.get_cached_scan_result(
            file_path=Path("test.py"),
            content_hash="hash123",
            scan_parameters=scan_parameters,
        )

        assert result is None
        mock_cache_manager.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_cached_scan_result_cache_hit(
        self, cache_coordinator, scan_parameters, mock_cache_manager
    ):
        """Test get_cached_scan_result with cache hit."""
        # Mock cached data
        cached_data = {
            "file_path": "test.py",
            "llm_threats": [],
            "semgrep_threats": [],
            "scan_metadata": {"test": "metadata"},
            "validation_results": {},
            "llm_usage_stats": {},
        }
        mock_cache_manager.get.return_value = cached_data

        result = await cache_coordinator.get_cached_scan_result(
            file_path=Path("test.py"),
            content_hash="hash123",
            scan_parameters=scan_parameters,
        )

        assert result is not None
        assert isinstance(result, EnhancedScanResult)
        assert result.file_path == "test.py"
        assert result.scan_metadata["cache_hit"] is True
        assert "cache_key" in result.scan_metadata

    @pytest.mark.asyncio
    async def test_get_cached_scan_result_exception(
        self, cache_coordinator, scan_parameters, mock_cache_manager
    ):
        """Test get_cached_scan_result when exception occurs."""
        mock_cache_manager.get.side_effect = Exception("Cache error")

        result = await cache_coordinator.get_cached_scan_result(
            file_path=Path("test.py"),
            content_hash="hash123",
            scan_parameters=scan_parameters,
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_cache_scan_result_no_cache_manager(self, sample_enhanced_result):
        """Test cache_scan_result without cache manager."""
        coordinator = CacheCoordinator(cache_manager=None)

        # Should not raise exception
        await coordinator.cache_scan_result(
            file_path=Path("test.py"),
            result=sample_enhanced_result,
            content_hash="hash123",
            scan_parameters={},
        )

    @pytest.mark.asyncio
    async def test_cache_scan_result_success(
        self,
        cache_coordinator,
        sample_enhanced_result,
        scan_parameters,
        mock_cache_manager,
    ):
        """Test successful cache_scan_result."""
        await cache_coordinator.cache_scan_result(
            file_path=Path("test.py"),
            result=sample_enhanced_result,
            content_hash="hash123",
            scan_parameters=scan_parameters,
            cache_expiry_seconds=3600,
        )

        mock_cache_manager.put.assert_called_once()
        call_args = mock_cache_manager.put.call_args
        assert call_args[0][2] == 3600  # cache_expiry_seconds
        assert sample_enhanced_result.scan_metadata["cache_hit"] is False
        assert "cache_key" in sample_enhanced_result.scan_metadata

    @pytest.mark.asyncio
    async def test_cache_scan_result_exception(
        self,
        cache_coordinator,
        sample_enhanced_result,
        scan_parameters,
        mock_cache_manager,
    ):
        """Test cache_scan_result when exception occurs."""
        mock_cache_manager.put.side_effect = Exception("Cache error")

        # Should not raise exception
        await cache_coordinator.cache_scan_result(
            file_path=Path("test.py"),
            result=sample_enhanced_result,
            content_hash="hash123",
            scan_parameters=scan_parameters,
        )

    def test_create_content_hash_no_cache_manager(self):
        """Test create_content_hash without cache manager."""
        coordinator = CacheCoordinator(cache_manager=None)
        result = coordinator.create_content_hash("test content")
        assert result == ""

    def test_create_content_hash_success(self, cache_coordinator, mock_cache_manager):
        """Test successful create_content_hash."""
        result = cache_coordinator.create_content_hash("test content")

        assert result == "content_hash_123"
        mock_cache_manager.get_hasher().hash_content.assert_called_once_with(
            "test content"
        )

    def test_create_content_hash_exception(self, cache_coordinator, mock_cache_manager):
        """Test create_content_hash when exception occurs."""
        mock_cache_manager.get_hasher().hash_content.side_effect = Exception(
            "Hash error"
        )

        result = cache_coordinator.create_content_hash("test content")
        assert result == ""

    def test_create_cache_key_for_code_no_cache_manager(self):
        """Test create_cache_key_for_code without cache manager."""
        coordinator = CacheCoordinator(cache_manager=None)
        result = coordinator.create_cache_key_for_code("code", {})
        assert result is None

    def test_create_cache_key_for_code_success(
        self, cache_coordinator, scan_parameters, mock_cache_manager
    ):
        """Test successful create_cache_key_for_code."""
        result = cache_coordinator.create_cache_key_for_code(
            "test code", scan_parameters
        )

        assert result is not None
        assert isinstance(result, CacheKey)
        assert result.cache_type == CacheType.FILE_ANALYSIS
        assert result.metadata_hash == "python"
        assert "code:content_hash_123:metadata_hash_456" in result.content_hash

    def test_create_cache_key_for_code_exception(
        self, cache_coordinator, mock_cache_manager
    ):
        """Test create_cache_key_for_code when exception occurs."""
        mock_cache_manager.get_hasher.side_effect = Exception("Hasher error")

        result = cache_coordinator.create_cache_key_for_code("code", {})
        assert result is None

    def test_get_cached_code_result_no_cache_manager(self):
        """Test get_cached_code_result without cache manager."""
        coordinator = CacheCoordinator(cache_manager=None)
        cache_key = CacheKey(CacheType.FILE_ANALYSIS, "test", "python")

        result = coordinator.get_cached_code_result(cache_key)
        assert result is None

    def test_get_cached_code_result_no_cache_key(self, cache_coordinator):
        """Test get_cached_code_result without cache key."""
        result = cache_coordinator.get_cached_code_result(None)
        assert result is None

    def test_get_cached_code_result_cache_miss(
        self, cache_coordinator, mock_cache_manager
    ):
        """Test get_cached_code_result with cache miss."""
        cache_key = CacheKey(CacheType.FILE_ANALYSIS, "test", "python")
        mock_cache_manager.get.return_value = None

        result = cache_coordinator.get_cached_code_result(cache_key)
        assert result is None

    def test_get_cached_code_result_cache_hit(
        self, cache_coordinator, mock_cache_manager
    ):
        """Test get_cached_code_result with cache hit."""
        cache_key = CacheKey(CacheType.FILE_ANALYSIS, "test", "python")
        cached_data = {
            "file_path": "test.py",
            "llm_threats": [],
            "semgrep_threats": [],
            "scan_metadata": {},
            "validation_results": {},
            "llm_usage_stats": {},
        }
        mock_cache_manager.get.return_value = cached_data

        result = cache_coordinator.get_cached_code_result(cache_key)

        assert result is not None
        assert result.scan_metadata["cache_hit"] is True
        assert "cache_key" in result.scan_metadata

    def test_get_cached_code_result_exception(
        self, cache_coordinator, mock_cache_manager
    ):
        """Test get_cached_code_result when exception occurs."""
        cache_key = CacheKey(CacheType.FILE_ANALYSIS, "test", "python")
        mock_cache_manager.get.side_effect = Exception("Cache error")

        result = cache_coordinator.get_cached_code_result(cache_key)
        assert result is None

    def test_cache_code_result_no_cache_manager(self, sample_enhanced_result):
        """Test cache_code_result without cache manager."""
        coordinator = CacheCoordinator(cache_manager=None)
        cache_key = CacheKey(CacheType.FILE_ANALYSIS, "test", "python")

        # Should not raise exception
        coordinator.cache_code_result(cache_key, sample_enhanced_result)

    def test_cache_code_result_no_cache_key(
        self, cache_coordinator, sample_enhanced_result
    ):
        """Test cache_code_result without cache key."""
        # Should not raise exception
        cache_coordinator.cache_code_result(None, sample_enhanced_result)

    def test_cache_code_result_success(
        self, cache_coordinator, sample_enhanced_result, mock_cache_manager
    ):
        """Test successful cache_code_result."""
        cache_key = CacheKey(CacheType.FILE_ANALYSIS, "test", "python")

        cache_coordinator.cache_code_result(cache_key, sample_enhanced_result, 7200)

        mock_cache_manager.put.assert_called_once()
        call_args = mock_cache_manager.put.call_args
        assert call_args[0][0] == cache_key
        assert call_args[0][2] == 7200  # cache_expiry_seconds
        assert sample_enhanced_result.scan_metadata["cache_hit"] is False
        assert "cache_key" in sample_enhanced_result.scan_metadata

    def test_cache_code_result_exception(
        self, cache_coordinator, sample_enhanced_result, mock_cache_manager
    ):
        """Test cache_code_result when exception occurs."""
        cache_key = CacheKey(CacheType.FILE_ANALYSIS, "test", "python")
        mock_cache_manager.put.side_effect = Exception("Cache error")

        # Should not raise exception
        cache_coordinator.cache_code_result(cache_key, sample_enhanced_result)

    def test_serialize_scan_result(self, cache_coordinator, sample_enhanced_result):
        """Test _serialize_scan_result."""
        # Add stats to test serialization
        sample_enhanced_result.stats = {"test": "stats"}

        serialized = cache_coordinator._serialize_scan_result(sample_enhanced_result)

        assert isinstance(serialized, dict)
        assert serialized["file_path"] == "test.py"
        assert "llm_threats" in serialized
        assert "semgrep_threats" in serialized
        assert serialized["scan_metadata"] == {"test": "metadata"}
        assert serialized["validation_results"] == {"test": "validation"}
        assert serialized["llm_usage_stats"] == {"test": "stats"}
        assert serialized["stats"] == {"test": "stats"}

    def test_deserialize_scan_result(self, cache_coordinator):
        """Test _deserialize_scan_result."""
        cached_data = {
            "file_path": "test.py",
            "llm_threats": [],
            "semgrep_threats": [],
            "scan_metadata": {"test": "metadata"},
            "validation_results": {"test": "validation"},
            "llm_usage_stats": {"test": "stats"},
            "stats": {"test": "stats"},
        }

        result = cache_coordinator._deserialize_scan_result(cached_data)

        assert isinstance(result, EnhancedScanResult)
        assert result.file_path == "test.py"
        assert result.scan_metadata == {"test": "metadata"}
        assert result.validation_results == {"test": "validation"}
        assert result.llm_usage_stats == {"test": "stats"}
        assert result.stats == {"test": "stats"}

    def test_deserialize_scan_result_missing_stats(self, cache_coordinator):
        """Test _deserialize_scan_result without stats."""
        cached_data = {
            "file_path": "test.py",
            "llm_threats": [],
            "semgrep_threats": [],
            "scan_metadata": {},
            "validation_results": {},
            "llm_usage_stats": {},
        }

        result = cache_coordinator._deserialize_scan_result(cached_data)

        assert isinstance(result, EnhancedScanResult)
        # stats attribute might be set to default value by EnhancedScanResult


class TestCacheCoordinatorEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_get_cached_scan_result_invalid_cached_data(
        self, cache_coordinator, mock_cache_manager
    ):
        """Test get_cached_scan_result with invalid cached data type."""
        mock_cache_manager.get.return_value = "invalid_data_type"

        result = await cache_coordinator.get_cached_scan_result(
            file_path=Path("test.py"),
            content_hash="hash123",
            scan_parameters={},
        )

        assert result is None

    def test_get_cached_code_result_invalid_cached_data(
        self, cache_coordinator, mock_cache_manager
    ):
        """Test get_cached_code_result with invalid cached data type."""
        cache_key = CacheKey(CacheType.FILE_ANALYSIS, "test", "python")
        mock_cache_manager.get.return_value = "invalid_data_type"

        result = cache_coordinator.get_cached_code_result(cache_key)
        assert result is None

    def test_serialize_scan_result_no_stats(
        self, cache_coordinator, sample_enhanced_result
    ):
        """Test _serialize_scan_result without stats attribute."""
        # Ensure no stats attribute exists
        if hasattr(sample_enhanced_result, "stats"):
            delattr(sample_enhanced_result, "stats")

        serialized = cache_coordinator._serialize_scan_result(sample_enhanced_result)

        assert serialized["stats"] is None

    @pytest.mark.asyncio
    async def test_cache_operations_with_none_parameters(
        self, cache_coordinator, scan_parameters
    ):
        """Test cache operations with None parameters."""
        # Test with None severity_threshold
        scan_params_with_none = scan_parameters.copy()
        scan_params_with_none["severity_threshold"] = None

        result = await cache_coordinator.get_cached_scan_result(
            file_path=Path("test.py"),
            content_hash="hash123",
            scan_parameters=scan_params_with_none,
        )

        assert result is None  # Cache miss is expected
