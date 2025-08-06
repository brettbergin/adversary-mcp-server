"""Tests for batch processing types."""

from pathlib import Path

from adversary_mcp_server.batch.types import (
    BatchConfig,
    BatchMetrics,
    BatchStrategy,
    FileAnalysisContext,
    Language,
)


class TestBatchStrategy:
    """Test BatchStrategy enum."""

    def test_batch_strategy_values(self):
        """Test batch strategy enum values."""
        assert BatchStrategy.FIXED_SIZE == "fixed_size"
        assert BatchStrategy.DYNAMIC_SIZE == "dynamic_size"
        assert BatchStrategy.TOKEN_BASED == "token_based"
        assert BatchStrategy.COMPLEXITY_BASED == "complexity_based"


class TestLanguage:
    """Test Language enum."""

    def test_language_values(self):
        """Test language enum values."""
        assert Language.PYTHON == "python"
        assert Language.JAVASCRIPT == "javascript"
        assert Language.JAVA == "java"
        assert Language.GENERIC == "generic"

    def test_all_languages_present(self):
        """Test that all expected languages are present."""
        expected_languages = [
            "python",
            "javascript",
            "typescript",
            "java",
            "csharp",
            "cpp",
            "c",
            "go",
            "rust",
            "php",
            "ruby",
            "kotlin",
            "swift",
            "generic",
        ]

        actual_languages = [lang.value for lang in Language]

        for expected in expected_languages:
            assert expected in actual_languages


class TestBatchConfig:
    """Test BatchConfig dataclass."""

    def test_batch_config_defaults(self):
        """Test default batch configuration."""
        config = BatchConfig()

        assert config.strategy == BatchStrategy.DYNAMIC_SIZE
        assert config.min_batch_size == 1
        assert config.max_batch_size == 20
        assert config.default_batch_size == 10
        assert config.max_tokens_per_batch == 100000
        assert config.target_tokens_per_batch == 80000

    def test_batch_config_custom(self):
        """Test custom batch configuration."""
        config = BatchConfig(
            strategy=BatchStrategy.FIXED_SIZE,
            min_batch_size=5,
            max_batch_size=50,
            default_batch_size=25,
            max_tokens_per_batch=200000,
        )

        assert config.strategy == BatchStrategy.FIXED_SIZE
        assert config.min_batch_size == 5
        assert config.max_batch_size == 50
        assert config.default_batch_size == 25
        assert config.max_tokens_per_batch == 200000

    def test_batch_config_validation(self):
        """Test batch configuration validation."""
        # Valid configuration
        config = BatchConfig(min_batch_size=5, max_batch_size=10, default_batch_size=7)
        assert (
            config.min_batch_size <= config.default_batch_size <= config.max_batch_size
        )


class TestFileAnalysisContext:
    """Test FileAnalysisContext dataclass."""

    def test_file_analysis_context_creation(self):
        """Test creating file analysis context."""
        file_path = Path("/test/example.py")
        content = "print('hello world')"
        language = Language.PYTHON

        context = FileAnalysisContext(
            file_path=file_path,
            content=content,
            language=language,
            file_size_bytes=len(content),
            estimated_tokens=50,
            complexity_score=2.5,
            priority=1,
        )

        assert context.file_path == file_path
        assert context.content == content
        assert context.language == language
        assert context.file_size_bytes == len(content)
        assert context.priority == 1
        assert context.estimated_tokens == 50
        assert context.complexity_score == 2.5

    def test_file_analysis_context_defaults(self):
        """Test file analysis context with default values."""
        context = FileAnalysisContext(
            file_path=Path("/test/example.py"),
            content="test",
            language=Language.PYTHON,
            file_size_bytes=4,
            estimated_tokens=10,
            complexity_score=1.0,
        )

        assert context.priority == 0  # default value
        assert isinstance(context.metadata, dict)

    def test_file_analysis_context_comparison(self):
        """Test comparing file analysis contexts."""
        context1 = FileAnalysisContext(
            file_path=Path("/test/file1.py"),
            content="content1",
            language=Language.PYTHON,
            file_size_bytes=8,
            estimated_tokens=20,
            complexity_score=1.0,
            priority=5,
        )

        context2 = FileAnalysisContext(
            file_path=Path("/test/file2.py"),
            content="content2",
            language=Language.PYTHON,
            file_size_bytes=8,
            estimated_tokens=20,
            complexity_score=1.0,
            priority=10,
        )

        # Higher priority should be "greater"
        assert context2.priority > context1.priority

    def test_file_analysis_context_str_representation(self):
        """Test string representation of context."""
        context = FileAnalysisContext(
            file_path=Path("/test/example.py"),
            content="test content",
            language=Language.PYTHON,
            file_size_bytes=12,
            estimated_tokens=25,
            complexity_score=1.5,
        )

        str_repr = str(context)
        assert isinstance(str_repr, str)

    def test_complexity_level(self):
        """Test complexity level property."""
        context_low = FileAnalysisContext(
            file_path=Path("/test/low.py"),
            content="x = 1",
            language=Language.PYTHON,
            file_size_bytes=5,
            estimated_tokens=10,
            complexity_score=0.2,
        )

        context_high = FileAnalysisContext(
            file_path=Path("/test/high.py"),
            content="complex code",
            language=Language.PYTHON,
            file_size_bytes=12,
            estimated_tokens=30,
            complexity_score=0.9,
        )

        assert context_low.complexity_level == "low"
        assert context_high.complexity_level == "very_high"


class TestBatchMetrics:
    """Test BatchMetrics dataclass."""

    def test_batch_metrics_defaults(self):
        """Test default batch metrics."""
        metrics = BatchMetrics()

        assert metrics.total_files == 0
        assert metrics.total_batches == 0
        assert metrics.files_processed == 0
        assert metrics.files_failed == 0
        assert metrics.total_processing_time == 0.0
        assert metrics.average_batch_size == 0.0

    def test_batch_metrics_calculations(self):
        """Test batch metrics calculations."""
        metrics = BatchMetrics(
            total_files=100,
            total_batches=10,
            files_processed=95,
            files_failed=5,
            total_processing_time=300.0,
        )

        # Test that we can calculate derived metrics
        if metrics.total_batches > 0:
            avg_batch_size = metrics.files_processed / metrics.total_batches
            assert avg_batch_size == 9.5

    def test_batch_metrics_update(self):
        """Test updating batch metrics."""
        metrics = BatchMetrics()

        # Update metrics
        metrics.total_files = 50
        metrics.total_batches = 5
        metrics.total_processing_time = 120.0

        assert metrics.total_files == 50
        assert metrics.total_batches == 5
        assert metrics.total_processing_time == 120.0

    def test_batch_metrics_to_dict(self):
        """Test converting metrics to dictionary."""
        metrics = BatchMetrics(
            total_files=100,
            total_batches=10,
            files_processed=95,
            total_processing_time=300.0,
        )

        metrics_dict = metrics.to_dict()

        assert isinstance(metrics_dict, dict)
        assert "total_files" in metrics_dict
        assert "total_batches" in metrics_dict
        assert "files_processed" in metrics_dict
        assert metrics_dict["total_files"] == 100

    def test_batch_metrics_mark_completed(self):
        """Test marking batch processing as completed."""
        metrics = BatchMetrics(
            total_batches=5, total_processing_time=100.0, total_tokens_processed=1000
        )

        metrics.mark_completed()

        assert metrics.end_time is not None
        assert metrics.average_batch_time == 20.0  # 100/5

    def test_batch_metrics_properties(self):
        """Test batch metrics properties."""
        metrics = BatchMetrics(total_files=100, files_processed=95, files_failed=5)

        assert metrics.success_rate == 0.95
        assert isinstance(metrics.total_duration, float)
        assert isinstance(metrics.files_per_second, float)
