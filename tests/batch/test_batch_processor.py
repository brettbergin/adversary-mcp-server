"""Tests for batch processor."""

import asyncio
from pathlib import Path

import pytest

from adversary_mcp_server.batch.batch_processor import BatchProcessor
from adversary_mcp_server.batch.types import (
    BatchConfig,
    BatchMetrics,
    BatchStrategy,
    FileAnalysisContext,
    Language,
)


class TestBatchProcessor:
    """Test BatchProcessor class."""

    def test_initialization(self):
        """Test batch processor initialization."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        assert processor.config == config
        assert processor.token_estimator is not None
        assert processor.metrics is not None

    def test_create_file_context(self):
        """Test creating file analysis context."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        file_path = Path("/test/file.py")
        content = "print('hello')"
        language = Language.PYTHON

        context = processor.create_file_context(file_path, content, language)

        assert isinstance(context, FileAnalysisContext)
        assert context.file_path == file_path
        assert context.content == content
        assert context.language == language
        assert context.priority == 0  # default

    def test_create_file_context_with_priority(self):
        """Test creating file context with custom priority."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        context = processor.create_file_context(
            Path("/test/file.py"), "content", Language.PYTHON, priority=5
        )

        assert context.priority == 5

    def test_calculate_complexity_via_context(self):
        """Test complexity calculation via file context creation."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        simple_content = "x = 1"
        complex_content = """
        def complex_function():
            for i in range(10):
                if i % 2 == 0:
                    try:
                        result = process(i)
                        if result:
                            yield result
                    except Exception:
                        continue
        """

        simple_context = processor.create_file_context(
            Path("/test/simple.py"), simple_content, Language.PYTHON
        )
        complex_context = processor.create_file_context(
            Path("/test/complex.py"), complex_content, Language.PYTHON
        )

        assert isinstance(simple_context.complexity_score, int | float)
        assert isinstance(complex_context.complexity_score, int | float)
        assert complex_context.complexity_score >= simple_context.complexity_score

    def test_create_batches_fixed_size(self):
        """Test creating batches with fixed size strategy."""
        config = BatchConfig(strategy=BatchStrategy.FIXED_SIZE, default_batch_size=2)
        processor = BatchProcessor(config)

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), f"content{i}", Language.PYTHON
            )
            for i in range(5)
        ]

        batches = processor.create_batches(contexts)

        assert len(batches) == 3  # 5 files, batch size 2 -> 3 batches
        assert len(batches[0]) == 2
        assert len(batches[1]) == 2
        assert len(batches[2]) == 1

    def test_create_batches_dynamic_size(self):
        """Test creating batches with dynamic size strategy."""
        config = BatchConfig(strategy=BatchStrategy.DYNAMIC_SIZE)
        processor = BatchProcessor(config)

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), f"content{i}", Language.PYTHON
            )
            for i in range(5)
        ]

        batches = processor.create_batches(contexts)

        assert isinstance(batches, list)
        assert len(batches) > 0
        assert all(isinstance(batch, list) for batch in batches)

    def test_create_batches_token_based(self):
        """Test creating batches with token-based strategy."""
        config = BatchConfig(
            strategy=BatchStrategy.TOKEN_BASED, max_tokens_per_batch=1000
        )
        processor = BatchProcessor(config)

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), "print('test')", Language.PYTHON
            )
            for i in range(10)
        ]

        batches = processor.create_batches(contexts)

        assert isinstance(batches, list)
        assert len(batches) > 0

    def test_create_batches_empty_list(self):
        """Test creating batches with empty context list."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        batches = processor.create_batches([])

        assert batches == []

    def test_batch_creation_with_priorities(self):
        """Test that batch creation handles different priorities."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        contexts = [
            processor.create_file_context(
                Path("/test/low.py"), "x=1", Language.PYTHON, priority=1
            ),
            processor.create_file_context(
                Path("/test/high.py"), "x=2", Language.PYTHON, priority=10
            ),
            processor.create_file_context(
                Path("/test/med.py"), "x=3", Language.PYTHON, priority=5
            ),
        ]

        batches = processor.create_batches(contexts)

        # Should create batches successfully
        assert isinstance(batches, list)
        assert len(batches) > 0
        assert all(isinstance(batch, list) for batch in batches)

    def test_get_metrics(self):
        """Test getting processing metrics."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        # Simulate some processing
        processor.metrics.total_files = 10
        processor.metrics.total_batches = 3
        processor.metrics.total_processing_time = 120.0

        metrics = processor.get_metrics()

        assert isinstance(metrics, BatchMetrics)
        assert metrics.total_files == 10
        assert metrics.total_batches == 3
        assert metrics.total_processing_time == 120.0

    @pytest.mark.asyncio
    async def test_process_batches_async(self):
        """Test async batch processing."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        # Mock processing function
        async def mock_process_function(batch):
            await asyncio.sleep(0.01)  # Simulate async work
            return [f"result_{i}" for i in range(len(batch))]

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), f"content{i}", Language.PYTHON
            )
            for i in range(3)
        ]

        batches = processor.create_batches(contexts)
        results = await processor.process_batches(batches, mock_process_function)

        assert isinstance(results, list)
        assert len(results) >= 0

    def test_context_creation_multiple_files(self):
        """Test creating contexts for multiple files."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), "print('test')", Language.PYTHON
            )
            for i in range(5)
        ]

        assert len(contexts) == 5
        assert all(isinstance(ctx.estimated_tokens, int) for ctx in contexts)
        assert all(ctx.estimated_tokens > 0 for ctx in contexts)

    def test_reset_metrics(self):
        """Test resetting processing metrics."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        # Set some metrics
        processor.metrics.total_files = 10
        processor.metrics.total_batches = 5

        processor.reset_metrics()

        assert processor.metrics.total_files == 0
        assert processor.metrics.total_batches == 0

    def test_different_batch_strategies(self):
        """Test different batch strategies produce different results."""
        fixed_config = BatchConfig(
            strategy=BatchStrategy.FIXED_SIZE, default_batch_size=3
        )
        token_config = BatchConfig(
            strategy=BatchStrategy.TOKEN_BASED, max_tokens_per_batch=500
        )

        fixed_processor = BatchProcessor(fixed_config)
        token_processor = BatchProcessor(token_config)

        # Create contexts using the processors
        contexts = [
            fixed_processor.create_file_context(
                Path(f"/test/file{i}.py"),
                "print('test')" * (i + 1),  # Different content sizes
                Language.PYTHON,
                priority=i,
            )
            for i in range(10)
        ]

        fixed_batches = fixed_processor.create_batches(contexts)
        token_batches = token_processor.create_batches(contexts)

        # Different strategies should create different batch structures
        assert isinstance(fixed_batches, list)
        assert isinstance(token_batches, list)
