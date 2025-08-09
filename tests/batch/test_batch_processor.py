"""Tests for batch processor."""

import asyncio
from pathlib import Path

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

    def test_complexity_calculation_empty_content(self):
        """Test complexity calculation with empty content (line 103)."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        # Test completely empty content
        empty_context = processor.create_file_context(
            Path("/test/empty.py"), "", Language.PYTHON
        )
        assert empty_context.complexity_score == 0.0

        # Test whitespace-only content
        whitespace_context = processor.create_file_context(
            Path("/test/whitespace.py"), "   \n\t  \n", Language.PYTHON
        )
        assert whitespace_context.complexity_score == 0.0

    def test_complexity_calculation_empty_lines_only(self):
        """Test complexity calculation with only empty lines (line 110)."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        # Content with only empty lines (no stripped content)
        empty_lines_content = "\n\n\n\n"
        context = processor.create_file_context(
            Path("/test/empty_lines.py"), empty_lines_content, Language.PYTHON
        )
        assert context.complexity_score == 0.0

    def test_complexity_calculation_python_nesting(self):
        """Test Python nesting depth calculation (line 132)."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        # Test Python indentation-based nesting
        python_nested_content = """
def outer():
    if True:
        for i in range(10):
            if i > 5:
                try:
                    result = process()
                    return result
                except:
                    pass
"""
        context = processor.create_file_context(
            Path("/test/nested.py"), python_nested_content, Language.PYTHON
        )
        # Should calculate complexity based on indentation depth
        assert context.complexity_score > 0.0

    def test_complexity_calculation_brace_languages(self):
        """Test complexity calculation for brace-based languages."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        # Test JavaScript with braces
        js_content = """
function test() {
    if (condition) {
        for (let i = 0; i < 10; i++) {
            if (i % 2) {
                doSomething();
            }
        }
    }
}
"""
        context = processor.create_file_context(
            Path("/test/nested.js"), js_content, Language.JAVASCRIPT
        )
        assert context.complexity_score > 0.0

    def test_unknown_batch_strategy_fallback(self):
        """Test fallback to dynamic_size for unknown strategy (lines 239-245)."""
        config = BatchConfig(strategy="UNKNOWN_STRATEGY")
        processor = BatchProcessor(config)

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), f"content{i}", Language.PYTHON
            )
            for i in range(3)
        ]

        # Should not crash and fall back to dynamic sizing
        batches = processor.create_batches(contexts)
        assert isinstance(batches, list)
        assert len(batches) > 0

    def test_batch_creation_with_metrics_collector(self):
        """Test batch creation with metrics collector integration (lines 257-298)."""
        from unittest.mock import Mock

        # Mock metrics collector
        mock_metrics_collector = Mock()
        config = BatchConfig()
        processor = BatchProcessor(config, metrics_collector=mock_metrics_collector)

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), f"content{i} " * 100, Language.PYTHON
            )
            for i in range(5)
        ]

        batches = processor.create_batches(contexts)

        # Verify metrics collector was called
        assert mock_metrics_collector.record_histogram.called
        assert mock_metrics_collector.record_metric.called

        # Check specific metrics were recorded
        histogram_calls = mock_metrics_collector.record_histogram.call_args_list
        metric_calls = mock_metrics_collector.record_metric.call_args_list

        # Should have recorded batch creation duration
        histogram_call_names = [call[0][0] for call in histogram_calls]
        assert "batch_creation_duration_seconds" in histogram_call_names

        # Should have recorded batch counts
        metric_call_names = [call[0][0] for call in metric_calls]
        assert "batch_processor_batches_created_total" in metric_call_names
        assert "batch_processor_files_batched_total" in metric_call_names

    def test_complexity_based_batches_empty_groups(self):
        """Test complexity-based batching with empty groups (lines 466-493)."""
        config = BatchConfig(strategy=BatchStrategy.COMPLEXITY_BASED)
        processor = BatchProcessor(config)

        # Create contexts with varying complexity
        contexts = [
            processor.create_file_context(
                Path("/test/simple.py"), "x = 1", Language.PYTHON
            ),
            processor.create_file_context(
                Path("/test/complex.py"),
                """
def complex():
    for i in range(100):
        if i > 50:
            try:
                result = process(i)
                if result:
                    return result
            except:
                continue
""",
                Language.PYTHON,
            ),
        ]

        batches = processor.create_batches(contexts)

        # Should create batches based on complexity groupings
        assert isinstance(batches, list)
        assert len(batches) > 0

    def test_complexity_based_batch_size_adjustment(self):
        """Test complexity-based batch size adjustment (lines 479-486)."""
        config = BatchConfig(strategy=BatchStrategy.COMPLEXITY_BASED, max_batch_size=8)
        processor = BatchProcessor(config)

        # Create a very complex context that should get smaller batch size
        very_complex_content = """
def very_complex_function():
    for i in range(100):
        for j in range(100):
            if i > j:
                try:
                    if condition1:
                        if condition2:
                            if condition3:
                                result = deep_process(i, j)
                                if result:
                                    return result
                except Exception as e:
                    if e.type == 'critical':
                        raise
                    else:
                        continue
"""

        contexts = [
            processor.create_file_context(
                Path(f"/test/very_complex_{i}.py"),
                very_complex_content,
                Language.PYTHON,
            )
            for i in range(10)
        ]

        batches = processor.create_batches(contexts)

        # Very complex files should result in smaller batches
        assert isinstance(batches, list)
        if batches:
            # At least some batches should be smaller than max_batch_size
            batch_sizes = [len(batch) for batch in batches]
            assert any(size <= config.max_batch_size // 2 for size in batch_sizes)

    async def test_process_batches_empty_list(self):
        """Test processing empty batch list (line 512)."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        async def dummy_process_func(batch):
            return f"processed_{len(batch)}"

        results = await processor.process_batches([], dummy_process_func)
        assert results == []

    async def test_process_batches_with_progress_callback(self):
        """Test batch processing with progress callback (line 635)."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), f"content{i}", Language.PYTHON
            )
            for i in range(3)
        ]
        batches = processor.create_batches(contexts)

        # Track progress callbacks
        progress_updates = []

        def progress_callback(completed, total):
            progress_updates.append((completed, total))

        async def dummy_process_func(batch):
            return f"processed_{len(batch)}"

        results = await processor.process_batches(
            batches, dummy_process_func, progress_callback
        )

        assert isinstance(results, list)
        assert len(results) == len(batches)

        # Should have called progress callback
        assert len(progress_updates) > 0
        # Last update should show all batches completed
        assert progress_updates[-1][0] == len(batches)
        assert progress_updates[-1][1] == len(batches)

    async def test_batch_deduplication_and_caching(self):
        """Test batch deduplication and result caching (lines 584-617, 622-630)."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        # Create identical contexts (should be deduplicated)
        contexts1 = [
            processor.create_file_context(
                Path("/test/file1.py"), "identical_content", Language.PYTHON
            ),
            processor.create_file_context(
                Path("/test/file2.py"), "identical_content", Language.PYTHON
            ),
        ]
        contexts2 = [
            processor.create_file_context(
                Path("/test/file1.py"), "identical_content", Language.PYTHON
            ),
            processor.create_file_context(
                Path("/test/file2.py"), "identical_content", Language.PYTHON
            ),
        ]

        batch1 = processor.create_batches(contexts1)[0]
        batch2 = processor.create_batches(contexts2)[0]

        call_count = 0

        async def counting_process_func(batch):
            nonlocal call_count
            call_count += 1
            return f"result_{call_count}"

        # Process first batch
        result1 = await processor.process_batches([batch1], counting_process_func)
        assert call_count == 1

        # Process identical batch (should use cache)
        result2 = await processor.process_batches([batch2], counting_process_func)
        # Should not increment call count due to caching
        assert call_count == 1
        assert result1 == result2

    async def test_batch_processing_metrics_collection(self):
        """Test batch processing with metrics collection (lines 584-619)."""
        from unittest.mock import Mock

        mock_metrics_collector = Mock()
        config = BatchConfig()
        processor = BatchProcessor(config, metrics_collector=mock_metrics_collector)

        contexts = [
            processor.create_file_context(
                Path(f"/test/file{i}.py"), f"content{i} " * 50, Language.PYTHON
            )
            for i in range(3)
        ]
        batches = processor.create_batches(contexts)

        async def dummy_process_func(batch):
            await asyncio.sleep(0.01)  # Simulate processing time
            return f"processed_{len(batch)}"

        await processor.process_batches(batches, dummy_process_func)

        # Should have recorded individual batch metrics
        assert mock_metrics_collector.record_histogram.called
        assert mock_metrics_collector.record_metric.called

        histogram_calls = mock_metrics_collector.record_histogram.call_args_list
        metric_calls = mock_metrics_collector.record_metric.call_args_list

        histogram_names = [call[0][0] for call in histogram_calls]
        metric_names = [call[0][0] for call in metric_calls]

        # Should record individual batch processing metrics
        assert "batch_individual_processing_duration_seconds" in histogram_names
        assert "batch_individual_complexity_score" in histogram_names
        assert "batch_processing_files_per_second" in histogram_names
        assert "batch_processing_tokens_per_second" in histogram_names

        assert "batch_individual_files_processed_total" in metric_names
        assert "batch_individual_tokens_processed_total" in metric_names
        assert "batch_individual_bytes_processed_total" in metric_names

    async def test_batch_cache_size_limit(self):
        """Test batch cache size limiting (lines 626-630)."""
        config = BatchConfig()
        processor = BatchProcessor(config)

        async def dummy_process_func(batch):
            return f"result_{hash(str(batch))}"

        # Fill cache beyond limit to trigger cleanup during processing
        test_cache = {}
        for i in range(1200):
            test_cache[f"key_{i}"] = f"value_{i}"

        processor.batch_results_cache = test_cache

        # Verify cache is over limit initially
        initial_cache_size = len(processor.batch_results_cache)
        assert initial_cache_size > 1000

        # Process a batch to trigger cleanup (line 626 check)
        contexts = [
            processor.create_file_context(
                Path("/test/trigger.py"), "trigger_content", Language.PYTHON
            )
        ]
        batches = processor.create_batches(contexts)
        await processor.process_batches(batches, dummy_process_func)

        # Cache should be reduced by cleanup (removes 100 oldest entries, adds 1 new)
        # So 1200 - 100 + 1 = 1101 is expected behavior
        final_cache_size = len(processor.batch_results_cache)
        assert final_cache_size < initial_cache_size  # Should be reduced
        assert (
            final_cache_size == initial_cache_size - 100 + 1
        )  # Verify exact cleanup logic

    def test_token_based_batch_creation_with_buffer(self):
        """Test token-based batch creation with buffer (lines 418-419)."""
        config = BatchConfig(
            strategy=BatchStrategy.TOKEN_BASED,
            target_tokens_per_batch=1000,  # Use target_tokens_per_batch, not max_tokens_per_batch
            token_buffer_percentage=0.1,  # 10% buffer
        )
        processor = BatchProcessor(config)

        # Create contexts with known token counts
        large_content = (
            "print('this is a test') " * 10
        )  # Smaller content to fit in batches
        contexts = [
            processor.create_file_context(
                Path(f"/test/large_{i}.py"), large_content, Language.PYTHON
            )
            for i in range(5)
        ]

        batches = processor.create_batches(contexts)

        # Should create batches respecting token limits with buffer
        assert isinstance(batches, list)
        assert len(batches) > 0

        # Calculate effective limit with buffer and prompt overhead
        token_buffer = int(
            config.target_tokens_per_batch * config.token_buffer_percentage
        )
        effective_limit = config.target_tokens_per_batch - token_buffer

        # Verify batches respect the effective token limit (including prompt overhead)
        for batch in batches:
            # Calculate total tokens including estimated prompt overhead (500 tokens per context)
            total_batch_tokens = sum(ctx.estimated_tokens + 500 for ctx in batch)
            assert total_batch_tokens <= effective_limit
