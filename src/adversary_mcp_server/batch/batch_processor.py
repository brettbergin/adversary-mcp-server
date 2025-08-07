"""Advanced batch processor with dynamic sizing and intelligent optimization."""

import asyncio
import hashlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..logger import get_logger
from .token_estimator import TokenEstimator
from .types import (
    BatchConfig,
    BatchMetrics,
    BatchStrategy,
    FileAnalysisContext,
    Language,
)

logger = get_logger("batch_processor")


class BatchProcessor:
    """Advanced batch processor for efficient LLM operations."""

    def __init__(self, config: BatchConfig, metrics_collector=None):
        """Initialize batch processor.

        Args:
            config: Batch processing configuration
            metrics_collector: Optional metrics collector for batch processing analytics
        """
        self.config = config
        self.token_estimator = TokenEstimator()
        self.metrics = BatchMetrics()
        self.metrics_collector = metrics_collector

        # Batch deduplication tracking
        self.processed_batch_hashes: set[str] = set()
        self.batch_results_cache: dict[str, Any] = {}

        logger.info(f"BatchProcessor initialized with strategy: {config.strategy}")

    def _calculate_batch_hash(self, batch: list[FileAnalysisContext]) -> str:
        """Calculate a unique hash for a batch based on file paths and content.

        Args:
            batch: List of file contexts in the batch

        Returns:
            SHA256 hash of the batch content
        """
        # Create a deterministic representation of the batch
        batch_data = []
        for ctx in sorted(batch, key=lambda x: str(x.file_path)):
            # Include file path and content hash for uniqueness
            content_hash = hashlib.sha256(ctx.content.encode("utf-8")).hexdigest()[:16]
            batch_data.append(f"{ctx.file_path}:{content_hash}:{ctx.language}")

        batch_string = "|".join(batch_data)
        return hashlib.sha256(batch_string.encode("utf-8")).hexdigest()

    def create_file_context(
        self, file_path: Path, content: str, language: Language, priority: int = 0
    ) -> FileAnalysisContext:
        """Create analysis context for a file.

        Args:
            file_path: Path to the file
            content: File content
            language: Programming language
            priority: Processing priority (higher = more important)

        Returns:
            File analysis context
        """
        # Calculate basic metrics
        file_size_bytes = len(content.encode("utf-8"))
        estimated_tokens = self.token_estimator.estimate_tokens(content, language)
        complexity_score = self._calculate_complexity_score(content, language)

        return FileAnalysisContext(
            file_path=file_path,
            content=content,
            language=language,
            file_size_bytes=file_size_bytes,
            estimated_tokens=estimated_tokens,
            complexity_score=complexity_score,
            priority=priority,
        )

    def _calculate_complexity_score(self, content: str, language: Language) -> float:
        """Calculate complexity score for content.

        Args:
            content: File content
            language: Programming language

        Returns:
            Complexity score from 0.0 to 1.0
        """
        if not content.strip():
            return 0.0

        lines = content.split("\n")
        total_lines = len(lines)
        non_empty_lines = len([line for line in lines if line.strip()])

        if non_empty_lines == 0:
            return 0.0

        # Basic complexity indicators
        complexity_indicators = []

        # Nesting depth (approximate)
        max_nesting = 0
        current_nesting = 0
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            # Count opening and closing braces/blocks
            if language in [
                Language.JAVASCRIPT,
                Language.TYPESCRIPT,
                Language.JAVA,
                Language.CSHARP,
                Language.CPP,
                Language.C,
            ]:
                current_nesting += line.count("{") - line.count("}")
            elif language == Language.PYTHON:
                # Rough Python indentation-based nesting
                indent_level = (len(line) - len(line.lstrip())) // 4
                current_nesting = max(0, indent_level)

            max_nesting = max(max_nesting, current_nesting)

        complexity_indicators.append(min(1.0, max_nesting / 10.0))

        # Function/method count
        function_patterns = {
            Language.PYTHON: [r"\bdef\s+\w+", r"\bclass\s+\w+"],
            Language.JAVASCRIPT: [r"\bfunction\s+\w+", r"\w+\s*:\s*function", r"=>"],
            Language.JAVA: [
                r"\b(public|private|protected)?\s*(static\s+)?\w+\s+\w+\s*\("
            ],
        }

        function_count = 0
        patterns = function_patterns.get(language, [])
        for pattern in patterns:
            import re

            matches = re.findall(pattern, content)
            function_count += len(matches)

        function_density = function_count / non_empty_lines
        complexity_indicators.append(min(1.0, function_density * 10))

        # Cyclomatic complexity indicators
        decision_keywords = {
            Language.PYTHON: [
                "if",
                "elif",
                "for",
                "while",
                "try",
                "except",
                "and",
                "or",
            ],
            Language.JAVASCRIPT: [
                "if",
                "else",
                "for",
                "while",
                "switch",
                "case",
                "&&",
                "||",
            ],
            Language.JAVA: ["if", "else", "for", "while", "switch", "case", "&&", "||"],
        }

        decision_count = 0
        keywords = decision_keywords.get(language, [])
        for keyword in keywords:
            decision_count += content.count(keyword)

        decision_density = decision_count / non_empty_lines
        complexity_indicators.append(min(1.0, decision_density * 2))

        # Line length and readability
        avg_line_length = sum(len(line) for line in lines) / total_lines
        length_complexity = min(1.0, avg_line_length / 100.0)
        complexity_indicators.append(length_complexity)

        # Calculate weighted average
        weights = [0.3, 0.25, 0.25, 0.2]  # Nesting, functions, decisions, length
        weighted_score = sum(
            score * weight
            for score, weight in zip(complexity_indicators, weights, strict=False)
        )

        return min(1.0, max(0.0, weighted_score))

    def create_batches(
        self, file_contexts: list[FileAnalysisContext], model: str | None = None
    ) -> list[list[FileAnalysisContext]]:
        """Create optimized batches from file contexts.

        Args:
            file_contexts: List of file contexts to batch
            model: LLM model name for token estimation

        Returns:
            List of batches (each batch is a list of file contexts)
        """
        if not file_contexts:
            return []

        batch_creation_start_time = time.time()
        logger.info(
            f"Creating batches for {len(file_contexts)} files using {self.config.strategy}"
        )

        # Sort files by priority and other factors
        sorted_contexts = self._sort_contexts(file_contexts)

        # Create batches based on strategy
        if self.config.strategy == BatchStrategy.FIXED_SIZE:
            batches = self._create_fixed_size_batches(sorted_contexts)
        elif self.config.strategy == BatchStrategy.DYNAMIC_SIZE:
            batches = self._create_dynamic_size_batches(sorted_contexts)
        elif self.config.strategy == BatchStrategy.TOKEN_BASED:
            batches = self._create_token_based_batches(sorted_contexts, model)
        elif self.config.strategy == BatchStrategy.COMPLEXITY_BASED:
            batches = self._create_complexity_based_batches(sorted_contexts)
        else:
            logger.warning(
                f"Unknown strategy {self.config.strategy}, using dynamic_size"
            )
            batches = self._create_dynamic_size_batches(sorted_contexts)

        # Update metrics
        self.metrics.total_files = len(file_contexts)
        self.metrics.total_batches = len(batches)
        if batches:
            batch_sizes = [len(batch) for batch in batches]
            self.metrics.min_batch_size = min(batch_sizes)
            self.metrics.max_batch_size = max(batch_sizes)

            # Record batch creation metrics
            if self.metrics_collector:
                batch_creation_duration = time.time() - batch_creation_start_time

                # Calculate resource usage metrics
                total_files = len(file_contexts)
                total_tokens = sum(ctx.estimated_tokens for ctx in file_contexts)
                total_bytes = sum(ctx.file_size_bytes for ctx in file_contexts)
                avg_complexity = (
                    sum(ctx.complexity_score for ctx in file_contexts) / total_files
                    if total_files > 0
                    else 0
                )

                # Record timing metrics
                self.metrics_collector.record_histogram(
                    "batch_creation_duration_seconds",
                    batch_creation_duration,
                    labels={"strategy": self.config.strategy.value},
                )

                # Record batch size distribution
                self.metrics_collector.record_metric(
                    "batch_processor_batches_created_total",
                    len(batches),
                    labels={"strategy": self.config.strategy.value},
                )
                self.metrics_collector.record_histogram(
                    "batch_size_files",
                    sum(batch_sizes) / len(batches) if batches else 0,
                    labels={"strategy": self.config.strategy.value},
                )

                # Record resource utilization
                self.metrics_collector.record_metric(
                    "batch_processor_files_batched_total", total_files
                )
                self.metrics_collector.record_metric(
                    "batch_processor_tokens_batched_total", total_tokens
                )
                self.metrics_collector.record_metric(
                    "batch_processor_bytes_batched_total", total_bytes
                )
                self.metrics_collector.record_histogram(
                    "batch_complexity_score", avg_complexity
                )

        logger.info(
            f"Created {len(batches)} batches with sizes: {[len(b) for b in batches]}"
        )
        return batches

    def _sort_contexts(
        self, contexts: list[FileAnalysisContext]
    ) -> list[FileAnalysisContext]:
        """Sort file contexts for optimal batching.

        Args:
            contexts: File contexts to sort

        Returns:
            Sorted file contexts
        """

        def sort_key(ctx: FileAnalysisContext) -> tuple:
            # Sort by: priority (desc), language, complexity, size
            return (
                -ctx.priority,  # Higher priority first
                ctx.language.value if self.config.group_by_language else "",
                ctx.complexity_score if self.config.group_by_complexity else 0,
                ctx.file_size_bytes if self.config.prefer_similar_file_sizes else 0,
            )

        return sorted(contexts, key=sort_key)

    def _create_fixed_size_batches(
        self, contexts: list[FileAnalysisContext]
    ) -> list[list[FileAnalysisContext]]:
        """Create fixed-size batches.

        Args:
            contexts: Sorted file contexts

        Returns:
            List of fixed-size batches
        """
        batch_size = self.config.default_batch_size
        batches = []

        for i in range(0, len(contexts), batch_size):
            batch = contexts[i : i + batch_size]
            batches.append(batch)

        return batches

    def _create_dynamic_size_batches(
        self, contexts: list[FileAnalysisContext]
    ) -> list[list[FileAnalysisContext]]:
        """Create dynamically sized batches based on file characteristics.

        Args:
            contexts: Sorted file contexts

        Returns:
            List of dynamically sized batches
        """
        batches = []
        current_batch = []
        current_batch_tokens = 0
        current_batch_complexity = 0.0

        for context in contexts:
            # Check if adding this file would exceed limits
            new_batch_size = len(current_batch) + 1
            new_batch_tokens = current_batch_tokens + context.estimated_tokens
            new_batch_complexity = (
                current_batch_complexity * float(len(current_batch))
                + context.complexity_score
            ) / new_batch_size

            # Decide whether to add to current batch or start new one
            should_create_new_batch = (
                new_batch_size > self.config.max_batch_size
                or new_batch_tokens > self.config.max_tokens_per_batch
                or (
                    new_batch_complexity > self.config.complexity_threshold_high
                    and len(current_batch) >= self.config.min_batch_size
                )
            )

            if should_create_new_batch and current_batch:
                batches.append(current_batch)
                current_batch = [context]
                current_batch_tokens = context.estimated_tokens
                current_batch_complexity = context.complexity_score
            else:
                current_batch.append(context)
                current_batch_tokens = new_batch_tokens
                current_batch_complexity = new_batch_complexity

        # Add final batch
        if current_batch:
            batches.append(current_batch)

        return batches

    def _create_token_based_batches(
        self, contexts: list[FileAnalysisContext], model: str | None
    ) -> list[list[FileAnalysisContext]]:
        """Create batches based on token limits.

        Args:
            contexts: Sorted file contexts
            model: LLM model name

        Returns:
            List of token-optimized batches
        """
        batches = []
        current_batch = []
        current_tokens = 0

        # Add buffer for prompt overhead
        token_buffer = int(
            self.config.target_tokens_per_batch * self.config.token_buffer_percentage
        )
        effective_limit = self.config.target_tokens_per_batch - token_buffer

        for context in contexts:
            # Estimate total tokens including prompt overhead
            estimated_prompt_tokens = 500  # Rough estimate for system/user prompt
            context_total_tokens = context.estimated_tokens + estimated_prompt_tokens

            # Check if adding this file would exceed token limit
            if (
                current_tokens + context_total_tokens > effective_limit
                and current_batch
                and len(current_batch) >= self.config.min_batch_size
            ):

                batches.append(current_batch)
                current_batch = [context]
                current_tokens = context_total_tokens
            else:
                current_batch.append(context)
                current_tokens += context_total_tokens

                # Also check max batch size
                if len(current_batch) >= self.config.max_batch_size:
                    batches.append(current_batch)
                    current_batch = []
                    current_tokens = 0

        # Add final batch
        if current_batch:
            batches.append(current_batch)

        return batches

    def _create_complexity_based_batches(
        self, contexts: list[FileAnalysisContext]
    ) -> list[list[FileAnalysisContext]]:
        """Create batches based on complexity levels.

        Args:
            contexts: Sorted file contexts

        Returns:
            List of complexity-grouped batches
        """
        # Group by complexity level
        complexity_groups = {"low": [], "medium": [], "high": [], "very_high": []}

        for context in contexts:
            complexity_groups[context.complexity_level].append(context)

        batches = []

        # Process each complexity group
        for complexity_level, group_contexts in complexity_groups.items():
            if not group_contexts:
                continue

            # Adjust batch size based on complexity
            if complexity_level == "very_high":
                max_batch_size = max(1, self.config.max_batch_size // 4)
            elif complexity_level == "high":
                max_batch_size = max(1, self.config.max_batch_size // 2)
            elif complexity_level == "medium":
                max_batch_size = self.config.max_batch_size
            else:  # low complexity
                max_batch_size = self.config.max_batch_size * 2

            # Create batches for this complexity level
            for i in range(0, len(group_contexts), max_batch_size):
                batch = group_contexts[i : i + max_batch_size]
                batches.append(batch)

        return batches

    async def process_batches(
        self,
        batches: list[list[FileAnalysisContext]],
        process_batch_func: Callable[[list[FileAnalysisContext]], Any],
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Any]:
        """Process batches with concurrency control and progress tracking.

        Args:
            batches: List of batches to process
            process_batch_func: Function to process each batch
            progress_callback: Optional callback for progress updates

        Returns:
            List of batch processing results
        """
        if not batches:
            return []

        # Check for duplicate batches and filter them out
        unique_batches = []
        cached_results = []
        skipped_batches = 0

        for i, batch in enumerate(batches):
            batch_hash = self._calculate_batch_hash(batch)

            if batch_hash in self.processed_batch_hashes:
                # Check if we have a cached result
                if batch_hash in self.batch_results_cache:
                    cached_results.append((i, self.batch_results_cache[batch_hash]))
                    skipped_batches += 1
                    logger.debug(
                        f"Skipping duplicate batch {i + 1}/{len(batches)} (cached result available)"
                    )
                else:
                    # Previously processed but no cached result - skip entirely
                    cached_results.append((i, None))
                    skipped_batches += 1
                    logger.debug(
                        f"Skipping duplicate batch {i + 1}/{len(batches)} (previously processed)"
                    )
            else:
                unique_batches.append((i, batch, batch_hash))

        logger.info(
            f"Processing {len(unique_batches)} unique batches ({skipped_batches} duplicates skipped) "
            f"with max concurrency: {self.config.max_concurrent_batches}"
        )

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent_batches)

        # Track progress
        completed_batches = 0
        results = []

        async def process_single_batch(
            batch_info: tuple[int, list[FileAnalysisContext], str],
        ) -> tuple[int, Any]:
            nonlocal completed_batches

            batch_idx, batch, batch_hash = batch_info

            async with semaphore:
                batch_start_time = time.time()

                try:
                    logger.debug(
                        f"Processing unique batch {batch_idx + 1}/{len(batches)} with {len(batch)} files"
                    )

                    # Add timeout to batch processing
                    result = await asyncio.wait_for(
                        process_batch_func(batch),
                        timeout=self.config.batch_timeout_seconds,
                    )

                    batch_time = time.time() - batch_start_time
                    self.metrics.total_processing_time += batch_time
                    self.metrics.files_processed += len(batch)

                    # Update token metrics
                    batch_tokens = sum(ctx.estimated_tokens for ctx in batch)
                    self.metrics.total_tokens_processed += batch_tokens

                    # Record individual batch metrics
                    if self.metrics_collector:
                        # Record batch processing timing
                        self.metrics_collector.record_histogram(
                            "batch_individual_processing_duration_seconds",
                            batch_time,
                            labels={"status": "success"},
                        )

                        # Record batch resource consumption
                        batch_bytes = sum(ctx.file_size_bytes for ctx in batch)
                        avg_complexity = sum(
                            ctx.complexity_score for ctx in batch
                        ) / len(batch)

                        self.metrics_collector.record_metric(
                            "batch_individual_files_processed_total", len(batch)
                        )
                        self.metrics_collector.record_metric(
                            "batch_individual_tokens_processed_total", batch_tokens
                        )
                        self.metrics_collector.record_metric(
                            "batch_individual_bytes_processed_total", batch_bytes
                        )
                        self.metrics_collector.record_histogram(
                            "batch_individual_complexity_score", avg_complexity
                        )

                        # Record batch efficiency metrics
                        if batch_time > 0:
                            files_per_second = len(batch) / batch_time
                            tokens_per_second = batch_tokens / batch_time

                            self.metrics_collector.record_histogram(
                                "batch_processing_files_per_second", files_per_second
                            )
                            self.metrics_collector.record_histogram(
                                "batch_processing_tokens_per_second", tokens_per_second
                            )

                    # Mark batch as processed and cache result
                    self.processed_batch_hashes.add(batch_hash)
                    if result is not None:  # Only cache successful results
                        self.batch_results_cache[batch_hash] = result
                        # Limit cache size to prevent memory issues
                        if len(self.batch_results_cache) > 1000:
                            # Remove oldest entries (simple FIFO cleanup)
                            oldest_keys = list(self.batch_results_cache.keys())[:100]
                            for key in oldest_keys:
                                del self.batch_results_cache[key]

                    completed_batches += 1

                    if progress_callback:
                        progress_callback(completed_batches, len(batches))

                    logger.debug(
                        f"Batch {batch_idx + 1} completed in {batch_time:.2f}s"
                    )
                    return (batch_idx, result)

                except TimeoutError:
                    batch_time = time.time() - batch_start_time
                    logger.error(
                        f"Batch {batch_idx + 1} timed out after {self.config.batch_timeout_seconds}s"
                    )
                    self.metrics.batch_failures += 1
                    self.metrics.files_failed += len(batch)

                    # Record timeout metrics
                    if self.metrics_collector:
                        self.metrics_collector.record_metric(
                            "batch_processing_timeouts_total", 1
                        )
                        self.metrics_collector.record_histogram(
                            "batch_individual_processing_duration_seconds",
                            batch_time,
                            labels={"status": "timeout"},
                        )
                        self.metrics_collector.record_metric(
                            "batch_processing_failed_files_total",
                            len(batch),
                            labels={"reason": "timeout"},
                        )

                    # Mark as processed but don't cache the failure
                    self.processed_batch_hashes.add(batch_hash)
                    return (batch_idx, None)

                except Exception as e:
                    batch_time = time.time() - batch_start_time
                    logger.error(f"Batch {batch_idx + 1} failed: {e}")
                    self.metrics.batch_failures += 1
                    self.metrics.files_failed += len(batch)

                    # Record error metrics
                    if self.metrics_collector:
                        self.metrics_collector.record_metric(
                            "batch_processing_errors_total",
                            1,
                            labels={"error_type": type(e).__name__},
                        )
                        self.metrics_collector.record_histogram(
                            "batch_individual_processing_duration_seconds",
                            batch_time,
                            labels={"status": "error"},
                        )
                        self.metrics_collector.record_metric(
                            "batch_processing_failed_files_total",
                            len(batch),
                            labels={"reason": "error"},
                        )

                    # Mark as processed but don't cache the failure
                    self.processed_batch_hashes.add(batch_hash)
                    return (batch_idx, None)

        # Record batch processing start metrics
        batch_processing_start_time = time.time()
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "batch_processing_sessions_total",
                1,
                labels={"strategy": self.config.strategy.value},
            )
            self.metrics_collector.record_metric(
                "batch_processing_queue_size", len(batches)
            )
            self.metrics_collector.record_metric(
                "batch_processing_unique_batches", len(unique_batches)
            )
            self.metrics_collector.record_metric(
                "batch_processing_deduplicated_batches", skipped_batches
            )

        # Process unique batches concurrently
        tasks = [process_single_batch(batch_info) for batch_info in unique_batches]

        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Combine processed results with cached results
        all_results = [None] * len(batches)

        # Add cached results
        for idx, result in cached_results:
            all_results[idx] = result

        # Add newly processed results
        for batch_result in batch_results:
            if isinstance(batch_result, tuple) and len(batch_result) == 2:
                idx, result = batch_result
                all_results[idx] = result

        # Filter out None results and exceptions
        valid_results = [
            r for r in all_results if r is not None and not isinstance(r, Exception)
        ]

        # Update final metrics
        self.metrics.mark_completed()

        # Record batch processing completion metrics
        if self.metrics_collector:
            total_processing_time = time.time() - batch_processing_start_time
            success_rate = len(valid_results) / len(batches) if batches else 0

            # Record timing and throughput metrics
            self.metrics_collector.record_histogram(
                "batch_processing_total_duration_seconds",
                total_processing_time,
                labels={"strategy": self.config.strategy.value},
            )
            self.metrics_collector.record_histogram(
                "batch_processing_throughput_batches_per_second",
                (
                    len(batches) / total_processing_time
                    if total_processing_time > 0
                    else 0
                ),
                labels={"strategy": self.config.strategy.value},
            )

            # Record success and failure metrics
            self.metrics_collector.record_metric(
                "batch_processing_successful_batches_total", len(valid_results)
            )
            self.metrics_collector.record_metric(
                "batch_processing_failed_batches_total",
                len(batches) - len(valid_results),
            )
            self.metrics_collector.record_histogram(
                "batch_processing_success_rate",
                success_rate,
                labels={"strategy": self.config.strategy.value},
            )

            # Record resource utilization metrics
            files_processed = sum(len(batch) for batch in batches if batch)
            self.metrics_collector.record_metric(
                "batch_processing_files_processed_total", files_processed
            )

            # Record queue management metrics
            self.metrics_collector.record_histogram(
                "batch_processing_queue_efficiency",
                len(unique_batches) / len(batches) if batches else 0,
                labels={"reason": "deduplication"},
            )

        logger.info(
            f"Batch processing completed: {len(valid_results)}/{len(batches)} batches succeeded "
            f"({len(unique_batches)} processed, {skipped_batches} deduplicated)"
        )

        return valid_results

    def get_metrics(self) -> BatchMetrics:
        """Get current batch processing metrics.

        Returns:
            Current batch metrics
        """
        return self.metrics

    def reset_metrics(self) -> None:
        """Reset batch processing metrics."""
        self.metrics = BatchMetrics()
        self.token_estimator.clear_cache()
        logger.debug("Batch processor metrics reset")
