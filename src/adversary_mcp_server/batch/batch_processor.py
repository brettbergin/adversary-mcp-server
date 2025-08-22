"""Advanced batch processor with dynamic sizing and intelligent optimization."""

import asyncio
import hashlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..cache import CacheKey, CacheType
from ..llm.pricing_manager import PricingManager
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

# Model-specific context limits for dynamic batch sizing
# NOTE: This serves as a fallback when pricing_config.json is unavailable
# Primary source is now get_model_context_limit() which loads from pricing config
MODEL_CONTEXT_LIMITS = {
    # OpenAI GPT-5 family (latest)
    "gpt-5": 272000,
    "gpt-5-mini": 272000,
    "gpt-5-nano": 272000,
    "gpt-5-chat-latest": 272000,
    # OpenAI GPT-4 family
    "gpt-4o": 128000,
    "gpt-4o-mini": 128000,
    "gpt-4-turbo": 128000,
    "gpt-4-turbo-preview": 128000,
    "gpt-4": 8192,
    # OpenAI legacy models
    "gpt-3.5-turbo": 16384,
    "gpt-3.5-turbo-16k": 16384,
    # OpenAI reasoning models
    "o3": 200000,
    "o4-mini": 200000,
    # Anthropic Claude 4 family (latest)
    "claude-opus-4.1": 200000,
    "claude-opus-4": 200000,
    "claude-sonnet-4-20250514": 1000000,  # Extended context available
    "claude-sonnet-3.7": 200000,
    # Anthropic Claude 3.5 family
    "claude-3-5-sonnet-20241022": 200000,
    "claude-3-5-haiku-20241022": 200000,
    # Anthropic Claude 3 family (legacy)
    "claude-3-opus-20240229": 200000,
    "claude-3-sonnet-20240229": 200000,
    "claude-3-haiku-20240307": 200000,
    # Default fallback
    "default": 8192,
}


def get_model_context_limit(model_name: str) -> int:
    """Get context limit for a model from pricing configuration.

    Dynamically loads model context limits from pricing_config.json,
    falling back to hardcoded values for backwards compatibility.

    Args:
        model_name: LLM model name

    Returns:
        Maximum context tokens for the model
    """
    try:
        pricing_manager = PricingManager()
        model_info = pricing_manager.get_model_info(model_name)

        if model_info and "max_context_tokens" in model_info:
            context_limit = model_info["max_context_tokens"]
            logger.debug(
                f"Got context limit {context_limit} for {model_name} from pricing config"
            )
            return context_limit

        # Fallback to hardcoded MODEL_CONTEXT_LIMITS
        if model_name in MODEL_CONTEXT_LIMITS:
            context_limit = MODEL_CONTEXT_LIMITS[model_name]
            logger.debug(
                f"Using hardcoded context limit {context_limit} for {model_name}"
            )
            return context_limit

        # Final fallback
        default_limit = MODEL_CONTEXT_LIMITS["default"]
        logger.warning(
            f"No context limit found for {model_name}, using default {default_limit}"
        )
        return default_limit

    except Exception as e:
        logger.warning(f"Failed to get context limit for {model_name}: {e}")
        return MODEL_CONTEXT_LIMITS.get(model_name, MODEL_CONTEXT_LIMITS["default"])


class BatchProcessor:
    """Advanced batch processor for efficient LLM operations."""

    def __init__(self, config: BatchConfig, metrics_collector=None, cache_manager=None):
        """Initialize batch processor.

        Args:
            config: Batch processing configuration
            metrics_collector: Optional metrics collector for batch processing analytics
            cache_manager: Optional cache manager for content deduplication
        """
        self.config = config
        self.token_estimator = TokenEstimator()
        self.metrics = BatchMetrics()
        self.metrics_collector = metrics_collector
        self.cache_manager = cache_manager

        # Batch deduplication tracking
        self.processed_batch_hashes: set[str] = set()
        self.batch_results_cache: dict[str, Any] = {}

        # Content deduplication for similar files
        self.content_similarity_threshold = 0.85  # 85% similarity threshold
        self.deduplicated_content_map: dict[str, str] = (
            {}
        )  # content_hash -> representative_content_hash

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
        elif self.config.strategy == BatchStrategy.ADAPTIVE_TOKEN_OPTIMIZED:
            batches = self._create_adaptive_token_optimized_batches(
                sorted_contexts, model
            )
        else:
            logger.warning(
                f"Unknown strategy {self.config.strategy}, using adaptive_token_optimized"
            )
            batches = self._create_adaptive_token_optimized_batches(
                sorted_contexts, model
            )

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
        """Sort file contexts for optimal batching with smart prioritization.

        Args:
            contexts: File contexts to sort

        Returns:
            Sorted file contexts with high-risk files prioritized
        """
        # Apply smart prioritization before sorting
        prioritized_contexts = self._apply_smart_prioritization(contexts)

        def sort_key(ctx: FileAnalysisContext) -> tuple:
            # Sort by: security_priority (desc), complexity, language, size
            return (
                -ctx.priority,  # Higher priority first (security-aware)
                -ctx.complexity_score,  # More complex files first (likely more bugs)
                ctx.language.value if self.config.group_by_language else "",
                (
                    -ctx.file_size_bytes if self.config.prefer_similar_file_sizes else 0
                ),  # Larger files first
            )

        return sorted(prioritized_contexts, key=sort_key)

    def _apply_smart_prioritization(
        self, contexts: list[FileAnalysisContext]
    ) -> list[FileAnalysisContext]:
        """Apply intelligent prioritization based on security risk indicators.

        Analyzes file paths, extensions, and content characteristics to identify
        high-risk files that should be scanned first for maximum security impact.

        Args:
            contexts: File contexts to prioritize

        Returns:
            File contexts with updated priority scores
        """
        logger.debug(f"Applying smart prioritization to {len(contexts)} files")

        for ctx in contexts:
            security_score = self._calculate_security_priority_score(ctx)
            # Override the basic priority with security-aware priority
            ctx.priority = security_score

        return contexts

    def _calculate_security_priority_score(self, ctx: FileAnalysisContext) -> int:
        """Calculate security-based priority score for a file.

        Higher scores indicate files more likely to contain security vulnerabilities
        that should be analyzed first for maximum impact.

        Args:
            ctx: File analysis context

        Returns:
            Priority score (higher = more important, 0-1000)
        """
        score = 0
        file_path_str = str(ctx.file_path).lower()
        file_name = ctx.file_path.name.lower()

        # Base score from complexity (0-200 points)
        score += int(ctx.complexity_score * 200)

        # High-risk file patterns (200 points each)
        high_risk_patterns = [
            "auth",
            "login",
            "password",
            "token",
            "jwt",
            "session",
            "cookie",
            "admin",
            "user",
            "account",
            "privilege",
            "permission",
            "role",
            "api",
            "endpoint",
            "route",
            "handler",
            "controller",
            "db",
            "database",
            "sql",
            "query",
            "model",
            "entity",
            "upload",
            "download",
            "file",
            "stream",
            "input",
            "form",
            "crypto",
            "encrypt",
            "decrypt",
            "hash",
            "secret",
            "key",
            "config",
            "settings",
            "env",
            "environment",
            "server",
            "client",
            "network",
            "http",
            "request",
            "response",
        ]

        for pattern in high_risk_patterns:
            if pattern in file_path_str or pattern in file_name:
                score += 200
                break  # Only count once per file

        # High-risk directories (150 points)
        high_risk_dirs = [
            "/auth",
            "/security",
            "/admin",
            "/api",
            "/routes",
            "/controllers",
            "/models",
            "/middleware",
            "/handlers",
            "/services",
            "/utils",
            "/config",
            "/settings",
            "/env",
            "/secrets",
            "/keys",
        ]

        for dir_pattern in high_risk_dirs:
            if dir_pattern in file_path_str:
                score += 150
                break

        # Language-specific security multipliers
        language_risk_multipliers = {
            Language.JAVASCRIPT: 1.3,  # High risk due to eval, innerHTML, etc.
            Language.TYPESCRIPT: 1.2,  # Slightly safer than JS
            Language.PYTHON: 1.2,  # eval, exec, os.system risks
            Language.PHP: 1.4,  # Very high risk language
            Language.C: 1.1,  # Buffer overflows, memory issues
            Language.CPP: 1.1,  # Similar to C
            Language.JAVA: 1.0,  # Relatively safer
            Language.CSHARP: 1.0,  # Relatively safer
            Language.GO: 0.9,  # Generally safer
            Language.RUST: 0.8,  # Memory safe by design
            Language.RUBY: 1.1,  # Some eval/injection risks
            Language.KOTLIN: 1.0,  # Similar to Java
            Language.SWIFT: 0.9,  # Relatively safe
            Language.GENERIC: 1.0,  # Unknown risk
        }

        score = int(score * language_risk_multipliers.get(ctx.language, 1.0))

        # File size factor (larger files potentially more complex/risky)
        # But cap it to avoid de-prioritizing small critical files
        size_bonus = min(
            100, ctx.file_size_bytes // 1000
        )  # Up to 100 points for large files
        score += size_bonus

        # Critical file extensions (100 points)
        critical_extensions = {
            ".env",
            ".config",
            ".conf",
            ".ini",
            ".yaml",
            ".yml",
            ".json",
            ".key",
            ".pem",
            ".cert",
            ".crt",
            ".p12",
            ".jks",
        }

        if ctx.file_path.suffix.lower() in critical_extensions:
            score += 100

        # De-prioritize low-value files (negative scores)
        low_value_patterns = [
            "test",
            "spec",
            "mock",
            ".test.",
            ".spec.",
            "_test",
            "_spec",
            "readme",
            "license",
            "changelog",
            "todo",
            "doc",
            "docs",
            "example",
            "sample",
            "demo",
            "tutorial",
        ]

        for pattern in low_value_patterns:
            if pattern in file_path_str or pattern in file_name:
                score -= 200  # Significantly lower priority
                break

        # Test directories get very low priority
        if any(
            test_dir in file_path_str
            for test_dir in ["/test", "/tests", "/spec", "/specs", "/__tests__"]
        ):
            score -= 300

        # Documentation and non-executable files get low priority
        doc_extensions = {
            ".md",
            ".txt",
            ".rst",
            ".adoc",
            ".html",
            ".css",
            ".scss",
            ".less",
        }
        if ctx.file_path.suffix.lower() in doc_extensions:
            score -= 150

        # Ensure score stays in reasonable range
        score = max(0, min(1000, score))

        if score > 500:  # Log high-priority files for debugging
            logger.debug(
                f"High-priority file detected: {ctx.file_path} "
                f"(score={score}, complexity={ctx.complexity_score:.2f}, lang={ctx.language})"
            )

        return score

    def should_continue_progressive_scan(
        self,
        processed_file_count: int,
        total_findings: list[Any],
        high_severity_findings: list[Any],
    ) -> bool:
        """Determine if progressive scanning should continue or exit early.

        Args:
            processed_file_count: Number of files processed so far
            total_findings: All findings discovered so far
            high_severity_findings: High/critical severity findings

        Returns:
            True if scanning should continue, False to exit early
        """
        if not self.config.enable_progressive_scanning:
            return True  # Progressive scanning disabled, continue normally

        # Check if we're in unlimited findings mode (comprehensive scanning)
        unlimited_mode = self.config.max_findings_before_early_exit >= 99999

        if not unlimited_mode:
            # Exit early if we've found enough findings (only in limited mode)
            if len(total_findings) >= self.config.max_findings_before_early_exit:
                logger.info(
                    f"Progressive scan: Early exit due to {len(total_findings)} findings "
                    f"(limit: {self.config.max_findings_before_early_exit})"
                )
                return False

            # Exit early if we have enough high-severity findings and have processed some files
            if (
                len(high_severity_findings)
                >= self.config.min_high_severity_findings_for_exit
                and processed_file_count >= 20
            ):  # Process at least 20 files before considering early exit
                logger.info(
                    f"Progressive scan: Early exit due to {len(high_severity_findings)} high-severity findings "
                    f"after {processed_file_count} files"
                )
                return False

            # Exit if we've hit the file processing limit with reasonable findings
            if (
                processed_file_count >= self.config.progressive_scan_file_limit
                and len(total_findings) >= 10
            ):  # Need at least some findings to justify early exit
                logger.info(
                    f"Progressive scan: Early exit after processing {processed_file_count} files "
                    f"with {len(total_findings)} findings"
                )
                return False
        else:
            # In unlimited mode, log progress but never exit early
            if processed_file_count % 50 == 0:  # Log every 50 files
                logger.info(
                    f"Comprehensive scan: Processed {processed_file_count} files, "
                    f"found {len(total_findings)} total findings "
                    f"({len(high_severity_findings)} high-severity)"
                )

        return True  # Continue scanning

    def deduplicate_similar_content(
        self, contexts: list[FileAnalysisContext]
    ) -> list[FileAnalysisContext]:
        """Deduplicate files with similar content to improve cache efficiency.

        Identifies files with very similar content and marks them for shared analysis results.
        This significantly improves performance when scanning codebases with generated files,
        templates, or repeated patterns.

        Args:
            contexts: List of file contexts to deduplicate

        Returns:
            Deduplicated list with similar files marked
        """
        if not self.cache_manager or len(contexts) < 2:
            return contexts

        logger.debug(f"Performing content deduplication on {len(contexts)} files")

        # Group files by size buckets for efficient comparison
        size_buckets: dict[int, list[FileAnalysisContext]] = {}
        for ctx in contexts:
            # Use size bucket (rounded to nearest 1KB) for initial filtering
            size_bucket = (ctx.file_size_bytes // 1024) * 1024
            if size_bucket not in size_buckets:
                size_buckets[size_bucket] = []
            size_buckets[size_bucket].append(ctx)

        deduplicated_contexts = []
        similarity_groups: list[list[FileAnalysisContext]] = []

        for bucket_size, bucket_contexts in size_buckets.items():
            if len(bucket_contexts) == 1:
                # No duplicates possible in this bucket
                deduplicated_contexts.extend(bucket_contexts)
                continue

            # Find similarity groups within this bucket
            remaining_contexts = bucket_contexts[:]

            while remaining_contexts:
                representative = remaining_contexts.pop(0)
                similarity_group = [representative]

                # Find similar files to the representative
                to_remove = []
                for i, candidate in enumerate(remaining_contexts):
                    if self._are_contents_similar(representative, candidate):
                        similarity_group.append(candidate)
                        to_remove.append(i)

                # Remove similar files from remaining (in reverse order to maintain indices)
                for i in reversed(to_remove):
                    remaining_contexts.pop(i)

                similarity_groups.append(similarity_group)

        # Process similarity groups
        deduplication_count = 0
        for group in similarity_groups:
            if len(group) == 1:
                # No duplicates
                deduplicated_contexts.append(group[0])
            else:
                # Choose the best representative (highest priority, then complexity)
                representative = max(
                    group, key=lambda ctx: (ctx.priority, ctx.complexity_score)
                )
                deduplicated_contexts.append(representative)

                # Cache the similarity mapping for later result sharing
                representative_hash = hashlib.sha256(
                    representative.content.encode()
                ).hexdigest()
                for similar_ctx in group:
                    if similar_ctx != representative:
                        similar_hash = hashlib.sha256(
                            similar_ctx.content.encode()
                        ).hexdigest()
                        self.deduplicated_content_map[similar_hash] = (
                            representative_hash
                        )
                        deduplication_count += 1

                        # Store in cache for future reference
                        if self.cache_manager:
                            cache_key = CacheKey(
                                cache_type=CacheType.DEDUPLICATED_CONTENT,
                                content_hash=similar_hash,
                                metadata_hash=representative_hash,
                            )
                            self.cache_manager.put(
                                cache_key, {"representative_hash": representative_hash}
                            )

        if deduplication_count > 0:
            logger.info(
                f"Content deduplication: {deduplication_count} similar files identified, "
                f"reduced from {len(contexts)} to {len(deduplicated_contexts)} unique files "
                f"({deduplication_count/len(contexts)*100:.1f}% reduction)"
            )

            # Record deduplication metrics
            if self.metrics_collector:
                self.metrics_collector.record_metric(
                    "content_deduplication_files_reduced", deduplication_count
                )
                self.metrics_collector.record_histogram(
                    "content_deduplication_reduction_ratio",
                    deduplication_count / len(contexts),
                )

        return deduplicated_contexts

    def _are_contents_similar(
        self, ctx1: FileAnalysisContext, ctx2: FileAnalysisContext
    ) -> bool:
        """Check if two file contents are similar enough to be deduplicated.

        Uses multiple similarity metrics to determine if files are similar enough
        to share analysis results.

        Args:
            ctx1: First file context
            ctx2: Second file context

        Returns:
            True if files are similar enough to deduplicate
        """
        # Quick size check - files must be reasonably similar in size
        size_ratio = min(ctx1.file_size_bytes, ctx2.file_size_bytes) / max(
            ctx1.file_size_bytes, ctx2.file_size_bytes
        )
        if size_ratio < 0.8:  # Files differ by more than 20% in size
            return False

        # Different languages are unlikely to be meaningfully similar
        if ctx1.language != ctx2.language:
            return False

        # Calculate content similarity using multiple methods
        content1_lines = set(ctx1.content.strip().split("\n"))
        content2_lines = set(ctx2.content.strip().split("\n"))

        # Jaccard similarity of lines
        intersection = len(content1_lines & content2_lines)
        union = len(content1_lines | content2_lines)
        jaccard_similarity = intersection / union if union > 0 else 0

        # Character-level similarity for smaller files
        if len(ctx1.content) < 5000 and len(ctx2.content) < 5000:
            # Use simple character similarity for small files
            char_similarity = self._calculate_character_similarity(
                ctx1.content, ctx2.content
            )
            # Weight both similarities
            combined_similarity = (jaccard_similarity * 0.7) + (char_similarity * 0.3)
        else:
            # For larger files, rely more on line-based similarity
            combined_similarity = jaccard_similarity

        is_similar = combined_similarity >= self.content_similarity_threshold

        if is_similar:
            logger.debug(
                f"Similar content detected: {ctx1.file_path.name} <-> {ctx2.file_path.name} "
                f"(similarity: {combined_similarity:.3f})"
            )

        return is_similar

    def _calculate_character_similarity(self, content1: str, content2: str) -> float:
        """Calculate character-level similarity between two strings.

        Uses a simple difflib-like approach for character similarity.

        Args:
            content1: First content string
            content2: Second content string

        Returns:
            Similarity ratio (0.0 to 1.0)
        """
        # Remove whitespace for more semantic comparison
        clean1 = "".join(content1.split())
        clean2 = "".join(content2.split())

        if not clean1 and not clean2:
            return 1.0
        if not clean1 or not clean2:
            return 0.0

        # Simple longest common subsequence approximation
        # This is a simplified version for performance
        shorter, longer = (
            (clean1, clean2) if len(clean1) <= len(clean2) else (clean2, clean1)
        )

        common_chars = 0
        for char in shorter:
            if char in longer:
                common_chars += 1
                longer = longer.replace(char, "", 1)  # Remove to avoid double counting

        return common_chars / len(shorter)

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

    def _create_adaptive_token_optimized_batches(
        self, contexts: list[FileAnalysisContext], model: str | None
    ) -> list[list[FileAnalysisContext]]:
        """Create adaptively optimized batches with model-aware token limits.

        This advanced strategy maximizes context window utilization while
        considering file complexity, language types, and model-specific limits.

        Args:
            contexts: Sorted file contexts
            model: LLM model name for context limit lookup

        Returns:
            List of highly optimized batches for maximum throughput
        """
        logger.debug(f"Creating adaptive token optimized batches for model: {model}")

        # Step 1: Apply content deduplication to reduce redundant processing
        deduplicated_contexts = self.deduplicate_similar_content(contexts)
        logger.debug(
            f"After deduplication: {len(deduplicated_contexts)} unique files to process"
        )

        # Get model-specific context limit dynamically
        model_context_limit = get_model_context_limit(model or "default")
        logger.debug(
            f"Using context limit: {model_context_limit} tokens for model {model}"
        )

        # Calculate dynamic limits based on model capacity
        # Reserve tokens for system prompt (typically 1000-2000 tokens)
        # Reserve tokens for response generation (typically 2000-4000 tokens)
        system_prompt_reserve = min(2000, model_context_limit * 0.1)  # 10% or 2K max
        response_reserve = min(4000, model_context_limit * 0.2)  # 20% or 4K max
        overhead_reserve = 1000  # Buffer for prompt formatting overhead

        available_tokens = (
            model_context_limit
            - system_prompt_reserve
            - response_reserve
            - overhead_reserve
        )
        target_tokens_per_batch = int(
            available_tokens * 0.85
        )  # 85% utilization for safety

        logger.info(
            f"Adaptive batching: model_limit={model_context_limit}, "
            f"available={available_tokens}, target_per_batch={target_tokens_per_batch}"
        )

        batches = []
        current_batch = []
        current_tokens = 0

        # Group contexts by language for better batch efficiency
        language_groups = {}
        for context in deduplicated_contexts:
            lang = context.language
            if lang not in language_groups:
                language_groups[lang] = []
            language_groups[lang].append(context)

        # Process each language group to create homogeneous batches when possible
        for language, lang_contexts in language_groups.items():
            logger.debug(f"Processing {len(lang_contexts)} {language} files")

            for context in lang_contexts:
                # Enhanced token estimation including language-specific overhead
                base_tokens = context.estimated_tokens

                # Language-specific prompt overhead estimation
                language_overhead = {
                    Language.PYTHON: 300,
                    Language.JAVASCRIPT: 350,
                    Language.TYPESCRIPT: 350,
                    Language.JAVA: 400,
                    Language.CSHARP: 400,
                    Language.CPP: 350,
                    Language.C: 300,
                    Language.GO: 300,
                    Language.RUST: 350,
                    Language.PHP: 300,
                    Language.RUBY: 300,
                }.get(context.language, 250)

                # Complexity-based overhead (more complex files need more instruction tokens)
                complexity_overhead = int(
                    context.complexity_score * 200
                )  # 0-200 extra tokens

                # File size overhead (larger files need more formatting tokens)
                size_overhead = min(
                    100, context.file_size_bytes // 1000
                )  # Up to 100 tokens for large files

                total_context_tokens = (
                    base_tokens
                    + language_overhead
                    + complexity_overhead
                    + size_overhead
                )

                # Adaptive batch size limits based on complexity
                if context.complexity_score > 0.8:
                    # Very complex files: smaller batches for better analysis quality
                    max_files_in_batch = min(self.config.max_batch_size // 2, 8)
                elif context.complexity_score > 0.5:
                    # Medium complexity: moderate batch sizes
                    max_files_in_batch = min(self.config.max_batch_size, 12)
                else:
                    # Low complexity: can handle larger batches
                    max_files_in_batch = self.config.max_batch_size

                # Decision logic: create new batch if limits exceeded
                should_start_new_batch = (
                    # Token limit would be exceeded
                    (
                        current_tokens + total_context_tokens > target_tokens_per_batch
                        and current_batch
                    )
                    # Or file count limit reached
                    or len(current_batch) >= max_files_in_batch
                    # Or mixing languages would hurt performance (prefer homogeneous batches)
                    or (
                        current_batch
                        and current_batch[0].language != context.language
                        and len(current_batch) >= 3
                    )
                )

                if should_start_new_batch:
                    if current_batch:
                        logger.debug(
                            f"Completed batch: {len(current_batch)} files, {current_tokens} tokens, "
                            f"avg_complexity={sum(c.complexity_score for c in current_batch)/len(current_batch):.2f}"
                        )
                        batches.append(current_batch)
                    current_batch = [context]
                    current_tokens = total_context_tokens
                else:
                    current_batch.append(context)
                    current_tokens += total_context_tokens

        # Add final batch if not empty
        if current_batch:
            logger.debug(
                f"Final batch: {len(current_batch)} files, {current_tokens} tokens, "
                f"avg_complexity={sum(c.complexity_score for c in current_batch)/len(current_batch):.2f}"
            )
            batches.append(current_batch)

        # Post-processing optimization: merge small batches if possible
        optimized_batches = []
        i = 0
        while i < len(batches):
            current = batches[i]
            current_tokens = sum(
                ctx.estimated_tokens + 250 for ctx in current  # Rough overhead estimate
            )

            # Try to merge with next batch if both are small
            if (
                i + 1 < len(batches)
                and len(current) < self.config.min_batch_size
                and len(batches[i + 1]) < self.config.min_batch_size
            ):

                next_batch = batches[i + 1]
                next_tokens = sum(ctx.estimated_tokens + 250 for ctx in next_batch)

                if current_tokens + next_tokens <= target_tokens_per_batch:
                    merged_batch = current + next_batch
                    logger.debug(
                        f"Merged two small batches: {len(current)} + {len(next_batch)} = {len(merged_batch)} files"
                    )
                    optimized_batches.append(merged_batch)
                    i += 2  # Skip next batch since we merged it
                    continue

            optimized_batches.append(current)
            i += 1

        # Log final batch statistics
        if optimized_batches:
            total_files = sum(len(batch) for batch in optimized_batches)
            avg_batch_size = total_files / len(optimized_batches)
            token_utilization = (
                sum(
                    sum(ctx.estimated_tokens for ctx in batch)
                    for batch in optimized_batches
                )
                / (len(optimized_batches) * target_tokens_per_batch)
                * 100
            )

            logger.info(
                f"Adaptive batching complete: {len(optimized_batches)} batches, "
                f"avg_size={avg_batch_size:.1f} files/batch, "
                f"token_utilization={token_utilization:.1f}%"
            )

        return optimized_batches

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
