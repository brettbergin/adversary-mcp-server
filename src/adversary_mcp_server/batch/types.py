"""Type definitions for batch processing system."""

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class BatchStrategy(str, Enum):
    """Batch processing strategies."""

    FIXED_SIZE = "fixed_size"
    DYNAMIC_SIZE = "dynamic_size"
    TOKEN_BASED = "token_based"
    COMPLEXITY_BASED = "complexity_based"
    ADAPTIVE_TOKEN_OPTIMIZED = "adaptive_token_optimized"  # New optimized strategy


class Language(str, Enum):
    """Supported programming languages for analysis."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    CPP = "cpp"
    C = "c"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    GENERIC = "generic"


@dataclass
class BatchConfig:
    """Configuration for batch processing."""

    # Basic batch settings
    strategy: BatchStrategy = BatchStrategy.DYNAMIC_SIZE
    min_batch_size: int = 1
    max_batch_size: int = 20
    default_batch_size: int = 10

    # Token-based settings
    max_tokens_per_batch: int = 100000
    target_tokens_per_batch: int = 80000
    token_buffer_percentage: float = 0.2  # 20% buffer

    # Complexity-based settings
    complexity_threshold_low: float = 0.3
    complexity_threshold_medium: float = 0.6
    complexity_threshold_high: float = 0.8

    # Performance settings
    enable_parallel_processing: bool = True
    max_concurrent_batches: int = 4
    batch_timeout_seconds: int = 300

    # Optimization settings
    group_by_language: bool = True
    group_by_complexity: bool = True
    prefer_similar_file_sizes: bool = True
    adaptive_sizing: bool = True

    # Progressive scanning settings
    enable_progressive_scanning: bool = True
    max_findings_before_early_exit: int = 99999  # Effectively unlimited findings
    min_high_severity_findings_for_exit: int = 5
    progressive_scan_file_limit: int = (
        100  # Stop after scanning this many files if enough findings
    )


@dataclass
class FileAnalysisContext:
    """Context information for file analysis."""

    file_path: Path
    content: str
    language: Language
    file_size_bytes: int
    estimated_tokens: int
    complexity_score: float
    priority: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def complexity_level(self) -> str:
        """Get complexity level as string."""
        if self.complexity_score < 0.3:
            return "low"
        elif self.complexity_score < 0.6:
            return "medium"
        elif self.complexity_score < 0.8:
            return "high"
        else:
            return "very_high"


@dataclass
class BatchMetrics:
    """Metrics for batch processing performance."""

    # Basic metrics
    total_files: int = 0
    total_batches: int = 0
    files_processed: int = 0
    files_failed: int = 0

    # Timing metrics
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    total_processing_time: float = 0.0
    average_batch_time: float = 0.0

    # Token metrics
    total_tokens_processed: int = 0
    average_tokens_per_batch: float = 0.0
    token_utilization_rate: float = 0.0

    # Batch size metrics
    average_batch_size: float = 0.0
    min_batch_size: int = 0
    max_batch_size: int = 0

    # Error metrics
    batch_failures: int = 0
    retry_attempts: int = 0
    cache_hits: int = 0
    cache_misses: int = 0

    def mark_completed(self) -> None:
        """Mark batch processing as completed."""
        self.end_time = time.time()
        if self.total_batches > 0:
            self.average_batch_time = self.total_processing_time / self.total_batches
            self.average_tokens_per_batch = (
                self.total_tokens_processed / self.total_batches
            )
            self.average_batch_size = self.files_processed / self.total_batches

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_files == 0:
            return 0.0
        return self.files_processed / self.total_files

    @property
    def total_duration(self) -> float:
        """Get total duration in seconds."""
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def files_per_second(self) -> float:
        """Calculate processing rate."""
        duration = self.total_duration
        if duration == 0:
            return 0.0
        return self.files_processed / duration

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_files": self.total_files,
            "total_batches": self.total_batches,
            "files_processed": self.files_processed,
            "files_failed": self.files_failed,
            "success_rate": round(self.success_rate * 100, 2),
            "total_duration_seconds": round(self.total_duration, 2),
            "files_per_second": round(self.files_per_second, 2),
            "total_processing_time": round(self.total_processing_time, 2),
            "average_batch_time": round(self.average_batch_time, 2),
            "total_tokens_processed": self.total_tokens_processed,
            "average_tokens_per_batch": round(self.average_tokens_per_batch, 2),
            "token_utilization_rate": round(self.token_utilization_rate * 100, 2),
            "average_batch_size": round(self.average_batch_size, 2),
            "min_batch_size": self.min_batch_size,
            "max_batch_size": self.max_batch_size,
            "batch_failures": self.batch_failures,
            "retry_attempts": self.retry_attempts,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        }
