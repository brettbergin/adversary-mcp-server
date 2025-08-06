"""Simple benchmark results and reporting."""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BenchmarkResult:
    """Result of a single benchmark test."""

    name: str
    duration_seconds: float
    success: bool
    files_processed: int = 0
    findings_count: int = 0
    memory_peak_mb: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def files_per_second(self) -> float:
        """Calculate processing rate."""
        if self.duration_seconds == 0:
            return 0.0
        return self.files_processed / self.duration_seconds

    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.cache_hits + self.cache_misses
        if total == 0:
            return 0.0
        return self.cache_hits / total

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "duration_seconds": round(self.duration_seconds, 3),
            "success": self.success,
            "files_processed": self.files_processed,
            "findings_count": self.findings_count,
            "files_per_second": round(self.files_per_second, 2),
            "memory_peak_mb": round(self.memory_peak_mb, 2),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": round(self.cache_hit_rate * 100, 1),
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


@dataclass
class BenchmarkSummary:
    """Summary of benchmark run results."""

    timestamp: float = field(default_factory=time.time)
    total_duration: float = 0.0
    results: list[BenchmarkResult] = field(default_factory=list)
    system_info: dict[str, Any] = field(default_factory=dict)

    def add_result(self, result: BenchmarkResult) -> None:
        """Add a benchmark result."""
        self.results.append(result)
        self.total_duration += result.duration_seconds

    @property
    def success_count(self) -> int:
        """Count of successful benchmarks."""
        return sum(1 for r in self.results if r.success)

    @property
    def total_files_processed(self) -> int:
        """Total files processed across all benchmarks."""
        return sum(r.files_processed for r in self.results)

    @property
    def average_files_per_second(self) -> float:
        """Average processing rate across all benchmarks."""
        if self.total_duration == 0:
            return 0.0
        return self.total_files_processed / self.total_duration

    def get_fastest_result(self) -> BenchmarkResult | None:
        """Get the fastest successful benchmark."""
        successful = [r for r in self.results if r.success and r.files_processed > 0]
        if not successful:
            return None
        return max(successful, key=lambda r: r.files_per_second)

    def get_slowest_result(self) -> BenchmarkResult | None:
        """Get the slowest successful benchmark."""
        successful = [r for r in self.results if r.success and r.files_processed > 0]
        if not successful:
            return None
        return min(successful, key=lambda r: r.files_per_second)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp,
            "total_duration": round(self.total_duration, 3),
            "summary": {
                "total_benchmarks": len(self.results),
                "successful_benchmarks": self.success_count,
                "total_files_processed": self.total_files_processed,
                "average_files_per_second": round(self.average_files_per_second, 2),
                "fastest_benchmark": (
                    self.get_fastest_result().name
                    if self.get_fastest_result()
                    else None
                ),
                "slowest_benchmark": (
                    self.get_slowest_result().name
                    if self.get_slowest_result()
                    else None
                ),
            },
            "results": [r.to_dict() for r in self.results],
            "system_info": self.system_info,
        }

    def save_to_file(self, file_path: Path) -> None:
        """Save benchmark results to JSON file."""
        with open(file_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def print_summary(self) -> None:
        """Print a human-readable summary."""
        print("\n" + "=" * 60)
        print("BENCHMARK SUMMARY")
        print("=" * 60)
        print(f"Total Benchmarks: {len(self.results)}")
        print(f"Successful: {self.success_count}")
        print(f"Total Duration: {self.total_duration:.2f}s")
        print(f"Files Processed: {self.total_files_processed}")
        print(f"Average Speed: {self.average_files_per_second:.2f} files/sec")

        fastest = self.get_fastest_result()
        slowest = self.get_slowest_result()

        if fastest:
            print(
                f"Fastest Test: {fastest.name} ({fastest.files_per_second:.2f} files/sec)"
            )
        if slowest:
            print(
                f"Slowest Test: {slowest.name} ({slowest.files_per_second:.2f} files/sec)"
            )

        print("\nDETAILED RESULTS:")
        print("-" * 60)
        for result in self.results:
            status = "✅" if result.success else "❌"
            print(f"{status} {result.name}")
            print(f"   Duration: {result.duration_seconds:.2f}s")
            if result.files_processed > 0:
                print(f"   Speed: {result.files_per_second:.2f} files/sec")
                print(
                    f"   Files: {result.files_processed}, Findings: {result.findings_count}"
                )
                if result.cache_hits + result.cache_misses > 0:
                    print(f"   Cache: {result.cache_hit_rate:.1f}% hit rate")
            if result.memory_peak_mb > 0:
                print(f"   Memory: {result.memory_peak_mb:.1f} MB peak")
            if result.error_message:
                print(f"   Error: {result.error_message}")
            print()

        print("=" * 60)
