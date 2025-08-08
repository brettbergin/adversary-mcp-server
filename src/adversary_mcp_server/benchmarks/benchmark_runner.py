"""Simple benchmark runner for performance testing."""

import asyncio
import gc
import os
import tempfile
import time
from pathlib import Path

import psutil

from ..credentials import CredentialManager, get_credential_manager
from ..logger import get_logger
from ..scanner.llm_scanner import LLMScanner
from .results import BenchmarkResult, BenchmarkSummary
from .test_scenarios import TestScenarios

logger = get_logger("benchmark_runner")


class BenchmarkRunner:
    """Simple performance benchmark runner."""

    def __init__(self, credential_manager: CredentialManager | None = None):
        """Initialize benchmark runner.

        Args:
            credential_manager: Optional credential manager for LLM access
        """
        self.credential_manager = credential_manager or get_credential_manager()
        self.process = psutil.Process()
        logger.info("BenchmarkRunner initialized")

    def get_system_info(self) -> dict:
        """Get basic system information."""
        try:
            return {
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
                "platform": os.name,
            }
        except Exception as e:
            logger.warning(f"Failed to get system info: {e}")
            return {"error": str(e)}

    async def run_all_benchmarks(self) -> BenchmarkSummary:
        """Run all standard benchmarks."""
        summary = BenchmarkSummary(system_info=self.get_system_info())

        # Get all benchmark scenarios
        scenarios = TestScenarios.get_benchmark_scenarios()

        for scenario_name, scenario_config in scenarios.items():
            logger.info(f"Running benchmark: {scenario_config['name']}")

            try:
                if scenario_name == "cache_test":
                    # Special handling for cache test
                    result = await self._run_cache_benchmark(
                        scenario_name, scenario_config
                    )
                else:
                    # Standard benchmark
                    result = await self._run_standard_benchmark(
                        scenario_name, scenario_config
                    )

                summary.add_result(result)
                logger.info(
                    f"Completed: {result.name} - {result.duration_seconds:.2f}s"
                )

            except Exception as e:
                logger.error(f"Benchmark {scenario_name} failed: {e}")
                error_result = BenchmarkResult(
                    name=scenario_config["name"],
                    duration_seconds=0.0,
                    success=False,
                    error_message=str(e),
                )
                summary.add_result(error_result)

        return summary

    async def _run_standard_benchmark(
        self, scenario_name: str, scenario_config: dict
    ) -> BenchmarkResult:
        """Run a standard benchmark scenario."""
        # Create temporary directory and test files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            files = TestScenarios.create_scenario_files(scenario_name, temp_path)

            # Initialize scanner
            scanner = LLMScanner(self.credential_manager)

            # Measure memory before
            gc.collect()  # Force garbage collection
            memory_start = self.process.memory_info().rss / (1024 * 1024)  # MB

            # Run benchmark
            start_time = time.time()

            try:
                if len(files) == 1:
                    # Single file analysis
                    findings = await scanner.analyze_file(files[0], "python")
                    total_findings = len(findings)
                else:
                    # Directory analysis
                    findings = await scanner.analyze_directory(temp_path)
                    total_findings = len(findings)

                success = True
                error_message = None

            except Exception as e:
                success = False
                total_findings = 0
                error_message = str(e)

            end_time = time.time()
            duration = end_time - start_time

            # Measure memory after
            gc.collect()
            memory_end = self.process.memory_info().rss / (1024 * 1024)  # MB
            memory_peak = max(memory_start, memory_end)

            # Get cache stats if available
            cache_hits = 0
            cache_misses = 0
            if hasattr(scanner, "cache_manager") and scanner.cache_manager:
                # This is a simplified way to get cache stats
                # In a real implementation, we'd need proper cache metrics
                cache_hits = getattr(scanner.cache_manager, "_cache_hits", 0)
                cache_misses = getattr(scanner.cache_manager, "_cache_misses", 0)

            return BenchmarkResult(
                name=scenario_config["name"],
                duration_seconds=duration,
                success=success,
                files_processed=len(files) if success else 0,
                findings_count=total_findings,
                memory_peak_mb=memory_peak,
                cache_hits=cache_hits,
                cache_misses=cache_misses,
                error_message=error_message,
                metadata={
                    "scenario": scenario_name,
                    "file_count": len(files),
                    "expected_findings": scenario_config.get("expected_findings", 0),
                },
            )

    async def _run_cache_benchmark(
        self, scenario_name: str, scenario_config: dict
    ) -> BenchmarkResult:
        """Run cache performance benchmark with repeated scans."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            files = TestScenarios.create_scenario_files(scenario_name, temp_path)

            scanner = LLMScanner(self.credential_manager)
            repeat_count = scenario_config.get("repeat_count", 3)

            gc.collect()
            memory_start = self.process.memory_info().rss / (1024 * 1024)

            start_time = time.time()
            total_findings = 0
            success = True
            error_message = None

            try:
                # Run multiple times to test cache effectiveness
                for i in range(repeat_count):
                    logger.debug(f"Cache test iteration {i+1}/{repeat_count}")
                    findings = await scanner.analyze_directory(temp_path)
                    total_findings = len(findings)  # Keep last count

                    # Small delay between iterations
                    await asyncio.sleep(0.1)

            except Exception as e:
                success = False
                error_message = str(e)

            end_time = time.time()
            duration = end_time - start_time

            gc.collect()
            memory_end = self.process.memory_info().rss / (1024 * 1024)
            memory_peak = max(memory_start, memory_end)

            # Cache stats
            cache_hits = 0
            cache_misses = 0
            if hasattr(scanner, "cache_manager") and scanner.cache_manager:
                cache_hits = getattr(scanner.cache_manager, "_cache_hits", 0)
                cache_misses = getattr(scanner.cache_manager, "_cache_misses", 0)

            return BenchmarkResult(
                name=scenario_config["name"],
                duration_seconds=duration,
                success=success,
                files_processed=len(files) * repeat_count if success else 0,
                findings_count=total_findings,
                memory_peak_mb=memory_peak,
                cache_hits=cache_hits,
                cache_misses=cache_misses,
                error_message=error_message,
                metadata={
                    "scenario": scenario_name,
                    "file_count": len(files),
                    "repeat_count": repeat_count,
                    "expected_findings": scenario_config.get("expected_findings", 0),
                },
            )

    async def run_single_benchmark(self, scenario_name: str) -> BenchmarkResult:
        """Run a single benchmark scenario."""
        scenarios = TestScenarios.get_benchmark_scenarios()
        if scenario_name not in scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}")

        scenario_config = scenarios[scenario_name]

        if scenario_name == "cache_test":
            return await self._run_cache_benchmark(scenario_name, scenario_config)
        else:
            return await self._run_standard_benchmark(scenario_name, scenario_config)

    async def run_custom_benchmark(
        self, name: str, files: list[Path], description: str = ""
    ) -> BenchmarkResult:
        """Run a custom benchmark with provided files."""
        scanner = LLMScanner(self.credential_manager)

        gc.collect()
        memory_start = self.process.memory_info().rss / (1024 * 1024)

        start_time = time.time()

        try:
            if len(files) == 1:
                findings = await scanner.analyze_file(files[0], "generic")
            else:
                # For multiple files, analyze the directory containing them
                parent_dir = files[0].parent
                findings = await scanner.analyze_directory(parent_dir)

            total_findings = len(findings)
            success = True
            error_message = None

        except Exception as e:
            success = False
            total_findings = 0
            error_message = str(e)

        end_time = time.time()
        duration = end_time - start_time

        gc.collect()
        memory_end = self.process.memory_info().rss / (1024 * 1024)
        memory_peak = max(memory_start, memory_end)

        return BenchmarkResult(
            name=name,
            duration_seconds=duration,
            success=success,
            files_processed=len(files) if success else 0,
            findings_count=total_findings,
            memory_peak_mb=memory_peak,
            error_message=error_message,
            metadata={
                "description": description,
                "file_count": len(files),
                "custom_benchmark": True,
            },
        )
