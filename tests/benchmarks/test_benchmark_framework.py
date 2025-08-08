"""Tests for the benchmarking framework components."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from adversary_mcp_server.benchmarks import (
    BenchmarkResult,
    BenchmarkRunner,
    BenchmarkSummary,
    TestScenarios,
)
from adversary_mcp_server.credentials import get_credential_manager


class TestBenchmarkResult:
    """Test BenchmarkResult functionality."""

    def test_benchmark_result_creation(self):
        """Test basic benchmark result creation."""
        result = BenchmarkResult(
            name="Test Benchmark",
            duration_seconds=1.5,
            success=True,
            files_processed=10,
            findings_count=5,
        )

        assert result.name == "Test Benchmark"
        assert result.duration_seconds == 1.5
        assert result.success
        assert result.files_processed == 10
        assert result.findings_count == 5

    def test_files_per_second_calculation(self):
        """Test files per second calculation."""
        result = BenchmarkResult(
            name="Test", duration_seconds=2.0, success=True, files_processed=10
        )

        assert result.files_per_second == 5.0

        # Test zero duration
        zero_duration = BenchmarkResult(
            name="Test", duration_seconds=0.0, success=True, files_processed=10
        )
        assert zero_duration.files_per_second == 0.0

    def test_cache_hit_rate_calculation(self):
        """Test cache hit rate calculation."""
        result = BenchmarkResult(
            name="Test",
            duration_seconds=1.0,
            success=True,
            cache_hits=8,
            cache_misses=2,
        )

        assert result.cache_hit_rate == 0.8

        # Test no cache data
        no_cache = BenchmarkResult(name="Test", duration_seconds=1.0, success=True)
        assert no_cache.cache_hit_rate == 0.0

    def test_to_dict_conversion(self):
        """Test conversion to dictionary."""
        result = BenchmarkResult(
            name="Performance Test",
            duration_seconds=2.534,
            success=True,
            files_processed=15,
            findings_count=7,
            memory_peak_mb=64.25,
            cache_hits=12,
            cache_misses=3,
            error_message=None,
            metadata={"scenario": "test", "file_count": 15},
        )

        result_dict = result.to_dict()

        assert result_dict["name"] == "Performance Test"
        assert result_dict["duration_seconds"] == 2.534
        assert result_dict["success"]
        assert result_dict["files_processed"] == 15
        assert result_dict["findings_count"] == 7
        assert abs(result_dict["files_per_second"] - 5.92) < 0.01  # 15/2.534 rounded
        assert result_dict["memory_peak_mb"] == 64.25
        assert result_dict["cache_hits"] == 12
        assert result_dict["cache_misses"] == 3
        assert result_dict["cache_hit_rate"] == 80.0  # 12/(12+3) * 100
        assert result_dict["error_message"] is None
        assert result_dict["metadata"]["scenario"] == "test"

    def test_failed_benchmark_result(self):
        """Test failed benchmark result."""
        result = BenchmarkResult(
            name="Failed Test",
            duration_seconds=0.5,
            success=False,
            error_message="Test error occurred",
        )

        assert not result.success
        assert result.error_message == "Test error occurred"
        assert result.files_per_second == 0.0


class TestBenchmarkSummary:
    """Test BenchmarkSummary functionality."""

    def test_benchmark_summary_creation(self):
        """Test benchmark summary creation."""
        summary = BenchmarkSummary(
            system_info={"cpu_count": 8, "memory_total_gb": 16.0}
        )

        assert summary.system_info["cpu_count"] == 8
        assert summary.system_info["memory_total_gb"] == 16.0
        assert len(summary.results) == 0
        assert summary.total_duration == 0.0

    def test_add_result(self):
        """Test adding benchmark results."""
        summary = BenchmarkSummary()

        result1 = BenchmarkResult("Test 1", 1.5, True, files_processed=10)
        result2 = BenchmarkResult("Test 2", 2.0, False, error_message="Error")

        summary.add_result(result1)
        summary.add_result(result2)

        assert len(summary.results) == 2
        assert summary.total_duration == 3.5

    def test_success_count(self):
        """Test success count calculation."""
        summary = BenchmarkSummary()

        summary.add_result(BenchmarkResult("Test 1", 1.0, True))
        summary.add_result(BenchmarkResult("Test 2", 1.0, True))
        summary.add_result(BenchmarkResult("Test 3", 1.0, False))

        assert summary.success_count == 2

    def test_total_files_processed(self):
        """Test total files processed calculation."""
        summary = BenchmarkSummary()

        summary.add_result(BenchmarkResult("Test 1", 1.0, True, files_processed=5))
        summary.add_result(BenchmarkResult("Test 2", 1.0, True, files_processed=10))
        summary.add_result(BenchmarkResult("Test 3", 1.0, False, files_processed=0))

        assert summary.total_files_processed == 15

    def test_average_files_per_second(self):
        """Test average files per second calculation."""
        summary = BenchmarkSummary()

        summary.add_result(BenchmarkResult("Test 1", 2.0, True, files_processed=10))
        summary.add_result(BenchmarkResult("Test 2", 3.0, True, files_processed=15))

        # Total: 25 files in 5.0 seconds = 5.0 files/sec
        assert summary.average_files_per_second == 5.0

        # Test zero duration
        empty_summary = BenchmarkSummary()
        assert empty_summary.average_files_per_second == 0.0

    def test_fastest_and_slowest_results(self):
        """Test fastest and slowest result identification."""
        summary = BenchmarkSummary()

        # Add results with different speeds
        summary.add_result(
            BenchmarkResult("Slow", 2.0, True, files_processed=4)
        )  # 2.0 files/sec
        summary.add_result(
            BenchmarkResult("Fast", 1.0, True, files_processed=10)
        )  # 10.0 files/sec
        summary.add_result(
            BenchmarkResult("Medium", 1.0, True, files_processed=5)
        )  # 5.0 files/sec
        summary.add_result(
            BenchmarkResult("Failed", 1.0, False, files_processed=0)
        )  # Should be ignored

        fastest = summary.get_fastest_result()
        slowest = summary.get_slowest_result()

        assert fastest.name == "Fast"
        assert slowest.name == "Slow"

        # Test empty summary
        empty_summary = BenchmarkSummary()
        assert empty_summary.get_fastest_result() is None
        assert empty_summary.get_slowest_result() is None

    def test_to_dict_conversion(self):
        """Test conversion to dictionary."""
        summary = BenchmarkSummary(system_info={"cpu_count": 4, "memory_total_gb": 8.0})

        summary.add_result(
            BenchmarkResult("Test 1", 1.0, True, files_processed=5)
        )  # 5 files/sec
        summary.add_result(
            BenchmarkResult("Test 2", 1.0, True, files_processed=10)
        )  # 10 files/sec

        summary_dict = summary.to_dict()

        assert "timestamp" in summary_dict
        assert summary_dict["total_duration"] == 2.0
        assert summary_dict["summary"]["total_benchmarks"] == 2
        assert summary_dict["summary"]["successful_benchmarks"] == 2
        assert summary_dict["summary"]["total_files_processed"] == 15
        assert summary_dict["summary"]["average_files_per_second"] == 7.5
        assert summary_dict["summary"]["fastest_benchmark"] == "Test 2"
        assert summary_dict["summary"]["slowest_benchmark"] == "Test 1"
        assert len(summary_dict["results"]) == 2
        assert summary_dict["system_info"]["cpu_count"] == 4

    def test_save_to_file(self):
        """Test saving results to JSON file."""
        summary = BenchmarkSummary()
        summary.add_result(BenchmarkResult("Test", 1.0, True, files_processed=5))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = Path(f.name)

        try:
            summary.save_to_file(temp_path)

            # Verify file was created and contains valid JSON
            assert temp_path.exists()

            with open(temp_path) as f:
                data = json.load(f)

            assert data["summary"]["total_benchmarks"] == 1
            assert len(data["results"]) == 1

        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_print_summary(self, capsys):
        """Test printing human-readable summary."""
        summary = BenchmarkSummary()
        summary.add_result(
            BenchmarkResult(
                "Fast Test", 0.5, True, files_processed=10, findings_count=3
            )
        )
        summary.add_result(
            BenchmarkResult("Slow Test", 2.0, True, files_processed=5, findings_count=1)
        )
        summary.add_result(
            BenchmarkResult("Failed Test", 1.0, False, error_message="Test error")
        )

        summary.print_summary()

        captured = capsys.readouterr()
        output = captured.out

        assert "BENCHMARK SUMMARY" in output
        assert "Total Benchmarks: 3" in output
        assert "Successful: 2" in output
        assert "Total Duration: 3.50s" in output
        assert "Files Processed: 15" in output
        assert "Fastest Test: Fast Test" in output
        assert "Slowest Test: Slow Test" in output
        assert "✅ Fast Test" in output
        assert "✅ Slow Test" in output
        assert "❌ Failed Test" in output
        assert "Error: Test error" in output


class TestTestScenarios:
    """Test TestScenarios functionality."""

    def test_create_sample_python_file(self):
        """Test creating sample Python file."""
        content = TestScenarios.create_sample_python_file(
            "test.py", lines=30, has_vulnerabilities=True
        )

        assert "#!/usr/bin/env python3" in content
        assert "import os" in content
        assert "def unsafe_eval" in content
        assert "API_KEY" in content
        assert len(content.split("\n")) >= 30

    def test_create_sample_python_file_secure(self):
        """Test creating secure Python file."""
        content = TestScenarios.create_sample_python_file(
            "test.py", lines=20, has_vulnerabilities=False
        )

        assert "#!/usr/bin/env python3" in content
        assert "def process_data" in content
        assert "unsafe_eval" not in content
        assert "API_KEY" not in content

    def test_create_sample_javascript_file(self):
        """Test creating sample JavaScript file."""
        content = TestScenarios.create_sample_javascript_file(
            "test.js", lines=40, has_vulnerabilities=True
        )

        assert "// Sample JavaScript file" in content
        assert "const express = require('express')" in content
        assert "function unsafeEval" in content
        assert "const API_KEY" in content
        assert len(content.split("\n")) >= 40

    def test_create_sample_javascript_file_secure(self):
        """Test creating secure JavaScript file."""
        content = TestScenarios.create_sample_javascript_file(
            "test.js", lines=20, has_vulnerabilities=False
        )

        assert "// Sample JavaScript file" in content
        assert "class DataProcessor" in content
        assert "unsafeEval" not in content
        assert "API_KEY" not in content

    def test_create_test_files(self):
        """Test creating multiple test files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            files = TestScenarios.create_test_files(temp_path, file_count=5)

            assert len(files) == 5

            # Check files were created
            for file_path in files:
                assert file_path.exists()
                assert file_path.stat().st_size > 0

            # Check alternating Python and JavaScript files
            assert files[0].suffix == ".py"
            assert files[1].suffix == ".js"
            assert files[2].suffix == ".py"
            assert files[3].suffix == ".js"
            assert files[4].suffix == ".py"

    def test_get_benchmark_scenarios(self):
        """Test getting predefined benchmark scenarios."""
        scenarios = TestScenarios.get_benchmark_scenarios()

        assert isinstance(scenarios, dict)
        assert "single_file" in scenarios
        assert "small_batch" in scenarios
        assert "medium_batch" in scenarios
        assert "cache_test" in scenarios
        assert "large_files" in scenarios

        # Check scenario structure
        single_file = scenarios["single_file"]
        assert single_file["name"] == "Single File Analysis"
        assert single_file["file_count"] == 1
        assert "expected_findings" in single_file

    def test_create_scenario_files(self):
        """Test creating files for specific scenarios."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Test single file scenario
            files = TestScenarios.create_scenario_files("single_file", temp_path)
            assert len(files) == 1
            assert files[0].exists()

            # Test small batch scenario
            files = TestScenarios.create_scenario_files("small_batch", temp_path)
            assert len(files) == 5

            # Test unknown scenario
            with pytest.raises(ValueError, match="Unknown scenario"):
                TestScenarios.create_scenario_files("unknown_scenario", temp_path)


class TestBenchmarkRunner:
    """Test BenchmarkRunner functionality."""

    def test_initialization(self):
        """Test benchmark runner initialization."""
        credential_manager = get_credential_manager()
        runner = BenchmarkRunner(credential_manager)

        assert runner.credential_manager == credential_manager

    def test_initialization_without_credential_manager(self):
        """Test initialization without credential manager."""
        runner = BenchmarkRunner()

        assert runner.credential_manager is not None

    def test_get_system_info(self):
        """Test getting system information."""
        runner = BenchmarkRunner()

        system_info = runner.get_system_info()

        assert isinstance(system_info, dict)
        if "error" not in system_info:
            assert "cpu_count" in system_info
            assert "memory_total_gb" in system_info
            assert "python_version" in system_info
            assert "platform" in system_info

    @pytest.mark.asyncio
    async def test_run_single_benchmark(self):
        """Test running single benchmark scenario."""
        runner = BenchmarkRunner()

        # Mock the LLM scanner to avoid actual API calls
        with patch(
            "adversary_mcp_server.benchmarks.benchmark_runner.LLMScanner"
        ) as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner_class.return_value = mock_scanner
            mock_scanner.analyze_file.return_value = []
            mock_scanner.analyze_directory.return_value = []

            result = await runner.run_single_benchmark("single_file")

            assert isinstance(result, BenchmarkResult)
            assert result.name == "Single File Analysis"
            assert result.success

    @pytest.mark.asyncio
    async def test_run_single_benchmark_unknown_scenario(self):
        """Test running unknown benchmark scenario."""
        runner = BenchmarkRunner()

        with pytest.raises(ValueError, match="Unknown scenario"):
            await runner.run_single_benchmark("unknown_scenario")

    @pytest.mark.asyncio
    async def test_run_cache_benchmark(self):
        """Test running cache benchmark scenario."""
        runner = BenchmarkRunner()

        with patch(
            "adversary_mcp_server.benchmarks.benchmark_runner.LLMScanner"
        ) as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner_class.return_value = mock_scanner
            mock_scanner.analyze_directory.return_value = []

            result = await runner.run_single_benchmark("cache_test")

            assert isinstance(result, BenchmarkResult)
            assert result.name == "Cache Performance Test"
            # Should have called analyze_directory multiple times
            assert mock_scanner.analyze_directory.call_count >= 3

    @pytest.mark.asyncio
    async def test_run_all_benchmarks(self):
        """Test running all benchmark scenarios."""
        runner = BenchmarkRunner()

        with patch(
            "adversary_mcp_server.benchmarks.benchmark_runner.LLMScanner"
        ) as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner_class.return_value = mock_scanner
            mock_scanner.analyze_file.return_value = []
            mock_scanner.analyze_directory.return_value = []

            summary = await runner.run_all_benchmarks()

            assert isinstance(summary, BenchmarkSummary)
            assert len(summary.results) == 5  # All scenarios
            assert summary.success_count >= 0

    @pytest.mark.asyncio
    async def test_run_custom_benchmark(self):
        """Test running custom benchmark with provided files."""
        runner = BenchmarkRunner()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files
            test_files = []
            for i in range(3):
                file_path = temp_path / f"test_{i}.py"
                file_path.write_text(f"# Test file {i}\nprint('hello {i}')")
                test_files.append(file_path)

            with patch(
                "adversary_mcp_server.benchmarks.benchmark_runner.LLMScanner"
            ) as mock_scanner_class:
                mock_scanner = AsyncMock()
                mock_scanner_class.return_value = mock_scanner
                mock_scanner.analyze_file.return_value = []
                mock_scanner.analyze_directory.return_value = []

                result = await runner.run_custom_benchmark(
                    "Custom Test", test_files, "Testing custom files"
                )

                assert isinstance(result, BenchmarkResult)
                assert result.name == "Custom Test"
                assert result.metadata["description"] == "Testing custom files"
                assert result.metadata["custom_benchmark"]

    @pytest.mark.asyncio
    async def test_benchmark_error_handling(self):
        """Test benchmark error handling."""
        runner = BenchmarkRunner()

        with patch(
            "adversary_mcp_server.benchmarks.benchmark_runner.LLMScanner"
        ) as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner_class.return_value = mock_scanner
            mock_scanner.analyze_file.side_effect = Exception("Scanner error")

            result = await runner.run_single_benchmark("single_file")

            assert isinstance(result, BenchmarkResult)
            assert not result.success
            assert "Scanner error" in result.error_message

    @pytest.mark.asyncio
    async def test_memory_measurement(self):
        """Test memory usage measurement during benchmarks."""
        runner = BenchmarkRunner()

        with patch(
            "adversary_mcp_server.benchmarks.benchmark_runner.LLMScanner"
        ) as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner_class.return_value = mock_scanner
            mock_scanner.analyze_file.return_value = []

            result = await runner.run_single_benchmark("single_file")

            assert result.memory_peak_mb >= 0
            # Memory measurement should be reasonable (not negative or extremely large)
            assert result.memory_peak_mb < 10000  # Less than 10GB
