"""Test scenarios and sample data for benchmarking."""

from pathlib import Path


class TestScenarios:
    """Generates test data and scenarios for benchmarking."""

    @staticmethod
    def create_sample_python_file(
        name: str, lines: int = 50, has_vulnerabilities: bool = True
    ) -> str:
        """Create a sample Python file with optional vulnerabilities."""
        content_parts = [
            "#!/usr/bin/env python3",
            '"""Sample Python file for benchmarking."""',
            "",
            "import os",
            "import subprocess",
            "import pickle",
            "from pathlib import Path",
            "",
        ]

        # Add some basic functions
        content_parts.extend(
            [
                "def process_data(data):",
                '    """Process some data."""',
                "    result = []",
                "    for item in data:",
                "        if item.strip():",
                "            result.append(item.lower())",
                "    return result",
                "",
            ]
        )

        if has_vulnerabilities:
            # Add some security issues for testing
            content_parts.extend(
                [
                    "# Potential security issues for testing",
                    "def unsafe_eval(user_input):",
                    "    return eval(user_input)  # Command injection vulnerability",
                    "",
                    "def unsafe_pickle(data):",
                    "    return pickle.loads(data)  # Deserialization vulnerability",
                    "",
                    "def unsafe_system(command):",
                    "    return os.system(command)  # Command injection",
                    "",
                    "# Hardcoded credentials",
                    'API_KEY = "sk-1234567890abcdef"',
                    'PASSWORD = "admin123"',
                    "",
                ]
            )

        # Fill to desired line count
        current_lines = len(content_parts)
        while current_lines < lines:
            content_parts.extend(
                [
                    f"def dummy_function_{current_lines}():",
                    f'    """Dummy function {current_lines}."""',
                    f"    return 'function_{current_lines}_result'",
                    "",
                ]
            )
            current_lines = len(content_parts)

        return "\n".join(content_parts)

    @staticmethod
    def create_sample_javascript_file(
        name: str, lines: int = 50, has_vulnerabilities: bool = True
    ) -> str:
        """Create a sample JavaScript file with optional vulnerabilities."""
        content_parts = [
            "// Sample JavaScript file for benchmarking",
            "",
            "const express = require('express');",
            "const fs = require('fs');",
            "const path = require('path');",
            "",
            "class DataProcessor {",
            "    constructor() {",
            "        this.data = [];",
            "    }",
            "",
            "    processItems(items) {",
            "        return items.filter(item => item.trim())",
            "                   .map(item => item.toLowerCase());",
            "    }",
            "}",
            "",
        ]

        if has_vulnerabilities:
            content_parts.extend(
                [
                    "// Potential security issues for testing",
                    "function unsafeEval(userInput) {",
                    "    return eval(userInput); // Code injection vulnerability",
                    "}",
                    "",
                    "function sqlQuery(userId) {",
                    "    const query = `SELECT * FROM users WHERE id = ${userId}`;",
                    "    return database.query(query); // SQL injection",
                    "}",
                    "",
                    "// Hardcoded credentials",
                    "const API_KEY = 'abc123-secret-key';",
                    "const DB_PASSWORD = 'password123';",
                    "",
                ]
            )

        # Fill to desired line count
        current_lines = len(content_parts)
        while current_lines < lines:
            content_parts.extend(
                [
                    f"function dummyFunction{current_lines}() {{",
                    f"    // Dummy function {current_lines}",
                    f"    return 'function_{current_lines}_result';",
                    "}",
                    "",
                ]
            )
            current_lines = len(content_parts)

        return "\n".join(content_parts)

    @classmethod
    def create_test_files(cls, temp_dir: Path, file_count: int = 5) -> list[Path]:
        """Create a set of test files for benchmarking."""
        files = []

        for i in range(file_count):
            # Alternate between Python and JavaScript files
            if i % 2 == 0:
                filename = f"test_file_{i}.py"
                content = cls.create_sample_python_file(
                    filename,
                    lines=50 + (i * 10),  # Varying file sizes
                    has_vulnerabilities=(
                        i % 3 != 0
                    ),  # Mix of clean and vulnerable files
                )
            else:
                filename = f"test_file_{i}.js"
                content = cls.create_sample_javascript_file(
                    filename, lines=40 + (i * 8), has_vulnerabilities=(i % 3 != 0)
                )

            file_path = temp_dir / filename
            with open(file_path, "w") as f:
                f.write(content)
            files.append(file_path)

        return files

    @classmethod
    def get_benchmark_scenarios(cls) -> dict[str, dict]:
        """Get predefined benchmark scenarios."""
        return {
            "single_file": {
                "name": "Single File Analysis",
                "description": "Baseline performance with one file",
                "file_count": 1,
                "expected_findings": 3,
            },
            "small_batch": {
                "name": "Small Batch (5 files)",
                "description": "Small batch processing test",
                "file_count": 5,
                "expected_findings": 10,
            },
            "medium_batch": {
                "name": "Medium Batch (20 files)",
                "description": "Medium batch processing test",
                "file_count": 20,
                "expected_findings": 35,
            },
            "cache_test": {
                "name": "Cache Performance Test",
                "description": "Test cache effectiveness with repeated scans",
                "file_count": 10,
                "repeat_count": 3,
                "expected_findings": 20,
            },
            "large_files": {
                "name": "Large File Processing",
                "description": "Performance with larger files",
                "file_count": 5,
                "lines_per_file": 500,
                "expected_findings": 15,
            },
        }

    @classmethod
    def create_scenario_files(cls, scenario_name: str, temp_dir: Path) -> list[Path]:
        """Create files for a specific benchmark scenario."""
        scenarios = cls.get_benchmark_scenarios()
        if scenario_name not in scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}")

        scenario = scenarios[scenario_name]
        file_count = scenario["file_count"]
        lines_per_file = scenario.get("lines_per_file", 50)

        files = []
        for i in range(file_count):
            if i % 2 == 0:
                filename = f"{scenario_name}_test_{i}.py"
                content = cls.create_sample_python_file(
                    filename, lines=lines_per_file + (i * 5), has_vulnerabilities=True
                )
            else:
                filename = f"{scenario_name}_test_{i}.js"
                content = cls.create_sample_javascript_file(
                    filename, lines=lines_per_file + (i * 3), has_vulnerabilities=True
                )

            file_path = temp_dir / filename
            with open(file_path, "w") as f:
                f.write(content)
            files.append(file_path)

        return files
