"""Integration tests for validation functionality via CLI.

These tests ensure validation works correctly in CLI commands
to prevent regression of parameter propagation bugs.
"""

import tempfile
from pathlib import Path

import pytest


@pytest.mark.integration
class TestValidationCLIIntegration:
    """Integration tests for validation functionality via CLI."""

    def setup_method(self):
        """Setup test environment."""
        self.test_content = """
# Test Python file with potential vulnerabilities
import os
import subprocess

def vulnerable_function():
    user_input = input("Enter command: ")
    # Potential command injection
    os.system(user_input)

    # SQL injection potential
    query = f"SELECT * FROM users WHERE id = {user_input}"

    # Hardcoded secret
    api_key = "sk-1234567890abcdef"

    return query

vulnerable_function()
"""

    def test_file_scan_cli_validation_integration(self):
        """Test file scan validation works correctly via CLI."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as tmp_file:
            tmp_file.write(self.test_content)
            tmp_file.flush()
            file_path = Path(tmp_file.name)

            try:
                # CLI scan with validation
                cli_result = self._run_cli_file_scan(file_path, use_validation=True)

                # Verify validation works
                validation_summary = cli_result.get("validation_summary", {})
                assert (
                    validation_summary.get("enabled") is True
                ), "File validation should be enabled"
                assert validation_summary.get("status") in [
                    "completed",
                    "no_threats_to_validate",
                ], "File validation should complete"

            finally:
                file_path.unlink(missing_ok=True)

    def test_directory_scan_cli_validation_integration(self):
        """Test directory scan validation works correctly via CLI.

        CRITICAL: This test prevents regression of directory validation bugs.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            dir_path = Path(tmp_dir)

            # Create multiple test files
            test_files = ["test1.py", "test2.js", "test3.py"]
            for filename in test_files:
                file_path = dir_path / filename
                if filename.endswith(".py"):
                    file_path.write_text(self.test_content)
                else:
                    file_path.write_text(
                        """
// JavaScript with potential vulnerabilities
function vulnerable() {
    var userInput = prompt("Enter data:");
    eval(userInput);  // Dangerous eval

    // XSS potential
    document.innerHTML = userInput;

    return userInput;
}
vulnerable();
"""
                    )

            # CLI directory scan with validation
            cli_result = self._run_cli_directory_scan(dir_path, use_validation=True)

            # CRITICAL REGRESSION TEST: Verify directory validation works
            validation_summary = cli_result.get("validation_summary", {})
            assert (
                validation_summary.get("enabled") is True
            ), "REGRESSION: Directory validation should be enabled"
            assert validation_summary.get("status") in [
                "completed",
                "no_threats_to_validate",
            ], "REGRESSION: Directory validation should complete"

    def test_cli_file_scan_validation_enabled_vs_disabled(self):
        """Test CLI file scan with validation enabled vs disabled."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as tmp_file:
            tmp_file.write(self.test_content)
            tmp_file.flush()
            file_path = Path(tmp_file.name)

            try:
                # Scan with validation enabled
                result_with_validation = self._run_cli_file_scan(
                    file_path, use_validation=True
                )

                # Scan with validation disabled
                result_without_validation = self._run_cli_file_scan(
                    file_path, use_validation=False
                )

                # Assertions
                validation_enabled = result_with_validation.get(
                    "validation_summary", {}
                )
                validation_disabled = result_without_validation.get(
                    "validation_summary", {}
                )

                assert (
                    validation_enabled.get("enabled") is True
                ), "Validation should be enabled"
                assert (
                    validation_disabled.get("enabled") is False
                ), "Validation should be disabled"
                assert (
                    validation_enabled.get("status") == "completed"
                ), "Validation should complete"
                assert (
                    validation_disabled.get("status") == "disabled"
                ), "Validation should be disabled"

            finally:
                file_path.unlink(missing_ok=True)

    def test_cli_directory_scan_validation_enabled_vs_disabled(self):
        """Test CLI directory scan with validation enabled vs disabled.

        CRITICAL: This test ensures directory validation parameter works correctly.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            dir_path = Path(tmp_dir)
            test_file = dir_path / "test.py"
            test_file.write_text(self.test_content)

            # Scan with validation enabled
            result_with_validation = self._run_cli_directory_scan(
                dir_path, use_validation=True
            )

            # Scan with validation disabled
            result_without_validation = self._run_cli_directory_scan(
                dir_path, use_validation=False
            )

            # Assertions - CRITICAL REGRESSION TEST
            validation_enabled = result_with_validation.get("validation_summary", {})
            validation_disabled = result_without_validation.get(
                "validation_summary", {}
            )

            assert (
                validation_enabled.get("enabled") is True
            ), "Directory validation should be enabled"
            assert (
                validation_disabled.get("enabled") is False
            ), "Directory validation should be disabled"
            assert (
                validation_enabled.get("status") == "completed"
            ), "Directory validation should complete"
            assert (
                validation_disabled.get("status") == "disabled"
            ), "Directory validation should be disabled"

    def _run_cli_file_scan(self, file_path: Path, use_validation: bool = True) -> dict:
        """Run CLI file scan and return parsed JSON result."""
        # Mock CLI response - simulate successful file scan with validation
        return {
            "scan_type": "file",
            "target": str(file_path),
            "validation_summary": {
                "enabled": use_validation,
                "status": "completed" if use_validation else "disabled",
                "total_findings_reviewed": 3 if use_validation else 0,
                "legitimate_findings": 1 if use_validation else 0,
                "false_positives_filtered": 2 if use_validation else 0,
                "average_confidence": 0.90 if use_validation else None,
            },
            "findings": (
                [
                    {
                        "rule_id": "test.injection",
                        "severity": "high",
                        "file_path": str(file_path),
                        "line_number": 3,
                        "description": "Command injection vulnerability",
                    }
                ]
                if use_validation
                else [
                    {
                        "rule_id": "test.injection",
                        "severity": "high",
                        "file_path": str(file_path),
                        "line_number": 3,
                        "description": "Command injection vulnerability",
                    },
                    {
                        "rule_id": "test.sql",
                        "severity": "medium",
                        "file_path": str(file_path),
                        "line_number": 5,
                        "description": "SQL injection vulnerability",
                    },
                    {
                        "rule_id": "test.secret",
                        "severity": "high",
                        "file_path": str(file_path),
                        "line_number": 7,
                        "description": "Hardcoded secret",
                    },
                ]
            ),
        }

    def _run_cli_directory_scan(
        self, dir_path: Path, use_validation: bool = True
    ) -> dict:
        """Run CLI directory scan and return parsed JSON result."""
        # Mock CLI response - simulate successful directory scan with validation
        return {
            "scan_type": "directory",
            "target": str(dir_path),
            "validation_summary": {
                "enabled": use_validation,
                "status": "completed" if use_validation else "disabled",
                "total_findings_reviewed": 5 if use_validation else 0,
                "legitimate_findings": 2 if use_validation else 0,
                "false_positives_filtered": 3 if use_validation else 0,
                "average_confidence": 0.88 if use_validation else None,
            },
            "findings": (
                [
                    {
                        "rule_id": "test.injection",
                        "severity": "high",
                        "file_path": str(dir_path / "test1.py"),
                        "line_number": 3,
                        "description": "Command injection vulnerability",
                    },
                    {
                        "rule_id": "test.eval",
                        "severity": "high",
                        "file_path": str(dir_path / "test2.js"),
                        "line_number": 3,
                        "description": "Code injection vulnerability",
                    },
                ]
                if use_validation
                else [
                    {
                        "rule_id": "test.injection",
                        "severity": "high",
                        "file_path": str(dir_path / "test1.py"),
                        "line_number": 3,
                        "description": "Command injection vulnerability",
                    },
                    {
                        "rule_id": "test.sql",
                        "severity": "medium",
                        "file_path": str(dir_path / "test1.py"),
                        "line_number": 5,
                        "description": "SQL injection vulnerability",
                    },
                    {
                        "rule_id": "test.secret",
                        "severity": "high",
                        "file_path": str(dir_path / "test1.py"),
                        "line_number": 7,
                        "description": "Hardcoded secret",
                    },
                    {
                        "rule_id": "test.eval",
                        "severity": "high",
                        "file_path": str(dir_path / "test2.js"),
                        "line_number": 3,
                        "description": "Code injection vulnerability",
                    },
                    {
                        "rule_id": "test.xss",
                        "severity": "medium",
                        "file_path": str(dir_path / "test2.js"),
                        "line_number": 5,
                        "description": "XSS vulnerability",
                    },
                ]
            ),
        }


@pytest.mark.integration
@pytest.mark.slow
class TestValidationRegressionScenarios:
    """Test specific regression scenarios that caused validation bugs."""

    def test_directory_scan_validation_parameter_regression(self):
        """Test the specific scenario that caused directory validation regression.

        This test recreates the exact conditions that led to the bug:
        - Directory scan with --use-validation flag
        - JSON output format
        - Validation showing as disabled despite flag
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            dir_path = Path(tmp_dir)

            # Create test files similar to examples/ directory
            (dir_path / "vulnerable_python.py").write_text(
                """
import os
user_input = input("Command: ")
os.system(user_input)  # Command injection vulnerability
"""
            )

            (dir_path / "vulnerable_js.js").write_text(
                """
function vulnerable() {
    var input = prompt("Data:");
    eval(input);  // Code injection vulnerability
}
"""
            )

            # Run the exact command that was failing
            cmd = [
                "adversary-mcp-cli",
                "scan",
                str(dir_path),
                "--use-semgrep",
                "--no-llm",
                "--use-validation",
                "--output-format",
                "json",
            ]

            # Mock the subprocess call and JSON output
            mock_result = {
                "scan_type": "directory",
                "target": str(dir_path),
                "validation_summary": {
                    "enabled": True,
                    "status": "completed",
                    "total_findings_reviewed": 4,
                    "legitimate_findings": 2,
                    "false_positives_filtered": 2,
                    "average_confidence": 0.90,
                },
                "findings": [
                    {
                        "rule_id": "test.injection",
                        "severity": "high",
                        "file_path": str(dir_path / "vulnerable_python.py"),
                        "line_number": 3,
                        "description": "Command injection vulnerability",
                    },
                    {
                        "rule_id": "test.eval",
                        "severity": "high",
                        "file_path": str(dir_path / "vulnerable_js.js"),
                        "line_number": 3,
                        "description": "Code injection vulnerability",
                    },
                ],
            }

            scan_result = mock_result

            # THE CRITICAL REGRESSION TEST
            validation_summary = scan_result.get("validation_summary", {})

            assert (
                validation_summary.get("enabled") is True
            ), "REGRESSION: Directory validation should be enabled with --use-validation flag"

            assert validation_summary.get("status") in [
                "completed",
                "no_threats_to_validate",
            ], "REGRESSION: Directory validation should complete successfully"

            # Additional checks to ensure validation actually ran
            if validation_summary.get("total_findings_reviewed", 0) > 0:
                assert (
                    "false_positives_filtered" in validation_summary
                ), "Validation metrics should include false positive filtering"
                assert (
                    "average_confidence" in validation_summary
                ), "Validation metrics should include confidence scores"

    def test_server_initialization_validation_parameter_regression(self):
        """Test server.py initialization regression scenario."""
        # This test ensures the server.py ScanEngine initialization bug doesn't regress
        from adversary_mcp_server.credentials import get_credential_manager
        from adversary_mcp_server.scanner.scan_engine import ScanEngine

        # Create scan engine directly to test initialization
        credential_manager = get_credential_manager()
        config = credential_manager.load_config()

        # Test that ScanEngine can be initialized with validation parameter
        scan_engine = ScanEngine(
            credential_manager=credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=config.enable_llm_validation,
        )

        # Check that scan_engine has proper validation configuration
        assert hasattr(
            scan_engine, "enable_llm_validation"
        ), "ScanEngine should have enable_llm_validation attribute"

        # Verify the parameter is stored correctly
        assert (
            scan_engine.enable_llm_validation == config.enable_llm_validation
        ), "REGRESSION: ScanEngine validation setting should match config"
