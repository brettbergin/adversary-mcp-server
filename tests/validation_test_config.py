"""Test configuration for validation regression tests.

This module provides pytest markers and configurations specifically
for validation regression testing.
"""


def pytest_configure(config):
    """Configure pytest markers for validation tests."""
    config.addinivalue_line(
        "markers",
        "validation_regression: Tests that prevent validation functionality regression",
    )
    config.addinivalue_line(
        "markers", "validation_symmetry: Tests that ensure CLI/MCP validation symmetry"
    )
    config.addinivalue_line(
        "markers", "validation_critical: Critical validation tests that must pass"
    )


# Test collection patterns for validation tests
VALIDATION_TEST_PATTERNS = [
    "tests/scanner/test_validation_regression.py",
    "tests/integration/test_validation_symmetry.py",
    "tests/scanner/test_llm_validator.py",
]

# Critical test methods that must always pass
CRITICAL_VALIDATION_TESTS = [
    "test_directory_scan_validation_enabled_with_threats",
    "test_file_scan_validation_enabled_with_threats",
    "test_directory_scan_validation_parameter_regression",
    "test_validation_parameter_propagation",
]


def run_validation_regression_tests():
    """Run validation regression test suite.

    This function can be called from CI/CD pipelines or development
    scripts to ensure validation functionality remains intact.
    """
    import subprocess
    import sys

    print("🔍 Running validation regression tests...")

    # Run regression tests
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/scanner/test_validation_regression.py",
        "tests/integration/test_validation_symmetry.py",
        "-v",
        "--tb=short",
        "-m",
        "not slow",  # Skip slow integration tests by default
    ]

    result = subprocess.run(cmd)

    if result.returncode == 0:
        print("✅ All validation regression tests passed!")
    else:
        print("❌ Validation regression tests failed!")
        sys.exit(1)

    return result.returncode == 0


def run_critical_validation_tests():
    """Run only the most critical validation tests.

    This is a fast subset of tests that can be run frequently
    during development.
    """
    import subprocess
    import sys

    print("🚨 Running critical validation tests...")

    # Build pytest command with specific test methods
    test_patterns = []
    for pattern in VALIDATION_TEST_PATTERNS:
        for test_name in CRITICAL_VALIDATION_TESTS:
            test_patterns.extend(["-k", test_name])

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/scanner/test_validation_regression.py",
        "-v",
        "--tb=short",
        *test_patterns,
    ]

    result = subprocess.run(cmd)
    return result.returncode == 0


if __name__ == "__main__":
    """Allow running validation tests directly."""
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--critical":
        success = run_critical_validation_tests()
    else:
        success = run_validation_regression_tests()

    sys.exit(0 if success else 1)
