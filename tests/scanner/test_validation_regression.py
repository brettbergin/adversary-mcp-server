"""Regression tests for validation functionality.

These tests ensure validation works correctly across all scan types
and prevent regression of critical validation bugs.
"""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.config import SecurityConfig
from adversary_mcp_server.scanner.llm_validator import ValidationResult
from adversary_mcp_server.scanner.scan_engine import ScanEngine
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


def create_mock_credential_manager_with_validation():
    """Create a mock credential manager with validation enabled."""
    mock_cm = Mock()
    mock_config = SecurityConfig()
    mock_config.enable_semgrep_scanning = True
    mock_config.enable_llm_analysis = False  # Disable LLM analysis for focused testing
    mock_config.enable_llm_validation = True  # Enable validation
    mock_config.semgrep_config = None
    mock_config.semgrep_rules = None
    mock_config.max_file_size_mb = 10
    mock_config.llm_provider = "anthropic"
    mock_config.llm_api_key = "test-key"
    mock_config.llm_model = "claude-3-sonnet"
    mock_config.enable_caching = False
    mock_config.cache_max_size_mb = 100
    mock_config.cache_max_age_hours = 24
    mock_config.cache_llm_responses = False
    mock_cm.load_config.return_value = mock_config
    return mock_cm


def create_fast_scan_engine(mock_cm, enable_llm_validation=True):
    """Create ScanEngine with minimal dependencies for fast testing."""
    with patch("adversary_mcp_server.scanner.scan_engine.CacheManager"):
        return ScanEngine(
            credential_manager=mock_cm,
            metrics_orchestrator=None,  # Skip telemetry for speed
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=enable_llm_validation,
        )


def create_sample_threats(count=3, file_path="/test/file.py"):
    """Create sample ThreatMatch objects for testing."""
    categories = [
        Category.INJECTION,
        Category.XSS,
        Category.RCE,
        Category.SECRETS,
        Category.MISC,
    ]
    return [
        ThreatMatch(
            rule_id=f"test-rule-{i}",
            rule_name=f"Test Rule {i}",
            description=f"Test threat {i}",
            category=categories[i % len(categories)],
            severity=Severity.HIGH,
            file_path=file_path,
            line_number=10 + i,
            code_snippet=f"test_code_{i} = 'vulnerable'",
            uuid=f"threat-uuid-{i}",
        )
        for i in range(count)
    ]


def create_validation_results(threats, legitimate_count=1):
    """Create ValidationResult objects for given threats."""
    results = {}
    for i, threat in enumerate(threats):
        is_legitimate = i < legitimate_count
        results[threat.uuid] = ValidationResult(
            finding_uuid=threat.uuid,
            is_legitimate=is_legitimate,
            confidence=0.85 if is_legitimate else 0.95,
            reasoning=f"Validation reasoning for {threat.uuid}",
            exploitation_vector="Test exploitation vector" if is_legitimate else None,
            exploit_poc=["test poc"] if is_legitimate else None,
            remediation_advice="Test remediation advice",
            severity_adjustment=threat.severity,
            validation_error=None,
        )
    return results


class TestValidationRegression:
    """Regression tests for validation functionality."""

    @pytest.mark.asyncio
    async def test_file_scan_validation_enabled_with_threats(self):
        """Test file scan with validation enabled processes threats correctly.

        This test ensures file scanning validation works as expected.
        """
        mock_cm = create_mock_credential_manager_with_validation()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_cls,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_cls,
            patch(
                "adversary_mcp_server.scanner.scan_engine.StreamingFileReader"
            ) as mock_reader_cls,
            tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False
            ) as tmp_file,
        ):
            # Write test content
            tmp_file.write("test_variable = 'vulnerable_code'")
            tmp_file.flush()
            file_path = Path(tmp_file.name)

            try:
                # Setup mock Semgrep scanner
                mock_semgrep = Mock()
                mock_semgrep.is_available.return_value = True
                mock_semgrep.get_status.return_value = {
                    "available": True,
                    "version": "1.0.0",
                    "configuration": "auto",
                }
                mock_semgrep_cls.return_value = mock_semgrep

                # Create sample threats
                sample_threats = create_sample_threats(
                    count=3, file_path=str(file_path)
                )

                # Mock scan_file as async function
                async def mock_scan_file(*args, **kwargs):
                    return sample_threats

                mock_semgrep.scan_file = mock_scan_file

                # Setup mock LLM validator
                mock_validator = Mock()
                mock_validator.is_fully_functional.return_value = True
                mock_validator_cls.return_value = mock_validator

                # Setup mock StreamingFileReader
                mock_reader = Mock()

                async def mock_read_file_async(file_path):
                    # Return the test content as chunks
                    content = "test_variable = 'vulnerable_code'"
                    for chunk in [content]:  # Single chunk for simplicity
                        yield chunk

                mock_reader.read_file_async = mock_read_file_async
                mock_reader_cls.return_value = mock_reader

                # Mock validation results (1 legitimate, 2 false positives)
                validation_results = create_validation_results(
                    sample_threats, legitimate_count=1
                )
                mock_validator._validate_findings_async = AsyncMock(
                    return_value=validation_results
                )
                mock_validator.get_validation_stats.return_value = {
                    "total_findings": 3,
                    "legitimate_findings": 1,
                    "false_positives": 2,
                    "average_confidence": 0.88,
                }

                # Mock filter methods to return filtered results
                legitimate_threats = [
                    sample_threats[0]
                ]  # Only first threat is legitimate
                mock_validator.filter_false_positives.return_value = legitimate_threats

                # Create fast ScanEngine for testing
                scan_engine = create_fast_scan_engine(
                    mock_cm, enable_llm_validation=True
                )

                result = await scan_engine.scan_file(
                    file_path=file_path,
                    use_llm=False,
                    use_semgrep=True,
                    use_validation=True,
                )

                # Debug final result
                print(
                    f"DEBUG: Final result - semgrep_threats: {len(result.semgrep_threats)}"
                )
                print(
                    f"DEBUG: Final result - validation_results: {len(result.validation_results) if result.validation_results else 0}"
                )
                print(
                    f"DEBUG: Final result - validation_success: {result.scan_metadata.get('llm_validation_success')}"
                )

                # Assertions
                assert result is not None
                assert (
                    len(result.semgrep_threats) == 1
                )  # Filtered to 1 legitimate threat
                assert result.validation_results is not None
                assert (
                    len(result.validation_results) == 3
                )  # All 3 threats were validated

                # Check validation metadata
                validation_summary = result.get_validation_summary()
                assert validation_summary["enabled"] is True
                assert validation_summary["status"] == "completed"
                assert validation_summary["total_findings_reviewed"] == 3
                assert validation_summary["legitimate_findings"] == 1
                assert validation_summary["false_positives_filtered"] == 2

                # Ensure validation was called
                mock_validator._validate_findings_async.assert_called_once()
                mock_validator.filter_false_positives.assert_called()

            finally:
                file_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_directory_scan_validation_enabled_with_threats(self):
        """Test directory scan with validation enabled processes threats correctly.

        This test ensures the directory scanning validation fix works correctly.
        CRITICAL: This test prevents regression of the directory validation bug.
        """
        mock_cm = create_mock_credential_manager_with_validation()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_cls,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_cls,
            tempfile.TemporaryDirectory() as tmp_dir,
        ):
            # Create test files
            dir_path = Path(tmp_dir)
            file1 = dir_path / "test1.py"
            file2 = dir_path / "test2.js"
            file1.write_text("test_variable = 'vulnerable_code'")
            file2.write_text("var test = 'vulnerable_code';")

            # Setup mock Semgrep scanner
            mock_semgrep = Mock()
            mock_semgrep.is_available.return_value = True
            mock_semgrep.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
                "configuration": "auto",
            }
            mock_semgrep_cls.return_value = mock_semgrep

            # Create sample threats across multiple files with unique UUIDs
            threats_file1 = [
                ThreatMatch(
                    rule_id=f"test-rule-file1-{i}",
                    rule_name=f"Test Rule File1 {i}",
                    description=f"Test threat file1 {i}",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path=str(file1),
                    line_number=10 + i,
                    code_snippet=f"test_code_file1_{i} = 'vulnerable'",
                    uuid=f"threat-file1-uuid-{i}",
                )
                for i in range(2)
            ]
            threats_file2 = [
                ThreatMatch(
                    rule_id=f"test-rule-file2-{i}",
                    rule_name=f"Test Rule File2 {i}",
                    description=f"Test threat file2 {i}",
                    category=Category.XSS,
                    severity=Severity.HIGH,
                    file_path=str(file2),
                    line_number=20 + i,
                    code_snippet=f"test_code_file2_{i} = 'vulnerable'",
                    uuid=f"threat-file2-uuid-{i}",
                )
                for i in range(3)
            ]
            all_threats = threats_file1 + threats_file2

            # Mock scan_directory as async function
            async def mock_scan_directory(*args, **kwargs):
                return all_threats

            mock_semgrep.scan_directory = mock_scan_directory

            # Setup mock LLM validator
            mock_validator = Mock()
            mock_validator.is_fully_functional.return_value = True
            mock_validator_cls.return_value = mock_validator

            # Mock validation results (2 legitimate, 3 false positives)
            validation_results = create_validation_results(
                all_threats, legitimate_count=2
            )
            mock_validator._validate_findings_async = AsyncMock(
                return_value=validation_results
            )
            mock_validator.get_validation_stats.return_value = {
                "total_findings": 5,
                "legitimate_findings": 2,
                "false_positives": 3,
                "average_confidence": 0.90,
            }

            # Mock filter methods to return filtered results (2 legitimate threats)
            legitimate_threats = all_threats[:2]  # First 2 threats are legitimate
            mock_validator.filter_false_positives.return_value = legitimate_threats

            # Create fast ScanEngine for testing
            scan_engine = create_fast_scan_engine(mock_cm, enable_llm_validation=True)

            results = await scan_engine.scan_directory(
                directory_path=dir_path,
                use_llm=False,
                use_semgrep=True,
                use_validation=True,
            )

            # Assertions - Focus on the critical regression test points
            assert len(results) == 1  # Directory scan returns single result
            result = results[0]

            assert result is not None
            assert result.validation_results is not None
            assert len(result.validation_results) == 5  # All 5 threats were validated

            # Check validation metadata - THIS IS THE CRITICAL REGRESSION TEST
            validation_summary = result.get_validation_summary()
            assert (
                validation_summary["enabled"] is True
            ), "REGRESSION: Directory validation should be enabled"
            assert (
                validation_summary["status"] == "completed"
            ), "REGRESSION: Directory validation should complete"
            assert validation_summary["total_findings_reviewed"] == 5

            # Ensure validation was called with directory context
            mock_validator._validate_findings_async.assert_called_once()
            call_args = mock_validator._validate_findings_async.call_args
            assert call_args[1]["findings"] == all_threats
            assert (
                "Directory scan of:" in call_args[1]["source_code"]
            )  # Directory context
            assert str(dir_path) in call_args[1]["file_path"]

            # The key regression test: validation should be called for directory scans
            mock_validator.get_validation_stats.assert_called_once()

    @pytest.mark.asyncio
    async def test_file_scan_validation_disabled_parameter(self):
        """Test file scan respects use_validation=False parameter."""
        mock_cm = create_mock_credential_manager_with_validation()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_cls,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_cls,
            tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False
            ) as tmp_file,
        ):
            tmp_file.write("test_variable = 'vulnerable_code'")
            tmp_file.flush()
            file_path = Path(tmp_file.name)

            try:
                # Setup mock Semgrep scanner
                mock_semgrep = Mock()
                mock_semgrep.is_available.return_value = True
                mock_semgrep.get_status.return_value = {
                    "available": True,
                    "version": "1.0.0",
                    "configuration": "auto",
                }
                mock_semgrep_cls.return_value = mock_semgrep

                sample_threats = create_sample_threats(
                    count=3, file_path=str(file_path)
                )

                # Mock scan_file as async function
                async def mock_scan_file(*args, **kwargs):
                    return sample_threats

                mock_semgrep.scan_file = mock_scan_file

                # Setup mock LLM validator
                mock_validator = Mock()
                mock_validator.is_fully_functional.return_value = True
                mock_validator_cls.return_value = mock_validator

                # Create fast ScanEngine for testing
                scan_engine = create_fast_scan_engine(
                    mock_cm, enable_llm_validation=True
                )

                result = await scan_engine.scan_file(
                    file_path=file_path,
                    use_llm=False,
                    use_semgrep=True,
                    use_validation=False,  # Explicitly disable validation
                )

                # Assertions
                assert result is not None
                assert len(result.semgrep_threats) == 3  # No filtering applied

                # Check validation metadata
                validation_summary = result.get_validation_summary()
                assert validation_summary["enabled"] is False
                assert validation_summary["status"] == "disabled"

                # Ensure validation was NOT called
                mock_validator._validate_findings_async.assert_not_called()

            finally:
                file_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_directory_scan_validation_disabled_parameter(self):
        """Test directory scan respects use_validation=False parameter."""
        mock_cm = create_mock_credential_manager_with_validation()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_cls,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_cls,
            tempfile.TemporaryDirectory() as tmp_dir,
        ):
            dir_path = Path(tmp_dir)
            file1 = dir_path / "test.py"
            file1.write_text("test_variable = 'vulnerable_code'")

            # Setup mocks
            mock_semgrep = Mock()
            mock_semgrep.is_available.return_value = True
            mock_semgrep.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
                "configuration": "auto",
            }
            mock_semgrep_cls.return_value = mock_semgrep

            sample_threats = create_sample_threats(count=3, file_path=str(file1))

            # Mock scan_directory as async function
            async def mock_scan_directory(*args, **kwargs):
                return sample_threats

            mock_semgrep.scan_directory = mock_scan_directory

            mock_validator = Mock()
            mock_validator.is_fully_functional.return_value = True
            mock_validator_cls.return_value = mock_validator

            # Create fast ScanEngine for testing
            scan_engine = create_fast_scan_engine(mock_cm, enable_llm_validation=True)

            results = await scan_engine.scan_directory(
                directory_path=dir_path,
                use_llm=False,
                use_semgrep=True,
                use_validation=False,  # Explicitly disable validation
            )

            # Assertions
            assert len(results) == 1
            result = results[0]

            assert result is not None
            assert len(result.semgrep_threats) == 3  # No filtering applied

            # Check validation metadata - THIS IS CRITICAL
            validation_summary = result.get_validation_summary()
            assert (
                validation_summary["enabled"] is False
            ), "Directory validation should be disabled"
            assert validation_summary["status"] == "disabled"

            # Ensure validation was NOT called
            mock_validator._validate_findings_async.assert_not_called()

    @pytest.mark.asyncio
    async def test_validation_unavailable_llm_validator_none(self):
        """Test behavior when LLM validator is unavailable (None)."""
        mock_cm = create_mock_credential_manager_with_validation()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_cls,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_cls,
            tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False
            ) as tmp_file,
        ):
            tmp_file.write("test_variable = 'vulnerable_code'")
            tmp_file.flush()
            file_path = Path(tmp_file.name)

            try:
                # Setup mock Semgrep scanner
                mock_semgrep = Mock()
                mock_semgrep.is_available.return_value = True
                mock_semgrep.get_status.return_value = {
                    "available": True,
                    "version": "1.0.0",
                    "configuration": "auto",
                }
                mock_semgrep_cls.return_value = mock_semgrep

                sample_threats = create_sample_threats(
                    count=3, file_path=str(file_path)
                )

                # Mock scan_file as async function
                async def mock_scan_file(*args, **kwargs):
                    return sample_threats

                mock_semgrep.scan_file = mock_scan_file

                # Make validator return None (unavailable)
                mock_validator_cls.return_value = None

                # Create fast ScanEngine for testing
                scan_engine = create_fast_scan_engine(
                    mock_cm, enable_llm_validation=True
                )

                result = await scan_engine.scan_file(
                    file_path=file_path,
                    use_llm=False,
                    use_semgrep=True,
                    use_validation=True,  # Request validation but it's unavailable
                )

                # Assertions
                assert result is not None
                assert len(result.semgrep_threats) == 3  # No filtering applied

                # Check validation metadata
                validation_summary = result.get_validation_summary()
                assert validation_summary["enabled"] is False
                assert validation_summary["status"] == "not_available"

            finally:
                file_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_validation_fallback_mode_behavior(self):
        """Test validation behavior when LLM client is unavailable (fallback mode)."""
        mock_cm = create_mock_credential_manager_with_validation()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_cls,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_cls,
            tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False
            ) as tmp_file,
        ):
            tmp_file.write("test_variable = 'vulnerable_code'")
            tmp_file.flush()
            file_path = Path(tmp_file.name)

            try:
                # Setup mock Semgrep scanner
                mock_semgrep = Mock()
                mock_semgrep.is_available.return_value = True
                mock_semgrep.get_status.return_value = {
                    "available": True,
                    "version": "1.0.0",
                    "configuration": "auto",
                }
                mock_semgrep_cls.return_value = mock_semgrep

                sample_threats = create_sample_threats(
                    count=3, file_path=str(file_path)
                )

                # Mock scan_file as async function
                async def mock_scan_file(*args, **kwargs):
                    return sample_threats

                mock_semgrep.scan_file = mock_scan_file

                # Setup mock LLM validator in fallback mode
                mock_validator = Mock()
                mock_validator.is_fully_functional.return_value = False  # Fallback mode
                mock_validator_cls.return_value = mock_validator

                # Mock validation results for fallback mode
                validation_results = create_validation_results(
                    sample_threats, legitimate_count=2
                )
                mock_validator._validate_findings_async = AsyncMock(
                    return_value=validation_results
                )
                mock_validator.get_validation_stats.return_value = {
                    "total_findings": 3,
                    "legitimate_findings": 2,
                    "false_positives": 1,
                    "average_confidence": 0.75,
                }
                mock_validator.filter_false_positives.return_value = sample_threats[:2]

                # Create fast ScanEngine for testing
                scan_engine = create_fast_scan_engine(
                    mock_cm, enable_llm_validation=True
                )

                result = await scan_engine.scan_file(
                    file_path=file_path,
                    use_llm=False,
                    use_semgrep=True,
                    use_validation=True,
                )

                # Assertions
                assert result is not None
                assert (
                    len(result.semgrep_threats) == 2
                )  # Filtering applied even in fallback

                # Check validation metadata shows fallback mode
                assert result.scan_metadata.get("llm_validation_mode") == "fallback"

                validation_summary = result.get_validation_summary()
                assert validation_summary["enabled"] is True
                assert validation_summary["status"] == "completed"

            finally:
                file_path.unlink(missing_ok=True)

    def test_validation_summary_calculation_accuracy(self):
        """Test that validation summary calculations are accurate."""
        # Create sample threats
        sample_threats = create_sample_threats(count=5)

        # Create validation results with mixed legitimate/false positive findings
        validation_results = {
            sample_threats[0].uuid: ValidationResult(
                finding_uuid=sample_threats[0].uuid,
                is_legitimate=True,
                confidence=0.95,
                reasoning="Legitimate threat",
            ),
            sample_threats[1].uuid: ValidationResult(
                finding_uuid=sample_threats[1].uuid,
                is_legitimate=True,
                confidence=0.88,
                reasoning="Legitimate threat",
            ),
            sample_threats[2].uuid: ValidationResult(
                finding_uuid=sample_threats[2].uuid,
                is_legitimate=False,
                confidence=0.92,
                reasoning="False positive",
            ),
            sample_threats[3].uuid: ValidationResult(
                finding_uuid=sample_threats[3].uuid,
                is_legitimate=False,
                confidence=0.85,
                reasoning="False positive",
            ),
            sample_threats[4].uuid: ValidationResult(
                finding_uuid=sample_threats[4].uuid,
                is_legitimate=True,
                confidence=0.70,
                reasoning="Low confidence legitimate",
                validation_error="Warning: Low confidence",
            ),
        }

        from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult

        result = EnhancedScanResult(
            file_path="/test/file.py",
            semgrep_threats=sample_threats,
            llm_threats=[],
            validation_results=validation_results,
            scan_metadata={"llm_validation_success": True},
        )

        validation_summary = result.get_validation_summary()

        # Assertions for accurate calculation
        assert validation_summary["enabled"] is True
        assert validation_summary["total_findings_reviewed"] == 5
        assert validation_summary["legitimate_findings"] == 3
        assert validation_summary["false_positives_filtered"] == 2
        assert validation_summary["false_positive_rate"] == 0.4  # 2/5
        assert (
            abs(validation_summary["average_confidence"] - 0.86) < 0.01
        )  # (0.95+0.88+0.92+0.85+0.70)/5
        assert validation_summary["validation_errors"] == 1  # One validation error
        assert validation_summary["status"] == "completed"


class TestValidationParameterPropagation:
    """Test validation parameter propagation from CLI/MCP to scan engine."""

    def test_scan_engine_initialization_validation_parameters(self):
        """Test ScanEngine initialization correctly uses validation parameters."""
        mock_cm = create_mock_credential_manager_with_validation()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_cls,
        ):
            # Test with validation enabled
            scan_engine = ScanEngine(
                credential_manager=mock_cm,
                enable_llm_analysis=False,
                enable_semgrep_analysis=True,
                enable_llm_validation=True,
            )

            # Assertions
            assert scan_engine.enable_llm_validation is True
            mock_validator_cls.assert_called_once()  # Validator should be initialized

    def test_scan_engine_initialization_validation_disabled(self):
        """Test ScanEngine initialization with validation disabled."""
        mock_cm = create_mock_credential_manager_with_validation()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_cls,
        ):
            # Test with validation disabled
            scan_engine = ScanEngine(
                credential_manager=mock_cm,
                enable_llm_analysis=False,
                enable_semgrep_analysis=True,
                enable_llm_validation=False,
            )

            # Assertions
            assert scan_engine.enable_llm_validation is False
            mock_validator_cls.assert_not_called()  # Validator should NOT be initialized
