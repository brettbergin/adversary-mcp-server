"""Tests for ValidationCoordinator."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from adversary_mcp_server.application.coordination.validation_coordinator import (
    ValidationCoordinator,
)
from adversary_mcp_server.scanner.types import Severity, ThreatMatch


@pytest.fixture
def mock_validator():
    """Create a mock validator."""
    validator = Mock()
    validator.validate_findings = Mock()
    validator.get_validation_stats = Mock()
    return validator


@pytest.fixture
def validation_coordinator(mock_validator):
    """Create a ValidationCoordinator instance."""
    return ValidationCoordinator(validator=mock_validator)


@pytest.fixture
def sample_threats():
    """Create sample threats for testing."""
    return [
        ThreatMatch(
            rule_id="sql-injection-1",
            rule_name="SQL Injection Detection",
            description="SQL injection vulnerability",
            category="sql-injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            column_number=5,
            code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
            confidence=0.9,
        ),
        ThreatMatch(
            rule_id="xss-1",
            rule_name="XSS Detection",
            description="XSS vulnerability",
            category="xss",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=25,
            column_number=10,
            code_snippet="document.innerHTML = userInput",
            confidence=0.7,
        ),
    ]


@pytest.fixture
def sample_validation_results():
    """Create sample validation results."""
    return {
        "threat-1": Mock(
            is_legitimate=True,
            confidence=0.9,
            validation_error=False,
        ),
        "threat-2": Mock(
            is_legitimate=False,
            confidence=0.3,
            validation_error=False,
        ),
        "threat-3": Mock(
            is_legitimate=True,
            confidence=0.85,
            validation_error=True,
        ),
    }


class TestValidationCoordinator:
    """Test ValidationCoordinator functionality."""

    def test_init_with_validator(self, mock_validator):
        """Test initialization with validator."""
        coordinator = ValidationCoordinator(validator=mock_validator)
        assert coordinator.validator == mock_validator

    def test_init_without_validator(self):
        """Test initialization without validator."""
        coordinator = ValidationCoordinator()
        assert coordinator.validator is None

    def test_should_validate_all_conditions_met(
        self, validation_coordinator, sample_threats
    ):
        """Test should_validate when all conditions are met."""
        result = validation_coordinator.should_validate(
            use_validation=True,
            enable_llm_validation=True,
            threats=sample_threats,
        )
        assert result is True

    def test_should_validate_use_validation_false(
        self, validation_coordinator, sample_threats
    ):
        """Test should_validate when use_validation is False."""
        result = validation_coordinator.should_validate(
            use_validation=False,
            enable_llm_validation=True,
            threats=sample_threats,
        )
        assert result is False

    def test_should_validate_enable_llm_validation_false(
        self, validation_coordinator, sample_threats
    ):
        """Test should_validate when enable_llm_validation is False."""
        result = validation_coordinator.should_validate(
            use_validation=True,
            enable_llm_validation=False,
            threats=sample_threats,
        )
        assert result is False

    def test_should_validate_no_validator(self, sample_threats):
        """Test should_validate when no validator is available."""
        coordinator = ValidationCoordinator(validator=None)
        result = coordinator.should_validate(
            use_validation=True,
            enable_llm_validation=True,
            threats=sample_threats,
        )
        assert result is False

    def test_should_validate_no_threats(self, validation_coordinator):
        """Test should_validate when no threats are provided."""
        result = validation_coordinator.should_validate(
            use_validation=True,
            enable_llm_validation=True,
            threats=[],
        )
        assert result is False

    def test_validate_findings_success(
        self, validation_coordinator, sample_threats, mock_validator
    ):
        """Test successful findings validation."""
        # Setup mock validator
        expected_results = {"threat-1": Mock(), "threat-2": Mock()}
        mock_validator.validate_findings.return_value = expected_results

        result = validation_coordinator.validate_findings(
            findings=sample_threats,
            file_content="test content",
            file_path=Path("test.py"),
            preview_size=1000,
        )

        assert result == expected_results
        mock_validator.validate_findings.assert_called_once()
        call_args = mock_validator.validate_findings.call_args
        assert call_args[1]["findings"] == sample_threats
        assert call_args[1]["source_code"] == "test content"
        assert call_args[1]["file_path"] == str(Path("test.py"))

    def test_validate_findings_no_validator(self, sample_threats):
        """Test validate_findings when no validator is available."""
        coordinator = ValidationCoordinator(validator=None)

        with pytest.raises(ValueError, match="No validator available"):
            coordinator.validate_findings(findings=sample_threats)

    def test_validate_findings_empty_findings(self, validation_coordinator):
        """Test validate_findings with empty findings list."""
        result = validation_coordinator.validate_findings(findings=[])
        assert result == {}

    def test_validate_findings_with_preview_size(
        self, validation_coordinator, sample_threats, mock_validator
    ):
        """Test validate_findings with content preview size limit."""
        mock_validator.validate_findings.return_value = {}
        long_content = "a" * 2000

        validation_coordinator.validate_findings(
            findings=sample_threats,
            file_content=long_content,
            preview_size=1000,
        )

        call_args = mock_validator.validate_findings.call_args
        assert len(call_args[1]["source_code"]) == 1000
        assert call_args[1]["source_code"] == "a" * 1000

    def test_validate_findings_validation_error(
        self, validation_coordinator, sample_threats, mock_validator
    ):
        """Test validate_findings when validation raises an error."""
        mock_validator.validate_findings.side_effect = Exception("Validation failed")

        with pytest.raises(Exception, match="Validation failed"):
            validation_coordinator.validate_findings(findings=sample_threats)

    def test_filter_false_positives_no_validation_results(
        self, validation_coordinator, sample_threats
    ):
        """Test filter_false_positives with no validation results."""
        result = validation_coordinator.filter_false_positives(
            threats=sample_threats,
            validation_results={},
        )
        assert result == sample_threats

    def test_filter_false_positives_no_threats(self, validation_coordinator):
        """Test filter_false_positives with no threats."""
        result = validation_coordinator.filter_false_positives(
            threats=[],
            validation_results={"threat-1": Mock()},
        )
        assert result == []

    def test_filter_false_positives_with_filtering(
        self, validation_coordinator, sample_threats
    ):
        """Test filter_false_positives with actual filtering."""
        # Create threats with IDs
        threats = []
        for i, threat in enumerate(sample_threats):
            threat.id = f"threat-{i+1}"
            threats.append(threat)

        # Create validation results
        validation_results = {
            "threat-1": Mock(is_legitimate=True, confidence=0.9),  # Keep
            "threat-2": Mock(is_legitimate=False, confidence=0.3),  # Filter
        }

        result = validation_coordinator.filter_false_positives(
            threats=threats,
            validation_results=validation_results,
            confidence_threshold=0.7,
        )

        assert len(result) == 1
        assert result[0].id == "threat-1"

    def test_filter_false_positives_confidence_threshold(
        self, validation_coordinator, sample_threats
    ):
        """Test filter_false_positives with confidence threshold."""
        # Create threat with ID
        threat = sample_threats[0]
        threat.id = "threat-1"

        validation_results = {
            "threat-1": Mock(is_legitimate=True, confidence=0.6),  # Below threshold
        }

        result = validation_coordinator.filter_false_positives(
            threats=[threat],
            validation_results=validation_results,
            confidence_threshold=0.7,
        )

        assert len(result) == 0  # Filtered due to low confidence

    def test_filter_false_positives_no_validation_for_threat(
        self, validation_coordinator, sample_threats
    ):
        """Test filter_false_positives when no validation exists for a threat."""
        threat = sample_threats[0]
        threat.id = "threat-1"

        result = validation_coordinator.filter_false_positives(
            threats=[threat],
            validation_results={},  # No validation for this threat
            confidence_threshold=0.7,
        )

        assert len(result) == 1  # Keep threat without validation
        assert result[0] == threat

    def test_build_validation_metadata_success(
        self, validation_coordinator, mock_validator, sample_validation_results
    ):
        """Test build_validation_metadata for successful validation."""
        mock_validator.get_validation_stats.return_value = {"test": "stats"}

        metadata = validation_coordinator.build_validation_metadata(
            use_validation=True,
            enable_llm_validation=True,
            validation_results=sample_validation_results,
        )

        assert metadata["llm_validation_success"] is True
        assert metadata["llm_validation_stats"] == {"test": "stats"}
        mock_validator.get_validation_stats.assert_called_once_with(
            sample_validation_results
        )

    def test_build_validation_metadata_with_error(
        self, validation_coordinator, sample_validation_results
    ):
        """Test build_validation_metadata with validation error."""
        metadata = validation_coordinator.build_validation_metadata(
            use_validation=True,
            enable_llm_validation=True,
            validation_results=sample_validation_results,
            validation_error="Test error",
        )

        assert metadata["llm_validation_success"] is False
        assert metadata["llm_validation_error"] == "Test error"

    def test_build_validation_metadata_disabled(self, validation_coordinator):
        """Test build_validation_metadata when validation is disabled."""
        metadata = validation_coordinator.build_validation_metadata(
            use_validation=False,
            enable_llm_validation=True,
            validation_results={},
        )

        assert metadata["llm_validation_success"] is False
        assert metadata["llm_validation_reason"] == "disabled"

    def test_build_validation_metadata_not_available(self, sample_validation_results):
        """Test build_validation_metadata when validator is not available."""
        coordinator = ValidationCoordinator(validator=None)

        metadata = coordinator.build_validation_metadata(
            use_validation=True,
            enable_llm_validation=True,
            validation_results={},
        )

        assert metadata["llm_validation_success"] is False
        assert metadata["llm_validation_reason"] == "not_available"

    def test_get_validation_stats_empty_results(self, validation_coordinator):
        """Test get_validation_stats with empty results."""
        stats = validation_coordinator.get_validation_stats({})

        assert stats["total_findings_reviewed"] == 0
        assert stats["legitimate_findings"] == 0
        assert stats["false_positives_filtered"] == 0
        assert stats["false_positive_rate"] == 0.0
        assert stats["average_confidence"] == 0.0
        assert stats["validation_errors"] == 0

    def test_get_validation_stats_with_results(
        self, validation_coordinator, sample_validation_results
    ):
        """Test get_validation_stats with actual results."""
        stats = validation_coordinator.get_validation_stats(sample_validation_results)

        assert stats["total_findings_reviewed"] == 3
        assert stats["legitimate_findings"] == 2  # threat-1 and threat-3
        assert stats["false_positives_filtered"] == 1  # threat-2
        assert stats["false_positive_rate"] == pytest.approx(1 / 3, rel=1e-2)
        assert stats["average_confidence"] == pytest.approx(
            0.683, rel=1e-2
        )  # (0.9 + 0.3 + 0.85) / 3
        assert stats["validation_errors"] == 1  # threat-3

    def test_detect_language_python(self, validation_coordinator):
        """Test language detection for Python files."""
        result = validation_coordinator._detect_language(Path("test.py"))
        assert result == "python"

    def test_detect_language_javascript(self, validation_coordinator):
        """Test language detection for JavaScript files."""
        result = validation_coordinator._detect_language(Path("test.js"))
        assert result == "javascript"

    def test_detect_language_unknown(self, validation_coordinator):
        """Test language detection for unknown file types."""
        result = validation_coordinator._detect_language(Path("test.unknown"))
        assert result is None

    def test_detect_language_no_path(self, validation_coordinator):
        """Test language detection with no file path."""
        result = validation_coordinator._detect_language(None)
        assert result is None


class TestValidationCoordinatorEdgeCases:
    """Test edge cases and error conditions."""

    def test_filter_false_positives_missing_attributes(
        self, validation_coordinator, sample_threats
    ):
        """Test filter_false_positives with validation results missing attributes."""
        threat = sample_threats[0]
        threat.id = "threat-1"

        # Mock validation result without standard attributes
        validation_mock = Mock()
        del validation_mock.is_legitimate  # Remove attribute
        del validation_mock.confidence  # Remove attribute

        validation_results = {"threat-1": validation_mock}

        result = validation_coordinator.filter_false_positives(
            threats=[threat],
            validation_results=validation_results,
        )

        # Should keep threat due to default values (is_legitimate=True, confidence=1.0)
        assert len(result) == 1
        assert result[0] == threat

    def test_get_validation_stats_missing_attributes(self, validation_coordinator):
        """Test get_validation_stats with results missing attributes."""
        # Create mock validation results without standard attributes
        validation_mock1 = Mock()
        validation_mock2 = Mock()
        del validation_mock1.is_legitimate
        del validation_mock1.confidence
        del validation_mock1.validation_error
        del validation_mock2.is_legitimate
        del validation_mock2.confidence
        del validation_mock2.validation_error

        validation_results = {
            "threat-1": validation_mock1,
            "threat-2": validation_mock2,
        }

        stats = validation_coordinator.get_validation_stats(validation_results)

        # Should use default values
        assert stats["total_findings_reviewed"] == 2
        assert stats["legitimate_findings"] == 2  # Default is_legitimate=True
        assert stats["false_positives_filtered"] == 0
        assert stats["average_confidence"] == 1.0  # Default confidence=1.0
        assert stats["validation_errors"] == 0  # Default validation_error=False

    def test_validate_findings_none_file_content(
        self, validation_coordinator, sample_threats, mock_validator
    ):
        """Test validate_findings with None file content."""
        mock_validator.validate_findings.return_value = {}

        validation_coordinator.validate_findings(
            findings=sample_threats,
            file_content=None,
            file_path=Path("test.py"),
        )

        call_args = mock_validator.validate_findings.call_args
        assert call_args[1]["source_code"] == ""
        assert call_args[1]["file_path"] == str(Path("test.py"))

    def test_language_detection_case_insensitive(self, validation_coordinator):
        """Test that language detection is case insensitive."""
        result = validation_coordinator._detect_language(Path("TEST.PY"))
        assert result == "python"

    def test_build_validation_metadata_no_validator_with_results(
        self, sample_validation_results
    ):
        """Test build_validation_metadata without validator but with results."""
        coordinator = ValidationCoordinator(validator=None)

        metadata = coordinator.build_validation_metadata(
            use_validation=True,
            enable_llm_validation=True,
            validation_results=sample_validation_results,
        )

        # Should still mark as success even without validator for stats
        assert metadata["llm_validation_success"] is True
        assert "llm_validation_stats" not in metadata  # No stats without validator
