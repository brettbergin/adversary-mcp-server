"""Tests for LLM validator module."""

import json
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.scanner.llm_validator import (
    LLMValidationError,
    LLMValidator,
    ValidationPrompt,
    ValidationResult,
)
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestValidationResult:
    """Test ValidationResult class."""

    def test_validation_result_initialization(self):
        """Test ValidationResult initialization."""
        result = ValidationResult(
            finding_uuid="test-uuid",
            is_legitimate=True,
            confidence=0.9,
            reasoning="Test reasoning",
            exploitation_vector="Test vector",
            exploit_poc=["test poc"],
            remediation_advice="Test remediation",
            severity_adjustment=Severity.HIGH,
            validation_error=None,
        )

        assert result.finding_uuid == "test-uuid"
        assert result.is_legitimate is True
        assert result.confidence == 0.9
        assert result.reasoning == "Test reasoning"
        assert result.exploitation_vector == "Test vector"
        assert result.exploit_poc == ["test poc"]
        assert result.remediation_advice == "Test remediation"
        assert result.severity_adjustment == Severity.HIGH
        assert result.validation_error is None

    def test_validation_result_to_dict(self):
        """Test ValidationResult to_dict method."""
        result = ValidationResult(
            finding_uuid="test-uuid",
            is_legitimate=False,
            confidence=0.7,
            reasoning="False positive",
            severity_adjustment=Severity.LOW,
        )

        result_dict = result.to_dict()
        assert result_dict["finding_uuid"] == "test-uuid"
        assert result_dict["is_legitimate"] is False
        assert result_dict["confidence"] == 0.7
        assert result_dict["reasoning"] == "False positive"
        assert result_dict["severity_adjustment"] == "low"
        assert result_dict["exploitation_vector"] is None
        assert result_dict["exploit_poc"] is None


class TestValidationPrompt:
    """Test ValidationPrompt class."""

    def test_validation_prompt_initialization(self):
        """Test ValidationPrompt initialization."""
        findings = [
            ThreatMatch(
                rule_id="test-rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
            )
        ]

        prompt = ValidationPrompt(
            system_prompt="System prompt",
            user_prompt="User prompt",
            findings=findings,
            source_code="test code",
        )

        assert prompt.system_prompt == "System prompt"
        assert prompt.user_prompt == "User prompt"
        assert len(prompt.findings) == 1
        assert prompt.source_code == "test code"

    def test_validation_prompt_to_dict(self):
        """Test ValidationPrompt to_dict method."""
        findings = [
            ThreatMatch(
                rule_id="test-rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
            )
        ]

        prompt = ValidationPrompt(
            system_prompt="System prompt",
            user_prompt="User prompt",
            findings=findings,
            source_code="test code",
        )

        prompt_dict = prompt.to_dict()
        assert prompt_dict["system_prompt"] == "System prompt"
        assert prompt_dict["user_prompt"] == "User prompt"
        assert prompt_dict["findings_count"] == 1
        assert prompt_dict["source_code_size"] == 9


class TestLLMValidator:
    """Test LLMValidator class."""

    @pytest.fixture
    def mock_credential_manager(self):
        """Create mock credential manager."""
        mock_cm = Mock()
        mock_config = Mock()
        mock_config.exploit_safety_mode = True
        mock_cm.load_config.return_value = mock_config
        return mock_cm

    @pytest.fixture
    def validator(self, mock_credential_manager):
        """Create LLMValidator instance."""
        with patch("adversary_mcp_server.scanner.llm_validator.ExploitGenerator"):
            return LLMValidator(mock_credential_manager)

    def test_llm_validator_initialization(self, mock_credential_manager):
        """Test LLMValidator initialization."""
        with patch(
            "adversary_mcp_server.scanner.llm_validator.ExploitGenerator"
        ) as mock_exploit_gen:
            validator = LLMValidator(mock_credential_manager)

            assert validator.credential_manager == mock_credential_manager
            assert validator.config is not None
            mock_exploit_gen.assert_called_once_with(mock_credential_manager)

    def test_validate_findings_empty(self, validator):
        """Test validate_findings with empty findings list."""
        results = validator.validate_findings([], "source code", "test.py")
        assert results == {}

    def test_validate_findings_with_exploits(self, validator):
        """Test validate_findings with exploit generation."""
        findings = [
            ThreatMatch(
                rule_id="test-rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
            )
        ]

        # Mock exploit generator
        validator.exploit_generator.is_llm_available.return_value = True
        validator.exploit_generator.generate_exploits.return_value = ["test exploit"]

        results = validator.validate_findings(
            findings, "source code", "test.py", generate_exploits=True
        )

        assert len(results) == 1
        assert "test-uuid-1" in results
        assert results["test-uuid-1"].is_legitimate is True
        assert results["test-uuid-1"].confidence == 0.5
        assert results["test-uuid-1"].exploit_poc == ["test exploit"]

    def test_validate_findings_exploit_generation_failure(self, validator):
        """Test validate_findings when exploit generation fails."""
        findings = [
            ThreatMatch(
                rule_id="test-rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
            )
        ]

        # Mock exploit generator to raise exception
        validator.exploit_generator.is_llm_available.return_value = True
        validator.exploit_generator.generate_exploits.side_effect = Exception(
            "Exploit generation failed"
        )

        results = validator.validate_findings(
            findings, "source code", "test.py", generate_exploits=True
        )

        assert len(results) == 1
        assert "test-uuid-1" in results
        assert results["test-uuid-1"].exploit_poc is None

    def test_create_validation_prompt(self, validator):
        """Test create_validation_prompt method."""
        findings = [
            ThreatMatch(
                rule_id="test-rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
            )
        ]

        prompt = validator.create_validation_prompt(findings, "source code", "test.py")

        assert isinstance(prompt, ValidationPrompt)
        assert "senior security engineer" in prompt.system_prompt
        assert "test.py" in prompt.user_prompt
        assert "test-uuid-1" in prompt.user_prompt
        assert len(prompt.findings) == 1

    def test_parse_validation_response_success(self, validator):
        """Test parse_validation_response with valid JSON."""
        findings = [
            ThreatMatch(
                rule_id="test-rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
            )
        ]

        response_text = json.dumps(
            {
                "validations": [
                    {
                        "finding_uuid": "test-uuid-1",
                        "is_legitimate": True,
                        "confidence": 0.8,
                        "reasoning": "This is a real vulnerability",
                        "exploitation_vector": "SQL injection via user input",
                        "remediation_advice": "Use parameterized queries",
                        "severity_adjustment": "critical",
                    }
                ]
            }
        )

        results = validator.parse_validation_response(response_text, findings)

        assert len(results) == 1
        assert "test-uuid-1" in results
        assert results["test-uuid-1"].is_legitimate is True
        assert results["test-uuid-1"].confidence == 0.8
        assert results["test-uuid-1"].severity_adjustment == Severity.CRITICAL

    def test_parse_validation_response_empty(self, validator):
        """Test parse_validation_response with empty response."""
        findings = []
        results = validator.parse_validation_response("", findings)
        assert results == {}

    def test_parse_validation_response_invalid_json(self, validator):
        """Test parse_validation_response with invalid JSON."""
        findings = []

        with pytest.raises(LLMValidationError, match="Invalid JSON response"):
            validator.parse_validation_response("invalid json", findings)

    def test_parse_validation_response_unknown_uuid(self, validator):
        """Test parse_validation_response with unknown UUID."""
        findings = [
            ThreatMatch(
                rule_id="test-rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
            )
        ]

        response_text = json.dumps(
            {
                "validations": [
                    {
                        "finding_uuid": "unknown-uuid",
                        "is_legitimate": True,
                        "confidence": 0.8,
                    }
                ]
            }
        )

        results = validator.parse_validation_response(response_text, findings)
        assert len(results) == 0  # Unknown UUID should be skipped

    def test_filter_false_positives(self, validator):
        """Test filter_false_positives method."""
        findings = [
            ThreatMatch(
                rule_id="test-rule-1",
                rule_name="Test Rule 1",
                description="Test description 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
            ),
            ThreatMatch(
                rule_id="test-rule-2",
                rule_name="Test Rule 2",
                description="Test description 2",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=20,
                uuid="test-uuid-2",
            ),
            ThreatMatch(
                rule_id="test-rule-3",
                rule_name="Test Rule 3",
                description="Test description 3",
                category=Category.SECRETS,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=30,
                uuid="test-uuid-3",
            ),
        ]

        validation_results = {
            "test-uuid-1": ValidationResult(
                finding_uuid="test-uuid-1",
                is_legitimate=True,
                confidence=0.9,
                reasoning="Real vulnerability",
                remediation_advice="Fix this",
                exploit_poc=["exploit 1"],
            ),
            "test-uuid-2": ValidationResult(
                finding_uuid="test-uuid-2",
                is_legitimate=False,  # False positive
                confidence=0.8,
                reasoning="Framework handles this",
            ),
            "test-uuid-3": ValidationResult(
                finding_uuid="test-uuid-3",
                is_legitimate=True,
                confidence=0.6,  # Below threshold
                reasoning="Maybe legitimate",
            ),
        }

        filtered = validator.filter_false_positives(
            findings, validation_results, confidence_threshold=0.7
        )

        assert len(filtered) == 1
        assert filtered[0].uuid == "test-uuid-1"
        assert filtered[0].remediation == "Fix this"
        assert filtered[0].exploit_examples == ["exploit 1"]

    def test_filter_false_positives_with_severity_adjustment(self, validator):
        """Test filter_false_positives with severity adjustment."""
        findings = [
            ThreatMatch(
                rule_id="test-rule-1",
                rule_name="Test Rule 1",
                description="Test description 1",
                category=Category.INJECTION,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
            ),
        ]

        validation_results = {
            "test-uuid-1": ValidationResult(
                finding_uuid="test-uuid-1",
                is_legitimate=True,
                confidence=0.9,
                reasoning="Real vulnerability",
                severity_adjustment=Severity.CRITICAL,
            ),
        }

        filtered = validator.filter_false_positives(findings, validation_results)

        assert len(filtered) == 1
        assert filtered[0].severity == Severity.CRITICAL  # Adjusted

    def test_filter_false_positives_no_validation_result(self, validator):
        """Test filter_false_positives when finding has no validation result."""
        findings = [
            ThreatMatch(
                rule_id="test-rule-1",
                rule_name="Test Rule 1",
                description="Test description 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
            ),
        ]

        validation_results = {}  # No validation for this finding

        filtered = validator.filter_false_positives(findings, validation_results)

        assert len(filtered) == 1  # Should keep finding (fail-open)
        assert filtered[0].uuid == "test-uuid-1"

    def test_get_validation_stats(self, validator):
        """Test get_validation_stats method."""
        validation_results = {
            "uuid-1": ValidationResult(
                finding_uuid="uuid-1",
                is_legitimate=True,
                confidence=0.9,
                reasoning="Real",
            ),
            "uuid-2": ValidationResult(
                finding_uuid="uuid-2",
                is_legitimate=False,
                confidence=0.8,
                reasoning="False positive",
            ),
            "uuid-3": ValidationResult(
                finding_uuid="uuid-3",
                is_legitimate=True,
                confidence=0.7,
                reasoning="Real",
                validation_error="Some error",
            ),
        }

        stats = validator.get_validation_stats(validation_results)

        assert stats["total_validated"] == 3
        assert stats["legitimate_findings"] == 2
        assert stats["false_positives"] == 1
        assert stats["false_positive_rate"] == pytest.approx(0.333, rel=0.01)
        assert stats["average_confidence"] == pytest.approx(0.8, rel=0.01)
        assert stats["validation_errors"] == 1

    def test_create_user_prompt_truncation(self, validator):
        """Test that user prompt truncates very long code."""
        findings = [
            ThreatMatch(
                rule_id="test-rule",
                rule_name="Test Rule",
                description="Test description",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="test-uuid-1",
                code_snippet="vulnerable code",
                confidence=0.9,
            )
        ]

        # Create very long source code
        long_code = "x" * 15000  # Longer than max_code_length

        prompt = validator._create_user_prompt(findings, long_code, "test.py")

        assert "... [truncated for analysis]" in prompt
        assert len(prompt) < 20000  # Should be reasonably sized
