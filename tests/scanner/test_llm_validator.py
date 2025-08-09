"""Tests for LLM validator module."""

import json
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.config import SecurityConfig
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
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
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

        # Set fallback mode to optimistic for this test
        from adversary_mcp_server.config import ValidationFallbackMode

        validator.config.validation_fallback_mode = ValidationFallbackMode.OPTIMISTIC

        # Mock exploit generator
        validator.exploit_generator.is_llm_available.return_value = True
        validator.exploit_generator.generate_exploits.return_value = ["test exploit"]

        results = validator.validate_findings(
            findings, "source code", "test.py", generate_exploits=True
        )

        assert len(results) == 1
        assert "test-uuid-1" in results
        assert results["test-uuid-1"].is_legitimate is True
        assert (
            results["test-uuid-1"].confidence == 0.7
        )  # Default confidence when LLM unavailable
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

    @pytest.mark.asyncio
    async def test_validate_findings_llm_unavailable(self, mock_credential_manager):
        """Test validate_findings when LLM client is not available."""
        # Create validator without LLM client
        from adversary_mcp_server.config import ValidationFallbackMode

        mock_config = SecurityConfig(
            enable_llm_validation=False, llm_provider=None, llm_api_key=None
        )
        mock_config.validation_fallback_mode = ValidationFallbackMode.OPTIMISTIC
        mock_credential_manager.load_config.return_value = mock_config

        with patch("adversary_mcp_server.scanner.llm_validator.ExploitGenerator"):
            validator = LLMValidator(mock_credential_manager)

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

            results = await validator._validate_findings_async(
                findings, "source code", "test.py"
            )

            # Should return default validation results when LLM is not available (fail-open behavior)
            assert len(results) == 1
            assert "test-uuid-1" in results
            assert results["test-uuid-1"].is_legitimate is True
            assert (
                results["test-uuid-1"].confidence == 0.7
            )  # Optimistic fallback confidence
            assert (
                "LLM validation unavailable. Finding treated as legitimate (fallback mode: optimistic)"
                in results["test-uuid-1"].reasoning
            )

    @pytest.mark.asyncio
    async def test_validate_findings_api_error(self, validator):
        """Test validate_findings when LLM API call fails."""
        # Set fallback mode to optimistic for this test
        from adversary_mcp_server.config import ValidationFallbackMode

        validator.config.validation_fallback_mode = ValidationFallbackMode.OPTIMISTIC

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

        # Create and set a mock LLM client to raise exception
        from unittest.mock import AsyncMock

        mock_client = AsyncMock()
        mock_client.complete_with_retry.side_effect = Exception("API Error")
        validator.llm_client = mock_client

        # Should return default results when API fails (fail-open behavior)
        results = await validator._validate_findings_async(
            findings, "source code", "test.py"
        )

        assert len(results) == 1
        assert "test-uuid-1" in results
        assert results["test-uuid-1"].is_legitimate is True
        assert results["test-uuid-1"].confidence == 0.7
        assert (
            "LLM validation unavailable. Finding treated as legitimate (fallback mode: optimistic)"
            in results["test-uuid-1"].reasoning
        )


class TestLLMValidatorSyncWrapper:
    """Test LLM validator sync wrapper for uncovered edge cases."""

    def test_validate_findings_no_event_loop(self):
        """Test validate_findings when no event loop exists."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_config.llm_provider = (
            None  # No LLM provider to avoid client initialization
        )
        mock_manager.load_config.return_value = mock_config

        # Mock the validator to take the event loop creation path
        with patch(
            "adversary_mcp_server.scanner.llm_validator.asyncio.get_event_loop"
        ) as mock_get_loop:
            # Simulate no event loop exists
            mock_get_loop.side_effect = RuntimeError("No event loop")

            with patch(
                "adversary_mcp_server.scanner.llm_validator.asyncio.new_event_loop"
            ) as mock_new_loop:
                with patch(
                    "adversary_mcp_server.scanner.llm_validator.asyncio.set_event_loop"
                ) as mock_set_loop:
                    mock_loop = Mock()
                    mock_new_loop.return_value = mock_loop

                    # Mock the async call to return default results (since no LLM client)
                    expected_result = {
                        "test-uuid": ValidationResult(
                            finding_uuid="test-uuid",
                            is_legitimate=True,
                            confidence=0.7,
                            reasoning="LLM validation not available, finding kept as precaution",
                            validation_error="LLM client not initialized",
                        )
                    }
                    mock_loop.run_until_complete.return_value = expected_result

                    validator = LLMValidator(mock_manager)

                    threat = ThreatMatch(
                        rule_id="test",
                        rule_name="Test",
                        description="Test threat",
                        category=Category.INJECTION,
                        severity=Severity.HIGH,
                        file_path="/test/file.py",
                        line_number=10,
                        uuid="test-uuid",
                    )

                    result = validator.validate_findings(
                        [threat], "test code", "test.py"
                    )

                    # When no LLM client is available, it should return early with default results
                    # and not create a new event loop - it returns from the sync path
                    assert isinstance(result, dict)
                    assert len(result) == 1
                    assert "test-uuid" in result

    def test_validate_findings_no_llm_client_default_results(self):
        """Test validate_findings returns default results when LLM client not available."""
        mock_manager = Mock()
        from adversary_mcp_server.config import ValidationFallbackMode

        mock_config = SecurityConfig()
        mock_config.llm_provider = None  # No LLM provider
        mock_config.validation_fallback_mode = ValidationFallbackMode.OPTIMISTIC
        mock_manager.load_config.return_value = mock_config

        validator = LLMValidator(mock_manager)

        threat = ThreatMatch(
            rule_id="test",
            rule_name="Test",
            description="Test threat",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="/test/file.py",
            line_number=10,
            uuid="test-uuid",
        )

        result = validator.validate_findings([threat], "test code", "test.py")

        # Should return default results since no LLM client
        assert len(result) == 1
        assert "test-uuid" in result
        assert result["test-uuid"].is_legitimate is True
        assert result["test-uuid"].confidence == 0.7
        assert "LLM validation unavailable" in result["test-uuid"].reasoning

    def test_validate_findings_empty_findings_list(self):
        """Test validate_findings with empty findings list."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        validator = LLMValidator(mock_manager)

        result = validator.validate_findings([], "test code", "test.py")

        # Should return empty dict for no findings
        assert result == {}


class TestLLMValidatorBatchProcessingErrors:
    """Test LLM validator batch processing error scenarios."""

    @pytest.mark.asyncio
    async def test_validate_findings_async_batch_processor_error(self):
        """Test _validate_findings_async when batch processor raises an error."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "test-key"
        mock_config.enable_caching = False  # Disable caching to simplify test
        mock_manager.load_config.return_value = mock_config

        with (
            patch(
                "adversary_mcp_server.scanner.llm_validator.create_llm_client"
            ) as mock_create_client,
            patch(
                "adversary_mcp_server.scanner.llm_validator.BatchProcessor"
            ) as mock_batch_processor_class,
        ):
            # Mock LLM client
            mock_llm_client = Mock()
            mock_create_client.return_value = mock_llm_client

            # Mock batch processor creation and methods
            from unittest.mock import AsyncMock

            mock_batch_processor = Mock()
            mock_batch_processor.create_batches.return_value = [[]]  # Empty batch list
            # Mock process_batches to return empty list as async function
            mock_batch_processor.process_batches = AsyncMock(
                return_value=[]
            )  # Return empty results
            mock_batch_processor.get_metrics.return_value = Mock()
            mock_batch_processor.get_metrics.return_value.to_dict.return_value = {}
            mock_batch_processor_class.return_value = mock_batch_processor

            validator = LLMValidator(mock_manager)
            validator.llm_client = (
                mock_llm_client  # Set directly to avoid initialization issues
            )

            threat = ThreatMatch(
                rule_id="test",
                rule_name="Test",
                description="Test threat",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="/test/file.py",
                line_number=10,
                uuid="test-uuid",
                code_snippet="test code",
            )

            # Should handle empty batch processing results gracefully
            result = await validator._validate_findings_async(
                [threat], "test code", "test.py"
            )

            # Should still return results dict (empty due to no batch results)
            assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_validate_findings_async_llm_response_error(self):
        """Test _validate_findings_async when LLM returns malformed response."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "test-key"
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_validator.create_llm_client"
        ) as mock_create_client:
            # Mock LLM client that returns invalid response
            mock_llm_client = Mock()
            mock_response = Mock()
            mock_response.content = "invalid json response"  # Not valid JSON
            mock_llm_client.complete_with_retry.return_value = mock_response
            mock_create_client.return_value = mock_llm_client

            validator = LLMValidator(mock_manager)
            validator.llm_client = mock_llm_client

            threat = ThreatMatch(
                rule_id="test",
                rule_name="Test",
                description="Test threat",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="/test/file.py",
                line_number=10,
                uuid="test-uuid",
            )

            # Should handle malformed response gracefully
            result = await validator._validate_findings_async(
                [threat], "test code", "test.py"
            )

            # Should return default results when parsing fails
            assert isinstance(result, dict)
            assert len(result) == 1
            assert "test-uuid" in result


class TestLLMValidatorEdgeCases:
    """Test LLM validator edge cases for better coverage."""

    def test_create_default_results_with_exploits(self):
        """Test _create_default_results with exploit generation enabled."""
        mock_manager = Mock()
        from adversary_mcp_server.config import ValidationFallbackMode

        mock_config = SecurityConfig()
        mock_config.validation_fallback_mode = ValidationFallbackMode.OPTIMISTIC
        mock_manager.load_config.return_value = mock_config

        validator = LLMValidator(mock_manager)

        threat = ThreatMatch(
            rule_id="test",
            rule_name="Test",
            description="Test threat",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="/test/file.py",
            line_number=10,
            uuid="test-uuid",
        )

        # Mock exploit generator to be available and return exploits
        validator.exploit_generator.is_llm_available = Mock(return_value=True)
        validator.exploit_generator.generate_exploits = Mock(
            return_value=["test exploit"]
        )

        # Test with exploit generation enabled
        result = validator._create_default_results([threat], True, "test code")

        assert len(result) == 1
        assert "test-uuid" in result
        validation_result = result["test-uuid"]
        assert validation_result.is_legitimate is True
        assert validation_result.confidence == 0.7
        assert "LLM validation unavailable" in validation_result.reasoning

        # Should have exploit POC when exploit generation enabled and succeeds
        assert validation_result.exploit_poc == ["test exploit"]
        # exploitation_vector is not created by _create_default_results (that's done elsewhere)
        assert validation_result.exploitation_vector is None

    def test_create_default_results_without_exploits(self):
        """Test _create_default_results with exploit generation disabled."""
        mock_manager = Mock()
        from adversary_mcp_server.config import ValidationFallbackMode

        mock_config = SecurityConfig()
        mock_config.validation_fallback_mode = ValidationFallbackMode.OPTIMISTIC
        mock_manager.load_config.return_value = mock_config

        validator = LLMValidator(mock_manager)

        threat = ThreatMatch(
            rule_id="test",
            rule_name="Test",
            description="Test threat",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="/test/file.py",
            line_number=10,
            uuid="test-uuid",
        )

        # Test with exploit generation disabled
        result = validator._create_default_results([threat], False, "test code")

        assert len(result) == 1
        assert "test-uuid" in result
        validation_result = result["test-uuid"]
        assert validation_result.is_legitimate is True
        assert validation_result.confidence == 0.7

        # Should not have exploitation vector when exploits disabled
        assert validation_result.exploitation_vector is None

    def test_filter_false_positives_edge_cases(self):
        """Test filter_false_positives with various confidence levels."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        validator = LLMValidator(mock_manager)

        # Create threats with different UUIDs
        threat1 = ThreatMatch(
            rule_id="test1",
            rule_name="Test1",
            description="Test threat 1",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="/test/file.py",
            line_number=10,
            uuid="uuid-1",
        )

        threat2 = ThreatMatch(
            rule_id="test2",
            rule_name="Test2",
            description="Test threat 2",
            category=Category.XSS,
            severity=Severity.MEDIUM,
            file_path="/test/file.py",
            line_number=20,
            uuid="uuid-2",
        )

        # Create validation results with different confidence levels
        validation_results = {
            "uuid-1": ValidationResult(
                finding_uuid="uuid-1",
                is_legitimate=True,
                confidence=0.8,  # Above threshold
                reasoning="High confidence",
            ),
            "uuid-2": ValidationResult(
                finding_uuid="uuid-2",
                is_legitimate=True,
                confidence=0.3,  # Below threshold
                reasoning="Low confidence",
            ),
        }

        filtered_threats = validator.filter_false_positives(
            [threat1, threat2], validation_results
        )

        # Should only keep threat1 (above confidence threshold)
        assert len(filtered_threats) == 1
        assert filtered_threats[0].uuid == "uuid-1"

    def test_get_validation_stats_comprehensive(self):
        """Test get_validation_stats with comprehensive validation results."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        validator = LLMValidator(mock_manager)

        # Create comprehensive validation results
        validation_results = {
            "uuid-1": ValidationResult(
                finding_uuid="uuid-1",
                is_legitimate=True,
                confidence=0.9,
                reasoning="High confidence legitimate",
            ),
            "uuid-2": ValidationResult(
                finding_uuid="uuid-2",
                is_legitimate=False,
                confidence=0.8,
                reasoning="High confidence false positive",
            ),
            "uuid-3": ValidationResult(
                finding_uuid="uuid-3",
                is_legitimate=True,
                confidence=0.4,  # Low confidence
                reasoning="Low confidence",
            ),
            "uuid-4": ValidationResult(
                finding_uuid="uuid-4",
                is_legitimate=True,
                confidence=0.7,
                reasoning="Medium confidence",
                validation_error="Some validation error",
            ),
        }

        stats = validator.get_validation_stats(validation_results)

        # Verify comprehensive stats
        assert stats["total_validated"] == 4
        assert stats["legitimate_findings"] == 3  # 3 marked as legitimate
        assert stats["false_positives"] == 1  # 1 marked as false positive
        assert stats["false_positive_rate"] == 0.25  # 1/4 = 0.25
        assert stats["average_confidence"] == 0.7  # (0.9 + 0.8 + 0.4 + 0.7) / 4
        assert stats["validation_errors"] == 1  # 1 has validation error
