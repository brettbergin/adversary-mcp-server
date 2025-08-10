"""Tests for ResultBuilder."""

from unittest.mock import Mock

import pytest

from adversary_mcp_server.infrastructure.builders.result_builder import ResultBuilder
from adversary_mcp_server.scanner.llm_validator import ValidationResult
from adversary_mcp_server.scanner.types import Severity, ThreatMatch


@pytest.fixture
def result_builder():
    """Create a ResultBuilder instance."""
    return ResultBuilder()


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
        ThreatMatch(
            rule_id="critical-1",
            rule_name="Critical Vulnerability",
            description="Code execution vulnerability",
            category="code-execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=50,
            column_number=1,
            code_snippet="eval(user_input)",
            confidence=0.95,
        ),
    ]


@pytest.fixture
def sample_validation_results():
    """Create sample validation results."""
    return {
        "threat-1": ValidationResult(
            finding_uuid="threat-1",
            is_legitimate=True,
            confidence=0.9,
            reasoning="Clear SQL injection pattern with user input concatenation",
            exploitation_vector="Inject malicious SQL to extract database contents",
        ),
        "threat-2": ValidationResult(
            finding_uuid="threat-2",
            is_legitimate=False,
            confidence=0.3,
            reasoning="innerHTML is used with trusted template data, not user input",
            exploitation_vector=None,
        ),
    }


class TestResultBuilder:
    """Test ResultBuilder functionality."""

    def test_calculate_threat_statistics_empty(self, result_builder):
        """Test statistics calculation with empty threat list."""
        stats = result_builder.calculate_threat_statistics([])

        assert stats["total_threats"] == 0
        assert stats["severity_counts"] == {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }
        assert stats["category_counts"] == {}
        assert stats["high_confidence_count"] == 0
        assert stats["critical_count"] == 0

    def test_calculate_threat_statistics(self, result_builder, sample_threats):
        """Test comprehensive statistics calculation."""
        stats = result_builder.calculate_threat_statistics(sample_threats)

        assert stats["total_threats"] == 3
        assert stats["severity_counts"]["high"] == 1
        assert stats["severity_counts"]["medium"] == 1
        assert stats["severity_counts"]["critical"] == 1
        assert stats["severity_counts"]["low"] == 0

        assert stats["category_counts"]["sql-injection"] == 1
        assert stats["category_counts"]["xss"] == 1
        assert stats["category_counts"]["code-execution"] == 1

        assert stats["high_confidence_count"] == 2  # confidence >= 0.8
        assert stats["critical_count"] == 1  # critical severity

    def test_count_by_severity(self, result_builder, sample_threats):
        """Test severity counting."""
        counts = result_builder._count_by_severity(sample_threats)

        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 0

    def test_count_by_category(self, result_builder, sample_threats):
        """Test category counting."""
        counts = result_builder._count_by_category(sample_threats)

        assert counts["sql-injection"] == 1
        assert counts["xss"] == 1
        assert counts["code-execution"] == 1

    def test_get_high_confidence_threats(self, result_builder, sample_threats):
        """Test high confidence threat filtering."""
        high_confidence = result_builder.get_high_confidence_threats(sample_threats)

        assert len(high_confidence) == 2  # confidence >= 0.8
        assert all(threat.confidence >= 0.8 for threat in high_confidence)

        # Test custom threshold
        very_high_confidence = result_builder.get_high_confidence_threats(
            sample_threats, 0.9
        )
        assert len(very_high_confidence) == 2  # confidence >= 0.9

    def test_get_critical_threats(self, result_builder, sample_threats):
        """Test critical threat filtering."""
        critical_threats = result_builder.get_critical_threats(sample_threats)

        assert len(critical_threats) == 1
        assert critical_threats[0].severity == Severity.CRITICAL
        assert critical_threats[0].category == "code-execution"

    def test_build_validation_summary_disabled(self, result_builder):
        """Test validation summary when validation is disabled."""
        scan_metadata = {"llm_validation_success": False}
        validation_results = {}

        summary = result_builder.build_validation_summary(
            validation_results, scan_metadata
        )

        assert summary["enabled"] is False
        assert summary["total_findings_reviewed"] == 0
        assert summary["status"] == "disabled"

    def test_build_validation_summary_enabled(
        self, result_builder, sample_validation_results
    ):
        """Test validation summary when validation is enabled."""
        scan_metadata = {"llm_validation_success": True}

        summary = result_builder.build_validation_summary(
            sample_validation_results, scan_metadata
        )

        assert summary["enabled"] is True
        assert summary["total_findings_reviewed"] == 2
        assert summary["legitimate_findings"] == 1
        assert summary["false_positives_filtered"] == 1
        assert summary["false_positive_rate"] == 0.5
        assert summary["average_confidence"] == 0.6  # (0.9 + 0.3) / 2
        assert summary["status"] == "completed"

    def test_build_scan_metadata(self, result_builder):
        """Test scan metadata building."""
        metadata = result_builder.build_scan_metadata(
            scan_type="file",
            language="python",
            use_llm=True,
            use_semgrep=True,
            use_validation=True,
            scan_duration_ms=1234.567,
            timestamp="2023-01-01T00:00:00Z",
            custom_field="custom_value",
        )

        assert metadata["scan_type"] == "file"
        assert metadata["language"] == "python"
        assert metadata["engines_used"]["llm_analysis"] is True
        assert metadata["engines_used"]["semgrep_analysis"] is True
        assert metadata["validation_enabled"] is True
        assert metadata["scan_duration_ms"] == 1234.57  # Rounded
        assert metadata["timestamp"] == "2023-01-01T00:00:00Z"
        assert metadata["custom_field"] == "custom_value"

    def test_create_default_llm_usage_stats(self, result_builder):
        """Test default LLM usage stats creation."""
        stats = result_builder._create_default_llm_usage_stats()

        assert "analysis" in stats
        assert "validation" in stats

        for section in ["analysis", "validation"]:
            assert stats[section]["total_tokens"] == 0
            assert stats[section]["prompt_tokens"] == 0
            assert stats[section]["completion_tokens"] == 0
            assert stats[section]["total_cost"] == 0.0
            assert stats[section]["api_calls"] == 0
            assert stats[section]["models_used"] == []

    def test_add_llm_usage_to_stats(self, result_builder):
        """Test adding LLM usage to existing stats."""
        usage_stats = result_builder._create_default_llm_usage_stats()
        cost_breakdown = {
            "tokens": {
                "total_tokens": 1000,
                "prompt_tokens": 800,
                "completion_tokens": 200,
            },
            "total_cost": 0.05,
            "model": "gpt-3.5-turbo",
        }

        result_builder.add_llm_usage_to_stats(usage_stats, "analysis", cost_breakdown)

        analysis_stats = usage_stats["analysis"]
        assert analysis_stats["total_tokens"] == 1000
        assert analysis_stats["prompt_tokens"] == 800
        assert analysis_stats["completion_tokens"] == 200
        assert analysis_stats["total_cost"] == 0.05
        assert analysis_stats["api_calls"] == 1
        assert "gpt-3.5-turbo" in analysis_stats["models_used"]

    def test_add_llm_usage_multiple_calls(self, result_builder):
        """Test adding LLM usage across multiple calls."""
        usage_stats = result_builder._create_default_llm_usage_stats()

        # First call
        cost_breakdown1 = {
            "tokens": {
                "total_tokens": 1000,
                "prompt_tokens": 800,
                "completion_tokens": 200,
            },
            "total_cost": 0.05,
            "model": "gpt-3.5-turbo",
        }
        result_builder.add_llm_usage_to_stats(usage_stats, "analysis", cost_breakdown1)

        # Second call
        cost_breakdown2 = {
            "tokens": {
                "total_tokens": 500,
                "prompt_tokens": 400,
                "completion_tokens": 100,
            },
            "total_cost": 0.025,
            "model": "gpt-4",
        }
        result_builder.add_llm_usage_to_stats(usage_stats, "analysis", cost_breakdown2)

        analysis_stats = usage_stats["analysis"]
        assert analysis_stats["total_tokens"] == 1500  # 1000 + 500
        assert analysis_stats["prompt_tokens"] == 1200  # 800 + 400
        assert analysis_stats["completion_tokens"] == 300  # 200 + 100
        assert (
            abs(analysis_stats["total_cost"] - 0.075) < 0.001
        )  # Account for floating point precision
        assert analysis_stats["api_calls"] == 2
        assert "gpt-3.5-turbo" in analysis_stats["models_used"]
        assert "gpt-4" in analysis_stats["models_used"]

    def test_add_llm_usage_unknown_type(self, result_builder):
        """Test adding LLM usage with unknown usage type."""
        usage_stats = result_builder._create_default_llm_usage_stats()
        cost_breakdown = {"total_cost": 0.05, "tokens": {"total_tokens": 1000}}

        # Should handle unknown usage type gracefully
        result_builder.add_llm_usage_to_stats(
            usage_stats, "unknown_type", cost_breakdown
        )

        # Stats should remain unchanged
        assert usage_stats["analysis"]["total_tokens"] == 0
        assert usage_stats["validation"]["total_tokens"] == 0

    def test_build_enhanced_result(
        self, result_builder, sample_threats, sample_validation_results
    ):
        """Test building complete enhanced result."""
        semgrep_threats = [sample_threats[0]]  # SQL injection
        llm_threats = [sample_threats[1], sample_threats[2]]  # XSS and code execution
        aggregated_threats = sample_threats  # All three

        scan_metadata = {
            "scan_type": "file",
            "language": "python",
            "llm_validation_success": True,
        }

        llm_usage_stats = {
            "analysis": {
                "total_tokens": 1000,
                "total_cost": 0.05,
                "api_calls": 1,
                "models_used": ["gpt-4"],
            },
            "validation": {
                "total_tokens": 500,
                "total_cost": 0.025,
                "api_calls": 1,
                "models_used": ["gpt-4"],
            },
        }

        result = result_builder.build_enhanced_result(
            file_path="test.py",
            semgrep_threats=semgrep_threats,
            llm_threats=llm_threats,
            aggregated_threats=aggregated_threats,
            scan_metadata=scan_metadata,
            validation_results=sample_validation_results,
            llm_usage_stats=llm_usage_stats,
        )

        assert result.file_path == "test.py"
        assert len(result.semgrep_threats) == 1
        assert len(result.llm_threats) == 2
        assert len(result.all_threats) == 3
        assert result.scan_metadata == scan_metadata
        assert result.validation_results == sample_validation_results
        assert result.llm_usage_stats == llm_usage_stats

    def test_build_enhanced_result_with_none_parameters(
        self, result_builder, sample_threats
    ):
        """Test building enhanced result with None validation_results and llm_usage_stats."""
        semgrep_threats = [sample_threats[0]]
        llm_threats = [sample_threats[1]]
        aggregated_threats = sample_threats[:2]

        scan_metadata = {"scan_type": "file", "language": "python"}

        # Test with None parameters to cover lines 56 and 58
        result = result_builder.build_enhanced_result(
            file_path="test.py",
            semgrep_threats=semgrep_threats,
            llm_threats=llm_threats,
            aggregated_threats=aggregated_threats,
            scan_metadata=scan_metadata,
            validation_results=None,  # Should default to {}
            llm_usage_stats=None,  # Should create default stats
        )

        assert result.validation_results == {}
        assert "analysis" in result.llm_usage_stats
        assert "validation" in result.llm_usage_stats


class TestResultBuilderEdgeCases:
    """Test edge cases and error conditions."""

    def test_threats_without_confidence(self, result_builder):
        """Test handling threats without confidence attribute."""
        threats = [
            ThreatMatch(
                rule_id="test-1",
                rule_name="Test Rule",
                description="Test",
                category="test",
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                column_number=1,
                code_snippet="test",
                # Note: no confidence attribute
            )
        ]

        # Should default to confidence 1.0
        high_confidence = result_builder.get_high_confidence_threats(threats, 0.8)
        assert len(high_confidence) == 1

    def test_category_with_enum_value(self, result_builder):
        """Test category counting with enum values."""
        # Create mock threat with category as enum-like object
        threat = Mock()
        threat.category = Mock()
        threat.category.value = "test-category"

        counts = result_builder._count_by_category([threat])
        assert counts["test-category"] == 1

    def test_validation_results_with_errors(self, result_builder):
        """Test validation summary with validation errors."""
        validation_results = {
            "threat-1": ValidationResult(
                finding_uuid="threat-1",
                is_legitimate=True,
                confidence=0.9,
                reasoning="Valid threat",
                validation_error=True,  # Has validation error
            ),
            "threat-2": ValidationResult(
                finding_uuid="threat-2",
                is_legitimate=False,
                confidence=0.7,
                reasoning="False positive",
                validation_error=False,
            ),
        }

        stats = result_builder._calculate_validation_statistics(validation_results)
        assert stats["validation_errors"] == 1

    def test_empty_cost_breakdown(self, result_builder):
        """Test adding LLM usage with empty cost breakdown."""
        usage_stats = result_builder._create_default_llm_usage_stats()

        # Empty cost breakdown
        result_builder.add_llm_usage_to_stats(usage_stats, "analysis", {})

        analysis_stats = usage_stats["analysis"]
        assert analysis_stats["total_tokens"] == 0
        assert analysis_stats["total_cost"] == 0.0
        assert analysis_stats["api_calls"] == 1  # Should still increment call count

    def test_unknown_severity_warning(self, result_builder):
        """Test handling of unknown severity levels."""
        # Create a mock threat with unknown severity
        from unittest.mock import Mock

        threat = Mock()
        threat.severity = Mock()
        threat.severity.value = Mock()
        threat.severity.value.lower.return_value = "unknown_severity"

        # This should trigger the warning on line 129
        counts = result_builder._count_by_severity([threat])

        # Should not crash and return default structure
        assert counts == {"low": 0, "medium": 0, "high": 0, "critical": 0}
