"""Comprehensive tests for ThreatAggregator domain service to achieve 100% coverage."""

from unittest.mock import patch

import pytest

from adversary_mcp_server.domain.aggregation.threat_aggregator import ThreatAggregator
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


def create_test_threat(
    rule_id: str = "test_rule",
    rule_name: str = "Test Rule",
    category: str = "test_category",
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    line_number: int = 1,
    file_path: str = "/test/file.py",
    description: str = "Test description",
) -> ThreatMatch:
    """Helper function to create test threats."""
    return ThreatMatch(
        rule_id=rule_id,
        rule_name=rule_name,
        category=category,
        severity=severity,
        description=description,
        file_path=FilePath.from_string(file_path),
        line_number=line_number,
    )


class TestThreatAggregatorInitialization:
    """Test ThreatAggregator initialization and configuration."""

    def test_default_initialization(self):
        """Test ThreatAggregator initialization with default parameters."""
        aggregator = ThreatAggregator()

        assert aggregator.proximity_threshold == 2
        assert aggregator._aggregation_stats == {
            "total_input_threats": 0,
            "deduplicated_threats": 0,
            "final_threat_count": 0,
        }

    def test_custom_proximity_threshold(self):
        """Test ThreatAggregator initialization with custom proximity threshold."""
        aggregator = ThreatAggregator(proximity_threshold=5)

        assert aggregator.proximity_threshold == 5

    def test_configure_proximity_threshold(self):
        """Test configuring proximity threshold after initialization."""
        aggregator = ThreatAggregator(proximity_threshold=2)

        aggregator.configure_proximity_threshold(10)

        assert aggregator.proximity_threshold == 10

    def test_configure_proximity_threshold_negative(self):
        """Test configuring proximity threshold with negative value raises error."""
        aggregator = ThreatAggregator()

        with pytest.raises(
            ValueError, match="Proximity threshold must be non-negative"
        ):
            aggregator.configure_proximity_threshold(-1)

    def test_configure_proximity_threshold_zero(self):
        """Test configuring proximity threshold with zero."""
        aggregator = ThreatAggregator()

        aggregator.configure_proximity_threshold(0)

        assert aggregator.proximity_threshold == 0


class TestThreatAggregation:
    """Test core threat aggregation functionality."""

    def test_aggregate_empty_lists(self):
        """Test aggregating empty threat lists."""
        aggregator = ThreatAggregator()

        result = aggregator.aggregate_threats([], [])

        assert result == []
        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 0
        assert stats["deduplicated_threats"] == 0
        assert stats["final_threat_count"] == 0

    def test_aggregate_only_semgrep_threats(self):
        """Test aggregating with only Semgrep threats."""
        aggregator = ThreatAggregator()

        semgrep_threats = [
            create_test_threat(rule_id="semgrep1", line_number=10),
            create_test_threat(rule_id="semgrep2", line_number=20),
        ]

        result = aggregator.aggregate_threats(semgrep_threats, [])

        assert len(result) == 2
        assert all(threat.rule_id.startswith("semgrep") for threat in result)

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 2
        assert stats["deduplicated_threats"] == 0
        assert stats["final_threat_count"] == 2

    def test_aggregate_only_llm_threats(self):
        """Test aggregating with only LLM threats."""
        aggregator = ThreatAggregator()

        llm_threats = [
            create_test_threat(rule_id="llm1", line_number=10),
            create_test_threat(rule_id="llm2", line_number=20),
        ]

        result = aggregator.aggregate_threats([], llm_threats)

        assert len(result) == 2
        assert all(threat.rule_id.startswith("llm") for threat in result)

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 2
        assert stats["deduplicated_threats"] == 0
        assert stats["final_threat_count"] == 2

    def test_aggregate_no_duplicates(self):
        """Test aggregating threats with no duplicates."""
        aggregator = ThreatAggregator()

        semgrep_threats = [
            create_test_threat(
                rule_id="semgrep1", line_number=10, category="sql-injection"
            ),
        ]
        llm_threats = [
            create_test_threat(rule_id="llm1", line_number=50, category="xss"),
        ]

        result = aggregator.aggregate_threats(semgrep_threats, llm_threats)

        assert len(result) == 2
        assert any(threat.rule_id == "semgrep1" for threat in result)
        assert any(threat.rule_id == "llm1" for threat in result)

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 2
        assert stats["deduplicated_threats"] == 0
        assert stats["final_threat_count"] == 2

    def test_aggregate_with_duplicates_proximity(self):
        """Test aggregating threats with duplicates based on proximity."""
        aggregator = ThreatAggregator(proximity_threshold=2)

        semgrep_threats = [
            create_test_threat(
                rule_id="semgrep1", line_number=10, category="sql-injection"
            ),
        ]
        llm_threats = [
            create_test_threat(
                rule_id="llm1", line_number=11, category="sql-injection"
            ),  # Within proximity
        ]

        result = aggregator.aggregate_threats(semgrep_threats, llm_threats)

        # Should keep only Semgrep threat (higher priority)
        assert len(result) == 1
        assert result[0].rule_id == "semgrep1"

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 2
        assert stats["deduplicated_threats"] == 1
        assert stats["final_threat_count"] == 1

    def test_aggregate_with_additional_threats(self):
        """Test aggregating with additional threats parameter."""
        aggregator = ThreatAggregator()

        semgrep_threats = [
            create_test_threat(rule_id="semgrep1", line_number=10),
        ]
        llm_threats = [
            create_test_threat(rule_id="llm1", line_number=20),
        ]
        additional_threats = [
            create_test_threat(rule_id="additional1", line_number=30),
            create_test_threat(rule_id="additional2", line_number=40),
        ]

        result = aggregator.aggregate_threats(
            semgrep_threats, llm_threats, additional_threats
        )

        assert len(result) == 4
        rule_ids = [threat.rule_id for threat in result]
        assert "semgrep1" in rule_ids
        assert "llm1" in rule_ids
        assert "additional1" in rule_ids
        assert "additional2" in rule_ids

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 4
        assert stats["deduplicated_threats"] == 0
        assert stats["final_threat_count"] == 4

    def test_aggregate_default_additional_threats(self):
        """Test aggregating with default None additional threats."""
        aggregator = ThreatAggregator()

        semgrep_threats = [create_test_threat(rule_id="semgrep1", line_number=10)]
        llm_threats = [
            create_test_threat(rule_id="llm1", line_number=50)
        ]  # Far apart to avoid deduplication

        # Call without additional_threats parameter (should default to None/[])
        result = aggregator.aggregate_threats(semgrep_threats, llm_threats)

        assert len(result) == 2


class TestThreatDeduplication:
    """Test threat deduplication logic."""

    def test_is_duplicate_same_line_same_category(self):
        """Test duplicate detection for same line and category."""
        aggregator = ThreatAggregator()

        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(line_number=10, category="sql-injection")

        existing_threats = [threat1]

        assert aggregator._is_duplicate(threat2, existing_threats)

    def test_is_duplicate_within_proximity_same_category(self):
        """Test duplicate detection within proximity threshold."""
        aggregator = ThreatAggregator(proximity_threshold=2)

        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(
            line_number=12, category="sql-injection"
        )  # Within 2 lines

        existing_threats = [threat1]

        assert aggregator._is_duplicate(threat2, existing_threats)

    def test_is_duplicate_outside_proximity(self):
        """Test no duplicate detection outside proximity threshold."""
        aggregator = ThreatAggregator(proximity_threshold=2)

        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(
            line_number=15, category="sql-injection"
        )  # Outside 2 lines

        existing_threats = [threat1]

        assert not aggregator._is_duplicate(threat2, existing_threats)

    def test_is_duplicate_different_category(self):
        """Test no duplicate detection for different categories."""
        aggregator = ThreatAggregator()

        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(line_number=10, category="xss")

        existing_threats = [threat1]

        assert not aggregator._is_duplicate(threat2, existing_threats)

    def test_are_threats_similar_exact_match(self):
        """Test threat similarity for exact matches."""
        aggregator = ThreatAggregator()

        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(line_number=10, category="sql-injection")

        assert aggregator._are_threats_similar(threat1, threat2)

    def test_are_threats_similar_within_proximity(self):
        """Test threat similarity within proximity."""
        aggregator = ThreatAggregator(proximity_threshold=3)

        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(line_number=13, category="sql-injection")

        assert aggregator._are_threats_similar(threat1, threat2)

    def test_are_threats_similar_outside_proximity(self):
        """Test threat similarity outside proximity."""
        aggregator = ThreatAggregator(proximity_threshold=2)

        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(line_number=15, category="sql-injection")

        assert not aggregator._are_threats_similar(threat1, threat2)

    def test_are_threats_similar_category_variations(self):
        """Test threat similarity for category variations."""
        aggregator = ThreatAggregator()

        # Test SQL injection variations
        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(line_number=10, category="injection")
        threat3 = create_test_threat(line_number=10, category="sqli")

        assert aggregator._are_threats_similar(threat1, threat2)
        assert aggregator._are_threats_similar(threat1, threat3)

        # Test XSS variations
        threat4 = create_test_threat(line_number=10, category="xss")
        threat5 = create_test_threat(line_number=10, category="cross-site-scripting")
        threat6 = create_test_threat(line_number=10, category="script-injection")

        assert aggregator._are_threats_similar(threat4, threat5)
        assert aggregator._are_threats_similar(threat4, threat6)

        # Test path traversal variations
        threat7 = create_test_threat(line_number=10, category="path-traversal")
        threat8 = create_test_threat(line_number=10, category="directory-traversal")
        threat9 = create_test_threat(line_number=10, category="path-injection")

        assert aggregator._are_threats_similar(threat7, threat8)
        assert aggregator._are_threats_similar(threat7, threat9)

    def test_are_threats_similar_case_insensitive(self):
        """Test threat similarity is case insensitive."""
        aggregator = ThreatAggregator()

        threat1 = create_test_threat(line_number=10, category="SQL-Injection")
        threat2 = create_test_threat(line_number=10, category="sql-injection")

        assert aggregator._are_threats_similar(threat1, threat2)

    def test_are_threats_similar_unrelated_categories(self):
        """Test threat similarity for unrelated categories."""
        aggregator = ThreatAggregator()

        threat1 = create_test_threat(line_number=10, category="sql-injection")
        threat2 = create_test_threat(line_number=10, category="memory-leak")

        assert not aggregator._are_threats_similar(threat1, threat2)


class TestThreatSorting:
    """Test threat sorting functionality."""

    def test_sort_threats_by_line_number(self):
        """Test sorting threats by line number."""
        aggregator = ThreatAggregator()

        threats = [
            create_test_threat(
                rule_id="threat3", line_number=30, severity=SeverityLevel.LOW
            ),
            create_test_threat(
                rule_id="threat1", line_number=10, severity=SeverityLevel.HIGH
            ),
            create_test_threat(
                rule_id="threat2", line_number=20, severity=SeverityLevel.MEDIUM
            ),
        ]

        sorted_threats = aggregator._sort_threats(threats)

        assert [t.line_number for t in sorted_threats] == [10, 20, 30]
        assert [t.rule_id for t in sorted_threats] == ["threat1", "threat2", "threat3"]

    def test_sort_threats_by_severity_when_same_line(self):
        """Test sorting threats by severity when line numbers are the same."""
        aggregator = ThreatAggregator()

        threats = [
            create_test_threat(
                rule_id="low", line_number=10, severity=SeverityLevel.LOW, category="b"
            ),
            create_test_threat(
                rule_id="high",
                line_number=10,
                severity=SeverityLevel.HIGH,
                category="a",
            ),
            create_test_threat(
                rule_id="medium",
                line_number=10,
                severity=SeverityLevel.MEDIUM,
                category="c",
            ),
        ]

        sorted_threats = aggregator._sort_threats(threats)

        # Should be sorted by severity value (HIGH=4, MEDIUM=3, LOW=2)
        assert (
            sorted_threats[0].severity == SeverityLevel.LOW
        )  # Lowest numeric value first
        assert sorted_threats[1].severity == SeverityLevel.MEDIUM
        assert sorted_threats[2].severity == SeverityLevel.HIGH

    def test_sort_threats_by_category_when_same_line_and_severity(self):
        """Test sorting threats by category when line and severity are the same."""
        aggregator = ThreatAggregator()

        threats = [
            create_test_threat(
                rule_id="z",
                line_number=10,
                severity=SeverityLevel.MEDIUM,
                category="z-category",
            ),
            create_test_threat(
                rule_id="a",
                line_number=10,
                severity=SeverityLevel.MEDIUM,
                category="a-category",
            ),
            create_test_threat(
                rule_id="m",
                line_number=10,
                severity=SeverityLevel.MEDIUM,
                category="m-category",
            ),
        ]

        sorted_threats = aggregator._sort_threats(threats)

        # Should be sorted by category alphabetically
        assert [t.category for t in sorted_threats] == [
            "a-category",
            "m-category",
            "z-category",
        ]


class TestThreatDistributionAnalysis:
    """Test threat distribution analysis functionality."""

    def test_analyze_threat_distribution_empty(self):
        """Test analyzing distribution of empty threat list."""
        aggregator = ThreatAggregator()

        distribution = aggregator.analyze_threat_distribution([])

        assert distribution == {
            "by_severity": {},
            "by_category": {},
            "by_line_range": {"1-50": 0, "51-100": 0, "101-500": 0, "500+": 0},
        }

    def test_analyze_threat_distribution_by_severity(self):
        """Test analyzing distribution by severity."""
        aggregator = ThreatAggregator()

        threats = [
            create_test_threat(severity=SeverityLevel.HIGH),
            create_test_threat(severity=SeverityLevel.HIGH),
            create_test_threat(severity=SeverityLevel.MEDIUM),
            create_test_threat(severity=SeverityLevel.LOW),
        ]

        distribution = aggregator.analyze_threat_distribution(threats)

        assert distribution["by_severity"]["high"] == 2
        assert distribution["by_severity"]["medium"] == 1
        assert distribution["by_severity"]["low"] == 1

    def test_analyze_threat_distribution_by_category(self):
        """Test analyzing distribution by category."""
        aggregator = ThreatAggregator()

        threats = [
            create_test_threat(category="sql-injection"),
            create_test_threat(category="sql-injection"),
            create_test_threat(category="xss"),
            create_test_threat(category="path-traversal"),
        ]

        distribution = aggregator.analyze_threat_distribution(threats)

        assert distribution["by_category"]["sql-injection"] == 2
        assert distribution["by_category"]["xss"] == 1
        assert distribution["by_category"]["path-traversal"] == 1

    def test_analyze_threat_distribution_by_line_range(self):
        """Test analyzing distribution by line range."""
        aggregator = ThreatAggregator()

        threats = [
            create_test_threat(line_number=25),  # 1-50
            create_test_threat(line_number=50),  # 1-50
            create_test_threat(line_number=75),  # 51-100
            create_test_threat(line_number=100),  # 51-100
            create_test_threat(line_number=200),  # 101-500
            create_test_threat(line_number=500),  # 101-500
            create_test_threat(line_number=1000),  # 500+
        ]

        distribution = aggregator.analyze_threat_distribution(threats)

        assert distribution["by_line_range"]["1-50"] == 2
        assert distribution["by_line_range"]["51-100"] == 2
        assert distribution["by_line_range"]["101-500"] == 2
        assert distribution["by_line_range"]["500+"] == 1

    def test_analyze_threat_distribution_comprehensive(self):
        """Test comprehensive threat distribution analysis."""
        aggregator = ThreatAggregator()

        threats = [
            create_test_threat(
                category="sql-injection", severity=SeverityLevel.HIGH, line_number=25
            ),
            create_test_threat(
                category="xss", severity=SeverityLevel.MEDIUM, line_number=75
            ),
            create_test_threat(
                category="sql-injection", severity=SeverityLevel.LOW, line_number=200
            ),
        ]

        distribution = aggregator.analyze_threat_distribution(threats)

        # Check all dimensions
        assert distribution["by_severity"]["high"] == 1
        assert distribution["by_severity"]["medium"] == 1
        assert distribution["by_severity"]["low"] == 1

        assert distribution["by_category"]["sql-injection"] == 2
        assert distribution["by_category"]["xss"] == 1

        assert distribution["by_line_range"]["1-50"] == 1
        assert distribution["by_line_range"]["51-100"] == 1
        assert distribution["by_line_range"]["101-500"] == 1
        assert distribution["by_line_range"]["500+"] == 0


class TestAggregationStatistics:
    """Test aggregation statistics functionality."""

    def test_get_aggregation_stats_initial(self):
        """Test getting initial aggregation statistics."""
        aggregator = ThreatAggregator()

        stats = aggregator.get_aggregation_stats()

        assert stats == {
            "total_input_threats": 0,
            "deduplicated_threats": 0,
            "final_threat_count": 0,
        }

        # Should return a copy, not the original
        stats["total_input_threats"] = 999
        assert aggregator._aggregation_stats["total_input_threats"] == 0

    def test_get_aggregation_stats_after_aggregation(self):
        """Test getting aggregation statistics after aggregation."""
        aggregator = ThreatAggregator()

        semgrep_threats = [
            create_test_threat(
                rule_id="semgrep1", line_number=10, category="sql-injection"
            ),
        ]
        llm_threats = [
            create_test_threat(
                rule_id="llm1", line_number=11, category="sql-injection"
            ),  # Duplicate
            create_test_threat(
                rule_id="llm2", line_number=50, category="xss"
            ),  # Not duplicate
        ]

        aggregator.aggregate_threats(semgrep_threats, llm_threats)

        stats = aggregator.get_aggregation_stats()

        assert stats["total_input_threats"] == 3
        assert stats["deduplicated_threats"] == 1  # One LLM threat was duplicate
        assert stats["final_threat_count"] == 2


class TestMergeThreats:
    """Test _merge_threats private method."""

    def test_merge_threats_no_duplicates(self):
        """Test merging threats with no duplicates."""
        aggregator = ThreatAggregator()

        existing_threats = [
            create_test_threat(rule_id="existing1", line_number=10),
        ]
        new_threats = [
            create_test_threat(rule_id="new1", line_number=50),
            create_test_threat(rule_id="new2", line_number=100),
        ]

        added_count = aggregator._merge_threats(existing_threats, new_threats)

        assert added_count == 2
        assert len(existing_threats) == 3
        rule_ids = [threat.rule_id for threat in existing_threats]
        assert "existing1" in rule_ids
        assert "new1" in rule_ids
        assert "new2" in rule_ids

    def test_merge_threats_with_duplicates(self):
        """Test merging threats with some duplicates."""
        aggregator = ThreatAggregator(proximity_threshold=2)

        existing_threats = [
            create_test_threat(
                rule_id="existing1", line_number=10, category="sql-injection"
            ),
        ]
        new_threats = [
            create_test_threat(
                rule_id="new1", line_number=11, category="sql-injection"
            ),  # Duplicate
            create_test_threat(
                rule_id="new2", line_number=50, category="xss"
            ),  # Not duplicate
        ]

        added_count = aggregator._merge_threats(existing_threats, new_threats)

        assert added_count == 1  # Only one threat added
        assert len(existing_threats) == 2
        rule_ids = [threat.rule_id for threat in existing_threats]
        assert "existing1" in rule_ids
        assert "new2" in rule_ids
        assert "new1" not in rule_ids  # Was duplicate


class TestThreatAggregatorLogging:
    """Test logging behavior of ThreatAggregator."""

    @patch("adversary_mcp_server.domain.aggregation.threat_aggregator.logger")
    def test_aggregation_logging(self, mock_logger):
        """Test that aggregation operations are logged."""
        aggregator = ThreatAggregator()

        semgrep_threats = [create_test_threat(rule_id="semgrep1")]
        llm_threats = [create_test_threat(rule_id="llm1")]

        aggregator.aggregate_threats(semgrep_threats, llm_threats)

        # Should log debug and info messages
        mock_logger.debug.assert_called()
        mock_logger.info.assert_called()

    @patch("adversary_mcp_server.domain.aggregation.threat_aggregator.logger")
    def test_duplicate_detection_logging(self, mock_logger):
        """Test that duplicate detection is logged."""
        aggregator = ThreatAggregator(proximity_threshold=2)

        semgrep_threats = [
            create_test_threat(
                rule_id="semgrep1", line_number=10, category="sql-injection"
            ),
        ]
        llm_threats = [
            create_test_threat(
                rule_id="llm1", line_number=11, category="sql-injection"
            ),  # Duplicate
        ]

        aggregator.aggregate_threats(semgrep_threats, llm_threats)

        # Should log duplicate detection
        debug_calls = [call.args[0] for call in mock_logger.debug.call_args_list]
        assert any("Duplicate threat detected" in msg for msg in debug_calls)

    @patch("adversary_mcp_server.domain.aggregation.threat_aggregator.logger")
    def test_proximity_threshold_configuration_logging(self, mock_logger):
        """Test that proximity threshold changes are logged."""
        aggregator = ThreatAggregator(proximity_threshold=2)

        aggregator.configure_proximity_threshold(5)

        # Should log threshold change
        mock_logger.info.assert_called_with("Proximity threshold changed: 2 → 5")


class TestThreatAggregatorIntegration:
    """Integration tests for ThreatAggregator."""

    def test_complex_aggregation_scenario(self):
        """Test complex aggregation scenario with multiple threat types."""
        aggregator = ThreatAggregator(proximity_threshold=3)

        # Semgrep threats (high priority)
        semgrep_threats = [
            create_test_threat(
                rule_id="semgrep.sql-injection",
                line_number=15,
                category="sql-injection",
                severity=SeverityLevel.HIGH,
            ),
            create_test_threat(
                rule_id="semgrep.xss",
                line_number=50,
                category="xss",
                severity=SeverityLevel.MEDIUM,
            ),
        ]

        # LLM threats (some duplicates, some unique)
        llm_threats = [
            create_test_threat(
                rule_id="llm.sql-injection",
                line_number=16,  # Close to semgrep finding
                category="injection",  # Similar category
                severity=SeverityLevel.MEDIUM,
            ),
            create_test_threat(
                rule_id="llm.path-traversal",
                line_number=100,  # Unique finding
                category="path-traversal",
                severity=SeverityLevel.HIGH,
            ),
            create_test_threat(
                rule_id="llm.xss-variant",
                line_number=52,  # Close to semgrep XSS
                category="script-injection",  # Similar to XSS
                severity=SeverityLevel.LOW,
            ),
        ]

        # Additional threats
        additional_threats = [
            create_test_threat(
                rule_id="custom.memory-leak",
                line_number=200,
                category="memory-leak",
                severity=SeverityLevel.LOW,
            ),
        ]

        result = aggregator.aggregate_threats(
            semgrep_threats, llm_threats, additional_threats
        )

        # Should prioritize Semgrep threats and deduplicate similar ones
        rule_ids = [threat.rule_id for threat in result]

        # Semgrep threats should be kept
        assert "semgrep.sql-injection" in rule_ids
        assert "semgrep.xss" in rule_ids

        # LLM path-traversal should be kept (unique)
        assert "llm.path-traversal" in rule_ids

        # Additional threat should be kept (unique)
        assert "custom.memory-leak" in rule_ids

        # LLM duplicates should be filtered out
        assert "llm.sql-injection" not in rule_ids  # Duplicate of semgrep SQL injection
        assert "llm.xss-variant" not in rule_ids  # Duplicate of semgrep XSS

        # Check statistics
        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 6
        assert stats["deduplicated_threats"] == 2
        assert stats["final_threat_count"] == 4

        # Check sorting (should be by line number)
        line_numbers = [threat.line_number for threat in result]
        assert line_numbers == sorted(line_numbers)

    def test_distribution_analysis_after_aggregation(self):
        """Test distribution analysis on aggregated results."""
        aggregator = ThreatAggregator()

        semgrep_threats = [
            create_test_threat(
                category="sql-injection", severity=SeverityLevel.HIGH, line_number=25
            ),
            create_test_threat(
                category="xss", severity=SeverityLevel.MEDIUM, line_number=75
            ),
        ]
        llm_threats = [
            create_test_threat(
                category="path-traversal", severity=SeverityLevel.LOW, line_number=150
            ),
        ]

        aggregated = aggregator.aggregate_threats(semgrep_threats, llm_threats)
        distribution = aggregator.analyze_threat_distribution(aggregated)

        # Verify distribution matches aggregated results
        assert len(aggregated) == 3
        assert distribution["by_severity"]["high"] == 1
        assert distribution["by_severity"]["medium"] == 1
        assert distribution["by_severity"]["low"] == 1
        assert distribution["by_category"]["sql-injection"] == 1
        assert distribution["by_category"]["xss"] == 1
        assert distribution["by_category"]["path-traversal"] == 1

    def test_zero_proximity_threshold(self):
        """Test aggregation with zero proximity threshold."""
        aggregator = ThreatAggregator(proximity_threshold=0)

        # Same line threats should still be duplicates
        semgrep_threats = [
            create_test_threat(
                rule_id="semgrep1", line_number=10, category="sql-injection"
            ),
        ]
        llm_threats = [
            create_test_threat(
                rule_id="llm1", line_number=10, category="sql-injection"
            ),  # Same line
            create_test_threat(
                rule_id="llm2", line_number=11, category="sql-injection"
            ),  # Different line, no proximity
        ]

        result = aggregator.aggregate_threats(semgrep_threats, llm_threats)

        # Should keep semgrep1 and llm2, filter out llm1
        rule_ids = [threat.rule_id for threat in result]
        assert "semgrep1" in rule_ids
        assert "llm2" in rule_ids
        assert "llm1" not in rule_ids

        assert len(result) == 2
