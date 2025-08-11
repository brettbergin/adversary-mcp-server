"""Tests for ThreatAggregator."""

import pytest

from adversary_mcp_server.domain.aggregation.threat_aggregator import ThreatAggregator
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


@pytest.fixture
def aggregator():
    """Create a ThreatAggregator instance."""
    return ThreatAggregator(proximity_threshold=2)


@pytest.fixture
def sample_semgrep_threats():
    """Create sample Semgrep threats."""
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
        ),
    ]


@pytest.fixture
def sample_llm_threats():
    """Create sample LLM threats."""
    return [
        ThreatMatch(
            rule_id="llm-sql-injection",
            rule_name="LLM SQL Injection Detection",
            description="Potential SQL injection - user input directly in query",
            category="sql-injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=11,  # Close to Semgrep threat at line 10
            column_number=8,
            code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
        ),
        ThreatMatch(
            rule_id="llm-path-traversal",
            rule_name="LLM Path Traversal Detection",
            description="Path traversal vulnerability",
            category="path-traversal",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=50,
            column_number=1,
            code_snippet="open(user_provided_path)",
        ),
    ]


class TestThreatAggregator:
    """Test ThreatAggregator functionality."""

    def test_initialization(self):
        """Test ThreatAggregator initialization."""
        aggregator = ThreatAggregator(proximity_threshold=3)
        assert aggregator.proximity_threshold == 3

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 0
        assert stats["deduplicated_threats"] == 0
        assert stats["final_threat_count"] == 0

    def test_default_initialization(self):
        """Test default initialization."""
        aggregator = ThreatAggregator()
        assert aggregator.proximity_threshold == 2

    def test_aggregate_no_threats(self, aggregator):
        """Test aggregation with no threats."""
        result = aggregator.aggregate_threats([], [])
        assert result == []

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 0
        assert stats["final_threat_count"] == 0

    def test_aggregate_semgrep_only(self, aggregator, sample_semgrep_threats):
        """Test aggregation with only Semgrep threats."""
        result = aggregator.aggregate_threats(sample_semgrep_threats, [])

        assert len(result) == 2
        assert result[0].category == "sql-injection"  # Line 10
        assert result[1].category == "xss"  # Line 25

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 2
        assert stats["deduplicated_threats"] == 0
        assert stats["final_threat_count"] == 2

    def test_aggregate_llm_only(self, aggregator, sample_llm_threats):
        """Test aggregation with only LLM threats."""
        result = aggregator.aggregate_threats([], sample_llm_threats)

        assert len(result) == 2
        assert result[0].category == "sql-injection"  # Line 11
        assert result[1].category == "path-traversal"  # Line 50

    def test_aggregate_with_deduplication(
        self, aggregator, sample_semgrep_threats, sample_llm_threats
    ):
        """Test aggregation with deduplication of similar threats."""
        result = aggregator.aggregate_threats(
            sample_semgrep_threats, sample_llm_threats
        )

        # Should have 3 threats: sql-injection (1, deduplicated), xss (1), path-traversal (1)
        assert len(result) == 3

        categories = [t.category for t in result]
        assert "sql-injection" in categories  # Only one should remain
        assert "xss" in categories
        assert "path-traversal" in categories

        # Check that it's sorted by line number
        line_numbers = [t.line_number for t in result]
        assert line_numbers == sorted(line_numbers)

        stats = aggregator.get_aggregation_stats()
        assert stats["total_input_threats"] == 4
        assert stats["deduplicated_threats"] == 1  # LLM SQL injection was deduplicated
        assert stats["final_threat_count"] == 3

    def test_proximity_threshold(self):
        """Test different proximity thresholds."""
        # Create threats at different distances
        semgrep_threat = ThreatMatch(
            rule_id="test-1",
            rule_name="Test Rule 1",
            description="Test",
            category="test",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            column_number=1,
            code_snippet="test",
        )

        # Threat at line 15 (distance = 5)
        llm_threat = ThreatMatch(
            rule_id="test-2",
            rule_name="Test Rule 2",
            description="Test",
            category="test",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=15,
            column_number=1,
            code_snippet="test",
        )

        # With threshold 3, should deduplicate (distance 5 > 3, so no deduplication)
        aggregator_strict = ThreatAggregator(proximity_threshold=3)
        result_strict = aggregator_strict.aggregate_threats(
            [semgrep_threat], [llm_threat]
        )
        assert len(result_strict) == 2  # Both threats kept

        # With threshold 10, should deduplicate (distance 5 <= 10)
        aggregator_loose = ThreatAggregator(proximity_threshold=10)
        result_loose = aggregator_loose.aggregate_threats(
            [semgrep_threat], [llm_threat]
        )
        assert len(result_loose) == 1  # One threat deduplicated

    def test_different_categories_not_deduplicated(self, aggregator):
        """Test that threats with different categories are not deduplicated."""
        semgrep_threat = ThreatMatch(
            rule_id="sql-1",
            rule_name="SQL Rule",
            description="SQL injection",
            category="sql-injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            column_number=1,
            code_snippet="test",
        )

        llm_threat = ThreatMatch(
            rule_id="xss-1",
            rule_name="XSS Rule",
            description="XSS vulnerability",
            category="xss",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=11,
            column_number=1,
            code_snippet="test",
        )

        result = aggregator.aggregate_threats([semgrep_threat], [llm_threat])
        assert len(result) == 2  # Different categories, both kept

    def test_similar_categories_deduplicated(self, aggregator):
        """Test that similar categories are deduplicated."""
        semgrep_threat = ThreatMatch(
            rule_id="sql-1",
            rule_name="SQL Rule",
            description="SQL injection",
            category="sql-injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            column_number=1,
            code_snippet="test",
        )

        llm_threat = ThreatMatch(
            rule_id="injection-1",
            rule_name="Injection Rule",
            description="Injection vulnerability",
            category="injection",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=11,
            column_number=1,
            code_snippet="test",
        )

        result = aggregator.aggregate_threats([semgrep_threat], [llm_threat])
        assert len(result) == 1  # Similar categories, deduplicated

    def test_additional_threats(self, aggregator, sample_semgrep_threats):
        """Test aggregation with additional threats from other scanners."""
        additional_threats = [
            ThreatMatch(
                rule_id="custom-rule",
                rule_name="Custom Rule",
                description="Custom vulnerability",
                category="custom-vuln",
                severity=Severity.LOW,
                file_path="test.py",
                line_number=100,
                column_number=1,
                code_snippet="custom code",
            )
        ]

        result = aggregator.aggregate_threats(
            sample_semgrep_threats, [], additional_threats
        )

        assert len(result) == 3  # 2 Semgrep + 1 additional
        assert any(t.category == "custom-vuln" for t in result)

    def test_threat_sorting(self, aggregator):
        """Test that threats are sorted correctly."""
        threats_unsorted = [
            ThreatMatch(
                rule_id="rule-3",
                rule_name="Rule 3",
                description="Test",
                category="vuln-c",
                severity=Severity.LOW,
                file_path="test.py",
                line_number=30,
                column_number=1,
                code_snippet="test",
            ),
            ThreatMatch(
                rule_id="rule-1",
                rule_name="Rule 1",
                description="Test",
                category="vuln-a",
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                column_number=1,
                code_snippet="test",
            ),
            ThreatMatch(
                rule_id="rule-2",
                rule_name="Rule 2",
                description="Test",
                category="vuln-b",
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=20,
                column_number=1,
                code_snippet="test",
            ),
        ]

        result = aggregator.aggregate_threats(threats_unsorted, [])

        # Should be sorted by line number
        line_numbers = [t.line_number for t in result]
        assert line_numbers == [10, 20, 30]

    def test_configure_proximity_threshold(self, aggregator):
        """Test configuring proximity threshold."""
        assert aggregator.proximity_threshold == 2

        aggregator.configure_proximity_threshold(5)
        assert aggregator.proximity_threshold == 5

    def test_invalid_proximity_threshold(self, aggregator):
        """Test invalid proximity threshold."""
        with pytest.raises(
            ValueError, match="Proximity threshold must be non-negative"
        ):
            aggregator.configure_proximity_threshold(-1)

    def test_analyze_threat_distribution(self, aggregator):
        """Test threat distribution analysis."""
        threats = [
            ThreatMatch(
                rule_id="rule-1",
                rule_name="Rule 1",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                column_number=1,
                code_snippet="test",
            ),
            ThreatMatch(
                rule_id="rule-2",
                rule_name="Rule 2",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=60,
                column_number=1,
                code_snippet="test",
            ),
            ThreatMatch(
                rule_id="rule-3",
                rule_name="Rule 3",
                description="Test",
                category=Category.XSS,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=150,
                column_number=1,
                code_snippet="test",
            ),
        ]

        distribution = aggregator.analyze_threat_distribution(threats)

        # Check severity distribution
        assert distribution["by_severity"]["HIGH"] == 2
        assert distribution["by_severity"]["MEDIUM"] == 1

        # Check category distribution
        assert distribution["by_category"]["injection"] == 2
        assert distribution["by_category"]["xss"] == 1

        # Check line range distribution
        assert distribution["by_line_range"]["1-50"] == 1  # Line 10
        assert distribution["by_line_range"]["51-100"] == 1  # Line 60
        assert distribution["by_line_range"]["101-500"] == 1  # Line 150

    def test_aggregation_stats_tracking(
        self, aggregator, sample_semgrep_threats, sample_llm_threats
    ):
        """Test that aggregation statistics are tracked correctly."""
        # Initial stats should be zeros
        initial_stats = aggregator.get_aggregation_stats()
        assert initial_stats["total_input_threats"] == 0

        # After aggregation, stats should be updated
        result = aggregator.aggregate_threats(
            sample_semgrep_threats, sample_llm_threats
        )
        final_stats = aggregator.get_aggregation_stats()

        assert final_stats["total_input_threats"] == 4
        assert final_stats["final_threat_count"] == len(result)
        assert final_stats["deduplicated_threats"] >= 0

        # Verify math: input - deduplicated = final
        assert (
            final_stats["total_input_threats"] - final_stats["deduplicated_threats"]
            == final_stats["final_threat_count"]
        )


class TestThreatAggregatorEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_threat_handling(self):
        """Test handling of empty threat lists."""
        aggregator = ThreatAggregator()

        # All empty
        result = aggregator.aggregate_threats([], [], [])
        assert result == []

        # Mixed empty and non-empty
        threat = ThreatMatch(
            rule_id="test",
            rule_name="Test Rule",
            description="Test",
            category="test",
            severity=Severity.LOW,
            file_path="test.py",
            line_number=1,
            column_number=1,
            code_snippet="test",
        )
        result = aggregator.aggregate_threats([threat], [], [])
        assert len(result) == 1

    def test_duplicate_detection_edge_cases(self):
        """Test edge cases in duplicate detection."""
        aggregator = ThreatAggregator(proximity_threshold=0)  # Exact match only

        # Identical threats except ID
        threat1 = ThreatMatch(
            rule_id="test-1",
            rule_name="Test Rule 1",
            description="Test",
            category="test",
            severity=Severity.LOW,
            file_path="test.py",
            line_number=10,
            column_number=1,
            code_snippet="test",
        )
        threat2 = ThreatMatch(
            rule_id="test-2",
            rule_name="Test Rule 2",
            description="Test",
            category="test",
            severity=Severity.LOW,
            file_path="test.py",
            line_number=10,
            column_number=1,
            code_snippet="test",
        )

        result = aggregator.aggregate_threats([threat1], [threat2])
        assert len(result) == 1  # Should be deduplicated

    def test_large_line_numbers(self):
        """Test handling of large line numbers."""
        aggregator = ThreatAggregator()

        threat = ThreatMatch(
            rule_id="test",
            rule_name="Test Rule",
            description="Test",
            category=Category.DISCLOSURE,
            severity=Severity.LOW,
            file_path="test.py",
            line_number=999999,
            column_number=1,
            code_snippet="test",
        )

        result = aggregator.aggregate_threats([threat], [])
        assert len(result) == 1

        distribution = aggregator.analyze_threat_distribution(result)
        assert distribution["by_line_range"]["500+"] == 1
        assert distribution["by_category"]["disclosure"] == 1
