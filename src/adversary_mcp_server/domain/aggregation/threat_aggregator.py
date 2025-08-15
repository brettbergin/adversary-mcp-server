"""Threat aggregation and deduplication logic.

This module provides intelligent combination of threats from multiple sources,
implementing sophisticated deduplication based on proximity and similarity.
"""

from ...logger import get_logger
from ..entities.threat_match import ThreatMatch

logger = get_logger("threat_aggregator")


class ThreatAggregator:
    """Intelligent threat aggregation with deduplication and prioritization.

    This class handles combining threats from multiple scanning engines:
    - Semgrep (static analysis)
    - LLM (intelligent analysis)
    - Future scanners

    Features:
    - Proximity-based deduplication (threats within 2 lines)
    - Category-aware merging
    - Severity-based prioritization
    - Configurable deduplication rules
    """

    def __init__(self, proximity_threshold: int = 2):
        """Initialize the threat aggregator.

        Args:
            proximity_threshold: Maximum line distance to consider threats duplicates
        """
        self.proximity_threshold = proximity_threshold
        self._aggregation_stats = {
            "total_input_threats": 0,
            "deduplicated_threats": 0,
            "final_threat_count": 0,
        }

    def aggregate_threats(
        self,
        semgrep_threats: list[ThreatMatch],
        llm_threats: list[ThreatMatch],
        additional_threats: list[ThreatMatch] = None,
    ) -> list[ThreatMatch]:
        """Aggregate threats from multiple sources with intelligent deduplication.

        Semgrep threats are prioritized as they tend to be more precise,
        then LLM threats are added if they don't duplicate existing findings.

        Args:
            semgrep_threats: Threats from Semgrep static analysis
            llm_threats: Threats from LLM analysis
            additional_threats: Optional additional threats from other scanners

        Returns:
            Deduplicated and prioritized list of threats
        """
        if additional_threats is None:
            additional_threats = []

        logger.debug(
            f"Aggregating threats: Semgrep={len(semgrep_threats)}, "
            f"LLM={len(llm_threats)}, Additional={len(additional_threats)}"
        )

        # Track aggregation statistics
        total_input = len(semgrep_threats) + len(llm_threats) + len(additional_threats)
        self._aggregation_stats["total_input_threats"] = total_input

        # Start with high-confidence Semgrep threats
        aggregated = list(semgrep_threats)
        logger.debug(f"Starting with {len(aggregated)} Semgrep threats")

        # Add LLM threats that don't duplicate Semgrep findings
        llm_added = self._merge_threats(aggregated, llm_threats)
        logger.debug(f"Added {llm_added} unique LLM threats")

        # Add any additional threats
        if additional_threats:
            additional_added = self._merge_threats(aggregated, additional_threats)
            logger.debug(f"Added {additional_added} additional threats")

        # Sort by line number and severity for consistent ordering
        aggregated = self._sort_threats(aggregated)

        # Update statistics
        deduplicated_count = total_input - len(aggregated)
        self._aggregation_stats["deduplicated_threats"] = deduplicated_count
        self._aggregation_stats["final_threat_count"] = len(aggregated)

        logger.info(
            f"Threat aggregation complete: {total_input} → {len(aggregated)} "
            f"({deduplicated_count} duplicates removed)"
        )

        return aggregated

    def _merge_threats(
        self, existing_threats: list[ThreatMatch], new_threats: list[ThreatMatch]
    ) -> int:
        """Merge new threats into existing list, avoiding duplicates.

        Args:
            existing_threats: List to merge into (modified in place)
            new_threats: Threats to potentially add

        Returns:
            Number of threats actually added
        """
        added_count = 0

        for threat in new_threats:
            if not self._is_duplicate(threat, existing_threats):
                existing_threats.append(threat)
                added_count += 1

        return added_count

    def _is_duplicate(
        self, threat: ThreatMatch, existing_threats: list[ThreatMatch]
    ) -> bool:
        """Check if a threat duplicates any existing threats.

        Duplication criteria:
        - Same file path
        - Line numbers within proximity threshold
        - Same threat category

        Args:
            threat: Threat to check for duplication
            existing_threats: List of existing threats

        Returns:
            True if threat is a duplicate
        """
        for existing in existing_threats:
            if self._are_threats_similar(threat, existing):
                logger.debug(
                    f"Duplicate threat detected: {threat.category} at line {threat.line_number} "
                    f"similar to existing at line {existing.line_number}"
                )
                return True

        return False

    def _are_threats_similar(self, threat1: ThreatMatch, threat2: ThreatMatch) -> bool:
        """Check if two threats are similar enough to be considered duplicates.

        Args:
            threat1: First threat to compare
            threat2: Second threat to compare

        Returns:
            True if threats are similar
        """
        # Must be same file (assuming single-file analysis)
        # If file paths are available, uncomment:
        # if getattr(threat1, 'file_path', None) != getattr(threat2, 'file_path', None):
        #     return False

        # Check line proximity
        line_distance = abs(threat1.line_number - threat2.line_number)
        if line_distance > self.proximity_threshold:
            return False

        # Check category similarity
        if threat1.category != threat2.category:
            # Special cases for similar categories
            similar_categories = {
                "sql-injection": ["injection", "sqli"],
                "xss": ["cross-site-scripting", "script-injection"],
                "path-traversal": ["directory-traversal", "path-injection"],
            }

            cat1_lower = threat1.category.lower()
            cat2_lower = threat2.category.lower()

            # Check if categories are in the same similarity group
            for main_cat, similar_cats in similar_categories.items():
                if (cat1_lower == main_cat or cat1_lower in similar_cats) and (
                    cat2_lower == main_cat or cat2_lower in similar_cats
                ):
                    return True

            return False

        return True

    def _sort_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """Sort threats by line number and severity for consistent ordering.

        Args:
            threats: List of threats to sort

        Returns:
            Sorted list of threats
        """
        return sorted(
            threats,
            key=lambda t: (
                t.line_number,  # Primary sort by line number
                t.severity.get_numeric_value(),  # Secondary sort by severity value (domain method)
                t.category,  # Tertiary sort by category for stability
            ),
        )

    def get_aggregation_stats(self) -> dict[str, int]:
        """Get statistics about the last aggregation operation.

        Returns:
            Dictionary with aggregation statistics
        """
        return self._aggregation_stats.copy()

    def configure_proximity_threshold(self, threshold: int) -> None:
        """Configure the proximity threshold for deduplication.

        Args:
            threshold: New proximity threshold (lines)
        """
        if threshold < 0:
            raise ValueError("Proximity threshold must be non-negative")

        old_threshold = self.proximity_threshold
        self.proximity_threshold = threshold
        logger.info(f"Proximity threshold changed: {old_threshold} → {threshold}")

    def analyze_threat_distribution(
        self, threats: list[ThreatMatch]
    ) -> dict[str, dict[str, int]]:
        """Analyze the distribution of threats by various dimensions.

        Args:
            threats: List of threats to analyze

        Returns:
            Dictionary with distribution analysis
        """
        by_severity = {}
        by_category = {}
        by_line_range = {"1-50": 0, "51-100": 0, "101-500": 0, "500+": 0}

        for threat in threats:
            # Count by severity (domain SeverityLevel)
            severity_name = str(threat.severity)  # SeverityLevel has __str__ method
            by_severity[severity_name] = by_severity.get(severity_name, 0) + 1

            # Count by category (domain category is string)
            category_name = threat.category
            by_category[category_name] = by_category.get(category_name, 0) + 1

            # Count by line range
            line_num = threat.line_number
            if line_num <= 50:
                by_line_range["1-50"] += 1
            elif line_num <= 100:
                by_line_range["51-100"] += 1
            elif line_num <= 500:
                by_line_range["101-500"] += 1
            else:
                by_line_range["500+"] += 1

        return {
            "by_severity": by_severity,
            "by_category": by_category,
            "by_line_range": by_line_range,
        }
