"""ThreatAggregator domain service with strategy pattern."""

import logging
from abc import ABC, abstractmethod

from ..entities.threat_match import ThreatMatch
from ..interfaces import AggregationError
from ..utils import merge_scanner_names

logger = logging.getLogger(__name__)


class BaseThreatAggregationStrategy(ABC):
    """Base class for threat aggregation strategies."""

    @abstractmethod
    def aggregate_threats(
        self, threat_groups: list[list[ThreatMatch]]
    ) -> list[ThreatMatch]:
        """Aggregate threats from multiple sources."""
        pass

    @abstractmethod
    def merge_similar_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """Merge threats that are similar or duplicates."""
        pass

    @abstractmethod
    def get_strategy_name(self) -> str:
        """Get the name of this aggregation strategy."""
        pass


class ProximityBasedAggregationStrategy(BaseThreatAggregationStrategy):
    """
    Aggregation strategy that merges threats based on proximity in the same file.

    Threats are considered similar if they are in the same file, have the same
    rule ID, and are within a specified number of lines from each other.
    """

    def __init__(self, proximity_threshold: int = 5):
        self.proximity_threshold = proximity_threshold

    def get_strategy_name(self) -> str:
        return f"proximity_based(threshold={self.proximity_threshold})"

    def aggregate_threats(
        self, threat_groups: list[list[ThreatMatch]]
    ) -> list[ThreatMatch]:
        """Aggregate threats from multiple sources using proximity-based merging."""
        if not threat_groups:
            return []

        # Flatten all threats from all groups
        all_threats = []
        for group in threat_groups:
            all_threats.extend(group)

        if not all_threats:
            return []

        # Merge similar threats within the combined set
        return self.merge_similar_threats(all_threats)

    def merge_similar_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """Merge threats that are close together in the same file."""
        if not threats:
            return []

        # Group threats by file and rule for efficient comparison
        threat_groups = self._group_threats_by_file_and_rule(threats)

        merged_threats = []

        for (file_path, rule_id), file_threats in threat_groups.items():
            # Sort by line number for proximity checking
            file_threats.sort(key=lambda t: t.line_number)

            # Merge threats that are close together
            merged_file_threats = self._merge_proximate_threats(file_threats)
            merged_threats.extend(merged_file_threats)

        logger.debug(
            f"Proximity merging: {len(threats)} -> {len(merged_threats)} threats"
        )
        return merged_threats

    def _group_threats_by_file_and_rule(
        self, threats: list[ThreatMatch]
    ) -> dict[tuple[str, str], list[ThreatMatch]]:
        """Group threats by file path (allow merging across different rule IDs based on proximity)."""
        groups = {}

        for threat in threats:
            # Only group by file path for proximity-based merging
            key = (str(threat.file_path), "")  # Empty rule_id allows cross-rule merging
            if key not in groups:
                groups[key] = []
            groups[key].append(threat)

        return groups

    def _merge_proximate_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """Merge threats that are within proximity threshold."""
        if not threats:
            return []

        merged = []
        current_group = [threats[0]]

        for threat in threats[1:]:
            # Check if this threat is close to any in the current group
            if any(
                abs(threat.line_number - t.line_number) <= self.proximity_threshold
                for t in current_group
            ):
                current_group.append(threat)
            else:
                # Process current group and start new one
                merged_threat = self._merge_threat_group(current_group)
                merged.append(merged_threat)
                current_group = [threat]

        # Process the last group
        if current_group:
            merged_threat = self._merge_threat_group(current_group)
            merged.append(merged_threat)

        return merged

    def _merge_threat_group(self, threats: list[ThreatMatch]) -> ThreatMatch:
        """Merge a group of similar threats into a single threat."""
        if len(threats) == 1:
            return threats[0]

        # Use the first threat as base and merge others into it
        base_threat = threats[0]

        for other_threat in threats[1:]:
            # For proximity-based grouping, we need to be more lenient with merging
            # Check if they can be merged using standard similarity check
            if base_threat.is_similar_to(other_threat):
                base_threat = base_threat.merge_with(other_threat)
            else:
                # For proximity-grouped threats that don't meet strict similarity,
                # manually merge by combining the information
                base_threat = self._force_merge_threats(base_threat, other_threat)

        return base_threat

    def _force_merge_threats(
        self, base: ThreatMatch, other: ThreatMatch
    ) -> ThreatMatch:
        """Force merge two threats that are proximity-grouped but not strictly similar."""
        # Use the higher confidence
        best_confidence = max(base.confidence, other.confidence)

        # Use the higher severity
        best_severity = max(base.severity, other.severity)

        # Combine exploit examples
        combined_exploits = list(set(base.exploit_examples + other.exploit_examples))

        # Combine remediation advice
        combined_remediation = base.remediation
        if other.remediation and other.remediation != base.remediation:
            combined_remediation = f"{base.remediation}; {other.remediation}"

        # Combine descriptions if different
        combined_description = base.description
        if other.description and other.description != base.description:
            combined_description = f"{base.description}; {other.description}"

        # Create merged threat with combined information
        return ThreatMatch(
            rule_id=base.rule_id,  # Keep base rule_id
            rule_name=(
                f"{base.rule_name} + {other.rule_name}"
                if base.rule_name != other.rule_name
                else base.rule_name
            ),
            description=combined_description,
            category=base.category,  # Keep base category
            severity=best_severity,
            file_path=base.file_path,
            line_number=min(
                base.line_number, other.line_number
            ),  # Use the earlier line
            column_number=base.column_number,
            code_snippet=base.code_snippet,  # Keep base code snippet
            function_name=base.function_name or other.function_name,
            exploit_examples=combined_exploits,
            remediation=combined_remediation,
            references=base.references
            + [ref for ref in other.references if ref not in base.references],
            cwe_id=base.cwe_id or other.cwe_id,
            owasp_category=base.owasp_category or other.owasp_category,
            confidence=best_confidence,
            source_scanner=merge_scanner_names(
                base.source_scanner, other.source_scanner
            ),
            is_false_positive=base.is_false_positive and other.is_false_positive,
            uuid=base.uuid,  # Keep base UUID
        )


class FingerprintBasedAggregationStrategy(BaseThreatAggregationStrategy):
    """
    Aggregation strategy that merges threats based on fingerprint similarity.

    Threats are considered identical if they have the same file path, line number,
    and category. This provides basic deduplication for security scan results.
    """

    def get_strategy_name(self) -> str:
        return "fingerprint_based"

    def aggregate_threats(
        self, threat_groups: list[list[ThreatMatch]]
    ) -> list[ThreatMatch]:
        """Aggregate threats from multiple sources using fingerprint-based deduplication."""
        if not threat_groups:
            return []

        # Flatten all threats from all groups
        all_threats = []
        for group in threat_groups:
            all_threats.extend(group)

        if not all_threats:
            return []

        # Apply fingerprint-based deduplication
        deduplicated = self.merge_similar_threats(all_threats)

        logger.debug(
            f"Fingerprint aggregation: {len(all_threats)} -> {len(deduplicated)} threats"
        )
        return deduplicated

    def merge_similar_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """Merge threats based on fingerprint similarity."""
        if not threats:
            return []

        # Group threats by fingerprint (file_path + line_number + category)
        fingerprint_groups = {}
        for threat in threats:
            fingerprint = f"{threat.file_path}:{threat.line_number}:{threat.category}"
            if fingerprint not in fingerprint_groups:
                fingerprint_groups[fingerprint] = []
            fingerprint_groups[fingerprint].append(threat)

        # Merge each group
        merged_threats = []
        for group in fingerprint_groups.values():
            if len(group) == 1:
                merged_threats.append(group[0])
            else:
                merged_threats.append(self._merge_identical_threats(group))

        logger.debug(
            f"Fingerprint merging: {len(threats)} -> {len(merged_threats)} threats"
        )
        return merged_threats

    def _merge_identical_threats(self, threats: list[ThreatMatch]) -> ThreatMatch:
        """Merge threats with identical fingerprints."""
        if len(threats) == 1:
            return threats[0]

        # Sort by confidence to use the most confident as base
        threats.sort(key=lambda t: t.confidence.get_decimal(), reverse=True)

        base_threat = threats[0]

        # Merge information from other threats
        for other_threat in threats[1:]:
            # Combine exploit examples
            for example in other_threat.exploit_examples:
                if example not in base_threat.exploit_examples:
                    base_threat = base_threat.add_exploit_example(example)

            # Use higher severity
            if other_threat.severity > base_threat.severity:
                # Create new threat with higher severity
                base_threat = ThreatMatch(
                    rule_id=base_threat.rule_id,
                    rule_name=base_threat.rule_name,
                    description=base_threat.description,
                    category=base_threat.category,
                    severity=other_threat.severity,
                    file_path=base_threat.file_path,
                    line_number=base_threat.line_number,
                    column_number=base_threat.column_number,
                    code_snippet=base_threat.code_snippet,
                    function_name=base_threat.function_name,
                    exploit_examples=base_threat.exploit_examples,
                    remediation=base_threat.remediation,
                    references=base_threat.references,
                    cwe_id=base_threat.cwe_id or other_threat.cwe_id,
                    owasp_category=base_threat.owasp_category
                    or other_threat.owasp_category,
                    confidence=base_threat.confidence,
                    source_scanner=merge_scanner_names(
                        base_threat.source_scanner, other_threat.source_scanner
                    ),
                    is_false_positive=base_threat.is_false_positive
                    and other_threat.is_false_positive,
                    uuid=base_threat.uuid,
                )

        return base_threat


class HybridAggregationStrategy(BaseThreatAggregationStrategy):
    """
    Hybrid aggregation strategy that combines multiple approaches.

    First applies fingerprint-based deduplication, then applies proximity-based
    merging for remaining threats to catch similar threats that aren't exact duplicates.
    """

    def __init__(self, proximity_threshold: int = 5):
        self.fingerprint_strategy = FingerprintBasedAggregationStrategy()
        self.proximity_strategy = ProximityBasedAggregationStrategy(proximity_threshold)

    def get_strategy_name(self) -> str:
        return f"hybrid(fingerprint+proximity_threshold={self.proximity_strategy.proximity_threshold})"

    def aggregate_threats(
        self, threat_groups: list[list[ThreatMatch]]
    ) -> list[ThreatMatch]:
        """Aggregate threats using hybrid approach."""
        if not threat_groups:
            return []

        # First apply fingerprint-based deduplication
        fingerprint_merged = self.fingerprint_strategy.aggregate_threats(threat_groups)

        # Then apply proximity-based merging
        hybrid_merged = self.proximity_strategy.merge_similar_threats(
            fingerprint_merged
        )

        logger.debug(
            f"Hybrid aggregation: {sum(len(g) for g in threat_groups)} -> {len(hybrid_merged)} threats"
        )
        return hybrid_merged

    def merge_similar_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """Merge similar threats using hybrid approach."""
        # Apply fingerprint deduplication first
        fingerprint_merged = self.fingerprint_strategy.merge_similar_threats(threats)

        # Then apply proximity merging
        return self.proximity_strategy.merge_similar_threats(fingerprint_merged)


class ThreatAggregator:
    """
    Domain service for threat aggregation with pluggable strategies.

    Provides a clean interface for aggregating threats from multiple sources
    while supporting different aggregation approaches through strategy pattern.
    """

    def __init__(self, strategy: BaseThreatAggregationStrategy = None):
        # Use hybrid strategy as default for comprehensive threat deduplication
        self.strategy = strategy or HybridAggregationStrategy()

    def set_strategy(self, strategy: BaseThreatAggregationStrategy) -> None:
        """Set the aggregation strategy."""
        self.strategy = strategy
        logger.debug(f"Set aggregation strategy: {strategy.get_strategy_name()}")

    def aggregate_threats(
        self, threat_groups: list[list[ThreatMatch]]
    ) -> list[ThreatMatch]:
        """
        Aggregate threats from multiple sources.

        Args:
            threat_groups: Groups of threats from different sources/scanners

        Returns:
            Deduplicated and merged list of threats

        Raises:
            AggregationError: If aggregation fails
        """
        try:
            if not threat_groups:
                return []

            # Filter out empty groups
            non_empty_groups = [group for group in threat_groups if group]

            if not non_empty_groups:
                return []

            logger.debug(
                f"Aggregating {len(non_empty_groups)} threat groups with strategy: {self.strategy.get_strategy_name()}"
            )

            result = self.strategy.aggregate_threats(non_empty_groups)

            logger.info(
                f"Threat aggregation completed: {sum(len(g) for g in non_empty_groups)} -> {len(result)} threats"
            )
            return result

        except Exception as e:
            logger.error(f"Threat aggregation failed: {e}")
            raise AggregationError(f"Threat aggregation failed: {e}") from e

    def merge_similar_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """
        Merge threats that are similar or duplicates.

        Args:
            threats: List of threats to deduplicate

        Returns:
            Deduplicated list with merged threat information

        Raises:
            AggregationError: If merging fails
        """
        try:
            if not threats:
                return []

            logger.debug(
                f"Merging {len(threats)} similar threats with strategy: {self.strategy.get_strategy_name()}"
            )

            result = self.strategy.merge_similar_threats(threats)

            logger.info(
                f"Threat merging completed: {len(threats)} -> {len(result)} threats"
            )
            return result

        except Exception as e:
            logger.error(f"Threat merging failed: {e}")
            raise AggregationError(f"Threat merging failed: {e}") from e

    def get_aggregation_strategy_name(self) -> str:
        """Get the name of the current aggregation strategy."""
        return self.strategy.get_strategy_name()

    def get_statistics(self, original_count: int, final_count: int) -> dict[str, any]:
        """Get aggregation statistics."""
        reduction_percentage = (
            ((original_count - final_count) / original_count * 100)
            if original_count > 0
            else 0
        )

        return {
            "strategy": self.get_aggregation_strategy_name(),
            "original_threat_count": original_count,
            "final_threat_count": final_count,
            "threats_merged": original_count - final_count,
            "reduction_percentage": round(reduction_percentage, 2),
        }
