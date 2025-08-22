"""ScanResult domain entity with aggregation and computation logic."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..value_objects.confidence_score import ConfidenceScore
from ..value_objects.severity_level import SeverityLevel
from .scan_request import ScanRequest
from .threat_match import ThreatMatch


@dataclass
class ScanStatistics:
    """Statistics about a scan operation."""

    total_threats_found: int = 0
    threats_by_severity: dict[str, int] = field(default_factory=dict)
    threats_by_source: dict[str, int] = field(default_factory=dict)
    threats_by_confidence: dict[str, int] = field(default_factory=dict)
    false_positives_filtered: int = 0
    files_scanned: int = 0
    lines_analyzed: int = 0
    scan_duration_seconds: float = 0.0

    def add_threat(self, threat: ThreatMatch) -> None:
        """Add a threat to the statistics."""
        self.total_threats_found += 1

        # Track by severity
        severity_key = str(threat.severity)
        self.threats_by_severity[severity_key] = (
            self.threats_by_severity.get(severity_key, 0) + 1
        )

        # Track by source
        self.threats_by_source[threat.source_scanner] = (
            self.threats_by_source.get(threat.source_scanner, 0) + 1
        )

        # Track by confidence level
        confidence_level = threat.confidence.get_quality_level()
        self.threats_by_confidence[confidence_level] = (
            self.threats_by_confidence.get(confidence_level, 0) + 1
        )

    def mark_false_positive(self) -> None:
        """Mark a threat as false positive."""
        self.false_positives_filtered += 1
        self.total_threats_found = max(0, self.total_threats_found - 1)


@dataclass
class ScanResult:
    """
    Domain entity representing the result of a security scan operation.

    Provides rich behavior for threat aggregation, filtering, analysis,
    and reporting. Encapsulates all scan outcomes and provides business
    logic for result processing and presentation.
    """

    request: ScanRequest
    threats: list[ThreatMatch] = field(default_factory=list)
    scan_metadata: dict[str, Any] = field(default_factory=dict)
    validation_applied: bool = False
    completed_at: datetime = field(default_factory=datetime.utcnow)

    # Computed properties (lazy evaluation)
    _statistics: dict[str, Any] | None = field(default=None, init=False)
    _threats_by_file: dict[str, list[ThreatMatch]] | None = field(
        default=None, init=False
    )
    _high_priority_threats: list[ThreatMatch] | None = field(default=None, init=False)

    @classmethod
    def create_empty(cls, request: ScanRequest) -> "ScanResult":
        """Create an empty scan result for a request."""
        return cls(
            request=request,
            threats=[],
            scan_metadata={"scan_id": request.context.metadata.scan_id},
            validation_applied=False,
        )

    @classmethod
    def create_from_threats(
        cls,
        request: ScanRequest,
        threats: list[ThreatMatch],
        scan_metadata: dict[str, Any] | None = None,
        validation_applied: bool = False,
    ) -> "ScanResult":
        """Create a scan result from a list of threats."""
        metadata = scan_metadata or {}
        metadata["scan_id"] = request.context.metadata.scan_id

        return cls(
            request=request,
            threats=threats.copy(),
            scan_metadata=metadata,
            validation_applied=validation_applied,
        )

    def add_threat(self, threat: ThreatMatch) -> "ScanResult":
        """Create a new scan result with an additional threat."""
        new_threats = self.threats.copy()
        new_threats.append(threat)

        return ScanResult(
            request=self.request,
            threats=new_threats,
            scan_metadata=self.scan_metadata.copy(),
            validation_applied=self.validation_applied,
            completed_at=self.completed_at,
        )

    def add_threats(self, threats: list[ThreatMatch]) -> "ScanResult":
        """Create a new scan result with additional threats."""
        if not threats:
            return self

        new_threats = self.threats.copy()
        new_threats.extend(threats)

        return ScanResult(
            request=self.request,
            threats=new_threats,
            scan_metadata=self.scan_metadata.copy(),
            validation_applied=self.validation_applied,
            completed_at=self.completed_at,
        )

    def filter_by_severity(self, min_severity: SeverityLevel) -> "ScanResult":
        """Create a new scan result with threats filtered by minimum severity."""
        filtered_threats = [
            threat
            for threat in self.threats
            if threat.severity.meets_threshold(min_severity)
        ]

        return ScanResult(
            request=self.request,
            threats=filtered_threats,
            scan_metadata=self.scan_metadata.copy(),
            validation_applied=self.validation_applied,
            completed_at=self.completed_at,
        )

    def filter_by_confidence(self, min_confidence: ConfidenceScore) -> "ScanResult":
        """Create a new scan result with threats filtered by minimum confidence."""
        filtered_threats = [
            threat
            for threat in self.threats
            if threat.confidence.meets_threshold(min_confidence)
        ]

        return ScanResult(
            request=self.request,
            threats=filtered_threats,
            scan_metadata=self.scan_metadata.copy(),
            validation_applied=self.validation_applied,
            completed_at=self.completed_at,
        )

    def exclude_false_positives(self) -> "ScanResult":
        """Create a new scan result with false positives excluded."""
        filtered_threats = [
            threat for threat in self.threats if not threat.is_false_positive
        ]

        return ScanResult(
            request=self.request,
            threats=filtered_threats,
            scan_metadata=self.scan_metadata.copy(),
            validation_applied=self.validation_applied,
            completed_at=self.completed_at,
        )

    def filter_actionable_threats(self) -> "ScanResult":
        """Create a new scan result with only actionable threats (high severity + confident)."""
        actionable_threats = [
            threat for threat in self.threats if threat.is_actionable()
        ]

        return ScanResult(
            request=self.request,
            threats=actionable_threats,
            scan_metadata=self.scan_metadata.copy(),
            validation_applied=self.validation_applied,
            completed_at=self.completed_at,
        )

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive statistics about this scan result."""
        if self._statistics is None:
            stats = ScanStatistics()

            for threat in self.threats:
                stats.add_threat(threat)

            # Calculate scan metadata
            stats.files_scanned = len(self.get_affected_files())
            stats.scan_duration_seconds = self.scan_metadata.get(
                "scan_duration_seconds", 0.0
            )
            stats.lines_analyzed = self.scan_metadata.get("lines_analyzed", 0)

            # Use validation metadata if available for accurate false positive count
            if "validation_stats" in self.scan_metadata:
                validation_stats = self.scan_metadata["validation_stats"]
                stats.false_positives_filtered = validation_stats.get(
                    "false_positives_filtered", 0
                )
            else:
                # Fallback to counting false positives in final threats
                stats.false_positives_filtered = len(
                    [t for t in self.threats if t.is_false_positive]
                )

            # Convert to dictionary format expected by formatters
            self._statistics = {
                "total_threats": stats.total_threats_found,
                "by_severity": stats.threats_by_severity,
                "by_source": stats.threats_by_source,
                "by_confidence": stats.threats_by_confidence,
                "false_positives_filtered": stats.false_positives_filtered,
                "files_scanned": stats.files_scanned,
                "lines_analyzed": stats.lines_analyzed,
                "scan_duration_seconds": stats.scan_duration_seconds,
            }

        return self._statistics

    def get_threats_by_file(self) -> dict[str, list[ThreatMatch]]:
        """Get threats organized by file path."""
        if self._threats_by_file is None:
            threats_by_file = {}

            for threat in self.threats:
                file_key = str(threat.file_path)
                if file_key not in threats_by_file:
                    threats_by_file[file_key] = []
                threats_by_file[file_key].append(threat)

            self._threats_by_file = threats_by_file

        return self._threats_by_file

    def get_high_priority_threats(self) -> list[ThreatMatch]:
        """Get threats that require immediate attention."""
        if self._high_priority_threats is None:
            high_priority = [
                threat
                for threat in self.threats
                if threat.get_priority_category() in ["Critical", "High"]
                and not threat.is_false_positive
            ]

            # Sort by risk score descending
            high_priority.sort(key=lambda t: t.get_risk_score(), reverse=True)
            self._high_priority_threats = high_priority

        return self._high_priority_threats

    def get_affected_files(self) -> list[str]:
        """Get list of unique file paths that have threats."""
        return list({str(threat.file_path) for threat in self.threats})

    def get_threat_categories(self) -> dict[str, int]:
        """Get count of threats by category."""
        categories = {}
        for threat in self.threats:
            categories[threat.category] = categories.get(threat.category, 0) + 1
        return categories

    def get_active_scanners(self) -> list[str]:
        """Get list of scanners that were used in this scan."""
        # Use validation metadata if available for accurate scanner list
        if "validation_stats" in self.scan_metadata:
            validation_stats = self.scan_metadata["validation_stats"]
            original_scanners = validation_stats.get("active_scanners_original", [])
            if original_scanners:
                return original_scanners

        # Fallback: Collect all unique scanner components from remaining threats
        all_scanners = set()
        for threat in self.threats:
            # Split scanner names by "+" and add individual components
            scanner_parts = threat.source_scanner.split("+")
            all_scanners.update(scanner_parts)

        return sorted(all_scanners)

    def has_critical_threats(self) -> bool:
        """Check if this result has any critical severity threats."""
        return any(threat.severity.is_critical() for threat in self.threats)

    def is_empty(self) -> bool:
        """Check if this scan result has no threats."""
        return len(self.threats) == 0

    def filter_by_confidence(self, min_confidence: float) -> list[ThreatMatch]:
        """Get threats with confidence above the specified threshold."""
        return [
            threat
            for threat in self.threats
            if threat.confidence.get_decimal() >= min_confidence
        ]

    def get_most_common_threats(self, limit: int = 5) -> list[tuple[str, int]]:
        """Get most common threat types."""
        threat_counts = {}
        for threat in self.threats:
            key = f"{threat.category}:{threat.rule_name}"
            threat_counts[key] = threat_counts.get(key, 0) + 1

        # Sort by count descending
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_threats[:limit]

    def get_overall_risk_score(self) -> float:
        """Calculate overall risk score for this scan (0.0-10.0)."""
        if not self.threats:
            return 0.0

        # Weight by threat count and individual risk scores
        total_risk = sum(threat.get_risk_score() for threat in self.threats)
        threat_count_factor = min(
            len(self.threats) / 10.0, 1.0
        )  # More threats = higher risk

        # Average risk * threat count factor
        avg_risk = total_risk / len(self.threats)
        overall_risk = avg_risk * (1.0 + threat_count_factor)

        return min(10.0, overall_risk)

    def get_security_posture(self) -> str:
        """Get overall security posture assessment."""
        risk_score = self.get_overall_risk_score()
        critical_count = len([t for t in self.threats if t.severity.is_critical()])
        high_count = len([t for t in self.threats if t.severity.is_high()])

        if critical_count > 0 or risk_score >= 8.0:
            return "Critical"
        elif high_count > 2 or risk_score >= 6.0:
            return "Poor"
        elif high_count > 0 or risk_score >= 4.0:
            return "Fair"
        elif risk_score >= 2.0:
            return "Good"
        else:
            return "Excellent"

    def has_threats(self) -> bool:
        """Check if this result has any threats."""
        return len(self.threats) > 0

    def has_actionable_threats(self) -> bool:
        """Check if this result has actionable threats."""
        return len(self.get_high_priority_threats()) > 0

    def needs_immediate_attention(self) -> bool:
        """Check if this result requires immediate security attention."""
        return (
            any(threat.severity.is_critical() for threat in self.threats)
            or len(self.get_high_priority_threats()) > 3
            or self.get_overall_risk_score() >= 8.0
        )

    def apply_validation_results(
        self, validation_results: list[ThreatMatch]
    ) -> "ScanResult":
        """Create new scan result with validation results applied."""
        # Create mapping of original threats by fingerprint
        threat_map = {threat.get_fingerprint(): threat for threat in self.threats}

        # Apply validation results
        validated_threats = []
        for validated_threat in validation_results:
            fingerprint = validated_threat.get_fingerprint()
            if fingerprint in threat_map:
                validated_threats.append(validated_threat)
            else:
                # New threat from validation
                validated_threats.append(validated_threat)

        return ScanResult(
            request=self.request,
            threats=validated_threats,
            scan_metadata=self.scan_metadata.copy(),
            validation_applied=True,
            completed_at=self.completed_at,
        )

    def merge_with(self, other: "ScanResult") -> "ScanResult":
        """Merge this scan result with another."""
        if (
            self.request.context.metadata.scan_id
            != other.request.context.metadata.scan_id
        ):
            raise ValueError("Cannot merge scan results from different scan operations")

        # Combine threats and deduplicate by fingerprint
        combined_threats = []
        seen_fingerprints = set()

        for threat in self.threats + other.threats:
            fingerprint = threat.get_fingerprint()
            if fingerprint not in seen_fingerprints:
                combined_threats.append(threat)
                seen_fingerprints.add(fingerprint)

        # Merge metadata
        merged_metadata = self.scan_metadata.copy()
        merged_metadata.update(other.scan_metadata)

        return ScanResult(
            request=self.request,
            threats=combined_threats,
            scan_metadata=merged_metadata,
            validation_applied=self.validation_applied or other.validation_applied,
            completed_at=max(self.completed_at, other.completed_at),
        )

    def to_summary_dict(self) -> dict[str, Any]:
        """Convert to summary dictionary for reporting."""
        stats = self.get_statistics()

        return {
            "scan_id": self.request.context.metadata.scan_id,
            "scan_type": self.request.context.metadata.scan_type,
            "target": str(self.request.context.target_path),
            "completed_at": self.completed_at.isoformat(),
            "validation_applied": self.validation_applied,
            "overall_risk_score": self.get_overall_risk_score(),
            "security_posture": self.get_security_posture(),
            "statistics": {
                "total_threats": stats.total_threats_found,
                "high_priority_threats": len(self.get_high_priority_threats()),
                "files_affected": len(self.get_affected_files()),
                "false_positives_filtered": stats.false_positives_filtered,
                "scan_duration_seconds": stats.scan_duration_seconds,
            },
            "threats_by_severity": stats.threats_by_severity,
            "threat_categories": self.get_threat_categories(),
        }

    def to_detailed_dict(self) -> dict[str, Any]:
        """Convert to detailed dictionary for comprehensive reporting."""
        summary = self.to_summary_dict()

        return {
            **summary,
            "request_configuration": self.request.get_configuration_summary(),
            "threats": [threat.to_detailed_dict() for threat in self.threats],
            "threats_by_file": {
                file_path: [threat.to_summary_dict() for threat in file_threats]
                for file_path, file_threats in self.get_threats_by_file().items()
            },
            "most_common_threats": self.get_most_common_threats(),
            "scan_metadata": self.scan_metadata,
        }

    def get_threats_by_severity(self, severity: "SeverityLevel") -> list[ThreatMatch]:
        """Get threats filtered by specific severity level."""
        return [threat for threat in self.threats if threat.severity == severity]

    def get_threats_by_category(self, category: str) -> list[ThreatMatch]:
        """Get threats filtered by specific category."""
        return [threat for threat in self.threats if threat.category == category]

    def filter_by_confidence(self, threshold: "ConfidenceScore") -> "ScanResult":
        """Create a new ScanResult with only threats meeting confidence threshold."""
        filtered_threats = [
            threat for threat in self.threats if threat.confidence >= threshold
        ]

        return ScanResult(
            request=self.request,
            threats=filtered_threats,
            scan_metadata=self.scan_metadata.copy(),
            validation_applied=self.validation_applied,
            completed_at=self.completed_at,
        )

    def clear_caches(self) -> None:
        """Clear internal caches to force recomputation."""
        self._statistics = None
        self._threats_by_file = None
        self._high_priority_threats = None
