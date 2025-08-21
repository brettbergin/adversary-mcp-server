"""ThreatMatch domain entity with domain logic."""

import uuid
from dataclasses import dataclass, field
from typing import Any

from ..exceptions import ValidationError
from ..utils import merge_scanner_names
from ..value_objects.confidence_score import ConfidenceScore
from ..value_objects.file_path import FilePath
from ..value_objects.severity_level import SeverityLevel


@dataclass
class ThreatMatch:
    """
    Domain entity representing a detected security threat with rich behavior and validation.

    Encapsulates all information about a security vulnerability detection,
    including metadata, location information, and business logic for threat
    analysis and processing.
    """

    # Core identification
    rule_id: str
    rule_name: str
    description: str
    category: str  # Will be enhanced with domain categories later
    severity: SeverityLevel

    # Location information
    file_path: FilePath
    line_number: int
    column_number: int = 0

    # Content and context
    code_snippet: str = ""
    function_name: str | None = None

    # Security metadata
    exploit_examples: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe_id: str | None = None
    owasp_category: str | None = None

    # Analysis metadata
    confidence: ConfidenceScore = field(default_factory=lambda: ConfidenceScore(1.0))
    source_scanner: str = "unknown"  # Scanner source: "semgrep", "llm", "rules"
    is_false_positive: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)  # Session-aware metadata

    # Unique identification
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        """Validate threat match after initialization."""
        self._validate_threat()

    @classmethod
    def create_semgrep_threat(
        cls,
        rule_id: str,
        rule_name: str,
        description: str,
        category: str,
        severity: str,
        file_path: str,
        line_number: int,
        column_number: int = 0,
        code_snippet: str = "",
        **kwargs,
    ) -> "ThreatMatch":
        """Create a threat match from Semgrep detection."""
        return cls(
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            category=category,
            severity=SeverityLevel.from_string(severity),
            file_path=FilePath.from_string(file_path),
            line_number=line_number,
            column_number=column_number,
            code_snippet=code_snippet,
            source_scanner="semgrep",
            confidence=ConfidenceScore(0.9),  # Semgrep is generally reliable
            **kwargs,
        )

    @classmethod
    def create_llm_threat(
        cls,
        rule_id: str,
        rule_name: str,
        description: str,
        category: str,
        severity: str,
        file_path: str,
        line_number: int,
        confidence: float = 0.7,
        code_snippet: str = "",
        **kwargs,
    ) -> "ThreatMatch":
        """Create a threat match from LLM analysis."""
        return cls(
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            category=category,
            severity=SeverityLevel.from_string(severity),
            file_path=FilePath.from_string(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            source_scanner="llm",
            confidence=ConfidenceScore(confidence),
            **kwargs,
        )

    @classmethod
    def create_rules_threat(
        cls,
        rule_id: str,
        rule_name: str,
        description: str,
        category: str,
        severity: str,
        file_path: str,
        line_number: int,
        **kwargs,
    ) -> "ThreatMatch":
        """Create a threat match from rules-based detection."""
        return cls(
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            category=category,
            severity=SeverityLevel.from_string(severity),
            file_path=FilePath.from_string(file_path),
            line_number=line_number,
            source_scanner="rules",
            confidence=ConfidenceScore(0.8),  # Rules are generally reliable
            **kwargs,
        )

    def _validate_threat(self) -> None:
        """Validate the threat match according to business rules."""
        if not self.rule_id.strip():
            raise ValidationError("Rule ID cannot be empty")

        if not self.rule_name.strip():
            raise ValidationError("Rule name cannot be empty")

        if not self.description.strip():
            raise ValidationError("Description cannot be empty")

        if self.line_number < 1:
            raise ValidationError("Line number must be positive")

        if self.column_number < 0:
            raise ValidationError("Column number cannot be negative")

        # Validate source scanner is known (allow combinations)
        valid_sources = {"semgrep", "llm", "rules", "unknown"}
        # Split combined sources and check each part
        source_parts = self.source_scanner.split("+")
        for part in source_parts:
            clean_part = part.strip()
            if clean_part not in valid_sources:
                raise ValidationError(
                    f"Invalid source_scanner part: {clean_part}. Must be one of: {valid_sources}"
                )

    def get_fingerprint(self) -> str:
        """
        Generate a unique fingerprint for this finding.

        Used to identify the same logical finding across multiple scans
        to preserve UUIDs and false positive markings.

        Returns:
            Unique fingerprint string based on file_path and line_number (location-based)
        """
        normalized_path = (
            str(self.file_path.path.resolve())
            if not self.file_path._is_virtual
            else str(self.file_path)
        )
        return f"{normalized_path}:{self.line_number}"

    def get_display_location(self) -> str:
        """Get human-readable location string."""
        if self.column_number > 0:
            return f"{self.file_path.name}:{self.line_number}:{self.column_number}"
        else:
            return f"{self.file_path.name}:{self.line_number}"

    def get_full_location(self) -> str:
        """Get full path location string."""
        if self.column_number > 0:
            return f"{self.file_path}:{self.line_number}:{self.column_number}"
        else:
            return f"{self.file_path}:{self.line_number}"

    def is_high_severity(self) -> bool:
        """Check if this threat is high or critical severity."""
        return self.severity.is_actionable()

    def is_confident(self, threshold: ConfidenceScore | None = None) -> bool:
        """Check if this threat meets confidence threshold."""
        if threshold is None:
            threshold = ConfidenceScore.default_threshold()
        return self.confidence.meets_threshold(threshold)

    def is_actionable(
        self, confidence_threshold: ConfidenceScore | None = None
    ) -> bool:
        """Check if this threat is actionable (high severity and confident)."""
        return self.is_high_severity() and self.is_confident(confidence_threshold)

    def should_be_reported(
        self, severity_threshold: SeverityLevel | None = None
    ) -> bool:
        """Check if this threat should be included in reports."""
        if self.is_false_positive:
            return False

        if severity_threshold is None:
            severity_threshold = SeverityLevel.get_default_threshold()

        return self.severity.meets_threshold(severity_threshold)

    def get_risk_score(self) -> float:
        """Calculate a numeric risk score for prioritization (0.0-10.0)."""
        # Base score from severity
        severity_weight = self.severity.get_priority_weight()  # 0.0-1.0

        # Confidence adjustment
        confidence_weight = self.confidence.get_decimal()  # 0.0-1.0

        # Source reliability adjustment
        source_weights = {
            "semgrep": 1.0,
            "rules": 0.9,
            "llm": 0.8,
            "unknown": 0.5,
        }
        source_weight = source_weights.get(self.source_scanner, 0.5)

        # Calculate final score (0.0-10.0)
        risk_score = severity_weight * confidence_weight * source_weight * 10.0

        return round(risk_score, 2)

    def get_priority_category(self) -> str:
        """Get priority category for triage."""
        risk_score = self.get_risk_score()

        if risk_score >= 8.0:
            return "Critical"
        elif risk_score >= 6.0:
            return "High"
        elif risk_score >= 4.0:
            return "Medium"
        elif risk_score >= 2.0:
            return "Low"
        else:
            return "Informational"

    def mark_as_false_positive(self, reason: str = "") -> "ThreatMatch":
        """Create a new instance marked as false positive."""
        # Create a copy with false positive marking
        new_threat = ThreatMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=self.category,
            severity=self.severity,
            file_path=self.file_path,
            line_number=self.line_number,
            column_number=self.column_number,
            code_snippet=self.code_snippet,
            function_name=self.function_name,
            exploit_examples=self.exploit_examples.copy(),
            remediation=self.remediation,
            references=self.references.copy(),
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            confidence=self.confidence,
            source_scanner=self.source_scanner,
            is_false_positive=True,
            uuid=self.uuid,  # Keep same UUID
        )
        return new_threat

    def update_confidence(self, new_confidence: ConfidenceScore) -> "ThreatMatch":
        """Create a new instance with updated confidence score."""
        return ThreatMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=self.category,
            severity=self.severity,
            file_path=self.file_path,
            line_number=self.line_number,
            column_number=self.column_number,
            code_snippet=self.code_snippet,
            function_name=self.function_name,
            exploit_examples=self.exploit_examples.copy(),
            remediation=self.remediation,
            references=self.references.copy(),
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            confidence=new_confidence,
            source_scanner=self.source_scanner,
            is_false_positive=self.is_false_positive,
            uuid=self.uuid,  # Keep same UUID
        )

    def enhance_with_validation_result(
        self, validation_confidence: ConfidenceScore, validation_reason: str = ""
    ) -> "ThreatMatch":
        """Create enhanced version with validation results."""
        # Combine original confidence with validation confidence
        combined_confidence = self.confidence.combine_with(
            validation_confidence, weight=0.7
        )

        return ThreatMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=self.category,
            severity=self.severity,
            file_path=self.file_path,
            line_number=self.line_number,
            column_number=self.column_number,
            code_snippet=self.code_snippet,
            function_name=self.function_name,
            exploit_examples=self.exploit_examples.copy(),
            remediation=self.remediation
            + (f"\n\nValidation: {validation_reason}" if validation_reason else ""),
            references=self.references.copy(),
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            confidence=combined_confidence,
            source_scanner=f"{self.source_scanner}+validation",
            is_false_positive=self.is_false_positive,
            uuid=self.uuid,  # Keep same UUID
        )

    def add_exploit_example(self, exploit: str) -> "ThreatMatch":
        """Create new instance with additional exploit example."""
        if exploit in self.exploit_examples:
            return self  # Already exists

        new_exploits = self.exploit_examples.copy()
        new_exploits.append(exploit)

        return ThreatMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=self.category,
            severity=self.severity,
            file_path=self.file_path,
            line_number=self.line_number,
            column_number=self.column_number,
            code_snippet=self.code_snippet,
            function_name=self.function_name,
            exploit_examples=new_exploits,
            remediation=self.remediation,
            references=self.references.copy(),
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            confidence=self.confidence,
            source_scanner=self.source_scanner,
            is_false_positive=self.is_false_positive,
            uuid=self.uuid,
        )

    def is_similar_to(self, other: "ThreatMatch", proximity_threshold: int = 5) -> bool:
        """Check if this threat is similar to another (for deduplication)."""
        if not isinstance(other, ThreatMatch):
            return False

        # Same file - required
        if self.file_path != other.file_path:
            return False

        # Same rule ID OR same category - at least one must match
        if self.rule_id != other.rule_id and self.category != other.category:
            return False

        # Lines are close together
        line_diff = abs(self.line_number - other.line_number)
        return line_diff <= proximity_threshold

    def merge_with(self, other: "ThreatMatch") -> "ThreatMatch":
        """Merge this threat with another similar threat."""
        if not self.is_similar_to(other):
            raise ValueError("Cannot merge dissimilar threats")

        # Use the higher confidence
        best_confidence = max(self.confidence, other.confidence)

        # Use the higher severity
        best_severity = max(self.severity, other.severity)

        # Combine exploit examples
        combined_exploits = list(set(self.exploit_examples + other.exploit_examples))

        # Combine references
        combined_references = list(set(self.references + other.references))

        # Use better code snippet (longer one)
        best_snippet = (
            self.code_snippet
            if len(self.code_snippet) > len(other.code_snippet)
            else other.code_snippet
        )

        # Combine remediation
        combined_remediation = self.remediation
        if other.remediation and other.remediation not in self.remediation:
            combined_remediation += f"\n\n{other.remediation}"

        return ThreatMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=self.category,
            severity=best_severity,
            file_path=self.file_path,
            line_number=min(self.line_number, other.line_number),  # Use earlier line
            column_number=self.column_number,
            code_snippet=best_snippet,
            function_name=self.function_name or other.function_name,
            exploit_examples=combined_exploits,
            remediation=combined_remediation,
            references=combined_references,
            cwe_id=self.cwe_id or other.cwe_id,
            owasp_category=self.owasp_category or other.owasp_category,
            confidence=best_confidence,
            source_scanner=merge_scanner_names(
                self.source_scanner, other.source_scanner
            ),
            is_false_positive=self.is_false_positive and other.is_false_positive,
            uuid=self.uuid,  # Keep original UUID
        )

    def to_summary_dict(self) -> dict:
        """Convert to dictionary for logging/reporting."""
        return {
            "uuid": self.uuid,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "location": self.get_display_location(),
            "risk_score": self.get_risk_score(),
            "priority": self.get_priority_category(),
            "source": self.source_scanner,
            "is_false_positive": self.is_false_positive,
        }

    def mark_false_positive(self) -> "ThreatMatch":
        """Create a copy marked as false positive."""
        return self.mark_as_false_positive()

    def add_metadata(self, metadata_dict: dict[str, Any]) -> "ThreatMatch":
        """Add metadata to the threat match and return a new instance."""
        new_metadata = {**self.metadata, **metadata_dict}
        return ThreatMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=self.category,
            severity=self.severity,
            file_path=self.file_path,
            line_number=self.line_number,
            column_number=self.column_number,
            code_snippet=self.code_snippet,
            function_name=self.function_name,
            exploit_examples=self.exploit_examples.copy(),
            remediation=self.remediation,
            references=self.references.copy(),
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            confidence=self.confidence,
            source_scanner=self.source_scanner,
            is_false_positive=self.is_false_positive,
            metadata=new_metadata,
            uuid=self.uuid,
        )

    def to_detailed_dict(self) -> dict:
        """Convert to detailed dictionary for full reporting."""
        return {
            **self.to_summary_dict(),
            "description": self.description,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "function_name": self.function_name,
            "exploit_examples": self.exploit_examples,
            "remediation": self.remediation,
            "references": self.references,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "fingerprint": self.get_fingerprint(),
        }
