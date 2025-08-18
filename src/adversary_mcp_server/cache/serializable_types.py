"""Serializable data types for cache storage."""

from dataclasses import asdict, dataclass
from typing import Any

from ..domain.entities.threat_match import ThreatMatch


def _safe_confidence_to_float(confidence) -> float:
    """Safely convert any confidence value to float."""
    # Check for ConfidenceScore with get_decimal method
    if hasattr(confidence, "get_decimal"):
        return confidence.get_decimal()

    # Check for objects with value attribute
    if hasattr(confidence, "value"):
        return float(confidence.value)

    # Handle primitive types
    if isinstance(confidence, int | float):
        return float(confidence)

    if isinstance(confidence, str):
        try:
            return float(confidence)
        except ValueError:
            return 0.7

    # Default fallback
    return 0.7


@dataclass
class SerializableThreatMatch:
    """Serializable version of ThreatMatch for cache storage."""

    uuid: str
    rule_id: str
    rule_name: str
    description: str
    category: str
    severity: str
    file_path: str
    line_number: int
    end_line_number: int
    code_snippet: str
    confidence: float
    source: str
    cwe_id: str | None = None
    owasp_category: str | None = None
    remediation: str = ""
    references: list[str] = None
    exploit_examples: list[str] = None
    is_false_positive: bool = False
    false_positive_metadata: dict[str, Any] | None = None

    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.exploit_examples is None:
            self.exploit_examples = []

    @classmethod
    def from_threat_match(cls, threat: ThreatMatch) -> "SerializableThreatMatch":
        """Convert ThreatMatch to serializable form."""
        return cls(
            uuid=threat.uuid,
            rule_id=threat.rule_id,
            rule_name=threat.rule_name,
            description=threat.description,
            category=threat.category,
            severity=str(threat.severity),
            file_path=str(threat.file_path),
            line_number=threat.line_number,
            end_line_number=getattr(threat, "end_line_number", threat.line_number),
            code_snippet=threat.code_snippet,
            confidence=_safe_confidence_to_float(threat.confidence),
            source=threat.source,
            cwe_id=threat.cwe_id,
            owasp_category=threat.owasp_category,
            remediation=threat.remediation,
            references=threat.references or [],
            exploit_examples=threat.exploit_examples or [],
            is_false_positive=threat.is_false_positive,
            false_positive_metadata=getattr(threat, "false_positive_metadata", None),
        )

    @classmethod
    def from_infrastructure_threat_match(cls, threat) -> "SerializableThreatMatch":
        """Convert infrastructure ThreatMatch to serializable form."""
        return cls(
            uuid=getattr(threat, "uuid", ""),
            rule_id=threat.rule_id,
            rule_name=threat.rule_name,
            description=threat.description,
            category=(
                threat.category.value
                if hasattr(threat.category, "value")
                else str(threat.category)
            ),
            severity=str(threat.severity),
            file_path=str(threat.file_path),
            line_number=threat.line_number,
            end_line_number=getattr(threat, "end_line_number", threat.line_number),
            code_snippet=threat.code_snippet,
            confidence=float(threat.confidence),
            source=getattr(
                threat, "source_scanner", getattr(threat, "source", "unknown")
            ),
            cwe_id=threat.cwe_id,
            owasp_category=threat.owasp_category,
            remediation=threat.remediation,
            references=getattr(threat, "references", []),
            exploit_examples=getattr(threat, "exploit_examples", []),
            is_false_positive=threat.is_false_positive,
            false_positive_metadata=getattr(threat, "false_positive_metadata", None),
        )

    def to_threat_match(self) -> ThreatMatch:
        """Convert back to ThreatMatch using domain entity."""
        from ..domain.value_objects.confidence_score import ConfidenceScore
        from ..domain.value_objects.file_path import FilePath
        from ..domain.value_objects.severity_level import SeverityLevel

        return ThreatMatch(
            uuid=self.uuid,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=self.category,
            severity=SeverityLevel.from_string(self.severity),
            file_path=FilePath.from_string(self.file_path),
            line_number=self.line_number,
            column_number=0,  # Default value for domain entity
            code_snippet=self.code_snippet,
            confidence=ConfidenceScore(self.confidence),
            source_scanner=self.source,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            remediation=self.remediation,
            references=self.references,
            exploit_examples=self.exploit_examples,
            is_false_positive=self.is_false_positive,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_infrastructure_threat_match(self):
        """Convert to infrastructure ThreatMatch type."""
        from ..scanner.types import Severity
        from ..scanner.types import ThreatMatch as InfraThreatMatch

        # Map severity string back to enum
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        severity = severity_map.get(self.severity.lower(), Severity.MEDIUM)

        return InfraThreatMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=self.category,
            severity=severity,
            file_path=self.file_path,
            line_number=self.line_number,
            column_number=0,  # Default for infrastructure
            code_snippet=self.code_snippet,
            confidence=self.confidence,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            references=self.references,
            function_name="",  # Default for infrastructure
            exploit_examples=self.exploit_examples,
            remediation=self.remediation,
            is_false_positive=self.is_false_positive,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SerializableThreatMatch":
        """Create from dictionary (JSON deserialization)."""
        return cls(**data)


@dataclass
class SerializableLLMResponse:
    """Serializable version of LLM response for cache storage."""

    content: str
    model: str
    usage: dict[str, int]
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SerializableLLMResponse":
        """Create from dictionary (JSON deserialization)."""
        return cls(**data)


@dataclass
class SerializableScanResult:
    """Serializable scan result for cache storage."""

    threats: list[SerializableThreatMatch]
    metadata: dict[str, Any]
    scan_type: str
    timestamp: float

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "threats": [threat.to_dict() for threat in self.threats],
            "metadata": self.metadata,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SerializableScanResult":
        """Create from dictionary (JSON deserialization)."""
        threats = [
            SerializableThreatMatch.from_dict(threat_data)
            for threat_data in data.get("threats", [])
        ]
        return cls(
            threats=threats,
            metadata=data.get("metadata", {}),
            scan_type=data.get("scan_type", "unknown"),
            timestamp=data.get("timestamp", 0.0),
        )
