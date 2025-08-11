"""Serializable data types for cache storage."""

from dataclasses import asdict, dataclass
from typing import Any

from ..scanner.types import ThreatMatch


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
            severity=(
                threat.severity.value
                if hasattr(threat.severity, "value")
                else str(threat.severity)
            ),
            file_path=threat.file_path,
            line_number=threat.line_number,
            end_line_number=getattr(threat, "end_line_number", threat.line_number),
            code_snippet=threat.code_snippet,
            confidence=threat.confidence,
            source=threat.source,
            cwe_id=threat.cwe_id,
            owasp_category=threat.owasp_category,
            remediation=threat.remediation,
            references=threat.references or [],
            exploit_examples=threat.exploit_examples or [],
            is_false_positive=threat.is_false_positive,
            false_positive_metadata=getattr(threat, "false_positive_metadata", None),
        )

    def to_threat_match(self) -> ThreatMatch:
        """Convert back to ThreatMatch."""
        from ..scanner.types import Category, Severity

        return ThreatMatch(
            uuid=self.uuid,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            category=Category(self.category),
            severity=Severity(self.severity),
            file_path=self.file_path,
            line_number=self.line_number,
            # end_line_number is not in ThreatMatch - skip it
            code_snippet=self.code_snippet,
            confidence=self.confidence,
            source=self.source,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            remediation=self.remediation,
            references=self.references,
            exploit_examples=self.exploit_examples,
            is_false_positive=self.is_false_positive,
            # false_positive_metadata is not in ThreatMatch - skip it
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

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
