"""Data models for threat modeling components and outputs."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ComponentType(str, Enum):
    """Types of architectural components in a threat model."""

    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"
    TRUST_BOUNDARY = "trust_boundary"


class ThreatType(str, Enum):
    """STRIDE threat categories."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class Severity(str, Enum):
    """Threat severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DataFlow:
    """Represents a data flow between components."""

    source: str
    target: str
    protocol: str
    data_type: str | None = None
    authentication: str | None = None
    encryption: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "source": self.source,
            "target": self.target,
            "protocol": self.protocol,
        }
        if self.data_type:
            result["data_type"] = self.data_type
        if self.authentication:
            result["authentication"] = self.authentication
        if self.encryption:
            result["encryption"] = self.encryption
        return result


@dataclass
class Component:
    """Base class for architectural components."""

    name: str
    component_type: ComponentType
    description: str | None = None
    trust_level: str | None = None
    exposed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "name": self.name,
            "type": self.component_type.value,
        }
        if self.description:
            result["description"] = self.description
        if self.trust_level:
            result["trust_level"] = self.trust_level
        if self.exposed:
            result["exposed"] = self.exposed
        return result


@dataclass
class Threat:
    """Represents a security threat identified in the system."""

    threat_type: ThreatType
    component: str
    title: str
    description: str
    severity: Severity
    likelihood: str = "medium"
    impact: str = "medium"
    mitigation: str | None = None
    cwe_id: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "type": self.threat_type.value,
            "component": self.component,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "likelihood": self.likelihood,
            "impact": self.impact,
        }
        if self.mitigation:
            result["mitigation"] = self.mitigation
        if self.cwe_id:
            result["cwe_id"] = self.cwe_id
        if self.references:
            result["references"] = self.references
        return result


@dataclass
class ThreatModelComponents:
    """Container for all threat model components."""

    boundaries: list[str] = field(default_factory=list)
    external_entities: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    data_stores: list[str] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary matching the requested JSON format."""
        return {
            "boundaries": self.boundaries,
            "external_entities": self.external_entities,
            "processes": self.processes,
            "data_stores": self.data_stores,
            "data_flows": [df.to_dict() for df in self.data_flows],
        }

    def add_data_flow(self, source: str, target: str, protocol: str, **kwargs):
        """Add a data flow between components."""
        flow = DataFlow(source=source, target=target, protocol=protocol, **kwargs)
        self.data_flows.append(flow)

    def add_component(self, name: str, component_type: ComponentType, **kwargs):
        """Add a component to the model."""
        component = Component(name=name, component_type=component_type, **kwargs)
        self.components.append(component)

        # Also add to appropriate list for backward compatibility
        if component_type == ComponentType.EXTERNAL_ENTITY:
            if name not in self.external_entities:
                self.external_entities.append(name)
        elif component_type == ComponentType.PROCESS:
            if name not in self.processes:
                self.processes.append(name)
        elif component_type == ComponentType.DATA_STORE:
            if name not in self.data_stores:
                self.data_stores.append(name)


@dataclass
class ThreatModel:
    """Complete threat model including components and threats."""

    components: ThreatModelComponents
    threats: list[Threat] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = self.components.to_dict()
        if self.threats:
            result["threats"] = [threat.to_dict() for threat in self.threats]
        if self.metadata:
            result["metadata"] = self.metadata
        return result

    def add_threat(self, threat: Threat):
        """Add a threat to the model."""
        self.threats.append(threat)

    def get_threats_by_component(self, component_name: str) -> list[Threat]:
        """Get all threats for a specific component."""
        return [threat for threat in self.threats if threat.component == component_name]

    def get_threats_by_severity(self, min_severity: Severity) -> list[Threat]:
        """Get threats above a minimum severity level."""
        severity_order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        min_level = severity_order[min_severity]
        return [
            threat
            for threat in self.threats
            if severity_order[threat.severity] >= min_level
        ]
