"""Data models for threat modeling components and outputs."""

import math
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


class DetectionSource(str, Enum):
    """Source of threat detection."""

    BUILT_IN_RULES = "built_in_rules"
    LLM_ANALYSIS = "llm_analysis"
    SEMGREP = "semgrep"
    MANUAL = "manual"


class ConfidenceLevel(str, Enum):
    """Confidence level in threat detection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class CVSSScore:
    """CVSS v3.1 scoring information."""

    # Base metrics
    attack_vector: str = "network"  # network, adjacent, local, physical
    attack_complexity: str = "low"  # low, high
    privileges_required: str = "none"  # none, low, high
    user_interaction: str = "none"  # none, required
    scope: str = "unchanged"  # unchanged, changed
    confidentiality_impact: str = "high"  # none, low, high
    integrity_impact: str = "high"  # none, low, high
    availability_impact: str = "high"  # none, low, high

    # Calculated scores
    base_score: float = 0.0
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    overall_score: float = 0.0

    # Vector string
    vector_string: str = ""

    def calculate_base_score(self) -> float:
        """Calculate CVSS v3.1 base score."""
        # Attack Vector
        av_values = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}
        av = av_values.get(self.attack_vector, 0.85)

        # Attack Complexity
        ac_values = {"low": 0.77, "high": 0.44}
        ac = ac_values.get(self.attack_complexity, 0.77)

        # Privileges Required
        pr_values = {
            "none": 0.85,
            "low": 0.62 if self.scope == "unchanged" else 0.68,
            "high": 0.27 if self.scope == "unchanged" else 0.50,
        }
        pr = pr_values.get(self.privileges_required, 0.85)

        # User Interaction
        ui_values = {"none": 0.85, "required": 0.62}
        ui = ui_values.get(self.user_interaction, 0.85)

        # Impact metrics
        impact_values = {"none": 0.0, "low": 0.22, "high": 0.56}
        c = impact_values.get(self.confidentiality_impact, 0.56)
        i = impact_values.get(self.integrity_impact, 0.56)
        a = impact_values.get(self.availability_impact, 0.56)

        # Calculate ISC (Impact Score)
        isc = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact
        if self.scope == "unchanged":
            impact = 6.42 * isc
        else:
            impact = 7.52 * (isc - 0.029) - 3.25 * pow(isc - 0.02, 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif self.scope == "unchanged":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

        # Round up to one decimal place
        self.base_score = math.ceil(base_score * 10) / 10
        self.overall_score = self.base_score

        # Generate vector string
        self._generate_vector_string()

        return self.base_score

    def _generate_vector_string(self):
        """Generate CVSS vector string."""
        av_map = {"network": "N", "adjacent": "A", "local": "L", "physical": "P"}
        ac_map = {"low": "L", "high": "H"}
        pr_map = {"none": "N", "low": "L", "high": "H"}
        ui_map = {"none": "N", "required": "R"}
        s_map = {"unchanged": "U", "changed": "C"}
        cia_map = {"none": "N", "low": "L", "high": "H"}

        self.vector_string = (
            f"CVSS:3.1/AV:{av_map.get(self.attack_vector, 'N')}/"
            f"AC:{ac_map.get(self.attack_complexity, 'L')}/"
            f"PR:{pr_map.get(self.privileges_required, 'N')}/"
            f"UI:{ui_map.get(self.user_interaction, 'N')}/"
            f"S:{s_map.get(self.scope, 'U')}/"
            f"C:{cia_map.get(self.confidentiality_impact, 'H')}/"
            f"I:{cia_map.get(self.integrity_impact, 'H')}/"
            f"A:{cia_map.get(self.availability_impact, 'H')}"
        )

    def get_severity_rating(self) -> str:
        """Get qualitative severity rating based on CVSS score."""
        if self.overall_score == 0.0:
            return "None"
        elif self.overall_score <= 3.9:
            return "Low"
        elif self.overall_score <= 6.9:
            return "Medium"
        elif self.overall_score <= 8.9:
            return "High"
        else:
            return "Critical"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "base_score": self.base_score,
            "temporal_score": self.temporal_score,
            "environmental_score": self.environmental_score,
            "overall_score": self.overall_score,
            "vector_string": self.vector_string,
            "severity_rating": self.get_severity_rating(),
            "metrics": {
                "attack_vector": self.attack_vector,
                "attack_complexity": self.attack_complexity,
                "privileges_required": self.privileges_required,
                "user_interaction": self.user_interaction,
                "scope": self.scope,
                "confidentiality_impact": self.confidentiality_impact,
                "integrity_impact": self.integrity_impact,
                "availability_impact": self.availability_impact,
            },
        }


@dataclass
class CodeLocation:
    """Location information for threat detection in code."""

    file_path: str
    line_number: int | None = None
    column_number: int | None = None
    function_name: str | None = None
    code_snippet: str | None = None
    lines_of_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {"file_path": self.file_path}
        if self.line_number is not None:
            result["line_number"] = self.line_number
        if self.column_number is not None:
            result["column_number"] = self.column_number
        if self.function_name:
            result["function_name"] = self.function_name
        if self.code_snippet:
            result["code_snippet"] = self.code_snippet
        if self.lines_of_code is not None:
            result["lines_of_code"] = self.lines_of_code
        return result


@dataclass
class ThreatMetadata:
    """Extended metadata for threat detection."""

    detection_source: DetectionSource
    confidence_level: ConfidenceLevel
    scanner_version: str | None = None
    detection_timestamp: str | None = None
    rule_id: str | None = None
    false_positive_risk: str = "low"  # low, medium, high
    remediation_effort: str = "medium"  # low, medium, high
    business_impact: str = "medium"  # low, medium, high

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "detection_source": self.detection_source.value,
            "confidence_level": self.confidence_level.value,
            "false_positive_risk": self.false_positive_risk,
            "remediation_effort": self.remediation_effort,
            "business_impact": self.business_impact,
        }
        if self.scanner_version:
            result["scanner_version"] = self.scanner_version
        if self.detection_timestamp:
            result["detection_timestamp"] = self.detection_timestamp
        if self.rule_id:
            result["rule_id"] = self.rule_id
        return result


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
    """Represents a security threat identified in the system with comprehensive analysis."""

    # Core threat information
    threat_type: ThreatType
    component: str
    title: str
    description: str
    severity: Severity

    # Traditional fields
    likelihood: str = "medium"
    impact: str = "medium"
    mitigation: str | None = None
    cwe_id: str | None = None
    references: list[str] = field(default_factory=list)

    # Enhanced fields
    cvss_score: CVSSScore | None = None
    threat_metadata: ThreatMetadata | None = None
    code_locations: list[CodeLocation] = field(default_factory=list)
    risk_score: float = 0.0
    risk_ranking: str = "medium"  # low, medium, high, critical

    # Additional analysis fields
    attack_scenarios: list[str] = field(default_factory=list)
    technical_details: str | None = None
    business_rationale: str | None = None
    compliance_references: list[str] = field(default_factory=list)

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on CVSS, confidence, and business impact."""
        base_score = 5.0  # Default medium risk

        # Use CVSS score if available
        if self.cvss_score and self.cvss_score.overall_score > 0:
            base_score = self.cvss_score.overall_score
        else:
            # Fallback to severity mapping
            severity_scores = {
                Severity.LOW: 2.5,
                Severity.MEDIUM: 5.0,
                Severity.HIGH: 7.5,
                Severity.CRITICAL: 9.0,
            }
            base_score = severity_scores.get(self.severity, 5.0)

        # Adjust based on confidence level
        if self.threat_metadata:
            confidence_multipliers = {
                ConfidenceLevel.LOW: 0.7,
                ConfidenceLevel.MEDIUM: 0.85,
                ConfidenceLevel.HIGH: 1.0,
                ConfidenceLevel.VERY_HIGH: 1.1,
            }
            confidence_mult = confidence_multipliers.get(
                self.threat_metadata.confidence_level, 1.0
            )
            base_score *= confidence_mult

            # Adjust based on business impact
            business_multipliers = {"low": 0.8, "medium": 1.0, "high": 1.2}
            business_mult = business_multipliers.get(
                self.threat_metadata.business_impact, 1.0
            )
            base_score *= business_mult

        # Cap at 10.0
        self.risk_score = min(base_score, 10.0)

        # Update risk ranking
        if self.risk_score <= 3.0:
            self.risk_ranking = "low"
        elif self.risk_score <= 6.0:
            self.risk_ranking = "medium"
        elif self.risk_score <= 8.5:
            self.risk_ranking = "high"
        else:
            self.risk_ranking = "critical"

        return self.risk_score

    def add_code_location(
        self, file_path: str, line_number: int | None = None, **kwargs
    ):
        """Add a code location where this threat was detected."""
        location = CodeLocation(file_path=file_path, line_number=line_number, **kwargs)
        self.code_locations.append(location)

    def get_primary_location(self) -> CodeLocation | None:
        """Get the primary code location for this threat."""
        return self.code_locations[0] if self.code_locations else None

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
            "risk_score": self.risk_score,
            "risk_ranking": self.risk_ranking,
        }

        # Optional core fields
        if self.mitigation:
            result["mitigation"] = self.mitigation
        if self.cwe_id:
            result["cwe_id"] = self.cwe_id
        if self.references:
            result["references"] = self.references

        # Enhanced fields
        if self.cvss_score:
            result["cvss_score"] = self.cvss_score.to_dict()
        if self.threat_metadata:
            result["threat_metadata"] = self.threat_metadata.to_dict()
        if self.code_locations:
            result["code_locations"] = [loc.to_dict() for loc in self.code_locations]
        if self.attack_scenarios:
            result["attack_scenarios"] = self.attack_scenarios
        if self.technical_details:
            result["technical_details"] = self.technical_details
        if self.business_rationale:
            result["business_rationale"] = self.business_rationale
        if self.compliance_references:
            result["compliance_references"] = self.compliance_references

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
    """Complete threat model including components and threats with comprehensive analysis."""

    components: ThreatModelComponents
    threats: list[Threat] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def calculate_comprehensive_statistics(self) -> dict[str, Any]:
        """Calculate comprehensive statistics about the threat model."""
        stats = {
            "threat_summary": self._get_threat_summary(),
            "severity_breakdown": self._get_severity_breakdown(),
            "detection_source_breakdown": self._get_detection_source_breakdown(),
            "confidence_breakdown": self._get_confidence_breakdown(),
            "risk_analysis": self._get_risk_analysis(),
            "cvss_statistics": self._get_cvss_statistics(),
            "component_analysis": self._get_component_analysis(),
            "code_coverage": self._get_code_coverage_stats(),
        }
        return stats

    def _get_threat_summary(self) -> dict[str, Any]:
        """Get basic threat summary statistics."""
        total_threats = len(self.threats)

        # Count by STRIDE category
        stride_counts = {}
        for threat_type in ThreatType:
            count = sum(1 for t in self.threats if t.threat_type == threat_type)
            stride_counts[threat_type.value] = count

        return {
            "total_threats": total_threats,
            "stride_breakdown": stride_counts,
            "unique_components_affected": len({t.component for t in self.threats}),
            "threats_with_cvss": sum(1 for t in self.threats if t.cvss_score),
            "threats_with_code_locations": sum(
                1 for t in self.threats if t.code_locations
            ),
        }

    def _get_severity_breakdown(self) -> dict[str, Any]:
        """Get breakdown by severity levels."""
        breakdown = {}
        for severity in Severity:
            count = sum(1 for t in self.threats if t.severity == severity)
            breakdown[severity.value] = count

        # Add percentages
        total = len(self.threats)
        if total > 0:
            for severity in breakdown:
                breakdown[severity] = {
                    "count": breakdown[severity],
                    "percentage": round((breakdown[severity] / total) * 100, 1),
                }

        return breakdown

    def _get_detection_source_breakdown(self) -> dict[str, Any]:
        """Get breakdown by detection source."""
        breakdown = {}
        for source in DetectionSource:
            count = sum(
                1
                for t in self.threats
                if t.threat_metadata and t.threat_metadata.detection_source == source
            )
            breakdown[source.value] = count

        # Add threats without metadata
        no_metadata = sum(1 for t in self.threats if not t.threat_metadata)
        if no_metadata > 0:
            breakdown["unknown"] = no_metadata

        return breakdown

    def _get_confidence_breakdown(self) -> dict[str, Any]:
        """Get breakdown by confidence levels."""
        breakdown = {}
        for confidence in ConfidenceLevel:
            count = sum(
                1
                for t in self.threats
                if t.threat_metadata
                and t.threat_metadata.confidence_level == confidence
            )
            breakdown[confidence.value] = count

        return breakdown

    def _get_risk_analysis(self) -> dict[str, Any]:
        """Get risk analysis statistics."""
        if not self.threats:
            return {}

        # Calculate risk scores for all threats
        risk_scores = []
        for threat in self.threats:
            if threat.risk_score > 0:
                risk_scores.append(threat.risk_score)
            else:
                # Calculate if not already done
                risk_scores.append(threat.calculate_risk_score())

        if not risk_scores:
            return {}

        return {
            "average_risk_score": round(sum(risk_scores) / len(risk_scores), 2),
            "highest_risk_score": max(risk_scores),
            "lowest_risk_score": min(risk_scores),
            "risk_ranking_breakdown": {
                "critical": sum(
                    1 for t in self.threats if t.risk_ranking == "critical"
                ),
                "high": sum(1 for t in self.threats if t.risk_ranking == "high"),
                "medium": sum(1 for t in self.threats if t.risk_ranking == "medium"),
                "low": sum(1 for t in self.threats if t.risk_ranking == "low"),
            },
        }

    def _get_cvss_statistics(self) -> dict[str, Any]:
        """Get CVSS scoring statistics."""
        threats_with_cvss = [t for t in self.threats if t.cvss_score]

        if not threats_with_cvss:
            return {"cvss_coverage": 0}

        cvss_scores = [t.cvss_score.overall_score for t in threats_with_cvss]

        return {
            "cvss_coverage": len(threats_with_cvss),
            "average_cvss_score": round(sum(cvss_scores) / len(cvss_scores), 2),
            "highest_cvss_score": max(cvss_scores),
            "lowest_cvss_score": min(cvss_scores),
            "cvss_severity_breakdown": {
                severity: len(
                    [
                        t
                        for t in threats_with_cvss
                        if t.cvss_score.get_severity_rating().lower() == severity
                    ]
                )
                for severity in ["low", "medium", "high", "critical"]
            },
        }

    def _get_component_analysis(self) -> dict[str, Any]:
        """Get component-level analysis."""
        component_threat_counts = {}
        for threat in self.threats:
            # Handle combined components (e.g., "Comp1, Comp2")
            components = [c.strip() for c in threat.component.split(",")]
            for component in components:
                if component not in component_threat_counts:
                    component_threat_counts[component] = 0
                component_threat_counts[component] += 1

        # Find most vulnerable components
        sorted_components = sorted(
            component_threat_counts.items(), key=lambda x: x[1], reverse=True
        )

        return {
            "total_components": len(
                self.components.processes
                + self.components.data_stores
                + self.components.external_entities
            ),
            "components_with_threats": len(component_threat_counts),
            "most_vulnerable_components": sorted_components[:5],
            "threat_distribution": component_threat_counts,
        }

    def _get_code_coverage_stats(self) -> dict[str, Any]:
        """Get code coverage and location statistics."""
        threats_with_locations = [t for t in self.threats if t.code_locations]

        if not threats_with_locations:
            return {"code_coverage": 0}

        all_files = set()
        total_lines = 0
        functions_analyzed = set()

        for threat in threats_with_locations:
            for location in threat.code_locations:
                all_files.add(location.file_path)
                if location.lines_of_code:
                    total_lines += location.lines_of_code
                if location.function_name:
                    functions_analyzed.add(location.function_name)

        return {
            "code_coverage": len(threats_with_locations),
            "files_analyzed": len(all_files),
            "total_lines_analyzed": total_lines,
            "functions_analyzed": len(functions_analyzed),
            "files_with_threats": list(all_files)[:10],  # Top 10 files
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for enhanced JSON serialization."""
        result = self.components.to_dict()

        if self.threats:
            result["threats"] = [threat.to_dict() for threat in self.threats]

        # Enhanced metadata with comprehensive statistics
        enhanced_metadata = dict(self.metadata)
        enhanced_metadata["statistics"] = self.calculate_comprehensive_statistics()
        result["metadata"] = enhanced_metadata

        return result

    def add_threat(self, threat: Threat):
        """Add a threat to the model and calculate its risk score."""
        threat.calculate_risk_score()
        self.threats.append(threat)

    def get_threats_by_component(self, component_name: str) -> list[Threat]:
        """Get all threats for a specific component."""
        return [threat for threat in self.threats if component_name in threat.component]

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

    def get_threats_by_detection_source(self, source: DetectionSource) -> list[Threat]:
        """Get threats detected by a specific source."""
        return [
            threat
            for threat in self.threats
            if threat.threat_metadata
            and threat.threat_metadata.detection_source == source
        ]

    def get_highest_risk_threats(self, limit: int = 10) -> list[Threat]:
        """Get the highest risk threats sorted by risk score."""
        # Ensure all threats have calculated risk scores
        for threat in self.threats:
            if threat.risk_score == 0.0:
                threat.calculate_risk_score()

        return sorted(self.threats, key=lambda t: t.risk_score, reverse=True)[:limit]
