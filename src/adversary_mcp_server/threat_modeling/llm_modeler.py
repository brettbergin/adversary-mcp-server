"""LLM-enhanced threat modeling for enriching traditional STRIDE analysis."""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..logger import get_logger
from .models import (
    Severity,
    Threat,
    ThreatModel,
    ThreatModelComponents,
    ThreatType,
)

logger = get_logger("llm_modeler")


@dataclass
class ThreatModelingPrompt:
    """Represents a prompt for LLM-enhanced threat modeling."""

    system_prompt: str
    user_prompt: str
    analysis_type: str
    source_path: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "analysis_type": self.analysis_type,
            "source_path": self.source_path,
            "metadata": self.metadata,
        }


class LLMThreatAnalysis:
    """Container for LLM-specific threat analysis results."""

    def __init__(self):
        self.enhanced_threats: list[Threat] = []
        self.business_logic_threats: list[Threat] = []
        self.architecture_insights: dict[str, Any] = {}
        self.llm_metadata: dict[str, Any] = {}


class LLMThreatModeler:
    """LLM-enhanced threat modeling that enriches traditional STRIDE analysis.

    This follows the same pattern as LLMScanner - it generates prompts for the client's
    LLM to process rather than making direct API calls.
    """

    def __init__(self):
        """Initialize the LLM threat modeler."""
        logger.info("Initializing LLMThreatModeler in client-based mode")

    def is_available(self) -> bool:
        """Check if LLM threat modeling is available.

        Returns:
            True (always available for client-based approach)
        """
        return True

    def get_status(self) -> dict[str, Any]:
        """Get LLM threat modeler status information.

        Returns:
            Dict containing status information
        """
        return {
            "available": True,
            "version": "client-based",
            "mode": "client-based",
            "description": "Uses client-side LLM for threat modeling enhancement",
        }

    def create_threat_modeling_prompts(
        self,
        threat_model: ThreatModel,
        source_path: str,
        code_context: str | None = None,
        analysis_options: dict[str, Any] | None = None,
    ) -> list[ThreatModelingPrompt]:
        """Create prompts for LLM-enhanced threat modeling.

        Args:
            threat_model: Base threat model from traditional analysis
            source_path: Path to source code
            code_context: Optional code content
            analysis_options: Analysis configuration options

        Returns:
            List of ThreatModelingPrompt objects for client processing
        """
        if not analysis_options:
            analysis_options = {
                "enable_business_logic": True,
                "enable_data_flow_analysis": True,
                "enable_attack_surface": True,
                "enable_contextual_enhancement": True,
            }

        logger.info(f"Creating threat modeling prompts for: {source_path}")

        # Prepare analysis context
        context_data = self._prepare_analysis_context(threat_model, code_context or "")

        prompts = []

        # Business logic analysis prompt
        if analysis_options.get("enable_business_logic", True):
            prompts.append(
                self._create_business_logic_prompt(context_data, source_path)
            )

        # Data flow analysis prompt
        if analysis_options.get("enable_data_flow_analysis", True):
            prompts.append(self._create_data_flow_prompt(context_data, source_path))

        # Attack surface analysis prompt
        if analysis_options.get("enable_attack_surface", True):
            prompts.append(
                self._create_attack_surface_prompt(context_data, source_path)
            )

        # Contextual enhancement prompt
        if analysis_options.get("enable_contextual_enhancement", True):
            prompts.append(
                self._create_contextual_enhancement_prompt(context_data, source_path)
            )

        logger.info(f"Created {len(prompts)} threat modeling prompts")
        return prompts

    def _create_business_logic_prompt(
        self, context_data: dict[str, Any], source_path: str
    ) -> ThreatModelingPrompt:
        """Create business logic analysis prompt."""
        system_prompt = """You are a senior security architect specializing in business logic vulnerabilities.
Your task is to analyze architectural components and code for business logic flaws that traditional 
static analysis tools typically miss.

Focus on vulnerabilities that arise from the business logic itself rather than technical implementation issues:
- Race conditions in critical business operations
- State machine bypasses and logic bombs  
- Authorization logic errors and privilege escalation
- Data validation gaps in business rules
- Transaction integrity and consistency issues
- Workflow bypasses and process manipulation
- Domain-specific security concerns

Response format: JSON object with "threats" array containing business logic threats.
Each threat should include: type, title, description, severity, component, likelihood, impact, mitigation, cwe_id (optional)."""

        user_prompt = f"""Analyze the following system for business logic vulnerabilities:

Code Context:
{context_data['code_context']}

Architectural Components:
{context_data['components_summary']}

Data Flows:
{json.dumps(context_data['data_flows'], indent=2)}

Trust Boundaries:
{', '.join(context_data['trust_boundaries'])}

Focus specifically on business logic flaws that could allow:
1. Race conditions in critical operations
2. State management bypasses
3. Authorization logic errors
4. Business rule validation gaps
5. Transaction integrity issues
6. Domain-specific security risks

Provide up to 10 business logic threats in JSON format with STRIDE categorization."""

        return ThreatModelingPrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            analysis_type="business_logic",
            source_path=source_path,
            metadata={"focus": "business_logic_vulnerabilities"},
        )

    def _create_data_flow_prompt(
        self, context_data: dict[str, Any], source_path: str
    ) -> ThreatModelingPrompt:
        """Create data flow analysis prompt."""
        system_prompt = """You are a security architect specializing in data flow analysis and trust boundary violations.
Your task is to analyze data flows between architectural components for security risks.

Focus on:
- Cross-boundary data flows and trust violations
- Sensitive data exposure through unintended channels  
- Privilege escalation through component interactions
- Missing security controls at trust boundaries
- Data leakage through side channels
- Component isolation failures

Response format: JSON object with "threats" array focusing on data flow security risks.
Each threat should map to STRIDE categories where appropriate."""

        user_prompt = f"""Analyze the data flows and architectural patterns for security risks:

Architectural Components:
{context_data['components_summary']}

Data Flows:
{json.dumps(context_data['data_flows'], indent=2)}

Trust Boundaries:
{', '.join(context_data['trust_boundaries'])}

Code Context:
{context_data['code_context'][:2000]}

Identify data flow security risks including:
1. Cross-boundary data flows without proper validation
2. Sensitive data exposure through unintended channels
3. Missing encryption or security controls at boundaries
4. Component isolation failures
5. Data leakage opportunities

Provide up to 8 data flow threats in JSON format."""

        return ThreatModelingPrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            analysis_type="data_flow_analysis",
            source_path=source_path,
            metadata={"focus": "data_flow_security"},
        )

    def _create_attack_surface_prompt(
        self, context_data: dict[str, Any], source_path: str
    ) -> ThreatModelingPrompt:
        """Create attack surface analysis prompt."""
        system_prompt = """You are a penetration tester analyzing attack surfaces and entry points.
Your task is to identify exposed attack vectors and potential attack chains.

Focus on:
- Exposed attack vectors and entry points
- Chained attack scenarios and pivoting opportunities
- Privilege escalation paths
- Lateral movement possibilities
- Data exfiltration channels
- Service disruption vectors

Response format: JSON object with "threats" array identifying attack surface risks.
Each threat should include realistic attack scenarios."""

        user_prompt = f"""Analyze the attack surface and potential attack vectors:

Code Context:
{context_data['code_context'][:2000]}

External Entities:
{', '.join(context_data['external_entities'])}

Exposed Components:
{', '.join(context_data['exposed_components'])}

Components Summary:
{context_data['components_summary']}

Identify attack surface risks including:
1. Exposed entry points and attack vectors
2. Chained attack scenarios
3. Privilege escalation opportunities
4. Lateral movement paths
5. Data exfiltration possibilities
6. Denial of service vectors

Provide up to 8 attack surface threats in JSON format."""

        return ThreatModelingPrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            analysis_type="attack_surface_analysis",
            source_path=source_path,
            metadata={"focus": "attack_surface"},
        )

    def _create_contextual_enhancement_prompt(
        self, context_data: dict[str, Any], source_path: str
    ) -> ThreatModelingPrompt:
        """Create contextual enhancement prompt."""
        system_prompt = """You are a security consultant enhancing existing threat analysis with contextual insights.
Your task is to review existing STRIDE threats and provide enhanced analysis based on actual code implementation.

For each existing threat, provide:
1. Enhanced description with code-specific context
2. More precise severity assessment based on implementation
3. Code-specific mitigation recommendations  
4. Additional related or chained threats

Also identify missing threat categories that traditional analysis might overlook.

Response format: JSON object with "threats" array containing enhanced and additional threats."""

        existing_threats_summary = [
            {
                "type": t["type"],
                "title": t["title"],
                "component": t["component"],
                "severity": t["severity"],
            }
            for t in context_data["existing_threats"][:10]  # Limit for prompt size
        ]

        user_prompt = f"""Enhance the existing STRIDE threat analysis with contextual insights:

Existing Threats:
{json.dumps(existing_threats_summary, indent=2)}

Code Context:
{context_data['code_context'][:2000]}

Components:
{context_data['components_summary']}

Provide contextual enhancements including:
1. Code-specific threat refinements
2. Implementation-based severity adjustments
3. Targeted mitigation recommendations
4. Additional threats missed by rule-based analysis
5. Threat chaining opportunities

Focus on threats specific to this implementation rather than generic vulnerabilities.
Provide up to 10 enhanced/additional threats in JSON format."""

        return ThreatModelingPrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            analysis_type="contextual_enhancement",
            source_path=source_path,
            metadata={
                "focus": "contextual_enhancement",
                "existing_threat_count": len(context_data["existing_threats"]),
            },
        )

    def parse_threat_modeling_response(
        self, response_text: str, analysis_type: str
    ) -> list[Threat]:
        """Parse LLM response into Threat objects.

        Args:
            response_text: Raw response from LLM
            analysis_type: Type of analysis performed

        Returns:
            List of Threat objects
        """
        logger.info(f"Parsing {analysis_type} threat modeling response")

        threats = []

        try:
            # Try to parse as JSON first
            try:
                response_data = json.loads(response_text)
                threat_list = response_data.get("threats", [])
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON response for {analysis_type}, skipping")
                return []

            for threat_data in threat_list:
                try:
                    threat = Threat(
                        threat_type=ThreatType(threat_data.get("type", "tampering")),
                        component=threat_data.get("component", "Unknown"),
                        title=threat_data.get("title", "LLM-Identified Threat"),
                        description=threat_data.get("description", ""),
                        severity=Severity(threat_data.get("severity", "medium")),
                        likelihood=threat_data.get("likelihood", "medium"),
                        impact=threat_data.get("impact", "medium"),
                        mitigation=threat_data.get("mitigation"),
                        cwe_id=threat_data.get("cwe_id"),
                    )

                    # Add LLM-specific metadata
                    threat.references = threat.references or []
                    threat.references.append(f"LLM Analysis ({analysis_type})")

                    threats.append(threat)

                except (ValueError, KeyError) as e:
                    logger.warning(f"Failed to parse threat data: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to parse LLM threat response: {e}")

        logger.info(f"Parsed {len(threats)} threats from {analysis_type} analysis")
        return threats

    def merge_threat_responses(
        self,
        original_model: ThreatModel,
        llm_responses: list[tuple[str, str]],  # (analysis_type, response_text) pairs
        analysis_options: dict[str, Any] | None = None,
    ) -> ThreatModel:
        """Merge LLM threat analysis responses into the original threat model.

        Args:
            original_model: Original threat model from traditional analysis
            llm_responses: List of (analysis_type, response_text) tuples
            analysis_options: Analysis configuration options

        Returns:
            Enhanced ThreatModel with LLM insights
        """
        logger.info(f"Merging {len(llm_responses)} LLM threat analysis responses")

        # Create enhanced model starting with original
        enhanced_model = ThreatModel(
            components=original_model.components,
            threats=original_model.threats.copy(),
            metadata=original_model.metadata.copy(),
        )

        # Parse and add threats from each response
        total_added = 0
        for analysis_type, response_text in llm_responses:
            new_threats = self.parse_threat_modeling_response(
                response_text, analysis_type
            )
            enhanced_model.threats.extend(new_threats)
            total_added += len(new_threats)

        # Remove duplicate threats (by title + component)
        seen = set()
        unique_threats = []

        for threat in enhanced_model.threats:
            threat_key = (threat.title, threat.component)
            if threat_key not in seen:
                seen.add(threat_key)
                unique_threats.append(threat)

        enhanced_model.threats = unique_threats

        # Filter by severity if specified
        if analysis_options and "severity_threshold" in analysis_options:
            enhanced_model.threats = self._filter_by_severity(
                enhanced_model.threats, analysis_options["severity_threshold"]
            )

        # Sort threats by severity then component
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        enhanced_model.threats.sort(
            key=lambda t: (-severity_order.get(t.severity.value, 2), t.component)
        )

        # Add LLM metadata
        enhanced_model.metadata.update(
            {
                "llm_enhanced": True,
                "llm_analysis_count": len(llm_responses),
                "llm_threats_added": total_added,
                "llm_timestamp": datetime.now().isoformat(),
                "analysis_types": [analysis_type for analysis_type, _ in llm_responses],
            }
        )

        logger.info(f"Enhanced threat model with {total_added} additional threats")
        return enhanced_model

    def _prepare_analysis_context(
        self, threat_model: ThreatModel, code_context: str
    ) -> dict[str, Any]:
        """Prepare context data for LLM analysis."""
        components = threat_model.components

        return {
            "code_context": code_context[:8000],  # Limit context size
            "components_summary": self._summarize_components(components),
            "data_flows": [flow.to_dict() for flow in components.data_flows],
            "trust_boundaries": components.boundaries,
            "external_entities": components.external_entities,
            "exposed_components": [c.name for c in components.components if c.exposed],
            "existing_threats": [
                {
                    "type": t.threat_type.value,
                    "title": t.title,
                    "component": t.component,
                    "severity": t.severity.value,
                }
                for t in threat_model.threats
            ],
        }

    def _summarize_components(self, components: ThreatModelComponents) -> str:
        """Create a summary of architectural components for LLM analysis."""
        summary = []

        if components.processes:
            summary.append(f"Processes: {', '.join(components.processes)}")

        if components.data_stores:
            summary.append(f"Data Stores: {', '.join(components.data_stores)}")

        if components.external_entities:
            summary.append(
                f"External Entities: {', '.join(components.external_entities)}"
            )

        if components.boundaries:
            summary.append(f"Trust Boundaries: {', '.join(components.boundaries)}")

        return "; ".join(summary)

    def _filter_by_severity(
        self, threats: list[Threat], threshold: str
    ) -> list[Threat]:
        """Filter threats by minimum severity level."""
        severity_order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        min_level = severity_order.get(threshold, 2)

        return [
            threat
            for threat in threats
            if severity_order.get(threat.severity.value, 2) >= min_level
        ]

    def _extract_code_context(self, source_path: str) -> str:
        """Extract code context from source path for analysis."""
        try:
            path = Path(source_path)

            if path.is_file():
                with open(path, encoding="utf-8") as f:
                    return f.read()[:10000]  # Limit context size
            elif path.is_dir():
                # Extract key files for context
                context_parts = []

                # Look for main application files
                key_patterns = [
                    "**/*.py",
                    "**/*.js",
                    "**/*.ts",
                    "**/*.java",
                    "**/*.go",
                    "**/*.rs",
                    "**/*.php",
                ]

                for pattern in key_patterns:
                    files = list(path.glob(pattern))[:5]  # Limit files
                    for file_path in files:
                        try:
                            with open(file_path, encoding="utf-8") as f:
                                content = f.read()[:2000]  # Limit per file
                                context_parts.append(
                                    f"=== {file_path.name} ===\n{content}"
                                )
                        except Exception as e:
                            logger.warning(f"Failed to read file {file_path}: {e}")
                            continue

                return "\n\n".join(context_parts)[:10000]
            else:
                return ""

        except Exception as e:
            logger.warning(f"Failed to extract code context: {e}")
            return ""
