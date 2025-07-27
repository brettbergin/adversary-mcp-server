"""Main threat model builder that orchestrates component extraction and threat analysis."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..logger import get_logger
from ..scanner.types import Language, LanguageSupport
from .extractors.base_extractor import BaseExtractor
from .extractors.js_extractor import JavaScriptExtractor
from .extractors.python_extractor import PythonExtractor
from .llm_modeler import LLMThreatModeler
from .models import ComponentType, Severity, ThreatModel, ThreatModelComponents
from .threat_catalog import STRIDE_THREATS

logger = get_logger("threat_model_builder")


class ThreatModelBuilder:
    """Main class for building threat models from source code."""

    def __init__(self, enable_llm: bool = False):
        """Initialize the threat model builder.

        Args:
            enable_llm: Whether to enable LLM-enhanced threat modeling
        """
        # Create a single instance of JavaScriptExtractor for both JS and TS
        js_extractor = JavaScriptExtractor()

        self.extractors: dict[Language, BaseExtractor] = {
            Language.PYTHON: PythonExtractor(),
            Language.JAVASCRIPT: js_extractor,
            Language.TYPESCRIPT: js_extractor,  # Share the same extractor instance
        }

        # Initialize LLM modeler for prompt generation
        self.llm_modeler = None
        if enable_llm:
            try:
                self.llm_modeler = LLMThreatModeler()
                logger.info("LLM threat modeling enabled (client-based)")
            except Exception as e:
                logger.warning(f"LLM threat modeling not available: {e}")

    def build_threat_model(
        self,
        source_path: str,
        include_threats: bool = True,
        severity_threshold: Severity = Severity.MEDIUM,
        use_llm: bool = False,
        llm_options: dict[str, Any] | None = None,
    ) -> ThreatModel:
        """Build a complete threat model from source code.

        Args:
            source_path: Path to source file or directory
            include_threats: Whether to include STRIDE threat analysis
            severity_threshold: Minimum severity level for included threats
            use_llm: Whether to enhance with LLM analysis
            llm_options: Options for LLM analysis

        Returns:
            Complete ThreatModel with components and threats
        """
        logger.info(f"Building threat model for: {source_path}")

        # Extract architectural components
        components = self._extract_components(source_path)

        # Create base threat model
        threat_model = ThreatModel(
            components=components,
            metadata={
                "source_path": source_path,
                "analysis_type": "STRIDE" if include_threats else "components_only",
                "severity_threshold": severity_threshold.value,
                "timestamp": datetime.now().isoformat(),
            },
        )

        # Add STRIDE threat analysis if requested
        if include_threats:
            threats = self._analyze_threats(components, severity_threshold)
            threat_model.threats = threats
            logger.info(
                f"Identified {len(threats)} threats above {severity_threshold.value} severity"
            )

        # Generate LLM prompts if requested and available
        if use_llm and self.llm_modeler:
            try:
                logger.info("Generating LLM prompts for threat model enhancement")

                # Extract code context if needed
                code_context = self.llm_modeler._extract_code_context(source_path)

                # Generate prompts for different analysis types
                prompts = self.llm_modeler.create_threat_modeling_prompts(
                    threat_model, source_path, code_context, llm_options
                )

                # Store prompts in metadata for client processing
                threat_model.metadata["llm_prompts"] = [p.to_dict() for p in prompts]
                threat_model.metadata["analysis_type"] += "_llm_prompts_available"
                threat_model.metadata["llm_prompt_count"] = len(prompts)

                logger.info(f"Generated {len(prompts)} LLM prompts for client analysis")

            except Exception as e:
                logger.error(f"LLM prompt generation failed: {e}")
                threat_model.metadata["llm_enhancement_error"] = str(e)
        elif use_llm and not self.llm_modeler:
            logger.warning("LLM enhancement requested but not available")
            threat_model.metadata["llm_enhancement_error"] = (
                "LLM modeler not initialized"
            )

        logger.info(
            f"Threat model complete: {len(components.processes)} processes, "
            f"{len(components.data_stores)} data stores, "
            f"{len(components.external_entities)} external entities, "
            f"{len(threat_model.threats)} total threats"
        )

        return threat_model

    def _extract_components(self, source_path: str) -> ThreatModelComponents:
        """Extract architectural components from source code.

        Args:
            source_path: Path to source file or directory

        Returns:
            ThreatModelComponents containing extracted architecture
        """
        path = Path(source_path)

        if path.is_file():
            return self._extract_from_file(str(path))
        elif path.is_dir():
            return self._extract_from_directory(str(path))
        else:
            raise ValueError(f"Invalid source path: {source_path}")

    def _extract_from_file(self, file_path: str) -> ThreatModelComponents:
        """Extract components from a single file."""
        language = LanguageSupport.detect_language(file_path)
        extractor = self.extractors.get(language)

        if not extractor:
            logger.warning(f"No extractor available for language: {language}")
            return ThreatModelComponents()

        logger.info(
            f"Extracting components from {file_path} using {language} extractor"
        )

        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()
            return extractor.extract_components(code, file_path)
        except (OSError, UnicodeDecodeError) as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return ThreatModelComponents()

    def _extract_from_directory(self, directory_path: str) -> ThreatModelComponents:
        """Extract components from all supported files in a directory."""
        combined_components = ThreatModelComponents()
        directory = Path(directory_path)

        # Get all supported file extensions
        all_extensions = set()
        for extractor in self.extractors.values():
            all_extensions.update(extractor.get_supported_extensions())

        # Find all supported files
        supported_files = []
        for ext in all_extensions:
            supported_files.extend(directory.rglob(f"*{ext}"))

        logger.info(f"Found {len(supported_files)} supported files in {directory_path}")

        # Group files by language for batch processing
        files_by_language = {}
        for file_path in supported_files:
            language = LanguageSupport.detect_language(str(file_path))
            if language in self.extractors:
                if language not in files_by_language:
                    files_by_language[language] = []
                files_by_language[language].append(file_path)

        # Process files by language
        for language, files in files_by_language.items():
            extractor = self.extractors[language]
            logger.info(f"Processing {len(files)} {language} files")

            for file_path in files:
                try:
                    with open(file_path, encoding="utf-8") as f:
                        code = f.read()
                    file_components = extractor.extract_components(code, str(file_path))
                    self._merge_components(combined_components, file_components)
                except (OSError, UnicodeDecodeError) as e:
                    logger.warning(f"Skipping file {file_path}: {e}")
                    continue

        # Post-process combined components
        self._post_process_combined_components(combined_components)

        return combined_components

    def _merge_components(
        self, target: ThreatModelComponents, source: ThreatModelComponents
    ):
        """Merge components from source into target, avoiding duplicates."""
        # Merge boundaries
        for boundary in source.boundaries:
            if boundary not in target.boundaries:
                target.boundaries.append(boundary)

        # Merge external entities
        for entity in source.external_entities:
            if entity not in target.external_entities:
                target.external_entities.append(entity)

        # Merge processes
        for process in source.processes:
            if process not in target.processes:
                target.processes.append(process)

        # Merge data stores
        for store in source.data_stores:
            if store not in target.data_stores:
                target.data_stores.append(store)

        # Merge data flows (check for duplicates by source-target-protocol)
        existing_flows = {(f.source, f.target, f.protocol) for f in target.data_flows}
        for flow in source.data_flows:
            flow_key = (flow.source, flow.target, flow.protocol)
            if flow_key not in existing_flows:
                target.data_flows.append(flow)
                existing_flows.add(flow_key)

        # Merge components
        existing_components = {c.name for c in target.components}
        for component in source.components:
            if component.name not in existing_components:
                target.components.append(component)
                existing_components.add(component.name)

    def _post_process_combined_components(self, components: ThreatModelComponents):
        """Post-process combined components for consistency."""
        # Ensure all referenced components in data flows exist
        all_component_names = set(
            components.external_entities + components.processes + components.data_stores
        )

        # Add missing components referenced in data flows
        for flow in components.data_flows:
            for component_name in [flow.source, flow.target]:
                if component_name not in all_component_names:
                    # Try to infer component type from name
                    component_type = self._infer_component_type(component_name)
                    components.add_component(component_name, component_type)
                    all_component_names.add(component_name)

        # Infer trust boundaries if not already set
        if not components.boundaries:
            components.boundaries = self._infer_trust_boundaries(components)

        # Sort all lists for consistent output
        components.boundaries.sort()
        components.external_entities.sort()
        components.processes.sort()
        components.data_stores.sort()
        components.data_flows.sort(key=lambda f: (f.source, f.target))

    def _infer_component_type(self, component_name: str) -> ComponentType:
        """Infer component type from name."""
        name_lower = component_name.lower()

        # External entity patterns
        if any(
            pattern in name_lower for pattern in ["api", "service", "client", "user"]
        ):
            if any(pattern in name_lower for pattern in ["user", "client", "browser"]):
                return ComponentType.EXTERNAL_ENTITY
            elif "api" in name_lower:
                return ComponentType.EXTERNAL_ENTITY

        # Data store patterns
        if any(
            pattern in name_lower
            for pattern in ["database", "db", "store", "cache", "file"]
        ):
            return ComponentType.DATA_STORE

        # Process patterns (default)
        return ComponentType.PROCESS

    def _infer_trust_boundaries(self, components: ThreatModelComponents) -> list[str]:
        """Infer trust boundaries from components."""
        boundaries = set()

        # Standard boundaries based on component presence
        if components.external_entities:
            boundaries.add("Internet")

        if components.processes:
            boundaries.add("Application")

        if components.data_stores:
            boundaries.add("Data Layer")

        # Infer additional boundaries from component names
        all_names = (
            components.external_entities + components.processes + components.data_stores
        )

        for name in all_names:
            name_lower = name.lower()

            if any(keyword in name_lower for keyword in ["api", "gateway", "proxy"]):
                boundaries.add("DMZ")

            if any(
                keyword in name_lower for keyword in ["admin", "internal", "private"]
            ):
                boundaries.add("Internal")

            if any(keyword in name_lower for keyword in ["public", "cdn", "static"]):
                boundaries.add("Public")

        return sorted(boundaries)

    def _analyze_threats(
        self, components: ThreatModelComponents, severity_threshold: Severity
    ) -> list:
        """Analyze components for STRIDE threats.

        Args:
            components: Extracted architectural components
            severity_threshold: Minimum severity level for threats

        Returns:
            List of identified threats above threshold
        """
        all_threats = []

        # Analyze external entities
        for entity in components.external_entities:
            entity_component = next(
                (c for c in components.components if c.name == entity), None
            )
            context = entity_component.description if entity_component else ""
            threats = STRIDE_THREATS.get_threats_for_component(
                entity, ComponentType.EXTERNAL_ENTITY, context
            )
            all_threats.extend(threats)

        # Analyze processes
        for process in components.processes:
            process_component = next(
                (c for c in components.components if c.name == process), None
            )
            context = process_component.description if process_component else ""
            threats = STRIDE_THREATS.get_threats_for_component(
                process, ComponentType.PROCESS, context
            )
            all_threats.extend(threats)

        # Analyze data stores
        for store in components.data_stores:
            store_component = next(
                (c for c in components.components if c.name == store), None
            )
            context = store_component.description if store_component else ""
            threats = STRIDE_THREATS.get_threats_for_component(
                store, ComponentType.DATA_STORE, context
            )
            all_threats.extend(threats)

        # Group similar threats by title and type, combining affected components
        threat_groups = {}

        for threat in all_threats:
            threat_key = (threat.title, threat.threat_type)
            if threat_key not in threat_groups:
                # First occurrence - create the threat with this component
                threat_groups[threat_key] = threat
            else:
                # Subsequent occurrence - combine components
                existing_threat = threat_groups[threat_key]
                if threat.component not in existing_threat.component:
                    # Add component to existing threat (if not already included)
                    component_list = existing_threat.component.split(", ")
                    if threat.component not in component_list:
                        component_list.append(threat.component)
                        existing_threat.component = ", ".join(component_list)

        all_threats = list(threat_groups.values())

        # Filter by severity threshold
        severity_order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        min_level = severity_order[severity_threshold]

        filtered_threats = [
            threat
            for threat in all_threats
            if severity_order[threat.severity] >= min_level
        ]

        # Sort by severity (highest first) then by component name
        filtered_threats.sort(key=lambda t: (-severity_order[t.severity], t.component))

        return filtered_threats

    def save_threat_model(
        self, threat_model: ThreatModel, output_path: str, format: str = "markdown"
    ):
        """Save threat model to file.

        Args:
            threat_model: ThreatModel to save
            output_path: Output file path
            format: Output format ('json' or 'markdown')
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if format.lower() == "json":
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(threat_model.to_dict(), f, indent=2, ensure_ascii=False)
        elif format.lower() == "markdown":
            markdown_content = self._generate_markdown_report(threat_model)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(markdown_content)
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Threat model saved to: {output_path}")

    def _generate_markdown_report(self, threat_model: ThreatModel) -> str:
        """Generate a markdown report from threat model."""
        components = threat_model.components
        threats = threat_model.threats

        report = []
        report.append("# Threat Model Report")
        report.append("")

        # Metadata
        if threat_model.metadata:
            report.append("## Analysis Details")
            report.append("")
            for key, value in threat_model.metadata.items():
                # Special formatting for specific metadata keys
                if key == "llm_prompts":
                    # Don't display the full prompts in markdown - just show count
                    if isinstance(value, list):
                        report.append(
                            f"- **LLM Prompts Generated**: {len(value)} analysis prompts"
                        )
                    else:
                        report.append("- **LLM Prompts**: Available")
                elif key == "analysis_type":
                    # Clean up analysis type formatting
                    if value == "STRIDE_llm_prompts_available":
                        report.append(
                            "- **Analysis Type**: STRIDE with LLM Enhancement"
                        )
                    else:
                        report.append(f"- **{key.replace('_', ' ').title()}**: {value}")
                elif key == "llm_prompt_count":
                    report.append(
                        f"- **LLM Analysis Types**: {value} specialized threat analysis prompts"
                    )
                else:
                    # Default formatting for other metadata
                    formatted_key = key.replace("_", " ").title()
                    report.append(f"- **{formatted_key}**: {value}")
            report.append("")

        # Architecture Components
        report.append("## Architecture Components")
        report.append("")

        if components.boundaries:
            report.append("### Trust Boundaries")
            for boundary in components.boundaries:
                report.append(f"- {boundary}")
            report.append("")

        if components.external_entities:
            report.append("### External Entities")
            for entity in components.external_entities:
                report.append(f"- {entity}")
            report.append("")

        if components.processes:
            report.append("### Processes")
            for process in components.processes:
                report.append(f"- {process}")
            report.append("")

        if components.data_stores:
            report.append("### Data Stores")
            for store in components.data_stores:
                report.append(f"- {store}")
            report.append("")

        # Data Flows
        if components.data_flows:
            report.append("### Data Flows")
            report.append("")
            for flow in components.data_flows:
                report.append(
                    f"- **{flow.source}** → **{flow.target}** ({flow.protocol})"
                )
            report.append("")

        # Comprehensive Statistics
        if threats:
            stats = threat_model.calculate_comprehensive_statistics()
            report.append("## Threat Analysis Summary")
            report.append("")

            # Threat Summary
            threat_summary = stats.get("threat_summary", {})
            report.append(
                f"- **Total Threats Identified**: {threat_summary.get('total_threats', 0)}"
            )
            report.append(
                f"- **Unique Components Affected**: {threat_summary.get('unique_components_affected', 0)}"
            )
            report.append(
                f"- **Threats with CVSS Scores**: {threat_summary.get('threats_with_cvss', 0)}"
            )
            report.append(
                f"- **Threats with Code Locations**: {threat_summary.get('threats_with_code_locations', 0)}"
            )
            report.append("")

            # Severity and Risk Breakdown
            severity_breakdown = stats.get("severity_breakdown", {})
            if severity_breakdown:
                report.append("### Severity Distribution")
                for severity, data in severity_breakdown.items():
                    if isinstance(data, dict):
                        count = data.get("count", 0)
                        percentage = data.get("percentage", 0)
                        report.append(
                            f"- **{severity.title()}**: {count} threats ({percentage}%)"
                        )
                    else:
                        report.append(f"- **{severity.title()}**: {data} threats")
                report.append("")

            # Detection Source Breakdown
            detection_breakdown = stats.get("detection_source_breakdown", {})
            if detection_breakdown and any(v > 0 for v in detection_breakdown.values()):
                report.append("### Detection Sources")
                for source, count in detection_breakdown.items():
                    if count > 0:
                        formatted_source = source.replace("_", " ").title()
                        report.append(f"- **{formatted_source}**: {count} threats")
                report.append("")

            # Risk Analysis
            risk_analysis = stats.get("risk_analysis", {})
            if risk_analysis:
                report.append("### Risk Analysis")
                if "average_risk_score" in risk_analysis:
                    report.append(
                        f"- **Average Risk Score**: {risk_analysis['average_risk_score']}/10.0"
                    )
                if "highest_risk_score" in risk_analysis:
                    report.append(
                        f"- **Highest Risk Score**: {risk_analysis['highest_risk_score']}/10.0"
                    )
                risk_breakdown = risk_analysis.get("risk_ranking_breakdown", {})
                if risk_breakdown:
                    for ranking, count in risk_breakdown.items():
                        if count > 0:
                            report.append(
                                f"- **{ranking.title()} Risk**: {count} threats"
                            )
                report.append("")

        # Threats
        if threats:
            report.append("## STRIDE Threat Analysis")
            report.append("")

            # Deduplicate threats by title and type, combining components
            threat_groups = {}
            for threat in threats:
                threat_key = (threat.title, threat.threat_type)
                if threat_key not in threat_groups:
                    # First occurrence - create the threat with this component
                    threat_groups[threat_key] = threat
                else:
                    # Subsequent occurrence - combine components
                    existing_threat = threat_groups[threat_key]
                    if threat.component not in existing_threat.component:
                        # Add component to existing threat (if not already included)
                        component_list = existing_threat.component.split(", ")
                        if threat.component not in component_list:
                            component_list.append(threat.component)
                            existing_threat.component = ", ".join(component_list)

            # Use deduplicated threats
            threats = list(threat_groups.values())

            # Sort by risk score (highest first) then by severity
            for threat in threats:
                if threat.risk_score == 0.0:
                    threat.calculate_risk_score()
            threats.sort(
                key=lambda t: (
                    -t.risk_score,
                    -{"low": 1, "medium": 2, "high": 3, "critical": 4}[
                        t.severity.value
                    ],
                )
            )

            # Group threats by severity
            threats_by_severity = {}
            for threat in threats:
                severity = threat.severity.value
                if severity not in threats_by_severity:
                    threats_by_severity[severity] = []
                threats_by_severity[severity].append(threat)

            # Output threats by severity (highest first)
            for severity in ["critical", "high", "medium", "low"]:
                if severity in threats_by_severity:
                    report.append(f"### {severity.title()} Severity Threats")
                    report.append("")

                    for threat in threats_by_severity[severity]:
                        report.append(f"#### {threat.title}")

                        # Basic threat information
                        report.append(f"**Component**: {threat.component}")
                        report.append(
                            f"**Type**: {threat.threat_type.value.replace('_', ' ').title()}"
                        )
                        report.append(f"**Description**: {threat.description}")

                        # Risk and scoring information
                        if threat.risk_score > 0:
                            report.append(
                                f"**Risk Score**: {threat.risk_score:.1f}/10.0 ({threat.risk_ranking.title()} Risk)"
                            )

                        # CVSS Score information
                        if threat.cvss_score:
                            cvss = threat.cvss_score
                            report.append(
                                f"**CVSS Score**: {cvss.overall_score:.1f} ({cvss.get_severity_rating()})"
                            )
                            report.append(f"**CVSS Vector**: {cvss.vector_string}")

                        # Detection metadata
                        if threat.threat_metadata:
                            metadata = threat.threat_metadata
                            detection_source = metadata.detection_source.value.replace(
                                "_", " "
                            ).title()
                            confidence = metadata.confidence_level.value.replace(
                                "_", " "
                            ).title()
                            report.append(f"**Detection Source**: {detection_source}")
                            report.append(f"**Confidence Level**: {confidence}")

                            if metadata.business_impact != "medium":
                                report.append(
                                    f"**Business Impact**: {metadata.business_impact.title()}"
                                )
                            if metadata.remediation_effort != "medium":
                                report.append(
                                    f"**Remediation Effort**: {metadata.remediation_effort.title()}"
                                )

                        # Code locations
                        if threat.code_locations:
                            primary_location = threat.get_primary_location()
                            if primary_location:
                                location_info = (
                                    f"**Code Location**: {primary_location.file_path}"
                                )
                                if primary_location.line_number:
                                    location_info += (
                                        f" (Line {primary_location.line_number})"
                                    )
                                if primary_location.function_name:
                                    location_info += (
                                        f" in {primary_location.function_name}()"
                                    )
                                report.append(location_info)

                                # Show code snippet if available
                                if primary_location.code_snippet:
                                    report.append("**Code Snippet**:")
                                    report.append("```")
                                    report.append(primary_location.code_snippet.strip())
                                    report.append("```")

                            # Show additional locations if multiple
                            if len(threat.code_locations) > 1:
                                additional_locations = threat.code_locations[1:]
                                location_list = []
                                for loc in additional_locations[
                                    :3
                                ]:  # Limit to first 3 additional
                                    loc_str = loc.file_path
                                    if loc.line_number:
                                        loc_str += f":{loc.line_number}"
                                    location_list.append(loc_str)
                                if location_list:
                                    report.append(
                                        f"**Additional Locations**: {', '.join(location_list)}"
                                    )
                                if len(threat.code_locations) > 4:
                                    report.append(
                                        f"*...and {len(threat.code_locations) - 4} more locations*"
                                    )

                        # Attack scenarios
                        if threat.attack_scenarios:
                            report.append("**Attack Scenarios**:")
                            for i, scenario in enumerate(
                                threat.attack_scenarios[:3], 1
                            ):  # Limit to first 3
                                report.append(f"{i}. {scenario}")

                        # Technical details
                        if threat.technical_details:
                            report.append(
                                f"**Technical Details**: {threat.technical_details}"
                            )

                        # Mitigation and compliance
                        if threat.mitigation:
                            report.append(f"**Mitigation**: {threat.mitigation}")

                        if threat.cwe_id:
                            report.append(f"**CWE**: {threat.cwe_id}")

                        # Business rationale
                        if threat.business_rationale:
                            report.append(
                                f"**Business Impact**: {threat.business_rationale}"
                            )

                        # Compliance references
                        if threat.compliance_references:
                            compliance_list = ", ".join(
                                threat.compliance_references[:3]
                            )  # Limit to first 3
                            report.append(f"**Compliance**: {compliance_list}")

                        # Additional references
                        if threat.references:
                            filtered_refs = [
                                ref
                                for ref in threat.references
                                if not ref.startswith("LLM Analysis")
                            ]
                            if filtered_refs:
                                report.append(
                                    f"**References**: {', '.join(filtered_refs[:2])}"
                                )  # Limit to first 2

                        report.append("")

        return "\n".join(report)
