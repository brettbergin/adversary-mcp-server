"""Main threat model builder that orchestrates component extraction and threat analysis."""

import json
from pathlib import Path

from ..logger import get_logger
from ..scanner.types import Language, LanguageSupport
from .extractors.base_extractor import BaseExtractor
from .extractors.js_extractor import JavaScriptExtractor
from .extractors.python_extractor import PythonExtractor
from .models import ComponentType, Severity, ThreatModel, ThreatModelComponents
from .threat_catalog import STRIDE_THREATS

logger = get_logger("threat_model_builder")


class ThreatModelBuilder:
    """Main class for building threat models from source code."""

    def __init__(self):
        """Initialize the threat model builder."""
        # Create a single instance of JavaScriptExtractor for both JS and TS
        js_extractor = JavaScriptExtractor()

        self.extractors: dict[Language, BaseExtractor] = {
            Language.PYTHON: PythonExtractor(),
            Language.JAVASCRIPT: js_extractor,
            Language.TYPESCRIPT: js_extractor,  # Share the same extractor instance
        }

    def build_threat_model(
        self,
        source_path: str,
        include_threats: bool = True,
        severity_threshold: Severity = Severity.MEDIUM,
    ) -> ThreatModel:
        """Build a complete threat model from source code.

        Args:
            source_path: Path to source file or directory
            include_threats: Whether to include STRIDE threat analysis
            severity_threshold: Minimum severity level for included threats

        Returns:
            Complete ThreatModel with components and threats
        """
        logger.info(f"Building threat model for: {source_path}")

        # Extract architectural components
        components = self._extract_components(source_path)

        # Create threat model
        threat_model = ThreatModel(
            components=components,
            metadata={
                "source_path": source_path,
                "analysis_type": "STRIDE" if include_threats else "components_only",
                "severity_threshold": severity_threshold.value,
            },
        )

        # Add STRIDE threat analysis if requested
        if include_threats:
            threats = self._analyze_threats(components, severity_threshold)
            threat_model.threats = threats
            logger.info(
                f"Identified {len(threats)} threats above {severity_threshold.value} severity"
            )

        logger.info(
            f"Threat model complete: {len(components.processes)} processes, "
            f"{len(components.data_stores)} data stores, "
            f"{len(components.external_entities)} external entities"
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
                report.append(f"- **{key.replace('_', ' ').title()}**: {value}")
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

        # Threats
        if threats:
            report.append("## STRIDE Threat Analysis")
            report.append("")

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
                        report.append(f"**Component**: {threat.component}")
                        report.append(
                            f"**Type**: {threat.threat_type.value.replace('_', ' ').title()}"
                        )
                        report.append(f"**Description**: {threat.description}")
                        if threat.mitigation:
                            report.append(f"**Mitigation**: {threat.mitigation}")
                        if threat.cwe_id:
                            report.append(f"**CWE**: {threat.cwe_id}")
                        report.append("")

        return "\n".join(report)
