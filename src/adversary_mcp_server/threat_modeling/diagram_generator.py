"""Mermaid diagram generator for threat model visualization."""

import re
from pathlib import Path

from ..logger import get_logger
from .models import Severity, ThreatModel, ThreatModelComponents

logger = get_logger("diagram_generator")


class MermaidDiagramGenerator:
    """Generator for Mermaid.js architecture diagrams from threat models."""

    def __init__(self):
        """Initialize the diagram generator."""
        self.node_counter = 0
        self.node_ids = {}  # Map component names to node IDs

    def generate_diagram(
        self,
        threat_model: ThreatModel,
        diagram_type: str = "flowchart",
        show_threats: bool = True,
        layout_direction: str = "TD",
    ) -> str:
        """Generate a Mermaid diagram from a threat model.

        Args:
            threat_model: ThreatModel to visualize
            diagram_type: Type of diagram ('flowchart', 'graph', 'sequence')
            show_threats: Whether to highlight threats in the diagram
            layout_direction: Layout direction ('TD', 'LR', 'BT', 'RL')

        Returns:
            Mermaid diagram as string
        """
        self._reset_state()

        if diagram_type == "flowchart":
            return self._generate_flowchart(
                threat_model, show_threats, layout_direction
            )
        elif diagram_type == "graph":
            return self._generate_graph(threat_model, show_threats, layout_direction)
        elif diagram_type == "sequence":
            return self._generate_sequence_diagram(threat_model)
        else:
            raise ValueError(f"Unsupported diagram type: {diagram_type}")

    def save_diagram(self, diagram_content: str, output_path: str):
        """Save Mermaid diagram to file.

        Args:
            diagram_content: Mermaid diagram content
            output_path: Output file path
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(diagram_content)

        logger.info(f"Mermaid diagram saved to: {output_path}")

    def _reset_state(self):
        """Reset generator state."""
        self.node_counter = 0
        self.node_ids = {}

    def _generate_flowchart(
        self, threat_model: ThreatModel, show_threats: bool, layout_direction: str
    ) -> str:
        """Generate a flowchart diagram."""
        components = threat_model.components
        threats = threat_model.threats if show_threats else []

        lines = [f"flowchart {layout_direction}"]

        # Create subgraphs for trust boundaries
        if components.boundaries:
            boundary_nodes = self._create_boundary_subgraphs(components, lines)

        # Add nodes for components
        self._add_component_nodes(components, lines)

        # Add edges for data flows
        self._add_data_flow_edges(components, lines)

        # Add threat styling if requested
        if show_threats:
            self._add_threat_styling(threats, lines)

        # Add CSS classes for styling
        self._add_css_classes(lines)

        return "\n".join(lines)

    def _generate_graph(
        self, threat_model: ThreatModel, show_threats: bool, layout_direction: str
    ) -> str:
        """Generate a graph diagram (similar to flowchart but simpler syntax)."""
        components = threat_model.components
        threats = threat_model.threats if show_threats else []

        lines = [f"graph {layout_direction}"]

        # Add nodes and edges
        self._add_component_nodes(components, lines, simple_format=True)
        self._add_data_flow_edges(components, lines, simple_format=True)

        # Add threat styling
        if show_threats:
            self._add_threat_styling(threats, lines)

        self._add_css_classes(lines)

        return "\n".join(lines)

    def _generate_sequence_diagram(self, threat_model: ThreatModel) -> str:
        """Generate a sequence diagram showing data flow interactions."""
        components = threat_model.components

        lines = ["sequenceDiagram"]

        # Collect participants
        participants = set()
        for flow in components.data_flows:
            participants.add(flow.source)
            participants.add(flow.target)

        # Add participants
        for participant in sorted(participants):
            sanitized_display_name = self._sanitize_display_name(participant)
            lines.append(
                f"    participant {self._get_node_id(participant)} as {sanitized_display_name}"
            )

        lines.append("")  # Empty line for readability

        # Add interactions
        for i, flow in enumerate(components.data_flows):
            source_id = self._get_node_id(flow.source)
            target_id = self._get_node_id(flow.target)
            label = f"{flow.protocol}"
            if flow.data_type:
                label += f" ({flow.data_type})"

            lines.append(f"    {source_id}->>+{target_id}: {label}")

            # Add response if it makes sense
            if not self._is_one_way_flow(flow):
                lines.append(f"    {target_id}-->>-{source_id}: Response")

        return "\n".join(lines)

    def _create_boundary_subgraphs(
        self, components: ThreatModelComponents, lines: list[str]
    ) -> dict[str, list[str]]:
        """Create subgraphs for trust boundaries."""
        boundary_nodes = {}

        # Map components to boundaries based on naming heuristics
        component_boundaries = self._map_components_to_boundaries(components)

        for boundary, boundary_components in component_boundaries.items():
            if boundary_components:
                boundary_id = self._sanitize_id(boundary)
                lines.append(f'    subgraph {boundary_id} ["{boundary}"]')

                boundary_nodes[boundary] = []
                for component in boundary_components:
                    node_id = self._get_node_id(component)
                    boundary_nodes[boundary].append(node_id)

                lines.append("    end")
                lines.append("")

        return boundary_nodes

    def _map_components_to_boundaries(
        self, components: ThreatModelComponents
    ) -> dict[str, list[str]]:
        """Map components to trust boundaries based on naming patterns."""
        boundary_map = {}

        # Initialize boundaries
        for boundary in components.boundaries:
            boundary_map[boundary] = []

        # Map external entities to Internet boundary
        if "Internet" in boundary_map:
            boundary_map["Internet"].extend(components.external_entities)

        # Map processes to Application boundary
        if "Application" in boundary_map:
            boundary_map["Application"].extend(components.processes)

        # Map data stores to Data Layer boundary
        if "Data Layer" in boundary_map:
            boundary_map["Data Layer"].extend(components.data_stores)

        # Handle special cases based on naming
        all_components = (
            components.external_entities + components.processes + components.data_stores
        )

        for component in all_components:
            component_lower = component.lower()

            # DMZ components
            if any(
                keyword in component_lower for keyword in ["api", "gateway", "proxy"]
            ):
                if "DMZ" in boundary_map:
                    # Remove from other boundaries if already assigned
                    for boundary_components in boundary_map.values():
                        if component in boundary_components:
                            boundary_components.remove(component)
                    boundary_map["DMZ"].append(component)

            # Internal components
            elif any(
                keyword in component_lower
                for keyword in ["admin", "internal", "private"]
            ):
                if "Internal" in boundary_map:
                    for boundary_components in boundary_map.values():
                        if component in boundary_components:
                            boundary_components.remove(component)
                    boundary_map["Internal"].append(component)

        return boundary_map

    def _add_component_nodes(
        self,
        components: ThreatModelComponents,
        lines: list[str],
        simple_format: bool = False,
    ):
        """Add nodes for all components."""
        # External entities
        for entity in components.external_entities:
            node_id = self._get_node_id(entity)
            if simple_format:
                lines.append(f'    {node_id}["{entity}"]')
            else:
                lines.append(
                    f'    {node_id}[("{entity}")]'
                )  # Round rectangle for external entities

        # Processes
        for process in components.processes:
            node_id = self._get_node_id(process)
            if simple_format:
                lines.append(f'    {node_id}["{process}"]')
            else:
                lines.append(f'    {node_id}["{process}"]')  # Rectangle for processes

        # Data stores
        for store in components.data_stores:
            node_id = self._get_node_id(store)
            if simple_format:
                lines.append(f'    {node_id}["{store}"]')
            else:
                lines.append(
                    f'    {node_id}[("{store}")]'
                )  # Database symbol for data stores

    def _add_data_flow_edges(
        self,
        components: ThreatModelComponents,
        lines: list[str],
        simple_format: bool = False,
    ):
        """Add edges for data flows."""
        if not components.data_flows:
            return

        lines.append("")  # Empty line for readability

        for flow in components.data_flows:
            source_id = self._get_node_id(flow.source)
            target_id = self._get_node_id(flow.target)

            # Create edge label
            label = flow.protocol
            if flow.data_type:
                label += f" ({flow.data_type})"

            # Choose arrow style based on security
            if flow.protocol.upper() in ["HTTPS", "SSL", "TLS"]:
                arrow = "==>"  # Thick arrow for secure connections
            else:
                arrow = "-->"  # Regular arrow

            if simple_format:
                lines.append(f"    {source_id} {arrow} {target_id}")
            else:
                lines.append(f"    {source_id} {arrow}|{label}| {target_id}")

    def _add_threat_styling(self, threats: list, lines: list[str]):
        """Add CSS classes for components with threats."""
        if not threats:
            return

        lines.append("")  # Empty line for readability

        # Group threats by component and severity
        component_threats = {}
        for threat in threats:
            component = threat.component
            if component not in component_threats:
                component_threats[component] = []
            component_threats[component].append(threat)

        # Apply styling based on highest severity threat per component
        for component, comp_threats in component_threats.items():
            highest_severity = max(
                comp_threats, key=lambda t: self._severity_order(t.severity)
            )
            node_id = self._get_node_id(component)

            if highest_severity.severity == Severity.CRITICAL:
                lines.append(f"    class {node_id} critical")
            elif highest_severity.severity == Severity.HIGH:
                lines.append(f"    class {node_id} high")
            elif highest_severity.severity == Severity.MEDIUM:
                lines.append(f"    class {node_id} medium")
            else:
                lines.append(f"    class {node_id} low")

    def _add_css_classes(self, lines: list[str]):
        """Add CSS class definitions for styling."""
        lines.extend(
            [
                "",
                "    classDef critical fill:#ff6b6b,stroke:#d63031,stroke-width:3px,color:#fff",
                "    classDef high fill:#ffa726,stroke:#ef6c00,stroke-width:2px,color:#fff",
                "    classDef medium fill:#ffeb3b,stroke:#f57f17,stroke-width:2px,color:#000",
                "    classDef low fill:#81c784,stroke:#388e3c,stroke-width:1px,color:#fff",
            ]
        )

    def _get_node_id(self, component_name: str) -> str:
        """Get or create a node ID for a component."""
        if component_name not in self.node_ids:
            # Create a sanitized ID
            sanitized = self._sanitize_id(component_name)
            self.node_ids[component_name] = sanitized

        return self.node_ids[component_name]

    def _sanitize_id(self, name: str) -> str:
        """Sanitize a name to be a valid Mermaid node ID."""
        # Replace spaces and special characters with underscores
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)

        # Ensure it starts with a letter
        if sanitized and not sanitized[0].isalpha():
            sanitized = f"node_{sanitized}"

        # Handle empty or invalid names
        if not sanitized:
            self.node_counter += 1
            sanitized = f"node_{self.node_counter}"

        return sanitized

    def _sanitize_display_name(self, name: str) -> str:
        """Sanitize a display name for Mermaid participant labels."""
        # Remove any line breaks and normalize whitespace
        sanitized = re.sub(r"\s+", " ", name.strip())

        # Remove or escape characters that could break Mermaid syntax
        sanitized = sanitized.replace("\n", " ").replace("\r", " ")

        # Remove control characters (ASCII 0-31 except space, and 127)
        sanitized = re.sub(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]", "", sanitized)

        # Limit length to prevent overly long participant names
        if len(sanitized) > 50:
            sanitized = sanitized[:47] + "..."

        return sanitized

    def _severity_order(self, severity: Severity) -> int:
        """Get numeric order for severity."""
        order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order.get(severity, 0)

    def _is_one_way_flow(self, flow) -> bool:
        """Determine if a data flow is one-way (no response expected)."""
        # Heuristics for one-way flows
        one_way_protocols = ["UDP", "Log", "Event", "Notification"]
        one_way_targets = ["Log", "File", "Queue", "Topic"]

        if flow.protocol in one_way_protocols:
            return True

        if any(
            keyword in flow.target.lower()
            for keyword in ["log", "file", "queue", "topic"]
        ):
            return True

        return False

    @staticmethod
    def generate_from_components_dict(
        components_dict: dict,
        show_threats: bool = False,
        diagram_type: str = "flowchart",
    ) -> str:
        """Generate diagram directly from components dictionary.

        Args:
            components_dict: Dictionary with components data
            show_threats: Whether to show threat styling
            diagram_type: Type of diagram to generate

        Returns:
            Mermaid diagram string
        """
        # Create a minimal threat model from the dict
        from .models import DataFlow, ThreatModel, ThreatModelComponents

        components = ThreatModelComponents(
            boundaries=components_dict.get("boundaries", []),
            external_entities=components_dict.get("external_entities", []),
            processes=components_dict.get("processes", []),
            data_stores=components_dict.get("data_stores", []),
        )

        # Convert data flows
        for flow_dict in components_dict.get("data_flows", []):
            flow = DataFlow(
                source=flow_dict["source"],
                target=flow_dict["target"],
                protocol=flow_dict["protocol"],
                data_type=flow_dict.get("data_type"),
                authentication=flow_dict.get("authentication"),
                encryption=flow_dict.get("encryption"),
            )
            components.data_flows.append(flow)

        threat_model = ThreatModel(components=components)

        generator = MermaidDiagramGenerator()
        return generator.generate_diagram(
            threat_model, diagram_type=diagram_type, show_threats=show_threats
        )
