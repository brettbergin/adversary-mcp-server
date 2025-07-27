"""Mermaid diagram generator using mermaid-py library for reliable diagram generation."""

from mermaid.flowchart import Link, Node
from mermaid.style import Style

from ..logger import get_logger
from .models import Severity, ThreatModel, ThreatModelComponents

logger = get_logger("mermaid_py_generator")


class DiagramGenerator:
    """Generator for Mermaid.js diagrams using the mermaid-py library."""

    def __init__(self):
        """Initialize the mermaid-py diagram generator."""
        self.node_registry: dict[str, Node] = {}  # Maps component names to Node objects
        self.subgraph_nodes: dict[str, list[Node]] = {}  # Maps boundaries to nodes

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
            diagram_type: Type of diagram ('flowchart' only supported currently)
            show_threats: Whether to highlight threats in the diagram
            layout_direction: Layout direction ('TD', 'LR', 'BT', 'RL')

        Returns:
            Mermaid diagram as string

        Raises:
            ValueError: If diagram_type is not supported
        """
        if diagram_type not in ["flowchart", "architecture"]:
            raise ValueError(
                f"Unsupported diagram type: {diagram_type}. Supported types: 'flowchart', 'architecture'."
            )

        logger.info(f"Generating {diagram_type} diagram with mermaid-py")

        # Reset state
        self.node_registry = {}
        self.subgraph_nodes = {}

        # Create all nodes first
        all_nodes = self._create_all_nodes(threat_model.components)

        # Create subgraphs for trust boundaries
        self._organize_nodes_by_boundaries(threat_model.components)

        # Create links for data flows
        all_links = self._create_all_links(threat_model.components)

        # Apply threat styling if requested
        if show_threats:
            self._apply_threat_styling(threat_model.threats, all_nodes)

        # Generate custom Mermaid syntax based on diagram type
        if diagram_type == "architecture":
            return self._generate_architecture_script(
                threat_model.components, show_threats
            )
        else:  # flowchart - use new subgraph-based approach
            return self._generate_subgraph_flowchart(
                threat_model.components,
                show_threats,
                layout_direction,
                threat_model.threats if show_threats else None,
            )

    def _create_all_nodes(self, components: ThreatModelComponents) -> list[Node]:
        """Create all nodes for the diagram."""
        all_nodes = []

        # Create external entity nodes (circles)
        for entity in components.external_entities:
            node_id = self._sanitize_id(entity)
            node = Node(
                id_=node_id,
                content=entity,
                shape="circle",  # External entities are circles
            )
            self.node_registry[entity] = node
            all_nodes.append(node)

        # Create process nodes (rectangles)
        for process in components.processes:
            node_id = self._sanitize_id(process)
            node = Node(
                id_=node_id, content=process, shape="normal"  # Processes are rectangles
            )
            self.node_registry[process] = node
            all_nodes.append(node)

        # Create data store nodes (cylinders)
        for store in components.data_stores:
            node_id = self._sanitize_id(store)
            node = Node(
                id_=node_id,
                content=store,
                shape="cylindrical",  # Data stores are cylinders
            )
            self.node_registry[store] = node
            all_nodes.append(node)

        logger.info(
            f"Created {len(all_nodes)} nodes: {len(components.external_entities)} external entities, "
            f"{len(components.processes)} processes, {len(components.data_stores)} data stores"
        )

        return all_nodes

    def _organize_nodes_by_boundaries(self, components: ThreatModelComponents):
        """Organize nodes into trust boundaries using subgraphs."""
        # Map components to boundaries based on naming heuristics
        boundary_map = self._map_components_to_boundaries(components)

        for boundary, boundary_components in boundary_map.items():
            if boundary_components:
                # Get the Node objects for components in this boundary
                boundary_nodes = []
                for component_name in boundary_components:
                    if component_name in self.node_registry:
                        boundary_nodes.append(self.node_registry[component_name])

                if boundary_nodes:
                    self.subgraph_nodes[boundary] = boundary_nodes
                    logger.debug(
                        f"Boundary '{boundary}' contains {len(boundary_nodes)} nodes"
                    )

    def _create_all_links(self, components: ThreatModelComponents) -> list[Link]:
        """Create all links for data flows."""
        all_links = []

        for flow in components.data_flows:
            source_node = self.node_registry.get(flow.source)
            target_node = self.node_registry.get(flow.target)

            if source_node and target_node:
                # Create message for the link
                message = flow.protocol
                if flow.data_type:
                    message += f" ({flow.data_type})"

                # Choose link style based on security (HTTPS = thick arrow)
                if flow.protocol.upper() in ["HTTPS", "SSL", "TLS"]:
                    # TODO: Check if mermaid-py supports thick arrows
                    link = Link(source_node, target_node, message=message)
                else:
                    link = Link(source_node, target_node, message=message)

                all_links.append(link)
            else:
                # Log missing nodes
                if not source_node:
                    logger.warning(
                        f"Source node not found for flow: {flow.source} -> {flow.target}"
                    )
                if not target_node:
                    logger.warning(
                        f"Target node not found for flow: {flow.source} -> {flow.target}"
                    )

        logger.info(
            f"Created {len(all_links)} links from {len(components.data_flows)} data flows"
        )
        return all_links

    def _apply_threat_styling(self, threats: list, all_nodes: list[Node]):
        """Apply CSS styling to nodes based on threats."""
        if not threats:
            return

        # Group threats by individual component and severity
        individual_component_threats = {}
        for threat in threats:
            # Parse comma-separated component names
            component_names = [name.strip() for name in threat.component.split(",")]

            for component_name in component_names:
                if component_name not in individual_component_threats:
                    individual_component_threats[component_name] = []
                individual_component_threats[component_name].append(threat)

        # Apply styling based on highest severity threat per component
        for component_name, comp_threats in individual_component_threats.items():
            if component_name in self.node_registry:
                node = self.node_registry[component_name]

                # Find highest severity threat
                highest_severity = max(
                    comp_threats, key=lambda t: self._severity_order(t.severity)
                )

                # Create style based on severity
                severity_colors = {
                    Severity.CRITICAL: {
                        "fill": "#ff6b6b",
                        "stroke": "#d63031",
                        "stroke-width": "3px",
                        "color": "#fff",
                    },
                    Severity.HIGH: {
                        "fill": "#ffa726",
                        "stroke": "#ef6c00",
                        "stroke-width": "2px",
                        "color": "#fff",
                    },
                    Severity.MEDIUM: {
                        "fill": "#ffeb3b",
                        "stroke": "#f57f17",
                        "stroke-width": "2px",
                        "color": "#000",
                    },
                    Severity.LOW: {
                        "fill": "#81c784",
                        "stroke": "#388e3c",
                        "stroke-width": "1px",
                        "color": "#fff",
                    },
                }

                if highest_severity.severity in severity_colors:
                    color_config = severity_colors[highest_severity.severity]

                    # Create style with required name parameter and severity-based class name
                    style_name = f"{highest_severity.severity.value}"
                    style = Style(
                        name=style_name,
                        fill=color_config["fill"],
                        stroke=color_config["stroke"],
                        stroke_width=color_config.get("stroke-width"),
                        color=color_config.get("color"),
                    )

                    # Add style to node
                    if not hasattr(node, "styles") or node.styles is None:
                        node.styles = []
                    node.styles.append(style)

        logger.info(
            f"Applied threat styling to {len(individual_component_threats)} components"
        )

    def _severity_order(self, severity: Severity) -> int:
        """Get numeric order for severity."""
        order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order.get(severity, 0)

    def _generate_mermaid_script(
        self,
        nodes: list[Node],
        links: list[Link],
        layout_direction: str,
        show_threats: bool,
    ) -> str:
        """Generate proper Mermaid script with correct syntax."""
        # For now, keep the old implementation but we'll replace this with subgraph-based approach
        lines = [f"flowchart {layout_direction}"]

        # Add CSS class definitions if threats are shown
        if show_threats:
            lines.extend(
                [
                    "\tclassDef critical fill:#ff6b6b,color:#fff,stroke-width:3px,stroke:#d63031",
                    "\tclassDef high fill:#ffa726,color:#fff,stroke-width:2px,stroke:#ef6c00",
                    "\tclassDef medium fill:#ffeb3b,color:#000,stroke-width:2px,stroke:#f57f17",
                    "\tclassDef low fill:#81c784,color:#fff,stroke-width:1px,stroke:#388e3c",
                ]
            )

        # Add nodes with inline styling
        for node in nodes:
            node_def = f"\t{node.id_}"

            # Add shape
            if node.shape == "circle":
                node_def += f'(("{node.content}"))'
            elif node.shape == "cylindrical":
                node_def += f'[("{node.content}")]'
            else:  # normal/rectangle
                node_def += f'["{node.content}"]'

            # Add CSS class inline if node has styles
            if hasattr(node, "styles") and node.styles:
                # Get the first style's name (severity level)
                style_name = node.styles[0].name
                node_def += f":::{style_name}"

            lines.append(node_def)

        # Add links
        for link in links:
            source_id = link.origin.id_
            target_id = link.end.id_
            message = link.message or ""

            # Strip pipes that mermaid-py automatically adds
            if message.startswith("|") and message.endswith("|"):
                message = message[1:-1]

            # Remove parentheses from message as they cause syntax errors
            if message:
                message = message.replace("(", "").replace(")", "")
                link_def = f"\t{source_id} -->|{message}| {target_id}"
            else:
                link_def = f"\t{source_id} --> {target_id}"

            lines.append(link_def)

        return "\n".join(lines)

    def _generate_subgraph_flowchart(
        self,
        components: ThreatModelComponents,
        show_threats: bool = True,
        layout_direction: str = "TD",
        threats: list = None,
    ) -> str:
        """Generate Mermaid flowchart with subgraph-based organization.

        Args:
            components: ThreatModelComponents containing the architecture
            show_threats: Whether to include threat highlighting

        Returns:
            Mermaid flowchart diagram as string with subgraphs
        """
        lines = [f"flowchart {layout_direction}"]

        # Add CSS class definitions if threats are shown
        if show_threats:
            lines.extend(
                [
                    "    classDef critical fill:#ff6b6b,color:#fff,stroke-width:3px,stroke:#d63031",
                    "    classDef high fill:#ffa726,color:#fff,stroke-width:2px,stroke:#ef6c00",
                    "    classDef medium fill:#ffeb3b,color:#000,stroke-width:2px,stroke:#f57f17",
                    "    classDef low fill:#81c784,color:#fff,stroke-width:1px,stroke:#388e3c",
                ]
            )

        # Map boundaries to emoji icons
        boundary_icons = {
            "Internet": "🌐",
            "DMZ": "🛡️",
            "Application": "☁️",
            "Application Layer": "☁️",
            "Data Layer": "🗄️",
            "Database": "🗄️",
            "External": "🌍",
            "Network": "🔗",
            "Security": "🔒",
        }

        # Create threat severity mapping for styling
        component_threat_severity = {}
        if threats and show_threats:
            for threat in threats:
                # Parse component from threat (handle comma-separated components)
                components_str = threat.component
                if components_str:
                    threat_components = [
                        comp.strip() for comp in components_str.split(",")
                    ]
                    for comp in threat_components:
                        # Get highest severity for each component
                        current_severity = component_threat_severity.get(comp)
                        if current_severity is None or self._severity_order(
                            threat.severity
                        ) > self._severity_order(current_severity):
                            component_threat_severity[comp] = threat.severity

        # Create subgraphs for each boundary
        component_to_boundary = self._map_components_to_boundaries(components)

        # Get all unique boundaries (both from components.boundaries and our mapping)
        all_boundaries = set(components.boundaries)
        for boundary in component_to_boundary.values():
            if boundary is not None:
                all_boundaries.add(boundary)

        for boundary in sorted(all_boundaries):
            # Add components that belong to this boundary
            boundary_components = [
                comp
                for comp, bound in component_to_boundary.items()
                if bound == boundary
            ]

            # Only create subgraph if it has components
            if boundary_components:
                emoji = boundary_icons.get(boundary, "📦")
                subgraph_id = self._sanitize_id(boundary)
                lines.append(f'    subgraph {subgraph_id}["{emoji} {boundary}"]')

                for component in boundary_components:
                    component_id = self._sanitize_id(component)
                    component_name = self._sanitize_service_name(component)

                    # Add threat styling if component has threats
                    if component in component_threat_severity and show_threats:
                        severity = component_threat_severity[component]
                        severity_class = severity.value.lower()
                        lines.append(
                            f'        {component_id}["{component_name}"]:::{severity_class}'
                        )
                    else:
                        lines.append(f'        {component_id}["{component_name}"]')

                lines.append("    end")
                lines.append("")  # Empty line for readability

        # Add components not in any boundary (orphaned components)
        orphaned_components = [
            comp for comp, bound in component_to_boundary.items() if bound is None
        ]
        for component in orphaned_components:
            component_id = self._sanitize_id(component)
            component_name = self._sanitize_service_name(component)

            # Add threat styling if component has threats
            if component in component_threat_severity and show_threats:
                severity = component_threat_severity[component]
                severity_class = severity.value.lower()
                lines.append(
                    f'    {component_id}["{component_name}"]:::{severity_class}'
                )
            else:
                lines.append(f'    {component_id}["{component_name}"]')

        if orphaned_components:
            lines.append("")  # Empty line for readability

        # Add connections (data flows) with comments for organization
        lines.append("    %% Component connections")

        # Use a set to prevent duplicate edges
        edges_added = set()
        for flow in components.data_flows:
            source_id = self._sanitize_id(flow.source)
            target_id = self._sanitize_id(flow.target)

            # Create edge key to prevent duplicates
            edge_key = f"{source_id}->{target_id}"
            if edge_key not in edges_added:
                # Include protocol and data type in the edge if available
                label_parts = []
                if hasattr(flow, "protocol") and flow.protocol:
                    label_parts.append(flow.protocol)
                if hasattr(flow, "data_type") and flow.data_type:
                    label_parts.append(flow.data_type)

                if label_parts:
                    # Combine protocol and data type, clean for Mermaid compatibility
                    label = " ".join(label_parts).replace("(", "").replace(")", "")
                    lines.append(f"    {source_id} -->|{label}| {target_id}")
                else:
                    lines.append(f"    {source_id} --> {target_id}")
                edges_added.add(edge_key)

        return "\n".join(lines)

    def _map_components_to_boundaries(
        self, components: ThreatModelComponents
    ) -> dict[str, str | None]:
        """Map components to their appropriate boundaries based on component type and name.

        Returns:
            Dictionary mapping component name to boundary name (or None if no boundary)
        """
        mapping: dict[str, str | None] = {}

        # Map external entities to Internet boundary
        for entity in components.external_entities:
            if any(
                keyword in entity.lower() for keyword in ["user", "client", "browser"]
            ):
                mapping[entity] = "Internet"
            elif (
                any(
                    keyword in entity.lower()
                    for keyword in ["api", "service", "endpoint"]
                )
                and "external" not in entity.lower()
            ):
                mapping[entity] = "DMZ"
            else:
                mapping[entity] = "Internet"  # Default for external entities

        # Map processes to appropriate boundaries
        for process in components.processes:
            if (
                any(
                    keyword in process.lower()
                    for keyword in ["api", "gateway", "proxy", "lb", "balancer"]
                )
                and "app" not in process.lower()
            ):
                mapping[process] = "DMZ"
            else:
                mapping[process] = "Application Layer"

        # Map data stores to Data Layer
        for store in components.data_stores:
            mapping[store] = "Data Layer"

        # Debug: print the mapping to see what's happening
        logger.debug(f"Component to boundary mapping: {mapping}")

        return mapping

    def _sanitize_id(self, name: str) -> str:
        """Sanitize a name to be a valid Mermaid node ID."""
        import re

        # For architecture diagrams, be much more conservative with IDs
        # Replace everything that's not alphanumeric with nothing
        sanitized = re.sub(r"[^a-zA-Z0-9]", "", name)

        # Ensure it starts with a letter and isn't too long
        if sanitized and not sanitized[0].isalpha():
            sanitized = f"node{sanitized}"

        # Limit length to avoid overly long IDs
        if len(sanitized) > 20:
            sanitized = sanitized[:20]

        # Handle empty names
        if not sanitized:
            sanitized = "unnamednode"

        return sanitized.lower()  # mermaid-py seems to prefer lowercase IDs

    def _sanitize_service_name(self, name: str) -> str:
        """Sanitize service name for Mermaid architecture diagrams.

        Architecture diagrams are more strict about service names than flowcharts.

        Args:
            name: Original service name

        Returns:
            Cleaned service name safe for Mermaid architecture syntax
        """
        # Remove problematic characters that cause Mermaid parsing issues
        import re

        # Replace common problematic patterns
        cleaned = name.replace("Node.js", "NodeJS")  # Remove periods
        cleaned = re.sub(r"[(){}[\]<>]", "", cleaned)  # Remove brackets and parentheses
        cleaned = re.sub(r"[.,:;]", "", cleaned)  # Remove punctuation
        cleaned = re.sub(r"[^a-zA-Z0-9\s_-]", "", cleaned)  # Keep only safe characters
        cleaned = re.sub(r"\s+", " ", cleaned).strip()  # Normalize whitespace

        # Limit length to avoid overly long names
        if len(cleaned) > 25:
            # Try to intelligently truncate
            words = cleaned.split()
            if len(words) > 1:
                # Take first word and last word if multiple words
                cleaned = f"{words[0]} {words[-1]}"
            if len(cleaned) > 25:
                cleaned = cleaned[:22] + "..."

        return cleaned if cleaned else "Service"

    def _generate_architecture_script(
        self, components: ThreatModelComponents, show_threats: bool = True
    ) -> str:
        """Generate Mermaid architecture diagram script.

        Args:
            components: ThreatModelComponents containing the architecture
            show_threats: Whether to include threat highlighting

        Returns:
            Mermaid architecture diagram as string
        """
        lines = ["architecture-beta"]

        # Add groups (trust boundaries)
        group_id_map = {}
        for i, boundary in enumerate(components.boundaries):
            group_id = f"group{i+1}"
            group_id_map[boundary] = group_id
            # Use appropriate icons for groups
            group_icon = self._get_group_icon(boundary)
            lines.append(f"    group {group_id}({group_icon})[{boundary}]")

        # Component to group mapping
        component_groups = self._map_components_to_architecture_groups(
            components, group_id_map
        )

        # Map components to architecture services with icons and group assignments
        service_lines = []

        # Add services without group assignments first, then group them
        all_components = (
            [(entity, "external_entity") for entity in components.external_entities]
            + [(process, "process") for process in components.processes]
            + [(store, "data_store") for store in components.data_stores]
        )

        for component_name, component_type in all_components:
            service_id = self._sanitize_id(component_name)
            clean_name = self._sanitize_service_name(component_name)
            icon = self._get_architecture_icon(component_name, component_type)
            group_assignment = component_groups.get(component_name, "")

            if group_assignment:
                # Services in groups should be properly indented
                service_lines.append(
                    f"    service {service_id}({icon})[{clean_name}] in {group_assignment}"
                )
            else:
                # Services without groups
                service_lines.append(f"service {service_id}({icon})[{clean_name}]")

        lines.extend(service_lines)

        # Add edges (data flows) - architecture diagram format
        # Use a set to prevent duplicate edges
        edges_added = set()
        for flow in components.data_flows:
            source_id = self._sanitize_id(flow.source)
            target_id = self._sanitize_id(flow.target)

            # Create edge key to prevent duplicates
            edge_key = f"{source_id}->{target_id}"
            if edge_key not in edges_added:
                # Simple edge format that matches documentation examples
                lines.append(f"{source_id}:R --> L:{target_id}")
                edges_added.add(edge_key)

        return "\n".join(lines)

    def _get_group_icon(self, boundary_name: str) -> str:
        """Get appropriate icon for a group/boundary.

        Args:
            boundary_name: Name of the boundary

        Returns:
            Icon name for the group
        """
        boundary_lower = boundary_name.lower()

        if "internet" in boundary_lower or "external" in boundary_lower:
            return "internet"
        elif "dmz" in boundary_lower or "public" in boundary_lower:
            return "cloud"
        elif "data" in boundary_lower or "database" in boundary_lower:
            return "database"
        else:
            return "cloud"  # Default group icon

    def _map_components_to_architecture_groups(
        self, components: ThreatModelComponents, group_id_map: dict[str, str]
    ) -> dict[str, str]:
        """Map components to architecture groups.

        Args:
            components: ThreatModelComponents
            group_id_map: Mapping of boundary names to group IDs

        Returns:
            Dictionary mapping component names to group IDs
        """
        component_groups = {}

        # Use the existing boundary mapping logic but for architecture groups
        component_to_boundary = self._map_components_to_boundaries(components)

        for component, boundary in component_to_boundary.items():
            if boundary and boundary in group_id_map:
                group_id = group_id_map[boundary]
                component_groups[component] = group_id

        return component_groups

    def _get_architecture_icon(self, component_name: str, component_type: str) -> str:
        """Get appropriate architecture diagram icon for a component.

        Args:
            component_name: Name of the component
            component_type: Type of component (external_entity, process, data_store)

        Returns:
            Icon name for the architecture diagram
        """
        component_lower = component_name.lower()

        # Icon selection based on component type and name patterns
        if component_type == "external_entity":
            # Check for API/service patterns first (higher priority)
            if any(
                keyword in component_lower for keyword in ["api", "service", "external"]
            ):
                return "cloud"
            elif any(
                keyword in component_lower for keyword in ["user", "admin", "client"]
            ):
                return "internet"
            else:
                return "internet"

        elif component_type == "process":
            if any(
                keyword in component_lower for keyword in ["api", "gateway", "proxy"]
            ):
                return "server"
            elif any(
                keyword in component_lower for keyword in ["web", "app", "application"]
            ):
                return "server"
            elif any(
                keyword in component_lower for keyword in ["auth", "login", "security"]
            ):
                return "server"
            else:
                return "server"

        elif component_type == "data_store":
            if any(
                keyword in component_lower for keyword in ["cache", "redis", "memory"]
            ):
                return "disk"
            elif any(
                keyword in component_lower
                for keyword in ["db", "database", "sql", "mongo"]
            ):
                return "database"
            elif any(
                keyword in component_lower for keyword in ["file", "storage", "blob"]
            ):
                return "disk"
            else:
                return "database"

        # Default fallback
        return "server"
