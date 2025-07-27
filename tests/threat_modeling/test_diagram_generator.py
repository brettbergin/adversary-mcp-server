"""Tests for DiagramGenerator (mermaid-py based)."""

import pytest

from adversary_mcp_server.threat_modeling.diagram_generator import DiagramGenerator
from adversary_mcp_server.threat_modeling.models import (
    DataFlow,
    Severity,
    Threat,
    ThreatModel,
    ThreatModelComponents,
    ThreatType,
)


@pytest.fixture
def sample_components():
    """Create sample threat model components for testing."""
    return ThreatModelComponents(
        external_entities=["Web User", "HTTP Client"],
        processes=["Django App", "Tornado App"],
        data_stores=["Database", "Redis"],
        boundaries=["Internet", "Application", "Data Layer"],
        data_flows=[
            DataFlow(
                source="Web User",
                target="Django App",
                protocol="HTTPS",
                data_type="user_requests",
            ),
            DataFlow(
                source="Django App",
                target="Database",
                protocol="SQL",
                data_type="queries",
            ),
        ],
    )


@pytest.fixture
def sample_threats():
    """Create sample threats for testing."""
    return [
        Threat(
            threat_type=ThreatType.TAMPERING,
            component="Database, Redis",
            title="SQL Injection",
            description="Database vulnerable to SQL injection",
            severity=Severity.CRITICAL,
            mitigation="Use parameterized queries",
        ),
        Threat(
            threat_type=ThreatType.SPOOFING,
            component="Django App",
            title="Weak Authentication",
            description="Authentication mechanism is weak",
            severity=Severity.HIGH,
            mitigation="Implement multi-factor authentication",
        ),
    ]


@pytest.fixture
def sample_threat_model(sample_components, sample_threats):
    """Create a complete threat model for testing."""
    return ThreatModel(
        components=sample_components,
        threats=sample_threats,
        metadata={
            "application_name": "Test App",
            "description": "Test application for threat modeling",
        },
    )


class TestDiagramGenerator:
    """Test cases for DiagramGenerator."""

    def test_init(self):
        """Test generator initialization."""
        generator = DiagramGenerator()
        assert generator.node_registry == {}
        assert generator.subgraph_nodes == {}

    def test_generate_diagram_basic(self, sample_threat_model):
        """Test basic diagram generation."""
        generator = DiagramGenerator()

        # Test successful generation
        diagram = generator.generate_diagram(sample_threat_model)

        # Should return a string
        assert isinstance(diagram, str)
        assert len(diagram) > 0

        # Should contain Mermaid flowchart syntax
        assert "flowchart TD" in diagram

    def test_generate_diagram_unsupported_type(self, sample_threat_model):
        """Test that unsupported diagram types raise ValueError."""
        generator = DiagramGenerator()

        with pytest.raises(ValueError, match="Unsupported diagram type"):
            generator.generate_diagram(sample_threat_model, diagram_type="gantt")

    def test_create_all_nodes(self, sample_components):
        """Test node creation from components."""
        generator = DiagramGenerator()
        nodes = generator._create_all_nodes(sample_components)

        # Should create nodes for all components
        total_components = (
            len(sample_components.external_entities)
            + len(sample_components.processes)
            + len(sample_components.data_stores)
        )
        assert len(nodes) == total_components

        # Check node registry is populated
        assert len(generator.node_registry) == total_components

        # Verify specific components are in registry
        assert "Web User" in generator.node_registry
        assert "Django App" in generator.node_registry
        assert "Database" in generator.node_registry

    def test_create_all_links(self, sample_components):
        """Test link creation from data flows."""
        generator = DiagramGenerator()

        # Need to create nodes first for links to work
        generator._create_all_nodes(sample_components)
        links = generator._create_all_links(sample_components)

        # Should create links for all data flows
        assert len(links) == len(sample_components.data_flows)

    def test_sanitize_id(self):
        """Test ID sanitization for Mermaid compatibility."""
        generator = DiagramGenerator()

        # Test normal names
        assert generator._sanitize_id("Django App") == "djangoapp"
        assert generator._sanitize_id("Web User") == "webuser"

        # Test special characters
        assert generator._sanitize_id("Test@API#Service") == "testapiservice"

        # Test names starting with numbers
        assert generator._sanitize_id("1st Service") == "node1stservice"

        # Test empty names
        assert generator._sanitize_id("") == "unnamednode"

    def test_severity_order(self):
        """Test severity ordering for threat prioritization."""
        generator = DiagramGenerator()

        assert generator._severity_order(Severity.LOW) == 1
        assert generator._severity_order(Severity.MEDIUM) == 2
        assert generator._severity_order(Severity.HIGH) == 3
        assert generator._severity_order(Severity.CRITICAL) == 4

    def test_map_components_to_boundaries(self, sample_components):
        """Test component-to-boundary mapping logic."""
        generator = DiagramGenerator()
        boundary_map = generator._map_components_to_boundaries(sample_components)

        # Should have mappings for all components
        assert len(boundary_map) > 0

        # Check that components are mapped to appropriate boundaries
        assert boundary_map.get("Django App") == "Application Layer"
        assert boundary_map.get("Database") == "Data Layer"
        assert boundary_map.get("Redis") == "Data Layer"
        assert boundary_map.get("Web User") == "Internet"

    def test_organize_nodes_by_boundaries(self, sample_components):
        """Test subgraph-based flowchart generation."""
        generator = DiagramGenerator()

        # Test the new subgraph flowchart generation
        diagram = generator._generate_subgraph_flowchart(
            sample_components, show_threats=True
        )

        # Should be a valid flowchart
        assert diagram.startswith("flowchart TD")

        # Should contain subgraph definitions
        assert "subgraph" in diagram
        assert "Application Layer" in diagram or "applicationlayer" in diagram
        assert "Data Layer" in diagram or "datalayer" in diagram
        assert "Internet" in diagram or "internet" in diagram

        # Should contain component definitions
        assert "djangoapp" in diagram
        assert "database" in diagram
        assert "webuser" in diagram

    def test_apply_threat_styling_with_individual_components(self, sample_threats):
        """Test threat styling with individual component parsing."""
        generator = DiagramGenerator()

        # Create mock nodes
        from mermaid.flowchart import Node

        mock_nodes = [
            Node(id_="database", content="Database", shape="cylindrical"),
            Node(id_="redis", content="Redis", shape="cylindrical"),
            Node(id_="djangoapp", content="Django App", shape="normal"),
        ]

        # Add to registry
        generator.node_registry = {
            "Database": mock_nodes[0],
            "Redis": mock_nodes[1],
            "Django App": mock_nodes[2],
        }

        # This should not raise an error now
        try:
            generator._apply_threat_styling(sample_threats, mock_nodes)
            # If we get here without error, the styling logic works
            styling_applied = True
        except Exception as e:
            # If there's still an error, we'll see it in the test output
            styling_applied = False
            pytest.fail(f"Styling failed with error: {e}")

        assert styling_applied

    def test_full_workflow_with_threats(self, sample_threat_model):
        """Test complete diagram generation workflow with threat styling."""
        generator = DiagramGenerator()

        # This is the main test - should complete without errors
        try:
            diagram = generator.generate_diagram(sample_threat_model, show_threats=True)

            # Basic validation
            assert isinstance(diagram, str)
            assert len(diagram) > 0
            assert "flowchart TD" in diagram

            workflow_success = True
        except Exception as e:
            workflow_success = False
            pytest.fail(f"Full workflow failed with error: {e}")

        assert workflow_success

    def test_diagram_contains_expected_elements(self, sample_threat_model):
        """Test that generated diagram contains expected elements."""
        generator = DiagramGenerator()
        diagram = generator.generate_diagram(sample_threat_model)

        # Should contain flowchart definition
        assert "flowchart TD" in diagram

        # Should contain node definitions (component names in sanitized form)
        assert "webuser" in diagram
        assert "djangoapp" in diagram
        assert "database" in diagram

        # Should contain styling classes
        assert "critical" in diagram
        assert "high" in diagram

        # Should contain links
        assert "-->" in diagram

    def test_generate_mermaid_script_syntax(self, sample_threat_model):
        """Test that _generate_mermaid_script produces valid Mermaid syntax."""
        generator = DiagramGenerator()
        diagram = generator.generate_diagram(sample_threat_model, show_threats=True)
        lines = diagram.split("\n")

        # Should start with flowchart declaration (no YAML frontmatter)
        assert lines[0] == "flowchart TD"
        assert not lines[0].startswith("---")

        # Should not contain YAML frontmatter anywhere
        assert "---" not in diagram
        assert "title:" not in diagram

        # CSS classes should use proper syntax
        assert any("classDef critical fill:#ff6b6b" in line for line in lines)
        assert any("classDef high fill:#ffa726" in line for line in lines)

        # Should contain subgraph definitions in new format
        assert any("subgraph" in line for line in lines)

        # Links should have single pipes, not double pipes
        link_lines = [line for line in lines if "-->|" in line]
        assert len(link_lines) > 0
        for line in link_lines:
            # Should not have double pipes
            assert "||" not in line
            # Should have proper single pipe syntax
            assert "-->|" in line and "|" in line.split("-->|")[1]

    def test_link_message_parentheses_removal(self):
        """Test that parentheses are removed from link messages."""
        from adversary_mcp_server.threat_modeling.models import (
            DataFlow,
            ThreatModel,
            ThreatModelComponents,
        )

        components = ThreatModelComponents(
            external_entities=["User"],
            processes=["App"],
            data_stores=["DB"],
            boundaries=["Web"],
            data_flows=[
                DataFlow(
                    source="App",
                    target="DB",
                    protocol="SQL",
                    data_type="result_sets",  # This becomes "SQL (result_sets)"
                )
            ],
        )
        threat_model = ThreatModel(components=components)
        generator = DiagramGenerator()

        diagram = generator.generate_diagram(threat_model)

        # Should not contain parentheses in link messages
        assert "(" not in diagram
        assert ")" not in diagram

        # Should contain the cleaned message
        assert "SQL result_sets" in diagram

    def test_mermaid_script_without_threats(self, sample_threat_model):
        """Test diagram generation without threat styling."""
        generator = DiagramGenerator()

        diagram = generator.generate_diagram(sample_threat_model, show_threats=False)

        # Should start with flowchart
        assert diagram.startswith("flowchart TD")

        # Should not contain CSS class definitions when threats are disabled
        assert "classDef critical" not in diagram
        assert "classDef high" not in diagram

        # Should still contain nodes and links
        assert "djangoapp" in diagram
        assert "-->" in diagram

    def test_layout_direction_options(self, sample_threat_model):
        """Test different layout directions are properly applied."""
        generator = DiagramGenerator()

        for direction in ["TD", "LR", "BT", "RL"]:
            diagram = generator.generate_diagram(
                sample_threat_model, layout_direction=direction
            )
            assert diagram.startswith(f"flowchart {direction}")

    def test_complex_node_names_sanitization(self):
        """Test that complex node names are properly sanitized for IDs."""
        from adversary_mcp_server.threat_modeling.models import (
            ThreatModel,
            ThreatModelComponents,
        )

        components = ThreatModelComponents(
            external_entities=["External API (v2.0)", "User@domain.com"],
            processes=["Web-App Server", "Cache & Queue"],
            data_stores=["MySQL 8.0", "Redis Cluster"],
            boundaries=["DMZ"],
            data_flows=[],
        )
        threat_model = ThreatModel(components=components)
        generator = DiagramGenerator()

        diagram = generator.generate_diagram(threat_model)

        # Should contain sanitized node IDs (no special characters)
        lines = diagram.split("\n")
        # Only get actual node lines (indented lines within subgraphs), not subgraph definitions
        node_lines = [
            line
            for line in lines
            if '["' in line and not line.strip().startswith("subgraph")
        ]

        for line in node_lines:
            # Extract node ID (part before the bracket)
            node_id = line.split('["')[0].strip()
            # Should only contain valid characters (alphanumeric only, no underscores in current implementation)
            assert all(c.isalnum() for c in node_id)
            # Should start with a letter or be prefixed with 'node'
            assert node_id[0].isalpha() or node_id.startswith("node")

    def test_css_class_application_syntax(self, sample_threat_model):
        """Test that CSS classes are applied with correct syntax."""
        generator = DiagramGenerator()
        diagram = generator.generate_diagram(sample_threat_model, show_threats=True)
        lines = diagram.split("\n")

        # Find lines with CSS class applications
        styled_lines = [line for line in lines if ":::" in line]
        assert len(styled_lines) > 0

        for line in styled_lines:
            # Should have proper syntax: node_id["Content"]:::class
            assert '["' in line
            assert '"]:::' in line
            # Class name should be valid (critical, high, medium, low)
            class_name = line.split(":::")[1].strip()
            assert class_name in ["critical", "high", "medium", "low"]
