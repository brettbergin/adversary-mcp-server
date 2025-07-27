"""Tests for architecture diagram generation functionality."""

import pytest

from adversary_mcp_server.threat_modeling.diagram_generator import DiagramGenerator
from adversary_mcp_server.threat_modeling.models import (
    DataFlow,
    ThreatModel,
    ThreatModelComponents,
)


class TestArchitectureDiagramGeneration:
    """Test architecture diagram generation."""

    def test_generate_architecture_diagram(self):
        """Test basic architecture diagram generation."""
        # Create test components
        components = ThreatModelComponents(
            boundaries=["Application", "Data Layer"],
            external_entities=["User"],
            processes=["Web App"],
            data_stores=["Database"],
            data_flows=[
                DataFlow(source="User", target="Web App", protocol="HTTPS"),
                DataFlow(source="Web App", target="Database", protocol="SQL"),
            ],
        )

        threat_model = ThreatModel(components=components)
        generator = DiagramGenerator()

        # Generate architecture diagram
        diagram = generator.generate_diagram(
            threat_model, diagram_type="architecture", show_threats=False
        )

        # Verify architecture syntax
        assert diagram.startswith("architecture-beta")
        assert "group group1(cloud)[Application]" in diagram
        assert "group group2(database)[Data Layer]" in diagram
        assert "service user(internet)[User]" in diagram
        assert "service webapp(server)[Web App]" in diagram
        assert "service database(database)[Database]" in diagram
        assert "user:R --> L:webapp" in diagram
        assert "webapp:R --> L:database" in diagram

    def test_architecture_icon_selection(self):
        """Test icon selection for different component types."""
        generator = DiagramGenerator()

        # Test external entity icons
        assert generator._get_architecture_icon("User", "external_entity") == "internet"
        assert (
            generator._get_architecture_icon("API Client", "external_entity") == "cloud"
        )

        # Test process icons
        assert generator._get_architecture_icon("Web App", "process") == "server"
        assert generator._get_architecture_icon("API Gateway", "process") == "server"

        # Test data store icons
        assert generator._get_architecture_icon("Database", "data_store") == "database"
        assert generator._get_architecture_icon("Redis Cache", "data_store") == "disk"
        assert generator._get_architecture_icon("File Storage", "data_store") == "disk"

    def test_generate_architecture_with_complex_components(self):
        """Test architecture generation with more complex components."""
        components = ThreatModelComponents(
            boundaries=["Internet", "DMZ", "Application", "Data Layer"],
            external_entities=["Web User", "API Client"],
            processes=["Load Balancer", "Web Application", "Auth Service"],
            data_stores=["User Database", "Session Cache", "Log Files"],
            data_flows=[
                DataFlow(source="Web User", target="Load Balancer", protocol="HTTPS"),
                DataFlow(
                    source="Load Balancer", target="Web Application", protocol="HTTP"
                ),
                DataFlow(
                    source="Web Application", target="Auth Service", protocol="gRPC"
                ),
                DataFlow(source="Auth Service", target="User Database", protocol="SQL"),
                DataFlow(
                    source="Web Application", target="Session Cache", protocol="Redis"
                ),
            ],
        )

        threat_model = ThreatModel(components=components)
        generator = DiagramGenerator()

        diagram = generator.generate_diagram(
            threat_model, diagram_type="architecture", show_threats=False
        )

        # Verify all components are included
        assert "architecture-beta" in diagram
        assert "service webuser(internet)[Web User]" in diagram
        assert "service apiclient(cloud)[API Client]" in diagram
        assert "service loadbalancer(server)[Load Balancer]" in diagram
        assert "service webapplication(server)[Web Application]" in diagram
        assert "service authservice(server)[Auth Service]" in diagram
        assert "service userdatabase(database)[User Database]" in diagram
        assert "service sessioncache(disk)[Session Cache]" in diagram
        assert "service logfiles(disk)[Log Files]" in diagram

        # Verify connections (simplified syntax without labels)
        assert "webuser:R --> L:loadbalancer" in diagram
        assert "loadbalancer:R --> L:webapplication" in diagram
        assert "webapplication:R --> L:authservice" in diagram

    def test_unsupported_diagram_type_error(self):
        """Test error for unsupported diagram types."""
        components = ThreatModelComponents()
        threat_model = ThreatModel(components=components)
        generator = DiagramGenerator()

        with pytest.raises(ValueError, match="Unsupported diagram type: invalid"):
            generator.generate_diagram(threat_model, diagram_type="invalid")

    def test_architecture_supports_both_types(self):
        """Test that both flowchart and architecture are supported."""
        components = ThreatModelComponents(
            external_entities=["User"],
            processes=["App"],
            data_stores=["DB"],
            data_flows=[DataFlow(source="User", target="App", protocol="HTTP")],
        )
        threat_model = ThreatModel(components=components)
        generator = DiagramGenerator()

        # Test flowchart generation
        flowchart = generator.generate_diagram(
            threat_model, diagram_type="flowchart", show_threats=False
        )
        assert flowchart.startswith("flowchart")

        # Test architecture generation
        architecture = generator.generate_diagram(
            threat_model, diagram_type="architecture", show_threats=False
        )
        assert architecture.startswith("architecture-beta")

        # They should be different
        assert flowchart != architecture

    def test_architecture_empty_components(self):
        """Test architecture generation with empty components."""
        components = ThreatModelComponents()
        threat_model = ThreatModel(components=components)
        generator = DiagramGenerator()

        diagram = generator.generate_diagram(
            threat_model, diagram_type="architecture", show_threats=False
        )

        # Should still generate valid architecture syntax
        assert diagram.startswith("architecture-beta")
        # Should contain no services or groups (just the header)
        lines = [line.strip() for line in diagram.split("\n") if line.strip()]
        assert len(lines) == 1  # Just the architecture-beta line
