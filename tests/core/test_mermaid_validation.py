"""Tests for Mermaid syntax validation functionality."""

from adversary_mcp_server.cli import _validate_mermaid_syntax


class TestMermaidValidation:
    """Test Mermaid syntax validation."""

    def test_validate_valid_flowchart(self):
        """Test validation of valid flowchart syntax."""
        valid_diagram = """flowchart TD
\tclassDef critical fill:#ff6b6b,color:#fff,stroke-width:3px,stroke:#d63031
\tclassDef high fill:#ffa726,color:#fff,stroke-width:2px,stroke:#ef6c00
\tweb_user["Web User"]
\tdjango_app["Django App"]:::high
\tdatabase["Database"]:::critical
\tweb_user -->|HTTPS requests| django_app
\tdjango_app -->|SQL queries| database"""

        result = _validate_mermaid_syntax(valid_diagram)

        assert result["valid"] is True
        assert result["error"] is None

    def test_validate_different_flowchart_directions(self):
        """Test validation with different flowchart directions."""
        for direction in ["TD", "LR", "BT", "RL"]:
            diagram = f"""flowchart {direction}
\tnode1["Node 1"]
\tnode2["Node 2"]
\tnode1 --> node2"""

            result = _validate_mermaid_syntax(diagram)
            assert result["valid"] is True, f"Failed for direction {direction}"

    def test_validate_node_shapes(self):
        """Test validation of different node shapes."""
        diagram = """flowchart TD
\tcircle_node(("Circle Node"))
\trect_node["Rectangle Node"]
\tcylinder_node[("Cylinder Node")]
\tcircle_node --> rect_node
\trect_node --> cylinder_node"""

        result = _validate_mermaid_syntax(diagram)
        assert result["valid"] is True

    def test_validate_css_classes(self):
        """Test validation with CSS class applications."""
        diagram = """flowchart TD
\tclassDef critical fill:#ff0000
\tclassDef high fill:#ff8800
\tnode1["Node 1"]:::critical
\tnode2["Node 2"]:::high
\tnode1 --> node2"""

        result = _validate_mermaid_syntax(diagram)
        assert result["valid"] is True

    def test_validate_link_messages(self):
        """Test validation of links with messages."""
        diagram = """flowchart TD
\tnode1["Node 1"]
\tnode2["Node 2"]
\tnode3["Node 3"]
\tnode1 -->|HTTP request| node2
\tnode2 -->|SQL query| node3
\tnode3 --> node1"""

        result = _validate_mermaid_syntax(diagram)
        assert result["valid"] is True

    def test_validate_empty_content(self):
        """Test validation with empty content."""
        result = _validate_mermaid_syntax("")

        assert result["valid"] is False
        # Empty content results in no lines, so diagram declaration check fails first
        assert "Missing diagram declaration" in result["error"]

    def test_validate_missing_flowchart_declaration(self):
        """Test validation with missing flowchart declaration."""
        invalid_diagram = """node1["Node 1"]
node2["Node 2"]
node1 --> node2"""

        result = _validate_mermaid_syntax(invalid_diagram)

        assert result["valid"] is False
        assert "Missing diagram declaration" in result["error"]

    def test_validate_invalid_node_syntax(self):
        """Test validation with invalid node syntax."""
        invalid_diagram = """flowchart TD
\tnode1[Invalid node syntax without closing bracket
\tnode2["Valid Node"]"""

        result = _validate_mermaid_syntax(invalid_diagram)

        assert result["valid"] is False
        assert "Invalid node syntax on line 2" in result["error"]

    def test_validate_invalid_link_syntax(self):
        """Test validation with invalid link syntax."""
        invalid_diagram = """flowchart TD
\tnode1["Node 1"]
\tnode2["Node 2"]
\tnode1 -->--> node2"""  # Invalid: double arrow with -->

        result = _validate_mermaid_syntax(invalid_diagram)

        assert result["valid"] is False
        assert "Invalid link syntax on line 4" in result["error"]

    def test_validate_invalid_link_message_syntax(self):
        """Test validation with invalid link message syntax."""
        invalid_diagram = """flowchart TD
\tnode1["Node 1"]
\tnode2["Node 2"]
\tnode1 -->|invalid message format node2"""

        result = _validate_mermaid_syntax(invalid_diagram)

        assert result["valid"] is False
        assert "Invalid link message syntax on line 4" in result["error"]

    def test_validate_complex_valid_diagram(self):
        """Test validation of complex but valid diagram."""
        complex_diagram = """flowchart TD
\tclassDef critical fill:#ff6b6b,color:#fff,stroke-width:3px,stroke:#d63031
\tclassDef high fill:#ffa726,color:#fff,stroke-width:2px,stroke:#ef6c00
\tclassDef medium fill:#ffeb3b,color:#000,stroke-width:2px,stroke:#f57f17
\tclassDef low fill:#81c784,color:#fff,stroke-width:1px,stroke:#388e3c
\texternal_api["External API"]:::high
\tweb_app["Web Application"]:::medium
\tdatabase[("Database")]:::critical
\tcache[("Redis Cache")]:::low
\tuser(("User"))
\tuser -->|HTTPS requests| web_app
\tweb_app -->|API calls| external_api
\tweb_app -->|SQL queries| database
\tweb_app -->|Cache operations| cache
\texternal_api -->|API responses| web_app
\tdatabase -->|Query results| web_app
\tcache -->|Cached data| web_app
\tweb_app -->|HTTPS responses| user"""

        result = _validate_mermaid_syntax(complex_diagram)
        assert result["valid"] is True

    def test_validate_with_comments_and_whitespace(self):
        """Test validation handles whitespace and empty lines properly."""
        diagram_with_whitespace = """flowchart TD

\tnode1["Node 1"]
\t
\tnode2["Node 2"]
\t
\tnode1 --> node2

"""

        result = _validate_mermaid_syntax(diagram_with_whitespace)
        assert result["valid"] is True

    def test_validate_special_characters_in_node_content(self):
        """Test validation with special characters in node content."""
        diagram = """flowchart TD
\tnode1["Node with @#$%^&*() chars"]
\tnode2["Another-Node_With.Special.Chars"]
\tnode1 --> node2"""

        result = _validate_mermaid_syntax(diagram)
        assert result["valid"] is True

    def test_validate_handles_tabs_and_spaces(self):
        """Test validation handles both tabs and spaces for indentation."""
        # Mixed indentation (tabs and spaces)
        diagram = """flowchart TD
    classDef critical fill:#ff0000
\tnode1["Node 1"]:::critical
    node2["Node 2"]
\tnode1 --> node2"""

        result = _validate_mermaid_syntax(diagram)
        assert result["valid"] is True

    def test_validate_error_handling(self):
        """Test that validation handles unexpected errors gracefully."""
        # Test None input
        result = _validate_mermaid_syntax(None)
        assert result["valid"] is False
        assert "Diagram content is None" in result["error"]

        # Test non-string input
        result = _validate_mermaid_syntax(123)
        assert result["valid"] is False
        assert "Diagram content must be a string" in result["error"]

    def test_validate_architecture_diagram(self):
        """Test validation of architecture diagrams."""
        architecture_diagram = """architecture-beta
    group group1(cloud)[Application]
    service web_app(server)[Web Application] in group1
    service database(database)[Database] in group1
    web_app:R --> L:database"""

        result = _validate_mermaid_syntax(architecture_diagram)
        assert result["valid"] is True

    def test_validate_invalid_architecture_group(self):
        """Test validation with invalid architecture group syntax."""
        invalid_diagram = """architecture-beta
    group invalidgroup
    service web_app(server)[Web App]"""

        result = _validate_mermaid_syntax(invalid_diagram)
        assert result["valid"] is False
        assert "Invalid group syntax" in result["error"]

    def test_validate_invalid_architecture_service(self):
        """Test validation with invalid architecture service syntax."""
        invalid_diagram = """architecture-beta
    service web_app[Web App]"""  # Missing icon

        result = _validate_mermaid_syntax(invalid_diagram)
        assert result["valid"] is False
        assert "Invalid service syntax" in result["error"]
