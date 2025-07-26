"""Tests for threat modeling MCP server integration."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp import types

from adversary_mcp_server.server import AdversaryMCPServer, AdversaryToolError


class TestThreatModelingServerIntegration:
    """Test threat modeling tools in MCP server."""

    @pytest.fixture
    def server(self):
        """Create server instance for testing."""
        return AdversaryMCPServer()

    @pytest.fixture
    def sample_python_code(self):
        """Sample Python code for testing."""
        return """
from flask import Flask, request, jsonify
import sqlite3
import requests

app = Flask(__name__)

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # Database query
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    result = cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    # External API call
    stripe_data = requests.get(f"https://api.stripe.com/v1/customers/{user_id}")

    return jsonify({
        "user": result,
        "payment_info": stripe_data.json()
    })

if __name__ == '__main__':
    app.run(debug=True)
"""

    @pytest.mark.asyncio
    async def test_generate_threat_model_tool(self, server, sample_python_code):
        """Test the adv_threat_model tool."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create source file
            source_file = Path(temp_dir) / "app.py"
            source_file.write_text(sample_python_code)

            # Create output file path
            output_file = Path(temp_dir) / "threat_model.json"

            # Test tool call
            arguments = {
                "source_path": str(source_file),
                "output_file": str(output_file),
                "include_threats": True,
                "severity_threshold": "medium",
                "output_format": "json",
            }

            result = await server._handle_generate_threat_model(arguments)

            # Verify response
            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)

            response_text = result[0].text
            assert "Threat Model Generated" in response_text
            assert "Architecture Summary" in response_text
            assert str(source_file) in response_text
            assert str(output_file) in response_text

            # Verify output file was created
            assert output_file.exists()

            # Verify JSON structure
            with open(output_file) as f:
                threat_model_data = json.load(f)

            required_keys = [
                "boundaries",
                "external_entities",
                "processes",
                "data_stores",
                "data_flows",
            ]
            for key in required_keys:
                assert key in threat_model_data
                assert isinstance(threat_model_data[key], list)

            # Should have detected Flask app, SQLite, and Stripe API
            assert len(threat_model_data["processes"]) > 0
            assert len(threat_model_data["data_stores"]) > 0
            assert len(threat_model_data["external_entities"]) > 0
            assert len(threat_model_data["data_flows"]) > 0

            # Check for specific components
            all_components = (
                threat_model_data["external_entities"]
                + threat_model_data["processes"]
                + threat_model_data["data_stores"]
            )
            component_text = " ".join(all_components).lower()
            assert any(keyword in component_text for keyword in ["flask", "web", "app"])
            assert any(keyword in component_text for keyword in ["sql", "database"])
            assert any(
                keyword in component_text for keyword in ["http", "api", "client"]
            )

    @pytest.mark.asyncio
    async def test_generate_threat_model_markdown_format(
        self, server, sample_python_code
    ):
        """Test threat model generation with markdown output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            source_file = Path(temp_dir) / "app.py"
            source_file.write_text(sample_python_code)

            output_file = Path(temp_dir) / "threat_model.md"

            arguments = {
                "source_path": str(source_file),
                "output_file": str(output_file),
                "include_threats": True,
                "output_format": "markdown",
            }

            result = await server._handle_generate_threat_model(arguments)

            # Verify response
            assert len(result) == 1
            response_text = result[0].text
            assert "Format:** markdown" in response_text

            # Verify markdown file was created
            assert output_file.exists()

            markdown_content = output_file.read_text()
            assert "# Threat Model Report" in markdown_content
            assert "## Architecture Components" in markdown_content
            assert "## STRIDE Threat Analysis" in markdown_content

    @pytest.mark.asyncio
    async def test_generate_diagram_from_source(self, server, sample_python_code):
        """Test diagram generation directly from source code."""
        with tempfile.TemporaryDirectory() as temp_dir:
            source_file = Path(temp_dir) / "app.py"
            source_file.write_text(sample_python_code)

            output_file = Path(temp_dir) / "diagram.mmd"

            arguments = {
                "source_path": str(source_file),
                "output_file": str(output_file),
                "diagram_type": "flowchart",
                "show_threats": True,
                "layout_direction": "TD",
            }

            result = await server._handle_generate_diagram(arguments)

            # Verify response
            assert len(result) == 1
            response_text = result[0].text
            assert "Mermaid Diagram Generated" in response_text
            assert "Diagram Type:** flowchart" in response_text
            assert "Show Threats:** True" in response_text
            assert "```mermaid" in response_text

            # Verify diagram file was created
            assert output_file.exists()

            diagram_content = output_file.read_text()
            assert diagram_content.startswith("flowchart TD")
            assert "classDef" in diagram_content  # CSS styling

    @pytest.mark.asyncio
    async def test_generate_diagram_from_json(self, server):
        """Test diagram generation from existing threat model JSON."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create sample threat model JSON
            threat_model_data = {
                "boundaries": ["Internet", "Application", "Data Layer"],
                "external_entities": ["User", "Payment API"],
                "processes": ["Web Server", "API Gateway"],
                "data_stores": ["User Database", "Session Cache"],
                "data_flows": [
                    {"source": "User", "target": "Web Server", "protocol": "HTTPS"},
                    {
                        "source": "Web Server",
                        "target": "API Gateway",
                        "protocol": "HTTP",
                    },
                    {
                        "source": "API Gateway",
                        "target": "User Database",
                        "protocol": "SQL",
                    },
                    {
                        "source": "API Gateway",
                        "target": "Payment API",
                        "protocol": "HTTPS",
                    },
                ],
            }

            json_file = Path(temp_dir) / "threat_model.json"
            with open(json_file, "w") as f:
                json.dump(threat_model_data, f, indent=2)

            output_file = Path(temp_dir) / "diagram.mmd"

            arguments = {
                "source_path": str(json_file),
                "output_file": str(output_file),
                "diagram_type": "sequence",
                "show_threats": False,
            }

            result = await server._handle_generate_diagram(arguments)

            # Verify response
            assert len(result) == 1
            response_text = result[0].text
            assert "Diagram Type:** sequence" in response_text
            assert "Show Threats:** False" in response_text

            # Verify diagram file
            assert output_file.exists()
            diagram_content = output_file.read_text()
            assert diagram_content.startswith("sequenceDiagram")
            assert "participant" in diagram_content

    @pytest.mark.asyncio
    async def test_generate_threat_model_directory(self, server):
        """Test threat model generation from directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create multiple Python files
            app_py = Path(temp_dir) / "app.py"
            app_py.write_text(
                """
from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return "Hello World"
"""
            )

            database_py = Path(temp_dir) / "database.py"
            database_py.write_text(
                """
import sqlite3

def get_connection():
    return sqlite3.connect('app.db')

def store_data(data):
    conn = get_connection()
    conn.execute("INSERT INTO data VALUES (?)", (data,))
    conn.commit()
"""
            )

            output_file = Path(temp_dir) / "threat_model.json"

            arguments = {
                "source_path": str(temp_dir),
                "output_file": str(output_file),
                "include_threats": False,  # Just test component extraction
                "output_format": "json",  # Specify JSON format for parsing
            }

            result = await server._handle_generate_threat_model(arguments)

            # Verify response
            assert len(result) == 1
            assert "Threat Model Generated" in result[0].text

            # Verify output file
            assert output_file.exists()

            with open(output_file) as f:
                threat_model_data = json.load(f)

            # Should have extracted components from both files
            assert len(threat_model_data["processes"]) > 0
            assert len(threat_model_data["data_stores"]) > 0

    @pytest.mark.asyncio
    async def test_error_handling_invalid_source(self, server):
        """Test error handling for invalid source paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "threat_model.json"

            arguments = {
                "source_path": "/nonexistent/path",
                "output_file": str(output_file),
            }

            with pytest.raises(AdversaryToolError) as exc_info:
                await server._handle_generate_threat_model(arguments)

            assert "does not exist" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_default_paths_functionality(self, server, sample_python_code):
        """Test default path functionality when no paths are provided."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change to temp directory to test defaults
            original_cwd = Path.cwd()
            try:
                import os

                os.chdir(temp_dir)

                # Create source file in current directory
                source_file = Path("app.py")
                source_file.write_text(sample_python_code)

                # Test with current directory as source_path (since we can't use empty args anymore)
                arguments = {"source_path": ".", "output_format": "json"}

                result = await server._handle_generate_threat_model(arguments)

                # Verify response
                assert len(result) == 1
                assert "Threat Model Generated" in result[0].text

                # Verify default files were created
                assert Path("threat_model.json").exists()

                # Test diagram generation with defaults
                diagram_result = await server._handle_generate_diagram(
                    {"source_path": "."}
                )
                assert len(diagram_result) == 1
                assert "Mermaid Diagram Generated" in diagram_result[0].text
                assert Path("threat_diagram.mmd").exists()

            finally:
                os.chdir(original_cwd)

    @pytest.mark.asyncio
    async def test_error_handling_invalid_json(self, server):
        """Test error handling for invalid JSON files in diagram generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create invalid JSON file
            invalid_json = Path(temp_dir) / "invalid.json"
            invalid_json.write_text("{ invalid json }")

            output_file = Path(temp_dir) / "diagram.mmd"

            arguments = {
                "source_path": str(invalid_json),
                "output_file": str(output_file),
            }

            with pytest.raises(AdversaryToolError) as exc_info:
                await server._handle_generate_diagram(arguments)

            assert "Invalid threat model JSON" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_different_diagram_types(self, server, sample_python_code):
        """Test different diagram types and layouts."""
        with tempfile.TemporaryDirectory() as temp_dir:
            source_file = Path(temp_dir) / "app.py"
            source_file.write_text(sample_python_code)

            # Test different diagram types
            diagram_types = ["flowchart", "graph", "sequence"]
            layout_directions = ["TD", "LR", "BT", "RL"]

            for diagram_type in diagram_types:
                for layout in layout_directions:
                    if diagram_type == "sequence" and layout != "TD":
                        continue  # Sequence diagrams don't use layout direction

                    output_file = (
                        Path(temp_dir) / f"diagram_{diagram_type}_{layout}.mmd"
                    )

                    arguments = {
                        "source_path": str(source_file),
                        "output_file": str(output_file),
                        "diagram_type": diagram_type,
                        "layout_direction": layout,
                    }

                    result = await server._handle_generate_diagram(arguments)

                    # Verify response
                    assert len(result) == 1
                    assert f"Diagram Type:** {diagram_type}" in result[0].text

                    # Verify file content
                    assert output_file.exists()
                    content = output_file.read_text()

                    if diagram_type == "sequence":
                        assert content.startswith("sequenceDiagram")
                    else:
                        expected_start = f"{diagram_type} {layout}"
                        assert content.startswith(expected_start)

    @pytest.mark.asyncio
    async def test_severity_threshold_filtering(self, server, sample_python_code):
        """Test threat filtering by severity threshold."""
        with tempfile.TemporaryDirectory() as temp_dir:
            source_file = Path(temp_dir) / "app.py"
            source_file.write_text(sample_python_code)

            # Test different severity thresholds
            for threshold in ["low", "medium", "high", "critical"]:
                output_file = Path(temp_dir) / f"threat_model_{threshold}.json"

                arguments = {
                    "source_path": str(source_file),
                    "output_file": str(output_file),
                    "include_threats": True,
                    "severity_threshold": threshold,
                    "output_format": "json",  # Specify JSON format for parsing
                }

                result = await server._handle_generate_threat_model(arguments)

                # Verify response
                assert len(result) == 1
                assert "Threat Model Generated" in result[0].text

                # Verify output file
                assert output_file.exists()

                with open(output_file) as f:
                    threat_model_data = json.load(f)

                # If threats are present, they should all be above threshold
                if "threats" in threat_model_data and threat_model_data["threats"]:
                    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                    min_level = severity_order[threshold]

                    for threat in threat_model_data["threats"]:
                        threat_level = severity_order[threat["severity"]]
                        assert threat_level >= min_level


@pytest.mark.integration
class TestThreatModelingWorkflow:
    """Integration test for complete threat modeling workflow."""

    @pytest.mark.asyncio
    async def test_complete_workflow(self):
        """Test complete workflow from code analysis to diagram generation."""
        # Sample application with multiple security issues
        vulnerable_app = """
from flask import Flask, request, jsonify, send_file
import sqlite3
import os
import requests
import subprocess

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # SQL injection vulnerability
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()

    return jsonify({"authenticated": bool(result)})

@app.route('/user/<user_id>')
def get_user(user_id):
    # External API calls to multiple services
    stripe_data = requests.get(f"https://api.stripe.com/v1/customers/{user_id}")
    github_data = requests.get(f"https://api.github.com/users/{user_id}")
    sendgrid_data = requests.post("https://api.sendgrid.com/v3/mail/send")

    return jsonify({
        "stripe": stripe_data.json(),
        "github": github_data.json(),
        "sendgrid": sendgrid_data.json()
    })

@app.route('/file/<path:filename>')
def get_file(filename):
    # Path traversal vulnerability
    return send_file(f"/app/files/{filename}")

@app.route('/execute', methods=['POST'])
def execute_command():
    # Command injection vulnerability
    command = request.json.get('command')
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
"""

        server = AdversaryMCPServer()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Step 1: Create source file
            source_file = Path(temp_dir) / "vulnerable_app.py"
            source_file.write_text(vulnerable_app)

            # Step 2: Generate threat model
            threat_model_file = Path(temp_dir) / "threat_model.json"

            threat_model_args = {
                "source_path": str(source_file),
                "output_file": str(threat_model_file),
                "include_threats": True,
                "severity_threshold": "medium",
                "output_format": "json",
            }

            threat_result = await server._handle_generate_threat_model(
                threat_model_args
            )

            # Verify threat model generation
            assert len(threat_result) == 1
            assert "Threat Model Generated" in threat_result[0].text
            assert threat_model_file.exists()

            # Load and verify threat model data
            with open(threat_model_file) as f:
                threat_data = json.load(f)

            # Should have detected multiple components
            assert (
                len(threat_data["external_entities"]) >= 1
            )  # At least one external service
            assert len(threat_data["processes"]) >= 1  # Flask app
            assert len(threat_data["data_stores"]) >= 1  # SQLite
            assert len(threat_data["data_flows"]) >= 1  # At least one connection

            # Should have detected multiple threats
            assert "threats" in threat_data
            assert len(threat_data["threats"]) > 0

            # Should have high/critical severity threats due to vulnerabilities
            high_severity_threats = [
                t
                for t in threat_data["threats"]
                if t["severity"] in ["high", "critical"]
            ]
            assert len(high_severity_threats) > 0

            # Step 3: Generate flowchart diagram from source
            flowchart_file = Path(temp_dir) / "flowchart.mmd"

            flowchart_args = {
                "source_path": str(source_file),
                "output_file": str(flowchart_file),
                "diagram_type": "flowchart",
                "show_threats": True,
                "layout_direction": "TD",
            }

            flowchart_result = await server._handle_generate_diagram(flowchart_args)

            # Verify flowchart generation
            assert len(flowchart_result) == 1
            assert "Mermaid Diagram Generated" in flowchart_result[0].text
            assert flowchart_file.exists()

            flowchart_content = flowchart_file.read_text()
            assert flowchart_content.startswith("flowchart TD")
            assert "classDef" in flowchart_content  # Threat styling

            # Step 4: Generate sequence diagram from JSON
            sequence_file = Path(temp_dir) / "sequence.mmd"

            sequence_args = {
                "source_path": str(threat_model_file),
                "output_file": str(sequence_file),
                "diagram_type": "sequence",
                "show_threats": False,
            }

            sequence_result = await server._handle_generate_diagram(sequence_args)

            # Verify sequence diagram generation
            assert len(sequence_result) == 1
            assert sequence_file.exists()

            sequence_content = sequence_file.read_text()
            assert sequence_content.startswith("sequenceDiagram")
            assert "participant" in sequence_content

            # Step 5: Generate markdown report
            markdown_file = Path(temp_dir) / "threat_report.md"

            markdown_args = {
                "source_path": str(source_file),
                "output_file": str(markdown_file),
                "include_threats": True,
                "output_format": "markdown",
            }

            markdown_result = await server._handle_generate_threat_model(markdown_args)

            # Verify markdown generation
            assert len(markdown_result) == 1
            assert markdown_file.exists()

            markdown_content = markdown_file.read_text()
            assert "# Threat Model Report" in markdown_content
            assert "## Architecture Components" in markdown_content
            assert "## STRIDE Threat Analysis" in markdown_content
            assert (
                "Critical Severity" in markdown_content
                or "High Severity" in markdown_content
            )

            # Verify all files were created successfully
            created_files = [
                threat_model_file,
                flowchart_file,
                sequence_file,
                markdown_file,
            ]
            for file_path in created_files:
                assert file_path.exists()
                assert file_path.stat().st_size > 0  # Non-empty files


if __name__ == "__main__":
    pytest.main([__file__])
