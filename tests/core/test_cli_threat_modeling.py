"""Tests for CLI threat modeling commands."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from adversary_mcp_server.cli import cli


class TestCLIThreatModelingCommands:
    """Test threat modeling CLI commands."""

    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()

    @pytest.fixture
    def mock_repo_structure(self):
        """Create a mock repository structure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "test-repo"
            repo_path.mkdir()

            # Create git directory to make it a valid project
            (repo_path / ".git").mkdir()

            # Create some Python files
            (repo_path / "app.py").write_text(
                """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    return {"authenticated": bool(cursor.fetchone())}
"""
            )

            (repo_path / "database.py").write_text(
                """
import sqlite3

def get_connection():
    return sqlite3.connect('app.db')
"""
            )

            yield repo_path

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_threat_model_command_basic(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test basic threat-model command."""
        mock_find_repo.return_value = mock_repo_structure

        result = runner.invoke(cli, ["threat-model", "test-repo"])

        assert result.exit_code == 0
        assert "Generating threat model" in result.output
        assert "Architecture Summary" in result.output
        assert "Threat model saved to" in result.output

        # Check that threat_model.json was created
        threat_model_file = mock_repo_structure / "threat_model.json"
        assert threat_model_file.exists()

        # Verify JSON structure
        with open(threat_model_file) as f:
            threat_data = json.load(f)

        assert "boundaries" in threat_data
        assert "external_entities" in threat_data
        assert "processes" in threat_data
        assert "data_stores" in threat_data
        assert "data_flows" in threat_data

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_threat_model_command_markdown_format(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test threat-model command with markdown output."""
        mock_find_repo.return_value = mock_repo_structure

        result = runner.invoke(
            cli, ["threat-model", "test-repo", "--format", "markdown"]
        )

        assert result.exit_code == 0
        assert "Saving threat model as markdown" in result.output

        # Check that threat_model.md was created
        threat_model_file = mock_repo_structure / "threat_model.md"
        assert threat_model_file.exists()

        # Verify markdown content
        content = threat_model_file.read_text()
        assert "# Threat Model Report" in content
        assert "## Architecture Components" in content

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_threat_model_command_no_threats(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test threat-model command without threat analysis."""
        mock_find_repo.return_value = mock_repo_structure

        result = runner.invoke(cli, ["threat-model", "test-repo", "--no-threats"])

        assert result.exit_code == 0
        assert "Architecture Summary" in result.output

        # Check that threats are not included
        threat_model_file = mock_repo_structure / "threat_model.json"
        with open(threat_model_file) as f:
            threat_data = json.load(f)

        # May or may not have threats key, but if it does, should be empty
        if "threats" in threat_data:
            assert len(threat_data["threats"]) == 0

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_threat_model_command_custom_output(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test threat-model command with custom output path."""
        mock_find_repo.return_value = mock_repo_structure

        custom_output = mock_repo_structure / "custom" / "threat_analysis.json"
        custom_output.parent.mkdir()

        result = runner.invoke(
            cli, ["threat-model", "test-repo", "--output", str(custom_output)]
        )

        assert result.exit_code == 0
        assert custom_output.exists()

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_threat_model_command_severity_filtering(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test threat-model command with severity threshold."""
        mock_find_repo.return_value = mock_repo_structure

        result = runner.invoke(cli, ["threat-model", "test-repo", "--severity", "high"])

        assert result.exit_code == 0
        assert "Architecture Summary" in result.output

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_threat_model_command_repo_not_found(self, mock_find_repo, runner):
        """Test threat-model command when repo is not found."""
        mock_find_repo.side_effect = SystemExit(1)

        result = runner.invoke(cli, ["threat-model", "nonexistent-repo"])

        assert result.exit_code == 1

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_diagram_command_basic(self, mock_find_repo, runner, mock_repo_structure):
        """Test basic diagram command."""
        mock_find_repo.return_value = mock_repo_structure

        # Create a threat model first
        threat_model_data = {
            "boundaries": ["Internet", "Application"],
            "external_entities": ["User"],
            "processes": ["Flask App"],
            "data_stores": ["SQLite"],
            "data_flows": [
                {"source": "User", "target": "Flask App", "protocol": "HTTPS"},
                {"source": "Flask App", "target": "SQLite", "protocol": "SQL"},
            ],
        }

        threat_model_file = mock_repo_structure / "threat_model.json"
        with open(threat_model_file, "w") as f:
            json.dump(threat_model_data, f)

        result = runner.invoke(cli, ["diagram", "test-repo"])

        assert result.exit_code == 0
        assert "Generating diagram" in result.output
        assert "Using existing threat model" in result.output
        assert "Diagram Generated!" in result.output

        # Check that diagram was created
        diagram_file = mock_repo_structure / "threat_diagram.mmd"
        assert diagram_file.exists()

        # Verify mermaid content
        content = diagram_file.read_text()
        assert (
            "flowchart" in content or "graph" in content or "sequenceDiagram" in content
        )

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_diagram_command_no_threat_model(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test diagram command without existing threat model."""
        mock_find_repo.return_value = mock_repo_structure

        result = runner.invoke(cli, ["diagram", "test-repo"])

        assert result.exit_code == 0
        assert "Analyzing source code" in result.output
        assert "Diagram Generated!" in result.output

        # Check that diagram was created
        diagram_file = mock_repo_structure / "threat_diagram.mmd"
        assert diagram_file.exists()

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_diagram_command_different_types(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test diagram command with different diagram types."""
        mock_find_repo.return_value = mock_repo_structure

        # Test each diagram type
        for diagram_type in ["flowchart", "graph", "sequence"]:
            result = runner.invoke(
                cli, ["diagram", "test-repo", "--type", diagram_type]
            )

            assert result.exit_code == 0
            assert "Diagram Generated!" in result.output

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    @patch("webbrowser.open")
    def test_diagram_command_open_browser(
        self, mock_browser, mock_find_repo, runner, mock_repo_structure
    ):
        """Test diagram command with browser opening."""
        mock_find_repo.return_value = mock_repo_structure
        mock_browser.return_value = True

        result = runner.invoke(cli, ["diagram", "test-repo", "--open"])

        assert result.exit_code == 0
        assert "Opening diagram in browser" in result.output
        assert "HTML saved to" in result.output

        # Check that HTML was created
        html_file = mock_repo_structure / "threat_diagram.html"
        assert html_file.exists()

        # Verify HTML content
        content = html_file.read_text()
        assert "<!DOCTYPE html>" in content
        assert "mermaid" in content
        assert "Threat Model Diagram" in content

        # Verify browser was called
        mock_browser.assert_called_once()

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_diagram_command_custom_output(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test diagram command with custom output path."""
        mock_find_repo.return_value = mock_repo_structure

        custom_output = mock_repo_structure / "diagrams" / "architecture.mmd"
        custom_output.parent.mkdir()

        result = runner.invoke(
            cli, ["diagram", "test-repo", "--output", str(custom_output)]
        )

        assert result.exit_code == 0
        assert custom_output.exists()

    @patch("adversary_mcp_server.cli._find_repo_by_name_cli")
    def test_diagram_command_layout_options(
        self, mock_find_repo, runner, mock_repo_structure
    ):
        """Test diagram command with different layout options."""
        mock_find_repo.return_value = mock_repo_structure

        for layout in ["TD", "LR", "BT", "RL"]:
            result = runner.invoke(cli, ["diagram", "test-repo", "--layout", layout])

            assert result.exit_code == 0
            assert "Diagram Generated!" in result.output

    def test_find_repo_by_name_cli(self):
        """Test the _find_repo_by_name_cli function."""
        from adversary_mcp_server.cli import _is_valid_project

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a valid project
            repo_path = Path(temp_dir) / "test-repo"
            repo_path.mkdir()
            (repo_path / ".git").mkdir()

            assert _is_valid_project(repo_path) is True

            # Test with non-project directory
            non_repo = Path(temp_dir) / "not-a-repo"
            non_repo.mkdir()

            assert _is_valid_project(non_repo) is False

    def test_threat_model_and_diagram_integration(self, runner):
        """Test integration between threat-model and diagram commands."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a mock repo
            repo_path = Path(temp_dir) / "integration-test"
            repo_path.mkdir()
            (repo_path / ".git").mkdir()
            (repo_path / "app.py").write_text("import flask")

            with patch("adversary_mcp_server.cli._find_repo_by_name_cli") as mock_find:
                mock_find.return_value = repo_path

                # First generate threat model
                result = runner.invoke(cli, ["threat-model", "integration-test"])
                assert result.exit_code == 0

                # Then generate diagram
                result = runner.invoke(cli, ["diagram", "integration-test"])
                assert result.exit_code == 0
                assert "Using existing threat model" in result.output
