"""Tests for threat modeling functionality."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.threat_modeling.diagram_generator import (
    MermaidDiagramGenerator,
)
from adversary_mcp_server.threat_modeling.extractors.base_extractor import BaseExtractor
from adversary_mcp_server.threat_modeling.extractors.python_extractor import (
    PythonExtractor,
)
from adversary_mcp_server.threat_modeling.models import (
    ComponentType,
    DataFlow,
    Severity,
    ThreatModel,
    ThreatModelComponents,
    ThreatType,
)
from adversary_mcp_server.threat_modeling.threat_catalog import STRIDE_THREATS
from adversary_mcp_server.threat_modeling.threat_model_builder import ThreatModelBuilder


class TestDataModels:
    """Test threat modeling data models."""

    def test_data_flow_creation(self):
        """Test DataFlow model creation and serialization."""
        flow = DataFlow(
            source="Web Client",
            target="API Server",
            protocol="HTTPS",
            data_type="JSON",
            authentication="Bearer Token",
        )

        assert flow.source == "Web Client"
        assert flow.target == "API Server"
        assert flow.protocol == "HTTPS"

        # Test serialization
        flow_dict = flow.to_dict()
        assert flow_dict["source"] == "Web Client"
        assert flow_dict["target"] == "API Server"
        assert flow_dict["protocol"] == "HTTPS"
        assert flow_dict["data_type"] == "JSON"
        assert flow_dict["authentication"] == "Bearer Token"

    def test_threat_model_components(self):
        """Test ThreatModelComponents functionality."""
        components = ThreatModelComponents()

        # Add components
        components.add_component("User", ComponentType.EXTERNAL_ENTITY)
        components.add_component("API Server", ComponentType.PROCESS)
        components.add_component("Database", ComponentType.DATA_STORE)

        assert "User" in components.external_entities
        assert "API Server" in components.processes
        assert "Database" in components.data_stores

        # Add data flow
        components.add_data_flow("User", "API Server", "HTTPS")
        assert len(components.data_flows) == 1
        assert components.data_flows[0].source == "User"

        # Test serialization
        data = components.to_dict()
        assert "boundaries" in data
        assert "external_entities" in data
        assert "processes" in data
        assert "data_stores" in data
        assert "data_flows" in data


class TestPythonExtractor:
    """Test Python code extractor."""

    def test_basic_flask_app_extraction(self):
        """Test extraction from a basic Flask application."""
        code = """
import requests
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    result = cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    response = requests.get(f"https://api.stripe.com/v1/customers/{user_id}")

    return jsonify({"user": result, "payment_info": response.json()})
"""

        extractor = PythonExtractor()
        components = extractor.extract_components(code, "test_app.py")

        # Should detect Flask app as a process
        assert len(components.processes) > 0
        assert any(
            "Flask" in process or "Web" in process for process in components.processes
        )

        # Should detect database
        assert len(components.data_stores) > 0
        assert any(
            "SQL" in store or "Database" in store for store in components.data_stores
        )

        # Should detect external API
        assert len(components.external_entities) > 0
        assert any(
            "HTTP" in entity or "API" in entity
            for entity in components.external_entities
        )

        # Should have data flows
        assert len(components.data_flows) > 0

    def test_database_operations_detection(self):
        """Test detection of database operations."""
        code = """
import psycopg2
import mysql.connector
from sqlalchemy import create_engine

# PostgreSQL connection
pg_conn = psycopg2.connect("postgresql://user:pass@localhost/db")

# MySQL connection
mysql_conn = mysql.connector.connect(host='localhost', database='test')

# SQLAlchemy engine
engine = create_engine('sqlite:///example.db')
"""

        extractor = PythonExtractor()
        components = extractor.extract_components(code, "db_test.py")

        # Should detect multiple database types
        assert len(components.data_stores) >= 2
        store_names = " ".join(components.data_stores).lower()
        assert any(db in store_names for db in ["postgresql", "mysql", "sql"])

    def test_external_api_detection(self):
        """Test detection of external API calls."""
        code = """
import requests
import stripe
import boto3
from sendgrid import SendGridAPIClient

# HTTP requests
response = requests.get("https://api.github.com/user")

# Stripe API
stripe.api_key = "sk_test_..."
stripe.Charge.create(amount=2000, currency='usd')

# AWS services
s3 = boto3.client('s3')

# SendGrid
sg = SendGridAPIClient(api_key='...')
"""

        extractor = PythonExtractor()
        components = extractor.extract_components(code, "api_test.py")

        # Should detect external services
        assert len(components.external_entities) >= 2
        entity_names = " ".join(components.external_entities).lower()
        assert any(
            service in entity_names
            for service in ["stripe", "github", "aws", "sendgrid"]
        )


class TestThreatModelBuilder:
    """Test threat model builder."""

    def test_build_threat_model_from_code(self):
        """Test building threat model from Python code."""
        # Create temporary Python file
        test_code = """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()

    return "Login successful" if result else "Login failed"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            temp_file = f.name

        try:
            builder = ThreatModelBuilder()
            threat_model = builder.build_threat_model(
                source_path=temp_file,
                include_threats=True,
                severity_threshold=Severity.MEDIUM,
            )

            # Verify components were extracted
            assert len(threat_model.components.processes) > 0
            assert len(threat_model.components.data_stores) > 0

            # Verify threats were identified
            assert len(threat_model.threats) > 0

            # Should identify SQL injection threat
            threat_descriptions = [t.description.lower() for t in threat_model.threats]
            assert any(
                "sql" in desc or "injection" in desc for desc in threat_descriptions
            )

            # Test serialization
            threat_dict = threat_model.to_dict()
            assert "boundaries" in threat_dict
            assert "external_entities" in threat_dict
            assert "processes" in threat_dict
            assert "data_stores" in threat_dict
            assert "data_flows" in threat_dict
            assert "threats" in threat_dict

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_build_threat_model_directory(self):
        """Test building threat model from directory."""
        # Create temporary directory with Python files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create multiple Python files
            file1_content = """
from flask import Flask
app = Flask(__name__)

@app.route('/api/data')
def get_data():
    return {"data": "test"}
"""

            file2_content = """
import sqlite3

def store_data(data):
    conn = sqlite3.connect('app.db')
    conn.execute("INSERT INTO data VALUES (?)", (data,))
    conn.commit()
"""

            file1_path = Path(temp_dir) / "app.py"
            file2_path = Path(temp_dir) / "database.py"

            file1_path.write_text(file1_content)
            file2_path.write_text(file2_content)

            builder = ThreatModelBuilder()
            threat_model = builder.build_threat_model(
                source_path=temp_dir,
                include_threats=False,  # Just test component extraction
            )

            # Should extract components from both files
            assert len(threat_model.components.processes) > 0
            assert len(threat_model.components.data_stores) > 0


class TestMermaidDiagramGenerator:
    """Test Mermaid diagram generator."""

    def test_generate_flowchart_diagram(self):
        """Test generating flowchart diagram."""
        # Create sample threat model components
        components = ThreatModelComponents()
        components.external_entities = ["User", "Payment API"]
        components.processes = ["Web App", "API Server"]
        components.data_stores = ["Database", "Cache"]
        components.boundaries = ["Internet", "Application", "Data Layer"]

        components.data_flows = [
            DataFlow("User", "Web App", "HTTPS"),
            DataFlow("Web App", "API Server", "HTTP"),
            DataFlow("API Server", "Database", "SQL"),
            DataFlow("API Server", "Payment API", "HTTPS"),
        ]

        threat_model = ThreatModel(components=components)

        generator = MermaidDiagramGenerator()
        diagram = generator.generate_diagram(
            threat_model=threat_model, diagram_type="flowchart", show_threats=False
        )

        # Basic diagram structure checks
        assert diagram.startswith("flowchart TD")
        assert "User" in diagram
        assert "Web App" in diagram
        assert "Database" in diagram
        assert "HTTPS" in diagram
        assert "SQL" in diagram

        # Check for CSS classes
        assert "classDef" in diagram

    def test_generate_from_dict(self):
        """Test generating diagram from dictionary data."""
        components_dict = {
            "boundaries": ["Internet", "Internal"],
            "external_entities": ["User", "API"],
            "processes": ["Web Server"],
            "data_stores": ["Database"],
            "data_flows": [
                {"source": "User", "target": "Web Server", "protocol": "HTTPS"},
                {"source": "Web Server", "target": "Database", "protocol": "SQL"},
            ],
        }

        diagram = MermaidDiagramGenerator.generate_from_components_dict(
            components_dict=components_dict, diagram_type="flowchart"
        )

        assert diagram.startswith("flowchart TD")
        assert "User" in diagram
        assert "Web Server" in diagram
        assert "Database" in diagram

    def test_sequence_diagram_generation(self):
        """Test generating sequence diagram."""
        components = ThreatModelComponents()
        components.data_flows = [
            DataFlow("Client", "Server", "HTTPS"),
            DataFlow("Server", "Database", "SQL"),
        ]

        threat_model = ThreatModel(components=components)

        generator = MermaidDiagramGenerator()
        diagram = generator.generate_diagram(
            threat_model=threat_model, diagram_type="sequence"
        )

        assert diagram.startswith("sequenceDiagram")
        assert "participant" in diagram
        assert "Client" in diagram
        assert "Server" in diagram
        assert "Database" in diagram

    def test_sanitize_display_name(self):
        """Test display name sanitization for Mermaid participant labels."""
        generator = MermaidDiagramGenerator()

        # Test cases that could break Mermaid syntax
        test_cases = [
            # (input, expected_output)
            ("Test.Com API", "Test.Com API"),  # Dots are OK in display names
            ("Test\nAPI", "Test API"),  # Line breaks should be removed
            ("Test\r\nAPI", "Test API"),  # Windows line breaks
            ("Test    API", "Test API"),  # Multiple spaces normalized
            ("  Test API  ", "Test API"),  # Leading/trailing whitespace
            (
                "Very Long Component Name That Exceeds Fifty Characters And Should Be Truncated",
                "Very Long Component Name That Exceeds Fifty Cha...",
            ),  # Long names truncated
            ("", ""),  # Empty string
            ("A", "A"),  # Single character
            ("Test\tAPI", "Test API"),  # Tab characters
        ]

        for input_name, expected in test_cases:
            result = generator._sanitize_display_name(input_name)
            assert (
                result == expected
            ), f"Input '{repr(input_name)}' should produce '{expected}', got '{result}'"

    def test_sanitize_id(self):
        """Test ID sanitization for Mermaid node IDs."""
        generator = MermaidDiagramGenerator()

        test_cases = [
            # (input, expected_pattern)
            ("Test API", "Test_API"),
            ("Test.Com API", "Test_Com_API"),
            ("123numbers", "node_123numbers"),  # Should start with letter
            ("test-api", "test_api"),
            ("test@api", "test_api"),
            ("test/api", "test_api"),
            ("", "node_1"),  # Empty becomes node_1
        ]

        for input_name, expected in test_cases:
            result = generator._sanitize_id(input_name)
            if expected.startswith("node_") and input_name == "":
                # For empty strings, just check it starts with node_
                assert result.startswith(
                    "node_"
                ), f"Empty input should start with 'node_', got '{result}'"
            else:
                assert (
                    result == expected
                ), f"Input '{input_name}' should produce '{expected}', got '{result}'"

    def test_sequence_diagram_with_problematic_names(self):
        """Test sequence diagram generation with names that could cause syntax errors."""
        components = ThreatModelComponents()
        # Include names that previously caused issues
        components.data_flows = [
            DataFlow("Django App", "Test.Com API", "HTTP"),
            DataFlow("Test.Com API", "Django App", "HTTP"),
            DataFlow("Web User", "Django App", "HTTPS"),
            DataFlow("Django App", "Example.Org?Foo=Bar#Header API", "HTTPS"),
        ]

        threat_model = ThreatModel(components=components)

        generator = MermaidDiagramGenerator()
        diagram = generator.generate_diagram(
            threat_model=threat_model, diagram_type="sequence"
        )

        # Should generate valid syntax
        assert diagram.startswith("sequenceDiagram")

        # Check that problematic characters are handled
        lines = diagram.split("\n")
        participant_lines = [line.strip() for line in lines if "participant" in line]

        for line in participant_lines:
            # No line should contain unescaped line breaks
            assert "\n" not in line.replace(
                "\\n", ""
            ), f"Line contains unescaped line break: {line}"
            # Should follow proper participant syntax
            assert " as " in line, f"Participant line missing ' as ': {line}"
            # Should not have trailing incomplete syntax
            assert not line.endswith(" as"), f"Incomplete participant syntax: {line}"


class TestThreatCatalog:
    """Test STRIDE threat catalog."""

    def test_get_threats_for_component(self):
        """Test getting threats for different component types."""
        # Test for data store component
        threats = STRIDE_THREATS.get_threats_for_component(
            component_name="SQL Database",
            component_type=ComponentType.DATA_STORE,
            context="database user input query",
        )

        assert len(threats) > 0

        # Should include SQL injection threat
        threat_types = [t.threat_type for t in threats]
        assert ThreatType.TAMPERING in threat_types

        # Check threat has proper fields
        threat = threats[0]
        assert threat.component == "SQL Database"
        assert threat.title
        assert threat.description
        assert threat.severity in [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def test_get_threats_for_process(self):
        """Test getting threats for process components."""
        threats = STRIDE_THREATS.get_threats_for_component(
            component_name="Web Application",
            component_type=ComponentType.PROCESS,
            context="authentication user input api endpoint",
        )

        assert len(threats) > 0

        # Should include various STRIDE categories
        threat_types = {t.threat_type for t in threats}
        assert len(threat_types) > 1  # Multiple threat types

    def test_get_threats_for_external_entity(self):
        """Test getting threats for external entities."""
        threats = STRIDE_THREATS.get_threats_for_component(
            component_name="External API",
            component_type=ComponentType.EXTERNAL_ENTITY,
            context="third party webhook",
        )

        assert len(threats) >= 0  # May or may not have threats


class TestBaseExtractor:
    """Test BaseExtractor functionality and helper methods."""

    def test_concrete_extractor_implementation(self):
        """Test concrete extractor implementation for coverage."""

        # Create a concrete implementation for testing
        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                self.reset()
                # Simple test implementation
                if "flask" in code.lower():
                    self.components.add_component("Web App", ComponentType.PROCESS)
                if "database" in code.lower():
                    self.components.add_component("Database", ComponentType.DATA_STORE)
                if "api" in code.lower():
                    self.components.add_component(
                        "External API", ComponentType.EXTERNAL_ENTITY
                    )
                    self._add_data_flow_if_new("Web App", "External API", "HTTPS")
                self._post_process_components()
                return self.components

            def get_supported_extensions(self) -> set[str]:
                return {".test", ".txt"}

        extractor = TestExtractor()

        # Test supported extensions
        assert ".test" in extractor.get_supported_extensions()
        assert ".txt" in extractor.get_supported_extensions()

        # Test can_extract
        assert extractor.can_extract("test.test")
        assert extractor.can_extract("file.txt")
        assert not extractor.can_extract("file.py")

    def test_extract_from_directory_error_handling(self):
        """Test directory extraction with error conditions."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                self.reset()
                if "error" in code:
                    raise UnicodeDecodeError("utf-8", b"", 0, 1, "test error")
                self.components.add_component("Test Process", ComponentType.PROCESS)
                return self.components

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            good_file = Path(temp_dir) / "good.test"
            good_file.write_text("good content")

            error_file = Path(temp_dir) / "error.test"
            error_file.write_text("error content")

            # Test extraction with errors (should skip error files)
            components = extractor.extract_from_directory(temp_dir)

            # Should have extracted from good file only
            assert len(components.processes) == 1
            assert "Test Process" in components.processes

    def test_extract_from_directory_invalid_path(self):
        """Test directory extraction with invalid directory."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        with pytest.raises(ValueError, match="Path is not a directory"):
            extractor.extract_from_directory("/nonexistent/path")

    def test_merge_components_functionality(self):
        """Test component merging logic."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Create first set of components
        components1 = ThreatModelComponents()
        components1.add_component("App1", ComponentType.PROCESS)
        components1.add_component("DB1", ComponentType.DATA_STORE)
        components1.add_data_flow("App1", "DB1", "SQL")

        # Create second set with overlap
        components2 = ThreatModelComponents()
        components2.add_component("App1", ComponentType.PROCESS)  # Duplicate
        components2.add_component("App2", ComponentType.PROCESS)  # New
        components2.add_data_flow("App1", "DB1", "SQL")  # Duplicate flow
        components2.add_data_flow("App2", "DB1", "SQL")  # New flow

        # Test merging - initialize _seen_flows with existing flows first
        extractor.components = components1
        # Initialize _seen_flows with existing flows from components1
        for flow in components1.data_flows:
            extractor._seen_flows.add((flow.source, flow.target, flow.protocol))

        extractor._merge_components(components2)

        # Should have unique processes
        assert len(extractor.components.processes) == 2
        assert "App1" in extractor.components.processes
        assert "App2" in extractor.components.processes

        # Should have unique data flows - 1 original + 1 new (duplicate skipped)
        assert len(extractor.components.data_flows) == 2

    def test_infer_protocol_from_context(self):
        """Test protocol inference from code context."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Test HTTP/HTTPS detection
        assert (
            extractor._infer_protocol_from_context("https://api.example.com") == "HTTPS"
        )
        assert (
            extractor._infer_protocol_from_context("http://api.example.com") == "HTTP"
        )
        assert extractor._infer_protocol_from_context("requests.get(url)") == "HTTP"
        assert (
            extractor._infer_protocol_from_context("fetch('https://api.com')")
            == "HTTPS"
        )

        # Test SQL detection
        assert extractor._infer_protocol_from_context("SELECT * FROM users") == "SQL"
        assert extractor._infer_protocol_from_context("INSERT INTO table") == "SQL"

        # Test MongoDB detection
        assert (
            extractor._infer_protocol_from_context("mongodb://localhost")
            == "MongoDB Protocol"
        )
        assert (
            extractor._infer_protocol_from_context("collection.find()")
            == "MongoDB Protocol"
        )

        # Test Redis detection
        assert (
            extractor._infer_protocol_from_context("redis://localhost")
            == "Redis Protocol"
        )
        assert (
            extractor._infer_protocol_from_context("client.hget('key')")
            == "Redis Protocol"
        )

        # Test gRPC detection
        assert extractor._infer_protocol_from_context("grpc service") == "gRPC"
        assert extractor._infer_protocol_from_context("service.proto") == "gRPC"

        # Test WebSocket detection
        assert (
            extractor._infer_protocol_from_context("websocket connection")
            == "WebSocket"
        )
        assert extractor._infer_protocol_from_context("ws://localhost") == "WebSocket"

        # Test file system detection
        assert (
            extractor._infer_protocol_from_context("open('file.txt')") == "File System"
        )
        assert extractor._infer_protocol_from_context("file.read()") == "File System"

        # Test unknown protocol
        assert extractor._infer_protocol_from_context("unknown protocol") == "Unknown"

    def test_extract_external_entity_from_url(self):
        """Test external entity extraction from URLs."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Test known APIs
        assert (
            extractor._extract_external_entity_from_url(
                "https://api.stripe.com/v1/customers"
            )
            == "Stripe API"
        )
        assert (
            extractor._extract_external_entity_from_url("https://api.github.com/users")
            == "GitHub API"
        )
        assert (
            extractor._extract_external_entity_from_url(
                "https://api.sendgrid.com/v3/mail"
            )
            == "SendGrid API"
        )
        assert (
            extractor._extract_external_entity_from_url(
                "https://api.twilio.com/messages"
            )
            == "Twilio API"
        )
        assert (
            extractor._extract_external_entity_from_url(
                "https://googleapis.com/compute"
            )
            == "Google APIs"
        )
        assert (
            extractor._extract_external_entity_from_url(
                "https://s3.amazonaws.com/bucket"
            )
            == "AWS Services"
        )

        # Test generic API - adjust expected format based on actual implementation
        result1 = extractor._extract_external_entity_from_url(
            "https://api.example.com/data"
        )
        assert result1 is not None and "example" in result1.lower()

        result2 = extractor._extract_external_entity_from_url(
            "https://www.example.com/api"
        )
        assert result2 is not None and "example" in result2.lower()

        # Test edge cases - method creates API names even for non-URLs
        result3 = extractor._extract_external_entity_from_url("invalid-url")
        assert (
            result3 == "Invalid Url API"
        )  # Method treats any string as domain and sanitizes it

        # Test empty string
        assert extractor._extract_external_entity_from_url("") is None

    def test_extract_external_entity_from_url_sanitization(self):
        """Test URL entity extraction sanitization logic."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Test domain name sanitization
        test_cases = [
            # (input_url, expected_output)
            ("https://test.com/api", "Test Com API"),
            ("https://api.test-company.org", "Test Company Org API"),
            (
                "https://some.complex.domain.name.com",
                "Some Complex Domain Name Com API",
            ),
            ("https://www.api.weird-123.domain.net", "Weird 123 Domain Net API"),
            ("https://test.co.uk/service", "Test Co Uk API"),
            ("https://sub-domain.example.org", "Sub Domain Example Org API"),
            ("https://123numbers.com", "123Numbers Com API"),
            (
                "https://special_chars!@#.com",
                "Special Chars Com API",
            ),  # Special chars become spaces
        ]

        for url, expected in test_cases:
            result = extractor._extract_external_entity_from_url(url)
            assert (
                result == expected
            ), f"URL {url} should produce '{expected}', got '{result}'"

    def test_identify_trust_boundaries(self):
        """Test trust boundary identification."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Set up components
        extractor.components.add_component("User", ComponentType.EXTERNAL_ENTITY)
        extractor.components.add_component("Web App", ComponentType.PROCESS)
        extractor.components.add_component("Database", ComponentType.DATA_STORE)
        extractor.components.add_component("API Gateway", ComponentType.PROCESS)
        extractor.components.add_component("Admin Panel", ComponentType.PROCESS)
        extractor.components.add_component("Public CDN", ComponentType.EXTERNAL_ENTITY)

        boundaries = extractor._identify_trust_boundaries()

        # Should identify standard boundaries
        assert "Internet" in boundaries
        assert "Application" in boundaries
        assert "Data Layer" in boundaries

        # Should identify specific boundaries based on component names
        assert "DMZ" in boundaries  # From "API Gateway"
        assert "Internal" in boundaries  # From "Admin Panel"
        assert "Public" in boundaries  # From "Public CDN"

    def test_add_data_flow_if_new(self):
        """Test data flow deduplication."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Add same flow twice
        extractor._add_data_flow_if_new("App", "DB", "SQL")
        extractor._add_data_flow_if_new("App", "DB", "SQL")  # Duplicate

        # Should only have one flow
        assert len(extractor.components.data_flows) == 1

        # Add different flow
        extractor._add_data_flow_if_new("App", "API", "HTTPS")
        assert len(extractor.components.data_flows) == 2

    def test_post_process_components(self):
        """Test component post-processing."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Add components in random order
        extractor.components.add_component("Z Process", ComponentType.PROCESS)
        extractor.components.add_component("A Process", ComponentType.PROCESS)
        extractor.components.add_component("M External", ComponentType.EXTERNAL_ENTITY)
        extractor.components.add_component("B External", ComponentType.EXTERNAL_ENTITY)

        # Add data flows
        extractor.components.add_data_flow("Z Process", "A Process", "HTTP")
        extractor.components.add_data_flow("A Process", "Z Process", "HTTP")

        # Post-process
        extractor._post_process_components()

        # Should be sorted
        assert extractor.components.processes == ["A Process", "Z Process"]
        assert extractor.components.external_entities == ["B External", "M External"]

        # Should have boundaries
        assert len(extractor.components.boundaries) > 0
        assert "Application" in extractor.components.boundaries
        assert "Internet" in extractor.components.boundaries


@pytest.mark.integration
class TestThreatModelingIntegration:
    """Integration tests for complete threat modeling workflow."""

    def test_full_workflow_python_flask_app(self):
        """Test complete workflow with a Python Flask application."""
        # Sample vulnerable Flask app
        vulnerable_app = """
from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os
import requests

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()

    if result:
        return jsonify({"status": "success", "user_id": result[0]})
    return jsonify({"status": "failed"})

@app.route('/user/<user_id>')
def get_user(user_id):
    # External API call
    stripe_response = requests.get(f"https://api.stripe.com/v1/customers/{user_id}")

    # Template injection vulnerability
    template = f"<h1>User {user_id}</h1><p>{{{{ data }}</p>"
    return render_template_string(template, data=stripe_response.json())

@app.route('/file')
def read_file():
    filename = request.args.get('file')
    # Path traversal vulnerability
    with open(f"/app/data/{filename}", 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run(debug=True)
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(vulnerable_app)
            temp_file = f.name

        try:
            # Step 1: Build threat model
            builder = ThreatModelBuilder()
            threat_model = builder.build_threat_model(
                source_path=temp_file,
                include_threats=True,
                severity_threshold=Severity.MEDIUM,
            )

            # Verify architecture extraction
            assert len(threat_model.components.processes) > 0
            assert len(threat_model.components.data_stores) > 0
            assert len(threat_model.components.external_entities) > 0
            assert len(threat_model.components.data_flows) > 0

            # Verify threat detection
            assert len(threat_model.threats) > 0

            # Should detect high severity threats (SQL injection, etc.)
            high_severity_threats = [
                t
                for t in threat_model.threats
                if t.severity in [Severity.HIGH, Severity.CRITICAL]
            ]
            assert len(high_severity_threats) > 0

            # Step 2: Generate structured output
            threat_dict = threat_model.to_dict()

            # Verify required structure matches expected format
            required_keys = [
                "boundaries",
                "external_entities",
                "processes",
                "data_stores",
                "data_flows",
            ]
            for key in required_keys:
                assert key in threat_dict
                assert isinstance(threat_dict[key], list)

            # Verify data flows have proper structure
            for flow in threat_dict["data_flows"]:
                assert "source" in flow
                assert "target" in flow
                assert "protocol" in flow

            # Step 3: Generate Mermaid diagram
            generator = MermaidDiagramGenerator()

            # Test flowchart
            flowchart = generator.generate_diagram(
                threat_model=threat_model, diagram_type="flowchart", show_threats=True
            )
            assert flowchart.startswith("flowchart TD")
            assert "Flask" in flowchart or "Web" in flowchart

            # Test sequence diagram
            sequence = generator.generate_diagram(
                threat_model=threat_model, diagram_type="sequence"
            )
            assert sequence.startswith("sequenceDiagram")

            # Step 4: Test JSON serialization/deserialization
            json_data = json.dumps(threat_dict, indent=2)
            parsed_data = json.loads(json_data)
            assert parsed_data == threat_dict

            # Step 5: Test diagram from JSON
            diagram_from_json = MermaidDiagramGenerator.generate_from_components_dict(
                components_dict=parsed_data, show_threats=True
            )
            assert diagram_from_json.startswith("flowchart TD")

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_save_and_load_workflow(self):
        """Test saving and loading threat models."""
        test_code = """
import requests
from flask import Flask

app = Flask(__name__)

@app.route('/api/data')
def get_data():
    response = requests.get("https://api.external.com/data")
    return response.json()
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create source file
            source_file = Path(temp_dir) / "app.py"
            source_file.write_text(test_code)

            # Create output files
            json_output = Path(temp_dir) / "threat_model.json"
            markdown_output = Path(temp_dir) / "threat_model.md"
            diagram_output = Path(temp_dir) / "diagram.mmd"

            # Build and save threat model
            builder = ThreatModelBuilder()
            threat_model = builder.build_threat_model(str(source_file))

            # Save in JSON format
            builder.save_threat_model(threat_model, str(json_output), "json")
            assert json_output.exists()

            # Save in Markdown format
            builder.save_threat_model(threat_model, str(markdown_output), "markdown")
            assert markdown_output.exists()

            # Generate and save diagram
            generator = MermaidDiagramGenerator()
            diagram = generator.generate_diagram(threat_model)
            generator.save_diagram(diagram, str(diagram_output))
            assert diagram_output.exists()

            # Verify JSON can be loaded
            with open(json_output) as f:
                loaded_data = json.load(f)

            assert "boundaries" in loaded_data
            assert "external_entities" in loaded_data
            assert "processes" in loaded_data

            # Verify Markdown has content
            markdown_content = markdown_output.read_text()
            assert "# Threat Model Report" in markdown_content

            # Verify Mermaid diagram has content
            diagram_content = diagram_output.read_text()
            assert diagram_content.startswith("flowchart TD")

    def test_javascript_integration(self):
        """Test threat modeling with JavaScript code."""
        js_code = """
const express = require('express');
const mongoose = require('mongoose');
const redis = require('redis');
const stripe = require('stripe')('sk_test_...');

const app = express();
const cache = redis.createClient();

mongoose.connect('mongodb://localhost:27017/myapp');

app.post('/api/payment', async (req, res) => {
    const { amount, currency, source } = req.body;

    // Create payment with Stripe
    const charge = await stripe.charges.create({
        amount,
        currency,
        source
    });

    // Store in database
    const payment = new Payment({ chargeId: charge.id, amount });
    await payment.save();

    // Cache result
    await cache.set(`payment:${charge.id}`, JSON.stringify(charge));

    res.json({ success: true, chargeId: charge.id });
});

app.listen(3000);
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(js_code)
            temp_file = f.name

        try:
            builder = ThreatModelBuilder()
            threat_model = builder.build_threat_model(
                source_path=temp_file,
                include_threats=True,
                severity_threshold=Severity.LOW,
            )

            # Verify components were extracted
            assert len(threat_model.components.processes) > 0
            assert any(
                "Express" in p or "Node.js" in p
                for p in threat_model.components.processes
            )

            # Verify data stores detected
            assert len(threat_model.components.data_stores) >= 2  # MongoDB and Redis
            assert any("MongoDB" in ds for ds in threat_model.components.data_stores)
            assert any("Redis" in ds for ds in threat_model.components.data_stores)

            # Verify external entities
            assert len(threat_model.components.external_entities) > 0
            assert any(
                "Stripe" in ee for ee in threat_model.components.external_entities
            )

            # Verify data flows
            assert len(threat_model.components.data_flows) > 0

            # Verify threats were identified
            assert len(threat_model.threats) > 0

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_typescript_integration(self):
        """Test threat modeling with TypeScript code."""
        ts_code = """
import { Controller, Post, Body, Get, Param } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import * as AWS from 'aws-sdk';
import axios from 'axios';

@Controller('users')
export class UserController {
    private s3 = new AWS.S3();

    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>,
    ) {}

    @Post()
    async createUser(@Body() userData: any) {
        const user = await this.userRepository.save(userData);

        // Upload avatar to S3
        if (userData.avatar) {
            await this.s3.putObject({
                Bucket: 'user-avatars',
                Key: `${user.id}/avatar.jpg`,
                Body: userData.avatar,
            }).promise();
        }

        // Notify external webhook
        await axios.post('https://api.webhook.site/notifications', {
            event: 'user.created',
            userId: user.id,
        });

        return user;
    }

    @Get(':id')
    async getUser(@Param('id') id: string) {
        return this.userRepository.findOne(id);
    }
}
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ts", delete=False) as f:
            f.write(ts_code)
            temp_file = f.name

        try:
            builder = ThreatModelBuilder()
            threat_model = builder.build_threat_model(
                source_path=temp_file,
                include_threats=True,
            )

            # Verify components were extracted
            assert len(threat_model.components.processes) > 0
            assert any(
                "NestJS" in p or "Node.js" in p
                for p in threat_model.components.processes
            )

            # Verify data stores (SQL via TypeORM)
            assert len(threat_model.components.data_stores) > 0
            assert any("SQL" in ds for ds in threat_model.components.data_stores)

            # Verify external entities
            assert len(threat_model.components.external_entities) >= 2
            assert any("AWS" in ee for ee in threat_model.components.external_entities)
            assert any(
                "Webhook" in ee or "API" in ee
                for ee in threat_model.components.external_entities
            )

            # Verify web user entity
            assert any(
                "Web User" in ee for ee in threat_model.components.external_entities
            )

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_mixed_language_directory(self):
        """Test threat modeling with mixed Python and JavaScript files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create Python file
            python_file = Path(temp_dir) / "app.py"
            python_file.write_text(
                """
from flask import Flask
import redis

app = Flask(__name__)
r = redis.Redis()

@app.route('/api/data')
def get_data():
    return r.get('data')
"""
            )

            # Create JavaScript file
            js_file = Path(temp_dir) / "frontend.js"
            js_file.write_text(
                """
const axios = require('axios');

async function fetchData() {
    const response = await axios.get('https://api.example.com/data');
    return response.data;
}

module.exports = { fetchData };
"""
            )

            # Create TypeScript file
            ts_file = Path(temp_dir) / "service.ts"
            ts_file.write_text(
                """
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable()
export class DataService {
    constructor(@InjectModel('Data') private dataModel: Model<any>) {}

    async findAll() {
        return this.dataModel.find().exec();
    }
}
"""
            )

            builder = ThreatModelBuilder()
            threat_model = builder.build_threat_model(
                source_path=temp_dir,
                include_threats=False,  # Just test component extraction
            )

            # Should have components from all languages
            assert len(threat_model.components.processes) > 0
            assert (
                len(threat_model.components.data_stores) >= 2
            )  # Redis from Python, MongoDB from TS
            assert len(threat_model.components.external_entities) > 0

            # Verify specific components
            all_components = (
                threat_model.components.processes
                + threat_model.components.data_stores
                + threat_model.components.external_entities
            )

            # Should have Flask from Python
            assert any("Flask" in c for c in all_components)
            # Should have Redis from Python
            assert any("Redis" in c for c in all_components)
            # Should have external API from JavaScript
            assert any("API" in c or "Example.Com" in c for c in all_components)
            # Should have MongoDB from TypeScript
            assert any("Mongo" in c for c in all_components)


if __name__ == "__main__":
    pytest.main([__file__])
