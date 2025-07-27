"""Tests for LLM-enhanced threat modeling functionality."""

import json

import pytest

from src.adversary_mcp_server.threat_modeling.llm_modeler import (
    LLMThreatModeler,
    ThreatModelingPrompt,
)
from src.adversary_mcp_server.threat_modeling.models import (
    ComponentType,
    Severity,
    Threat,
    ThreatModel,
    ThreatModelComponents,
    ThreatType,
)


@pytest.fixture
def sample_threat_model():
    """Create a sample threat model for testing."""
    components = ThreatModelComponents()
    components.add_component("Web App", ComponentType.PROCESS, exposed=True)
    components.add_component("Database", ComponentType.DATA_STORE)
    components.add_component("User", ComponentType.EXTERNAL_ENTITY)
    components.add_data_flow("User", "Web App", "HTTPS", data_type="user_data")
    components.add_data_flow("Web App", "Database", "SQL", data_type="queries")

    # Add some base threats
    base_threat = Threat(
        threat_type=ThreatType.TAMPERING,
        component="Web App",
        title="SQL Injection",
        description="User input not properly sanitized",
        severity=Severity.HIGH,
        mitigation="Use parameterized queries",
    )

    threat_model = ThreatModel(
        components=components,
        threats=[base_threat],
        metadata={"source_path": "/test/app", "analysis_type": "STRIDE"},
    )

    return threat_model


@pytest.fixture
def llm_modeler():
    """Create an LLM threat modeler instance."""
    return LLMThreatModeler()


class TestLLMThreatModeler:
    """Test cases for LLMThreatModeler."""

    def test_initialization(self):
        """Test proper initialization of LLMThreatModeler."""
        modeler = LLMThreatModeler()
        assert modeler.is_available() is True
        status = modeler.get_status()
        assert status["available"] is True
        assert status["mode"] == "client-based"

    def test_create_threat_modeling_prompts(self, llm_modeler, sample_threat_model):
        """Test creation of threat modeling prompts."""
        # Create prompts
        prompts = llm_modeler.create_threat_modeling_prompts(
            sample_threat_model, "/test/app", "test code context"
        )

        # Verify prompts were created
        assert (
            len(prompts) == 4
        )  # Business logic, data flow, attack surface, contextual

        # Check prompt types
        analysis_types = [p.analysis_type for p in prompts]
        expected_types = [
            "business_logic",
            "data_flow_analysis",
            "attack_surface_analysis",
            "contextual_enhancement",
        ]
        for expected_type in expected_types:
            assert expected_type in analysis_types

        # Verify prompt structure
        for prompt in prompts:
            assert isinstance(prompt, ThreatModelingPrompt)
            assert prompt.system_prompt
            assert prompt.user_prompt
            assert prompt.source_path == "/test/app"
            assert prompt.metadata

            # Check that prompt contains relevant context
            assert "Web App" in prompt.user_prompt
            assert "Database" in prompt.user_prompt

    def test_business_logic_prompt_creation(self, llm_modeler, sample_threat_model):
        """Test business logic threat analysis prompt creation."""
        prompts = llm_modeler.create_threat_modeling_prompts(
            sample_threat_model, "/test/app", "test code context"
        )

        # Find the business logic prompt
        business_logic_prompt = None
        for prompt in prompts:
            if prompt.analysis_type == "business_logic":
                business_logic_prompt = prompt
                break

        assert business_logic_prompt is not None
        assert "business logic vulnerabilities" in business_logic_prompt.system_prompt
        assert "Web App" in business_logic_prompt.user_prompt
        assert "Database" in business_logic_prompt.user_prompt

    def test_data_flow_prompt_creation(self, llm_modeler, sample_threat_model):
        """Test data flow analysis prompt creation."""
        prompts = llm_modeler.create_threat_modeling_prompts(
            sample_threat_model, "/test/app", "test code context"
        )

        # Find the data flow prompt
        data_flow_prompt = None
        for prompt in prompts:
            if prompt.analysis_type == "data_flow_analysis":
                data_flow_prompt = prompt
                break

        assert data_flow_prompt is not None
        assert "data flow" in data_flow_prompt.system_prompt
        assert "trust boundary" in data_flow_prompt.system_prompt

    def test_parse_threat_modeling_response_json(self, llm_modeler):
        """Test parsing valid JSON threat response."""
        json_response = json.dumps(
            {
                "threats": [
                    {
                        "type": "spoofing",
                        "title": "Test Threat",
                        "description": "Test description",
                        "severity": "high",
                        "component": "Test Component",
                        "mitigation": "Test mitigation",
                    }
                ]
            }
        )

        threats = llm_modeler.parse_threat_modeling_response(json_response, "test")

        assert len(threats) == 1
        threat = threats[0]
        assert threat.title == "Test Threat"
        assert threat.severity == Severity.HIGH
        assert threat.threat_type == ThreatType.SPOOFING
        assert "LLM Analysis (test)" in threat.references

    def test_parse_threat_modeling_response_invalid_json(self, llm_modeler):
        """Test parsing invalid JSON response."""
        invalid_response = "This is not JSON at all"

        threats = llm_modeler.parse_threat_modeling_response(invalid_response, "test")

        # Should return empty list for invalid JSON
        assert len(threats) == 0

    def test_filter_by_severity(self, llm_modeler):
        """Test severity filtering."""
        threats = [
            Threat(
                threat_type=ThreatType.TAMPERING,
                component="Test",
                title="Low Threat",
                description="Low severity",
                severity=Severity.LOW,
            ),
            Threat(
                threat_type=ThreatType.TAMPERING,
                component="Test",
                title="High Threat",
                description="High severity",
                severity=Severity.HIGH,
            ),
            Threat(
                threat_type=ThreatType.TAMPERING,
                component="Test",
                title="Critical Threat",
                description="Critical severity",
                severity=Severity.CRITICAL,
            ),
        ]

        # Filter by medium threshold
        filtered = llm_modeler._filter_by_severity(threats, "medium")
        assert len(filtered) == 2  # High and Critical should remain

        # Filter by high threshold
        filtered = llm_modeler._filter_by_severity(threats, "high")
        assert len(filtered) == 2  # High and Critical should remain

        # Filter by critical threshold
        filtered = llm_modeler._filter_by_severity(threats, "critical")
        assert len(filtered) == 1  # Only Critical should remain

    def test_merge_threat_responses(self, llm_modeler, sample_threat_model):
        """Test merging of LLM threat analysis responses."""
        # Mock LLM responses
        responses = [
            (
                "business_logic",
                json.dumps(
                    {
                        "threats": [
                            {
                                "type": "tampering",
                                "title": "Race Condition",
                                "description": "Concurrent access issue",
                                "severity": "medium",
                                "component": "Web App",
                                "mitigation": "Use proper locking",
                            }
                        ]
                    }
                ),
            ),
            (
                "data_flow_analysis",
                json.dumps(
                    {
                        "threats": [
                            {
                                "type": "information_disclosure",
                                "title": "Data Leakage",
                                "description": "Sensitive data exposed",
                                "severity": "high",
                                "component": "Database",
                                "mitigation": "Encrypt sensitive data",
                            }
                        ]
                    }
                ),
            ),
        ]

        # Merge responses
        enhanced_model = llm_modeler.merge_threat_responses(
            sample_threat_model, responses
        )

        # Verify merge
        assert len(enhanced_model.threats) == 3  # 1 original + 2 LLM threats
        assert enhanced_model.metadata["llm_enhanced"] is True
        assert enhanced_model.metadata["llm_threats_added"] == 2
        assert enhanced_model.metadata["llm_analysis_count"] == 2

        # Check that LLM threats were added
        llm_threats = [
            t for t in enhanced_model.threats if "LLM Analysis" in str(t.references)
        ]
        assert len(llm_threats) == 2

    def test_extract_code_context_file(self, llm_modeler, tmp_path):
        """Test extracting code context from a file."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_content = "def vulnerable_function():\n    return user_input"
        test_file.write_text(test_content)

        context = llm_modeler._extract_code_context(str(test_file))

        assert test_content in context
        assert len(context) <= 10000  # Should be limited

    def test_extract_code_context_directory(self, llm_modeler, tmp_path):
        """Test extracting code context from a directory."""
        # Create test files
        (tmp_path / "app.py").write_text("print('Hello World')")
        (tmp_path / "models.py").write_text("class User: pass")

        context = llm_modeler._extract_code_context(str(tmp_path))

        assert "app.py" in context
        assert "Hello World" in context
        assert len(context) <= 10000  # Should be limited

    def test_prepare_analysis_context(self, llm_modeler, sample_threat_model):
        """Test preparation of analysis context data."""
        context = llm_modeler._prepare_analysis_context(
            sample_threat_model, "test code content"
        )

        assert "code_context" in context
        assert "components_summary" in context
        assert "data_flows" in context
        assert "existing_threats" in context

        assert context["code_context"] == "test code content"
        assert len(context["data_flows"]) == 2  # Two flows in sample model
        assert len(context["existing_threats"]) == 1  # One threat in sample model

    def test_summarize_components(self, llm_modeler, sample_threat_model):
        """Test component summarization for LLM context."""
        summary = llm_modeler._summarize_components(sample_threat_model.components)

        assert "Processes: Web App" in summary
        assert "Data Stores: Database" in summary
        assert "External Entities: User" in summary
