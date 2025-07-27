"""Simplified tests for LLM-enhanced threat modeling functionality."""

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


class TestLLMThreatModeler:
    """Test cases for LLMThreatModeler."""

    def test_initialization(self):
        """Test proper initialization of LLMThreatModeler."""
        modeler = LLMThreatModeler()
        assert modeler.is_available() is True
        status = modeler.get_status()
        assert status["available"] is True
        assert status["mode"] == "client-based"

    def test_create_threat_modeling_prompts(self, sample_threat_model):
        """Test creation of threat modeling prompts."""
        modeler = LLMThreatModeler()

        # Create prompts
        prompts = modeler.create_threat_modeling_prompts(
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

            # Verify prompt can be serialized
            prompt_dict = prompt.to_dict()
            assert "system_prompt" in prompt_dict
            assert "user_prompt" in prompt_dict
            assert "analysis_type" in prompt_dict

    def test_parse_threat_modeling_response(self):
        """Test parsing of LLM threat modeling responses."""
        modeler = LLMThreatModeler()

        # Mock LLM response
        mock_response = json.dumps(
            {
                "threats": [
                    {
                        "type": "elevation_of_privilege",
                        "title": "Authorization Bypass",
                        "description": "Business logic flaw allows privilege escalation",
                        "severity": "high",
                        "component": "Web App",
                        "likelihood": "medium",
                        "impact": "high",
                        "mitigation": "Implement proper authorization checks",
                        "cwe_id": "CWE-269",
                    }
                ]
            }
        )

        # Parse response
        threats = modeler.parse_threat_modeling_response(
            mock_response, "business_logic"
        )

        # Verify parsing
        assert len(threats) == 1
        threat = threats[0]
        assert threat.title == "Authorization Bypass"
        assert threat.severity == Severity.HIGH
        assert threat.component == "Web App"
        assert threat.threat_type == ThreatType.ELEVATION_OF_PRIVILEGE
        assert "LLM Analysis (business_logic)" in threat.references

    def test_merge_threat_responses(self, sample_threat_model):
        """Test merging of LLM threat analysis responses."""
        modeler = LLMThreatModeler()

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
        enhanced_model = modeler.merge_threat_responses(sample_threat_model, responses)

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

    def test_filter_by_severity(self):
        """Test severity filtering."""
        modeler = LLMThreatModeler()

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
        filtered = modeler._filter_by_severity(threats, "medium")
        assert len(filtered) == 2  # High and Critical should remain

        # Filter by high threshold
        filtered = modeler._filter_by_severity(threats, "high")
        assert len(filtered) == 2  # High and Critical should remain

        # Filter by critical threshold
        filtered = modeler._filter_by_severity(threats, "critical")
        assert len(filtered) == 1  # Only Critical should remain

    def test_prepare_analysis_context(self, sample_threat_model):
        """Test preparation of analysis context data."""
        modeler = LLMThreatModeler()

        context = modeler._prepare_analysis_context(
            sample_threat_model, "test code content"
        )

        assert "code_context" in context
        assert "components_summary" in context
        assert "data_flows" in context
        assert "existing_threats" in context

        assert context["code_context"] == "test code content"
        assert len(context["data_flows"]) == 2  # Two flows in sample model
        assert len(context["existing_threats"]) == 1  # One threat in sample model

    def test_summarize_components(self, sample_threat_model):
        """Test component summarization for LLM context."""
        modeler = LLMThreatModeler()

        summary = modeler._summarize_components(sample_threat_model.components)

        assert "Processes: Web App" in summary
        assert "Data Stores: Database" in summary
        assert "External Entities: User" in summary

    def test_extract_code_context_file(self, tmp_path):
        """Test extracting code context from a file."""
        modeler = LLMThreatModeler()

        # Create test file
        test_file = tmp_path / "test.py"
        test_content = "def vulnerable_function():\n    return user_input"
        test_file.write_text(test_content)

        context = modeler._extract_code_context(str(test_file))

        assert test_content in context
        assert len(context) <= 10000  # Should be limited

    def test_extract_code_context_directory(self, tmp_path):
        """Test extracting code context from a directory."""
        modeler = LLMThreatModeler()

        # Create test files
        (tmp_path / "app.py").write_text("print('Hello World')")
        (tmp_path / "models.py").write_text("class User: pass")

        context = modeler._extract_code_context(str(tmp_path))

        assert "app.py" in context
        assert "Hello World" in context
        assert len(context) <= 10000  # Should be limited

    def test_parse_invalid_json_response(self):
        """Test parsing invalid JSON response."""
        modeler = LLMThreatModeler()

        invalid_response = "This is not JSON at all"

        threats = modeler.parse_threat_modeling_response(invalid_response, "test")

        # Should return empty list for invalid JSON
        assert len(threats) == 0
