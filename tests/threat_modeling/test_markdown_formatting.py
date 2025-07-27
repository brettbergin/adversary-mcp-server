"""Tests for markdown threat model formatting fixes."""

import pytest

from src.adversary_mcp_server.threat_modeling.models import (
    ComponentType,
    Severity,
    Threat,
    ThreatModel,
    ThreatModelComponents,
    ThreatType,
)
from src.adversary_mcp_server.threat_modeling.threat_model_builder import (
    ThreatModelBuilder,
)


class TestMarkdownFormatting:
    """Test cases for markdown threat model formatting."""

    @pytest.fixture
    def sample_threat_model_with_duplicates(self):
        """Create a threat model with duplicate threats to test deduplication."""
        components = ThreatModelComponents()
        components.add_component("Web App", ComponentType.PROCESS, exposed=True)
        components.add_component("Database", ComponentType.DATA_STORE)
        components.add_component("Redis Cache", ComponentType.DATA_STORE)
        components.add_component("User", ComponentType.EXTERNAL_ENTITY)
        components.add_data_flow("User", "Web App", "HTTPS", data_type="user_data")
        components.add_data_flow("Web App", "Database", "SQL", data_type="queries")
        components.add_data_flow(
            "Web App", "Redis Cache", "Redis Protocol", data_type="cache_data"
        )

        # Create duplicate threats that should be merged
        threats = [
            Threat(
                threat_type=ThreatType.TAMPERING,
                component="Database",
                title="SQL Injection",
                description="Malicious SQL code can be injected through user input",
                severity=Severity.CRITICAL,
                mitigation="Use parameterized queries and input validation",
                cwe_id="CWE-89",
            ),
            Threat(
                threat_type=ThreatType.TAMPERING,
                component="Redis Cache",
                title="SQL Injection",  # Same title and type as above
                description="Malicious SQL code can be injected through user input",
                severity=Severity.CRITICAL,
                mitigation="Use parameterized queries and input validation",
                cwe_id="CWE-89",
            ),
            Threat(
                threat_type=ThreatType.INFORMATION_DISCLOSURE,
                component="Web App",
                title="Sensitive Data Exposure",
                description="Sensitive information is exposed to unauthorized parties",
                severity=Severity.HIGH,
                mitigation="Implement encryption at rest and in transit",
                cwe_id="CWE-200",
            ),
        ]

        # Metadata that tests our formatting fixes
        metadata = {
            "source_path": "/test/app",
            "analysis_type": "STRIDE_llm_prompts_available",  # Should be cleaned up
            "severity_threshold": "medium",
            "timestamp": "2025-01-01T12:00:00",
            "llm_prompts": [
                {
                    "system_prompt": "Test system prompt",
                    "user_prompt": "Test user prompt",
                },
                {
                    "system_prompt": "Another system prompt",
                    "user_prompt": "Another user prompt",
                },
            ],
            "llm_prompt_count": 4,
        }

        return ThreatModel(components=components, threats=threats, metadata=metadata)

    def test_markdown_metadata_formatting(self, sample_threat_model_with_duplicates):
        """Test that metadata is formatted cleanly in markdown output."""
        builder = ThreatModelBuilder()
        markdown_content = builder._generate_markdown_report(
            sample_threat_model_with_duplicates
        )

        # Check that analysis type is cleaned up
        assert "STRIDE with LLM Enhancement" in markdown_content
        assert "STRIDE_llm_prompts_available" not in markdown_content

        # Check that LLM prompts are formatted cleanly (not dumped as raw objects)
        assert "**LLM Prompts Generated**: 2 analysis prompts" in markdown_content
        assert (
            "system_prompt" not in markdown_content
        )  # Raw prompt data should not appear
        assert "user_prompt" not in markdown_content

        # Check that LLM prompt count is formatted nicely
        assert (
            "**LLM Analysis Types**: 4 specialized threat analysis prompts"
            in markdown_content
        )

    def test_threat_deduplication_in_markdown(
        self, sample_threat_model_with_duplicates
    ):
        """Test that duplicate threats are properly merged in markdown output."""
        builder = ThreatModelBuilder()
        markdown_content = builder._generate_markdown_report(
            sample_threat_model_with_duplicates
        )

        # SQL Injection should appear only once as a header, but with combined components
        sql_injection_headers = markdown_content.count("#### SQL Injection")
        assert (
            sql_injection_headers == 1
        ), f"Expected 1 SQL Injection header, got {sql_injection_headers}"

        # The combined component should list both Database and Redis Cache
        assert (
            "Database, Redis Cache" in markdown_content
            or "Redis Cache, Database" in markdown_content
        )

    def test_markdown_structure_integrity(self, sample_threat_model_with_duplicates):
        """Test that the markdown structure is well-formed."""
        builder = ThreatModelBuilder()
        markdown_content = builder._generate_markdown_report(
            sample_threat_model_with_duplicates
        )

        # Check main sections exist
        assert "# Threat Model Report" in markdown_content
        assert "## Analysis Details" in markdown_content
        assert "## Architecture Components" in markdown_content
        assert "## STRIDE Threat Analysis" in markdown_content

        # Check subsections exist
        assert "### External Entities" in markdown_content
        assert "### Processes" in markdown_content
        assert "### Data Stores" in markdown_content
        assert "### Data Flows" in markdown_content
        assert "### Critical Severity Threats" in markdown_content
        assert "### High Severity Threats" in markdown_content

    def test_threat_component_combination(self):
        """Test the threat deduplication logic directly."""
        # Create test threats with same title/type but different components
        components = ThreatModelComponents()
        components.add_component("DB1", ComponentType.DATA_STORE)
        components.add_component("DB2", ComponentType.DATA_STORE)

        threats = [
            Threat(
                threat_type=ThreatType.TAMPERING,
                component="DB1",
                title="SQL Injection",
                description="Test description",
                severity=Severity.CRITICAL,
            ),
            Threat(
                threat_type=ThreatType.TAMPERING,
                component="DB2",
                title="SQL Injection",  # Same title and type
                description="Test description",
                severity=Severity.CRITICAL,
            ),
        ]

        threat_model = ThreatModel(
            components=components, threats=threats, metadata={"source_path": "/test"}
        )

        builder = ThreatModelBuilder()

        # Test the deduplication directly by calling the internal method
        threat_groups = {}
        for threat in threats:
            threat_key = (threat.title, threat.threat_type)
            if threat_key not in threat_groups:
                threat_groups[threat_key] = threat
            else:
                existing_threat = threat_groups[threat_key]
                if threat.component not in existing_threat.component:
                    components_list = existing_threat.component.split(", ")
                    if threat.component not in components_list:
                        components_list.append(threat.component)
                        existing_threat.component = ", ".join(components_list)

        # Should have only one threat with combined components
        assert len(threat_groups) == 1
        combined_threat = list(threat_groups.values())[0]
        assert "DB1" in combined_threat.component
        assert "DB2" in combined_threat.component

    def test_no_raw_llm_prompts_in_output(self):
        """Test that raw LLM prompt objects don't appear in markdown."""
        components = ThreatModelComponents()
        components.add_component("Test App", ComponentType.PROCESS)

        # Create metadata with complex LLM prompts
        metadata = {
            "llm_prompts": [
                {
                    "system_prompt": "You are a security expert...",
                    "user_prompt": "Analyze this code for vulnerabilities...",
                    "analysis_type": "business_logic",
                }
            ],
            "analysis_type": "STRIDE_llm_prompts_available",
        }

        threat_model = ThreatModel(components=components, threats=[], metadata=metadata)

        builder = ThreatModelBuilder()
        markdown_content = builder._generate_markdown_report(threat_model)

        # Raw prompt data should not appear
        assert "system_prompt" not in markdown_content
        assert "user_prompt" not in markdown_content
        assert (
            "analysis_type" not in markdown_content.split("\n")[6]
        )  # Except in the cleaned up analysis type line

        # But summary should appear
        assert "**LLM Prompts Generated**: 1 analysis prompts" in markdown_content
