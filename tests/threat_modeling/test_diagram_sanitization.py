"""Comprehensive tests for diagram sanitization logic.

This module contains tests for the sanitization fixes that prevent
Mermaid syntax errors in generated diagrams, specifically addressing
issues like line breaks in participant names.
"""

import pytest

from adversary_mcp_server.threat_modeling.diagram_generator import (
    MermaidDiagramGenerator,
)
from adversary_mcp_server.threat_modeling.extractors.base_extractor import BaseExtractor
from adversary_mcp_server.threat_modeling.models import (
    DataFlow,
    ThreatModel,
    ThreatModelComponents,
)


class TestDiagramSanitization:
    """Test sanitization of component names in diagram generation."""

    def test_sequence_diagram_line_break_regression(self):
        """Regression test for the specific 'Test.Com API' line break issue."""
        # This is the exact scenario that caused the original syntax error
        components = ThreatModelComponents()

        # Add the problematic component name that was causing line breaks
        components.data_flows = [
            DataFlow(
                "Django App", "Test.Com\n API", "HTTP"
            ),  # Simulated line break issue
            DataFlow("Test.Com\n API", "Django App", "HTTP"),
        ]

        threat_model = ThreatModel(components=components)
        generator = MermaidDiagramGenerator()

        diagram = generator.generate_diagram(
            threat_model=threat_model, diagram_type="sequence"
        )

        # Verify no syntax errors in the generated diagram
        lines = diagram.split("\n")
        for line in lines:
            if "participant" in line and "Test" in line:
                # Should not contain the problematic line break syntax
                assert "Test.Com\n API" not in line
                # Should be properly sanitized
                assert "Test.Com API" in line or "Test Com API" in line

    def test_extreme_sanitization_cases(self):
        """Test edge cases that could break diagram generation."""
        generator = MermaidDiagramGenerator()

        extreme_cases = [
            # Various types of whitespace and special characters
            "Test\n\r\t API\n\n",
            "API\x00With\x01Control\x02Chars",
            "🚀 Emoji API 🎯",
            "API with \"quotes\" and 'apostrophes'",
            "Multi\nLine\nAPI\nName",
            "   \n\n\t\r   ",  # Only whitespace
            "A" * 200,  # Very long name
            "CamelCaseAPIWithVeryLongNameThatExceedsReasonableLimits",
        ]

        for test_input in extreme_cases:
            result = generator._sanitize_display_name(test_input)

            # Should not contain problematic characters
            assert "\n" not in result
            assert "\r" not in result
            assert "\x00" not in result

            # Should not be excessively long
            assert len(result) <= 53  # 50 + "..."

            # Should handle empty/whitespace-only input gracefully
            if not test_input.strip():
                assert result == ""

    def test_url_extraction_sanitization_edge_cases(self):
        """Test URL extraction with complex domain names."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Test problematic URLs that could generate bad component names
        problematic_urls = [
            "https://test.com.evil.domain.co.uk/api",
            "https://api-v2.test-company.co.uk/v1",
            "https://subdomain.test.internal.domain.com",
            "https://123.456.789.0/api",  # IP address
            "https://test_underscore.domain.com",
            "https://test--double-dash.com",
            "https://test..double.dot..com",
        ]

        for url in problematic_urls:
            result = extractor._extract_external_entity_from_url(url)

            if result:  # Skip None results
                # Should not contain problematic characters for Mermaid
                assert "\n" not in result
                assert "\r" not in result

                # Should end with 'API'
                assert result.endswith(" API")

                # Should not have excessive punctuation
                assert ".." not in result
                assert "--" not in result

    def test_mermaid_syntax_validation(self):
        """Test that generated diagrams follow valid Mermaid syntax."""
        components = ThreatModelComponents()

        # Create a complex scenario with potentially problematic names
        problematic_names = [
            "API-Gateway",
            "User.Interface",
            "Database_Store",
            "External\nAPI",  # This would break without sanitization
            "Service with spaces",
            "123-numeric-service",
        ]

        for i, name in enumerate(problematic_names):
            if i % 2 == 0:
                components.external_entities.append(name)
            else:
                components.processes.append(name)

        # Add flows between these components
        for i in range(len(problematic_names) - 1):
            source = problematic_names[i]
            target = problematic_names[i + 1]
            components.data_flows.append(DataFlow(source, target, "HTTP"))

        threat_model = ThreatModel(components=components)
        generator = MermaidDiagramGenerator()

        # Test all diagram types
        for diagram_type in ["flowchart", "graph", "sequence"]:
            diagram = generator.generate_diagram(
                threat_model=threat_model, diagram_type=diagram_type
            )

            # Basic syntax validation
            if diagram_type == "sequence":
                assert diagram.startswith("sequenceDiagram")
                # Check participant syntax
                lines = diagram.split("\n")
                participant_lines = [line for line in lines if "participant" in line]
                for line in participant_lines:
                    # Must follow pattern: participant ID as DisplayName
                    parts = line.strip().split(" as ")
                    assert len(parts) == 2, f"Invalid participant syntax: {line}"
                    assert (
                        "participant " in parts[0]
                    ), f"Missing participant keyword: {line}"
                    assert parts[1].strip(), f"Empty display name: {line}"
            else:
                assert diagram.startswith(f"{diagram_type} ")

    def test_component_name_consistency(self):
        """Test that component names are consistently sanitized across all operations."""
        generator = MermaidDiagramGenerator()

        # Test the same problematic name through different methods
        problematic_name = "Test.Com\nAPI Service"

        # Test ID sanitization
        sanitized_id = generator._sanitize_id(problematic_name)
        assert "\n" not in sanitized_id
        assert "." not in sanitized_id  # Should be replaced with _

        # Test display name sanitization
        sanitized_display = generator._sanitize_display_name(problematic_name)
        assert "\n" not in sanitized_display
        assert (
            sanitized_display == "Test.Com API Service"
        )  # Dots OK in display, line breaks removed

        # Both should be valid for their intended use
        assert (
            sanitized_id.replace("_", "").replace("node", "").isalnum()
            or sanitized_id == "node_1"
        )
        assert len(sanitized_display) <= 50

    def test_real_world_domain_sanitization(self):
        """Test sanitization with real-world domain patterns."""

        class TestExtractor(BaseExtractor):
            def extract_components(
                self, code: str, file_path: str
            ) -> ThreatModelComponents:
                return ThreatModelComponents()

            def get_supported_extensions(self) -> set[str]:
                return {".test"}

        extractor = TestExtractor()

        # Real domain patterns that could be problematic
        real_world_cases = [
            ("https://docs.sourcemod.net/api", "Docs Sourcemod Net API"),
            ("https://encoding.spec.whatwg.org/api", "Encoding Spec Whatwg Org API"),
            ("https://test.pypi.org/api", "Test Pypi Org API"),
            (
                "https://api.github-enterprise.company.com",
                "Github Enterprise Company Com API",
            ),
            ("https://v2.api.complex-domain.co.uk", "V2 Complex Domain Co Uk API"),
        ]

        for url, expected in real_world_cases:
            result = extractor._extract_external_entity_from_url(url)
            assert (
                result == expected
            ), f"URL {url} should produce '{expected}', got '{result}'"

    def test_empty_and_none_handling(self):
        """Test handling of empty, None, and edge case inputs."""
        generator = MermaidDiagramGenerator()

        # Test _sanitize_display_name with edge cases
        edge_cases = [
            ("", ""),
            (None, ""),  # Should handle None gracefully
            ("   ", ""),  # Only whitespace
            ("\n\r\t", ""),  # Only control characters
        ]

        for input_val, expected in edge_cases:
            if input_val is None:
                # Handle None case separately since it might raise TypeError
                try:
                    result = generator._sanitize_display_name(input_val)
                    assert result == expected
                except (TypeError, AttributeError):
                    # It's acceptable to raise an error for None input
                    pass
            else:
                result = generator._sanitize_display_name(input_val)
                assert result == expected

    def test_integration_sequence_diagram_end_to_end(self):
        """Integration test: full sequence diagram generation with problematic inputs."""
        # Create a realistic but problematic scenario
        components = ThreatModelComponents()

        # This mimics the actual badapp scenario that caused the original issue
        entities_and_flows = [
            ("Web User", "Django App", "HTTPS"),
            ("Django App", "Database", "SQL"),
            ("Django App", "Test.Com\n API", "HTTP"),  # The problematic one
            ("Django App", "Example.Org?Foo=Bar#Header API", "HTTPS"),
            ("Django App", "Docs.Sourcemod.Net API", "HTTP"),
        ]

        # Add all components
        for source, target, protocol in entities_and_flows:
            if (
                source not in components.external_entities
                and source not in components.processes
            ):
                if "Django" in source or "App" in source:
                    components.processes.append(source)
                elif "Database" in source:
                    components.data_stores.append(source)
                else:
                    components.external_entities.append(source)

            if (
                target not in components.external_entities
                and target not in components.processes
                and target not in components.data_stores
            ):
                if "Django" in target or "App" in target:
                    components.processes.append(target)
                elif "Database" in target:
                    components.data_stores.append(target)
                else:
                    components.external_entities.append(target)

            components.data_flows.append(DataFlow(source, target, protocol))

        threat_model = ThreatModel(components=components)
        generator = MermaidDiagramGenerator()

        # Generate the diagram
        diagram = generator.generate_diagram(
            threat_model=threat_model, diagram_type="sequence", show_threats=True
        )

        # Comprehensive validation
        assert diagram.startswith("sequenceDiagram")

        # Split into lines and validate each
        lines = diagram.split("\n")

        # Check participant declarations
        participant_lines = [
            line.strip() for line in lines if line.strip().startswith("participant")
        ]
        assert len(participant_lines) > 0, "Should have participant declarations"

        for line in participant_lines:
            # Each line should be complete (no broken syntax)
            assert " as " in line, f"Participant line missing ' as ': {line}"
            parts = line.split(" as ")
            assert len(parts) == 2, f"Malformed participant line: {line}"

            # Display name should be sanitized
            display_name = parts[1].strip()
            assert (
                "\n" not in display_name
            ), f"Line break in display name: {display_name}"
            assert (
                "\r" not in display_name
            ), f"Carriage return in display name: {display_name}"

        # Check interaction lines
        interaction_lines = [
            line.strip() for line in lines if "->>" in line or "-->" in line
        ]
        assert len(interaction_lines) > 0, "Should have interaction lines"

        # Should contain our problematic entities in sanitized form
        diagram_text = " ".join(lines)
        assert "Test Com API" in diagram_text or "Test.Com API" in diagram_text
        # The complex URL becomes a component name, check for sanitization
        assert (
            "Example.Org?Foo=Bar#Header API" in diagram_text
            or "Example Org" in diagram_text
        )

        print(f"Generated diagram:\n{diagram}")  # For debugging if test fails


if __name__ == "__main__":
    pytest.main([__file__])
