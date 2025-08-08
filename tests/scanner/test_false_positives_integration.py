"""Integration tests for false positive workflow with synthetic data."""

import json
import tempfile
from pathlib import Path

import pytest

from adversary_mcp_server.scanner.false_positive_manager import FalsePositiveManager
from adversary_mcp_server.server import AdversaryMCPServer


class TestFalsePositiveIntegration:
    """Integration tests for the complete false positive workflow."""

    @pytest.fixture
    def synthetic_adversary_data(self):
        """Create synthetic .adversary.json data for testing."""
        return {
            "version": "2.0",
            "scan_metadata": {
                "scan_type": "comprehensive",
                "timestamp": "2024-01-01T00:00:00Z",
                "total_threats": 3,
            },
            "threats": [
                {
                    "uuid": "test-uuid-1",
                    "rule_id": "hardcoded-secret",
                    "rule_name": "Hardcoded API Key",
                    "description": "Hardcoded API key detected",
                    "category": "secrets",
                    "severity": "high",
                    "file_path": "src/config.py",
                    "line_number": 15,
                    "code_snippet": "API_KEY = 'sk-1234567890'",
                    "confidence": 0.9,
                    "is_false_positive": False,
                },
                {
                    "uuid": "test-uuid-2",
                    "rule_id": "sql-injection",
                    "rule_name": "SQL Injection",
                    "description": "Potential SQL injection vulnerability",
                    "category": "injection",
                    "severity": "critical",
                    "file_path": "src/database.py",
                    "line_number": 42,
                    "code_snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'",
                    "confidence": 0.8,
                    "is_false_positive": True,
                    "false_positive_reason": "This is test data, not real SQL",
                    "false_positive_marked_date": "2024-01-01T12:00:00Z",
                    "false_positive_last_updated": "2024-01-01T12:00:00Z",
                    "false_positive_marked_by": "test_user",
                },
                {
                    "uuid": "test-uuid-3",
                    "rule_id": "xss-vulnerability",
                    "rule_name": "Cross-Site Scripting",
                    "description": "Potential XSS vulnerability detected",
                    "category": "xss",
                    "severity": "medium",
                    "file_path": "src/web.py",
                    "line_number": 23,
                    "code_snippet": "document.innerHTML = user_input",
                    "confidence": 0.7,
                    "is_false_positive": False,
                },
            ],
        }

    @pytest.fixture
    def temp_project_with_adversary_file(self, synthetic_adversary_data):
        """Create a temporary project directory with a synthetic .adversary.json file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            adversary_file = temp_path / ".adversary.json"

            # Write synthetic data to the file
            with open(adversary_file, "w") as f:
                json.dump(synthetic_adversary_data, f, indent=2)

            yield {
                "project_dir": temp_path,
                "adversary_file": adversary_file,
                "data": synthetic_adversary_data,
            }

    def test_false_positive_manager_workflow(self, temp_project_with_adversary_file):
        """Test the complete FalsePositiveManager workflow with synthetic data."""
        project_dir = temp_project_with_adversary_file["project_dir"]
        adversary_file = temp_project_with_adversary_file["adversary_file"]

        # Create FalsePositiveManager with temp project
        adversary_file_path = str(project_dir / ".adversary.json")
        fp_manager = FalsePositiveManager(adversary_file_path=adversary_file_path)

        # Verify file exists and loads correctly
        assert adversary_file.exists()
        data = fp_manager._load_adversary_json()
        assert data is not None
        assert len(data["threats"]) == 3

        # Test getting existing false positives
        false_positives = fp_manager.get_false_positives()
        assert len(false_positives) == 1
        assert false_positives[0]["uuid"] == "test-uuid-2"
        assert false_positives[0]["reason"] == "This is test data, not real SQL"

        # Test checking if specific UUIDs are false positives
        assert fp_manager.is_false_positive("test-uuid-1") is False
        assert fp_manager.is_false_positive("test-uuid-2") is True
        assert fp_manager.is_false_positive("test-uuid-3") is False

        # Test marking a new finding as false positive
        result = fp_manager.mark_false_positive(
            "test-uuid-1", "Actually a test API key, not real", "integration_test"
        )
        assert result is True

        # Verify the marking worked
        assert fp_manager.is_false_positive("test-uuid-1") is True
        false_positives = fp_manager.get_false_positives()
        assert len(false_positives) == 2

        # Find the newly marked false positive
        new_fp = next(
            (fp for fp in false_positives if fp["uuid"] == "test-uuid-1"), None
        )
        assert new_fp is not None
        assert new_fp["reason"] == "Actually a test API key, not real"
        assert new_fp["marked_by"] == "integration_test"

        # Test unmarking a false positive
        result = fp_manager.unmark_false_positive("test-uuid-2")
        assert result is True

        # Verify the unmarking worked
        assert fp_manager.is_false_positive("test-uuid-2") is False
        false_positives = fp_manager.get_false_positives()
        assert len(false_positives) == 1  # Only test-uuid-1 should remain
        assert false_positives[0]["uuid"] == "test-uuid-1"

        # Test clearing all false positives
        fp_manager.clear_all_false_positives()
        false_positives = fp_manager.get_false_positives()
        assert len(false_positives) == 0
        assert fp_manager.is_false_positive("test-uuid-1") is False

    @pytest.mark.asyncio
    async def test_mcp_server_false_positive_workflow(
        self, temp_project_with_adversary_file
    ):
        """Test the MCP server false positive tools with synthetic data."""
        project_dir = temp_project_with_adversary_file["project_dir"]

        # Create server instance
        server = AdversaryMCPServer()

        # Test mark false positive via MCP tool
        arguments = {
            "finding_uuid": "test-uuid-1",
            "reason": "Test marking via MCP",
            "path": str(project_dir),
        }

        result = await server._handle_mark_false_positive(arguments)
        assert len(result) == 1
        assert "marked as false positive" in result[0].text
        assert "test-uuid-1" in result[0].text

        # Test list false positives via MCP tool
        list_arguments = {"path": str(project_dir)}

        result = await server._handle_list_false_positives(list_arguments)
        assert len(result) == 1
        # Should show both the original false positive and the newly marked one
        assert "test-uuid-1" in result[0].text or "test-uuid-2" in result[0].text

        # Test unmark false positive via MCP tool
        unmark_arguments = {
            "finding_uuid": "test-uuid-1",
            "path": str(project_dir),
        }

        result = await server._handle_unmark_false_positive(unmark_arguments)
        assert len(result) == 1
        assert "unmarked as false positive" in result[0].text

    def test_false_positive_manager_edge_cases(self, temp_project_with_adversary_file):
        """Test edge cases and error conditions."""
        project_dir = temp_project_with_adversary_file["project_dir"]

        adversary_file_path = str(project_dir / ".adversary.json")
        fp_manager = FalsePositiveManager(adversary_file_path=adversary_file_path)

        # Test marking non-existent UUID
        result = fp_manager.mark_false_positive("non-existent-uuid", "test reason")
        assert result is False

        # Test unmarking non-existent UUID
        result = fp_manager.unmark_false_positive("non-existent-uuid")
        assert result is False

        # Test unmarking UUID that's not marked as false positive
        result = fp_manager.unmark_false_positive("test-uuid-3")
        assert result is False

        # Test with empty project directory
        empty_dir = project_dir / "empty"
        empty_dir.mkdir()
        adversary_file_path_empty = str(empty_dir / ".adversary.json")
        fp_manager_empty = FalsePositiveManager(
            adversary_file_path=adversary_file_path_empty
        )

        result = fp_manager_empty.mark_false_positive("any-uuid", "test")
        assert result is False

        false_positives = fp_manager_empty.get_false_positives()
        assert len(false_positives) == 0

    def test_cache_invalidation_with_file_changes(
        self, temp_project_with_adversary_file
    ):
        """Test that cache properly invalidates when .adversary.json changes."""
        project_dir = temp_project_with_adversary_file["project_dir"]
        adversary_file = temp_project_with_adversary_file["adversary_file"]

        adversary_file_path = str(project_dir / ".adversary.json")
        fp_manager = FalsePositiveManager(adversary_file_path=adversary_file_path)

        # Initial state - should have one false positive
        assert len(fp_manager.get_false_positives()) == 1
        assert fp_manager.is_false_positive("test-uuid-2") is True

        # Directly modify the file (simulating external change)
        import time

        time.sleep(0.1)  # Ensure different mtime

        data = fp_manager._load_adversary_json()
        # Remove false positive marking from test-uuid-2
        for threat in data["threats"]:
            if threat["uuid"] == "test-uuid-2":
                threat["is_false_positive"] = False
                break

        with open(adversary_file, "w") as f:
            json.dump(data, f, indent=2)

        # Cache should invalidate and reflect the change
        assert len(fp_manager.get_false_positives()) == 0
        assert fp_manager.is_false_positive("test-uuid-2") is False

    def test_filter_false_positives_from_threats(
        self, temp_project_with_adversary_file
    ):
        """Test filtering false positives from threat lists."""
        project_dir = temp_project_with_adversary_file["project_dir"]

        adversary_file_path = str(project_dir / ".adversary.json")
        fp_manager = FalsePositiveManager(adversary_file_path=adversary_file_path)

        # Create mock threat objects
        from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch

        threats = [
            ThreatMatch(
                rule_id="test-rule-1",
                rule_name="Test Rule 1",
                description="Test threat 1",
                category=Category.SECRETS,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1,
                uuid="test-uuid-1",
            ),
            ThreatMatch(
                rule_id="test-rule-2",
                rule_name="Test Rule 2",
                description="Test threat 2",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=2,
                uuid="test-uuid-2",  # This one is marked as false positive
            ),
            ThreatMatch(
                rule_id="test-rule-3",
                rule_name="Test Rule 3",
                description="Test threat 3",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=3,
                uuid="test-uuid-3",
            ),
        ]

        # Filter threats to mark false positives
        filtered_threats = fp_manager.filter_false_positives(threats)

        assert len(filtered_threats) == 3  # All threats returned

        # Check that the false positive is marked
        fp_threat = next(t for t in filtered_threats if t.uuid == "test-uuid-2")
        assert fp_threat.is_false_positive is True

        # Check that non-false positives are not marked
        normal_threat = next(t for t in filtered_threats if t.uuid == "test-uuid-1")
        assert normal_threat.is_false_positive is False
