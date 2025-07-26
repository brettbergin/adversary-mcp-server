"""Tests for UUID persistence across multiple scans."""

import json
import tempfile
from pathlib import Path

import pytest

from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch
from adversary_mcp_server.server import AdversaryMCPServer


class TestUUIDPersistence:
    """Test UUID persistence and false positive preservation across scans."""

    @pytest.fixture
    def temp_project_dir(self):
        """Create a temporary project directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.fixture
    def server(self):
        """Create an AdversaryMCPServer instance for testing."""
        return AdversaryMCPServer()

    def create_sample_threats(self, file_path: str = "test.py") -> list[ThreatMatch]:
        """Create sample threats for testing."""
        return [
            ThreatMatch(
                rule_id="hardcoded-secret",
                rule_name="Hardcoded API Key",
                description="API key detected",
                category=Category.SECRETS,
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=10,
                code_snippet="API_KEY = 'secret123'",
            ),
            ThreatMatch(
                rule_id="sql-injection",
                rule_name="SQL Injection",
                description="SQL injection vulnerability",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=25,
                code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            ),
        ]

    def test_threat_match_fingerprint(self, temp_project_dir):
        """Test that ThreatMatch generates consistent fingerprints."""
        threat = ThreatMatch(
            rule_id="test-rule",
            rule_name="Test Rule",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path=str(temp_project_dir / "test.py"),
            line_number=42,
        )

        fingerprint1 = threat.get_fingerprint()
        fingerprint2 = threat.get_fingerprint()

        # Should be consistent
        assert fingerprint1 == fingerprint2

        # Should contain the key components
        assert "test-rule" in fingerprint1
        assert "test.py" in fingerprint1
        assert "42" in fingerprint1

    def test_uuid_preservation_first_scan(self, server, temp_project_dir):
        """Test that first scan generates new UUIDs."""
        adversary_file = temp_project_dir / ".adversary.json"
        threats = self.create_sample_threats(str(temp_project_dir / "test.py"))

        # Convert to dict format like the server does
        threat_dicts = [
            {
                "uuid": t.uuid,
                "rule_id": t.rule_id,
                "rule_name": t.rule_name,
                "description": t.description,
                "category": t.category.value,
                "severity": t.severity.value,
                "file_path": t.file_path,
                "line_number": t.line_number,
                "code_snippet": t.code_snippet,
                "is_false_positive": False,
            }
            for t in threats
        ]

        # First scan - no existing file
        preserved_threats = server._preserve_uuids_and_false_positives(
            threat_dicts, adversary_file
        )

        # Should return the same threats unchanged (no existing file)
        assert len(preserved_threats) == 2
        assert preserved_threats[0]["uuid"] == threat_dicts[0]["uuid"]
        assert preserved_threats[1]["uuid"] == threat_dicts[1]["uuid"]

    def test_uuid_preservation_second_scan(self, server, temp_project_dir):
        """Test that second scan preserves UUIDs from first scan."""
        adversary_file = temp_project_dir / ".adversary.json"
        test_file_path = str(temp_project_dir / "test.py")

        # Create initial scan data
        initial_threats = self.create_sample_threats(test_file_path)
        initial_uuid_1 = initial_threats[0].uuid
        initial_uuid_2 = initial_threats[1].uuid

        # Save initial scan results
        initial_data = {
            "version": "2.0",
            "scan_metadata": {"scan_type": "comprehensive"},
            "threats": [
                {
                    "uuid": initial_uuid_1,
                    "rule_id": initial_threats[0].rule_id,
                    "rule_name": initial_threats[0].rule_name,
                    "description": initial_threats[0].description,
                    "category": initial_threats[0].category.value,
                    "severity": initial_threats[0].severity.value,
                    "file_path": initial_threats[0].file_path,
                    "line_number": initial_threats[0].line_number,
                    "code_snippet": initial_threats[0].code_snippet,
                    "is_false_positive": False,
                },
                {
                    "uuid": initial_uuid_2,
                    "rule_id": initial_threats[1].rule_id,
                    "rule_name": initial_threats[1].rule_name,
                    "description": initial_threats[1].description,
                    "category": initial_threats[1].category.value,
                    "severity": initial_threats[1].severity.value,
                    "file_path": initial_threats[1].file_path,
                    "line_number": initial_threats[1].line_number,
                    "code_snippet": initial_threats[1].code_snippet,
                    "is_false_positive": False,
                },
            ],
        }

        with open(adversary_file, "w", encoding="utf-8") as f:
            json.dump(initial_data, f, indent=2)

        # Create second scan with new ThreatMatch objects (new UUIDs)
        second_threats = self.create_sample_threats(test_file_path)
        new_uuid_1 = second_threats[0].uuid
        new_uuid_2 = second_threats[1].uuid

        # Verify new UUIDs are different
        assert new_uuid_1 != initial_uuid_1
        assert new_uuid_2 != initial_uuid_2

        # Convert to dict format
        threat_dicts = [
            {
                "uuid": t.uuid,
                "rule_id": t.rule_id,
                "rule_name": t.rule_name,
                "description": t.description,
                "category": t.category.value,
                "severity": t.severity.value,
                "file_path": t.file_path,
                "line_number": t.line_number,
                "code_snippet": t.code_snippet,
                "is_false_positive": False,
            }
            for t in second_threats
        ]

        # Preserve UUIDs from existing file
        preserved_threats = server._preserve_uuids_and_false_positives(
            threat_dicts, adversary_file
        )

        # Should preserve the original UUIDs
        assert len(preserved_threats) == 2
        assert preserved_threats[0]["uuid"] == initial_uuid_1  # Preserved!
        assert preserved_threats[1]["uuid"] == initial_uuid_2  # Preserved!

    def test_false_positive_preservation(self, server, temp_project_dir):
        """Test that false positive markings are preserved across scans."""
        adversary_file = temp_project_dir / ".adversary.json"
        test_file_path = str(temp_project_dir / "test.py")

        # Create initial scan with one threat marked as false positive
        initial_threats = self.create_sample_threats(test_file_path)
        initial_uuid_1 = initial_threats[0].uuid
        initial_uuid_2 = initial_threats[1].uuid

        initial_data = {
            "version": "2.0",
            "scan_metadata": {"scan_type": "comprehensive"},
            "threats": [
                {
                    "uuid": initial_uuid_1,
                    "rule_id": initial_threats[0].rule_id,
                    "rule_name": initial_threats[0].rule_name,
                    "description": initial_threats[0].description,
                    "category": initial_threats[0].category.value,
                    "severity": initial_threats[0].severity.value,
                    "file_path": initial_threats[0].file_path,
                    "line_number": initial_threats[0].line_number,
                    "code_snippet": initial_threats[0].code_snippet,
                    "is_false_positive": True,  # Marked as false positive
                    "false_positive_reason": "Test data, not real secret",
                    "false_positive_marked_date": "2024-01-01T12:00:00Z",
                    "false_positive_last_updated": "2024-01-01T12:00:00Z",
                    "false_positive_marked_by": "test_user",
                },
                {
                    "uuid": initial_uuid_2,
                    "rule_id": initial_threats[1].rule_id,
                    "rule_name": initial_threats[1].rule_name,
                    "description": initial_threats[1].description,
                    "category": initial_threats[1].category.value,
                    "severity": initial_threats[1].severity.value,
                    "file_path": initial_threats[1].file_path,
                    "line_number": initial_threats[1].line_number,
                    "code_snippet": initial_threats[1].code_snippet,
                    "is_false_positive": False,
                },
            ],
        }

        with open(adversary_file, "w", encoding="utf-8") as f:
            json.dump(initial_data, f, indent=2)

        # Create second scan with new ThreatMatch objects
        second_threats = self.create_sample_threats(test_file_path)

        threat_dicts = [
            {
                "uuid": t.uuid,
                "rule_id": t.rule_id,
                "rule_name": t.rule_name,
                "description": t.description,
                "category": t.category.value,
                "severity": t.severity.value,
                "file_path": t.file_path,
                "line_number": t.line_number,
                "code_snippet": t.code_snippet,
                "is_false_positive": False,  # New scan doesn't know about false positives
            }
            for t in second_threats
        ]

        # Preserve UUIDs and false positive markings
        preserved_threats = server._preserve_uuids_and_false_positives(
            threat_dicts, adversary_file
        )

        # First threat should preserve false positive marking
        assert preserved_threats[0]["uuid"] == initial_uuid_1
        assert preserved_threats[0]["is_false_positive"] is True
        assert (
            preserved_threats[0]["false_positive_reason"]
            == "Test data, not real secret"
        )
        assert preserved_threats[0]["false_positive_marked_by"] == "test_user"

        # Second threat should not be marked as false positive
        assert preserved_threats[1]["uuid"] == initial_uuid_2
        assert preserved_threats[1]["is_false_positive"] is False

    def test_new_threat_gets_new_uuid(self, server, temp_project_dir):
        """Test that genuinely new threats get new UUIDs."""
        adversary_file = temp_project_dir / ".adversary.json"
        test_file_path = str(temp_project_dir / "test.py")

        # Create initial scan with one threat
        initial_threat = self.create_sample_threats(test_file_path)[0]
        initial_data = {
            "version": "2.0",
            "scan_metadata": {"scan_type": "comprehensive"},
            "threats": [
                {
                    "uuid": initial_threat.uuid,
                    "rule_id": initial_threat.rule_id,
                    "rule_name": initial_threat.rule_name,
                    "description": initial_threat.description,
                    "category": initial_threat.category.value,
                    "severity": initial_threat.severity.value,
                    "file_path": initial_threat.file_path,
                    "line_number": initial_threat.line_number,
                    "code_snippet": initial_threat.code_snippet,
                    "is_false_positive": False,
                }
            ],
        }

        with open(adversary_file, "w", encoding="utf-8") as f:
            json.dump(initial_data, f, indent=2)

        # Create second scan with the original threat PLUS a new one
        all_threats = self.create_sample_threats(test_file_path)  # Both threats

        threat_dicts = [
            {
                "uuid": t.uuid,
                "rule_id": t.rule_id,
                "rule_name": t.rule_name,
                "description": t.description,
                "category": t.category.value,
                "severity": t.severity.value,
                "file_path": t.file_path,
                "line_number": t.line_number,
                "code_snippet": t.code_snippet,
                "is_false_positive": False,
            }
            for t in all_threats
        ]

        preserved_threats = server._preserve_uuids_and_false_positives(
            threat_dicts, adversary_file
        )

        # Should have 2 threats now
        assert len(preserved_threats) == 2

        # First threat should preserve existing UUID
        assert preserved_threats[0]["uuid"] == initial_threat.uuid

        # Second threat should keep its new UUID (genuinely new finding)
        assert preserved_threats[1]["uuid"] == all_threats[1].uuid
        assert preserved_threats[1]["uuid"] != initial_threat.uuid
