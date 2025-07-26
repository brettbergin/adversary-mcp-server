"""Tests for the false positive manager module."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from adversary_mcp_server.scanner.false_positive_manager import FalsePositiveManager
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestFalsePositiveManager:
    """Test cases for FalsePositiveManager."""

    @pytest.fixture
    def temp_project_dir(self):
        """Create a temporary project directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.fixture
    def fp_manager(self, temp_project_dir):
        """Create a FalsePositiveManager instance for testing."""
        adversary_file_path = str(temp_project_dir / ".adversary.json")
        return FalsePositiveManager(adversary_file_path=adversary_file_path)

    @pytest.fixture
    def sample_adversary_data(self):
        """Sample .adversary.json data for testing."""
        return {
            "version": "1.0",
            "threats": [
                {
                    "uuid": "test-uuid-1",
                    "rule_id": "test-rule-1",
                    "description": "Test threat 1",
                    "severity": "high",
                    "is_false_positive": False,
                },
                {
                    "uuid": "test-uuid-2",
                    "rule_id": "test-rule-2",
                    "description": "Test threat 2",
                    "severity": "medium",
                    "is_false_positive": True,
                    "false_positive_reason": "Test reason",
                    "false_positive_marked_date": "2024-01-01T00:00:00",
                    "false_positive_last_updated": "2024-01-01T00:00:00",
                    "false_positive_marked_by": "user",
                },
            ],
        }

    def test_initialization(self, fp_manager, temp_project_dir):
        """Test FalsePositiveManager initialization."""
        expected_adversary_file = temp_project_dir / ".adversary.json"

        assert fp_manager.adversary_file == expected_adversary_file

    def test_load_adversary_json_not_exists(self, fp_manager):
        """Test loading .adversary.json when file doesn't exist."""
        data = fp_manager._load_adversary_json()
        assert data is None

    def test_save_and_load_adversary_json(self, fp_manager, sample_adversary_data):
        """Test saving and loading .adversary.json."""
        # Save data
        assert fp_manager._save_adversary_json(sample_adversary_data) is True

        # Load data
        loaded_data = fp_manager._load_adversary_json()
        assert loaded_data == sample_adversary_data

    def test_save_adversary_json_io_error(self, fp_manager):
        """Test saving .adversary.json with IO error."""
        with patch("builtins.open", side_effect=OSError("Test error")):
            result = fp_manager._save_adversary_json({"test": "data"})
            assert result is False

    def test_load_adversary_json_invalid_json(self, fp_manager):
        """Test loading .adversary.json with invalid JSON."""
        # Create invalid JSON file
        fp_manager.adversary_file.write_text("invalid json")

        data = fp_manager._load_adversary_json()
        assert data is None

    def test_mark_false_positive_new(self, fp_manager, sample_adversary_data):
        """Test marking a finding as false positive."""
        # Setup .adversary.json file
        fp_manager._save_adversary_json(sample_adversary_data)

        uuid = "test-uuid-1"
        reason = "Test false positive reason"

        result = fp_manager.mark_false_positive(uuid, reason, "test_marker")
        assert result is True

        # Verify the threat was marked
        data = fp_manager._load_adversary_json()
        threat = next(t for t in data["threats"] if t["uuid"] == uuid)
        assert threat["is_false_positive"] is True
        assert threat["false_positive_reason"] == reason
        assert threat["false_positive_marked_by"] == "test_marker"
        assert "false_positive_marked_date" in threat
        assert "false_positive_last_updated" in threat

    def test_mark_false_positive_no_file(self, fp_manager):
        """Test marking false positive when no .adversary.json exists."""
        result = fp_manager.mark_false_positive("test-uuid", "reason")
        assert result is False

    def test_mark_false_positive_not_found(self, fp_manager, sample_adversary_data):
        """Test marking false positive for non-existent UUID."""
        fp_manager._save_adversary_json(sample_adversary_data)

        result = fp_manager.mark_false_positive("non-existent-uuid", "reason")
        assert result is False

    def test_unmark_false_positive(self, fp_manager, sample_adversary_data):
        """Test unmarking a false positive."""
        fp_manager._save_adversary_json(sample_adversary_data)

        uuid = "test-uuid-2"  # This one is already marked as false positive
        result = fp_manager.unmark_false_positive(uuid)
        assert result is True

        # Verify the threat was unmarked
        data = fp_manager._load_adversary_json()
        threat = next(t for t in data["threats"] if t["uuid"] == uuid)
        assert threat["is_false_positive"] is False
        assert threat["false_positive_reason"] is None
        assert threat["false_positive_marked_date"] is None
        assert threat["false_positive_last_updated"] is None
        assert threat["false_positive_marked_by"] is None

    def test_unmark_false_positive_no_file(self, fp_manager):
        """Test unmarking false positive when no .adversary.json exists."""
        result = fp_manager.unmark_false_positive("test-uuid")
        assert result is False

    def test_is_false_positive(self, fp_manager, sample_adversary_data):
        """Test checking if a finding is a false positive."""
        fp_manager._save_adversary_json(sample_adversary_data)

        # Build cache
        fp_manager._build_false_positive_cache()

        assert fp_manager.is_false_positive("test-uuid-1") is False
        assert fp_manager.is_false_positive("test-uuid-2") is True
        assert fp_manager.is_false_positive("non-existent") is False

    def test_get_false_positives(self, fp_manager, sample_adversary_data):
        """Test getting all false positives."""
        fp_manager._save_adversary_json(sample_adversary_data)

        false_positives = fp_manager.get_false_positives()

        assert len(false_positives) == 1
        fp = false_positives[0]
        assert fp["uuid"] == "test-uuid-2"
        assert fp["reason"] == "Test reason"
        assert fp["marked_by"] == "user"
        assert fp["source"] == "project"

    def test_get_false_positive_uuids(self, fp_manager, sample_adversary_data):
        """Test getting set of false positive UUIDs."""
        fp_manager._save_adversary_json(sample_adversary_data)

        uuids = fp_manager.get_false_positive_uuids()
        assert uuids == {"test-uuid-2"}

    def test_filter_false_positives(self, fp_manager):
        """Test filtering false positives from threat matches."""
        # Create test threat matches
        threat1 = ThreatMatch(
            rule_id="rule1",
            rule_name="Rule 1",
            description="Test threat 1",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            uuid="fp-uuid",
        )

        threat2 = ThreatMatch(
            rule_id="rule2",
            rule_name="Rule 2",
            description="Test threat 2",
            category=Category.XSS,
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=2,
            uuid="normal-uuid",
        )

        threats = [threat1, threat2]

        with patch.object(
            fp_manager, "get_false_positive_uuids", return_value={"fp-uuid"}
        ):
            filtered = fp_manager.filter_false_positives(threats)

            assert len(filtered) == 2
            assert filtered[0].uuid == "fp-uuid"
            assert filtered[0].is_false_positive is True
            assert filtered[1].uuid == "normal-uuid"
            assert filtered[1].is_false_positive is False

    def test_clear_all_false_positives(self, fp_manager, sample_adversary_data):
        """Test clearing all false positives."""
        fp_manager._save_adversary_json(sample_adversary_data)

        fp_manager.clear_all_false_positives()

        # Verify all false positive flags are cleared
        data = fp_manager._load_adversary_json()
        for threat in data["threats"]:
            assert threat["is_false_positive"] is False
            assert threat.get("false_positive_reason") is None

    def test_export_false_positives(
        self, fp_manager, sample_adversary_data, temp_project_dir
    ):
        """Test exporting false positives to file."""
        fp_manager._save_adversary_json(sample_adversary_data)
        export_path = temp_project_dir / "export.json"

        fp_manager.export_false_positives(export_path)

        assert export_path.exists()
        with open(export_path) as f:
            exported_data = json.load(f)

        assert "false_positives" in exported_data
        assert exported_data["version"] == "2.0"
        assert len(exported_data["false_positives"]) == 1
        assert exported_data["false_positives"][0]["uuid"] == "test-uuid-2"

    def test_cache_invalidation(self, fp_manager, sample_adversary_data):
        """Test that cache is invalidated when file changes."""
        fp_manager._save_adversary_json(sample_adversary_data)

        # Build initial cache
        fp_manager._build_false_positive_cache()
        assert len(fp_manager._fp_cache) == 1

        # Modify file (simulate external change)
        import time

        time.sleep(0.1)  # Ensure different mtime
        sample_adversary_data["threats"][0]["is_false_positive"] = True
        sample_adversary_data["threats"][0]["false_positive_reason"] = "New FP"
        fp_manager._save_adversary_json(sample_adversary_data)

        # Check cache invalidation
        fp_manager._invalidate_cache_if_needed()
        fp_manager._build_false_positive_cache()
        assert len(fp_manager._fp_cache) == 2
