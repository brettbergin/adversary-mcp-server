"""Tests for the false positive manager module."""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.false_positive_manager import FalsePositiveManager
from adversary_mcp_server.threat_engine import Category, Severity, ThreatMatch


class TestFalsePositiveManager:
    """Test cases for FalsePositiveManager."""

    @pytest.fixture
    def temp_config_dir(self):
        """Create a temporary config directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "adversary_mcp_server.false_positive_manager.Path.home"
            ) as mock_home:
                mock_home.return_value = Path(temp_dir)
                yield Path(temp_dir)

    @pytest.fixture
    def fp_manager(self, temp_config_dir):
        """Create a FalsePositiveManager instance for testing."""
        return FalsePositiveManager()

    def test_initialization(self, fp_manager, temp_config_dir):
        """Test FalsePositiveManager initialization."""
        expected_config_dir = (
            temp_config_dir / ".local" / "share" / "adversary-mcp-server"
        )
        expected_fp_file = expected_config_dir / "false_positives.json"

        assert fp_manager.config_dir == expected_config_dir
        assert fp_manager.false_positives_file == expected_fp_file
        assert expected_config_dir.exists()

    def test_load_false_positives_new_file(self, fp_manager):
        """Test loading false positives when file doesn't exist."""
        data = fp_manager._load_false_positives()

        assert data == {"false_positives": [], "version": "1.0"}

    def test_save_and_load_false_positives(self, fp_manager):
        """Test saving and loading false positives."""
        test_data = {
            "false_positives": [
                {
                    "uuid": "test-uuid-1",
                    "reason": "Test reason",
                    "marked_date": "2024-01-01T00:00:00",
                    "last_updated": "2024-01-01T00:00:00",
                }
            ],
            "version": "1.0",
        }

        fp_manager._save_false_positives(test_data)
        loaded_data = fp_manager._load_false_positives()

        assert loaded_data == test_data

    def test_save_false_positives_io_error(self, fp_manager):
        """Test saving false positives with IO error."""
        with patch("builtins.open", side_effect=OSError("Test error")):
            with pytest.raises(
                RuntimeError, match="Failed to save false positives: Test error"
            ):
                fp_manager._save_false_positives({"test": "data"})

    def test_load_false_positives_invalid_json(self, fp_manager):
        """Test loading false positives with invalid JSON."""
        # Create invalid JSON file
        fp_manager.false_positives_file.parent.mkdir(parents=True, exist_ok=True)
        fp_manager.false_positives_file.write_text("invalid json")

        data = fp_manager._load_false_positives()
        assert data == {"false_positives": [], "version": "1.0"}

    def test_mark_false_positive_new(self, fp_manager):
        """Test marking a new finding as false positive."""
        uuid = "test-uuid-1"
        reason = "Test reason"

        with patch.object(
            fp_manager,
            "_load_false_positives",
            return_value={"false_positives": [], "version": "1.0"},
        ):
            with patch.object(fp_manager, "_save_false_positives") as mock_save:
                fp_manager.mark_false_positive(uuid, reason)

                # Check that save was called with correct data
                mock_save.assert_called_once()
                saved_data = mock_save.call_args[0][0]
                assert len(saved_data["false_positives"]) == 1
                assert saved_data["false_positives"][0]["uuid"] == uuid
                assert saved_data["false_positives"][0]["reason"] == reason

    def test_mark_false_positive_existing(self, fp_manager):
        """Test updating an existing false positive."""
        uuid = "test-uuid-1"
        old_reason = "Old reason"
        new_reason = "New reason"

        existing_data = {
            "false_positives": [
                {
                    "uuid": uuid,
                    "reason": old_reason,
                    "marked_date": "2024-01-01T00:00:00",
                    "last_updated": "2024-01-01T00:00:00",
                }
            ],
            "version": "1.0",
        }

        with patch.object(
            fp_manager, "_load_false_positives", return_value=existing_data
        ):
            with patch.object(fp_manager, "_save_false_positives") as mock_save:
                fp_manager.mark_false_positive(uuid, new_reason)

                # Check that save was called with updated data
                mock_save.assert_called_once()
                saved_data = mock_save.call_args[0][0]
                assert len(saved_data["false_positives"]) == 1
                assert saved_data["false_positives"][0]["uuid"] == uuid
                assert saved_data["false_positives"][0]["reason"] == new_reason

    def test_unmark_false_positive_existing(self, fp_manager):
        """Test unmarking an existing false positive."""
        uuid = "test-uuid-1"

        existing_data = {
            "false_positives": [
                {
                    "uuid": uuid,
                    "reason": "Test reason",
                    "marked_date": "2024-01-01T00:00:00",
                    "last_updated": "2024-01-01T00:00:00",
                }
            ],
            "version": "1.0",
        }

        with patch.object(
            fp_manager, "_load_false_positives", return_value=existing_data
        ):
            with patch.object(fp_manager, "_save_false_positives") as mock_save:
                result = fp_manager.unmark_false_positive(uuid)

                assert result is True
                mock_save.assert_called_once()
                saved_data = mock_save.call_args[0][0]
                assert len(saved_data["false_positives"]) == 0

    def test_unmark_false_positive_not_existing(self, fp_manager):
        """Test unmarking a non-existing false positive."""
        uuid = "non-existing-uuid"

        existing_data = {
            "false_positives": [
                {
                    "uuid": "other-uuid",
                    "reason": "Test reason",
                    "marked_date": "2024-01-01T00:00:00",
                    "last_updated": "2024-01-01T00:00:00",
                }
            ],
            "version": "1.0",
        }

        with patch.object(
            fp_manager, "_load_false_positives", return_value=existing_data
        ):
            result = fp_manager.unmark_false_positive(uuid)
            assert result is False

    def test_is_false_positive(self, fp_manager):
        """Test checking if a finding is a false positive."""
        uuid1 = "fp-uuid"
        uuid2 = "not-fp-uuid"

        existing_data = {
            "false_positives": [
                {
                    "uuid": uuid1,
                    "reason": "Test reason",
                    "marked_date": "2024-01-01T00:00:00",
                    "last_updated": "2024-01-01T00:00:00",
                }
            ],
            "version": "1.0",
        }

        with patch.object(
            fp_manager, "_load_false_positives", return_value=existing_data
        ):
            assert fp_manager.is_false_positive(uuid1) is True
            assert fp_manager.is_false_positive(uuid2) is False

    def test_get_false_positives(self, fp_manager):
        """Test getting all false positives."""
        false_positives = [
            {
                "uuid": "uuid1",
                "reason": "Reason 1",
                "marked_date": "2024-01-01T00:00:00",
                "last_updated": "2024-01-01T00:00:00",
            },
            {
                "uuid": "uuid2",
                "reason": "Reason 2",
                "marked_date": "2024-01-02T00:00:00",
                "last_updated": "2024-01-02T00:00:00",
            },
        ]

        existing_data = {"false_positives": false_positives, "version": "1.0"}

        # Expected result includes 'source' field for legacy data
        expected_result = [
            {
                "uuid": "uuid1",
                "reason": "Reason 1",
                "marked_date": "2024-01-01T00:00:00",
                "last_updated": "2024-01-01T00:00:00",
                "source": "legacy",
            },
            {
                "uuid": "uuid2",
                "reason": "Reason 2",
                "marked_date": "2024-01-02T00:00:00",
                "last_updated": "2024-01-02T00:00:00",
                "source": "legacy",
            },
        ]

        with patch.object(
            fp_manager, "_load_false_positives", return_value=existing_data
        ):
            result = fp_manager.get_false_positives()
            assert result == expected_result

    def test_get_false_positive_uuids(self, fp_manager):
        """Test getting set of false positive UUIDs."""
        false_positives = [
            {"uuid": "uuid1", "reason": "Reason 1"},
            {"uuid": "uuid2", "reason": "Reason 2"},
        ]

        existing_data = {"false_positives": false_positives, "version": "1.0"}

        with patch.object(
            fp_manager, "_load_false_positives", return_value=existing_data
        ):
            result = fp_manager.get_false_positive_uuids()
            assert result == {"uuid1", "uuid2"}

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

    def test_filter_false_positives_no_uuid_attr(self, fp_manager):
        """Test filtering when threats don't have uuid attribute."""
        # Create mock threat without uuid
        threat = Mock()
        threat.uuid = "test-uuid"
        # Remove is_false_positive attribute to test the hasattr check
        if hasattr(threat, "is_false_positive"):
            del threat.is_false_positive

        threats = [threat]

        with patch.object(fp_manager, "get_false_positive_uuids", return_value=set()):
            filtered = fp_manager.filter_false_positives(threats)
            assert len(filtered) == 1
            assert filtered[0] == threat

    def test_clear_all_false_positives(self, fp_manager):
        """Test clearing all false positives."""
        with patch.object(fp_manager, "_save_false_positives") as mock_save:
            fp_manager.clear_all_false_positives()

            mock_save.assert_called_once_with({"false_positives": [], "version": "1.0"})

    def test_export_false_positives(self, fp_manager, temp_config_dir):
        """Test exporting false positives to file."""
        export_path = temp_config_dir / "export.json"
        test_data = {"false_positives": [{"uuid": "test"}], "version": "1.0"}

        with patch.object(fp_manager, "_load_false_positives", return_value=test_data):
            fp_manager.export_false_positives(export_path)

            assert export_path.exists()
            with open(export_path) as f:
                exported_data = json.load(f)
            assert exported_data == test_data

    def test_import_false_positives_replace(self, fp_manager, temp_config_dir):
        """Test importing false positives (replace mode)."""
        import_path = temp_config_dir / "import.json"
        import_data = {"false_positives": [{"uuid": "imported"}], "version": "1.0"}

        with open(import_path, "w") as f:
            json.dump(import_data, f)

        with patch.object(fp_manager, "_save_false_positives") as mock_save:
            fp_manager.import_false_positives(import_path, merge=False)

            mock_save.assert_called_once_with(import_data)

    def test_import_false_positives_merge(self, fp_manager, temp_config_dir):
        """Test importing false positives (merge mode)."""
        import_path = temp_config_dir / "import.json"
        import_data = {"false_positives": [{"uuid": "imported"}], "version": "1.0"}
        existing_data = {"false_positives": [{"uuid": "existing"}], "version": "1.0"}

        with open(import_path, "w") as f:
            json.dump(import_data, f)

        with patch.object(
            fp_manager, "_load_false_positives", return_value=existing_data
        ):
            with patch.object(fp_manager, "_save_false_positives") as mock_save:
                fp_manager.import_false_positives(import_path, merge=True)

                # Check that both existing and imported UUIDs are present
                saved_data = mock_save.call_args[0][0]
                uuids = {fp["uuid"] for fp in saved_data["false_positives"]}
                assert "existing" in uuids
                assert "imported" in uuids

    def test_import_false_positives_merge_no_duplicates(
        self, fp_manager, temp_config_dir
    ):
        """Test importing false positives (merge mode) with duplicate UUIDs."""
        import_path = temp_config_dir / "import.json"
        import_data = {"false_positives": [{"uuid": "duplicate"}], "version": "1.0"}
        existing_data = {"false_positives": [{"uuid": "duplicate"}], "version": "1.0"}

        with open(import_path, "w") as f:
            json.dump(import_data, f)

        with patch.object(
            fp_manager, "_load_false_positives", return_value=existing_data
        ):
            with patch.object(fp_manager, "_save_false_positives") as mock_save:
                fp_manager.import_false_positives(import_path, merge=True)

                # Check that duplicate is not added twice
                saved_data = mock_save.call_args[0][0]
                assert len(saved_data["false_positives"]) == 1
                assert saved_data["false_positives"][0]["uuid"] == "duplicate"
