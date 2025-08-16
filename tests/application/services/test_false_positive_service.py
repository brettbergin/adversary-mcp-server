"""Tests for Clean Architecture False Positive Service."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from adversary_mcp_server.application.services.false_positive_service import (
    FalsePositiveService,
)
from adversary_mcp_server.domain.value_objects.false_positive_info import (
    FalsePositiveInfo,
)
from adversary_mcp_server.infrastructure.false_positive_json_repository import (
    FalsePositiveJsonRepository,
)


class TestFalsePositiveService:
    """Test cases for the Clean Architecture False Positive Service."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp()).resolve()
        self.adversary_file = self.temp_dir / "adversary.json"

        # Create a sample adversary.json file with threats
        sample_data = {
            "scan_metadata": {
                "scan_id": "test-scan",
                "timestamp": datetime.now().isoformat(),
            },
            "threats": [
                {
                    "uuid": "threat-1",
                    "rule_id": "test-rule-1",
                    "rule_name": "Test Rule 1",
                    "description": "Test threat 1",
                    "severity": "high",
                    "is_false_positive": False,
                },
                {
                    "uuid": "threat-2",
                    "rule_id": "test-rule-2",
                    "rule_name": "Test Rule 2",
                    "description": "Test threat 2",
                    "severity": "medium",
                    "is_false_positive": True,
                    "false_positive_reason": "Existing false positive",
                    "false_positive_marked_by": "test-user",
                    "false_positive_marked_date": "2024-01-01T10:00:00",
                    "false_positive_last_updated": "2024-01-01T10:00:00",
                },
            ],
        }

        self.adversary_file.write_text(json.dumps(sample_data, indent=2))

        # Create repository and service
        self.repository = FalsePositiveJsonRepository(str(self.adversary_file))
        self.service = FalsePositiveService(self.repository)

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    @pytest.mark.asyncio
    async def test_mark_as_false_positive(self):
        """Test marking a threat as false positive."""
        # Mark threat-1 as false positive
        success = await self.service.mark_as_false_positive(
            uuid="threat-1", reason="Test false positive", marked_by="test-user"
        )

        assert success is True

        # Verify it was marked
        is_fp = await self.service.is_false_positive("threat-1")
        assert is_fp is True

        # Verify details
        details = await self.service.get_false_positive_details("threat-1")
        assert details is not None
        assert details["false_positive_reason"] == "Test false positive"
        assert details["false_positive_marked_by"] == "test-user"

    @pytest.mark.asyncio
    async def test_unmark_false_positive(self):
        """Test unmarking a false positive."""
        # threat-2 is already marked as false positive
        is_fp_before = await self.service.is_false_positive("threat-2")
        assert is_fp_before is True

        # Unmark it
        success = await self.service.unmark_false_positive("threat-2")
        assert success is True

        # Verify it's no longer marked
        is_fp_after = await self.service.is_false_positive("threat-2")
        assert is_fp_after is False

        # Verify details are cleared
        details = await self.service.get_false_positive_details("threat-2")
        assert details is None

    @pytest.mark.asyncio
    async def test_update_false_positive_reason(self):
        """Test updating the reason for a false positive."""
        # threat-2 is already marked as false positive
        original_details = await self.service.get_false_positive_details("threat-2")
        assert original_details["false_positive_reason"] == "Existing false positive"

        # Update the reason
        success = await self.service.update_false_positive_reason(
            uuid="threat-2", new_reason="Updated reason", updated_by="new-user"
        )
        assert success is True

        # Verify the reason was updated
        updated_details = await self.service.get_false_positive_details("threat-2")
        assert updated_details["false_positive_reason"] == "Updated reason"
        assert updated_details["false_positive_marked_by"] == "new-user"

    @pytest.mark.asyncio
    async def test_list_all_false_positives(self):
        """Test listing all false positives."""
        fp_list = await self.service.list_all_false_positives()

        # Should have one existing false positive (threat-2)
        assert len(fp_list) == 1
        assert fp_list[0]["uuid"] == "threat-2"

        # Mark another one
        await self.service.mark_as_false_positive("threat-1", "Another FP", "user")

        # Should now have two
        fp_list = await self.service.list_all_false_positives()
        assert len(fp_list) == 2

        uuids = {fp["uuid"] for fp in fp_list}
        assert uuids == {"threat-1", "threat-2"}

    @pytest.mark.asyncio
    async def test_get_false_positive_stats(self):
        """Test getting false positive statistics."""
        stats = await self.service.get_false_positive_stats()

        # Should have one existing false positive
        assert stats["total_false_positives"] == 1
        assert "test-user" in stats["marked_by"]
        assert stats["marked_by"]["test-user"] == 1

    @pytest.mark.asyncio
    async def test_nonexistent_threat(self):
        """Test operations on non-existent threats."""
        # Try to mark non-existent threat
        success = await self.service.mark_as_false_positive(
            "nonexistent", "test", "user"
        )
        assert success is False

        # Try to unmark non-existent threat
        success = await self.service.unmark_false_positive("nonexistent")
        assert success is False

        # Check if non-existent threat is false positive
        is_fp = await self.service.is_false_positive("nonexistent")
        assert is_fp is False

    @pytest.mark.asyncio
    async def test_invalid_inputs(self):
        """Test handling of invalid inputs."""
        # Empty UUID
        success = await self.service.mark_as_false_positive("", "reason", "user")
        assert success is False

        success = await self.service.unmark_false_positive("")
        assert success is False

        # Whitespace-only UUID
        success = await self.service.mark_as_false_positive("   ", "reason", "user")
        assert success is False

    def test_false_positive_info_value_object(self):
        """Test the FalsePositiveInfo value object."""
        # Test creating false positive
        fp_info = FalsePositiveInfo.create_false_positive(
            uuid="test-uuid", reason="Test reason", marked_by="test-user"
        )

        assert fp_info.uuid == "test-uuid"
        assert fp_info.is_false_positive is True
        assert fp_info.reason == "Test reason"
        assert fp_info.marked_by == "test-user"
        assert fp_info.marked_date is not None
        assert fp_info.last_updated is not None

        # Test creating legitimate finding
        legit_info = FalsePositiveInfo.create_legitimate("test-uuid-2")
        assert legit_info.uuid == "test-uuid-2"
        assert legit_info.is_false_positive is False
        assert legit_info.reason is None

        # Test updating reason
        updated_info = fp_info.update_reason("New reason", "new-user")
        assert updated_info.reason == "New reason"
        assert updated_info.marked_by == "new-user"
        assert updated_info.last_updated > fp_info.last_updated

        # Test removing false positive marking
        removed_info = fp_info.remove_false_positive_marking()
        assert removed_info.is_false_positive is False
        assert removed_info.uuid == fp_info.uuid

    def test_false_positive_info_serialization(self):
        """Test serialization and deserialization of FalsePositiveInfo."""
        # Create false positive info
        original_info = FalsePositiveInfo.create_false_positive(
            uuid="test-uuid", reason="Test reason", marked_by="test-user"
        )

        # Convert to dict
        data_dict = original_info.to_dict()
        assert data_dict["uuid"] == "test-uuid"
        assert data_dict["is_false_positive"] is True
        assert data_dict["false_positive_reason"] == "Test reason"
        assert data_dict["false_positive_marked_by"] == "test-user"

        # Convert back from dict
        restored_info = FalsePositiveInfo.from_dict(data_dict)
        assert restored_info.uuid == original_info.uuid
        assert restored_info.is_false_positive == original_info.is_false_positive
        assert restored_info.reason == original_info.reason
        assert restored_info.marked_by == original_info.marked_by
