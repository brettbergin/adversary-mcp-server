"""Integration tests for separation of concerns between scanners and validation."""

from datetime import UTC, datetime

import pytest

from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.interfaces import ValidationError
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata


class TestSeparationOfConcerns:
    """Test that scanners and validation can operate independently."""

    @pytest.fixture
    def file_context(self):
        """Create a test file context."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-separation",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-separation",
        )
        return ScanContext(target_path=file_path, metadata=metadata)

    def test_semgrep_only_scan(self, file_context):
        """Test Semgrep scanning without LLM or validation."""
        request = ScanRequest(
            context=file_context,
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=False,
        )

        assert request.enable_semgrep is True
        assert request.enable_llm is False
        assert request.enable_validation is False

    def test_llm_only_scan(self, file_context):
        """Test LLM scanning without Semgrep or validation."""
        request = ScanRequest(
            context=file_context,
            enable_semgrep=False,
            enable_llm=True,
            enable_validation=False,
        )

        assert request.enable_semgrep is False
        assert request.enable_llm is True
        assert request.enable_validation is False

    def test_semgrep_with_validation(self, file_context):
        """Test Semgrep scanning with validation (no LLM scanning)."""
        # This is the key test - validation should work with Semgrep-only results
        request = ScanRequest(
            context=file_context,
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=True,
        )

        assert request.enable_semgrep is True
        assert request.enable_llm is False
        assert request.enable_validation is True

    def test_llm_with_validation(self, file_context):
        """Test LLM scanning with validation."""
        request = ScanRequest(
            context=file_context,
            enable_semgrep=False,
            enable_llm=True,
            enable_validation=True,
        )

        assert request.enable_semgrep is False
        assert request.enable_llm is True
        assert request.enable_validation is True

    def test_both_scanners_with_validation(self, file_context):
        """Test both scanners with validation."""
        request = ScanRequest(
            context=file_context,
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=True,
        )

        assert request.enable_semgrep is True
        assert request.enable_llm is True
        assert request.enable_validation is True

    def test_both_scanners_without_validation(self, file_context):
        """Test both scanners without validation."""
        request = ScanRequest(
            context=file_context,
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=False,
        )

        assert request.enable_semgrep is True
        assert request.enable_llm is True
        assert request.enable_validation is False

    def test_validation_only_configuration_invalid(self, file_context):
        """Test that validation-only configuration is invalid (no scanners)."""
        with pytest.raises(
            ValidationError, match="At least one scanner must be enabled"
        ):
            ScanRequest(
                context=file_context,
                enable_semgrep=False,
                enable_llm=False,
                enable_validation=True,
            )

    def test_no_scanners_no_validation_invalid(self, file_context):
        """Test that no scanners and no validation is invalid."""
        with pytest.raises(
            ValidationError, match="At least one scanner must be enabled"
        ):
            ScanRequest(
                context=file_context,
                enable_semgrep=False,
                enable_llm=False,
                enable_validation=False,
            )
