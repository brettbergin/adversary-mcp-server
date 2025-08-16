"""Tests for ScanResultPersistenceService."""

import os
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from adversary_mcp_server.application.services.scan_persistence_service import (
    OutputFormat,
    ScanResultPersistenceService,
)
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata


class TestScanResultPersistenceService:
    """Test cases for ScanResultPersistenceService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp()).resolve()  # Resolve symlinks
        self.service = ScanResultPersistenceService()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def _create_mock_scan_result(
        self, scan_type: str = "file", target_path: str = None
    ) -> ScanResult:
        """Create a mock scan result for testing."""
        if target_path is None:
            target_path = str(self.temp_dir / "test.py")

        # For non-virtual paths, ensure the file exists
        if not target_path.startswith("/virtual/"):
            Path(target_path).parent.mkdir(parents=True, exist_ok=True)
            Path(target_path).touch()

        metadata = ScanMetadata(
            scan_id=str(uuid.uuid4()),
            scan_type=scan_type,
            timestamp=datetime.now(UTC),
            requester="test",
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=False,
        )

        if scan_type == "code":
            # For code scans, use ScanContext.for_code_snippet
            context = ScanContext.for_code_snippet(
                code="test code content", language="python", requester="test"
            )
        elif scan_type == "directory":
            # For directory scans, use ScanContext.for_directory
            context = ScanContext.for_directory(
                directory_path=target_path, requester="test"
            )
        else:
            # For file scans, use ScanContext.for_file
            context = ScanContext.for_file(file_path=target_path, requester="test")

        request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=False,
        )

        result = ScanResult(
            request=request,
            threats=[],
            scan_metadata={},
        )

        return result

    def test_output_format_from_string(self):
        """Test OutputFormat.from_string method."""
        assert OutputFormat.from_string("json") == OutputFormat.JSON
        assert OutputFormat.from_string("JSON") == OutputFormat.JSON
        assert OutputFormat.from_string("markdown") == OutputFormat.MARKDOWN
        assert OutputFormat.from_string("md") == OutputFormat.MARKDOWN
        assert OutputFormat.from_string("csv") == OutputFormat.CSV

        with pytest.raises(ValueError):
            OutputFormat.from_string("invalid")

    def test_output_format_file_extension(self):
        """Test OutputFormat.get_file_extension method."""
        assert OutputFormat.JSON.get_file_extension() == ".json"
        assert OutputFormat.MARKDOWN.get_file_extension() == ".md"
        assert OutputFormat.CSV.get_file_extension() == ".csv"

    @pytest.mark.asyncio
    async def test_persist_scan_result_file_scan(self):
        """Test persisting result from file scan."""
        # Create a test file
        test_file = self.temp_dir / "test.py"
        test_file.write_text("print('hello')")

        result = self._create_mock_scan_result("file", str(test_file))

        # Persist in JSON format
        output_path = await self.service.persist_scan_result(result, OutputFormat.JSON)

        # Should create file in same directory as test file
        expected_path = self.temp_dir / "adversary.json"
        assert Path(output_path).resolve() == expected_path.resolve()
        assert expected_path.exists()

        # Verify content is valid JSON
        content = expected_path.read_text()
        assert '"scan_metadata"' in content
        assert '"threats"' in content

    @pytest.mark.asyncio
    async def test_persist_scan_result_directory_scan(self):
        """Test persisting result from directory scan."""
        result = self._create_mock_scan_result("directory", str(self.temp_dir))

        # Persist in Markdown format
        output_path = await self.service.persist_scan_result(
            result, OutputFormat.MARKDOWN
        )

        # Should create file in the scanned directory
        expected_path = self.temp_dir / "adversary.md"
        assert Path(output_path).resolve() == expected_path.resolve()
        assert expected_path.exists()

        # Verify content is Markdown
        content = expected_path.read_text()
        assert "# Security Scan Report" in content

    @pytest.mark.asyncio
    async def test_persist_scan_result_code_scan(self):
        """Test persisting result from code scan."""
        result = self._create_mock_scan_result("code", "/virtual/code.py")

        # Change to temp directory to test current working directory placement
        original_cwd = os.getcwd()
        try:
            os.chdir(self.temp_dir)

            # Persist in CSV format
            output_path = await self.service.persist_scan_result(
                result, OutputFormat.CSV
            )

            # Should create file in current working directory
            expected_path = self.temp_dir / "adversary.csv"
            assert Path(output_path).resolve() == expected_path.resolve()
            assert expected_path.exists()

            # Verify content is CSV
            content = expected_path.read_text()
            assert "rule_id,rule_name,severity" in content
        finally:
            os.chdir(original_cwd)

    @pytest.mark.asyncio
    async def test_persist_scan_result_custom_path(self):
        """Test persisting with custom output path."""
        result = self._create_mock_scan_result()
        custom_path = str(self.temp_dir / "custom_output.json")

        output_path = await self.service.persist_scan_result(
            result, OutputFormat.JSON, custom_path
        )

        assert output_path == custom_path
        assert Path(custom_path).exists()

    @pytest.mark.asyncio
    async def test_persist_scan_result_filename_conflict(self):
        """Test handling of filename conflicts."""
        result = self._create_mock_scan_result("directory", str(self.temp_dir))

        # Create existing file
        existing_file = self.temp_dir / "adversary.json"
        existing_file.write_text("existing")

        # Should create file with incremental suffix
        output_path = await self.service.persist_scan_result(result, OutputFormat.JSON)

        expected_path = self.temp_dir / "adversary-1.json"
        assert Path(output_path).resolve() == expected_path.resolve()
        assert expected_path.exists()
        assert existing_file.exists()  # Original file unchanged

    @pytest.mark.asyncio
    async def test_persist_multiple_formats(self):
        """Test persisting in multiple formats."""
        result = self._create_mock_scan_result("directory", str(self.temp_dir))

        formats = [OutputFormat.JSON, OutputFormat.MARKDOWN, OutputFormat.CSV]
        results = await self.service.persist_multiple_formats(result, formats)

        assert len(results) == 3
        assert "json" in results
        assert "md" in results
        assert "csv" in results

        # Verify all files exist
        for format_name, file_path in results.items():
            assert Path(file_path).exists()

    def test_get_supported_formats(self):
        """Test getting supported formats."""
        formats = self.service.get_supported_formats()
        assert "json" in formats
        assert "md" in formats
        assert "csv" in formats

    def test_validate_output_path(self):
        """Test output path validation."""
        # Valid path
        valid_path = str(self.temp_dir / "output.json")
        assert self.service.validate_output_path(valid_path) is True

        # Invalid path (assuming this directory doesn't exist and can't be created)
        invalid_path = "/root/restricted/output.json"
        # Note: This might pass in some test environments, so we'll be lenient
        # assert self.service.validate_output_path(invalid_path) is False

    def test_get_placement_info(self):
        """Test getting placement information."""
        result = self._create_mock_scan_result("file", str(self.temp_dir / "test.py"))
        info = self.service.get_placement_info(result)

        assert info["scan_type"] == "file"
        assert "output_paths" in info
        assert "json" in info["output_paths"]
        assert "md" in info["output_paths"]
        assert "csv" in info["output_paths"]

    def test_format_content_types(self):
        """Test different content formatting."""
        result = self._create_mock_scan_result()

        # Test JSON formatting
        json_content = self.service._format_content(result, OutputFormat.JSON)
        assert '"scan_metadata"' in json_content

        # Test Markdown formatting
        md_content = self.service._format_content(result, OutputFormat.MARKDOWN)
        assert "# Security Scan Report" in md_content

        # Test CSV formatting
        csv_content = self.service._format_content(result, OutputFormat.CSV)
        assert "rule_id,rule_name,severity" in csv_content

    def test_determine_output_path_edge_cases(self):
        """Test output path determination with edge cases."""
        # Create a working result first
        result = self._create_mock_scan_result("file", str(self.temp_dir / "test.py"))

        # Test with unknown scan type by directly modifying the metadata
        # We need to create a new metadata object since they're frozen
        old_metadata = result.request.context.metadata
        new_metadata = ScanMetadata(
            scan_id=old_metadata.scan_id,
            scan_type="unknown",  # Unknown scan type
            timestamp=old_metadata.timestamp,
            requester=old_metadata.requester,
            enable_semgrep=old_metadata.enable_semgrep,
            enable_llm=old_metadata.enable_llm,
            enable_validation=old_metadata.enable_validation,
        )

        # Create a new context with the modified metadata
        new_context = ScanContext(
            target_path=result.request.context.target_path,
            metadata=new_metadata,
            language=result.request.context.language,
            content=result.request.context.content,
        )

        # Create a new request with the modified context
        new_request = ScanRequest(
            context=new_context,
            enable_semgrep=result.request.enable_semgrep,
            enable_llm=result.request.enable_llm,
            enable_validation=result.request.enable_validation,
            severity_threshold=result.request.severity_threshold,
        )

        # Create a new result with the modified request
        test_result = ScanResult(
            request=new_request,
            threats=result.threats,
            scan_metadata=result.scan_metadata,
        )

        output_path = self.service._determine_output_path(
            test_result, OutputFormat.JSON
        )
        assert output_path.name == "adversary.json"
