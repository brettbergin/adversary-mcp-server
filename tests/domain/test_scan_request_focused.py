"""Focused tests to improve coverage for ScanRequest entity methods."""

from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class TestScanRequestFocused:
    """Tests targeting uncovered code paths in ScanRequest."""

    def test_for_file_scan_with_severity(self):
        """Test for_file_scan with severity threshold."""
        request = ScanRequest.for_file_scan(
            file_path="examples/vulnerable_python.py",
            requester="test-user",
            severity_threshold="high",
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=False,
        )

        assert request.severity_threshold == SeverityLevel.from_string("high")
        assert request.enable_semgrep is True
        assert request.enable_llm is False
        assert request.enable_validation is False

    def test_for_directory_scan_with_severity(self):
        """Test for_directory_scan with severity threshold."""
        request = ScanRequest.for_directory_scan(
            directory_path="examples/",
            requester="test-user",
            severity_threshold="critical",
            enable_semgrep=False,
            enable_llm=True,
            enable_validation=False,
        )

        assert request.severity_threshold == SeverityLevel.from_string("critical")
        assert request.enable_semgrep is False
        assert request.enable_llm is True
        assert request.enable_validation is False

    def test_for_code_scan_with_severity(self):
        """Test for_code_scan with severity threshold."""
        request = ScanRequest.for_code_scan(
            code="print('hello')",
            language="python",
            requester="test-user",
            severity_threshold="medium",
        )

        assert request.severity_threshold == SeverityLevel.from_string("medium")
        assert request.context.content == "print('hello')"

    def test_get_enabled_scanners_method(self):
        """Test get_enabled_scanners method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)

        # Test different combinations
        request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=False,
        )

        scanners = request.get_enabled_scanners()
        assert "semgrep" in scanners
        assert "llm" not in scanners
        assert "validation" not in scanners

    def test_is_scanner_enabled_method(self):
        """Test is_scanner_enabled method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)

        request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=True,
        )

        assert request.is_scanner_enabled("semgrep") is True
        assert request.is_scanner_enabled("llm") is True
        assert request.is_scanner_enabled("validation") is True

    def test_requires_file_system_access_method(self):
        """Test requires_file_system_access method."""
        # File scan
        file_request = ScanRequest.for_file_scan(
            file_path="examples/vulnerable_python.py", requester="test-user"
        )
        assert file_request.requires_file_system_access() is True

        # Code scan
        code_request = ScanRequest.for_code_scan(
            code="test code", language="python", requester="test-user"
        )
        assert code_request.requires_file_system_access() is False

    def test_should_use_hybrid_scanning_method(self):
        """Test should_use_hybrid_scanning method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)

        # Both scanners enabled
        hybrid_request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=False,
        )
        assert hybrid_request.should_use_hybrid_scanning() is True

        # Only one scanner
        single_request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=False,
        )
        assert single_request.should_use_hybrid_scanning() is False

    def test_estimate_scan_complexity_method(self):
        """Test estimate_scan_complexity method."""
        # Simple file
        simple_request = ScanRequest.for_file_scan(
            file_path="examples/vulnerable_typescript.ts", requester="test-user"
        )
        complexity = simple_request.estimate_scan_complexity()
        assert complexity in ["low", "medium", "high"]

        # Directory scan should be more complex
        dir_request = ScanRequest.for_directory_scan(
            directory_path="examples/", requester="test-user"
        )
        dir_complexity = dir_request.estimate_scan_complexity()
        assert dir_complexity in ["low", "medium", "high"]

    def test_get_scan_scope_description_method(self):
        """Test get_scan_scope_description method."""
        # File scan
        file_request = ScanRequest.for_file_scan(
            file_path="examples/vulnerable_python.py", requester="test-user"
        )
        description = file_request.get_scan_scope_description()
        assert "file" in description.lower()

        # Directory scan
        dir_request = ScanRequest.for_directory_scan(
            directory_path="examples/", requester="test-user"
        )
        description = dir_request.get_scan_scope_description()
        assert "directory" in description.lower()

    def test_create_child_request_for_file_method(self):
        """Test create_child_request_for_file method."""
        # Parent directory request
        parent_request = ScanRequest.for_directory_scan(
            directory_path="examples/",
            requester="test-user",
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=True,
        )

        # Create child for specific file
        child_request = parent_request.create_child_request_for_file(
            "examples/vulnerable_python.py"
        )

        # Should inherit parent configuration
        assert child_request.enable_semgrep == parent_request.enable_semgrep
        assert child_request.enable_llm == parent_request.enable_llm
        assert child_request.enable_validation == parent_request.enable_validation
        assert child_request.severity_threshold == parent_request.severity_threshold

        # Should have different target (absolute path)
        assert str(child_request.context.target_path).endswith(
            "examples/vulnerable_python.py"
        )
