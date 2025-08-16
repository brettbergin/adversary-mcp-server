"""Simplified tests for Mock Semgrep adapter."""

from unittest.mock import Mock

import pytest

from adversary_mcp_server.application.adapters.mock_semgrep_adapter import (
    MockSemgrepScanStrategy,
)
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.interfaces import IScanStrategy


class TestMockSemgrepScanStrategy:
    """Test cases for MockSemgrepScanStrategy."""

    def setup_method(self):
        """Set up test fixtures."""
        self.strategy = MockSemgrepScanStrategy()

    def test_get_strategy_name(self):
        """Test getting strategy name."""
        assert self.strategy.get_strategy_name() == "mock_semgrep_static_analysis"

    def test_get_supported_languages(self):
        """Test getting supported languages."""
        languages = self.strategy.get_supported_languages()
        expected_languages = ["python", "javascript", "java", "go", "typescript"]

        assert isinstance(languages, list)
        assert len(languages) == 5
        assert all(lang in languages for lang in expected_languages)

    def test_can_scan_supported_types(self):
        """Test can_scan with supported scan types."""
        # Create a mock context that supports different scan types
        mock_context = Mock()
        mock_context.metadata.scan_type = "file"
        assert self.strategy.can_scan(mock_context) is True

        mock_context.metadata.scan_type = "directory"
        assert self.strategy.can_scan(mock_context) is True

        mock_context.metadata.scan_type = "code"
        assert self.strategy.can_scan(mock_context) is True

        mock_context.metadata.scan_type = "diff"
        assert self.strategy.can_scan(mock_context) is True

    def test_cannot_scan_unsupported_type(self):
        """Test can_scan returns False for unsupported scan types."""
        mock_context = Mock()
        mock_context.metadata.scan_type = "unsupported_type"
        assert self.strategy.can_scan(mock_context) is False

    @pytest.mark.asyncio
    async def test_execute_scan_code_snippet(self):
        """Test executing scan on code snippet."""
        # Use code scan which doesn't require file system access
        request = ScanRequest.for_code_scan('password = "secret123"', "python")

        result = await self.strategy.execute_scan(request)

        # Verify result structure
        assert result is not None
        assert result.threats is not None
        assert len(result.threats) == 3  # Mock returns 3 threats

        # Verify metadata
        assert result.scan_metadata is not None
        assert result.scan_metadata["scanner"] == "mock_semgrep"
        assert result.scan_metadata["mock_adapter"] is True
        assert result.scan_metadata["rules_executed"] == 10
        assert result.scan_metadata["files_scanned"] == 1
        assert isinstance(result.scan_metadata["scan_duration_ms"], int)

    @pytest.mark.asyncio
    async def test_mock_threats_content(self):
        """Test that mock threats have expected content."""
        request = ScanRequest.for_code_scan("test code", "python")

        result = await self.strategy.execute_scan(request)
        threats = result.threats

        # Verify we have the expected threats
        threat_rule_ids = [threat.rule_id for threat in threats]
        expected_rule_ids = [
            "mock.security.hardcoded-password",
            "mock.security.sql-injection",
            "mock.security.weak-hash",
        ]
        assert all(rule_id in threat_rule_ids for rule_id in expected_rule_ids)

        # Check high severity threat details - severity is SeverityLevel object
        high_threat = next(t for t in threats if str(t.severity) == "high")
        assert high_threat.rule_id == "mock.security.hardcoded-password"
        assert high_threat.rule_name == "Hardcoded Password"
        assert "hardcoded password" in high_threat.description.lower()
        assert high_threat.category == "secrets"
        assert high_threat.line_number == 10
        assert high_threat.column_number == 5
        assert 'password = "secret123"' in high_threat.code_snippet
        assert high_threat.cwe_id == "CWE-798"
        assert "A02:2021" in high_threat.owasp_category

        # Check medium severity threat details
        medium_threat = next(t for t in threats if str(t.severity) == "medium")
        assert medium_threat.rule_id == "mock.security.sql-injection"
        assert medium_threat.rule_name == "Potential SQL Injection"
        assert "sql injection" in medium_threat.description.lower()
        assert medium_threat.category == "injection"
        assert medium_threat.line_number == 25
        assert medium_threat.column_number == 10
        assert "SELECT * FROM users" in medium_threat.code_snippet
        assert medium_threat.cwe_id == "CWE-89"
        assert "A03:2021" in medium_threat.owasp_category

        # Check low severity threat details
        low_threat = next(t for t in threats if str(t.severity) == "low")
        assert low_threat.rule_id == "mock.security.weak-hash"
        assert low_threat.rule_name == "Weak Hash Algorithm"
        assert "weak hash" in low_threat.description.lower()
        assert low_threat.category == "crypto"
        assert low_threat.line_number == 35
        assert low_threat.column_number == 15
        assert "hashlib.md5" in low_threat.code_snippet
        assert low_threat.cwe_id == "CWE-327"

    @pytest.mark.asyncio
    async def test_scan_result_request_reference(self):
        """Test that scan result maintains reference to original request."""
        request = ScanRequest.for_code_scan("test code", "python")

        result = await self.strategy.execute_scan(request)

        # Verify result contains reference to original request
        assert result.request == request

    @pytest.mark.asyncio
    async def test_threat_file_path_matches_request(self):
        """Test that threat file paths match the request target."""
        request = ScanRequest.for_code_scan("test code", "python")

        result = await self.strategy.execute_scan(request)

        # All threats should reference the target path (allow for path resolution differences)
        for threat in result.threats:
            assert "<snippet>.python" in str(threat.file_path)
            assert "<snippet>.python" in str(request.context.target_path)

    def test_mock_strategy_implements_interface(self):
        """Test that MockSemgrepScanStrategy properly implements IScanStrategy."""
        assert isinstance(self.strategy, IScanStrategy)

        # Check all required methods exist
        assert hasattr(self.strategy, "get_strategy_name")
        assert hasattr(self.strategy, "get_supported_languages")
        assert hasattr(self.strategy, "can_scan")
        assert hasattr(self.strategy, "execute_scan")

        # Check methods are callable
        assert callable(self.strategy.get_strategy_name)
        assert callable(self.strategy.get_supported_languages)
        assert callable(self.strategy.can_scan)
        assert callable(self.strategy.execute_scan)

    @pytest.mark.asyncio
    async def test_scan_performance_metadata(self):
        """Test that scan includes performance metadata."""
        request = ScanRequest.for_code_scan("test code", "python")

        result = await self.strategy.execute_scan(request)

        metadata = result.scan_metadata
        assert "scan_duration_ms" in metadata
        assert isinstance(metadata["scan_duration_ms"], int)
        assert metadata["scan_duration_ms"] > 0  # Should be positive
        assert metadata["scan_duration_ms"] < 1000  # Should be reasonable for mock

    @pytest.mark.asyncio
    async def test_threats_have_scanner_attribution(self):
        """Test that threats are properly attributed to mock scanner."""
        request = ScanRequest.for_code_scan("test code", "python")

        result = await self.strategy.execute_scan(request)

        # All threats should be attributed to the scanner
        for threat in result.threats:
            # Check that threat was created via Semgrep factory method
            assert (
                threat.source_scanner == "semgrep"
            )  # This is set by create_semgrep_threat
            assert threat.rule_id.startswith("mock.")  # Mock rule prefix

    @pytest.mark.asyncio
    async def test_different_code_languages(self):
        """Test execute_scan works with different programming languages."""
        languages = ["python", "javascript", "java", "go", "typescript"]

        for language in languages:
            request = ScanRequest.for_code_scan("test code", language)
            result = await self.strategy.execute_scan(request)

            assert result is not None
            assert len(result.threats) == 3
            assert result.scan_metadata["mock_adapter"] is True

    @pytest.mark.asyncio
    async def test_consistent_threat_generation(self):
        """Test that the same request generates consistent threats."""
        request = ScanRequest.for_code_scan("test code", "python")

        # Run scan multiple times
        result1 = await self.strategy.execute_scan(request)
        result2 = await self.strategy.execute_scan(request)

        # Should have same number of threats
        assert len(result1.threats) == len(result2.threats)

        # Should have same threat types
        rule_ids_1 = [t.rule_id for t in result1.threats]
        rule_ids_2 = [t.rule_id for t in result2.threats]
        assert set(rule_ids_1) == set(rule_ids_2)

    @pytest.mark.asyncio
    async def test_mock_metadata_completeness(self):
        """Test that mock scan metadata is complete."""
        request = ScanRequest.for_code_scan("test code", "python")

        result = await self.strategy.execute_scan(request)
        metadata = result.scan_metadata

        # Check all expected metadata fields
        expected_fields = {
            "scanner",
            "scan_duration_ms",
            "rules_executed",
            "files_scanned",
            "mock_adapter",
        }
        assert all(field in metadata for field in expected_fields)

        # Check metadata values
        assert metadata["scanner"] == "mock_semgrep"
        assert metadata["mock_adapter"] is True
        assert isinstance(metadata["rules_executed"], int)
        assert isinstance(metadata["files_scanned"], int)
        assert metadata["rules_executed"] > 0
        assert metadata["files_scanned"] > 0
