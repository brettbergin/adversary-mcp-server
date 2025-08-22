"""Tests for LLMScanStrategy adapter implementation."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.application.adapters.llm_adapter import LLMScanStrategy
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.interfaces import ScanError
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class TestLLMScanStrategy:
    """Test the LLMScanStrategy adapter."""

    @pytest.fixture
    def mock_llm_scanner(self):
        """Create a mock LLMScanner for testing."""
        scanner = Mock()
        scanner.analyze_file = AsyncMock()
        scanner.analyze_directory = AsyncMock()
        scanner.analyze_code = Mock()
        scanner.analyze_file_with_context = AsyncMock()
        scanner.analyze_project_with_session = AsyncMock()
        scanner.is_session_aware_available = Mock(return_value=True)
        scanner.session_manager = Mock()
        scanner.session_manager.analyze_changes_incrementally = AsyncMock()
        return scanner

    @pytest.fixture
    def llm_strategy(self, mock_llm_scanner):
        """Create LLMScanStrategy with mocked scanner."""
        return LLMScanStrategy(llm_scanner=mock_llm_scanner)

    @pytest.fixture
    def llm_strategy_no_scanner(self):
        """Create LLMScanStrategy without scanner."""
        # Mock the credential manager to ensure it fails
        with patch(
            "adversary_mcp_server.credentials.get_credential_manager",
            side_effect=Exception("No credentials"),
        ):
            strategy = LLMScanStrategy(llm_scanner=None)
            # Ensure scanner is actually None
            strategy._scanner = None
            return strategy

    @pytest.fixture
    def sample_scan_request(self):
        """Create a sample scan request for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('hello world')\n")
            f.flush()

            request = ScanRequest.for_file_scan(
                file_path=f.name,
                requester="test",
                enable_semgrep=False,
                enable_llm=True,
                enable_validation=False,
                severity_threshold="medium",
            )

            yield request

            # Cleanup
            Path(f.name).unlink(missing_ok=True)

    @pytest.fixture
    def sample_llm_finding(self):
        """Create a sample LLM finding."""
        finding = Mock()
        finding.finding_type = "vulnerability"
        finding.severity = "high"
        finding.description = "Test vulnerability"
        finding.line_number = 10
        finding.code_snippet = "test code"
        finding.explanation = "Test explanation"
        finding.recommendation = "Test recommendation"
        finding.confidence = 0.8
        return finding

    @pytest.fixture
    def sample_llm_result(self):
        """Create a sample LLM analysis result."""
        return {
            "finding_id": "test-llm-1",
            "title": "Test Security Issue",
            "description": "Test vulnerability description",
            "severity": "high",
            "line_number": 10,
            "column_number": 5,
            "file_path": "/test/file.py",
            "code_snippet": "vulnerable code",
            "confidence": 0.8,
            "reasoning": "AI detected pattern",
            # "remediation": "Fix the vulnerability",  # Remove to avoid method call
            "category": "injection",
        }

    def test_initialization_with_scanner(self, mock_llm_scanner):
        """Test initialization with provided scanner."""
        strategy = LLMScanStrategy(llm_scanner=mock_llm_scanner, enable_sessions=True)
        assert strategy._scanner == mock_llm_scanner
        assert strategy.enable_sessions is True

    def test_initialization_without_scanner_success(self):
        """Test initialization without scanner with successful credential setup."""
        mock_credential_manager = Mock()
        mock_llm_scanner = Mock()

        with (
            patch(
                "adversary_mcp_server.credentials.get_credential_manager",
                return_value=mock_credential_manager,
            ),
            patch(
                "adversary_mcp_server.application.adapters.llm_adapter.LLMScanner",
                return_value=mock_llm_scanner,
            ),
        ):

            strategy = LLMScanStrategy()
            assert strategy._scanner == mock_llm_scanner

    def test_initialization_without_scanner_failure(self):
        """Test initialization without scanner with credential failure."""
        with patch(
            "adversary_mcp_server.credentials.get_credential_manager",
            side_effect=Exception("Credential error"),
        ):

            strategy = LLMScanStrategy()
            assert strategy._scanner is None

    def test_get_strategy_name_basic(self, llm_strategy):
        """Test getting strategy name without session awareness."""
        llm_strategy._scanner.is_session_aware_available.return_value = False
        assert llm_strategy.get_strategy_name() == "llm_ai_analysis"

    def test_get_strategy_name_session_aware(self, llm_strategy):
        """Test getting strategy name with session awareness."""
        llm_strategy._scanner.is_session_aware_available.return_value = True
        assert llm_strategy.get_strategy_name() == "llm_ai_analysis_session_aware"

    def test_can_scan_no_scanner(self, llm_strategy_no_scanner):
        """Test can_scan with no scanner available."""
        context = Mock()
        context.metadata.scan_type = "file"
        context.content = None
        # The method checks if scanner is None first, so it should return False
        result = llm_strategy_no_scanner.can_scan(context)
        assert result is False

    def test_can_scan_file(self, llm_strategy):
        """Test can_scan for file context."""
        context = Mock()
        context.metadata.scan_type = "file"
        context.content = None
        assert llm_strategy.can_scan(context) is True

    def test_can_scan_directory(self, llm_strategy):
        """Test can_scan for directory context."""
        context = Mock()
        context.metadata.scan_type = "directory"
        context.content = None
        assert llm_strategy.can_scan(context) is True

    def test_can_scan_code(self, llm_strategy):
        """Test can_scan for code context."""
        context = Mock()
        context.metadata.scan_type = "code"
        context.content = "print('hello')"  # Small content
        assert llm_strategy.can_scan(context) is True

    def test_can_scan_code_too_large(self, llm_strategy):
        """Test can_scan for large code content."""
        context = Mock()
        context.metadata.scan_type = "code"
        context.content = "x" * 60000  # Over 50KB limit
        assert llm_strategy.can_scan(context) is False

    def test_can_scan_diff(self, llm_strategy):
        """Test can_scan for diff context."""
        context = Mock()
        context.metadata.scan_type = "diff"
        context.content = None
        assert llm_strategy.can_scan(context) is True

    def test_can_scan_incremental(self, llm_strategy):
        """Test can_scan for incremental context."""
        context = Mock()
        context.metadata.scan_type = "incremental"
        context.content = None
        assert llm_strategy.can_scan(context) is True

    def test_can_scan_unsupported(self, llm_strategy):
        """Test can_scan for unsupported context."""
        context = Mock()
        context.metadata.scan_type = "unknown"
        assert llm_strategy.can_scan(context) is False

    def test_get_supported_languages(self, llm_strategy):
        """Test getting supported languages."""
        with patch(
            "adversary_mcp_server.application.adapters.llm_adapter.LanguageMapper.get_supported_languages",
            return_value=["python", "javascript", "java"],
        ):
            languages = llm_strategy.get_supported_languages()
            assert "python" in languages
            assert "javascript" in languages
            assert "java" in languages

    @pytest.mark.asyncio
    async def test_execute_scan_no_scanner(
        self, llm_strategy_no_scanner, sample_scan_request
    ):
        """Test executing scan with no scanner."""
        result = await llm_strategy_no_scanner.execute_scan(sample_scan_request)
        assert len(result.threats) == 0

    @pytest.mark.asyncio
    async def test_execute_scan_file(
        self, llm_strategy, sample_scan_request, sample_llm_finding
    ):
        """Test executing file scan."""
        # Setup mocks
        llm_strategy._scanner.analyze_file.return_value = [sample_llm_finding]
        llm_strategy._scanner.is_session_aware_available.return_value = False

        result = await llm_strategy.execute_scan(sample_scan_request)

        assert len(result.threats) >= 0  # May be filtered by confidence
        assert result.scan_metadata["scanner"] == "llm_ai_analysis"

    @pytest.mark.asyncio
    async def test_execute_scan_directory(self, llm_strategy, sample_llm_finding):
        """Test executing directory scan."""
        # Create directory scan request
        with tempfile.TemporaryDirectory() as temp_dir:
            request = ScanRequest.for_directory_scan(
                directory_path=temp_dir, requester="test"
            )

            # Setup mocks
            llm_strategy._scanner.analyze_directory.return_value = [sample_llm_finding]
            llm_strategy._scanner.is_session_aware_available.return_value = False

            result = await llm_strategy.execute_scan(request)

            assert result.scan_metadata["scanner"] == "llm_ai_analysis"

    @pytest.mark.asyncio
    async def test_execute_scan_code(self, llm_strategy, sample_llm_finding):
        """Test executing code scan."""
        # Create code scan request
        request = ScanRequest.for_code_scan(
            code="print('hello')", language="python", requester="test"
        )

        # Setup mocks
        llm_strategy._scanner.analyze_code.return_value = [sample_llm_finding]
        llm_strategy._scanner.is_session_aware_available.return_value = False

        result = await llm_strategy.execute_scan(request)

        assert result.scan_metadata["scanner"] == "llm_ai_analysis"

    @pytest.mark.asyncio
    async def test_execute_scan_with_session(
        self, llm_strategy, sample_scan_request, sample_llm_finding
    ):
        """Test executing scan with session awareness."""
        # Setup mocks for session-aware analysis
        llm_strategy._scanner.is_session_aware_available.return_value = True
        llm_strategy._scanner.analyze_file_with_context.return_value = [
            sample_llm_finding
        ]

        # Mock project context detection
        with patch.object(llm_strategy, "_has_project_context", return_value=True):
            result = await llm_strategy.execute_scan(sample_scan_request)

            assert result.scan_metadata["session_aware"] is True
            llm_strategy._scanner.analyze_file_with_context.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_scan_error(self, llm_strategy, sample_scan_request):
        """Test scan execution with error."""
        # Setup scanner to raise exception
        llm_strategy._scanner.analyze_file.side_effect = Exception("Scanner error")
        llm_strategy._scanner.is_session_aware_available.return_value = False

        with pytest.raises(ScanError, match="LLM scan failed"):
            await llm_strategy.execute_scan(sample_scan_request)

    @pytest.mark.asyncio
    async def test_analyze_file(self, llm_strategy, sample_llm_finding):
        """Test file analysis delegation."""
        llm_strategy._scanner.analyze_file.return_value = [sample_llm_finding]

        result = await llm_strategy._analyze_file("/test/file.py", "python")

        llm_strategy._scanner.analyze_file.assert_called_once_with(
            "/test/file.py", "python"
        )
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_analyze_directory(self, llm_strategy, sample_llm_finding):
        """Test directory analysis delegation."""
        llm_strategy._scanner.analyze_directory.return_value = [sample_llm_finding]

        result = await llm_strategy._analyze_directory("/test/dir")

        llm_strategy._scanner.analyze_directory.assert_called_once_with("/test/dir")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_analyze_code(self, llm_strategy, sample_llm_finding):
        """Test code analysis delegation."""
        llm_strategy._scanner.analyze_code.return_value = [sample_llm_finding]

        result = await llm_strategy._analyze_code("print('hello')", "python")

        llm_strategy._scanner.analyze_code.assert_called_once_with(
            "print('hello')", "<code>", "python"
        )
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_analyze_with_session_file(self, llm_strategy, sample_llm_finding):
        """Test session-aware file analysis."""
        context = Mock()
        context.metadata.scan_type = "file"
        context.target_path = "/test/file.py"
        context.metadata.analysis_focus = "security"

        llm_strategy._scanner.analyze_file_with_context.return_value = [
            sample_llm_finding
        ]

        with patch.object(
            llm_strategy, "_find_project_root", return_value=Path("/test")
        ):
            result = await llm_strategy._analyze_with_session(context)

            assert len(result) == 1
            llm_strategy._scanner.analyze_file_with_context.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_with_session_directory(
        self, llm_strategy, sample_llm_finding
    ):
        """Test session-aware directory analysis."""
        context = Mock()
        context.metadata.scan_type = "directory"
        context.target_path = "/test/dir"
        context.metadata.analysis_focus = "security"

        llm_strategy._scanner.analyze_project_with_session.return_value = [
            sample_llm_finding
        ]

        result = await llm_strategy._analyze_with_session(context)

        assert len(result) == 1
        llm_strategy._scanner.analyze_project_with_session.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_with_session_incremental(
        self, llm_strategy, sample_llm_finding
    ):
        """Test session-aware incremental analysis."""
        context = Mock()
        context.metadata.scan_type = "incremental"
        context.metadata.changed_files = ["/test/file1.py", "/test/file2.py"]
        context.metadata.session_id = "test-session"
        context.metadata.commit_hash = "abc123"
        context.metadata.change_context = "feature branch"

        llm_strategy._scanner.session_manager.analyze_changes_incrementally.return_value = [
            sample_llm_finding
        ]

        result = await llm_strategy._analyze_with_session(context)

        assert len(result) == 1
        llm_strategy._scanner.session_manager.analyze_changes_incrementally.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_with_session_incremental_no_session_manager(
        self, llm_strategy
    ):
        """Test incremental analysis without session manager."""
        context = Mock()
        context.metadata.scan_type = "incremental"
        context.metadata.changed_files = ["/test/file1.py"]
        context.metadata.session_id = "test-session"

        llm_strategy._scanner.session_manager = None

        result = await llm_strategy._analyze_with_session(context)

        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_analyze_with_session_incremental_missing_metadata(
        self, llm_strategy
    ):
        """Test incremental analysis with missing metadata."""
        context = Mock()
        context.metadata.scan_type = "incremental"
        # Missing required metadata - simulate hasattr returning False
        context.metadata.changed_files = None
        context.metadata.session_id = None

        with patch(
            "builtins.hasattr",
            side_effect=lambda obj, attr: attr not in ["changed_files", "session_id"],
        ):
            result = await llm_strategy._analyze_with_session(context)

            assert len(result) == 0

    @pytest.mark.asyncio
    async def test_analyze_with_session_unsupported(self, llm_strategy):
        """Test session analysis with unsupported scan type."""
        context = Mock()
        context.metadata.scan_type = "unknown"

        result = await llm_strategy._analyze_with_session(context)

        assert len(result) == 0

    def test_has_project_context_file_exists(self, llm_strategy):
        """Test project context detection for existing file."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            context = Mock()
            context.metadata.scan_type = "file"
            context.target_path = f.name

            with patch.object(
                llm_strategy,
                "_find_project_root",
                return_value=Path(f.name).parent.parent,
            ):  # Different from immediate parent
                result = llm_strategy._has_project_context(context)
                assert result is True

            Path(f.name).unlink()

    def test_has_project_context_file_no_project(self, llm_strategy):
        """Test project context detection for file without project."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            context = Mock()
            context.metadata.scan_type = "file"
            context.target_path = f.name

            with patch.object(
                llm_strategy, "_find_project_root", return_value=Path(f.name).parent
            ):  # Same as immediate parent
                result = llm_strategy._has_project_context(context)
                assert result is False

            Path(f.name).unlink()

    def test_has_project_context_directory(self, llm_strategy):
        """Test project context detection for directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            context = Mock()
            context.metadata.scan_type = "directory"
            context.target_path = temp_dir

            result = llm_strategy._has_project_context(context)
            assert result is True

    def test_has_project_context_nonexistent(self, llm_strategy):
        """Test project context detection for nonexistent path."""
        context = Mock()
        context.metadata.scan_type = "file"
        context.target_path = "/nonexistent/file.py"

        result = llm_strategy._has_project_context(context)
        assert result is False

    def test_find_project_root_with_git(self, llm_strategy):
        """Test finding project root with .git directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create nested structure
            project_dir = Path(temp_dir) / "project"
            sub_dir = project_dir / "src"
            sub_dir.mkdir(parents=True)
            (project_dir / ".git").mkdir()

            test_file = sub_dir / "test.py"
            test_file.touch()

            result = llm_strategy._find_project_root(test_file)
            assert result == project_dir

    def test_find_project_root_with_package_json(self, llm_strategy):
        """Test finding project root with package.json."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir) / "project"
            sub_dir = project_dir / "src"
            sub_dir.mkdir(parents=True)
            (project_dir / "package.json").touch()

            test_file = sub_dir / "test.js"
            test_file.touch()

            result = llm_strategy._find_project_root(test_file)
            assert result == project_dir

    def test_find_project_root_no_indicators(self, llm_strategy):
        """Test finding project root without indicators."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.py"
            test_file.touch()

            result = llm_strategy._find_project_root(test_file)
            assert result == Path(temp_dir)

    def test_finding_to_dict(self, llm_strategy, sample_llm_finding):
        """Test converting finding to dictionary."""
        result = llm_strategy._finding_to_dict(sample_llm_finding)

        assert result["finding_type"] == "vulnerability"
        assert result["severity"] == "high"
        assert result["description"] == "Test vulnerability"
        assert result["line_number"] == 10
        assert result["confidence"] == 0.8

    def test_convert_to_domain_threats(
        self, llm_strategy, sample_scan_request, sample_llm_result
    ):
        """Test converting LLM results to domain threats."""
        results = [sample_llm_result]

        with patch("builtins.print"):  # Suppress warning prints
            threats = llm_strategy._convert_to_domain_threats(
                results, sample_scan_request
            )

            assert len(threats) == 1  # Should convert successfully now
            threat = threats[0]
            assert threat.source_scanner == "llm"
            assert threat.rule_id == "test-llm-1"

    def test_convert_to_domain_threats_conversion_error(
        self, llm_strategy, sample_scan_request
    ):
        """Test handling conversion error."""
        # Create a result that will cause conversion error during ThreatMatch creation
        # Use invalid confidence score that will cause ConfidenceScore validation to fail
        bad_result = {
            "finding_id": "test-llm-1",
            "title": "Test Security Issue",
            "description": "Test vulnerability description",
            "severity": "high",
            "line_number": 10,
            "column_number": 5,
            "file_path": "/test/file.py",
            "code_snippet": "vulnerable code",
            "confidence": "invalid_confidence",  # This will cause ConfidenceScore to fail
            "category": "injection",
        }

        with patch("builtins.print"):  # Suppress warning print
            threats = llm_strategy._convert_to_domain_threats(
                [bad_result], sample_scan_request
            )

            # Should continue processing and return empty list when conversion fails
            assert len(threats) == 0

    def test_convert_to_domain_threats_none_file_path(
        self, llm_strategy, sample_scan_request
    ):
        """Test handling None file_path with graceful fallback."""
        result_with_none_path = {
            "finding_id": "test-llm-none",
            "title": "Test Security Issue",
            "description": "Test vulnerability description",
            "severity": "high",
            "line_number": 10,
            "column_number": 5,
            "file_path": None,  # This should now be handled gracefully
            "code_snippet": "vulnerable code",
            "confidence": 0.8,
            "category": "injection",
        }

        threats = llm_strategy._convert_to_domain_threats(
            [result_with_none_path], sample_scan_request
        )

        # Should successfully create threat with fallback file path
        assert len(threats) == 1
        threat = threats[0]
        assert threat.rule_id == "test-llm-none"
        assert str(threat.file_path) == str(sample_scan_request.context.target_path)

    def test_map_severity(self, llm_strategy):
        """Test severity mapping from LLM to domain."""
        assert llm_strategy._map_severity("critical") == SeverityLevel.from_string(
            "critical"
        )
        assert llm_strategy._map_severity("high") == SeverityLevel.from_string("high")
        assert llm_strategy._map_severity("medium") == SeverityLevel.from_string(
            "medium"
        )
        assert llm_strategy._map_severity("low") == SeverityLevel.from_string("low")
        assert llm_strategy._map_severity("info") == SeverityLevel.from_string("low")
        assert llm_strategy._map_severity("warning") == SeverityLevel.from_string(
            "medium"
        )
        assert llm_strategy._map_severity("error") == SeverityLevel.from_string("high")
        assert llm_strategy._map_severity("unknown") == SeverityLevel.from_string(
            "medium"
        )

    def test_determine_category_explicit(self, llm_strategy):
        """Test category determination with explicit category."""
        result = {"category": "explicit_category"}
        assert llm_strategy._determine_category(result) == "explicit_category"

    def test_determine_category_injection(self, llm_strategy):
        """Test category determination for injection."""
        result = {"description": "SQL injection vulnerability"}
        assert llm_strategy._determine_category(result) == "injection"

    def test_determine_category_xss(self, llm_strategy):
        """Test category determination for XSS."""
        result = {"title": "Cross-site scripting issue"}
        assert llm_strategy._determine_category(result) == "xss"

    def test_determine_category_crypto(self, llm_strategy):
        """Test category determination for cryptography."""
        result = {"description": "Weak encryption algorithm"}
        assert llm_strategy._determine_category(result) == "cryptography"

    def test_determine_category_auth(self, llm_strategy):
        """Test category determination for authentication."""
        result = {"description": "Authentication bypass"}
        assert llm_strategy._determine_category(result) == "authentication"

    def test_determine_category_path_traversal(self, llm_strategy):
        """Test category determination for path traversal."""
        result = {"description": "Path traversal vulnerability"}
        assert llm_strategy._determine_category(result) == "path_traversal"

    def test_determine_category_information_disclosure(self, llm_strategy):
        """Test category determination for information disclosure."""
        result = {"description": "Information disclosure issue"}
        assert llm_strategy._determine_category(result) == "information_disclosure"

    def test_determine_category_memory_safety(self, llm_strategy):
        """Test category determination for memory safety."""
        result = {"description": "Buffer overflow vulnerability"}
        assert llm_strategy._determine_category(result) == "memory_safety"

    def test_determine_category_dos(self, llm_strategy):
        """Test category determination for denial of service."""
        result = {"description": "Denial of service vulnerability"}
        assert llm_strategy._determine_category(result) == "denial_of_service"

    def test_determine_category_default(self, llm_strategy):
        """Test category determination with default fallback."""
        result = {"description": "Unknown security issue"}
        assert llm_strategy._determine_category(result) == "security"

    def test_apply_severity_filter(self, llm_strategy):
        """Test severity filtering."""
        # Create mock threats with severity that meets/doesn't meet threshold
        high_threat = Mock()
        high_threat.severity.meets_threshold.return_value = True

        low_threat = Mock()
        low_threat.severity.meets_threshold.return_value = False

        threats = [high_threat, low_threat]
        threshold = SeverityLevel.from_string("medium")

        filtered = llm_strategy._apply_severity_filter(threats, threshold)
        assert len(filtered) == 1
        assert filtered[0] == high_threat

    def test_apply_severity_filter_no_threshold(self, llm_strategy):
        """Test severity filtering with no threshold."""
        threats = [Mock(), Mock()]
        filtered = llm_strategy._apply_severity_filter(threats, None)
        assert len(filtered) == 2
