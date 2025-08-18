"""Tests for SessionAwareLLMScanStrategy Clean Architecture adapter."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from adversary_mcp_server.application.adapters.session_aware_llm_adapter import (
    SessionAwareLLMScanStrategy,
)
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.threat_match import (
    ThreatMatch as DomainThreatMatch,
)
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel
from adversary_mcp_server.scanner.types import Category, Severity
from adversary_mcp_server.scanner.types import ThreatMatch as ScannerThreatMatch


class TestSessionAwareLLMScanStrategy:
    """Test SessionAwareLLMScanStrategy Clean Architecture adapter."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_scanner = Mock()
        self.adapter = SessionAwareLLMScanStrategy(self.mock_scanner)

    def test_initialization_with_scanner(self):
        """Test adapter initialization with provided scanner."""
        assert self.adapter._scanner == self.mock_scanner

    def test_initialization_without_scanner(self):
        """Test adapter initialization without scanner (auto-init)."""
        # This will likely fail to initialize and warn via logger
        adapter = SessionAwareLLMScanStrategy()
        # Should not crash, may have None scanner
        # The scanner should be None since credential manager likely unavailable in tests

    def test_get_strategy_name(self):
        """Test strategy name."""
        assert self.adapter.get_strategy_name() == "session_aware_llm_analysis"

    def test_can_scan_with_available_scanner(self):
        """Test can_scan with available scanner."""
        self.mock_scanner.is_available.return_value = True

        # Test different scan types
        scan_types = ["file", "directory", "code", "diff"]

        for scan_type in scan_types:
            if scan_type == "file":
                metadata = ScanMetadata.for_file_scan(language="python")
            elif scan_type == "directory":
                metadata = ScanMetadata.for_directory_scan()
            elif scan_type == "code":
                metadata = ScanMetadata.for_code_scan("python")
            else:  # diff
                metadata = ScanMetadata.for_diff_scan("main", "feature")

            context = ScanContext(
                target_path=FilePath.from_string("/test/path"),
                language="python",
                content="test code",
                metadata=metadata,
            )

            assert self.adapter.can_scan(context) is True

    def test_can_scan_with_unavailable_scanner(self):
        """Test can_scan with unavailable scanner."""
        self.mock_scanner.is_available.return_value = False

        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            language="python",
            metadata=ScanMetadata.for_file_scan(language="python"),
        )

        assert self.adapter.can_scan(context) is False

    def test_can_scan_with_none_scanner(self):
        """Test can_scan with None scanner."""
        adapter = SessionAwareLLMScanStrategy(None)

        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            language="python",
            metadata=ScanMetadata.for_file_scan(language="python"),
        )

        assert adapter.can_scan(context) is False

    def test_get_supported_languages(self):
        """Test supported languages list."""
        languages = self.adapter.get_supported_languages()

        # Should support major languages
        expected_languages = [
            "python",
            "javascript",
            "typescript",
            "java",
            "go",
            "rust",
        ]
        for lang in expected_languages:
            assert lang in languages

    @pytest.mark.asyncio
    async def test_execute_scan_file_type(self):
        """Test execute_scan for file scan type."""
        # Create scan request
        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            language="python",
            metadata=ScanMetadata.for_file_scan(language="python"),
        )

        request = ScanRequest(
            context=context, severity_threshold=SeverityLevel.from_string("medium")
        )

        # Mock scanner response
        mock_threat = ScannerThreatMatch(
            rule_id="test_rule",
            rule_name="Test Vulnerability",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path=__file__,
            line_number=10,
            confidence=0.9,
        )

        self.mock_scanner.analyze_file_with_context = AsyncMock(
            return_value=[mock_threat]
        )

        # Execute scan
        result = await self.adapter.execute_scan(request)

        # Verify scanner was called correctly
        self.mock_scanner.analyze_file_with_context.assert_called_once()
        call_args = self.mock_scanner.analyze_file_with_context.call_args
        assert call_args[1]["file_path"] == Path(__file__)

        # Verify result
        assert len(result.threats) == 1
        threat = result.threats[0]
        assert threat.rule_id == "test_rule"
        assert threat.severity == SeverityLevel.from_string("high")

        # Verify metadata
        assert result.scan_metadata["scanner"] == "session_aware_llm_analysis"
        assert result.scan_metadata["analysis_type"] == "session_aware_ai"
        assert result.scan_metadata["context_loaded"] is True

    @pytest.mark.asyncio
    async def test_execute_scan_directory_type(self):
        """Test execute_scan for directory scan type."""
        context = ScanContext(
            target_path=FilePath.from_string(
                "/Users/brettbergin/code/adversary-mcp-server"
            ),
            metadata=ScanMetadata.for_directory_scan(),
        )

        request = ScanRequest(context=context)

        # Mock scanner response
        mock_threats = [
            ScannerThreatMatch(
                rule_id="dir_rule_1",
                rule_name="Directory Issue 1",
                description="Directory security issue 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="/test/project/file1.py",
                line_number=1,
                confidence=0.8,
            ),
            ScannerThreatMatch(
                rule_id="dir_rule_2",
                rule_name="Directory Issue 2",
                description="Directory security issue 2",
                category=Category.INJECTION,
                severity=Severity.MEDIUM,
                file_path="/test/project/file2.py",
                line_number=1,
                confidence=0.7,
            ),
        ]

        self.mock_scanner.analyze_project_with_session = AsyncMock(
            return_value=mock_threats
        )

        result = await self.adapter.execute_scan(request)

        # Verify scanner was called
        self.mock_scanner.analyze_project_with_session.assert_called_once()
        call_args = self.mock_scanner.analyze_project_with_session.call_args
        assert call_args[1]["project_root"] == Path(
            "/Users/brettbergin/code/adversary-mcp-server"
        )

        # Verify results
        assert len(result.threats) == 2
        assert result.scan_metadata["cross_file_analysis"] is True

    @pytest.mark.asyncio
    async def test_execute_scan_code_type(self):
        """Test execute_scan for code scan type."""
        code_content = "def vulnerable_function(user_input): return eval(user_input)"

        context = ScanContext(
            target_path=FilePath.from_string("test_snippet.py"),
            language="python",
            content=code_content,
            metadata=ScanMetadata.for_code_scan("python"),
        )

        request = ScanRequest(context=context)

        # Mock scanner response
        mock_threat = ScannerThreatMatch(
            rule_id="code_injection",
            rule_name="Code Injection via eval()",
            description="Code injection vulnerability using eval()",
            category=Category.INJECTION,
            severity=Severity.CRITICAL,
            file_path="test_snippet.py",
            line_number=1,
            confidence=0.95,
        )

        self.mock_scanner.analyze_code_with_context = AsyncMock(
            return_value=[mock_threat]
        )

        result = await self.adapter.execute_scan(request)

        # Verify scanner was called with code content
        self.mock_scanner.analyze_code_with_context.assert_called_once()
        call_args = self.mock_scanner.analyze_code_with_context.call_args
        assert call_args[1]["code_content"] == code_content
        assert call_args[1]["language"] == "python"
        assert call_args[1]["file_name"] == "test_snippet.py"

    @pytest.mark.asyncio
    async def test_execute_scan_diff_type(self):
        """Test execute_scan for diff scan type."""
        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            language="python",
            metadata=ScanMetadata.for_diff_scan("main", "feature"),
        )

        request = ScanRequest(context=context)

        mock_threat = ScannerThreatMatch(
            rule_id="diff_issue",
            rule_name="Issue in Changed Code",
            description="Issue found in changed code",
            category=Category.INJECTION,
            severity=Severity.MEDIUM,
            file_path=__file__,
            line_number=1,
            confidence=0.8,
        )

        self.mock_scanner.analyze_file_with_context = AsyncMock(
            return_value=[mock_threat]
        )

        result = await self.adapter.execute_scan(request)

        # Verify context hint includes diff-specific guidance
        call_args = self.mock_scanner.analyze_file_with_context.call_args
        context_hint = call_args[1]["context_hint"]
        assert "recent changes" in context_hint.lower()

    @pytest.mark.asyncio
    async def test_execute_scan_with_none_scanner(self):
        """Test execute_scan with None scanner."""
        adapter = SessionAwareLLMScanStrategy(None)

        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            metadata=ScanMetadata.for_file_scan(),
        )

        request = ScanRequest(context=context)

        result = await adapter.execute_scan(request)

        # Should return empty result
        assert len(result.threats) == 0
        assert result.scan_metadata["scanner"] == "session_aware_llm_analysis"

    @pytest.mark.asyncio
    async def test_severity_filtering(self):
        """Test severity threshold filtering."""
        context = ScanContext(
            target_path=FilePath.from_string(
                __file__
            ),  # Use this test file as a real path
            metadata=ScanMetadata.for_file_scan(),
        )

        request = ScanRequest(
            context=context, severity_threshold=SeverityLevel.from_string("high")
        )

        # Mock threats with different severities
        mock_threats = [
            ScannerThreatMatch(
                rule_id="critical_issue",
                rule_name="Critical Issue",
                description="Critical security issue",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path=__file__,
                line_number=1,
                confidence=0.9,
            ),
            ScannerThreatMatch(
                rule_id="high_issue",
                rule_name="High Issue",
                description="High security issue",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path=__file__,
                line_number=2,
                confidence=0.8,
            ),
            ScannerThreatMatch(
                rule_id="medium_issue",
                rule_name="Medium Issue",
                description="Medium security issue",
                category=Category.INJECTION,
                severity=Severity.MEDIUM,
                file_path=__file__,
                line_number=3,
                confidence=0.7,
            ),
            ScannerThreatMatch(
                rule_id="low_issue",
                rule_name="Low Issue",
                description="Low security issue",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path=__file__,
                line_number=4,
                confidence=0.6,
            ),
        ]

        self.mock_scanner.analyze_file_with_context = AsyncMock(
            return_value=mock_threats
        )

        result = await self.adapter.execute_scan(request)

        # Should only include HIGH and CRITICAL
        assert len(result.threats) == 2
        severities = [str(threat.severity) for threat in result.threats]
        assert "critical" in severities
        assert "high" in severities
        assert "medium" not in severities
        assert "low" not in severities

    @pytest.mark.asyncio
    async def test_confidence_filtering(self):
        """Test confidence threshold filtering."""
        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            metadata=ScanMetadata.for_file_scan(),
        )

        request = ScanRequest(context=context)

        # Mock threats with different confidence levels
        mock_threats = [
            DomainThreatMatch.create_llm_threat(
                rule_id="high_confidence",
                rule_name="High Confidence Threat",
                description="High confidence test description",
                category="misc",
                severity="high",
                file_path=__file__,
                line_number=1,
                confidence=0.9,  # Above threshold
            ),
            DomainThreatMatch.create_llm_threat(
                rule_id="medium_confidence",
                rule_name="Medium Confidence Threat",
                description="Medium confidence test description",
                category="misc",
                severity="high",
                file_path=__file__,
                line_number=2,
                confidence=0.65,  # Above threshold
            ),
            DomainThreatMatch.create_llm_threat(
                rule_id="low_confidence",
                rule_name="Low Confidence Threat",
                description="Low confidence test description",
                category="misc",
                severity="high",
                file_path=__file__,
                line_number=3,
                confidence=0.5,  # Below threshold (0.6)
            ),
        ]

        self.mock_scanner.analyze_file_with_context = AsyncMock(
            return_value=mock_threats
        )

        result = await self.adapter.execute_scan(request)

        # Should filter out low confidence findings
        assert len(result.threats) == 2
        rule_ids = [threat.rule_id for threat in result.threats]
        assert "high_confidence" in rule_ids
        assert "medium_confidence" in rule_ids
        assert "low_confidence" not in rule_ids

    def test_find_project_root(self):
        """Test project root detection."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create nested structure
            project_root = temp_path / "project"
            src_dir = project_root / "src"
            src_dir.mkdir(parents=True)
            test_file = src_dir / "app.py"
            test_file.write_text("# test")

            # Create project indicator
            (project_root / ".git").mkdir()

            # Test project root detection
            detected_root = self.adapter._find_project_root(test_file)
            assert detected_root == project_root

    def test_find_project_root_no_indicators(self):
        """Test project root detection without indicators."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "standalone.py"
            test_file.write_text("# standalone")

            # Should fall back to file's parent directory
            detected_root = self.adapter._find_project_root(test_file)
            assert detected_root == test_file.parent

    def test_create_context_hint(self):
        """Test context hint creation."""
        # Test with Python language
        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            language="python",
            metadata=ScanMetadata.for_file_scan(),
        )

        request = ScanRequest(
            context=context, severity_threshold=SeverityLevel.from_string("high")
        )

        hint = self.adapter._create_context_hint(request)

        assert "Flask/Django" in hint or "Python" in hint
        # Should include severity-based hints for high threshold
        assert "high-impact" in hint or "system compromise" in hint

    def test_create_context_hint_javascript(self):
        """Test context hint for JavaScript."""
        context = ScanContext(
            target_path=FilePath.from_string(
                "/Users/brettbergin/code/adversary-mcp-server/examples/vulnerable_javascript.js"
            ),
            language="javascript",
            metadata=ScanMetadata.for_directory_scan(),
        )

        request = ScanRequest(context=context)

        hint = self.adapter._create_context_hint(request)

        assert "XSS" in hint or "JavaScript" in hint
        assert "comprehensive" in hint

    def test_create_analysis_focus(self):
        """Test analysis focus creation."""
        context = ScanContext(
            target_path=FilePath.from_string(
                "/Users/brettbergin/code/adversary-mcp-server"
            ),
            language="python",
            metadata=ScanMetadata.for_directory_scan(),
        )

        request = ScanRequest(
            context=context, severity_threshold=SeverityLevel.from_string("critical")
        )

        focus = self.adapter._create_analysis_focus(request)

        assert "comprehensive security analysis" in focus
        assert "python security patterns" in focus
        # Should include severity-based focus for critical threshold
        assert "high-impact" in focus or "prioritizing" in focus

    @pytest.mark.asyncio
    async def test_convert_to_domain_threats(self):
        """Test conversion to domain threats with metadata enhancement."""
        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            metadata=ScanMetadata.for_file_scan(),
        )

        request = ScanRequest(context=context)

        # Mock threat from scanner
        mock_threat = ScannerThreatMatch(
            rule_id="original_rule",
            rule_name="Original Name",
            description="Test description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path=__file__,
            line_number=1,
            confidence=0.8,
        )

        enhanced_threats = self.adapter._convert_to_domain_threats(
            [mock_threat], request
        )

        assert len(enhanced_threats) == 1
        enhanced_threat = enhanced_threats[0]

        # Should have enhanced metadata
        assert enhanced_threat.metadata["scan_request_id"] == id(
            request
        )  # Use object id
        assert enhanced_threat.metadata["scan_type"] == "file"
        assert enhanced_threat.metadata["session_aware"] is True
        assert enhanced_threat.metadata["context_loaded"] is True

    def test_apply_severity_filter(self):
        """Test severity filtering logic."""
        # Create domain threats directly
        domain_threats = [
            DomainThreatMatch.create_llm_threat(
                rule_id="critical",
                rule_name="Critical Test",
                description="Critical test description",
                category="misc",
                severity="critical",
                file_path=__file__,
                line_number=1,
                confidence=0.9,
            ),
            DomainThreatMatch.create_llm_threat(
                rule_id="high",
                rule_name="High Test",
                description="High test description",
                category="misc",
                severity="high",
                file_path=__file__,
                line_number=2,
                confidence=0.8,
            ),
            DomainThreatMatch.create_llm_threat(
                rule_id="medium",
                rule_name="Medium Test",
                description="Medium test description",
                category="misc",
                severity="medium",
                file_path=__file__,
                line_number=3,
                confidence=0.7,
            ),
            DomainThreatMatch.create_llm_threat(
                rule_id="low",
                rule_name="Low Test",
                description="Low test description",
                category="misc",
                severity="low",
                file_path=__file__,
                line_number=4,
                confidence=0.6,
            ),
        ]

        # Test filtering with HIGH threshold
        high_threshold = SeverityLevel.from_string("high")
        filtered = self.adapter._apply_severity_filter(domain_threats, high_threshold)

        assert len(filtered) == 2  # CRITICAL and HIGH only
        rule_ids = [t.rule_id for t in filtered]
        assert "critical" in rule_ids
        assert "high" in rule_ids

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in execute_scan."""
        context = ScanContext(
            target_path=FilePath.from_string(__file__),
            metadata=ScanMetadata.for_file_scan(),
        )

        request = ScanRequest(context=context)

        # Mock scanner to raise exception
        self.mock_scanner.analyze_file_with_context = AsyncMock(
            side_effect=Exception("Scanner error")
        )

        with pytest.raises(Exception) as exc_info:
            await self.adapter.execute_scan(request)

        # Should wrap in ScanError
        assert "Session-aware LLM scan failed" in str(exc_info.value)


@pytest.fixture
def temp_project_for_adapter():
    """Create temporary project for adapter testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        project_root = Path(temp_dir) / "adapter_test_project"
        project_root.mkdir()

        # Create project structure
        (project_root / "package.json").write_text('{"name": "test-project"}')
        (project_root / "src").mkdir()
        (project_root / "src" / "index.js").write_text(
            """
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // Vulnerable to SQL injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});
"""
        )

        yield project_root


class TestSessionAwareLLMScanStrategyIntegration:
    """Integration tests for SessionAwareLLMScanStrategy."""

    @pytest.mark.asyncio
    async def test_full_adapter_workflow(self, temp_project_for_adapter):
        """Test complete adapter workflow with realistic project."""
        mock_scanner = Mock()
        adapter = SessionAwareLLMScanStrategy(mock_scanner)

        # Mock scanner responses
        sql_injection_threat = DomainThreatMatch.create_llm_threat(
            rule_id="sql_injection_template_literal",
            rule_name="SQL Injection via Template Literal",
            description="User input directly interpolated into SQL query",
            category="injection",
            severity="critical",
            file_path="src/index.js",
            line_number=7,
            confidence=0.95,
            code_snippet="const query = `SELECT * FROM users WHERE id = ${userId}`;",
        )

        mock_scanner.is_available.return_value = True
        mock_scanner.analyze_project_with_session = AsyncMock(
            return_value=[sql_injection_threat]
        )

        # Create scan request for directory analysis
        context = ScanContext(
            target_path=FilePath.from_string(str(temp_project_for_adapter)),
            language="javascript",
            metadata=ScanMetadata.for_directory_scan(),
        )

        request = ScanRequest(
            context=context, severity_threshold=SeverityLevel.from_string("medium")
        )

        # Execute scan
        result = await adapter.execute_scan(request)

        # Verify scanner was called appropriately
        mock_scanner.analyze_project_with_session.assert_called_once()
        call_args = mock_scanner.analyze_project_with_session.call_args
        # Use resolve() to handle symlinks like /private/var -> /var on macOS
        assert (
            call_args[1]["project_root"].resolve() == temp_project_for_adapter.resolve()
        )
        assert "comprehensive" in call_args[1]["analysis_focus"]

        # Verify results
        assert len(result.threats) == 1
        threat = result.threats[0]
        assert threat.rule_id == "sql_injection_template_literal"
        assert threat.severity == SeverityLevel.from_string("critical")
        assert threat.confidence.value == 0.95

        # Verify domain metadata
        assert threat.metadata["session_aware"] is True
        assert threat.metadata["context_loaded"] is True
        assert threat.metadata["scan_type"] == "directory"

        # Verify scan result metadata
        assert result.scan_metadata["scanner"] == "session_aware_llm_analysis"
        assert result.scan_metadata["analysis_type"] == "session_aware_ai"
        assert result.scan_metadata["cross_file_analysis"] is True
        assert result.scan_metadata["total_findings"] == 1
        assert result.scan_metadata["filtered_findings"] == 1

    @pytest.mark.asyncio
    async def test_adapter_with_multiple_languages(self, temp_project_for_adapter):
        """Test adapter handling multiple languages in project."""
        mock_scanner = Mock()
        adapter = SessionAwareLLMScanStrategy(mock_scanner)

        # Add Python file to the JavaScript project
        python_file = temp_project_for_adapter / "scripts" / "deploy.py"
        python_file.parent.mkdir()
        python_file.write_text(
            """
import os
import subprocess

def deploy_app(branch):
    # Vulnerable command injection
    command = f"git checkout {branch} && npm run build"
    subprocess.shell(command, shell=True)
"""
        )

        # Mock threats from different languages
        js_threat = DomainThreatMatch.create_llm_threat(
            rule_id="js_sql_injection",
            rule_name="JS SQL Injection",
            description="SQL injection in JavaScript",
            category="injection",
            severity="high",
            file_path="src/index.js",
            line_number=1,
            confidence=0.9,
        )

        python_threat = DomainThreatMatch.create_llm_threat(
            rule_id="python_command_injection",
            rule_name="Python Command Injection",
            description="Command injection in Python",
            category="injection",
            severity="critical",
            file_path="scripts/deploy.py",
            line_number=1,
            confidence=0.95,
        )

        mock_scanner.is_available.return_value = True
        mock_scanner.analyze_project_with_session = AsyncMock(
            return_value=[js_threat, python_threat]
        )

        context = ScanContext(
            target_path=FilePath.from_string(str(temp_project_for_adapter)),
            metadata=ScanMetadata.for_directory_scan(),
        )

        request = ScanRequest(context=context)

        result = await adapter.execute_scan(request)

        # Should handle both languages
        assert len(result.threats) == 2

        # Verify language diversity is handled
        file_paths = [str(threat.file_path) for threat in result.threats]
        assert any("src/index.js" in fp for fp in file_paths)
        assert any("scripts/deploy.py" in fp for fp in file_paths)

    @pytest.mark.asyncio
    async def test_adapter_performance_with_large_result_set(self):
        """Test adapter performance with large number of findings."""
        mock_scanner = Mock()
        adapter = SessionAwareLLMScanStrategy(mock_scanner)

        # Generate large number of mock threats
        mock_threats = []
        for i in range(100):
            threat = DomainThreatMatch.create_llm_threat(
                rule_id=f"rule_{i}",
                rule_name=f"Rule {i}",
                description=f"Description for rule {i}",
                category="misc",
                severity="medium" if i % 2 == 0 else "high",
                file_path=__file__,  # Use this test file as a real path
                line_number=i + 1,
                confidence=0.7 + (i % 3) * 0.1,  # Varying confidence
            )
            mock_threats.append(threat)

        mock_scanner.is_available.return_value = True
        mock_scanner.analyze_project_with_session = AsyncMock(return_value=mock_threats)

        context = ScanContext(
            target_path=FilePath.from_string(
                "/Users/brettbergin/code/adversary-mcp-server"
            ),
            metadata=ScanMetadata.for_directory_scan(),
        )

        request = ScanRequest(
            context=context, severity_threshold=SeverityLevel.from_string("high")
        )

        result = await adapter.execute_scan(request)

        # Should filter appropriately and handle large sets efficiently
        # HIGH threshold should filter out MEDIUM findings
        assert len(result.threats) == 50  # Only HIGH severity findings

        # Verify all results are properly converted to domain objects
        for threat in result.threats:
            assert isinstance(threat.severity, SeverityLevel)
            assert isinstance(threat.confidence, ConfidenceScore)
            assert threat.metadata["session_aware"] is True
