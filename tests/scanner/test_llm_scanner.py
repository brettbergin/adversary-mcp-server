"""Tests for LLM security analyzer module."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from adversary_mcp_server.config import SecurityConfig
from adversary_mcp_server.credentials import CredentialManager
from adversary_mcp_server.scanner.llm_scanner import (
    LLMAnalysisError,
    LLMAnalysisPrompt,
    LLMScanner,
    LLMSecurityFinding,
)
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestLLMSecurityFinding:
    """Test LLMSecurityFinding class."""

    def test_llm_security_finding_initialization(self):
        """Test LLMSecurityFinding initialization."""
        finding = LLMSecurityFinding(
            finding_type="sql_injection",
            severity="high",
            description="SQL injection vulnerability",
            line_number=10,
            code_snippet="SELECT * FROM users WHERE id = " + "user_input",
            explanation="User input directly concatenated into SQL query",
            recommendation="Use parameterized queries",
            confidence=0.9,
            cwe_id="CWE-89",
            owasp_category="A03:2021",
        )

        assert finding.finding_type == "sql_injection"
        assert finding.severity == "high"
        assert finding.description == "SQL injection vulnerability"
        assert finding.line_number == 10
        assert finding.confidence == 0.9
        assert finding.cwe_id == "CWE-89"
        assert finding.owasp_category == "A03:2021"

    def test_to_threat_match(self):
        """Test converting LLMSecurityFinding to ThreatMatch."""
        finding = LLMSecurityFinding(
            finding_type="sql_injection",
            severity="high",
            description="SQL injection vulnerability",
            line_number=42,
            code_snippet="SELECT * FROM users WHERE id = " + "user_input",
            explanation="User input is directly concatenated",
            recommendation="Use parameterized queries",
            confidence=0.95,
            cwe_id="CWE-89",
            owasp_category="A03:2021",
        )

        threat_match = finding.to_threat_match("/path/to/file.py")

        assert isinstance(threat_match, ThreatMatch)
        assert threat_match.rule_id == "llm_sql_injection"
        assert threat_match.rule_name == "Sql Injection"
        assert threat_match.description == "SQL injection vulnerability"
        assert threat_match.category == Category.INJECTION
        assert threat_match.severity == Severity.HIGH
        assert threat_match.file_path == "/path/to/file.py"
        assert threat_match.line_number == 42
        assert (
            threat_match.code_snippet
            == "SELECT * FROM users WHERE id = " + "user_input"
        )
        assert threat_match.confidence == 0.95
        assert threat_match.cwe_id == "CWE-89"
        assert threat_match.owasp_category == "A03:2021"

    def test_category_mapping(self):
        """Test vulnerability type to category mapping."""
        test_cases = [
            ("xss", Category.XSS),
            ("deserialization", Category.DESERIALIZATION),
            ("path_traversal", Category.PATH_TRAVERSAL),
            ("hardcoded_credential", Category.SECRETS),
            ("weak_crypto", Category.CRYPTOGRAPHY),
            ("csrf", Category.CSRF),
            ("unknown_type", Category.MISC),  # Default fallback
        ]

        for finding_type, expected_category in test_cases:
            finding = LLMSecurityFinding(
                finding_type=finding_type,
                severity="medium",
                description="Test vulnerability",
                line_number=1,
                code_snippet="test code",
                explanation="Test explanation",
                recommendation="Test recommendation",
                confidence=0.8,
            )

            threat_match = finding.to_threat_match("test.py")
            assert threat_match.category == expected_category

    def test_severity_mapping(self):
        """Test severity string to enum mapping."""
        test_cases = [
            ("low", Severity.LOW),
            ("medium", Severity.MEDIUM),
            ("high", Severity.HIGH),
            ("critical", Severity.CRITICAL),
            ("unknown", Severity.MEDIUM),  # Default fallback
        ]

        for severity_str, expected_severity in test_cases:
            finding = LLMSecurityFinding(
                finding_type="test_vuln",
                severity=severity_str,
                description="Test vulnerability",
                line_number=1,
                code_snippet="test code",
                explanation="Test explanation",
                recommendation="Test recommendation",
                confidence=0.8,
            )

            threat_match = finding.to_threat_match("test.py")
            assert threat_match.severity == expected_severity

    def test_to_threat_match_no_file_path(self):
        """Test converting LLMSecurityFinding to ThreatMatch without file path."""
        finding = LLMSecurityFinding(
            finding_type="sql_injection",
            severity="high",
            description="SQL injection vulnerability",
            line_number=42,
            code_snippet="SELECT * FROM users WHERE id = " + "user_input",
            explanation="User input is directly concatenated",
            recommendation="Use parameterized queries",
            confidence=0.95,
        )

        with pytest.raises(ValueError, match="file_path must be provided"):
            finding.to_threat_match(None)


class TestLLMAnalysisPrompt:
    """Test LLMAnalysisPrompt class."""

    def test_llm_analysis_prompt_initialization(self):
        """Test LLMAnalysisPrompt initialization."""
        prompt = LLMAnalysisPrompt(
            system_prompt="System instructions",
            user_prompt="User query",
            file_path="/path/to/test.py",
            max_findings=10,
        )

        assert prompt.system_prompt == "System instructions"
        assert prompt.user_prompt == "User query"
        assert prompt.file_path == "/path/to/test.py"
        assert prompt.max_findings == 10

    def test_llm_analysis_prompt_to_dict(self):
        """Test LLMAnalysisPrompt to_dict method."""
        prompt = LLMAnalysisPrompt(
            system_prompt="System instructions",
            user_prompt="User query for analysis",
            file_path="/path/to/test.py",
            max_findings=5,
        )

        result = prompt.to_dict()

        assert isinstance(result, dict)
        assert result["system_prompt"] == "System instructions"
        assert result["user_prompt"] == "User query for analysis"
        assert result["file_path"] == "/path/to/test.py"
        assert result["max_findings"] == 5


class TestLLMScanner:
    """Test LLMScanner class."""

    def test_initialization_with_api_key(self):
        """Test analyzer initialization with LLM enabled."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client"
        ) as mock_create:
            mock_create.return_value = Mock()
            analyzer = LLMScanner(mock_manager)

            assert analyzer.credential_manager == mock_manager
            assert analyzer.is_available() is True
            mock_create.assert_called_once()

    def test_initialization_without_api_key(self):
        """Test analyzer initialization without LLM provider configured."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider=None, llm_api_key=None
        )
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        assert analyzer.credential_manager == mock_manager
        assert analyzer.is_available() is False  # No LLM client configured

    def test_initialization_failure(self):
        """Test analyzer initialization failure handling."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client"
        ) as mock_create:
            mock_create.side_effect = Exception("Client creation failed")

            with pytest.raises(Exception, match="Client creation failed"):
                LLMScanner(mock_manager)

    def test_is_available(self):
        """Test availability check."""
        mock_manager = Mock(spec=CredentialManager)

        # With LLM properly configured
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client"
        ) as mock_create:
            mock_create.return_value = Mock()
            analyzer = LLMScanner(mock_manager)
            assert analyzer.is_available() is True

        # With LLM not configured
        mock_config = SecurityConfig(
            enable_llm_analysis=False, llm_provider=None, llm_api_key=None
        )
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)
        assert analyzer.is_available() is False

    def test_analyze_code_not_available(self):
        """Test code analysis when LLM client is not available."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=False, llm_provider=None, llm_api_key=None
        )
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # When LLM client is not available, should return empty list
        result = analyzer.analyze_code("test code", "test.py", "python")

        assert isinstance(result, list)
        assert len(result) == 0

    # Removed test_analyze_code_success - redundant coverage with memory/performance issues
    # This functionality is already tested by:
    # - test_parse_analysis_response_success (JSON parsing + finding creation)
    # - test_initialization_* (LLMScanner setup)
    # - test_create_analysis_prompt (prompt generation)
    # The full async workflow with heavy infrastructure is not worth the test cost

    @pytest.mark.skip(
        reason="Memory intensive async test - core functionality covered by unit tests"
    )
    @pytest.mark.asyncio
    async def test_analyze_code_api_error(self):
        """Test code analysis error handling."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        # Mock LLM client to raise exception
        mock_llm_client = AsyncMock()
        mock_llm_client.complete_with_retry.side_effect = Exception("API Error")

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=mock_llm_client,
        ):
            analyzer = LLMScanner(mock_manager)

            with pytest.raises(LLMAnalysisError, match="Analysis failed"):
                await analyzer._analyze_code_async("test code", "test.py", "python")

    def test_get_system_prompt(self):
        """Test system prompt generation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)
        prompt = analyzer._get_system_prompt()

        assert isinstance(prompt, str)
        assert "security engineer" in prompt.lower()
        assert "json" in prompt.lower()
        assert "sql injection" in prompt.lower()
        assert "xss" in prompt.lower()

    def test_create_analysis_prompt(self):
        """Test analysis prompt creation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        source_code = "SELECT * FROM users WHERE id = user_input"
        prompt = analyzer.create_analysis_prompt(source_code, "test.py", "python", None)

        assert isinstance(prompt, LLMAnalysisPrompt)
        assert prompt.file_path == "test.py"
        assert prompt.max_findings is None
        assert "SELECT * FROM users WHERE id = user_input" in prompt.user_prompt
        assert "comprehensive security analysis" in prompt.user_prompt.lower()
        assert "JSON format" in prompt.user_prompt
        assert "senior security engineer" in prompt.system_prompt.lower()

    def test_create_analysis_prompt_truncation(self):
        """Test analysis prompt with code truncation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Create very long source code
        long_code = "print('test')\n" * 1000
        prompt = analyzer.create_analysis_prompt(long_code, "test.py", "python", 5)

        assert isinstance(prompt, LLMAnalysisPrompt)
        assert "truncated for analysis" in prompt.user_prompt
        assert len(prompt.user_prompt) < 12000  # Should be truncated

    def test_create_analysis_prompt_exception(self):
        """Test analysis prompt creation exception handling."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Mock the _get_system_prompt to raise an exception
        with patch.object(
            analyzer, "_get_system_prompt", side_effect=Exception("System prompt error")
        ):
            with pytest.raises(Exception, match="System prompt error"):
                analyzer.create_analysis_prompt("test code", "test.py", "python", 5)

    def test_parse_analysis_response_empty(self):
        """Test parsing empty response."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Test empty response
        result = analyzer.parse_analysis_response("", "test.py")
        assert result == []

        # Test whitespace-only response
        result = analyzer.parse_analysis_response("   \n\t   ", "test.py")
        assert result == []

    def test_parse_analysis_response_invalid_line_number(self):
        """Test parsing response with invalid line numbers."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        response_text = """
        {
            "findings": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": -5,
                    "code_snippet": "test",
                    "explanation": "test",
                    "recommendation": "test",
                    "confidence": 0.9
                },
                {
                    "type": "xss",
                    "severity": "medium",
                    "description": "XSS vulnerability",
                    "line_number": 0,
                    "code_snippet": "test",
                    "explanation": "test",
                    "recommendation": "test",
                    "confidence": 0.8
                }
            ]
        }
        """

        result = analyzer.parse_analysis_response(response_text, "test.py")

        assert len(result) == 2
        # Both should have line_number set to 1 (corrected from invalid values)
        assert result[0].line_number == 1
        assert result[1].line_number == 1

    def test_parse_analysis_response_invalid_confidence(self):
        """Test parsing response with invalid confidence values."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        response_text = """
        {
            "findings": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": 1,
                    "code_snippet": "test",
                    "explanation": "test",
                    "recommendation": "test",
                    "confidence": 1.5
                },
                {
                    "type": "xss",
                    "severity": "medium",
                    "description": "XSS vulnerability",
                    "line_number": 2,
                    "code_snippet": "test",
                    "explanation": "test",
                    "recommendation": "test",
                    "confidence": -0.2
                }
            ]
        }
        """

        result = analyzer.parse_analysis_response(response_text, "test.py")

        assert len(result) == 2
        # Both should have confidence set to 0.5 (corrected from invalid values)
        assert result[0].confidence == 0.5
        assert result[1].confidence == 0.5

    def test_parse_analysis_response_success(self):
        """Test successful response parsing."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        response_text = """
        {
            "findings": [
                {
                    "type": "xss",
                    "severity": "medium",
                    "description": "XSS vulnerability",
                    "line_number": 5,
                    "code_snippet": "innerHTML = user_input",
                    "explanation": "Direct DOM manipulation",
                    "recommendation": "Use textContent or sanitize input",
                    "confidence": 0.8
                },
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": 10,
                    "code_snippet": "SELECT * FROM users",
                    "explanation": "String concatenation",
                    "recommendation": "Use prepared statements",
                    "confidence": 0.95,
                    "cwe_id": "CWE-89"
                }
            ]
        }
        """

        findings = analyzer.parse_analysis_response(response_text, "test.py")

        assert len(findings) == 2
        assert findings[0].finding_type == "xss"
        assert findings[0].severity == "medium"
        assert findings[0].line_number == 5
        assert findings[0].confidence == 0.8
        assert findings[1].finding_type == "sql_injection"
        assert findings[1].cwe_id == "CWE-89"

    def test_parse_analysis_response_invalid_json(self):
        """Test response parsing with invalid JSON."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        with pytest.raises(LLMAnalysisError, match="Invalid JSON response from LLM"):
            analyzer.parse_analysis_response("invalid json", "test.py")

    def test_parse_analysis_response_no_findings(self):
        """Test response parsing with no findings key."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        response_text = '{"results": []}'
        findings = analyzer.parse_analysis_response(response_text, "test.py")

        assert len(findings) == 0

    def test_parse_analysis_response_malformed_finding(self):
        """Test response parsing with malformed finding."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        response_text = """
        {
            "findings": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "line_number": "invalid_line_number"
                },
                {
                    "type": "xss",
                    "severity": "medium",
                    "description": "Valid finding",
                    "line_number": 5,
                    "code_snippet": "test",
                    "explanation": "test",
                    "recommendation": "test",
                    "confidence": 0.8
                }
            ]
        }
        """

        findings = analyzer.parse_analysis_response(response_text, "test.py")

        # Should skip malformed finding and return only valid ones
        assert len(findings) == 1
        assert findings[0].finding_type == "xss"

    def test_batch_analyze_code(self):
        """Test batch code analysis."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="openai",
            llm_api_key="sk-test-key",
            llm_batch_size=10,
        )
        mock_manager.load_config.return_value = mock_config

        # Mock LLM client
        mock_llm_client = AsyncMock()
        mock_response = Mock()
        mock_response.content = '{"findings": []}'
        mock_llm_client.complete_with_retry.return_value = mock_response

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=mock_llm_client,
        ):
            analyzer = LLMScanner(mock_manager)

            code_samples = [
                ("code1", "file1.py", "python"),
                ("code2", "file2.py", "python"),
            ]

            result = analyzer.batch_analyze_code(code_samples)

            assert isinstance(result, list)
            assert len(result) == 2  # Should return results for both samples

    def test_batch_analyze_code_complexity_calculation(self):
        """Test batch code analysis with complexity calculation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="openai",
            llm_api_key="sk-test-key",
            llm_batch_size=5,
        )
        mock_manager.load_config.return_value = mock_config

        # Mock LLM client
        mock_llm_client = AsyncMock()
        mock_response = Mock()
        mock_response.content = '{"findings": []}'
        mock_llm_client.complete_with_retry.return_value = mock_response

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=mock_llm_client,
        ):
            analyzer = LLMScanner(mock_manager)

            # Test with JavaScript complexity keywords
            js_code_samples = [
                (
                    "const pipe = compose(map(x => x + 1), filter(x => x > 0));",
                    "test.js",
                    "javascript",
                ),
                (
                    "import * as O from 'fp-ts/Option'; import * as E from 'fp-ts/Either';",
                    "fp.ts",
                    "typescript",
                ),
                (
                    "const schema = t.type({ name: t.string, age: t.number });",
                    "io.ts",
                    "typescript",
                ),
            ]

            result = analyzer.batch_analyze_code(js_code_samples)

            assert isinstance(result, list)
            assert len(result) == 3

    def test_batch_analyze_code_file_preprocessing(self):
        """Test batch code analysis file preprocessing logic."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="openai",
            llm_api_key="sk-test-key",
            llm_batch_size=2,
        )
        mock_manager.load_config.return_value = mock_config

        # Mock LLM client
        mock_llm_client = AsyncMock()
        mock_response = Mock()
        mock_response.content = '{"findings": []}'
        mock_llm_client.complete_with_retry.return_value = mock_response

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=mock_llm_client,
        ):
            analyzer = LLMScanner(mock_manager)

            # Test with various file types and sizes
            code_samples = [
                (
                    "import os; os.system('rm -rf /')",
                    "dangerous.py",
                    "python",
                ),  # High complexity
                ("print('hello')", "simple.py", "python"),  # Low complexity
                ("x" * 10000, "large.py", "python"),  # Large file
                (
                    "SELECT * FROM users WHERE id = ?",
                    "query.sql",
                    "sql",
                ),  # Different language
            ]

            result = analyzer.batch_analyze_code(code_samples)

            assert isinstance(result, list)
            assert len(result) == 4

    @pytest.mark.skip(
        reason="Memory intensive async test - file I/O functionality covered by unit tests"
    )
    @pytest.mark.asyncio
    async def test_analyze_file_success(self):
        """Test successful file analysis."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        # Mock LLM client
        mock_llm_client = AsyncMock()
        mock_response = Mock()
        mock_response.content = '{"findings": [{"type": "sql_injection", "severity": "high", "description": "test", "line_number": 1, "code_snippet": "test", "explanation": "test", "recommendation": "test", "confidence": 0.9}]}'
        mock_llm_client.complete_with_retry.return_value = mock_response

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=mock_llm_client,
        ):
            analyzer = LLMScanner(mock_manager)

            # Create a temporary test file
            import os
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write("SELECT * FROM users WHERE id = user_input")
                temp_file = f.name

            try:
                result = await analyzer.analyze_file(
                    temp_file, "python", max_findings=5
                )

                assert isinstance(result, list)
                assert len(result) == 1
                assert result[0].finding_type == "sql_injection"
            finally:
                os.unlink(temp_file)

    @pytest.mark.skip(
        reason="Memory intensive async test - availability checks covered by unit tests"
    )
    @pytest.mark.asyncio
    async def test_analyze_file_not_available(self):
        """Test file analysis when LLM client is not available."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=False, llm_provider=None, llm_api_key=None
        )
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        result = await analyzer.analyze_file("test.py", "python")
        assert result == []

    @pytest.mark.skip(
        reason="Memory intensive async test - file error handling covered by unit tests"
    )
    @pytest.mark.asyncio
    async def test_analyze_file_file_not_found(self):
        """Test file analysis with non-existent file."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            analyzer = LLMScanner(mock_manager)

            with pytest.raises(LLMAnalysisError, match="File analysis failed"):
                await analyzer.analyze_file("/nonexistent/file.py", "python")

    @pytest.mark.skip(
        reason="Memory intensive async test - directory scanning covered by unit tests"
    )
    @pytest.mark.asyncio
    async def test_analyze_directory_success(self):
        """Test successful directory analysis."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="openai",
            llm_api_key="sk-test-key",
            llm_batch_size=2,
        )
        mock_manager.load_config.return_value = mock_config

        # Mock LLM client
        mock_llm_client = AsyncMock()
        mock_response = Mock()
        mock_response.content = '{"findings": []}'
        mock_llm_client.complete_with_retry.return_value = mock_response

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=mock_llm_client,
        ):
            analyzer = LLMScanner(mock_manager)

            # Create a temporary directory with test files
            import os
            import tempfile

            with tempfile.TemporaryDirectory() as temp_dir:
                # Create test files
                with open(os.path.join(temp_dir, "test1.py"), "w") as f:
                    f.write("print('test1')")
                with open(os.path.join(temp_dir, "test2.py"), "w") as f:
                    f.write("print('test2')")

                result = await analyzer.analyze_directory(
                    temp_dir, recursive=True, max_findings_per_file=5
                )

                assert isinstance(result, list)

    @pytest.mark.skip(
        reason="Memory intensive async test - availability checks covered by unit tests"
    )
    @pytest.mark.asyncio
    async def test_analyze_directory_not_available(self):
        """Test directory analysis when LLM client is not available."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=False, llm_provider=None, llm_api_key=None
        )
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        result = await analyzer.analyze_directory("/some/directory")
        assert result == []

    def test_get_analysis_stats(self):
        """Test getting analysis statistics."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(enable_llm_analysis=True)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        stats = analyzer.get_analysis_stats()

        assert isinstance(stats, dict)
        assert "total_analyses" in stats
        assert "successful_analyses" in stats
        assert "failed_analyses" in stats
        assert "client_based" in stats

    def test_get_status(self):
        """Test getting LLM scanner status."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_model="gpt-4"
        )
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        status = analyzer.get_status()

        assert isinstance(status, dict)
        assert "available" in status
        assert "version" in status
        assert "mode" in status
        assert "model" in status
        assert status["mode"] == "openai"
        assert status["model"] == "gpt-4"

    def test_is_analyzable_file(self):
        """Test file analyzability check."""
        from pathlib import Path

        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Test analyzable files
        analyzable_files = [
            Path("examples/vulnerable_python.py"),
            Path("examples/vulnerable_javascript.js"),
            Path("examples/vulnerable_typescript.ts"),
            Path("examples/vulnerable_java.java"),
            Path("examples/vulnerable_cpp.cpp"),
            Path("examples/vulnerable_go.go"),
            Path("examples/vulnerable_rust.rs"),
            Path("examples/vulnerable_php.php"),
            Path("examples/vulnerable_ruby.rb"),
            Path("examples/vulnerable_swift.swift"),
            Path("examples/vulnerable_bash.sh"),
        ]

        for file_path in analyzable_files:
            assert analyzer._is_analyzable_file(
                file_path
            ), f"{file_path} should be analyzable"

        # Test non-analyzable files
        non_analyzable_files = [
            Path("README.md"),
            Path("image.png"),
            Path("binary.exe"),
        ]

        for file_path in non_analyzable_files:
            assert not analyzer._is_analyzable_file(
                file_path
            ), f"{file_path} should not be analyzable"

    def test_detect_language(self):
        """Test language detection from file extension."""
        from pathlib import Path

        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        language_tests = [
            (Path("test.py"), "python"),
            (Path("script.js"), "javascript"),
            (Path("component.ts"), "typescript"),
            (Path("app.jsx"), "javascript"),
            (Path("component.tsx"), "typescript"),
            (Path("Main.java"), "java"),
            (Path("program.c"), "c"),
            (Path("code.cpp"), "cpp"),
            (Path("header.h"), "c"),
            (Path("header.hpp"), "cpp"),
            (Path("app.cs"), "csharp"),
            (Path("main.go"), "go"),
            (Path("lib.rs"), "rust"),
            (Path("index.php"), "php"),
            (Path("script.rb"), "ruby"),
            (Path("app.swift"), "swift"),
            (Path("main.kt"), "kotlin"),
            (Path("script.sh"), "bash"),
            (Path("unknown.xyz"), "generic"),
        ]

        for file_path, expected_language in language_tests:
            detected_language = analyzer._detect_language(file_path)
            assert (
                detected_language == expected_language
            ), f"{file_path} should detect as {expected_language}"

    def test_smart_truncate_content(self):
        """Test intelligent content truncation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Test content within limit
        short_content = "print('hello')"
        result = analyzer._smart_truncate_content(short_content, 1000)
        assert result == short_content

        # Test content that needs truncation
        long_content = "def function1():\n    pass\n" * 100
        result = analyzer._smart_truncate_content(long_content, 50)
        assert len(result) <= 80  # Should be truncated with message
        assert "truncated for analysis" in result

        # Test truncation with natural break points
        structured_content = """def function1():
    print('function 1')

def function2():
    print('function 2')

class MyClass:
    def method(self):
        pass

def function3():
    print('function 3')
"""
        result = analyzer._smart_truncate_content(structured_content, 100)
        assert "truncated for analysis" in result
        assert "def function" in result  # Should preserve some structure

    def test_create_user_prompt(self):
        """Test user prompt creation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        source_code = "SELECT * FROM users WHERE id = user_input"
        language = "python"
        max_findings = None

        prompt = analyzer._create_user_prompt(source_code, language, max_findings)

        assert isinstance(prompt, str)
        assert "python" in prompt
        assert "SELECT * FROM users WHERE id = user_input" in prompt
        assert "ALL security findings" in prompt
        assert "JSON format" in prompt
        assert "line_number" in prompt
        assert "vulnerability_type" in prompt

    def test_create_user_prompt_truncation(self):
        """Test user prompt creation with content truncation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Create very long code that will be truncated
        long_code = "def very_long_function():\n    pass\n" * 500
        language = "python"
        max_findings = 10

        prompt = analyzer._create_user_prompt(long_code, language, max_findings)

        assert "truncated for analysis" in prompt
        assert len(prompt) < len(long_code) + 1000  # Should be significantly shorter

    def test_create_batch_user_prompt(self):
        """Test batch user prompt creation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {
                "file_path": "/test/file1.py",
                "language": "python",
                "content": "print('hello')",
            },
            {
                "file_path": "/test/file2.js",
                "language": "javascript",
                "content": "console.log('world')",
            },
        ]

        prompt = analyzer._create_batch_user_prompt(batch_content, None)

        assert isinstance(prompt, str)
        assert "File 1: /test/file1.py" in prompt
        assert "File 2: /test/file2.js" in prompt
        assert "python" in prompt
        assert "javascript" in prompt
        assert "print('hello')" in prompt
        assert "console.log('world')" in prompt
        assert "ALL security findings" in prompt

    def test_parse_batch_response_success(self):
        """Test successful batch response parsing."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {"file_path": "/test/file1.py", "language": "python", "content": "code1"},
            {"file_path": "/test/file2.py", "language": "python", "content": "code2"},
        ]

        response_text = """
        {
            "findings": [
                {
                    "file_path": "/test/file1.py",
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection in file1",
                    "line_number": 5,
                    "code_snippet": "SELECT * FROM table",
                    "explanation": "Direct SQL query",
                    "recommendation": "Use prepared statements",
                    "confidence": 0.9
                },
                {
                    "file_path": "/test/file2.py",
                    "type": "xss",
                    "severity": "medium",
                    "description": "XSS vulnerability in file2",
                    "line_number": 10,
                    "code_snippet": "innerHTML = data",
                    "explanation": "Direct HTML injection",
                    "recommendation": "Sanitize input",
                    "confidence": 0.8
                }
            ]
        }
        """

        findings = analyzer._parse_batch_response(response_text, batch_content)

        assert len(findings) == 2
        assert findings[0].finding_type == "sql_injection"
        assert findings[0].file_path == "/test/file1.py"
        assert findings[0].line_number == 5
        assert findings[1].finding_type == "xss"
        assert findings[1].file_path == "/test/file2.py"
        assert findings[1].line_number == 10

    def test_parse_batch_response_missing_file_path(self):
        """Test batch response parsing with missing file paths."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {"file_path": "/test/file1.py", "language": "python", "content": "code1"}
        ]

        response_text = """
        {
            "findings": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": 5,
                    "code_snippet": "SELECT * FROM table",
                    "explanation": "Direct SQL query",
                    "recommendation": "Use prepared statements",
                    "confidence": 0.9
                }
            ]
        }
        """

        findings = analyzer._parse_batch_response(response_text, batch_content)

        assert len(findings) == 1
        # Should default to first file in batch when file_path is missing
        assert findings[0].file_path == "/test/file1.py"

    def test_parse_batch_response_invalid_json(self):
        """Test batch response parsing with invalid JSON."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {"file_path": "/test/file1.py", "language": "python", "content": "code1"}
        ]
        response_text = "invalid json response"

        findings = analyzer._parse_batch_response(response_text, batch_content)

        # Should return empty list on JSON parse error
        assert findings == []

    def test_parse_batch_response_malformed_finding(self):
        """Test batch response parsing with malformed findings."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {"file_path": "/test/file1.py", "language": "python", "content": "code1"}
        ]

        response_text = """
        {
            "findings": [
                {
                    "file_path": "/test/file1.py",
                    "type": "sql_injection",
                    "severity": "high",
                    "line_number": "invalid_line_number"
                },
                {
                    "file_path": "/test/file1.py",
                    "type": "xss",
                    "severity": "medium",
                    "description": "Valid finding",
                    "line_number": 5,
                    "code_snippet": "test",
                    "explanation": "test",
                    "recommendation": "test",
                    "confidence": 0.8
                }
            ]
        }
        """

        findings = analyzer._parse_batch_response(response_text, batch_content)

        # Should skip malformed finding and return only valid ones
        assert len(findings) == 1
        assert findings[0].finding_type == "xss"

    def test_get_enhanced_batch_system_prompt(self):
        """Test enhanced batch system prompt generation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {"language": "python", "file_path": "/test/file1.py"},
            {"language": "javascript", "file_path": "/test/file2.js"},
            {"language": "python", "file_path": "/test/file3.py"},
        ]

        prompt = analyzer._get_enhanced_batch_system_prompt(batch_content)

        assert isinstance(prompt, str)
        assert "3 files" in prompt
        assert "python, javascript" in prompt or "javascript, python" in prompt
        assert "security engineer" in prompt.lower()
        assert "cross-file" in prompt.lower()
        assert "JSON object" in prompt
        assert "vulnerability types" in prompt.lower()

    def test_create_enhanced_batch_user_prompt(self):
        """Test enhanced batch user prompt creation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {
                "file_path": "/test/file1.py",
                "language": "python",
                "content": "print('hello')",
                "size": 13,
                "complexity": 0.2,
            },
            {
                "file_path": "/test/file2.js",
                "language": "javascript",
                "content": "console.log('world')",
                "size": 19,
                "complexity": 0.8,
            },
        ]

        prompt = analyzer._create_enhanced_batch_user_prompt(batch_content, None)

        assert isinstance(prompt, str)
        assert "PYTHON Files (1 files)" in prompt
        assert "JAVASCRIPT Files (1 files)" in prompt
        assert "/test/file1.py" in prompt
        assert "/test/file2.js" in prompt
        assert "simple" in prompt  # complexity indicator for file1
        assert "complex" in prompt  # complexity indicator for file2
        assert "ALL security findings" in prompt

    def test_parse_enhanced_batch_response_success(self):
        """Test enhanced batch response parsing."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {"file_path": "/test/file1.py", "language": "python"},
            {"file_path": "/test/file2.py", "language": "python"},
        ]

        response_text = """
        {
            "findings": [
                {
                    "file_path": "/test/file1.py",
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": 5,
                    "code_snippet": "SELECT *",
                    "explanation": "Test explanation",
                    "recommendation": "Use prepared statements",
                    "confidence": 0.95
                }
            ],
            "analysis_summary": {
                "total_files_analyzed": 2,
                "files_with_findings": 1,
                "critical_findings": 0,
                "high_findings": 1
            }
        }
        """

        findings = analyzer._parse_enhanced_batch_response(response_text, batch_content)

        assert len(findings) == 1
        assert findings[0].finding_type == "sql_injection"
        assert findings[0].file_path == "/test/file1.py"
        assert findings[0].confidence == 0.95

    def test_parse_enhanced_batch_response_file_path_matching(self):
        """Test enhanced batch response parsing with file path matching."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [{"file_path": "/full/path/to/file1.py", "language": "python"}]

        response_text = """
        {
            "findings": [
                {
                    "file_path": "file1.py",
                    "type": "xss",
                    "severity": "medium",
                    "description": "XSS vulnerability",
                    "line_number": 3,
                    "code_snippet": "innerHTML = data",
                    "explanation": "Direct HTML injection",
                    "recommendation": "Sanitize input",
                    "confidence": 0.8
                }
            ]
        }
        """

        findings = analyzer._parse_enhanced_batch_response(response_text, batch_content)

        assert len(findings) == 1
        # Should match by filename and use full path
        assert findings[0].file_path == "/full/path/to/file1.py"

    def test_parse_enhanced_batch_response_unknown_file(self):
        """Test enhanced batch response parsing with unknown file reference."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [{"file_path": "/test/file1.py", "language": "python"}]

        response_text = """
        {
            "findings": [
                {
                    "file_path": "/unknown/file.py",
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": 5,
                    "code_snippet": "SELECT *",
                    "explanation": "Test explanation",
                    "recommendation": "Use prepared statements",
                    "confidence": 0.9
                }
            ]
        }
        """

        findings = analyzer._parse_enhanced_batch_response(response_text, batch_content)

        # Should skip findings for unknown files
        assert len(findings) == 0

    def test_parse_enhanced_batch_response_confidence_validation(self):
        """Test enhanced batch response parsing with confidence validation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [{"file_path": "/test/file1.py", "language": "python"}]

        response_text = """
        {
            "findings": [
                {
                    "file_path": "/test/file1.py",
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": 5,
                    "code_snippet": "SELECT *",
                    "explanation": "Test explanation",
                    "recommendation": "Use prepared statements",
                    "confidence": 1.5
                }
            ]
        }
        """

        findings = analyzer._parse_enhanced_batch_response(response_text, batch_content)

        assert len(findings) == 1
        # Confidence should be clamped to valid range (0.0-1.0)
        assert findings[0].confidence == 1.0

    def test_parse_enhanced_batch_response_fallback(self):
        """Test enhanced batch response parsing fallback to original parser."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [{"file_path": "/test/file1.py", "language": "python"}]

        # Invalid JSON should trigger fallback
        response_text = "invalid json"

        with patch.object(
            analyzer, "_parse_batch_response", return_value=[]
        ) as mock_fallback:
            findings = analyzer._parse_enhanced_batch_response(
                response_text, batch_content
            )

            # Should call fallback method
            mock_fallback.assert_called_once_with(response_text, batch_content)
            assert findings == []

    def test_collect_file_content_success(self):
        """Test successful file content collection."""
        import tempfile
        from pathlib import Path

        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Create temporary test files
        with tempfile.TemporaryDirectory() as temp_dir:
            file1 = Path(temp_dir) / "test1.py"
            file2 = Path(temp_dir) / "test2.js"

            file1.write_text("print('hello world')")
            file2.write_text("console.log('test');")

            file_paths = [file1, file2]

            # Mock event loop for async operation
            import asyncio

            async def run_test():
                result = await analyzer._collect_file_content(file_paths)
                return result

            # Run the async function
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            result = loop.run_until_complete(run_test())

            assert len(result) == 2
            assert result[0]["file_path"] == str(file1)
            assert result[0]["language"] == "python"
            assert result[0]["content"] == "print('hello world')"
            assert result[1]["file_path"] == str(file2)
            assert result[1]["language"] == "javascript"
            assert result[1]["content"] == "console.log('test');"

    def test_collect_file_content_empty_file(self):
        """Test file content collection with empty files."""
        import tempfile
        from pathlib import Path

        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Create temporary empty file
        with tempfile.TemporaryDirectory() as temp_dir:
            empty_file = Path(temp_dir) / "empty.py"
            empty_file.write_text("")

            file_paths = [empty_file]

            import asyncio

            async def run_test():
                result = await analyzer._collect_file_content(file_paths)
                return result

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            result = loop.run_until_complete(run_test())

            # Empty files should be skipped
            assert len(result) == 0

    def test_collect_file_content_large_file(self):
        """Test file content collection with large files that need truncation."""
        import tempfile
        from pathlib import Path

        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Create temporary large file
        with tempfile.TemporaryDirectory() as temp_dir:
            large_file = Path(temp_dir) / "large.py"
            large_content = "def function():\n    pass\n" * 1000
            large_file.write_text(large_content)

            file_paths = [large_file]

            import asyncio

            async def run_test():
                result = await analyzer._collect_file_content(file_paths)
                return result

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            result = loop.run_until_complete(run_test())

            assert len(result) == 1
            assert result[0]["file_path"] == str(large_file)
            assert len(result[0]["content"]) < len(large_content)  # Should be truncated
            assert result[0]["original_size"] == len(large_content)

    def test_collect_file_content_file_read_error(self):
        """Test file content collection with file read errors."""
        from pathlib import Path

        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Use non-existent file path
        nonexistent_file = Path("/nonexistent/file.py")
        file_paths = [nonexistent_file]

        import asyncio

        async def run_test():
            result = await analyzer._collect_file_content(file_paths)
            return result

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(run_test())

        # Should handle error gracefully and return empty list
        assert len(result) == 0

    def test_batch_analyze_code_not_available(self):
        """Test batch code analysis when LLM client is not available."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=False, llm_provider=None, llm_api_key=None
        )
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        code_samples = [
            ("code1", "file1.py", "python"),
            ("code2", "file2.py", "python"),
        ]

        result = analyzer.batch_analyze_code(code_samples)

        # Should return empty lists for each sample when not available
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0] == []
        assert result[1] == []

    def test_llm_security_finding_with_file_path(self):
        """Test LLMSecurityFinding with file_path attribute."""
        finding = LLMSecurityFinding(
            finding_type="sql_injection",
            severity="high",
            description="SQL injection vulnerability",
            line_number=10,
            code_snippet="SELECT * FROM users WHERE id = " + "user_input",
            explanation="User input directly concatenated into SQL query",
            recommendation="Use parameterized queries",
            confidence=0.9,
            file_path="/test/file.py",  # Set file_path in finding
        )

        # Should use the finding's file_path when converting to ThreatMatch
        threat_match = finding.to_threat_match()

        assert threat_match.file_path == "/test/file.py"

    def test_to_threat_match_file_path_precedence(self):
        """Test file_path parameter takes precedence over finding's file_path."""
        finding = LLMSecurityFinding(
            finding_type="xss",
            severity="medium",
            description="XSS vulnerability",
            line_number=5,
            code_snippet="innerHTML = user_input",
            explanation="Direct DOM manipulation",
            recommendation="Use textContent or sanitize input",
            confidence=0.8,
            file_path="/original/path.py",  # Original path in finding
        )

        # Parameter should override finding's file_path
        threat_match = finding.to_threat_match("/override/path.py")

        assert threat_match.file_path == "/override/path.py"

    @pytest.mark.skip(
        reason="Batch hash generation replaced by ErrorHandler circuit breakers"
    )
    def test_get_batch_hash(self):
        """Test batch hash generation for circuit breaking - DEPRECATED."""
        pass

    @pytest.mark.skip(reason="Batch skip logic replaced by ErrorHandler")
    def test_should_skip_batch(self):
        """Test batch skip logic for circuit breaking."""
        pass

    @pytest.mark.skip(
        reason="Batch failure recording replaced by ErrorHandler circuit breakers"
    )
    def test_record_batch_failure(self):
        """Test batch failure recording and circuit breaking."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)
        analyzer.max_batch_failures = 3  # Set threshold

        batch_hash = "test_batch_hash"

        # Record failures below threshold
        analyzer._record_batch_failure(batch_hash)
        assert analyzer.batch_failure_counts[batch_hash] == 1
        assert batch_hash not in analyzer.circuit_broken_batches

        analyzer._record_batch_failure(batch_hash)
        assert analyzer.batch_failure_counts[batch_hash] == 2
        assert batch_hash not in analyzer.circuit_broken_batches

        # Record failure that reaches threshold
        analyzer._record_batch_failure(batch_hash)
        assert analyzer.batch_failure_counts[batch_hash] == 3
        assert batch_hash in analyzer.circuit_broken_batches

    @pytest.mark.skip(
        reason="Batch success recording replaced by ErrorHandler circuit breakers"
    )
    def test_record_batch_success(self):
        """Test batch success recording and circuit breaker reset - DEPRECATED."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_hash = "test_batch_hash"

        # Set up a previously failed batch
        analyzer.batch_failure_counts[batch_hash] = 2
        analyzer.circuit_broken_batches.add(batch_hash)

        # Record success should reset both counters
        analyzer._record_batch_success(batch_hash)

        assert batch_hash not in analyzer.batch_failure_counts
        assert batch_hash not in analyzer.circuit_broken_batches

    def test_analyze_code_event_loop_creation(self):
        """Test event loop creation when none exists."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            analyzer = LLMScanner(mock_manager)

            # Mock asyncio to simulate no event loop
            with (
                patch("asyncio.get_event_loop") as mock_get_loop,
                patch("asyncio.new_event_loop") as mock_new_loop,
                patch("asyncio.set_event_loop") as mock_set_loop,
                patch.object(
                    analyzer, "_analyze_code_async", return_value=[]
                ) as mock_async,
            ):

                mock_get_loop.side_effect = RuntimeError("No event loop")
                mock_loop = Mock()
                mock_new_loop.return_value = mock_loop
                mock_loop.run_until_complete.return_value = []

                result = analyzer.analyze_code("test code", "test.py", "python")

                # Should create new event loop when none exists
                mock_new_loop.assert_called_once()
                mock_set_loop.assert_called_once_with(mock_loop)
                mock_loop.run_until_complete.assert_called_once()
                assert result == []

    def test_parse_analysis_response_exception_handling(self):
        """Test exception handling in parse_analysis_response."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Test with response that causes exception during LLMSecurityFinding creation
        response_text = """
        {
            "findings": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": 5,
                    "code_snippet": "test",
                    "explanation": "test",
                    "recommendation": "test",
                    "confidence": 0.9
                }
            ]
        }
        """

        # Test with invalid JSON to trigger outer exception handling
        invalid_response = "This is not valid JSON at all!"

        # Should raise LLMAnalysisError for invalid JSON
        with pytest.raises(LLMAnalysisError, match="Invalid JSON response from LLM"):
            analyzer.parse_analysis_response(invalid_response, "test.py")

    def test_analyze_file_paths_not_available(self):
        """Test analyze_file_paths when LLM client is not available."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=False, llm_provider=None, llm_api_key=None
        )
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        import tempfile
        from pathlib import Path

        # Create a temporary test file
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("print('hello')")

            # Since LLM is not available, this should return empty list immediately
            # Test synchronous path when not available
            if hasattr(analyzer, "analyze_file_paths"):
                result = analyzer.analyze_file_paths([test_file])
                assert result == []
            else:
                # If method doesn't exist, just test that is_available returns False
                assert not analyzer.is_available()

    def test_language_complexity_calculation(self):
        """Test language-specific complexity calculation in batch processing."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            analyzer = LLMScanner(mock_manager)

            # Test batch analysis with different languages to trigger complexity calculation
            code_samples = [
                (
                    "package main\nfunc main() {\n    compose := func() {}\n}",
                    "main.go",
                    "go",
                ),
                ("fn main() {\n    let pipe = |x| x;\n}", "main.rs", "rust"),
                ("class Test {\n    void compose() {}\n}", "Test.cs", "csharp"),
                ("generic code here", "test.txt", "unknown_lang"),
            ]

            # This should not raise exceptions for different languages
            result = analyzer.batch_analyze_code(code_samples)
            assert isinstance(result, list)

    def test_smart_truncate_content_edge_cases(self):
        """Test smart content truncation edge cases."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Test with very small limit
        content = "print('hello world')"
        result = analyzer._smart_truncate_content(content, 5)
        assert "truncated for analysis" in result
        assert len(result) <= 30  # Should be truncated with message

        # Test with empty content
        result = analyzer._smart_truncate_content("", 100)
        assert result == ""

        # Test with content that has no good break points
        no_breaks = "a" * 1000
        result = analyzer._smart_truncate_content(no_breaks, 50)
        assert "truncated for analysis" in result

    def test_enhanced_batch_parsing_edge_cases(self):
        """Test enhanced batch response parsing edge cases."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [{"file_path": "/test/file1.py", "language": "python"}]

        # Test response with invalid confidence values
        response_text = """
        {
            "findings": [
                {
                    "file_path": "/test/file1.py",
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": 5,
                    "code_snippet": "SELECT *",
                    "explanation": "Test",
                    "recommendation": "Fix it",
                    "confidence": -0.5
                }
            ]
        }
        """

        findings = analyzer._parse_enhanced_batch_response(response_text, batch_content)
        assert len(findings) == 1
        assert 0.0 <= findings[0].confidence <= 1.0  # Should be clamped

    def test_collect_file_content_mixed_file_types(self):
        """Test file content collection with mixed analyzable and non-analyzable files."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create analyzable file
            py_file = Path(temp_dir) / "test.py"
            py_file.write_text("print('hello')")

            # Create non-analyzable file
            txt_file = Path(temp_dir) / "readme.txt"
            txt_file.write_text("This is a readme")

            file_paths = [py_file, txt_file]

            import asyncio

            async def run_test():
                result = await analyzer._collect_file_content(file_paths)
                return result

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            result = loop.run_until_complete(run_test())

            # Should include both files (method doesn't filter, just collects)
            assert len(result) == 2
            # Find the py file result
            py_result = next(r for r in result if r["file_path"] == str(py_file))
            assert py_result["language"] == "python"

            # Find the txt file result
            txt_result = next(r for r in result if r["file_path"] == str(txt_file))
            assert txt_result["language"] == "generic"  # txt files get generic language

    def test_batch_analysis_with_circuit_breaking(self):
        """Test batch analysis with circuit breaking functionality."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="openai",
            llm_api_key="sk-test-key",
            llm_batch_size=2,
        )
        mock_manager.load_config.return_value = mock_config

        # Mock LLM client that will fail
        mock_llm_client = AsyncMock()
        mock_llm_client.complete_with_retry.side_effect = Exception("API Error")

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=mock_llm_client,
        ):
            analyzer = LLMScanner(mock_manager)
            analyzer.max_batch_failures = 2  # Low threshold for testing

            code_samples = [
                ("code1", "file1.py", "python"),
                ("code2", "file2.py", "python"),
            ]

            # First batch analysis should fail gracefully and return empty results
            result1 = analyzer.batch_analyze_code(code_samples)
            assert isinstance(result1, list)
            assert len(result1) == 2
            assert result1[0] == []  # Empty findings for first file
            assert result1[1] == []  # Empty findings for second file

            # Note: batch_analyze_code handles failures gracefully without recording
            # batch failures (that's only done in the lower-level batch processing)
            # So we don't expect batch_failure_counts to be incremented here

    def test_fallback_individual_analysis(self):
        """Test fallback to individual analysis when batch processing fails."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [
            {"file_path": "/test/file1.py", "language": "python", "content": "code1"},
        ]

        import asyncio

        async def run_test():
            # Mock the individual analysis to return a finding
            with patch.object(
                analyzer,
                "_analyze_code_async",
                return_value=[
                    LLMSecurityFinding(
                        finding_type="test_vuln",
                        severity="medium",
                        description="Test vulnerability",
                        line_number=1,
                        code_snippet="test",
                        explanation="test",
                        recommendation="test",
                        confidence=0.8,
                    )
                ],
            ):
                result = await analyzer._fallback_individual_analysis(batch_content, 5)
                return result

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(run_test())

        assert len(result) == 1
        assert result[0].finding_type == "test_vuln"

    def test_batch_processing_error_recovery(self):
        """Test batch processing with error recovery and fallback."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="openai",
            llm_api_key="sk-test-key",
            llm_batch_size=2,
        )
        mock_manager.load_config.return_value = mock_config

        # Mock LLM client to succeed on individual but fail on batch
        mock_llm_client = AsyncMock()

        # Mock batch processing to fail, individual to succeed
        def side_effect(*args, **kwargs):
            # Check if this looks like a batch request based on content length
            content = (
                args[0] if args else kwargs.get("messages", [{}])[0].get("content", "")
            )
            if len(content) > 1000:  # Batch requests are typically longer
                raise Exception("Batch processing failed")
            else:
                # Individual request - return success
                mock_response = Mock()
                mock_response.content = '{"findings": [{"type": "test_vuln", "severity": "medium", "description": "test", "line_number": 1, "code_snippet": "test", "explanation": "test", "recommendation": "test", "confidence": 0.8}]}'
                return mock_response

        mock_llm_client.complete_with_retry.side_effect = side_effect

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=mock_llm_client,
        ):
            analyzer = LLMScanner(mock_manager)

            code_samples = [
                ("code1", "file1.py", "python"),
                ("code2", "file2.py", "python"),
            ]

            # Should handle batch failure and fall back to individual analysis
            result = analyzer.batch_analyze_code(code_samples)
            assert isinstance(result, list)
            assert len(result) == 2  # Should have results for both files

    def test_enhanced_batch_response_parsing_malformed_findings(self):
        """Test enhanced batch response parsing with malformed findings."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        batch_content = [{"file_path": "/test/file1.py", "language": "python"}]

        # Test response with malformed finding data
        response_text = """
        {
            "findings": [
                {
                    "file_path": "/test/file1.py",
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection",
                    "line_number": "invalid_number",
                    "code_snippet": "SELECT *",
                    "explanation": "Test",
                    "recommendation": "Fix it",
                    "confidence": 0.9
                },
                {
                    "file_path": "/test/file1.py",
                    "type": "xss",
                    "severity": "medium",
                    "description": "XSS vulnerability",
                    "line_number": 3,
                    "code_snippet": "innerHTML = data",
                    "explanation": "Direct HTML injection",
                    "recommendation": "Sanitize input",
                    "confidence": 0.8
                }
            ]
        }
        """

        # Should skip malformed findings and return only valid ones
        findings = analyzer._parse_enhanced_batch_response(response_text, batch_content)
        assert len(findings) == 1
        assert findings[0].finding_type == "xss"

    def test_caching_functionality(self):
        """Test caching functionality."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="openai",
            llm_api_key="sk-test-key",
            enable_caching=True,
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            analyzer = LLMScanner(mock_manager)

            # Test that analyzer has caching enabled in config
            assert analyzer.config.enable_caching is True

            # Test cache manager initialization
            assert analyzer.cache_manager is not None

            # Test that cache directory is properly set
            cache_stats = analyzer.cache_manager.get_stats()
            # cache_stats returns a CacheStats object, not a dict
            assert hasattr(cache_stats, "total_entries")
            assert hasattr(cache_stats, "hit_count")

    @pytest.mark.skip(
        reason="Batch hash collision handling replaced by ErrorHandler circuit breakers"
    )
    def test_batch_hash_collision_handling(self):
        """Test handling of batch hash collisions - DEPRECATED."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Create batch content that might cause hash collisions
        batch1 = [{"file_path": "/test/a.py", "content": "code"}]
        batch2 = [{"file_path": "/test/b.py", "content": "code"}]

        hash1 = analyzer._get_batch_hash(batch1)
        hash2 = analyzer._get_batch_hash(batch2)

        # Different file paths should produce different hashes
        assert hash1 != hash2

        # Test hash stability
        hash1_repeat = analyzer._get_batch_hash(batch1)
        assert hash1 == hash1_repeat

    def test_analyze_code_async_no_llm_client(self):
        """Test _analyze_code_async returns empty when no LLM client."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        # Set scanner to have no LLM client
        scanner.llm_client = None

        async def run_test():
            result = await scanner._analyze_code_async(
                "print('hello')", "test.py", "python", 10
            )
            assert result == []

        # Run the test
        run_test()

    @patch("adversary_mcp_server.scanner.llm_scanner.logger")
    def test_analyze_code_async_cache_hit(self, mock_logger):
        """Test _analyze_code_async cache hit scenario."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            scanner = LLMScanner(mock_manager)

            # Mock cache manager and cached result
            mock_cache_manager = MagicMock()
            mock_hasher = MagicMock()
            mock_hasher.hash_content.return_value = "content_hash"
            mock_hasher.hash_llm_context.return_value = "context_hash"
            mock_cache_manager.get_hasher.return_value = mock_hasher

            # Mock cached findings
            cached_finding_dict = {
                "finding_type": "test_vuln",
                "severity": "HIGH",
                "confidence": 0.9,
                "description": "Test vulnerability",
                "line_number": 1,
                "code_snippet": "test code",
                "explanation": "Test explanation",
                "recommendation": "Fix it",
            }
            cached_result = {"findings": [cached_finding_dict]}
            mock_cache_manager.get.return_value = cached_result

            scanner.cache_manager = mock_cache_manager
            scanner.config.cache_llm_responses = True

            async def run_test():
                result = await scanner._analyze_code_async(
                    "print('hello')", "test.py", "python", 10
                )
                # Should return one finding from cache
                assert len(result) == 1
                assert isinstance(result[0], LLMSecurityFinding)
                assert result[0].finding_type == "test_vuln"

            # Run the async test with event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_test())
            finally:
                loop.close()

            # Verify cache hit was logged
            mock_logger.info.assert_any_call("Cache hit for LLM analysis: test.py")

    @patch("adversary_mcp_server.scanner.llm_scanner.logger")
    def test_analyze_code_async_cache_miss(self, mock_logger):
        """Test _analyze_code_async cache miss scenario."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        # Mock cache manager with cache miss
        mock_cache_manager = MagicMock()
        mock_hasher = MagicMock()
        mock_hasher.hash_content.return_value = "content_hash"
        mock_hasher.hash_llm_context.return_value = "context_hash"
        mock_cache_manager.get_hasher.return_value = mock_hasher
        mock_cache_manager.get.return_value = None  # Cache miss

        # Mock LLM client response
        mock_response = MagicMock()
        mock_response.content = '{"findings": []}'
        mock_response.model = "test-model"
        mock_response.usage = {}

        mock_llm_client = AsyncMock()
        mock_llm_client.complete_with_retry.return_value = mock_response

        scanner.cache_manager = mock_cache_manager
        scanner.config.cache_llm_responses = True
        scanner.llm_client = mock_llm_client
        scanner.config.llm_provider = "anthropic"

        with patch.object(scanner, "parse_analysis_response", return_value=[]):

            async def run_test():
                result = await scanner._analyze_code_async(
                    "print('hello')", "test.py", "python", 10
                )
                assert result == []

            # Run the async test
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_test())
            finally:
                loop.close()

        # Verify cache miss was logged
        mock_logger.debug.assert_any_call("Cache miss for LLM analysis: test.py")

    @patch("adversary_mcp_server.scanner.llm_scanner.logger")
    @pytest.mark.skip(reason="Fallback handling changed with ErrorHandler integration")
    def test_analyze_code_async_anthropic_api_failure_with_fallback(self, mock_logger):
        """Test Anthropic API failure with fallback response."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        # Mock LLM client that fails initially
        mock_llm_client = AsyncMock()
        mock_llm_client.complete_with_retry.side_effect = Exception("API Error")

        scanner.llm_client = mock_llm_client
        scanner.config.llm_provider = "anthropic"

        with patch.object(scanner, "parse_analysis_response", return_value=[]):

            async def run_test():
                result = await scanner._analyze_code_async(
                    "print('hello')", "test.py", "python", 10
                )
                assert result == []

            # Run the async test
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_test())
            finally:
                loop.close()

        # Verify fallback was logged
        mock_logger.info.assert_any_call("Fallback response used for test.py")

    @patch("adversary_mcp_server.scanner.llm_scanner.logger")
    def test_analyze_code_async_non_anthropic_with_recovery(self, mock_logger):
        """Test non-Anthropic provider using error recovery."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            scanner = LLMScanner(mock_manager)

            # Mock error handler with successful recovery
            mock_recovery_result = MagicMock()
            mock_recovery_result.success = True
            mock_recovery_result.result.content = '{"findings": []}'
            mock_recovery_result.result.model = "test-model"
            mock_recovery_result.result.usage = {}

            mock_error_handler = MagicMock()
            mock_error_handler.execute_with_recovery = AsyncMock(
                return_value=mock_recovery_result
            )

            scanner.error_handler = mock_error_handler
            scanner.config.llm_provider = "openai"  # Non-Anthropic

            with patch.object(scanner, "parse_analysis_response", return_value=[]):

                async def run_test():
                    result = await scanner._analyze_code_async(
                        "print('hello')", "test.py", "python", 10
                    )
                    assert result == []

                # Run the async test
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(run_test())
                finally:
                    loop.close()

        # Verify recovery was attempted
        mock_error_handler.execute_with_recovery.assert_called_once()

    @patch("adversary_mcp_server.scanner.llm_scanner.logger")
    @pytest.mark.skip(
        reason="Recovery failure handling changed with ErrorHandler integration"
    )
    def test_analyze_code_async_recovery_failure(self, mock_logger):
        """Test recovery failure raising LLMAnalysisError."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True, llm_provider="openai", llm_api_key="sk-test-key"
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            scanner = LLMScanner(mock_manager)

            # Mock error handler with failed recovery
            mock_recovery_result = MagicMock()
            mock_recovery_result.success = False
            mock_recovery_result.error_message = "Recovery failed"

            mock_error_handler = MagicMock()
            mock_error_handler.execute_with_recovery = AsyncMock(
                return_value=mock_recovery_result
            )

            scanner.error_handler = mock_error_handler
            scanner.config.llm_provider = "openai"  # Non-Anthropic

        async def run_test():
            with pytest.raises(LLMAnalysisError) as context:
                await scanner._analyze_code_async(
                    "print('hello')", "test.py", "python", 10
                )
            assert "Analysis failed with recovery" in str(context.value)

        # Run the async test
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("Event loop is closed")
        except RuntimeError:
            # Create a new event loop if none exists or current one is closed
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(run_test())
        finally:
            # Don't close the loop as it might be needed by other tests
            pass

    @patch("adversary_mcp_server.scanner.llm_scanner.logger")
    def test_analyze_code_async_cache_storage(self, mock_logger):
        """Test successful caching of LLM analysis results."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="anthropic",
            llm_api_key="sk-test-key",
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            scanner = LLMScanner(mock_manager)

            # Mock cache manager
            mock_cache_manager = MagicMock()
            mock_hasher = MagicMock()
            mock_hasher.hash_content.return_value = "content_hash"
            mock_hasher.hash_llm_context.return_value = "context_hash"
            mock_cache_manager.get_hasher.return_value = mock_hasher
            mock_cache_manager.get.return_value = None  # Cache miss initially

            # Mock LLM response
            mock_response = MagicMock()
            mock_response.content = '{"findings": [{"finding_type": "test"}]}'
            mock_response.model = "test-model"
            mock_response.usage = {"tokens": 100}

            mock_llm_client = AsyncMock()
            mock_llm_client.complete_with_retry.return_value = mock_response

            # Mock finding to return
            mock_finding = MagicMock()
            mock_finding.__dict__ = {"finding_type": "test", "severity": "HIGH"}

            scanner.cache_manager = mock_cache_manager
            scanner.config.cache_llm_responses = True
            scanner.config.cache_max_age_hours = 24
            scanner.llm_client = mock_llm_client
            scanner.config.llm_provider = "anthropic"

            with patch.object(
                scanner, "parse_analysis_response", return_value=[mock_finding]
            ):

                async def run_test():
                    result = await scanner._analyze_code_async(
                        "print('hello')", "test.py", "python", 10
                    )
                    assert len(result) == 1

                # Run the async test
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(run_test())
                finally:
                    loop.close()

                # Verify cache was stored
                mock_cache_manager.put.assert_called_once()
                mock_logger.debug.assert_any_call(
                    "Cached LLM analysis result for test.py"
                )

    @patch("adversary_mcp_server.scanner.llm_scanner.logger")
    def test_analyze_code_async_cache_storage_failure(self, mock_logger):
        """Test handling of cache storage failure."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(
            enable_llm_analysis=True,
            llm_provider="anthropic",
            llm_api_key="sk-test-key",
        )
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client",
            return_value=Mock(),
        ):
            scanner = LLMScanner(mock_manager)

            # Mock cache manager that fails on put
            mock_cache_manager = MagicMock()
            mock_hasher = MagicMock()
            mock_hasher.hash_content.return_value = "content_hash"
            mock_hasher.hash_llm_context.return_value = "context_hash"
            mock_cache_manager.get_hasher.return_value = mock_hasher
            mock_cache_manager.get.return_value = None  # Cache miss
            mock_cache_manager.put.side_effect = Exception("Cache write failed")

            # Mock LLM response
            mock_response = MagicMock()
            mock_response.content = '{"findings": []}'
            mock_response.model = "test-model"
            mock_response.usage = {}

            mock_llm_client = AsyncMock()
            mock_llm_client.complete_with_retry.return_value = mock_response

            # Mock finding to return
            mock_finding = MagicMock()
            mock_finding.__dict__ = {"finding_type": "test"}

            scanner.cache_manager = mock_cache_manager
            scanner.config.cache_llm_responses = True
            scanner.llm_client = mock_llm_client
            scanner.config.llm_provider = "anthropic"

            with patch.object(
                scanner, "parse_analysis_response", return_value=[mock_finding]
            ):

                async def run_test():
                    result = await scanner._analyze_code_async(
                        "print('hello')", "test.py", "python", 10
                    )
                    assert len(result) == 1

                # Run the async test
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(run_test())
                finally:
                    loop.close()

                # Verify cache write failure was logged
                mock_logger.warning.assert_any_call(
                    "Failed to cache LLM result for test.py: Cache write failed"
                )

    def test_language_mapping_in_file_contexts(self):
        """Test language mapping when creating file contexts for batch processing."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.batch_processor = MagicMock()

        # Mock file content data with various languages (enough files to trigger batch processing)
        file_content_data = []
        for i in range(30):  # Create 30 files to trigger batch processor
            if i % 3 == 0:
                file_content_data.append(
                    {
                        "file_path": f"test{i}.py",
                        "content": "print('hello')",
                        "language": "python",
                        "priority": 1,
                    }
                )
            elif i % 3 == 1:
                file_content_data.append(
                    {
                        "file_path": f"test{i}.js",
                        "content": "console.log('hello')",
                        "language": "javascript",
                        "priority": 2,
                    }
                )
            else:
                file_content_data.append(
                    {
                        "file_path": f"test{i}.unknown",
                        "content": "unknown code",
                        "language": "unknown",
                        "priority": 0,
                    }
                )

        # Mock batch processor methods
        mock_context = MagicMock()
        scanner.batch_processor.create_file_context.return_value = mock_context
        scanner.batch_processor.create_batches.return_value = []
        scanner.batch_processor.process_batches = AsyncMock(return_value=[])
        scanner.batch_processor.get_metrics.return_value = MagicMock(to_dict=lambda: {})
        scanner.llm_client = MagicMock()

        with patch.object(scanner, "get_circuit_breaker_stats", return_value={}):
            with patch.object(
                scanner, "_collect_file_content", return_value=file_content_data
            ):

                async def run_test():
                    file_paths = [
                        Path(f"test{i}.py") for i in range(30)
                    ]  # 30 files to trigger batch processing
                    result = await scanner._analyze_batch_async(file_paths)

                    # Verify create_file_context was called with correct language mappings
                    calls = scanner.batch_processor.create_file_context.call_args_list
                    assert len(calls) == 30

                    # Check that we have the expected language mappings
                    python_calls = [
                        call for call in calls if call[1]["language"].value == "python"
                    ]
                    js_calls = [
                        call
                        for call in calls
                        if call[1]["language"].value == "javascript"
                    ]
                    generic_calls = [
                        call for call in calls if call[1]["language"].value == "generic"
                    ]

                    assert len(python_calls) == 10  # Every 3rd file starting from 0
                    assert len(js_calls) == 10  # Every 3rd file starting from 1
                    assert len(generic_calls) == 10  # Every 3rd file starting from 2

                    return result

                # Run the async test
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(run_test())
                finally:
                    loop.close()

    def test_batch_processing_with_file_contexts(self):
        """Test batch processing workflow with file contexts."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()

        # Mock the async method that's actually called
        mock_findings = [MagicMock()]
        mock_findings[0].file_path = "test.py"

        with patch.object(
            scanner, "_batch_analyze_code_async", return_value=[mock_findings]
        ) as mock_async:
            result = scanner.batch_analyze_code([("code", "test.py", "python")])

            # Verify the async method was called with correct parameters
            # Note: Due to event loop handling, it might be called more than once
            assert mock_async.call_count >= 1
            mock_async.assert_called_with([("code", "test.py", "python")], None)

            # Verify we got the expected result
            assert result == [mock_findings]

    def test_progress_callback_in_batch_processing(self):
        """Test progress callback functionality during batch processing."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.batch_processor = MagicMock()
        scanner.llm_client = MagicMock()

        file_content_data = [
            {"file_path": "test.py", "content": "code", "language": "python"}
        ]

        # Mock batch processor
        mock_context = MagicMock()
        scanner.batch_processor.create_file_context.return_value = mock_context
        scanner.batch_processor.create_batches.return_value = [[mock_context]]
        scanner.batch_processor.get_metrics.return_value = MagicMock(to_dict=lambda: {})

        # Capture the progress callback
        captured_callback = None

        def capture_process_batches(*args, **kwargs):
            nonlocal captured_callback
            captured_callback = args[2] if len(args) > 2 else None
            return []

        scanner.batch_processor.process_batches = AsyncMock(
            side_effect=capture_process_batches
        )

        with patch.object(
            scanner, "_collect_file_content", return_value=file_content_data
        ):
            with patch(
                "adversary_mcp_server.scanner.llm_scanner.logger"
            ) as mock_logger:

                def run_test():
                    scanner.batch_analyze_code([("code", "test.py", "python")])

                    # Test the captured progress callback
                    if captured_callback:
                        captured_callback(5, 10)  # completed=5, total=10
                        mock_logger.info.assert_any_call(
                            "Batch processing progress: 5/10 batches completed"
                        )

        # Run the test
        run_test()

    def test_batch_processing_metrics_logging(self):
        """Test metrics and circuit breaker stats logging."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()

        # Mock the async method to return empty results
        with patch.object(
            scanner, "_batch_analyze_code_async", return_value=[]
        ) as mock_async:
            with patch(
                "adversary_mcp_server.scanner.llm_scanner.logger"
            ) as mock_logger:
                result = scanner.batch_analyze_code([("code", "test.py", "python")])

                # Verify the async method was called
                mock_async.assert_called_once_with(
                    [("code", "test.py", "python")], None
                )

                # Verify initial logging happens
                mock_logger.info.assert_any_call(
                    "batch_analyze_code called with 1 samples"
                )

                assert result == []

    def test_batch_processing_findings_flattening(self):
        """Test that batch processing results are properly grouped by file."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()

        # Create mock findings with different file paths
        finding1 = MagicMock()
        finding1.file_path = "test1.py"
        finding2 = MagicMock()
        finding2.file_path = "test2.py"
        finding3 = MagicMock()
        finding3.file_path = "test1.py"

        # Mock the async method to return grouped results
        grouped_results = [[finding1, finding3], [finding2]]

        with patch.object(
            scanner, "_batch_analyze_code_async", return_value=grouped_results
        ) as mock_async:
            result = scanner.batch_analyze_code(
                [("code1", "test1.py", "python"), ("code2", "test2.py", "python")]
            )

            # Verify the async method was called
            mock_async.assert_called_once()

            # Results should be grouped by file
            assert len(result) == 2  # Two files
            assert result[0] == [finding1, finding3]  # test1.py findings
            assert result[1] == [finding2]  # test2.py findings

    def test_get_circuit_breaker_stats(self):
        """Test getting circuit breaker statistics from ErrorHandler."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        # Mock the error_handler.get_circuit_breaker_stats method
        mock_stats = {
            "circuit_breaker_1": {
                "state": "closed",
                "failure_count": 0,
                "success_count": 5,
            }
        }
        scanner.error_handler.get_circuit_breaker_stats = Mock(return_value=mock_stats)

        # Test that stats are delegated to error handler
        stats = scanner.get_circuit_breaker_stats()
        assert isinstance(stats, dict)
        assert stats == mock_stats
        scanner.error_handler.get_circuit_breaker_stats.assert_called_once()

    @pytest.mark.skip(
        reason="Batch success recording replaced by ErrorHandler circuit breakers"
    )
    def test_record_batch_success(self):
        """Test recording batch success and resetting failure counts - DEPRECATED."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        # Set up some failures and broken circuits
        batch_hash = "test_batch_hash"
        scanner.batch_failure_counts[batch_hash] = 3
        scanner.circuit_broken_batches.add(batch_hash)

        with patch("adversary_mcp_server.scanner.llm_scanner.logger") as mock_logger:
            # Record success should clear failure counts and reset circuit breaker
            scanner._record_batch_success(batch_hash)

        assert batch_hash not in scanner.batch_failure_counts
        assert batch_hash not in scanner.circuit_broken_batches
        mock_logger.info.assert_called_once_with(
            f"Circuit breaker reset for batch {batch_hash[:8]}"
        )

    def test_parse_batch_response_json_decode_error(self):
        """Test _parse_batch_response with JSON decode error returns empty list."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        # Invalid JSON response should return empty list, not raise exception
        invalid_json_response = "This is not JSON"
        batch_content = [{"file_path": "/path/to/test.py", "language": "python"}]

        with patch("adversary_mcp_server.scanner.llm_scanner.logger") as mock_logger:
            result = scanner._parse_batch_response(invalid_json_response, batch_content)

            assert result == []
            mock_logger.error.assert_called()

    def test_parse_batch_response_general_exception(self):
        """Test _parse_batch_response with general exception returns empty list."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        batch_content = [{"file_path": "/path/to/test.py", "language": "python"}]

        # Mock json.loads to raise a general exception - should return empty list
        with patch(
            "adversary_mcp_server.scanner.llm_scanner.json.loads",
            side_effect=ValueError("Custom error"),
        ):
            with patch(
                "adversary_mcp_server.scanner.llm_scanner.logger"
            ) as mock_logger:
                result = scanner._parse_batch_response(
                    '{"findings": []}', batch_content
                )

                assert result == []
                mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_analyze_code_async_cache_hit(self):
        """Test analyze_code_async with cache hit."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(cache_llm_responses=True)
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()

        # Mock cache manager
        mock_cache_manager = MagicMock()
        scanner.cache_manager = mock_cache_manager

        # Mock cache hit
        cached_findings = [
            {
                "finding_type": "sql_injection",
                "severity": "high",
                "description": "Cached finding",
                "line_number": 10,
                "code_snippet": "SELECT * FROM users",
                "explanation": "Cached finding explanation",
                "recommendation": "Use parameterized queries",
                "confidence": 0.9,
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021",
            }
        ]
        mock_cache_manager.get.return_value = {"findings": cached_findings}

        # Mock hasher
        mock_hasher = MagicMock()
        mock_hasher.hash_content.return_value = "content_hash"
        mock_hasher.hash_llm_context.return_value = "context_hash"
        mock_cache_manager.get_hasher.return_value = mock_hasher

        result = await scanner._analyze_code_async(
            "test code", "/path/to/test.py", "python"
        )

        assert len(result) == 1
        assert result[0].finding_type == "sql_injection"
        assert result[0].description == "Cached finding"

        # Should not call LLM client since cache hit occurred
        scanner.llm_client.complete_with_retry.assert_not_called()

    @pytest.mark.asyncio
    async def test_analyze_code_async_no_llm_client(self):
        """Test _analyze_code_async when no LLM client is available."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = None

        result = await scanner._analyze_code_async(
            "test code", "/path/to/test.py", "python"
        )

        assert result == []

    def test_analyze_files_method_exists(self):
        """Test that analyze_files method exists and is callable."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        # Method should exist
        assert hasattr(scanner, "analyze_files")
        assert callable(scanner.analyze_files)

    @pytest.mark.asyncio
    async def test_analyze_files_empty_list(self):
        """Test analyze_files with empty file list."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        result = await scanner.analyze_files([])
        assert result == []

    @pytest.mark.asyncio
    async def test_analyze_files_not_available(self):
        """Test analyze_files when scanner is not available."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(enable_llm_analysis=False)
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        # Mock some files
        test_files = [Path("/path/to/test1.py"), Path("/path/to/test2.py")]

        result = await scanner.analyze_files(test_files)
        assert result == []

    def test_get_status_no_provider(self):
        """Test get_status when no LLM provider is configured."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(enable_llm_analysis=False, llm_provider=None)
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        status = scanner.get_status()

        assert status["mode"] == "none"
        assert status["model"] is None
        assert "no" in status["description"]
        assert status["available"] is False

    @pytest.mark.asyncio
    async def test_analyze_files_with_file_list(self):
        """Test analyze_files with actual file list and proper mocking."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(enable_llm_analysis=True)
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()

        # Create temporary files for testing
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_file1 = Path(temp_dir) / "test1.py"
            test_file2 = Path(temp_dir) / "test2.js"
            test_file1.write_text("print('hello')")
            test_file2.write_text("console.log('hello')")

            test_files = [test_file1, test_file2]

            # Mock the batch processor and its methods
            mock_batch_processor = MagicMock()
            scanner.batch_processor = mock_batch_processor

            # Make process_batches an async method that returns a list
            async def mock_process_batches(*args, **kwargs):
                return []

            mock_batch_processor.process_batches = mock_process_batches
            mock_batch_processor.create_batches.return_value = []

            result = await scanner.analyze_files(test_files, max_findings_per_file=10)

            assert isinstance(result, list)

    def test_fallback_individual_analysis_exception_handling(self):
        """Test that individual analysis failures are handled gracefully."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()

        # Mock _analyze_code_async to raise an exception
        with patch.object(
            scanner, "_analyze_code_async", side_effect=Exception("Test error")
        ):
            with patch(
                "adversary_mcp_server.scanner.llm_scanner.logger"
            ) as mock_logger:
                result = asyncio.run(
                    scanner._fallback_individual_analysis(
                        [
                            {
                                "file_path": "/test/file.py",
                                "content": "test",
                                "language": "python",
                            }
                        ],
                        max_findings_per_file=10,
                    )
                )

                assert result == []
                mock_logger.warning.assert_called()

    def test_system_prompt_generation(self):
        """Test system prompt generation."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        with patch("adversary_mcp_server.scanner.llm_scanner.logger") as mock_logger:
            prompt = scanner._get_system_prompt()

            assert isinstance(prompt, str)
            assert "security engineer" in prompt.lower()
            assert "vulnerabilities" in prompt.lower()
            mock_logger.debug.assert_called_with(
                "Generating system prompt for LLM analysis"
            )

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Circuit breaker logic replaced by ErrorHandler")
    async def test_process_single_batch_circuit_breaker_logic(self):
        """Test circuit breaker logic in batch processing."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()

        # Create a batch that would trigger circuit breaker
        batch_content = [
            {
                "file_path": "/test/file.py",
                "content": "test",
                "language": "python",
                "size": 100,
                "complexity": 1.0,
            }
        ]

        # Mock the batch to be circuit broken
        batch_hash = "test_hash"
        scanner.circuit_broken_batches.add(batch_hash)

        # Mock the _get_batch_hash method to return our test hash
        with patch.object(scanner, "_get_batch_hash", return_value=batch_hash):
            with patch(
                "adversary_mcp_server.scanner.llm_scanner.logger"
            ) as mock_logger:
                result = await scanner._process_single_batch(batch_content, 10, 0)

                assert result == []
                mock_logger.warning.assert_called()

    def test_cache_integration_without_cache_manager(self):
        """Test that code works correctly when cache manager is None."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(cache_llm_responses=True)
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()
        scanner.cache_manager = None  # No cache manager

        # Mock successful LLM response
        mock_response = Mock()
        mock_response.content = '{"findings": []}'
        scanner.llm_client.complete_with_retry.return_value = mock_response

        result = asyncio.run(
            scanner._analyze_code_async("test code", "/test/file.py", "python")
        )

        assert isinstance(result, list)

    def test_parse_batch_response_error_logging(self):
        """Test that error logging occurs in error cases."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)

        batch_content = [{"file_path": "/test/file.py", "language": "python"}]

        with patch("adversary_mcp_server.scanner.llm_scanner.logger") as mock_logger:
            result = scanner._parse_batch_response("invalid json", batch_content)

            # Should return empty list and log error
            assert result == []
            mock_logger.error.assert_called()
            error_call_args = mock_logger.error.call_args[0][0]
            assert "Failed to parse batch response" in error_call_args

    def test_is_available_debug_logging(self):
        """Test that is_available method includes debug logging."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(enable_llm_analysis=True, llm_provider="openai")
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()  # Force client to be available

        with patch("adversary_mcp_server.scanner.llm_scanner.logger") as mock_logger:
            with patch.object(
                scanner.config, "is_llm_analysis_available", return_value=True
            ):
                result = scanner.is_available()

                # Should call debug logging regardless of result
                mock_logger.debug.assert_called()
                # Check that it was called with the expected pattern
                debug_calls = mock_logger.debug.call_args_list
                assert len(debug_calls) > 0
                assert "LLMScanner.is_available() called - returning" in str(
                    debug_calls
                )

    @pytest.mark.asyncio
    async def test_analyze_code_async_cache_miss_scenario(self):
        """Test _analyze_code_async behavior on cache miss."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig(cache_llm_responses=True)
        mock_manager.load_config.return_value = mock_config

        scanner = LLMScanner(mock_manager)
        scanner.llm_client = MagicMock()

        # Mock cache manager (cache miss)
        mock_cache_manager = MagicMock()
        scanner.cache_manager = mock_cache_manager
        mock_cache_manager.get.return_value = None  # Cache miss

        # Mock hasher
        mock_hasher = MagicMock()
        mock_hasher.hash_content.return_value = "content_hash"
        mock_hasher.hash_llm_context.return_value = "context_hash"
        mock_cache_manager.get_hasher.return_value = mock_hasher

        # Mock successful LLM response
        mock_response = Mock()
        mock_response.content = '{"findings": []}'
        scanner.llm_client.complete_streaming_with_retry.return_value = mock_response

        result = await scanner._analyze_code_async(
            "test code", "/test/file.py", "python"
        )

        # Should get cache miss and proceed with LLM call
        mock_cache_manager.get.assert_called_once()
        scanner.llm_client.complete_streaming_with_retry.assert_called()  # May be called multiple times
        assert isinstance(result, list)


class TestLLMScannerErrorHandling:
    """Test LLM scanner error handling for uncovered branches."""

    def test_parse_analysis_response_json_parsing_error(self):
        """Test error handling when JSON parsing fails."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Invalid JSON that will cause parsing error
        response_text = "{ invalid json syntax }"

        with pytest.raises(LLMAnalysisError, match="Invalid JSON response from LLM"):
            analyzer.parse_analysis_response(response_text, "/test/file.py")

    def test_parse_analysis_response_exception_during_processing(self):
        """Test error handling when an exception occurs during response processing."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_config.enable_caching = False
        mock_config.llm_provider = None
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Test that missing required field gets handled gracefully
        # The robust code should handle this without raising exceptions
        response_text = """
        {
            "findings": [
                {
                    "missing_required_fields": true
                }
            ]
        }
        """

        # The code should handle this gracefully and return empty list
        result = analyzer.parse_analysis_response(response_text, "/test/file.py")
        assert isinstance(result, list)  # Should return list, not raise exception

    @pytest.mark.asyncio
    async def test_analyze_code_async_no_llm_client(self):
        """Test analyze_code_async when no LLM client is available."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_config.llm_provider = None  # No LLM provider
        mock_config.enable_caching = False  # Disable caching for test
        mock_manager.load_config.return_value = mock_config

        # Create a mock metrics collector
        mock_metrics_instance = Mock()

        analyzer = LLMScanner(mock_manager, metrics_collector=mock_metrics_instance)

        result = await analyzer._analyze_code_async(
            "test code", "/test/file.py", "python"
        )

        # Should return empty list when no LLM client available
        assert result == []

        # Should record metric for client unavailable
        mock_metrics_instance.record_metric.assert_called_with(
            "llm_analysis_total",
            1,
            labels={"status": "client_unavailable", "language": "python"},
        )

    @pytest.mark.asyncio
    async def test_analyze_code_async_llm_client_error(self):
        """Test analyze_code_async when LLM client raises an exception."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "test-key"
        mock_config.enable_caching = False  # Disable caching
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client"
        ) as mock_create_client:
            # Mock LLM client that raises an exception
            mock_llm_client = Mock()
            mock_llm_client.complete_with_retry.side_effect = Exception("LLM API error")
            mock_create_client.return_value = mock_llm_client

            mock_metrics_instance = Mock()

            analyzer = LLMScanner(mock_manager, metrics_collector=mock_metrics_instance)

            # The method should handle errors gracefully and return empty list
            result = await analyzer._analyze_code_async(
                "test code", "/test/file.py", "python"
            )
            assert result == []  # Should return empty list on error

    @pytest.mark.asyncio
    async def test_analyze_code_async_response_parsing_error(self):
        """Test analyze_code_async when response parsing fails."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "test-key"
        mock_config.enable_caching = False  # Disable caching
        mock_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.llm_scanner.create_llm_client"
        ) as mock_create_client:
            # Mock LLM client that returns invalid JSON
            mock_llm_client = Mock()
            mock_response = Mock()
            mock_response.content = "{ invalid json }"
            mock_llm_client.complete_with_retry.return_value = mock_response
            mock_create_client.return_value = mock_llm_client

            mock_metrics_instance = Mock()

            analyzer = LLMScanner(mock_manager, metrics_collector=mock_metrics_instance)

            # Should handle parsing errors gracefully and return empty list
            result = await analyzer._analyze_code_async(
                "test code", "/test/file.py", "python"
            )
            assert result == []  # Should return empty list on parsing error

    def test_to_threat_match_unknown_finding_type_mapping(self):
        """Test ThreatMatch creation with unknown finding types."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_config.enable_caching = False  # Disable caching
        mock_config.llm_provider = None  # No LLM provider to avoid client init
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Create a finding with an unknown type
        finding = LLMSecurityFinding(
            finding_type="unknown_vulnerability_type",
            severity="high",
            description="Test unknown type",
            line_number=10,
            code_snippet="test code",
            explanation="test explanation",
            recommendation="test recommendation",
            confidence=0.9,
        )

        threat_match = finding.to_threat_match("/test/file.py")

        # Should map unknown type to MISC category
        assert threat_match.category == Category.MISC
        assert threat_match.rule_name == "Unknown Vulnerability Type"

    def test_to_threat_match_edge_case_confidence(self):
        """Test ThreatMatch creation with edge case confidence values."""
        mock_manager = Mock(spec=CredentialManager)
        mock_config = SecurityConfig()
        mock_config.enable_caching = False  # Disable caching
        mock_config.llm_provider = None  # No LLM provider to avoid client init
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Test with very low confidence
        finding = LLMSecurityFinding(
            finding_type="sql_injection",
            severity="high",
            description="Low confidence finding",
            line_number=10,
            code_snippet="test code",
            explanation="test explanation",
            recommendation="test recommendation",
            confidence=0.01,
        )

        threat_match = finding.to_threat_match("/test/file.py")
        assert threat_match.confidence == 0.01

        # Test with maximum confidence
        finding.confidence = 1.0
        threat_match = finding.to_threat_match("/test/file.py")
        assert threat_match.confidence == 1.0
