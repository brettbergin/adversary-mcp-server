"""Tests for LLM security analyzer module."""

import os
import sys
from unittest.mock import Mock, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.credential_manager import CredentialManager, SecurityConfig
from adversary_mcp_server.llm_security_analyzer import (
    LLMAnalysisError,
    LLMSecurityAnalyzer,
    LLMSecurityFinding,
)
from adversary_mcp_server.threat_engine import Category, Language, Severity


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
        """Test converting finding to ThreatMatch."""
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
        )

        threat_match = finding.to_threat_match("test.py")

        assert threat_match.rule_id == "llm_sql_injection"
        assert threat_match.rule_name == "LLM: Sql Injection"
        assert threat_match.category == Category.INJECTION
        assert threat_match.severity == Severity.HIGH
        assert threat_match.file_path == "test.py"
        assert threat_match.line_number == 10
        assert threat_match.confidence == 0.9
        assert threat_match.cwe_id == "CWE-89"

    def test_category_mapping(self):
        """Test vulnerability type to category mapping."""
        test_cases = [
            ("xss", Category.XSS),
            ("deserialization", Category.DESERIALIZATION),
            ("path_traversal", Category.LFI),
            ("hardcoded_credential", Category.SECRETS),
            ("weak_crypto", Category.CRYPTOGRAPHY),
            ("csrf", Category.CSRF),
            ("unknown_type", Category.INJECTION),  # Default fallback
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


class TestLLMSecurityAnalyzer:
    """Test LLMSecurityAnalyzer class."""

    def test_initialization_with_api_key(self):
        """Test analyzer initialization with API key."""
        mock_manager = Mock()
        mock_config = SecurityConfig(openai_api_key="sk-test123")
        mock_manager.load_config.return_value = mock_config

        with patch("adversary_mcp_server.llm_security_analyzer.OpenAI") as mock_openai:
            analyzer = LLMSecurityAnalyzer(mock_manager)

            assert analyzer.credential_manager == mock_manager
            assert analyzer.config == mock_config
            mock_openai.assert_called_once_with(api_key="sk-test123")

    def test_initialization_without_api_key(self):
        """Test analyzer initialization without API key."""
        mock_manager = Mock()
        mock_config = SecurityConfig(openai_api_key="")
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

        assert analyzer.credential_manager == mock_manager
        assert analyzer.config == mock_config
        assert analyzer.client is None

    def test_is_available(self):
        """Test availability check."""
        mock_manager = Mock()

        # With API key
        mock_config = SecurityConfig(openai_api_key="sk-test123")
        mock_manager.load_config.return_value = mock_config

        with patch("adversary_mcp_server.llm_security_analyzer.OpenAI"):
            analyzer = LLMSecurityAnalyzer(mock_manager)
            assert analyzer.is_available() is True

        # Without API key
        mock_config = SecurityConfig(openai_api_key="")
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)
        assert analyzer.is_available() is False

    def test_analyze_code_not_available(self):
        """Test code analysis when analyzer is not available."""
        mock_manager = Mock()
        mock_config = SecurityConfig(openai_api_key="")
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

        with pytest.raises(LLMAnalysisError, match="LLM analysis not available"):
            analyzer.analyze_code("test code", "test.py", Language.PYTHON)

    @patch("adversary_mcp_server.llm_security_analyzer.OpenAI")
    def test_analyze_code_success(self, mock_openai):
        """Test successful code analysis."""
        mock_manager = Mock()
        mock_config = SecurityConfig(openai_api_key="sk-test123")
        mock_manager.load_config.return_value = mock_config

        # Mock OpenAI client
        mock_client = Mock()
        mock_openai.return_value = mock_client

        # Mock successful response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = """
        {
            "findings": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection vulnerability",
                    "line_number": 10,
                    "code_snippet": "SELECT * FROM users WHERE id = user_input",
                    "explanation": "Direct string concatenation in SQL query",
                    "recommendation": "Use parameterized queries",
                    "confidence": 0.9,
                    "cwe_id": "CWE-89"
                }
            ]
        }
        """
        mock_client.chat.completions.create.return_value = mock_response

        analyzer = LLMSecurityAnalyzer(mock_manager)
        analyzer.client = mock_client

        results = analyzer.analyze_code("test code", "test.py", Language.PYTHON)

        assert len(results) == 1
        assert results[0].finding_type == "sql_injection"
        assert results[0].severity == "high"
        assert results[0].line_number == 10
        assert results[0].confidence == 0.9

        # Verify API call
        mock_client.chat.completions.create.assert_called_once()
        call_args = mock_client.chat.completions.create.call_args
        assert call_args[1]["model"] == mock_config.openai_model
        assert call_args[1]["temperature"] == 0.1
        assert call_args[1]["response_format"] == {"type": "json_object"}

    @patch("adversary_mcp_server.llm_security_analyzer.OpenAI")
    def test_analyze_code_api_error(self, mock_openai):
        """Test code analysis with API error."""
        mock_manager = Mock()
        mock_config = SecurityConfig(openai_api_key="sk-test123")
        mock_manager.load_config.return_value = mock_config

        # Mock OpenAI client
        mock_client = Mock()
        mock_openai.return_value = mock_client

        # Mock API error
        mock_client.chat.completions.create.side_effect = Exception("API Error")

        analyzer = LLMSecurityAnalyzer(mock_manager)
        analyzer.client = mock_client

        with pytest.raises(LLMAnalysisError, match="LLM analysis failed"):
            analyzer.analyze_code("test code", "test.py", Language.PYTHON)

    def test_get_system_prompt(self):
        """Test system prompt generation."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)
        prompt = analyzer._get_system_prompt()

        assert isinstance(prompt, str)
        assert "security engineer" in prompt.lower()
        assert "json" in prompt.lower()
        assert "sql injection" in prompt.lower()
        assert "xss" in prompt.lower()

    def test_create_analysis_prompt(self):
        """Test analysis prompt creation."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

        source_code = "SELECT * FROM users WHERE id = user_input"
        prompt = analyzer._create_analysis_prompt(source_code, Language.PYTHON, 5)

        assert isinstance(prompt, str)
        assert source_code in prompt
        assert "python" in prompt.lower()
        assert "up to 5" in prompt
        assert "json" in prompt.lower()

    def test_create_analysis_prompt_truncation(self):
        """Test analysis prompt with code truncation."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

        # Create very long source code
        long_code = "print('test')\n" * 1000
        prompt = analyzer._create_analysis_prompt(long_code, Language.PYTHON, 5)

        assert isinstance(prompt, str)
        assert "[truncated for analysis]" in prompt
        assert len(prompt) < len(long_code) + 2000  # Should be significantly shorter

    def test_parse_analysis_response_success(self):
        """Test successful response parsing."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

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

        findings = analyzer._parse_analysis_response(response_text, "test.py")

        assert len(findings) == 2
        assert findings[0].finding_type == "xss"
        assert findings[0].severity == "medium"
        assert findings[1].finding_type == "sql_injection"
        assert findings[1].confidence == 0.95
        assert findings[1].cwe_id == "CWE-89"

    def test_parse_analysis_response_invalid_json(self):
        """Test response parsing with invalid JSON."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

        with pytest.raises(LLMAnalysisError, match="Invalid JSON response"):
            analyzer._parse_analysis_response("invalid json", "test.py")

    def test_parse_analysis_response_no_findings(self):
        """Test response parsing with no findings key."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

        response_text = '{"results": []}'
        findings = analyzer._parse_analysis_response(response_text, "test.py")

        assert len(findings) == 0

    def test_parse_analysis_response_malformed_finding(self):
        """Test response parsing with malformed finding."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

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

        findings = analyzer._parse_analysis_response(response_text, "test.py")

        # Should get 1 valid finding (malformed one should be skipped)
        assert len(findings) == 1
        assert findings[0].finding_type == "xss"

    @patch("adversary_mcp_server.llm_security_analyzer.OpenAI")
    def test_batch_analyze_code(self, mock_openai):
        """Test batch code analysis."""
        mock_manager = Mock()
        mock_config = SecurityConfig(openai_api_key="sk-test123")
        mock_manager.load_config.return_value = mock_config

        # Mock OpenAI client
        mock_client = Mock()
        mock_openai.return_value = mock_client

        # Mock successful response for each chunk
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = """
        {
            "findings": [
                {
                    "type": "test_vuln",
                    "severity": "medium",
                    "description": "Test vulnerability",
                    "line_number": 1,
                    "code_snippet": "test",
                    "explanation": "test",
                    "recommendation": "test",
                    "confidence": 0.8
                }
            ]
        }
        """
        mock_client.chat.completions.create.return_value = mock_response

        analyzer = LLMSecurityAnalyzer(mock_manager)
        analyzer.client = mock_client

        code_chunks = [
            ("code1", "file1.py", Language.PYTHON),
            ("code2", "file2.py", Language.JAVASCRIPT),
        ]

        results = analyzer.batch_analyze_code(code_chunks, max_findings_per_chunk=5)

        assert len(results) == 2  # One finding per chunk
        assert results[0].finding_type == "test_vuln"
        assert results[1].finding_type == "test_vuln"

        # Should have called API twice
        assert mock_client.chat.completions.create.call_count == 2

    def test_get_analysis_stats(self):
        """Test getting analysis statistics."""
        mock_manager = Mock()
        mock_config = SecurityConfig(
            openai_api_key="sk-test123",
            openai_model="gpt-4",
            openai_max_tokens=2048,
        )
        mock_manager.load_config.return_value = mock_config

        with patch("adversary_mcp_server.llm_security_analyzer.OpenAI"):
            analyzer = LLMSecurityAnalyzer(mock_manager)

        stats = analyzer.get_analysis_stats()

        assert stats["available"] is True
        assert stats["model"] == "gpt-4"
        assert stats["max_tokens"] == 2048
        assert stats["api_key_configured"] is True
        assert "python" in stats["supported_languages"]
        assert "javascript" in stats["supported_languages"]
        assert "typescript" in stats["supported_languages"]

    def test_get_analysis_stats_not_available(self):
        """Test getting analysis statistics when not available."""
        mock_manager = Mock()
        mock_config = SecurityConfig(openai_api_key="")
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMSecurityAnalyzer(mock_manager)

        stats = analyzer.get_analysis_stats()

        assert stats["available"] is False
        assert stats["model"] is None
        assert stats["api_key_configured"] is False 