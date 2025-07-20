"""Tests for LLM security analyzer module."""

import os
import sys
from unittest.mock import Mock

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.credential_manager import SecurityConfig
from adversary_mcp_server.llm_scanner import (
    LLMAnalysisError,
    LLMAnalysisPrompt,
    LLMScanner,
    LLMSecurityFinding,
)
from adversary_mcp_server.threat_engine import Category, Language, Severity, ThreatMatch


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


class TestLLMScanner:
    """Test LLMScanner class."""

    def test_initialization_with_api_key(self):
        """Test analyzer initialization with LLM enabled."""
        mock_manager = Mock()
        mock_config = SecurityConfig(enable_llm_analysis=True)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        assert analyzer.credential_manager == mock_manager
        assert analyzer.is_available() is True

    def test_initialization_without_api_key(self):
        """Test analyzer initialization with LLM disabled."""
        mock_manager = Mock()
        mock_config = SecurityConfig(enable_llm_analysis=False)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        assert analyzer.credential_manager == mock_manager
        assert analyzer.is_available() is True  # Client-based LLM is always available

    def test_is_available(self):
        """Test availability check."""
        mock_manager = Mock()

        # With LLM enabled
        mock_config = SecurityConfig(enable_llm_analysis=True)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)
        assert analyzer.is_available() is True

        # With LLM disabled (still available for client-based)
        mock_config = SecurityConfig(enable_llm_analysis=False)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)
        assert analyzer.is_available() is True

    def test_analyze_code_not_available(self):
        """Test code analysis when analyzer is configured but not used."""
        mock_manager = Mock()
        mock_config = SecurityConfig(enable_llm_analysis=False)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Even when disabled, analyzer should work (client-based)
        result = analyzer.analyze_code("test code", "test.py", Language.PYTHON)

        assert isinstance(result, list)

    def test_analyze_code_success(self):
        """Test successful code analysis (client-based)."""
        mock_manager = Mock()
        mock_config = SecurityConfig(enable_llm_analysis=True)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Client-based analysis returns prompts instead of making API calls
        result = analyzer.analyze_code(
            "SELECT * FROM users WHERE id = user_input",
            "test.py",
            Language.PYTHON,
            max_findings=5,
        )

        assert isinstance(result, list)
        # Should be empty since no actual LLM call is made
        assert len(result) == 0

    def test_analyze_code_api_error(self):
        """Test code analysis error handling."""
        mock_manager = Mock()
        mock_config = SecurityConfig(enable_llm_analysis=True)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Client-based approach doesn't make API calls, so no API errors
        result = analyzer.analyze_code("test code", "test.py", Language.PYTHON)

        assert isinstance(result, list)
        assert len(result) == 0

    def test_get_system_prompt(self):
        """Test system prompt generation."""
        mock_manager = Mock()
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
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        source_code = "SELECT * FROM users WHERE id = user_input"
        prompt = analyzer.create_analysis_prompt(
            source_code, "test.py", Language.PYTHON, 5
        )

        assert isinstance(prompt, LLMAnalysisPrompt)
        assert prompt.file_path == "test.py"
        assert prompt.language == Language.PYTHON
        assert prompt.max_findings == 5
        assert "SELECT * FROM users WHERE id = user_input" in prompt.user_prompt
        assert "security vulnerabilities" in prompt.user_prompt.lower()
        assert "JSON format" in prompt.user_prompt
        assert "senior security engineer" in prompt.system_prompt.lower()

    def test_create_analysis_prompt_truncation(self):
        """Test analysis prompt with code truncation."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        # Create very long source code
        long_code = "print('test')\n" * 1000
        prompt = analyzer.create_analysis_prompt(
            long_code, "test.py", Language.PYTHON, 5
        )

        assert isinstance(prompt, LLMAnalysisPrompt)
        assert "truncated for analysis" in prompt.user_prompt
        assert len(prompt.user_prompt) < 12000  # Should be truncated

    def test_parse_analysis_response_success(self):
        """Test successful response parsing."""
        mock_manager = Mock()
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
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        with pytest.raises(LLMAnalysisError, match="Invalid JSON response"):
            analyzer.parse_analysis_response("invalid json", "test.py")

    def test_parse_analysis_response_no_findings(self):
        """Test response parsing with no findings key."""
        mock_manager = Mock()
        mock_config = SecurityConfig()
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        response_text = '{"results": []}'
        findings = analyzer.parse_analysis_response(response_text, "test.py")

        assert len(findings) == 0

    def test_parse_analysis_response_malformed_finding(self):
        """Test response parsing with malformed finding."""
        mock_manager = Mock()
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
        mock_manager = Mock()
        mock_config = SecurityConfig(enable_llm_analysis=True)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        code_samples = [
            ("code1", "file1.py", Language.PYTHON),
            ("code2", "file2.py", Language.PYTHON),
        ]

        result = analyzer.batch_analyze_code(code_samples)

        assert isinstance(result, list)
        assert len(result) == 2  # Should return results for both samples

    def test_get_analysis_stats(self):
        """Test getting analysis statistics."""
        mock_manager = Mock()
        mock_config = SecurityConfig(enable_llm_analysis=True)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        stats = analyzer.get_analysis_stats()

        assert isinstance(stats, dict)
        assert "total_analyses" in stats
        assert "successful_analyses" in stats
        assert "failed_analyses" in stats

    def test_get_analysis_stats_not_available(self):
        """Test getting analysis statistics when not available."""
        mock_manager = Mock()
        mock_config = SecurityConfig(enable_llm_analysis=False)
        mock_manager.load_config.return_value = mock_config

        analyzer = LLMScanner(mock_manager)

        stats = analyzer.get_analysis_stats()

        assert isinstance(stats, dict)
        assert "total_analyses" in stats
        assert "successful_analyses" in stats
        assert "failed_analyses" in stats
