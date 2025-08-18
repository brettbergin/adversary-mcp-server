"""Tests for SessionAwareLLMScanner."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.scanner.session_aware_llm_scanner import (
    SessionAwareLLMScanner,
)
from adversary_mcp_server.scanner.types import Severity
from adversary_mcp_server.session.session_types import SecurityFinding


class TestSessionAwareLLMScanner:
    """Test SessionAwareLLMScanner functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_credential_manager = Mock()
        self.mock_config = Mock()
        self.mock_config.llm_provider = "openai"
        self.mock_config.llm_api_key = "test-key"
        self.mock_config.llm_model = "gpt-4"
        self.mock_credential_manager.load_config.return_value = self.mock_config

    def test_initialization_with_credentials(self):
        """Test scanner initialization with valid credentials."""
        with patch(
            "adversary_mcp_server.scanner.session_aware_llm_scanner.create_llm_client"
        ) as mock_create_client:
            mock_llm_client = Mock()
            mock_create_client.return_value = mock_llm_client

            with patch(
                "adversary_mcp_server.scanner.session_aware_llm_scanner.LLMSessionManager"
            ) as mock_session_manager_class:
                mock_session_manager = Mock()
                mock_session_manager_class.return_value = mock_session_manager

                scanner = SessionAwareLLMScanner(self.mock_credential_manager)

                assert scanner.credential_manager == self.mock_credential_manager
                assert scanner.session_manager == mock_session_manager
                mock_create_client.assert_called_once()
                mock_session_manager_class.assert_called_once_with(
                    llm_client=mock_llm_client,
                    max_context_tokens=50000,
                    session_timeout_seconds=3600,
                )

    def test_initialization_without_credentials(self):
        """Test scanner initialization without valid credentials."""
        self.mock_config.llm_provider = None
        self.mock_config.llm_api_key = None

        scanner = SessionAwareLLMScanner(self.mock_credential_manager)

        assert scanner.session_manager is None

    def test_is_available_with_session_manager(self):
        """Test availability check with session manager."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)
        scanner.session_manager = Mock()

        assert scanner.is_available() is True

    def test_is_available_without_session_manager(self):
        """Test availability check without session manager."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)
        scanner.session_manager = None

        assert scanner.is_available() is False

    @pytest.mark.asyncio
    async def test_analyze_project_with_session(self):
        """Test project analysis with session."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)

        # Mock session manager
        mock_session_manager = Mock()
        mock_session = Mock()
        mock_session.session_id = "test-session-123"

        # Mock security findings
        mock_findings = [
            SecurityFinding(
                rule_id="sql_injection",
                rule_name="SQL Injection",
                description="Potential SQL injection vulnerability",
                severity=Severity.HIGH,
                file_path="app.py",
                line_number=42,
                confidence=0.9,
            ),
            SecurityFinding(
                rule_id="xss",
                rule_name="Cross-Site Scripting",
                description="Potential XSS vulnerability",
                severity=Severity.MEDIUM,
                file_path="template.html",
                line_number=15,
                confidence=0.8,
            ),
        ]

        mock_session_manager.create_session = AsyncMock(return_value=mock_session)
        mock_session_manager.analyze_with_session = AsyncMock(
            return_value=mock_findings[:1]
        )
        mock_session_manager.continue_analysis = AsyncMock(
            side_effect=[mock_findings[1:], []]
        )
        mock_session_manager.close_session = Mock()

        scanner.session_manager = mock_session_manager

        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            (project_root / "app.py").write_text("# test file")

            threat_matches = await scanner.analyze_project_with_session(
                project_root=project_root,
                analysis_focus="comprehensive security analysis",
            )

            # Verify session workflow
            mock_session_manager.create_session.assert_called_once_with(
                project_root=project_root,
                target_files=None,
                session_metadata={
                    "analysis_focus": "comprehensive security analysis",
                    "scanner_type": "session_aware_llm",
                },
            )

            # Should perform comprehensive analysis (3 phases)
            assert mock_session_manager.analyze_with_session.call_count == 1
            assert mock_session_manager.continue_analysis.call_count == 2

            mock_session_manager.close_session.assert_called_once_with(
                mock_session.session_id
            )

            # Verify threat matches
            assert len(threat_matches) == 2
            assert threat_matches[0].rule_id == "sql_injection"
            assert threat_matches[1].rule_id == "xss"

    @pytest.mark.asyncio
    async def test_analyze_project_without_session_manager(self):
        """Test project analysis without session manager."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)
        scanner.session_manager = None

        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            threat_matches = await scanner.analyze_project_with_session(project_root)

            assert threat_matches == []

    @pytest.mark.asyncio
    async def test_analyze_file_with_context(self):
        """Test file analysis with project context."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)

        # Mock session manager
        mock_session_manager = Mock()
        mock_session = Mock()
        mock_session.session_id = "file-session-123"

        mock_finding = SecurityFinding(
            rule_id="hardcoded_secret",
            rule_name="Hardcoded Secret",
            description="Hardcoded API key found",
            severity=Severity.HIGH,
            file_path="config.py",
            line_number=10,
            confidence=0.95,
        )

        mock_session_manager.create_session = AsyncMock(return_value=mock_session)
        mock_session_manager.analyze_with_session = AsyncMock(
            return_value=[mock_finding]
        )
        mock_session_manager.close_session = Mock()

        scanner.session_manager = mock_session_manager

        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir) / "project"
            project_root.mkdir()
            (project_root / ".git").mkdir()  # Make it look like a git project

            file_path = project_root / "config.py"
            file_path.write_text("API_KEY = 'secret123'")

            threat_matches = await scanner.analyze_file_with_context(
                file_path=file_path, context_hint="Look for hardcoded secrets"
            )

            # Verify session was created with project context
            mock_session_manager.create_session.assert_called_once()
            call_args = mock_session_manager.create_session.call_args
            assert call_args[1]["project_root"] == project_root
            assert call_args[1]["target_files"] == [file_path]

            # Verify analysis was performed
            mock_session_manager.analyze_with_session.assert_called_once()
            analysis_call_args = mock_session_manager.analyze_with_session.call_args
            assert "config.py" in analysis_call_args[1]["analysis_query"]
            assert analysis_call_args[1]["context_hint"] == "Look for hardcoded secrets"

            # Verify results
            assert len(threat_matches) == 1
            assert threat_matches[0].rule_id == "hardcoded_secret"

    @pytest.mark.asyncio
    async def test_analyze_code_with_context(self):
        """Test code analysis with minimal context."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)

        # Mock session manager
        mock_session_manager = Mock()
        mock_session = Mock()
        mock_session.session_id = "code-session-123"

        mock_finding = SecurityFinding(
            rule_id="eval_injection",
            rule_name="Code Injection via eval()",
            description="Use of eval() with user input",
            severity=Severity.CRITICAL,
            file_path="script.py",
            line_number=5,
            confidence=0.95,
        )

        mock_session_manager.create_session = AsyncMock(return_value=mock_session)
        mock_session_manager.analyze_with_session = AsyncMock(
            return_value=[mock_finding]
        )
        mock_session_manager.close_session = Mock()

        scanner.session_manager = mock_session_manager

        code_content = """
def process_input(user_input):
    # Dangerous use of eval
    result = eval(user_input)
    return result
"""

        threat_matches = await scanner.analyze_code_with_context(
            code_content=code_content,
            language="python",
            file_name="dangerous_script.py",
            context_hint="Look for code injection vulnerabilities",
        )

        # Verify session creation
        mock_session_manager.create_session.assert_called_once()

        # Verify analysis query contains code
        mock_session_manager.analyze_with_session.assert_called_once()
        analysis_call_args = mock_session_manager.analyze_with_session.call_args
        query = analysis_call_args[1]["analysis_query"]
        assert "python" in query
        assert "dangerous_script.py" in query
        assert "eval(user_input)" in query

        # Verify results
        assert len(threat_matches) == 1
        assert threat_matches[0].rule_id == "eval_injection"
        # File path should be updated to reflect the code snippet
        assert str(threat_matches[0].file_path).endswith("dangerous_script.py")

    @pytest.mark.asyncio
    async def test_perform_comprehensive_analysis(self):
        """Test comprehensive analysis phases."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)

        mock_session_manager = Mock()

        # Mock findings for each phase
        general_findings = [
            SecurityFinding(rule_id="general1", rule_name="General Issue")
        ]
        arch_findings = [
            SecurityFinding(rule_id="arch1", rule_name="Architecture Issue")
        ]
        interaction_findings = [
            SecurityFinding(rule_id="interaction1", rule_name="Interaction Issue")
        ]

        mock_session_manager.analyze_with_session = AsyncMock(
            return_value=general_findings
        )
        mock_session_manager.continue_analysis = AsyncMock(
            side_effect=[arch_findings, interaction_findings]
        )

        scanner.session_manager = mock_session_manager

        all_findings = await scanner._perform_comprehensive_analysis("test-session")

        # Verify all three phases were called
        mock_session_manager.analyze_with_session.assert_called_once()
        assert mock_session_manager.continue_analysis.call_count == 2

        # Check analysis queries
        initial_call = mock_session_manager.analyze_with_session.call_args
        initial_query = initial_call[1]["analysis_query"]
        assert "comprehensive security analysis" in initial_query
        assert "injection" in initial_query

        # Check follow-up queries
        continue_calls = mock_session_manager.continue_analysis.call_args_list
        arch_query = continue_calls[0][1]["follow_up_query"]
        interaction_query = continue_calls[1][1]["follow_up_query"]

        assert "architectural" in arch_query.lower()
        assert (
            "cross-file" in interaction_query.lower()
            or "interaction" in interaction_query.lower()
        )

        # Verify all findings are collected
        assert len(all_findings) == 3
        assert all_findings[0].rule_id == "general1"
        assert all_findings[1].rule_id == "arch1"
        assert all_findings[2].rule_id == "interaction1"

    def test_legacy_analyze_code_compatibility(self):
        """Test legacy analyze_code method for backwards compatibility."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)
        scanner.session_manager = None  # No session manager available

        # Should return empty list gracefully
        findings = scanner.analyze_code(
            source_code="print('hello')", file_path="test.py", language="python"
        )

        assert findings == []

    @pytest.mark.asyncio
    async def test_legacy_analyze_file_compatibility(self):
        """Test legacy analyze_file method for backwards compatibility."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)

        # Mock session manager for legacy method
        mock_session_manager = Mock()
        mock_session = Mock()
        mock_session.session_id = "legacy-test-123"
        mock_finding = SecurityFinding(rule_id="test", rule_name="Test")

        mock_session_manager.create_session = AsyncMock(return_value=mock_session)
        mock_session_manager.analyze_with_session = AsyncMock(
            return_value=[mock_finding]
        )
        mock_session_manager.close_session = Mock()
        scanner.session_manager = mock_session_manager

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "test.py"
            file_path.write_text("print('test')")

            findings = await scanner.analyze_file(file_path, "python")

            assert len(findings) == 1
            # Should be converted to LLMSecurityFinding format
            assert hasattr(findings[0], "finding_type")
            assert hasattr(findings[0], "severity")

    def test_cleanup_expired_sessions(self):
        """Test cleanup of expired sessions."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)

        # With session manager
        mock_session_manager = Mock()
        mock_session_manager.cleanup_expired_sessions.return_value = 3
        scanner.session_manager = mock_session_manager

        count = scanner.cleanup_expired_sessions()
        assert count == 3
        mock_session_manager.cleanup_expired_sessions.assert_called_once()

        # Without session manager
        scanner.session_manager = None
        count = scanner.cleanup_expired_sessions()
        assert count == 0

    @pytest.mark.asyncio
    async def test_analyze_with_different_project_structures(self):
        """Test analysis with various project structures."""
        scanner = SessionAwareLLMScanner(self.mock_credential_manager)

        mock_session_manager = Mock()
        mock_session = Mock()
        mock_session.session_id = "struct-test"

        mock_session_manager.create_session = AsyncMock(return_value=mock_session)
        mock_session_manager.analyze_with_session = AsyncMock(return_value=[])
        mock_session_manager.continue_analysis = AsyncMock(return_value=[])
        mock_session_manager.close_session = Mock()

        scanner.session_manager = mock_session_manager

        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            # Create different project structures to test project root detection
            structures = [
                {"indicators": [".git"], "expected": project_root},
                {"indicators": ["package.json"], "expected": project_root},
                {"indicators": ["pyproject.toml"], "expected": project_root},
                {"indicators": ["requirements.txt"], "expected": project_root},
            ]

            for structure in structures:
                # Clean up previous indicators
                for indicator in [
                    ".git",
                    "package.json",
                    "pyproject.toml",
                    "requirements.txt",
                ]:
                    indicator_path = project_root / indicator
                    if indicator_path.exists():
                        if indicator_path.is_dir():
                            indicator_path.rmdir()
                        else:
                            indicator_path.unlink()

                # Create current indicator
                for indicator in structure["indicators"]:
                    indicator_path = project_root / indicator
                    if indicator == ".git":
                        indicator_path.mkdir()
                    else:
                        indicator_path.write_text("{}")

                test_file = project_root / "src" / "test.py"
                test_file.parent.mkdir(exist_ok=True)
                test_file.write_text("print('test')")

                await scanner.analyze_file_with_context(test_file)

                # Verify session was created - project root detection should work
                mock_session_manager.create_session.assert_called()


@pytest.fixture
def temp_project_structure():
    """Create a temporary project structure for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        project_root = Path(temp_dir) / "test_project"
        project_root.mkdir()

        # Create realistic project structure
        (project_root / ".git").mkdir()
        (project_root / "src").mkdir()
        (project_root / "tests").mkdir()

        # Main application file
        main_file = project_root / "src" / "app.py"
        main_file.write_text(
            """
from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Vulnerable SQL injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return render_template('dashboard.html', username=username)
    else:
        return "Login failed"

@app.route('/profile/<user_id>')
def profile(user_id):
    # Vulnerable to path traversal
    with open(f'/var/www/profiles/{user_id}.txt', 'r') as f:
        content = f.read()
    return content

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production
"""
        )

        # Configuration file
        config_file = project_root / "src" / "config.py"
        config_file.write_text(
            """
# Configuration settings
DATABASE_URL = "sqlite:///users.db"
SECRET_KEY = "hardcoded-secret-key-123"  # Hardcoded secret
DEBUG = True
ALLOWED_HOSTS = ["*"]  # Overly permissive
"""
        )

        # Requirements file
        requirements_file = project_root / "requirements.txt"
        requirements_file.write_text(
            """
flask==2.0.0
sqlite3
requests==2.25.0
"""
        )

        # Test file
        test_file = project_root / "tests" / "test_app.py"
        test_file.write_text(
            """
import unittest
from src.app import app

class TestApp(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_login(self):
        response = self.app.post('/login', data={'username': 'admin', 'password': 'password'})
        self.assertEqual(response.status_code, 200)
"""
        )

        yield project_root


class TestSessionAwareLLMScannerIntegration:
    """Integration tests for SessionAwareLLMScanner."""

    @pytest.mark.asyncio
    async def test_realistic_vulnerability_detection(self, temp_project_structure):
        """Test vulnerability detection in realistic project structure."""
        scanner = SessionAwareLLMScanner(Mock())

        # Mock session manager with realistic responses
        mock_session_manager = Mock()
        mock_session = Mock()
        mock_session.session_id = "realistic-test"

        # Mock comprehensive findings
        sql_injection = SecurityFinding(
            rule_id="sql_injection",
            rule_name="SQL Injection Vulnerability",
            description="Dynamic SQL query construction using string formatting",
            severity=Severity.CRITICAL,
            file_path="src/app.py",
            line_number=15,
            code_snippet="query = f\"SELECT * FROM users WHERE username='{username}'\"",
            confidence=0.95,
            architectural_context="Flask web application with direct database queries",
            remediation_advice="Use parameterized queries or an ORM",
        )

        path_traversal = SecurityFinding(
            rule_id="path_traversal",
            rule_name="Path Traversal Vulnerability",
            description="User input directly used in file path construction",
            severity=Severity.HIGH,
            file_path="src/app.py",
            line_number=24,
            code_snippet="with open(f'/var/www/profiles/{user_id}.txt', 'r')",
            confidence=0.90,
            cross_file_references=["config.py"],
            remediation_advice="Validate and sanitize user_id parameter",
        )

        hardcoded_secret = SecurityFinding(
            rule_id="hardcoded_secret",
            rule_name="Hardcoded Secret Key",
            description="Secret key hardcoded in configuration file",
            severity=Severity.HIGH,
            file_path="src/config.py",
            line_number=3,
            code_snippet='SECRET_KEY = "hardcoded-secret-key-123"',
            confidence=0.98,
            architectural_context="Flask application configuration",
        )

        debug_mode = SecurityFinding(
            rule_id="debug_mode_production",
            rule_name="Debug Mode in Production",
            description="Flask debug mode enabled which exposes sensitive information",
            severity=Severity.MEDIUM,
            file_path="src/app.py",
            line_number=30,
            code_snippet="app.run(debug=True)",
            confidence=0.85,
        )

        mock_session_manager.create_session = AsyncMock(return_value=mock_session)
        mock_session_manager.analyze_with_session = AsyncMock(
            return_value=[sql_injection, path_traversal]
        )
        mock_session_manager.continue_analysis = AsyncMock(
            side_effect=[[hardcoded_secret], [debug_mode]]
        )
        mock_session_manager.close_session = Mock()

        scanner.session_manager = mock_session_manager

        # Perform analysis
        threat_matches = await scanner.analyze_project_with_session(
            project_root=temp_project_structure,
            analysis_focus="comprehensive security analysis for web application",
        )

        # Verify comprehensive analysis was performed
        mock_session_manager.analyze_with_session.assert_called_once()
        assert mock_session_manager.continue_analysis.call_count == 2

        # Verify findings - should have findings from mocked responses
        assert (
            len(threat_matches) >= 2
        ), f"Expected at least 2 findings, got {len(threat_matches)}"

        # Check specific vulnerabilities were found
        rule_ids = [tm.rule_id for tm in threat_matches]
        assert "sql_injection" in rule_ids, f"sql_injection not found in {rule_ids}"
        assert "path_traversal" in rule_ids, f"path_traversal not found in {rule_ids}"
        assert "debug_mode_production" in rule_ids

        # Verify severity distribution (check string severities since ThreatMatch uses strings)
        critical_findings = [
            tm for tm in threat_matches if str(tm.severity).lower() == "critical"
        ]
        high_findings = [
            tm for tm in threat_matches if str(tm.severity).lower() == "high"
        ]
        medium_findings = [
            tm for tm in threat_matches if str(tm.severity).lower() == "medium"
        ]

        assert (
            len(critical_findings) == 1
        ), f"Expected 1 critical finding, got {len(critical_findings)}: {[tm.rule_id for tm in critical_findings]}"
        assert (
            len(high_findings) >= 2
        ), f"Expected at least 2 high findings, got {len(high_findings)}: {[tm.rule_id for tm in high_findings]}"
        assert (
            len(medium_findings) >= 1
        ), f"Expected at least 1 medium finding, got {len(medium_findings)}: {[tm.rule_id for tm in medium_findings]}"

        # Verify architectural context is preserved
        sql_finding = next(tm for tm in threat_matches if tm.rule_id == "sql_injection")
        assert "Flask" in sql_finding.metadata.get("architectural_context", "")

    @pytest.mark.asyncio
    async def test_cross_file_vulnerability_analysis(self, temp_project_structure):
        """Test detection of vulnerabilities that span multiple files."""
        scanner = SessionAwareLLMScanner(Mock())

        mock_session_manager = Mock()
        mock_session = Mock()

        # Mock cross-file vulnerability finding
        cross_file_vuln = SecurityFinding(
            rule_id="cross_file_data_exposure",
            rule_name="Cross-File Data Exposure",
            description="Hardcoded secret in config.py used insecurely in app.py",
            severity=Severity.HIGH,
            file_path="src/app.py",
            line_number=8,
            confidence=0.85,
            cross_file_references=["src/config.py"],
            architectural_context="Secret management across application modules",
        )

        # Add a finding from phase 1 to ensure phase 3 runs
        initial_finding = SecurityFinding(
            rule_id="initial_vuln",
            rule_name="Initial Vulnerability",
            description="Initial finding to trigger cross-file analysis",
            severity=Severity.LOW,
        )

        mock_session_manager.create_session = AsyncMock(return_value=mock_session)
        mock_session_manager.analyze_with_session = AsyncMock(
            return_value=[initial_finding]
        )
        mock_session_manager.continue_analysis = AsyncMock(
            side_effect=[[], [cross_file_vuln]]
        )
        mock_session_manager.close_session = Mock()

        scanner.session_manager = mock_session_manager

        threat_matches = await scanner.analyze_project_with_session(
            temp_project_structure
        )

        # Verify cross-file analysis was performed
        continue_calls = mock_session_manager.continue_analysis.call_args_list
        interaction_query = continue_calls[1][1]["follow_up_query"]
        assert (
            "cross-file" in interaction_query.lower()
            or "interaction" in interaction_query.lower()
        )

        # Verify cross-file vulnerability was detected (plus initial finding)
        assert len(threat_matches) == 2
        cross_file_finding = next(
            tm for tm in threat_matches if tm.rule_id == "cross_file_data_exposure"
        )
        assert cross_file_finding.rule_id == "cross_file_data_exposure"
        cross_refs = cross_file_finding.metadata.get("cross_file_references", [])
        assert any(
            "config.py" in ref for ref in cross_refs
        ), f"Expected config.py in {cross_refs}"

    @pytest.mark.asyncio
    async def test_error_handling_and_graceful_degradation(
        self, temp_project_structure
    ):
        """Test error handling during session-aware analysis."""
        scanner = SessionAwareLLMScanner(Mock())

        mock_session_manager = Mock()

        # Test session creation failure
        mock_session_manager.create_session = AsyncMock(
            side_effect=Exception("Session creation failed")
        )
        scanner.session_manager = mock_session_manager

        with pytest.raises(Exception, match="Session creation failed"):
            await scanner.analyze_project_with_session(temp_project_structure)

        # Test analysis failure with session cleanup
        mock_session = Mock()
        mock_session.session_id = "error-test"

        # Reset the mock for the second test
        mock_session_manager.reset_mock()
        mock_session_manager.create_session = AsyncMock(return_value=mock_session)

        # Mock the _perform_comprehensive_analysis method to fail
        original_method = scanner._perform_comprehensive_analysis
        scanner._perform_comprehensive_analysis = AsyncMock(
            side_effect=Exception("Analysis failed")
        )
        mock_session_manager.close_session = Mock()

        try:
            with pytest.raises(Exception, match="Analysis failed"):
                await scanner.analyze_project_with_session(temp_project_structure)

            # Verify session was still cleaned up despite error
            mock_session_manager.close_session.assert_called_with(
                mock_session.session_id
            )
        finally:
            # Restore original method
            scanner._perform_comprehensive_analysis = original_method

    @pytest.mark.asyncio
    async def test_context_hint_integration(self, temp_project_structure):
        """Test integration of context hints in analysis."""
        scanner = SessionAwareLLMScanner(Mock())

        mock_session_manager = Mock()
        mock_session = Mock()

        mock_session_manager.create_session = AsyncMock(return_value=mock_session)
        mock_session_manager.analyze_with_session = AsyncMock(return_value=[])
        mock_session_manager.close_session = Mock()

        scanner.session_manager = mock_session_manager

        # Test file analysis with context hint
        test_file = temp_project_structure / "src" / "app.py"
        await scanner.analyze_file_with_context(
            file_path=test_file,
            context_hint="Focus on SQL injection and input validation",
        )

        # Verify context hint was passed through
        analysis_call = mock_session_manager.analyze_with_session.call_args
        assert (
            analysis_call[1]["context_hint"]
            == "Focus on SQL injection and input validation"
        )
