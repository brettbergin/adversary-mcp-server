"""Tests for the AST scanner component."""

from pathlib import Path

import pytest

from adversary_mcp_server.ast_scanner import (
    ASTScanner,
    CodeContext,
    JavaScriptAnalyzer,
    PythonAnalyzer,
)
from adversary_mcp_server.threat_engine import Language, ThreatEngine


class TestCodeContext:
    """Test cases for the CodeContext class."""

    def test_python_context(self):
        """Test Python code context."""
        code = """
import os
import sqlite3

def vulnerable_function(user_input):
    os.system("echo " + user_input)
    return True
        """

        context = CodeContext("test.py", code, Language.PYTHON)

        assert context.file_path == "test.py"
        assert context.language == Language.PYTHON
        assert len(context.lines) > 0
        assert context.ast_tree is not None

    def test_javascript_context(self):
        """Test JavaScript code context."""
        code = """
function processInput(userInput) {
    document.getElementById('output').innerHTML = userInput;
    eval('console.log("' + userInput + '")');
}
        """

        context = CodeContext("test.js", code, Language.JAVASCRIPT)

        assert context.file_path == "test.js"
        assert context.language == Language.JAVASCRIPT
        assert len(context.lines) > 0
        assert context.ast_tree is not None

    def test_get_line_content(self):
        """Test getting line content."""
        code = "line1\nline2\nline3"
        context = CodeContext("test.py", code, Language.PYTHON)

        assert context.get_line_content(1) == "line1"
        assert context.get_line_content(2) == "line2"
        assert context.get_line_content(3) == "line3"
        assert context.get_line_content(0) == ""
        assert context.get_line_content(10) == ""

    def test_get_code_snippet(self):
        """Test getting code snippets."""
        code = "line1\nline2\nline3\nline4\nline5"
        context = CodeContext("test.py", code, Language.PYTHON)

        snippet = context.get_code_snippet(3, 1)
        lines = snippet.split("\n")

        assert len(lines) == 3  # 2 context + 1 center
        assert ">>> 3:" in snippet  # Center line marker


class TestPythonAnalyzer:
    """Test cases for the PythonAnalyzer class."""

    def test_function_call_detection(self):
        """Test detecting function calls in Python code."""
        code = """
import os
import subprocess

def vulnerable_function():
    os.system("ls")
    subprocess.call(["ls", "-la"])
    print("hello")
        """

        context = CodeContext("test.py", code, Language.PYTHON)
        analyzer = PythonAnalyzer()
        results = analyzer.analyze(context)

        assert "function_calls" in results
        function_calls = results["function_calls"]

        assert "os.system" in function_calls
        assert "subprocess.call" in function_calls
        assert "print" in function_calls

    def test_import_detection(self):
        """Test detecting imports in Python code."""
        code = """
import os
import sys
from pathlib import Path
from typing import List, Dict
        """

        context = CodeContext("test.py", code, Language.PYTHON)
        analyzer = PythonAnalyzer()
        results = analyzer.analyze(context)

        assert "imports" in results
        imports = results["imports"]

        assert "os" in imports
        assert "sys" in imports
        assert "pathlib.Path" in imports
        assert "typing.List" in imports
        assert "typing.Dict" in imports

    def test_variable_detection(self):
        """Test detecting variables in Python code."""
        code = """
username = "admin"
password = "secret"
query = "SELECT * FROM users"
        """

        context = CodeContext("test.py", code, Language.PYTHON)
        analyzer = PythonAnalyzer()
        results = analyzer.analyze(context)

        assert "variables" in results
        variables = results["variables"]

        assert "username" in variables
        assert "password" in variables
        assert "query" in variables

    def test_syntax_error_handling(self):
        """Test handling of Python syntax errors."""
        code = """
def invalid_function(
    # Missing closing parenthesis and colon
        """

        context = CodeContext("test.py", code, Language.PYTHON)
        analyzer = PythonAnalyzer()
        results = analyzer.analyze(context)

        # Should return empty results for invalid syntax
        assert results == {}


class TestJavaScriptAnalyzer:
    """Test cases for the JavaScriptAnalyzer class."""

    def test_function_call_detection(self):
        """Test detecting function calls in JavaScript code."""
        code = """
function processData(input) {
    eval('console.log("' + input + '")');
    document.getElementById('output').innerHTML = input;
    fetch(input);
}
        """

        context = CodeContext("test.js", code, Language.JAVASCRIPT)
        analyzer = JavaScriptAnalyzer()
        results = analyzer.analyze(context)

        assert "function_calls" in results
        function_calls = results["function_calls"]

        assert "eval" in function_calls
        assert "fetch" in function_calls

    def test_property_detection(self):
        """Test detecting property access in JavaScript code."""
        code = """
document.getElementById('test').innerHTML = userInput;
window.location.href = maliciousUrl;
        """

        context = CodeContext("test.js", code, Language.JAVASCRIPT)
        analyzer = JavaScriptAnalyzer()
        results = analyzer.analyze(context)

        assert "properties" in results
        properties = results["properties"]

        assert "innerHTML" in properties
        assert "href" in properties

    def test_variable_detection(self):
        """Test detecting variables in JavaScript code."""
        code = """
var username = "admin";
let password = "secret";
const apiKey = "12345";
        """

        context = CodeContext("test.js", code, Language.JAVASCRIPT)
        analyzer = JavaScriptAnalyzer()
        results = analyzer.analyze(context)

        assert "variables" in results
        variables = results["variables"]

        assert "username" in variables
        assert "password" in variables
        assert "apiKey" in variables


class TestASTScanner:
    """Test cases for the ASTScanner class."""

    def test_init(self):
        """Test ASTScanner initialization."""
        threat_engine = ThreatEngine()
        scanner = ASTScanner(threat_engine)

        assert scanner.threat_engine is threat_engine
        assert scanner.python_analyzer is not None
        assert scanner.js_analyzer is not None

    def test_scan_python_code(self):
        """Test scanning Python code for vulnerabilities."""
        code = """
import os
import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def execute_command(user_input):
    os.system("echo " + user_input)
        """

        threat_engine = ThreatEngine()
        scanner = ASTScanner(threat_engine)

        threats = scanner.scan_code(code, "test.py", Language.PYTHON)

        # Should detect SQL injection and command injection
        assert len(threats) > 0

        # Check for specific vulnerability types
        rule_ids = [threat.rule_id for threat in threats]
        assert any("sql_injection" in rule_id for rule_id in rule_ids)
        assert any("command_injection" in rule_id for rule_id in rule_ids)

    def test_scan_javascript_code(self):
        """Test scanning JavaScript code for vulnerabilities."""
        code = """
function updateProfile(username) {
    document.getElementById('profile').innerHTML = '<h1>Welcome ' + username + '</h1>';
}

function processData(userInput) {
    eval('console.log("Processing: ' + userInput + '")');
}
        """

        threat_engine = ThreatEngine()
        scanner = ASTScanner(threat_engine)

        threats = scanner.scan_code(code, "test.js", Language.JAVASCRIPT)

        # Should detect XSS and code injection
        assert len(threats) > 0

        # Check for specific vulnerability types
        rule_ids = [threat.rule_id for threat in threats]
        assert any("xss" in rule_id or "eval" in rule_id for rule_id in rule_ids)

    def test_language_detection(self):
        """Test automatic language detection."""
        threat_engine = ThreatEngine()
        scanner = ASTScanner(threat_engine)

        # Test Python detection
        python_path = Path("test.py")
        detected_lang = scanner._detect_language(python_path)
        assert detected_lang == Language.PYTHON

        # Test JavaScript detection
        js_path = Path("test.js")
        detected_lang = scanner._detect_language(js_path)
        assert detected_lang == Language.JAVASCRIPT

        # Test TypeScript detection
        ts_path = Path("test.ts")
        detected_lang = scanner._detect_language(ts_path)
        assert detected_lang == Language.TYPESCRIPT

    def test_empty_code(self):
        """Test scanning empty code."""
        threat_engine = ThreatEngine()
        scanner = ASTScanner(threat_engine)

        threats = scanner.scan_code("", "empty.py", Language.PYTHON)
        assert len(threats) == 0

    def test_safe_code(self):
        """Test scanning safe code."""
        safe_python_code = """
import hashlib

def secure_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def safe_function():
    return "Hello, World!"
        """

        threat_engine = ThreatEngine()
        scanner = ASTScanner(threat_engine)

        threats = scanner.scan_code(safe_python_code, "safe.py", Language.PYTHON)

        # Safe code should have minimal or no threats
        assert len(threats) == 0 or all(
            threat.severity.value in ["low", "medium"] for threat in threats
        )

    def test_threat_match_properties(self):
        """Test properties of detected threat matches."""
        code = """
import os
os.system("echo test")
        """

        threat_engine = ThreatEngine()
        scanner = ASTScanner(threat_engine)

        threats = scanner.scan_code(code, "test.py", Language.PYTHON)

        if threats:
            threat = threats[0]

            # Check required properties
            assert threat.rule_id is not None
            assert threat.rule_name is not None
            assert threat.description is not None
            assert threat.category is not None
            assert threat.severity is not None
            assert threat.file_path == "test.py"
            assert threat.line_number > 0
            assert isinstance(threat.confidence, float)
            assert 0.0 <= threat.confidence <= 1.0


@pytest.mark.integration
class TestASTScannerIntegration:
    """Integration tests for the AST scanner."""

    def test_complex_python_scan(self):
        """Test scanning a complex Python file."""
        code = """
import os
import sqlite3
import pickle
import subprocess

class VulnerableApp:
    def __init__(self):
        self.db = sqlite3.connect('app.db')
    
    def authenticate(self, username, password):
        # SQL Injection vulnerability
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor = self.db.cursor()
        cursor.execute(query)
        return cursor.fetchone()
    
    def execute_system_command(self, command):
        # Command injection vulnerability
        os.system(f"ls {command}")
        subprocess.call(f"echo {command}", shell=True)
    
    def load_user_data(self, data):
        # Unsafe deserialization
        return pickle.loads(data)
    
    def get_file_content(self, filename):
        # Path traversal vulnerability
        with open(f"/var/www/{filename}", "r") as f:
            return f.read()
        """

        threat_engine = ThreatEngine()
        scanner = ASTScanner(threat_engine)

        threats = scanner.scan_code(code, "vulnerable_app.py", Language.PYTHON)

        # Should detect multiple vulnerabilities
        assert len(threats) >= 3

        # Check for various vulnerability categories
        categories = [threat.category.value for threat in threats]
        severities = [threat.severity.value for threat in threats]

        assert "injection" in categories
        assert "deserialization" in categories
        assert any(severity in ["high", "critical"] for severity in severities)
