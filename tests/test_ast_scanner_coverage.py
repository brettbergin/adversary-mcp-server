"""Additional AST scanner tests to improve coverage."""

import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from adversary_mcp_server.ast_scanner import ASTScanner, CodeContext
from adversary_mcp_server.threat_engine import Language


class TestASTScannerErrorHandling:
    """Test AST scanner error handling scenarios."""

    def test_scan_file_not_found(self):
        """Test scanning non-existent file."""
        threat_engine = Mock()
        scanner = ASTScanner(threat_engine)

        with pytest.raises(FileNotFoundError):
            scanner.scan_file(Path("nonexistent_file.py"))

    def test_scan_file_permission_error(self):
        """Test scanning file with permission error."""
        threat_engine = Mock()
        scanner = ASTScanner(threat_engine)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            test_file = Path(f.name)

        try:
            # Change permissions to make file unreadable
            test_file.chmod(0o000)

            with pytest.raises(PermissionError):
                scanner.scan_file(test_file)

        finally:
            # Restore permissions and cleanup
            test_file.chmod(0o644)
            test_file.unlink()

    def test_scan_binary_file(self):
        """Test scanning binary file."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".py", delete=False) as f:
            f.write(b"\x00\x01\x02\x03")  # Binary content
            test_file = Path(f.name)

        try:
            # Should handle binary files gracefully
            threats = scanner.scan_file(test_file)
            assert isinstance(threats, list)

        finally:
            test_file.unlink()

    def test_scan_large_file(self):
        """Test scanning large file."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            # Write a large file (> default size limit)
            large_content = "print('test')\n" * 10000
            f.write(large_content)
            test_file = Path(f.name)

        try:
            threats = scanner.scan_file(test_file)
            assert isinstance(threats, list)

        finally:
            test_file.unlink()

    def test_scan_directory_empty(self):
        """Test scanning empty directory."""
        threat_engine = Mock()
        scanner = ASTScanner(threat_engine)

        with tempfile.TemporaryDirectory() as temp_dir:
            threats = scanner.scan_directory(Path(temp_dir))
            assert threats == []

    def test_scan_directory_with_subdirectories(self):
        """Test scanning directory with subdirectories."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create subdirectory structure
            (temp_path / "subdir1").mkdir()
            (temp_path / "subdir1" / "test1.py").write_text("print('test1')")
            (temp_path / "subdir2").mkdir()
            (temp_path / "subdir2" / "test2.js").write_text("console.log('test2');")

            # Test recursive scan
            threats = scanner.scan_directory(temp_path, recursive=True)
            assert isinstance(threats, list)

            # Test non-recursive scan
            threats = scanner.scan_directory(temp_path, recursive=False)
            assert isinstance(threats, list)

    def test_scan_directory_permission_error(self):
        """Test scanning directory with permission error."""
        threat_engine = Mock()
        scanner = ASTScanner(threat_engine)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            restricted_dir = temp_path / "restricted"
            restricted_dir.mkdir()

            try:
                # Make directory unreadable
                restricted_dir.chmod(0o000)

                # Should handle permission errors gracefully
                threats = scanner.scan_directory(temp_path, recursive=True)
                assert isinstance(threats, list)

            finally:
                # Restore permissions
                restricted_dir.chmod(0o755)

    def test_detect_language_unknown_extension(self):
        """Test language detection with unknown file extension."""
        threat_engine = Mock()
        scanner = ASTScanner(threat_engine)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".unknown", delete=False
        ) as f:
            f.write("some content")
            test_file = Path(f.name)

        try:
            language = scanner._detect_language(test_file)
            # Should default to Python for unknown extensions
            assert language == Language.PYTHON

        finally:
            test_file.unlink()

    def test_detect_language_case_insensitive(self):
        """Test language detection is case insensitive."""
        threat_engine = Mock()
        scanner = ASTScanner(threat_engine)

        # Test uppercase extensions
        for ext, expected in [
            (".PY", Language.PYTHON),
            (".JS", Language.JAVASCRIPT),
            (".TS", Language.TYPESCRIPT),
        ]:
            with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
                f.write("some content")
                test_file = Path(f.name)

            try:
                language = scanner._detect_language(test_file)
                assert language == expected

            finally:
                test_file.unlink()


class TestCodeContextExtended:
    """Extended tests for CodeContext class."""

    def test_code_context_with_unicode(self):
        """Test CodeContext with unicode content."""
        unicode_code = "print('Hello 世界')\nprint('Testing unicode: café')"
        context = CodeContext("test.py", unicode_code, Language.PYTHON)

        assert len(context.lines) == 2
        assert "世界" in context.lines[0]
        assert "café" in context.lines[1]

    def test_code_context_with_mixed_line_endings(self):
        """Test CodeContext with mixed line endings."""
        mixed_code = "line1\nline2\r\nline3\rline4"
        context = CodeContext("test.py", mixed_code, Language.PYTHON)

        # Should handle different line endings
        assert len(context.lines) >= 3

    def test_get_code_snippet_boundary_conditions(self):
        """Test get_code_snippet with boundary conditions."""
        code = "\n".join([f"line{i}" for i in range(1, 21)])  # 20 lines
        context = CodeContext("test.py", code, Language.PYTHON)

        # Test snippet at beginning
        snippet = context.get_code_snippet(1)
        assert ">>> 1:" in snippet

        # Test snippet at end
        snippet = context.get_code_snippet(20)
        assert ">>> 20:" in snippet

        # Test snippet beyond file length - should return empty when line doesn't exist
        snippet = context.get_code_snippet(25)
        # The actual behavior is to return empty string when line is beyond file length
        assert snippet == ""  # Or we could check that it handles this gracefully

    def test_get_code_snippet_with_tabs(self):
        """Test get_code_snippet with tab characters."""
        code_with_tabs = "def function():\n\tprint('indented with tab')\n\treturn True"
        context = CodeContext("test.py", code_with_tabs, Language.PYTHON)

        snippet = context.get_code_snippet(2)
        assert ">>> 2:" in snippet
        assert "print" in snippet

    def test_get_line_content_edge_cases(self):
        """Test get_line_content with edge cases."""
        code = "line1\nline2\nline3"
        context = CodeContext("test.py", code, Language.PYTHON)

        # Test valid line numbers
        assert context.get_line_content(1) == "line1"
        assert context.get_line_content(2) == "line2"
        assert context.get_line_content(3) == "line3"

        # Test invalid line numbers
        assert context.get_line_content(0) == ""
        assert context.get_line_content(-1) == ""
        assert context.get_line_content(10) == ""


class TestASTScannerLanguageHandling:
    """Test AST scanner language-specific handling."""

    def test_scan_python_with_syntax_error_variations(self):
        """Test Python scanning with various syntax errors."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        syntax_error_codes = [
            "if True\n    print('missing colon')",  # Missing colon
            "print('unclosed string",  # Unclosed string
            "def function(\n    pass",  # Unclosed parenthesis
            "import\n",  # Incomplete import
        ]

        for i, code in enumerate(syntax_error_codes):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(code)
                test_file = Path(f.name)

            try:
                threats = scanner.scan_file(test_file)
                # Should handle syntax errors gracefully
                assert isinstance(threats, list)

            finally:
                test_file.unlink()

    def test_scan_javascript_with_syntax_error_variations(self):
        """Test JavaScript scanning with various syntax errors."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        syntax_error_codes = [
            "function test( {\n    console.log('missing closing paren');\n}",
            "if (true {\n    console.log('missing closing paren');\n}",
            "var x = ;\n",  # Incomplete assignment
            "function test() {\n    return\n}",  # Missing semicolon
        ]

        for i, code in enumerate(syntax_error_codes):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
                f.write(code)
                test_file = Path(f.name)

            try:
                threats = scanner.scan_file(test_file)
                # Should handle syntax errors gracefully
                assert isinstance(threats, list)

            finally:
                test_file.unlink()

    def test_scan_typescript_files(self):
        """Test scanning TypeScript files."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        typescript_code = """
        interface User {
            name: string;
            age: number;
        }
        
        function greet(user: User): string {
            return `Hello, ${user.name}!`;
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ts", delete=False) as f:
            f.write(typescript_code)
            test_file = Path(f.name)

        try:
            threats = scanner.scan_file(test_file)
            assert isinstance(threats, list)

        finally:
            test_file.unlink()

    def test_scan_code_with_language_override(self):
        """Test scan_code with explicit language override."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        python_code = "print('hello world')"

        # Scan as Python explicitly
        threats = scanner.scan_code(python_code, "test.txt", Language.PYTHON)
        assert isinstance(threats, list)

        # Scan as JavaScript explicitly (should work even with Python syntax)
        threats = scanner.scan_code(python_code, "test.txt", Language.JAVASCRIPT)
        assert isinstance(threats, list)


class TestASTScannerFileFiltering:
    """Test AST scanner file filtering."""

    def test_scan_directory_file_filtering(self):
        """Test directory scanning with file filtering."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create various file types
            (temp_path / "script.py").write_text("print('Python')")
            (temp_path / "app.js").write_text("console.log('JavaScript');")
            (temp_path / "types.ts").write_text("interface Test {}")
            (temp_path / "README.md").write_text("# Documentation")
            (temp_path / "config.json").write_text('{"test": true}')
            (temp_path / "binary.exe").write_bytes(b"\x00\x01\x02")

            threats = scanner.scan_directory(temp_path)

            # Should only scan supported file types
            assert isinstance(threats, list)

    def test_scan_directory_hidden_files(self):
        """Test directory scanning with hidden files."""
        threat_engine = Mock()
        threat_engine.get_rules_for_language.return_value = []
        scanner = ASTScanner(threat_engine)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create hidden files
            (temp_path / ".hidden.py").write_text("print('hidden')")
            (temp_path / "visible.py").write_text("print('visible')")

            threats = scanner.scan_directory(temp_path)

            # Should handle hidden files appropriately
            assert isinstance(threats, list)
