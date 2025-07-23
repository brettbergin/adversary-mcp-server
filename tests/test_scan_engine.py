"""Tests for enhanced scanner module."""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.scan_engine import EnhancedScanResult, ScanEngine
from adversary_mcp_server.threat_engine import (
    Category,
    Language,
    LanguageSupport,
    Severity,
    ThreatMatch,
)


class TestEnhancedScanResult:
    """Test EnhancedScanResult class."""

    def test_enhanced_scan_result_initialization(self):
        """Test EnhancedScanResult initialization."""
        rules_threats = [
            ThreatMatch(
                rule_id="test_rule_1",
                rule_name="Test Rule 1",
                description="Test description 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
            )
        ]

        llm_threats = [
            ThreatMatch(
                rule_id="llm_test_rule_1",
                rule_name="LLM Test Rule 1",
                description="LLM test description 1",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=20,
            )
        ]

        scan_metadata = {
            "rules_scan_success": True,
            "llm_scan_success": True,
            "source_lines": 100,
        }

        result = EnhancedScanResult(
            file_path="test.py",
            language=Language.PYTHON,
            rules_threats=rules_threats,
            llm_threats=llm_threats,
            semgrep_threats=[],
            scan_metadata=scan_metadata,
        )

        assert result.file_path == "test.py"
        assert result.language == Language.PYTHON
        assert len(result.rules_threats) == 1
        assert len(result.llm_threats) == 1
        assert len(result.all_threats) == 2  # Combined
        assert result.scan_metadata == scan_metadata

    def test_combine_threats_no_duplicates(self):
        """Test threat combination with no duplicates."""
        rules_threats = [
            ThreatMatch(
                rule_id="rule_1",
                rule_name="Rule 1",
                description="Description 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
            )
        ]

        llm_threats = [
            ThreatMatch(
                rule_id="llm_rule_1",
                rule_name="LLM Rule 1",
                description="LLM Description 1",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=20,
            )
        ]

        result = EnhancedScanResult(
            file_path="test.py",
            language=Language.PYTHON,
            rules_threats=rules_threats,
            llm_threats=llm_threats,
            semgrep_threats=[],
            scan_metadata={},
        )

        assert len(result.all_threats) == 2
        assert result.all_threats[0].rule_id == "rule_1"  # Rules first
        assert result.all_threats[1].rule_id == "llm_rule_1"

    def test_combine_threats_with_duplicates(self):
        """Test threat combination with potential duplicates."""
        rules_threats = [
            ThreatMatch(
                rule_id="rule_1",
                rule_name="Rule 1",
                description="Description 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
            )
        ]

        # LLM threat on same line with same category (should be filtered out)
        llm_threats = [
            ThreatMatch(
                rule_id="llm_rule_1",
                rule_name="LLM Rule 1",
                description="LLM Description 1",
                category=Category.INJECTION,  # Same category
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=11,  # Close line (within 2 lines)
            ),
            ThreatMatch(
                rule_id="llm_rule_2",
                rule_name="LLM Rule 2",
                description="LLM Description 2",
                category=Category.XSS,  # Different category
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=30,  # Different line
            ),
        ]

        result = EnhancedScanResult(
            file_path="test.py",
            language=Language.PYTHON,
            rules_threats=rules_threats,
            llm_threats=llm_threats,
            semgrep_threats=[],
            scan_metadata={},
        )

        # Should have 2 threats (rules threat + non-duplicate LLM threat)
        assert len(result.all_threats) == 2
        assert result.all_threats[0].rule_id == "rule_1"
        assert result.all_threats[1].rule_id == "llm_rule_2"

    def test_calculate_stats(self):
        """Test statistics calculation."""
        rules_threats = [
            ThreatMatch(
                rule_id="rule_1",
                rule_name="Rule 1",
                description="Description 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
            ),
            ThreatMatch(
                rule_id="rule_2",
                rule_name="Rule 2",
                description="Description 2",
                category=Category.XSS,
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=20,
            ),
        ]

        llm_threats = [
            ThreatMatch(
                rule_id="llm_rule_1",
                rule_name="LLM Rule 1",
                description="LLM Description 1",
                category=Category.SECRETS,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=30,
            )
        ]

        result = EnhancedScanResult(
            file_path="test.py",
            language=Language.PYTHON,
            rules_threats=rules_threats,
            llm_threats=llm_threats,
            semgrep_threats=[],
            scan_metadata={},
        )

        stats = result.stats

        assert stats["total_threats"] == 3
        assert stats["rules_threats"] == 2
        assert stats["llm_threats"] == 1
        assert stats["unique_threats"] == 3
        assert stats["severity_counts"]["high"] == 1
        assert stats["severity_counts"]["critical"] == 1
        assert stats["severity_counts"]["medium"] == 1
        assert stats["category_counts"]["injection"] == 1
        assert stats["category_counts"]["xss"] == 1
        assert stats["category_counts"]["secrets"] == 1
        assert stats["sources"]["rules_engine"] is True
        assert stats["sources"]["llm_analysis"] is True

    def test_get_high_confidence_threats(self):
        """Test filtering threats by confidence."""
        threats = [
            ThreatMatch(
                rule_id="rule_1",
                rule_name="Rule 1",
                description="Description 1",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                confidence=0.9,
            ),
            ThreatMatch(
                rule_id="rule_2",
                rule_name="Rule 2",
                description="Description 2",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=20,
                confidence=0.7,
            ),
        ]

        result = EnhancedScanResult(
            file_path="test.py",
            language=Language.PYTHON,
            rules_threats=threats,
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={},
        )

        high_confidence = result.get_high_confidence_threats(0.8)
        assert len(high_confidence) == 1
        assert high_confidence[0].rule_id == "rule_1"

    def test_get_critical_threats(self):
        """Test filtering critical threats."""
        threats = [
            ThreatMatch(
                rule_id="rule_1",
                rule_name="Rule 1",
                description="Description 1",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=10,
            ),
            ThreatMatch(
                rule_id="rule_2",
                rule_name="Rule 2",
                description="Description 2",
                category=Category.XSS,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=20,
            ),
        ]

        result = EnhancedScanResult(
            file_path="test.py",
            language=Language.PYTHON,
            rules_threats=threats,
            llm_threats=[],
            semgrep_threats=[],
            scan_metadata={},
        )

        critical_threats = result.get_critical_threats()
        assert len(critical_threats) == 1
        assert critical_threats[0].rule_id == "rule_1"


class TestScanEngine:
    """Test ScanEngine class."""

    def test_scan_engine_initialization(self):
        """Test ScanEngine initialization."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        with patch("adversary_mcp_server.scan_engine.ASTScanner") as mock_ast_scanner:
            with patch(
                "adversary_mcp_server.scan_engine.LLMScanner"
            ) as mock_llm_analyzer:
                mock_llm_instance = Mock()
                mock_llm_instance.is_available.return_value = True
                mock_llm_analyzer.return_value = mock_llm_instance

                scanner = ScanEngine(
                    threat_engine=mock_threat_engine,
                    credential_manager=mock_credential_manager,
                    enable_llm_analysis=True,
                )

                assert scanner.threat_engine == mock_threat_engine
                assert scanner.credential_manager == mock_credential_manager
                assert scanner.enable_llm_analysis is True
                mock_ast_scanner.assert_called_once_with(mock_threat_engine)
                mock_llm_analyzer.assert_called_once_with(mock_credential_manager)

    def test_scan_engine_initialization_llm_disabled(self):
        """Test ScanEngine initialization with LLM disabled."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        with patch("adversary_mcp_server.scan_engine.ASTScanner"):
            scanner = ScanEngine(
                threat_engine=mock_threat_engine,
                credential_manager=mock_credential_manager,
                enable_llm_analysis=False,
            )

            assert scanner.enable_llm_analysis is False
            assert scanner.llm_analyzer is None

    def test_scan_engine_initialization_llm_unavailable(self):
        """Test ScanEngine initialization with LLM unavailable."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        with patch("adversary_mcp_server.scan_engine.ASTScanner"):
            with patch(
                "adversary_mcp_server.scan_engine.LLMScanner"
            ) as mock_llm_analyzer:
                mock_llm_instance = Mock()
                mock_llm_instance.is_available.return_value = False
                mock_llm_analyzer.return_value = mock_llm_instance

                scanner = ScanEngine(
                    threat_engine=mock_threat_engine,
                    credential_manager=mock_credential_manager,
                    enable_llm_analysis=True,
                )

                assert scanner.enable_llm_analysis is False  # Should be disabled

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    @patch("adversary_mcp_server.scan_engine.LLMScanner")
    def test_scan_code_rules_only(self, mock_llm_analyzer, mock_ast_scanner):
        """Test code scanning with rules only."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        # Mock AST scanner
        mock_ast_instance = Mock()
        mock_ast_scanner.return_value = mock_ast_instance

        rule_threat = ThreatMatch(
            rule_id="rule_1",
            rule_name="Rule 1",
            description="Description 1",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
        )
        mock_ast_instance.scan_code.return_value = [rule_threat]

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            language=Language.PYTHON,
            use_llm=False,
        )

        assert isinstance(result, EnhancedScanResult)
        assert len(result.rules_threats) == 1
        assert len(result.llm_threats) == 0
        assert len(result.all_threats) == 1
        assert result.scan_metadata["rules_scan_success"] is True
        assert result.scan_metadata["llm_scan_success"] is False

        mock_ast_instance.scan_code.assert_called_once_with(
            "test code", "test.py", Language.PYTHON
        )

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    @patch("adversary_mcp_server.scan_engine.LLMScanner")
    def test_scan_code_with_llm(self, mock_llm_analyzer, mock_ast_scanner):
        """Test code scanning with both rules and LLM (client-based approach)."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        # Mock AST scanner
        mock_ast_instance = Mock()
        mock_ast_scanner.return_value = mock_ast_instance

        rule_threat = ThreatMatch(
            rule_id="rule_1",
            rule_name="Rule 1",
            description="Description 1",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
        )
        mock_ast_instance.scan_code.return_value = [rule_threat]

        # Mock LLM analyzer (client-based approach)
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_analyzer.return_value = mock_llm_instance

        # Mock prompt creation (client-based approach)
        from adversary_mcp_server.llm_scanner import LLMAnalysisPrompt

        mock_prompt = LLMAnalysisPrompt(
            system_prompt="System prompt",
            user_prompt="User prompt",
            file_path="test.py",
            language=Language.PYTHON,
            max_findings=20,
        )
        mock_llm_instance.create_analysis_prompt.return_value = mock_prompt
        mock_llm_instance.analyze_code.return_value = (
            []
        )  # Client-based approach returns empty list

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            language=Language.PYTHON,
            use_llm=True,
        )

        assert isinstance(result, EnhancedScanResult)
        assert len(result.rules_threats) == 1
        assert (
            len(result.llm_threats) == 0
        )  # Client-based approach doesn't populate this
        assert len(result.all_threats) == 1  # Only rules threats
        assert result.scan_metadata["rules_scan_success"] is True
        assert result.scan_metadata["llm_scan_success"] is True
        assert "llm_analysis_prompt" in result.scan_metadata

        mock_ast_instance.scan_code.assert_called_once()
        mock_llm_instance.create_analysis_prompt.assert_called_once_with(
            "test code", "test.py", Language.PYTHON
        )

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    @patch("adversary_mcp_server.scan_engine.LLMScanner")
    def test_scan_code_ast_failure(self, mock_llm_analyzer, mock_ast_scanner):
        """Test code scanning with AST scanner failure."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        # Mock AST scanner with failure
        mock_ast_instance = Mock()
        mock_ast_scanner.return_value = mock_ast_instance
        mock_ast_instance.scan_code.side_effect = Exception("AST scanning failed")

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            language=Language.PYTHON,
            use_llm=False,
        )

        assert isinstance(result, EnhancedScanResult)
        assert len(result.rules_threats) == 0
        assert result.scan_metadata["rules_scan_success"] is False
        assert "rules_scan_error" in result.scan_metadata

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    @patch("adversary_mcp_server.scan_engine.LLMScanner")
    def test_scan_code_llm_failure(self, mock_llm_analyzer, mock_ast_scanner):
        """Test code scanning with LLM analyzer failure."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        # Mock AST scanner
        mock_ast_instance = Mock()
        mock_ast_scanner.return_value = mock_ast_instance
        mock_ast_instance.scan_code.return_value = []

        # Mock LLM analyzer with failure at prompt creation level
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_analyzer.return_value = mock_llm_instance
        mock_llm_instance.create_analysis_prompt.side_effect = Exception(
            "LLM prompt creation failed"
        )

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            language=Language.PYTHON,
            use_llm=True,
        )

        assert isinstance(result, EnhancedScanResult)
        assert len(result.llm_threats) == 0
        assert result.scan_metadata["llm_scan_success"] is False
        assert "llm_scan_error" in result.scan_metadata

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    def test_scan_file_success(self, mock_ast_scanner):
        """Test file scanning success."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        # Mock AST scanner
        mock_ast_instance = Mock()
        mock_ast_scanner.return_value = mock_ast_instance
        mock_ast_instance.scan_code.return_value = []

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_file = Path(f.name)

        try:
            result = scanner.scan_file_sync(
                file_path=temp_file,
                language=Language.PYTHON,
                use_llm=False,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.file_path == str(temp_file)
            assert result.language == Language.PYTHON

        finally:
            # Clean up
            temp_file.unlink()

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    def test_scan_file_not_found(self, mock_ast_scanner):
        """Test file scanning with non-existent file."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        with pytest.raises(FileNotFoundError):
            scanner.scan_file_sync(
                file_path=Path("non_existent_file.py"),
                language=Language.PYTHON,
                use_llm=False,
            )

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    def test_scan_directory_success(self, mock_ast_scanner):
        """Test directory scanning success."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        # Mock AST scanner
        mock_ast_instance = Mock()
        mock_ast_scanner.return_value = mock_ast_instance
        mock_ast_instance.scan_code.return_value = []

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        # Create a temporary directory with Python files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files
            (temp_path / "test1.py").write_text("print('test1')")
            (temp_path / "test2.js").write_text("console.log('test2');")
            (temp_path / "test3.txt").write_text("not a code file")

            results = scanner.scan_directory_sync(
                directory_path=temp_path,
                recursive=False,
                use_llm=False,
            )

            # Should scan 3 files (Python, JavaScript, and Generic)
            assert len(results) == 3
            assert all(isinstance(result, EnhancedScanResult) for result in results)

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    def test_scan_directory_not_found(self, mock_ast_scanner):
        """Test directory scanning with non-existent directory."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        with pytest.raises(FileNotFoundError):
            scanner.scan_directory_sync(
                directory_path=Path("non_existent_directory"),
                use_llm=False,
            )

    def test_detect_language(self):
        """Test language detection from file extensions."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        test_cases = [
            ("test.py", Language.PYTHON),
            ("test.js", Language.JAVASCRIPT),
            ("test.jsx", Language.JAVASCRIPT),
            ("test.ts", Language.TYPESCRIPT),
            ("test.tsx", Language.TYPESCRIPT),
            ("test.html", Language.HTML),
            ("test.htm", Language.HTML),
            ("test.ejs", Language.HTML),
            ("test.handlebars", Language.HTML),
            ("test.hbs", Language.HTML),
            ("test.vue", Language.HTML),
            ("test.svelte", Language.HTML),
            ("test.css", Language.CSS),
            ("test.scss", Language.CSS),
            ("test.sass", Language.CSS),
            ("test.json", Language.JSON),
            ("test.yaml", Language.YAML),
            ("test.yml", Language.YAML),
            ("test.xml", Language.XML),
            ("test.svg", Language.XML),
            ("test.php", Language.PHP),
            ("test.sh", Language.SHELL),
            ("test.bash", Language.SHELL),
            ("test.dockerfile", Language.DOCKERFILE),
            ("test.go", Language.GO),
            ("test.rb", Language.RUBY),
            ("test.java", Language.JAVA),
            ("test.cs", Language.CSHARP),
            ("test.sql", Language.SQL),
            ("test.tf", Language.TERRAFORM),
            ("test.tfvars", Language.TERRAFORM),
            ("test.hcl", Language.TERRAFORM),
            ("test.unknown", Language.GENERIC),  # Updated fallback
        ]

        for filename, expected_language in test_cases:
            detected_language = scanner._detect_language(Path(filename))
            assert detected_language == expected_language

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    def test_scan_directory_includes_expanded_file_types(self, mock_ast_scanner):
        """Test that directory scanning includes new file types like .ejs, .html, etc."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        # Mock AST scanner
        mock_ast_instance = Mock()
        mock_ast_scanner.return_value = mock_ast_instance
        mock_ast_instance.scan_code.return_value = []

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files with various extensions
            test_files = [
                "test.py",
                "test.js",
                "test.html",
                "test.ejs",
                "template.handlebars",
                "styles.css",
                "config.json",
                "settings.yaml",
                "data.xml",
                "script.php",
                "deploy.sh",
                "app.go",
                "service.rb",
                "Main.java",
                "Program.cs",
                "query.sql",
                "main.tf",
                "variables.tfvars",
                "readme.md",
                "config.env",
            ]

            for filename in test_files:
                file_path = Path(temp_dir) / filename
                file_path.write_text(f"// Sample content for {filename}")

            # Scan directory
            results = scanner.scan_directory_sync(
                directory_path=Path(temp_dir),
                recursive=False,
                use_llm=False,
            )

            # Should scan all supported file types (everything except maybe some generic ones)
            scanned_files = [result.file_path for result in results]

            # Check that major web file types are included
            assert any("test.html" in path for path in scanned_files)
            assert any("test.ejs" in path for path in scanned_files)
            assert any("template.handlebars" in path for path in scanned_files)
            assert any("styles.css" in path for path in scanned_files)
            assert any("config.json" in path for path in scanned_files)
            assert any("settings.yaml" in path for path in scanned_files)
            assert any("data.xml" in path for path in scanned_files)
            assert any("script.php" in path for path in scanned_files)
            assert any("main.tf" in path for path in scanned_files)
            assert any("variables.tfvars" in path for path in scanned_files)

            # Should have more files than the old limited set
            assert (
                len(results) >= len(test_files) - 2
            )  # Allow for some generic files not being scanned

    def test_filter_by_severity(self):
        """Test severity filtering."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        threats = [
            ThreatMatch(
                rule_id="rule_1",
                rule_name="Rule 1",
                description="Description 1",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=10,
            ),
            ThreatMatch(
                rule_id="rule_2",
                rule_name="Rule 2",
                description="Description 2",
                category=Category.XSS,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=20,
            ),
            ThreatMatch(
                rule_id="rule_3",
                rule_name="Rule 3",
                description="Description 3",
                category=Category.SECRETS,
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=30,
            ),
        ]

        # Filter for HIGH and above
        filtered = scanner._filter_by_severity(threats, Severity.HIGH)
        assert len(filtered) == 2
        assert filtered[0].severity == Severity.HIGH
        assert filtered[1].severity == Severity.CRITICAL

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    @patch("adversary_mcp_server.scan_engine.LLMScanner")
    def test_get_scanner_stats(self, mock_llm_analyzer, mock_ast_scanner):
        """Test getting scanner statistics."""
        mock_threat_engine = Mock()
        mock_threat_engine.get_rule_statistics.return_value = {"total_rules": 10}
        mock_credential_manager = Mock()

        # Mock LLM analyzer
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_instance.get_analysis_stats.return_value = {"available": True}
        mock_llm_analyzer.return_value = mock_llm_instance

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        stats = scanner.get_scanner_stats()

        assert stats["ast_scanner_available"] is True
        assert stats["llm_analyzer_available"] is True
        assert stats["llm_analysis_enabled"] is True
        assert stats["threat_engine_stats"]["total_rules"] == 10
        assert stats["llm_stats"]["available"] is True

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    @patch("adversary_mcp_server.scan_engine.LLMScanner")
    def test_set_llm_enabled(self, mock_llm_analyzer, mock_ast_scanner):
        """Test enabling/disabling LLM analysis."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        # Mock LLM analyzer
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_analyzer.return_value = mock_llm_instance

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        assert scanner.enable_llm_analysis is False

        # Enable LLM analysis
        scanner.set_llm_enabled(True)
        assert scanner.enable_llm_analysis is True

        # Disable LLM analysis
        scanner.set_llm_enabled(False)
        assert scanner.enable_llm_analysis is False

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    @patch("adversary_mcp_server.scan_engine.LLMScanner")
    def test_reload_configuration(self, mock_llm_analyzer, mock_ast_scanner):
        """Test configuration reload."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        # Mock LLM analyzer
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_analyzer.return_value = mock_llm_instance

        scanner = ScanEngine(
            threat_engine=mock_threat_engine,
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        scanner.reload_configuration()

        # Should reload threat engine rules
        mock_threat_engine.reload_rules.assert_called_once()

        # Should reinitialize LLM analyzer
        assert mock_llm_analyzer.call_count >= 2  # Initial + reload


class TestLanguageSupport:
    """Test centralized LanguageSupport class."""

    def test_get_supported_languages(self):
        """Test getting list of supported languages."""
        languages = LanguageSupport.get_supported_languages()

        # Should include all our expected languages
        assert Language.PYTHON in languages
        assert Language.JAVASCRIPT in languages
        assert Language.TERRAFORM in languages
        assert Language.HTML in languages
        assert Language.GENERIC in languages

        # Should be a reasonable number of languages
        assert len(languages) >= 17  # Current count including TERRAFORM

    def test_extension_to_language_mapping(self):
        """Test file extension to language mapping."""
        extension_map = LanguageSupport.get_extension_to_language_map()

        # Test some key mappings
        assert extension_map[".py"] == Language.PYTHON
        assert extension_map[".js"] == Language.JAVASCRIPT
        assert extension_map[".tf"] == Language.TERRAFORM
        assert extension_map[".tfvars"] == Language.TERRAFORM
        assert extension_map[".html"] == Language.HTML
        assert extension_map[".ejs"] == Language.HTML

    def test_language_to_extension_mapping(self):
        """Test language to primary extension mapping."""
        lang_map = LanguageSupport.get_language_to_extension_map()

        # Test primary extensions
        assert lang_map[Language.PYTHON] == ".py"
        assert lang_map[Language.JAVASCRIPT] == ".js"
        assert lang_map[Language.TERRAFORM] == ".tf"
        assert lang_map[Language.HTML] == ".html"

    def test_detect_language(self):
        """Test language detection from file paths."""
        test_cases = [
            ("main.tf", Language.TERRAFORM),
            ("variables.tfvars", Language.TERRAFORM),
            ("config.hcl", Language.TERRAFORM),
            ("template.ejs", Language.HTML),
            ("script.py", Language.PYTHON),
            ("Dockerfile", Language.DOCKERFILE),
            ("unknown.xyz", Language.GENERIC),
        ]

        for file_path, expected_lang in test_cases:
            detected = LanguageSupport.detect_language(file_path)
            assert (
                detected == expected_lang
            ), f"Failed for {file_path}: expected {expected_lang}, got {detected}"

    def test_get_extensions_for_language(self):
        """Test getting all extensions for a specific language."""
        # Test Terraform extensions
        tf_extensions = LanguageSupport.get_extensions_for_language(Language.TERRAFORM)
        assert ".tf" in tf_extensions
        assert ".tfvars" in tf_extensions
        assert ".hcl" in tf_extensions

        # Test HTML extensions
        html_extensions = LanguageSupport.get_extensions_for_language(Language.HTML)
        assert ".html" in html_extensions
        assert ".ejs" in html_extensions
        assert ".vue" in html_extensions

    def test_get_primary_extension(self):
        """Test getting primary extension for languages."""
        assert LanguageSupport.get_primary_extension(Language.TERRAFORM) == ".tf"
        assert LanguageSupport.get_primary_extension(Language.PYTHON) == ".py"
        assert LanguageSupport.get_primary_extension(Language.HTML) == ".html"

    def test_get_language_enum_values(self):
        """Test getting language enum values for API schemas."""
        enum_values = LanguageSupport.get_language_enum_values()

        # Should include all language string values
        assert "terraform" in enum_values
        assert "python" in enum_values
        assert "javascript" in enum_values
        assert "html" in enum_values
        assert "generic" in enum_values

        # Should be strings, not Language enums
        assert all(isinstance(val, str) for val in enum_values)

    def test_centralized_configuration_consistency(self):
        """Test that centralized configuration is internally consistent."""
        # All languages should have both extension mapping and primary extension
        supported_languages = LanguageSupport.get_supported_languages()
        extension_map = LanguageSupport.get_extension_to_language_map()
        primary_map = LanguageSupport.get_language_to_extension_map()

        for language in supported_languages:
            # Each language should have a primary extension
            assert language in primary_map

            # Primary extension should be in the extension map
            primary_ext = primary_map[language]
            assert primary_ext in extension_map
            assert extension_map[primary_ext] == language
