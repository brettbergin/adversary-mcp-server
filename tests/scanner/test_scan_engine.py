"""Tests for enhanced scanner module."""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, mock_open, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult, ScanEngine
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


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
            llm_threats=llm_threats,
            semgrep_threats=rules_threats,  # Rules threats now go in semgrep_threats
            scan_metadata=scan_metadata,
        )

        assert result.file_path == "test.py"
        # Language is now auto-detected as generic
        assert len(result.semgrep_threats) == 1
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
            llm_threats=llm_threats,
            semgrep_threats=rules_threats,
            scan_metadata={},
        )

        assert len(result.all_threats) == 2
        assert result.all_threats[0].rule_id == "rule_1"  # Semgrep first
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
            llm_threats=llm_threats,
            semgrep_threats=rules_threats + [],
            scan_metadata={},
        )

        # Should have 2 threats (rules threat + non-duplicate LLM threat)
        assert len(result.all_threats) == 2
        assert result.all_threats[0].rule_id == "rule_1"
        assert result.all_threats[1].rule_id == "llm_rule_2"

    def test_combine_threats_with_semgrep_duplicates(self):
        """Test threat combination with Semgrep threats that duplicate rules."""
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

        # Semgrep threat on similar line with same category (should be filtered out)
        semgrep_threats = [
            ThreatMatch(
                rule_id="semgrep_rule_1",
                rule_name="Semgrep Rule 1",
                description="Semgrep Description 1",
                category=Category.INJECTION,  # Same category
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=11,  # Close line (within 2 lines)
            ),
            ThreatMatch(
                rule_id="semgrep_rule_2",
                rule_name="Semgrep Rule 2",
                description="Semgrep Description 2",
                category=Category.XSS,  # Different category
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=30,  # Different line
            ),
        ]

        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=rules_threats + semgrep_threats,
            scan_metadata={},
        )

        # Should have 3 threats (all semgrep threats since there are no LLM threats to deduplicate)
        assert len(result.all_threats) == 3
        assert result.all_threats[0].rule_id == "rule_1"
        assert result.all_threats[1].rule_id == "semgrep_rule_1"
        assert result.all_threats[2].rule_id == "semgrep_rule_2"

    def test_combine_threats_with_semgrep_and_llm_duplicates(self):
        """Test threat combination with both Semgrep and LLM threats that have duplicates."""
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

        semgrep_threats = [
            ThreatMatch(
                rule_id="semgrep_rule_1",
                rule_name="Semgrep Rule 1",
                description="Semgrep Description 1",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=20,
            )
        ]

        # LLM threat that duplicates semgrep threat
        llm_threats = [
            ThreatMatch(
                rule_id="llm_rule_1",
                rule_name="LLM Rule 1",
                description="LLM Description 1",
                category=Category.XSS,  # Same category as semgrep
                severity=Severity.LOW,
                file_path="test.py",
                line_number=21,  # Close line (within 2 lines)
            ),
            ThreatMatch(
                rule_id="llm_rule_2",
                rule_name="LLM Rule 2",
                description="LLM Description 2",
                category=Category.SECRETS,  # Different category
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=40,  # Different line
            ),
        ]

        result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=llm_threats,
            semgrep_threats=rules_threats + semgrep_threats,
            scan_metadata={},
        )

        # Should have 3 threats (rules + semgrep + non-duplicate LLM)
        assert len(result.all_threats) == 3
        assert result.all_threats[0].rule_id == "rule_1"
        assert result.all_threats[1].rule_id == "semgrep_rule_1"
        assert result.all_threats[2].rule_id == "llm_rule_2"

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
            llm_threats=llm_threats,
            semgrep_threats=rules_threats + [],
            scan_metadata={},
        )

        stats = result.stats

        assert stats["total_threats"] == 3
        assert stats["semgrep_threats"] == 2  # Rules threats are now in semgrep_threats
        assert stats["llm_threats"] == 1
        assert stats["unique_threats"] == 3
        assert stats["severity_counts"]["high"] == 1
        assert stats["severity_counts"]["critical"] == 1
        assert stats["severity_counts"]["medium"] == 1
        assert stats["category_counts"]["injection"] == 1
        assert stats["category_counts"]["xss"] == 1
        assert stats["category_counts"]["secrets"] == 1
        assert stats["sources"]["semgrep_analysis"] is True
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
            llm_threats=[],
            semgrep_threats=threats,
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
            llm_threats=[],
            semgrep_threats=threats,
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

        with patch(
            "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
        ) as mock_semgrep_scanner:
            with patch(
                "adversary_mcp_server.scanner.scan_engine.LLMScanner"
            ) as mock_llm_analyzer:
                mock_llm_instance = Mock()
                mock_llm_instance.is_available.return_value = True
                mock_llm_analyzer.return_value = mock_llm_instance

                scanner = ScanEngine(
                    credential_manager=mock_credential_manager,
                    enable_llm_analysis=True,
                )

                assert scanner.credential_manager == mock_credential_manager
                assert scanner.enable_llm_analysis is True
                mock_semgrep_scanner.assert_called_once()
                mock_llm_analyzer.assert_called_once_with(mock_credential_manager)

    def test_scan_engine_initialization_llm_disabled(self):
        """Test ScanEngine initialization with LLM disabled."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        with patch("adversary_mcp_server.scanner.semgrep_scanner.SemgrepScanner"):
            scanner = ScanEngine(
                credential_manager=mock_credential_manager,
                enable_llm_analysis=False,
            )

            assert scanner.enable_llm_analysis is False
            assert scanner.llm_analyzer is None

    def test_scan_engine_initialization_llm_unavailable(self):
        """Test ScanEngine initialization with LLM unavailable."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()

        with patch("adversary_mcp_server.scanner.semgrep_scanner.SemgrepScanner"):
            with patch(
                "adversary_mcp_server.scanner.scan_engine.LLMScanner"
            ) as mock_llm_analyzer:
                mock_llm_instance = Mock()
                mock_llm_instance.is_available.return_value = False
                mock_llm_analyzer.return_value = mock_llm_instance

                scanner = ScanEngine(
                    credential_manager=mock_credential_manager,
                    enable_llm_analysis=True,
                )

                assert scanner.enable_llm_analysis is False  # Should be disabled

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    def test_scan_code_with_llm(self, mock_llm_analyzer, mock_semgrep_scanner):
        """Test code scanning with both rules and LLM (client-based approach)."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        rule_threat = ThreatMatch(
            rule_id="rule_1",
            rule_name="Rule 1",
            description="Description 1",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
        )
        mock_semgrep_instance.scan_code = AsyncMock(return_value=[rule_threat])

        # Mock LLM analyzer (client-based approach)
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_analyzer.return_value = mock_llm_instance

        # Mock prompt creation (client-based approach)
        from adversary_mcp_server.scanner.llm_scanner import LLMAnalysisPrompt

        mock_prompt = LLMAnalysisPrompt(
            system_prompt="System prompt",
            user_prompt="User prompt",
            file_path="test.py",
            max_findings=20,
        )
        mock_llm_instance.create_analysis_prompt.return_value = mock_prompt
        mock_llm_instance.analyze_code.return_value = (
            []
        )  # Client-based approach returns empty list

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
            enable_semgrep_analysis=True,
            enable_llm_validation=False,  # Disable validation for this test
        )

        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            use_llm=True,
        )

        assert isinstance(result, EnhancedScanResult)
        assert len(result.semgrep_threats) == 1
        assert (
            len(result.llm_threats) == 0
        )  # Client-based approach doesn't populate this
        assert len(result.all_threats) == 1  # Only rules threats
        assert result.scan_metadata.get("semgrep_scan_success", True) is True
        assert result.scan_metadata["llm_scan_success"] is True
        assert "llm_analysis_prompt" in result.scan_metadata

        mock_semgrep_instance.scan_code.assert_called_once()
        mock_llm_instance.create_analysis_prompt.assert_called_once_with(
            "test code", "test.py", "generic"
        )

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    def test_scan_code_llm_failure(self, mock_llm_analyzer, mock_semgrep_scanner):
        """Test code scanning with LLM analyzer failure."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance
        mock_semgrep_instance.scan_code.return_value = []

        # Mock LLM analyzer with failure at prompt creation level
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_analyzer.return_value = mock_llm_instance
        mock_llm_instance.create_analysis_prompt.side_effect = Exception(
            "LLM prompt creation failed"
        )

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            use_llm=True,
        )

        assert isinstance(result, EnhancedScanResult)
        assert len(result.llm_threats) == 0
        assert result.scan_metadata["llm_scan_success"] is False
        assert "llm_scan_error" in result.scan_metadata

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_file_success(self, mock_semgrep_scanner):
        """Test file scanning success."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance
        mock_semgrep_instance.scan_code.return_value = []

        scanner = ScanEngine(
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
                use_llm=False,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.file_path == str(temp_file)
            # Language is now auto-detected as generic

        finally:
            # Clean up
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_file_not_found(self, mock_semgrep_scanner):
        """Test file scanning with non-existent file."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        with pytest.raises(FileNotFoundError):
            scanner.scan_file_sync(
                file_path=Path("non_existent_file.py"),
                use_llm=False,
            )

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_directory_success(self, mock_semgrep_scanner):
        """Test directory scanning success."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance
        mock_semgrep_instance.scan_code.return_value = []

        scanner = ScanEngine(
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

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_directory_not_found(self, mock_semgrep_scanner):
        """Test directory scanning with non-existent directory."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        with pytest.raises(FileNotFoundError):
            scanner.scan_directory_sync(
                directory_path=Path("non_existent_directory"),
                use_llm=False,
            )

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_directory_includes_expanded_file_types(self, mock_semgrep_scanner):
        """Test that directory scanning includes new file types like .ejs, .html, etc."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance
        mock_semgrep_instance.scan_code.return_value = []

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )
        mock_semgrep_instance.scan_code.return_value = []

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
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_credential_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
        ) as mock_semgrep_scanner:
            # Mock Semgrep scanner
            mock_semgrep_instance = Mock()
            mock_semgrep_instance.is_available.return_value = True
            mock_semgrep_scanner.return_value = mock_semgrep_instance

            scanner = ScanEngine(
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

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    def test_get_scanner_stats(self, mock_llm_analyzer, mock_semgrep_scanner):
        """Test getting scanner statistics."""
        mock_threat_engine = Mock()
        mock_threat_engine.get_rule_statistics.return_value = {"total_rules": 10}
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM analyzer
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_instance.get_analysis_stats.return_value = {"available": True}
        mock_llm_analyzer.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        stats = scanner.get_scanner_stats()

        assert stats["semgrep_scanner_available"] is True
        assert stats["llm_analyzer_available"] is True
        assert stats["llm_analysis_enabled"] is True
        assert stats["semgrep_analysis_enabled"] is True
        assert stats["llm_stats"]["available"] is True

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    def test_set_llm_enabled(self, mock_llm_analyzer, mock_semgrep_scanner):
        """Test enabling/disabling LLM analysis."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM analyzer
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_analyzer.return_value = mock_llm_instance

        scanner = ScanEngine(
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

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    def test_reload_configuration(self, mock_llm_analyzer, mock_semgrep_scanner):
        """Test configuration reload."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM analyzer
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_analyzer.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        scanner.reload_configuration()

        # Should reinitialize LLM analyzer (called twice - once during init, once during reload)
        assert mock_llm_analyzer.call_count == 2

        # Should reinitialize LLM analyzer
        assert mock_llm_analyzer.call_count >= 2  # Initial + reload

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @pytest.mark.asyncio
    async def test_scan_file_llm_analysis_success(
        self, mock_llm_scanner, mock_semgrep_scanner
    ):
        """Test scan_file with successful LLM analysis."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.return_value = []
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner
        from adversary_mcp_server.scanner.llm_scanner import LLMSecurityFinding

        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_finding = LLMSecurityFinding(
            finding_type="test",
            severity="high",
            description="Test finding",
            line_number=10,
            code_snippet="test code",
            explanation="Test explanation",
            recommendation="Test recommendation",
            confidence=0.9,
        )
        mock_llm_instance.analyze_file = AsyncMock(return_value=[mock_finding])
        mock_llm_scanner.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
            enable_llm_validation=False,  # Disable validation for this test
        )

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_file = Path(f.name)

        try:
            result = await scanner.scan_file(
                file_path=temp_file,
                use_llm=True,
                use_semgrep=False,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["llm_scan_success"] is True
            assert result.scan_metadata["llm_scan_reason"] == "analysis_completed"
            assert len(result.llm_threats) == 1

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @pytest.mark.asyncio
    async def test_scan_file_llm_analysis_exception(
        self, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test scan_file handles LLM analysis exceptions."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.return_value = []
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner to raise exception
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_instance.analyze_file = AsyncMock(
            side_effect=Exception("LLM analysis failed")
        )
        mock_llm_scanner.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_file = Path(f.name)

        try:
            result = await scanner.scan_file(
                file_path=temp_file,
                use_llm=True,
                use_semgrep=False,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["llm_scan_success"] is False
            assert result.scan_metadata["llm_scan_reason"] == "analysis_failed"
            assert "LLM analysis failed" in result.scan_metadata["llm_scan_error"]

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_file_llm_disabled_by_user(
        self, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test scan_file with LLM disabled by user."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.return_value = []
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_scanner.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_file = Path(f.name)

        try:
            result = scanner.scan_file_sync(
                file_path=temp_file,
                use_llm=False,  # Disabled by user
                use_semgrep=False,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["llm_scan_success"] is False
            assert result.scan_metadata["llm_scan_reason"] == "disabled_by_user"

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @pytest.mark.asyncio
    async def test_scan_directory_llm_analysis_success(
        self, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test scan_directory with successful LLM analysis."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.return_value = []
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_instance.get_status.return_value = {
            "available": False,
            "error": "Semgrep not found",
            "installation_status": "not_installed",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner
        from adversary_mcp_server.scanner.llm_scanner import LLMSecurityFinding

        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_instance.get_status.return_value = {
            "available": True,
            "version": "client-based",
            "installation_status": "available",
            "mode": "client-based",
        }
        mock_llm_scanner.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
            enable_llm_validation=False,  # Disable validation for this test
        )

        # Create a temporary directory with files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "test.py").write_text("print('test')")

            # Create mock finding with the correct file path
            mock_finding = LLMSecurityFinding(
                finding_type="test",
                severity="high",
                description="Test finding",
                line_number=10,
                code_snippet="test code",
                explanation="Test explanation",
                recommendation="Test recommendation",
                confidence=0.9,
                file_path=str(
                    temp_path / "test.py"
                ),  # Include file_path in constructor
            )
            mock_llm_instance.analyze_directory = AsyncMock(return_value=[mock_finding])

            results = await scanner.scan_directory(
                directory_path=temp_path,
                recursive=False,
                use_llm=True,
                use_semgrep=False,
            )

            assert len(results) == 1
            result = results[0]
            assert result.scan_metadata["llm_scan_success"] is True
            assert (
                result.scan_metadata["llm_scan_reason"]
                == "directory_analysis_completed"
            )
            assert len(result.llm_threats) == 1

    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @pytest.mark.asyncio
    async def test_scan_directory_llm_analysis_exception(
        self, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test scan_directory handles LLM analysis exceptions."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.return_value = []
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner to raise exception
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_instance.analyze_directory = AsyncMock(
            side_effect=Exception("LLM directory analysis failed")
        )
        mock_llm_scanner.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
        )

        # Create a temporary directory with files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "test.py").write_text("print('test')")

            results = await scanner.scan_directory(
                directory_path=temp_path,
                recursive=False,
                use_llm=True,
                use_semgrep=False,
            )

            assert len(results) == 1
            result = results[0]
            assert result.scan_metadata["llm_scan_success"] is False
            assert (
                result.scan_metadata["llm_scan_reason"] == "directory_analysis_failed"
            )
            assert (
                "LLM directory analysis failed"
                in result.scan_metadata["llm_scan_error"]
            )

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @pytest.mark.asyncio
    async def test_scan_directory_semgrep_directory_scan_exception(
        self, mock_semgrep_scanner
    ):
        """Test scan_directory handles Semgrep directory scan exceptions."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.return_value = []
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner to raise exception in directory scan
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_instance.scan_directory = AsyncMock(
            side_effect=Exception("Semgrep directory scan failed")
        )
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        # Create a temporary directory with files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "test.py").write_text("print('test')")

            results = await scanner.scan_directory(
                directory_path=temp_path,
                recursive=False,
                use_llm=False,
                use_semgrep=True,
            )

            assert len(results) == 1
            result = results[0]
            assert result.scan_metadata["semgrep_scan_success"] is False
            assert (
                result.scan_metadata["semgrep_scan_reason"] == "directory_scan_failed"
            )
            assert (
                "Semgrep directory scan failed"
                in result.scan_metadata["semgrep_scan_error"]
            )

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_directory_binary_file_in_directory(self, mock_semgrep_scanner):
        """Test scan_directory handles binary files in directory gracefully."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        # Create a temporary directory with a binary file
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create binary file
            binary_file = temp_path / "binary.py"
            with open(binary_file, "wb") as f:
                f.write(b"\x00\x01\x02\x03\xff\xfe")

            # Use patch to mock the file opening to simulate UnicodeDecodeError during directory scan
            with patch("builtins.open", mock_open()) as mock_file:
                # Configure the mock to raise UnicodeDecodeError when reading
                mock_file.return_value.__enter__.return_value.read.side_effect = (
                    UnicodeDecodeError(
                        "utf-8", b"\x00\x01\x02\x03\xff\xfe", 0, 1, "invalid start byte"
                    )
                )

                results = scanner.scan_directory_sync(
                    directory_path=temp_path,
                    recursive=False,
                    use_llm=False,
                    use_semgrep=False,
                )

                assert len(results) == 1
                result = results[0]
                assert result.scan_metadata.get("semgrep_scan_success", True) is False
                assert (
                    result.scan_metadata.get("semgrep_scan_reason", "unknown")
                    == "disabled_by_user"
                )

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_directory_file_processing_exception(self, mock_semgrep_scanner):
        """Test scan_directory handles file processing exceptions."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner to raise exception
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.side_effect = Exception(
            "File processing failed"
        )
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        # Create a temporary directory with files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "test.py").write_text("print('test')")

            # Use a mock to simulate the _detect_language method raising an exception
            # This will be caught at a higher level and create an error result
            with patch.object(
                scanner,
                "_detect_language",
                side_effect=Exception("File processing failed"),
            ):
                results = scanner.scan_directory_sync(
                    directory_path=temp_path,
                    recursive=False,
                    use_llm=False,
                    use_semgrep=False,
                )

                assert len(results) == 1
                result = results[0]
                assert "error" in result.scan_metadata
                assert "File processing failed" in result.scan_metadata["error"]

    def test_scan_code_severity_filtering(self):
        """Test scan_code applies severity filtering correctly."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
        ) as mock_semgrep_scanner:
            # Mock Semgrep scanner with threats of different severities
            mock_semgrep_instance = Mock()
            mock_semgrep_instance.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
            }
            mock_semgrep_instance.is_available.return_value = True
            low_threat = ThreatMatch(
                rule_id="rule_low",
                rule_name="Low Rule",
                description="Low severity",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=10,
            )
            high_threat = ThreatMatch(
                rule_id="rule_high",
                rule_name="High Rule",
                description="High severity",
                category=Category.XSS,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=20,
            )
            mock_semgrep_instance.scan_code = AsyncMock(
                return_value=[low_threat, high_threat]
            )
            mock_semgrep_scanner.return_value = mock_semgrep_instance

            scanner = ScanEngine(
                credential_manager=mock_credential_manager,
                enable_llm_analysis=False,
                enable_semgrep_analysis=True,
                enable_llm_validation=False,  # Disable validation for this test
            )

            # Scan with HIGH severity threshold
            result = scanner.scan_code_sync(
                source_code="test code",
                file_path="test.py",
                use_llm=False,
                use_semgrep=True,
                severity_threshold=Severity.HIGH,
            )

            # Should only have the HIGH severity threat
            assert len(result.semgrep_threats) == 1
            assert result.semgrep_threats[0].severity == Severity.HIGH

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_get_scanner_stats_semgrep_unavailable(self, mock_semgrep_scanner):
        """Test get_scanner_stats when Semgrep is unavailable."""
        mock_threat_engine = Mock()
        mock_threat_engine.get_rule_statistics.return_value = {"total_rules": 10}
        mock_credential_manager = Mock()

        # Mock Semgrep scanner as unavailable
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        stats = scanner.get_scanner_stats()

        assert stats["semgrep_scanner_available"] is False
        assert stats["semgrep_analysis_enabled"] is False

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_engine_initialization_semgrep_unavailable_warning(
        self, mock_semgrep_scanner
    ):
        """Test ScanEngine initialization with Semgrep unavailable generates warning."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner as unavailable
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        with patch("adversary_mcp_server.scanner.scan_engine.logger") as mock_logger:
            scanner = ScanEngine(
                credential_manager=mock_credential_manager,
                enable_llm_analysis=False,
            )

            # Should log warning about Semgrep not being available
            mock_logger.warning.assert_called_with(
                "Semgrep not available - install semgrep for enhanced analysis"
            )
            assert scanner.enable_semgrep_analysis is False

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_file_generic_language_skips_ast(self, mock_semgrep_scanner):
        """Test that scan_file skips AST scanning for generic files."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        # Create a temporary file with generic extension
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".unknown", delete=False
        ) as f:
            f.write("some generic content")
            temp_file = Path(f.name)

        try:
            result = scanner.scan_file_sync(
                file_path=temp_file,
                use_llm=False,
                use_semgrep=False,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata.get("semgrep_scan_success", True) is False
            assert (
                result.scan_metadata.get("semgrep_scan_reason", "unknown")
                == "disabled_by_user"
            )

            # AST scanner should not be called for generic files
            mock_semgrep_scanner.return_value.scan_code.assert_not_called()

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_file_binary_file_handling(self, mock_semgrep_scanner):
        """Test that scan_file handles binary files gracefully."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
        )

        # Create a temporary binary file
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".py", delete=False) as f:
            f.write(b"\x00\x01\x02\x03\xff\xfe")  # More obvious binary content
            temp_file = Path(f.name)

        try:
            # Use patch to mock the file opening to simulate UnicodeDecodeError
            with patch(
                "builtins.open", mock_open(read_data=b"\x00\x01\x02\x03\xff\xfe")
            ) as mock_file:
                # Configure the mock to raise UnicodeDecodeError when reading
                mock_file.return_value.__enter__.return_value.read.side_effect = (
                    UnicodeDecodeError(
                        "utf-8", b"\x00\x01\x02\x03\xff\xfe", 0, 1, "invalid start byte"
                    )
                )

                result = scanner.scan_file_sync(
                    file_path=temp_file,
                    use_llm=False,
                    use_semgrep=False,
                )

                assert isinstance(result, EnhancedScanResult)
                assert result.scan_metadata.get("semgrep_scan_success", True) is False
                assert (
                    result.scan_metadata.get("semgrep_scan_reason", "unknown")
                    == "disabled_by_user"
                )

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_file_rules_disabled(self, mock_semgrep_scanner):
        """Test scan_file with rules disabled."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = False
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
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
                use_llm=False,
                use_semgrep=False,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata.get("semgrep_scan_success", True) is False
            assert (
                result.scan_metadata.get("semgrep_scan_reason", "unknown")
                == "disabled_by_user"
            )

            # AST scanner should not be called
            mock_semgrep_scanner.return_value.scan_code.assert_not_called()

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_file_semgrep_unavailable(self, mock_semgrep_scanner):
        """Test scan_file with Semgrep unavailable."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.return_value = []
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner as unavailable
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_instance.get_status.return_value = {
            "available": False,
            "error": "Semgrep not found",
            "installation_status": "not_installed",
            "installation_guidance": "Run: pip install semgrep",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
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
                use_llm=False,
                use_semgrep=True,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["semgrep_scan_success"] is False
            assert result.scan_metadata["semgrep_scan_reason"] == "not_available"

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @pytest.mark.asyncio
    async def test_scan_file_semgrep_scan_exception(self, mock_semgrep_scanner):
        """Test scan_file handles Semgrep scan exceptions."""
        mock_threat_engine = Mock()
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock AST scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.scan_code.return_value = []
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock Semgrep scanner to raise exception
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_instance.scan_file = AsyncMock(
            side_effect=Exception("Semgrep scan failed")
        )
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
        )

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_file = Path(f.name)

        try:
            result = await scanner.scan_file(
                file_path=temp_file,
                use_llm=False,
                use_semgrep=True,
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["semgrep_scan_success"] is False
            assert result.scan_metadata["semgrep_scan_reason"] == "scan_failed"
            assert "Semgrep scan failed" in result.scan_metadata["semgrep_scan_error"]

        finally:
            temp_file.unlink()


class TestScanEngineValidation:
    """Test ScanEngine with LLM validation integration."""

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMValidator")
    def test_scan_code_with_validation(
        self, mock_llm_validator_class, mock_llm_scanner, mock_semgrep_scanner
    ):
        """Test code scanning with LLM validation enabled."""
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        semgrep_threat = ThreatMatch(
            rule_id="semgrep_rule",
            rule_name="Semgrep Rule",
            description="Semgrep finding",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
            uuid="semgrep-uuid",
        )
        mock_semgrep_instance.scan_code = AsyncMock(return_value=[semgrep_threat])
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = False
        mock_llm_scanner.return_value = mock_llm_instance

        # Mock LLM validator
        from adversary_mcp_server.scanner.llm_validator import ValidationResult

        mock_validator_instance = Mock()
        validation_results = {
            "semgrep-uuid": ValidationResult(
                finding_uuid="semgrep-uuid",
                is_legitimate=True,
                confidence=0.9,
                reasoning="Confirmed vulnerability",
                exploitation_vector="SQL injection",
                exploit_poc=["test exploit"],
            )
        }
        mock_validator_instance.validate_findings.return_value = validation_results
        mock_validator_instance.filter_false_positives.return_value = [semgrep_threat]
        mock_validator_instance.get_validation_stats.return_value = {
            "total_validated": 1,
            "legitimate_findings": 1,
            "false_positives": 0,
        }
        mock_llm_validator_class.return_value = mock_validator_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=True,
        )

        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            use_llm=False,
            use_semgrep=True,
            use_validation=True,
        )

        assert isinstance(result, EnhancedScanResult)
        assert len(result.semgrep_threats) == 1
        assert result.scan_metadata["llm_validation_success"] is True
        assert result.scan_metadata["llm_validation_stats"]["total_validated"] == 1
        assert result.validation_results == validation_results

        mock_validator_instance.validate_findings.assert_called_once()
        mock_validator_instance.filter_false_positives.assert_called()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMValidator")
    def test_scan_code_validation_disabled(
        self, mock_llm_validator_class, mock_llm_scanner, mock_semgrep_scanner
    ):
        """Test scan_code with validation disabled."""
        mock_credential_manager = Mock()
        mock_config = Mock()
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        threat = ThreatMatch(
            rule_id="rule1",
            rule_name="Rule 1",
            description="Test threat",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=10,
        )
        mock_semgrep_instance.scan_code = AsyncMock(return_value=[threat])
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = False
        mock_llm_scanner.return_value = mock_llm_instance

        # Mock LLM validator
        mock_validator_instance = Mock()
        mock_llm_validator_class.return_value = mock_validator_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=True,
        )

        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            use_llm=False,
            use_semgrep=True,
            use_validation=False,  # Disabled by user
        )

        assert len(result.all_threats) == 1
        assert result.scan_metadata["llm_validation_success"] is False
        assert result.scan_metadata["llm_validation_reason"] == "disabled"

        # Validator should not be called
        mock_validator_instance.validate_findings.assert_not_called()
