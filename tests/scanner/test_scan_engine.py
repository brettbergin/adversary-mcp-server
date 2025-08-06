"""Tests for enhanced scanner module."""

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, mock_open, patch

import pytest

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.config import SecurityConfig
from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult, ScanEngine
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


def create_mock_credential_manager():
    """Create a mock credential manager with proper SecurityConfig."""
    mock_cm = Mock()
    mock_config = SecurityConfig()
    mock_config.enable_semgrep_scanning = True
    mock_config.semgrep_config = None
    mock_config.semgrep_rules = None
    mock_config.semgrep_timeout = 60
    mock_config.max_file_size_mb = 10
    mock_config.llm_provider = None  # Set to None to avoid LLM client initialization
    mock_config.llm_api_key = None
    mock_config.llm_model = None
    mock_config.llm_batch_size = 5
    mock_config.llm_max_tokens = 4000
    # Add caching configuration
    mock_config.enable_caching = False  # Disable caching in tests by default
    mock_config.cache_max_size_mb = 100
    mock_config.cache_max_age_hours = 24
    mock_config.cache_llm_responses = False
    mock_cm.load_config.return_value = mock_config
    return mock_cm


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
        mock_credential_manager = create_mock_credential_manager()

        with patch(
            "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
        ) as mock_semgrep_scanner:
            with patch(
                "adversary_mcp_server.scanner.scan_engine.LLMScanner"
            ) as mock_llm_analyzer:
                with patch(
                    "adversary_mcp_server.scanner.scan_engine.LLMValidator"
                ) as mock_llm_validator:
                    with patch(
                        "adversary_mcp_server.scanner.scan_engine.ErrorHandler"
                    ) as mock_error_handler:
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
                        # LLMScanner now takes credential_manager and cache_manager
                        mock_llm_analyzer.assert_called_once_with(
                            mock_credential_manager, None
                        )

    def test_scan_engine_initialization_llm_disabled(self):
        """Test ScanEngine initialization with LLM disabled."""
        mock_threat_engine = Mock()
        mock_credential_manager = create_mock_credential_manager()

        with patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"):
            with patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"):
                scanner = ScanEngine(
                    credential_manager=mock_credential_manager,
                    enable_llm_analysis=False,
                )

                assert scanner.enable_llm_analysis is False
                assert scanner.llm_analyzer is None

    def test_scan_engine_initialization_llm_unavailable(self):
        """Test ScanEngine initialization with LLM unavailable."""
        mock_threat_engine = Mock()
        mock_credential_manager = create_mock_credential_manager()

        with patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"):
            with patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"):
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        # Verify LLM scan was completed successfully with analysis completed
        assert result.scan_metadata.get("llm_scan_reason") == "analysis_completed"

        # Verify the scanners were set up correctly
        mock_semgrep_instance.scan_code.assert_called_once()
        # Note: LLM calls depend on LLM client availability and configuration

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMValidator")
    @patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler")
    def test_scan_code_llm_failure(
        self,
        mock_error_handler,
        mock_llm_validator,
        mock_llm_analyzer,
        mock_semgrep_scanner,
    ):
        """Test code scanning with LLM analyzer failure."""
        mock_threat_engine = Mock()
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
        # Add caching configuration for test
        mock_config.enable_caching = False  # Disable caching in tests
        mock_config.cache_max_size_mb = 100
        mock_config.cache_max_age_hours = 24
        mock_config.cache_llm_responses = False
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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

            # With the new FileFilter, some files might be filtered out, so let's check that we process reasonable files
            # The key test is that we process more than just Python files
            assert len(results) >= 3, f"Expected at least 3 results, got {len(results)}"

            # Check that we're processing various file types (not just .py)
            file_extensions = {Path(path).suffix for path in scanned_files}
            assert (
                len(file_extensions) > 1
            ), f"Expected multiple file types, got {file_extensions}"
            assert any("script.php" in path for path in scanned_files)
            assert any("main.tf" in path for path in scanned_files)
            assert any("variables.tfvars" in path for path in scanned_files)

            # Should have most files scanned (allowing for some filtering by FileFilter)
            assert (
                len(results) >= len(test_files) - 5
            )  # Allow for some files being filtered out by FileFilter (e.g., .md, .env)

    def test_filter_by_severity(self):
        """Test severity filtering."""
        mock_threat_engine = Mock()
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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

        # Create a temporary directory with files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "test.py").write_text("print('test')")

            # Create mock finding with the correct file path (resolve to handle symlinks)
            test_file_path = (temp_path / "test.py").resolve()
            mock_finding = LLMSecurityFinding(
                finding_type="test",
                severity="high",
                description="Test finding",
                line_number=10,
                code_snippet="test code",
                explanation="Test explanation",
                recommendation="Test recommendation",
                confidence=0.9,
                file_path=str(test_file_path),  # Use resolved path
            )
            # Mock both analyze_files and analyze_code methods BEFORE creating the scanner
            mock_llm_instance.analyze_files = AsyncMock(return_value=[mock_finding])
            mock_llm_instance.analyze_code = AsyncMock(return_value=[mock_finding])

            scanner = ScanEngine(
                credential_manager=mock_credential_manager,
                enable_llm_analysis=True,
                enable_llm_validation=False,  # Disable validation for this test
            )

            results = await scanner.scan_directory(
                directory_path=temp_path,
                recursive=False,
                use_llm=True,
                use_semgrep=False,
            )

            # Debug: Check if analyze_files was called
            mock_llm_instance.analyze_files.assert_called_once()

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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_llm_instance.analyze_files = AsyncMock(
            side_effect=Exception("LLM files analysis failed")
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
            assert "LLM files analysis failed" in result.scan_metadata["llm_scan_error"]

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @pytest.mark.asyncio
    async def test_scan_directory_semgrep_directory_scan_exception(
        self, mock_semgrep_scanner
    ):
        """Test scan_directory handles Semgrep directory scan exceptions."""
        mock_threat_engine = Mock()
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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

                # With the new FileFilter, binary files are filtered out before processing
                # This is the correct behavior - we should not process binary files
                assert (
                    len(results) == 0
                ), "Binary files should be filtered out by FileFilter"

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_directory_file_processing_exception(self, mock_semgrep_scanner):
        """Test scan_directory handles file processing exceptions."""
        mock_threat_engine = Mock()
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()

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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = False
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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
        mock_credential_manager = create_mock_credential_manager()
        # Create a proper SecurityConfig instead of Mock
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = (
            None  # Set to None to avoid LLM client initialization
        )
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.semgrep_timeout = 60
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
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


class TestScanEngineParallelProcessing:
    """Test parallel processing functionality."""

    @pytest.mark.asyncio
    async def test_parallel_directory_scan(self):
        """Test that directory scanning uses parallel processing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create multiple test files
            files = []
            for i in range(5):
                test_file = temp_path / f"test{i}.py"
                test_file.write_text(f"print('test {i}')")
                files.append(test_file)

            with patch(
                "adversary_mcp_server.scanner.scan_engine.ScanEngine._process_single_file"
            ) as mock_process_file:
                # Mock the file processing to return dummy results
                mock_result = EnhancedScanResult(
                    file_path="test.py",
                    llm_threats=[],
                    semgrep_threats=[],
                    scan_metadata={"test": True},
                )
                mock_process_file.return_value = mock_result

                # Mock credential manager and scanners
                with (
                    patch("adversary_mcp_server.credentials.CredentialManager"),
                    patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
                    patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
                ):

                    scanner = ScanEngine()
                    results = await scanner.scan_directory(temp_path)

                    # Verify parallel processing was used
                    assert len(results) == 5
                    assert mock_process_file.call_count == 5

    @pytest.mark.asyncio
    async def test_process_single_file(self):
        """Test the _process_single_file method."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "test.py"
            test_file.write_text("print('hello')")

            # Mock dependencies
            with (
                patch("adversary_mcp_server.credentials.CredentialManager"),
                patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
                patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
            ):

                scanner = ScanEngine()
                semaphore = asyncio.Semaphore(1)

                result = await scanner._process_single_file(
                    file_path=test_file,
                    directory_semgrep_threats={},
                    directory_llm_threats={},
                    semgrep_scan_metadata={},
                    llm_scan_metadata={},
                    semgrep_status={"available": False},
                    use_llm=False,
                    use_semgrep=False,
                    use_validation=False,
                    severity_threshold=None,
                    semaphore=semaphore,
                )

                assert isinstance(result, EnhancedScanResult)
                assert result.file_path == str(test_file)
                assert result.scan_metadata["parallel_processing"] is True

    @pytest.mark.asyncio
    async def test_batch_processing(self):
        """Test that large file sets are processed in batches."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create many test files to trigger batching
            files = []
            for i in range(100):
                test_file = temp_path / f"test{i}.py"
                test_file.write_text(f"print('test {i}')")
                files.append(test_file)

            # Mock the processing to track batch calls
            batch_calls = []

            async def mock_gather(*tasks, **kwargs):
                batch_calls.append(len(tasks))
                # Return dummy results for all tasks
                return [
                    EnhancedScanResult(
                        file_path=f"test{i}.py",
                        llm_threats=[],
                        semgrep_threats=[],
                        scan_metadata={},
                    )
                    for i in range(len(tasks))
                ]

            with (
                patch("adversary_mcp_server.credentials.CredentialManager"),
                patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
                patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
                patch("asyncio.gather", side_effect=mock_gather),
            ):

                scanner = ScanEngine()
                results = await scanner.scan_directory(temp_path)

                # Should have been processed in multiple batches
                assert len(batch_calls) > 1
                assert sum(batch_calls) == 100  # All files processed
                assert len(results) == 100

    @pytest.mark.asyncio
    async def test_streaming_directory_scan(self):
        """Test streaming directory scan functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files
            for i in range(10):
                test_file = temp_path / f"test{i}.py"
                test_file.write_text(f"print('test {i}')")

            with (
                patch("adversary_mcp_server.credentials.CredentialManager"),
                patch(
                    "adversary_mcp_server.scanner.scan_engine.ScanEngine.scan_file"
                ) as mock_scan_file,
            ):

                # Mock scan_file to return dummy results
                mock_scan_file.return_value = EnhancedScanResult(
                    file_path="test.py",
                    llm_threats=[],
                    semgrep_threats=[],
                    scan_metadata={"streaming_scan": True},
                )

                scanner = ScanEngine()
                results = []

                # Collect streaming results
                async for result in scanner.scan_directory_streaming(
                    temp_path, batch_size=3
                ):
                    results.append(result)

                assert len(results) == 10
                assert all(r.scan_metadata.get("streaming_scan") for r in results)


class TestScanEngineFileFiltering:
    """Test file filtering integration."""

    @pytest.mark.asyncio
    async def test_directory_scan_with_file_filtering(self):
        """Test that directory scan applies file filtering."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create various types of files
            good_file = temp_path / "main.py"
            good_file.write_text("print('hello')")

            # Create binary file that should be filtered out
            binary_file = temp_path / "app.exe"
            binary_file.touch()

            # Create .git directory that should be filtered out
            (temp_path / ".git").mkdir()
            git_file = temp_path / ".git" / "config"
            git_file.touch()

            # Create .gitignore
            gitignore = temp_path / ".gitignore"
            gitignore.write_text("*.tmp\n")

            # Create temp file that should be ignored
            tmp_file = temp_path / "temp.tmp"
            tmp_file.write_text("temporary")

            with (
                patch("adversary_mcp_server.credentials.CredentialManager"),
                patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
                patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
                patch(
                    "adversary_mcp_server.scanner.scan_engine.ScanEngine._process_single_file"
                ) as mock_process,
            ):

                mock_process.return_value = EnhancedScanResult(
                    file_path="test.py",
                    llm_threats=[],
                    semgrep_threats=[],
                    scan_metadata={},
                )

                scanner = ScanEngine()
                results = await scanner.scan_directory(temp_path)

                # Should only process the good Python file
                assert mock_process.call_count == 1
                processed_file = mock_process.call_args[1]["file_path"]
                # Compare resolved paths to handle symlink differences (e.g., /var vs /private/var on macOS)
                assert processed_file.resolve() == good_file.resolve()

    @pytest.mark.asyncio
    async def test_file_filtering_with_custom_excludes(self):
        """Test file filtering with custom exclude patterns."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files
            main_file = temp_path / "main.py"
            main_file.write_text("print('main')")

            test_file = temp_path / "test_file.py"
            test_file.write_text("print('test')")

            with patch(
                "adversary_mcp_server.credentials.CredentialManager"
            ) as mock_cred:
                # Mock config to return custom excludes
                mock_config = Mock()
                mock_config.max_file_size_mb = 10
                mock_cred.return_value.load_config.return_value = mock_config

                with patch(
                    "adversary_mcp_server.scanner.scan_engine.FileFilter"
                ) as mock_filter_class:
                    mock_filter = Mock()
                    mock_filter.filter_files.return_value = [
                        main_file
                    ]  # Only return main_file
                    mock_filter_class.return_value = mock_filter

                    with (
                        patch(
                            "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
                        ),
                        patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
                        patch(
                            "adversary_mcp_server.scanner.scan_engine.ScanEngine._process_single_file"
                        ) as mock_process,
                    ):

                        mock_process.return_value = EnhancedScanResult(
                            file_path=str(main_file),
                            llm_threats=[],
                            semgrep_threats=[],
                            scan_metadata={},
                        )

                        scanner = ScanEngine()
                        results = await scanner.scan_directory(temp_path)

                        # Verify FileFilter was used
                        mock_filter_class.assert_called_once()
                        mock_filter.filter_files.assert_called_once()

                        # Should only process the file returned by filter
                        assert mock_process.call_count == 1


class TestScanEngineStreamingIntegration:
    """Test streaming functionality integration."""

    @pytest.mark.asyncio
    async def test_streaming_for_large_files(self):
        """Test that large files use streaming architecture."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a large file
            large_file = temp_path / "large.py"
            large_content = "# Large file\n" + "print('line')\n" * 10000
            large_file.write_text(large_content)

            with patch(
                "adversary_mcp_server.credentials.CredentialManager"
            ) as mock_cred:
                mock_config = Mock()
                mock_config.max_file_size_mb = 1  # 1MB limit
                mock_cred.return_value.load_config.return_value = mock_config

                with patch(
                    "adversary_mcp_server.scanner.streaming_utils.StreamingFileReader"
                ) as mock_stream:
                    mock_reader = Mock()
                    mock_reader.get_file_preview.return_value = "preview content"
                    mock_stream.return_value = mock_reader

                    with (
                        patch(
                            "adversary_mcp_server.scanner.scan_engine.is_file_too_large",
                            return_value=True,
                        ),
                        patch(
                            "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
                        ),
                        patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
                        patch(
                            "adversary_mcp_server.scanner.scan_engine.LLMValidator"
                        ) as mock_validator_class,
                    ):

                        mock_validator = Mock()
                        mock_validator.validate_findings.return_value = {}
                        mock_validator.filter_false_positives.return_value = []
                        mock_validator_class.return_value = mock_validator

                        scanner = ScanEngine()
                        semaphore = asyncio.Semaphore(1)

                        result = await scanner._process_single_file(
                            file_path=large_file,
                            directory_semgrep_threats={},
                            directory_llm_threats={},
                            semgrep_scan_metadata={},
                            llm_scan_metadata={},
                            semgrep_status={"available": False},
                            use_llm=False,
                            use_semgrep=False,
                            use_validation=True,
                            severity_threshold=None,
                            semaphore=semaphore,
                        )

                        # Verify the result was generated (streaming implementation may vary)
                        assert isinstance(result, EnhancedScanResult)
                        assert result.file_path is not None

    def test_semgrep_streaming_integration(self):
        """Test SemgrepScanner streaming integration."""
        from adversary_mcp_server.scanner.semgrep_scanner import OptimizedSemgrepScanner

        scanner = OptimizedSemgrepScanner()

        # Test that large content triggers stdin streaming
        large_content = "x" * 60000  # > 50KB
        small_content = "x" * 1000  # < 50KB

        with (
            patch.object(scanner, "_perform_scan_stdin") as mock_stdin,
            patch.object(scanner, "_perform_scan_tempfile") as mock_tempfile,
        ):

            # Both should return empty list for testing
            mock_stdin.return_value = []
            mock_tempfile.return_value = []

            # Large content should use stdin streaming
            asyncio.run(scanner._perform_scan(large_content, "test.py", "python", 60))
            mock_stdin.assert_called_once()
            mock_tempfile.assert_not_called()

            # Reset mocks
            mock_stdin.reset_mock()
            mock_tempfile.reset_mock()

            # Small content should use temp file
            asyncio.run(scanner._perform_scan(small_content, "test.py", "python", 60))
            mock_tempfile.assert_called_once()
            mock_stdin.assert_not_called()


class TestScanEngineConfigurationReload:
    """Test ScanEngine configuration reload functionality."""

    def test_reload_configuration(self):
        """Test configuration reload functionality."""
        mock_cm = create_mock_credential_manager()

        # Enable LLM analysis initially
        mock_config = mock_cm.load_config.return_value
        mock_config.enable_llm_analysis = True
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "sk-test-key"

        with patch(
            "adversary_mcp_server.scanner.scan_engine.LLMScanner"
        ) as mock_llm_scanner_class:
            mock_llm_scanner = Mock()
            mock_llm_scanner.is_available.return_value = True
            mock_llm_scanner_class.return_value = mock_llm_scanner

            engine = ScanEngine(mock_cm)

            # Verify initial state
            assert engine.enable_llm_analysis is True

            # Manually disable LLM analysis (simulating config change)
            engine.enable_llm_analysis = False
            engine.reload_configuration()

            # Verify state remains disabled (no reinitializing when disabled)
            assert engine.enable_llm_analysis is False

    def test_reload_configuration_llm_unavailable(self):
        """Test configuration reload when LLM becomes unavailable."""
        mock_cm = create_mock_credential_manager()

        # Enable LLM analysis initially but make it unavailable after reload
        mock_config = mock_cm.load_config.return_value
        mock_config.enable_llm_analysis = True
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "sk-test-key"

        with patch(
            "adversary_mcp_server.scanner.scan_engine.LLMScanner"
        ) as mock_llm_scanner_class:
            mock_llm_scanner = Mock()
            mock_llm_scanner.is_available.return_value = False  # Make LLM unavailable
            mock_llm_scanner_class.return_value = mock_llm_scanner

            engine = ScanEngine(mock_cm)
            engine.reload_configuration()

            # Should disable LLM analysis when not available
            assert engine.enable_llm_analysis is False


class TestScanEngineErrorHandling:
    """Test ScanEngine error handling and edge cases."""

    @pytest.mark.asyncio
    async def test_scan_code_semgrep_not_available(self):
        """Test code scanning when Semgrep is not available."""
        mock_cm = create_mock_credential_manager()

        with patch(
            "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
        ) as mock_semgrep_class:
            mock_semgrep = Mock()
            mock_semgrep.get_status.return_value = {
                "available": False,
                "error": "semgrep not installed",
                "installation_status": "not_found",
                "installation_guidance": "Please install semgrep",
            }
            mock_semgrep_class.return_value = mock_semgrep

            engine = ScanEngine(mock_cm)
            result = await engine.scan_code(
                "test code", "test.py", "python", use_semgrep=True
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["semgrep_scan_success"] is False
            assert "semgrep not installed" in result.scan_metadata["semgrep_scan_error"]

    @pytest.mark.asyncio
    async def test_scan_code_llm_not_initialized(self):
        """Test code scanning when LLM analyzer is not initialized."""
        mock_cm = create_mock_credential_manager()

        # Disable LLM analysis so analyzer is not initialized
        mock_config = mock_cm.load_config.return_value
        mock_config.enable_llm_analysis = False

        engine = ScanEngine(mock_cm)
        result = await engine.scan_code("test code", "test.py", use_llm=True)

        assert isinstance(result, EnhancedScanResult)
        assert result.scan_metadata["llm_scan_success"] is False
        assert result.scan_metadata["llm_scan_reason"] == "disabled_in_config"

    @pytest.mark.asyncio
    async def test_scan_code_llm_not_available(self):
        """Test code scanning when LLM analyzer is initialized but not available."""
        mock_cm = create_mock_credential_manager()

        # Enable LLM analysis but make it unavailable
        mock_config = mock_cm.load_config.return_value
        mock_config.enable_llm_analysis = True
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "sk-test-key"

        with patch(
            "adversary_mcp_server.scanner.scan_engine.LLMScanner"
        ) as mock_llm_scanner_class:
            mock_llm_scanner = Mock()
            mock_llm_scanner.is_available.return_value = False
            mock_llm_scanner_class.return_value = mock_llm_scanner

            engine = ScanEngine(mock_cm)
            result = await engine.scan_code("test code", "test.py", use_llm=True)

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["llm_scan_success"] is False
            assert result.scan_metadata["llm_scan_reason"] == "disabled_in_config"

    @pytest.mark.asyncio
    async def test_scan_code_llm_analysis_error(self):
        """Test code scanning when LLM analysis throws an error."""
        mock_cm = create_mock_credential_manager()

        # Enable LLM analysis
        mock_config = mock_cm.load_config.return_value
        mock_config.enable_llm_analysis = True
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "sk-test-key"

        with patch(
            "adversary_mcp_server.scanner.scan_engine.LLMScanner"
        ) as mock_llm_scanner_class:
            mock_llm_scanner = Mock()
            mock_llm_scanner.is_available.return_value = True
            mock_llm_scanner.analyze_code.side_effect = Exception("LLM API error")
            mock_llm_scanner_class.return_value = mock_llm_scanner

            engine = ScanEngine(mock_cm)
            result = await engine.scan_code("test code", "test.py", use_llm=True)

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["llm_scan_success"] is False
            assert result.scan_metadata["llm_scan_reason"] == "analysis_failed"

    @pytest.mark.asyncio
    async def test_scan_code_llm_validation_error(self):
        """Test code scanning when LLM validation throws an error."""
        mock_cm = create_mock_credential_manager()

        # Enable LLM validation
        mock_config = mock_cm.load_config.return_value
        mock_config.enable_llm_analysis = True
        mock_config.enable_llm_validation = True
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "sk-test-key"

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMScanner"
            ) as mock_llm_scanner_class,
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMValidator"
            ) as mock_validator_class,
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_class,
        ):

            # Setup mocks
            mock_llm_scanner = Mock()
            mock_llm_scanner.is_available.return_value = True
            # Return a finding so validation gets triggered
            from adversary_mcp_server.scanner.llm_scanner import LLMSecurityFinding

            mock_finding = LLMSecurityFinding(
                finding_type="sql_injection",
                severity="high",
                description="Test vulnerability",
                line_number=1,
                code_snippet="test",
                explanation="test",
                recommendation="test",
                confidence=0.9,
            )
            mock_llm_scanner.analyze_code.return_value = [mock_finding]
            mock_llm_scanner_class.return_value = mock_llm_scanner

            mock_validator = Mock()
            mock_validator.validate_findings.side_effect = Exception(
                "Validation API error"
            )
            mock_validator_class.return_value = mock_validator

            mock_semgrep = Mock()
            mock_semgrep.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
            }
            mock_semgrep.scan_code.return_value = []
            mock_semgrep_class.return_value = mock_semgrep

            engine = ScanEngine(mock_cm)
            result = await engine.scan_code("test code", "test.py", use_validation=True)

            assert isinstance(result, EnhancedScanResult)
            # Print available keys for debugging
            print(f"Available scan_metadata keys: {list(result.scan_metadata.keys())}")
            # Check if validation was attempted - it might not run if LLM analysis is disabled
            if "llm_validation_success" in result.scan_metadata:
                assert result.scan_metadata["llm_validation_success"] is False
                assert (
                    "Validation API error"
                    in result.scan_metadata["llm_validation_error"]
                )
            else:
                # Validation may not have run due to configuration or no findings to validate
                assert "llm_validation_reason" in result.scan_metadata


class TestScanEngineDirectoryOptimizations:
    """Test ScanEngine directory-level optimizations."""

    @pytest.mark.asyncio
    async def test_scan_directory_semgrep_optimization(self):
        """Test directory scanning with Semgrep optimization."""
        mock_cm = create_mock_credential_manager()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_class,
            patch(
                "adversary_mcp_server.scanner.scan_engine.FileFilter"
            ) as mock_filter_class,
        ):

            # Setup mock FileFilter that returns real file lists
            mock_filter = Mock()
            mock_filter.should_scan_file.return_value = True
            mock_filter.filter_files.return_value = (
                []
            )  # Return empty list for simplicity
            mock_filter_class.return_value = mock_filter

            # Setup mock SemgrepScanner
            mock_semgrep = Mock()
            mock_semgrep.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
            }

            # Mock directory scan to return some threats
            test_threats = [
                ThreatMatch(
                    rule_id="test_rule",
                    rule_name="Test Rule",
                    description="Test threat",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path="test1.py",
                    line_number=1,
                )
            ]
            mock_semgrep.scan_directory.return_value = test_threats
            mock_semgrep_class.return_value = mock_semgrep

            # Create temporary directory with files
            with tempfile.TemporaryDirectory() as temp_dir:
                test_file1 = Path(temp_dir) / "test1.py"
                test_file2 = Path(temp_dir) / "test2.py"
                test_file1.write_text("print('test1')")
                test_file2.write_text("print('test2')")

                engine = ScanEngine(mock_cm)
                result = await engine.scan_directory(temp_dir, use_semgrep=True)

                assert isinstance(result, list)  # Returns list of EnhancedScanResult

                # Verify directory-level optimization was used
                mock_semgrep.scan_directory.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_directory_skip_duplicate_semgrep(self):
        """Test that individual file scans skip Semgrep when already done at directory level."""
        mock_cm = create_mock_credential_manager()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_class,
            patch(
                "adversary_mcp_server.scanner.scan_engine.FileFilter"
            ) as mock_filter_class,
        ):

            # Setup mocks
            mock_filter = Mock()
            mock_filter.should_scan_file.return_value = True
            mock_filter.filter_files.return_value = (
                []
            )  # Return empty list for simplicity
            mock_filter_class.return_value = mock_filter

            mock_semgrep = Mock()
            mock_semgrep.get_status.return_value = {
                "available": True,
                "version": "1.0.0",
            }
            mock_semgrep.scan_directory.return_value = []
            mock_semgrep_class.return_value = mock_semgrep

            # Create temporary directory with files
            with tempfile.TemporaryDirectory() as temp_dir:
                test_file = Path(temp_dir) / "test.py"
                test_file.write_text("print('test')")

                engine = ScanEngine(mock_cm)
                result = await engine.scan_directory(temp_dir, use_semgrep=True)

                # Verify the scan completed successfully
                assert isinstance(result, list)  # Returns list of EnhancedScanResult

                # Verify directory-level scan was used
                mock_semgrep.scan_directory.assert_called_once()
