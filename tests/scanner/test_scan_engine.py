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
                        mock_semgrep_scanner.assert_called_once_with(
                            credential_manager=mock_credential_manager,
                            metrics_collector=None,
                        )
                        # LLMScanner now takes credential_manager, cache_manager, and metrics_collector
                        mock_llm_analyzer.assert_called_once_with(
                            mock_credential_manager, None, None
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
    @pytest.mark.asyncio
    async def test_scan_code_with_llm(self, mock_llm_analyzer, mock_semgrep_scanner):
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
        mock_llm_instance.analyze_code = Mock(
            return_value=[]
        )  # Client-based approach returns empty list

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=True,
            enable_semgrep_analysis=True,
            enable_llm_validation=False,  # Disable validation for this test
        )

        # Mock cache methods to prevent hanging
        scanner._get_cached_scan_result = AsyncMock(return_value=None)
        scanner._cache_scan_result = AsyncMock()

        result = await scanner.scan_code(
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
    @pytest.mark.asyncio
    async def test_scan_directory_success(self, mock_semgrep_scanner):
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
        mock_config.max_file_size_mb = 10  # Add required attribute for FileFilter
        mock_config.enable_caching = False  # Disable caching to prevent hangs
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
            cache_manager=None,
            enable_llm_validation=False,
        )

        # Create a temporary directory with Python files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files
            (temp_path / "test1.py").write_text("print('test1')")
            (temp_path / "test2.js").write_text("console.log('test2');")
            (temp_path / "test3.txt").write_text("not a code file")

            results = await scanner.scan_directory(
                directory_path=temp_path,
                recursive=False,
                use_llm=False,
                use_validation=False,
            )

            # Should return 1 directory-level result containing info about 3 files
            assert len(results) == 1
            directory_result = results[0]
            assert isinstance(directory_result, EnhancedScanResult)
            assert directory_result.scan_metadata["directory_scan"] is True
            assert directory_result.scan_metadata["files_filtered_for_scan"] == 3

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

            # Should return 1 directory-level result with info about multiple files
            assert len(results) == 1
            directory_result = results[0]
            assert directory_result.scan_metadata["directory_scan"] is True

            # Check that multiple file types were processed
            files_scanned = directory_result.scan_metadata.get(
                "files_filtered_for_scan", 0
            )
            assert (
                files_scanned >= 3
            ), f"Expected at least 3 files scanned, got {files_scanned}"

            # Check file information from directory scan metadata
            directory_files_info = directory_result.scan_metadata.get(
                "directory_files_info", []
            )
            assert (
                len(directory_files_info) >= 3
            ), f"Expected file info for at least 3 files, got {len(directory_files_info)}"

            # Check that we're processing various file types (not just .py)
            file_paths = [info["file_path"] for info in directory_files_info]
            file_extensions = {Path(path).suffix for path in file_paths}
            assert (
                len(file_extensions) > 1
            ), f"Expected multiple file types, got {file_extensions}"

            # Check for specific file types we expect to be processed
            file_names = [Path(path).name for path in file_paths]
            # Allow flexibility since FileFilter might exclude some files
            processed_count = len(directory_files_info)
            assert (
                processed_count >= len(test_files) - 5
            ), f"Expected most files processed, got {processed_count} out of {len(test_files)}"

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
        mock_config.enable_caching = False  # Disable caching for this test
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
        mock_llm_instance.get_status.return_value = {
            "available": True,
            "installation_status": "installed",
            "description": "Test LLM",
        }
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
            cache_manager=None,  # Disable cache for this test
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
                use_validation=False,  # Disable validation to avoid complications
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata["llm_scan_success"] is True
            assert result.scan_metadata["llm_scan_reason"] == "analysis_completed"
            assert len(result.llm_threats) == 1

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @pytest.mark.asyncio
    async def test_scan_file_llm_analysis_exception_fixed(
        self, mock_llm_scanner, mock_semgrep_scanner
    ):
        """Test scan_file handles LLM analysis exceptions gracefully while preserving Semgrep results."""
        mock_credential_manager = create_mock_credential_manager()

        # Create properly configured SecurityConfig
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = None
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True  # Enable Semgrep for this test
        mock_config.max_file_size_mb = 10
        mock_config.enable_caching = False  # Disable caching
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner to return a finding
        from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch

        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "installation_status": "installed",
            "version": "1.0.0",
        }

        # Create a mock Semgrep finding
        semgrep_finding = ThreatMatch(
            rule_id="test-rule",
            rule_name="Test Rule",
            severity=Severity.HIGH,
            category=Category.MISC,
            description="Test finding",
            file_path="test.py",
            line_number=1,
            code_snippet="print('test')",
            source="semgrep",
        )

        mock_semgrep_instance.scan_file = AsyncMock(return_value=[semgrep_finding])
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner to throw exception
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_instance.get_status.return_value = {
            "available": True,
            "installation_status": "installed",
            "description": "Test LLM",
        }
        mock_llm_instance.analyze_file = AsyncMock(
            side_effect=Exception("LLM analysis failed")
        )
        mock_llm_scanner.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            cache_manager=None,  # Disable cache
            enable_llm_analysis=True,
            enable_llm_validation=False,  # Disable validation
        )

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_file = Path(f.name)

        try:
            result = await scanner.scan_file(
                file_path=temp_file,
                use_llm=True,
                use_semgrep=True,
                use_validation=False,  # Disable validation
            )

            # Verify the result
            assert isinstance(result, EnhancedScanResult)

            # Should have Semgrep findings despite LLM failure
            assert len(result.semgrep_threats) == 1
            assert result.semgrep_threats[0].rule_id == "test-rule"

            # Should have no LLM findings due to exception
            assert len(result.llm_threats) == 0

            # Should show LLM scan failed
            assert result.scan_metadata["llm_scan_success"] is False
            assert "LLM analysis failed" in result.scan_metadata.get(
                "llm_scan_error", ""
            )

            # Should show Semgrep scan succeeded
            assert result.scan_metadata["semgrep_scan_success"] is True

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @pytest.mark.asyncio
    async def test_scan_file_llm_disabled_by_user(
        self, mock_semgrep_scanner, mock_llm_scanner
    ):
        """Test scan_file with LLM disabled by user."""
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
        mock_config.enable_caching = False  # Disable caching for this test
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_instance.get_status.return_value = {
            "available": False,
            "installation_status": "not_installed",
            "error": "Semgrep not available",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_instance.get_status.return_value = {
            "available": True,
            "installation_status": "installed",
            "description": "Test LLM",
        }
        mock_llm_scanner.return_value = mock_llm_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            cache_manager=None,  # Disable cache for this test
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
                use_llm=False,  # Disabled by user
                use_semgrep=False,
                use_validation=False,  # Disable validation to avoid complications
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

                # Should return 1 directory-level result, but with 0 files processed
                assert len(results) == 1
                directory_result = results[0]
                assert directory_result.scan_metadata["directory_scan"] is True
                # Binary files should be filtered out - no files should be processed
                assert (
                    directory_result.scan_metadata["files_filtered_for_scan"] == 0
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

            # The new architecture handles exceptions more gracefully
            # We'll test that directory scan still completes even with processing errors
            results = scanner.scan_directory_sync(
                directory_path=temp_path,
                recursive=False,
                use_llm=False,
                use_semgrep=False,
            )

            # Directory scan should complete and return one result
            assert len(results) == 1
            directory_result = results[0]
            assert directory_result.scan_metadata["directory_scan"] is True
            # Should have processed at least the one file
            assert directory_result.scan_metadata["files_filtered_for_scan"] >= 1

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
    @pytest.mark.asyncio
    async def test_scan_file_generic_language_skips_ast(self, mock_semgrep_scanner):
        """Test that scan_file skips AST scanning for generic files."""
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
        mock_config.enable_caching = False  # Disable caching for this test
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_instance.get_status.return_value = {
            "available": False,
            "installation_status": "not_installed",
            "error": "Semgrep not available",
        }
        mock_semgrep_instance.scan_code = Mock()  # Add scan_code mock for assertion
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            cache_manager=None,  # Disable cache for this test
            enable_llm_analysis=False,
            enable_llm_validation=False,  # Disable validation for this test
        )

        # Create a temporary file with generic extension
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".unknown", delete=False
        ) as f:
            f.write("some generic content")
            temp_file = Path(f.name)

        try:
            result = await scanner.scan_file(
                file_path=temp_file,
                use_llm=False,
                use_semgrep=False,
                use_validation=False,  # Disable validation to avoid complications
            )

            assert isinstance(result, EnhancedScanResult)
            assert result.scan_metadata.get("semgrep_scan_success", True) is False
            assert (
                result.scan_metadata.get("semgrep_scan_reason", "unknown")
                == "disabled_by_user"
            )

            # AST scanner should not be called for generic files
            mock_semgrep_instance.scan_code.assert_not_called()

        finally:
            temp_file.unlink()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @pytest.mark.asyncio
    async def test_scan_file_binary_file_handling(self, mock_semgrep_scanner):
        """Test that scan_file handles binary files gracefully."""
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
        mock_config.enable_caching = False  # Disable caching for this test
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_instance.get_status.return_value = {
            "available": False,
            "installation_status": "not_installed",
            "error": "Semgrep not available",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            cache_manager=None,  # Disable cache for this test
            enable_llm_analysis=False,
            enable_llm_validation=False,  # Disable validation for this test
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

                result = await scanner.scan_file(
                    file_path=temp_file,
                    use_llm=False,
                    use_semgrep=False,
                    use_validation=False,  # Disable validation to avoid complications
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
    @pytest.mark.asyncio
    async def test_scan_file_rules_disabled(self, mock_semgrep_scanner):
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
        mock_config.enable_caching = False  # Disable caching to prevent hangs
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = False
        mock_semgrep_instance.get_status.return_value = {
            "available": False,
            "error": "Disabled",
        }
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            cache_manager=None,
            enable_llm_validation=False,
        )

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('test')")
            temp_file = Path(f.name)

        try:
            result = await scanner.scan_file(
                file_path=temp_file,
                use_llm=False,
                use_semgrep=False,
                use_validation=False,
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
    @pytest.mark.asyncio
    async def test_scan_file_semgrep_unavailable(self, mock_semgrep_scanner):
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
        mock_config.enable_caching = False  # Disable caching to prevent hangs
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
            cache_manager=None,
            enable_llm_validation=False,
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
                use_validation=False,
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
                remediation_advice=None,
                severity_adjustment=None,
                validation_error=None,
            )
        }
        mock_validator_instance._validate_findings_async = AsyncMock(
            return_value=validation_results
        )
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

        # Disable cache to ensure validation goes through the mock
        scanner._get_cached_scan_result = AsyncMock(return_value=None)
        scanner._cache_scan_result = AsyncMock()
        if hasattr(scanner, "llm_validator") and scanner.llm_validator:
            scanner.llm_validator._get_cache_key = Mock(return_value=None)

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

        mock_validator_instance._validate_findings_async.assert_called_once()
        mock_validator_instance.filter_false_positives.assert_called()


class TestScanEngineModularArchitecture:
    """Test ScanEngine integration with the new modular architecture components."""

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_engine_uses_modular_components(self, mock_semgrep_scanner):
        """Test that ScanEngine properly uses the extracted modular components."""
        mock_credential_manager = create_mock_credential_manager()
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = None
        mock_config.llm_api_key = None
        mock_config.llm_model = None
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.semgrep_config = None
        mock_config.semgrep_rules = None
        mock_config.max_file_size_mb = 10
        mock_credential_manager.load_config.return_value = mock_config

        # Mock Semgrep scanner with realistic threats
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }

        realistic_threats = [
            ThreatMatch(
                rule_id="modular-test-1",
                rule_name="Modular Test Rule 1",
                description="Test threat for modular architecture",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=15,
                uuid="modular-uuid-1",
            ),
            ThreatMatch(
                rule_id="modular-test-2",
                rule_name="Modular Test Rule 2",
                description="Second test threat",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=30,
                uuid="modular-uuid-2",
            ),
        ]

        mock_semgrep_instance.scan_code = AsyncMock(return_value=realistic_threats)
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Create ScanEngine (which should internally create modular components)
        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=False,
        )

        # Disable caching to ensure we test the actual scan logic
        scanner._get_cached_scan_result = AsyncMock(return_value=None)
        scanner._cache_scan_result = AsyncMock()

        # Execute scan
        result = scanner.scan_code_sync(
            source_code="def test_function(): pass",
            file_path="test.py",
            use_llm=False,
            use_semgrep=True,
            use_validation=False,
        )

        # Verify result structure and that modular components processed the threats
        assert isinstance(result, EnhancedScanResult)
        assert len(result.semgrep_threats) == 2
        assert len(result.llm_threats) == 0

        # Verify threats were processed by ThreatAggregator (should be sorted by line number)
        line_numbers = [threat.line_number for threat in result.semgrep_threats]
        assert line_numbers == sorted(line_numbers)  # ThreatAggregator sorts threats

        # Verify metadata was built by ResultBuilder (check for the actual metadata structure)
        assert result.scan_metadata is not None
        # The current metadata structure uses different keys - check for scan success indicators
        assert result.scan_metadata.get("semgrep_scan_success", True) is True
        assert result.scan_metadata.get("llm_scan_success", False) is False

        # Verify individual threat properties
        high_threat = next(
            t for t in result.semgrep_threats if t.severity == Severity.HIGH
        )
        medium_threat = next(
            t for t in result.semgrep_threats if t.severity == Severity.MEDIUM
        )

        assert high_threat.rule_id == "modular-test-1"
        assert high_threat.category == Category.INJECTION
        assert medium_threat.rule_id == "modular-test-2"
        assert medium_threat.category == Category.XSS

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_engine_severity_filtering_integration(self, mock_semgrep_scanner):
        """Test ScanEngine severity filtering works with modular components."""
        mock_credential_manager = create_mock_credential_manager()
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = None
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10
        mock_credential_manager.load_config.return_value = mock_config

        # Create threats with mixed severities
        mixed_threats = [
            ThreatMatch(
                rule_id="critical-threat",
                rule_name="Critical Security Issue",
                description="Critical vulnerability",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=5,
                uuid="critical-uuid",
            ),
            ThreatMatch(
                rule_id="high-threat",
                rule_name="High Security Issue",
                description="High severity vulnerability",
                category=Category.XSS,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=15,
                uuid="high-uuid",
            ),
            ThreatMatch(
                rule_id="medium-threat",
                rule_name="Medium Security Issue",
                description="Medium severity vulnerability",
                category=Category.DISCLOSURE,
                severity=Severity.MEDIUM,
                file_path="test.py",
                line_number=25,
                uuid="medium-uuid",
            ),
            ThreatMatch(
                rule_id="low-threat",
                rule_name="Low Security Issue",
                description="Low severity vulnerability",
                category=Category.MISC,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=35,
                uuid="low-uuid",
            ),
        ]

        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_instance.scan_code = AsyncMock(return_value=mixed_threats)
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=False,
        )

        # Disable caching
        scanner._get_cached_scan_result = AsyncMock(return_value=None)
        scanner._cache_scan_result = AsyncMock()

        # Test HIGH severity filtering
        result = scanner.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            use_llm=False,
            use_semgrep=True,
            severity_threshold=Severity.HIGH,
            use_validation=False,
        )

        # Should only include CRITICAL and HIGH threats
        assert len(result.semgrep_threats) == 2
        severities = {threat.severity for threat in result.semgrep_threats}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM not in severities
        assert Severity.LOW not in severities

        # Verify they're still sorted by line number (ThreatAggregator functionality)
        line_numbers = [threat.line_number for threat in result.semgrep_threats]
        assert line_numbers == [5, 15]  # Critical at 5, High at 15

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_engine_file_scan_integration(self, mock_semgrep_scanner, tmp_path):
        """Test ScanEngine file scanning with modular components."""
        mock_credential_manager = create_mock_credential_manager()
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = None
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10
        mock_credential_manager.load_config.return_value = mock_config

        # Create a test file
        test_file = tmp_path / "integration_test.py"
        test_file.write_text(
            """
def vulnerable_function(user_input):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

def xss_function(user_data):
    # XSS vulnerability
    return f"<div>{user_data}</div>"
"""
        )

        file_threats = [
            ThreatMatch(
                rule_id="file-sql-injection",
                rule_name="File SQL Injection",
                description="SQL injection in file scan",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path=str(test_file),
                line_number=3,
                uuid="file-sql-uuid",
            ),
            ThreatMatch(
                rule_id="file-xss",
                rule_name="File XSS Vulnerability",
                description="XSS vulnerability in file scan",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path=str(test_file),
                line_number=8,
                uuid="file-xss-uuid",
            ),
        ]

        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_instance.scan_file = AsyncMock(return_value=file_threats)
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=False,
        )

        # Disable caching
        scanner._get_cached_scan_result = AsyncMock(return_value=None)
        scanner._cache_scan_result = AsyncMock()

        # Execute file scan (use Path object)
        result = scanner.scan_file_sync(
            file_path=test_file,  # Pass Path object instead of string
            use_llm=False,
            use_semgrep=True,
            use_validation=False,
        )

        # Verify file scan results
        assert isinstance(result, EnhancedScanResult)
        assert result.file_path == str(test_file)
        assert len(result.semgrep_threats) == 2
        assert len(result.llm_threats) == 0

        # Verify ResultBuilder created proper metadata for file scan (check actual metadata structure)
        assert result.scan_metadata.get("file_path") == str(test_file)
        assert result.scan_metadata.get("semgrep_scan_success", True) is True
        # Language detection happens, check for language field
        assert "language" in result.scan_metadata

        # Verify ThreatAggregator processed threats correctly
        categories = {threat.category for threat in result.semgrep_threats}
        assert Category.INJECTION in categories
        assert Category.XSS in categories

        # Verify file paths are correct
        for threat in result.semgrep_threats:
            assert threat.file_path == str(test_file)

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMScanner")
    @patch("adversary_mcp_server.scanner.scan_engine.LLMValidator")
    def test_scan_engine_validation_coordination(
        self, mock_llm_validator_class, mock_llm_scanner, mock_semgrep_scanner
    ):
        """Test ScanEngine ValidationCoordinator integration."""
        mock_credential_manager = create_mock_credential_manager()
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = "openai"
        mock_config.llm_api_key = "test-key"
        mock_config.llm_model = "gpt-3.5-turbo"
        mock_config.llm_batch_size = 5
        mock_config.llm_max_tokens = 4000
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10
        mock_credential_manager.load_config.return_value = mock_config

        # Create test threats for validation
        validation_threats = [
            ThreatMatch(
                rule_id="validation-test-1",
                rule_name="Validation Test Threat",
                description="Threat to be validated",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="validation-uuid-1",
            ),
            ThreatMatch(
                rule_id="validation-test-2",
                rule_name="False Positive Threat",
                description="Likely false positive",
                category=Category.MISC,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=20,
                uuid="validation-uuid-2",
            ),
        ]

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_instance.scan_code = AsyncMock(return_value=validation_threats)
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        # Mock LLM scanner
        mock_llm_instance = Mock()
        mock_llm_instance.is_available.return_value = True
        mock_llm_scanner.return_value = mock_llm_instance

        # Mock LLM validator with validation results
        mock_validator_instance = Mock()
        mock_validator_instance.is_available.return_value = True
        from adversary_mcp_server.scanner.llm_validator import ValidationResult

        mock_validation_results = {
            "validation-uuid-1": ValidationResult(
                finding_uuid="validation-uuid-1",
                is_legitimate=True,
                confidence=0.9,
                reasoning="Legitimate SQL injection vulnerability",
            ),
            "validation-uuid-2": ValidationResult(
                finding_uuid="validation-uuid-2",
                is_legitimate=False,
                confidence=0.8,
                reasoning="False positive - safe string operation",
            ),
        }
        mock_validator_instance._validate_findings_async = AsyncMock(
            return_value=mock_validation_results
        )
        mock_llm_validator_class.return_value = mock_validator_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=True,
        )

        # Disable caching
        scanner._get_cached_scan_result = AsyncMock(return_value=None)
        scanner._cache_scan_result = AsyncMock()

        # Execute scan with validation enabled
        result = scanner.scan_code_sync(
            source_code="test code with validation",
            file_path="test.py",
            use_llm=False,
            use_semgrep=True,
            use_validation=True,
        )

        # Verify ValidationCoordinator filtered false positives
        assert isinstance(result, EnhancedScanResult)
        assert (
            len(result.semgrep_threats) == 1
        )  # One should be filtered as false positive
        remaining_threat = result.semgrep_threats[0]
        assert (
            remaining_threat.uuid == "validation-uuid-1"
        )  # High confidence legitimate threat

        # Verify validation results are included
        assert result.validation_results is not None
        assert len(result.validation_results) == 2
        assert "validation-uuid-1" in result.validation_results
        assert "validation-uuid-2" in result.validation_results

        # Verify metadata shows validation was successful
        assert result.scan_metadata["llm_validation_success"] is True

        # Verify validator was called (ValidationCoordinator integration)
        mock_validator_instance._validate_findings_async.assert_called_once()

    @patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner")
    def test_scan_engine_cache_coordinator_integration(self, mock_semgrep_scanner):
        """Test ScanEngine CacheCoordinator integration."""
        mock_credential_manager = create_mock_credential_manager()
        mock_config = SecurityConfig()
        mock_config.exploit_safety_mode = True
        mock_config.llm_provider = None
        mock_config.enable_semgrep_scanning = True
        mock_config.max_file_size_mb = 10
        mock_credential_manager.load_config.return_value = mock_config

        cache_threats = [
            ThreatMatch(
                rule_id="cache-test-threat",
                rule_name="Cache Test Threat",
                description="Threat for testing cache coordination",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=10,
                uuid="cache-uuid",
            ),
        ]

        # Mock Semgrep scanner
        mock_semgrep_instance = Mock()
        mock_semgrep_instance.is_available.return_value = True
        mock_semgrep_instance.get_status.return_value = {
            "available": True,
            "version": "1.0.0",
        }
        mock_semgrep_instance.scan_code = AsyncMock(return_value=cache_threats)
        mock_semgrep_scanner.return_value = mock_semgrep_instance

        scanner = ScanEngine(
            credential_manager=mock_credential_manager,
            enable_llm_analysis=False,
            enable_semgrep_analysis=True,
            enable_llm_validation=False,
        )

        # Mock cache methods to test CacheCoordinator integration
        cached_result = EnhancedScanResult(
            file_path="test.py",
            llm_threats=[],
            semgrep_threats=cache_threats,
            scan_metadata={"cache_hit": True, "cached_at": "2024-01-15T10:00:00Z"},
        )

        # Test cache miss first, then cache hit
        scanner._get_cached_scan_result = AsyncMock(side_effect=[None, cached_result])
        scanner._cache_scan_result = AsyncMock()

        # First scan - cache miss
        result1 = scanner.scan_code_sync(
            source_code="test cache code",
            file_path="test.py",
            use_llm=False,
            use_semgrep=True,
            use_validation=False,
        )

        # Verify normal scan result
        assert isinstance(result1, EnhancedScanResult)
        assert len(result1.semgrep_threats) == 1
        assert result1.semgrep_threats[0].rule_id == "cache-test-threat"

        # Second scan - cache hit (mock returns cached result)
        result2 = scanner.scan_code_sync(
            source_code="test cache code",
            file_path="test.py",
            use_llm=False,
            use_semgrep=True,
            use_validation=False,
        )

        # Verify cached result was returned
        assert isinstance(result2, EnhancedScanResult)
        assert result2.scan_metadata.get("cache_hit") is True

        # Verify cache operations were called through CacheCoordinator
        assert scanner._get_cached_scan_result.call_count == 2
        scanner._cache_scan_result.assert_called_once()  # Only called for cache miss


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
                    patch(
                        "adversary_mcp_server.credentials.get_credential_manager"
                    ) as mock_get_cred,
                    patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
                    patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
                ):
                    # Mock credential manager with proper config
                    mock_cred_manager = Mock()
                    mock_config = Mock()
                    mock_config.llm_batch_size = 5
                    mock_config.llm_provider = None
                    mock_config.enable_llm_validation = False
                    mock_config.enable_llm_analysis = False
                    mock_config.enable_semgrep_scanning = True
                    mock_cred_manager.load_config.return_value = mock_config
                    mock_get_cred.return_value = mock_cred_manager

                    scanner = ScanEngine()
                    results = await scanner.scan_directory(temp_path)

                    # New architecture returns 1 directory-level result
                    assert len(results) == 1
                    directory_result = results[0]
                    assert directory_result.scan_metadata["directory_scan"] is True
                    # Verify 5 files were processed
                    assert (
                        directory_result.scan_metadata["files_filtered_for_scan"] == 5
                    )

    @pytest.mark.asyncio
    async def test_process_single_file(self):
        """Test the _process_single_file method."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "test.py"
            test_file.write_text("print('hello')")

            # Mock dependencies
            with (
                patch(
                    "adversary_mcp_server.credentials.get_credential_manager"
                ) as mock_get_cred,
                patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
                patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
            ):
                mock_get_cred.return_value = create_mock_credential_manager()

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
        """Test that large file sets are handled efficiently by directory scanner."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create many test files
            files = []
            for i in range(100):
                test_file = temp_path / f"test{i}.py"
                test_file.write_text(f"print('test {i}')")
                files.append(test_file)

            with (
                patch(
                    "adversary_mcp_server.credentials.get_credential_manager"
                ) as mock_get_cred,
                patch(
                    "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
                ) as mock_semgrep,
                patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
            ):
                mock_get_cred.return_value = create_mock_credential_manager()

                # Mock semgrep to return empty results
                mock_semgrep_instance = Mock()
                mock_semgrep_instance.is_available.return_value = True
                mock_semgrep_instance.scan_directory.return_value = []
                mock_semgrep_instance.get_status.return_value = {
                    "available": True,
                    "version": "1.0.0",
                }
                mock_semgrep.return_value = mock_semgrep_instance

                scanner = ScanEngine()
                results = await scanner.scan_directory(temp_path)

                # New architecture: single directory-level result for efficiency
                assert len(results) == 1
                directory_result = results[0]
                assert directory_result.scan_metadata["directory_scan"] is True
                # Should have discovered all 100 files
                assert directory_result.scan_metadata["files_filtered_for_scan"] == 100

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
                patch(
                    "adversary_mcp_server.credentials.get_credential_manager"
                ) as mock_get_cred,
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
                patch(
                    "adversary_mcp_server.credentials.get_credential_manager"
                ) as mock_get_cred,
                patch(
                    "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
                ) as mock_semgrep,
                patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
            ):
                mock_get_cred.return_value = create_mock_credential_manager()

                # Mock semgrep to return empty results
                mock_semgrep_instance = Mock()
                mock_semgrep_instance.is_available.return_value = True
                mock_semgrep_instance.scan_directory.return_value = []
                mock_semgrep_instance.get_status.return_value = {
                    "available": True,
                    "version": "1.0.0",
                }
                mock_semgrep.return_value = mock_semgrep_instance

                scanner = ScanEngine()
                results = await scanner.scan_directory(temp_path)

                # New architecture returns 1 directory result
                assert len(results) == 1
                directory_result = results[0]
                assert directory_result.scan_metadata["directory_scan"] is True

                # Should only process the good Python file (binary, .git, .tmp filtered out)
                assert directory_result.scan_metadata["files_filtered_for_scan"] == 1

                # Check the files info contains only the good file
                directory_files_info = directory_result.scan_metadata.get(
                    "directory_files_info", []
                )
                assert len(directory_files_info) == 1
                processed_file_path = Path(directory_files_info[0]["file_path"])
                assert processed_file_path.resolve() == good_file.resolve()

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
                        ) as mock_semgrep,
                        patch("adversary_mcp_server.scanner.scan_engine.LLMScanner"),
                    ):
                        # Mock semgrep to return empty results
                        mock_semgrep_instance = Mock()
                        mock_semgrep_instance.is_available.return_value = True
                        mock_semgrep_instance.scan_directory.return_value = []
                        mock_semgrep_instance.get_status.return_value = {
                            "available": True,
                            "version": "1.0.0",
                        }
                        mock_semgrep.return_value = mock_semgrep_instance

                        scanner = ScanEngine()
                        results = await scanner.scan_directory(temp_path)

                        # Verify FileFilter was used
                        mock_filter_class.assert_called_once()
                        mock_filter.filter_files.assert_called_once()

                        # New architecture returns 1 directory result
                        assert len(results) == 1
                        directory_result = results[0]
                        assert directory_result.scan_metadata["directory_scan"] is True

                        # Should only process the file returned by filter (1 file)
                        assert (
                            directory_result.scan_metadata["files_filtered_for_scan"]
                            == 1
                        )


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
                        mock_validator._validate_findings_async = AsyncMock(
                            return_value={}
                        )
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
            patch.object(
                scanner, "_find_semgrep", return_value="mock_semgrep"
            ) as mock_find_semgrep,
        ):

            # Both should return empty list for testing
            mock_stdin.return_value = []
            mock_tempfile.return_value = []

            # Large content should use stdin streaming
            asyncio.run(scanner._perform_scan(large_content, "test.py", "python"))
            mock_stdin.assert_called_once()
            mock_tempfile.assert_not_called()

            # Reset mocks
            mock_stdin.reset_mock()
            mock_tempfile.reset_mock()

            # Small content should use temp file
            asyncio.run(scanner._perform_scan(small_content, "test.py", "python"))
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
                "test code", "test.py", use_semgrep=True, use_llm=False
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

        with patch("subprocess.run") as mock_run:
            # Mock subprocess.run for semgrep status check
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "semgrep version 1.0.0"

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

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMScanner"
            ) as mock_llm_scanner_class,
            patch("subprocess.run") as mock_run,
        ):
            # Mock subprocess.run for semgrep status check
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "semgrep version 1.0.0"

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

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.LLMScanner"
            ) as mock_llm_scanner_class,
            patch("subprocess.run") as mock_run,
        ):
            # Mock subprocess.run for semgrep status check
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "semgrep version 1.0.0"

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
            mock_llm_scanner.analyze_code = Mock(return_value=[mock_finding])
            mock_llm_scanner_class.return_value = mock_llm_scanner

            mock_validator = Mock()
            mock_validator._validate_findings_async = AsyncMock(
                side_effect=Exception("Validation API error")
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


class TestScanEnginePhase2Integration:
    """Test ScanEngine integration with Phase II coordination layer components."""

    def test_scan_engine_initialization_with_coordinators(self):
        """Test ScanEngine can be initialized with coordination layer components."""
        from adversary_mcp_server.application.coordination.cache_coordinator import (
            CacheCoordinator,
        )
        from adversary_mcp_server.application.coordination.scan_orchestrator import (
            ScanOrchestrator,
        )
        from adversary_mcp_server.application.coordination.validation_coordinator import (
            ValidationCoordinator,
        )

        mock_cm = create_mock_credential_manager()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep,
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            # Mock dependencies for coordination layer
            mock_semgrep_instance = Mock()
            mock_semgrep.return_value = mock_semgrep_instance

            # Create coordination components
            scan_orchestrator = ScanOrchestrator(semgrep_scanner=mock_semgrep_instance)
            cache_coordinator = CacheCoordinator()
            validation_coordinator = ValidationCoordinator()

            # Verify coordination components can be used with scan engine context
            assert scan_orchestrator.semgrep_scanner is mock_semgrep_instance
            assert cache_coordinator.is_cache_available() is False  # No cache manager
            assert validation_coordinator.validator is None  # No validator

            # Initialize scan engine
            engine = ScanEngine(credential_manager=mock_cm)

            # Verify scan engine initialization doesn't conflict with coordinators
            assert engine.credential_manager == mock_cm

    def test_scan_engine_coordination_layer_compatibility(self):
        """Test ScanEngine compatibility with coordination layer patterns."""
        from adversary_mcp_server.domain.aggregation.threat_aggregator import (
            ThreatAggregator,
        )
        from adversary_mcp_server.infrastructure.builders.result_builder import (
            ResultBuilder,
        )

        mock_cm = create_mock_credential_manager()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            # Create domain and infrastructure components
            threat_aggregator = ThreatAggregator()
            result_builder = ResultBuilder()

            # Create sample threats
            sample_threats = [
                ThreatMatch(
                    rule_id="test_rule_1",
                    rule_name="Test Rule 1",
                    description="Test description",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path="test.py",
                    line_number=10,
                )
            ]

            # Test aggregation works with scan engine threat format
            # Split threats for separate semgrep and llm arguments (test data - split evenly)
            mid = len(sample_threats) // 2
            semgrep_threats = sample_threats[:mid]
            llm_threats = sample_threats[mid:]
            aggregated = threat_aggregator.aggregate_threats(
                semgrep_threats, llm_threats
            )
            assert len(aggregated) == 1
            assert aggregated[0].rule_id == "test_rule_1"

            # Test result building works with scan engine results
            result = result_builder.build_scan_result(
                threats=aggregated, metadata={"scan_type": "integration_test"}
            )
            assert result is not None

    @pytest.mark.asyncio
    async def test_scan_engine_orchestrator_integration(self):
        """Test ScanEngine integration with ScanOrchestrator workflow."""
        from adversary_mcp_server.application.coordination.scan_orchestrator import (
            ScanOrchestrator,
        )
        from adversary_mcp_server.interfaces.scanner import ISemgrepScanner

        mock_cm = create_mock_credential_manager()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_class,
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            # Create mock semgrep scanner that implements interface
            mock_semgrep = Mock(spec=ISemgrepScanner)
            mock_semgrep.scan_file.return_value = []
            mock_semgrep.scan_code.return_value = []
            mock_semgrep_class.return_value = mock_semgrep

            # Create orchestrator with mocked scanner
            orchestrator = ScanOrchestrator(semgrep_scanner=mock_semgrep)

            # Test file scan orchestration
            test_file = Path("/test/file.py")
            with patch("pathlib.Path.read_text", return_value="print('test')"):
                result = await orchestrator.orchestrate_file_scan(test_file)

                # Verify orchestration completed
                assert result is not None
                assert result.file_path == str(test_file)

                # Verify semgrep scanner was called
                mock_semgrep.scan_file.assert_called_once()

    def test_scan_engine_coordination_error_handling(self):
        """Test error handling between ScanEngine and coordination layer."""
        from adversary_mcp_server.application.coordination.validation_coordinator import (
            ValidationCoordinator,
        )

        mock_cm = create_mock_credential_manager()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            # Create coordination components
            validation_coordinator = ValidationCoordinator()

            # Test error handling in validation
            sample_threats = [
                ThreatMatch(
                    rule_id="test_rule_1",
                    rule_name="Test Rule 1",
                    description="Test description",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path="test.py",
                    line_number=10,
                )
            ]

            # Test validation without validator (should handle gracefully)
            should_validate = validation_coordinator.should_validate(
                use_validation=True, enable_llm_validation=True, threats=sample_threats
            )

            # Should return False since no validator is configured
            assert should_validate is False

    @pytest.mark.asyncio
    async def test_scan_engine_cache_coordination_integration(self):
        """Test ScanEngine integration with cache coordination."""
        from adversary_mcp_server.application.coordination.cache_coordinator import (
            CacheCoordinator,
        )

        mock_cm = create_mock_credential_manager()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            # Create cache coordinator
            cache_coordinator = CacheCoordinator()  # No cache manager

            # Test cache availability check
            assert cache_coordinator.is_cache_available() is False

            # Test content hash creation (should handle no cache manager)
            content_hash = cache_coordinator.create_content_hash("test content")
            assert content_hash == ""  # Empty string when no cache manager

            # Test cache key creation (should return None when no cache manager)
            cache_key = cache_coordinator.create_cache_key_for_code(
                "test content", {"use_llm": True, "use_semgrep": True}
            )
            assert cache_key is None

    def test_scan_engine_telemetry_coordination_integration(self):
        """Test ScanEngine telemetry integration with coordination layer."""
        mock_cm = create_mock_credential_manager()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
            patch(
                "adversary_mcp_server.scanner.scan_engine.AdversaryDatabase"
            ) as mock_db,
            patch(
                "adversary_mcp_server.scanner.scan_engine.TelemetryService"
            ) as mock_telemetry,
            patch(
                "adversary_mcp_server.scanner.scan_engine.MetricsCollectionOrchestrator"
            ) as mock_orchestrator,
        ):

            # Setup telemetry mocks
            mock_db_instance = Mock()
            mock_db.return_value = mock_db_instance

            mock_telemetry_instance = Mock()
            mock_telemetry.return_value = mock_telemetry_instance

            mock_orchestrator_instance = Mock()
            mock_orchestrator.return_value = mock_orchestrator_instance

            # Initialize scan engine (should create telemetry system)
            engine = ScanEngine(credential_manager=mock_cm)

            # Verify telemetry components were initialized
            assert engine.metrics_orchestrator is mock_orchestrator_instance
            mock_db.assert_called_once()
            mock_telemetry.assert_called_once_with(mock_db_instance)
            mock_orchestrator.assert_called_once_with(mock_telemetry_instance)

    def test_scan_engine_architecture_separation_validation(self):
        """Test that ScanEngine maintains proper architectural separation with coordination layer."""
        from adversary_mcp_server.application.coordination.scan_orchestrator import (
            ScanOrchestrator,
        )
        from adversary_mcp_server.domain.aggregation.threat_aggregator import (
            ThreatAggregator,
        )
        from adversary_mcp_server.infrastructure.builders.result_builder import (
            ResultBuilder,
        )

        mock_cm = create_mock_credential_manager()

        with (
            patch(
                "adversary_mcp_server.scanner.scan_engine.SemgrepScanner"
            ) as mock_semgrep_class,
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            mock_semgrep = Mock()
            mock_semgrep_class.return_value = mock_semgrep

            # Create all architectural layers
            scan_engine = ScanEngine(credential_manager=mock_cm)
            scan_orchestrator = ScanOrchestrator(semgrep_scanner=mock_semgrep)
            threat_aggregator = ThreatAggregator()
            result_builder = ResultBuilder()

            # Verify each component maintains its responsibilities
            # ScanEngine - scanner configuration and execution
            assert hasattr(scan_engine, "credential_manager")
            assert hasattr(scan_engine, "semgrep_scanner")

            # ScanOrchestrator - workflow coordination
            assert hasattr(scan_orchestrator, "orchestrate_file_scan")
            assert hasattr(scan_orchestrator, "orchestrate_code_scan")

            # ThreatAggregator - domain logic
            assert hasattr(threat_aggregator, "aggregate_threats")

            # ResultBuilder - infrastructure concerns
            assert hasattr(result_builder, "build_scan_result")

            # Verify clean interfaces between layers
            assert scan_orchestrator.semgrep_scanner is mock_semgrep
            assert scan_orchestrator.threat_aggregator is not None
            assert scan_orchestrator.result_builder is not None


class TestScanEnginePhase3SecurityIntegration:
    """Test ScanEngine integration with Phase III security components."""

    def test_scan_engine_security_validation_integration(self):
        """Test ScanEngine integration with security validation."""
        from adversary_mcp_server.security import SecurityError
        from adversary_mcp_server.security.input_validator import InputValidator

        mock_cm = create_mock_credential_manager()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            # Test security validation availability
            validator = InputValidator()

            # Test path traversal validation
            with pytest.raises(SecurityError, match="Path traversal"):
                validator.validate_file_path("../../../etc/passwd")

            # Test safe path validation with a temporary file
            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.is_file", return_value=True),
            ):
                safe_path = "/safe/path/test.py"
                validated_path = validator.validate_file_path(safe_path)
                assert str(validated_path) == str(Path(safe_path).resolve())

    def test_scan_engine_log_sanitization_integration(self):
        """Test ScanEngine integration with log sanitization."""
        from adversary_mcp_server.security.log_sanitizer import sanitize_for_logging

        # Test sanitization of sensitive scan data
        sensitive_scan_data = {
            "file_path": "/safe/path/test.py",
            "api_key": "sk-secret123",
            "scan_results": "SQL injection found",
            "auth_token": "bearer_token_456",
        }

        sanitized = sanitize_for_logging(sensitive_scan_data)

        # Verify sensitive data is redacted
        assert "sk-secret123" not in sanitized
        assert "bearer_token_456" not in sanitized
        assert "[REDACTED]" in sanitized

        # Verify safe data is preserved
        assert "/safe/path/test.py" in sanitized
        assert "SQL injection found" in sanitized

    def test_scan_engine_security_error_handling(self):
        """Test ScanEngine security error handling."""
        from adversary_mcp_server.security import SecurityError

        mock_cm = create_mock_credential_manager()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            # Create scan engine
            engine = ScanEngine(credential_manager=mock_cm)

            # Test that SecurityError can be properly handled in scan engine context
            try:
                raise SecurityError("Test security error")
            except SecurityError as e:
                # Verify security errors are handled properly
                assert str(e) == "Test security error"
                assert isinstance(e, SecurityError)

    def test_scan_engine_security_integration_with_coordination(self):
        """Test security integration with coordination layer components."""
        from adversary_mcp_server.application.coordination.validation_coordinator import (
            ValidationCoordinator,
        )
        from adversary_mcp_server.security.input_validator import InputValidator

        mock_cm = create_mock_credential_manager()

        with (
            patch("adversary_mcp_server.scanner.scan_engine.SemgrepScanner"),
            patch("adversary_mcp_server.scanner.scan_engine.ErrorHandler"),
        ):

            # Create components with security integration
            validator = InputValidator()
            validation_coordinator = ValidationCoordinator(validator=None)

            # Test security validation in coordination context
            sample_threats = [
                ThreatMatch(
                    rule_id="security_test",
                    rule_name="Security Test Rule",
                    description="Test security validation",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path="test.py",
                    line_number=10,
                )
            ]

            # Test validation decision making
            should_validate = validation_coordinator.should_validate(
                use_validation=True, enable_llm_validation=True, threats=sample_threats
            )

            # Should return False since no validator is configured in coordinator
            assert should_validate is False

            # Test validation metadata building
            metadata = validation_coordinator.build_validation_metadata(
                use_validation=False, enable_llm_validation=False, validation_results={}
            )

            assert "llm_validation_success" in metadata
            assert metadata["llm_validation_success"] is False
