"""Tests for the use_rules flag functionality."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from adversary_mcp_server.credential_manager import CredentialManager
from adversary_mcp_server.scan_engine import ScanEngine
from adversary_mcp_server.threat_engine import Language, Severity, ThreatEngine


class TestUseRulesFlag:
    """Test the use_rules flag functionality across all scan methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.threat_engine = ThreatEngine()
        self.credential_manager = CredentialManager()
        self.scan_engine = ScanEngine(self.threat_engine, self.credential_manager)

    def test_scan_code_with_rules_disabled(self):
        """Test scan_code with use_rules=False."""
        test_code = """
import os
os.system(user_input)  # Should be detected by rules
"""

        result = self.scan_engine.scan_code_sync(
            source_code=test_code,
            file_path="test.py",
            language=Language.PYTHON,
            use_rules=False,
            use_semgrep=False,
            use_llm=False,
        )

        assert len(result.rules_threats) == 0
        assert len(result.all_threats) == 0
        assert result.scan_metadata["use_rules"] is False
        assert result.scan_metadata["rules_scan_success"] is False
        assert result.scan_metadata["rules_scan_reason"] == "disabled"

    def test_scan_code_with_rules_enabled(self):
        """Test scan_code with use_rules=True."""
        test_code = """
import os
os.system(user_input)  # Should be detected by rules
"""

        result = self.scan_engine.scan_code_sync(
            source_code=test_code,
            file_path="test.py",
            language=Language.PYTHON,
            use_rules=True,
            use_semgrep=False,
            use_llm=False,
        )

        assert len(result.rules_threats) >= 1
        assert len(result.all_threats) >= 1
        assert result.scan_metadata["use_rules"] is True
        assert result.scan_metadata["rules_scan_success"] is True
        assert result.scan_metadata["rules_scan_reason"] == "analysis_completed"

    def test_scan_code_rules_default_enabled(self):
        """Test that rules are enabled by default."""
        test_code = """
import os
os.system(user_input)
"""

        result = self.scan_engine.scan_code_sync(
            source_code=test_code,
            file_path="test.py",
            language=Language.PYTHON,
            use_semgrep=False,
            use_llm=False,
        )

        # Should have rules threats by default
        assert len(result.rules_threats) >= 1
        assert result.scan_metadata["use_rules"] is True

    def test_scan_file_with_rules_disabled(self):
        """Test scan_file with use_rules=False."""
        test_code = """
import os
os.system(user_input)
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            test_file = Path(f.name)

        try:
            result = self.scan_engine.scan_file_sync(
                file_path=test_file,
                language=Language.PYTHON,
                use_rules=False,
                use_semgrep=False,
                use_llm=False,
            )

            assert len(result.rules_threats) == 0
            assert len(result.all_threats) == 0
            assert result.scan_metadata["use_rules"] is False
        finally:
            test_file.unlink()

    def test_scan_file_with_rules_enabled(self):
        """Test scan_file with use_rules=True."""
        test_code = """
import os
os.system(user_input)
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            test_file = Path(f.name)

        try:
            result = self.scan_engine.scan_file_sync(
                file_path=test_file,
                language=Language.PYTHON,
                use_rules=True,
                use_semgrep=False,
                use_llm=False,
            )

            assert len(result.rules_threats) >= 1
            assert len(result.all_threats) >= 1
            assert result.scan_metadata["use_rules"] is True
        finally:
            test_file.unlink()

    def test_scan_directory_with_rules_disabled(self):
        """Test scan_directory with use_rules=False."""
        test_code = """
import os
os.system(user_input)
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text(test_code)

            results = self.scan_engine.scan_directory_sync(
                directory_path=Path(temp_dir),
                use_rules=False,
                use_semgrep=False,
                use_llm=False,
            )

            assert len(results) == 1
            result = results[0]
            assert len(result.rules_threats) == 0
            assert len(result.all_threats) == 0
            assert result.scan_metadata["use_rules"] is False

    def test_scan_directory_with_rules_enabled(self):
        """Test scan_directory with use_rules=True."""
        test_code = """
import os
os.system(user_input)
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text(test_code)

            results = self.scan_engine.scan_directory_sync(
                directory_path=Path(temp_dir),
                use_rules=True,
                use_semgrep=False,
                use_llm=False,
            )

            assert len(results) == 1
            result = results[0]
            assert len(result.rules_threats) >= 1
            assert len(result.all_threats) >= 1
            assert result.scan_metadata["use_rules"] is True

    #     def test_flag_combinations(self):
    #         """Test different combinations of scanner flags."""
    #         test_code = """
    # import os
    # os.system(user_input)
    # """

    #         # Test all disabled
    #         result1 = self.scan_engine.scan_code(
    #             source_code=test_code,
    #             file_path="test.py",
    #             language=Language.PYTHON,
    #             use_rules=False,
    #             use_semgrep=False,
    #             use_llm=False,
    #         )
    #         assert len(result1.all_threats) == 0

    #         # Test only rules enabled
    #         result2 = self.scan_engine.scan_code(
    #             source_code=test_code,
    #             file_path="test.py",
    #             language=Language.PYTHON,
    #             use_rules=True,
    #             use_semgrep=False,
    #             use_llm=False,
    #         )
    #         assert len(result2.rules_threats) >= 1
    #         assert len(result2.semgrep_threats) == 0
    #         assert len(result2.llm_threats) == 0

    #         # Test rules + semgrep (if available)
    #         result3 = self.scan_engine.scan_code(
    #             source_code=test_code,
    #             file_path="test.py",
    #             language=Language.PYTHON,
    #             use_rules=True,
    #             use_semgrep=True,
    #             use_llm=False,
    #         )
    #         assert len(result3.rules_threats) >= 1
    #         # Note: semgrep might not find anything or might not be available

    @patch("adversary_mcp_server.scan_engine.ASTScanner")
    def test_rules_scanner_error_handling(self, mock_ast_scanner):
        """Test error handling when rules scanner fails."""
        # Mock AST scanner to raise an exception
        mock_scanner_instance = Mock()
        mock_scanner_instance.scan_code.side_effect = Exception("Scanner error")
        mock_ast_scanner.return_value = mock_scanner_instance

        # Create new scan engine with mocked AST scanner
        scan_engine = ScanEngine(self.threat_engine, self.credential_manager)

        result = scan_engine.scan_code_sync(
            source_code="test code",
            file_path="test.py",
            language=Language.PYTHON,
            use_rules=True,
            use_semgrep=False,
            use_llm=False,
        )

        assert len(result.rules_threats) == 0
        assert result.scan_metadata["rules_scan_success"] is False
        assert result.scan_metadata["rules_scan_reason"] == "scan_failed"
        assert "Scanner error" in result.scan_metadata["rules_scan_error"]

    def test_severity_filtering_with_rules_disabled(self):
        """Test that severity filtering works when rules are disabled."""
        test_code = """
import os
os.system(user_input)
"""

        result = self.scan_engine.scan_code_sync(
            source_code=test_code,
            file_path="test.py",
            language=Language.PYTHON,
            use_rules=False,
            use_semgrep=False,
            use_llm=False,
            severity_threshold=Severity.HIGH,
        )

        # No threats should be found since rules are disabled
        assert len(result.rules_threats) == 0
        assert len(result.all_threats) == 0

    def test_severity_filtering_with_rules_enabled(self):
        """Test that severity filtering works when rules are enabled."""
        test_code = """
import os
os.system(user_input)
"""

        # Test with high threshold
        result_high = self.scan_engine.scan_code_sync(
            source_code=test_code,
            file_path="test.py",
            language=Language.PYTHON,
            use_rules=True,
            use_semgrep=False,
            use_llm=False,
            severity_threshold=Severity.HIGH,
        )

        # Test with low threshold
        result_low = self.scan_engine.scan_code_sync(
            source_code=test_code,
            file_path="test.py",
            language=Language.PYTHON,
            use_rules=True,
            use_semgrep=False,
            use_llm=False,
            severity_threshold=Severity.LOW,
        )

        # Should have threats with both thresholds (os.system is critical)
        assert len(result_high.rules_threats) >= 1
        assert len(result_low.rules_threats) >= 1

        # All threats should be at or above the threshold
        for threat in result_high.all_threats:
            assert threat.severity.value in ["high", "critical"]
