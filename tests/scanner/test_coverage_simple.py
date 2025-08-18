"""Simple tests to improve coverage for scan_engine.py and semgrep_scanner.py."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from adversary_mcp_server.scanner.scan_engine import ScanEngine
from adversary_mcp_server.scanner.semgrep_scanner import OptimizedSemgrepScanner
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestCoverageImprovements:
    """Simple tests to improve coverage."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = Path(self.temp_dir) / "test.py"
        self.test_file.write_text("print('hello world')")

    def teardown_method(self):
        """Clean up test fixtures."""
        import os
        import shutil

        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_scan_engine_severity_filtering(self):
        """Test severity filtering in ScanEngine."""
        engine = ScanEngine()

        # Create threats with different severities
        threats = [
            ThreatMatch(
                rule_id="test1",
                rule_name="Low Severity",
                description="Test",
                category=Category.MISC,
                severity=Severity.LOW,
                file_path=str(self.test_file),
                line_number=1,
            ),
            ThreatMatch(
                rule_id="test2",
                rule_name="High Severity",
                description="Test",
                category=Category.MISC,
                severity=Severity.HIGH,
                file_path=str(self.test_file),
                line_number=2,
            ),
        ]

        # Test filtering
        filtered = engine._filter_by_severity(threats, Severity.MEDIUM)
        assert len(filtered) == 1  # Only high severity should pass

    def test_scan_engine_language_detection(self):
        """Test language detection in ScanEngine."""
        engine = ScanEngine()

        # Test various file extensions
        assert engine._detect_language(Path("test.py")) == "python"
        assert engine._detect_language(Path("test.js")) == "javascript"
        assert engine._detect_language(Path("test.unknown")) == "generic"

    def test_scan_engine_validation_filter(self):
        """Test validation filtering in ScanEngine."""
        engine = ScanEngine()

        threat = ThreatMatch(
            rule_id="test",
            rule_name="Test",
            description="Test",
            category=Category.MISC,
            severity=Severity.HIGH,
            file_path=str(self.test_file),
            line_number=1,
        )

        # Test with empty validation results
        result = engine._apply_validation_filter([threat], {})
        assert len(result) == 1

    def test_semgrep_scanner_pro_status(self):
        """Test pro status extraction in SemgrepScanner."""
        scanner = OptimizedSemgrepScanner()

        # Test pro status extraction
        result = {"user": {"subscription_type": "pro", "user_id": "test-user"}}

        scanner._extract_and_store_pro_status(result)
        status = scanner.get_pro_status()
        assert status["is_pro_user"] is True

    def test_semgrep_scanner_env_handling(self):
        """Test environment variable handling in SemgrepScanner."""
        scanner = OptimizedSemgrepScanner()

        # Test clean environment generation
        env = scanner._get_clean_env()
        assert "PATH" in env

    @patch("adversary_mcp_server.scanner.scan_engine.get_credential_manager")
    def test_scan_engine_config_exception(self, mock_get_creds):
        """Test exception handling in ScanEngine configuration."""
        # Mock config that raises exception
        mock_config = Mock()
        mock_config.enable_caching = property(
            lambda self: (_ for _ in ()).throw(Exception("test"))
        )
        # Use valid LLMProvider enum value to avoid enum errors
        mock_config.llm_provider = "openai"
        # Provide string values for fields that need len() operation
        mock_config.llm_api_key = "test-api-key"
        mock_config.llm_model = "gpt-3.5-turbo"

        mock_creds = Mock()
        mock_creds.load_config.return_value = mock_config
        mock_get_creds.return_value = mock_creds

        # Should handle exception gracefully
        engine = ScanEngine()
        assert engine is not None

    @patch("subprocess.run")
    def test_semgrep_availability_exception(self, mock_run):
        """Test semgrep availability check exception handling."""
        # Force module reload to trigger availability check
        mock_run.side_effect = OSError("Test error")

        import importlib

        from adversary_mcp_server.scanner import semgrep_scanner

        importlib.reload(semgrep_scanner)

        # Should handle exception gracefully
        assert hasattr(semgrep_scanner, "_SEMGREP_AVAILABLE")

    @patch("adversary_mcp_server.scanner.semgrep_scanner.ConfigurationTracker")
    def test_semgrep_config_tracker_error(self, mock_tracker):
        """Test configuration tracker initialization error."""
        mock_tracker.side_effect = Exception("Tracker failed")

        # Should handle exception gracefully
        scanner = OptimizedSemgrepScanner()
        assert scanner is not None

    def test_threat_match_fingerprint(self):
        """Test ThreatMatch fingerprint generation."""
        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test",
            category=Category.MISC,
            severity=Severity.HIGH,
            file_path=str(self.test_file),
            line_number=42,
        )

        # Test fingerprint generation
        fingerprint = threat.get_fingerprint()
        assert "test_rule" in fingerprint
        assert str(42) in fingerprint
        assert str(Path(self.test_file).resolve()) in fingerprint
