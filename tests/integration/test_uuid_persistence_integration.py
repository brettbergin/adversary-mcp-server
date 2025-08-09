"""Integration tests for UUID persistence in real scan workflows."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch
from adversary_mcp_server.server import AdversaryMCPServer


class TestUUIDPersistenceIntegration:
    """Integration tests for UUID persistence across real scan workflows."""

    @pytest.fixture
    def temp_project_dir(self):
        """Create a temporary project directory with test files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Create a test Python file with vulnerabilities
            test_file = project_path / "vulnerable.py"
            test_file.write_text(
                """
# Test file with vulnerabilities
API_KEY = "sk-1234567890abcdef"  # Line 3 - hardcoded secret

def query_user(user_id):
    # Line 6 - SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

def render_template(user_input):
    # Line 10 - XSS vulnerability
    return f"<div>{user_input}</div>"
"""
            )

            yield project_path

    @pytest.fixture
    def server(self):
        """Create server instance with mocked scan engines."""
        with patch(
            "adversary_mcp_server.scanner.semgrep_scanner.OptimizedSemgrepScanner.get_status"
        ) as mock_status:
            # Mock semgrep status to avoid subprocess calls
            mock_status.return_value = {
                "semgrep_installed": True,
                "semgrep_version": "1.0.0",
                "semgrep_path": "/mock/semgrep",
                "config_status": "loaded",
            }
            server = AdversaryMCPServer()
            yield server

    def create_mock_scan_results(self, file_path: str):
        """Create consistent mock scan results that would be found in the test file."""
        return [
            ThreatMatch(
                rule_id="hardcoded-secret",
                rule_name="Hardcoded API Key",
                description="Hardcoded API key detected",
                category=Category.SECRETS,
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=3,
                code_snippet='API_KEY = "sk-1234567890abcdef"',
                source="rules",
            ),
            ThreatMatch(
                rule_id="sql-injection",
                rule_name="SQL Injection Vulnerability",
                description="Potential SQL injection detected",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=6,
                code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
                source="rules",
            ),
            ThreatMatch(
                rule_id="xss-vulnerability",
                rule_name="Cross-Site Scripting",
                description="Potential XSS vulnerability detected",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=10,
                code_snippet='return f"<div>{user_input}</div>"',
                source="rules",
            ),
        ]

    @pytest.mark.asyncio
    async def test_uuid_persistence_across_file_scans(self, server, temp_project_dir):
        """Test UUID persistence across multiple file scans."""
        test_file = temp_project_dir / "vulnerable.py"
        adversary_file = temp_project_dir / ".adversary.json"

        # Mock the scan engine to return consistent results
        mock_threats = self.create_mock_scan_results(str(test_file))

        async def mock_scan_file(*args, **kwargs):
            from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult

            # Language enum removed - using strings directly

            return EnhancedScanResult(
                file_path=str(test_file),
                llm_threats=[],
                semgrep_threats=mock_threats,
                scan_metadata={"file_path": str(test_file)},
            )

        with patch.object(server.scan_engine, "scan_file", side_effect=mock_scan_file):
            with patch.object(
                server, "_get_project_root", return_value=temp_project_dir
            ):
                # First scan - using relative path since we're mocking project root
                arguments1 = {
                    "path": "vulnerable.py",  # Relative to project root
                }

                result1 = await server._handle_scan_file(arguments1)

            # Verify scan completed and file was saved
            assert adversary_file.exists()

            # Load the first scan results and capture UUIDs
            with open(adversary_file) as f:
                first_scan_data = json.load(f)

            first_threats = first_scan_data["threats"]
            assert len(first_threats) == 3

            # Capture original UUIDs
            original_uuids = {
                (t["rule_id"], t["file_path"], t["line_number"]): t["uuid"]
                for t in first_threats
            }

            # Second scan with same file - should preserve UUIDs
            with patch.object(
                server, "_get_project_root", return_value=temp_project_dir
            ):
                arguments2 = {
                    "path": "vulnerable.py",  # Relative to project root
                }

                result2 = await server._handle_scan_file(arguments2)

            # Load second scan results
            with open(adversary_file) as f:
                second_scan_data = json.load(f)

            second_threats = second_scan_data["threats"]
            assert len(second_threats) == 3

            # Verify UUIDs were preserved
            for threat in second_threats:
                key = (threat["rule_id"], threat["file_path"], threat["line_number"])
                assert key in original_uuids
                assert threat["uuid"] == original_uuids[key]
                print(f"✅ UUID preserved for {threat['rule_id']}: {threat['uuid']}")

    @pytest.mark.asyncio
    async def test_false_positive_persistence_across_scans(
        self, server, temp_project_dir
    ):
        """Test that false positive markings persist across scans."""
        test_file = temp_project_dir / "vulnerable.py"
        adversary_file = temp_project_dir / ".adversary.json"

        # Mock the scan engine
        mock_threats = self.create_mock_scan_results(str(test_file))

        async def mock_scan_file(*args, **kwargs):
            from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult

            # Language enum removed - using strings directly

            return EnhancedScanResult(
                file_path=str(test_file),
                llm_threats=[],
                semgrep_threats=mock_threats,
                scan_metadata={"file_path": str(test_file)},
            )

        with patch.object(server.scan_engine, "scan_file", side_effect=mock_scan_file):
            with patch.object(
                server, "_get_project_root", return_value=temp_project_dir
            ):
                # First scan
                await server._handle_scan_file(
                    {
                        "path": "vulnerable.py",
                    }
                )

            # Load results and get UUID of first threat
            with open(adversary_file) as f:
                scan_data = json.load(f)

            first_threat_uuid = scan_data["threats"][0]["uuid"]

            # Mark the first threat as false positive
            await server._handle_mark_false_positive(
                {
                    "finding_uuid": first_threat_uuid,
                    "reason": "This is test data, not a real secret",
                    "marked_by": "integration_test",
                    "path": str(temp_project_dir),
                }
            )

            # Verify false positive was marked
            with open(adversary_file) as f:
                marked_data = json.load(f)

            marked_threat = next(
                t for t in marked_data["threats"] if t["uuid"] == first_threat_uuid
            )
            assert marked_threat["is_false_positive"] is True
            assert (
                marked_threat["false_positive_reason"]
                == "This is test data, not a real secret"
            )

            # Run second scan - should preserve false positive marking
            with patch.object(
                server, "_get_project_root", return_value=temp_project_dir
            ):
                await server._handle_scan_file(
                    {
                        "path": "vulnerable.py",
                    }
                )

            # Verify false positive marking persisted
            with open(adversary_file) as f:
                final_data = json.load(f)

            preserved_threat = next(
                t for t in final_data["threats"] if t["uuid"] == first_threat_uuid
            )
            assert preserved_threat["is_false_positive"] is True
            assert (
                preserved_threat["false_positive_reason"]
                == "This is test data, not a real secret"
            )
            assert preserved_threat["false_positive_marked_by"] == "integration_test"

            print(
                f"✅ False positive marking preserved across scans for UUID: {first_threat_uuid}"
            )

    @pytest.mark.asyncio
    async def test_new_vulnerabilities_get_new_uuids(self, server, temp_project_dir):
        """Test that new vulnerabilities discovered in subsequent scans get new UUIDs."""
        test_file = temp_project_dir / "vulnerable.py"
        adversary_file = temp_project_dir / ".adversary.json"

        # First scan with 2 threats
        initial_threats = self.create_mock_scan_results(str(test_file))[
            :2
        ]  # Only first 2

        async def mock_scan_file_initial(*args, **kwargs):
            from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult

            # Language enum removed - using strings directly

            return EnhancedScanResult(
                file_path=str(test_file),
                llm_threats=[],
                semgrep_threats=initial_threats,
                scan_metadata={"file_path": str(test_file)},
            )

        with patch.object(
            server.scan_engine, "scan_file", side_effect=mock_scan_file_initial
        ):
            with patch.object(
                server, "_get_project_root", return_value=temp_project_dir
            ):
                await server._handle_scan_file(
                    {
                        "path": "vulnerable.py",
                    }
                )

        # Capture original UUIDs
        with open(adversary_file) as f:
            first_data = json.load(f)

        original_uuids = {t["uuid"] for t in first_data["threats"]}
        assert len(original_uuids) == 2

        # Second scan with all 3 threats (1 new one added)
        all_threats = self.create_mock_scan_results(str(test_file))  # All 3

        async def mock_scan_file_expanded(*args, **kwargs):
            from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult

            # Language enum removed - using strings directly

            return EnhancedScanResult(
                file_path=str(test_file),
                llm_threats=[],
                semgrep_threats=all_threats,
                scan_metadata={"file_path": str(test_file)},
            )

        with patch.object(
            server.scan_engine, "scan_file", side_effect=mock_scan_file_expanded
        ):
            with patch.object(
                server, "_get_project_root", return_value=temp_project_dir
            ):
                await server._handle_scan_file(
                    {
                        "path": "vulnerable.py",
                    }
                )

        # Check final results
        with open(adversary_file) as f:
            final_data = json.load(f)

        final_threats = final_data["threats"]
        assert len(final_threats) == 3

        final_uuids = {t["uuid"] for t in final_threats}

        # Should have 2 preserved UUIDs + 1 new UUID
        preserved_uuids = original_uuids.intersection(final_uuids)
        new_uuids = final_uuids - original_uuids

        assert len(preserved_uuids) == 2  # Original 2 preserved
        assert len(new_uuids) == 1  # 1 new UUID for new threat

        print(
            f"✅ Preserved {len(preserved_uuids)} UUIDs, added {len(new_uuids)} new UUIDs"
        )

    @pytest.mark.asyncio
    async def test_uuid_persistence_code_scan(self, server, temp_project_dir):
        """Test UUID persistence works with adv_scan_code (not just file scans)."""
        test_code = """
API_KEY = "test-secret-123"
query = f"SELECT * FROM users WHERE id = {user_id}"
"""

        adversary_file = temp_project_dir / ".adversary.json"

        # Mock scan results for code scanning
        mock_threats = [
            ThreatMatch(
                rule_id="hardcoded-secret",
                rule_name="Hardcoded Secret",
                description="Secret detected",
                category=Category.SECRETS,
                severity=Severity.HIGH,
                file_path="<code>",
                line_number=2,
                code_snippet='API_KEY = "test-secret-123"',
                source="rules",
            ),
            ThreatMatch(
                rule_id="sql-injection",
                rule_name="SQL Injection",
                description="SQL injection detected",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                file_path="<code>",
                line_number=3,
                code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
                source="rules",
            ),
        ]

        async def mock_scan_code(*args, **kwargs):
            from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult

            # Language enum removed - using strings directly

            return EnhancedScanResult(
                file_path="<code>",
                llm_threats=[],
                semgrep_threats=mock_threats,
                scan_metadata={},
            )

        with patch.object(server.scan_engine, "scan_code", side_effect=mock_scan_code):
            with patch.object(
                server, "_get_project_root", return_value=temp_project_dir
            ):
                # First code scan
                await server._handle_scan_code(
                    {
                        "content": test_code,
                        "path": str(temp_project_dir),
                    }
                )

                # Get original UUIDs
                with open(adversary_file) as f:
                    first_data = json.load(f)

                original_uuids = [t["uuid"] for t in first_data["threats"]]

                # Second identical code scan
                await server._handle_scan_code(
                    {
                        "content": test_code,
                        "path": str(temp_project_dir),
                    }
                )

            # Verify UUIDs were preserved
            with open(adversary_file) as f:
                second_data = json.load(f)

            preserved_uuids = [t["uuid"] for t in second_data["threats"]]

            assert len(preserved_uuids) == 2
            assert preserved_uuids[0] == original_uuids[0]
            assert preserved_uuids[1] == original_uuids[1]

            print(f"✅ Code scan UUID persistence working: {preserved_uuids}")
