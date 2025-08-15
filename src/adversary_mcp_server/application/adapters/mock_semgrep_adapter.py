"""Mock Semgrep adapter for testing Clean Architecture without blocking Semgrep calls."""

from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.interfaces import IScanStrategy, ScanError
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext


class MockSemgrepScanStrategy(IScanStrategy):
    """
    Mock Semgrep adapter that returns a known set of test threats.

    This allows testing the Clean Architecture without depending on Semgrep execution.
    Used temporarily to verify the Clean Architecture flow works end-to-end.
    """

    def get_strategy_name(self) -> str:
        """Get the name of this scan strategy."""
        return "mock_semgrep_static_analysis"

    def get_supported_languages(self) -> list[str]:
        """Get list of programming languages supported by mock Semgrep."""
        return ["python", "javascript", "java", "go", "typescript"]

    def can_scan(self, context: ScanContext) -> bool:
        """Check if this strategy can scan the given context."""
        if context.metadata.scan_type in ["file", "directory", "code", "diff"]:
            return True
        return False

    async def execute_scan(self, request: ScanRequest) -> ScanResult:
        """Execute mock Semgrep scan that returns test threats."""
        try:
            # Create a few mock threats for testing
            mock_threats = []

            # Add a mock high-severity threat
            mock_threats.append(
                ThreatMatch.create_semgrep_threat(
                    rule_id="mock.security.hardcoded-password",
                    rule_name="Hardcoded Password",
                    description="Found hardcoded password in source code",
                    category="secrets",
                    severity="high",
                    file_path=str(request.context.target_path),
                    line_number=10,
                    column_number=5,
                    code_snippet='password = "secret123"',
                    cwe_id="CWE-798",
                    owasp_category="A02:2021 - Cryptographic Failures",
                )
            )

            # Add a mock medium-severity threat
            mock_threats.append(
                ThreatMatch.create_semgrep_threat(
                    rule_id="mock.security.sql-injection",
                    rule_name="Potential SQL Injection",
                    description="Potential SQL injection vulnerability detected",
                    category="injection",
                    severity="medium",
                    file_path=str(request.context.target_path),
                    line_number=25,
                    column_number=10,
                    code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 - Injection",
                )
            )

            # Add a mock low-severity threat
            mock_threats.append(
                ThreatMatch.create_semgrep_threat(
                    rule_id="mock.security.weak-hash",
                    rule_name="Weak Hash Algorithm",
                    description="Use of weak hash algorithm MD5 detected",
                    category="crypto",
                    severity="low",
                    file_path=str(request.context.target_path),
                    line_number=35,
                    column_number=15,
                    code_snippet="hashlib.md5(data.encode()).hexdigest()",
                    cwe_id="CWE-327",
                    owasp_category="A02:2021 - Cryptographic Failures",
                )
            )

            # Create scan result
            result = ScanResult.create_from_threats(
                request=request,
                threats=mock_threats,
                scan_metadata={
                    "scanner": "mock_semgrep",
                    "scan_duration_ms": 150,  # Mock fast execution
                    "rules_executed": 10,
                    "files_scanned": 1,
                    "mock_adapter": True,
                },
            )

            return result

        except Exception as e:
            raise ScanError(f"Mock Semgrep scan failed: {e}")
