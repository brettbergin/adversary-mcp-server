"""Adapter for SemgrepScanner to implement domain IScanStrategy interface."""

import json
import subprocess
import time
from pathlib import Path

from adversary_mcp_server.application.adapters.input_models import (
    SemgrepScanResultInput,
    safe_convert_to_input_model,
)
from adversary_mcp_server.credentials import get_credential_manager
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import (
    ThreatMatch as DomainThreatMatch,
)
from adversary_mcp_server.domain.interfaces import IScanStrategy, ScanError
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel
from adversary_mcp_server.logger import get_logger
from adversary_mcp_server.scanner.language_mapping import LanguageMapper
from adversary_mcp_server.scanner.semgrep_scanner import SemgrepScanner
from adversary_mcp_server.scanner.types import ThreatMatch as InfraThreatMatch


class SemgrepScanStrategy(IScanStrategy):
    """
    Adapter that wraps SemgrepScanner to implement the domain IScanStrategy interface.

    This adapter bridges the gap between the existing infrastructure-layer SemgrepScanner
    and the domain-layer scan strategy interface, enabling the domain layer to use
    Semgrep scanning without depending on infrastructure details.
    """

    def __init__(self, semgrep_scanner: SemgrepScanner | None = None):
        """Initialize the adapter with an optional SemgrepScanner instance."""
        if semgrep_scanner:
            self._scanner = semgrep_scanner
        else:
            # Detect Semgrep API key configuration and use appropriate ruleset
            try:
                credential_manager = get_credential_manager()
                semgrep_api_key = credential_manager.get_semgrep_api_key()

                if semgrep_api_key:
                    # User has Pro subscription - use auto config for Pro rules
                    config = "auto"
                    get_logger(__name__).info(
                        "Semgrep API key detected - using Pro ruleset with config='auto'"
                    )
                else:
                    # No API key - use community rules
                    config = "p/security-audit"
                    get_logger(__name__).info(
                        "No Semgrep API key detected - using community ruleset with config='p/security-audit'"
                    )

                self._scanner = SemgrepScanner(config=config)

            except Exception as e:
                # Fallback to community rules if credential detection fails
                get_logger(__name__).warning(
                    f"Failed to detect Semgrep API key configuration: {e}"
                )
                get_logger(__name__).info(
                    "Falling back to community ruleset with config='p/security-audit'"
                )
                self._scanner = SemgrepScanner(config="p/security-audit")

    def get_strategy_name(self) -> str:
        """Get the name of this scan strategy."""
        return "semgrep_static_analysis"

    def can_scan(self, context: ScanContext) -> bool:
        """
        Check if this strategy can scan the given context.

        Semgrep can scan files, directories, and code snippets.
        """
        # Semgrep can handle all scan types
        if context.metadata.scan_type in ["file", "directory", "code", "diff"]:
            return True

        return False

    def get_supported_languages(self) -> list[str]:
        """Get list of programming languages supported by Semgrep."""
        return LanguageMapper.get_supported_languages()

    async def execute_scan(self, request: ScanRequest) -> ScanResult:
        """
        Execute Semgrep scan using the domain request and return domain result.

        This method coordinates between domain and infrastructure layers:
        1. Converts domain request to infrastructure parameters
        2. Executes infrastructure scan
        3. Converts infrastructure results to domain objects
        """
        try:
            context = request.context
            scan_type = context.metadata.scan_type

            # Start timing the scan execution
            start_time = time.time()

            # Convert domain objects to infrastructure parameters
            semgrep_results = []
            lines_analyzed = 0

            if scan_type == "file":
                # File scan
                file_path = str(context.target_path)
                language = (
                    context.language
                    or LanguageMapper.detect_language_from_extension(file_path)
                )
                semgrep_results = await self._scan_file(file_path, language)
                lines_analyzed = self._count_lines_in_file(file_path)

            elif scan_type == "directory":
                # Directory scan
                dir_path = str(context.target_path)
                semgrep_results = await self._scan_directory(dir_path)
                lines_analyzed = self._count_lines_in_directory(dir_path)

            elif scan_type == "code":
                # Code snippet scan
                code_content = context.content or ""
                language = context.language or "generic"
                semgrep_results = await self._scan_code(code_content, language)
                lines_analyzed = len(code_content.splitlines()) if code_content else 0

            elif scan_type == "diff":
                # Diff scan - requires special handling
                # For now, treat as file scan of the target
                file_path = str(context.target_path)
                language = (
                    context.language
                    or LanguageMapper.detect_language_from_extension(file_path)
                )
                semgrep_results = await self._scan_file(file_path, language)
                lines_analyzed = self._count_lines_in_file(file_path)

            # Calculate scan duration
            scan_duration_ms = int((time.time() - start_time) * 1000)

            # Convert infrastructure results to domain objects
            domain_threats = self._convert_to_domain_threats(semgrep_results, request)

            # Apply severity filtering
            filtered_threats = self._apply_severity_filter(
                domain_threats, request.severity_threshold
            )

            # Get actual semgrep metadata
            semgrep_version = await self._get_semgrep_version()
            rules_count = await self._get_rules_count()

            # Create scan metadata with validation
            scan_metadata = {
                "scanner": self.get_strategy_name(),
                "rules_count": rules_count,
                "scan_duration_ms": scan_duration_ms,
                "semgrep_version": semgrep_version,
                "lines_analyzed": lines_analyzed,
                "scan_id": request.context.metadata.scan_id,
            }

            # Validate metrics
            self._validate_scan_metadata(scan_metadata)

            # Create domain scan result
            return ScanResult.create_from_threats(
                request=request,
                threats=filtered_threats,
                scan_metadata=scan_metadata,
            )

        except Exception as e:
            # Convert infrastructure exceptions to domain exceptions
            raise ScanError(f"Semgrep scan failed: {str(e)}") from e

    async def _scan_file(self, file_path: str, language: str) -> list[InfraThreatMatch]:
        """Execute Semgrep file scan."""
        return await self._scanner.scan_file(file_path, language)

    async def _scan_directory(self, dir_path: str) -> list[InfraThreatMatch]:
        """Execute Semgrep directory scan."""
        return await self._scanner.scan_directory(dir_path)

    async def _scan_code(
        self, code_content: str, language: str
    ) -> list[InfraThreatMatch]:
        """Execute Semgrep code scan."""
        return await self._scanner.scan_code(code_content, language)

    def _convert_to_domain_threats(
        self, semgrep_results: list[InfraThreatMatch], request: ScanRequest
    ) -> list[DomainThreatMatch]:
        """Convert Semgrep ThreatMatch objects to domain ThreatMatch objects."""
        domain_threats = []

        for threat in semgrep_results:
            try:
                # The Semgrep scanner already returns ThreatMatch objects, but we need to convert
                # them to domain objects with proper domain value objects

                # Convert file path to domain value object
                file_path = FilePath.from_string(str(threat.file_path))

                # Convert infrastructure severity to domain severity
                domain_severity = self._map_infrastructure_severity_to_domain(
                    threat.severity
                )

                # Create domain threat match
                domain_threat = DomainThreatMatch(
                    rule_id=threat.rule_id,
                    rule_name=threat.rule_name,
                    description=threat.description,
                    category=(
                        threat.category.value
                        if hasattr(threat.category, "value")
                        else str(threat.category)
                    ),
                    severity=domain_severity,
                    file_path=file_path,
                    line_number=threat.line_number,
                    column_number=getattr(threat, "column_number", 0),
                    code_snippet=threat.code_snippet,
                    confidence=ConfidenceScore(threat.confidence),
                    source_scanner="semgrep",
                    # Map additional fields from scanner result
                    cwe_id=getattr(threat, "cwe_id", None),
                    owasp_category=getattr(threat, "owasp_category", None),
                    references=getattr(threat, "references", []),
                    function_name=getattr(threat, "function_name", None),
                    exploit_examples=getattr(threat, "exploit_examples", []),
                    remediation=(
                        str(getattr(threat, "remediation", ""))
                        if getattr(threat, "remediation", None)
                        else ""
                    ),
                    is_false_positive=getattr(threat, "is_false_positive", False),
                )

                domain_threats.append(domain_threat)

            except Exception as e:
                # Log conversion error but continue processing other results
                get_logger(__name__).warning(
                    f"Failed to convert infrastructure threat to domain threat: {e}"
                )
                continue

        return domain_threats

    def _convert_legacy_threat_to_domain(self, legacy_threat) -> DomainThreatMatch:
        """Convert a single legacy ThreatMatch to domain ThreatMatch using type-safe input models."""
        # Convert to type-safe input model to avoid getattr/hasattr calls
        input_threat = safe_convert_to_input_model(
            legacy_threat, SemgrepScanResultInput
        )

        # Map scanner severity to domain severity
        severity = self._map_scanner_severity(input_threat.severity)

        # Convert file path
        file_path = FilePath.from_string(str(input_threat.file_path))

        # Create domain threat with type-safe access
        return DomainThreatMatch(
            rule_id=input_threat.rule_id,
            rule_name=input_threat.rule_name,
            description=input_threat.description,
            category=input_threat.category,
            severity=severity,
            file_path=file_path,
            line_number=input_threat.line_number,
            column_number=input_threat.column_number,
            code_snippet=input_threat.code_snippet,
            function_name=input_threat.function_name,
            exploit_examples=input_threat.exploit_examples,
            remediation=input_threat.remediation,
            references=input_threat.references,
            cwe_id=input_threat.cwe_id,
            owasp_category=input_threat.owasp_category,
            confidence=ConfidenceScore(input_threat.confidence),
            source_scanner="semgrep",
            is_false_positive=input_threat.is_false_positive,
        )

    def _map_severity(self, semgrep_severity: str) -> SeverityLevel:
        """Map Semgrep severity to domain SeverityLevel."""
        severity_mapping = {
            "error": "critical",
            "warning": "high",
            "info": "medium",
            "note": "low",
        }

        domain_severity = severity_mapping.get(semgrep_severity.lower(), "medium")
        return SeverityLevel.from_string(domain_severity)

    def _map_scanner_severity(self, scanner_severity: str) -> SeverityLevel:
        """Map scanner severity enum values to domain SeverityLevel."""
        # The scanner returns severity enum values like 'severity.critical', 'severity.high', etc.
        # Strip the 'severity.' prefix if present
        severity_str = scanner_severity.replace("severity.", "").lower()
        return SeverityLevel.from_string(severity_str)

    def _determine_category(self, result: dict) -> str:
        """Determine threat category from Semgrep result."""
        # Extract category from rule metadata
        rule_id = result.get("check_id", "").lower()

        # Common category mappings
        if "injection" in rule_id or "sqli" in rule_id:
            return "injection"
        elif "xss" in rule_id:
            return "xss"
        elif "crypto" in rule_id or "hash" in rule_id:
            return "cryptography"
        elif "auth" in rule_id or "session" in rule_id:
            return "authentication"
        elif "path" in rule_id or "traversal" in rule_id:
            return "path_traversal"
        elif "disclosure" in rule_id or "leak" in rule_id:
            return "information_disclosure"
        else:
            return "security"

    def _map_infrastructure_severity_to_domain(self, infra_severity) -> SeverityLevel:
        """Map infrastructure severity to domain SeverityLevel."""
        # Handle both enum and string values
        if hasattr(infra_severity, "value"):
            severity_str = infra_severity.value.lower()
        else:
            severity_str = str(infra_severity).lower()

        # Map common severity values
        if severity_str in ["critical"]:
            return SeverityLevel.from_string("critical")
        elif severity_str in ["high"]:
            return SeverityLevel.from_string("high")
        elif severity_str in ["medium", "warning"]:
            return SeverityLevel.from_string("medium")
        elif severity_str in ["low", "info"]:
            return SeverityLevel.from_string("low")
        else:
            # Default to medium for unknown severities
            return SeverityLevel.from_string("medium")

    def _apply_severity_filter(
        self, threats: list[DomainThreatMatch], threshold: SeverityLevel | None
    ) -> list[DomainThreatMatch]:
        """Filter threats based on severity threshold."""
        if threshold is None:
            return threats

        return [
            threat for threat in threats if threat.severity.meets_threshold(threshold)
        ]

    def _count_lines_in_file(self, file_path: str) -> int:
        """Count lines in a single file."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                return sum(1 for _ in f)
        except (OSError, UnicodeDecodeError) as e:
            get_logger(__name__).debug(f"Could not count lines in {file_path}: {e}")
            return 0

    def _count_lines_in_directory(self, dir_path: str) -> int:
        """Count lines in all supported files in a directory."""
        total_lines = 0
        supported_extensions = LanguageMapper.get_supported_extensions()

        try:
            for file_path in Path(dir_path).rglob("*"):
                if (
                    file_path.is_file()
                    and file_path.suffix.lower() in supported_extensions
                ):
                    total_lines += self._count_lines_in_file(str(file_path))
        except Exception as e:
            get_logger(__name__).debug(
                f"Could not count lines in directory {dir_path}: {e}"
            )

        return total_lines

    async def _get_semgrep_version(self) -> str:
        """Get the actual semgrep version."""
        try:
            # Try to get version from semgrep command
            result = subprocess.run(
                ["semgrep", "--version"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return "unknown"
        except (
            subprocess.TimeoutExpired,
            FileNotFoundError,
            subprocess.SubprocessError,
        ):
            # Fallback to checking if semgrep is available
            return getattr(self._scanner, "_version", "unknown")

    async def _get_rules_count(self) -> int:
        """Get the number of rules available to semgrep."""
        try:
            # Try to get rules count from scanner's pro status
            if hasattr(self._scanner, "_pro_status") and self._scanner._pro_status:
                rules_available = self._scanner._pro_status.get("rules_available")
                if rules_available is not None:
                    return rules_available

            # Fallback: Try to run semgrep with --dump-config to count rules
            config = getattr(self._scanner, "config", "p/security-audit")
            result = subprocess.run(
                ["semgrep", f"--config={config}", "--dump-config"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                try:
                    config_data = json.loads(result.stdout)
                    if isinstance(config_data, dict) and "rules" in config_data:
                        return len(config_data["rules"])
                except (json.JSONDecodeError, KeyError):
                    pass

            return getattr(self._scanner, "_rules_count", 0)
        except (
            subprocess.TimeoutExpired,
            FileNotFoundError,
            subprocess.SubprocessError,
        ):
            return getattr(self._scanner, "_rules_count", 0)

    def _validate_scan_metadata(self, metadata: dict) -> None:
        """Validate that scan metadata contains proper values."""
        logger = get_logger(__name__)

        # Validate semgrep version
        if metadata.get("semgrep_version") == "unknown":
            logger.warning("Semgrep version could not be determined")

        # Validate rules count
        rules_count = metadata.get("rules_count", 0)
        if rules_count == 0:
            logger.warning(
                "No Semgrep rules detected - this may indicate a configuration issue"
            )
        elif rules_count < 10:
            logger.info(
                f"Low rules count detected: {rules_count} - consider using more comprehensive rulesets"
            )

        # Validate scan duration
        scan_duration_ms = metadata.get("scan_duration_ms", 0)
        if scan_duration_ms == 0:
            logger.warning(
                "Scan duration is 0ms - this may indicate timing measurement failure"
            )
        elif scan_duration_ms > 300000:  # 5 minutes
            logger.warning(f"Scan took unusually long: {scan_duration_ms}ms")

        # Validate lines analyzed
        lines_analyzed = metadata.get("lines_analyzed", 0)
        if lines_analyzed == 0:
            logger.info(
                "No lines were analyzed - target may be empty or unsupported file types"
            )

        # Log successful validation
        logger.debug(f"Scan metadata validation passed: {metadata}")
