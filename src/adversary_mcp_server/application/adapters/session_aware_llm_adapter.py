"""Session-aware LLM adapter for Clean Architecture integration."""

from pathlib import Path
from typing import Any

from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import (
    ThreatMatch as DomainThreatMatch,
)
from adversary_mcp_server.domain.interfaces import IScanStrategy, ScanError
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel
from adversary_mcp_server.logger import get_logger
from adversary_mcp_server.scanner.session_aware_llm_scanner import (
    SessionAwareLLMScanner,
)

logger = get_logger("session_aware_llm_adapter")


class SessionAwareLLMScanStrategy(IScanStrategy):
    """
    Enhanced LLM scan strategy using session-aware context management.

    This adapter bridges the domain layer with the new session-aware LLM scanner,
    enabling context-aware security analysis while maintaining Clean Architecture principles.
    """

    def __init__(self, scanner: SessionAwareLLMScanner | None = None):
        """Initialize with optional scanner instance."""
        if scanner:
            self._scanner = scanner
        else:
            # Try to initialize with default dependencies
            try:
                from adversary_mcp_server.credentials import get_credential_manager

                credential_manager = get_credential_manager()
                self._scanner = SessionAwareLLMScanner(credential_manager)
            except Exception as e:
                logger.warning(f"Could not initialize SessionAwareLLMScanner: {e}")
                self._scanner = None

    def get_strategy_name(self) -> str:
        """Get the name of this scan strategy."""
        return "session_aware_llm_analysis"

    def can_scan(self, context: ScanContext) -> bool:
        """Check if this strategy can scan the given context."""
        # Check if scanner is available
        if self._scanner is None or not self._scanner.is_available():
            return False

        # Session-aware scanner can handle all scan types with context
        return context.metadata.scan_type in ["file", "directory", "code", "diff"]

    def get_supported_languages(self) -> list[str]:
        """Get list of supported languages from language mapper."""
        from adversary_mcp_server.scanner.language_mapping import LanguageMapper

        # Session-aware scanner supports all languages that the mapper recognizes
        return LanguageMapper.get_supported_languages()

    async def execute_scan(self, request: ScanRequest) -> ScanResult:
        """Execute session-aware LLM scan."""
        if self._scanner is None:
            return ScanResult.create_empty(request)

        try:
            context = request.context
            scan_type = context.metadata.scan_type

            # Execute different analysis based on scan type
            threat_matches = []

            if scan_type == "file":
                threat_matches = await self._analyze_file_with_context(request)
            elif scan_type == "directory":
                threat_matches = await self._analyze_directory_with_context(request)
            elif scan_type == "code":
                threat_matches = await self._analyze_code_with_context(request)
            elif scan_type == "diff":
                threat_matches = await self._analyze_diff_with_context(request)

            # Convert to domain objects and apply filtering
            domain_threats = self._convert_to_domain_threats(threat_matches, request)
            filtered_threats = self._apply_severity_filter(
                domain_threats, request.severity_threshold
            )

            # Apply confidence filtering
            confidence_threshold = ConfidenceScore(
                0.6
            )  # Higher threshold for session-aware analysis
            high_confidence_threats = [
                threat
                for threat in filtered_threats
                if threat.confidence.meets_threshold(confidence_threshold)
            ]

            # Create comprehensive scan result
            return ScanResult.create_from_threats(
                request=request,
                threats=high_confidence_threats,
                scan_metadata={
                    "scanner": self.get_strategy_name(),
                    "analysis_type": "session_aware_ai",
                    "context_loaded": True,
                    "total_findings": len(threat_matches),
                    "filtered_findings": len(high_confidence_threats),
                    "confidence_threshold": confidence_threshold.get_percentage(),
                    "cross_file_analysis": scan_type in ["directory", "diff"],
                },
            )

        except Exception as e:
            raise ScanError(f"Session-aware LLM scan failed: {str(e)}") from e

    async def _analyze_file_with_context(self, request: ScanRequest) -> list[Any]:
        """Analyze single file with project context."""
        file_path = Path(request.context.target_path)

        # Try to determine project root from file path
        project_root = self._find_project_root(file_path)

        # Create context hint based on scan parameters
        context_hint = self._create_context_hint(request)

        return await self._scanner.analyze_file_with_context(
            file_path=file_path,
            project_root=project_root,
            context_hint=context_hint,
        )

    async def _analyze_directory_with_context(self, request: ScanRequest) -> list[Any]:
        """Analyze directory with full project context."""
        project_root = Path(request.context.target_path)

        # For directory scans, analyze all relevant files
        target_files = None
        if hasattr(request.context, "target_files") and request.context.target_files:
            target_files = [Path(f) for f in request.context.target_files]

        analysis_focus = self._create_analysis_focus(request)

        return await self._scanner.analyze_project_with_session(
            project_root=project_root,
            target_files=target_files,
            analysis_focus=analysis_focus,
        )

    async def _analyze_code_with_context(self, request: ScanRequest) -> list[Any]:
        """Analyze code snippet with minimal context."""
        code_content = request.context.content or ""
        language = request.context.language or "generic"

        # Use target path as file name if available
        file_name = "code_snippet"
        if request.context.target_path:
            file_name = Path(request.context.target_path).name

        context_hint = self._create_context_hint(request)

        return await self._scanner.analyze_code_with_context(
            code_content=code_content,
            language=language,
            file_name=file_name,
            context_hint=context_hint,
        )

    async def _analyze_diff_with_context(self, request: ScanRequest) -> list[Any]:
        """Analyze git diff with change context."""
        file_path = Path(request.context.target_path)
        project_root = self._find_project_root(file_path)

        # For diff analysis, focus on the changed code
        context_hint = (
            f"Focus on security implications of recent changes. "
            f"Look for vulnerabilities introduced or security controls removed. "
            f"{self._create_context_hint(request)}"
        )

        return await self._scanner.analyze_file_with_context(
            file_path=file_path,
            project_root=project_root,
            context_hint=context_hint,
        )

    def _find_project_root(self, file_path: Path) -> Path:
        """Find the project root directory using centralized detection."""
        from adversary_mcp_server.scanner.language_mapping import LanguageMapper

        return LanguageMapper.find_project_root(file_path)

    def _create_context_hint(self, request: ScanRequest) -> str:
        """Create context hint based on scan request."""
        hints = []

        # Add language-specific hints using centralized mapping
        if request.context.language:
            from adversary_mcp_server.scanner.language_mapping import LanguageMapper

            language_hint = LanguageMapper.get_security_analysis_hints(
                request.context.language
            )
            hints.append(language_hint)

        # Add severity-based hints
        if request.severity_threshold:
            severity_str = str(request.severity_threshold)
            if severity_str in ["high", "critical"]:
                hints.append(
                    "Focus on high-impact vulnerabilities that could lead to system compromise"
                )
            elif severity_str == "medium":
                hints.append("Look for both high and medium severity vulnerabilities")

        # Add scan type hints
        scan_type = request.context.metadata.scan_type
        if scan_type == "directory":
            hints.append(
                "Perform comprehensive analysis including cross-file interactions"
            )
        elif scan_type == "diff":
            hints.append("Focus on security implications of code changes")

        return ". ".join(hints) if hints else "Perform comprehensive security analysis"

    def _create_analysis_focus(self, request: ScanRequest) -> str:
        """Create analysis focus description for project-wide scans."""
        focus_parts = ["comprehensive security analysis"]

        # Add specific focus based on context
        if request.context.language:
            focus_parts.append(
                f"with emphasis on {request.context.language} security patterns"
            )

        if request.severity_threshold and str(request.severity_threshold) in [
            "high",
            "critical",
        ]:
            focus_parts.append("prioritizing high-impact vulnerabilities")

        return " ".join(focus_parts)

    def _convert_to_domain_threats(
        self, threat_matches: list[Any], request: ScanRequest
    ) -> list[DomainThreatMatch]:
        """Convert scanner results to domain threats."""

        enhanced_threats = []
        for threat in threat_matches:
            # If it's already a domain threat, add metadata
            if hasattr(threat, "add_metadata"):
                enhanced_threat = threat.add_metadata(
                    {
                        "scan_request_id": id(
                            request
                        ),  # Use object id as unique identifier
                        "scan_timestamp": request.context.metadata.timestamp,
                        "scan_type": request.context.metadata.scan_type,
                        "session_aware": True,
                        "context_loaded": True,
                        "cross_file_references": getattr(
                            threat, "cross_file_references", []
                        ),
                        "architectural_context": getattr(
                            threat, "architectural_context", ""
                        ),
                    }
                )
            else:
                # Convert scanner ThreatMatch to domain ThreatMatch
                enhanced_threat = DomainThreatMatch.create_llm_threat(
                    rule_id=threat.rule_id,
                    rule_name=threat.rule_name,
                    description=threat.description,
                    category=(
                        threat.category.value
                        if hasattr(threat.category, "value")
                        else str(threat.category)
                    ),
                    severity=(
                        threat.severity.value
                        if hasattr(threat.severity, "value")
                        else str(threat.severity)
                    ),
                    file_path=threat.file_path,
                    line_number=threat.line_number,
                    confidence=threat.confidence,
                    code_snippet=getattr(threat, "code_snippet", ""),
                    column_number=getattr(threat, "column_number", 0),
                    function_name=getattr(threat, "function_name", None),
                    remediation=getattr(threat, "remediation", ""),
                    cwe_id=getattr(threat, "cwe_id", None),
                    owasp_category=getattr(threat, "owasp_category", None),
                ).add_metadata(
                    {
                        "scan_request_id": id(
                            request
                        ),  # Use object id as unique identifier
                        "scan_timestamp": request.context.metadata.timestamp,
                        "scan_type": request.context.metadata.scan_type,
                        "session_aware": True,
                        "context_loaded": True,
                    }
                )

            enhanced_threats.append(enhanced_threat)

        return enhanced_threats

    def _apply_severity_filter(
        self,
        threats: list[DomainThreatMatch],
        severity_threshold: SeverityLevel | None,
    ) -> list[DomainThreatMatch]:
        """Apply severity filtering to threats."""
        if not severity_threshold:
            return threats

        return [
            threat
            for threat in threats
            if threat.severity.meets_threshold(severity_threshold)
        ]
