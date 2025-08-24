"""Adapter for LLMScanner to implement domain IScanStrategy interface."""

import asyncio
import time
from pathlib import Path
from typing import Any

from adversary_mcp_server.application.adapters.input_models import (
    LLMScanResultInput,
    safe_convert_to_input_model,
)
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.interfaces import IScanStrategy, ScanError
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel
from adversary_mcp_server.logger import get_logger
from adversary_mcp_server.scanner.language_mapping import LanguageMapper
from adversary_mcp_server.scanner.llm_scanner import LLMScanner

logger = get_logger("llm_adapter")


class LLMScanStrategy(IScanStrategy):
    """
    Adapter that wraps LLMScanner to implement the domain IScanStrategy interface.

    This adapter enables the domain layer to use LLM-powered security analysis
    while maintaining clean separation between domain logic and infrastructure concerns.

    Features session-aware analysis when available for enhanced context and
    cross-file vulnerability detection.
    """

    def __init__(
        self, llm_scanner: LLMScanner | None = None, enable_sessions: bool = True
    ):
        """Initialize the adapter with an optional LLMScanner instance.

        Args:
            llm_scanner: Pre-configured LLMScanner instance (optional)
            enable_sessions: Enable session-aware analysis capabilities
        """
        self.enable_sessions = enable_sessions

        if llm_scanner:
            self._scanner = llm_scanner
        else:
            # Try to initialize with default dependencies
            try:
                from adversary_mcp_server.credentials import get_credential_manager

                credential_manager = get_credential_manager()
                self._scanner = LLMScanner(
                    credential_manager, enable_sessions=enable_sessions
                )
            except Exception as e:
                logger.warning(f"Could not initialize LLMScanner: {e}")
                self._scanner = None

    def get_strategy_name(self) -> str:
        """Get the name of this scan strategy."""
        base_name = "llm_ai_analysis"
        if self._scanner and self._scanner.is_session_aware_available():
            return f"{base_name}_session_aware"
        return base_name

    def can_scan(self, context: ScanContext) -> bool:
        """
        Check if this strategy can scan the given context.

        LLM scanner can analyze files, directories, and code snippets when enabled.
        """
        # Check if scanner is available
        if self._scanner is None:
            return False

        # LLM can handle most scan types, but may have size limitations
        if context.metadata.scan_type in [
            "file",
            "directory",
            "code",
            "diff",
            "incremental",
        ]:
            # Check content size constraints for code scans
            if context.content and len(context.content) > 50000:  # 50KB limit
                return False
            return True

        return False

    def get_supported_languages(self) -> list[str]:
        """Get list of programming languages supported by LLM analysis."""
        return LanguageMapper.get_supported_languages()

    async def execute_scan(self, request: ScanRequest) -> ScanResult:
        """
        Execute LLM scan using the domain request and return domain result.

        This method coordinates between domain and infrastructure layers:
        1. Converts domain request to LLM analysis parameters
        2. Executes LLM analysis
        3. Converts LLM results to domain objects
        """
        print("******* LLM ADAPTER execute_scan called *******")
        if self._scanner is None:
            # Return empty result if scanner not available
            return ScanResult.create_empty(request)

        scan_start_time = time.time()
        try:
            context = request.context
            scan_type = context.metadata.scan_type

            logger.info(
                f"Starting LLM scan - Type: {scan_type}, Target: {context.target_path}"
            )

            # Convert domain objects to infrastructure parameters
            llm_results = []

            # Use session-aware analysis when available and project context is provided
            session_available = (
                self._scanner.is_session_aware_available() if self._scanner else False
            )
            has_project_context = self._has_project_context(context)

            logger.error(
                f"[DEBUG] Session analysis check - Available: {session_available}, "
                f"Scan type: {scan_type}, Has context: {has_project_context}"
            )

            use_session_analysis = (
                session_available
                and scan_type in ["file", "directory"]
                and has_project_context
            )

            if use_session_analysis:
                logger.error(
                    f"[DEBUG] Using session-aware analysis for {scan_type} scan"
                )
                try:
                    llm_results = await self._analyze_with_session(context)
                    logger.error(
                        f"[DEBUG] Session analysis completed with {len(llm_results)} results"
                    )
                except Exception as e:
                    logger.error(
                        f"Session analysis failed, falling back to legacy: {e}"
                    )
                    use_session_analysis = False

            if not use_session_analysis or not llm_results:
                # Fall back to legacy analysis methods
                logger.info(f"Using legacy analysis for {scan_type} scan")
                if scan_type == "file":
                    # File analysis - use content from context if available, otherwise read file
                    if context.content:
                        llm_results = await self._analyze_code(
                            context.content, context.language
                        )
                    else:
                        file_path = str(context.target_path)
                        llm_results = await self._analyze_file(
                            file_path, context.language
                        )

                elif scan_type == "directory":
                    # Directory analysis
                    dir_path = str(context.target_path)
                    llm_results = await self._analyze_directory(dir_path)

                elif scan_type == "code":
                    # Code snippet analysis
                    code_content = context.content or ""
                    llm_results = await self._analyze_code(
                        code_content, context.language
                    )

                elif scan_type == "diff":
                    # Diff analysis - analyze the target file with diff context
                    file_path = str(context.target_path)
                    llm_results = await self._analyze_file(file_path, context.language)

                logger.info(
                    f"Legacy analysis completed with {len(llm_results)} results"
                )

            # Convert infrastructure results to domain objects
            domain_threats = self._convert_to_domain_threats(llm_results, request)

            # Apply severity filtering
            filtered_threats = self._apply_severity_filter(
                domain_threats, request.severity_threshold
            )

            # Apply confidence filtering
            confidence_threshold = ConfidenceScore(
                0.5
            )  # Default LLM confidence threshold
            high_confidence_threats = [
                threat
                for threat in filtered_threats
                if threat.confidence.meets_threshold(confidence_threshold)
            ]

            # Create domain scan result with performance metrics
            analysis_type = "ai_powered"
            if self._scanner and self._scanner.is_session_aware_available():
                analysis_type = "session_aware_ai"

            scan_duration = time.time() - scan_start_time

            logger.info(
                f"LLM scan completed - Duration: {scan_duration:.2f}s, "
                f"Total findings: {len(llm_results)}, "
                f"High-confidence findings: {len(high_confidence_threats)}, "
                f"Analysis type: {analysis_type}"
            )

            return ScanResult.create_from_threats(
                request=request,
                threats=high_confidence_threats,
                scan_metadata={
                    "scanner": self.get_strategy_name(),
                    "analysis_type": analysis_type,
                    "total_findings": len(llm_results),
                    "filtered_findings": len(high_confidence_threats),
                    "confidence_threshold": confidence_threshold.get_percentage(),
                    "session_aware": (
                        self._scanner.is_session_aware_available()
                        if self._scanner
                        else False
                    ),
                    "scan_duration_seconds": round(scan_duration, 2),
                    "findings_per_second": round(
                        len(llm_results) / max(scan_duration, 0.01), 2
                    ),
                },
            )

        except Exception as e:
            # Log performance metrics even on failure
            scan_duration = time.time() - scan_start_time
            logger.error(
                f"LLM scan failed after {scan_duration:.2f}s - Error: {str(e)}"
            )
            # Convert infrastructure exceptions to domain exceptions
            raise ScanError(f"LLM scan failed: {str(e)}") from e

    async def _analyze_file(
        self, file_path: str, language: str | None = None
    ) -> list[dict[str, Any]]:
        """Execute LLM file analysis."""
        # LLMScanner.analyze_file is async, so call it directly
        findings = await self._scanner.analyze_file(file_path, language or "")
        return [self._finding_to_dict(finding) for finding in findings]

    async def _analyze_directory(self, dir_path: str) -> list[dict[str, Any]]:
        """Execute LLM directory analysis."""
        # LLMScanner.analyze_directory is async, so call it directly
        findings = await self._scanner.analyze_directory(dir_path)
        return [self._finding_to_dict(finding) for finding in findings]

    async def _analyze_code(
        self, code_content: str, language: str | None = None
    ) -> list[dict[str, Any]]:
        """Execute LLM code analysis."""
        # LLMScanner.analyze_code is sync, so use executor
        loop = asyncio.get_event_loop()
        findings = await loop.run_in_executor(
            None,
            lambda: self._scanner.analyze_code(code_content, "<code>", language or ""),
        )
        return [self._finding_to_dict(finding) for finding in findings]

    async def _analyze_with_session(self, context: ScanContext) -> list[dict[str, Any]]:
        """Execute session-aware analysis when available."""
        scan_type = context.metadata.scan_type

        if scan_type == "file":
            # Use session-aware file analysis
            file_path = Path(context.target_path)
            project_root = self._find_project_root(file_path)
            context_hint = getattr(context.metadata, "analysis_focus", None)

            findings = await self._scanner.analyze_file_with_context(
                file_path=file_path,
                project_root=project_root,
                context_hint=context_hint,
                max_findings=None,
            )

        elif scan_type == "directory":
            # Use session-aware project analysis
            project_root = Path(context.target_path)
            analysis_focus = getattr(
                context.metadata, "analysis_focus", "comprehensive security analysis"
            )

            findings = await self._scanner.analyze_project_with_session(
                project_root=project_root,
                analysis_focus=analysis_focus,
                max_findings=None,
            )

        elif scan_type == "incremental":
            # Use incremental analysis for changed files
            if hasattr(context.metadata, "changed_files") and hasattr(
                context.metadata, "session_id"
            ):
                changed_files = [Path(f) for f in context.metadata.changed_files]
                commit_hash = getattr(context.metadata, "commit_hash", None)
                change_context = getattr(context.metadata, "change_context", None)

                if self._scanner.session_manager:
                    findings = await self._scanner.session_manager.analyze_changes_incrementally(
                        session_id=context.metadata.session_id,
                        changed_files=changed_files,
                        commit_hash=commit_hash,
                        change_context=change_context,
                    )
                else:
                    logger.warning(
                        "Session manager not available for incremental analysis"
                    )
                    return []
            else:
                logger.warning(
                    "Incremental analysis requires changed_files and session_id metadata"
                )
                return []

        else:
            # Fallback to legacy analysis
            logger.warning(
                f"Session-aware analysis not supported for scan type: {scan_type}"
            )
            return []

        return [self._finding_to_dict(finding) for finding in findings]

    def _has_project_context(self, context: ScanContext) -> bool:
        """Check if the context has sufficient information for session-aware analysis."""
        # Check if target path exists and looks like it has project structure
        target_path = Path(context.target_path)

        if not target_path.exists():
            return False

        # For files, check if we can find a project root
        if context.metadata.scan_type == "file":
            project_root = self._find_project_root(target_path)
            return project_root != target_path.parent  # Found actual project indicators

        # For directories, assume they are project roots
        elif context.metadata.scan_type == "directory":
            return True

        return False

    def _find_project_root(self, file_path: Path) -> Path:
        """Find project root by looking for common project indicators."""
        current = file_path.parent if file_path.is_file() else file_path

        while current.parent != current:
            if any(
                (current / indicator).exists()
                for indicator in [
                    ".git",
                    "package.json",
                    "pyproject.toml",
                    "requirements.txt",
                    ".project",
                ]
            ):
                return current
            current = current.parent

        # Fallback to original directory
        return file_path.parent if file_path.is_file() else file_path

    def _finding_to_dict(self, finding) -> dict[str, Any]:
        """Convert LLMSecurityFinding to dictionary format."""
        return {
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "description": finding.description,
            "line_number": finding.line_number,
            "code_snippet": finding.code_snippet,
            "explanation": finding.explanation,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
        }

    def _convert_to_domain_threats(
        self, llm_results: list[dict[str, Any]], request: ScanRequest
    ) -> list[ThreatMatch]:
        """Convert LLM analysis results to domain ThreatMatch objects."""
        threats = []

        for result in llm_results:
            try:
                # Extract data from LLM result format
                rule_id = result.get("finding_id", f"llm_{len(threats) + 1}")
                rule_name = result.get("title", "AI-detected Security Issue")
                description = result.get(
                    "description", "Security vulnerability detected by AI analysis"
                )

                # Map LLM severity to domain severity
                llm_severity = result.get("severity", "medium")
                severity = self._map_severity(llm_severity)

                # Extract location information
                line_number = result.get("line_number", 1)
                column_number = result.get("column_number", 1)

                # Extract file path - use unique placeholder for missing paths
                file_path_str = result.get("file_path")
                if not file_path_str:
                    # For directory scans, generate unique placeholder instead of using directory path
                    if request.context.metadata.scan_type == "directory":
                        import uuid

                        placeholder_name = f"<unknown-file-{uuid.uuid4().hex[:8]}>"
                        logger.warning(
                            f"LLM finding missing file_path, using placeholder: {placeholder_name}"
                        )
                        file_path_str = placeholder_name
                    else:
                        # For file/code scans, fall back to target path
                        file_path_str = str(request.context.target_path)

                file_path = FilePath.from_string(file_path_str)

                # Validate that file_path is not a directory (unless it's a placeholder)
                if (
                    not file_path_str.startswith("<unknown-file-")
                    and file_path.exists()
                    and file_path.is_directory()
                ):
                    logger.warning(
                        f"Skipping LLM finding with directory path: {file_path_str}"
                    )
                    continue

                # Extract code snippet
                code_snippet = result.get("code_snippet", "")

                # Determine category from LLM analysis
                category = self._determine_category(result)

                # Extract confidence from LLM analysis
                confidence_score = result.get("confidence", 0.7)
                confidence = ConfidenceScore(min(1.0, max(0.0, confidence_score)))

                # Create domain threat
                threat = ThreatMatch(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    description=description,
                    category=category,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_number,
                    column_number=column_number,
                    code_snippet=code_snippet,
                    confidence=confidence,
                    source_scanner="llm",
                    metadata={
                        "llm_analysis": True,
                        "reasoning": result.get("reasoning", ""),
                        "remediation": result.get("remediation", ""),
                        "original_result": result,
                    },
                )

                # Add remediation advice if available
                if "remediation" in result:
                    threat = threat.add_remediation_advice(result["remediation"])

                threats.append(threat)

            except Exception as e:
                # Log conversion error but continue processing other results
                print(f"Warning: Failed to convert LLM result to domain threat: {e}")
                continue

        return threats

    def _convert_legacy_threat_to_domain(self, legacy_threat) -> ThreatMatch:
        """Convert a single legacy ThreatMatch to domain ThreatMatch using type-safe input models."""
        # Convert to type-safe input model to avoid getattr/hasattr calls
        input_threat = safe_convert_to_input_model(legacy_threat, LLMScanResultInput)

        # Map scanner severity to domain severity
        severity = SeverityLevel.from_string(input_threat.severity)

        # Convert file path
        file_path = FilePath.from_string(str(input_threat.file_path))

        logger.debug(
            f"[THREAT_MATCH_DEBUG] Creating ThreatMatch: rule_id='{input_threat.rule_id}', line_number={input_threat.line_number}"
        )

        # Create domain threat with type-safe access
        threat_match = ThreatMatch(
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
            source_scanner="llm",
            is_false_positive=input_threat.is_false_positive,
        )

        logger.debug(
            f"[THREAT_MATCH_DEBUG] Created ThreatMatch with fingerprint: {threat_match.get_fingerprint()}"
        )
        return threat_match

    def _map_severity(self, llm_severity: str) -> SeverityLevel:
        """Map LLM severity to domain SeverityLevel."""
        severity_mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "low",
            "warning": "medium",
            "error": "high",
        }

        domain_severity = severity_mapping.get(llm_severity.lower(), "medium")
        return SeverityLevel.from_string(domain_severity)

    def _determine_category(self, result: dict[str, Any]) -> str:
        """Determine threat category from LLM analysis result."""
        # Extract category from LLM analysis
        if "category" in result:
            return result["category"]

        # Infer category from description/title
        description = (
            result.get("description", "") + " " + result.get("title", "")
        ).lower()

        if any(keyword in description for keyword in ["injection", "sql", "command"]):
            return "injection"
        elif any(keyword in description for keyword in ["xss", "cross-site"]):
            return "xss"
        elif any(
            keyword in description for keyword in ["crypto", "encryption", "hash"]
        ):
            return "cryptography"
        elif any(keyword in description for keyword in ["auth", "session", "token"]):
            return "authentication"
        elif any(
            keyword in description for keyword in ["path", "traversal", "directory"]
        ):
            return "path_traversal"
        elif any(
            keyword in description for keyword in ["disclosure", "leak", "expose"]
        ):
            return "information_disclosure"
        elif any(
            keyword in description for keyword in ["buffer", "overflow", "memory"]
        ):
            return "memory_safety"
        elif any(keyword in description for keyword in ["dos", "denial", "resource"]):
            return "denial_of_service"
        else:
            return "security"

    def _apply_severity_filter(
        self, threats: list[ThreatMatch], threshold: SeverityLevel | None
    ) -> list[ThreatMatch]:
        """Filter threats based on severity threshold."""
        if threshold is None:
            return threats

        return [
            threat for threat in threats if threat.severity.meets_threshold(threshold)
        ]
