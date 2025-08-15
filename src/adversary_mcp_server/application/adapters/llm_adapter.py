"""Adapter for LLMScanner to implement domain IScanStrategy interface."""

import asyncio
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
    """

    def __init__(self, llm_scanner: LLMScanner | None = None):
        """Initialize the adapter with an optional LLMScanner instance."""
        if llm_scanner:
            self._scanner = llm_scanner
        else:
            # Try to initialize with default dependencies
            try:
                from adversary_mcp_server.credentials import get_credential_manager

                credential_manager = get_credential_manager()
                self._scanner = LLMScanner(credential_manager)
            except Exception as e:
                logger.warning(f"Could not initialize LLMScanner: {e}")
                self._scanner = None

    def get_strategy_name(self) -> str:
        """Get the name of this scan strategy."""
        return "llm_ai_analysis"

    def can_scan(self, context: ScanContext) -> bool:
        """
        Check if this strategy can scan the given context.

        LLM scanner can analyze files, directories, and code snippets when enabled.
        """
        # Check if scanner is available
        if self._scanner is None:
            return False

        # LLM can handle most scan types, but may have size limitations
        if context.metadata.scan_type in ["file", "directory", "code", "diff"]:
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
        if self._scanner is None:
            # Return empty result if scanner not available
            return ScanResult.create_empty(request)

        try:
            context = request.context
            scan_type = context.metadata.scan_type

            # Convert domain objects to infrastructure parameters
            llm_results = []

            if scan_type == "file":
                # File analysis
                file_path = str(context.target_path)
                llm_results = await self._analyze_file(file_path, context.language)

            elif scan_type == "directory":
                # Directory analysis
                dir_path = str(context.target_path)
                llm_results = await self._analyze_directory(dir_path)

            elif scan_type == "code":
                # Code snippet analysis
                code_content = context.content or ""
                llm_results = await self._analyze_code(code_content, context.language)

            elif scan_type == "diff":
                # Diff analysis - analyze the target file with diff context
                file_path = str(context.target_path)
                llm_results = await self._analyze_file(file_path, context.language)

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

            # Create domain scan result
            return ScanResult.create_from_threats(
                request=request,
                threats=high_confidence_threats,
                scan_metadata={
                    "scanner": self.get_strategy_name(),
                    "analysis_type": "ai_powered",
                    "total_findings": len(llm_results),
                    "filtered_findings": len(high_confidence_threats),
                    "confidence_threshold": confidence_threshold.get_percentage(),
                },
            )

        except Exception as e:
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

                # Extract file path
                file_path_str = result.get(
                    "file_path", str(request.context.target_path)
                )
                file_path = FilePath.from_string(file_path_str)

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

        # Create domain threat with type-safe access
        return ThreatMatch(
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
