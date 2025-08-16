"""Application service for coordinating security scans using Clean Architecture."""

import uuid
from datetime import UTC, datetime
from typing import Any

from adversary_mcp_server.application.adapters.llm_adapter import LLMScanStrategy
from adversary_mcp_server.application.adapters.llm_validation_adapter import (
    LLMValidationStrategy,
)

# Import adapters
from adversary_mcp_server.application.adapters.semgrep_adapter import (
    SemgrepScanStrategy,
)
from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.services.scan_orchestrator import ScanOrchestrator
from adversary_mcp_server.domain.services.threat_aggregator import ThreatAggregator
from adversary_mcp_server.domain.services.validation_service import ValidationService
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel
from adversary_mcp_server.scanner.language_mapping import LanguageMapper


class ScanApplicationService:
    """
    Application service that coordinates security scanning using Clean Architecture principles.

    This service:
    - Orchestrates domain services and strategies
    - Converts between application and domain models
    - Manages infrastructure dependencies through adapters
    - Provides a clean API for the presentation layer (MCP/CLI)
    """

    def __init__(self):
        """Initialize the application service with domain services and adapters."""
        # Domain services
        self._scan_orchestrator = ScanOrchestrator()
        self._threat_aggregator = ThreatAggregator()
        self._validation_service = ValidationService()

        # Initialize and register scan strategies
        self._semgrep_strategy = SemgrepScanStrategy()
        self._llm_strategy = LLMScanStrategy()
        self._llm_validation_strategy = LLMValidationStrategy()

        self._scan_orchestrator.register_scan_strategy(self._semgrep_strategy)
        self._scan_orchestrator.register_scan_strategy(self._llm_strategy)
        self._scan_orchestrator.register_validation_strategy(
            self._llm_validation_strategy
        )
        self._scan_orchestrator.set_threat_aggregator(self._threat_aggregator)

    async def scan_file(
        self,
        file_path: str,
        *,
        requester: str = "application",
        enable_semgrep: bool = True,
        enable_llm: bool = False,
        enable_validation: bool = False,
        severity_threshold: str | None = None,
        timeout_seconds: int | None = None,
        language: str | None = None,
    ) -> ScanResult:
        """
        Scan a single file for security vulnerabilities.

        Args:
            file_path: Path to the file to scan
            requester: Who requested the scan
            enable_semgrep: Whether to enable Semgrep scanning
            enable_llm: Whether to enable LLM analysis
            enable_validation: Whether to enable LLM validation
            severity_threshold: Minimum severity level to include
            timeout_seconds: Scan timeout in seconds
            language: Programming language hint

        Returns:
            ScanResult containing found threats and metadata

        Raises:
            ValidationError: If scan parameters are invalid
            SecurityError: If file access is restricted
            ConfigurationError: If no scanners are enabled
        """
        # Create domain objects using the proper factory method
        context = ScanContext.for_file(
            file_path=file_path,
            requester=requester,
            language=language,
            timeout_seconds=timeout_seconds,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
        )

        severity_level = (
            SeverityLevel.from_string(severity_threshold)
            if severity_threshold
            else None
        )

        request = ScanRequest(
            context=context,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
            severity_threshold=severity_level,
        )

        # Validate request using domain service
        self._validation_service.validate_scan_request(request)
        self._validation_service.enforce_security_constraints(context)

        # Execute scan using domain orchestrator
        result = await self._scan_orchestrator.execute_scan(request)

        return result

    async def scan_directory(
        self,
        directory_path: str,
        *,
        requester: str = "application",
        enable_semgrep: bool = True,
        enable_llm: bool = False,
        enable_validation: bool = False,
        severity_threshold: str | None = None,
        timeout_seconds: int | None = None,
        recursive: bool = True,
    ) -> ScanResult:
        """
        Scan a directory for security vulnerabilities.

        Args:
            directory_path: Path to the directory to scan
            requester: Who requested the scan
            enable_semgrep: Whether to enable Semgrep scanning
            enable_llm: Whether to enable LLM analysis
            enable_validation: Whether to enable LLM validation
            severity_threshold: Minimum severity level to include
            timeout_seconds: Scan timeout in seconds
            recursive: Whether to scan subdirectories

        Returns:
            ScanResult containing found threats and metadata
        """
        # Create domain objects
        dir_path_obj = FilePath.from_string(directory_path)

        metadata = ScanMetadata(
            scan_id=str(uuid.uuid4()),
            scan_type="directory",
            timestamp=datetime.now(UTC),
            requester=requester,
            timeout_seconds=timeout_seconds
            or 600,  # Default 10 minutes for directories
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
        )

        context = ScanContext(target_path=dir_path_obj, metadata=metadata)

        severity_level = (
            SeverityLevel.from_string(severity_threshold)
            if severity_threshold
            else None
        )

        request = ScanRequest(
            context=context,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
            severity_threshold=severity_level,
        )

        # Validate and execute
        self._validation_service.validate_scan_request(request)
        self._validation_service.enforce_security_constraints(context)

        result = await self._scan_orchestrator.execute_scan(request)

        return result

    async def scan_code(
        self,
        code_content: str,
        language: str,
        *,
        requester: str = "application",
        enable_semgrep: bool = True,
        enable_llm: bool = True,
        enable_validation: bool = False,
        severity_threshold: str | None = None,
    ) -> ScanResult:
        """
        Scan code content for security vulnerabilities.

        Args:
            code_content: Source code to analyze
            language: Programming language of the code
            requester: Who requested the scan
            enable_semgrep: Whether to enable Semgrep scanning
            enable_llm: Whether to enable LLM analysis
            enable_validation: Whether to enable LLM validation
            severity_threshold: Minimum severity level to include

        Returns:
            ScanResult containing found threats and metadata
        """
        # Create domain objects
        metadata = ScanMetadata(
            scan_id=str(uuid.uuid4()),
            scan_type="code",
            timestamp=datetime.now(UTC),
            requester=requester,
            language=language,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
        )

        # Use a virtual file path for code analysis
        virtual_path = FilePath.from_string(
            f"/virtual/code.{self._get_extension_for_language(language)}"
        )

        context = ScanContext(
            target_path=virtual_path,
            metadata=metadata,
            content=code_content,
            language=language,
        )

        severity_level = (
            SeverityLevel.from_string(severity_threshold)
            if severity_threshold
            else None
        )

        request = ScanRequest(
            context=context,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
            severity_threshold=severity_level,
        )

        # Validate and execute
        self._validation_service.validate_scan_request(request)
        self._validation_service.enforce_security_constraints(context)

        result = await self._scan_orchestrator.execute_scan(request)

        return result

    def get_scan_capabilities(self) -> dict[str, Any]:
        """Get information about available scan capabilities."""
        strategies = self._scan_orchestrator.get_registered_strategies()

        return {
            "scan_strategies": strategies["scan_strategies"],
            "validation_strategies": strategies["validation_strategies"],
            "threat_aggregator": strategies["threat_aggregator"],
            "supported_scan_types": ["file", "directory", "code"],
            "supported_languages": self._get_supported_languages(),
            "severity_levels": ["low", "medium", "high", "critical"],
            "default_timeouts": {"file": 120, "directory": 600, "code": 60},
        }

    def get_security_constraints(self) -> dict[str, Any]:
        """Get current security constraints."""
        return self._validation_service.get_security_constraints()

    def update_security_constraints(self, **constraints) -> None:
        """Update security constraints."""
        self._validation_service.update_security_constraints(**constraints)

    def _get_extension_for_language(self, language: str) -> str:
        """Get file extension for a programming language using shared language mapping."""
        return LanguageMapper.get_extension_for_language(language)

    def _get_supported_languages(self) -> list[str]:
        """Get list of supported programming languages using shared language mapping."""
        return LanguageMapper.get_supported_languages()
