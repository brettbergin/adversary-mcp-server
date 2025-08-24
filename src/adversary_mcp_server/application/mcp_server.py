"""Clean Architecture MCP Server implementation using domain layer."""

import asyncio
import json
import traceback
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import ServerCapabilities, Tool, ToolsCapability
from pydantic import BaseModel

from adversary_mcp_server.application.services.false_positive_service import (
    FalsePositiveService,
)
from adversary_mcp_server.application.services.scan_application_service import (
    ScanApplicationService,
)
from adversary_mcp_server.application.services.scan_persistence_service import (
    OutputFormat,
    ScanResultPersistenceService,
)
from adversary_mcp_server.domain.entities.scan_request import (
    ScanRequest as DomainScanRequest,
)
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.interfaces import (
    ConfigurationError,
    SecurityError,
    ValidationError,
)
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel
from adversary_mcp_server.infrastructure.false_positive_json_repository import (
    FalsePositiveJsonRepository,
)
from adversary_mcp_server.logger import get_logger
from adversary_mcp_server.security import InputValidator
from adversary_mcp_server.session.llm_session_manager import LLMSessionManager

logger = get_logger("clean_mcp_server")


class CleanAdversaryToolError(Exception):
    """Exception raised when a tool operation fails in Clean Architecture implementation."""

    pass


class ScanRequest(BaseModel):
    """Request for scanning using Clean Architecture."""

    content: str | None = None
    path: str | None = None
    use_semgrep: bool = True
    use_llm: bool = False
    use_validation: bool = False
    severity_threshold: str = "medium"
    timeout_seconds: int | None = None
    language: str | None = None
    requester: str = "mcp_client"


class DiffScanRequest(BaseModel):
    """Request for diff scanning using Clean Architecture."""

    source_branch: str
    target_branch: str
    path: str = "."
    use_semgrep: bool = True
    use_llm: bool = False
    use_validation: bool = False
    severity_threshold: str = "medium"


class CleanMCPServer:
    """
    Clean Architecture MCP Server that uses domain services and application layer.

    This server implementation maintains the same MCP interface while using
    the new Clean Architecture domain layer internally.
    """

    def __init__(self):
        """Initialize the Clean Architecture MCP server."""
        self.server = Server("adversary-clean")
        self._scan_service = ScanApplicationService()
        self._persistence_service = ScanResultPersistenceService()
        self._input_validator = InputValidator()

        # Initialize session manager for session-aware tools
        self._session_manager: LLMSessionManager | None = None
        self._init_session_manager()

        # Register MCP tools
        self._register_tools()

    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension using shared mapper."""
        from ..scanner.language_mapping import LanguageMapper

        return LanguageMapper.detect_language_from_extension(file_path)

    def _register_tools(self):
        """Register all MCP tools with their Clean Architecture implementations."""

        # Register the list_tools handler
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available tools."""
            return self.get_tools()

        # Register a single dispatcher function to avoid closure issues
        @self.server.call_tool()
        async def tool_dispatcher(
            name: str, arguments: dict
        ) -> list[types.TextContent]:
            """Dispatch MCP tool calls to the appropriate handler."""
            if name == "adv_scan_file":
                return await self._handle_scan_file(name, arguments)
            elif name == "adv_scan_folder":
                return await self._handle_scan_folder(name, arguments)
            elif name == "adv_scan_code":
                return await self._handle_scan_code(name, arguments)
            elif name == "adv_get_status":
                return await self._handle_get_status(name, arguments)
            elif name == "adv_get_version":
                return await self._handle_get_version(name, arguments)
            elif name == "adv_mark_false_positive":
                return await self._handle_mark_false_positive(name, arguments)
            elif name == "adv_unmark_false_positive":
                return await self._handle_unmark_false_positive(name, arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")

    async def _handle_scan_file(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle file scanning requests."""
        try:
            # Log raw arguments received
            logger.debug(f"MCP scan_file raw arguments: {arguments}")

            # Comprehensive input validation
            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, tool_name="adv_scan_file"
            )

            # Log validated arguments
            logger.debug(f"MCP scan_file validated arguments: {validated_args}")

            # Extract validated parameters
            path = validated_args.get("path", "")
            if not path:
                raise CleanAdversaryToolError("Path parameter is required")

            use_semgrep = validated_args.get("use_semgrep", True)
            use_llm = validated_args.get("use_llm", False)
            use_validation = validated_args.get("use_validation", False)

            # Log extracted parameters for debugging
            logger.debug(
                f"MCP scan_file parameters - use_semgrep: {use_semgrep}, use_llm: {use_llm}, use_validation: {use_validation}"
            )
            severity_threshold = validated_args.get("severity_threshold", "medium")
            timeout_seconds = validated_args.get("timeout_seconds")
            language = validated_args.get("language")
            output_format = validated_args.get("output_format", "json")

            # Use the same scan service as CLI for consistency and proper orchestration
            result = await self._scan_service.scan_file(
                file_path=path,
                requester="cli",
                enable_semgrep=use_semgrep,
                enable_llm=use_llm,
                enable_validation=use_validation,
                severity_threshold=severity_threshold,
                timeout_seconds=timeout_seconds,
                language=language,
            )

            # Persist scan result automatically
            try:
                output_format_enum = OutputFormat.from_string(output_format)
                file_path = await self._persistence_service.persist_scan_result(
                    result, output_format_enum
                )
                logger.info(f"Scan result persisted to {file_path}")
            except Exception as e:
                logger.warning(f"Failed to persist scan result: {e}")
                # Don't fail the scan if persistence fails

            # Format result for MCP response
            formatted_result = self._format_scan_result(result)

            # Add persistence info to the response
            formatted_result["persistence"] = {
                "output_format": output_format,
                "file_path": file_path if "file_path" in locals() else None,
                "persisted": "file_path" in locals(),
            }

            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(formatted_result, indent=2, default=str),
                )
            ]

        except (ValidationError, SecurityError, ConfigurationError) as e:
            logger.error(f"File scan failed: {e}")
            raise CleanAdversaryToolError(f"Scan failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in file scan: {e}")
            logger.error(traceback.format_exc())
            raise CleanAdversaryToolError(f"Internal error: {str(e)}")

    async def _handle_scan_folder(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle folder scanning requests."""
        try:
            # Comprehensive input validation
            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, tool_name="adv_scan_folder"
            )

            path = validated_args.get("path", ".")
            use_semgrep = validated_args.get("use_semgrep", True)
            use_llm = validated_args.get("use_llm", False)
            use_validation = validated_args.get("use_validation", False)
            severity_threshold = validated_args.get("severity_threshold", "medium")
            timeout_seconds = validated_args.get("timeout_seconds")
            recursive = validated_args.get("recursive", True)
            output_format = validated_args.get("output_format", "json")

            # Use the same scan service as CLI for consistency and proper orchestration
            result = await self._scan_service.scan_directory(
                directory_path=path,
                requester="cli",
                enable_semgrep=use_semgrep,
                enable_llm=use_llm,
                enable_validation=use_validation,
                severity_threshold=severity_threshold,
                timeout_seconds=timeout_seconds,
                recursive=recursive,
            )

            # Persist scan result automatically
            try:
                output_format_enum = OutputFormat.from_string(output_format)
                file_path = await self._persistence_service.persist_scan_result(
                    result, output_format_enum
                )
                logger.info(f"Scan result persisted to {file_path}")
            except Exception as e:
                logger.warning(f"Failed to persist scan result: {e}")
                # Don't fail the scan if persistence fails

            formatted_result = self._format_scan_result(result)

            # Add persistence info to the response
            formatted_result["persistence"] = {
                "output_format": output_format,
                "file_path": file_path if "file_path" in locals() else None,
                "persisted": "file_path" in locals(),
            }

            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(formatted_result, indent=2, default=str),
                )
            ]

        except (ValidationError, SecurityError, ConfigurationError) as e:
            logger.error(f"Directory scan failed: {e}")
            raise CleanAdversaryToolError(f"Scan failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in directory scan: {e}")
            logger.error(traceback.format_exc())
            raise CleanAdversaryToolError(f"Internal error: {str(e)}")

    async def _handle_scan_code(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle code scanning requests."""
        try:
            # Comprehensive input validation
            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, tool_name="adv_scan_code"
            )

            content = validated_args.get("content", "")
            language = validated_args.get("language", "")

            if not content:
                raise CleanAdversaryToolError("Content parameter is required")
            if not language:
                raise CleanAdversaryToolError("Language parameter is required")

            use_semgrep = validated_args.get("use_semgrep", True)
            use_llm = validated_args.get(
                "use_llm", True
            )  # Default to true for code analysis
            use_validation = validated_args.get("use_validation", False)
            severity_threshold = validated_args.get("severity_threshold", "medium")
            output_format = validated_args.get("output_format", "json")

            # Auto-detect project context from current working directory
            project_path = Path.cwd()

            # Try to use session-aware analysis when available
            if self._session_manager and (use_llm or use_validation):
                # Auto-warm cache if this looks like a new project
                if not self._session_manager.session_cache.get_cached_project_context(
                    project_path
                ):
                    self._session_manager.warm_project_cache(project_path)

                # Use session-aware code analysis with auto-detected project context
                result = await self._handle_session_code_analysis(
                    content=content,
                    language=language,
                    project_path=str(project_path),
                    use_semgrep=use_semgrep,
                    use_llm=use_llm,
                    use_validation=use_validation,
                    severity_threshold=severity_threshold,
                    output_format=output_format,
                )
            else:
                # Fall back to standard code scan
                result = await self._scan_service.scan_code(
                    code_content=content,
                    language=language,
                    requester="mcp_client",
                    enable_semgrep=use_semgrep,
                    enable_llm=use_llm,
                    enable_validation=use_validation,
                    severity_threshold=severity_threshold,
                )

            # Persist scan result automatically
            try:
                output_format_enum = OutputFormat.from_string(output_format)
                file_path = await self._persistence_service.persist_scan_result(
                    result, output_format_enum
                )
                logger.info(f"Scan result persisted to {file_path}")
            except Exception as e:
                logger.warning(f"Failed to persist scan result: {e}")
                # Don't fail the scan if persistence fails

            formatted_result = self._format_scan_result(result)

            # Add persistence info to the response
            formatted_result["persistence"] = {
                "output_format": output_format,
                "file_path": file_path if "file_path" in locals() else None,
                "persisted": "file_path" in locals(),
            }

            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(formatted_result, indent=2, default=str),
                )
            ]

        except (ValidationError, SecurityError, ConfigurationError) as e:
            logger.error(f"Code scan failed: {e}")
            raise CleanAdversaryToolError(f"Scan failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in code scan: {e}")
            logger.error(traceback.format_exc())
            raise CleanAdversaryToolError(f"Internal error: {str(e)}")

    async def _handle_get_status(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle comprehensive status requests including session management."""
        try:
            capabilities = self._scan_service.get_scan_capabilities()
            security_constraints = self._scan_service.get_security_constraints()

            status = {
                "server": "adversary",
                "capabilities": capabilities,
                "security_constraints": security_constraints,
                "status": "operational",
                "session_management": {
                    "available": self._session_manager is not None,
                    "active_sessions": 0,
                    "cache_statistics": {},
                },
            }

            # Add session management information if available
            if self._session_manager:
                status["session_management"]["active_sessions"] = len(
                    self._session_manager.list_active_sessions()
                )
                status["session_management"][
                    "cache_statistics"
                ] = self._session_manager.get_cache_statistics()
                status["session_management"]["features"] = [
                    "context_aware_analysis",
                    "project_context_caching",
                    "multi_phase_analysis",
                    "cross_file_analysis",
                    "intelligent_cache_warming",
                ]

            return [
                types.TextContent(
                    type="text", text=json.dumps(status, indent=2, default=str)
                )
            ]

        except Exception as e:
            logger.error(f"Status check failed: {e}")
            raise CleanAdversaryToolError(f"Status check failed: {str(e)}")

    async def _handle_get_version(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Get server version information."""
        try:
            from adversary_mcp_server import get_version

            version_info = {
                "version": get_version(),
                "server_type": "mcp",
                "domain_layer": "enabled",
            }

            return [
                types.TextContent(type="text", text=json.dumps(version_info, indent=2))
            ]

        except Exception as e:
            logger.error(f"Version check failed: {e}")
            raise CleanAdversaryToolError(f"Version check failed: {str(e)}")

    async def _handle_mark_false_positive(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle mark false positive requests."""
        try:
            # Comprehensive input validation
            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, tool_name="adv_mark_false_positive"
            )

            finding_uuid = validated_args.get("finding_uuid", "")
            reason = validated_args.get("reason", "")
            marked_by = validated_args.get("marked_by", "user")
            adversary_file_path = validated_args.get(
                "adversary_file_path", ".adversary.json"
            )

            if not finding_uuid:
                raise CleanAdversaryToolError("finding_uuid parameter is required")

            # Initialize false positive repository and service
            fp_repository = FalsePositiveJsonRepository(adversary_file_path)
            fp_service = FalsePositiveService(fp_repository)

            # Mark as false positive
            success = await fp_service.mark_as_false_positive(
                uuid=finding_uuid, reason=reason, marked_by=marked_by
            )

            result = {
                "success": success,
                "finding_uuid": finding_uuid,
                "message": (
                    f"Finding {finding_uuid} marked as false positive"
                    if success
                    else f"Failed to mark finding {finding_uuid} as false positive"
                ),
            }

            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            logger.error(f"Mark false positive failed: {e}")
            raise CleanAdversaryToolError(f"Mark false positive failed: {str(e)}")

    async def _handle_unmark_false_positive(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle unmark false positive requests."""
        try:
            # Comprehensive input validation
            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, tool_name="adv_unmark_false_positive"
            )

            finding_uuid = validated_args.get("finding_uuid", "")
            adversary_file_path = validated_args.get(
                "adversary_file_path", ".adversary.json"
            )

            if not finding_uuid:
                raise CleanAdversaryToolError("finding_uuid parameter is required")

            # Initialize false positive repository and service
            fp_repository = FalsePositiveJsonRepository(adversary_file_path)
            fp_service = FalsePositiveService(fp_repository)

            # Unmark false positive
            success = await fp_service.unmark_false_positive(finding_uuid)

            result = {
                "success": success,
                "finding_uuid": finding_uuid,
                "message": (
                    f"Finding {finding_uuid} unmarked as false positive"
                    if success
                    else f"Failed to unmark finding {finding_uuid} as false positive"
                ),
            }

            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            logger.error(f"Unmark false positive failed: {e}")
            raise CleanAdversaryToolError(f"Unmark false positive failed: {str(e)}")

    def _format_scan_result(self, result: ScanResult) -> dict[str, Any]:
        """Format domain ScanResult for MCP response."""
        return {
            "scan_metadata": {
                "scan_id": result.request.context.metadata.scan_id,
                "scan_type": result.request.context.metadata.scan_type,
                "target_path": str(result.request.context.target_path),
                "timestamp": result.request.context.metadata.timestamp.isoformat(),
                "requester": result.request.context.metadata.requester,
                "language": result.request.context.language,
                "scanners_used": result.get_active_scanners(),
                **{
                    k: v
                    for k, v in result.scan_metadata.items()
                    if k != "scanners_used"
                },
            },
            "statistics": result.get_statistics(),
            "threats": [self._format_threat(threat) for threat in result.threats],
            "summary": {
                "total_threats": len(result.threats),
                "critical_threats": len(
                    result.get_threats_by_severity(SeverityLevel.CRITICAL.value)
                ),
                "high_threats": len(
                    result.get_threats_by_severity(SeverityLevel.HIGH.value)
                ),
                "medium_threats": len(
                    result.get_threats_by_severity(SeverityLevel.MEDIUM.value)
                ),
                "low_threats": len(
                    result.get_threats_by_severity(SeverityLevel.LOW.value)
                ),
                "threat_categories": list(result.get_threat_categories()),
                "has_critical_threats": result.has_critical_threats(),
                "is_empty": result.is_empty(),
            },
        }

    def _format_threat(self, threat: ThreatMatch) -> dict[str, Any]:
        """Format domain ThreatMatch for MCP response."""
        return {
            "rule_id": threat.rule_id,
            "rule_name": threat.rule_name,
            "description": threat.description,
            "category": threat.category,
            "severity": str(threat.severity),
            "confidence": {
                "score": threat.confidence.get_decimal(),
                "percentage": threat.confidence.get_percentage(),
                "level": threat.confidence.get_quality_level(),
            },
            "location": {
                "file_path": str(threat.file_path),
                "line_number": threat.line_number,
                "column_number": threat.column_number,
            },
            "code_snippet": threat.code_snippet,
            "source_scanner": threat.source_scanner,
            "fingerprint": threat.get_fingerprint(),
            "is_false_positive": threat.is_false_positive,
            "false_positive_reason": "",  # Domain ThreatMatch doesn't have this field
            "exploit_examples": threat.exploit_examples,
            "remediation_advice": threat.remediation,
            "metadata": {},
        }

    def _init_session_manager(self):
        """Initialize session manager if LLM is available."""
        try:
            from adversary_mcp_server.credentials import get_credential_manager

            credential_manager = get_credential_manager()
            config = credential_manager.load_config()

            if config.llm_provider and config.llm_api_key:
                from adversary_mcp_server.llm import LLMProvider, create_llm_client

                llm_client = create_llm_client(
                    provider=LLMProvider(config.llm_provider),
                    api_key=config.llm_api_key,
                    model=config.llm_model,
                )

                self._session_manager = LLMSessionManager(
                    llm_client=llm_client,
                    max_context_tokens=50000,
                    session_timeout_seconds=3600,
                )
                logger.info("Session manager initialized for MCP server")
            else:
                logger.info(
                    "LLM not configured - session-aware tools will be unavailable"
                )

        except Exception as e:
            logger.warning(f"Failed to initialize session manager: {e}")
            self._session_manager = None

    async def _handle_session_scan_project(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle session-aware project scanning requests."""
        try:
            if not self._session_manager:
                return [
                    types.TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "error": "Session-aware analysis not available. Please configure LLM settings.",
                                "success": False,
                            }
                        ),
                    )
                ]

            # Validate and extract arguments
            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, name
            )

            project_path = Path(validated_args["path"]).resolve()
            analysis_focus = validated_args.get(
                "analysis_focus", "comprehensive security analysis"
            )
            target_files_list = validated_args.get("target_files", [])
            output_format = validated_args.get("output_format", "json")

            if not project_path.exists():
                return [
                    types.TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "error": f"Project path does not exist: {project_path}",
                                "success": False,
                            }
                        ),
                    )
                ]

            logger.info(f"Starting session-aware project scan: {project_path}")

            # Convert target files to Path objects if provided
            target_files = None
            if target_files_list:
                target_files = [Path(f) for f in target_files_list]

            # Create session and analyze project
            session = await self._session_manager.create_session(
                project_root=project_path,
                target_files=target_files,
                session_metadata={
                    "analysis_focus": analysis_focus,
                    "mcp_session": True,
                    "requester": "mcp_session_aware",
                },
            )

            # Perform comprehensive analysis
            findings = await self._perform_mcp_session_analysis(
                session.session_id, analysis_focus
            )

            # Close session
            self._session_manager.close_session(session.session_id)

            # Format response
            response_data = {
                "success": True,
                "analysis_type": "session_aware_project",
                "project_path": str(project_path),
                "findings_count": len(findings),
                "findings": [
                    {
                        "rule_id": finding.rule_id,
                        "rule_name": finding.rule_name,
                        "description": finding.description,
                        "severity": (
                            finding.severity.value
                            if hasattr(finding.severity, "value")
                            else str(finding.severity)
                        ),
                        "confidence": (
                            finding.confidence
                            if hasattr(finding, "confidence")
                            else 0.7
                        ),
                        "session_context": getattr(finding, "session_context", {}),
                    }
                    for finding in findings
                ],
            }

            # Auto-persist results
            try:
                persistence_result = (
                    await self._persistence_service.persist_scan_result(
                        scan_result=None,  # We don't have a ScanResult object here
                        target_path=project_path,
                        output_format=OutputFormat(output_format),
                        custom_data=response_data,
                    )
                )
                response_data["persistence"] = {
                    "file_path": str(persistence_result.file_path),
                    "format": persistence_result.format.value,
                    "success": persistence_result.success,
                }
            except Exception as e:
                logger.warning(f"Failed to persist session scan results: {e}")
                response_data["persistence"] = {"success": False, "error": str(e)}

            logger.info(
                f"Session-aware project scan completed: {len(findings)} findings"
            )

            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(response_data, indent=2),
                )
            ]

        except Exception as e:
            error_msg = f"Session-aware project scan failed: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": error_msg,
                            "success": False,
                        }
                    ),
                )
            ]

    async def _handle_session_scan_file(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle session-aware file scanning requests."""
        try:
            if not self._session_manager:
                return [
                    types.TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "error": "Session-aware analysis not available. Please configure LLM settings.",
                                "success": False,
                            }
                        ),
                    )
                ]

            # Validate and extract arguments
            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, name
            )

            file_path = Path(validated_args["path"]).resolve()
            context_hint = validated_args.get("context_hint")
            output_format = validated_args.get("output_format", "json")

            if not file_path.exists():
                return [
                    types.TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "error": f"File does not exist: {file_path}",
                                "success": False,
                            }
                        ),
                    )
                ]

            logger.info(f"Starting session-aware file scan: {file_path}")

            # Find project root
            project_root = self._find_project_root(file_path)

            # Create session focused on this file
            session = await self._session_manager.create_session(
                project_root=project_root,
                target_files=[file_path],
                session_metadata={
                    "analysis_type": "focused_file",
                    "target_file": str(file_path),
                    "context_hint": context_hint,
                    "mcp_session": True,
                },
            )

            # Analyze the specific file with actual content (same enhancement as CLI path)
            language = self._detect_language(file_path)

            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    file_lines = f.readlines()

                # Format content with line numbers (same as CLI fix)
                numbered_content = ""
                for i, line in enumerate(file_lines, 1):
                    numbered_content += f"{i:4d} | {line}"

                query = f"""Analyze {file_path.name} ({language}) for security vulnerabilities.

## File Content with Line Numbers:
```{language}
{numbered_content}```

Please analyze the above code for security vulnerabilities. Provide the EXACT line number where each vulnerability occurs."""

                if context_hint:
                    query += f"\n\nAdditional context: {context_hint}"

            except Exception as e:
                logger.warning(
                    f"Failed to read file content for MCP scan {file_path}: {e}"
                )
                # Fallback to original query without content
                query = f"Analyze {file_path.name} for security vulnerabilities"
                if context_hint:
                    query += f". {context_hint}"

            findings = await self._session_manager.analyze_with_session(
                session_id=session.session_id,
                analysis_query=query,
                context_hint=context_hint,
            )

            # Close session
            self._session_manager.close_session(session.session_id)

            # Format response
            response_data = {
                "success": True,
                "analysis_type": "session_aware_file",
                "file_path": str(file_path),
                "project_root": str(project_root),
                "findings_count": len(findings),
                "findings": [
                    {
                        "rule_id": finding.rule_id,
                        "rule_name": finding.rule_name,
                        "description": finding.description,
                        "severity": (
                            finding.severity.value
                            if hasattr(finding.severity, "value")
                            else str(finding.severity)
                        ),
                        "confidence": (
                            finding.confidence
                            if hasattr(finding, "confidence")
                            else 0.7
                        ),
                        "session_context": getattr(finding, "session_context", {}),
                    }
                    for finding in findings
                ],
            }

            # Auto-persist results
            try:
                persistence_result = (
                    await self._persistence_service.persist_scan_result(
                        scan_result=None,
                        target_path=file_path,
                        output_format=OutputFormat(output_format),
                        custom_data=response_data,
                    )
                )
                response_data["persistence"] = {
                    "file_path": str(persistence_result.file_path),
                    "format": persistence_result.format.value,
                    "success": persistence_result.success,
                }
            except Exception as e:
                logger.warning(f"Failed to persist session scan results: {e}")
                response_data["persistence"] = {"success": False, "error": str(e)}

            logger.info(f"Session-aware file scan completed: {len(findings)} findings")

            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(response_data, indent=2),
                )
            ]

        except Exception as e:
            error_msg = f"Session-aware file scan failed: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": error_msg,
                            "success": False,
                        }
                    ),
                )
            ]

    async def _handle_session_status(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle session status requests."""
        try:
            status = {
                "session_manager_available": self._session_manager is not None,
                "active_sessions": 0,
                "cache_statistics": {},
            }

            if self._session_manager:
                status["active_sessions"] = len(
                    self._session_manager.list_active_sessions()
                )
                status["cache_statistics"] = (
                    self._session_manager.get_cache_statistics()
                )

            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(status, indent=2),
                )
            ]

        except Exception as e:
            error_msg = f"Session status failed: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": error_msg,
                            "success": False,
                        }
                    ),
                )
            ]

    async def _handle_session_cache_warm(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle cache warming requests."""
        try:
            if not self._session_manager:
                return [
                    types.TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "error": "Session manager not available",
                                "success": False,
                            }
                        ),
                    )
                ]

            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, name
            )
            project_path = Path(validated_args["path"]).resolve()

            success = self._session_manager.warm_project_cache(project_path)

            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "success": success,
                            "project_path": str(project_path),
                            "message": (
                                "Cache warmed successfully"
                                if success
                                else "Cache warming failed"
                            ),
                        }
                    ),
                )
            ]

        except Exception as e:
            error_msg = f"Cache warming failed: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": error_msg,
                            "success": False,
                        }
                    ),
                )
            ]

    async def _handle_session_cache_stats(
        self, name: str, arguments: dict
    ) -> list[types.TextContent]:
        """Handle cache statistics requests."""
        try:
            if not self._session_manager:
                return [
                    types.TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "error": "Session manager not available",
                                "cache_available": False,
                            }
                        ),
                    )
                ]

            cache_stats = self._session_manager.get_cache_statistics()

            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "cache_available": True,
                            "statistics": cache_stats,
                        },
                        indent=2,
                    ),
                )
            ]

        except Exception as e:
            error_msg = f"Cache statistics failed: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": error_msg,
                            "success": False,
                        }
                    ),
                )
            ]

    async def _perform_mcp_session_analysis(self, session_id: str, analysis_focus: str):
        """Perform comprehensive session analysis for MCP."""
        # Phase 1: General security analysis
        findings = await self._session_manager.analyze_with_session(
            session_id=session_id,
            analysis_query=f"""
Perform a {analysis_focus} of this codebase. Look for:

1. Authentication and authorization vulnerabilities
2. Input validation issues and injection flaws
3. Cross-site scripting (XSS) vulnerabilities
4. Cross-site request forgery (CSRF) issues
5. SQL injection and database security
6. File upload and path traversal vulnerabilities
7. Session management issues
8. Cryptographic implementation problems
9. Information disclosure risks
10. Business logic flaws

Focus on real, exploitable vulnerabilities with high confidence.
""",
        )

        # Phase 2: Architectural analysis if we found some issues
        if len(findings) > 0:
            arch_findings = await self._session_manager.continue_analysis(
                session_id=session_id,
                follow_up_query="""
Now analyze the overall architecture for security issues:

1. Are there any trust boundary violations?
2. How does data flow between components - any risks?
3. Are authentication/authorization consistently applied?
4. Any privilege escalation opportunities?
5. Configuration and deployment security issues?
6. Third-party dependency risks?

Focus on systemic and architectural vulnerabilities.
""",
            )
            findings.extend(arch_findings)

        return findings

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

        # Fallback to file's parent directory
        return file_path.parent if file_path.is_file() else file_path

    async def _handle_session_file_analysis(
        self,
        path: str,
        use_semgrep: bool = True,
        use_llm: bool = False,
        use_validation: bool = False,
        severity_threshold: str = "medium",
        timeout_seconds: int | None = None,
        language: str | None = None,
        output_format: str = "json",
    ):
        """Handle session-aware file analysis."""
        if not self._session_manager:
            raise CleanAdversaryToolError("Session manager not available")

        file_path_obj = Path(path).resolve()
        project_root = self._find_project_root(file_path_obj)

        # Create session for contextual analysis
        session = await self._session_manager.create_session(
            project_root=project_root,
            target_files=[file_path_obj],
            session_metadata={
                "mcp_session": True,
                "requester": "mcp_session_file",
            },
        )

        try:
            # Create comprehensive security analysis query
            query = "Perform comprehensive security analysis of this specific file"

            # Perform session-aware analysis
            findings = await self._session_manager.analyze_with_session(
                session.session_id, query, None
            )

            # Convert session findings to scan result format
            result = self._convert_session_findings_to_scan_result(
                findings, file_path_obj, use_semgrep, use_llm, use_validation
            )

            return result

        finally:
            # Clean up session
            self._session_manager.close_session(session.session_id)

    async def _handle_session_folder_analysis(
        self,
        path: str,
        use_semgrep: bool = True,
        use_llm: bool = False,
        use_validation: bool = False,
        severity_threshold: str = "medium",
        timeout_seconds: int | None = None,
        recursive: bool = True,
        output_format: str = "json",
    ):
        """Handle session-aware project/folder analysis."""
        if not self._session_manager:
            raise CleanAdversaryToolError("Session manager not available")

        project_root = Path(path).resolve()

        # Create session for comprehensive project analysis
        session = await self._session_manager.create_session(
            project_root=project_root,
            target_files=None,  # Analyze entire project
            session_metadata={
                "mcp_session": True,
                "requester": "mcp_session_project",
            },
        )

        try:
            # Perform comprehensive multi-phase session analysis
            findings = await self._perform_mcp_session_analysis(
                session.session_id, "comprehensive security analysis"
            )

            # Convert session findings to scan result format
            result = self._convert_session_findings_to_scan_result(
                findings, project_root, use_semgrep, use_llm, use_validation
            )

            return result

        finally:
            # Clean up session
            self._session_manager.close_session(session.session_id)

    def _convert_session_findings_to_scan_result(
        self, findings, target_path, use_semgrep, use_llm, use_validation
    ):
        """Convert session findings to standard scan result format."""
        from ..domain.entities.scan_result import ScanResult
        from ..domain.entities.threat_match import ThreatMatch as DomainThreatMatch

        # Convert session findings to ThreatMatch objects using domain entity
        threat_matches = []
        for finding in findings:
            # Get severity as string first, then convert via domain value object
            severity_str = getattr(finding, "severity", "medium")
            if hasattr(severity_str, "name"):  # If it's an enum
                severity_str = severity_str.name.lower()
            elif hasattr(severity_str, "value"):  # If it's a value object
                severity_str = str(severity_str).lower()

            threat_match = DomainThreatMatch.create_llm_threat(
                rule_id=getattr(finding, "rule_id", "session_finding"),
                rule_name=getattr(finding, "rule_name", "Session Analysis Finding"),
                description=getattr(finding, "description", str(finding)),
                category=getattr(finding, "category", "session_analysis"),
                severity=severity_str,
                file_path=str(target_path),
                line_number=getattr(finding, "line_number", 1),
                confidence=getattr(finding, "confidence", 0.8),
                code_snippet=getattr(finding, "code_snippet", ""),
                metadata={
                    "session_analysis": True,
                    "session_context": getattr(finding, "session_context", {}),
                    **getattr(finding, "metadata", {}),
                },
            )
            threat_matches.append(threat_match)

        # Create scan request using domain entity factory method
        scan_request = DomainScanRequest.for_file_scan(
            file_path=target_path,
            requester="mcp_session",
            enable_semgrep=use_semgrep,
            enable_llm=use_llm,
            enable_validation=use_validation,
        )

        # Create scan result
        result = ScanResult(
            request=scan_request,
            threats=threat_matches,
            scan_metadata={
                "session_enhanced": True,
                "findings_count": len(threat_matches),
                "analysis_type": "session_aware",
            },
        )

        return result

    async def _handle_session_code_analysis(
        self,
        content: str,
        language: str,
        project_path: str,
        use_semgrep: bool = True,
        use_llm: bool = True,
        use_validation: bool = False,
        severity_threshold: str = "medium",
        output_format: str = "json",
    ):
        """Handle session-aware code analysis with project context."""
        if not self._session_manager:
            raise CleanAdversaryToolError("Session manager not available")

        project_root = Path(project_path).resolve()

        # Create session for contextual code analysis
        session = await self._session_manager.create_session(
            project_root=project_root,
            session_metadata={
                "mcp_session": True,
                "requester": "mcp_session_code",
                "language": language,
            },
        )

        try:
            # Create comprehensive security analysis query for code
            query = f"Perform comprehensive security analysis of this {language} code snippet"
            query += f"\n\nCode:\n```{language}\n{content}\n```"

            # Perform session-aware analysis
            findings = await self._session_manager.analyze_with_session(
                session.session_id, query, None
            )

            # Convert session findings to scan result format for code
            result = self._convert_session_findings_to_scan_result(
                findings,
                f"<code_snippet>.{language}",
                use_semgrep,
                use_llm,
                use_validation,
            )

            return result

        finally:
            # Clean up session
            self._session_manager.close_session(session.session_id)

    def get_capabilities(self) -> ServerCapabilities:
        """Get MCP server capabilities."""
        return ServerCapabilities(tools=ToolsCapability())

    def get_tools(self) -> list[Tool]:
        """Get list of available MCP tools."""
        return [
            Tool(
                name="adv_scan_file",
                description="Scan a file for security vulnerabilities using Clean Architecture. Automatically uses session-aware analysis when LLM is configured.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the file to scan",
                        },
                        "use_semgrep": {
                            "type": "boolean",
                            "description": "Enable Semgrep analysis",
                            "default": True,
                        },
                        "use_llm": {
                            "type": "boolean",
                            "description": "Enable LLM analysis",
                            "default": False,
                        },
                        "use_validation": {
                            "type": "boolean",
                            "description": "Enable LLM validation",
                            "default": False,
                        },
                        "severity_threshold": {
                            "type": "string",
                            "description": "Minimum severity level",
                            "default": "medium",
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "description": "Scan timeout in seconds",
                        },
                        "language": {
                            "type": "string",
                            "description": "Programming language hint",
                        },
                        "output_format": {
                            "type": "string",
                            "description": "Output format for persisted scan results",
                            "enum": ["json", "md", "markdown", "csv"],
                            "default": "json",
                        },
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="adv_scan_folder",
                description="Scan a directory for security vulnerabilities using Clean Architecture. Automatically uses session-aware project analysis when LLM is configured.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the directory to scan",
                            "default": ".",
                        },
                        "use_semgrep": {
                            "type": "boolean",
                            "description": "Enable Semgrep analysis",
                            "default": True,
                        },
                        "use_llm": {
                            "type": "boolean",
                            "description": "Enable LLM analysis",
                            "default": False,
                        },
                        "use_validation": {
                            "type": "boolean",
                            "description": "Enable LLM validation",
                            "default": False,
                        },
                        "severity_threshold": {
                            "type": "string",
                            "description": "Minimum severity level",
                            "default": "medium",
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "description": "Scan timeout in seconds",
                        },
                        "recursive": {
                            "type": "boolean",
                            "description": "Scan subdirectories",
                            "default": True,
                        },
                        "output_format": {
                            "type": "string",
                            "description": "Output format for persisted scan results",
                            "enum": ["json", "md", "markdown", "csv"],
                            "default": "json",
                        },
                    },
                },
            ),
            Tool(
                name="adv_scan_code",
                description="Scan code content for security vulnerabilities using Clean Architecture. Automatically uses session-aware analysis with project context when available.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "Source code to analyze",
                        },
                        "language": {
                            "type": "string",
                            "description": "Programming language of the code",
                        },
                        "use_semgrep": {
                            "type": "boolean",
                            "description": "Enable Semgrep analysis",
                            "default": True,
                        },
                        "use_llm": {
                            "type": "boolean",
                            "description": "Enable LLM analysis",
                            "default": True,
                        },
                        "use_validation": {
                            "type": "boolean",
                            "description": "Enable LLM validation",
                            "default": False,
                        },
                        "severity_threshold": {
                            "type": "string",
                            "description": "Minimum severity level",
                            "default": "medium",
                        },
                        "output_format": {
                            "type": "string",
                            "description": "Output format for persisted scan results",
                            "enum": ["json", "md", "markdown", "csv"],
                            "default": "json",
                        },
                    },
                    "required": ["content", "language"],
                },
            ),
            Tool(
                name="adv_get_status",
                description="Get comprehensive server status including session management capabilities, active sessions, and cache statistics",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="adv_get_version",
                description="Get server version information",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="adv_mark_false_positive",
                description="Mark a finding as a false positive",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_uuid": {
                            "type": "string",
                            "description": "UUID of the finding to mark as false positive",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Reason for marking as false positive",
                            "default": "",
                        },
                        "marked_by": {
                            "type": "string",
                            "description": "Who marked it as false positive",
                            "default": "user",
                        },
                        "adversary_file_path": {
                            "type": "string",
                            "description": "Path to .adversary.json file",
                            "default": ".adversary.json",
                        },
                    },
                    "required": ["finding_uuid"],
                },
            ),
            Tool(
                name="adv_unmark_false_positive",
                description="Remove false positive marking from a finding",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_uuid": {
                            "type": "string",
                            "description": "UUID of the finding to unmark",
                        },
                        "adversary_file_path": {
                            "type": "string",
                            "description": "Path to .adversary.json file",
                            "default": ".adversary.json",
                        },
                    },
                    "required": ["finding_uuid"],
                },
            ),
        ]

    async def run(self):
        """Run the Clean Architecture MCP server."""
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="adversary-clean",
                    server_version="clean-architecture",
                    capabilities=self.get_capabilities(),
                ),
            )


async def main():
    """Main entry point for Clean Architecture MCP server."""
    server = CleanMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
