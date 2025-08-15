"""Clean Architecture MCP Server implementation using domain layer."""

import asyncio
import json
import traceback
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import ServerCapabilities, Tool, ToolsCapability
from pydantic import BaseModel

from adversary_mcp_server.application.services.scan_application_service import (
    ScanApplicationService,
)
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.interfaces import (
    ConfigurationError,
    SecurityError,
    ValidationError,
)
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel
from adversary_mcp_server.logger import get_logger
from adversary_mcp_server.scanner.false_positive_manager import FalsePositiveManager
from adversary_mcp_server.security import InputValidator

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
        self._input_validator = InputValidator()

        # Register MCP tools
        self._register_tools()

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
            # Comprehensive input validation
            validated_args = self._input_validator.validate_mcp_arguments(
                arguments, tool_name="adv_scan_file"
            )

            # Extract validated parameters
            path = validated_args.get("path", "")
            if not path:
                raise CleanAdversaryToolError("Path parameter is required")

            use_semgrep = validated_args.get("use_semgrep", True)
            use_llm = validated_args.get("use_llm", False)
            use_validation = validated_args.get("use_validation", False)
            severity_threshold = validated_args.get("severity_threshold", "medium")
            timeout_seconds = validated_args.get("timeout_seconds")
            language = validated_args.get("language")

            # Execute scan using domain service
            result = await self._scan_service.scan_file(
                file_path=path,
                requester="mcp_client",
                enable_semgrep=use_semgrep,
                enable_llm=use_llm,
                enable_validation=use_validation,
                severity_threshold=severity_threshold,
                timeout_seconds=timeout_seconds,
                language=language,
            )

            # Format result for MCP response
            formatted_result = self._format_scan_result(result)

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

            result = await self._scan_service.scan_directory(
                directory_path=path,
                requester="mcp_client",
                enable_semgrep=use_semgrep,
                enable_llm=use_llm,
                enable_validation=use_validation,
                severity_threshold=severity_threshold,
                timeout_seconds=timeout_seconds,
                recursive=recursive,
            )

            formatted_result = self._format_scan_result(result)

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

            result = await self._scan_service.scan_code(
                code_content=content,
                language=language,
                requester="mcp_client",
                enable_semgrep=use_semgrep,
                enable_llm=use_llm,
                enable_validation=use_validation,
                severity_threshold=severity_threshold,
            )

            formatted_result = self._format_scan_result(result)

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
        """Handle status requests."""
        try:
            capabilities = self._scan_service.get_scan_capabilities()
            security_constraints = self._scan_service.get_security_constraints()

            status = {
                "server": "adversary-clean",
                "architecture": "clean_architecture",
                "capabilities": capabilities,
                "security_constraints": security_constraints,
                "status": "operational",
            }

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
                "architecture": "clean_architecture",
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

            # Initialize false positive manager
            fp_manager = FalsePositiveManager(adversary_file_path)

            # Mark as false positive
            success = fp_manager.mark_false_positive(
                finding_uuid=finding_uuid, reason=reason, marked_by=marked_by
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

            # Initialize false positive manager
            fp_manager = FalsePositiveManager(adversary_file_path)

            # Unmark false positive
            success = fp_manager.unmark_false_positive(finding_uuid)

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
                **result.scan_metadata,
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

    def get_capabilities(self) -> ServerCapabilities:
        """Get MCP server capabilities."""
        return ServerCapabilities(tools=ToolsCapability())

    def get_tools(self) -> list[Tool]:
        """Get list of available MCP tools."""
        return [
            Tool(
                name="adv_scan_file",
                description="Scan a file for security vulnerabilities using Clean Architecture",
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
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="adv_scan_folder",
                description="Scan a directory for security vulnerabilities using Clean Architecture",
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
                    },
                },
            ),
            Tool(
                name="adv_scan_code",
                description="Scan code content for security vulnerabilities using Clean Architecture",
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
                    },
                    "required": ["content", "language"],
                },
            ),
            Tool(
                name="adv_get_status",
                description="Get server status and capabilities",
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
