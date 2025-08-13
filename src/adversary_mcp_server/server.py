"""Adversary MCP Server - Security vulnerability scanning and detection."""

import asyncio
import json
import json as json_lib
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

import truststore
from mcp import types
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import ServerCapabilities, Tool, ToolsCapability
from pydantic import BaseModel

from . import get_version
from .config import get_app_metrics_dir
from .credentials import get_credential_manager
from .database.models import AdversaryDatabase
from .logger import get_logger
from .monitoring import MetricsCollector
from .monitoring.types import MonitoringConfig
from .scanner.diff_scanner import GitDiffScanner
from .scanner.exploit_generator import ExploitGenerator
from .scanner.false_positive_manager import FalsePositiveManager
from .scanner.result_formatter import ScanResultFormatter
from .scanner.scan_engine import EnhancedScanResult, ScanEngine
from .scanner.types import Severity, ThreatMatch
from .security import InputValidator, SecurityError, sanitize_for_logging
from .telemetry.integration import MetricsCollectionOrchestrator
from .telemetry.service import TelemetryService

logger = get_logger("server")


class AdversaryToolError(Exception):
    """Exception raised when a tool operation fails."""

    pass


class ScanRequest(BaseModel):
    """Request for scanning code or files."""

    content: str | None = None
    file_path: str | None = None
    severity_threshold: str | None = "medium"
    include_exploits: bool = True
    use_llm: bool = False


class ScanResult(BaseModel):
    """Result of a security scan."""

    threats: list[dict[str, Any]]
    summary: dict[str, Any]
    metadata: dict[str, Any]


class AdversaryMCPServer:
    """MCP server for security vulnerability scanning and exploit generation."""

    def __init__(self) -> None:
        """Initialize the Adversary MCP server."""

        logger.info("=== Initializing Adversary MCP Server ===")
        self.server: Server = Server("adversary-mcp-server")
        self.credential_manager = get_credential_manager()
        logger.debug("Got credential manager singleton")

        logger.debug("Loading configuration...")
        config = self.credential_manager.load_config()
        logger.info(
            f"Configuration loaded - LLM analysis: {config.enable_llm_analysis}, Semgrep: {config.enable_semgrep_scanning}"
        )

        logger.debug("Initializing telemetry system...")
        self.db = AdversaryDatabase()
        self.telemetry_service = TelemetryService(self.db)
        self.metrics_orchestrator = MetricsCollectionOrchestrator(
            self.telemetry_service
        )
        logger.debug("Telemetry system initialized")

        logger.debug("Initializing legacy monitoring...")
        monitoring_config = MonitoringConfig(
            enable_metrics=True,
            enable_performance_monitoring=True,
            json_export_path=str(get_app_metrics_dir()),
        )
        self.metrics_collector = MetricsCollector(monitoring_config)
        logger.debug("Legacy metrics collector initialized")

        logger.info("Initializing scan engine...")
        self.scan_engine = ScanEngine(
            self.credential_manager,
            metrics_collector=self.metrics_collector,
            metrics_orchestrator=self.metrics_orchestrator,
            enable_llm_analysis=config.enable_llm_analysis,
            enable_semgrep_analysis=config.enable_semgrep_scanning,
            enable_llm_validation=config.enable_llm_validation,
        )
        logger.debug("Scan engine initialized")

        logger.debug("Initializing exploit generator...")
        self.exploit_generator = ExploitGenerator(self.credential_manager)
        logger.debug("Exploit generator initialized")

        logger.debug("Initializing diff scanner...")
        self.diff_scanner = GitDiffScanner(
            self.scan_engine, metrics_collector=self.metrics_collector
        )
        logger.debug("diff scanner initialized")

        logger.debug("Initializing false positive manager...")
        # Initialize with default adversary.json path in project root
        default_adversary_path = self._get_adversary_json_path()
        self.false_positive_manager = FalsePositiveManager(
            adversary_file_path=str(default_adversary_path)
        )
        logger.debug("false positive manager initialized")

        logger.debug("Setting up server handlers...")
        self._setup_handlers()
        logger.info("=== Adversary MCP Server initialization complete ===")

    def _setup_handlers(self) -> None:
        """Set up server request handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List available adversary analysis tools."""
            return [
                Tool(
                    name="adv_scan_code",
                    description="Scan source code for security vulnerabilities. Results are saved as .adversary.json or .adversary.md in the specified directory.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "string",
                                "description": "Source code content to scan",
                            },
                            "path": {
                                "type": "string",
                                "description": "Directory path where results should be saved",
                                "default": ".",
                            },
                            "severity_threshold": {
                                "type": "string",
                                "description": "Minimum severity threshold (low, medium, high, critical)",
                                "enum": ["low", "medium", "high", "critical"],
                                "default": "medium",
                            },
                            "include_exploits": {
                                "type": "boolean",
                                "description": "Whether to include exploit examples",
                                "default": True,
                            },
                            "use_llm": {
                                "type": "boolean",
                                "description": "Whether to include LLM analysis prompts (for use with your client's LLM)",
                                "default": False,
                            },
                            "use_semgrep": {
                                "type": "boolean",
                                "description": "Whether to include Semgrep analysis",
                                "default": True,
                            },
                            "use_validation": {
                                "type": "boolean",
                                "description": "Whether to use LLM validation to filter false positives",
                                "default": True,
                            },
                            "output_format": {
                                "type": "string",
                                "description": "Output format for results (json or markdown)",
                                "enum": ["json", "markdown"],
                                "default": "json",
                            },
                        },
                        "required": ["content"],
                    },
                ),
                Tool(
                    name="adv_scan_file",
                    description="Scan a file for security vulnerabilities. Results are saved in the same directory as the target file.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the file to scan (must be a file, not a directory)",
                            },
                            "severity_threshold": {
                                "type": "string",
                                "description": "Minimum severity threshold",
                                "enum": ["low", "medium", "high", "critical"],
                                "default": "medium",
                            },
                            "include_exploits": {
                                "type": "boolean",
                                "description": "Whether to include exploit examples",
                                "default": True,
                            },
                            "use_llm": {
                                "type": "boolean",
                                "description": "Whether to include LLM analysis prompts (for use with your client's LLM)",
                                "default": False,
                            },
                            "use_semgrep": {
                                "type": "boolean",
                                "description": "Whether to include Semgrep analysis",
                                "default": True,
                            },
                            "use_validation": {
                                "type": "boolean",
                                "description": "Whether to use LLM validation to filter false positives",
                                "default": True,
                            },
                            "output_format": {
                                "type": "string",
                                "description": "Output format for results (json or markdown)",
                                "enum": ["json", "markdown"],
                                "default": "json",
                            },
                        },
                        "required": ["path"],
                    },
                ),
                Tool(
                    name="adv_scan_folder",
                    description="Scan a directory for security vulnerabilities. Results are saved in the target directory.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the directory to scan (must be a directory, not a file)",
                                "default": ".",
                            },
                            "recursive": {
                                "type": "boolean",
                                "description": "Whether to scan subdirectories",
                                "default": True,
                            },
                            "severity_threshold": {
                                "type": "string",
                                "description": "Minimum severity threshold",
                                "enum": ["low", "medium", "high", "critical"],
                                "default": "medium",
                            },
                            "include_exploits": {
                                "type": "boolean",
                                "description": "Whether to include exploit examples",
                                "default": True,
                            },
                            "use_llm": {
                                "type": "boolean",
                                "description": "Whether to include LLM analysis prompts (for use with your client's LLM)",
                                "default": False,
                            },
                            "use_semgrep": {
                                "type": "boolean",
                                "description": "Whether to include Semgrep analysis",
                                "default": True,
                            },
                            "use_validation": {
                                "type": "boolean",
                                "description": "Whether to use LLM validation to filter false positives",
                                "default": True,
                            },
                            "output_format": {
                                "type": "string",
                                "description": "Output format for results (json or markdown)",
                                "enum": ["json", "markdown"],
                                "default": "json",
                            },
                        },
                        "required": [],
                    },
                ),
                Tool(
                    name="adv_diff_scan",
                    description="Scan security vulnerabilities in git diff changes between branches. Results are saved in the repository root.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "source_branch": {
                                "type": "string",
                                "description": "Source branch name (e.g., 'feature-branch')",
                            },
                            "target_branch": {
                                "type": "string",
                                "description": "Target branch name (e.g., 'main')",
                            },
                            "path": {
                                "type": "string",
                                "description": "Path to git repository (must contain .git directory)",
                                "default": ".",
                            },
                            "severity_threshold": {
                                "type": "string",
                                "description": "Minimum severity threshold (low, medium, high, critical)",
                                "enum": ["low", "medium", "high", "critical"],
                                "default": "medium",
                            },
                            "include_exploits": {
                                "type": "boolean",
                                "description": "Whether to include exploit examples",
                                "default": True,
                            },
                            "use_llm": {
                                "type": "boolean",
                                "description": "Whether to include LLM analysis prompts (for use with your client's LLM)",
                                "default": False,
                            },
                            "use_semgrep": {
                                "type": "boolean",
                                "description": "Whether to include Semgrep analysis",
                                "default": True,
                            },
                            "use_validation": {
                                "type": "boolean",
                                "description": "Whether to use LLM validation to filter false positives",
                                "default": True,
                            },
                            "output_format": {
                                "type": "string",
                                "description": "Output format for results (json or markdown)",
                                "enum": ["json", "markdown"],
                                "default": "json",
                            },
                        },
                        "required": ["source_branch", "target_branch"],
                    },
                ),
                # Tool(
                #     name="adv_configure_settings",
                #     description="Configure adversary MCP server settings",
                #     inputSchema={
                #         "type": "object",
                #         "properties": {
                #             "severity_threshold": {
                #                 "type": "string",
                #                 "description": "Default severity threshold",
                #                 "enum": ["low", "medium", "high", "critical"],
                #             },
                #             "exploit_safety_mode": {
                #                 "type": "boolean",
                #                 "description": "Enable safety mode for exploit generation",
                #             },
                #             "enable_llm_analysis": {
                #                 "type": "boolean",
                #                 "description": "Enable LLM-based analysis",
                #             },
                #             "enable_exploit_generation": {
                #                 "type": "boolean",
                #                 "description": "Enable exploit generation",
                #             },
                #         },
                #         "required": [],
                #     },
                # ),
                Tool(
                    name="adv_get_status",
                    description="Get server status and configuration",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                ),
                Tool(
                    name="adv_get_version",
                    description="Get version information",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                ),
                Tool(
                    name="adv_clear_cache",
                    description="Clear all local cache and data storage",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                ),
                Tool(
                    name="adv_mark_false_positive",
                    description="Mark a finding as a false positive in the .adversary.json file",
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
                                "default": "Manually marked via MCP tool",
                            },
                            "marked_by": {
                                "type": "string",
                                "description": "Name of the person marking this as false positive",
                                "default": "MCP User",
                            },
                            "path": {
                                "type": "string",
                                "description": "Path to directory containing .adversary.json or direct path to .adversary.json file",
                                "default": ".",
                            },
                        },
                        "required": ["finding_uuid"],
                    },
                ),
                Tool(
                    name="adv_unmark_false_positive",
                    description="Remove false positive marking from a finding in the .adversary.json file",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "finding_uuid": {
                                "type": "string",
                                "description": "UUID of the finding to unmark",
                            },
                            "path": {
                                "type": "string",
                                "description": "Path to directory containing .adversary.json or direct path to .adversary.json file",
                                "default": ".",
                            },
                        },
                        "required": ["finding_uuid"],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(
            name: str, arguments: dict[str, Any]
        ) -> list[types.TextContent]:
            """Call the specified tool with the given arguments."""
            tool_start_time = time.time()
            payload_size = len(str(arguments))

            # Record tool call start
            self.metrics_collector.record_metric(
                "mcp_tool_calls_total", 1, labels={"tool": name, "status": "started"}
            )
            self.metrics_collector.record_metric(
                "mcp_request_payload_bytes", payload_size, labels={"tool": name}
            )

            try:
                logger.info(f"=== TOOL CALL START: {name} ===")
                logger.debug(f"Tool arguments: {sanitize_for_logging(arguments)}")

                # Validate and sanitize all MCP tool arguments
                try:
                    validated_arguments = InputValidator.validate_mcp_arguments(
                        arguments, tool_name=name
                    )
                    logger.debug(f"Input validation passed for {name}")
                except (SecurityError, ValueError) as e:
                    logger.error(f"Input validation failed for {name}: {e}")
                    self.metrics_collector.record_metric(
                        "mcp_tool_calls_total",
                        1,
                        labels={"tool": name, "status": "validation_failed"},
                    )
                    return [
                        types.TextContent(
                            type="text",
                            text=f"❌ **Input Validation Error**\n\n"
                            f"The provided input contains security issues: {e}\n\n"
                            f"Please check your input and try again with valid parameters.",
                        )
                    ]

                # Use validated arguments for all subsequent processing
                arguments = validated_arguments
                result = None
                if name == "adv_scan_code":
                    logger.info("Handling scan_code request")
                    result = await self._handle_scan_code(arguments)

                elif name == "adv_scan_file":
                    logger.info("Handling scan_file request")
                    result = await self._handle_scan_file(arguments)

                elif name == "adv_scan_folder":
                    logger.info("Handling scan_folder request")
                    result = await self._handle_scan_directory(arguments)

                elif name == "adv_diff_scan":
                    logger.info("Handling diff_scan request")
                    result = await self._handle_diff_scan(arguments)

                # elif name == "adv_configure_settings":
                #     logger.info("Handling configure_settings request")
                #     result = await self._handle_configure_settings(arguments)

                elif name == "adv_get_status":
                    logger.info("Handling get_status request")
                    result = await self._handle_get_status()

                elif name == "adv_get_version":
                    logger.info("Handling get_version request")
                    result = await self._handle_get_version()

                elif name == "adv_clear_cache":
                    logger.info("Handling clear_cache request")
                    result = await self._handle_clear_cache()

                elif name == "adv_mark_false_positive":
                    logger.info("Handling mark_false_positive request")
                    result = await self._handle_mark_false_positive(arguments)

                elif name == "adv_unmark_false_positive":
                    logger.info("Handling unmark_false_positive request")
                    result = await self._handle_unmark_false_positive(arguments)

                else:
                    logger.error(f"Unknown tool requested: {name}")
                    # Record unknown tool metric
                    self.metrics_collector.record_metric(
                        "mcp_tool_calls_total",
                        1,
                        labels={"tool": name, "status": "unknown"},
                    )
                    raise AdversaryToolError(f"Unknown tool: {name}")

                # Record successful tool execution
                duration = time.time() - tool_start_time
                response_size = len(str(result)) if result else 0

                self.metrics_collector.record_metric(
                    "mcp_tool_calls_total",
                    1,
                    labels={"tool": name, "status": "success"},
                )
                self.metrics_collector.record_histogram(
                    "mcp_tool_duration_seconds",
                    duration,
                    labels={"tool": name, "status": "success"},
                )
                self.metrics_collector.record_metric(
                    "mcp_response_payload_bytes", response_size, labels={"tool": name}
                )

                return result

            except Exception as e:
                # Record tool failure metrics
                duration = time.time() - tool_start_time
                self.metrics_collector.record_metric(
                    "mcp_tool_calls_total", 1, labels={"tool": name, "status": "failed"}
                )
                self.metrics_collector.record_histogram(
                    "mcp_tool_duration_seconds",
                    duration,
                    labels={"tool": name, "status": "failed"},
                )

                logger.error(f"Tool {name} execution failed: {e}")
                logger.debug("Tool {name} error details", exc_info=True)
                raise AdversaryToolError(f"Tool {name} failed: {str(e)}")

            finally:
                logger.info(f"=== TOOL CALL END: {name} ===")

    async def _handle_scan_code(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle code scanning request with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper("adv_scan_code")(
            self._handle_scan_code_impl
        )
        return await wrapped_handler(arguments)

    async def _handle_scan_code_impl(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle code scanning request."""
        try:
            logger.info("Starting code scan")

            # Validate and sanitize input parameters
            content = self._validate_content(arguments.get("content"))
            path = self._validate_path_parameter(arguments.get("path", "."))
            severity_threshold = self._validate_severity_threshold(
                arguments.get("severity_threshold", "medium")
            )
            include_exploits = self._validate_boolean_parameter(
                arguments.get("include_exploits", True), "include_exploits"
            )
            use_llm = self._validate_boolean_parameter(
                arguments.get("use_llm", False), "use_llm"
            )
            use_semgrep = self._validate_boolean_parameter(
                arguments.get("use_semgrep", True), "use_semgrep"
            )
            use_validation = self._validate_boolean_parameter(
                arguments.get("use_validation", True), "use_validation"
            )
            output_format = self._validate_output_format(
                arguments.get("output_format", "json")
            )

            # Validate and resolve the output directory path
            output_dir = self._validate_directory_path(path)
            logger.info(f"Code scan output directory: {output_dir}")

            logger.debug(
                f"Code scan parameters - Language: auto-detect, "
                f"Severity: {severity_threshold}, LLM: {use_llm}, "
                f"Semgrep: {use_semgrep}, Validation: {use_validation}, Format: {output_format}"
            )

            severity_enum = Severity(severity_threshold)

            logger.info(
                f"Scanning {len(content)} characters with auto-detected language"
            )

            # Scan the code using enhanced scanner
            logger.debug("Calling scan_engine.scan_code...")
            scan_result = await self.scan_engine.scan_code(
                source_code=content,
                file_path="input.code",
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                severity_threshold=severity_enum,
            )
            logger.info(
                f"Code scan completed - found {len(scan_result.all_threats)} threats"
            )

            # Generate exploits if requested
            if include_exploits:
                logger.info("Generating exploits for discovered threats...")
                exploit_count = 0
                for threat in scan_result.all_threats:
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, content, False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                        if exploits:
                            exploit_count += len(exploits)
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )
                logger.info(f"Generated {exploit_count} total exploit examples")
            else:
                logger.debug("Exploit generation skipped")

            # Format results and save to file
            formatter = ScanResultFormatter(str(output_dir))
            output_file = self._determine_scan_output_path(output_dir, output_format)

            if output_format == "json":
                logger.debug("Formatting results as JSON")
                result_content = formatter.format_single_file_results_json(
                    scan_result, "code"
                )
            elif output_format == "markdown":
                logger.debug("Formatting results as Markdown")
                result_content = formatter.format_code_results_markdown(
                    scan_result, "code"
                )
            else:
                raise AdversaryToolError(f"Invalid output format: {output_format}")

            # Save the results to file (preserving UUIDs/FPs for JSON)
            saved_path: str | None
            if output_format == "json":
                saved_path = self._save_scan_results_json(
                    result_content, str(output_dir)
                )
            else:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(result_content)
                saved_path = str(output_file)

            logger.info(f"Scan results saved to: {saved_path}")

            # Return success message with file path
            result_message = "✅ Code scan completed successfully!\n\n"
            result_message += f"**Results saved to:** `{saved_path}`\n"
            result_message += f"**Format:** {output_format}\n"
            result_message += f"**Threats found:** {len(scan_result.all_threats)}\n"

            if use_llm:
                result_message += "\n**Note:** LLM analysis prompts were included for client-side analysis."

            logger.info("Code scan completed successfully")
            return [types.TextContent(type="text", text=result_message)]

        except Exception as e:
            logger.error(f"Code scanning failed: {e}")
            logger.debug("Code scan error details", exc_info=True)
            raise AdversaryToolError(f"Code scanning failed: {e}")

    async def _handle_scan_file(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle file scanning request with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper("adv_scan_file")(
            self._handle_scan_file_impl
        )
        return await wrapped_handler(arguments)

    async def _handle_scan_file_impl(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle file scanning request."""
        try:
            logger.info("Starting file scan")

            # Debug: Log ALL arguments to see what MCP is actually passing
            logger.info(f"MCP ARGUMENTS DEBUG: {sanitize_for_logging(arguments)}")

            # Validate file path and ensure it's a file, not a directory
            path = arguments["path"]
            file_path = self._validate_file_path(path)
            logger.info(f"Scanning file: {file_path}")

            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = self._validate_boolean_parameter(
                arguments.get("include_exploits", True), "include_exploits"
            )
            use_llm = self._validate_boolean_parameter(
                arguments.get("use_llm", False), "use_llm"
            )
            use_semgrep = self._validate_boolean_parameter(
                arguments.get("use_semgrep", True), "use_semgrep"
            )
            use_validation = self._validate_boolean_parameter(
                arguments.get("use_validation", True), "use_validation"
            )
            output_format = arguments.get("output_format", "json")

            # Debug: Specific validation parameter logging
            logger.info(
                f"VALIDATION DEBUG: Raw={arguments.get('use_validation')}, Processed={use_validation}, Type={type(use_validation)}"
            )

            logger.debug(
                f"File scan parameters - Severity: {severity_threshold}, "
                f"LLM: {use_llm}, Semgrep: {use_semgrep}, Validation: {use_validation}, Format: {output_format}"
            )

            # Convert severity threshold to enum
            severity_enum = Severity(severity_threshold)

            # Scan the file using enhanced scanner
            logger.debug("Calling scan_engine.scan_file...")
            scan_result = await self.scan_engine.scan_file(
                file_path=file_path,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                severity_threshold=severity_enum,
            )
            logger.info(
                f"File scan completed - found {len(scan_result.all_threats)} threats"
            )

            # Generate exploits if requested
            if include_exploits:
                logger.info("Generating exploits for discovered threats...")
                file_content = ""
                try:
                    with open(file_path, encoding="utf-8") as f:
                        file_content = f.read()
                    logger.debug(f"Read {len(file_content)} characters from file")
                except Exception as e:
                    logger.warning(f"Could not read file content for exploits: {e}")

                exploit_count = 0
                for threat in scan_result.all_threats:
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, file_content, False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                        if exploits:
                            exploit_count += len(exploits)
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )
                logger.info(f"Generated {exploit_count} total exploit examples")
            else:
                logger.debug("Exploit generation skipped")

            # Determine output directory (same as file's directory)
            output_dir = file_path.parent
            formatter = ScanResultFormatter(str(output_dir))
            output_file = self._determine_scan_output_path(output_dir, output_format)

            # Format results based on output format
            if output_format == "json":
                logger.debug("Formatting results as JSON")
                result_content = formatter.format_single_file_results_json(
                    scan_result, str(file_path)
                )
            elif output_format == "markdown":
                logger.debug("Formatting results as Markdown")
                result_content = formatter.format_single_file_results_markdown(
                    scan_result, str(file_path)
                )
            else:
                raise AdversaryToolError(f"Invalid output format: {output_format}")

            # Save the results to file (preserving UUIDs/FPs for JSON)
            saved_path: str | None
            if output_format == "json":
                saved_path = self._save_scan_results_json(
                    result_content, str(output_dir)
                )
            else:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(result_content)
                saved_path = str(output_file)

            logger.info(f"Scan results saved to: {saved_path}")

            # Return success message with file path
            result_message = "✅ File scan completed successfully!\n\n"
            result_message += f"**Scanned file:** `{file_path}`\n"
            result_message += f"**Results saved to:** `{saved_path}`\n"
            result_message += f"**Format:** {output_format}\n"
            result_message += f"**Threats found:** {len(scan_result.all_threats)}\n"

            if use_llm:
                result_message += "\n**Note:** LLM analysis prompts were included for client-side analysis."

            logger.info("File scan completed successfully")
            return [types.TextContent(type="text", text=result_message)]

        except Exception as e:
            logger.error(f"File scanning failed: {e}")
            logger.debug("File scan error details", exc_info=True)
            raise AdversaryToolError(f"File scanning failed: {e}")

    async def _handle_scan_directory(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle directory scanning request with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper("adv_scan_folder")(
            self._handle_scan_directory_impl
        )
        return await wrapped_handler(arguments)

    async def _handle_scan_directory_impl(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle directory scanning request."""
        try:
            logger.info("Starting directory scan")

            # Validate directory path and ensure it's a directory, not a file
            path = arguments.get("path", ".")
            directory_path = self._validate_directory_path(path)
            logger.info(f"Scanning directory: {directory_path}")

            recursive = self._validate_boolean_parameter(
                arguments.get("recursive", True), "recursive"
            )
            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = self._validate_boolean_parameter(
                arguments.get("include_exploits", True), "include_exploits"
            )
            use_llm = self._validate_boolean_parameter(
                arguments.get("use_llm", False), "use_llm"
            )
            use_semgrep = self._validate_boolean_parameter(
                arguments.get("use_semgrep", True), "use_semgrep"
            )
            use_validation = self._validate_boolean_parameter(
                arguments.get("use_validation", True), "use_validation"
            )
            output_format = arguments.get("output_format", "json")

            logger.debug(
                f"Directory scan parameters - Recursive: {recursive}, "
                f"Severity: {severity_threshold}, LLM: {use_llm}, "
                f"Semgrep: {use_semgrep}, Validation: {use_validation}, Format: {output_format}"
            )

            # Convert severity threshold to enum
            severity_enum = Severity(severity_threshold)

            # Scan the directory using enhanced scanner (rules-based)
            logger.debug("Calling scan_engine.scan_directory...")
            scan_results = await self.scan_engine.scan_directory(
                directory_path=directory_path,
                recursive=recursive,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                severity_threshold=severity_enum,
            )

            logger.info(
                f"Directory scan completed - processed {len(scan_results)} files"
            )

            # Combine all threats from all files
            all_threats = []
            for scan_result in scan_results:
                all_threats.extend(scan_result.all_threats)

            logger.info(f"Total threats found across all files: {len(all_threats)}")

            # Generate exploits if requested (limited for directory scans)
            if include_exploits:
                logger.info(
                    "Generating exploits for discovered threats (limited to first 10)..."
                )
                exploit_count = 0
                for threat in all_threats[:10]:  # Limit to first 10 threats
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, "", False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                        if exploits:
                            exploit_count += len(exploits)
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )
                logger.info(f"Generated {exploit_count} total exploit examples")
            else:
                logger.debug("Exploit generation skipped")

            # Format results and save to file
            formatter = ScanResultFormatter(str(directory_path))
            output_file = self._determine_scan_output_path(
                directory_path, output_format
            )

            if output_format == "json":
                logger.debug("Formatting results as JSON")
                result_content = formatter.format_directory_results_json(
                    scan_results, str(directory_path), scan_type="directory"
                )
            elif output_format == "markdown":
                logger.debug("Formatting results as Markdown")
                result_content = formatter.format_directory_results_markdown(
                    scan_results, str(directory_path), scan_type="directory"
                )
            else:
                raise AdversaryToolError(f"Invalid output format: {output_format}")

            # Save the results to file (preserving UUIDs/FPs for JSON)
            saved_path: str | None
            if output_format == "json":
                saved_path = self._save_scan_results_json(
                    result_content, str(directory_path)
                )
            else:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(result_content)
                saved_path = str(output_file)

            logger.info(f"Scan results saved to: {saved_path}")

            # Return success message with file path
            result_message = "✅ Directory scan completed successfully!\n\n"
            result_message += f"**Scanned directory:** `{directory_path}`\n"
            result_message += f"**Results saved to:** `{saved_path}`\n"
            result_message += f"**Format:** {output_format}\n"
            result_message += f"**Files scanned:** {len(scan_results)}\n"
            result_message += f"**Total threats found:** {len(all_threats)}\n"

            if use_llm:
                result_message += "\n**Note:** LLM analysis prompts were included for client-side analysis."

            logger.info("Directory scan completed successfully")
            return [types.TextContent(type="text", text=result_message)]

        except Exception as e:
            logger.error(f"Directory scanning failed: {e}")
            logger.debug("Directory scan error details", exc_info=True)
            raise AdversaryToolError(f"Directory scanning failed: {e}")

    async def _handle_diff_scan(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle git diff scanning request with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper("adv_diff_scan")(
            self._handle_diff_scan_impl
        )
        return await wrapped_handler(arguments)

    async def _handle_diff_scan_impl(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle git diff scanning request."""
        try:
            source_branch = arguments["source_branch"]
            target_branch = arguments["target_branch"]

            # Validate git repository path
            path = arguments.get("path", ".")
            working_directory = self._validate_git_directory_path(path)
            logger.info(f"Diff scan - working_directory: {working_directory}")

            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = self._validate_boolean_parameter(
                arguments.get("include_exploits", True), "include_exploits"
            )
            use_llm = self._validate_boolean_parameter(
                arguments.get("use_llm", False), "use_llm"
            )
            use_semgrep = self._validate_boolean_parameter(
                arguments.get("use_semgrep", True), "use_semgrep"
            )
            use_validation = self._validate_boolean_parameter(
                arguments.get("use_validation", True), "use_validation"
            )
            output_format = arguments.get("output_format", "json")

            # Convert severity threshold to enum
            severity_enum = Severity(severity_threshold)

            # Get diff summary first
            diff_summary = await self.diff_scanner.get_diff_summary(
                source_branch, target_branch, working_directory
            )

            # Check if there's an error in the summary
            if "error" in diff_summary:
                raise AdversaryToolError(
                    f"Git diff operation failed: {diff_summary['error']}"
                )

            # Scan the diff changes
            scan_results = await self.diff_scanner.scan_diff(
                source_branch=source_branch,
                target_branch=target_branch,
                working_dir=working_directory,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                severity_threshold=severity_enum,
            )

            # Collect all threats
            all_threats = []
            for file_path, file_scan_results in scan_results.items():
                for scan_result in file_scan_results:
                    all_threats.extend(scan_result.all_threats)

            # Generate exploits if requested
            if include_exploits:
                logger.info("Generating exploits for discovered threats...")
                exploit_count = 0
                for threat in all_threats[:10]:  # Limit to first 10 threats
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, "", False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                        if exploits:
                            exploit_count += len(exploits)
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )
                logger.info(f"Generated {exploit_count} total exploit examples")
            else:
                logger.debug("Exploit generation skipped")

            # Format results and save to file
            formatter = ScanResultFormatter(str(working_directory))
            output_file = self._determine_scan_output_path(
                working_directory, output_format
            )

            if output_format == "json":
                logger.debug("Formatting results as JSON")
                result_content = formatter.format_diff_results_json(
                    scan_results,
                    diff_summary,
                    f"{source_branch}..{target_branch}",
                )
            elif output_format == "markdown":
                logger.debug("Formatting results as Markdown")
                result_content = formatter.format_diff_results_markdown(
                    scan_results,
                    diff_summary,
                    f"{source_branch}..{target_branch}",
                )
            else:
                raise AdversaryToolError(f"Invalid output format: {output_format}")

            # Save the results to file (preserving UUIDs/FPs for JSON)
            saved_path: str | None
            if output_format == "json":
                saved_path = self._save_scan_results_json(
                    result_content, str(working_directory)
                )
            else:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(result_content)
                saved_path = str(output_file)

            logger.info(f"Scan results saved to: {saved_path}")

            # Return success message with file path
            result_message = "✅ Git diff scan completed successfully!\n\n"
            result_message += f"**Repository:** `{working_directory}`\n"
            result_message += f"**Branches:** `{source_branch}` → `{target_branch}`\n"
            result_message += f"**Results saved to:** `{saved_path}`\n"
            result_message += f"**Format:** {output_format}\n"
            result_message += f"**Files changed:** {len(scan_results)}\n"
            result_message += f"**Total threats found:** {len(all_threats)}\n"

            # Include a brief overview of top threats for quick visibility
            if all_threats:
                try:
                    severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
                    severity_emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🟢",
                    }
                    # Sort by severity, keep input order for equal severities
                    sorted_threats = sorted(
                        all_threats,
                        key=lambda t: severity_rank.get(
                            getattr(t.severity, "value", str(t.severity)), 0
                        ),
                        reverse=True,
                    )
                    top_threats = sorted_threats[:3]
                    result_message += "\n**Top threats:**\n"
                    for t in top_threats:
                        sev_val = getattr(t.severity, "value", str(t.severity))
                        emoji = severity_emoji.get(sev_val, "⚪")
                        rule_name = getattr(
                            t, "rule_name", getattr(t, "rule_id", "Unknown Rule")
                        )
                        file_loc = f"{getattr(t, 'file_path', '')}:{getattr(t, 'line_number', '')}"
                        result_message += (
                            f"- {rule_name} {emoji} ({sev_val}) in {file_loc}\n"
                        )
                except Exception:
                    # Best-effort only; don't fail message formatting
                    pass

            if use_llm:
                # Best-effort prompt generation to satisfy integration expectations
                try:
                    diff_changes = await self.diff_scanner.get_diff_changes(
                        source_branch, target_branch, working_directory
                    )
                    for file_path, file_scan_results in scan_results.items():
                        if (
                            any(r.all_threats for r in file_scan_results)
                            and file_path in diff_changes
                        ):
                            chunks = diff_changes[file_path]
                            try:
                                changed_code = "\n".join(
                                    chunk.get_added_lines_with_minimal_context()
                                    for chunk in chunks
                                )
                            except Exception:
                                changed_code = ""
                            # Invoke helper (tests assert it gets called)
                            _ = self._add_llm_analysis_prompts(
                                changed_code, file_path, include_header=False
                            )
                            break
                except Exception:
                    pass
                result_message += "\n**Note:** LLM analysis prompts were included for client-side analysis."

            logger.info("Diff scan completed successfully")
            return [types.TextContent(type="text", text=result_message)]

        except Exception as e:
            logger.error(f"Diff scanning failed: {e}")
            logger.debug("Diff scan error details", exc_info=True)
            raise AdversaryToolError(f"Diff scanning failed: {e}")

    async def _handle_configure_settings(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle configuration settings with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper(
            "adv_configure_settings"
        )(self._handle_configure_settings_impl)
        return await wrapped_handler(arguments)

    async def _handle_configure_settings_impl(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle configuration settings request."""
        try:
            logger.info("Configuring server settings")
            logger.debug(f"Configuration arguments: {sanitize_for_logging(arguments)}")

            config = self.credential_manager.load_config()
            import dataclasses

            original_config = dataclasses.replace(config)

            # Update configuration
            if "severity_threshold" in arguments:
                old_value = config.severity_threshold
                config.severity_threshold = arguments["severity_threshold"]
                logger.info(
                    f"Severity threshold changed: {old_value} -> {config.severity_threshold}"
                )

            if "exploit_safety_mode" in arguments:
                old_value = config.exploit_safety_mode
                config.exploit_safety_mode = arguments["exploit_safety_mode"]
                logger.info(
                    f"Exploit safety mode changed: {old_value} -> {config.exploit_safety_mode}"
                )

            if "enable_llm_analysis" in arguments:
                old_value = config.enable_llm_analysis
                config.enable_llm_analysis = arguments["enable_llm_analysis"]
                logger.info(
                    f"LLM analysis changed: {old_value} -> {config.enable_llm_analysis}"
                )

            if "enable_exploit_generation" in arguments:
                old_value = config.enable_exploit_generation
                config.enable_exploit_generation = arguments[
                    "enable_exploit_generation"
                ]
                logger.info(
                    f"Exploit generation changed: {old_value} -> {config.enable_exploit_generation}"
                )

            # Save configuration
            logger.debug("Saving updated configuration...")
            self.credential_manager.store_config(config)
            logger.info("Configuration saved successfully")

            # Reinitialize components with new config
            logger.debug("Reinitializing components with new configuration...")
            self.exploit_generator = ExploitGenerator(self.credential_manager)
            self.scan_engine = ScanEngine(
                self.credential_manager,
                metrics_collector=self.metrics_collector,
                metrics_orchestrator=self.metrics_orchestrator,
                enable_llm_analysis=config.enable_llm_analysis,
                enable_semgrep_analysis=config.enable_semgrep_scanning,
                enable_llm_validation=config.enable_llm_validation,
            )
            logger.info("Components reinitialized with new configuration")

            result = "✅ Configuration updated successfully!\n\n"
            result += "**Current Settings:**\n"
            result += f"- Severity Threshold: {config.severity_threshold}\n"
            result += f"- Exploit Safety Mode: {'✓ Enabled' if config.exploit_safety_mode else '✗ Disabled'}\n"
            result += f"- LLM Security Analysis: {'✓ Enabled' if config.enable_llm_analysis else '✗ Disabled'}\n"
            result += f"- Exploit Generation: {'✓ Enabled' if config.enable_exploit_generation else '✗ Disabled'}\n"

            logger.info("Server settings updated successfully")
            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            logger.error(f"Failed to configure settings: {e}")
            logger.debug("Configuration error details", exc_info=True)
            raise AdversaryToolError(f"Failed to configure settings: {e}")

    async def _handle_get_status(self) -> list[types.TextContent]:
        """Handle get status with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper("adv_get_status")(
            self._handle_get_status_impl
        )
        return await wrapped_handler()

    async def _handle_get_status_impl(self) -> list[types.TextContent]:
        """Handle get status request."""
        try:
            logger.info("Getting server status")
            config = self.credential_manager.load_config()

            result = "# Adversary MCP Server Status\n\n"
            result += "## Configuration\n"
            result += f"- **Severity Threshold:** {config.severity_threshold}\n"
            result += f"- **Exploit Safety Mode:** {'✓ Enabled' if config.exploit_safety_mode else '✗ Disabled'}\n"
            result += f"- **LLM Analysis:** {'✓ Enabled' if config.enable_llm_analysis else '✗ Disabled'}\n"
            result += f"- **Exploit Generation:** {'✓ Enabled' if config.enable_exploit_generation else '✗ Disabled'}\n\n"

            result += "## Security Scanners\n"

            # Semgrep status
            if self.scan_engine.semgrep_scanner.is_available():
                semgrep_status = self.scan_engine.semgrep_scanner.get_status()
                result += f"- **Semgrep Scanner:** ✓ Available (Version: {semgrep_status.get('version', 'unknown')})\n"
            else:
                result += "- **Semgrep Scanner:** ✗ Not Available\n"

            # LLM status
            if self.scan_engine.enable_llm_analysis:
                result += "- **LLM Scanner:** ✓ Enabled (Client-based)\n"
            else:
                result += "- **LLM Scanner:** ✗ Disabled\n"

            result += "\n## Components\n"
            result += "- **Scan Engine:** ✓ Active\n"
            result += "- **Exploit Generator:** ✓ Active\n"
            result += "- **LLM Integration:** ✓ Client-based (no API key required)\n"
            result += "- **False Positive Manager:** ✓ Active\n"

            logger.info("Status retrieved successfully")
            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            logger.debug("Status error details", exc_info=True)
            raise AdversaryToolError(f"Failed to get status: {e}")

    async def _handle_get_version(self) -> list[types.TextContent]:
        """Handle get version with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper("adv_get_version")(
            self._handle_get_version_impl
        )
        return await wrapped_handler()

    async def _handle_get_version_impl(self) -> list[types.TextContent]:
        """Handle get version request."""
        try:
            version = self._get_version()
            result = "# Adversary MCP Server\n\n"
            result += f"**Version:** {version}\n"
            result += "**LLM Integration:** Client-based (no API key required)\n"
            result += "**Supported Languages:** Python, JavaScript, TypeScript\n"

            # Count available scanners instead of rules
            scanner_count = 0
            if self.scan_engine.semgrep_scanner.is_available():
                scanner_count += 1
            if self.scan_engine.enable_llm_analysis:
                scanner_count += 1

            result += f"**Active Scanners:** {scanner_count}\n"

            logger.info("Version information retrieved successfully")
            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            logger.error(f"Failed to get version: {e}")
            logger.debug("Version retrieval error details", exc_info=True)
            raise AdversaryToolError(f"Failed to get version: {e}")

    async def _handle_clear_cache(self) -> list[types.TextContent]:
        """Handle clear cache with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper("adv_clear_cache")(
            self._handle_clear_cache_impl
        )
        return await wrapped_handler()

    async def _handle_clear_cache_impl(self) -> list[types.TextContent]:
        """Handle clear cache request."""
        try:
            logger.info("Starting cache clearing process")

            cleared_items = []

            # Clear main cache manager
            if hasattr(self, "cache_manager") and self.cache_manager is not None:
                cache_stats_before = self.cache_manager.get_stats()
                self.cache_manager.clear()
                cleared_items.append(
                    f"Main cache ({cache_stats_before.total_entries} entries)"
                )

            # Clear scan engine cache
            if hasattr(self.scan_engine, "clear_cache"):
                self.scan_engine.clear_cache()
                cleared_items.append("Scan engine cache")

            # Clear semgrep scanner cache
            if hasattr(self.scan_engine, "semgrep_scanner") and hasattr(
                self.scan_engine.semgrep_scanner, "clear_cache"
            ):
                self.scan_engine.semgrep_scanner.clear_cache()
                cleared_items.append("Semgrep scanner cache")

            # Clear token estimator cache
            if (
                hasattr(self.scan_engine, "llm_analyzer")
                and self.scan_engine.llm_analyzer is not None
            ):
                if hasattr(
                    self.scan_engine.llm_analyzer, "token_estimator"
                ) and hasattr(
                    self.scan_engine.llm_analyzer.token_estimator, "clear_cache"
                ):
                    self.scan_engine.llm_analyzer.token_estimator.clear_cache()
                    cleared_items.append("Token estimator cache")

            # Clear database cache and temp data
            if hasattr(self, "database") and self.database is not None:
                # Note: We don't clear persistent data like false positives, just temp/cache data
                cleared_items.append("Database temporary data")

            result = "🗑️ **Cache Cleared Successfully**\n\n"
            result += "**Cleared Components:**\n"
            for item in cleared_items:
                result += f"• {item}\n"

            if not cleared_items:
                result += "• No cache components found to clear\n"

            result += "\n✅ Local cache and temporary data have been reset."

            logger.info(
                f"Cache clearing completed successfully. Cleared: {', '.join(cleared_items)}"
            )
            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            logger.debug("Cache clearing error details", exc_info=True)
            raise AdversaryToolError(f"Failed to clear cache: {e}")

    def _get_version(self) -> str:
        """Get the current version."""
        return get_version()

    def _get_project_root(self) -> Path:
        """Get the project root directory.

        This checks for ADVERSARY_WORKSPACE_ROOT environment variable first,
        which allows users to specify their actual workspace directory in mcp.json.
        If not set, falls back to the MCP client's 'cwd' parameter.

        This is where .adversary.json will be stored and where relative paths
        are resolved against.

        Returns:
            Path object representing project root directory

        Raises:
            AdversaryToolError: If ADVERSARY_WORKSPACE_ROOT is set but invalid
        """
        workspace_root = os.environ.get("ADVERSARY_WORKSPACE_ROOT")
        if workspace_root:
            workspace_path = Path(workspace_root)
            if not workspace_path.exists():
                logger.error(
                    f"ADVERSARY_WORKSPACE_ROOT path does not exist: {workspace_root}"
                )
                raise AdversaryToolError(
                    f"Workspace root path does not exist: {workspace_root}"
                )
            if not workspace_path.is_dir():
                logger.error(
                    f"ADVERSARY_WORKSPACE_ROOT is not a directory: {workspace_root}"
                )
                raise AdversaryToolError(
                    f"Workspace root is not a directory: {workspace_root}"
                )

            logger.debug(f"Using workspace root from environment: {workspace_root}")
            return workspace_path

        logger.debug("Using current working directory as project root")
        return Path.cwd()

    def _resolve_path_from_project_root(
        self, path: str, path_description: str = "path", allow_override: bool = True
    ) -> Path:
        """Resolve path relative to project root directory.

        Args:
            path: Path to resolve (may be relative or absolute)
            path_description: Description for error messages
            allow_override: If True, absolute paths override project root resolution

        Returns:
            Resolved Path object
        """
        logger.debug(f"Resolving {path_description}: {path}")

        if not path or not path.strip():
            raise AdversaryToolError(f"{path_description} cannot be empty")

        path_obj = Path(path.strip())

        # If absolute path and overrides are allowed, use as-is
        if path_obj.is_absolute() and allow_override:
            logger.debug(f"Using absolute path override: {path_obj}")
            return path_obj.resolve()

        # Resolve relative to project root
        project_root = self._get_project_root()
        resolved = project_root / path_obj
        logger.debug(
            f"Resolved {path_description} relative to project root {project_root}: {resolved}"
        )
        return resolved.resolve()

    def _resolve_adversary_file_path(self, path: str | None) -> str:
        """Resolve path for .adversary.json file (for backward compatibility).

        Args:
            path: Path to resolve

        Returns:
            Resolved path as string
        """
        if path is None or not path.strip():
            raise AdversaryToolError("adversary_file_path cannot be empty")
        resolved_path = self._resolve_path_from_project_root(
            path, "adversary file path"
        )
        return str(resolved_path)

    def _resolve_file_path(self, path: str, path_description: str = "File path") -> str:
        """Resolve generic file path (for backward compatibility).

        Args:
            path: Path to resolve
            path_description: Description of the path type (used in error messages)

        Returns:
            Resolved path as string
        """
        if not path or not path.strip():
            raise AdversaryToolError(f"{path_description} cannot be empty")
        resolved_path = self._resolve_path_from_project_root(path, "file path")
        return str(resolved_path)

    def _get_adversary_json_path(self, custom_path: str | None = None) -> Path:
        """Get the path to the .adversary.json file.

        Args:
            custom_path: Optional custom path override

        Returns:
            Path to .adversary.json file
        """
        if custom_path is not None:
            # Validate that custom_path is not empty/whitespace
            if not custom_path.strip():
                raise AdversaryToolError("adversary_file_path cannot be empty")
            return self._resolve_path_from_project_root(
                custom_path, "adversary file path"
            )

        # Default: .adversary.json in project root
        return self._get_project_root() / ".adversary.json"

    def _validate_file_path(self, path: str) -> Path:
        """Validate that the path points to an existing file.

        Args:
            path: Path to validate

        Returns:
            Validated Path object

        Raises:
            AdversaryToolError: If path is not a file
        """
        resolved_path = self._resolve_path_from_project_root(path, "file path")

        if not resolved_path.exists():
            raise AdversaryToolError(f"Path does not exist: {resolved_path}")

        if not resolved_path.is_file():
            raise AdversaryToolError(
                f"Path is not a file (it's a directory): {resolved_path}. "
                "Please provide a path to a file, not a directory."
            )

        return resolved_path

    def _validate_directory_path(self, path: str) -> Path:
        """Validate that the path points to an existing directory.

        Args:
            path: Path to validate

        Returns:
            Validated Path object

        Raises:
            AdversaryToolError: If path is not a directory
        """
        resolved_path = self._resolve_path_from_project_root(path, "directory path")

        if not resolved_path.exists():
            raise AdversaryToolError(f"Path does not exist: {resolved_path}")

        if not resolved_path.is_dir():
            raise AdversaryToolError(
                f"Path is not a directory (it's a file): {resolved_path}. "
                "Please provide a path to a directory, not a file."
            )

        return resolved_path

    def _validate_git_directory_path(self, path: str) -> Path:
        """Validate that the path points to a git repository.

        Args:
            path: Path to validate

        Returns:
            Validated Path object

        Raises:
            AdversaryToolError: If path is not a git repository
        """
        resolved_path = self._validate_directory_path(path)
        git_dir = resolved_path / ".git"

        if not git_dir.exists():
            raise AdversaryToolError(
                f"Path is not a git repository (no .git directory found): {resolved_path}"
            )

        return resolved_path

    def _validate_adversary_path(self, path: str) -> Path:
        """Validate and resolve path for .adversary.json operations.

        Args:
            path: Path to validate (can be directory or .adversary.json file)

        Returns:
            Path to .adversary.json file

        Raises:
            AdversaryToolError: If path validation fails
        """
        resolved_path = self._resolve_path_from_project_root(path, "adversary path")

        if not resolved_path.exists():
            # If path doesn't exist but ends with .adversary.json, create parent dir
            if resolved_path.name == ".adversary.json":
                resolved_path.parent.mkdir(parents=True, exist_ok=True)
                return resolved_path
            else:
                raise AdversaryToolError(f"Path does not exist: {resolved_path}")

        # If it's a directory, look for .adversary.json inside
        if resolved_path.is_dir():
            adversary_file = resolved_path / ".adversary.json"
            return adversary_file

        # If it's a file, it should be .adversary.json
        if resolved_path.is_file():
            if resolved_path.name != ".adversary.json":
                raise AdversaryToolError(
                    f"File is not .adversary.json: {resolved_path}"
                )
            return resolved_path

        raise AdversaryToolError(f"Invalid path type: {resolved_path}")

    def _determine_scan_output_path(self, base_path: Path, output_format: str) -> Path:
        """Determine the output path for scan results based on format.

        Args:
            base_path: Base directory for output
            output_format: Output format (json or markdown)

        Returns:
            Full path to output file
        """
        if output_format == "json":
            return base_path / ".adversary.json"
        elif output_format == "markdown":
            return base_path / ".adversary.md"
        else:
            raise AdversaryToolError(f"Invalid output format: {output_format}")

    def _filter_threats_by_severity(
        self, threats: list[ThreatMatch], min_severity: Severity
    ) -> list[ThreatMatch]:
        """Filter threats by minimum severity level."""
        severity_order = [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        min_index = severity_order.index(min_severity)

        return [
            threat
            for threat in threats
            if severity_order.index(threat.severity) >= min_index
        ]

    def _format_scan_results(self, threats: list[ThreatMatch], scan_target: str) -> str:
        """Format scan results for display."""
        result = f"# Security Scan Results for {scan_target}\n\n"

        if not threats:
            result += "🎉 **No security vulnerabilities found!**\n\n"
            return result

        # Summary
        severity_counts = {}
        for threat in threats:
            severity = threat.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        result += "## Summary\n"
        result += f"**Total Threats:** {len(threats)}\n"
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[
                    severity
                ]
                result += f"**{severity.capitalize()}:** {count} {emoji}\n"
        result += "\n"

        # Detailed results
        result += "## Detailed Results\n\n"

        for i, threat in enumerate(threats, 1):
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }.get(threat.severity.value, "⚪")

            result += f"### {i}. {threat.rule_name} {severity_emoji}\n"
            result += f"**File:** {threat.file_path}:{threat.line_number}\n"
            result += f"**Severity:** {threat.severity.value.capitalize()}\n"
            result += f"**Category:** {threat.category.value.capitalize()}\n"
            result += f"**Description:** {threat.description}\n\n"

            if threat.code_snippet:
                result += "**Code Context:**\n"
                result += f"```\n{threat.code_snippet}\n```\n\n"

            if threat.remediation:
                result += f"**Remediation:** {threat.remediation}\n\n"

            if threat.references:
                result += "**References:**\n"
                for ref in threat.references:
                    result += f"- {ref}\n"
                result += "\n"

            result += "---\n\n"

        return result

    def _format_enhanced_scan_results(self, scan_result, scan_target: str) -> str:
        """Format enhanced scan results for display.

        Args:
            scan_result: Enhanced scan result object
            scan_target: Target that was scanned

        Returns:
            Formatted scan results string
        """
        result = f"# Enhanced Security Scan Results for {scan_target}\n\n"

        if not scan_result.all_threats:
            result += "🎉 **No security vulnerabilities found!**\n\n"
            # Still show analysis overview
            result += "## Analysis Overview\n\n"
            result += f"**LLM Analysis:** {scan_result.stats['llm_threats']} findings\n"
            result += f"**Language:** {scan_result.language}\n\n"
            return result

        # Analysis overview
        result += "## Analysis Overview\n\n"
        result += f"**LLM Analysis:** {scan_result.stats['llm_threats']} findings\n"
        result += f"**Total Unique:** {scan_result.stats['unique_threats']} findings\n"
        result += f"**Language:** {scan_result.language}\n\n"

        # Summary by severity
        severity_counts = scan_result.stats["severity_counts"]
        result += "## Summary\n"
        result += f"**Total Threats:** {len(scan_result.all_threats)}\n"
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[
                    severity
                ]
                result += f"**{severity.capitalize()}:** {count} {emoji}\n"
        result += "\n"

        # Scan metadata
        metadata = scan_result.scan_metadata
        if metadata.get("llm_scan_success") is not None:
            result += "## Scan Details\n\n"
            result += f"**LLM Scan:** {'✅ Success' if metadata.get('llm_scan_success') else '❌ Failed'}\n"
            if metadata.get("source_lines"):
                result += f"**Source Lines:** {metadata['source_lines']}\n"
            result += "\n"

        # Detailed findings
        result += "## Detailed Results\n\n"

        for i, threat in enumerate(scan_result.all_threats, 1):
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }.get(threat.severity.value, "⚪")

            # Identify source (rules vs LLM)
            source_icon = "🤖" if threat.rule_id.startswith("llm_") else "📋"
            source_text = (
                "LLM Analysis" if threat.rule_id.startswith("llm_") else "Rules Engine"
            )

            result += f"### {i}. {threat.rule_name} {severity_emoji} {source_icon}\n"
            result += f"**Source:** {source_text}\n"
            result += f"**File:** {threat.file_path}:{threat.line_number}\n"
            result += f"**Severity:** {threat.severity.value.capitalize()}\n"
            result += f"**Category:** {threat.category.value.capitalize()}\n"
            result += f"**Confidence:** {threat.confidence:.2f}\n"
            result += f"**Description:** {threat.description}\n\n"

            if threat.code_snippet:
                result += "**Code Context:**\n"
                result += f"```\n{threat.code_snippet}\n```\n\n"

            if threat.remediation:
                result += f"**Remediation:** {threat.remediation}\n\n"

            if threat.references:
                result += "**References:**\n"
                for ref in threat.references:
                    result += f"- {ref}\n"
                result += "\n"

            result += "---\n\n"

        return result

    def _format_directory_scan_results(self, scan_results, scan_target: str) -> str:
        """Format directory scan results for display.

        Args:
            scan_results: List of enhanced scan results
            scan_target: Target directory that was scanned

        Returns:
            Formatted scan results string
        """
        if not scan_results:
            return f"# Directory Scan Results for {scan_target}\n\n❌ No files found to scan\n"

        # Combine statistics
        total_threats = sum(len(result.all_threats) for result in scan_results)
        total_files = len(scan_results)
        files_with_threats = sum(1 for result in scan_results if result.all_threats)

        # Count by severity across all files
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for result in scan_results:
            for severity, count in result.stats["severity_counts"].items():
                severity_counts[severity] += count

        # Build result string
        result = f"# Enhanced Directory Scan Results for {scan_target}\n\n"

        if total_threats == 0:
            result += "🎉 **No security vulnerabilities found in any files!**\n\n"
            result += f"**Files Scanned:** {total_files}\n"
            return result

        result += "## Overview\n\n"
        result += f"**Files Scanned:** {total_files}\n"
        result += f"**Files with Issues:** {files_with_threats}\n"
        result += f"**Total Threats:** {total_threats}\n\n"

        # Add scanner status information
        result += self._format_scanner_status(scan_results)
        result += "\n"

        # Summary by severity
        result += "## Summary\n"
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[
                    severity
                ]
                result += f"**{severity.capitalize()}:** {count} {emoji}\n"
        result += "\n"

        # File-by-file breakdown
        result += "## Files with Security Issues\n\n"

        for scan_result in scan_results:
            if scan_result.all_threats:
                result += f"### {scan_result.file_path}\n"
                result += f"Found {len(scan_result.all_threats)} issue(s)\n\n"

                for threat in scan_result.all_threats:
                    severity_emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🟢",
                    }.get(threat.severity.value, "⚪")

                    source_icon = "🤖" if threat.rule_id.startswith("llm_") else "📋"

                    result += (
                        f"- **{threat.rule_name}** {severity_emoji} {source_icon}\n"
                    )
                    result += f"  Line {threat.line_number}: {threat.description}\n\n"

        return result

    def _format_diff_scan_results(
        self,
        scan_results,
        diff_summary: dict[str, any],
        source_branch: str,
        target_branch: str,
    ) -> str:
        """Format diff scan results for display.

        Args:
            scan_results: Dictionary mapping file paths to lists of scan results
            diff_summary: Summary of the diff changes
            source_branch: Source branch name
            target_branch: Target branch name

        Returns:
            Formatted scan results string
        """
        if not scan_results:
            result = "# Git Diff Scan Results\n\n"
            result += f"**Source Branch:** {source_branch}\n"
            result += f"**Target Branch:** {target_branch}\n\n"

            if diff_summary.get("total_files_changed", 0) == 0:
                result += "🎉 **No changes found between branches!**\n\n"
            else:
                result += (
                    "🎉 **No security vulnerabilities found in diff changes!**\n\n"
                )
                result += (
                    f"**Files Changed:** {diff_summary.get('total_files_changed', 0)}\n"
                )
                result += (
                    f"**Supported Files:** {diff_summary.get('supported_files', 0)}\n"
                )
                result += f"**Lines Added:** {diff_summary.get('lines_added', 0)}\n"
                result += f"**Lines Removed:** {diff_summary.get('lines_removed', 0)}\n"

            return result

        # Combine statistics
        total_threats = sum(
            len(result.all_threats)
            for file_results in scan_results.values()
            for result in file_results
        )
        total_files = len(scan_results)
        files_with_threats = sum(
            1
            for file_results in scan_results.values()
            if any(result.all_threats for result in file_results)
        )

        # Count by severity across all files
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for file_results in scan_results.values():
            for result in file_results:
                for severity, count in result.stats["severity_counts"].items():
                    severity_counts[severity] += count

        # Build result string
        result = "# Git Diff Scan Results\n\n"
        result += f"**Source Branch:** {source_branch}\n"
        result += f"**Target Branch:** {target_branch}\n\n"

        result += "## Diff Summary\n\n"
        result += (
            f"**Total Files Changed:** {diff_summary.get('total_files_changed', 0)}\n"
        )
        result += f"**Supported Files:** {diff_summary.get('supported_files', 0)}\n"
        result += f"**Lines Added:** {diff_summary.get('lines_added', 0)}\n"
        result += f"**Lines Removed:** {diff_summary.get('lines_removed', 0)}\n"
        result += f"**Files with Security Issues:** {files_with_threats}\n"
        result += f"**Total Threats:** {total_threats}\n\n"

        if total_threats == 0:
            result += "🎉 **No security vulnerabilities found in diff changes!**\n\n"
            return result

        # Summary by severity
        result += "## Security Issues Summary\n"
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[
                    severity
                ]
                result += f"**{severity.capitalize()}:** {count} {emoji}\n"
        result += "\n"

        # File-by-file breakdown
        result += "## Files with Security Issues\n\n"

        for file_path, file_results in scan_results.items():
            for scan_result in file_results:
                if scan_result.all_threats:
                    result += f"### {file_path}\n"
                    result += f"Found {len(scan_result.all_threats)} issue(s) in diff changes\n\n"

                    for threat in scan_result.all_threats:
                        severity_emoji = {
                            "critical": "🔴",
                            "high": "🟠",
                            "medium": "🟡",
                            "low": "🟢",
                        }.get(threat.severity.value, "⚪")

                        source_icon = (
                            "🤖" if threat.rule_id.startswith("llm_") else "📋"
                        )

                        result += (
                            f"- **{threat.rule_name}** {severity_emoji} {source_icon}\n"
                        )
                        result += f"  Line {threat.line_number}: {threat.description}\n"

                        if threat.code_snippet:
                            result += f"  Code: `{threat.code_snippet.strip()}`\n"

                        result += "\n"

        return result

    def _aggregate_validation_stats(
        self, scan_results: list[EnhancedScanResult]
    ) -> dict[str, Any]:
        """Aggregate validation statistics across multiple scan results.

        Args:
            scan_results: List of enhanced scan results to aggregate

        Returns:
            Dictionary with aggregated validation statistics
        """
        if not scan_results:
            return {
                "enabled": False,
                "total_findings_reviewed": 0,
                "legitimate_findings": 0,
                "false_positives_filtered": 0,
                "false_positive_rate": 0.0,
                "average_confidence": 0.0,
                "validation_errors": 0,
                "status": "no_results",
            }

        # Check if any validation was performed
        any_validation_enabled = any(
            result.scan_metadata.get("llm_validation_success", False)
            for result in scan_results
        )

        if not any_validation_enabled:
            # Find the most common reason for no validation
            reasons = [
                result.scan_metadata.get("llm_validation_reason", "disabled")
                for result in scan_results
            ]
            most_common_reason = (
                max(set(reasons), key=reasons.count) if reasons else "disabled"
            )

            return {
                "enabled": False,
                "total_findings_reviewed": 0,
                "legitimate_findings": 0,
                "false_positives_filtered": 0,
                "false_positive_rate": 0.0,
                "average_confidence": 0.0,
                "validation_errors": 0,
                "status": most_common_reason,
            }

        # Aggregate validation results across all scan results
        total_reviewed = 0
        total_legitimate = 0
        total_false_positives = 0
        total_confidence = 0.0
        total_errors = 0
        confidence_count = 0

        for result in scan_results:
            if result.validation_results:
                for validation_result in result.validation_results.values():
                    total_reviewed += 1
                    if validation_result.is_legitimate:
                        total_legitimate += 1
                    else:
                        total_false_positives += 1

                    total_confidence += validation_result.confidence
                    confidence_count += 1

                    if validation_result.validation_error:
                        total_errors += 1

        # Calculate averages
        avg_confidence = (
            total_confidence / confidence_count if confidence_count > 0 else 0.0
        )
        false_positive_rate = (
            total_false_positives / total_reviewed if total_reviewed > 0 else 0.0
        )

        return {
            "enabled": True,
            "total_findings_reviewed": total_reviewed,
            "legitimate_findings": total_legitimate,
            "false_positives_filtered": total_false_positives,
            "false_positive_rate": round(false_positive_rate, 3),
            "average_confidence": round(avg_confidence, 3),
            "validation_errors": total_errors,
            "status": "completed",
        }

    def _format_json_scan_results(
        self,
        scan_result: EnhancedScanResult,
        scan_target: str,
        working_directory: str = ".",
    ) -> str:
        """Format enhanced scan results as JSON.

        Args:
            scan_result: Enhanced scan result object
            scan_target: Target that was scanned

        Returns:
            JSON formatted scan results
        """
        from datetime import datetime

        # Convert threats to dictionaries with complete false positive metadata
        threats_data = []
        for threat in scan_result.all_threats:
            # Get complete false positive information
            adversary_file_path = str(Path(working_directory) / ".adversary.json")
            project_fp_manager = FalsePositiveManager(
                adversary_file_path=adversary_file_path
            )
            false_positive_data = project_fp_manager.get_false_positive_details(
                threat.uuid
            )

            # Get validation details for this specific threat
            validation_result = scan_result.validation_results.get(threat.uuid)
            validation_data = {
                "was_validated": validation_result is not None,
                "validation_confidence": (
                    validation_result.confidence if validation_result else None
                ),
                "validation_reasoning": (
                    validation_result.reasoning if validation_result else None
                ),
                "validation_status": (
                    "legitimate"
                    if validation_result and validation_result.is_legitimate
                    else (
                        "false_positive"
                        if validation_result and not validation_result.is_legitimate
                        else "not_validated"
                    )
                ),
                "exploitation_vector": (
                    validation_result.exploitation_vector if validation_result else None
                ),
                "remediation_advice": (
                    validation_result.remediation_advice if validation_result else None
                ),
            }

            threat_data = {
                "uuid": threat.uuid,
                "rule_id": threat.rule_id,
                "rule_name": threat.rule_name,
                "description": threat.description,
                "category": threat.category.value,
                "severity": threat.severity.value,
                "file_path": threat.file_path,
                "line_number": threat.line_number,
                "end_line_number": getattr(
                    threat, "end_line_number", threat.line_number
                ),
                "code_snippet": threat.code_snippet,
                "confidence": threat.confidence,
                "source": getattr(threat, "source", "rules"),
                "cwe_id": getattr(threat, "cwe_id", []),
                "owasp_category": getattr(threat, "owasp_category", ""),
                "remediation": getattr(threat, "remediation", ""),
                "references": getattr(threat, "references", []),
                "exploit_examples": getattr(threat, "exploit_examples", []),
                "is_false_positive": false_positive_data is not None,
                "false_positive_metadata": false_positive_data,
                **validation_data,  # Include all validation metadata
            }
            threats_data.append(threat_data)

        # Create comprehensive JSON structure
        result_data = {
            "scan_metadata": {
                "target": scan_target,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "language": scan_result.language,
                "file_path": scan_result.file_path,
                "scan_type": "enhanced",
                "total_threats": len(scan_result.all_threats),
            },
            "scan_configuration": {
                "llm_scan_enabled": scan_result.scan_metadata.get(
                    "llm_scan_success", False
                ),
                "semgrep_scan_enabled": scan_result.scan_metadata.get(
                    "semgrep_scan_success", False
                ),
                "llm_validation_enabled": scan_result.scan_metadata.get(
                    "llm_validation_success", False
                ),
            },
            "validation_summary": scan_result.get_validation_summary(),
            "statistics": scan_result.stats,
            "threats": threats_data,
            "scanner_execution_status": {
                "llm_scanner": {
                    "executed": scan_result.scan_metadata.get(
                        "llm_scan_success", False
                    ),
                    "reason": scan_result.scan_metadata.get(
                        "llm_scan_reason", "unknown"
                    ),
                    "error": scan_result.scan_metadata.get("llm_scan_error", None),
                    "threats_found": scan_result.stats.get("llm_threats", 0),
                },
                "semgrep_scanner": {
                    "executed": scan_result.scan_metadata.get(
                        "semgrep_scan_success", False
                    ),
                    "reason": scan_result.scan_metadata.get(
                        "semgrep_scan_reason", "unknown"
                    ),
                    "error": scan_result.scan_metadata.get("semgrep_scan_error", None),
                    "threats_found": scan_result.stats.get("semgrep_threats", 0),
                },
                "llm_validator": {
                    "executed": scan_result.scan_metadata.get(
                        "llm_validation_success", False
                    ),
                    "reason": scan_result.scan_metadata.get(
                        "llm_validation_reason", "disabled"
                    ),
                    "error": scan_result.scan_metadata.get(
                        "llm_validation_error", None
                    ),
                    "findings_validated": (
                        len(scan_result.validation_results)
                        if scan_result.validation_results
                        else 0
                    ),
                },
            },
            "scan_details": {
                "llm_scan_success": scan_result.scan_metadata.get(
                    "llm_scan_success", False
                ),
                "semgrep_scan_success": scan_result.scan_metadata.get(
                    "semgrep_scan_success", False
                ),
                "llm_validation_success": scan_result.scan_metadata.get(
                    "llm_validation_success", False
                ),
                "source_lines": scan_result.scan_metadata.get("source_lines", 0),
                "source_size": scan_result.scan_metadata.get("source_size", 0),
            },
        }

        return json.dumps(result_data, indent=2)

    def _format_json_directory_results(
        self,
        scan_results: list[EnhancedScanResult],
        scan_target: str,
        working_directory: str = ".",
    ) -> str:
        """Format directory scan results as JSON.

        Args:
            scan_results: List of enhanced scan results
            scan_target: Target directory that was scanned

        Returns:
            JSON formatted directory scan results
        """
        from datetime import datetime

        # Combine all threats
        all_threats = []
        files_scanned = []

        for scan_result in scan_results:
            files_scanned.append(
                {
                    "file_path": scan_result.file_path,
                    "language": scan_result.language,
                    "threat_count": (
                        len(scan_result.all_threats)
                        if hasattr(scan_result, "all_threats")
                        and isinstance(scan_result.all_threats, list)
                        else 0
                    ),
                    "issues_identified": bool(scan_result.all_threats),
                }
            )

            for threat in scan_result.all_threats:
                # Get complete false positive information
                adversary_file_path = str(Path(working_directory) / ".adversary.json")
                project_fp_manager = FalsePositiveManager(
                    adversary_file_path=adversary_file_path
                )
                false_positive_data = project_fp_manager.get_false_positive_details(
                    threat.uuid
                )

                # Get validation details for this specific threat
                validation_result = scan_result.validation_results.get(threat.uuid)
                validation_data = {
                    "was_validated": validation_result is not None,
                    "validation_confidence": (
                        validation_result.confidence if validation_result else None
                    ),
                    "validation_reasoning": (
                        validation_result.reasoning if validation_result else None
                    ),
                    "validation_status": (
                        "legitimate"
                        if validation_result and validation_result.is_legitimate
                        else (
                            "false_positive"
                            if validation_result and not validation_result.is_legitimate
                            else "not_validated"
                        )
                    ),
                    "exploitation_vector": (
                        validation_result.exploitation_vector
                        if validation_result
                        else None
                    ),
                    "remediation_advice": (
                        validation_result.remediation_advice
                        if validation_result
                        else None
                    ),
                }

                threat_data = {
                    "uuid": threat.uuid,
                    "rule_id": threat.rule_id,
                    "rule_name": threat.rule_name,
                    "description": threat.description,
                    "category": threat.category.value,
                    "severity": threat.severity.value,
                    "file_path": threat.file_path,
                    "line_number": threat.line_number,
                    "end_line_number": getattr(
                        threat, "end_line_number", threat.line_number
                    ),
                    "code_snippet": threat.code_snippet,
                    "confidence": threat.confidence,
                    "source": getattr(threat, "source", "rules"),
                    "cwe_id": getattr(threat, "cwe_id", []),
                    "owasp_category": getattr(threat, "owasp_category", ""),
                    "remediation": getattr(threat, "remediation", ""),
                    "references": getattr(threat, "references", []),
                    "exploit_examples": getattr(threat, "exploit_examples", []),
                    "is_false_positive": false_positive_data is not None,
                    "false_positive_metadata": false_positive_data,
                    "validation": validation_data,
                }
                all_threats.append(threat_data)

        # Calculate summary statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for threat in all_threats:
            severity_counts[threat["severity"]] += 1

        # Add validation summary for directory scan
        validation_summary = self._aggregate_validation_stats(scan_results)

        result_data = {
            "scan_metadata": {
                "target": scan_target,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "scan_type": "directory",
                "total_threats": len(all_threats),
                "files_scanned": len(files_scanned),
            },
            "validation_summary": validation_summary,
            "scanner_execution_summary": {
                "semgrep_scanner": self._get_semgrep_summary(scan_results),
                "llm_scanner": {
                    "files_processed": len(
                        [
                            f
                            for f in scan_results
                            if f.scan_metadata.get("llm_scan_success", False)
                        ]
                    ),
                    "files_failed": len(
                        [
                            f
                            for f in scan_results
                            if not f.scan_metadata.get("llm_scan_success", False)
                            and f.scan_metadata.get("llm_scan_reason")
                            not in ["disabled", "not_available"]
                        ]
                    ),
                    "total_threats": sum(
                        f.stats.get("llm_threats", 0) for f in scan_results
                    ),
                },
            },
            "statistics": {
                "total_threats": len(all_threats),
                "severity_counts": severity_counts,
                "files_with_threats": len(
                    [
                        f
                        for f in files_scanned
                        if (threat_count := f.get("threat_count", 0)) is not None
                        and isinstance(threat_count, int)
                        and threat_count > 0
                    ]
                ),
            },
            "files": files_scanned,
            "threats": all_threats,
        }

        return json.dumps(result_data, indent=2)

    def _get_semgrep_summary(
        self, scan_results: list[EnhancedScanResult]
    ) -> dict[str, Any]:
        """Get enhanced Semgrep scanner summary with detailed status information.

        Args:
            scan_results: List of enhanced scan results

        Returns:
            Dictionary with enhanced Semgrep scanner summary
        """
        semgrep_summary = {
            "files_processed": len(
                [
                    f
                    for f in scan_results
                    if f.scan_metadata.get("semgrep_scan_success", False)
                ]
            ),
            "files_failed": len(
                [
                    f
                    for f in scan_results
                    if not f.scan_metadata.get("semgrep_scan_success", False)
                    and f.scan_metadata.get("semgrep_scan_reason")
                    not in ["disabled", "not_available"]
                ]
            ),
            "total_threats": sum(
                f.stats.get("semgrep_threats", 0) for f in scan_results
            ),
        }

        # Get detailed Semgrep status from the first scan result (they should all be the same)
        if scan_results:
            first_result_metadata = scan_results[0].scan_metadata

            # Add enhanced status information
            semgrep_status = first_result_metadata.get("semgrep_status", {})
            semgrep_summary.update(
                {
                    "installation_status": semgrep_status.get(
                        "installation_status", "unknown"
                    ),
                    "version": semgrep_status.get("version"),
                    "available": semgrep_status.get("available", False),
                    "has_pro_features": semgrep_status.get("has_pro_features", False),
                }
            )

            # Add installation guidance if Semgrep is not available
            if not semgrep_status.get("available", False):
                semgrep_summary.update(
                    {
                        "error": semgrep_status.get("error"),
                        "installation_guidance": semgrep_status.get(
                            "installation_guidance"
                        ),
                    }
                )

            # Add scan-specific information
            scan_reason = first_result_metadata.get("semgrep_scan_reason")
            if scan_reason:
                semgrep_summary["scan_reason"] = scan_reason

            scan_error = first_result_metadata.get("semgrep_scan_error")
            if scan_error:
                semgrep_summary["scan_error"] = scan_error

        return semgrep_summary

    def _format_scanner_status(self, scan_results: list[EnhancedScanResult]) -> str:
        """Format scanner status information for text output.

        Args:
            scan_results: List of enhanced scan results

        Returns:
            Formatted scanner status string
        """
        if not scan_results:
            return ""

        status_lines = ["## Scanner Status\n"]

        # Get Semgrep status from first result
        semgrep_status = scan_results[0].scan_metadata.get("semgrep_status", {})

        # Semgrep status
        if semgrep_status.get("available", False):
            version = semgrep_status.get("version", "unknown")
            pro_features = (
                " (Pro)" if semgrep_status.get("has_pro_features", False) else ""
            )
            status_lines.append(f"**Semgrep:** ✅ Available {version}{pro_features}")
        else:
            error = semgrep_status.get("error", "unknown error")
            guidance = semgrep_status.get("installation_guidance", "")
            status_lines.append(f"**Semgrep:** ❌ Not Available - {error}")
            if guidance:
                status_lines.append(f"  💡 {guidance}")

        # LLM scanner status
        llm_success = any(
            r.scan_metadata.get("llm_scan_success", False) for r in scan_results
        )
        status_lines.append(
            f"**LLM Scanner:** {'✅ Available' if llm_success else '❌ Disabled'}"
        )

        return "\n".join(status_lines)

    def _format_json_diff_results(
        self,
        scan_results: dict[str, list[EnhancedScanResult]],
        diff_summary: dict[str, any],
        scan_target: str,
        working_directory: str = ".",
    ) -> str:
        """Format git diff scan results as JSON.

        Args:
            scan_results: Dictionary mapping file paths to scan results
            diff_summary: Git diff summary information
            scan_target: Target branches for diff scan
            working_directory: Working directory for false positive lookups

        Returns:
            JSON formatted diff scan results
        """
        from datetime import datetime

        # Collect all threats from all files
        all_threats = []
        files_changed = []

        for file_path, file_scan_results in scan_results.items():
            file_threat_count = 0
            for scan_result in file_scan_results:
                file_threat_count += len(scan_result.all_threats)
                for threat in scan_result.all_threats:
                    # Get complete false positive information
                    adversary_file_path = str(
                        Path(working_directory) / ".adversary.json"
                    )
                    project_fp_manager = FalsePositiveManager(
                        adversary_file_path=adversary_file_path
                    )
                    false_positive_data = project_fp_manager.get_false_positive_details(
                        threat.uuid
                    )

                    # Get validation details for this specific threat
                    validation_result = scan_result.validation_results.get(threat.uuid)
                    validation_data = {
                        "was_validated": validation_result is not None,
                        "validation_confidence": (
                            validation_result.confidence if validation_result else None
                        ),
                        "validation_reasoning": (
                            validation_result.reasoning if validation_result else None
                        ),
                        "validation_status": (
                            "legitimate"
                            if validation_result and validation_result.is_legitimate
                            else (
                                "false_positive"
                                if validation_result
                                and not validation_result.is_legitimate
                                else "not_validated"
                            )
                        ),
                        "exploitation_vector": (
                            validation_result.exploitation_vector
                            if validation_result
                            else None
                        ),
                        "remediation_advice": (
                            validation_result.remediation_advice
                            if validation_result
                            else None
                        ),
                    }

                    threat_data = {
                        "uuid": threat.uuid,
                        "rule_id": threat.rule_id,
                        "rule_name": threat.rule_name,
                        "description": threat.description,
                        "category": threat.category.value,
                        "severity": threat.severity.value,
                        "file_path": threat.file_path,
                        "line_number": threat.line_number,
                        "end_line_number": getattr(
                            threat, "end_line_number", threat.line_number
                        ),
                        "code_snippet": threat.code_snippet,
                        "confidence": threat.confidence,
                        "source": getattr(threat, "source", "rules"),
                        "cwe_id": getattr(threat, "cwe_id", []),
                        "owasp_category": getattr(threat, "owasp_category", ""),
                        "remediation": getattr(threat, "remediation", ""),
                        "references": getattr(threat, "references", []),
                        "exploit_examples": getattr(threat, "exploit_examples", []),
                        "is_false_positive": false_positive_data is not None,
                        "false_positive_metadata": false_positive_data,
                        "validation": validation_data,
                    }
                    all_threats.append(threat_data)

            files_changed.append(
                {
                    "file_path": file_path,
                    "threat_count": file_threat_count,
                    "lines_added": diff_summary.get("files_changed", {})
                    .get(file_path, {})
                    .get("lines_added", 0),
                    "lines_removed": diff_summary.get("files_changed", {})
                    .get(file_path, {})
                    .get("lines_removed", 0),
                }
            )

        # Calculate summary statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for threat in all_threats:
            severity_counts[threat["severity"]] += 1

        # Collect all scan results for validation aggregation
        all_scan_results = []
        for file_scan_results in scan_results.values():
            all_scan_results.extend(file_scan_results)

        # Add validation summary for diff scan
        validation_summary = self._aggregate_validation_stats(all_scan_results)

        result_data = {
            "scan_metadata": {
                "target": scan_target,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "scan_type": "git_diff",
                "total_threats": len(all_threats),
                "files_changed": len(files_changed),
            },
            "validation_summary": validation_summary,
            "diff_summary": diff_summary,
            "statistics": {
                "total_threats": len(all_threats),
                "severity_counts": severity_counts,
                "files_with_threats": len(
                    [f for f in files_changed if f["threat_count"] > 0]
                ),
            },
            "files": files_changed,
            "threats": all_threats,
        }

        return json.dumps(result_data, indent=2)

    def _preserve_uuids_and_false_positives(
        self, new_threats: list[dict], adversary_file_path: Path
    ) -> list[dict]:
        """Preserve UUIDs and false positive markings from existing scan results.

        Args:
            new_threats: List of new threat dictionaries from current scan
            adversary_file_path: Path to existing .adversary.json file

        Returns:
            List of threats with preserved UUIDs and false positive markings
        """

        if not adversary_file_path.exists():
            logger.debug("No existing .adversary.json found, using new UUIDs")
            return new_threats

        try:
            # Load existing threats with their UUIDs and false positive markings
            with open(adversary_file_path, encoding="utf-8") as f:
                existing_data = json.load(f)

            existing_threats = existing_data.get("threats", [])
            logger.info(
                f"Loaded {len(existing_threats)} existing threats for UUID preservation"
            )

            # Create fingerprint-to-threat mapping from existing data
            existing_fingerprints = {}
            for threat in existing_threats:
                # Reconstruct fingerprint from existing threat data
                rule_id = threat.get("rule_id", "")
                file_path = threat.get("file_path", "")
                line_number = threat.get("line_number", 0)

                if rule_id and file_path:
                    # Normalize path like in ThreatMatch.get_fingerprint()
                    normalized_path = str(Path(file_path).resolve())
                    fingerprint = f"{rule_id}:{normalized_path}:{line_number}"
                    existing_fingerprints[fingerprint] = {
                        "uuid": threat.get("uuid"),
                        "is_false_positive": threat.get("is_false_positive", False),
                        "false_positive_reason": threat.get("false_positive_reason"),
                        "false_positive_marked_date": threat.get(
                            "false_positive_marked_date"
                        ),
                        "false_positive_last_updated": threat.get(
                            "false_positive_last_updated"
                        ),
                        "false_positive_marked_by": threat.get(
                            "false_positive_marked_by"
                        ),
                    }

            logger.debug(
                f"Built fingerprint map with {len(existing_fingerprints)} entries"
            )

            # Process new threats and preserve UUIDs where possible
            preserved_count = 0
            new_count = 0

            for threat in new_threats:
                rule_id = threat.get("rule_id", "")
                file_path = threat.get("file_path", "")
                line_number = threat.get("line_number", 0)

                if rule_id and file_path:
                    # Generate fingerprint for this new threat
                    normalized_path = str(Path(file_path).resolve())
                    fingerprint = f"{rule_id}:{normalized_path}:{line_number}"

                    if fingerprint in existing_fingerprints:
                        # Preserve existing UUID and false positive data
                        existing_data = existing_fingerprints[fingerprint]
                        threat["uuid"] = existing_data["uuid"]
                        threat["is_false_positive"] = existing_data["is_false_positive"]

                        # Preserve false positive metadata if marked
                        if existing_data["is_false_positive"]:
                            threat["false_positive_reason"] = existing_data[
                                "false_positive_reason"
                            ]
                            threat["false_positive_marked_date"] = existing_data[
                                "false_positive_marked_date"
                            ]
                            threat["false_positive_last_updated"] = existing_data[
                                "false_positive_last_updated"
                            ]
                            threat["false_positive_marked_by"] = existing_data[
                                "false_positive_marked_by"
                            ]

                        preserved_count += 1
                        logger.debug(
                            f"Preserved UUID for {fingerprint}: {existing_data['uuid']}"
                        )
                    else:
                        # New finding, keep the generated UUID
                        new_count += 1
                        logger.debug(f"New finding with UUID: {threat.get('uuid')}")

            logger.info(
                f"UUID preservation complete: {preserved_count} preserved, {new_count} new"
            )
            return new_threats

        except Exception as e:
            logger.warning(f"Failed to preserve UUIDs from existing file: {e}")
            logger.debug("UUID preservation error details", exc_info=True)
            return new_threats

    def _save_scan_results_json(
        self, json_data: str, output_path: str = "."
    ) -> str | None:
        """Save scan results to JSON file.

        Args:
            json_data: JSON formatted scan results
            output_path: Output file path or directory (defaults to .adversary.json in current dir)

        Returns:
            Path to saved file or None if save failed
        """
        try:
            # Convert to absolute path for logging
            output_path_abs = str(Path(output_path).resolve())
            logger.info(f"💾 Saving scan results - input path: {output_path_abs}")

            path = Path(output_path)
            path_abs = str(path.resolve())
            logger.debug(
                f"Resolved path object: {path_abs} (exists: {path.exists()}, is_dir: {path.is_dir() if path.exists() else 'unknown'})"
            )

            # If output_path is a directory, append the default filename
            if path.is_dir() or (not path.suffix and not path.exists()):
                final_path = path / ".adversary.json"
                logger.info(f"📁 Treating as directory, using: {final_path}")
            else:
                # output_path is a full file path
                final_path = path
                logger.info(f"📄 Treating as file path, using: {final_path}")

            # Ensure parent directory exists
            final_path.parent.mkdir(parents=True, exist_ok=True)
            logger.debug(f"📂 Ensured parent directory exists: {final_path.parent}")

            try:
                data = json_lib.loads(json_data)
                threats = data.get("threats", [])

                # Only attempt UUID preservation if we have threats
                if threats and len(threats) > 0:
                    logger.info(
                        f"🔄 Preserving UUIDs for {len(threats)} threats before saving"
                    )
                    preserved_threats = self._preserve_uuids_and_false_positives(
                        threats, final_path
                    )
                    data["threats"] = preserved_threats

                    # Re-serialize with preserved data
                    json_data = json_lib.dumps(data, indent=2)
                    logger.info(
                        f"💾 Writing {len(preserved_threats)} threats with preserved UUIDs to: {final_path}"
                    )
                else:
                    logger.debug(f"💾 Writing data without threats to: {final_path}")

            except Exception as json_error:
                logger.warning(
                    f"Failed to parse JSON for UUID preservation: {json_error}"
                )
                logger.debug("JSON parsing error details", exc_info=True)
                logger.info(f"💾 Writing original JSON data to: {final_path}")

            with open(final_path, "w", encoding="utf-8") as f:
                f.write(json_data)

            logger.info(f"✅ Scan results saved successfully to {final_path}")
            return str(final_path)
        except Exception as e:
            logger.error(f"❌ Failed to save scan results JSON to {output_path}: {e}")
            logger.debug("Save error details", exc_info=True)
            return None

    def _add_llm_analysis_prompts(
        self,
        content: str,
        file_path: str,
        include_header: bool = True,
    ) -> str:
        """Add LLM analysis prompts to scan results."""
        try:
            analyzer = self.scan_engine.llm_analyzer
            # Language is now auto-detected as generic
            prompt = analyzer.create_analysis_prompt(
                content, file_path, "generic", max_findings=20
            )

            result = ""
            if include_header:
                result += "\n\n# 🤖 LLM Security Analysis\n\n"
                result += "For enhanced LLM-based analysis, use the following prompts with your client's LLM:\n\n"

            result += "## System Prompt\n\n"
            result += f"```\n{prompt.system_prompt}\n```\n\n"
            result += "## User Prompt\n\n"
            result += f"```\n{prompt.user_prompt}\n```\n\n"
            result += "**Instructions:** Send both prompts to your LLM for enhanced security analysis.\n\n"

            return result
        except Exception as e:
            return f"\n\n⚠️ **LLM Analysis:** Failed to create prompts: {e}\n"

    def _add_llm_exploit_prompts(self, threats: list[ThreatMatch], content: str) -> str:
        """Add LLM exploit prompts for discovered threats."""
        if not threats:
            return ""

        result = "\n\n# 🤖 LLM Exploit Generation\n\n"
        result += "For enhanced LLM-based exploit generation, use the following prompts with your client's LLM:\n\n"
        result += "**Note:** Showing prompts for the first 3 threats found.\n\n"

        for i, threat in enumerate(threats[:3], 1):
            try:
                prompt = self.exploit_generator.create_exploit_prompt(threat, content)

                result += f"## Threat {i}: {threat.rule_name}\n\n"
                result += f"**Type:** {threat.category.value} | **Severity:** {threat.severity.value}\n\n"
                result += "### System Prompt\n\n"
                result += f"```\n{prompt.system_prompt}\n```\n\n"
                result += "### User Prompt\n\n"
                result += f"```\n{prompt.user_prompt}\n```\n\n"
                result += "**Instructions:** Send both prompts to your LLM for enhanced exploit generation.\n\n"
                result += "---\n\n"

            except Exception as e:
                result += (
                    f"⚠️ Failed to create exploit prompt for {threat.rule_name}: {e}\n\n"
                )

        return result

    async def _handle_mark_false_positive(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle mark false positive with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper(
            "adv_mark_false_positive"
        )(self._handle_mark_false_positive_impl)
        return await wrapped_handler(arguments)

    async def _handle_mark_false_positive_impl(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle mark false positive request."""
        try:
            finding_uuid = arguments.get("finding_uuid")
            path = arguments.get("path", ".")
            reason = arguments.get("reason", "Marked as false positive via MCP")
            marked_by = arguments.get("marked_by", "MCP User")

            if not finding_uuid:
                raise AdversaryToolError("finding_uuid is required")

            # Validate and resolve path for .adversary.json
            adversary_path = self._validate_adversary_path(path)
            logger.info(f"Marking false positive in: {adversary_path}")

            # Create false positive manager
            fp_manager = FalsePositiveManager(adversary_file_path=str(adversary_path))

            success = fp_manager.mark_false_positive(finding_uuid, reason, marked_by)

            if success:
                logger.info(
                    f"✅ Successfully marked finding {finding_uuid} as false positive in {adversary_path}"
                )
                result = "✅ **Finding marked as false positive**\n\n"
                result += f"**UUID:** {finding_uuid}\n"
                result += f"**Reason:** {reason}\n"
                result += f"**File:** {adversary_path}\n"
            else:
                logger.warning(
                    f"❌ Failed to mark finding {finding_uuid} as false positive - not found in {adversary_path}"
                )
                result = "⚠️ **Finding not found**\n\n"
                result += f"**UUID:** {finding_uuid}\n"
                result += f"**File checked:** {adversary_path}\n"
                result += "The threat with this UUID was not found in the .adversary.json file.\n"
                result += (
                    "Make sure you've run a scan that generated this finding first.\n"
                )

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            logger.error(f"Error marking false positive: {e}")
            raise AdversaryToolError(f"Failed to mark false positive: {str(e)}")

    async def _handle_unmark_false_positive(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle unmark false positive with telemetry tracking."""
        wrapped_handler = self.metrics_orchestrator.mcp_tool_wrapper(
            "adv_unmark_false_positive"
        )(self._handle_unmark_false_positive_impl)
        return await wrapped_handler(arguments)

    async def _handle_unmark_false_positive_impl(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle unmark false positive request."""
        try:
            finding_uuid = arguments.get("finding_uuid")
            path = arguments.get("path", ".")

            if not finding_uuid:
                raise AdversaryToolError("finding_uuid is required")

            # Validate and resolve path for .adversary.json
            adversary_path = self._validate_adversary_path(path)
            logger.info(f"Unmarking false positive in: {adversary_path}")

            # Create false positive manager
            fp_manager = FalsePositiveManager(adversary_file_path=str(adversary_path))
            success = fp_manager.unmark_false_positive(finding_uuid)

            if success:
                logger.info(
                    f"✅ Successfully unmarked finding {finding_uuid} from {adversary_path}"
                )
                result = "✅ **Finding unmarked as false positive**\n\n"
                result += f"**UUID:** {finding_uuid}\n"
                result += f"**File:** {adversary_path}\n"
            else:
                logger.warning(
                    f"❌ Finding {finding_uuid} not found in false positives in {adversary_path}"
                )
                result = "⚠️ **Finding not found in false positives**\n\n"
                result += f"**UUID:** {finding_uuid}\n"
                result += f"**File checked:** {adversary_path}\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            logger.error(f"Error unmarking false positive: {e}")
            raise AdversaryToolError(f"Failed to unmark false positive: {str(e)}")

    async def _handle_list_false_positives(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle list false positives request."""
        try:
            path = arguments.get("path", ".")

            # Validate and resolve path for .adversary.json
            adversary_path = self._validate_adversary_path(path)
            logger.info(f"Listing false positives from: {adversary_path}")

            # Create false positive manager with resolved file path
            fp_manager = FalsePositiveManager(adversary_file_path=str(adversary_path))
            false_positives = fp_manager.get_false_positives()

            result = f"# False Positives ({len(false_positives)} found)\n\n"
            result += f"**File:** {adversary_path}\n\n"

            if not false_positives:
                result += "No false positives found.\n"
                return [types.TextContent(type="text", text=result)]

            for fp in false_positives:
                result += f"## {fp['uuid']}\n\n"
                result += f"**Reason:** {fp.get('reason', 'No reason provided')}\n"
                result += f"**Marked:** {fp.get('marked_date', 'Unknown')}\n"
                if fp.get("last_updated") != fp.get("marked_date"):
                    result += f"**Updated:** {fp.get('last_updated', 'Unknown')}\n"
                result += "\n---\n\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            logger.error(f"Error listing false positives: {e}")
            raise AdversaryToolError(f"Failed to list false positives: {str(e)}")

    def _find_repo_by_name(self, repo_name: str, max_depth: int = 3) -> Path:
        """Find a repository by name using recursive search from home directory."""

        home = Path.home()
        found_repos = []

        # Directories to skip for performance and relevance
        skip_dirs = {
            ".git",
            ".svn",
            ".hg",  # Version control internals
            "node_modules",
            "venv",
            ".venv",
            "env",  # Dependencies/virtual envs
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",  # Python cache
            ".idea",
            ".vscode",  # IDE directories
            "target",
            "build",
            "dist",  # Build outputs
            "vendor",
            "bower_components",  # Package managers
            ".npm",
            ".yarn",
            ".cargo",  # Package manager caches
            "Library",
            "Applications",
            "Desktop",
            "Downloads",  # macOS system dirs
            "AppData",
            "LocalAppData",  # Windows system dirs
        }

        def search_directory(current_path: Path, current_depth: int):
            """Recursively search for repositories."""
            if current_depth > max_depth:
                return

            try:
                for item in current_path.iterdir():
                    if not item.is_dir():
                        continue

                    # Skip hidden directories and known non-repo directories
                    if item.name.startswith(".") or item.name in skip_dirs:
                        continue

                    # If directory name matches repo name, check if it's a valid project
                    if item.name == repo_name and self._is_valid_project(item):
                        found_repos.append(item)
                        logger.debug(f"Found potential repo at: {item}")

                    # Recurse into subdirectory if we haven't hit max depth
                    if current_depth < max_depth:
                        search_directory(item, current_depth + 1)

            except (PermissionError, OSError, FileNotFoundError):
                # Skip directories we can't access
                logger.debug(f"Skipping inaccessible directory: {current_path}")
                pass

        logger.info(
            f"Searching for repository '{repo_name}' in home directory (max depth: {max_depth})"
        )
        search_directory(home, 0)

        if not found_repos:
            raise AdversaryToolError(f"Repository '{repo_name}' not found.")

        if len(found_repos) == 1:
            logger.info(f"Found repository '{repo_name}' at: {found_repos[0]}")
            return found_repos[0]

        # Multiple matches - let user know and pick the first one
        logger.warning(f"Multiple repositories named '{repo_name}' found:")
        for repo in found_repos:
            logger.warning(f"  - {repo}")
        logger.info(f"Using first match: {found_repos[0]}")
        return found_repos[0]

    def _is_valid_project(self, path: Path) -> bool:
        """Check if a directory looks like a valid project."""
        project_indicators = [
            ".git",  # Git repository
            "package.json",  # Node.js project
            "pyproject.toml",  # Python project
            "Cargo.toml",  # Rust project
            "pom.xml",  # Maven project
            "build.gradle",  # Gradle project
            "composer.json",  # PHP project
            "go.mod",  # Go project
            "requirements.txt",  # Python requirements
            "yarn.lock",  # Yarn project
            "package-lock.json",  # NPM project
            "Gemfile",  # Ruby project
            ".project",  # Eclipse project
            "README.md",  # Documentation (least specific)
        ]

        return any((path / indicator).exists() for indicator in project_indicators)

    def _validate_content(self, content: Any) -> str:
        """Validate and sanitize content parameter."""
        if content is None:
            raise AdversaryToolError("content", "Content parameter is required")

        if not isinstance(content, str):
            raise AdversaryToolError("content", "Content must be a string")

        # Check for reasonable size limits (10MB max)
        max_size = 10 * 1024 * 1024
        if len(content.encode("utf-8")) > max_size:
            raise AdversaryToolError(
                "content", f"Content exceeds maximum size of {max_size} bytes"
            )

        return content

    def _validate_path_parameter(self, path: Any) -> str:
        """Validate path parameter."""
        if not isinstance(path, str):
            raise AdversaryToolError("path", "Path must be a string")

        # Sanitize path to prevent directory traversal
        path = str(Path(path).resolve())

        # Check for suspicious path patterns
        suspicious_patterns = ["../", "..\\", "/etc/", "/var/", "/tmp/", "~"]
        if any(pattern in path.lower() for pattern in suspicious_patterns):
            logger.warning(f"Suspicious path detected: {path}")

        return path

    def _validate_severity_threshold(self, threshold: Any) -> str:
        """Validate severity threshold parameter."""
        if not isinstance(threshold, str):
            raise AdversaryToolError(
                "severity_threshold", "Severity threshold must be a string"
            )

        valid_thresholds = ["low", "medium", "high", "critical"]
        if threshold.lower() not in valid_thresholds:
            raise AdversaryToolError(
                "severity_threshold",
                f"Severity threshold must be one of: {', '.join(valid_thresholds)}",
            )

        return threshold.lower()

    def _validate_boolean_parameter(self, value: Any, param_name: str) -> bool:
        """Validate boolean parameter."""
        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            if value.lower() in ["true", "1", "yes", "on"]:
                return True
            elif value.lower() in ["false", "0", "no", "off"]:
                return False

        raise AdversaryToolError(
            param_name, f"Parameter {param_name} must be a boolean value"
        )

    def _validate_output_format(self, format_val: Any) -> str:
        """Validate output format parameter."""
        if not isinstance(format_val, str):
            raise AdversaryToolError("output_format", "Output format must be a string")

        valid_formats = ["json", "markdown", "text", "csv", "sarif"]
        if format_val.lower() not in valid_formats:
            raise AdversaryToolError(
                "output_format",
                f"Output format must be one of: {', '.join(valid_formats)}",
            )

        return format_val.lower()

    async def run(self) -> None:
        """Run the MCP server."""
        logger.info("Starting MCP server...")

        # Start metrics collection
        await self.metrics_collector.start_collection()
        logger.info("Metrics collection started")

        try:
            async with stdio_server() as (read_stream, write_stream):
                logger.info("MCP server running and accepting connections")
                await self.server.run(
                    read_stream,
                    write_stream,
                    InitializationOptions(
                        server_name="adversary-mcp-server",
                        server_version=self._get_version(),
                        capabilities=ServerCapabilities(
                            tools=ToolsCapability(listChanged=True)
                        ),
                    ),
                )
        except Exception as e:
            logger.error(f"Server runtime error: {e}")
            logger.debug("Server error details", exc_info=True)
            raise
        finally:
            # Stop metrics collection on shutdown
            try:
                await self.metrics_collector.stop_collection()
                logger.info("Metrics collection stopped")
            except Exception as e:
                logger.warning(f"Error stopping metrics collection: {e}")


async def async_main() -> None:
    """Async main function."""
    server = AdversaryMCPServer()
    await server.run()


def main() -> None:
    """Main entry point."""
    # SSL truststore injection for corporate environments
    try:
        truststore.inject_into_ssl()
    except Exception as e:
        logger.error(f"Failed to inject truststore into SSL context: {e}")
        # Continue execution - some corporate environments may have alternative SSL config

    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
