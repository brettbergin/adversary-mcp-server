"""Adversary MCP Server - Security vulnerability scanning and exploit generation."""

import asyncio
import json
import logging
import sys
import traceback
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server  # Add this import
from mcp.types import ServerCapabilities, Tool, ToolsCapability
from pydantic import BaseModel

from . import get_version
from .ast_scanner import ASTScanner
from .credential_manager import CredentialManager
from .diff_scanner import GitDiffScanner
from .exploit_generator import ExploitGenerator
from .false_positive_manager import FalsePositiveManager
from .scan_engine import EnhancedScanResult, ScanEngine
from .threat_engine import Category, Language, Severity, ThreatEngine, ThreatMatch

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class AdversaryToolError(Exception):
    """Exception raised when a tool operation fails."""

    pass


class ScanRequest(BaseModel):
    """Request for scanning code or files."""

    content: str | None = None
    file_path: str | None = None
    language: str | None = None
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
        self.server: Server = Server("adversary-mcp-server")
        self.credential_manager = CredentialManager()

        # Initialize core components
        self.threat_engine = ThreatEngine()
        self.ast_scanner = ASTScanner(self.threat_engine)
        self.scan_engine = ScanEngine(self.threat_engine, self.credential_manager)
        self.exploit_generator = ExploitGenerator(self.credential_manager)
        self.diff_scanner = GitDiffScanner(self.scan_engine)
        self.false_positive_manager = FalsePositiveManager()

        # Set up server handlers
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Set up server request handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List available adversary analysis tools."""
            return [
                Tool(
                    name="adv_scan_code",
                    description="Scan source code for security vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "string",
                                "description": "Source code content to scan",
                            },
                            "language": {
                                "type": "string",
                                "description": "Programming language (python, javascript, typescript)",
                                "enum": ["python", "javascript", "typescript"],
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
                            "output_format": {
                                "type": "string",
                                "description": "Output format for results",
                                "enum": ["text", "json"],
                                "default": "text",
                            },
                        },
                        "required": ["content", "language"],
                    },
                ),
                Tool(
                    name="adv_scan_file",
                    description="Scan a file for security vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the file to scan",
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
                            "output_format": {
                                "type": "string",
                                "description": "Output format for results",
                                "enum": ["text", "json"],
                                "default": "text",
                            },
                        },
                        "required": ["file_path"],
                    },
                ),
                Tool(
                    name="adv_scan_directory",
                    description="Scan a directory for security vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "directory_path": {
                                "type": "string",
                                "description": "Path to the directory to scan",
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
                            "output_format": {
                                "type": "string",
                                "description": "Output format for results",
                                "enum": ["text", "json"],
                                "default": "text",
                            },
                        },
                        "required": ["directory_path"],
                    },
                ),
                Tool(
                    name="adv_diff_scan",
                    description="Scan security vulnerabilities in git diff changes between branches",
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
                            "working_directory": {
                                "type": "string",
                                "description": "Working directory path for git operations (defaults to current directory)",
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
                            "output_format": {
                                "type": "string",
                                "description": "Output format for results",
                                "enum": ["text", "json"],
                                "default": "text",
                            },
                        },
                        "required": ["source_branch", "target_branch"],
                    },
                ),
                Tool(
                    name="adv_generate_exploit",
                    description="Generate exploit for a specific vulnerability",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "vulnerability_type": {
                                "type": "string",
                                "description": "Type of vulnerability (sql_injection, xss, etc.)",
                            },
                            "code_context": {
                                "type": "string",
                                "description": "Vulnerable code context",
                            },
                            "target_language": {
                                "type": "string",
                                "description": "Target programming language",
                                "enum": ["python", "javascript", "typescript"],
                            },
                            "use_llm": {
                                "type": "boolean",
                                "description": "Whether to include LLM exploit generation prompts",
                                "default": False,
                            },
                        },
                        "required": [
                            "vulnerability_type",
                            "code_context",
                            "target_language",
                        ],
                    },
                ),
                Tool(
                    name="adv_list_rules",
                    description="List all available threat detection rules",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "category": {
                                "type": "string",
                                "description": "Filter by category (optional)",
                            },
                            "severity": {
                                "type": "string",
                                "description": "Filter by minimum severity (optional)",
                                "enum": ["low", "medium", "high", "critical"],
                            },
                            "language": {
                                "type": "string",
                                "description": "Filter by language (optional)",
                                "enum": ["python", "javascript", "typescript"],
                            },
                        },
                        "required": [],
                    },
                ),
                Tool(
                    name="adv_get_rule_details",
                    description="Get detailed information about a specific rule",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "rule_id": {
                                "type": "string",
                                "description": "ID of the rule to get details for",
                            },
                        },
                        "required": ["rule_id"],
                    },
                ),
                Tool(
                    name="adv_configure_settings",
                    description="Configure adversary MCP server settings",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "severity_threshold": {
                                "type": "string",
                                "description": "Default severity threshold",
                                "enum": ["low", "medium", "high", "critical"],
                            },
                            "exploit_safety_mode": {
                                "type": "boolean",
                                "description": "Enable safety mode for exploit generation",
                            },
                            "enable_llm_analysis": {
                                "type": "boolean",
                                "description": "Enable LLM-based analysis",
                            },
                            "enable_exploit_generation": {
                                "type": "boolean",
                                "description": "Enable exploit generation",
                            },
                        },
                        "required": [],
                    },
                ),
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
                        },
                        "required": ["finding_uuid"],
                    },
                ),
                Tool(
                    name="adv_list_false_positives",
                    description="List all findings marked as false positives",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(
            name: str, arguments: dict[str, Any]
        ) -> list[types.TextContent]:
            """Call the specified tool with the given arguments."""
            try:
                if name == "adv_scan_code":
                    return await self._handle_scan_code(arguments)
                elif name == "adv_scan_file":
                    return await self._handle_scan_file(arguments)
                elif name == "adv_scan_directory":
                    return await self._handle_scan_directory(arguments)
                elif name == "adv_diff_scan":
                    return await self._handle_diff_scan(arguments)
                elif name == "adv_generate_exploit":
                    return await self._handle_generate_exploit(arguments)
                elif name == "adv_list_rules":
                    return await self._handle_list_rules(arguments)
                elif name == "adv_get_rule_details":
                    return await self._handle_get_rule_details(arguments)
                elif name == "adv_configure_settings":
                    return await self._handle_configure_settings(arguments)
                elif name == "adv_get_status":
                    return await self._handle_get_status()
                elif name == "adv_get_version":
                    return await self._handle_get_version()
                elif name == "adv_mark_false_positive":
                    return await self._handle_mark_false_positive(arguments)
                elif name == "adv_unmark_false_positive":
                    return await self._handle_unmark_false_positive(arguments)
                elif name == "adv_list_false_positives":
                    return await self._handle_list_false_positives(arguments)
                else:
                    raise AdversaryToolError(f"Unknown tool: {name}")
            except Exception as e:
                logger.error(f"Error calling tool {name}: {e}")
                raise AdversaryToolError(f"Tool {name} failed: {str(e)}")

    async def _handle_scan_code(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle code scanning request."""
        try:
            content = arguments["content"]
            language_str = arguments["language"]
            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = arguments.get("include_exploits", True)
            use_llm = arguments.get("use_llm", False)
            use_semgrep = arguments.get("use_semgrep", True)
            output_format = arguments.get("output_format", "text")

            # Convert language string to enum
            language = Language(language_str)
            severity_enum = Severity(severity_threshold)

            # Scan the code using enhanced scanner (rules-based)
            scan_result = self.scan_engine.scan_code(
                source_code=content,
                file_path="input.code",
                language=language,
                use_llm=False,  # Always False for rules scan
                use_semgrep=use_semgrep,
                severity_threshold=severity_enum,
            )

            # Generate exploits if requested
            if include_exploits:
                for threat in scan_result.all_threats:
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, content, False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )

            # Format results based on output format
            if output_format == "json":
                result = self._format_json_scan_results(scan_result, "code")
                # Auto-save JSON results to project root
                self._save_scan_results_json(result, ".")
            else:
                # Format results with enhanced information
                result = self._format_enhanced_scan_results(scan_result, "code")

                # Add LLM prompts if requested
                if use_llm:
                    result += self._add_llm_analysis_prompts(
                        content, language, "input.code"
                    )

                    # Add LLM exploit prompts for each threat found
                    if include_exploits and scan_result.all_threats:
                        result += self._add_llm_exploit_prompts(
                            scan_result.all_threats, content
                        )

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Code scanning failed: {e}")

    async def _handle_scan_file(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle file scanning request."""
        try:
            file_path = Path(arguments["file_path"])
            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = arguments.get("include_exploits", True)
            use_llm = arguments.get("use_llm", False)
            use_semgrep = arguments.get("use_semgrep", True)
            output_format = arguments.get("output_format", "text")

            if not file_path.exists():
                raise AdversaryToolError(f"File not found: {file_path}")

            # Convert severity threshold to enum
            severity_enum = Severity(severity_threshold)

            # Scan the file using enhanced scanner (rules-based)
            scan_result = self.scan_engine.scan_file(
                file_path=file_path,
                use_llm=False,  # Always False for rules scan
                use_semgrep=use_semgrep,
                severity_threshold=severity_enum,
            )

            # Generate exploits if requested
            if include_exploits:
                file_content = ""
                try:
                    with open(file_path, encoding="utf-8") as f:
                        file_content = f.read()
                except Exception:
                    pass

                for threat in scan_result.all_threats:
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, file_content, False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )

            # Format results based on output format
            if output_format == "json":
                result = self._format_json_scan_results(scan_result, str(file_path))
                # Auto-save JSON results to project root
                self._save_scan_results_json(result, str(file_path.parent))
            else:
                # Format results with enhanced information
                result = self._format_enhanced_scan_results(scan_result, str(file_path))

                # Add LLM prompts if requested
                if use_llm:
                    # Read file content for LLM analysis
                    try:
                        with open(file_path, encoding="utf-8") as f:
                            file_content = f.read()

                        # Detect language from file extension
                        file_ext = file_path.suffix.lower()
                        language_map = {
                            ".py": Language.PYTHON,
                            ".js": Language.JAVASCRIPT,
                            ".ts": Language.TYPESCRIPT,
                        }
                        language = language_map.get(file_ext, Language.PYTHON)

                        result += self._add_llm_analysis_prompts(
                            file_content, language, str(file_path)
                        )

                        # Add LLM exploit prompts for each threat found
                        if include_exploits and scan_result.all_threats:
                            result += self._add_llm_exploit_prompts(
                                scan_result.all_threats, file_content
                            )

                    except Exception as e:
                        result += f"\n\n⚠️ **LLM Analysis:** Could not read file for LLM analysis: {e}\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"File scanning failed: {e}")

    async def _handle_scan_directory(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle directory scanning request."""
        try:
            directory_path = Path(arguments["directory_path"])
            recursive = arguments.get("recursive", True)
            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = arguments.get("include_exploits", True)
            use_llm = arguments.get("use_llm", False)
            use_semgrep = arguments.get("use_semgrep", True)
            output_format = arguments.get("output_format", "text")

            if not directory_path.exists():
                raise AdversaryToolError(f"Directory not found: {directory_path}")

            # Convert severity threshold to enum
            severity_enum = Severity(severity_threshold)

            # Scan the directory using enhanced scanner (rules-based)
            scan_results = self.scan_engine.scan_directory(
                directory_path=directory_path,
                recursive=recursive,
                use_llm=False,  # Always False for rules scan
                use_semgrep=use_semgrep,
                severity_threshold=severity_enum,
                max_files=50,  # Limit files for performance
            )

            # Combine all threats from all files
            all_threats = []
            for scan_result in scan_results:
                all_threats.extend(scan_result.all_threats)

            # Generate exploits if requested (limited for directory scans)
            if include_exploits:
                for threat in all_threats[:10]:  # Limit to first 10 threats
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, "", False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )

            # Format results based on output format
            if output_format == "json":
                result = self._format_json_directory_results(
                    scan_results, str(directory_path)
                )
                # Auto-save JSON results to project root
                self._save_scan_results_json(result, str(directory_path))
            else:
                # Format results with enhanced information
                result = self._format_directory_scan_results(
                    scan_results, str(directory_path)
                )

                # Add LLM prompts if requested (only for files with issues)
                if use_llm and scan_results:
                    result += "\n\n# 🤖 LLM Analysis Prompts\n\n"
                    result += "For enhanced LLM-based analysis, use the following prompts with your client's LLM:\n\n"
                    result += "**Note:** Directory scans include prompts for the first 3 files with security issues.\n\n"

                    files_with_issues = [sr for sr in scan_results if sr.all_threats][
                        :3
                    ]
                    for i, scan_result in enumerate(files_with_issues, 1):
                        try:
                            with open(scan_result.file_path, encoding="utf-8") as f:
                                file_content = f.read()

                            # Detect language
                            file_ext = Path(scan_result.file_path).suffix.lower()
                            language_map = {
                                ".py": Language.PYTHON,
                                ".js": Language.JAVASCRIPT,
                                ".ts": Language.TYPESCRIPT,
                            }
                            language = language_map.get(file_ext, Language.PYTHON)

                            result += f"## File {i}: {scan_result.file_path}\n\n"
                            result += self._add_llm_analysis_prompts(
                                file_content,
                                language,
                                str(scan_result.file_path),
                                include_header=False,
                            )

                        except Exception as e:
                            result += f"⚠️ Could not read {scan_result.file_path} for LLM analysis: {e}\n\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Directory scanning failed: {e}")

    async def _handle_diff_scan(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle git diff scanning request."""
        try:
            source_branch = arguments["source_branch"]
            target_branch = arguments["target_branch"]
            working_directory = arguments.get("working_directory", ".")
            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = arguments.get("include_exploits", True)
            use_llm = arguments.get("use_llm", False)
            use_semgrep = arguments.get("use_semgrep", True)
            output_format = arguments.get("output_format", "text")

            # Convert severity threshold to enum
            severity_enum = Severity(severity_threshold)

            # Convert working directory to Path object
            working_dir_path = Path(working_directory).resolve()

            # Get diff summary first
            diff_summary = self.diff_scanner.get_diff_summary(
                source_branch, target_branch, working_dir_path
            )

            # Check if there's an error in the summary
            if "error" in diff_summary:
                raise AdversaryToolError(
                    f"Git diff operation failed: {diff_summary['error']}"
                )

            # Scan the diff changes
            scan_results = self.diff_scanner.scan_diff(
                source_branch=source_branch,
                target_branch=target_branch,
                working_dir=working_dir_path,
                use_llm=False,  # Always False for rules scan
                use_semgrep=use_semgrep,
                severity_threshold=severity_enum,
            )

            # Collect all threats
            all_threats = []
            for file_path, file_scan_results in scan_results.items():
                for scan_result in file_scan_results:
                    all_threats.extend(scan_result.all_threats)

            # Generate exploits if requested
            if include_exploits:
                for threat in all_threats[:10]:  # Limit to first 10 threats
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, "", False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )

            # Format results based on output format
            if output_format == "json":
                result = self._format_json_diff_results(
                    scan_results, diff_summary, f"{source_branch}..{target_branch}"
                )
                # Auto-save JSON results to project root
                self._save_scan_results_json(result, str(working_dir_path))
            else:
                # Format results
                result = self._format_diff_scan_results(
                    scan_results, diff_summary, source_branch, target_branch
                )

                # Add LLM prompts if requested
                if use_llm and scan_results:
                    result += "\n\n# 🤖 LLM Analysis Prompts\n\n"
                    result += "For enhanced LLM-based analysis, use the following prompts with your client's LLM:\n\n"
                    result += "**Note:** Diff scans include prompts for changed code in files with security issues.\n\n"

                    files_with_issues = [
                        (path, results)
                        for path, results in scan_results.items()
                        if any(r.all_threats for r in results)
                    ][:3]
                    for i, (file_path, file_scan_results) in enumerate(
                        files_with_issues, 1
                    ):
                        try:
                            # Get the changed code from the diff
                            diff_changes = self.diff_scanner.get_diff_changes(
                                source_branch, target_branch, working_dir_path
                            )
                            if file_path in diff_changes:
                                chunks = diff_changes[file_path]
                                # For LLM analysis, include minimal context for better understanding
                                changed_code = "\n".join(
                                    chunk.get_added_lines_with_minimal_context()
                                    for chunk in chunks
                                )

                                # Detect language
                                file_ext = Path(file_path).suffix.lower()
                                language_map = {
                                    ".py": Language.PYTHON,
                                    ".js": Language.JAVASCRIPT,
                                    ".ts": Language.TYPESCRIPT,
                                }
                                language = language_map.get(file_ext, Language.PYTHON)

                                result += f"## File {i}: {file_path}\n\n"
                                result += self._add_llm_analysis_prompts(
                                    changed_code,
                                    language,
                                    file_path,
                                    include_header=False,
                                )

                        except Exception as e:
                            result += (
                                f"⚠️ Could not get changed code for {file_path}: {e}\n\n"
                            )

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Diff scanning failed: {e}")

    async def _handle_generate_exploit(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle exploit generation request."""
        try:
            vulnerability_type = arguments["vulnerability_type"]
            code_context = arguments["code_context"]
            target_language = arguments["target_language"]
            use_llm = arguments.get("use_llm", False)

            # Create a mock threat match for exploit generation
            # Map vulnerability type to category
            type_to_category = {
                "sql_injection": Category.INJECTION,
                "command_injection": Category.INJECTION,
                "xss": Category.XSS,
                "deserialization": Category.DESERIALIZATION,
                "path_traversal": Category.LFI,
            }

            category = type_to_category.get(vulnerability_type, Category.INJECTION)

            mock_threat = ThreatMatch(
                rule_id=f"custom_{vulnerability_type}",
                rule_name=vulnerability_type.replace("_", " ").title(),
                description=f"Custom {vulnerability_type} vulnerability",
                category=category,
                severity=Severity.HIGH,
                file_path="custom_scan",
                line_number=1,
                code_snippet=code_context,
            )

            # Generate exploits (template-based only for now)
            exploits = self.exploit_generator.generate_exploits(
                mock_threat, code_context, False  # Don't use LLM directly
            )

            # Format results
            result = f"# {vulnerability_type.replace('_', ' ').title()} Exploit\n\n"
            result += f"**Target Language:** {target_language}\n"
            result += f"**Vulnerability Type:** {vulnerability_type}\n"
            result += "**Severity:** HIGH\n\n"
            result += "**Code Context:**\n"
            result += f"```{target_language}\n{code_context}\n```\n\n"
            result += "**Generated Exploits:**\n\n"

            if exploits:
                for i, exploit in enumerate(exploits, 1):
                    result += f"### Exploit {i}:\n\n"
                    result += f"```\n{exploit}\n```\n\n"
            else:
                result += "No template-based exploits available for this vulnerability type.\n\n"

            # Add LLM exploit prompts if requested
            if use_llm:
                result += "# 🤖 LLM Exploit Generation\n\n"
                result += "For enhanced LLM-based exploit generation, use the following prompts with your client's LLM:\n\n"

                prompt = self.exploit_generator.create_exploit_prompt(
                    mock_threat, code_context
                )

                result += "## System Prompt\n\n"
                result += f"```\n{prompt.system_prompt}\n```\n\n"
                result += "## User Prompt\n\n"
                result += f"```\n{prompt.user_prompt}\n```\n\n"
                result += "**Instructions:** Send both prompts to your LLM to generate exploits based on the vulnerability analysis.\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Exploit generation failed: {e}")

    async def _handle_list_rules(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle list rules request."""
        try:
            category = arguments.get("category")
            severity = arguments.get("severity")
            language = arguments.get("language")

            # Get all rules
            rules = self.threat_engine.list_rules(
                category=category,
                min_severity=Severity(severity) if severity else None,
                language=Language(language) if language else None,
            )

            # Format results
            result = "# Threat Detection Rules\n\n"
            result += f"**Total Rules:** {len(rules)}\n"

            if category:
                result += f"**Category Filter:** {category}\n"
            if severity:
                result += f"**Minimum Severity:** {severity}\n"
            if language:
                result += f"**Language Filter:** {language}\n"

            result += "\n## Rules\n\n"

            # Group rules by category
            categories = {}
            for rule in rules:
                cat = rule["category"]
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(rule)

            for category, cat_rules in categories.items():
                result += f"### {category}\n\n"
                for rule in cat_rules:
                    result += (
                        f"- **{rule['id']}**: {rule['name']} ({rule['severity']})\n"
                    )
                    result += f"  - Languages: {', '.join(rule['languages'])}\n"
                    result += f"  - {rule['description']}\n\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to list rules: {e}")

    async def _handle_get_rule_details(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle get rule details request."""
        try:
            rule_id = arguments["rule_id"]

            # Get rule details
            rule = self.threat_engine.get_rule_details(rule_id)
            if not rule:
                raise AdversaryToolError(f"Rule not found: {rule_id}")

            # Format results
            result = f"# Rule Details: {rule['name']}\n\n"
            result += f"**ID:** {rule['id']}\n"
            result += f"**Category:** {rule['category']}\n"
            result += f"**Severity:** {rule['severity']}\n"
            result += f"**Languages:** {', '.join(rule['languages'])}\n\n"
            result += f"**Description:** {rule['description']}\n\n"

            if rule.get("pattern"):
                result += f"**Pattern:** `{rule['pattern']}`\n\n"

            if rule.get("cwe_id"):
                result += f"**CWE ID:** {rule['cwe_id']}\n"

            if rule.get("owasp_category"):
                result += f"**OWASP Category:** {rule['owasp_category']}\n"

            if rule.get("references"):
                result += "**References:**\n"
                for ref in rule["references"]:
                    result += f"- {ref}\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to get rule details: {e}")

    async def _handle_configure_settings(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle configuration settings request."""
        try:
            config = self.credential_manager.load_config()

            # Update configuration
            if "severity_threshold" in arguments:
                config.severity_threshold = arguments["severity_threshold"]

            if "exploit_safety_mode" in arguments:
                config.exploit_safety_mode = arguments["exploit_safety_mode"]

            if "enable_llm_analysis" in arguments:
                config.enable_llm_analysis = arguments["enable_llm_analysis"]

            if "enable_exploit_generation" in arguments:
                config.enable_exploit_generation = arguments[
                    "enable_exploit_generation"
                ]

            # Save configuration
            self.credential_manager.store_config(config)

            # Reinitialize components with new config
            self.exploit_generator = ExploitGenerator(self.credential_manager)
            self.scan_engine = ScanEngine(self.threat_engine, self.credential_manager)

            result = "✅ Configuration updated successfully!\n\n"
            result += "**Current Settings:**\n"
            result += f"- Severity Threshold: {config.severity_threshold}\n"
            result += f"- Exploit Safety Mode: {'✓ Enabled' if config.exploit_safety_mode else '✗ Disabled'}\n"
            result += f"- LLM Security Analysis: {'✓ Enabled' if config.enable_llm_analysis else '✗ Disabled'}\n"
            result += f"- Exploit Generation: {'✓ Enabled' if config.enable_exploit_generation else '✗ Disabled'}\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to configure settings: {e}")

    async def _handle_get_status(self) -> list[types.TextContent]:
        """Handle get status request."""
        try:
            config = self.credential_manager.load_config()

            result = "# Adversary MCP Server Status\n\n"
            result += "## Configuration\n"
            result += f"- **Severity Threshold:** {config.severity_threshold}\n"
            result += f"- **Exploit Safety Mode:** {'✓ Enabled' if config.exploit_safety_mode else '✗ Disabled'}\n"
            result += f"- **LLM Analysis:** {'✓ Enabled' if config.enable_llm_analysis else '✗ Disabled'}\n"
            result += f"- **Exploit Generation:** {'✓ Enabled' if config.enable_exploit_generation else '✗ Disabled'}\n\n"

            result += "## Threat Engine\n"
            rules = self.threat_engine.list_rules()
            result += f"- **Total Rules:** {len(rules)}\n"

            # Count by language
            lang_counts = {}
            for rule in rules:
                for lang in rule["languages"]:
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1

            for lang, count in lang_counts.items():
                result += f"- **{lang.capitalize()} Rules:** {count}\n"

            result += "\n## Components\n"
            result += "- **AST Scanner:** ✓ Active\n"
            result += "- **Exploit Generator:** ✓ Active\n"
            result += "- **LLM Integration:** ✓ Client-based (no API key required)\n"
            result += "- **Scan Engine:** ✓ Active\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to get status: {e}")

    async def _handle_get_version(self) -> list[types.TextContent]:
        """Handle get version request."""
        try:
            version = self._get_version()
            result = "# Adversary MCP Server\n\n"
            result += f"**Version:** {version}\n"
            result += "**LLM Integration:** Client-based (no API key required)\n"
            result += "**Supported Languages:** Python, JavaScript, TypeScript\n"
            result += f"**Security Rules:** {len(self.threat_engine.list_rules())}\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to get version: {e}")

    def _get_version(self) -> str:
        """Get the current version."""
        return get_version()

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

            if threat.exploit_examples:
                result += "**Exploit Examples:**\n"
                for j, exploit in enumerate(threat.exploit_examples, 1):
                    result += f"*Example {j}:*\n"
                    result += f"```\n{exploit}\n```\n\n"

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
            result += (
                f"**Rules Engine:** {scan_result.stats['rules_threats']} findings\n"
            )
            result += f"**LLM Analysis:** {scan_result.stats['llm_threats']} findings\n"
            result += f"**Language:** {scan_result.language.value}\n\n"
            return result

        # Analysis overview
        result += "## Analysis Overview\n\n"
        result += f"**Rules Engine:** {scan_result.stats['rules_threats']} findings\n"
        result += f"**LLM Analysis:** {scan_result.stats['llm_threats']} findings\n"
        result += f"**Total Unique:** {scan_result.stats['unique_threats']} findings\n"
        result += f"**Language:** {scan_result.language.value}\n\n"

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
            result += f"**Rules Scan:** {'✅ Success' if metadata.get('rules_scan_success') else '❌ Failed'}\n"
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

            if threat.exploit_examples:
                result += "**Exploit Examples:**\n"
                for j, exploit in enumerate(threat.exploit_examples, 1):
                    result += f"*Example {j}:*\n"
                    result += f"```\n{exploit}\n```\n\n"

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

                        if threat.exploit_examples:
                            result += f"  Exploit Examples: {len(threat.exploit_examples)} available\n"

                        result += "\n"

        return result

    def _format_json_scan_results(
        self, scan_result: EnhancedScanResult, scan_target: str
    ) -> str:
        """Format enhanced scan results as JSON.

        Args:
            scan_result: Enhanced scan result object
            scan_target: Target that was scanned

        Returns:
            JSON formatted scan results
        """
        from datetime import datetime

        # Convert threats to dictionaries
        threats_data = []
        for threat in scan_result.all_threats:
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
                "is_false_positive": getattr(threat, "is_false_positive", False),
            }
            threats_data.append(threat_data)

        # Create comprehensive JSON structure
        result_data = {
            "scan_metadata": {
                "target": scan_target,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "language": scan_result.language.value,
                "file_path": scan_result.file_path,
                "scan_type": "enhanced",
                "total_threats": len(scan_result.all_threats),
            },
            "scan_configuration": {
                "rules_scan_enabled": scan_result.scan_metadata.get(
                    "rules_scan_success", False
                ),
                "llm_scan_enabled": scan_result.scan_metadata.get(
                    "llm_scan_success", False
                ),
                "semgrep_scan_enabled": scan_result.scan_metadata.get(
                    "semgrep_scan_success", False
                ),
            },
            "statistics": scan_result.stats,
            "threats": threats_data,
            "scan_details": {
                "rules_scan_success": scan_result.scan_metadata.get(
                    "rules_scan_success", False
                ),
                "llm_scan_success": scan_result.scan_metadata.get(
                    "llm_scan_success", False
                ),
                "semgrep_scan_success": scan_result.scan_metadata.get(
                    "semgrep_scan_success", False
                ),
                "source_lines": scan_result.scan_metadata.get("source_lines", 0),
                "source_size": scan_result.scan_metadata.get("source_size", 0),
            },
        }

        return json.dumps(result_data, indent=2)

    def _format_json_directory_results(
        self, scan_results: list[EnhancedScanResult], scan_target: str
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
                    "language": scan_result.language.value,
                    "threat_count": len(scan_result.all_threats),
                    "scan_success": scan_result.scan_metadata.get(
                        "rules_scan_success", False
                    ),
                }
            )

            for threat in scan_result.all_threats:
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
                    "is_false_positive": getattr(threat, "is_false_positive", False),
                }
                all_threats.append(threat_data)

        # Calculate summary statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for threat in all_threats:
            severity_counts[threat["severity"]] += 1

        result_data = {
            "scan_metadata": {
                "target": scan_target,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "scan_type": "directory",
                "total_threats": len(all_threats),
                "files_scanned": len(files_scanned),
            },
            "statistics": {
                "total_threats": len(all_threats),
                "severity_counts": severity_counts,
                "files_with_threats": len(
                    [f for f in files_scanned if f["threat_count"] > 0]
                ),
            },
            "files": files_scanned,
            "threats": all_threats,
        }

        return json.dumps(result_data, indent=2)

    def _format_json_diff_results(
        self,
        scan_results: dict[str, list[EnhancedScanResult]],
        diff_summary: dict[str, any],
        scan_target: str,
    ) -> str:
        """Format git diff scan results as JSON.

        Args:
            scan_results: Dictionary mapping file paths to scan results
            diff_summary: Git diff summary information
            scan_target: Target branches for diff scan

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
                        "is_false_positive": getattr(threat, "is_false_positive", False),
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

        result_data = {
            "scan_metadata": {
                "target": scan_target,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "scan_type": "git_diff",
                "total_threats": len(all_threats),
                "files_changed": len(files_changed),
            },
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

    def _save_scan_results_json(
        self, json_data: str, working_dir: str = "."
    ) -> str | None:
        """Save scan results to .adversary-scan-results.json in project root.

        Args:
            json_data: JSON formatted scan results
            working_dir: Working directory to save file in

        Returns:
            Path to saved file or None if save failed
        """
        try:
            from pathlib import Path

            output_path = Path(working_dir) / ".adversary-scan-results.json"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_data)

            logger.info(f"Scan results saved to {output_path}")
            return str(output_path)
        except Exception as e:
            logger.warning(f"Failed to save scan results JSON: {e}")
            return None

    async def run(self) -> None:
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
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

    def _add_llm_analysis_prompts(
        self,
        content: str,
        language: Language,
        file_path: str,
        include_header: bool = True,
    ) -> str:
        """Add LLM analysis prompts to scan results."""
        try:
            analyzer = self.scan_engine.llm_analyzer
            prompt = analyzer.create_analysis_prompt(
                content, file_path, language, max_findings=20
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
        """Handle mark false positive request."""
        try:
            finding_uuid = arguments.get("finding_uuid")
            reason = arguments.get("reason", "Marked as false positive via MCP")
            
            if not finding_uuid:
                raise AdversaryToolError("finding_uuid is required")
                
            self.false_positive_manager.mark_false_positive(finding_uuid, reason)
            
            result = f"✅ **Finding marked as false positive**\n\n"
            result += f"**UUID:** {finding_uuid}\n"
            result += f"**Reason:** {reason}\n"
            
            return [types.TextContent(type="text", text=result)]
            
        except Exception as e:
            logger.error(f"Error marking false positive: {e}")
            raise AdversaryToolError(f"Failed to mark false positive: {str(e)}")

    async def _handle_unmark_false_positive(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle unmark false positive request."""
        try:
            finding_uuid = arguments.get("finding_uuid")
            
            if not finding_uuid:
                raise AdversaryToolError("finding_uuid is required")
                
            success = self.false_positive_manager.unmark_false_positive(finding_uuid)
            
            if success:
                result = f"✅ **Finding unmarked as false positive**\n\n"
                result += f"**UUID:** {finding_uuid}\n"
            else:
                result = f"⚠️ **Finding not found in false positives**\n\n"
                result += f"**UUID:** {finding_uuid}\n"
            
            return [types.TextContent(type="text", text=result)]
            
        except Exception as e:
            logger.error(f"Error unmarking false positive: {e}")
            raise AdversaryToolError(f"Failed to unmark false positive: {str(e)}")

    async def _handle_list_false_positives(
        self, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle list false positives request."""
        try:
            false_positives = self.false_positive_manager.get_false_positives()
            
            result = f"# False Positives ({len(false_positives)} found)\n\n"
            
            if not false_positives:
                result += "No false positives found.\n"
                return [types.TextContent(type="text", text=result)]
            
            for fp in false_positives:
                result += f"## {fp['uuid']}\n\n"
                result += f"**Reason:** {fp.get('reason', 'No reason provided')}\n"
                result += f"**Marked:** {fp.get('marked_date', 'Unknown')}\n"
                if fp.get('last_updated') != fp.get('marked_date'):
                    result += f"**Updated:** {fp.get('last_updated', 'Unknown')}\n"
                result += "\n---\n\n"
            
            return [types.TextContent(type="text", text=result)]
            
        except Exception as e:
            logger.error(f"Error listing false positives: {e}")
            raise AdversaryToolError(f"Failed to list false positives: {str(e)}")


async def async_main() -> None:
    """Async main function."""
    server = AdversaryMCPServer()
    await server.run()


def main() -> None:
    """Main entry point."""
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
