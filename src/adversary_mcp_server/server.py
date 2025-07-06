"""MCP server for adversarial security analysis and vulnerability detection."""

import asyncio
import json
import logging
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from mcp import types
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    EmbeddedResource,
    ImageContent,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field

from .ast_scanner import ASTScanner
from .credential_manager import CredentialManager, CredentialNotFoundError
from .exploit_generator import ExploitGenerator
from .threat_engine import Language, Severity, ThreatEngine, ThreatMatch

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AdversaryToolError(Exception):
    """Exception for adversary tool errors."""

    pass


class ScanRequest(BaseModel):
    """Request for scanning code or files."""

    content: Optional[str] = None
    file_path: Optional[str] = None
    language: Optional[str] = None
    severity_threshold: Optional[str] = "medium"
    include_exploits: bool = True
    use_llm: bool = True


class ScanResult(BaseModel):
    """Result of a security scan."""

    threats: List[Dict[str, Any]]
    summary: Dict[str, Any]
    metadata: Dict[str, Any]


class AdversaryMCPServer:
    """MCP server for adversarial security analysis."""

    def __init__(self) -> None:
        """Initialize the MCP server."""
        self.server: Server = Server("adversary-mcp-server")
        self.credential_manager = CredentialManager()

        # Initialize core components
        self.threat_engine = ThreatEngine()
        self.ast_scanner = ASTScanner(self.threat_engine)
        self.exploit_generator = ExploitGenerator(self.credential_manager)

        # Set up server handlers
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Set up server request handlers."""

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
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
                                "description": "Whether to use LLM for enhanced analysis",
                                "default": True,
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
                                "description": "Whether to use LLM for enhanced analysis",
                                "default": True,
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
                                "description": "Whether to use LLM for enhanced analysis",
                                "default": False,
                            },
                        },
                        "required": ["directory_path"],
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
                                "description": "Whether to use LLM for generation",
                                "default": True,
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
                            "openai_api_key": {
                                "type": "string",
                                "description": "OpenAI API key for LLM features",
                            },
                            "severity_threshold": {
                                "type": "string",
                                "description": "Default severity threshold",
                                "enum": ["low", "medium", "high", "critical"],
                            },
                            "exploit_safety_mode": {
                                "type": "boolean",
                                "description": "Enable safety mode for exploit generation",
                            },
                            "enable_llm": {
                                "type": "boolean",
                                "description": "Enable LLM-based analysis",
                            },
                        },
                        "required": [],
                    },
                ),
                Tool(
                    name="adv_get_status",
                    description="Get status and configuration of the adversary MCP server",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(
            name: str, arguments: Dict[str, Any]
        ) -> List[types.TextContent]:
            """Handle tool calls."""
            try:
                if name == "adv_scan_code":
                    return await self._handle_scan_code(arguments)
                elif name == "adv_scan_file":
                    return await self._handle_scan_file(arguments)
                elif name == "adv_scan_directory":
                    return await self._handle_scan_directory(arguments)
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
                else:
                    raise AdversaryToolError(f"Unknown tool: {name}")

            except Exception as e:
                logger.error(f"Tool call failed: {e}")
                logger.error(traceback.format_exc())
                return [types.TextContent(type="text", text=f"Error: {str(e)}")]

    async def _handle_scan_code(
        self, arguments: Dict[str, Any]
    ) -> List[types.TextContent]:
        """Handle code scanning request."""
        try:
            content = arguments["content"]
            language_str = arguments["language"]
            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = arguments.get("include_exploits", True)
            use_llm = arguments.get("use_llm", True)

            # Convert language string to enum
            language = Language(language_str)

            # Scan the code
            threats = self.ast_scanner.scan_code(content, "input.code", language)

            # Filter by severity
            severity_enum = Severity(severity_threshold)
            filtered_threats = self._filter_threats_by_severity(threats, severity_enum)

            # Generate exploits if requested
            if include_exploits:
                for threat in filtered_threats:
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, content, use_llm
                        )
                        threat.exploit_examples = exploits
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )

            # Format results
            result = self._format_scan_results(filtered_threats, "code")
            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Code scanning failed: {e}")

    async def _handle_scan_file(
        self, arguments: Dict[str, Any]
    ) -> List[types.TextContent]:
        """Handle file scanning request."""
        try:
            file_path = Path(arguments["file_path"])
            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = arguments.get("include_exploits", True)
            use_llm = arguments.get("use_llm", True)

            if not file_path.exists():
                raise AdversaryToolError(f"File not found: {file_path}")

            # Scan the file
            threats = self.ast_scanner.scan_file(file_path)

            # Filter by severity
            severity_enum = Severity(severity_threshold)
            filtered_threats = self._filter_threats_by_severity(threats, severity_enum)

            # Generate exploits if requested
            if include_exploits:
                file_content = ""
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        file_content = f.read()
                except Exception:
                    pass

                for threat in filtered_threats:
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, file_content, use_llm
                        )
                        threat.exploit_examples = exploits
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )

            # Format results
            result = self._format_scan_results(filtered_threats, str(file_path))
            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"File scanning failed: {e}")

    async def _handle_scan_directory(
        self, arguments: Dict[str, Any]
    ) -> List[types.TextContent]:
        """Handle directory scanning request."""
        try:
            directory_path = Path(arguments["directory_path"])
            recursive = arguments.get("recursive", True)
            severity_threshold = arguments.get("severity_threshold", "medium")
            include_exploits = arguments.get("include_exploits", True)
            use_llm = arguments.get(
                "use_llm", False
            )  # Default to False for directory scans

            if not directory_path.exists():
                raise AdversaryToolError(f"Directory not found: {directory_path}")

            # Scan the directory
            threats = self.ast_scanner.scan_directory(directory_path, recursive)

            # Filter by severity
            severity_enum = Severity(severity_threshold)
            filtered_threats = self._filter_threats_by_severity(threats, severity_enum)

            # Generate exploits if requested (limited for directory scans)
            if include_exploits:
                for threat in filtered_threats[:10]:  # Limit to first 10 threats
                    try:
                        exploits = self.exploit_generator.generate_exploits(
                            threat, "", use_llm
                        )
                        threat.exploit_examples = exploits
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate exploits for {threat.rule_id}: {e}"
                        )

            # Format results
            result = self._format_scan_results(filtered_threats, str(directory_path))
            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Directory scanning failed: {e}")

    async def _handle_generate_exploit(
        self, arguments: Dict[str, Any]
    ) -> List[types.TextContent]:
        """Handle exploit generation request."""
        try:
            vulnerability_type = arguments["vulnerability_type"]
            code_context = arguments["code_context"]
            target_language = arguments["target_language"]
            use_llm = arguments.get("use_llm", True)

            # Create a mock threat match for exploit generation
            from .threat_engine import Category, Severity, ThreatMatch

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

            # Generate exploits
            exploits = self.exploit_generator.generate_exploits(
                mock_threat, code_context, use_llm
            )

            # Format results
            result = "# Generated Exploits\n\n"
            result += f"**Vulnerability Type:** {vulnerability_type}\n"
            result += f"**Target Language:** {target_language}\n"
            result += f"**Code Context:**\n```\n{code_context}\n```\n\n"

            if exploits:
                result += "## Exploit Examples\n\n"
                for i, exploit in enumerate(exploits, 1):
                    result += f"### Exploit {i}\n\n"
                    result += f"```\n{exploit}\n```\n\n"
            else:
                result += (
                    "No exploits could be generated for this vulnerability type.\n"
                )

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Exploit generation failed: {e}")

    async def _handle_list_rules(
        self, arguments: Dict[str, Any]
    ) -> List[types.TextContent]:
        """Handle list rules request."""
        try:
            category = arguments.get("category")
            severity = arguments.get("severity")
            language = arguments.get("language")

            rules = self.threat_engine.list_rules()

            # Apply filters
            if category:
                rules = [rule for rule in rules if rule["category"] == category]

            if severity:
                severity_enum = Severity(severity)
                rules = [
                    rule
                    for rule in rules
                    if Severity(rule["severity"]) >= severity_enum
                ]

            if language:
                rules = [rule for rule in rules if language in rule["languages"]]

            # Format results
            result = f"# Threat Detection Rules ({len(rules)} rules)\n\n"

            for rule in rules:
                result += f"## {rule['name']} ({rule['id']})\n"
                result += f"- **Category:** {rule['category']}\n"
                result += f"- **Severity:** {rule['severity']}\n"
                result += f"- **Languages:** {', '.join(rule['languages'])}\n"
                result += f"- **Description:** {rule['description']}\n\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to list rules: {e}")

    async def _handle_get_rule_details(
        self, arguments: Dict[str, Any]
    ) -> List[types.TextContent]:
        """Handle get rule details request."""
        try:
            rule_id = arguments["rule_id"]
            rule = self.threat_engine.get_rule_by_id(rule_id)

            if not rule:
                raise AdversaryToolError(f"Rule not found: {rule_id}")

            # Format rule details
            result = f"# Rule Details: {rule.name}\n\n"
            result += f"**ID:** {rule.id}\n"
            result += f"**Category:** {rule.category.value}\n"
            result += f"**Severity:** {rule.severity.value}\n"
            result += f"**Languages:** {', '.join([lang.value for lang in rule.languages])}\n\n"
            result += f"**Description:**\n{rule.description}\n\n"

            if rule.conditions:
                result += "**Conditions:**\n"
                for i, condition in enumerate(rule.conditions, 1):
                    result += f"{i}. Type: {condition.type}, Value: {condition.value}\n"
                result += "\n"

            if rule.remediation:
                result += f"**Remediation:**\n{rule.remediation}\n\n"

            if rule.references:
                result += "**References:**\n"
                for ref in rule.references:
                    result += f"- {ref}\n"
                result += "\n"

            if rule.cwe_id:
                result += f"**CWE ID:** {rule.cwe_id}\n"

            if rule.owasp_category:
                result += f"**OWASP Category:** {rule.owasp_category}\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to get rule details: {e}")

    async def _handle_configure_settings(
        self, arguments: Dict[str, Any]
    ) -> List[types.TextContent]:
        """Handle configuration settings request."""
        try:
            config = self.credential_manager.load_config()

            # Update configuration
            if "openai_api_key" in arguments:
                config.openai_api_key = arguments["openai_api_key"]

            if "severity_threshold" in arguments:
                config.severity_threshold = arguments["severity_threshold"]

            if "exploit_safety_mode" in arguments:
                config.exploit_safety_mode = arguments["exploit_safety_mode"]

            if "enable_llm" in arguments:
                config.enable_exploit_generation = arguments["enable_llm"]

            # Save configuration
            self.credential_manager.store_config(config)

            # Reinitialize exploit generator with new config
            self.exploit_generator = ExploitGenerator(self.credential_manager)

            result = "✅ Configuration updated successfully!\n\n"
            result += "**Current Settings:**\n"
            result += f"- OpenAI API Key: {'✓ Configured' if config.openai_api_key else '✗ Not configured'}\n"
            result += f"- Severity Threshold: {config.severity_threshold}\n"
            result += f"- Exploit Safety Mode: {'✓ Enabled' if config.exploit_safety_mode else '✗ Disabled'}\n"
            result += f"- LLM Generation: {'✓ Enabled' if config.enable_exploit_generation else '✗ Disabled'}\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to configure settings: {e}")

    async def _handle_get_status(self) -> List[types.TextContent]:
        """Handle get status request."""
        try:
            config = self.credential_manager.load_config()

            result = "# Adversary MCP Server Status\n\n"
            result += "## Configuration\n"
            result += f"- **OpenAI API Key:** {'✓ Configured' if config.openai_api_key else '✗ Not configured'}\n"
            result += f"- **Severity Threshold:** {config.severity_threshold}\n"
            result += f"- **Exploit Safety Mode:** {'✓ Enabled' if config.exploit_safety_mode else '✗ Disabled'}\n"
            result += f"- **LLM Generation:** {'✓ Enabled' if config.enable_exploit_generation else '✗ Disabled'}\n\n"

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
            result += f"- **AST Scanner:** ✓ Active\n"
            result += f"- **Exploit Generator:** ✓ Active\n"
            result += f"- **LLM Integration:** {'✓ Available' if self.exploit_generator.is_llm_available() else '✗ Not available'}\n"

            return [types.TextContent(type="text", text=result)]

        except Exception as e:
            raise AdversaryToolError(f"Failed to get status: {e}")

    def _filter_threats_by_severity(
        self, threats: List[ThreatMatch], min_severity: Severity
    ) -> List[ThreatMatch]:
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

    def _format_scan_results(self, threats: List[ThreatMatch], scan_target: str) -> str:
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

    async def run(self) -> None:
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, write_stream, self.server.create_initialization_options()
            )


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
