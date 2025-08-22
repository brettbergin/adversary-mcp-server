"""Clean Architecture CLI implementation using domain layer."""

import asyncio
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from adversary_mcp_server import get_version
from adversary_mcp_server.application.formatters.domain_result_formatter import (
    DomainScanResultFormatter,
)
from adversary_mcp_server.application.services.scan_application_service import (
    ScanApplicationService,
)
from adversary_mcp_server.application.services.scan_persistence_service import (
    OutputFormat,
    ScanResultPersistenceService,
)
from adversary_mcp_server.config import SecurityConfig
from adversary_mcp_server.credentials import CredentialManager, get_credential_manager
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.interfaces import (
    ConfigurationError,
    SecurityError,
    ValidationError,
)
from adversary_mcp_server.logger import get_logger
from adversary_mcp_server.security.input_validator import InputValidator
from adversary_mcp_server.session.llm_session_manager import LLMSessionManager

console = Console()
logger = get_logger("clean_cli")


class CleanCLI:
    """
    Clean Architecture CLI that uses domain services and application layer.

    This CLI implementation maintains the same user interface while using
    the new Clean Architecture domain layer internally.
    """

    def __init__(self):
        """Initialize the Clean Architecture CLI."""
        self._scan_service = ScanApplicationService()
        self._formatter = DomainScanResultFormatter()
        self._persistence_service = ScanResultPersistenceService()
        self._input_validator = InputValidator()

        # Initialize session manager for session-aware commands
        self._session_manager: LLMSessionManager | None = None
        self._init_session_manager()

    async def scan_file(
        self,
        file_path: str,
        use_semgrep: bool = True,
        use_llm: bool = False,
        use_validation: bool = False,
        severity_threshold: str = "medium",
        output_format: str = "json",
        output_file: str | None = None,
        verbose: bool = False,
    ) -> None:
        """Scan a file using Clean Architecture."""
        logger.info(f"Starting file scan: {file_path}")
        logger.debug(
            f"Scan configuration: semgrep={use_semgrep}, llm={use_llm}, validation={use_validation}, severity={severity_threshold}"
        )

        # Comprehensive input validation
        try:
            cli_args = {
                "path": file_path,
                "use_semgrep": use_semgrep,
                "use_llm": use_llm,
                "use_validation": use_validation,
                "severity_threshold": severity_threshold,
                "output_format": output_format,
                "verbose": verbose,
            }
            if output_file:
                cli_args["output_file"] = output_file

            validated_args = self._input_validator.validate_mcp_arguments(
                cli_args, "adv_scan_file"
            )

            # Extract validated parameters
            file_path = validated_args["path"]
            use_semgrep = validated_args["use_semgrep"]
            use_llm = validated_args["use_llm"]
            use_validation = validated_args["use_validation"]
            severity_threshold = validated_args["severity_threshold"]
            output_format = validated_args["output_format"]
            verbose = validated_args["verbose"]
            output_file = validated_args.get("output_file")

        except (ValueError, SecurityError) as e:
            logger.error(f"Input validation failed for file scan: {e}")
            console.print(f"[red]Input validation failed:[/red] {e}")
            sys.exit(1)

        if verbose:
            console.print(f"[blue]Scanning file:[/blue] {file_path}")
            console.print(
                f"[blue]Configuration:[/blue] Semgrep={use_semgrep}, LLM={use_llm}, Validation={use_validation}"
            )

        logger.debug(f"Starting scan execution for file: {file_path}")

        try:
            # Skip Rich progress for JSON output to stdout to avoid broken pipe errors when piping
            if output_format == "json" and not output_file:
                result = await self._scan_service.scan_file(
                    file_path=file_path,
                    requester="cli",
                    enable_semgrep=use_semgrep,
                    enable_llm=use_llm,
                    enable_validation=use_validation,
                    severity_threshold=severity_threshold,
                )
                await self._output_results(result, output_format, output_file, verbose)
            else:
                # Use Rich progress for interactive output or file output
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Scanning file...", total=None)

                    # Execute scan using domain service
                    logger.debug(f"Calling scan service for file: {file_path}")
                    result = await self._scan_service.scan_file(
                        file_path=file_path,
                        requester="cli",
                        enable_semgrep=use_semgrep,
                        enable_llm=use_llm,
                        enable_validation=use_validation,
                        severity_threshold=severity_threshold,
                    )
                    logger.info(f"File scan completed successfully: {file_path}")

                    progress.update(task, description="Formatting results...")

                    # Format and output results
                    await self._output_results(
                        result, output_format, output_file, verbose
                    )

        except (ValidationError, SecurityError, ConfigurationError) as e:
            logger.error(f"File scan failed: {e}")
            console.print(f"[red]Scan failed:[/red] {e}")
            sys.exit(1)
        except Exception as e:
            import traceback

            logger.error(f"Unexpected error: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            console.print(f"[red]Unexpected error:[/red] {e}")
            console.print("[yellow]Full traceback:[/yellow]")
            console.print(traceback.format_exc())
            sys.exit(1)

    async def scan_directory(
        self,
        directory_path: str,
        use_semgrep: bool = True,
        use_llm: bool = False,
        use_validation: bool = False,
        severity_threshold: str = "medium",
        output_format: str = "json",
        output_file: str | None = None,
        verbose: bool = False,
    ) -> None:
        """Scan a directory using Clean Architecture."""
        logger.info(f"Starting directory scan: {directory_path}")
        logger.debug(
            f"Scan configuration: semgrep={use_semgrep}, llm={use_llm}, validation={use_validation}, severity={severity_threshold}"
        )

        # Comprehensive input validation
        try:
            cli_args = {
                "path": directory_path,
                "use_semgrep": use_semgrep,
                "use_llm": use_llm,
                "use_validation": use_validation,
                "severity_threshold": severity_threshold,
                "output_format": output_format,
                "verbose": verbose,
            }
            if output_file:
                cli_args["output_file"] = output_file

            validated_args = self._input_validator.validate_mcp_arguments(
                cli_args, "adv_scan_folder"
            )

            # Extract validated parameters
            directory_path = validated_args["path"]
            use_semgrep = validated_args["use_semgrep"]
            use_llm = validated_args["use_llm"]
            use_validation = validated_args["use_validation"]
            severity_threshold = validated_args["severity_threshold"]
            output_format = validated_args["output_format"]
            verbose = validated_args["verbose"]
            output_file = validated_args.get("output_file")

        except (ValueError, SecurityError) as e:
            logger.error(f"Input validation failed for directory scan: {e}")
            console.print(f"[red]Input validation failed:[/red] {e}")
            sys.exit(1)

        if verbose:
            console.print(f"[blue]Scanning directory:[/blue] {directory_path}")

        logger.debug(f"Starting scan execution for directory: {directory_path}")

        try:
            # Skip Rich progress for JSON output to stdout to avoid broken pipe errors when piping
            if output_format == "json" and not output_file:
                result = await self._scan_service.scan_directory(
                    directory_path=directory_path,
                    requester="cli",
                    enable_semgrep=use_semgrep,
                    enable_llm=use_llm,
                    enable_validation=use_validation,
                    severity_threshold=severity_threshold,
                )
                await self._output_results(result, output_format, output_file, verbose)
            else:
                # Use Rich progress for interactive output or file output
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Scanning directory...", total=None)

                    logger.debug(
                        f"Calling scan service for directory: {directory_path}"
                    )
                    result = await self._scan_service.scan_directory(
                        directory_path=directory_path,
                        requester="cli",
                        enable_semgrep=use_semgrep,
                        enable_llm=use_llm,
                        enable_validation=use_validation,
                        severity_threshold=severity_threshold,
                    )
                    logger.info(
                        f"Directory scan completed successfully: {directory_path}"
                    )

                    progress.update(task, description="Formatting results...")

                    await self._output_results(
                        result, output_format, output_file, verbose
                    )

        except (ValidationError, SecurityError, ConfigurationError) as e:
            logger.error(f"Directory scan failed: {e}")
            console.print(f"[red]Scan failed:[/red] {e}")
            sys.exit(1)
        except Exception as e:
            import traceback

            logger.error(f"Unexpected error: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            console.print(f"[red]Unexpected error:[/red] {e}")
            console.print("[yellow]Full traceback:[/yellow]")
            console.print(traceback.format_exc())
            sys.exit(1)

    async def scan_code(
        self,
        code_content: str,
        language: str,
        use_semgrep: bool = True,
        use_llm: bool = True,
        use_validation: bool = False,
        severity_threshold: str = "medium",
        output_format: str = "json",
        output_file: str | None = None,
        verbose: bool = False,
    ) -> None:
        """Scan code content using Clean Architecture."""
        logger.info(
            f"Starting code scan: {language} code ({len(code_content)} characters)"
        )
        logger.debug(
            f"Scan configuration: semgrep={use_semgrep}, llm={use_llm}, validation={use_validation}, severity={severity_threshold}"
        )

        # Comprehensive input validation
        try:
            cli_args = {
                "content": code_content,
                "language": language,
                "use_semgrep": use_semgrep,
                "use_llm": use_llm,
                "use_validation": use_validation,
                "severity_threshold": severity_threshold,
                "output_format": output_format,
                "verbose": verbose,
            }
            if output_file:
                cli_args["output_file"] = output_file

            validated_args = self._input_validator.validate_mcp_arguments(
                cli_args, "adv_scan_code"
            )

            # Extract validated parameters
            code_content = validated_args["content"]
            language = validated_args["language"]
            use_semgrep = validated_args["use_semgrep"]
            use_llm = validated_args["use_llm"]
            use_validation = validated_args["use_validation"]
            severity_threshold = validated_args["severity_threshold"]
            output_format = validated_args["output_format"]
            verbose = validated_args["verbose"]
            output_file = validated_args.get("output_file")

        except (ValueError, SecurityError) as e:
            logger.error(f"Input validation failed for code scan: {e}")
            console.print(f"[red]Input validation failed:[/red] {e}")
            sys.exit(1)

        if verbose:
            console.print(
                f"[blue]Scanning code:[/blue] {language} ({len(code_content)} characters)"
            )

        logger.debug(f"Starting scan execution for {language} code")

        try:
            # Skip Rich progress for JSON output to stdout to avoid broken pipe errors when piping
            if output_format == "json" and not output_file:
                result = await self._scan_service.scan_code(
                    code_content=code_content,
                    language=language,
                    requester="cli",
                    enable_semgrep=use_semgrep,
                    enable_llm=use_llm,
                    enable_validation=use_validation,
                    severity_threshold=severity_threshold,
                )
                await self._output_results(result, output_format, output_file, verbose)
            else:
                # Use Rich progress for interactive output or file output
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Analyzing code...", total=None)

                    logger.debug(f"Calling scan service for {language} code")
                    result = await self._scan_service.scan_code(
                        code_content=code_content,
                        language=language,
                        requester="cli",
                        enable_semgrep=use_semgrep,
                        enable_llm=use_llm,
                        enable_validation=use_validation,
                        severity_threshold=severity_threshold,
                    )
                    logger.info(f"Code scan completed successfully: {language}")

                    progress.update(task, description="Formatting results...")

                    await self._output_results(
                        result, output_format, output_file, verbose
                    )

        except (ValidationError, SecurityError, ConfigurationError) as e:
            logger.error(f"Code scan failed: {e}")
            console.print(f"[red]Scan failed:[/red] {e}")
            sys.exit(1)
        except Exception as e:
            import traceback

            logger.error(f"Unexpected error: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            console.print(f"[red]Unexpected error:[/red] {e}")
            console.print("[yellow]Full traceback:[/yellow]")
            console.print(traceback.format_exc())
            sys.exit(1)

    async def get_status(self) -> None:
        """Get Clean Architecture status with real availability information."""
        logger.info("Starting system status check")
        try:
            capabilities = self._scan_service.get_scan_capabilities()
            security_constraints = self._scan_service.get_security_constraints()

            # Create status table
            table = Table(title="Adversary System Status")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details")

            # === REAL STATUS CHECKS ===

            # MCP Server (we're running, so it's available)
            table.add_row(
                "MCP Server",
                "[green]Available[/green]",
                "Adversary MCP Service Running",
            )

            # Database status check
            database_status = self._get_database_status()
            table.add_row(
                "Database",
                (
                    f"[green]{database_status['status']}[/green]"
                    if database_status["available"]
                    else f"[red]{database_status['status']}[/red]"
                ),
                database_status["details"],
            )

            # Cache status check
            cache_status = self._get_cache_status()
            table.add_row(
                "Cache",
                (
                    f"[green]{cache_status['status']}[/green]"
                    if cache_status["available"]
                    else f"[red]{cache_status['status']}[/red]"
                ),
                cache_status["details"],
            )

            # LLM Configuration status
            llm_status = self._get_llm_configuration_status()
            table.add_row(
                "LLM Configuration",
                (
                    f"[green]{llm_status['status']}[/green]"
                    if llm_status["available"]
                    else f"[yellow]{llm_status['status']}[/yellow]"
                ),
                llm_status["details"],
            )

            # Scanner capabilities with real status
            scanner_statuses = self._get_scanner_statuses()
            for scanner_name in capabilities["scan_strategies"]:
                status_info = scanner_statuses.get(
                    scanner_name,
                    {
                        "available": False,
                        "status": "Unknown",
                        "details": "Status check unavailable",
                    },
                )

                color = "green" if status_info["available"] else "red"
                table.add_row(
                    f"Scanner: {scanner_name}",
                    f"[{color}]{status_info['status']}[/{color}]",
                    status_info["details"],
                )

            # Validation strategies with real status
            validation_statuses = self._get_validation_statuses()
            for validator_name in capabilities["validation_strategies"]:
                status_info = validation_statuses.get(
                    validator_name,
                    {
                        "available": False,
                        "status": "Unknown",
                        "details": "Status check unavailable",
                    },
                )

                color = "green" if status_info["available"] else "red"
                table.add_row(
                    f"Validator: {validator_name}",
                    f"[{color}]{status_info['status']}[/{color}]",
                    "False Positive Filter",
                )

            console.print(table)
            logger.info("System status check completed successfully")

            # # Security constraints (with real values)
            # console.print("\n[yellow]Security Constraints:[/yellow]")
            # constraints_table = Table()
            # constraints_table.add_column("Setting", style="cyan")
            # constraints_table.add_column("Value", style="green")

            # for key, value in security_constraints.items():
            #     # Show actual values instead of just length
            #     if isinstance(value, list):
            #         display_value = f"{len(value)} items"
            #     elif isinstance(value, (int, float)):
            #         display_value = str(value)
            #     else:
            #         display_value = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)

            #     constraints_table.add_row(key, display_value)

            # console.print(constraints_table)

            # Add current configuration summary
            # console.print("\n[yellow]Current Configuration:[/yellow]")
            credential_manager = get_credential_manager()
            try:
                current_config = credential_manager.load_config()
                await self._show_configuration_summary(
                    current_config, credential_manager
                )
            except Exception as config_error:
                console.print(
                    f"[red]Failed to load configuration:[/red] {config_error}"
                )
                # Show minimal default config info
                console.print(
                    "[yellow]Using default configuration - run [bold]adversary-mcp-cli configure[/bold] to set up[/yellow]"
                )

        except Exception as e:
            logger.error(f"Status check error: {e}")
            console.print(f"[red]Status check failed:[/red] {e}")
            sys.exit(1)

    async def _output_results(
        self,
        result: ScanResult,
        output_format: str,
        output_file: str | None,
        verbose: bool,
    ) -> None:
        """Output scan results in specified format."""

        # Automatically persist scan result using persistence service
        try:
            logger.debug(f"Persisting scan result in {output_format} format")
            output_format_enum = OutputFormat.from_string(output_format)
            persisted_file_path = await self._persistence_service.persist_scan_result(
                result, output_format_enum
            )
            logger.info(f"Scan result persisted to: {persisted_file_path}")
            if verbose:
                console.print(
                    f"[green]Scan result persisted to:[/green] {persisted_file_path}"
                )
        except Exception as e:
            logger.warning(f"Failed to persist scan result: {e}")
            if verbose:
                console.print(
                    f"[yellow]Warning: Failed to persist scan result:[/yellow] {e}"
                )
            # Don't fail the scan if persistence fails

        # Format results
        if output_format == "json":
            output_content = self._formatter.format_json(result)
        elif output_format == "markdown":
            output_content = self._formatter.format_markdown(result)
        elif output_format == "csv":
            output_content = self._formatter.format_csv(result)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        # Output to file or console
        if output_file:
            try:
                logger.debug(f"Writing output to file: {output_file}")
                # Validate output path before writing
                safe_output_path = Path(output_file).resolve()
                # Check if parent directory exists
                safe_output_path.parent.mkdir(parents=True, exist_ok=True)
                safe_output_path.write_text(output_content)
                logger.info(f"Results written to file: {safe_output_path}")
                console.print(f"[green]Results written to:[/green] {safe_output_path}")
            except (OSError, PermissionError) as e:
                logger.error(f"Failed to write output file {output_file}: {e}")
                console.print(f"[red]Failed to write output file:[/red] {e}")
                sys.exit(1)
        else:
            if verbose and output_format == "json":
                # Pretty print summary in verbose mode
                self._print_summary(result)

            # For JSON output, use plain print to avoid Rich formatting and broken pipe errors
            if output_format == "json":
                print(output_content)
            else:
                console.print(output_content)

    def _print_summary(self, result: ScanResult) -> None:
        """Print a summary of scan results."""
        stats = result.get_statistics()

        # Summary panel
        summary_lines = [
            f"Total Threats: {stats['total_threats']}",
            f"Critical: {stats['by_severity'].get('critical', 0)}",
            f"High: {stats['by_severity'].get('high', 0)}",
            f"Medium: {stats['by_severity'].get('medium', 0)}",
            f"Low: {stats['by_severity'].get('low', 0)}",
        ]

        if result.get_active_scanners():
            summary_lines.append(f"Scanners: {', '.join(result.get_active_scanners())}")

        console.print(
            Panel("\n".join(summary_lines), title="Scan Summary", title_align="left")
        )

        # Threat details
        if result.threats:
            threats_table = Table(title="Threats Found")
            threats_table.add_column("Severity", style="red")
            threats_table.add_column("Rule", style="cyan")
            threats_table.add_column("Location", style="yellow")
            threats_table.add_column("Confidence", style="green")

            for threat in result.threats:  # Show all threats
                threats_table.add_row(
                    str(threat.severity).upper(),
                    threat.rule_name,
                    f"{threat.file_path}:{threat.line_number}",
                    f"{threat.confidence.get_percentage():.1f}%",
                )

            console.print(threats_table)

    def _get_database_status(self) -> dict[str, Any]:
        """Get real database availability status."""
        try:
            from sqlalchemy import text

            from adversary_mcp_server.database.models import AdversaryDatabase

            db = AdversaryDatabase()
            # Test database connectivity
            with db.get_session() as session:
                result = session.execute(text("SELECT 1")).fetchone()

            return {
                "available": True,
                "status": "Available",
                "details": "Database connected and operational",
            }
        except Exception as e:
            return {
                "available": False,
                "status": "Unavailable",
                "details": f"Database error: {str(e)[:50]}...",
            }

    def _get_cache_status(self) -> dict[str, Any]:
        """Get real cache system availability status."""
        try:
            from adversary_mcp_server.cache.cache_manager import CacheManager

            cache_manager = CacheManager(
                cache_dir=Path("~/.local/share/adversary-mcp-server/cache/")
            )
            return {
                "available": True,
                "status": "Available",
                "details": "Cache system initialized",
            }
        except Exception as e:
            return {
                "available": False,
                "status": "Unavailable",
                "details": f"Cache error: {str(e)[:30]}...",
            }

    def _get_llm_configuration_status(self) -> dict[str, Any]:
        """Get LLM configuration status with provider and model information."""
        try:
            credential_manager = get_credential_manager()
            config = credential_manager.load_config()

            if not config.llm_provider:
                return {
                    "available": False,
                    "status": "Not Configured",
                    "details": "No LLM provider configured",
                }

            # Check if API key is available
            has_api_key = bool(
                config.llm_api_key and len(config.llm_api_key.strip()) > 0
            )

            # Build detailed status message
            if config.llm_model:
                details = f"{config.llm_provider.title()} - {config.llm_model}"
            else:
                details = f"{config.llm_provider.title()} - Default model"

            if has_api_key:
                status = "Configured"
                available = True
                details += " (API key configured)"
            else:
                status = "API Key Missing"
                available = False
                details += " (API key needed)"

            return {
                "available": available,
                "status": status,
                "details": details,
            }

        except Exception as e:
            return {
                "available": False,
                "status": "Error",
                "details": f"Configuration error: {str(e)[:40]}...",
            }

    def _get_scanner_statuses(self) -> dict[str, dict[str, Any]]:
        """Get real scanner availability statuses."""
        statuses = {}

        try:
            # Get credential manager to check for API keys
            credential_manager = get_credential_manager()
            semgrep_api_key = credential_manager.get_semgrep_api_key()

            # Access the scan orchestrator strategies
            scan_orchestrator = self._scan_service._scan_orchestrator

            for strategy in scan_orchestrator._scan_strategies:
                strategy_name = strategy.get_strategy_name()

                if hasattr(strategy, "_scanner") and strategy._scanner:
                    if hasattr(strategy._scanner, "get_status"):
                        # Get detailed status from scanner
                        scanner_status = strategy._scanner.get_status()
                        available = scanner_status.get("available", False)
                        version = scanner_status.get("version", "unknown")
                        description = scanner_status.get("description", "")

                        # Create detailed status message
                        if available:
                            details = f"Version: {version}"

                            # For Semgrep, add API key status
                            if "semgrep" in strategy_name.lower():
                                if semgrep_api_key:
                                    details += " - Pro rules enabled"
                                else:
                                    details += " - Community rules only"
                            elif description and "no" not in description.lower():
                                details += f" - {description}"
                        else:
                            # Provide helpful error details
                            error_msg = description or scanner_status.get(
                                "error", "unknown error"
                            )
                            if "no llm" in error_msg.lower():
                                details = (
                                    "LLM not configured - check API keys in credentials"
                                )
                            elif "semgrep not found" in error_msg.lower():
                                details = "Semgrep not installed - run: brew/pip install semgrep"
                            else:
                                details = error_msg

                        statuses[strategy_name] = {
                            "available": available,
                            "status": "Available" if available else "Unavailable",
                            "details": details,
                        }
                    elif hasattr(strategy._scanner, "is_available"):
                        # Simple availability check
                        available = strategy._scanner.is_available()
                        details = (
                            "Scanner initialized"
                            if available
                            else "Scanner not available"
                        )

                        # For Semgrep, add API key status even with simple check
                        if available and "semgrep" in strategy_name.lower():
                            if semgrep_api_key:
                                details = "Scanner initialized - Pro rules enabled"
                            else:
                                details = "Scanner initialized - Community rules only"

                        statuses[strategy_name] = {
                            "available": available,
                            "status": "Available" if available else "Unavailable",
                            "details": details,
                        }
                    else:
                        # Assume available if scanner exists
                        details = "Scanner loaded"

                        # For Semgrep, add API key status even with basic check
                        if "semgrep" in strategy_name.lower():
                            if semgrep_api_key:
                                details = "Scanner loaded - Pro rules enabled"
                            else:
                                details = "Scanner loaded - Community rules only"

                        statuses[strategy_name] = {
                            "available": True,
                            "status": "Available",
                            "details": details,
                        }
                else:
                    statuses[strategy_name] = {
                        "available": False,
                        "status": "Unavailable",
                        "details": "Scanner not initialized",
                    }

        except Exception as e:
            logger.warning(f"Failed to get scanner statuses: {e}")

        return statuses

    def _get_validation_statuses(self) -> dict[str, dict[str, Any]]:
        """Get real validation strategy availability statuses."""
        statuses = {}

        try:
            # Check if LLM is configured (required for validation)
            credential_manager = get_credential_manager()
            config = credential_manager.load_config()
            llm_configured = config.llm_provider and config.llm_api_key

            # Access the validation strategies
            scan_orchestrator = self._scan_service._scan_orchestrator

            for strategy in scan_orchestrator._validation_strategies:
                strategy_name = strategy.get_strategy_name()

                # For LLM-based validators, check LLM configuration first
                if "llm" in strategy_name.lower():
                    if not llm_configured:
                        statuses[strategy_name] = {
                            "available": False,
                            "status": "Unavailable",
                            "details": "LLM not configured - check API keys in credentials",
                        }
                        continue

                if hasattr(strategy, "_validator") and strategy._validator:
                    if hasattr(strategy._validator, "get_status"):
                        validator_status = strategy._validator.get_status()
                        statuses[strategy_name] = {
                            "available": validator_status.get("available", False),
                            "status": (
                                "Available"
                                if validator_status.get("available", False)
                                else "Unavailable"
                            ),
                            "details": validator_status.get(
                                "description", "Validator operational"
                            ),
                        }
                    elif hasattr(strategy._validator, "is_available"):
                        available = strategy._validator.is_available()
                        statuses[strategy_name] = {
                            "available": available,
                            "status": "Available" if available else "Unavailable",
                            "details": (
                                "Validator initialized"
                                if available
                                else "Validator not available"
                            ),
                        }
                    else:
                        statuses[strategy_name] = {
                            "available": True,
                            "status": "Available",
                            "details": "Validator loaded",
                        }
                else:
                    statuses[strategy_name] = {
                        "available": False,
                        "status": "Unavailable",
                        "details": "Validator not initialized",
                    }

        except Exception as e:
            logger.warning(f"Failed to get validation statuses: {e}")

        return statuses

    async def configure_settings(
        self,
        llm_api_key: str | None = None,
        semgrep_api_key: str | None = None,
        llm_provider: str | None = None,
        llm_model: str | None = None,
        severity_threshold: str | None = None,
        enable_llm_analysis: bool | None = None,
        enable_llm_validation: bool | None = None,
        enable_semgrep_scanning: bool | None = None,
        interactive: bool = True,
    ) -> None:
        """Configure Adversary MCP server settings.

        This is the main configuration command that sets up the security scanner
        for first-time use or updates existing configuration.
        """
        logger.info("Starting configuration setup")
        logger.debug(
            f"Configuration mode: {'interactive' if interactive else 'non-interactive'}"
        )
        try:
            console.print(
                "\n[bold blue]🔧 Adversary MCP Server Configuration[/bold blue]"
            )
            console.print("Setting up your security analysis environment...")

            # Get credential manager
            credential_manager = get_credential_manager()

            # Load existing configuration or create new one
            try:
                current_config = credential_manager.load_config()
                console.print("\n[green]✓[/green] Found existing configuration")
                if interactive:
                    console.print(
                        "[yellow]Current settings will be updated with new values[/yellow]"
                    )
            except Exception:
                console.print("\n[blue]Creating new configuration...[/blue]")
                current_config = SecurityConfig()

            # Update configuration with provided values
            updated_config = self._update_config_from_params(
                current_config,
                llm_api_key=llm_api_key,
                llm_provider=llm_provider,
                llm_model=llm_model,
                severity_threshold=severity_threshold,
                enable_llm_analysis=enable_llm_analysis,
                enable_llm_validation=enable_llm_validation,
                enable_semgrep_scanning=enable_semgrep_scanning,
            )

            # Handle Semgrep API key separately (stored in keyring, not in config)
            if semgrep_api_key:
                credential_manager.store_semgrep_api_key(semgrep_api_key)

            # Interactive configuration if requested
            if interactive:
                updated_config = await self._interactive_configure(
                    updated_config, credential_manager
                )

            # Validate configuration
            is_valid, error_message = updated_config.validate_llm_configuration()
            if not is_valid and (
                updated_config.enable_llm_analysis
                or updated_config.enable_llm_validation
            ):
                console.print(
                    f"\n[yellow]⚠️ LLM Configuration Warning:[/yellow] {error_message}"
                )
                console.print(
                    "[yellow]LLM features will be disabled until API keys are configured[/yellow]"
                )

            # Store configuration
            credential_manager.store_config(updated_config)
            logger.info("Configuration saved successfully")

            # Show configuration summary
            await self._show_configuration_summary(updated_config, credential_manager)

            console.print("\n[green]✅ Configuration saved successfully![/green]")
            console.print("\n[blue]Next steps:[/blue]")
            console.print("• Run [bold]adversary-mcp-cli status[/bold] to verify setup")
            console.print("• Configure Cursor IDE with MCP integration")
            console.print("• Start scanning with [bold]adversary-mcp-cli scan[/bold]")

        except Exception as e:
            logger.error(f"Configuration error: {e}")
            console.print(f"\n[red]❌ Configuration failed:[/red] {e}")
            sys.exit(1)

    def _update_config_from_params(
        self, config: SecurityConfig, **kwargs
    ) -> SecurityConfig:
        """Update configuration with provided parameters."""
        from dataclasses import replace

        # Only update fields that were explicitly provided (not None)
        updates = {k: v for k, v in kwargs.items() if v is not None}

        return replace(config, **updates)

    async def _interactive_configure(
        self, config: SecurityConfig, credential_manager: CredentialManager
    ) -> SecurityConfig:
        """Interactive configuration prompts."""
        console.print("\n[bold]🔧 Interactive Configuration[/bold]")

        # LLM Provider Configuration
        if not config.llm_provider:
            provider_choice = click.prompt(
                "\nChoose LLM provider",
                type=click.Choice(["openai", "anthropic", "none"]),
                default="none",
                show_default=True,
            )
            if provider_choice != "none":
                config.llm_provider = provider_choice

                # Get API key if not set
                if not config.llm_api_key:
                    api_key = click.prompt(
                        f"Enter {provider_choice} API key",
                        hide_input=True,
                        default="",
                        show_default=False,
                    )
                    if api_key:
                        config.llm_api_key = api_key

                # Model selection after API key is configured
                if config.llm_api_key:
                    await self._configure_llm_model(config, provider_choice)

        # LLM Model configuration for existing providers
        elif config.llm_provider and config.llm_api_key:
            if click.confirm(
                f"\nConfigure LLM model for {config.llm_provider}?", default=False
            ):
                await self._configure_llm_model(config, config.llm_provider)

        # Semgrep API Key (optional) - check if already exists in keyring
        existing_semgrep_key = credential_manager.get_semgrep_api_key()
        if config.enable_semgrep_scanning and not existing_semgrep_key:
            if click.confirm(
                "\nConfigure Semgrep Pro API key? (optional, improves rule coverage)",
                default=False,
            ):
                semgrep_key = click.prompt(
                    "Enter Semgrep API key",
                    hide_input=True,
                    default="",
                    show_default=False,
                )
                if semgrep_key:
                    credential_manager.store_semgrep_api_key(semgrep_key)

        # Severity threshold
        if click.confirm(
            f"\nChange severity threshold from '{config.severity_threshold}'?",
            default=False,
        ):
            config.severity_threshold = click.prompt(
                "Severity threshold",
                type=click.Choice(["low", "medium", "high", "critical"]),
                default=config.severity_threshold,
                show_default=True,
            )

        return config

    async def _configure_llm_model(self, config: SecurityConfig, provider: str) -> None:
        """Configure LLM model selection based on provider."""
        logger.debug(f"Configuring LLM model for provider: {provider}")

        try:
            # Load available models from pricing config
            from adversary_mcp_server.llm.pricing_manager import PricingManager

            pricing_manager = PricingManager()
            available_models = pricing_manager.get_models_by_provider(
                provider, available_only=True
            )

            if not available_models:
                console.print(
                    f"[yellow]No models found for provider '{provider}'. You can set a custom model.[/yellow]"
                )
                # Allow setting custom model even if none found
                custom_model = click.prompt(
                    f"Enter {provider} model name",
                    default="",
                    show_default=False,
                )
                if custom_model.strip():
                    config.llm_model = custom_model.strip()
                    console.print(f"[green]✓[/green] Model set: {custom_model}")
                return

            console.print(f"\n[cyan]Select {provider.title()} model:[/cyan]")

            # Show current model if set
            current_model = config.llm_model or "Not set"
            console.print(f"Current model: [yellow]{current_model}[/yellow]")

            # Build choices list with model IDs plus "custom" option
            model_choices = [model["id"] for model in available_models] + ["custom"]

            # Find the best default model (prefer latest category, then first available)
            default_choice = None
            for model in available_models:
                if model["category"] == "latest":
                    default_choice = model["id"]
                    break
            if not default_choice and available_models:
                default_choice = available_models[0]["id"]
            if not default_choice:
                default_choice = "custom"

            # Display model details to help user choose
            console.print("\n[dim]Available models:[/dim]")
            for model in available_models:
                category_color = {
                    "latest": "green",
                    "specialized": "blue",
                    "budget": "yellow",
                    "legacy": "dim",
                }.get(model["category"], "white")

                console.print(
                    f"  [{category_color}]{model['id']}[/{category_color}] - {model['display_name']}"
                )
                if model.get("description"):
                    console.print(f"    [dim]{model['description']}[/dim]")
                if model.get("best_for"):
                    console.print(
                        f"    [dim]Best for: {', '.join(model['best_for'])}[/dim]"
                    )

                # Display cost information
                prompt_cost = model.get("prompt_tokens_per_1k", 0)
                completion_cost = model.get("completion_tokens_per_1k", 0)
                currency = model.get("currency", "USD")

                if prompt_cost > 0 or completion_cost > 0:
                    console.print(
                        f"    [dim]Cost per 1K tokens: ${prompt_cost:.4f} input / ${completion_cost:.4f} output ({currency})[/dim]"
                    )

                    # Show usage estimates for typical scenarios
                    try:
                        typical_estimate = (
                            pricing_manager.estimate_cost_for_usage_scenario(
                                model["id"], "typical"
                            )
                        )
                        light_estimate = (
                            pricing_manager.estimate_cost_for_usage_scenario(
                                model["id"], "light"
                            )
                        )

                        # Create budget indicator
                        daily_cost = typical_estimate["daily_cost"]
                        if daily_cost < 1.0:
                            budget_indicator = "[green]💰 Budget-friendly[/green]"
                        elif daily_cost < 5.0:
                            budget_indicator = "[yellow]💰💰 Moderate cost[/yellow]"
                        else:
                            budget_indicator = "[red]💰💰💰 Premium pricing[/red]"

                        console.print(
                            f"    [dim]Estimated daily cost: ${daily_cost:.2f} (typical usage) | ${light_estimate['daily_cost']:.2f} (light usage)[/dim]"
                        )
                        console.print(f"    {budget_indicator}")

                    except Exception as e:
                        logger.debug(f"Failed to estimate costs for {model['id']}: {e}")
                        # Don't show estimates if calculation fails

            model_choice = click.prompt(
                f"\nChoose {provider} model",
                type=click.Choice(model_choices),
                default=default_choice,
                show_default=True,
            )

            if model_choice == "custom":
                custom_model = click.prompt(
                    f"Enter custom {provider} model name",
                    default="",
                    show_default=False,
                )
                if custom_model.strip():
                    config.llm_model = custom_model.strip()
                    console.print(f"[green]✓[/green] Custom model set: {custom_model}")
                else:
                    console.print(
                        "[yellow]No custom model entered, keeping current setting[/yellow]"
                    )
            else:
                config.llm_model = model_choice
                # Find the selected model for display name
                selected_model = next(
                    (m for m in available_models if m["id"] == model_choice), None
                )
                display_name = (
                    selected_model["display_name"] if selected_model else model_choice
                )
                console.print(f"[green]✓[/green] Model configured: {display_name}")

        except Exception as e:
            logger.warning(f"Failed to load models from pricing config: {e}")
            # Fallback to asking for custom model
            console.print(
                "[yellow]Unable to load model list. Please enter a model name manually.[/yellow]"
            )
            custom_model = click.prompt(
                f"Enter {provider} model name",
                default="",
                show_default=False,
            )
            if custom_model.strip():
                config.llm_model = custom_model.strip()
                console.print(f"[green]✓[/green] Model set: {custom_model}")

    async def _show_configuration_summary(
        self, config: SecurityConfig, credential_manager: CredentialManager
    ) -> None:
        """Show configuration summary."""
        # console.print("\n[bold]📋 Configuration Summary[/bold]")

        # Create summary table
        table = Table(title="Current Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Status")

        # LLM Configuration
        if config.llm_provider:
            table.add_row(
                "LLM Provider",
                config.llm_provider,
                (
                    "[green]✓ Configured[/green]"
                    if config.llm_api_key
                    else "[yellow]⚠ API key needed[/yellow]"
                ),
            )
            if config.llm_model:
                table.add_row("LLM Model", config.llm_model, "[green]✓[/green]")
        else:
            table.add_row(
                "LLM Provider", "None", "[yellow]⚠ LLM features disabled[/yellow]"
            )

        # Semgrep Configuration
        table.add_row(
            "Semgrep Scanning",
            "Enabled" if config.enable_semgrep_scanning else "Disabled",
            "[green]✓[/green]" if config.enable_semgrep_scanning else "[red]✗[/red]",
        )

        if config.enable_semgrep_scanning:
            # Check for Semgrep API key from credential manager
            semgrep_api_key = credential_manager.get_semgrep_api_key()
            table.add_row(
                "Semgrep Pro",
                "Enabled" if semgrep_api_key else "Community",
                (
                    "[green]✓ Pro rules[/green]"
                    if semgrep_api_key
                    else "[yellow]Community rules[/yellow]"
                ),
            )

        # Analysis Configuration
        # Check if LLM is properly configured for analysis and validation
        llm_configured = config.llm_provider and config.llm_api_key

        if config.enable_llm_analysis:
            if llm_configured:
                llm_analysis_status = "[green]✓ Enabled[/green]"
                llm_analysis_value = "Enabled"
            else:
                llm_analysis_status = "[yellow]⚠ API key needed[/yellow]"
                llm_analysis_value = "[yellow]Disabled (API key needed)[/yellow]"
        else:
            llm_analysis_status = "[red]✗ Disabled[/red]"
            llm_analysis_value = "Disabled"

        table.add_row("LLM Analysis", llm_analysis_value, llm_analysis_status)

        if config.enable_llm_validation:
            if llm_configured:
                llm_validation_status = "[green]✓ Enabled[/green]"
                llm_validation_value = "Enabled"
            else:
                llm_validation_status = "[yellow]⚠ API key needed[/yellow]"
                llm_validation_value = "[yellow]Disabled (API key needed)[/yellow]"
        else:
            llm_validation_status = "[red]✗ Disabled[/red]"
            llm_validation_value = "Disabled"

        table.add_row("LLM Validation", llm_validation_value, llm_validation_status)

        table.add_row(
            "Severity Threshold", config.severity_threshold.upper(), "[green]✓[/green]"
        )

        console.print(table)

    async def reset_configuration(self, confirm: bool = False) -> None:
        """Reset all configuration to defaults and clear stored credentials."""
        logger.info("Starting configuration reset")
        try:
            if not confirm:
                console.print("\n[bold red]⚠️  Configuration Reset[/bold red]")
                console.print("This will clear all stored configuration and API keys:")
                console.print("• LLM provider and API keys")
                console.print("• Semgrep API key")
                console.print("• All custom settings")
                console.print("• Configuration will return to defaults")

                if not click.confirm(
                    "\nAre you sure you want to reset all configuration?", default=False
                ):
                    console.print("[yellow]Reset cancelled.[/yellow]")
                    return

            console.print("\n[blue]Resetting configuration...[/blue]")

            # Get credential manager
            credential_manager = get_credential_manager()

            # Clear all stored configuration and credentials
            credential_manager.delete_config()

            # Clear individual API keys
            credential_manager.delete_llm_api_key("openai")
            credential_manager.delete_llm_api_key("anthropic")
            credential_manager.delete_semgrep_api_key()

            # Reset credential manager cache
            from adversary_mcp_server.credentials import reset_credential_manager

            reset_credential_manager()
            logger.info("Configuration reset completed successfully")

            console.print("\n[green]✅ Configuration reset successfully![/green]")
            console.print("\n[blue]Next steps:[/blue]")
            console.print(
                "• Run [bold]adversary-mcp-cli configure[/bold] to set up your environment"
            )
            console.print("• Configure API keys for enhanced analysis")

        except Exception as e:
            logger.error(f"Configuration reset error: {e}")
            console.print(f"\n[red]❌ Reset failed:[/red] {e}")
            sys.exit(1)

    def _init_session_manager(self):
        """Initialize session manager if LLM is available."""
        try:
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
                logger.info("Session manager initialized for CLI")
            else:
                logger.info(
                    "LLM not configured - session-aware commands will be unavailable"
                )

        except Exception as e:
            logger.warning(f"Failed to initialize session manager: {e}")
            self._session_manager = None

    async def scan_project_with_context(
        self,
        project_path: str,
        target_files: list[str] | None = None,
        analysis_focus: str = "comprehensive security analysis",
        output_format: str = "json",
        output_file: str | None = None,
        verbose: bool = False,
    ) -> None:
        """Scan a project using session-aware context analysis."""
        if not self._session_manager:
            console.print(
                "[red]Error:[/red] Session-aware analysis not available. Please configure LLM settings."
            )
            return

        project_root = Path(project_path).resolve()

        if not project_root.exists():
            console.print(
                f"[red]Error:[/red] Project path does not exist: {project_path}"
            )
            return

        logger.info(f"Starting session-aware project analysis: {project_path}")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "Initializing session-aware analysis...", total=None
                )

                # Convert target files to Path objects if provided
                target_file_paths = None
                if target_files:
                    target_file_paths = [Path(f) for f in target_files]

                progress.update(task, description="Creating analysis session...")

                # Create session and analyze project
                session = await self._session_manager.create_session(
                    project_root=project_root,
                    target_files=target_file_paths,
                    session_metadata={
                        "analysis_focus": analysis_focus,
                        "cli_session": True,
                        "requester": "cli_session_aware",
                    },
                )

                progress.update(
                    task, description="Performing comprehensive analysis..."
                )

                # Perform multi-phase analysis
                findings = await self._perform_cli_session_analysis(
                    session.session_id, analysis_focus
                )

                progress.update(task, description="Finalizing results...")

                # Close session
                self._session_manager.close_session(session.session_id)

            # Display results
            if findings:
                console.print(
                    f"\n[green]✓ Session analysis complete![/green] Found {len(findings)} potential security issues."
                )

                # Format and display findings
                if verbose:
                    self._display_session_findings(findings)

                # Save results if requested
                if output_file:
                    await self._save_session_results(
                        findings, output_file, output_format
                    )
            else:
                console.print("[green]✓ No security issues found![/green]")

        except Exception as e:
            console.print(f"[red]Session analysis failed:[/red] {e}")
            logger.error(f"Session analysis error: {e}")

    def get_session_status(self) -> dict[str, Any]:
        """Get status of session management capabilities."""
        status = {
            "session_manager_available": self._session_manager is not None,
            "active_sessions": 0,
            "cache_statistics": {},
        }

        if self._session_manager:
            status["active_sessions"] = len(
                self._session_manager.list_active_sessions()
            )
            status["cache_statistics"] = self._session_manager.get_cache_statistics()

        return status

    async def _perform_cli_session_analysis(self, session_id: str, analysis_focus: str):
        """Perform comprehensive session analysis for CLI."""
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

    def _display_session_findings(self, findings):
        """Display session findings in a formatted table."""
        table = Table(title="Session-Aware Security Analysis Results")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Description", style="white")
        table.add_column("Confidence", style="green")

        for finding in findings:  # Show all findings
            severity = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity)
            )
            confidence = (
                f"{finding.confidence:.1%}" if hasattr(finding, "confidence") else "N/A"
            )

            table.add_row(
                finding.rule_id,
                severity.upper(),
                finding.description,
                confidence,
            )

        console.print(table)

    async def _save_session_results(
        self, findings, output_file: str, output_format: str
    ):
        """Save session findings to file."""
        try:
            # Convert findings to dictionary format for saving
            results_data = {
                "analysis_type": "session_aware",
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

            if output_format.lower() == "json":
                import json

                with open(output_file, "w") as f:
                    json.dump(results_data, f, indent=2)
            else:
                # Default to JSON if format not recognized
                import json

                with open(output_file, "w") as f:
                    json.dump(results_data, f, indent=2)

            console.print(f"[green]Results saved to:[/green] {output_file}")

        except Exception as e:
            console.print(f"[red]Failed to save results:[/red] {e}")


# Click CLI commands
@click.group()
@click.version_option(version=get_version())
def cli():
    """Clean Architecture security scanner CLI."""
    pass


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--use-semgrep/--no-semgrep", default=True, help="Enable/disable Semgrep analysis"
)
@click.option("--use-llm/--no-llm", default=False, help="Enable/disable LLM analysis")
@click.option(
    "--use-validation/--no-validation",
    default=False,
    help="Enable/disable LLM validation",
)
@click.option(
    "--severity",
    default="medium",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Minimum severity threshold",
)
@click.option(
    "--output-format",
    default="json",
    type=click.Choice(["json", "markdown", "csv"]),
    help="Output format",
)
@click.option("--output-file", type=click.Path(), help="Output file path")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan_file(
    file_path: str,
    use_semgrep: bool,
    use_llm: bool,
    use_validation: bool,
    severity: str,
    output_format: str,
    output_file: str,
    verbose: bool,
):
    """Scan a file for security vulnerabilities using Clean Architecture."""
    try:
        # Validate all inputs using InputValidator
        validated_file_path = str(InputValidator.validate_file_path(file_path))
        validated_severity = InputValidator.validate_severity_threshold(severity)
        validated_output_format = InputValidator.validate_string_param(
            output_format,
            "output_format",
            max_length=20,
            allowed_chars_pattern=r"^[a-zA-Z]+$",
        )

        # Validate output file if provided
        validated_output_file = None
        if output_file:
            validated_output_file = InputValidator.validate_string_param(
                output_file,
                "output_file",
                max_length=500,
                allowed_chars_pattern=r"^[a-zA-Z0-9\s\.\-_/\\:]+$",
            )

        clean_cli = CleanCLI()
        asyncio.run(
            clean_cli.scan_file(
                file_path=validated_file_path,
                use_semgrep=use_semgrep,
                use_llm=use_llm,
                use_validation=use_validation,
                severity_threshold=validated_severity,
                output_format=validated_output_format,
                output_file=validated_output_file,
                verbose=verbose,
            )
        )
    except (ValueError, SecurityError, FileNotFoundError) as e:
        console.print(f"[red]Input validation failed:[/red] {e}")
        sys.exit(1)


@cli.command("scan-folder")
@click.argument("directory_path", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--use-semgrep/--no-semgrep", default=True, help="Enable/disable Semgrep analysis"
)
@click.option("--use-llm/--no-llm", default=False, help="Enable/disable LLM analysis")
@click.option(
    "--use-validation/--no-validation",
    default=False,
    help="Enable/disable LLM validation",
)
@click.option(
    "--severity",
    default="medium",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Minimum severity threshold",
)
@click.option(
    "--output-format",
    default="json",
    type=click.Choice(["json", "markdown", "csv"]),
    help="Output format",
)
@click.option("--output-file", type=click.Path(), help="Output file path")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan_directory(
    directory_path: str,
    use_semgrep: bool,
    use_llm: bool,
    use_validation: bool,
    severity: str,
    output_format: str,
    output_file: str,
    verbose: bool,
):
    """Scan a folder for security vulnerabilities using Clean Architecture."""
    try:
        # Validate all inputs using InputValidator
        validated_directory_path = str(
            InputValidator.validate_directory_path(directory_path)
        )
        validated_severity = InputValidator.validate_severity_threshold(severity)
        validated_output_format = InputValidator.validate_string_param(
            output_format,
            "output_format",
            max_length=20,
            allowed_chars_pattern=r"^[a-zA-Z]+$",
        )

        # Validate output file if provided
        validated_output_file = None
        if output_file:
            validated_output_file = InputValidator.validate_string_param(
                output_file,
                "output_file",
                max_length=500,
                allowed_chars_pattern=r"^[a-zA-Z0-9\s\.\-_/\\:]+$",
            )

        clean_cli = CleanCLI()
        asyncio.run(
            clean_cli.scan_directory(
                directory_path=validated_directory_path,
                use_semgrep=use_semgrep,
                use_llm=use_llm,
                use_validation=use_validation,
                severity_threshold=validated_severity,
                output_format=validated_output_format,
                output_file=validated_output_file,
                verbose=verbose,
            )
        )
    except (ValueError, SecurityError, FileNotFoundError) as e:
        console.print(f"[red]Input validation failed:[/red] {e}")
        sys.exit(1)


@cli.command()
@click.option("--language", required=True, help="Programming language of the code")
@click.option("--input-file", type=click.Path(exists=True), help="Read code from file")
@click.option(
    "--use-semgrep/--no-semgrep", default=True, help="Enable/disable Semgrep analysis"
)
@click.option("--use-llm/--no-llm", default=True, help="Enable/disable LLM analysis")
@click.option(
    "--use-validation/--no-validation",
    default=False,
    help="Enable/disable LLM validation",
)
@click.option(
    "--severity",
    default="medium",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Minimum severity threshold",
)
@click.option(
    "--output-format",
    default="json",
    type=click.Choice(["json", "markdown", "csv"]),
    help="Output format",
)
@click.option("--output-file", type=click.Path(), help="Output file path")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan_code(
    language: str,
    input_file: str,
    use_semgrep: bool,
    use_llm: bool,
    use_validation: bool,
    severity: str,
    output_format: str,
    output_file: str,
    verbose: bool,
):
    """Scan code content for security vulnerabilities using Clean Architecture."""
    try:
        # Validate all inputs using InputValidator
        validated_language = InputValidator.validate_language(language)
        validated_severity = InputValidator.validate_severity_threshold(severity)
        validated_output_format = InputValidator.validate_string_param(
            output_format,
            "output_format",
            max_length=20,
            allowed_chars_pattern=r"^[a-zA-Z]+$",
        )

        # Validate output file if provided
        validated_output_file = None
        if output_file:
            validated_output_file = InputValidator.validate_string_param(
                output_file,
                "output_file",
                max_length=500,
                allowed_chars_pattern=r"^[a-zA-Z0-9\s\.\-_/\\:]+$",
            )

        # Validate input file if provided
        if input_file:
            validated_file = InputValidator.validate_file_path(input_file)
            code_content = validated_file.read_text()
        else:
            console.print("Enter code content (Ctrl+D to finish):")
            code_content = sys.stdin.read()

        # Validate code content
        if not code_content.strip():
            console.print("[red]Error:[/red] No code content provided")
            sys.exit(1)

        validated_code_content = InputValidator.validate_code_content(code_content)

        clean_cli = CleanCLI()
        asyncio.run(
            clean_cli.scan_code(
                code_content=validated_code_content,
                language=validated_language,
                use_semgrep=use_semgrep,
                use_llm=use_llm,
                use_validation=use_validation,
                severity_threshold=validated_severity,
                output_format=validated_output_format,
                output_file=validated_output_file,
                verbose=verbose,
            )
        )
    except (ValueError, SecurityError, FileNotFoundError) as e:
        console.print(f"[red]Input validation failed:[/red] {e}")
        sys.exit(1)


@cli.command()
def status():
    """Get Clean Architecture system status."""
    clean_cli = CleanCLI()
    asyncio.run(clean_cli.get_status())


@cli.group(invoke_without_command=True)
@click.pass_context
@click.option("--llm-api-key", help="LLM API key (OpenAI or Anthropic)")
@click.option(
    "--llm-provider", type=click.Choice(["openai", "anthropic"]), help="LLM provider"
)
@click.option("--llm-model", help="LLM model to use")
@click.option("--semgrep-api-key", help="Semgrep Pro API key (optional)")
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Minimum severity threshold",
)
@click.option(
    "--enable-llm-analysis/--disable-llm-analysis",
    default=None,
    help="Enable/disable LLM analysis",
)
@click.option(
    "--enable-llm-validation/--disable-llm-validation",
    default=None,
    help="Enable/disable LLM validation",
)
@click.option(
    "--enable-semgrep/--disable-semgrep",
    default=None,
    help="Enable/disable Semgrep scanning",
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Non-interactive mode (use defaults/provided values)",
)
def configure(
    ctx,
    llm_api_key: str,
    llm_provider: str,
    llm_model: str,
    semgrep_api_key: str,
    severity: str,
    enable_llm_analysis: bool,
    enable_llm_validation: bool,
    enable_semgrep: bool,
    non_interactive: bool,
):
    """Configure Adversary MCP server settings.

    Use subcommands:
    • setup - Set up or update configuration
    • reset - Reset all configuration to defaults

    Or run without subcommand to configure directly.
    """
    if ctx.invoked_subcommand is None:
        # Called directly, run the setup logic
        try:
            clean_cli = CleanCLI()
            asyncio.run(
                clean_cli.configure_settings(
                    llm_api_key=llm_api_key,
                    semgrep_api_key=semgrep_api_key,
                    llm_provider=llm_provider,
                    llm_model=llm_model,
                    severity_threshold=severity,
                    enable_llm_analysis=enable_llm_analysis,
                    enable_llm_validation=enable_llm_validation,
                    enable_semgrep_scanning=enable_semgrep,
                    interactive=not non_interactive,
                )
            )
        except (ValueError, SecurityError) as e:
            console.print(f"[red]Configuration failed:[/red] {e}")
            sys.exit(1)


@configure.command()
@click.option("--llm-api-key", help="LLM API key (OpenAI or Anthropic)")
@click.option(
    "--llm-provider", type=click.Choice(["openai", "anthropic"]), help="LLM provider"
)
@click.option("--llm-model", help="LLM model to use")
@click.option("--semgrep-api-key", help="Semgrep Pro API key (optional)")
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Minimum severity threshold",
)
@click.option(
    "--enable-llm-analysis/--disable-llm-analysis",
    default=None,
    help="Enable/disable LLM analysis",
)
@click.option(
    "--enable-llm-validation/--disable-llm-validation",
    default=None,
    help="Enable/disable LLM validation",
)
@click.option(
    "--enable-semgrep/--disable-semgrep",
    default=None,
    help="Enable/disable Semgrep scanning",
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Non-interactive mode (use defaults/provided values)",
)
def setup(
    llm_api_key: str,
    llm_provider: str,
    llm_model: str,
    semgrep_api_key: str,
    severity: str,
    enable_llm_analysis: bool,
    enable_llm_validation: bool,
    enable_semgrep: bool,
    non_interactive: bool,
):
    """Set up or update Adversary MCP server configuration."""
    try:
        clean_cli = CleanCLI()
        asyncio.run(
            clean_cli.configure_settings(
                llm_api_key=llm_api_key,
                semgrep_api_key=semgrep_api_key,
                llm_provider=llm_provider,
                llm_model=llm_model,
                severity_threshold=severity,
                enable_llm_analysis=enable_llm_analysis,
                enable_llm_validation=enable_llm_validation,
                enable_semgrep_scanning=enable_semgrep,
                interactive=not non_interactive,
            )
        )
    except (ValueError, SecurityError) as e:
        console.print(f"[red]Configuration failed:[/red] {e}")
        sys.exit(1)


@configure.command()
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def reset(yes: bool):
    """Reset all configuration to defaults and clear stored credentials."""
    try:
        clean_cli = CleanCLI()
        asyncio.run(clean_cli.reset_configuration(confirm=yes))
    except (ValueError, SecurityError) as e:
        console.print(f"[red]Reset failed:[/red] {e}")
        sys.exit(1)


@cli.command()
@click.option(
    "--hours",
    default=24,
    type=int,
    help="Number of hours of data to include in dashboard (default: 24)",
)
@click.option(
    "--no-launch",
    is_flag=True,
    help="Generate dashboard without auto-launching browser",
)
@click.option(
    "--output-dir",
    type=click.Path(),
    help="Custom output directory for dashboard files",
)
def dashboard(hours: int, no_launch: bool, output_dir: str):
    """Generate and launch comprehensive HTML dashboard."""
    try:
        # Validate inputs
        if hours <= 0:
            console.print("[red]Error:[/red] Hours must be a positive integer")
            sys.exit(1)

        if hours > 8760:  # More than a year
            console.print(
                "[red]Warning:[/red] Requesting more than 1 year of data may be slow"
            )

        # Import dashboard here for lazy loading
        from adversary_mcp_server.dashboard.html_dashboard import (
            ComprehensiveHTMLDashboard,
        )
        from adversary_mcp_server.database.models import AdversaryDatabase

        console.print(
            f"[blue]Generating dashboard with {hours} hours of data...[/blue]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Collecting telemetry data...", total=None)

            # Initialize dashboard
            db = AdversaryDatabase()
            dashboard_generator = ComprehensiveHTMLDashboard(db)

            # Override output directory if provided
            if output_dir:
                from pathlib import Path

                dashboard_generator.output_dir = Path(output_dir).expanduser().resolve()
                dashboard_generator.output_dir.mkdir(parents=True, exist_ok=True)

            progress.update(task, description="Generating HTML dashboard...")

            # Generate dashboard
            auto_launch = not no_launch
            dashboard_file = dashboard_generator.generate_and_launch_dashboard(
                hours=hours, auto_launch=auto_launch
            )

            progress.update(task, description="Dashboard ready!")

        console.print("[green]✓ Dashboard generated successfully![/green]")
        console.print(f"[cyan]Dashboard location:[/cyan] {dashboard_file}")

        if no_launch:
            console.print(
                f"[yellow]To view dashboard:[/yellow] open {dashboard_file} in your browser"
            )
        else:
            console.print("[green]Dashboard opened in your default browser[/green]")

    except Exception as e:
        console.print(f"[red]Dashboard generation failed:[/red] {e}")
        logger.error(f"Dashboard error: {e}")
        sys.exit(1)


def main():
    """Main entry point for Clean Architecture CLI."""
    # SSL truststore injection for corporate environments (e.g., Netskope)
    try:
        import truststore

        truststore.inject_into_ssl()
        logger.debug("Truststore injected into SSL context for corporate CA support")
    except ImportError:
        logger.debug("Truststore not available - using system SSL configuration")
    except Exception as e:
        logger.debug(f"Failed to inject truststore into SSL context: {e}")

    cli()


if __name__ == "__main__":
    main()
