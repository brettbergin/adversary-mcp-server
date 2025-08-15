"""Clean Architecture CLI implementation using domain layer."""

import asyncio
import sys
from pathlib import Path

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
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.interfaces import (
    ConfigurationError,
    SecurityError,
    ValidationError,
)
from adversary_mcp_server.logger import get_logger
from adversary_mcp_server.security.input_validator import InputValidator

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
        self._input_validator = InputValidator()

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
            console.print(f"[red]Input validation failed:[/red] {e}")
            sys.exit(1)

        if verbose:
            console.print(f"[blue]Scanning file:[/blue] {file_path}")
            console.print(
                f"[blue]Configuration:[/blue] Semgrep={use_semgrep}, LLM={use_llm}, Validation={use_validation}"
            )

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Scanning file...", total=None)

                # Execute scan using domain service
                result = await self._scan_service.scan_file(
                    file_path=file_path,
                    requester="cli",
                    enable_semgrep=use_semgrep,
                    enable_llm=use_llm,
                    enable_validation=use_validation,
                    severity_threshold=severity_threshold,
                )

                progress.update(task, description="Formatting results...")

                # Format and output results
                await self._output_results(result, output_format, output_file, verbose)

        except (ValidationError, SecurityError, ConfigurationError) as e:
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
            console.print(f"[red]Input validation failed:[/red] {e}")
            sys.exit(1)

        if verbose:
            console.print(f"[blue]Scanning directory:[/blue] {directory_path}")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Scanning directory...", total=None)

                result = await self._scan_service.scan_directory(
                    directory_path=directory_path,
                    requester="cli",
                    enable_semgrep=use_semgrep,
                    enable_llm=use_llm,
                    enable_validation=use_validation,
                    severity_threshold=severity_threshold,
                )

                progress.update(task, description="Formatting results...")

                await self._output_results(result, output_format, output_file, verbose)

        except (ValidationError, SecurityError, ConfigurationError) as e:
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
            console.print(f"[red]Input validation failed:[/red] {e}")
            sys.exit(1)

        if verbose:
            console.print(
                f"[blue]Scanning code:[/blue] {language} ({len(code_content)} characters)"
            )

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Analyzing code...", total=None)

                result = await self._scan_service.scan_code(
                    code_content=code_content,
                    language=language,
                    requester="cli",
                    enable_semgrep=use_semgrep,
                    enable_llm=use_llm,
                    enable_validation=use_validation,
                    severity_threshold=severity_threshold,
                )

                progress.update(task, description="Formatting results...")

                await self._output_results(result, output_format, output_file, verbose)

        except (ValidationError, SecurityError, ConfigurationError) as e:
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
        """Get Clean Architecture status."""
        try:
            capabilities = self._scan_service.get_scan_capabilities()
            security_constraints = self._scan_service.get_security_constraints()

            # Create status table
            table = Table(title="Clean Architecture Status")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details")

            table.add_row(
                "Architecture", "✓ Clean Architecture", "Domain-driven design enabled"
            )
            table.add_row("Domain Layer", "✓ Active", "Pure business logic")
            table.add_row("Application Layer", "✓ Active", "Use cases and coordination")
            table.add_row("Infrastructure", "✓ Adapted", "Legacy scanners wrapped")

            # Scanner capabilities
            for scanner in capabilities["scan_strategies"]:
                table.add_row(
                    f"Scanner: {scanner}", "✓ Available", "Via domain adapter"
                )

            # Validation
            for validator in capabilities["validation_strategies"]:
                table.add_row(
                    f"Validator: {validator}", "✓ Available", "False positive reduction"
                )

            console.print(table)

            # Security constraints
            console.print("\n[yellow]Security Constraints:[/yellow]")
            constraints_table = Table()
            constraints_table.add_column("Setting", style="cyan")
            constraints_table.add_column("Value", style="green")

            for key, value in security_constraints.items():
                constraints_table.add_row(key, str(value))

            console.print(constraints_table)

        except Exception as e:
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
                # Validate output path before writing
                safe_output_path = Path(output_file).resolve()
                # Check if parent directory exists
                safe_output_path.parent.mkdir(parents=True, exist_ok=True)
                safe_output_path.write_text(output_content)
                console.print(f"[green]Results written to:[/green] {safe_output_path}")
            except (OSError, PermissionError) as e:
                console.print(f"[red]Failed to write output file:[/red] {e}")
                sys.exit(1)
        else:
            if verbose and output_format == "json":
                # Pretty print summary in verbose mode
                self._print_summary(result)

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

            for threat in result.threats[:10]:  # Show first 10
                threats_table.add_row(
                    str(threat.severity).upper(),
                    threat.rule_name,
                    f"{threat.file_path}:{threat.line_number}",
                    f"{threat.confidence.get_percentage():.1f}%",
                )

            if len(result.threats) > 10:
                threats_table.add_row(
                    "...", f"({len(result.threats) - 10} more)", "", ""
                )

            console.print(threats_table)


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
    clean_cli = CleanCLI()
    asyncio.run(
        clean_cli.scan_file(
            file_path=file_path,
            use_semgrep=use_semgrep,
            use_llm=use_llm,
            use_validation=use_validation,
            severity_threshold=severity,
            output_format=output_format,
            output_file=output_file,
            verbose=verbose,
        )
    )


@cli.command()
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
    """Scan a directory for security vulnerabilities using Clean Architecture."""
    clean_cli = CleanCLI()
    asyncio.run(
        clean_cli.scan_directory(
            directory_path=directory_path,
            use_semgrep=use_semgrep,
            use_llm=use_llm,
            use_validation=use_validation,
            severity_threshold=severity,
            output_format=output_format,
            output_file=output_file,
            verbose=verbose,
        )
    )


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

    # Validate input file if provided
    if input_file:
        try:
            validator = InputValidator()
            validated_file = validator.validate_file_path(input_file)
            code_content = validated_file.read_text()
        except (ValueError, SecurityError, FileNotFoundError) as e:
            console.print(f"[red]Input file validation failed:[/red] {e}")
            sys.exit(1)
    else:
        console.print("Enter code content (Ctrl+D to finish):")
        code_content = sys.stdin.read()

    if not code_content.strip():
        console.print("[red]Error:[/red] No code content provided")
        sys.exit(1)

    clean_cli = CleanCLI()
    asyncio.run(
        clean_cli.scan_code(
            code_content=code_content,
            language=language,
            use_semgrep=use_semgrep,
            use_llm=use_llm,
            use_validation=use_validation,
            severity_threshold=severity,
            output_format=output_format,
            output_file=output_file,
            verbose=verbose,
        )
    )


@cli.command()
def status():
    """Get Clean Architecture system status."""
    clean_cli = CleanCLI()
    asyncio.run(clean_cli.get_status())


def main():
    """Main entry point for Clean Architecture CLI."""
    cli()


if __name__ == "__main__":
    main()
