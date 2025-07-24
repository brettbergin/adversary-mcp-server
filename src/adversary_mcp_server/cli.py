"""Command-line interface for the Adversary MCP server."""

import datetime
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from . import get_version
from .credential_manager import CredentialManager
from .diff_scanner import GitDiffScanner
from .logging_config import get_logger
from .scan_engine import ScanEngine
from .types import Language, Severity

console = Console()
logger = get_logger("cli")


def get_cli_version():
    """Get version for CLI."""
    logger.debug("Getting CLI version")
    version = get_version()
    logger.debug(f"CLI version: {version}")
    return version


@click.group()
@click.version_option(version=get_cli_version(), prog_name="adversary-mcp-cli")
def cli():
    """Adversary MCP Server - Security-focused vulnerability scanner."""
    logger.info("=== Adversary MCP CLI Started ===")


@cli.command()
@click.option(
    "--severity-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Default severity threshold for scanning",
)
@click.option(
    "--enable-safety-mode/--disable-safety-mode",
    default=True,
    help="Enable/disable exploit safety mode",
)
def configure(severity_threshold: str | None, enable_safety_mode: bool):
    """Configure the Adversary MCP server settings."""
    logger.info("=== Starting configuration command ===")
    console.print("🔧 [bold]Adversary MCP Server Configuration[/bold]")

    try:
        credential_manager = CredentialManager()
        config = credential_manager.load_config()

        # Update configuration based on options
        config_updated = False

        if severity_threshold:
            config.severity_threshold = severity_threshold
            config_updated = True
            logger.info(f"Default severity threshold set to: {severity_threshold}")

        config.exploit_safety_mode = enable_safety_mode
        config_updated = True
        logger.info(f"Exploit safety mode set to: {enable_safety_mode}")

        if config_updated:
            credential_manager.save_config(config)
            console.print("✅ Configuration updated successfully!", style="green")

        logger.info("=== Configuration command completed successfully ===")

    except Exception as e:
        logger.error(f"Configuration command failed: {e}")
        logger.debug("Configuration error details", exc_info=True)
        console.print(f"❌ Configuration failed: {e}", style="red")
        sys.exit(1)


@cli.command()
def status():
    """Show current server status and configuration."""
    logger.info("=== Starting status command ===")

    try:
        logger.debug("Initializing components for status check...")
        credential_manager = CredentialManager()
        config = credential_manager.load_config()
        scan_engine = ScanEngine(credential_manager)
        logger.debug("Components initialized successfully")

        # Status panel
        console.print("📊 [bold]Adversary MCP Server Status[/bold]")

        # Configuration table
        config_table = Table(title="Configuration")
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="magenta")

        config_table.add_row("Version", get_version())
        config_table.add_row(
            "Safety Mode", "Enabled" if config.exploit_safety_mode else "Disabled"
        )
        config_table.add_row(
            "Default Severity Threshold", str(config.severity_threshold)
        )
        config_table.add_row(
            "Semgrep Available",
            "Yes" if scan_engine.semgrep_scanner.is_available() else "No",
        )
        config_table.add_row(
            "LLM Available",
            (
                "Yes"
                if scan_engine.llm_analyzer and scan_engine.llm_analyzer.is_available()
                else "No"
            ),
        )

        console.print(config_table)

        # Scanner status
        console.print("\n🔍 [bold]Scanner Status[/bold]")
        scanners_table = Table(title="Available Scanners")
        scanners_table.add_column("Scanner", style="cyan")
        scanners_table.add_column("Status", style="green")
        scanners_table.add_column("Description", style="yellow")

        scanners_table.add_row(
            "Semgrep",
            (
                "Available"
                if scan_engine.semgrep_scanner.is_available()
                else "Unavailable"
            ),
            "Static analysis tool",
        )
        scanners_table.add_row(
            "LLM",
            (
                "Available"
                if scan_engine.llm_analyzer and scan_engine.llm_analyzer.is_available()
                else "Unavailable"
            ),
            "AI-powered analysis",
        )

        console.print(scanners_table)

        logger.info("=== Status command completed successfully ===")

    except Exception as e:
        logger.error(f"Status command failed: {e}")
        logger.debug("Status error details", exc_info=True)
        console.print(f"❌ Failed to get status: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument("target", type=click.Path(exists=True), required=False)
@click.option(
    "--source-branch",
    help="Source branch for git diff scanning (e.g., feature-branch)",
)
@click.option(
    "--target-branch",
    help="Target branch for git diff scanning (e.g., main)",
)
@click.option(
    "--language",
    type=click.Choice(["python", "javascript", "typescript"]),
    help="Target language for scanning",
)
@click.option("--use-llm/--no-llm", default=True, help="Use LLM analysis")
@click.option("--use-semgrep/--no-semgrep", default=True, help="Use Semgrep analysis")
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Minimum severity threshold",
)
@click.option("--output", type=click.Path(), help="Output file for results (JSON)")
@click.option("--include-exploits", is_flag=True, help="Include exploit examples")
def scan(
    target: str | None,
    source_branch: str | None,
    target_branch: str | None,
    language: str | None,
    use_llm: bool,
    use_semgrep: bool,
    severity: str | None,
    output: str | None,
    include_exploits: bool,
):
    """Scan a file or directory for security vulnerabilities."""
    logger.info("=== Starting scan command ===")
    logger.debug(
        f"Scan parameters - Target: {target}, Source: {source_branch}, "
        f"Target branch: {target_branch}, Language: {language}, "
        f"LLM: {use_llm}, Semgrep: {use_semgrep}, Severity: {severity}, "
        f"Output: {output}, Include exploits: {include_exploits}"
    )

    try:
        # Initialize scanner components
        logger.debug("Initializing scan engine...")
        credential_manager = CredentialManager()
        scan_engine = ScanEngine(credential_manager)

        # Git diff scanning mode
        if source_branch and target_branch:
            logger.info(f"Git diff mode: {source_branch} -> {target_branch}")

            # Initialize git diff scanner
            git_diff_scanner = GitDiffScanner(
                scan_engine=scan_engine, working_dir=Path(target) if target else None
            )
            logger.debug("Git diff scanner initialized")

            # Perform diff scan
            severity_enum = Severity(severity) if severity else None
            logger.info(f"Starting diff scan with severity threshold: {severity_enum}")

            scan_results = git_diff_scanner.scan_diff_sync(
                source_branch=source_branch,
                target_branch=target_branch,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                severity_threshold=severity_enum,
            )
            logger.info(f"Diff scan completed - {len(scan_results)} files scanned")

            # Collect all threats from scan results
            all_threats = []
            for file_path, file_scan_results in scan_results.items():
                for scan_result in file_scan_results:
                    all_threats.extend(scan_result.all_threats)

            logger.info(f"Total threats found in diff scan: {len(all_threats)}")

            # Display results for git diff scanning
            if scan_results:
                console.print("\n🎯 [bold]Git Diff Scan Results[/bold]")
                _display_scan_results(
                    all_threats, f"diff: {source_branch}...{target_branch}"
                )
            else:
                console.print(
                    "✅ No changes detected or no security threats found!",
                    style="green",
                )

        # Traditional file/directory scanning mode
        else:
            if not target:
                logger.error("Target path is required for non-diff scanning")
                console.print(
                    "❌ Target path is required for non-diff scanning", style="red"
                )
                sys.exit(1)

            target_path = Path(target)
            logger.info(f"Starting traditional scan of: {target_path}")

            if target_path.is_file():
                # Single file scan
                logger.info(f"Scanning single file: {target_path}")

                # Auto-detect language if not provided
                if not language:
                    # Simple language detection based on file extension
                    ext = target_path.suffix.lower()
                    lang_map = {
                        ".py": "python",
                        ".js": "javascript",
                        ".ts": "typescript",
                    }
                    language = lang_map.get(ext)

                    if not language:
                        logger.error(f"Cannot auto-detect language for {target}")
                        console.print(
                            f"❌ Cannot auto-detect language for {target}", style="red"
                        )
                        sys.exit(1)
                    logger.info(f"Auto-detected language: {language}")

                # Initialize scan engine
                language_enum = Language(language.upper())
                severity_enum = Severity(severity) if severity else None

                # Perform scan
                logger.debug(f"Scanning file {target_path} as {language_enum}")
                scan_result = scan_engine.scan_file_sync(
                    target_path,
                    language=language_enum,
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    severity_threshold=severity_enum,
                )
                threats = scan_result.all_threats
                logger.info(f"File scan completed: {len(threats)} threats found")

            elif target_path.is_dir():
                # Directory scan
                logger.info(f"Scanning directory: {target_path}")

                severity_enum = Severity(severity) if severity else None

                # Perform directory scan
                logger.debug(f"Scanning directory {target_path}")
                scan_results = scan_engine.scan_directory_sync(
                    target_path,
                    recursive=True,
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    severity_threshold=severity_enum,
                )

                # Collect all threats
                threats = []
                for scan_result in scan_results:
                    threats.extend(scan_result.all_threats)

                logger.info(f"Directory scan completed: {len(threats)} threats found")

            else:
                logger.error(f"Invalid target type: {target}")
                console.print(f"❌ Invalid target: {target}", style="red")
                sys.exit(1)

            # Display results for traditional scanning
            _display_scan_results(threats, target)

        # Save results to file if requested
        if output and "all_threats" in locals():
            _save_results_to_file(all_threats, output)
        elif output and "threats" in locals():
            _save_results_to_file(threats, output)

        logger.info("=== Scan command completed successfully ===")

    except Exception as e:
        logger.error(f"Scan command failed: {e}")
        logger.debug("Scan error details", exc_info=True)
        console.print(f"❌ Scan failed: {e}", style="red")
        sys.exit(1)


@cli.command()
def demo():
    """Run a demonstration of the vulnerability scanner."""
    logger.info("=== Starting demo command ===")
    console.print("🎯 [bold]Adversary MCP Server Demo[/bold]")
    console.print(
        "This demo shows common security vulnerabilities and their detection.\n"
    )

    # Create sample vulnerable code
    python_code = """
import os
import pickle
import sqlite3

# SQL Injection vulnerability
def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

# Command injection vulnerability
def backup_file(filename):
    # Vulnerable: unsanitized user input in system command
    command = f"cp {filename} /backup/"
    os.system(command)

# Deserialization vulnerability
def load_data(data):
    # Vulnerable: pickle deserialization of untrusted data
    return pickle.loads(data)
"""

    javascript_code = """
// XSS vulnerability
function displayMessage(message) {
    // Vulnerable: direct HTML injection
    document.getElementById('output').innerHTML = message;
}

// Prototype pollution vulnerability
function merge(target, source) {
    for (let key in source) {
        // Vulnerable: no prototype check
        target[key] = source[key];
    }
    return target;
}

// Hardcoded credentials
const API_KEY = "sk-1234567890abcdef";
const PASSWORD = "admin123";
"""

    try:
        # Initialize scanner
        logger.debug("Initializing scanner components for demo...")
        credential_manager = CredentialManager()
        scan_engine = ScanEngine(credential_manager)

        all_threats = []

        # Scan Python code
        logger.info("Starting Python code demo scan...")
        console.print("\n🔍 [bold]Scanning Python Code...[/bold]")
        python_result = scan_engine.scan_code_sync(
            python_code, "demo.py", Language.PYTHON
        )
        python_threats = python_result.all_threats
        logger.info(f"Python demo scan completed: {len(python_threats)} threats found")

        # Scan JavaScript code
        logger.info("Starting JavaScript code demo scan...")
        console.print("\n🔍 [bold]Scanning JavaScript Code...[/bold]")
        js_result = scan_engine.scan_code_sync(
            javascript_code, "demo.js", Language.JAVASCRIPT
        )
        js_threats = js_result.all_threats
        logger.info(f"JavaScript demo scan completed: {len(js_threats)} threats found")

        # Combine results
        all_threats.extend(python_threats)
        all_threats.extend(js_threats)
        logger.info(f"Total demo threats found: {len(all_threats)}")

        # Display results
        _display_scan_results(all_threats, "demo")

        console.print("\n✅ [bold green]Demo completed![/bold green]")
        console.print(
            "Use 'adversary-mcp configure' to set up the server for production use."
        )
        logger.info("=== Demo command completed successfully ===")

    except Exception as e:
        logger.error(f"Demo command failed: {e}")
        logger.debug("Demo error details", exc_info=True)
        console.print(f"❌ Demo failed: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument("finding_uuid")
@click.option("--reason", type=str, help="Reason for marking as false positive")
@click.option("--reviewer", type=str, help="Name of reviewer")
def mark_false_positive(finding_uuid: str, reason: str | None, reviewer: str | None):
    """Mark a finding as a false positive by UUID."""
    logger.info(
        f"=== Starting mark-false-positive command for finding: {finding_uuid} ==="
    )

    try:
        from .false_positive_manager import FalsePositiveManager

        fp_manager = FalsePositiveManager()

        # Mark as false positive
        fp_manager.mark_false_positive(
            finding_uuid=finding_uuid,
            reason=reason or "Manually marked as false positive",
            reviewer=reviewer or "CLI User",
        )

        console.print(
            f"✅ Finding {finding_uuid} marked as false positive", style="green"
        )
        logger.info(f"Finding {finding_uuid} successfully marked as false positive")

    except Exception as e:
        logger.error(f"Mark-false-positive command failed: {e}")
        logger.debug("Mark-false-positive error details", exc_info=True)
        console.print(f"❌ Failed to mark as false positive: {e}", style="red")
        sys.exit(1)

    logger.info("=== Mark-false-positive command completed successfully ===")


@cli.command()
@click.argument("finding_uuid")
def unmark_false_positive(finding_uuid: str):
    """Remove false positive marking from a finding by UUID."""
    logger.info(
        f"=== Starting unmark-false-positive command for finding: {finding_uuid} ==="
    )

    try:
        from .false_positive_manager import FalsePositiveManager

        fp_manager = FalsePositiveManager()
        fp_manager.unmark_false_positive(finding_uuid)

        console.print(
            f"✅ False positive marking removed from {finding_uuid}", style="green"
        )
        logger.info(f"False positive marking removed from {finding_uuid}")

    except Exception as e:
        logger.error(f"Unmark-false-positive command failed: {e}")
        logger.debug("Unmark-false-positive error details", exc_info=True)
        console.print(f"❌ Failed to unmark false positive: {e}", style="red")
        sys.exit(1)

    logger.info("=== Unmark-false-positive command completed successfully ===")


@cli.command()
def list_false_positives():
    """List all findings marked as false positives."""
    logger.info("=== Starting list-false-positives command ===")

    try:
        from .false_positive_manager import FalsePositiveManager

        fp_manager = FalsePositiveManager()
        false_positives = fp_manager.list_false_positives()

        if not false_positives:
            console.print("No false positives found.", style="yellow")
            return

        # Create table
        table = Table(title=f"False Positives ({len(false_positives)} found)")
        table.add_column("UUID", style="cyan")
        table.add_column("Reason", style="magenta")
        table.add_column("Reviewer", style="green")
        table.add_column("Date", style="yellow")

        for fp in false_positives:
            table.add_row(
                fp.get("finding_uuid", "Unknown"),
                fp.get("reason", "No reason provided"),
                fp.get("reviewer", "Unknown"),
                fp.get("created_at", "Unknown"),
            )

        console.print(table)
        logger.info("=== List-false-positives command completed successfully ===")

    except Exception as e:
        logger.error(f"List-false-positives command failed: {e}")
        logger.debug("List-false-positives error details", exc_info=True)
        console.print(f"❌ Failed to list false positives: {e}", style="red")
        sys.exit(1)


@cli.command()
def reset():
    """Reset all configuration and credentials."""
    logger.info("=== Starting reset command ===")

    if Confirm.ask("Are you sure you want to reset all configuration?"):
        try:
            logger.debug("User confirmed configuration reset")
            credential_manager = CredentialManager()
            credential_manager.reset_config()
            console.print("✅ Configuration reset successfully!", style="green")
            logger.info("Configuration reset completed")
        except Exception as e:
            logger.error(f"Reset command failed: {e}")
            logger.debug("Reset error details", exc_info=True)
            console.print(f"❌ Reset failed: {e}", style="red")
            sys.exit(1)
    else:
        logger.info("User cancelled configuration reset")

    logger.info("=== Reset command completed successfully ===")


def _display_scan_results(threats, target):
    """Display scan results in a formatted table."""
    logger.debug(f"Displaying scan results for target: {target}")
    if not threats:
        console.print("✅ No security threats detected!", style="green")
        logger.info("No security threats detected")
        return

    # Group threats by severity
    critical = [t for t in threats if t.severity == Severity.CRITICAL]
    high = [t for t in threats if t.severity == Severity.HIGH]
    medium = [t for t in threats if t.severity == Severity.MEDIUM]
    low = [t for t in threats if t.severity == Severity.LOW]

    # Summary
    console.print(
        f"\n🚨 [bold red]Found {len(threats)} security threats in {target}[/bold red]"
    )
    console.print(
        f"Critical: {len(critical)}, High: {len(high)}, Medium: {len(medium)}, Low: {len(low)}"
    )

    # Create table
    table = Table(title=f"Security Threats ({len(threats)} found)")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Type", style="green")
    table.add_column("Description", style="yellow")

    for threat in threats:
        # Color severity
        severity_color = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
        }.get(threat.severity, "white")

        table.add_row(
            Path(threat.file_path).name,
            str(threat.line_number),
            f"[{severity_color}]{threat.severity.value.upper()}[/{severity_color}]",
            threat.rule_name,
            (
                threat.description[:40] + "..."
                if len(threat.description) > 40
                else threat.description
            ),
        )

    console.print(table)
    logger.info(f"Displayed scan results for {target}")


def _save_results_to_file(threats, output_file):
    """Save scan results to a JSON file."""
    logger.info(f"Saving results to file: {output_file}")
    try:
        output_path = Path(output_file)

        # Convert threats to serializable format
        logger.debug(f"Converting {len(threats)} threats to serializable format...")
        results = []
        for threat in threats:
            threat_data = {
                "file_path": threat.file_path,
                "line_number": threat.line_number,
                "rule_id": threat.rule_id,
                "rule_name": threat.rule_name,
                "description": threat.description,
                "severity": threat.severity.value,
                "category": threat.category.value,
                "confidence": threat.confidence,
                "code_snippet": threat.code_snippet,
            }

            # Add optional fields if present
            if hasattr(threat, "cwe_id") and threat.cwe_id:
                threat_data["cwe_id"] = threat.cwe_id
            if hasattr(threat, "owasp_category") and threat.owasp_category:
                threat_data["owasp_category"] = threat.owasp_category
            if hasattr(threat, "exploit_examples") and threat.exploit_examples:
                threat_data["exploit_examples"] = threat.exploit_examples

            results.append(threat_data)

        # Save to file
        with open(output_path, "w") as f:
            json.dump(
                {
                    "scan_timestamp": datetime.datetime.now().isoformat(),
                    "threats_count": len(threats),
                    "threats": results,
                },
                f,
                indent=2,
            )

        console.print(f"✅ Results saved to {output_path}", style="green")
        logger.info(f"Results saved to {output_path}")

    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        logger.debug("Save results error details", exc_info=True)
        console.print(f"❌ Failed to save results: {e}", style="red")


def main():
    """Main entry point for the CLI."""
    logger.info("=== Adversary MCP CLI Main Entry Point ===")
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n👋 Goodbye!", style="yellow")
        logger.info("CLI terminated by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")
        logger.debug("Main error details", exc_info=True)
        console.print(f"❌ Unexpected error: {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    main()
