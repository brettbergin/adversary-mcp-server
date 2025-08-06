"""Command-line interface for the Adversary MCP server."""

import datetime
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import get_version
from .benchmarks import BenchmarkRunner
from .credentials import CredentialManager
from .logger import get_logger
from .scanner.diff_scanner import GitDiffScanner
from .scanner.scan_engine import ScanEngine
from .scanner.types import Severity

console = Console()
logger = get_logger("cli")


def _get_project_root(custom_path: str | None = None) -> Path:
    """Get the project root directory.

    Args:
        custom_path: Optional custom path override

    Returns:
        Path object representing project root directory
    """
    if custom_path:
        return Path(custom_path).resolve()
    return Path.cwd()


def _get_adversary_json_path(custom_path: str | None = None) -> Path:
    """Get the path to the .adversary.json file.

    Args:
        custom_path: Optional custom path override for the directory containing .adversary.json

    Returns:
        Path to .adversary.json file
    """
    project_root = _get_project_root(custom_path)
    return project_root / ".adversary.json"


def _resolve_target_path(
    target: str | None, custom_working_dir: str | None = None
) -> Path:
    """Resolve target path relative to project root.

    Args:
        target: Target path (file/directory)
        custom_working_dir: Optional custom working directory override

    Returns:
        Resolved Path object
    """
    project_root = _get_project_root(custom_working_dir)

    if not target:
        return project_root

    target_path = Path(target)

    # If absolute path, use as-is
    if target_path.is_absolute():
        return target_path.resolve()

    # Resolve relative to project root
    return (project_root / target_path).resolve()


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
@click.option(
    "--llm-provider",
    type=click.Choice(["openai", "anthropic"]),
    help="LLM provider to use for AI-powered analysis",
)
@click.option(
    "--clear-llm",
    is_flag=True,
    help="Clear all LLM configuration",
)
def configure(
    severity_threshold: str | None,
    enable_safety_mode: bool,
    llm_provider: str | None,
    clear_llm: bool,
):
    """Configure the Adversary MCP server settings including API keys."""
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

        # Only prompt for Semgrep API key if not already configured
        existing_key = credential_manager.get_semgrep_api_key()
        if not existing_key:
            console.print("\n🔑 [bold]Semgrep API Key Configuration[/bold]")
            console.print("ℹ️  No Semgrep API key found", style="yellow")
            configure_key = Confirm.ask(
                "Would you like to configure your Semgrep API key now?", default=True
            )

            if configure_key:
                console.print("\n📝 Enter your Semgrep API key:")
                console.print(
                    "   • Get your API key from: https://semgrep.dev/orgs/-/settings/tokens"
                )
                console.print("   • Leave blank to skip configuration")

                api_key = Prompt.ask("SEMGREP_API_KEY", password=True, default="")

                if api_key.strip():
                    try:
                        credential_manager.store_semgrep_api_key(api_key.strip())
                        console.print(
                            "✅ Semgrep API key stored securely in keyring!",
                            style="green",
                        )
                        logger.info("Semgrep API key configured successfully")
                    except Exception as e:
                        console.print(
                            f"❌ Failed to store Semgrep API key: {e}", style="red"
                        )
                        logger.error(f"Failed to store Semgrep API key: {e}")
                else:
                    console.print(
                        "⏭️  Skipped Semgrep API key configuration", style="yellow"
                    )
        else:
            # Key exists - just show a brief confirmation without prompting
            console.print("\n🔑 Semgrep API key: ✅ Configured", style="green")

        # Handle LLM configuration
        if clear_llm:
            console.print("\n🧹 [bold]Clearing LLM Configuration[/bold]")
            credential_manager.clear_llm_configuration()
            console.print("✅ LLM configuration cleared!", style="green")
            config_updated = True
            logger.info("LLM configuration cleared")
        elif llm_provider:
            console.print(f"\n🤖 [bold]Configuring {llm_provider.title()} LLM[/bold]")

            # Clear any existing LLM configuration first
            if config.llm_provider and config.llm_provider != llm_provider:
                console.print(
                    f"ℹ️  Switching from {config.llm_provider} to {llm_provider}",
                    style="yellow",
                )
                credential_manager.clear_llm_configuration()

            # Get API key
            console.print(f"\n📝 Enter your {llm_provider.title()} API key:")
            if llm_provider == "openai":
                console.print(
                    "   • Get your API key from: https://platform.openai.com/api-keys"
                )
            else:  # anthropic
                console.print(
                    "   • Get your API key from: https://console.anthropic.com/settings/keys"
                )

            api_key = Prompt.ask(f"{llm_provider.upper()}_API_KEY", password=True)

            if api_key.strip():
                try:
                    # Store API key in keyring
                    credential_manager.store_llm_api_key(llm_provider, api_key.strip())

                    # Update configuration
                    config.llm_provider = llm_provider
                    # Don't store the actual API key in config - it's already in keyring

                    # Ask for model selection
                    if llm_provider == "openai":
                        default_model = "gpt-4-turbo-preview"
                        model_choices = [
                            "gpt-4-turbo-preview",
                            "gpt-4",
                            "gpt-3.5-turbo",
                        ]
                        console.print(
                            f"\n🎯 Select OpenAI model (default: {default_model}):"
                        )
                    else:  # anthropic
                        default_model = "claude-3-5-sonnet-20241022"
                        model_choices = [
                            "claude-3-5-sonnet-20241022",
                            "claude-3-5-haiku-20241022",
                            "claude-3-opus-latest",
                            "claude-3-sonnet-20240229",
                            "claude-3-haiku-20240307",
                        ]
                        console.print(
                            f"\n🎯 Select Anthropic model (default: {default_model}):"
                        )

                    for i, model in enumerate(model_choices, 1):
                        console.print(f"   {i}. {model}")

                    model_input = Prompt.ask("Model", default=default_model)
                    config.llm_model = (
                        model_input if model_input in model_choices else default_model
                    )

                    config_updated = True
                    console.print(
                        f"✅ {llm_provider.title()} configuration complete!",
                        style="green",
                    )
                    logger.info(
                        f"{llm_provider} LLM configured successfully with model: {config.llm_model}"
                    )

                except Exception as e:
                    console.print(
                        f"❌ Failed to configure {llm_provider}: {e}", style="red"
                    )
                    logger.error(f"Failed to configure {llm_provider}: {e}")
            else:
                console.print(
                    f"⏭️  Skipped {llm_provider} configuration", style="yellow"
                )
        else:
            # Show current LLM status if not configuring
            if config.llm_provider:
                console.print(
                    f"\n🤖 LLM Provider: ✅ {config.llm_provider.title()} (Model: {config.llm_model})",
                    style="green",
                )
            else:
                console.print("\n🤖 LLM Provider: ❌ Not configured", style="yellow")
                console.print(
                    "   • Use --llm-provider openai or --llm-provider anthropic to configure",
                    style="dim",
                )

        if config_updated:
            credential_manager.store_config(config)
            console.print("\n✅ Configuration updated successfully!", style="green")

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
        # LLM Configuration details
        is_llm_valid, llm_error = config.validate_llm_configuration()
        if config.llm_provider:
            llm_status = (
                f"{config.llm_provider.title()} ({config.llm_model or 'default'})"
            )
            if not is_llm_valid:
                llm_status += f" - Error: {llm_error}"
        else:
            llm_status = "Not configured"

        config_table.add_row("LLM Provider", llm_status)
        config_table.add_row(
            "LLM Analysis", "Enabled" if config.enable_llm_analysis else "Disabled"
        )
        config_table.add_row(
            "LLM Validation", "Enabled" if config.enable_llm_validation else "Disabled"
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
        scanners_table.add_row(
            "LLM Validation",
            "Available" if scan_engine.llm_validator else "Unavailable",
            "False positive filtering",
        )

        console.print(scanners_table)

        logger.info("=== Status command completed successfully ===")

    except Exception as e:
        logger.error(f"Status command failed: {e}")
        logger.debug("Status error details", exc_info=True)
        console.print(f"❌ Failed to get status: {e}", style="red")
        sys.exit(1)


@cli.command()
def debug_config():
    """Debug configuration persistence by showing keyring state."""
    logger.info("=== Starting debug-config command ===")
    try:
        credential_manager = CredentialManager()

        console.print("🔧 [bold]Configuration Debug Information[/bold]")

        # Get keyring state
        keyring_state = credential_manager.debug_keyring_state()

        # Display keyring information
        keyring_table = Table(title="Keyring State")
        keyring_table.add_column("Item", style="cyan")
        keyring_table.add_column("Status", style="magenta")
        keyring_table.add_column("Details", style="yellow")

        keyring_table.add_row("Service Name", keyring_state["keyring_service"], "")

        # Main config
        main_config = keyring_state["main_config"]
        if main_config.get("found"):
            keyring_table.add_row(
                "Main Config",
                "✅ Found",
                f"Provider: {main_config.get('llm_provider', 'None')}",
            )
            keyring_table.add_row(
                "Config LLM Key", main_config.get("llm_api_key_status", "UNKNOWN"), ""
            )
            keyring_table.add_row(
                "Config Semgrep Key",
                main_config.get("semgrep_api_key_status", "UNKNOWN"),
                "",
            )
        else:
            error_msg = main_config.get("error", "Not found")
            keyring_table.add_row("Main Config", "❌ Missing", error_msg)

        # Individual API keys
        for provider in ["openai", "anthropic"]:
            key_info = keyring_state[f"llm_{provider}_key"]
            if key_info.get("found"):
                keyring_table.add_row(
                    f"{provider.title()} API Key",
                    "✅ Found",
                    f"{key_info.get('length', 0)} chars",
                )
            else:
                error_msg = key_info.get("error", "Not found")
                keyring_table.add_row(
                    f"{provider.title()} API Key", "❌ Missing", error_msg
                )

        # Semgrep key
        semgrep_info = keyring_state["semgrep_key"]
        if semgrep_info.get("found"):
            keyring_table.add_row(
                "Semgrep API Key", "✅ Found", f"{semgrep_info.get('length', 0)} chars"
            )
        else:
            error_msg = semgrep_info.get("error", "Not found")
            keyring_table.add_row("Semgrep API Key", "❌ Missing", error_msg)

        # Cache state
        keyring_table.add_row(
            "Cache Loaded", "✅ Yes" if keyring_state["cache_loaded"] else "❌ No", ""
        )

        cached_config = keyring_state["cached_config"]
        if cached_config.get("found"):
            keyring_table.add_row(
                "Cached Config",
                "✅ Found",
                f"Provider: {cached_config.get('llm_provider', 'None')}",
            )
            keyring_table.add_row(
                "Cached LLM Key", cached_config.get("llm_api_key_status", "UNKNOWN"), ""
            )
            keyring_table.add_row(
                "Cached Semgrep Key",
                cached_config.get("semgrep_api_key_status", "UNKNOWN"),
                "",
            )
        else:
            keyring_table.add_row("Cached Config", "❌ Missing", "")

        console.print(keyring_table)

        # Also try loading config to see what happens
        console.print("\n🔄 [bold]Testing Configuration Load[/bold]")
        try:
            config = credential_manager.load_config()
            load_table = Table(title="Loaded Configuration")
            load_table.add_column("Setting", style="cyan")
            load_table.add_column("Value", style="magenta")

            load_table.add_row("LLM Provider", str(config.llm_provider))
            load_table.add_row("LLM Model", str(config.llm_model))
            load_table.add_row("LLM API Key", "SET" if config.llm_api_key else "NULL")
            load_table.add_row("Semgrep Scanning", str(config.enable_semgrep_scanning))
            load_table.add_row(
                "Semgrep API Key", "SET" if config.semgrep_api_key else "NULL"
            )
            load_table.add_row("LLM Validation", str(config.enable_llm_validation))

            console.print(load_table)

        except Exception as load_error:
            console.print(f"❌ Failed to load config: {load_error}", style="red")

        # Show raw JSON output for advanced debugging
        console.print("\n📋 [bold]Raw Debug Data (JSON)[/bold]")
        console.print(json.dumps(keyring_state, indent=2))

        logger.info("=== Debug-config command completed successfully ===")

    except Exception as e:
        logger.error(f"Debug-config command failed: {e}")
        logger.debug("Debug-config error details", exc_info=True)
        console.print(f"❌ Debug command failed: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument("target", required=False)
@click.option(
    "--source-branch",
    help="Source branch for git diff scanning (e.g., feature-branch)",
)
@click.option(
    "--target-branch",
    help="Target branch for git diff scanning (e.g., main)",
)
@click.option("--use-llm/--no-llm", default=True, help="Use LLM analysis")
@click.option("--use-semgrep/--no-semgrep", default=True, help="Use Semgrep analysis")
@click.option(
    "--use-validation/--no-validation",
    default=True,
    help="Use LLM validation to filter false positives",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Minimum severity threshold",
)
@click.option("--output", type=click.Path(), help="Output file for results (JSON)")
@click.option("--include-exploits", is_flag=True, help="Include exploit examples")
@click.option(
    "--working-directory",
    help="Working directory to use as project root (defaults to current directory)",
)
def scan(
    target: str | None,
    source_branch: str | None,
    target_branch: str | None,
    use_llm: bool,
    use_semgrep: bool,
    use_validation: bool,
    severity: str | None,
    output: str | None,
    include_exploits: bool,
    working_directory: str | None,
):
    """Scan a file or directory for security vulnerabilities."""
    logger.info("=== Starting scan command ===")
    logger.debug(
        f"Scan parameters - Target: {target}, Source: {source_branch}, "
        f"Target branch: {target_branch}, "
        f"LLM: {use_llm}, Semgrep: {use_semgrep}, Validation: {use_validation}, "
        f"Severity: {severity}, Output: {output}, Include exploits: {include_exploits}"
    )

    try:
        # Initialize scanner components
        logger.debug("Initializing scan engine...")
        credential_manager = CredentialManager()
        scan_engine = ScanEngine(
            credential_manager=credential_manager,
            enable_llm_validation=use_validation,
        )

        # Git diff scanning mode
        if source_branch and target_branch:
            logger.info(f"Git diff mode: {source_branch} -> {target_branch}")

            # Get working directory using helper function
            project_root = _get_project_root(working_directory)

            # Initialize git diff scanner with project root
            git_diff_scanner = GitDiffScanner(
                scan_engine=scan_engine, working_dir=project_root
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
                use_validation=use_validation,
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

            # Use helper function to resolve target path
            target_path = _resolve_target_path(target, working_directory)
            target_path_abs = str(target_path)
            logger.info(f"Starting traditional scan of: {target_path_abs}")

            if target_path.is_file():
                # Single file scan
                logger.info(f"Scanning single file: {target_path_abs}")

                # Initialize scan engine
                severity_enum = Severity(severity) if severity else None

                # Perform scan (language will be auto-detected by scan engine)
                logger.debug(f"Scanning file {target_path} with auto-detected language")
                scan_result = scan_engine.scan_file_sync(
                    target_path,
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    use_validation=use_validation,
                    severity_threshold=severity_enum,
                )
                threats = scan_result.all_threats
                logger.info(f"File scan completed: {len(threats)} threats found")

            elif target_path.is_dir():
                # Directory scan
                logger.info(f"Scanning directory: {target_path_abs}")

                severity_enum = Severity(severity) if severity else None

                # Perform directory scan
                logger.debug(f"Scanning directory {target_path_abs}")
                scan_results = scan_engine.scan_directory_sync(
                    target_path,
                    recursive=True,
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    use_validation=use_validation,
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
        python_result = scan_engine.scan_code_sync(python_code, "demo.py", "python")
        python_threats = python_result.all_threats
        logger.info(f"Python demo scan completed: {len(python_threats)} threats found")

        # Scan JavaScript code
        logger.info("Starting JavaScript code demo scan...")
        console.print("\n🔍 [bold]Scanning JavaScript Code...[/bold]")
        js_result = scan_engine.scan_code_sync(javascript_code, "demo.js", "javascript")
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
@click.option("--marked-by", type=str, help="Name of person marking as false positive")
@click.option(
    "--working-directory",
    type=click.Path(exists=True),
    help="Working directory to search for .adversary.json",
)
def mark_false_positive(
    finding_uuid: str,
    reason: str | None,
    marked_by: str | None,
    working_directory: str | None,
):
    """Mark a finding as a false positive by UUID."""
    logger.info(
        f"=== Starting mark-false-positive command for finding: {finding_uuid} ==="
    )

    try:
        from .scanner.false_positive_manager import FalsePositiveManager

        # Use helper function to get adversary.json path
        adversary_file_path = _get_adversary_json_path(working_directory)

        # Check if file exists, if not use the legacy search approach
        if not adversary_file_path.exists():
            # Fall back to legacy search in parent directories
            project_root = working_directory or "."
            current_dir = Path(project_root)

            logger.info(
                f".adversary.json not found at {adversary_file_path}, searching parent directories..."
            )
            search_dir = current_dir.resolve()
            home_dir = Path.home().resolve()

            found = False
            while search_dir != search_dir.parent and search_dir >= home_dir:
                test_file = search_dir / ".adversary.json"
                if test_file.exists():
                    adversary_file_path = test_file
                    logger.info(
                        f"✅ Found .adversary.json in parent directory: {search_dir}"
                    )
                    found = True
                    break
                search_dir = search_dir.parent

            if not found:
                console.print(
                    "❌ No .adversary.json file found in directory tree", style="red"
                )
                sys.exit(1)

        fp_manager = FalsePositiveManager(adversary_file_path=str(adversary_file_path))

        # Mark as false positive
        success = fp_manager.mark_false_positive(
            finding_uuid,
            reason or "Manually marked as false positive via CLI",
            marked_by or "CLI User",
        )

        if success:
            console.print(
                f"✅ Finding {finding_uuid} marked as false positive", style="green"
            )
            console.print(f"📁 File: {adversary_file_path}", style="dim")
            logger.info(f"Finding {finding_uuid} successfully marked as false positive")
        else:
            console.print(
                f"❌ Finding {finding_uuid} not found in scan results", style="red"
            )
            sys.exit(1)

    except Exception as e:
        logger.error(f"Mark-false-positive command failed: {e}")
        logger.debug("Mark-false-positive error details", exc_info=True)
        console.print(f"❌ Failed to mark as false positive: {e}", style="red")
        sys.exit(1)

    logger.info("=== Mark-false-positive command completed successfully ===")


@cli.command()
@click.argument("finding_uuid")
@click.option(
    "--working-directory",
    type=click.Path(exists=True),
    help="Working directory to search for .adversary.json",
)
def unmark_false_positive(finding_uuid: str, working_directory: str | None):
    """Remove false positive marking from a finding by UUID."""
    logger.info(
        f"=== Starting unmark-false-positive command for finding: {finding_uuid} ==="
    )

    try:
        from .scanner.false_positive_manager import FalsePositiveManager

        # Use helper function to get adversary.json path
        adversary_file_path = _get_adversary_json_path(working_directory)

        # Check if file exists, if not use the legacy search approach
        if not adversary_file_path.exists():
            # Fall back to legacy search in parent directories
            project_root = working_directory or "."
            current_dir = Path(project_root)

            logger.info(
                f".adversary.json not found at {adversary_file_path}, searching parent directories..."
            )
            search_dir = current_dir.resolve()
            home_dir = Path.home().resolve()

            found = False
            while search_dir != search_dir.parent and search_dir >= home_dir:
                test_file = search_dir / ".adversary.json"
                if test_file.exists():
                    adversary_file_path = test_file
                    logger.info(
                        f"✅ Found .adversary.json in parent directory: {search_dir}"
                    )
                    found = True
                    break
                search_dir = search_dir.parent

            if not found:
                console.print(
                    "❌ No .adversary.json file found in directory tree", style="red"
                )
                sys.exit(1)

        fp_manager = FalsePositiveManager(adversary_file_path=str(adversary_file_path))
        success = fp_manager.unmark_false_positive(finding_uuid)

        if success:
            console.print(
                f"✅ False positive marking removed from {finding_uuid}", style="green"
            )
            console.print(f"📁 File: {adversary_file_path}", style="dim")
            logger.info(f"False positive marking removed from {finding_uuid}")
        else:
            console.print(
                f"❌ Finding {finding_uuid} was not marked as false positive",
                style="red",
            )
            sys.exit(1)

    except Exception as e:
        logger.error(f"Unmark-false-positive command failed: {e}")
        logger.debug("Unmark-false-positive error details", exc_info=True)
        console.print(f"❌ Failed to unmark false positive: {e}", style="red")
        sys.exit(1)

    logger.info("=== Unmark-false-positive command completed successfully ===")


@cli.command()
@click.option(
    "--working-directory",
    type=click.Path(exists=True),
    help="Working directory to search for .adversary.json",
)
def list_false_positives(working_directory: str | None):
    """List all findings marked as false positives."""
    logger.info("=== Starting list-false-positives command ===")

    try:
        from .scanner.false_positive_manager import FalsePositiveManager

        # Use helper function to get adversary.json path
        adversary_file_path = _get_adversary_json_path(working_directory)

        # Check if file exists, if not use the legacy search approach
        if not adversary_file_path.exists():
            # Fall back to legacy search in parent directories
            project_root = working_directory or "."
            current_dir = Path(project_root)

            logger.info(
                f".adversary.json not found at {adversary_file_path}, searching parent directories..."
            )
            search_dir = current_dir.resolve()
            home_dir = Path.home().resolve()

            found = False
            while search_dir != search_dir.parent and search_dir >= home_dir:
                test_file = search_dir / ".adversary.json"
                if test_file.exists():
                    adversary_file_path = test_file
                    logger.info(
                        f"✅ Found .adversary.json in parent directory: {search_dir}"
                    )
                    found = True
                    break
                search_dir = search_dir.parent

            if not found:
                console.print(
                    "❌ No .adversary.json file found in directory tree", style="red"
                )
                sys.exit(1)

        fp_manager = FalsePositiveManager(adversary_file_path=str(adversary_file_path))
        false_positives = fp_manager.get_false_positives()

        if not false_positives:
            console.print("No false positives found.", style="yellow")
            console.print(f"📁 Checked: {adversary_file_path}", style="dim")
            return

        # Create table
        table = Table(title=f"False Positives ({len(false_positives)} found)")
        table.add_column("UUID", style="cyan")
        table.add_column("Reason", style="magenta")
        table.add_column("Marked By", style="green")
        table.add_column("Date", style="yellow")
        table.add_column("Source", style="blue")

        for fp in false_positives:
            table.add_row(
                fp.get("uuid", "Unknown"),
                fp.get("reason", "No reason provided"),
                fp.get("marked_by", "Unknown"),
                fp.get("marked_date", "Unknown"),
                fp.get("source", "Unknown"),
            )

        console.print(table)
        console.print(f"📁 Source: {adversary_file_path}", style="dim")
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

            # Delete main configuration
            credential_manager.delete_config()
            console.print("✅ Main configuration deleted", style="green")

            # Delete Semgrep API key
            api_key_deleted = credential_manager.delete_semgrep_api_key()
            if api_key_deleted:
                console.print("✅ Semgrep API key deleted", style="green")
            else:
                console.print("ℹ️  No Semgrep API key found to delete", style="yellow")

            console.print("✅ All configuration reset successfully!", style="green")
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


@cli.command()
def reset_semgrep_key():
    """Remove the stored Semgrep API key from keyring."""
    logger.info("=== Starting reset-semgrep-key command ===")

    try:
        credential_manager = CredentialManager()
        existing_key = credential_manager.get_semgrep_api_key()

        if not existing_key:
            console.print("ℹ️  No Semgrep API key found in keyring", style="yellow")
            return

        console.print("🔑 Found existing Semgrep API key in keyring")
        if Confirm.ask(
            "Are you sure you want to remove the Semgrep API key?", default=False
        ):
            success = credential_manager.delete_semgrep_api_key()

            if success:
                console.print("✅ Semgrep API key removed from keyring!", style="green")
                logger.info("Semgrep API key successfully removed")
            else:
                console.print("❌ Failed to remove Semgrep API key", style="red")
                logger.error("Failed to remove Semgrep API key from keyring")
                sys.exit(1)
        else:
            console.print("⏭️  Cancelled - API key remains in keyring", style="yellow")

    except Exception as e:
        logger.error(f"Reset-semgrep-key command failed: {e}")
        logger.debug("Reset-semgrep-key error details", exc_info=True)
        console.print(f"❌ Failed to reset Semgrep API key: {e}", style="red")
        sys.exit(1)

    logger.info("=== Reset-semgrep-key command completed successfully ===")


@cli.command()
@click.option(
    "--scenario",
    type=str,
    help="Run specific benchmark scenario (single_file, small_batch, medium_batch, cache_test, large_files)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Save benchmark results to JSON file",
)
def benchmark(scenario: str | None, output: str | None):
    """Run performance benchmarks to test scanner performance."""
    logger.info("=== Starting benchmark command ===")
    console.print("⚡ [bold]Adversary MCP Performance Benchmark[/bold]")

    try:
        # Initialize benchmark runner
        credential_manager = CredentialManager()
        benchmark_runner = BenchmarkRunner(credential_manager)

        if scenario:
            # Run single scenario
            logger.info(f"Running single benchmark scenario: {scenario}")
            console.print(f"\n🏃 Running scenario: [bold]{scenario}[/bold]")

            import asyncio

            result = asyncio.run(benchmark_runner.run_single_benchmark(scenario))

            # Display single result
            console.print(f"\n📊 [bold]Benchmark Result: {result.name}[/bold]")
            status = "✅" if result.success else "❌"
            console.print(
                f"{status} Status: {'Success' if result.success else 'Failed'}"
            )

            if result.success:
                console.print(f"⏱️  Duration: {result.duration_seconds:.2f}s")
                if result.files_processed > 0:
                    console.print(f"📁 Files: {result.files_processed}")
                    console.print(f"🚀 Speed: {result.files_per_second:.2f} files/sec")
                    console.print(f"🔍 Findings: {result.findings_count}")
                if result.memory_peak_mb > 0:
                    console.print(f"💾 Memory Peak: {result.memory_peak_mb:.1f} MB")
                if result.cache_hits + result.cache_misses > 0:
                    console.print(f"📄 Cache Hit Rate: {result.cache_hit_rate:.1f}%")
            else:
                console.print(f"❌ Error: {result.error_message}")

            # Save single result if requested
            if output:
                from .benchmarks.results import BenchmarkSummary

                summary = BenchmarkSummary()
                summary.add_result(result)
                summary.save_to_file(Path(output))
                console.print(f"💾 Results saved to {output}", style="green")

        else:
            # Run all benchmarks
            logger.info("Running all benchmark scenarios")
            console.print("\n🏃 Running all benchmark scenarios...")

            import asyncio

            summary = asyncio.run(benchmark_runner.run_all_benchmarks())

            # Display summary
            summary.print_summary()

            # Save results if requested
            if output:
                summary.save_to_file(Path(output))
                console.print(f"💾 Results saved to {output}", style="green")

        logger.info("=== Benchmark command completed successfully ===")

    except ValueError as e:
        if "Unknown scenario" in str(e):
            console.print(f"❌ Unknown scenario: {scenario}", style="red")
            console.print(
                "Available scenarios: single_file, small_batch, medium_batch, cache_test, large_files",
                style="yellow",
            )
        else:
            console.print(f"❌ Benchmark failed: {e}", style="red")
        logger.error(f"Benchmark command failed: {e}")
        sys.exit(1)

    except Exception as e:
        logger.error(f"Benchmark command failed: {e}")
        logger.debug("Benchmark error details", exc_info=True)
        console.print(f"❌ Benchmark failed: {e}", style="red")
        sys.exit(1)


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
