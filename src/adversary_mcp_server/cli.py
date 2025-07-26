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
from .credentials import CredentialManager
from .logger import get_logger
from .scanner.diff_scanner import GitDiffScanner
from .scanner.scan_engine import ScanEngine
from .scanner.types import Language, Severity
from .threat_modeling.diagram_generator import MermaidDiagramGenerator
from .threat_modeling.models import Severity as ThreatSeverity
from .threat_modeling.threat_model_builder import ThreatModelBuilder

console = Console()
logger = get_logger("cli")


def _is_valid_project(path: Path) -> bool:
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
        "requirements.txt",  # Python project
        "setup.py",  # Python project
        "Gemfile",  # Ruby project
        ".svn",  # SVN repository
        ".hg",  # Mercurial repository
    ]

    for indicator in project_indicators:
        if (path / indicator).exists():
            return True

    return False


def _find_repo_by_name_cli(repo_name: str, max_depth: int = 3) -> Path:
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
                if item.name == repo_name and _is_valid_project(item):
                    found_repos.append(item)
                    logger.debug(f"Found potential repo at: {item}")

                # Recurse into subdirectory if we haven't hit max depth
                if current_depth < max_depth:
                    search_directory(item, current_depth + 1)

        except (PermissionError, OSError, FileNotFoundError):
            # Skip directories we can't access
            logger.debug(f"Skipping inaccessible directory: {current_path}")
            pass

    console.print(f"🔍 Searching for repository '{repo_name}'...", style="yellow")
    search_directory(home, 0)

    if not found_repos:
        console.print(f"❌ Repository '{repo_name}' not found.", style="red")
        sys.exit(1)

    if len(found_repos) == 1:
        console.print(f"✅ Found repository at: {found_repos[0]}", style="green")
        return found_repos[0]

    # Multiple matches - let user know and pick the first one
    console.print(
        f"⚠️  Multiple repositories named '{repo_name}' found:", style="yellow"
    )
    for repo in found_repos:
        console.print(f"  - {repo}", style="cyan")
    console.print(f"ℹ️  Using first match: {found_repos[0]}", style="blue")
    return found_repos[0]


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
    """Configure the Adversary MCP server settings including Semgrep API key."""
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

        if config_updated:
            credential_manager.store_config(config)
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
            target_path_abs = str(target_path.resolve())
            logger.info(f"Starting traditional scan of: {target_path_abs}")

            if target_path.is_file():
                # Single file scan
                logger.info(f"Scanning single file: {target_path_abs}")

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
                logger.info(f"Scanning directory: {target_path_abs}")

                severity_enum = Severity(severity) if severity else None

                # Perform directory scan
                logger.debug(f"Scanning directory {target_path_abs}")
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

        # Smart search for .adversary.json file like the MCP server does
        project_root = working_directory or "."
        from pathlib import Path

        current_dir = Path(project_root)
        adversary_file = current_dir / ".adversary.json"

        # Convert to absolute path for better logging
        project_root_abs = str(Path(project_root).resolve())
        logger.info(f"Starting mark-false-positive in directory: {project_root_abs}")

        # If .adversary.json doesn't exist in working_directory, search up the directory tree
        if not adversary_file.exists():
            logger.info(
                f".adversary.json not found at {adversary_file}, searching parent directories..."
            )
            search_dir = current_dir.resolve()
            home_dir = Path.home().resolve()

            found = False
            while search_dir != search_dir.parent and search_dir >= home_dir:
                test_file = search_dir / ".adversary.json"
                if test_file.exists():
                    project_root = str(search_dir)
                    logger.info(
                        f"✅ Found .adversary.json in parent directory: {project_root}"
                    )
                    found = True
                    break
                search_dir = search_dir.parent

            if not found:
                console.print(
                    "❌ No .adversary.json file found in directory tree", style="red"
                )
                sys.exit(1)

        adversary_file_path = str(Path(project_root) / ".adversary.json")
        fp_manager = FalsePositiveManager(adversary_file_path=adversary_file_path)

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
            console.print(
                f"📁 File: {Path(project_root) / '.adversary.json'}", style="dim"
            )
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

        # Smart search for .adversary.json file like the MCP server does
        project_root = working_directory or "."
        from pathlib import Path

        current_dir = Path(project_root)
        adversary_file = current_dir / ".adversary.json"

        # Convert to absolute path for better logging
        project_root_abs = str(Path(project_root).resolve())
        logger.info(f"Starting unmark-false-positive in directory: {project_root_abs}")

        # If .adversary.json doesn't exist in working_directory, search up the directory tree
        if not adversary_file.exists():
            logger.info(
                f".adversary.json not found at {adversary_file}, searching parent directories..."
            )
            search_dir = current_dir.resolve()
            home_dir = Path.home().resolve()

            found = False
            while search_dir != search_dir.parent and search_dir >= home_dir:
                test_file = search_dir / ".adversary.json"
                if test_file.exists():
                    project_root = str(search_dir)
                    logger.info(
                        f"✅ Found .adversary.json in parent directory: {project_root}"
                    )
                    found = True
                    break
                search_dir = search_dir.parent

            if not found:
                console.print(
                    "❌ No .adversary.json file found in directory tree", style="red"
                )
                sys.exit(1)

        adversary_file_path = str(Path(project_root) / ".adversary.json")
        fp_manager = FalsePositiveManager(adversary_file_path=adversary_file_path)
        success = fp_manager.unmark_false_positive(finding_uuid)

        if success:
            console.print(
                f"✅ False positive marking removed from {finding_uuid}", style="green"
            )
            console.print(
                f"📁 File: {Path(project_root) / '.adversary.json'}", style="dim"
            )
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

        # Smart search for .adversary.json file like the MCP server does
        project_root = working_directory or "."
        from pathlib import Path

        current_dir = Path(project_root)
        adversary_file = current_dir / ".adversary.json"

        # Convert to absolute path for better logging
        project_root_abs = str(Path(project_root).resolve())
        logger.info(f"Starting list-false-positives in directory: {project_root_abs}")

        # If .adversary.json doesn't exist in working_directory, search up the directory tree
        if not adversary_file.exists():
            logger.info(
                f".adversary.json not found at {adversary_file}, searching parent directories..."
            )
            search_dir = current_dir.resolve()
            home_dir = Path.home().resolve()

            found = False
            while search_dir != search_dir.parent and search_dir >= home_dir:
                test_file = search_dir / ".adversary.json"
                if test_file.exists():
                    project_root = str(search_dir)
                    logger.info(
                        f"✅ Found .adversary.json in parent directory: {project_root}"
                    )
                    found = True
                    break
                search_dir = search_dir.parent

            if not found:
                console.print(
                    "❌ No .adversary.json file found in directory tree", style="red"
                )
                sys.exit(1)

        adversary_file_path = str(Path(project_root) / ".adversary.json")
        fp_manager = FalsePositiveManager(adversary_file_path=adversary_file_path)
        false_positives = fp_manager.get_false_positives()

        if not false_positives:
            console.print("No false positives found.", style="yellow")
            console.print(
                f"📁 Checked: {Path(project_root) / '.adversary.json'}", style="dim"
            )
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
        console.print(
            f"📁 Source: {Path(project_root) / '.adversary.json'}", style="dim"
        )
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
@click.argument("repo_name")
@click.option(
    "--output",
    type=click.Path(),
    help="Output file path (default: <repo>/threat_model.json)",
)
@click.option(
    "--format",
    type=click.Choice(["json", "markdown"]),
    default="json",
    help="Output format",
)
@click.option(
    "--include-threats/--no-threats",
    default=True,
    help="Include STRIDE threat analysis",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Minimum severity threshold",
)
@click.option(
    "--search-depth", type=int, default=3, help="Max directory depth to search for repo"
)
def threat_model(
    repo_name: str,
    output: str | None,
    format: str,
    include_threats: bool,
    severity: str,
    search_depth: int,
):
    """Generate a threat model for a repository by name."""
    logger.info(f"=== Starting threat-model command for repo: {repo_name} ===")

    try:
        # Find repository by name
        repo_path = _find_repo_by_name_cli(repo_name, max_depth=search_depth)

        # Set default output file in the project directory
        if output is None:
            extension = "json" if format == "json" else "md"
            output_file = repo_path / f"threat_model.{extension}"
        else:
            output_file = Path(output)

        console.print(f"📊 Generating threat model for: {repo_path}", style="cyan")
        console.print(f"📁 Output file: {output_file}", style="dim")

        # Create threat model builder
        builder = ThreatModelBuilder()

        # Convert severity string to enum
        severity_threshold = ThreatSeverity(severity.lower())

        # Build threat model
        console.print("🔍 Analyzing source code...", style="yellow")
        threat_model = builder.build_threat_model(
            str(repo_path),
            include_threats=include_threats,
            severity_threshold=severity_threshold,
        )

        # Save threat model
        console.print(f"💾 Saving threat model as {format}...", style="yellow")
        builder.save_threat_model(threat_model, str(output_file), format=format)

        # Display summary
        console.print("\n✅ [bold green]Threat Model Generated![/bold green]")

        # Architecture summary
        components = threat_model.components
        console.print("\n📋 [bold]Architecture Summary:[/bold]")
        console.print(f"  • Trust Boundaries: {len(components.boundaries)}")
        console.print(f"  • External Entities: {len(components.external_entities)}")
        console.print(f"  • Processes: {len(components.processes)}")
        console.print(f"  • Data Stores: {len(components.data_stores)}")
        console.print(f"  • Data Flows: {len(components.data_flows)}")

        if include_threats and threat_model.threats:
            console.print("\n🎯 [bold]Threat Analysis:[/bold]")

            # Group threats by severity
            threats_by_severity = {}
            for threat in threat_model.threats:
                sev = threat.severity.value
                if sev not in threats_by_severity:
                    threats_by_severity[sev] = 0
                threats_by_severity[sev] += 1

            # Display counts
            for sev in ["critical", "high", "medium", "low"]:
                if sev in threats_by_severity:
                    count = threats_by_severity[sev]
                    color = {
                        "critical": "red",
                        "high": "orange3",
                        "medium": "yellow",
                        "low": "green",
                    }.get(sev, "white")
                    console.print(f"  • {sev.title()}: [{color}]{count}[/{color}]")

        console.print(f"\n📄 Threat model saved to: {output_file}")
        console.print("\n💡 Next steps:")
        console.print(
            f"  • Run 'adversary-mcp-cli diagram {repo_name}' to create a visual diagram"
        )
        console.print(f"  • Review the {format} file for detailed findings")

        logger.info("=== Threat-model command completed successfully ===")

    except Exception as e:
        logger.error(f"Threat-model command failed: {e}")
        logger.debug("Threat-model error details", exc_info=True)
        console.print(f"❌ Failed to generate threat model: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument("repo_name")
@click.option(
    "--output",
    type=click.Path(),
    help="Output file path (default: <repo>/threat_diagram.mmd)",
)
@click.option(
    "--type",
    "diagram_type",
    type=click.Choice(["flowchart", "graph", "sequence"]),
    default="flowchart",
    help="Diagram type",
)
@click.option(
    "--show-threats/--no-threats",
    default=True,
    help="Highlight components with threats",
)
@click.option(
    "--layout",
    type=click.Choice(["TD", "LR", "BT", "RL"]),
    default="TD",
    help="Layout direction",
)
@click.option("--open", "open_browser", is_flag=True, help="Open diagram in browser")
@click.option(
    "--search-depth", type=int, default=3, help="Max directory depth to search for repo"
)
def diagram(
    repo_name: str,
    output: str | None,
    diagram_type: str,
    show_threats: bool,
    layout: str,
    open_browser: bool,
    search_depth: int,
):
    """Generate a Mermaid diagram for a repository by name."""
    logger.info(f"=== Starting diagram command for repo: {repo_name} ===")

    try:
        import json
        import webbrowser

        # Find repository by name
        repo_path = _find_repo_by_name_cli(repo_name, max_depth=search_depth)

        # Set default output file in the project directory
        if output is None:
            output_file = repo_path / "threat_diagram.mmd"
        else:
            output_file = Path(output)

        console.print(f"📊 Generating diagram for: {repo_path}", style="cyan")
        console.print(f"📁 Output file: {output_file}", style="dim")

        # Check if source is an existing threat model JSON file
        threat_model_json = repo_path / "threat_model.json"

        if threat_model_json.exists():
            console.print(
                f"📄 Using existing threat model: {threat_model_json}", style="green"
            )
            with open(threat_model_json, encoding="utf-8") as f:
                threat_model_data = json.load(f)

            # Generate diagram from JSON data
            generator = MermaidDiagramGenerator()
            diagram_content = generator.generate_from_components_dict(
                threat_model_data, show_threats=show_threats, diagram_type=diagram_type
            )
        else:
            console.print("🔍 Analyzing source code...", style="yellow")

            # Build threat model from source
            builder = ThreatModelBuilder()
            threat_model = builder.build_threat_model(
                str(repo_path), include_threats=show_threats
            )

            # Generate diagram from threat model
            generator = MermaidDiagramGenerator()
            diagram_content = generator.generate_diagram(
                threat_model,
                diagram_type=diagram_type,
                show_threats=show_threats,
                layout_direction=layout,
            )

        # Save diagram
        console.print("💾 Saving Mermaid diagram...", style="yellow")
        generator.save_diagram(diagram_content, str(output_file))

        # If open flag is set, create HTML and open in browser
        if open_browser:
            console.print("🌐 Opening diagram in browser...", style="yellow")

            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Threat Model Diagram - {repo_name}</title>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({{
            startOnLoad: true,
            theme: 'default',
            themeVariables: {{
                darkMode: false
            }}
        }});
    </script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #333; }}
        .controls {{ margin: 20px 0; }}
        button {{
            background: #0066cc;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }}
        button:hover {{ background: #0052cc; }}
        .mermaid {{
            text-align: center;
            margin: 20px 0;
        }}
        .info {{
            background: #e3f2fd;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Threat Model Diagram: {repo_name}</h1>
        <div class="info">
            <strong>Type:</strong> {diagram_type} |
            <strong>Layout:</strong> {layout} |
            <strong>Threats:</strong> {'Highlighted' if show_threats else 'Hidden'}
        </div>
        <div class="controls">
            <button onclick="copyDiagram()">Copy Diagram Code</button>
            <button onclick="window.print()">Print</button>
        </div>
        <div class="mermaid">
{diagram_content}
        </div>
    </div>
    <script>
        function copyDiagram() {{
            const diagram = `{diagram_content}`;
            navigator.clipboard.writeText(diagram).then(() => {{
                alert('Diagram code copied to clipboard!');
            }});
        }}
    </script>
</body>
</html>"""

            # Save HTML file
            html_file = output_file.with_suffix(".html")
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            # Open in browser
            webbrowser.open(f"file://{html_file.absolute()}")
            console.print(f"✅ HTML saved to: {html_file}", style="green")

        # Display summary
        console.print("\n✅ [bold green]Diagram Generated![/bold green]")
        console.print(f"\n📄 Mermaid diagram saved to: {output_file}")

        if open_browser:
            console.print("🌐 Diagram opened in your default browser")
        else:
            console.print("\n💡 To view the diagram:")
            console.print("  • Run with --open flag to open in browser")
            console.print("  • Copy the .mmd file content to any Mermaid viewer")
            console.print("  • Use the diagram in your documentation")

        logger.info("=== Diagram command completed successfully ===")

    except Exception as e:
        logger.error(f"Diagram command failed: {e}")
        logger.debug("Diagram error details", exc_info=True)
        console.print(f"❌ Failed to generate diagram: {e}", style="red")
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
