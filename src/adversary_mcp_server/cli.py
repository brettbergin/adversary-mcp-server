"""Command-line interface for the Adversary MCP server."""

import datetime
import json
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import get_version
from .credential_manager import CredentialManager
from .diff_scanner import GitDiffScanner
from .exploit_generator import ExploitGenerator
from .scan_engine import ScanEngine
from .security_config import SecurityConfig
from .threat_engine import Language, Severity, ThreatEngine, get_user_rules_directory

# Conditional import for hot_reload to avoid dependency issues in tests
try:
    from .hot_reload import create_hot_reload_service

    HOT_RELOAD_AVAILABLE = True
except ImportError:
    HOT_RELOAD_AVAILABLE = False
    create_hot_reload_service = None

console = Console()


def get_cli_version():
    """Get version for CLI."""
    return get_version()


@click.group()
@click.version_option(version=get_cli_version(), prog_name="adversary-mcp-cli")
def cli():
    """Adversary MCP Server - Security-focused vulnerability scanner."""
    pass


@cli.command()
@click.option(
    "--severity-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Default severity threshold for scanning",
)
@click.option(
    "--enable-safety-mode/--disable-safety-mode",
    default=None,
    help="Enable safety mode for exploit generation",
)
@click.option(
    "--enable-llm/--disable-llm",
    default=None,
    help="Enable LLM analysis and exploit generation (uses client's LLM)",
)
@click.option(
    "--interactive/--no-interactive",
    default=True,
    help="Use interactive prompts when options are not provided",
)
def configure(
    severity_threshold: str | None,
    enable_safety_mode: bool | None,
    enable_llm: bool | None,
    interactive: bool,
):
    """Configure the Adversary MCP server settings."""
    try:
        credential_manager = CredentialManager()

        # Load existing config or create new one
        try:
            config = credential_manager.load_config()
            console.print("📋 Current configuration loaded", style="blue")
        except Exception:
            config = SecurityConfig()
            console.print("🆕 Creating new configuration", style="blue")

        # Determine if we should use interactive mode
        # Only prompt if interactive is enabled AND no CLI options were provided
        use_interactive = interactive and (
            severity_threshold is None
            and enable_safety_mode is None
            and enable_llm is None
        )

        # Show current config first (only in truly interactive mode)
        if use_interactive:
            console.print("\n📊 [bold]Current Configuration:[/bold]")
            current_table = Table()
            current_table.add_column("Setting", style="cyan")
            current_table.add_column("Current Value", style="magenta")

            current_table.add_row("Severity Threshold", config.severity_threshold)
            current_table.add_row(
                "Safety Mode",
                "✓ Enabled" if config.exploit_safety_mode else "✗ Disabled",
            )
            current_table.add_row(
                "LLM Analysis",
                "✓ Enabled" if config.enable_llm_analysis else "✗ Disabled",
            )
            current_table.add_row(
                "Exploit Generation",
                "✓ Enabled" if config.enable_exploit_generation else "✗ Disabled",
            )
            current_table.add_row(
                "Semgrep Scanning",
                "✓ Enabled" if config.enable_semgrep_scanning else "✗ Disabled",
            )
            console.print(current_table)
            console.print()

        # Interactive prompts for missing options (only if truly interactive)
        if use_interactive:
            severity_threshold = Prompt.ask(
                "Choose severity threshold",
                choices=["low", "medium", "high", "critical"],
                default=config.severity_threshold,
                show_choices=True,
            )

            enable_safety_mode = Confirm.ask(
                "Enable safety mode for exploit generation?",
                default=config.exploit_safety_mode,
            )

            enable_llm = Confirm.ask(
                "Enable LLM analysis and exploit generation?",
                default=config.enable_llm_analysis,
            )

        # Update configuration only if values were provided
        if severity_threshold is not None:
            config.severity_threshold = severity_threshold

        if enable_safety_mode is not None:
            config.exploit_safety_mode = enable_safety_mode

        # Override LLM settings if explicitly specified
        if enable_llm is not None:
            config.enable_llm_analysis = enable_llm
            config.enable_exploit_generation = enable_llm

        # Save configuration
        credential_manager.store_config(config)

        console.print("\n✅ Configuration saved successfully!", style="green")

        # Show current configuration
        table = Table(title="Current Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row("Severity Threshold", config.severity_threshold)
        table.add_row(
            "Safety Mode", "✓ Enabled" if config.exploit_safety_mode else "✗ Disabled"
        )
        table.add_row(
            "LLM Analysis",
            "✓ Enabled" if config.enable_llm_analysis else "✗ Disabled",
        )
        table.add_row(
            "Exploit Generation",
            "✓ Enabled" if config.enable_exploit_generation else "✗ Disabled",
        )

        console.print(table)

    except Exception as e:
        console.print(f"❌ Configuration failed: {e}", style="red")
        sys.exit(1)


@cli.command()
def status():
    """Show current server status and configuration."""
    try:
        credential_manager = CredentialManager()
        config = credential_manager.load_config()
        threat_engine = ThreatEngine()

        # Status panel
        status_text = "🟢 **Server Status:** Running\n"
        status_text += f"🔧 **Configuration:** {'✓ Configured' if credential_manager.has_config() else '✗ Not configured'}\n"
        status_text += "🤖 **LLM Integration:** Client-based (no API key required)\n"

        console.print(
            Panel(
                status_text, title="Adversary MCP Server Status", border_style="green"
            )
        )

        # Configuration table
        config_table = Table(title="Configuration")
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="magenta")

        config_table.add_row("Severity Threshold", config.severity_threshold)
        config_table.add_row(
            "Safety Mode", "✓ Enabled" if config.exploit_safety_mode else "✗ Disabled"
        )
        config_table.add_row(
            "LLM Analysis",
            "✓ Enabled" if config.enable_llm_analysis else "✗ Disabled",
        )
        config_table.add_row(
            "Exploit Generation",
            "✓ Enabled" if config.enable_exploit_generation else "✗ Disabled",
        )
        config_table.add_row(
            "Semgrep Scanning",
            "✓ Enabled" if config.enable_semgrep_scanning else "✗ Disabled",
        )
        config_table.add_row("Max File Size", f"{config.max_file_size_mb} MB")
        config_table.add_row("Scan Depth", str(config.max_scan_depth))
        config_table.add_row("Timeout", f"{config.timeout_seconds} seconds")

        console.print(config_table)

        # Rules statistics
        rules = threat_engine.list_rules()
        rules_table = Table(title="Threat Detection Rules")
        rules_table.add_column("Language", style="cyan")
        rules_table.add_column("Count", style="magenta")

        lang_counts = {}
        for rule in rules:
            for lang in rule["languages"]:
                lang_counts[lang] = lang_counts.get(lang, 0) + 1

        for lang, count in lang_counts.items():
            rules_table.add_row(lang.capitalize(), str(count))

        rules_table.add_row("Total", str(len(rules)), style="bold")

        console.print(rules_table)

    except Exception as e:
        console.print(f"❌ Failed to get status: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument("target", type=click.Path(exists=True), required=False)
@click.option(
    "--language",
    type=click.Choice(["python", "javascript", "typescript"]),
    help="Programming language (auto-detected if not specified)",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Minimum severity threshold (uses global config if not specified)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output file for results (JSON format)",
)
@click.option(
    "--recursive/--no-recursive",
    default=True,
    help="Scan directories recursively",
)
@click.option(
    "--include-exploits/--no-exploits",
    default=True,
    help="Include exploit examples in results",
)
@click.option(
    "--use-llm/--no-llm",
    default=True,
    help="Use LLM for enhanced analysis",
)
@click.option(
    "--use-semgrep/--no-semgrep",
    default=True,
    help="Use Semgrep for static analysis",
)
@click.option(
    "--use-rules/--no-rules",
    default=True,
    help="Use rules-based scanner for threat detection",
)
@click.option(
    "--diff/--no-diff",
    default=False,
    help="Enable git diff-aware scanning (scans only changed files)",
)
@click.option(
    "--source-branch",
    default="main",
    help="Source branch for git diff comparison (default: main)",
)
@click.option(
    "--target-branch",
    default="HEAD",
    help="Target branch for git diff comparison (default: HEAD)",
)
def scan(
    target: str | None,
    language: str | None,
    severity: str | None,
    output: str | None,
    recursive: bool,
    include_exploits: bool,
    use_llm: bool,
    use_semgrep: bool,
    use_rules: bool,
    diff: bool,
    source_branch: str,
    target_branch: str,
):
    """Scan a file or directory for security vulnerabilities.

    Can perform traditional file/directory scanning or git diff-aware scanning.
    When --diff is enabled, only changes between branches are scanned.
    """
    try:
        # Initialize scanner components
        threat_engine = ThreatEngine()

        # Load configuration
        try:
            credential_manager = CredentialManager()
            config = credential_manager.load_config()
        except Exception:
            config = SecurityConfig()
            console.print("⚠️  Using default configuration", style="yellow")

        # Use global severity threshold if not specified
        if severity is None:
            severity = config.severity_threshold
            console.print(
                f"🔧 Using global severity threshold: {severity}", style="blue"
            )

        # Handle git diff-aware scanning
        if diff:
            console.print(
                f"🔍 Git diff-aware scanning between {source_branch} and {target_branch}"
            )

            # Use current directory if no target specified for diff scanning
            if not target:
                target = "."

            # Initialize git diff scanner
            scan_engine = ScanEngine(threat_engine, credential_manager)
            git_diff_scanner = GitDiffScanner(
                scan_engine=scan_engine, working_dir=Path(target)
            )

            # Perform diff scan
            severity_enum = Severity(severity) if severity else None

            scan_results = git_diff_scanner.scan_diff_sync(
                source_branch=source_branch,
                target_branch=target_branch,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_rules=use_rules,
                severity_threshold=severity_enum,
            )

            # Get diff summary for display
            diff_summary = git_diff_scanner.get_diff_summary(
                source_branch, target_branch
            )

            # Collect all threats from scan results
            all_threats = []
            for file_path, file_scan_results in scan_results.items():
                for scan_result in file_scan_results:
                    all_threats.extend(scan_result.all_threats)

            # Generate exploits if requested
            if include_exploits:
                for threat in all_threats[:10]:  # Limit to first 10 threats
                    try:
                        exploit_generator = ExploitGenerator()
                        exploits = exploit_generator.generate_exploits(
                            threat, "", False  # Don't use LLM directly
                        )
                        threat.exploit_examples = exploits
                    except Exception as e:
                        console.print(
                            f"⚠️  Failed to generate exploits for {threat.rule_id}: {e}",
                            style="yellow",
                        )
                        continue

            # Create results structure for display
            results = {
                "threats": all_threats,
                "stats": {
                    "files_changed": diff_summary.get("files_changed", 0),
                    "lines_added": diff_summary.get("lines_added", 0),
                    "lines_removed": diff_summary.get("lines_removed", 0),
                    "threat_counts": {},
                },
            }

            # Calculate threat counts by severity
            for threat in all_threats:
                severity_str = threat.severity.value
                results["stats"]["threat_counts"][severity_str] = (
                    results["stats"]["threat_counts"].get(severity_str, 0) + 1
                )

            # Display git diff results
            _display_git_diff_results(results)

            # Extract threats for further processing
            threats = results.get("threats", [])

        else:
            # Traditional file/directory scanning
            if not target:
                console.print(
                    "❌ Target path is required for non-diff scanning", style="red"
                )
                sys.exit(1)

            target_path = Path(target)

            if target_path.is_file():
                # Single file scan
                console.print(f"🔍 Scanning file: {target}")

                # Auto-detect language if not specified
                if not language:
                    if target_path.suffix == ".py":
                        language = "python"
                    elif target_path.suffix in [".js", ".jsx"]:
                        language = "javascript"
                    elif target_path.suffix in [".ts", ".tsx"]:
                        language = "typescript"
                    else:
                        console.print(
                            f"❌ Cannot auto-detect language for {target}", style="red"
                        )
                        sys.exit(1)

                # Initialize scan engine
                scan_engine = ScanEngine(threat_engine, credential_manager)

                # Scan file using enhanced scanner
                severity_enum = Severity(severity) if severity else None
                scan_result = scan_engine.scan_file_sync(
                    file_path=target_path,
                    language=Language(language),
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    use_rules=use_rules,
                    severity_threshold=severity_enum,
                )

                threats = scan_result.all_threats

            elif target_path.is_dir():
                # Directory scan using enhanced scanner
                console.print(f"🔍 Scanning directory: {target}")

                # Initialize scan engine
                scan_engine = ScanEngine(threat_engine, credential_manager)

                # Scan directory using enhanced scanner
                severity_enum = Severity(severity) if severity else None
                scan_results = scan_engine.scan_directory_sync(
                    directory_path=target_path,
                    recursive=recursive,
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    use_rules=use_rules,
                    severity_threshold=severity_enum,
                    max_files=50,  # Limit for performance
                )

                # Collect all threats from scan results
                threats = []
                file_count = len(scan_results)
                for scan_result in scan_results:
                    threats.extend(scan_result.all_threats)

                console.print(f"📊 Scanned {file_count} files")
            else:
                console.print(f"❌ Invalid target: {target}", style="red")
                sys.exit(1)

            # Display results for traditional scanning
            _display_scan_results(threats, target)

        # Save to file if requested
        if output:
            _save_results_to_file(threats, output)

    except Exception as e:
        console.print(f"❌ Scan failed: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.option(
    "--category",
    help="Filter by category (injection, xss, etc.)",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Filter by minimum severity",
)
@click.option(
    "--language",
    type=click.Choice(["python", "javascript", "typescript"]),
    help="Filter by language",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output file for rules (JSON format)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show full absolute paths for source files",
)
def list_rules(
    category: str | None,
    severity: str | None,
    language: str | None,
    output: str | None,
    verbose: bool,
):
    """List available threat detection rules."""
    try:
        threat_engine = ThreatEngine()
        rules = threat_engine.list_rules()

        # Apply filters
        if category:
            rules = [r for r in rules if r["category"] == category]

        if severity:
            severity_order = ["low", "medium", "high", "critical"]
            min_index = severity_order.index(severity)
            rules = [
                r for r in rules if severity_order.index(r["severity"]) >= min_index
            ]

        if language:
            rules = [r for r in rules if language in r["languages"]]

        if not rules:
            console.print("No rules found matching the criteria.", style="yellow")
            return

        # Create rules table
        table = Table(title=f"Threat Detection Rules ({len(rules)} found)")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Category", style="green")
        table.add_column("Severity", style="red")
        table.add_column("Languages", style="blue")
        table.add_column("Source File", style="yellow")

        for rule in rules:
            # Color severity
            severity_color = {
                "low": "green",
                "medium": "yellow",
                "high": "red",
                "critical": "bold red",
            }.get(rule["severity"], "white")

            # Format source file path for display
            source_file = rule.get("source_file", "Unknown")
            if verbose or source_file == "Unknown" or source_file == "<built-in>":
                # Show full path in verbose mode, or special names as-is
                source_file_display = source_file
            else:
                # Show just the filename for readability in normal mode
                source_file_display = Path(source_file).name

            table.add_row(
                rule["id"],
                rule["name"],
                rule["category"],
                f"[{severity_color}]{rule['severity']}[/{severity_color}]",
                ", ".join(rule["languages"]),
                source_file_display,
            )

        console.print(table)

        # Save to file if requested
        if output:
            output_path = Path(output)
            with open(output_path, "w") as f:
                json.dump(rules, f, indent=2)
            console.print(f"✅ Rules saved to {output_path}", style="green")

    except Exception as e:
        console.print(f"❌ Failed to list rules: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument("rule_id")
def rule_details(rule_id: str):
    """Show detailed information about a specific rule."""
    try:
        threat_engine = ThreatEngine()
        rule = threat_engine.get_rule_by_id(rule_id)

        if not rule:
            console.print(f"❌ Rule not found: {rule_id}", style="red")
            sys.exit(1)

        # Rule details panel
        details_text = f"**ID:** {rule.id}\n"
        details_text += f"**Name:** {rule.name}\n"
        details_text += f"**Description:** {rule.description}\n\n"
        details_text += f"**Category:** {rule.category.value}\n"
        details_text += f"**Severity:** {rule.severity.value}\n"
        details_text += (
            f"**Languages:** {', '.join([lang.value for lang in rule.languages])}\n\n"
        )

        if rule.cwe_id:
            details_text += f"**CWE ID:** {rule.cwe_id}\n"
        if rule.owasp_category:
            details_text += f"**OWASP Category:** {rule.owasp_category}\n"
        if rule.tags:
            details_text += f"**Tags:** {', '.join(rule.tags)}\n"

        console.print(
            Panel(details_text, title=f"Rule Details: {rule.name}", border_style="blue")
        )

        # Conditions table
        if rule.conditions:
            conditions_table = Table(title="Detection Conditions")
            conditions_table.add_column("Type", style="cyan")
            conditions_table.add_column("Value", style="magenta")
            conditions_table.add_column("Case Sensitive", style="green")

            for condition in rule.conditions:
                value_str = str(condition.value)
                if isinstance(condition.value, list):
                    value_str = ", ".join(condition.value)
                elif len(value_str) > 50:
                    value_str = value_str[:47] + "..."

                conditions_table.add_row(
                    condition.type, value_str, "✓" if condition.case_sensitive else "✗"
                )

            console.print(conditions_table)

        # Exploit templates
        if rule.exploit_templates:
            console.print("\n[bold]Exploit Templates:[/bold]")
            for i, template in enumerate(rule.exploit_templates, 1):
                template_text = f"**Type:** {template.type}\n"
                template_text += f"**Description:** {template.description}\n"
                template_text += f"**Template:**\n{template.template}"

                console.print(
                    Panel(template_text, title=f"Template {i}", border_style="yellow")
                )

        # Remediation
        if rule.remediation:
            console.print(
                Panel(rule.remediation, title="Remediation", border_style="green")
            )

        # References
        if rule.references:
            console.print("\n[bold]References:[/bold]")
            for ref in rule.references:
                console.print(f"• {ref}")

    except Exception as e:
        console.print(f"❌ Failed to get rule details: {e}", style="red")
        sys.exit(1)


@cli.group()
def rules():
    """Manage threat detection rules."""
    pass


@rules.command()
@click.argument("output_file", type=click.Path())
@click.option(
    "--format",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    help="Output format (yaml or json)",
)
def export(output_file: str, format: str):
    """Export all rules to a file."""
    try:
        threat_engine = ThreatEngine()
        output_path = Path(output_file)

        if format == "yaml":
            # YAML export
            rules_data = {
                "rules": [
                    rule.model_dump(mode="json")
                    for rule in threat_engine.rules.values()
                ]
            }
            with open(output_path, "w") as f:
                yaml.dump(rules_data, f, default_flow_style=False, sort_keys=False)
        else:
            # JSON export
            rules_data = {
                "rules": [
                    rule.model_dump(mode="json")
                    for rule in threat_engine.rules.values()
                ]
            }
            with open(output_path, "w") as f:
                json.dump(rules_data, f, indent=2)

        console.print(f"✅ Rules exported to {output_path}", style="green")

    except Exception as e:
        console.print(f"❌ Export failed: {e}", style="red")
        sys.exit(1)


@rules.command()
@click.argument("import_file", type=click.Path(exists=True))
@click.option(
    "--target-dir",
    type=click.Path(),
    help="Directory to copy the file to (default: ~/.local/share/adversary-mcp-server/rules/custom/)",
)
@click.option(
    "--validate/--no-validate",
    default=True,
    help="Validate rules before importing",
)
def import_rules(import_file: str, target_dir: str | None, validate: bool):
    """Import rules from an external file."""
    try:
        threat_engine = ThreatEngine()
        import_path = Path(import_file)

        if validate:
            console.print("🔍 Validating rules before import...")
            # Test load in temporary engine
            temp_engine = ThreatEngine()
            temp_engine.load_rules_from_file(import_path)

            # Validate all rules
            validation_errors = temp_engine.validate_all_rules()
            if validation_errors:
                console.print("❌ Validation failed:", style="red")
                for rule_id, errors in validation_errors.items():
                    console.print(f"  {rule_id}: {', '.join(errors)}", style="red")
                sys.exit(1)

            console.print("✅ Validation passed", style="green")

        # Use default target directory if not provided
        if target_dir is None:
            target_path = get_user_rules_directory() / "custom"
        else:
            target_path = Path(target_dir)

        # Import rules
        threat_engine.import_rules_from_file(import_path, target_path)

        console.print(f"✅ Rules imported successfully to {target_path}", style="green")

    except Exception as e:
        console.print(f"❌ Import failed: {e}", style="red")
        sys.exit(1)


@rules.command()
def validate():
    """Validate all loaded rules."""
    try:
        threat_engine = ThreatEngine()
        validation_errors = threat_engine.validate_all_rules()

        if not validation_errors:
            console.print("✅ All rules are valid", style="green")
            return

        console.print(
            f"❌ Found {len(validation_errors)} rules with errors:", style="red"
        )

        for rule_id, errors in validation_errors.items():
            console.print(f"\n[bold red]{rule_id}:[/bold red]")
            for error in errors:
                console.print(f"  • {error}")

        sys.exit(1)

    except Exception as e:
        console.print(f"❌ Validation failed: {e}", style="red")
        sys.exit(1)


@rules.command()
def reload():
    """Reload all rules from their source files."""
    try:
        threat_engine = ThreatEngine()
        threat_engine.reload_rules()

        stats = threat_engine.get_rule_statistics()
        console.print(
            f"✅ Reloaded {stats['total_rules']} rules from {stats['loaded_files']} files",
            style="green",
        )

    except Exception as e:
        console.print(f"❌ Reload failed: {e}", style="red")
        sys.exit(1)


@rules.command()
def stats():
    """Show rule statistics."""
    try:
        threat_engine = ThreatEngine()
        stats = threat_engine.get_rule_statistics()

        # Main statistics
        console.print("📊 [bold]Rule Statistics[/bold]")
        console.print(f"Total Rules: {stats['total_rules']}")
        console.print(f"Loaded Files: {stats['loaded_files']}")

        # Categories table
        if stats["categories"]:
            cat_table = Table(title="Rules by Category")
            cat_table.add_column("Category", style="cyan")
            cat_table.add_column("Count", style="magenta")

            for category, count in stats["categories"].items():
                cat_table.add_row(category, str(count))

            console.print(cat_table)

        # Severity table
        if stats["severities"]:
            sev_table = Table(title="Rules by Severity")
            sev_table.add_column("Severity", style="cyan")
            sev_table.add_column("Count", style="magenta")

            for severity, count in stats["severities"].items():
                sev_table.add_row(severity, str(count))

            console.print(sev_table)

        # Language table
        if stats["languages"]:
            lang_table = Table(title="Rules by Language")
            lang_table.add_column("Language", style="cyan")
            lang_table.add_column("Count", style="magenta")

            for language, count in stats["languages"].items():
                lang_table.add_row(language, str(count))

            console.print(lang_table)

        # Rule files
        if stats["rule_files"]:
            console.print("\n[bold]Loaded Rule Files:[/bold]")
            for file_path in stats["rule_files"]:
                console.print(f"• {file_path}")

    except Exception as e:
        console.print(f"❌ Failed to get statistics: {e}", style="red")
        sys.exit(1)


@cli.command()
def demo():
    """Run a demonstration of the vulnerability scanner."""
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
    # Vulnerable: user input passed to shell command
    os.system(f"cp {filename} backup/")

# Insecure deserialization
def load_user_data(data):
    # Vulnerable: pickle deserialization of untrusted data
    return pickle.loads(data)
"""

    js_code = """
// DOM-based XSS vulnerability
function displayMessage(message) {
    // Vulnerable: direct innerHTML assignment
    document.getElementById('output').innerHTML = message;
}

// Code injection via eval
function calculate(expression) {
    // Vulnerable: eval with user input
    return eval(expression);
}
"""

    console.print("[bold cyan]Sample Vulnerable Python Code:[/bold cyan]")
    console.print(python_code)

    console.print("\n[bold cyan]Sample Vulnerable JavaScript Code:[/bold cyan]")
    console.print(js_code)

    # Initialize scanner
    threat_engine = ThreatEngine()
    credential_manager = CredentialManager()
    scan_engine = ScanEngine(threat_engine, credential_manager)

    # Scan Python code
    console.print("\n🔍 [bold]Scanning Python Code...[/bold]")
    python_result = scan_engine.scan_code_sync(python_code, "demo.py", Language.PYTHON)
    python_threats = python_result.all_threats

    # Scan JavaScript code
    console.print("\n🔍 [bold]Scanning JavaScript Code...[/bold]")
    js_result = scan_engine.scan_code_sync(js_code, "demo.js", Language.JAVASCRIPT)
    js_threats = js_result.all_threats

    # Display results
    all_threats = python_threats + js_threats
    _display_scan_results(all_threats, "demo")

    console.print("\n✅ [bold green]Demo completed![/bold green]")
    console.print(
        "Use 'adversary-mcp configure' to set up the server for production use."
    )


@cli.command()
@click.argument("finding_uuid")
@click.option(
    "--reason",
    type=str,
    help="Reason for marking as false positive",
)
@click.option(
    "--confirm/--no-confirm",
    default=True,
    help="Require confirmation before marking as false positive",
)
def mark_false_positive(finding_uuid: str, reason: str | None, confirm: bool):
    """Mark a finding as a false positive by UUID."""
    try:
        from .false_positive_manager import FalsePositiveManager

        fp_manager = FalsePositiveManager()

        if confirm and not Confirm.ask(
            f"Mark finding {finding_uuid} as false positive?"
        ):
            console.print("Operation cancelled", style="yellow")
            return

        fp_manager.mark_false_positive(
            finding_uuid, reason or "User marked as false positive"
        )
        console.print(
            f"✅ Finding {finding_uuid} marked as false positive", style="green"
        )

    except Exception as e:
        console.print(f"❌ Failed to mark as false positive: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument("finding_uuid")
def unmark_false_positive(finding_uuid: str):
    """Remove false positive marking from a finding by UUID."""
    try:
        from .false_positive_manager import FalsePositiveManager

        fp_manager = FalsePositiveManager()
        fp_manager.unmark_false_positive(finding_uuid)
        console.print(
            f"✅ Finding {finding_uuid} unmarked as false positive", style="green"
        )

    except Exception as e:
        console.print(f"❌ Failed to unmark false positive: {e}", style="red")
        sys.exit(1)


@cli.command()
def list_false_positives():
    """List all findings marked as false positives."""
    try:
        from .false_positive_manager import FalsePositiveManager

        fp_manager = FalsePositiveManager()
        false_positives = fp_manager.get_false_positives()

        if not false_positives:
            console.print("No false positives found", style="green")
            return

        table = Table(title=f"False Positives ({len(false_positives)} found)")
        table.add_column("UUID", style="cyan")
        table.add_column("Reason", style="magenta")
        table.add_column("Marked Date", style="yellow")

        for fp in false_positives:
            table.add_row(
                fp["uuid"],
                fp.get("reason", "No reason provided"),
                fp.get("marked_date", "Unknown"),
            )

        console.print(table)

    except Exception as e:
        console.print(f"❌ Failed to list false positives: {e}", style="red")
        sys.exit(1)


@cli.command()
def reset():
    """Reset all configuration and credentials."""
    if Confirm.ask("Are you sure you want to reset all configuration?"):
        try:
            credential_manager = CredentialManager()
            credential_manager.delete_config()
            console.print("✅ Configuration reset successfully!", style="green")
        except Exception as e:
            console.print(f"❌ Reset failed: {e}", style="red")
            sys.exit(1)


def _display_scan_results(threats, target):
    """Display scan results in a formatted table."""
    if not threats:
        console.print("✅ No security threats detected!", style="green")
        return

    # Summary
    console.print(
        f"\n🚨 [bold red]Found {len(threats)} security threats in {target}[/bold red]"
    )

    # Count by severity
    severity_counts = {}
    for threat in threats:
        severity = threat.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    summary_text = "**Severity Breakdown:**\n"
    for severity in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            color = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
            }[severity]
            summary_text += f"• {severity.capitalize()}: {count}\n"

    console.print(Panel(summary_text, title="Scan Summary", border_style="red"))

    # Detailed results table
    table = Table(title="Detected Threats")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta")
    table.add_column("Rule", style="green")
    table.add_column("Severity", style="red")
    table.add_column("Scanner", style="yellow")
    table.add_column("CWE", style="dim cyan")
    table.add_column("Description", style="blue")

    for threat in threats:
        # Color severity
        severity_color = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }.get(threat.severity.value, "white")

        # Format scanner source with appropriate styling
        scanner_text = threat.source.upper() if hasattr(threat, "source") else "RULES"
        scanner_color = {"RULES": "green", "SEMGREP": "blue", "LLM": "magenta"}.get(
            scanner_text, "white"
        )

        # Format CWE ID
        cwe_text = threat.cwe_id if hasattr(threat, "cwe_id") and threat.cwe_id else "-"

        table.add_row(
            threat.file_path,
            str(threat.line_number),
            threat.rule_name,
            f"[{severity_color}]{threat.severity.value}[/{severity_color}]",
            f"[{scanner_color}]{scanner_text}[/{scanner_color}]",
            cwe_text,
            (
                threat.description[:40] + "..."
                if len(threat.description) > 40
                else threat.description
            ),
        )

    console.print(table)


def _save_results_to_file(threats, output_file):
    """Save scan results to a JSON file."""
    try:
        output_path = Path(output_file)

        # Convert threats to serializable format
        results = []
        for threat in threats:
            results.append(
                {
                    "uuid": threat.uuid,
                    "rule_id": threat.rule_id,
                    "rule_name": threat.rule_name,
                    "description": threat.description,
                    "category": threat.category.value,
                    "severity": threat.severity.value,
                    "file_path": threat.file_path,
                    "line_number": threat.line_number,
                    "column_number": threat.column_number,
                    "code_snippet": threat.code_snippet,
                    "function_name": threat.function_name,
                    "exploit_examples": threat.exploit_examples,
                    "remediation": threat.remediation,
                    "references": threat.references,
                    "cwe_id": threat.cwe_id,
                    "owasp_category": threat.owasp_category,
                    "confidence": threat.confidence,
                    "source": getattr(threat, "source", "rules"),
                    "is_false_positive": threat.is_false_positive,
                }
            )

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        console.print(f"✅ Results saved to {output_path}", style="green")

    except Exception as e:
        console.print(f"❌ Failed to save results: {e}", style="red")


def _display_git_diff_results(results):
    """Display git diff scan results in a formatted table."""
    threats = results.get("threats", [])
    stats = results.get("stats", {})

    # Display diff summary
    console.print("\n📊 [bold]Git Diff Summary[/bold]")

    summary_table = Table(title="Diff Statistics")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="magenta")

    summary_table.add_row("Files Changed", str(stats.get("files_changed", 0)))
    summary_table.add_row("Lines Added", str(stats.get("lines_added", 0)))
    summary_table.add_row("Lines Removed", str(stats.get("lines_removed", 0)))
    summary_table.add_row("Threats Found", str(len(threats)))

    # Show threat breakdown by severity
    threat_counts = stats.get("threat_counts", {})
    for severity, count in threat_counts.items():
        if count > 0:
            summary_table.add_row(f"  {severity.capitalize()}", str(count))

    console.print(summary_table)

    # Display threats if any found
    if threats:
        console.print(
            f"\n🚨 [bold red]Found {len(threats)} security threats in changed files[/bold red]"
        )
        _display_scan_results(threats, "git diff")
    else:
        console.print(
            "\n✅ No security threats detected in changed files!", style="green"
        )


@cli.group()
def watch():
    """Manage hot-reload service for rule files."""
    pass


@watch.command()
@click.option(
    "--directory",
    "-d",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    multiple=True,
    help="Additional directories to watch (defaults to user rules directory)",
)
@click.option(
    "--debounce",
    type=float,
    default=1.0,
    help="Debounce time in seconds between reloads (default: 1.0)",
)
def start(directory: tuple, debounce: float):
    """Start the hot-reload service."""
    if not HOT_RELOAD_AVAILABLE:
        console.print(
            "❌ Hot-reload requires the 'watchdog' package. Install with: pip install watchdog",
            style="red",
        )
        sys.exit(1)

    try:
        # Create threat engine
        threat_engine = ThreatEngine()

        # Create hot-reload service
        if directory:
            custom_dirs = [Path(d) for d in directory]
        else:
            # Use user rules directory by default
            custom_dirs = [get_user_rules_directory()]

        service = create_hot_reload_service(threat_engine, custom_dirs)
        service.set_debounce_time(debounce)

        # Show initial status
        console.print("🔄 [bold]Starting Hot-Reload Service[/bold]")
        console.print("📁 Watching directories:")
        for watch_dir in service.watch_directories:
            console.print(f"  • {watch_dir}")

        stats = threat_engine.get_rule_statistics()
        console.print(
            f"📊 Loaded {stats['total_rules']} rules from {stats['loaded_files']} files"
        )

        # Start the service daemon
        service.run_daemon()

    except KeyboardInterrupt:
        console.print("\n👋 Hot-reload service stopped", style="yellow")
    except Exception as e:
        console.print(f"❌ Failed to start hot-reload service: {e}", style="red")
        sys.exit(1)


@watch.command()
@click.option(
    "--directory",
    "-d",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    multiple=True,
    help="Additional directories to watch (defaults to user rules directory)",
)
def status(directory: tuple):
    """Show hot-reload service status."""
    if not HOT_RELOAD_AVAILABLE:
        console.print(
            "❌ Hot-reload requires the 'watchdog' package. Install with: pip install watchdog",
            style="red",
        )
        sys.exit(1)

    try:
        # Create threat engine and service
        threat_engine = ThreatEngine()
        custom_dirs = [Path(d) for d in directory] if directory else None
        service = create_hot_reload_service(threat_engine, custom_dirs)

        # Get status
        status_info = service.get_status()

        # Display status
        status_text = f"**Service Status:** {'🟢 Running' if status_info['is_running'] else '🔴 Stopped'}\n"
        status_text += (
            f"**Watched Directories:** {len(status_info['watch_directories'])}\n"
        )
        status_text += f"**Pending Reloads:** {status_info['pending_reloads']}\n"
        status_text += f"**Total Reloads:** {status_info['reload_count']}\n"
        status_text += f"**Debounce Time:** {status_info['debounce_seconds']} seconds\n"

        if status_info["last_reload_time"]:
            last_reload = datetime.datetime.fromtimestamp(
                status_info["last_reload_time"]
            )
            status_text += (
                f"**Last Reload:** {last_reload.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

        console.print(
            Panel(status_text, title="Hot-Reload Service Status", border_style="blue")
        )

        # Show watched directories
        if status_info["watch_directories"]:
            console.print("\n[bold]Watched Directories:[/bold]")
            for dir_path in status_info["watch_directories"]:
                console.print(f"• {dir_path}")

        # Show last reload files
        if status_info["last_reload_files"]:
            console.print("\n[bold]Last Reload Files:[/bold]")
            for file_path in status_info["last_reload_files"]:
                console.print(f"• {file_path}")

    except ImportError:
        console.print(
            "❌ Hot-reload requires the 'watchdog' package. Install with: pip install watchdog",
            style="red",
        )
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Failed to get hot-reload status: {e}", style="red")
        sys.exit(1)


@watch.command()
@click.option(
    "--directory",
    "-d",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    multiple=True,
    help="Additional directories to watch (defaults to user rules directory)",
)
def test(directory: tuple):
    """Test hot-reload functionality by forcing a reload."""
    if not HOT_RELOAD_AVAILABLE:
        console.print(
            "❌ Hot-reload requires the 'watchdog' package. Install with: pip install watchdog",
            style="red",
        )
        sys.exit(1)

    try:
        # Create threat engine and service
        threat_engine = ThreatEngine()

        if directory:
            custom_dirs = [Path(d) for d in directory]
        else:
            # Use user rules directory by default
            custom_dirs = [get_user_rules_directory()]

        service = create_hot_reload_service(threat_engine, custom_dirs)

        # Show initial state
        console.print("🧪 [bold]Testing Hot-Reload Functionality[/bold]")
        console.print("📁 Watching directories:")
        for watch_dir in service.watch_directories:
            console.print(f"  • {watch_dir}")

        stats = threat_engine.get_rule_statistics()
        console.print(
            f"📊 Current: {stats['total_rules']} rules from {stats['loaded_files']} files"
        )

        # Force reload
        service.force_reload()

        # Show final state
        stats = threat_engine.get_rule_statistics()
        console.print(
            f"📊 After reload: {stats['total_rules']} rules from {stats['loaded_files']} files"
        )

        console.print("✅ Hot-reload test completed successfully!", style="green")

    except ImportError:
        console.print(
            "❌ Hot-reload requires the 'watchdog' package. Install with: pip install watchdog",
            style="red",
        )
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Hot-reload test failed: {e}", style="red")
        sys.exit(1)


def show_user_rules_directory():
    """Show the user's rules directory location."""
    user_rules_dir = get_user_rules_directory()

    console.print(f"📁 [bold]User Rules Directory:[/bold] {user_rules_dir}")
    console.print("📂 Structure:")
    console.print("  • built-in/     - Core security rules")
    console.print("  • custom/       - User-defined rules")
    console.print("  • organization/ - Company/team rules")
    console.print("  • templates/    - Rule templates")

    if user_rules_dir.exists():
        console.print("\n📊 Directory contents:")
        for subdir in ["built-in", "custom", "organization", "templates"]:
            subdir_path = user_rules_dir / subdir
            if subdir_path.exists():
                rule_files = list(subdir_path.glob("*.yaml")) + list(
                    subdir_path.glob("*.yml")
                )
                console.print(f"  • {subdir}/ ({len(rule_files)} files)")
                for rule_file in rule_files:
                    console.print(f"    - {rule_file.name}")
    else:
        console.print(
            "\n⚠️  Directory does not exist yet. It will be created on first use."
        )


@cli.command()
def show_rules_dir():
    """Show the location of the user's rules directory."""
    show_user_rules_directory()


def main():
    """Main entry point for the CLI."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n👋 Goodbye!", style="yellow")
        sys.exit(0)
    except Exception as e:
        console.print(f"❌ Unexpected error: {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    main()
