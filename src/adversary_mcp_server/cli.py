"""Command-line interface for the Adversary MCP server."""

import getpass
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .ast_scanner import ASTScanner
from .credential_manager import CredentialManager, SecurityConfig
from .exploit_generator import ExploitGenerator
from .threat_engine import Language, Severity, ThreatEngine

console = Console()


@click.group()
@click.version_option()
def cli():
    """Adversary MCP Server - Security-focused vulnerability scanner."""
    pass


@cli.command()
@click.option(
    "--openai-api-key",
    help="OpenAI API key for LLM-based analysis",
    prompt="OpenAI API Key (optional, press Enter to skip)",
    default="",
    hide_input=True,
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Default severity threshold for scanning",
)
@click.option(
    "--enable-safety-mode/--disable-safety-mode",
    default=True,
    help="Enable safety mode for exploit generation",
)
@click.option(
    "--enable-llm/--disable-llm",
    default=True,
    help="Enable LLM-based analysis and exploit generation",
)
def configure(
    openai_api_key: str,
    severity_threshold: str,
    enable_safety_mode: bool,
    enable_llm: bool,
):
    """Configure the Adversary MCP server settings."""
    try:
        credential_manager = CredentialManager()

        # Load existing config or create new one
        try:
            config = credential_manager.load_config()
        except Exception:
            config = SecurityConfig()

        # Update configuration
        if openai_api_key:
            config.openai_api_key = openai_api_key

        config.severity_threshold = severity_threshold
        config.exploit_safety_mode = enable_safety_mode
        config.enable_exploit_generation = enable_llm

        # Save configuration
        credential_manager.store_config(config)

        console.print("✅ Configuration saved successfully!", style="green")

        # Show current configuration
        table = Table(title="Current Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row(
            "OpenAI API Key",
            "✓ Configured" if config.openai_api_key else "✗ Not configured",
        )
        table.add_row("Severity Threshold", config.severity_threshold)
        table.add_row(
            "Safety Mode", "✓ Enabled" if config.exploit_safety_mode else "✗ Disabled"
        )
        table.add_row(
            "LLM Generation",
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
        status_text += f"🤖 **LLM Integration:** {'✓ Available' if config.openai_api_key else '✗ Not available'}\n"

        console.print(
            Panel(
                status_text, title="Adversary MCP Server Status", border_style="green"
            )
        )

        # Configuration table
        config_table = Table(title="Configuration")
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="magenta")

        config_table.add_row(
            "OpenAI API Key",
            "✓ Configured" if config.openai_api_key else "✗ Not configured",
        )
        config_table.add_row("Severity Threshold", config.severity_threshold)
        config_table.add_row(
            "Safety Mode", "✓ Enabled" if config.exploit_safety_mode else "✗ Disabled"
        )
        config_table.add_row(
            "LLM Generation",
            "✓ Enabled" if config.enable_exploit_generation else "✗ Disabled",
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
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--language",
    type=click.Choice(["python", "javascript", "typescript"]),
    help="Programming language (auto-detected if not specified)",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Minimum severity threshold",
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
def scan(
    target: str,
    language: Optional[str],
    severity: str,
    output: Optional[str],
    recursive: bool,
    include_exploits: bool,
    use_llm: bool,
):
    """Scan a file or directory for security vulnerabilities."""
    try:
        target_path = Path(target)

        # Initialize components
        credential_manager = CredentialManager()
        threat_engine = ThreatEngine()
        ast_scanner = ASTScanner(threat_engine)
        exploit_generator = ExploitGenerator(credential_manager)

        console.print(f"🔍 Scanning: {target_path}")

        # Perform scan
        if target_path.is_file():
            # Scan single file
            lang_enum = None
            if language:
                lang_enum = Language(language)

            threats = ast_scanner.scan_file(target_path, lang_enum)
        else:
            # Scan directory
            threats = ast_scanner.scan_directory(target_path, recursive)

        # Filter by severity
        severity_enum = Severity(severity)
        severity_order = [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        min_index = severity_order.index(severity_enum)

        filtered_threats = [
            threat
            for threat in threats
            if severity_order.index(threat.severity) >= min_index
        ]

        # Generate exploits if requested
        if include_exploits and filtered_threats:
            console.print("🚀 Generating exploits...")

            for threat in filtered_threats[:10]:  # Limit to first 10 threats
                try:
                    exploits = exploit_generator.generate_exploits(threat, "", use_llm)
                    threat.exploit_examples = exploits
                except Exception as e:
                    console.print(
                        f"⚠️  Failed to generate exploits for {threat.rule_id}: {e}",
                        style="yellow",
                    )

        # Display results
        _display_scan_results(filtered_threats, target_path)

        # Save to file if requested
        if output:
            _save_results_to_file(filtered_threats, output)
            console.print(f"💾 Results saved to: {output}")

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
def list_rules(
    category: Optional[str],
    severity: Optional[str],
    language: Optional[str],
    output: Optional[str],
):
    """List available threat detection rules."""
    try:
        threat_engine = ThreatEngine()
        rules = threat_engine.list_rules()

        # Apply filters
        if category:
            rules = [rule for rule in rules if rule["category"] == category]

        if severity:
            severity_enum = Severity(severity)
            severity_order = [
                Severity.LOW,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            ]
            min_index = severity_order.index(severity_enum)
            rules = [
                rule
                for rule in rules
                if severity_order.index(Severity(rule["severity"])) >= min_index
            ]

        if language:
            rules = [rule for rule in rules if language in rule["languages"]]

        # Display rules
        table = Table(title=f"Threat Detection Rules ({len(rules)} rules)")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Category", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Languages", style="green")

        for rule in rules:
            table.add_row(
                rule["id"],
                rule["name"],
                rule["category"],
                rule["severity"],
                ", ".join(rule["languages"]),
            )

        console.print(table)

        # Save to file if requested
        if output:
            with open(output, "w") as f:
                json.dump(rules, f, indent=2)
            console.print(f"💾 Rules saved to: {output}")

    except Exception as e:
        console.print(f"❌ Failed to list rules: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument("rule_id")
def rule_details(rule_id: str):
    """Get detailed information about a specific rule."""
    try:
        threat_engine = ThreatEngine()
        rule = threat_engine.get_rule_by_id(rule_id)

        if not rule:
            console.print(f"❌ Rule not found: {rule_id}", style="red")
            sys.exit(1)

        # Display rule details
        console.print(
            Panel(
                f"**{rule.name}**",
                title=f"Rule Details: {rule.id}",
                border_style="blue",
            )
        )

        details_table = Table()
        details_table.add_column("Property", style="cyan")
        details_table.add_column("Value", style="magenta")

        details_table.add_row("ID", rule.id)
        details_table.add_row("Category", rule.category.value)
        details_table.add_row("Severity", rule.severity.value)
        details_table.add_row(
            "Languages", ", ".join([lang.value for lang in rule.languages])
        )
        details_table.add_row("Description", rule.description)

        if rule.remediation:
            details_table.add_row("Remediation", rule.remediation)

        if rule.cwe_id:
            details_table.add_row("CWE ID", rule.cwe_id)

        if rule.owasp_category:
            details_table.add_row("OWASP Category", rule.owasp_category)

        console.print(details_table)

        # Display conditions
        if rule.conditions:
            conditions_table = Table(title="Conditions")
            conditions_table.add_column("Type", style="cyan")
            conditions_table.add_column("Value", style="magenta")

            for condition in rule.conditions:
                conditions_table.add_row(condition.type, str(condition.value))

            console.print(conditions_table)

        # Display exploit templates
        if rule.exploit_templates:
            console.print("🚀 **Exploit Templates:**")
            for i, template in enumerate(rule.exploit_templates, 1):
                console.print(f"{i}. {template.description}")
                console.print(f"   Type: {template.type}")
                console.print(f"   Template: {template.template}")
                console.print()

        # Display references
        if rule.references:
            console.print("🔗 **References:**")
            for ref in rule.references:
                console.print(f"   - {ref}")

    except Exception as e:
        console.print(f"❌ Failed to get rule details: {e}", style="red")
        sys.exit(1)


@cli.command()
def demo():
    """Run a demo of the adversary MCP server."""
    try:
        console.print(Panel("🎯 Adversary MCP Server Demo", style="bold blue"))

        # Demo vulnerable code samples
        demo_code = {
            "python": """
import sqlite3
import os
import pickle

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def execute_command(user_input):
    # Vulnerable command injection
    os.system("echo " + user_input)

def load_data(data):
    # Vulnerable deserialization
    return pickle.loads(data)
            """,
            "javascript": """
function updateProfile(username) {
    // Vulnerable DOM XSS
    document.getElementById('profile').innerHTML = '<h1>Welcome ' + username + '</h1>';
}

function processData(userInput) {
    // Vulnerable code injection
    eval('console.log("Processing: ' + userInput + '")');
}

function loadScript(url) {
    // Potential SSRF
    fetch(url).then(response => response.text()).then(data => {
        document.body.innerHTML = data;
    });
}
            """,
        }

        console.print("🔍 Scanning demo code samples...")

        # Initialize components
        credential_manager = CredentialManager()
        threat_engine = ThreatEngine()
        ast_scanner = ASTScanner(threat_engine)
        exploit_generator = ExploitGenerator(credential_manager)

        total_threats = []

        for language, code in demo_code.items():
            console.print(f"\n📄 Scanning {language.capitalize()} code...")

            lang_enum = Language(language)
            threats = ast_scanner.scan_code(code, f"demo.{language}", lang_enum)

            if threats:
                console.print(f"  Found {len(threats)} threats")
                total_threats.extend(threats)
            else:
                console.print("  No threats found")

        if total_threats:
            console.print(
                f"\n🚨 Demo Results: {len(total_threats)} total threats found"
            )
            _display_scan_results(total_threats, "demo code")
        else:
            console.print("\n🎉 No vulnerabilities found in demo code!")

    except Exception as e:
        console.print(f"❌ Demo failed: {e}", style="red")
        sys.exit(1)


@cli.command()
def reset():
    """Reset configuration and clear stored credentials."""
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
        console.print("🎉 No security vulnerabilities found!", style="green")
        return

    # Summary
    severity_counts = {}
    for threat in threats:
        severity = threat.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    summary_text = f"🚨 **{len(threats)} threats found in {target}**\n"
    for severity in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[
                severity
            ]
            summary_text += f"{emoji} {severity.capitalize()}: {count}\n"

    console.print(Panel(summary_text, title="Scan Summary", border_style="red"))

    # Detailed results
    results_table = Table(title="Security Vulnerabilities")
    results_table.add_column("Severity", style="red")
    results_table.add_column("Rule", style="cyan")
    results_table.add_column("File", style="magenta")
    results_table.add_column("Line", style="yellow")
    results_table.add_column("Description", style="white")

    for threat in threats:
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }.get(threat.severity.value, "⚪")

        results_table.add_row(
            f"{severity_emoji} {threat.severity.value}",
            threat.rule_name,
            threat.file_path,
            str(threat.line_number),
            (
                threat.description[:50] + "..."
                if len(threat.description) > 50
                else threat.description
            ),
        )

    console.print(results_table)


def _save_results_to_file(threats, output_file):
    """Save scan results to a JSON file."""
    results = []
    for threat in threats:
        results.append(
            {
                "rule_id": threat.rule_id,
                "rule_name": threat.rule_name,
                "description": threat.description,
                "category": threat.category.value,
                "severity": threat.severity.value,
                "file_path": threat.file_path,
                "line_number": threat.line_number,
                "code_snippet": threat.code_snippet,
                "function_name": threat.function_name,
                "exploit_examples": threat.exploit_examples,
                "remediation": threat.remediation,
                "references": threat.references,
                "cwe_id": threat.cwe_id,
                "owasp_category": threat.owasp_category,
                "confidence": threat.confidence,
            }
        )

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)


def main():
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
