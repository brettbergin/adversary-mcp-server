"""Command-line interface for the Adversary MCP server."""

import datetime
import json
import sys
import time
from functools import wraps
from pathlib import Path

import click
import truststore
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import get_version
from .benchmarks import BenchmarkRunner
from .cache import CacheManager
from .config import get_app_cache_dir, get_app_metrics_dir
from .credentials import CredentialManager, get_credential_manager
from .database.models import AdversaryDatabase
from .llm.model_catalog import ModelCatalogService
from .llm.model_types import ModelProvider
from .logger import get_logger
from .monitoring import MetricsCollector
from .monitoring.types import MonitoringConfig
from .monitoring.unified_dashboard import UnifiedDashboard
from .scanner.diff_scanner import GitDiffScanner
from .scanner.scan_engine import ScanEngine
from .scanner.types import Severity
from .security import InputValidator, SecurityError, sanitize_for_logging
from .telemetry.integration import MetricsCollectionOrchestrator
from .telemetry.service import TelemetryService

console = Console()
logger = get_logger("cli")

# Global shared metrics collector for CLI commands to persist metrics across invocations
_shared_metrics_collector: MetricsCollector | None = None

# Global shared cache manager for CLI commands to persist cache across invocations
_shared_cache_manager = None

# Global shared telemetry system for CLI commands
_shared_db: AdversaryDatabase | None = None
_shared_telemetry_service: TelemetryService | None = None
_shared_metrics_orchestrator: MetricsCollectionOrchestrator | None = None


def _initialize_telemetry_system() -> MetricsCollectionOrchestrator:
    """Initialize shared telemetry system for CLI operations.

    Uses shared instances to persist telemetry across CLI commands.

    Returns:
        MetricsCollectionOrchestrator instance
    """
    global _shared_db, _shared_telemetry_service, _shared_metrics_orchestrator

    if _shared_metrics_orchestrator is None:
        _shared_db = AdversaryDatabase()
        _shared_telemetry_service = TelemetryService(_shared_db)
        _shared_metrics_orchestrator = MetricsCollectionOrchestrator(
            _shared_telemetry_service
        )
        logger.debug("Initialized shared telemetry system for CLI")

    return _shared_metrics_orchestrator


def _initialize_cache_manager(enable_caching: bool = True) -> CacheManager | None:
    """Initialize shared cache manager for CLI operations.

    Uses a shared cache manager instance to persist cache across CLI commands.

    Args:
        enable_caching: Whether to enable caching

    Returns:
        CacheManager instance or None if disabled
    """
    global _shared_cache_manager

    if not enable_caching:
        return None

    # Return existing shared cache manager if already initialized
    if _shared_cache_manager is not None:
        return _shared_cache_manager

    try:
        logger.debug("Initializing shared CLI cache manager...")
        cache_dir = get_app_cache_dir()

        # Initialize cache manager with reasonable defaults for CLI usage
        _shared_cache_manager = CacheManager(
            cache_dir=cache_dir,
            max_size_mb=100,  # 100MB cache limit
            max_age_hours=24,  # 24 hour cache expiry
            enable_persistence=True,  # Persist across CLI invocations
            metrics_collector=_shared_metrics_collector,  # Link to shared metrics
        )
        logger.debug(f"Shared CLI cache manager initialized at {cache_dir}")
        return _shared_cache_manager
    except Exception as e:
        logger.warning(f"Failed to initialize CLI cache manager: {e}")
        return None


def _initialize_monitoring(enable_metrics: bool = True) -> MetricsCollector | None:
    """Initialize central monitoring for CLI operations.

    Uses a shared metrics collector instance to persist metrics across CLI commands.

    Args:
        enable_metrics: Whether to enable metrics collection

    Returns:
        MetricsCollector instance or None if disabled
    """
    global _shared_metrics_collector

    if not enable_metrics:
        return None

    # Return existing shared collector if already initialized
    if _shared_metrics_collector is not None:
        return _shared_metrics_collector

    try:
        logger.debug("Initializing shared CLI monitoring...")
        monitoring_config = MonitoringConfig(
            enable_metrics=True,
            enable_performance_monitoring=True,
            json_export_path=str(get_app_metrics_dir()),
        )
        _shared_metrics_collector = MetricsCollector(monitoring_config)
        logger.debug("Shared CLI monitoring initialized successfully")
        return _shared_metrics_collector
    except Exception as e:
        logger.warning(f"Failed to initialize CLI monitoring: {e}")
        return None


def _initialize_scan_components(
    use_validation: bool = True,
    metrics_collector: MetricsCollector | None = None,
    cache_manager: CacheManager | None = None,
) -> tuple[CredentialManager, ScanEngine]:
    """Initialize scan components with centralized monitoring and caching.

    Args:
        use_validation: Whether to enable LLM validation
        metrics_collector: Optional metrics collector for monitoring
        cache_manager: Optional cache manager for caching

    Returns:
        Tuple of (CredentialManager, ScanEngine)
    """
    logger.debug("Initializing scan components...")
    credential_manager = get_credential_manager()
    config = credential_manager.load_config()

    scan_engine = ScanEngine(
        credential_manager=credential_manager,
        cache_manager=cache_manager,
        metrics_collector=metrics_collector,
        enable_llm_validation=use_validation,
        enable_llm_analysis=config.enable_llm_analysis,
        enable_semgrep_analysis=config.enable_semgrep_scanning,
    )

    logger.debug("Scan components initialized with monitoring and caching support")
    return credential_manager, scan_engine


def cli_command_monitor(command_name: str):
    """Decorator to monitor CLI command execution timing and outcomes with telemetry.

    Args:
        command_name: Name of the CLI command for metrics labeling
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.debug(f"Starting CLI command: {command_name}")

            # Initialize monitoring for this command (legacy)
            metrics_collector = _initialize_monitoring()

            # Initialize telemetry system (new)
            metrics_orchestrator = _initialize_telemetry_system()

            # Use the new telemetry system wrapper
            telemetry_wrapped = metrics_orchestrator.cli_command_wrapper(command_name)(
                func
            )

            # Legacy metrics collection
            if metrics_collector:
                metrics_collector.record_metric(
                    "cli_commands_total",
                    1,
                    labels={"command": command_name, "status": "started"},
                )

            try:
                # Execute the command with telemetry tracking
                result = telemetry_wrapped(*args, **kwargs)

                # Legacy metrics collection for backward compatibility
                if metrics_collector:
                    metrics_collector.record_metric(
                        "cli_commands_total",
                        1,
                        labels={"command": command_name, "status": "success"},
                    )

                logger.debug(f"CLI command {command_name} completed successfully")
                return result

            except Exception as e:
                # Legacy metrics collection for errors
                if metrics_collector:
                    metrics_collector.record_metric(
                        "cli_commands_total",
                        1,
                        labels={
                            "command": command_name,
                            "status": "error",
                            "error_type": type(e).__name__,
                        },
                    )

                logger.error(f"CLI command {command_name} failed: {e}")
                raise

        return wrapper

    return decorator


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
@cli_command_monitor("configure")
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
        credential_manager = get_credential_manager()
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

            # Check if API key already exists
            existing_api_key = credential_manager.get_llm_api_key(llm_provider)

            if existing_api_key:
                console.print(
                    f"✅ {llm_provider.title()} API key already configured",
                    style="green",
                )
                # Update the config to use this provider
                config.llm_provider = llm_provider
                config_updated = True
            else:
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
                        credential_manager.store_llm_api_key(
                            llm_provider, api_key.strip()
                        )
                        console.print(
                            f"✅ {llm_provider.title()} API key stored!", style="green"
                        )

                        # Update configuration
                        config.llm_provider = llm_provider
                        config_updated = True

                    except Exception as e:
                        console.print(
                            f"❌ Failed to store {llm_provider} API key: {e}",
                            style="red",
                        )
                        logger.error(f"Failed to store {llm_provider} API key: {e}")
                        return
                else:
                    console.print(
                        f"⏭️  Skipped {llm_provider} configuration", style="yellow"
                    )
                    return

            # Always do model selection when configuring a provider
            try:
                provider_enum = (
                    ModelProvider.OPENAI
                    if llm_provider == "openai"
                    else ModelProvider.ANTHROPIC
                )

                # Use simple synchronous model selection for now
                console.print(f"\n🤖 [bold]Select {llm_provider.title()} Model[/bold]")

                # Get available models synchronously
                catalog = ModelCatalogService()

                # Get models from pricing config (synchronous fallback)
                fallback_models = catalog._load_fallback_models()
                provider_models = [
                    m for m in fallback_models if m.provider == provider_enum
                ]

                if provider_models:
                    console.print("\n📋 Available models:")

                    # Group by category for display
                    categorized = catalog.get_categorized_models(provider_models)

                    choices = []
                    choice_map = {}
                    index = 1

                    for category, models in categorized.items():
                        console.print(
                            f"\n{category.value.title()} Models:", style="bold"
                        )
                        for model in models[:5]:  # Limit to top 5 per category
                            choice_text = f"{index}. {model.display_name} - {model.cost_description}"
                            console.print(f"   {choice_text}")
                            choices.append(str(index))
                            choice_map[str(index)] = model
                            index += 1

                    # Get user selection
                    selection = Prompt.ask(
                        f"Select model (1-{index-1})",
                        choices=choices,
                        default="1",
                    )

                    selected_model = choice_map.get(selection)
                    if selected_model:
                        config.llm_model = selected_model.id
                        console.print(
                            f"✅ Selected model: {selected_model.display_name}",
                            style="green",
                        )
                    else:
                        raise ValueError("Invalid selection")
                else:
                    raise ValueError("No models available")

            except Exception as e:
                logger.warning(f"Model selection failed, using fallback: {e}")
                # Fallback to default models - now using Claude Sonnet 4 as default
                default_model = (
                    "gpt-4o" if llm_provider == "openai" else "claude-sonnet-4-20250514"
                )
                config.llm_model = default_model
                console.print(
                    f"⏭️  Using default model: {default_model}", style="yellow"
                )

            config_updated = True
            console.print(
                f"✅ {llm_provider.title()} configuration complete!",
                style="green",
            )
            logger.info(
                f"{llm_provider} LLM configured successfully with model: {config.llm_model}"
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
@cli_command_monitor("status")
def status():
    """Show current server status and configuration."""
    logger.info("=== Starting status command ===")

    try:
        logger.debug("Initializing components for status check...")
        metrics_collector = _initialize_monitoring()
        cache_manager = _initialize_cache_manager()
        credential_manager, scan_engine = _initialize_scan_components(
            use_validation=True,  # Need to initialize validation to report its status
            metrics_collector=metrics_collector,
            cache_manager=cache_manager,
        )
        config = credential_manager.load_config()
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
        # Enhanced Semgrep status with pro user information
        semgrep_available = scan_engine.semgrep_scanner.is_available()
        if semgrep_available:
            # Get pro user status
            pro_status = scan_engine.semgrep_scanner.get_pro_status()
            if pro_status["is_pro_user"] is True:
                semgrep_status = f"✓ Available (Pro User: {pro_status.get('subscription_type', 'Unknown').title()})"
            elif pro_status["is_pro_user"] is False:
                if pro_status["authentication_status"] == "authenticated":
                    semgrep_status = "✓ Available (Free User)"
                elif pro_status["authentication_status"] == "failed":
                    semgrep_status = "✓ Available (Auth Failed)"
                else:
                    semgrep_status = "✓ Available (Anonymous)"
            else:
                semgrep_status = "✓ Available (Status Unknown)"
        else:
            semgrep_status = "✗ Not Available"

        config_table.add_row("Semgrep Status", semgrep_status)

        # Add dedicated Semgrep capability row
        if semgrep_available:
            pro_status = scan_engine.semgrep_scanner.get_pro_status()
            if pro_status["is_pro_user"] is True:
                capability = f"Professional ({pro_status.get('subscription_type', 'Unknown').title()})"
            elif pro_status["is_pro_user"] is False:
                if pro_status["authentication_status"] == "authenticated":
                    capability = "Community (Authenticated)"
                elif pro_status["authentication_status"] == "failed":
                    capability = "Community (Auth Failed)"
                else:
                    capability = "Community (Anonymous)"
            else:
                capability = "Unknown"
        else:
            capability = "Not Available"

        config_table.add_row("Semgrep Capability", capability)
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

        # Show LLM Analysis status based on actual availability
        if config.llm_provider and is_llm_valid:
            llm_analysis_status = (
                "Available" if config.enable_llm_analysis else "Disabled"
            )
        elif config.enable_llm_analysis and not config.llm_provider:
            llm_analysis_status = "Inactive (Provider Missing)"
        else:
            llm_analysis_status = "Disabled"

        config_table.add_row("LLM Analysis", llm_analysis_status)

        # Show LLM Validation status based on actual availability
        if config.llm_provider and is_llm_valid:
            llm_validation_status = (
                "Available" if config.enable_llm_validation else "Disabled"
            )
        elif config.enable_llm_validation and not config.llm_provider:
            llm_validation_status = "Inactive (Provider Missing)"
        else:
            llm_validation_status = "Disabled"

        config_table.add_row("LLM Validation", llm_validation_status)

        console.print(config_table)

        # Scanner status
        console.print("\n🔍 [bold]Scanner Status[/bold]")
        scanners_table = Table(title="Available Scanners")
        scanners_table.add_column("Scanner", style="cyan")
        scanners_table.add_column("Status", style="green")
        scanners_table.add_column("Description", style="yellow")

        # Enhanced Semgrep scanner status with pro information
        semgrep_scanner_available = scan_engine.semgrep_scanner.is_available()
        if semgrep_scanner_available:
            pro_status = scan_engine.semgrep_scanner.get_pro_status()
            if pro_status["is_pro_user"] is True:
                semgrep_scanner_status = f"Available (Pro: {pro_status.get('subscription_type', 'unknown').title()})"
                semgrep_description = f"Static analysis with Pro rules ({pro_status.get('rules_available', 0)} rules)"
            elif pro_status["is_pro_user"] is False:
                if pro_status["authentication_status"] == "authenticated":
                    semgrep_scanner_status = "Available (Free)"
                    semgrep_description = "Static analysis with community rules"
                else:
                    semgrep_scanner_status = "Available (Community)"
                    semgrep_description = "Static analysis with open-source rules"
            else:
                semgrep_scanner_status = "Available"
                semgrep_description = "Static analysis tool (status unknown)"
        else:
            semgrep_scanner_status = "Unavailable"
            semgrep_description = "Static analysis tool (not installed)"

        scanners_table.add_row("Semgrep", semgrep_scanner_status, semgrep_description)
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
        credential_manager = get_credential_manager()

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
@click.argument("path", required=False, default=".")
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
@click.option(
    "--output-format",
    type=click.Choice(["json", "markdown"]),
    default="json",
    help="Output format for results",
)
@click.option("--include-exploits", is_flag=True, help="Include exploit examples")
@cli_command_monitor("scan")
def scan(
    path: str,
    source_branch: str | None,
    target_branch: str | None,
    use_llm: bool,
    use_semgrep: bool,
    use_validation: bool,
    severity: str | None,
    output_format: str,
    include_exploits: bool,
):
    """Scan a file or directory for security vulnerabilities."""
    logger.info("=== Starting scan command ===")

    # Sanitize sensitive parameters for logging
    scan_params = {
        "path": path,
        "source_branch": source_branch,
        "target_branch": target_branch,
        "use_llm": use_llm,
        "use_semgrep": use_semgrep,
        "use_validation": use_validation,
        "severity": severity,
        "output_format": output_format,
        "include_exploits": include_exploits,
    }
    logger.debug(f"Scan parameters: {sanitize_for_logging(scan_params)}")

    # Validate and sanitize CLI arguments
    try:
        validated_path = (
            InputValidator.validate_file_path(path)
            if Path(path).is_file()
            else InputValidator.validate_directory_path(path)
        )
        if severity:
            validated_severity = InputValidator.validate_severity_threshold(severity)
        else:
            validated_severity = severity

        if source_branch:
            validated_source_branch = InputValidator.validate_string_param(
                source_branch, "source_branch", 100, r"^[a-zA-Z0-9_.-]+$"
            )
        else:
            validated_source_branch = source_branch

        if target_branch:
            validated_target_branch = InputValidator.validate_string_param(
                target_branch, "target_branch", 100, r"^[a-zA-Z0-9_.-]+$"
            )
        else:
            validated_target_branch = target_branch

        # Update parameters with validated values
        path = str(validated_path)
        severity = validated_severity
        source_branch = validated_source_branch
        target_branch = validated_target_branch

        logger.debug("CLI argument validation passed")

    except (SecurityError, ValueError, FileNotFoundError) as e:
        logger.error(f"CLI argument validation failed: {e}")
        console.print("❌ [bold red]Input Validation Error[/bold red]")
        console.print(f"The provided input contains issues: {e}")
        console.print("Please check your input and try again with valid parameters.")
        sys.exit(1)

    try:
        # Initialize scanner components
        logger.debug("Initializing scan components with monitoring and caching...")
        metrics_collector = _initialize_monitoring()
        cache_manager = _initialize_cache_manager()
        credential_manager, scan_engine = _initialize_scan_components(
            use_validation=use_validation,
            metrics_collector=metrics_collector,
            cache_manager=cache_manager,
        )

        # Resolve the path
        target_path = Path(path).resolve()

        # Git diff scanning mode
        if source_branch and target_branch:
            logger.info(f"Git diff mode: {source_branch} -> {target_branch}")

            # Validate git repository
            if not (target_path / ".git").exists():
                console.print(
                    f"❌ Path is not a git repository: {target_path}", style="red"
                )
                sys.exit(1)

            project_root = target_path

            # Initialize git diff scanner with project root
            git_diff_scanner = GitDiffScanner(
                scan_engine=scan_engine,
                working_dir=project_root,
                metrics_collector=metrics_collector,
            )
            logger.debug("Git diff scanner initialized with monitoring")

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
            if not target_path.exists():
                console.print(f"❌ Path does not exist: {target_path}", style="red")
                sys.exit(1)

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
                logger.error(f"Invalid target type: {target_path}")
                console.print(f"❌ Invalid target: {target_path}", style="red")
                sys.exit(1)

            # Display results for traditional scanning
            _display_scan_results(threats, str(target_path))

        # Save results to file based on output format
        from .scanner.result_formatter import ScanResultFormatter

        # Determine output directory based on scan type
        if source_branch and target_branch:
            output_dir = project_root
            scan_target = f"diff: {source_branch}...{target_branch}"
        else:
            if target_path.is_file():
                output_dir = target_path.parent
                scan_target = str(target_path)
            else:
                output_dir = target_path
                scan_target = str(target_path)

        # Determine output filename
        if output_format == "json":
            output_file = output_dir / ".adversary.json"
        else:  # markdown
            output_file = output_dir / ".adversary.md"

        # Format and save results
        formatter = ScanResultFormatter(str(output_dir))

        if source_branch and target_branch and "scan_results" in locals():
            # Git diff scan
            diff_summary = git_diff_scanner.get_diff_summary_sync(
                source_branch, target_branch
            )
            if output_format == "json":
                result_content = formatter.format_diff_results_json(
                    scan_results, diff_summary, scan_target
                )
            else:
                result_content = formatter.format_diff_results_markdown(
                    scan_results, diff_summary, scan_target
                )
        elif "scan_result" in locals() and not isinstance(
            locals().get("scan_results"), list
        ):
            # Single file scan
            if output_format == "json":
                result_content = formatter.format_single_file_results_json(
                    scan_result, scan_target
                )
            else:
                result_content = formatter.format_single_file_results_markdown(
                    scan_result, scan_target
                )
        elif "scan_results" in locals() and isinstance(
            locals().get("scan_results"), list
        ):
            # Directory scan - scan_results is list[EnhancedScanResult]
            from typing import cast

            directory_scan_results = cast(list, scan_results)  # Type narrowing for mypy
            if output_format == "json":
                result_content = formatter.format_directory_results_json(
                    directory_scan_results, scan_target, "directory"
                )
            else:
                result_content = formatter.format_directory_results_markdown(
                    directory_scan_results, scan_target, "directory"
                )
        else:
            logger.warning("No scan results to save")
            result_content = None

        if result_content:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result_content)
            console.print(f"✅ Results saved to {output_file}", style="green")
            logger.info(f"Scan results saved to {output_file}")

        # Export metrics to persist scan data for monitoring
        if metrics_collector:
            try:
                import asyncio

                metrics_file = asyncio.run(metrics_collector.export_metrics())
                if metrics_file:
                    logger.debug(f"Scan metrics exported to: {metrics_file}")
            except Exception as e:
                logger.warning(f"Failed to export scan metrics: {e}")

        # Display cache statistics for performance verification
        if cache_manager:
            try:
                cache_stats = cache_manager.get_stats()
                total_requests = cache_stats.hit_count + cache_stats.miss_count
                console.print("\n📊 [bold]Cache Performance[/bold]")
                console.print(f"   Cache hits: {cache_stats.hit_count}")
                console.print(f"   Cache misses: {cache_stats.miss_count}")
                if total_requests > 0:
                    hit_rate = (cache_stats.hit_count / total_requests) * 100
                    console.print(f"   Hit rate: {hit_rate:.1f}%")
                else:
                    console.print("   Hit rate: N/A (no cache requests)")
                logger.info(
                    f"Cache performance - Hits: {cache_stats.hit_count}, Misses: {cache_stats.miss_count}"
                )
            except Exception as e:
                logger.warning(f"Failed to get cache statistics: {e}")
                console.print(f"   ❌ Cache statistics unavailable: {e}", style="red")

        logger.info("=== Scan command completed successfully ===")

    except Exception as e:
        logger.error(f"Scan command failed: {e}")
        logger.debug("Scan error details", exc_info=True)
        console.print(f"❌ Scan failed: {e}", style="red")
        sys.exit(1)


@cli.command()
@cli_command_monitor("demo")
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
        metrics_collector = _initialize_monitoring()
        cache_manager = _initialize_cache_manager()
        credential_manager, scan_engine = _initialize_scan_components(
            use_validation=False,  # Simple demo without validation
            metrics_collector=metrics_collector,
            cache_manager=cache_manager,
        )

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
    "--path",
    type=click.Path(exists=True),
    default=".",
    help="Path to directory containing .adversary.json or direct path to .adversary.json file",
)
def mark_false_positive(
    finding_uuid: str,
    reason: str | None,
    marked_by: str | None,
    path: str,
):
    """Mark a finding as a false positive by UUID."""
    logger.info(
        f"=== Starting mark-false-positive command for finding: {finding_uuid} ==="
    )

    try:
        from .scanner.false_positive_manager import FalsePositiveManager

        # Use helper function to get adversary.json path
        adversary_file_path = _get_adversary_json_path(path)

        # Check if file exists, if not use the legacy search approach
        if not adversary_file_path.exists():
            # Fall back to legacy search in parent directories
            project_root = path or "."
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
            credential_manager = get_credential_manager()

            # Delete main configuration
            credential_manager.delete_config()
            console.print("✅ Main configuration deleted", style="green")

            # Delete Semgrep API key
            api_key_deleted = credential_manager.delete_semgrep_api_key()
            if api_key_deleted:
                console.print("✅ Semgrep API key deleted", style="green")
            else:
                console.print("ℹ️  No Semgrep API key found to delete", style="yellow")

            # Delete LLM API keys
            credential_manager.clear_llm_configuration()
            console.print("✅ LLM API keys cleared", style="green")

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
                threat.description[:80] + "..."
                if len(threat.description) > 80
                else threat.description
            ),
        )

    console.print(table)
    logger.info(f"Displayed scan results for {target}")


def _save_results_to_file(
    scan_results, scan_target, output_file, working_directory="."
):
    """Save comprehensive scan results to a JSON file using unified formatter.

    Args:
        scan_results: Enhanced scan results (single EnhancedScanResult or list)
        scan_target: Target that was scanned (file path or directory)
        output_file: Output file path
        working_directory: Working directory for false positive tracking
    """
    logger.info(f"Saving comprehensive scan results to file: {output_file}")
    try:
        from .scanner.result_formatter import ScanResultFormatter

        output_path = Path(output_file)
        formatter = ScanResultFormatter(working_directory)

        # Handle both single results and lists of results
        if isinstance(scan_results, list):
            logger.debug(
                f"Formatting {len(scan_results)} scan results as directory scan"
            )
            json_content = formatter.format_directory_results_json(
                scan_results, scan_target, scan_type="directory"
            )
        else:
            logger.debug("Formatting single scan result as file scan")
            json_content = formatter.format_single_file_results_json(
                scan_results, scan_target
            )

        # Save to file
        with open(output_path, "w") as f:
            f.write(json_content)

        console.print(f"✅ Comprehensive results saved to {output_path}", style="green")
        logger.info(f"Comprehensive scan results saved to {output_path}")

    except Exception as e:
        logger.error(f"Failed to save comprehensive results: {e}")
        logger.debug("Save comprehensive results error details", exc_info=True)
        console.print(f"❌ Failed to save results: {e}", style="red")


@cli.command()
def reset_semgrep_key():
    """Remove the stored Semgrep API key from keyring."""
    logger.info("=== Starting reset-semgrep-key command ===")

    try:
        credential_manager = get_credential_manager()
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
        credential_manager = get_credential_manager()
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


@cli.command()
@click.option(
    "--hours",
    type=int,
    default=24,
    help="Hours of data to include in dashboard (default: 24)",
)
@click.option(
    "--no-launch",
    is_flag=True,
    help="Don't automatically open dashboard in browser",
)
@cli_command_monitor("dashboard")
def dashboard(hours: int, no_launch: bool):
    """Generate and launch rich HTML dashboard with comprehensive telemetry."""
    try:
        from .dashboard.html_dashboard import ComprehensiveHTMLDashboard

        console.print("🚀 Generating comprehensive HTML dashboard...")

        # Initialize telemetry system
        orchestrator = _initialize_telemetry_system()
        db = orchestrator.telemetry.db

        # Create dashboard
        html_dashboard = ComprehensiveHTMLDashboard(db)

        console.print(f"📊 Collecting {hours} hours of telemetry data...")

        # Generate and launch dashboard
        html_file = html_dashboard.generate_and_launch_dashboard(
            hours=hours, auto_launch=not no_launch
        )

        console.print("✅ Dashboard generated successfully!")
        console.print(f"📄 Dashboard file: {html_file}")

        if no_launch:
            console.print(f"🌐 Open in browser: file://{Path(html_file).absolute()}")
        else:
            console.print("🚀 Dashboard launched in your default browser!")

    except ImportError as e:
        console.print(f"❌ Dashboard dependencies missing: {e}")
        console.print("💡 Install with: pip install jinja2")
        sys.exit(1)

    except Exception as e:
        console.print(f"❌ Failed to generate dashboard: {e}")
        logger.error(f"Dashboard generation failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--export-format",
    type=click.Choice(["json", "prometheus"]),
    default="json",
    help="Export format for metrics data",
)
@click.option(
    "--output-path", type=click.Path(), help="Custom output path for exported metrics"
)
@click.option(
    "--show-dashboard", is_flag=True, help="Display real-time monitoring dashboard"
)
@cli_command_monitor("monitoring")
def monitoring(export_format: str, output_path: str | None, show_dashboard: bool):
    """Monitor system metrics and export monitoring data.

    DEPRECATED: Use 'adversary-mcp-cli dashboard' for the new HTML dashboard.
    """
    logger.info("=== Starting legacy monitoring command ===")

    console.print("⚠️  [yellow]WARNING: This command is deprecated![/yellow]")
    console.print(
        "🚀 [cyan]Use 'adversary-mcp-cli dashboard' for the new HTML dashboard[/cyan]"
    )
    console.print(
        "📊 [dim]Legacy monitoring functionality preserved for compatibility[/dim]\n"
    )

    try:
        # Initialize monitoring components (legacy compatibility)
        metrics_collector = _initialize_monitoring(enable_metrics=True)
        if not metrics_collector:
            console.print("❌ [red]Failed to initialize monitoring system[/red]")
            sys.exit(1)

        # Use the new unified dashboard
        from .monitoring.unified_dashboard import UnifiedDashboard

        dashboard = UnifiedDashboard(metrics_collector, console)

        if show_dashboard:
            console.print("🔍 [bold cyan]Real-Time Monitoring Dashboard[/bold cyan]")
            console.print("Press Ctrl+C to exit the dashboard\n")

            try:
                import signal

                def signal_handler(sig, frame):
                    console.print("\n👋 [yellow]Dashboard monitoring stopped[/yellow]")
                    sys.exit(0)

                signal.signal(signal.SIGINT, signal_handler)

                # Display dashboard continuously
                while True:
                    dashboard.display_real_time_dashboard()
                    console.print(
                        "\n⏱️  [dim]Refreshing in 4 seconds... (Press Ctrl+C to exit)[/dim]"
                    )
                    time.sleep(4)

            except KeyboardInterrupt:
                console.print("\n👋 [yellow]Dashboard monitoring stopped[/yellow]")
                return  # Exit normally without using sys.exit()
        else:
            # Export metrics using unified dashboard
            console.print(
                f"📤 [cyan]Exporting metrics in {export_format} format...[/cyan]"
            )

            exported_file = dashboard.export_metrics(export_format, output_path)

            if exported_file:
                console.print("✅ [green]Metrics exported successfully[/green]")
            else:
                console.print(
                    f"❌ [red]Failed to export metrics in {export_format} format[/red]"
                )

            # Show summary
            console.print("\n📋 [bold]Current Metrics Summary:[/bold]")
            dashboard.display_real_time_dashboard()

    except KeyboardInterrupt:
        console.print("\n👋 [yellow]Dashboard monitoring stopped[/yellow]")
        return  # Exit normally without using sys.exit()
    except Exception as e:
        logger.error(f"Monitoring command failed: {e}")
        logger.debug("Monitoring error details", exc_info=True)
        console.print(f"❌ [red]Monitoring command failed: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option(
    "--metrics-dir",
    type=click.Path(exists=True),
    help="Directory containing metrics files to analyze",
)
@click.option(
    "--time-range",
    type=str,
    default="24h",
    help="Time range for analysis (e.g., 1h, 24h, 7d)",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format for analysis results",
)
@cli_command_monitor("metrics-analyze")
def metrics_analyze(metrics_dir: str | None, time_range: str, output_format: str):
    """Analyze historical metrics data and generate insights."""
    logger.info("=== Starting metrics analysis command ===")

    try:
        # Initialize monitoring for analysis
        metrics_collector = _initialize_monitoring(enable_metrics=True)
        if not metrics_collector:
            console.print("❌ [red]Failed to initialize monitoring system[/red]")
            sys.exit(1)

        dashboard = UnifiedDashboard(metrics_collector, console)

        console.print(
            f"📊 [bold cyan]Metrics Analysis - {time_range} time range[/bold cyan]\n"
        )

        # Parse time range
        time_multiplier = {"h": 3600, "d": 86400, "w": 604800}
        time_unit = time_range[-1].lower()
        time_value = int(time_range[:-1])
        lookback_seconds = time_value * time_multiplier.get(time_unit, 3600)
        lookback_minutes = lookback_seconds // 60

        # Generate analysis report
        analysis_data = {
            "analysis_period": time_range,
            "system_overview": dashboard._generate_system_overview_data(),
            "scanner_performance": dashboard._generate_scanner_performance_data(),
            "error_analytics": dashboard._generate_error_analytics_data(),
            "resource_utilization": dashboard._generate_resource_utilization_data(),
        }

        if output_format == "table":
            # Display analysis in table format
            console.print("🔍 [bold]System Performance Analysis[/bold]")
            dashboard.display_real_time_dashboard()

        elif output_format == "json":
            # Export as JSON
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_file = Path(f"metrics_analysis_{timestamp}.json")

            with open(analysis_file, "w") as f:
                json.dump(analysis_data, f, indent=2)

            console.print(f"📁 [green]Analysis exported to: {analysis_file}[/green]")

        elif output_format == "csv":
            # Export as CSV (simplified metrics)
            import csv

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_file = Path(f"metrics_analysis_{timestamp}.csv")

            with open(csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Metric", "Category", "Value", "Unit"])

                # System overview metrics
                for metric, data in analysis_data["system_overview"].items():
                    if isinstance(data, dict):
                        for key, value in data.items():
                            writer.writerow([f"{metric}_{key}", "system", value, ""])
                    else:
                        writer.writerow([metric, "system", data, ""])

                # Scanner performance
                for scanner, data in analysis_data["scanner_performance"].items():
                    for key, value in data.items():
                        writer.writerow([f"{scanner}_{key}", "scanner", value, ""])

                # Error analytics
                for error_type, count in analysis_data["error_analytics"].items():
                    writer.writerow([error_type, "error", count, "count"])

                # Resource utilization
                for resource, value in analysis_data["resource_utilization"].items():
                    writer.writerow([resource, "resource", value, ""])

            console.print(f"📊 [green]CSV analysis exported to: {csv_file}[/green]")

        logger.info("=== Metrics analysis completed successfully ===")

    except Exception as e:
        logger.error(f"Metrics analysis failed: {e}")
        logger.debug("Metrics analysis error details", exc_info=True)
        console.print(f"❌ [red]Metrics analysis failed: {e}[/red]")
        sys.exit(1)


@cli.command(name="clear-cache")
@cli_command_monitor("clear-cache")
def clear_cache():
    """Clear all local cache and data storage."""
    logger.info("=== Starting cache clearing command ===")

    try:
        logger.debug("Initializing components for cache clearing...")
        metrics_collector = _initialize_monitoring()
        cache_manager = _initialize_cache_manager()
        credential_manager, scan_engine = _initialize_scan_components(
            use_validation=False,  # Don't need validation for cache clearing
            metrics_collector=metrics_collector,
            cache_manager=cache_manager,
        )
        logger.debug("Components initialized successfully")

        console.print("🗑️ [bold]Clearing Local Cache and Data Storage[/bold]")
        console.print()

        cleared_items = []

        # Clear main cache manager
        if cache_manager is not None:
            cache_stats_before = cache_manager.get_stats()
            cache_manager.clear()
            cleared_items.append(
                f"Main cache ({cache_stats_before.total_entries} entries)"
            )
            console.print(
                f"✅ Cleared main cache: {cache_stats_before.total_entries} entries"
            )

        # Clear scan engine cache
        if hasattr(scan_engine, "clear_cache"):
            scan_engine.clear_cache()
            cleared_items.append("Scan engine cache")
            console.print("✅ Cleared scan engine cache")

        # Clear semgrep scanner cache
        if hasattr(scan_engine, "semgrep_scanner") and hasattr(
            scan_engine.semgrep_scanner, "clear_cache"
        ):
            scan_engine.semgrep_scanner.clear_cache()
            cleared_items.append("Semgrep scanner cache")
            console.print("✅ Cleared Semgrep scanner cache")

        # Clear token estimator cache if available
        if (
            hasattr(scan_engine, "llm_analyzer")
            and scan_engine.llm_analyzer is not None
        ):
            if hasattr(scan_engine.llm_analyzer, "token_estimator") and hasattr(
                scan_engine.llm_analyzer.token_estimator, "clear_cache"
            ):
                scan_engine.llm_analyzer.token_estimator.clear_cache()
                cleared_items.append("Token estimator cache")
                console.print("✅ Cleared token estimator cache")

        console.print()
        if cleared_items:
            console.print("🎉 [green]Cache clearing completed successfully![/green]")
            console.print(f"📊 [cyan]Cleared components: {len(cleared_items)}[/cyan]")
        else:
            console.print("ℹ️ [yellow]No cache components found to clear[/yellow]")

        logger.info(
            f"Cache clearing completed successfully. Cleared: {', '.join(cleared_items)}"
        )

    except Exception as e:
        logger.error(f"Cache clearing failed: {e}")
        logger.debug("Cache clearing error details", exc_info=True)
        console.print(f"❌ [red]Cache clearing failed: {e}[/red]")
        sys.exit(1)


@cli.command(name="migrate-data")
@cli_command_monitor("migrate-data")
def migrate_data():
    """Fix inconsistencies between summary fields and actual threat findings in database."""
    logger.info("=== Starting data migration command ===")

    try:
        from .database.migrations import DataMigrationManager

        logger.debug("Initializing database for data migration...")
        telemetry_system = _initialize_telemetry_system()
        db = telemetry_system.telemetry.db
        logger.debug("Database initialized successfully")

        console.print("🔧 [bold]Database Data Migration[/bold]")
        console.print(
            "Fixing inconsistencies between summary fields and actual threat findings..."
        )
        console.print()

        # Run data migration
        migration_manager = DataMigrationManager(db)
        results = migration_manager.fix_summary_field_inconsistencies()

        if results["migration_success"]:
            console.print("✅ [green]Data migration completed successfully![/green]")
            console.print()

            # Display migration statistics
            table = Table(
                title="Migration Results", show_header=True, header_style="bold blue"
            )
            table.add_column("Table", style="cyan")
            table.add_column("Records Checked", justify="right")
            table.add_column("Inconsistencies Found", justify="right")
            table.add_column("Records Updated", justify="right")

            for fix_type in [
                "mcp_tool_fixes",
                "cli_command_fixes",
                "scan_engine_fixes",
            ]:
                fix_data = results[fix_type]
                table.add_row(
                    fix_data["table"],
                    str(fix_data["records_checked"]),
                    str(fix_data["inconsistencies_found"]),
                    str(fix_data["records_updated"]),
                )

            console.print(table)
            console.print()
            console.print(
                f"📊 [bold]Total records fixed: {results['total_records_fixed']}[/bold]"
            )

            logger.info(
                f"Data migration completed successfully: {results['total_records_fixed']} records fixed"
            )

        else:
            console.print(f"❌ [red]Data migration failed: {results['error']}[/red]")
            logger.error(f"Data migration failed: {results['error']}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Data migration command failed: {e}")
        logger.debug("Data migration error details", exc_info=True)
        console.print(f"❌ [red]Data migration failed: {e}[/red]")
        sys.exit(1)


@cli.command(name="validate-data")
@cli_command_monitor("validate-data")
def validate_data():
    """Validate data consistency across telemetry tables and report any inconsistencies."""
    logger.info("=== Starting data validation command ===")

    try:
        from .database.migrations import DataMigrationManager

        logger.debug("Initializing database for data validation...")
        telemetry_system = _initialize_telemetry_system()
        db = telemetry_system.telemetry.db
        logger.debug("Database initialized successfully")

        console.print("🔍 [bold]Database Data Validation[/bold]")
        console.print(
            "Checking consistency between summary fields and actual threat findings..."
        )
        console.print()

        # Run data validation
        migration_manager = DataMigrationManager(db)
        results = migration_manager.validate_data_consistency()

        if results["validation_success"]:
            if results["data_consistent"]:
                console.print(
                    "✅ [green]All data is consistent! No inconsistencies found.[/green]"
                )
            else:
                console.print(
                    f"⚠️ [yellow]Found {results['total_inconsistencies']} inconsistencies in database.[/yellow]"
                )
                console.print()
                console.print(
                    "🔧 Run 'adversary-mcp-cli migrate-data' to fix these issues."
                )

            console.print()

            # Display validation statistics
            table = Table(
                title="Validation Results", show_header=True, header_style="bold blue"
            )
            table.add_column("Table", style="cyan")
            table.add_column("Records Checked", justify="right")
            table.add_column(
                "Inconsistencies Found",
                justify="right",
                style="red" if results["total_inconsistencies"] > 0 else "green",
            )

            for validation_type in [
                "mcp_tool_validation",
                "cli_command_validation",
                "scan_engine_validation",
            ]:
                validation_data = results[validation_type]
                table.add_row(
                    validation_data["table"],
                    str(validation_data["records_checked"]),
                    str(validation_data["inconsistencies_found"]),
                )

            console.print(table)
            console.print()
            console.print(
                f"📊 [bold]Total inconsistencies: {results['total_inconsistencies']}[/bold]"
            )

            logger.info(
                f"Data validation completed: {results['total_inconsistencies']} inconsistencies found"
            )

        else:
            console.print(f"❌ [red]Data validation failed: {results['error']}[/red]")
            logger.error(f"Data validation failed: {results['error']}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Data validation command failed: {e}")
        logger.debug("Data validation error details", exc_info=True)
        console.print(f"❌ [red]Data validation failed: {e}[/red]")
        sys.exit(1)


@cli.command(name="health-check")
@cli_command_monitor("health-check")
def health_check():
    """Run comprehensive database health checks and report any issues."""
    logger.info("=== Starting database health check command ===")

    try:
        from .database.health_checks import DatabaseHealthChecker

        logger.debug("Initializing database for health check...")
        telemetry_system = _initialize_telemetry_system()
        db = telemetry_system.telemetry.db
        logger.debug("Database initialized successfully")

        console.print("🏥 [bold]Database Health Check[/bold]")
        console.print("Running comprehensive health checks on telemetry database...")
        console.print()

        # Run health check
        health_checker = DatabaseHealthChecker(db)
        results = health_checker.run_comprehensive_health_check()

        # Display overall health status
        health_status = results["overall_health"]
        if health_status == "healthy":
            console.print("✅ [green]Database is healthy![/green]")
        elif health_status == "fair":
            console.print(
                "⚠️ [yellow]Database health is fair - minor issues found[/yellow]"
            )
        elif health_status == "warning":
            console.print(
                "🟡 [yellow]Database health warning - attention needed[/yellow]"
            )
        elif health_status == "critical":
            console.print(
                "🔴 [red]Database health is critical - immediate action required[/red]"
            )
        else:
            console.print(f"❓ [blue]Database health status: {health_status}[/blue]")

        console.print()

        # Display summary statistics
        summary_table = Table(
            title="Health Check Summary", show_header=True, header_style="bold blue"
        )
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", justify="right")

        summary_table.add_row("Total Issues", str(results["total_issues"]))
        summary_table.add_row(
            "Critical Issues",
            str(results["critical_issues"]),
            style="red" if results["critical_issues"] > 0 else "green",
        )
        summary_table.add_row(
            "Warning Issues",
            str(results["warning_issues"]),
            style="yellow" if results["warning_issues"] > 0 else "green",
        )
        summary_table.add_row(
            "Info Issues",
            str(results["info_issues"]),
            style="blue" if results["info_issues"] > 0 else "green",
        )

        console.print(summary_table)
        console.print()

        # Display detailed check results
        if results["total_issues"] > 0:
            console.print("📋 [bold]Detailed Issues:[/bold]")
            console.print()

            for check_name, check_results in results["checks"].items():
                if check_results.get("issues"):
                    console.print(
                        f"🔍 [bold]{check_name.replace('_', ' ').title()}[/bold]"
                    )

                    for issue in check_results["issues"]:
                        severity_style = {
                            "critical": "red",
                            "warning": "yellow",
                            "info": "blue",
                        }.get(issue["severity"], "white")

                        severity_icon = {
                            "critical": "🚨",
                            "warning": "⚠️",
                            "info": "ℹ️",
                        }.get(issue["severity"], "•")

                        console.print(
                            f"  {severity_icon} [{severity_style}]{issue['description']}[/{severity_style}]"
                        )
                        console.print(f"    💡 {issue['recommendation']}")

                    console.print()

        # Display recommendations
        if results["recommendations"]:
            console.print("📝 [bold]Recommendations:[/bold]")
            for i, recommendation in enumerate(results["recommendations"], 1):
                console.print(f"  {i}. {recommendation}")
            console.print()

        # Display performance metrics if available
        performance_metrics = (
            results["checks"].get("performance", {}).get("metrics", {})
        )
        if performance_metrics:
            console.print("📊 [bold]Performance Metrics:[/bold]")

            metrics_table = Table(show_header=True, header_style="bold blue")
            metrics_table.add_column("Metric", style="cyan")
            metrics_table.add_column("Value", justify="right")

            for metric, value in performance_metrics.items():
                if isinstance(value, float):
                    formatted_value = f"{value:.2f}"
                elif isinstance(value, int):
                    formatted_value = f"{value:,}"
                else:
                    formatted_value = str(value)

                metrics_table.add_row(metric.replace("_", " ").title(), formatted_value)

            console.print(metrics_table)
            console.print()

        # Set exit code based on health status
        if health_status == "critical":
            logger.warning(
                f"Health check completed with critical issues: {results['critical_issues']}"
            )
            sys.exit(2)  # Critical issues
        elif health_status in ["warning", "fair"]:
            logger.info(
                f"Health check completed with warnings: {results['warning_issues']}"
            )
            sys.exit(1)  # Warning issues
        else:
            logger.info("Health check completed successfully - database is healthy")
            sys.exit(0)  # Healthy

    except Exception as e:
        logger.error(f"Health check command failed: {e}")
        logger.debug("Health check error details", exc_info=True)
        console.print(f"❌ [red]Health check failed: {e}[/red]")
        sys.exit(1)


@cli.command(name="cleanup-orphaned")
@cli_command_monitor("cleanup-orphaned")
def cleanup_orphaned():
    """Clean up orphaned records in the database (threat findings without scan executions)."""
    logger.info("=== Starting orphaned records cleanup command ===")

    try:
        from .database.migrations import cleanup_orphaned_records

        logger.debug("Initializing database for orphaned records cleanup...")
        console.print("🧹 [bold]Orphaned Records Cleanup[/bold]")
        console.print(
            "Removing threat findings that reference non-existent scan executions..."
        )
        console.print()

        # Run cleanup
        results = cleanup_orphaned_records()

        if results["cleanup_success"]:
            console.print(
                "✅ [green]Orphaned records cleanup completed successfully![/green]"
            )
            console.print()
            console.print("📊 [bold]Cleanup Results:[/bold]")
            console.print(
                f"  • Orphaned threat findings deleted: {results['orphaned_threats_deleted']}"
            )
            console.print(
                f"  • Total records cleaned: {results['total_records_cleaned']}"
            )

            if results["total_records_cleaned"] > 0:
                console.print()
                console.print(
                    "💡 [blue]Recommendation: Run 'adversary-mcp-cli health-check' to verify database health[/blue]"
                )

            logger.info(
                f"Orphaned records cleanup completed: {results['total_records_cleaned']} records cleaned"
            )

        else:
            console.print(
                f"❌ [red]Orphaned records cleanup failed: {results['error']}[/red]"
            )
            logger.error(f"Orphaned records cleanup failed: {results['error']}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Orphaned records cleanup command failed: {e}")
        logger.debug("Cleanup error details", exc_info=True)
        console.print(f"❌ [red]Cleanup failed: {e}[/red]")
        sys.exit(1)


@cli.command(name="cleanup-stale")
@cli_command_monitor("cleanup-stale")
def cleanup_stale():
    """Mark stale/hanging executions as failed (operations started >24h ago without completion)."""
    logger.info("=== Starting stale executions cleanup command ===")

    try:
        from .database.migrations import mark_stale_executions_as_failed

        logger.debug("Initializing database for stale executions cleanup...")
        console.print("⏰ [bold]Stale Executions Cleanup[/bold]")
        console.print(
            "Marking executions started >24h ago without completion as failed..."
        )
        console.print()

        # Run cleanup
        results = mark_stale_executions_as_failed()

        if results["cleanup_success"]:
            console.print(
                "✅ [green]Stale executions cleanup completed successfully![/green]"
            )
            console.print()

            # Display cleanup statistics
            table = Table(
                title="Cleanup Results", show_header=True, header_style="bold blue"
            )
            table.add_column("Execution Type", style="cyan")
            table.add_column("Marked as Failed", justify="right")

            table.add_row("MCP Tool Executions", str(results["stale_mcp_executions"]))
            table.add_row(
                "CLI Command Executions", str(results["stale_cli_executions"])
            )
            table.add_row(
                "Scan Engine Executions", str(results["stale_scan_executions"])
            )

            console.print(table)
            console.print()
            console.print(
                f"📊 [bold]Total executions fixed: {results['total_executions_fixed']}[/bold]"
            )

            if results["total_executions_fixed"] > 0:
                console.print()
                console.print(
                    "💡 [blue]Recommendation: Run 'adversary-mcp-cli health-check' to verify improvements[/blue]"
                )

            logger.info(
                f"Stale executions cleanup completed: {results['total_executions_fixed']} executions marked as failed"
            )

        else:
            console.print(
                f"❌ [red]Stale executions cleanup failed: {results['error']}[/red]"
            )
            logger.error(f"Stale executions cleanup failed: {results['error']}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Stale executions cleanup command failed: {e}")
        logger.debug("Cleanup error details", exc_info=True)
        console.print(f"❌ [red]Cleanup failed: {e}[/red]")
        sys.exit(1)


@cli.command(name="install-constraints")
@cli_command_monitor("install-constraints")
def install_constraints():
    """Install database constraints and triggers to prevent future data inconsistencies."""
    logger.info("=== Starting database constraints installation command ===")

    try:
        from .database.constraints import install_database_constraints

        logger.debug("Installing database constraints and triggers...")
        console.print("🔧 [bold]Database Constraints Installation[/bold]")
        console.print(
            "Installing constraints and triggers to maintain data consistency..."
        )
        console.print()

        # Install constraints
        results = install_database_constraints()

        if results["installation_success"]:
            console.print(
                "✅ [green]Database constraints installation completed successfully![/green]"
            )
            console.print()

            # Display installation results
            if results["constraints_installed"]:
                console.print("📋 [bold]Constraints Installed:[/bold]")
                for constraint in results["constraints_installed"]:
                    console.print(
                        f"  • {constraint['name']}: {constraint['description']}"
                    )
                console.print()

            if results["triggers_installed"]:
                console.print("⚡ [bold]Triggers Installed:[/bold]")
                for trigger in results["triggers_installed"]:
                    console.print(f"  • {trigger['name']}: {trigger['description']}")
                console.print()

            if results["errors"]:
                console.print("⚠️ [yellow]Warnings during installation:[/yellow]")
                for error in results["errors"]:
                    console.print(f"  • {error}")
                console.print()

            console.print(
                "💡 [blue]Recommendation: Run 'adversary-mcp-cli validate-constraints' to verify installation[/blue]"
            )

            logger.info(
                f"Constraints installation completed: {len(results['constraints_installed'])} constraints, {len(results['triggers_installed'])} triggers"
            )

        else:
            console.print("❌ [red]Database constraints installation failed[/red]")
            for error in results["errors"]:
                console.print(f"  • [red]{error}[/red]")
            logger.error(f"Constraints installation failed: {results['errors']}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Constraints installation command failed: {e}")
        logger.debug("Installation error details", exc_info=True)
        console.print(f"❌ [red]Installation failed: {e}[/red]")
        sys.exit(1)


@cli.command(name="validate-constraints")
@cli_command_monitor("validate-constraints")
def validate_constraints():
    """Validate that database constraints are active and working correctly."""
    logger.info("=== Starting database constraints validation command ===")

    try:
        from .database.constraints import validate_database_constraints

        logger.debug("Validating database constraints...")
        console.print("🔍 [bold]Database Constraints Validation[/bold]")
        console.print(
            "Checking that constraints and triggers are active and working..."
        )
        console.print()

        # Validate constraints
        results = validate_database_constraints()

        if results["validation_success"]:
            # Display foreign keys status
            if results["foreign_keys_enabled"]:
                console.print("✅ [green]Foreign key constraints are enabled[/green]")
            else:
                console.print(
                    "⚠️ [yellow]Foreign key constraints are not enabled[/yellow]"
                )

            # Display active triggers
            if results["triggers_active"]:
                console.print("⚡ [bold]Active Triggers:[/bold]")
                for trigger in results["triggers_active"]:
                    console.print(f"  • {trigger}")
            else:
                console.print(
                    "⚠️ [yellow]No count maintenance triggers are active[/yellow]"
                )

            console.print()

            # Display constraint violations if any
            if results["constraint_violations"]:
                console.print("🚨 [red]Constraint Violations Found:[/red]")
                for violation in results["constraint_violations"]:
                    console.print(f"  • {violation['description']}")
                console.print()
                console.print(
                    "💡 [blue]Recommendation: Run data migration to fix violations[/blue]"
                )
            else:
                console.print("✅ [green]No constraint violations found[/green]")

            # Overall status
            total_violations = len(results["constraint_violations"])
            if total_violations == 0:
                console.print()
                console.print(
                    "🎉 [green]All database constraints are working correctly![/green]"
                )

            logger.info(
                f"Constraints validation completed: {len(results['triggers_active'])} triggers active, {total_violations} violations"
            )

        else:
            console.print("❌ [red]Database constraints validation failed[/red]")
            for error in results["errors"]:
                console.print(f"  • [red]{error}[/red]")
            logger.error(f"Constraints validation failed: {results['errors']}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Constraints validation command failed: {e}")
        logger.debug("Validation error details", exc_info=True)
        console.print(f"❌ [red]Validation failed: {e}[/red]")
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    # SSL truststore injection for corporate environments
    try:
        truststore.inject_into_ssl()
    except Exception as e:
        logger.error(f"Failed to inject truststore into SSL context: {e}")
        # Continue execution - some corporate environments may have alternative SSL config

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
