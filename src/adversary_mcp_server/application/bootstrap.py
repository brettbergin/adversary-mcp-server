"""Dependency injection configuration and application bootstrap.

This module sets up the dependency injection container with all service
registrations, providing a centralized place to configure the application's
dependency graph.
"""

from pathlib import Path

from ..cache.cache_manager import CacheManager
from ..config import get_app_cache_dir
from ..container import ServiceContainer
from ..credentials import get_credential_manager
from ..interfaces import (
    ICacheManager,
    ICredentialManager,
    ILLMScanner,
    ILLMValidator,
    IMetricsCollector,
    IScanEngine,
    ISemgrepScanner,
    IValidator,
)
from ..logger import get_logger
from ..monitoring.metrics_collector import MetricsCollector
from ..scanner.llm_scanner import LLMScanner
from ..scanner.llm_validator import LLMValidator
from ..scanner.scan_engine import ScanEngine
from ..scanner.semgrep_scanner import SemgrepScanner

logger = get_logger("bootstrap")


def configure_container(
    container: ServiceContainer, config_dir: Path | None = None
) -> None:
    """Configure the service container with all application dependencies.

    This function sets up the complete dependency injection configuration,
    registering all services with appropriate lifetimes.

    Args:
        container: ServiceContainer to configure
        config_dir: Optional configuration directory for credential manager
    """
    logger.info("Configuring dependency injection container")

    # === Core Services (Singletons) ===
    # These services are stateless and can be shared across the application

    # Credential Manager - Singleton for secure configuration management
    credential_manager = get_credential_manager(config_dir)
    container.register_instance(ICredentialManager, credential_manager)  # type: ignore[type-abstract]

    # Cache Manager - Singleton for shared caching across operations
    container.register_factory(ICacheManager, _create_cache_manager)  # type: ignore[type-abstract]

    # Metrics Collector - Singleton for centralized metrics collection
    container.register_factory(IMetricsCollector, _create_metrics_collector)  # type: ignore[type-abstract]

    # === Scanner Services ===
    # These services handle the core scanning functionality

    # Semgrep Scanner - Singleton as it's stateless pattern matching
    container.register_singleton(ISemgrepScanner, SemgrepScanner)

    # LLM Scanner - Scoped to allow different configurations per operation
    container.register_scoped(ILLMScanner, LLMScanner)

    # LLM Validator - Scoped for operation-specific validation
    container.register_singleton(ILLMValidator, LLMValidator)  # type: ignore[type-abstract]
    container.register_singleton(
        IValidator, LLMValidator  # type: ignore[type-abstract]
    )  # Also register under base interface

    # Main Scan Engine - Scoped to allow different configurations
    # NOTE: This will be replaced with orchestrator in Phase 1 decomposition
    container.register_scoped(IScanEngine, ScanEngine)  # type: ignore[type-abstract]

    logger.info(
        f"Container configured with {len(container.get_registered_services())} services"
    )


def create_configured_container(config_dir: Path | None = None) -> ServiceContainer:
    """Create and configure a new service container.

    Convenience function that creates a ServiceContainer and configures it
    with all application dependencies.

    Args:
        config_dir: Optional configuration directory for credential manager

    Returns:
        Fully configured ServiceContainer ready for use
    """
    container = ServiceContainer()
    configure_container(container, config_dir)
    return container


# === Factory Functions ===
# These functions create services with complex initialization logic


def _create_cache_manager(
    credential_manager: ICredentialManager,
    metrics_collector: IMetricsCollector | None = None,
) -> CacheManager:
    """Factory function for creating cache manager.

    Args:
        credential_manager: Credential manager for configuration
        metrics_collector: Optional metrics collector for cache metrics

    Returns:
        Configured CacheManager instance
    """
    try:
        # Load configuration to determine cache settings
        config = credential_manager.load_config()
        cache_dir = get_app_cache_dir()

        # Create cache manager with configuration-based settings
        cache_manager = CacheManager(
            cache_dir=cache_dir,
            max_size_mb=getattr(config, "cache_size_mb", 100),
            max_age_hours=getattr(config, "cache_ttl_seconds", 3600)
            // 3600,  # Convert seconds to hours
            enable_persistence=True,
            metrics_collector=metrics_collector,
        )

        logger.debug(f"Created cache manager with dir: {cache_dir}")
        return cache_manager

    except Exception as e:
        logger.warning(f"Failed to load config for cache manager: {e}, using defaults")
        # Fallback to default configuration
        return CacheManager(
            cache_dir=get_app_cache_dir(),
            max_size_mb=100,
            max_age_hours=1,  # 1 hour default
            enable_persistence=True,
            metrics_collector=metrics_collector,
        )


def _create_metrics_collector(
    credential_manager: ICredentialManager,
) -> IMetricsCollector:
    """Factory function for creating metrics collector.

    Args:
        credential_manager: Credential manager for configuration

    Returns:
        Configured MetricsCollector instance
    """
    try:
        # Load configuration for monitoring settings
        config = credential_manager.load_config()

        # Extract monitoring configuration if available
        monitoring_config = getattr(config, "monitoring", None)
        if monitoring_config is None:
            # Create default monitoring configuration
            from ..monitoring.types import MonitoringConfig

            monitoring_config = MonitoringConfig(
                enable_metrics=True,
                collection_interval_seconds=60,
                metrics_retention_hours=24,
            )

        metrics_collector = MetricsCollector(monitoring_config)
        logger.debug("Created metrics collector with configuration")
        return metrics_collector  # type: ignore[return-value]

    except Exception as e:
        logger.warning(
            f"Failed to load config for metrics collector: {e}, using defaults"
        )
        # Fallback to default configuration
        from ..monitoring.types import MonitoringConfig

        default_config = MonitoringConfig(
            enable_metrics=True,
            collection_interval_seconds=60,
            metrics_retention_hours=24,
        )
        return MetricsCollector(default_config)  # type: ignore[return-value]


# === Container Lifecycle Management ===


async def initialize_container_async(container: ServiceContainer) -> None:
    """Initialize container and start async services.

    Args:
        container: Container to initialize
    """
    logger.info("Initializing container async services")

    # Start metrics collection if available
    try:
        metrics_collector = container.resolve(IMetricsCollector)  # type: ignore[type-abstract]
        if hasattr(metrics_collector, "start_collection"):
            await metrics_collector.start_collection()
            logger.debug("Started metrics collection")
    except Exception as e:
        logger.warning(f"Failed to start metrics collection: {e}")


async def shutdown_container_async(container: ServiceContainer) -> None:
    """Shutdown container and dispose of resources.

    Args:
        container: Container to shutdown
    """
    logger.info("Shutting down container")

    # Stop metrics collection
    try:
        metrics_collector = container.resolve(IMetricsCollector)  # type: ignore[type-abstract]
        if hasattr(metrics_collector, "stop_collection"):
            await metrics_collector.stop_collection()
            logger.debug("Stopped metrics collection")
    except Exception as e:
        logger.warning(f"Error stopping metrics collection: {e}")

    # Dispose of all services
    await container.dispose_async()
    logger.info("Container shutdown complete")
