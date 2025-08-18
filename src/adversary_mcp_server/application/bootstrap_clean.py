"""Clean Architecture bootstrap for integration testing."""

import logging
from functools import lru_cache
from typing import Protocol

from ..application.adapters.llm_adapter import LLMScanStrategy
from ..application.adapters.llm_validation_adapter import LLMValidationStrategy
from ..application.adapters.semgrep_adapter import SemgrepScanStrategy
from ..domain.interfaces import IScanStrategy, IValidationStrategy
from ..domain.services.scan_orchestrator import ScanOrchestrator
from ..domain.services.threat_aggregator import ThreatAggregator
from ..domain.services.validation_service import ValidationService

logger = logging.getLogger(__name__)


class StrategyFactory(Protocol):
    """Protocol for strategy factories."""

    def create(self) -> IScanStrategy | IValidationStrategy:
        """Create a strategy instance."""
        ...


def _create_strategy_safely(factory_class, strategy_name: str):
    """
    Safely create a strategy instance with proper error handling.

    Args:
        factory_class: The strategy class to instantiate
        strategy_name: Name for logging purposes

    Returns:
        Strategy instance or None if creation failed
    """
    try:
        return factory_class()
    except Exception as e:
        logger.debug(f"Strategy '{strategy_name}' not available: {e}")
        return None


class CleanArchitectureBootstrap:
    """
    Simplified bootstrap for Clean Architecture dependency injection.

    Uses functional programming principles with caching instead of
    stateful lazy initialization for better testability and clarity.
    """

    @staticmethod
    @lru_cache(maxsize=1)
    def get_scan_strategies() -> list[IScanStrategy]:
        """Get configured scan strategies (cached)."""
        strategies = []

        # Available strategy factories
        strategy_configs = [
            (SemgrepScanStrategy, "semgrep"),
            (LLMScanStrategy, "llm"),
        ]

        for factory_class, name in strategy_configs:
            strategy = _create_strategy_safely(factory_class, name)
            if strategy:
                strategies.append(strategy)

        logger.info(f"Initialized {len(strategies)} scan strategies")
        return strategies

    @staticmethod
    @lru_cache(maxsize=1)
    def get_validation_strategies() -> list[IValidationStrategy]:
        """Get configured validation strategies (cached)."""
        strategies = []

        # Available validation strategy factories
        strategy_configs = [
            (LLMValidationStrategy, "llm_validation"),
        ]

        for factory_class, name in strategy_configs:
            strategy = _create_strategy_safely(factory_class, name)
            if strategy:
                strategies.append(strategy)

        logger.info(f"Initialized {len(strategies)} validation strategies")
        return strategies

    @staticmethod
    @lru_cache(maxsize=1)
    def get_threat_aggregator() -> ThreatAggregator:
        """Get threat aggregator service (cached)."""
        return ThreatAggregator()

    @staticmethod
    @lru_cache(maxsize=1)
    def get_validation_service() -> ValidationService:
        """Get validation service (cached)."""
        return ValidationService()

    @classmethod
    @lru_cache(maxsize=1)
    def get_scan_orchestrator(cls) -> ScanOrchestrator:
        """Get fully configured domain scan orchestrator (cached)."""
        orchestrator = ScanOrchestrator()

        # Register all available strategies
        for strategy in cls.get_scan_strategies():
            orchestrator.register_scan_strategy(strategy)

        for strategy in cls.get_validation_strategies():
            orchestrator.register_validation_strategy(strategy)

        # Set threat aggregator
        orchestrator.set_threat_aggregator(cls.get_threat_aggregator())

        logger.info("Scan orchestrator configured successfully")
        return orchestrator

    @classmethod
    def create_for_testing(
        cls,
        scan_strategies: list[IScanStrategy] | None = None,
        validation_strategies: list[IValidationStrategy] | None = None,
    ) -> ScanOrchestrator:
        """
        Create orchestrator with custom strategies for testing.

        This bypasses caching to allow different configurations per test.
        """
        orchestrator = ScanOrchestrator()

        # Use provided strategies or defaults
        scan_strats = scan_strategies or cls.get_scan_strategies()
        val_strats = validation_strategies or cls.get_validation_strategies()

        for strategy in scan_strats:
            orchestrator.register_scan_strategy(strategy)

        for strategy in val_strats:
            orchestrator.register_validation_strategy(strategy)

        orchestrator.set_threat_aggregator(cls.get_threat_aggregator())
        return orchestrator

    @staticmethod
    def clear_cache():
        """Clear all cached instances (useful for testing)."""
        CleanArchitectureBootstrap.get_scan_strategies.cache_clear()
        CleanArchitectureBootstrap.get_validation_strategies.cache_clear()
        CleanArchitectureBootstrap.get_threat_aggregator.cache_clear()
        CleanArchitectureBootstrap.get_validation_service.cache_clear()
        CleanArchitectureBootstrap.get_scan_orchestrator.cache_clear()
