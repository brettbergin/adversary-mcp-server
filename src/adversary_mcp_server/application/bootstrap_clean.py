"""Clean Architecture bootstrap for integration testing."""

from ..application.adapters.llm_adapter import LLMScanStrategy
from ..application.adapters.llm_validation_adapter import LLMValidationStrategy
from ..application.adapters.semgrep_adapter import SemgrepScanStrategy
from ..domain.interfaces import IScanStrategy, IValidationStrategy
from ..domain.services.scan_orchestrator import ScanOrchestrator
from ..domain.services.threat_aggregator import ThreatAggregator
from ..domain.services.validation_service import ValidationService


class CleanArchitectureBootstrap:
    """
    Bootstrap class for Clean Architecture dependency injection.

    Provides factory methods to create properly configured domain services
    and adapters for integration testing and production use.
    """

    def __init__(self):
        """Initialize bootstrap with default configuration."""
        self._scan_strategies: list[IScanStrategy] | None = None
        self._validation_strategies: list[IValidationStrategy] | None = None
        self._scan_orchestrator: ScanOrchestrator | None = None
        self._threat_aggregator: ThreatAggregator | None = None
        self._validation_service: ValidationService | None = None

    def get_scan_strategies(self) -> list[IScanStrategy]:
        """Get configured scan strategies."""
        if self._scan_strategies is None:
            self._scan_strategies = []

            # Add Semgrep strategy (always available)
            try:
                semgrep_strategy = SemgrepScanStrategy()
                self._scan_strategies.append(semgrep_strategy)
            except Exception:
                # Semgrep might not be available in test environment
                pass

            # Add LLM strategy if available
            try:
                llm_strategy = LLMScanStrategy()
                self._scan_strategies.append(llm_strategy)
            except Exception:
                # LLM scanner might not be available
                pass

        return self._scan_strategies

    def get_validation_strategies(self) -> list[IValidationStrategy]:
        """Get configured validation strategies."""
        if self._validation_strategies is None:
            self._validation_strategies = []

            # Add LLM validation if available
            try:
                llm_validation = LLMValidationStrategy()
                self._validation_strategies.append(llm_validation)
            except Exception:
                # LLM validator might not be available
                pass

        return self._validation_strategies

    def get_scan_orchestrator(self) -> ScanOrchestrator:
        """Get domain scan orchestrator."""
        if self._scan_orchestrator is None:
            self._scan_orchestrator = ScanOrchestrator()

            # Register scan strategies
            strategies = self.get_scan_strategies()
            for strategy in strategies:
                self._scan_orchestrator.register_scan_strategy(strategy)

            # Register validation strategies
            validation_strategies = self.get_validation_strategies()
            for strategy in validation_strategies:
                self._scan_orchestrator.register_validation_strategy(strategy)

            # Set threat aggregator
            aggregator = self.get_threat_aggregator()
            self._scan_orchestrator.set_threat_aggregator(aggregator)

        return self._scan_orchestrator

    def get_threat_aggregator(self) -> ThreatAggregator:
        """Get threat aggregator service."""
        if self._threat_aggregator is None:
            self._threat_aggregator = ThreatAggregator()

        return self._threat_aggregator

    def get_validation_service(self) -> ValidationService:
        """Get validation service."""
        if self._validation_service is None:
            self._validation_service = ValidationService()

        return self._validation_service

    def create_with_mock_strategies(
        self,
        scan_strategies: list[IScanStrategy],
        validation_strategies: list[IValidationStrategy] | None = None,
    ) -> "CleanArchitectureBootstrap":
        """Create bootstrap with mock strategies for testing."""
        bootstrap = CleanArchitectureBootstrap()
        bootstrap._scan_strategies = scan_strategies
        bootstrap._validation_strategies = validation_strategies or []
        return bootstrap
