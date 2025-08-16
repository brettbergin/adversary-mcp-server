"""Core domain interfaces defining contracts for domain services."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .exceptions import (
    AggregationError,
    ConfigurationError,
    ScanError,
    SecurityError,
    ValidationError,
)

if TYPE_CHECKING:
    from .entities.scan_request import ScanRequest
    from .entities.scan_result import ScanResult
    from .entities.threat_match import ThreatMatch
    from .value_objects.false_positive_info import FalsePositiveInfo
    from .value_objects.scan_context import ScanContext


@runtime_checkable
class IScanStrategy(Protocol):
    """
    Protocol defining the contract for security scanning strategies.

    Different scanning strategies can implement this interface to provide
    various approaches to security analysis (static analysis, LLM-based,
    hybrid approaches, etc.).
    """

    def can_scan(self, context: "ScanContext") -> bool:
        """
        Check if this strategy can scan the given context.

        Args:
            context: The scan context to evaluate

        Returns:
            True if this strategy can handle the scan context
        """
        ...

    async def execute_scan(self, request: "ScanRequest") -> "ScanResult":
        """
        Execute the security scan using this strategy.

        Args:
            request: The scan request containing context and configuration

        Returns:
            Scan result containing detected threats and metadata

        Raises:
            ScanError: If the scan fails for any reason
        """
        ...

    def get_strategy_name(self) -> str:
        """Get the name of this scanning strategy."""
        ...

    def get_supported_languages(self) -> list[str]:
        """Get list of programming languages supported by this strategy."""
        ...


@runtime_checkable
class IValidationStrategy(Protocol):
    """
    Protocol defining the contract for threat validation strategies.

    Validation strategies analyze detected threats to filter false positives
    and enhance threat information with confidence scores and additional context.
    """

    def can_validate(self, threats: list["ThreatMatch"]) -> bool:
        """
        Check if this strategy can validate the given threats.

        Args:
            threats: List of threats to potentially validate

        Returns:
            True if this strategy can validate these threats
        """
        ...

    async def validate_threats(
        self, threats: list["ThreatMatch"], context: "ScanContext"
    ) -> list["ThreatMatch"]:
        """
        Validate threats and return enhanced versions.

        Args:
            threats: List of threats to validate
            context: Original scan context for additional validation context

        Returns:
            List of validated threats with updated confidence scores

        Raises:
            ValidationError: If validation fails for any reason
        """
        ...

    def get_strategy_name(self) -> str:
        """Get the name of this validation strategy."""
        ...

    def get_confidence_threshold(self) -> float:
        """Get the confidence threshold used by this strategy."""
        ...


@runtime_checkable
class IThreatAggregator(Protocol):
    """
    Protocol defining the contract for threat aggregation strategies.

    Aggregation strategies combine and deduplicate threats from multiple
    sources, handling overlaps and conflicts between different scanning
    approaches.
    """

    def aggregate_threats(
        self, threat_groups: list[list["ThreatMatch"]]
    ) -> list["ThreatMatch"]:
        """
        Aggregate threats from multiple sources.

        Args:
            threat_groups: Groups of threats from different sources/scanners

        Returns:
            Deduplicated and merged list of threats

        Raises:
            AggregationError: If aggregation fails for any reason
        """
        ...

    def merge_similar_threats(
        self, threats: list["ThreatMatch"]
    ) -> list["ThreatMatch"]:
        """
        Merge threats that are similar or duplicates.

        Args:
            threats: List of threats to deduplicate

        Returns:
            Deduplicated list with merged threat information
        """
        ...

    def get_aggregation_strategy_name(self) -> str:
        """Get the name of this aggregation strategy."""
        ...


@runtime_checkable
class IScanOrchestrator(Protocol):
    """
    Protocol defining the contract for scan orchestration.

    Orchestrators coordinate the execution of multiple scanning strategies,
    validation, and aggregation to produce comprehensive scan results.
    """

    async def execute_scan(self, request: "ScanRequest") -> "ScanResult":
        """
        Execute a complete scan operation.

        Args:
            request: The scan request with configuration and context

        Returns:
            Complete scan result with all threats and metadata

        Raises:
            ScanError: If the orchestrated scan fails
        """
        ...

    def register_scan_strategy(self, strategy: IScanStrategy) -> None:
        """
        Register a scanning strategy with this orchestrator.

        Args:
            strategy: The scanning strategy to register
        """
        ...

    def register_validation_strategy(self, strategy: IValidationStrategy) -> None:
        """
        Register a validation strategy with this orchestrator.

        Args:
            strategy: The validation strategy to register
        """
        ...

    def set_threat_aggregator(self, aggregator: IThreatAggregator) -> None:
        """
        Set the threat aggregator for this orchestrator.

        Args:
            aggregator: The threat aggregator to use
        """
        ...


class IValidationService(ABC):
    """
    Abstract base class for validation services.

    Validation services provide business logic for validating scan requests,
    threat data, and ensuring business rules are enforced throughout the
    scanning process.
    """

    @abstractmethod
    def validate_scan_request(self, request: "ScanRequest") -> None:
        """
        Validate a scan request according to business rules.

        Args:
            request: The scan request to validate

        Raises:
            ValidationError: If the request violates business rules
        """
        pass

    @abstractmethod
    def validate_threat_data(self, threat: "ThreatMatch") -> None:
        """
        Validate threat data for consistency and completeness.

        Args:
            threat: The threat to validate

        Raises:
            ValidationError: If the threat data is invalid
        """
        pass

    @abstractmethod
    def validate_scan_result(self, result: "ScanResult") -> None:
        """
        Validate a scan result for consistency and completeness.

        Args:
            result: The scan result to validate

        Raises:
            ValidationError: If the result is invalid
        """
        pass

    @abstractmethod
    def enforce_security_constraints(self, context: "ScanContext") -> None:
        """
        Enforce security constraints for scan operations.

        Args:
            context: The scan context to check

        Raises:
            SecurityError: If security constraints are violated
        """
        pass


@runtime_checkable
class IFalsePositiveRepository(Protocol):
    """
    Protocol defining the contract for false positive data persistence.

    Repository implementations handle storage and retrieval of false positive
    information while maintaining domain model integrity.
    """

    async def get_false_positive_info(self, uuid: str) -> "FalsePositiveInfo | None":
        """
        Retrieve false positive information for a finding.

        Args:
            uuid: UUID of the finding

        Returns:
            FalsePositiveInfo if found, None otherwise
        """
        ...

    async def save_false_positive_info(self, info: "FalsePositiveInfo") -> bool:
        """
        Save false positive information.

        Args:
            info: False positive information to save

        Returns:
            True if saved successfully, False otherwise
        """
        ...

    async def remove_false_positive_info(self, uuid: str) -> bool:
        """
        Remove false positive information for a finding.

        Args:
            uuid: UUID of the finding

        Returns:
            True if removed successfully, False if not found
        """
        ...

    async def list_false_positives(self) -> list["FalsePositiveInfo"]:
        """
        List all false positive information.

        Returns:
            List of all false positive entries
        """
        ...


# Helper Types for Type Hints

ScanStrategyType = IScanStrategy
ValidationStrategyType = IValidationStrategy
ThreatAggregatorType = IThreatAggregator
ScanOrchestratorType = IScanOrchestrator

# Export exceptions for convenience
__all__ = [
    "IScanStrategy",
    "IValidationStrategy",
    "IThreatAggregator",
    "IScanOrchestrator",
    "IValidationService",
    "IFalsePositiveRepository",
    "ScanError",
    "ValidationError",
    "AggregationError",
    "SecurityError",
    "ConfigurationError",
    "ScanStrategyType",
    "ValidationStrategyType",
    "ThreatAggregatorType",
    "ScanOrchestratorType",
]
