"""ScanOrchestrator domain service for pure business orchestration."""

import asyncio
import logging
from datetime import datetime
from typing import Any

from ..entities.scan_request import ScanRequest
from ..entities.scan_result import ScanResult
from ..entities.threat_match import ThreatMatch
from ..interfaces import (
    ConfigurationError,
    IScanStrategy,
    IThreatAggregator,
    IValidationStrategy,
    ScanError,
    ValidationError,
)

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Domain service responsible for orchestrating complete scan operations.

    Coordinates multiple scanning strategies, validation, and threat aggregation
    to produce comprehensive scan results. Implements pure business logic
    without dependencies on infrastructure concerns.
    """

    def __init__(self):
        self._scan_strategies: list[IScanStrategy] = []
        self._validation_strategies: list[IValidationStrategy] = []
        self._threat_aggregator: IThreatAggregator | None = None

    def register_scan_strategy(self, strategy: IScanStrategy) -> None:
        """Register a scanning strategy with this orchestrator."""
        if strategy not in self._scan_strategies:
            self._scan_strategies.append(strategy)
            logger.debug(f"Registered scan strategy: {strategy.get_strategy_name()}")

    def register_validation_strategy(self, strategy: IValidationStrategy) -> None:
        """Register a validation strategy with this orchestrator."""
        if strategy not in self._validation_strategies:
            self._validation_strategies.append(strategy)
            logger.debug(
                f"Registered validation strategy: {strategy.get_strategy_name()}"
            )

    def set_threat_aggregator(self, aggregator: IThreatAggregator) -> None:
        """Set the threat aggregator for this orchestrator."""
        self._threat_aggregator = aggregator
        logger.debug(
            f"Set threat aggregator: {aggregator.get_aggregation_strategy_name()}"
        )

    async def execute_scan(self, request: ScanRequest) -> ScanResult:
        """
        Execute a complete scan operation with orchestrated strategies.

        Args:
            request: The scan request with configuration and context

        Returns:
            Complete scan result with all threats and metadata

        Raises:
            ScanError: If the orchestrated scan fails
            ConfigurationError: If configuration is invalid
        """
        start_time = datetime.utcnow()

        try:
            # Validate the scan request
            self._validate_request(request)

            # Get applicable strategies for this request
            applicable_strategies = self._get_applicable_strategies(request)

            if not applicable_strategies:
                raise ConfigurationError(
                    "No applicable scan strategies found for this request"
                )

            logger.info(f"Executing scan with {len(applicable_strategies)} strategies")

            # Execute all applicable scanning strategies in parallel
            scan_results = await self._execute_scan_strategies(
                request, applicable_strategies
            )

            # Aggregate threats from all strategies
            aggregated_threats = self._aggregate_threats(scan_results)

            # Apply validation strategies if enabled
            validated_threats = aggregated_threats
            if request.enable_validation and self._validation_strategies:
                validated_threats = await self._apply_validation(
                    aggregated_threats, request
                )

            # Apply severity filtering
            filtered_threats = self._apply_severity_filtering(
                validated_threats, request
            )

            # Build comprehensive scan metadata
            scan_metadata = self._build_scan_metadata(request, scan_results, start_time)

            # Create final result
            result = ScanResult.create_from_threats(
                request=request,
                threats=filtered_threats,
                scan_metadata=scan_metadata,
                validation_applied=request.enable_validation
                and bool(self._validation_strategies),
            )

            logger.info(f"Scan completed: {len(filtered_threats)} threats found")
            return result

        except Exception as e:
            logger.error(f"Scan orchestration failed: {e}")
            if isinstance(e, ScanError | ValidationError | ConfigurationError):
                raise
            raise ScanError(f"Scan orchestration failed: {e}") from e

    def _validate_request(self, request: ScanRequest) -> None:
        """Validate that the scan request can be processed."""
        # Basic validation is handled by ScanRequest itself
        # Additional orchestration-level validation can go here

        if request.enable_validation and not self._validation_strategies:
            logger.warning(
                "Validation requested but no validation strategies registered"
            )

        # Check if we have strategies that can handle this request
        if not any(
            strategy.can_scan(request.context) for strategy in self._scan_strategies
        ):
            raise ConfigurationError(
                f"No registered strategies can scan {request.context.metadata.scan_type} targets"
            )

    def _get_applicable_strategies(self, request: ScanRequest) -> list[IScanStrategy]:
        """Get scanning strategies that can handle this request."""
        applicable = []

        for strategy in self._scan_strategies:
            if strategy.can_scan(request.context):
                # Check if this strategy type is enabled in the request
                strategy_name = strategy.get_strategy_name().lower()

                if "semgrep" in strategy_name and not request.enable_semgrep:
                    continue
                if "llm" in strategy_name and not request.enable_llm:
                    continue

                applicable.append(strategy)

        return applicable

    async def _execute_scan_strategies(
        self, request: ScanRequest, strategies: list[IScanStrategy]
    ) -> list[ScanResult]:
        """Execute multiple scan strategies in parallel."""

        async def execute_strategy(strategy: IScanStrategy) -> ScanResult:
            try:
                logger.debug(f"Executing strategy: {strategy.get_strategy_name()}")
                result = await strategy.execute_scan(request)
                logger.debug(
                    f"Strategy {strategy.get_strategy_name()} found {len(result.threats)} threats"
                )
                return result
            except Exception as e:
                logger.error(f"Strategy {strategy.get_strategy_name()} failed: {e}")
                # Return empty result instead of failing the entire scan
                return ScanResult.create_empty(request)

        # Execute all strategies in parallel
        results = await asyncio.gather(
            *[execute_strategy(strategy) for strategy in strategies],
            return_exceptions=True,
        )

        # Filter out exceptions and log them
        valid_results: list[ScanResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                strategy_name = strategies[i].get_strategy_name()
                logger.error(
                    f"Strategy {strategy_name} failed with exception: {result}"
                )
            elif isinstance(result, ScanResult):
                valid_results.append(result)

        return valid_results

    def _aggregate_threats(self, scan_results: list[ScanResult]) -> list[ThreatMatch]:
        """Aggregate threats from multiple scan results."""
        if not scan_results:
            return []

        # Extract all threats from all results
        all_threats = []
        for result in scan_results:
            all_threats.extend(result.threats)

        if not all_threats:
            return []

        # Use threat aggregator if available
        if self._threat_aggregator:
            try:
                # Group threats by source for aggregation
                threat_groups = []
                for result in scan_results:
                    if result.threats:
                        threat_groups.append(result.threats)

                aggregated = self._threat_aggregator.aggregate_threats(threat_groups)
                logger.debug(
                    f"Aggregated {len(all_threats)} threats down to {len(aggregated)}"
                )
                return aggregated

            except Exception as e:
                logger.error(f"Threat aggregation failed: {e}")
                # Fall back to simple deduplication
                pass
        # Simple deduplication by fingerprint as fallback
        seen_fingerprints = set()
        deduplicated = []

        for threat in all_threats:
            fingerprint = threat.get_fingerprint()
            if fingerprint not in seen_fingerprints:
                deduplicated.append(threat)
                seen_fingerprints.add(fingerprint)

        logger.debug(
            f"Simple deduplication: {len(all_threats)} -> {len(deduplicated)} threats"
        )
        return deduplicated

    async def _apply_validation(
        self, threats: list[ThreatMatch], request: ScanRequest
    ) -> list[ThreatMatch]:
        """Apply validation strategies to filter and enhance threats."""
        if not threats or not self._validation_strategies:
            return threats

        validated_threats = threats

        for strategy in self._validation_strategies:
            if strategy.can_validate(validated_threats):
                try:
                    logger.debug(
                        f"Applying validation strategy: {strategy.get_strategy_name()}"
                    )
                    validated_threats = await strategy.validate_threats(
                        validated_threats, request.context
                    )
                    logger.debug(
                        f"Validation {strategy.get_strategy_name()} resulted in {len(validated_threats)} threats"
                    )
                except Exception as e:
                    logger.error(
                        f"Validation strategy {strategy.get_strategy_name()} failed: {e}"
                    )
                    # Continue with other validation strategies
                    continue

        return validated_threats

    def _apply_severity_filtering(
        self, threats: list[ThreatMatch], request: ScanRequest
    ) -> list[ThreatMatch]:
        """Apply severity threshold filtering."""
        if not threats:
            return threats

        severity_threshold = request.get_effective_severity_threshold()

        filtered_threats = [
            threat
            for threat in threats
            if threat.severity.meets_threshold(severity_threshold)
        ]

        if len(filtered_threats) != len(threats):
            logger.debug(
                f"Severity filtering: {len(threats)} -> {len(filtered_threats)} threats "
                f"(threshold: {severity_threshold})"
            )

        return filtered_threats

    def _build_scan_metadata(
        self, request: ScanRequest, scan_results: list[ScanResult], start_time: datetime
    ) -> dict[str, Any]:
        """Build comprehensive metadata for the scan operation."""
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        # Calculate aggregate statistics
        total_original_threats = sum(len(result.threats) for result in scan_results)
        strategy_results = {}

        for result in scan_results:
            # Try to identify strategy from metadata or threats
            strategy_name = "unknown"
            if result.threats:
                # Infer strategy from threat sources
                sources = {threat.source_scanner for threat in result.threats}
                if sources:
                    strategy_name = "+".join(sorted(sources))

            strategy_results[strategy_name] = {
                "threats_found": len(result.threats),
                "metadata": result.scan_metadata,
            }

        # Extract validation metadata from the adapter cache if available
        validation_metadata = None
        try:
            from ...application.adapters.llm_validation_adapter import (
                LLMValidationStrategy,
            )

            scan_id = request.context.metadata.scan_id
            logger.debug(f"Looking for validation metadata for scan_id: {scan_id}")

            if hasattr(LLMValidationStrategy, "_validation_metadata_cache"):
                cache = LLMValidationStrategy._validation_metadata_cache
                logger.debug(
                    f"Validation metadata cache exists with keys: {list(cache.keys())}"
                )
                validation_metadata = cache.get(scan_id)
                if validation_metadata:
                    logger.debug(f"Found validation metadata: {validation_metadata}")
                    # Clean up the cache entry to prevent memory leaks
                    del LLMValidationStrategy._validation_metadata_cache[scan_id]
                else:
                    logger.warning(
                        f"No validation metadata found for scan_id: {scan_id}"
                    )
                    # Try backup cache
                    if hasattr(LLMValidationStrategy, "_module_validation_cache"):
                        backup_cache = LLMValidationStrategy._module_validation_cache
                        logger.debug(
                            f"Checking backup cache with keys: {list(backup_cache.keys())}"
                        )
                        validation_metadata = backup_cache.get(scan_id)
                        if validation_metadata:
                            logger.debug(
                                f"Found validation metadata in backup cache: {validation_metadata}"
                            )
                            del LLMValidationStrategy._module_validation_cache[scan_id]
            else:
                logger.warning(
                    "LLMValidationStrategy has no _validation_metadata_cache attribute"
                )
        except ImportError as e:
            logger.warning(f"Failed to import LLMValidationStrategy: {e}")
            pass

        metadata = {
            "scan_id": request.context.metadata.scan_id,
            "orchestration_version": "domain_v1",
            "scan_duration_seconds": duration,
            "strategies_executed": len(scan_results),
            "strategy_results": strategy_results,
            "total_original_threats": total_original_threats,
            "aggregation_applied": self._threat_aggregator is not None,
            "validation_applied": request.enable_validation
            and bool(self._validation_strategies),
            "severity_threshold": str(request.get_effective_severity_threshold()),
            "execution_timestamp": end_time.isoformat(),
            "request_configuration": request.get_configuration_summary(),
        }

        # Include validation metadata if available
        if validation_metadata:
            metadata.update(validation_metadata)

        return metadata

    def get_registered_strategies(self) -> dict[str, list[str]]:
        """Get information about registered strategies."""
        return {
            "scan_strategies": [s.get_strategy_name() for s in self._scan_strategies],
            "validation_strategies": [
                s.get_strategy_name() for s in self._validation_strategies
            ],
            "threat_aggregator": (
                [self._threat_aggregator.get_aggregation_strategy_name()]
                if self._threat_aggregator
                else []
            ),
        }

    def can_execute_scan(self, request: ScanRequest) -> bool:
        """Check if this orchestrator can execute the given scan request."""
        try:
            applicable_strategies = self._get_applicable_strategies(request)
            return len(applicable_strategies) > 0
        except Exception:
            return False
