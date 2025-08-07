"""Comprehensive error handling and recovery strategies."""

import asyncio
import time
from collections.abc import Callable
from typing import Any

from ..logger import get_logger
from .circuit_breaker import CircuitBreaker, CircuitBreakerError, CircuitBreakerRegistry
from .retry_manager import RetryExhaustedException, RetryManager
from .types import (
    ErrorCategory,
    FallbackFunction,
    RecoveryAction,
    RecoveryResult,
    ResilienceConfig,
    RetryStrategy,
)

logger = get_logger("error_handler")


class ErrorRecoveryStrategy:
    """Strategy for recovering from specific types of errors."""

    def __init__(
        self,
        error_category: ErrorCategory,
        action: RecoveryAction,
        fallback_func: FallbackFunction | None = None,
        retry_strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF,
        max_attempts: int | None = None,
    ):
        """Initialize error recovery strategy.

        Args:
            error_category: Category of errors this strategy handles
            action: Primary recovery action to take
            fallback_func: Optional fallback function
            retry_strategy: Retry strategy if action is RETRY
            max_attempts: Override for max retry attempts
        """
        self.error_category = error_category
        self.action = action
        self.fallback_func = fallback_func
        self.retry_strategy = retry_strategy
        self.max_attempts = max_attempts


class ErrorHandler:
    """Comprehensive error handler with multiple recovery strategies."""

    def __init__(self, config: ResilienceConfig, metrics_collector=None):
        """Initialize error handler.

        Args:
            config: Resilience configuration
            metrics_collector: Optional metrics collector for error handling analytics
        """
        self.config = config
        self.metrics_collector = metrics_collector
        self.retry_manager = RetryManager(config, metrics_collector)
        self.circuit_breakers = CircuitBreakerRegistry(config, metrics_collector)
        self.recovery_strategies: dict[ErrorCategory, ErrorRecoveryStrategy] = {}

        # Setup default recovery strategies
        self._setup_default_strategies()

        logger.info("ErrorHandler initialized with comprehensive recovery strategies")

    def _setup_default_strategies(self) -> None:
        """Setup default error recovery strategies."""
        self.recovery_strategies = {
            ErrorCategory.NETWORK: ErrorRecoveryStrategy(
                ErrorCategory.NETWORK,
                RecoveryAction.RETRY,
                retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            ),
            ErrorCategory.API_RATE_LIMIT: ErrorRecoveryStrategy(
                ErrorCategory.API_RATE_LIMIT,
                RecoveryAction.RETRY,
                retry_strategy=RetryStrategy.LINEAR_BACKOFF,
            ),
            ErrorCategory.API_SERVER_ERROR: ErrorRecoveryStrategy(
                ErrorCategory.API_SERVER_ERROR,
                RecoveryAction.RETRY,
                retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            ),
            ErrorCategory.TIMEOUT: ErrorRecoveryStrategy(
                ErrorCategory.TIMEOUT,
                RecoveryAction.RETRY,
                retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            ),
            ErrorCategory.API_QUOTA_EXCEEDED: ErrorRecoveryStrategy(
                ErrorCategory.API_QUOTA_EXCEEDED, RecoveryAction.CIRCUIT_BREAK
            ),
            ErrorCategory.API_AUTHENTICATION: ErrorRecoveryStrategy(
                ErrorCategory.API_AUTHENTICATION, RecoveryAction.FAIL
            ),
            ErrorCategory.VALIDATION_ERROR: ErrorRecoveryStrategy(
                ErrorCategory.VALIDATION_ERROR, RecoveryAction.FAIL
            ),
            ErrorCategory.CONFIGURATION_ERROR: ErrorRecoveryStrategy(
                ErrorCategory.CONFIGURATION_ERROR, RecoveryAction.FAIL
            ),
            ErrorCategory.RESOURCE_EXHAUSTED: ErrorRecoveryStrategy(
                ErrorCategory.RESOURCE_EXHAUSTED, RecoveryAction.DEGRADE
            ),
            ErrorCategory.UNKNOWN: ErrorRecoveryStrategy(
                ErrorCategory.UNKNOWN,
                RecoveryAction.RETRY,
                retry_strategy=RetryStrategy.JITTER,
                max_attempts=2,
            ),
        }

    def register_strategy(self, strategy: ErrorRecoveryStrategy) -> None:
        """Register a custom error recovery strategy.

        Args:
            strategy: Error recovery strategy to register
        """
        self.recovery_strategies[strategy.error_category] = strategy
        logger.info(
            f"Registered recovery strategy for {strategy.error_category}: {strategy.action}"
        )

    def register_fallback(
        self, error_category: ErrorCategory, fallback_func: FallbackFunction
    ) -> None:
        """Register a fallback function for an error category.

        Args:
            error_category: Category of errors
            fallback_func: Fallback function to use
        """
        if error_category in self.recovery_strategies:
            self.recovery_strategies[error_category].fallback_func = fallback_func
        else:
            # Create new strategy with fallback
            self.recovery_strategies[error_category] = ErrorRecoveryStrategy(
                error_category, RecoveryAction.FALLBACK, fallback_func=fallback_func
            )
        logger.info(f"Registered fallback function for {error_category}")

    async def execute_with_recovery(
        self,
        func: Callable,
        operation_name: str,
        circuit_breaker_name: str | None = None,
        fallback_func: FallbackFunction | None = None,
        error_classifier: Callable[[Exception], ErrorCategory] | None = None,
        *args,
        **kwargs,
    ) -> RecoveryResult:
        """Execute function with comprehensive error recovery.

        Args:
            func: Function to execute
            operation_name: Name of the operation
            circuit_breaker_name: Optional circuit breaker name
            fallback_func: Optional fallback function
            error_classifier: Optional custom error classifier
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Recovery result with outcome and metadata
        """
        start_time = time.time()
        circuit_breaker: CircuitBreaker | None = None

        # Record error recovery operation start
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "error_recovery_operations_total",
                1,
                labels={"operation": operation_name, "status": "started"},
            )

        # Get circuit breaker if name provided
        if circuit_breaker_name and self.config.enable_circuit_breaker:
            circuit_breaker = await self.circuit_breakers.get_breaker(
                circuit_breaker_name
            )

        try:
            # Execute with circuit breaker protection if available
            if circuit_breaker:
                result = await circuit_breaker.call(func, *args, **kwargs)
            else:
                result = await self._execute_function(func, *args, **kwargs)

            # Success case
            duration = time.time() - start_time

            # Record successful recovery
            if self.metrics_collector:
                self.metrics_collector.record_metric(
                    "error_recovery_operations_total",
                    1,
                    labels={"operation": operation_name, "status": "success"},
                )
                self.metrics_collector.record_histogram(
                    "error_recovery_duration_seconds",
                    duration,
                    labels={"operation": operation_name, "outcome": "success"},
                )

            return RecoveryResult(
                success=True,
                action_taken=RecoveryAction.RETRY,  # No action needed for success
                result=result,
                total_duration=duration,
            )

        except CircuitBreakerError as e:
            # Circuit breaker is open
            logger.warning(f"Circuit breaker open for '{operation_name}': {e}")

            # Record circuit breaker failure
            if self.metrics_collector:
                self.metrics_collector.record_metric(
                    "error_recovery_circuit_breaker_trips_total",
                    1,
                    labels={"operation": operation_name, "breaker_name": e.name},
                )

            return await self._handle_circuit_breaker_error(
                e, operation_name, fallback_func, start_time, *args, **kwargs
            )

        except Exception as original_error:
            # Record error occurrence
            if self.metrics_collector:
                error_category = self._classify_error(original_error, error_classifier)
                self.metrics_collector.record_metric(
                    "error_recovery_errors_total",
                    1,
                    labels={
                        "operation": operation_name,
                        "error_type": type(original_error).__name__,
                        "error_category": error_category.value,
                    },
                )

            # Handle other errors with recovery strategies
            return await self._handle_error_with_strategy(
                original_error,
                func,
                operation_name,
                circuit_breaker_name,
                fallback_func,
                error_classifier,
                start_time,
                *args,
                **kwargs,
            )

    async def _handle_circuit_breaker_error(
        self,
        error: CircuitBreakerError,
        operation_name: str,
        fallback_func: FallbackFunction | None,
        start_time: float,
        *args,
        **kwargs,
    ) -> RecoveryResult:
        """Handle circuit breaker open errors.

        Args:
            error: Circuit breaker error
            operation_name: Name of the operation
            fallback_func: Optional fallback function
            start_time: Start time of operation

        Returns:
            Recovery result
        """
        if fallback_func and self.config.enable_graceful_degradation:
            try:
                logger.info(
                    f"Using fallback for '{operation_name}' due to open circuit breaker"
                )
                fallback_result = await self._execute_function(
                    fallback_func, *args, **kwargs
                )

                return RecoveryResult(
                    success=True,
                    action_taken=RecoveryAction.FALLBACK,
                    result=fallback_result,
                    fallback_used=True,
                    total_duration=time.time() - start_time,
                )

            except Exception as fallback_error:
                logger.error(
                    f"Fallback failed for '{operation_name}': {fallback_error}"
                )
                return RecoveryResult(
                    success=False,
                    action_taken=RecoveryAction.FALLBACK,
                    fallback_used=True,
                    total_duration=time.time() - start_time,
                    error_message=f"Circuit breaker open and fallback failed: {fallback_error}",
                )

        # No fallback available or disabled - re-raise the circuit breaker error
        raise error

    async def _handle_error_with_strategy(
        self,
        error: Exception,
        func: Callable,
        operation_name: str,
        circuit_breaker_name: str | None,
        fallback_func: FallbackFunction | None,
        error_classifier: Callable[[Exception], ErrorCategory] | None,
        start_time: float,
        *args,
        **kwargs,
    ) -> RecoveryResult:
        """Handle error using appropriate recovery strategy.

        Args:
            error: Original exception
            func: Function that failed
            operation_name: Name of the operation
            circuit_breaker_name: Circuit breaker name
            fallback_func: Optional fallback function
            error_classifier: Optional error classifier
            start_time: Start time of operation
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Recovery result
        """
        # Classify the error
        error_category = self._classify_error(error, error_classifier)

        # Get recovery strategy
        strategy = self.recovery_strategies.get(error_category)
        if not strategy:
            logger.warning(f"No recovery strategy for {error_category}, using default")
            strategy = self.recovery_strategies[ErrorCategory.UNKNOWN]

        logger.info(
            f"Handling {error_category} error for '{operation_name}' with action: {strategy.action}"
        )

        # Execute recovery action
        if strategy.action == RecoveryAction.RETRY:
            return await self._handle_retry_recovery(
                error,
                func,
                operation_name,
                strategy,
                circuit_breaker_name,
                fallback_func,
                error_classifier,
                start_time,
                *args,
                **kwargs,
            )

        elif strategy.action == RecoveryAction.FALLBACK:
            return await self._handle_fallback_recovery(
                error,
                operation_name,
                strategy.fallback_func or fallback_func,
                start_time,
                *args,
                **kwargs,
            )

        elif strategy.action == RecoveryAction.CIRCUIT_BREAK:
            # Force circuit breaker to open
            if circuit_breaker_name:
                circuit_breaker = await self.circuit_breakers.get_breaker(
                    circuit_breaker_name
                )
                await circuit_breaker.force_open()

            return RecoveryResult(
                success=False,
                action_taken=RecoveryAction.CIRCUIT_BREAK,
                total_duration=time.time() - start_time,
                error_message=f"Circuit breaker opened due to {error_category}: {error}",
            )

        elif strategy.action == RecoveryAction.DEGRADE:
            return await self._handle_degraded_recovery(
                error, operation_name, fallback_func, start_time, *args, **kwargs
            )

        elif strategy.action == RecoveryAction.SKIP:
            logger.warning(
                f"Skipping '{operation_name}' due to {error_category}: {error}"
            )
            return RecoveryResult(
                success=True,  # Consider skip as success
                action_taken=RecoveryAction.SKIP,
                result=None,
                total_duration=time.time() - start_time,
            )

        else:  # RecoveryAction.FAIL
            # For FAIL action, re-raise the original error
            raise error

    async def _handle_retry_recovery(
        self,
        error: Exception,
        func: Callable,
        operation_name: str,
        strategy: ErrorRecoveryStrategy,
        circuit_breaker_name: str | None,
        fallback_func: FallbackFunction | None,
        error_classifier: Callable[[Exception], ErrorCategory] | None,
        start_time: float,
        *args,
        **kwargs,
    ) -> RecoveryResult:
        """Handle recovery using retry strategy."""
        try:
            # Create a wrapper function
            # If circuit breaker was already used for the first attempt, don't use it again for retries
            # The circuit breaker has already recorded the failure and will manage its own state
            async def protected_func(*args, **kwargs):
                return await self._execute_function(func, *args, **kwargs)

            # Execute with retry
            result = await self.retry_manager.execute_with_retry(
                protected_func,
                operation_name,
                *args,
                retry_strategy=strategy.retry_strategy,
                error_classifier=error_classifier,
                **kwargs,
            )

            return RecoveryResult(
                success=True,
                action_taken=RecoveryAction.RETRY,
                result=result,
                retry_count=1,  # At least one retry happened
                total_duration=time.time() - start_time,
            )

        except (RetryExhaustedException, CircuitBreakerError) as retry_error:
            # Retry failed, try fallback if available
            if fallback_func and self.config.enable_graceful_degradation:
                return await self._handle_fallback_recovery(
                    retry_error,
                    operation_name,
                    fallback_func,
                    start_time,
                    *args,
                    **kwargs,
                )

            # No fallback available, re-raise the original error if it exists
            if (
                isinstance(retry_error, RetryExhaustedException)
                and retry_error.last_error
            ):
                raise retry_error.last_error
            else:
                raise retry_error

        except Exception as other_error:
            # Other errors during retry setup, try fallback if available
            if fallback_func and self.config.enable_graceful_degradation:
                return await self._handle_fallback_recovery(
                    other_error,
                    operation_name,
                    fallback_func,
                    start_time,
                    *args,
                    **kwargs,
                )

            # No fallback available, re-raise the original error
            raise other_error

    async def _handle_fallback_recovery(
        self,
        error: Exception,
        operation_name: str,
        fallback_func: FallbackFunction | None,
        start_time: float,
        *args,
        **kwargs,
    ) -> RecoveryResult:
        """Handle recovery using fallback function."""
        if not fallback_func:
            return RecoveryResult(
                success=False,
                action_taken=RecoveryAction.FALLBACK,
                total_duration=time.time() - start_time,
                error_message=f"No fallback available for '{operation_name}': {error}",
            )

        try:
            logger.info(f"Using fallback for '{operation_name}' due to error: {error}")
            fallback_result = await self._execute_function(
                fallback_func, *args, **kwargs
            )

            return RecoveryResult(
                success=True,
                action_taken=RecoveryAction.FALLBACK,
                result=fallback_result,
                fallback_used=True,
                total_duration=time.time() - start_time,
            )

        except Exception as fallback_error:
            logger.error(f"Fallback failed for '{operation_name}': {fallback_error}")
            return RecoveryResult(
                success=False,
                action_taken=RecoveryAction.FALLBACK,
                fallback_used=True,
                total_duration=time.time() - start_time,
                error_message=f"Original error: {error}. Fallback error: {fallback_error}",
            )

    async def _handle_degraded_recovery(
        self,
        error: Exception,
        operation_name: str,
        fallback_func: FallbackFunction | None,
        start_time: float,
        *args,
        **kwargs,
    ) -> RecoveryResult:
        """Handle recovery with degraded functionality."""
        if fallback_func:
            # Try fallback first
            result = await self._handle_fallback_recovery(
                error, operation_name, fallback_func, start_time, *args, **kwargs
            )
            if result.success:
                result.action_taken = RecoveryAction.DEGRADE
                return result

        # Return partial success with degraded functionality
        logger.warning(
            f"Operating in degraded mode for '{operation_name}' due to: {error}"
        )
        return RecoveryResult(
            success=True,  # Consider degraded as partial success
            action_taken=RecoveryAction.DEGRADE,
            result=None,  # No result in degraded mode
            total_duration=time.time() - start_time,
            error_message=f"Degraded operation due to: {error}",
        )

    async def _execute_function(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function, handling both sync and async functions."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in executor to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    def _classify_error(
        self, error: Exception, classifier: Callable | None
    ) -> ErrorCategory:
        """Classify error using custom classifier or default logic."""
        if classifier:
            try:
                return classifier(error)
            except Exception as e:
                logger.warning(f"Error classifier failed: {e}, using default")

        # Use retry manager's error classification
        return self.retry_manager._classify_error(error, None)

    def get_circuit_breaker_stats(self) -> dict[str, dict]:
        """Get statistics for all circuit breakers."""
        return self.circuit_breakers.get_all_stats()

    async def reset_all_circuit_breakers(self) -> None:
        """Reset all circuit breakers to closed state."""
        await self.circuit_breakers.reset_all()
        logger.info("All circuit breakers reset")

    def get_recovery_strategies(self) -> dict[ErrorCategory, ErrorRecoveryStrategy]:
        """Get all registered recovery strategies."""
        return self.recovery_strategies.copy()
