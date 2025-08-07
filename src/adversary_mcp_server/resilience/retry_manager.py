"""Retry manager with exponential backoff and jitter."""

import asyncio
import time
from collections.abc import Callable
from typing import Any

from ..logger import get_logger
from .types import (
    ErrorCategory,
    ErrorContext,
    RecoveryResult,
    ResilienceConfig,
    RetryStrategy,
)

logger = get_logger("retry_manager")


class RetryExhaustedException(Exception):
    """Exception raised when all retry attempts are exhausted."""

    def __init__(self, operation: str, attempts: int, last_error: Exception):
        self.operation = operation
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(
            f"Retry exhausted for '{operation}' after {attempts} attempts. Last error: {last_error}"
        )


class RetryManager:
    """Manages retry logic with various backoff strategies."""

    def __init__(self, config: ResilienceConfig, metrics_collector=None):
        """Initialize retry manager.

        Args:
            config: Resilience configuration
            metrics_collector: Optional metrics collector for retry analytics
        """
        self.config = config
        self.metrics_collector = metrics_collector
        logger.info(
            f"RetryManager initialized with max attempts: {config.max_retry_attempts}"
        )

    async def execute_with_retry(
        self,
        func: Callable,
        operation_name: str,
        *args,
        retry_strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF,
        error_classifier: Callable[[Exception], ErrorCategory] | None = None,
        **kwargs,
    ) -> Any:
        """Execute function with retry logic.

        Args:
            func: Function to execute
            operation_name: Name of the operation for logging
            *args: Positional arguments for function
            retry_strategy: Strategy for retry delays
            error_classifier: Function to classify errors
            **kwargs: Keyword arguments for function

        Returns:
            Function result

        Raises:
            RetryExhaustedException: When all retries are exhausted
        """
        if not self.config.enable_retry:
            # Retry disabled, execute once
            return await self._execute_function(func, *args, **kwargs)

        start_time = time.time()
        last_error: Exception | None = None

        # Record retry operation start
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "retry_operations_total",
                1,
                labels={"operation": operation_name, "strategy": retry_strategy.value},
            )

        for attempt in range(1, self.config.max_retry_attempts + 1):
            try:
                logger.debug(
                    f"Executing '{operation_name}' attempt {attempt}/{self.config.max_retry_attempts}"
                )
                attempt_start_time = time.time()
                result = await self._execute_function(func, *args, **kwargs)
                attempt_duration = time.time() - attempt_start_time

                # Record successful retry
                if self.metrics_collector:
                    self.metrics_collector.record_metric(
                        "retry_attempts_total",
                        attempt,
                        labels={
                            "operation": operation_name,
                            "status": "success",
                            "final_attempt": str(attempt),
                        },
                    )
                    self.metrics_collector.record_histogram(
                        "retry_attempt_duration_seconds",
                        attempt_duration,
                        labels={"operation": operation_name, "attempt": str(attempt)},
                    )

                if attempt > 1:
                    logger.info(f"'{operation_name}' succeeded on attempt {attempt}")

                return result

            except Exception as e:
                last_error = e
                error_category = self._classify_error(e, error_classifier)

                # Record failed attempt
                if self.metrics_collector:
                    self.metrics_collector.record_metric(
                        "retry_failed_attempts_total",
                        1,
                        labels={
                            "operation": operation_name,
                            "attempt": str(attempt),
                            "error_type": type(e).__name__,
                            "error_category": error_category.value,
                        },
                    )

                # Create error context
                context = ErrorContext(
                    error=e,
                    error_category=error_category,
                    operation=operation_name,
                    attempt_number=attempt,
                    total_attempts=self.config.max_retry_attempts,
                    start_time=start_time,
                )

                # If this is the last attempt, exit retry loop
                if context.is_final_attempt:
                    logger.error(
                        f"'{operation_name}' failed after {attempt} attempts: {e}"
                    )
                    break

                # Check if we should retry this error type
                if not self._should_retry(error_category, context):
                    logger.info(
                        f"'{operation_name}' failed with non-retryable error: {e}"
                    )
                    break

                # Calculate delay and wait before retry
                delay = self._calculate_delay(attempt, retry_strategy)
                logger.warning(
                    f"'{operation_name}' attempt {attempt} failed: {e}. Retrying in {delay:.2f}s"
                )

                # Record retry delay
                if self.metrics_collector:
                    self.metrics_collector.record_histogram(
                        "retry_delay_seconds",
                        delay,
                        labels={
                            "operation": operation_name,
                            "strategy": retry_strategy.value,
                        },
                    )

                await asyncio.sleep(delay)

        # All retries exhausted
        if self.metrics_collector:
            total_duration = time.time() - start_time
            self.metrics_collector.record_metric(
                "retry_exhausted_total",
                1,
                labels={
                    "operation": operation_name,
                    "final_error": (
                        type(last_error).__name__ if last_error else "unknown"
                    ),
                },
            )
            self.metrics_collector.record_histogram(
                "retry_total_duration_seconds",
                total_duration,
                labels={"operation": operation_name, "outcome": "exhausted"},
            )

        raise RetryExhaustedException(
            operation_name,
            self.config.max_retry_attempts,
            last_error or Exception("No error captured during retry attempts"),
        )

    async def _execute_function(self, func: Callable, *args, **kwargs) -> Any:
        """Execute the function, handling both sync and async functions."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in executor to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    def _classify_error(
        self, error: Exception, classifier: Callable | None
    ) -> ErrorCategory:
        """Classify error for retry decision making.

        Args:
            error: Exception that occurred
            classifier: Optional custom error classifier

        Returns:
            Error category
        """
        if classifier:
            try:
                return classifier(error)
            except Exception as e:
                logger.warning(f"Error classifier failed: {e}, falling back to default")

        # Default error classification
        error_type = type(error).__name__
        error_message = str(error).lower()

        # Network-related errors
        if any(
            term in error_message
            for term in ["connection", "network", "dns", "timeout"]
        ):
            return ErrorCategory.NETWORK

        # API rate limiting
        if any(
            term in error_message for term in ["rate limit", "too many requests", "429"]
        ):
            return ErrorCategory.API_RATE_LIMIT

        # API quota exceeded
        if any(
            term in error_message for term in ["quota", "limit exceeded", "usage limit"]
        ):
            return ErrorCategory.API_QUOTA_EXCEEDED

        # Authentication errors
        if any(
            term in error_message
            for term in ["auth", "unauthorized", "401", "403", "api key"]
        ):
            return ErrorCategory.API_AUTHENTICATION

        # Server errors
        if any(
            term in error_message
            for term in ["500", "502", "503", "504", "server error", "internal error"]
        ):
            return ErrorCategory.API_SERVER_ERROR

        # Timeout errors
        if "timeout" in error_type.lower() or "timeout" in error_message:
            return ErrorCategory.TIMEOUT

        # Resource exhaustion
        if any(
            term in error_message
            for term in ["memory", "resource", "exhausted", "full"]
        ):
            return ErrorCategory.RESOURCE_EXHAUSTED

        # Validation errors
        if any(
            term in error_message
            for term in ["validation", "invalid", "bad request", "400"]
        ):
            return ErrorCategory.VALIDATION_ERROR

        return ErrorCategory.UNKNOWN

    def _should_retry(
        self, error_category: ErrorCategory, context: ErrorContext
    ) -> bool:
        """Determine if error should be retried based on category and context.

        Args:
            error_category: Category of the error
            context: Error context information

        Returns:
            True if should retry, False otherwise
        """
        # Never retry certain error categories
        if error_category in [
            ErrorCategory.API_AUTHENTICATION,
            ErrorCategory.VALIDATION_ERROR,
            ErrorCategory.CONFIGURATION_ERROR,
        ]:
            return False

        # Don't retry if we've exceeded maximum attempts
        if context.attempt_number >= self.config.max_retry_attempts:
            return False

        # Retry network, timeout, and server errors
        if error_category in [
            ErrorCategory.NETWORK,
            ErrorCategory.TIMEOUT,
            ErrorCategory.API_SERVER_ERROR,
            ErrorCategory.RESOURCE_EXHAUSTED,
        ]:
            return True

        # For rate limiting, use longer delays
        if error_category == ErrorCategory.API_RATE_LIMIT:
            return True

        # For quota exceeded, generally don't retry (unless it's a short-term limit)
        if error_category == ErrorCategory.API_QUOTA_EXCEEDED:
            return False

        # For unknown errors, retry with caution (but allow all configured attempts)
        if error_category == ErrorCategory.UNKNOWN:
            return (
                not context.is_final_attempt
            )  # Retry unless this is the final attempt

        return False

    def _calculate_delay(self, attempt: int, strategy: RetryStrategy) -> float:
        """Calculate delay before retry based on strategy.

        Args:
            attempt: Current attempt number (1-based)
            strategy: Retry strategy to use

        Returns:
            Delay in seconds
        """
        if strategy == RetryStrategy.NO_RETRY:
            return 0.0

        elif strategy == RetryStrategy.FIXED_DELAY:
            delay = self.config.base_delay_seconds

        elif strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay_seconds * attempt

        elif strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay_seconds * (
                self.config.backoff_multiplier ** (attempt - 1)
            )

        elif strategy == RetryStrategy.JITTER:
            # Exponential backoff with jitter
            exp_delay = self.config.base_delay_seconds * (
                self.config.backoff_multiplier ** (attempt - 1)
            )
            # Use secrets.randbits for better randomness in jitter
            import secrets

            jitter_factor = secrets.randbits(32) / (2**32)  # 0.0-1.0
            delay = exp_delay * (
                0.5 + jitter_factor * 0.5
            )  # 50-100% of calculated delay

        else:
            # Default to exponential backoff
            delay = self.config.base_delay_seconds * (
                self.config.backoff_multiplier ** (attempt - 1)
            )

        # Apply jitter if enabled (except for JITTER strategy which already has it)
        if self.config.jitter_enabled and strategy != RetryStrategy.JITTER:
            import secrets

            jitter_factor = 0.1  # ±10% jitter
            # Use secrets for cryptographically secure randomness
            random_val = secrets.randbits(32) / (2**32)  # 0.0-1.0
            jitter = delay * jitter_factor * (2 * random_val - 1)
            delay += jitter

        # Cap the delay to maximum
        delay = min(delay, self.config.max_delay_seconds)

        return max(0.0, delay)

    def create_recovery_result(
        self,
        success: bool,
        result: Any = None,
        retry_count: int = 0,
        duration: float = 0.0,
        error_message: str | None = None,
    ) -> RecoveryResult:
        """Create a recovery result object.

        Args:
            success: Whether the operation succeeded
            result: Result of the operation
            retry_count: Number of retries attempted
            duration: Total duration of operation
            error_message: Error message if failed

        Returns:
            Recovery result object
        """
        from .types import RecoveryAction

        return RecoveryResult(
            success=success,
            action_taken=RecoveryAction.RETRY,
            result=result,
            retry_count=retry_count,
            total_duration=duration,
            error_message=error_message,
        )
