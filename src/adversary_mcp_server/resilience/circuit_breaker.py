"""Circuit breaker implementation for preventing cascading failures."""

import asyncio
import time
from collections.abc import Callable
from typing import Any

from ..logger import get_logger
from .types import CircuitBreakerState, CircuitBreakerStats, ResilienceConfig

logger = get_logger("circuit_breaker")


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open."""

    def __init__(self, name: str, stats: CircuitBreakerStats):
        self.name = name
        self.stats = stats
        super().__init__(
            f"Circuit breaker '{name}' is open. Last failure: {stats.time_since_last_failure:.1f}s ago"
        )


class CircuitBreaker:
    """Circuit breaker for preventing cascading failures in external service calls."""

    def __init__(self, name: str, config: ResilienceConfig, metrics_collector=None):
        """Initialize circuit breaker.

        Args:
            name: Unique name for this circuit breaker
            config: Resilience configuration
            metrics_collector: Optional metrics collector for circuit breaker analytics
        """
        self.name = name
        self.config = config
        self.stats = CircuitBreakerStats(name=name, state=CircuitBreakerState.CLOSED)
        self.metrics_collector = metrics_collector
        self._lock = asyncio.Lock()

        logger.info(
            f"Circuit breaker '{name}' initialized with threshold: {config.failure_threshold}"
        )

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Function result

        Raises:
            CircuitBreakerError: When circuit is open
            Exception: Original exception from function
        """
        if not self.config.enable_circuit_breaker:
            # Circuit breaker disabled, call function directly
            return await self._execute_function(func, *args, **kwargs)

        async with self._lock:
            # Check circuit state before execution
            await self._update_state()

            if self.stats.state == CircuitBreakerState.OPEN:
                logger.warning(f"Circuit breaker '{self.name}' is open, failing fast")

                # Record circuit breaker rejection
                if self.metrics_collector:
                    self.metrics_collector.record_metric(
                        "circuit_breaker_rejections_total",
                        1,
                        labels={"breaker_name": self.name, "state": "open"},
                    )

                raise CircuitBreakerError(self.name, self.stats)

            # Execute function and handle result
            execution_start_time = time.time()
            try:
                result = await self._execute_function(func, *args, **kwargs)
                execution_time = time.time() - execution_start_time
                await self._record_success(execution_time)
                return result

            except Exception as e:
                execution_time = time.time() - execution_start_time
                await self._record_failure(e, execution_time)
                raise

    async def _execute_function(self, func: Callable, *args, **kwargs) -> Any:
        """Execute the function, handling both sync and async functions."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in executor to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    async def _update_state(self) -> None:
        """Update circuit breaker state based on current conditions."""
        current_time = time.time()

        if self.stats.state == CircuitBreakerState.OPEN:
            # Check if enough time has passed to try half-open
            if (
                self.stats.time_since_last_failure
                >= self.config.recovery_timeout_seconds
            ):
                await self._transition_to_half_open()

        elif self.stats.state == CircuitBreakerState.HALF_OPEN:
            # In half-open, we allow limited requests to test recovery
            pass  # State will be updated based on success/failure

        elif self.stats.state == CircuitBreakerState.CLOSED:
            # Check if we should open due to too many failures
            if (
                self.stats.failure_count >= self.config.failure_threshold
                and self.stats.total_requests >= self.config.failure_threshold
            ):
                await self._transition_to_open()

    async def _record_success(self, execution_time: float = 0.0) -> None:
        """Record a successful operation."""
        self.stats.success_count += 1
        self.stats.total_requests += 1
        self.stats.last_success_time = time.time()

        # Record success metrics
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "circuit_breaker_requests_total",
                1,
                labels={
                    "breaker_name": self.name,
                    "status": "success",
                    "state": self.stats.state.value,
                },
            )
            self.metrics_collector.record_histogram(
                "circuit_breaker_execution_duration_seconds",
                execution_time,
                labels={"breaker_name": self.name, "status": "success"},
            )

        if self.stats.state == CircuitBreakerState.HALF_OPEN:
            # Check if we have enough successes to close the circuit
            if self.stats.success_count >= self.config.success_threshold:
                await self._transition_to_closed()

        logger.debug(
            f"Circuit breaker '{self.name}' recorded success: {self.stats.success_count} total"
        )

    async def _record_failure(
        self, error: Exception, execution_time: float = 0.0
    ) -> None:
        """Record a failed operation."""
        self.stats.failure_count += 1
        self.stats.total_requests += 1
        self.stats.last_failure_time = time.time()

        # Record failure metrics
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "circuit_breaker_requests_total",
                1,
                labels={
                    "breaker_name": self.name,
                    "status": "failure",
                    "state": self.stats.state.value,
                },
            )
            self.metrics_collector.record_histogram(
                "circuit_breaker_execution_duration_seconds",
                execution_time,
                labels={"breaker_name": self.name, "status": "failure"},
            )
            self.metrics_collector.record_metric(
                "circuit_breaker_failures_total",
                1,
                labels={"breaker_name": self.name, "error_type": type(error).__name__},
            )

        if self.stats.state == CircuitBreakerState.HALF_OPEN:
            # Any failure in half-open immediately opens the circuit
            await self._transition_to_open()
        elif self.stats.state == CircuitBreakerState.CLOSED:
            # Check if we should open due to failures
            if self.stats.failure_count >= self.config.failure_threshold:
                await self._transition_to_open()

        logger.warning(f"Circuit breaker '{self.name}' recorded failure: {error}")

    async def _transition_to_open(self) -> None:
        """Transition circuit breaker to OPEN state."""
        if self.stats.state != CircuitBreakerState.OPEN:
            previous_state = self.stats.state
            self.stats.state = CircuitBreakerState.OPEN
            self.stats.state_change_time = time.time()

            # Record state transition
            if self.metrics_collector:
                self.metrics_collector.record_metric(
                    "circuit_breaker_state_changes_total",
                    1,
                    labels={
                        "breaker_name": self.name,
                        "from_state": previous_state.value,
                        "to_state": "open",
                    },
                )
                self.metrics_collector.record_metric(
                    "circuit_breaker_open_events_total",
                    1,
                    labels={"breaker_name": self.name},
                )

            logger.warning(f"Circuit breaker '{self.name}' opened due to failures")

    async def _transition_to_half_open(self) -> None:
        """Transition circuit breaker to HALF_OPEN state."""
        previous_state = self.stats.state
        self.stats.state = CircuitBreakerState.HALF_OPEN
        self.stats.state_change_time = time.time()
        # Reset counters for half-open testing
        self.stats.success_count = 0
        self.stats.failure_count = 0

        # Record state transition
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "circuit_breaker_state_changes_total",
                1,
                labels={
                    "breaker_name": self.name,
                    "from_state": previous_state.value,
                    "to_state": "half_open",
                },
            )

        logger.info(f"Circuit breaker '{self.name}' moved to half-open for testing")

    async def _transition_to_closed(self) -> None:
        """Transition circuit breaker to CLOSED state."""
        previous_state = self.stats.state
        self.stats.state = CircuitBreakerState.CLOSED
        self.stats.state_change_time = time.time()
        # Reset failure count when closing
        self.stats.failure_count = 0

        # Record state transition and recovery
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "circuit_breaker_state_changes_total",
                1,
                labels={
                    "breaker_name": self.name,
                    "from_state": previous_state.value,
                    "to_state": "closed",
                },
            )
            self.metrics_collector.record_metric(
                "circuit_breaker_recovery_events_total",
                1,
                labels={"breaker_name": self.name},
            )

        logger.info(f"Circuit breaker '{self.name}' closed after successful recovery")

    def get_stats(self) -> CircuitBreakerStats:
        """Get current circuit breaker statistics."""
        return self.stats

    def is_open(self) -> bool:
        """Check if circuit breaker is open."""
        return self.stats.state == CircuitBreakerState.OPEN

    def is_half_open(self) -> bool:
        """Check if circuit breaker is half-open."""
        return self.stats.state == CircuitBreakerState.HALF_OPEN

    def is_closed(self) -> bool:
        """Check if circuit breaker is closed."""
        return self.stats.state == CircuitBreakerState.CLOSED

    async def reset(self) -> None:
        """Reset circuit breaker to initial state."""
        async with self._lock:
            self.stats = CircuitBreakerStats(
                name=self.name, state=CircuitBreakerState.CLOSED
            )
            logger.info(f"Circuit breaker '{self.name}' reset to closed state")

    async def force_open(self) -> None:
        """Force circuit breaker to open state (for testing/maintenance)."""
        async with self._lock:
            await self._transition_to_open()
            logger.warning(f"Circuit breaker '{self.name}' forced to open state")

    async def force_closed(self) -> None:
        """Force circuit breaker to closed state (for testing/maintenance)."""
        async with self._lock:
            await self._transition_to_closed()
            logger.info(f"Circuit breaker '{self.name}' forced to closed state")


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers."""

    def __init__(self, config: ResilienceConfig, metrics_collector=None):
        """Initialize circuit breaker registry.

        Args:
            config: Resilience configuration
            metrics_collector: Optional metrics collector for circuit breaker analytics
        """
        self.config = config
        self.metrics_collector = metrics_collector
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = asyncio.Lock()

    async def get_breaker(self, name: str) -> CircuitBreaker:
        """Get or create a circuit breaker by name.

        Args:
            name: Circuit breaker name

        Returns:
            Circuit breaker instance
        """
        if name not in self._breakers:
            async with self._lock:
                # Double-check pattern
                if name not in self._breakers:
                    self._breakers[name] = CircuitBreaker(
                        name, self.config, self.metrics_collector
                    )

                    # Record new circuit breaker creation
                    if self.metrics_collector:
                        self.metrics_collector.record_metric(
                            "circuit_breaker_instances_total",
                            1,
                            labels={"breaker_name": name},
                        )

        return self._breakers[name]

    def get_all_stats(self) -> dict[str, dict]:
        """Get statistics for all circuit breakers.

        Returns:
            Dictionary mapping breaker names to their statistics
        """
        return {
            name: breaker.get_stats().to_dict()
            for name, breaker in self._breakers.items()
        }

    async def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            await breaker.reset()
        logger.info("All circuit breakers reset")

    def get_breaker_count(self) -> int:
        """Get total number of registered circuit breakers."""
        return len(self._breakers)
