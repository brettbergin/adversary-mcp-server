"""Tests for circuit breaker functionality."""

import asyncio
import time

import pytest

from adversary_mcp_server.resilience.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerState,
)
from adversary_mcp_server.resilience.types import CircuitBreakerStats, ResilienceConfig


class TestCircuitBreakerStats:
    """Test CircuitBreakerStats functionality."""

    def test_stats_initialization(self):
        """Test stats initialization with defaults."""
        stats = CircuitBreakerStats(name="test", state=CircuitBreakerState.CLOSED)
        assert stats.state == CircuitBreakerState.CLOSED
        assert stats.failure_count == 0
        assert stats.success_count == 0
        assert stats.last_failure_time is None
        assert stats.total_requests == 0

    def test_stats_with_custom_values(self):
        """Test stats initialization with custom values."""
        now = time.time()
        stats = CircuitBreakerStats(
            name="test",
            state=CircuitBreakerState.OPEN,
            failure_count=5,
            success_count=10,
            last_failure_time=now,
            total_requests=15,
        )
        assert stats.state == CircuitBreakerState.OPEN
        assert stats.failure_count == 5
        assert stats.success_count == 10
        assert stats.last_failure_time == now
        assert stats.total_requests == 15

    def test_stats_reset(self):
        """Test stats reset functionality."""
        stats = CircuitBreakerStats(
            name="test",
            state=CircuitBreakerState.OPEN,
            failure_count=5,
            success_count=10,
            last_failure_time=time.time(),
            total_requests=15,
        )
        # Note: CircuitBreakerStats doesn't have a reset method, let's test the to_dict method instead
        stats_dict = stats.to_dict()
        assert stats_dict["failure_count"] == 5
        assert stats_dict["success_count"] == 10
        assert stats_dict["total_requests"] == 15


class TestCircuitBreaker:
    """Test CircuitBreaker functionality."""

    def test_initialization(self):
        """Test circuit breaker initialization."""
        config = ResilienceConfig(failure_threshold=3, recovery_timeout_seconds=30)
        cb = CircuitBreaker("test_breaker", config)
        assert cb.name == "test_breaker"
        assert cb.config.failure_threshold == 3
        assert cb.config.recovery_timeout_seconds == 30
        assert cb.stats.state == CircuitBreakerState.CLOSED

    def test_initialization_with_defaults(self):
        """Test circuit breaker with default values."""
        config = ResilienceConfig()
        cb = CircuitBreaker("test", config)
        assert cb.name == "test"
        assert cb.config.failure_threshold == 5
        assert cb.config.recovery_timeout_seconds == 60

    @pytest.mark.asyncio
    async def test_successful_call_closed_state(self):
        """Test successful function call in closed state."""
        config = ResilienceConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config)

        async def success_func():
            return "success"

        result = await cb.call(success_func)
        assert result == "success"
        assert cb.stats.success_count == 1
        assert cb.stats.failure_count == 0
        assert cb.stats.total_requests == 1
        assert cb.stats.state == CircuitBreakerState.CLOSED

    @pytest.mark.asyncio
    async def test_failed_call_closed_state(self):
        """Test failed function call in closed state."""
        config = ResilienceConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config)

        async def fail_func():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            await cb.call(fail_func)

        assert cb.stats.failure_count == 1
        assert cb.stats.success_count == 0
        assert cb.stats.total_requests == 1
        assert cb.stats.state == CircuitBreakerState.CLOSED
        assert cb.stats.last_failure_time is not None

    @pytest.mark.asyncio
    async def test_circuit_opens_after_failures(self):
        """Test circuit opens after reaching failure threshold."""
        config = ResilienceConfig(failure_threshold=2)
        cb = CircuitBreaker("test", config)

        async def fail_func():
            raise ValueError("test error")

        # First failure
        with pytest.raises(ValueError):
            await cb.call(fail_func)
        assert cb.stats.state == CircuitBreakerState.CLOSED

        # Second failure - should open circuit
        with pytest.raises(ValueError):
            await cb.call(fail_func)
        assert cb.stats.state == CircuitBreakerState.OPEN
        assert cb.stats.failure_count == 2

    @pytest.mark.asyncio
    async def test_circuit_rejects_calls_when_open(self):
        """Test circuit rejects calls when open."""
        config = ResilienceConfig(failure_threshold=1, recovery_timeout_seconds=10.0)
        cb = CircuitBreaker("test", config)

        async def fail_func():
            raise ValueError("test error")

        # Cause circuit to open
        with pytest.raises(ValueError):
            await cb.call(fail_func)
        assert cb.stats.state == CircuitBreakerState.OPEN

        # Next call should be rejected with CircuitBreakerError
        async def success_func():
            return "success"

        with pytest.raises(CircuitBreakerError) as exc_info:
            await cb.call(success_func)
        assert "test" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_circuit_transitions_to_half_open(self):
        """Test circuit transitions to half-open after timeout."""
        config = ResilienceConfig(
            failure_threshold=1, recovery_timeout_seconds=0.1, success_threshold=1
        )
        cb = CircuitBreaker("test", config)

        async def fail_func():
            raise ValueError("test error")

        # Open the circuit
        with pytest.raises(ValueError):
            await cb.call(fail_func)
        assert cb.stats.state == CircuitBreakerState.OPEN

        # Wait for recovery timeout
        await asyncio.sleep(0.2)

        # Next call should transition to half-open
        async def success_func():
            return "success"

        result = await cb.call(success_func)
        assert result == "success"
        assert cb.stats.state == CircuitBreakerState.CLOSED  # Should close on success

    @pytest.mark.asyncio
    async def test_half_open_success_closes_circuit(self):
        """Test successful call in half-open state closes circuit."""
        config = ResilienceConfig(
            failure_threshold=1, recovery_timeout_seconds=0.1, success_threshold=1
        )
        cb = CircuitBreaker("test", config)

        # Open circuit
        async def fail_func():
            raise ValueError("test error")

        with pytest.raises(ValueError):
            await cb.call(fail_func)

        # Wait for recovery timeout
        await asyncio.sleep(0.2)

        # Successful call should close circuit
        async def success_func():
            return "success"

        result = await cb.call(success_func)
        assert result == "success"
        assert cb.stats.state == CircuitBreakerState.CLOSED
        assert cb.stats.failure_count == 0  # Should reset on successful recovery

    @pytest.mark.asyncio
    async def test_half_open_failure_reopens_circuit(self):
        """Test failed call in half-open state reopens circuit."""
        config = ResilienceConfig(
            failure_threshold=1, recovery_timeout_seconds=0.1, success_threshold=1
        )
        cb = CircuitBreaker("test", config)

        # Open circuit
        async def fail_func():
            raise ValueError("test error")

        with pytest.raises(ValueError):
            await cb.call(fail_func)

        # Wait for recovery timeout
        await asyncio.sleep(0.2)

        # Failed call should reopen circuit
        with pytest.raises(ValueError):
            await cb.call(fail_func)
        assert cb.stats.state == CircuitBreakerState.OPEN

    @pytest.mark.asyncio
    async def test_concurrent_calls(self):
        """Test circuit breaker with concurrent calls."""
        config = ResilienceConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config)

        async def slow_success():
            await asyncio.sleep(0.1)
            return "success"

        # Make multiple concurrent calls
        tasks = [cb.call(slow_success) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        assert all(r == "success" for r in results)
        assert cb.stats.success_count == 5
        assert cb.stats.total_requests == 5

    @pytest.mark.asyncio
    async def test_function_with_args_and_kwargs(self):
        """Test circuit breaker with function arguments."""
        config = ResilienceConfig()
        cb = CircuitBreaker("test", config)

        async def func_with_args(a, b, c=None):
            return f"{a}-{b}-{c}"

        result = await cb.call(func_with_args, "arg1", "arg2", c="kwarg1")
        assert result == "arg1-arg2-kwarg1"

    @pytest.mark.asyncio
    async def test_reset_circuit_breaker(self):
        """Test manual reset of circuit breaker."""
        config = ResilienceConfig(failure_threshold=1)
        cb = CircuitBreaker("test", config)

        async def fail_func():
            raise ValueError("test error")

        # Open circuit
        with pytest.raises(ValueError):
            await cb.call(fail_func)
        assert cb.stats.state == CircuitBreakerState.OPEN

        # Reset circuit
        await cb.reset()
        assert cb.stats.state == CircuitBreakerState.CLOSED
        assert cb.stats.failure_count == 0
        assert cb.stats.success_count == 0

    def test_circuit_breaker_error(self):
        """Test CircuitBreakerError properties."""
        import time

        stats = CircuitBreakerStats(
            name="test_circuit",
            state=CircuitBreakerState.OPEN,
            last_failure_time=time.time() - 10.0,  # 10 seconds ago
        )
        error = CircuitBreakerError("test_circuit", stats)

        assert "test_circuit" in str(error)
        assert "open" in str(error).lower()
        assert error.name == "test_circuit"
        assert error.stats == stats

    @pytest.mark.asyncio
    async def test_sync_function_call(self):
        """Test circuit breaker with synchronous function."""
        config = ResilienceConfig()
        cb = CircuitBreaker("test", config)

        def sync_func():
            return "sync_result"

        result = await cb.call(sync_func)
        assert result == "sync_result"

    @pytest.mark.asyncio
    async def test_exception_handling_preserves_original(self):
        """Test that original exceptions are preserved."""
        config = ResilienceConfig(failure_threshold=2)
        cb = CircuitBreaker("test", config)

        class CustomError(Exception):
            def __init__(self, msg, code):
                super().__init__(msg)
                self.code = code

        async def custom_fail():
            raise CustomError("custom message", 42)

        with pytest.raises(CustomError) as exc_info:
            await cb.call(custom_fail)

        assert str(exc_info.value) == "custom message"
        assert exc_info.value.code == 42
