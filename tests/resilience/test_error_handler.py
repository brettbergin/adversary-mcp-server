"""Tests for error handler orchestration."""

import pytest

from adversary_mcp_server.resilience.circuit_breaker import CircuitBreakerError
from adversary_mcp_server.resilience.error_handler import ErrorHandler
from adversary_mcp_server.resilience.types import (
    ErrorCategory,
    RecoveryAction,
    ResilienceConfig,
)


class TestErrorHandler:
    """Test ErrorHandler orchestration functionality."""

    def test_initialization(self):
        """Test error handler initialization."""
        config = ResilienceConfig()
        handler = ErrorHandler(config)
        assert handler.config == config
        assert handler.retry_manager is not None
        assert handler.circuit_breakers.get_breaker_count() == 0

    def test_initialization_with_disabled_features(self):
        """Test initialization with disabled features."""
        config = ResilienceConfig(enable_circuit_breaker=False, enable_retry=False)
        handler = ErrorHandler(config)
        assert handler.config == config

    @pytest.mark.asyncio
    async def test_successful_execution(self):
        """Test successful function execution without errors."""
        handler = ErrorHandler(ResilienceConfig())

        async def success_func():
            return "success"

        result = await handler.execute_with_recovery(success_func, "test_op")
        assert result.success
        assert result.result == "success"

    @pytest.mark.asyncio
    async def test_execution_with_retry_success(self):
        """Test execution that succeeds after retries."""
        config = ResilienceConfig(
            enable_retry=True, max_retry_attempts=3, base_delay_seconds=0.01
        )
        handler = ErrorHandler(config)

        call_count = 0

        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("temporary error")
            return "success after retry"

        result = await handler.execute_with_recovery(fail_then_succeed, "test_op")
        assert result.success
        assert result.result == "success after retry"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_execution_with_circuit_breaker(self):
        """Test execution with circuit breaker protection."""
        config = ResilienceConfig(
            enable_circuit_breaker=True,
            enable_retry=False,  # Disable retry to test circuit breaker behavior directly
            failure_threshold=2,
            recovery_timeout_seconds=0.1,
        )
        handler = ErrorHandler(config)

        async def always_fail():
            raise ValueError("persistent error")

        # First call should fail normally
        with pytest.raises(ValueError):
            await handler.execute_with_recovery(
                always_fail, "test_op", circuit_breaker_name="test_breaker"
            )

        # Second call should fail and open circuit
        with pytest.raises(ValueError):
            await handler.execute_with_recovery(
                always_fail, "test_op", circuit_breaker_name="test_breaker"
            )

        # Third call should be rejected by circuit breaker
        with pytest.raises(CircuitBreakerError):
            await handler.execute_with_recovery(
                always_fail, "test_op", circuit_breaker_name="test_breaker"
            )

    @pytest.mark.asyncio
    async def test_execution_with_fallback(self):
        """Test execution with fallback function."""
        handler = ErrorHandler(ResilienceConfig(enable_retry=False))

        async def always_fail():
            raise ValueError("main function failed")

        async def fallback_func():
            return "fallback result"

        result = await handler.execute_with_recovery(
            always_fail, "test_op", fallback_func=fallback_func
        )
        assert result.success
        assert result.result == "fallback result"

    @pytest.mark.asyncio
    async def test_fallback_with_args_and_kwargs(self):
        """Test fallback function receives original args and kwargs."""
        handler = ErrorHandler(ResilienceConfig(enable_retry=False))

        async def always_fail(a, b, c=None):
            raise ValueError("main function failed")

        received_args = []
        received_kwargs = {}

        async def fallback_func(*args, **kwargs):
            received_args.extend(args)
            received_kwargs.update(kwargs)
            return "fallback result"

        result = await handler.execute_with_recovery(
            always_fail,
            "test_op",
            None,
            fallback_func,
            None,
            "arg1",
            "arg2",
            c="kwarg1",
        )

        assert result.success
        assert result.result == "fallback result"
        assert received_args == ["arg1", "arg2"]
        assert received_kwargs == {"c": "kwarg1"}

    @pytest.mark.asyncio
    async def test_error_classification(self):
        """Test error classification functionality."""
        handler = ErrorHandler(ResilienceConfig())

        # Test different error types
        network_error = ConnectionError("network issue")
        timeout_error = TimeoutError("operation timed out")
        value_error = ValueError("some error message")

        assert handler._classify_error(network_error, None) == ErrorCategory.NETWORK
        assert handler._classify_error(timeout_error, None) == ErrorCategory.TIMEOUT
        assert handler._classify_error(value_error, None) == ErrorCategory.UNKNOWN

    def test_recovery_strategy_setup(self):
        """Test recovery strategy setup."""
        config = ResilienceConfig(
            enable_retry=True,
            enable_circuit_breaker=True,
            enable_graceful_degradation=True,
        )
        handler = ErrorHandler(config)

        # Check that default strategies are registered
        assert ErrorCategory.NETWORK in handler.recovery_strategies
        assert ErrorCategory.API_RATE_LIMIT in handler.recovery_strategies
        assert ErrorCategory.TIMEOUT in handler.recovery_strategies

        # Network errors should use retry strategy
        network_strategy = handler.recovery_strategies[ErrorCategory.NETWORK]
        assert network_strategy.action == RecoveryAction.RETRY

    @pytest.mark.asyncio
    async def test_api_rate_limit_handling(self):
        """Test API rate limit error handling."""
        config = ResilienceConfig(
            enable_retry=True, max_retry_attempts=2, base_delay_seconds=0.01
        )
        handler = ErrorHandler(config)

        # Simulate rate limit error
        class RateLimitError(Exception):
            pass

        call_count = 0

        async def rate_limited_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RateLimitError("rate limit exceeded")
            return "success after rate limit"

        result = await handler.execute_with_recovery(rate_limited_func, "api_call")
        assert result.success
        assert result.result == "success after rate limit"

    @pytest.mark.asyncio
    async def test_graceful_degradation_config(self):
        """Test graceful degradation configuration."""
        config = ResilienceConfig(enable_graceful_degradation=True, enable_retry=False)
        handler = ErrorHandler(config)

        async def always_fail():
            raise ValueError("service unavailable")

        async def degraded_fallback():
            return "degraded service result"

        result = await handler.execute_with_recovery(
            always_fail, "service_call", fallback_func=degraded_fallback
        )
        assert result.success
        assert result.result == "degraded service result"

    @pytest.mark.asyncio
    async def test_circuit_breaker_creation_and_reuse(self):
        """Test circuit breaker creation and reuse."""
        config = ResilienceConfig(enable_circuit_breaker=True)
        handler = ErrorHandler(config)

        async def test_func():
            return "test"

        # First call should create circuit breaker
        await handler.execute_with_recovery(
            test_func, "test_op", circuit_breaker_name="test_breaker"
        )
        assert handler.circuit_breakers.get_breaker_count() >= 1

        # Second call should reuse existing breaker
        original_breaker = await handler.circuit_breakers.get_breaker("test_breaker")
        await handler.execute_with_recovery(
            test_func, "test_op", circuit_breaker_name="test_breaker"
        )
        same_breaker = await handler.circuit_breakers.get_breaker("test_breaker")
        assert same_breaker is original_breaker

    @pytest.mark.asyncio
    async def test_sync_function_execution(self):
        """Test execution with synchronous function."""
        handler = ErrorHandler(ResilienceConfig())

        def sync_func():
            return "sync result"

        result = await handler.execute_with_recovery(sync_func, "sync_op")
        assert result.success
        assert result.result == "sync result"

    @pytest.mark.asyncio
    async def test_sync_fallback_function(self):
        """Test execution with synchronous fallback function."""
        handler = ErrorHandler(ResilienceConfig(enable_retry=False))

        async def async_fail():
            raise ValueError("async failed")

        def sync_fallback():
            return "sync fallback"

        result = await handler.execute_with_recovery(
            async_fail, "test_op", fallback_func=sync_fallback
        )
        assert result.success
        assert result.result == "sync fallback"

    @pytest.mark.asyncio
    async def test_complex_error_recovery_workflow(self):
        """Test complex error recovery workflow with all features."""
        config = ResilienceConfig(
            enable_retry=True,
            enable_circuit_breaker=True,
            enable_graceful_degradation=True,
            max_retry_attempts=2,
            failure_threshold=3,
            base_delay_seconds=0.01,
        )
        handler = ErrorHandler(config)

        call_count = 0

        async def intermittent_service():
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                raise ConnectionError("network error")  # Should retry
            return "service recovered"

        async def service_fallback():
            return "fallback service"

        result = await handler.execute_with_recovery(
            intermittent_service,
            "complex_service",
            circuit_breaker_name="service_breaker",
            fallback_func=service_fallback,
        )

        assert result.success
        assert result.result == "service recovered"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_disabled_features_fallback_only(self):
        """Test behavior when retry and circuit breaker are disabled."""
        config = ResilienceConfig(
            enable_retry=False,
            enable_circuit_breaker=False,
            enable_graceful_degradation=True,
        )
        handler = ErrorHandler(config)

        async def always_fail():
            raise ValueError("service error")

        async def simple_fallback():
            return "fallback only"

        result = await handler.execute_with_recovery(
            always_fail, "simple_op", fallback_func=simple_fallback
        )
        assert result.success
        assert result.result == "fallback only"

    @pytest.mark.asyncio
    async def test_no_recovery_options_propagates_error(self):
        """Test that errors propagate when no recovery options are available."""
        config = ResilienceConfig(
            enable_retry=False,
            enable_circuit_breaker=False,
            enable_graceful_degradation=False,
        )
        handler = ErrorHandler(config)

        async def always_fail():
            raise ValueError("unrecoverable error")

        with pytest.raises(ValueError, match="unrecoverable error"):
            await handler.execute_with_recovery(always_fail, "no_recovery_op")

    @pytest.mark.asyncio
    async def test_timeout_error_handling(self):
        """Test specific timeout error handling."""
        config = ResilienceConfig(
            enable_retry=True, max_retry_attempts=2, base_delay_seconds=0.01
        )
        handler = ErrorHandler(config)

        call_count = 0

        async def timeout_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise TimeoutError("operation timed out")
            return "completed after timeout"

        result = await handler.execute_with_recovery(timeout_then_succeed, "timeout_op")
        assert result.success
        assert result.result == "completed after timeout"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_custom_error_with_attributes(self):
        """Test handling of custom errors with additional attributes."""
        handler = ErrorHandler(ResilienceConfig(enable_retry=False))

        class CustomServiceError(Exception):
            def __init__(self, message, error_code, retry_after=None):
                super().__init__(message)
                self.error_code = error_code
                self.retry_after = retry_after

        async def custom_fail():
            raise CustomServiceError("Service unavailable", 503, retry_after=30)

        async def error_aware_fallback():
            return "custom fallback"

        result = await handler.execute_with_recovery(
            custom_fail, "custom_op", fallback_func=error_aware_fallback
        )
        assert result.success
        assert result.result == "custom fallback"
