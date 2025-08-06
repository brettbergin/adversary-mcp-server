"""Integration tests for resilience framework."""

import asyncio

import pytest

from adversary_mcp_server.resilience import ErrorHandler, ResilienceConfig, RetryManager
from adversary_mcp_server.resilience.circuit_breaker import CircuitBreakerError


class TestResilienceIntegration:
    """Test integration between resilience components."""

    @pytest.mark.asyncio
    async def test_error_handler_with_retry_and_circuit_breaker(self):
        """Test error handler orchestrating retry and circuit breaker."""
        config = ResilienceConfig(
            enable_retry=True,
            enable_circuit_breaker=True,
            max_retry_attempts=2,
            failure_threshold=3,
            base_delay_seconds=0.01,
            recovery_timeout_seconds=0.1,
        )

        handler = ErrorHandler(config)

        call_count = 0

        async def intermittent_service():
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                raise ConnectionError("network error")
            return f"success on attempt {call_count}"

        # Should succeed after retry
        result = await handler.execute_with_recovery(
            intermittent_service, "test_service", circuit_breaker_name="test_breaker"
        )

        assert result.success
        assert result.result == "success on attempt 2"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_circuit_breaker_prevents_retry_spam(self):
        """Test circuit breaker prevents excessive retries."""
        config = ResilienceConfig(
            enable_retry=True,
            enable_circuit_breaker=True,
            max_retry_attempts=5,
            failure_threshold=2,
            base_delay_seconds=0.01,
        )

        handler = ErrorHandler(config)

        async def always_fail():
            raise ValueError("persistent error")

        # First call - should retry and fail
        with pytest.raises(ValueError):
            await handler.execute_with_recovery(
                always_fail, "failing_service", circuit_breaker_name="fail_breaker"
            )

        # Second call - should retry and fail, opening circuit
        with pytest.raises(ValueError):
            await handler.execute_with_recovery(
                always_fail, "failing_service", circuit_breaker_name="fail_breaker"
            )

        # Third call - should be rejected by circuit breaker without retries
        with pytest.raises(CircuitBreakerError):
            await handler.execute_with_recovery(
                always_fail, "failing_service", circuit_breaker_name="fail_breaker"
            )

    @pytest.mark.asyncio
    async def test_fallback_with_retry_failure(self):
        """Test fallback is used when retries are exhausted."""
        config = ResilienceConfig(
            enable_retry=True, max_retry_attempts=2, base_delay_seconds=0.01
        )

        handler = ErrorHandler(config)

        async def always_fail():
            raise ValueError("service unavailable")

        async def reliable_fallback():
            return "fallback result"

        result = await handler.execute_with_recovery(
            always_fail, "unreliable_service", fallback_func=reliable_fallback
        )

        assert result.success
        assert result.result == "fallback result"

    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery_integration(self):
        """Test circuit breaker recovery after timeout."""
        config = ResilienceConfig(
            enable_circuit_breaker=True,
            enable_retry=False,  # Disable retry to test circuit breaker directly
            failure_threshold=2,
            recovery_timeout_seconds=0.1,
        )

        handler = ErrorHandler(config)

        async def service_that_always_fails():
            raise ValueError("persistent error")

        # First call - should fail normally
        with pytest.raises(ValueError):
            await handler.execute_with_recovery(
                service_that_always_fails,
                "recovery_service",
                circuit_breaker_name="recovery_breaker",
            )

        # Second call - should fail and open circuit
        with pytest.raises(ValueError):
            await handler.execute_with_recovery(
                service_that_always_fails,
                "recovery_service",
                circuit_breaker_name="recovery_breaker",
            )

        # Circuit should be open - should be rejected by circuit breaker
        with pytest.raises(CircuitBreakerError):
            await handler.execute_with_recovery(
                service_that_always_fails,
                "recovery_service",
                circuit_breaker_name="recovery_breaker",
            )

        # Wait for recovery timeout
        await asyncio.sleep(0.2)

        # Define a function that succeeds
        async def service_that_recovers():
            return "service recovered"

        # Should succeed and close circuit
        result = await handler.execute_with_recovery(
            service_that_recovers,
            "recovery_service",
            circuit_breaker_name="recovery_breaker",
        )

        assert result.success
        assert result.result == "service recovered"

    @pytest.mark.asyncio
    async def test_multiple_circuit_breakers(self):
        """Test multiple independent circuit breakers."""
        config = ResilienceConfig(enable_circuit_breaker=True, failure_threshold=2)

        handler = ErrorHandler(config)

        async def service_a_fail():
            raise ValueError("service A error")

        async def service_b_success():
            return "service B success"

        # Fail service A to open its breaker
        with pytest.raises(ValueError):
            await handler.execute_with_recovery(
                service_a_fail, "service_a", circuit_breaker_name="breaker_a"
            )

        with pytest.raises(ValueError):
            await handler.execute_with_recovery(
                service_a_fail, "service_a", circuit_breaker_name="breaker_a"
            )

        # Service A breaker should be open
        with pytest.raises(CircuitBreakerError):
            await handler.execute_with_recovery(
                service_a_fail, "service_a", circuit_breaker_name="breaker_a"
            )

        # Service B should still work (independent breaker)
        result = await handler.execute_with_recovery(
            service_b_success, "service_b", circuit_breaker_name="breaker_b"
        )

        assert result.success
        assert result.result == "service B success"

    @pytest.mark.asyncio
    async def test_retry_with_different_strategies(self):
        """Test retry manager with different backoff strategies."""
        config = ResilienceConfig(
            max_retry_attempts=3, base_delay_seconds=0.01, max_delay_seconds=0.1
        )

        retry_manager = RetryManager(config)

        call_counts = {}

        async def fail_twice(strategy_name):
            if strategy_name not in call_counts:
                call_counts[strategy_name] = 0
            call_counts[strategy_name] += 1

            if call_counts[strategy_name] <= 2:
                raise ValueError("temporary error")
            return f"success with {strategy_name}"

        from adversary_mcp_server.resilience.retry_manager import RetryStrategy

        # Test different strategies
        strategies = [
            RetryStrategy.EXPONENTIAL_BACKOFF,
            RetryStrategy.LINEAR_BACKOFF,
            RetryStrategy.FIXED_DELAY,
            RetryStrategy.FIXED_DELAY,
        ]

        for strategy in strategies:
            result = await retry_manager.execute_with_retry(
                fail_twice,
                f"test_{strategy.value}",
                strategy.value,
                retry_strategy=strategy,
            )
            assert result == f"success with {strategy.value}"

    @pytest.mark.asyncio
    async def test_graceful_degradation_workflow(self):
        """Test complete graceful degradation workflow."""
        config = ResilienceConfig(
            enable_retry=True,
            enable_circuit_breaker=True,
            enable_graceful_degradation=True,
            max_retry_attempts=2,
            failure_threshold=2,
            base_delay_seconds=0.01,
        )

        handler = ErrorHandler(config)

        # Simulate a service that's completely down
        async def primary_service():
            raise ConnectionError("service unavailable")

        # Degraded service that provides minimal functionality
        async def degraded_service():
            return "degraded response"

        # Should exhaust retries and fall back to degraded service
        result = await handler.execute_with_recovery(
            primary_service,
            "primary_service",
            circuit_breaker_name="primary_breaker",
            fallback_func=degraded_service,
        )

        assert result.success
        assert result.result == "degraded response"

    @pytest.mark.asyncio
    async def test_concurrent_resilience_operations(self):
        """Test resilience framework under concurrent load."""
        config = ResilienceConfig(
            enable_retry=True,
            enable_circuit_breaker=True,
            max_retry_attempts=2,
            failure_threshold=5,
            base_delay_seconds=0.01,
        )

        handler = ErrorHandler(config)

        async def variable_service(task_id):
            # Some tasks fail, some succeed
            if task_id % 3 == 0:
                raise ValueError(f"task {task_id} failed")
            return f"task {task_id} success"

        async def fallback_service(task_id):
            return f"task {task_id} fallback"

        # Run many concurrent operations
        tasks = []
        for i in range(20):
            # Create a proper fallback function that accepts task_id
            async def make_fallback(task_id):
                return await fallback_service(task_id)

            task = handler.execute_with_recovery(
                variable_service,
                f"service_task_{i}",
                circuit_breaker_name="concurrent_breaker",
                fallback_func=make_fallback,
                task_id=i,  # task_id passed as kwargs
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All tasks should complete (either succeed or use fallback)
        assert len(results) == 20
        successful_results = [
            r for r in results if not isinstance(r, Exception) and r.success
        ]
        assert len(successful_results) == 20  # All should succeed or fallback

    @pytest.mark.asyncio
    async def test_error_classification_affects_recovery(self):
        """Test that error classification affects recovery strategy."""
        config = ResilienceConfig(
            enable_retry=True,
            enable_graceful_degradation=True,
            max_retry_attempts=1,
            base_delay_seconds=0.01,
        )

        handler = ErrorHandler(config)

        # Network errors should be retried
        network_call_count = 0

        async def network_error_service():
            nonlocal network_call_count
            network_call_count += 1
            if network_call_count <= 1:
                raise ConnectionError("network error")
            return "network success"

        result = await handler.execute_with_recovery(
            network_error_service, "network_service"
        )
        assert result.success
        assert result.result == "network success"
        assert network_call_count == 2  # Should have retried

        # Application errors might not be retried as aggressively
        app_call_count = 0

        async def app_error_service():
            nonlocal app_call_count
            app_call_count += 1
            raise ValueError("application error")

        async def app_fallback():
            return "app fallback"

        result = await handler.execute_with_recovery(
            app_error_service, "app_service", fallback_func=app_fallback
        )
        assert result.success
        assert result.result == "app fallback"

    @pytest.mark.asyncio
    async def test_resilience_with_timeouts(self):
        """Test resilience framework with timeout handling."""
        config = ResilienceConfig(
            enable_retry=True,
            max_retry_attempts=2,
            base_delay_seconds=0.01,
            llm_timeout_seconds=0.1,
        )

        handler = ErrorHandler(config)

        timeout_count = 0

        async def timeout_service():
            nonlocal timeout_count
            timeout_count += 1
            if timeout_count <= 1:
                raise TimeoutError("operation timed out")
            return "completed after timeout"

        result = await handler.execute_with_recovery(timeout_service, "timeout_service")

        assert result.success
        assert result.result == "completed after timeout"
        assert timeout_count == 2

    @pytest.mark.asyncio
    async def test_resilience_disabled_features(self):
        """Test resilience framework with all features disabled."""
        config = ResilienceConfig(
            enable_retry=False,
            enable_circuit_breaker=False,
            enable_graceful_degradation=False,
        )

        handler = ErrorHandler(config)

        async def failing_service():
            raise ValueError("service error")

        # Should propagate error directly without any recovery
        with pytest.raises(ValueError, match="service error"):
            await handler.execute_with_recovery(failing_service, "no_recovery_service")

    @pytest.mark.asyncio
    async def test_resilience_stats_and_monitoring(self):
        """Test resilience framework provides useful stats."""
        config = ResilienceConfig(enable_circuit_breaker=True, failure_threshold=3)

        handler = ErrorHandler(config)

        async def monitored_service():
            return "success"

        async def failing_service():
            raise ValueError("error")

        # Successful calls
        for _ in range(5):
            result = await handler.execute_with_recovery(
                monitored_service, "monitored", circuit_breaker_name="stats_breaker"
            )
            assert result.success

        # Some failures
        for _ in range(2):
            with pytest.raises(ValueError):
                await handler.execute_with_recovery(
                    failing_service, "monitored", circuit_breaker_name="stats_breaker"
                )

        # Check circuit breaker stats
        breaker = await handler.circuit_breakers.get_breaker("stats_breaker")
        assert breaker.stats.success_count == 5
        assert breaker.stats.failure_count == 2
        assert breaker.stats.total_requests == 7
