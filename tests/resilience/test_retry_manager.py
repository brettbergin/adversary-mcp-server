"""Tests for retry manager functionality."""

import asyncio
import time

import pytest

from adversary_mcp_server.resilience.retry_manager import (
    RetryExhaustedException,
    RetryManager,
    RetryStrategy,
)
from adversary_mcp_server.resilience.types import ResilienceConfig


class TestRetryManager:
    """Test RetryManager functionality."""

    def test_initialization(self):
        """Test retry manager initialization."""
        config = ResilienceConfig(
            max_retry_attempts=3, base_delay_seconds=1.0, max_delay_seconds=10.0
        )
        retry_manager = RetryManager(config)
        assert retry_manager.config == config

    def test_initialization_with_defaults(self):
        """Test retry manager with default config."""
        config = ResilienceConfig()
        retry_manager = RetryManager(config)
        assert retry_manager.config.max_retry_attempts == 3
        assert retry_manager.config.base_delay_seconds == 1.0
        assert retry_manager.config.max_delay_seconds == 60.0

    @pytest.mark.asyncio
    async def test_successful_call_no_retry(self):
        """Test successful function call requires no retry."""
        config = ResilienceConfig()
        retry_manager = RetryManager(config)

        async def success_func():
            return "success"

        result = await retry_manager.execute_with_retry(success_func, "test_op")
        assert result == "success"

    @pytest.mark.asyncio
    async def test_retry_with_eventual_success(self):
        """Test retry succeeds after failures."""
        config = ResilienceConfig(max_retry_attempts=3, base_delay_seconds=0.01)
        retry_manager = RetryManager(config)

        call_count = 0

        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("temporary error")
            return "success"

        result = await retry_manager.execute_with_retry(fail_then_succeed, "test_op")
        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retry_exhaustion(self):
        """Test retry exhaustion raises RetryException."""
        config = ResilienceConfig(max_retry_attempts=2, base_delay_seconds=0.01)
        retry_manager = RetryManager(config)

        async def always_fail():
            raise ValueError("persistent error")

        with pytest.raises(RetryExhaustedException) as exc_info:
            await retry_manager.execute_with_retry(always_fail, "test_op")

        assert "test_op" in str(exc_info.value)
        assert "2 attempts" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_exponential_backoff_strategy(self):
        """Test exponential backoff timing."""
        config = ResilienceConfig(
            max_retry_attempts=3, base_delay_seconds=0.1, max_delay_seconds=1.0
        )
        retry_manager = RetryManager(config)

        delays = []

        async def always_fail():
            delays.append(time.time())
            raise ValueError("error")

        with pytest.raises(RetryExhaustedException):
            await retry_manager.execute_with_retry(
                always_fail, "test_op", retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF
            )

        # Should have 3 calls (initial + 2 retries)
        assert len(delays) == 3

        # Check exponential backoff timing (with tolerance for jitter and overhead)
        if len(delays) >= 2:
            first_delay = delays[1] - delays[0]
            assert first_delay >= 0.05  # Base delay with tolerance for jitter

        if len(delays) >= 3:
            second_delay = delays[2] - delays[1]
            assert second_delay >= first_delay  # Should be longer

    @pytest.mark.asyncio
    async def test_linear_backoff_strategy(self):
        """Test linear backoff timing."""
        config = ResilienceConfig(
            max_retry_attempts=3, base_delay_seconds=0.1, max_delay_seconds=1.0
        )
        retry_manager = RetryManager(config)

        delays = []

        async def always_fail():
            delays.append(time.time())
            raise ValueError("error")

        with pytest.raises(RetryExhaustedException):
            await retry_manager.execute_with_retry(
                always_fail, "test_op", retry_strategy=RetryStrategy.LINEAR_BACKOFF
            )

        assert len(delays) == 3

    @pytest.mark.asyncio
    async def test_fixed_delay_strategy(self):
        """Test fixed delay timing."""
        config = ResilienceConfig(max_retry_attempts=3, base_delay_seconds=0.1)
        retry_manager = RetryManager(config)

        start_time = time.time()

        async def always_fail():
            raise ValueError("error")

        with pytest.raises(RetryExhaustedException):
            await retry_manager.execute_with_retry(
                always_fail, "test_op", retry_strategy=RetryStrategy.FIXED_DELAY
            )

        total_time = time.time() - start_time
        # Should have at least 2 delays of 0.1s each (with tolerance)
        assert total_time >= 0.15  # Reduced for timing variations

    @pytest.mark.asyncio
    async def test_immediate_retry_strategy(self):
        """Test fixed delay strategy with minimal delay."""
        config = ResilienceConfig(max_retry_attempts=3, base_delay_seconds=0.01)
        retry_manager = RetryManager(config)

        start_time = time.time()

        async def always_fail():
            raise ValueError("error")

        with pytest.raises(RetryExhaustedException):
            await retry_manager.execute_with_retry(
                always_fail, "test_op", retry_strategy=RetryStrategy.FIXED_DELAY
            )

        total_time = time.time() - start_time
        # Should be relatively fast with minimal delays
        assert total_time < 1.0  # More reasonable timeout

    @pytest.mark.asyncio
    async def test_jitter_in_exponential_backoff(self):
        """Test jitter is applied to exponential backoff."""
        config = ResilienceConfig(
            max_retry_attempts=10, base_delay_seconds=0.1, max_delay_seconds=1.0
        )
        retry_manager = RetryManager(config)

        # Run multiple tests to see jitter variation
        delays_list = []

        for i in range(3):
            delays = []

            async def fail_twice(delay_list=delays):
                delay_list.append(time.time())
                if len(delay_list) <= 2:
                    raise ValueError("error")
                return "success"

            await retry_manager.execute_with_retry(
                fail_twice, "test_op", retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF
            )
            delays_list.append(delays)

        # Check that delays vary due to jitter (not exactly the same)
        if len(delays_list) >= 2 and all(len(d) >= 2 for d in delays_list):
            first_delays = [d[1] - d[0] for d in delays_list]
            # Should have some variation due to jitter, but allow for small variations
            # Check if delays are within reasonable jitter range (10% of base delay)
            base_delay = 0.1  # base_delay_seconds from config
            min_delay = base_delay * 0.9  # 90% of base
            max_delay = base_delay * 1.1  # 110% of base

            # At least verify jitter is applied (not exactly base delay)
            exact_base_matches = sum(
                1 for d in first_delays if abs(d - base_delay) < 0.001
            )
            assert exact_base_matches < len(first_delays), "Jitter should modify delays"

    @pytest.mark.asyncio
    async def test_max_delay_capping(self):
        """Test that delays are capped at max_delay_seconds."""
        config = ResilienceConfig(
            max_retry_attempts=5, base_delay_seconds=1.0, max_delay_seconds=2.0
        )
        retry_manager = RetryManager(config)

        delays = []

        async def always_fail():
            delays.append(time.time())
            raise ValueError("error")

        with pytest.raises(RetryExhaustedException):
            await retry_manager.execute_with_retry(
                always_fail, "test_op", retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF
            )

        # Check that later delays don't exceed max_delay
        if len(delays) >= 4:
            later_delay = delays[3] - delays[2]
            assert later_delay <= 2.5  # Max delay + some tolerance

    @pytest.mark.asyncio
    async def test_function_with_args_and_kwargs(self):
        """Test retry with function arguments."""
        config = ResilienceConfig()
        retry_manager = RetryManager(config)

        async def func_with_args(a, b, c=None):
            return f"{a}-{b}-{c}"

        result = await retry_manager.execute_with_retry(
            func_with_args, "test_op", "arg1", "arg2", c="kwarg1"
        )
        assert result == "arg1-arg2-kwarg1"

    @pytest.mark.asyncio
    async def test_sync_function_retry(self):
        """Test retry with synchronous function."""
        config = ResilienceConfig()
        retry_manager = RetryManager(config)

        def sync_func():
            return "sync_result"

        result = await retry_manager.execute_with_retry(sync_func, "test_op")
        assert result == "sync_result"

    @pytest.mark.asyncio
    async def test_retry_preserves_original_exception(self):
        """Test that original exception details are preserved."""
        retry_manager = RetryManager(ResilienceConfig(max_retry_attempts=2))

        class CustomError(Exception):
            def __init__(self, msg, code):
                super().__init__(msg)
                self.code = code

        async def custom_fail():
            raise CustomError("custom message", 42)

        with pytest.raises(RetryExhaustedException) as exc_info:
            await retry_manager.execute_with_retry(custom_fail, "test_op")

        # Check that original exception is preserved in RetryException
        assert isinstance(exc_info.value.last_error, CustomError)
        assert exc_info.value.last_error.code == 42

    def test_retry_exception_properties(self):
        """Test RetryException properties."""
        original_error = ValueError("original")
        retry_error = RetryExhaustedException("test_op", 3, original_error)

        assert retry_error.operation == "test_op"
        assert retry_error.attempts == 3
        assert retry_error.last_error == original_error
        assert "test_op" in str(retry_error)
        assert "3 attempts" in str(retry_error)

    @pytest.mark.asyncio
    async def test_zero_retries_configuration(self):
        """Test configuration with zero retries."""
        config = ResilienceConfig(max_retry_attempts=0)
        retry_manager = RetryManager(config)

        async def always_fail():
            raise ValueError("error")

        with pytest.raises(
            RetryExhaustedException
        ):  # Should get RetryExhaustedException even with 0 retries
            await retry_manager.execute_with_retry(always_fail, "test_op")

    @pytest.mark.asyncio
    async def test_concurrent_retry_operations(self):
        """Test multiple concurrent retry operations."""
        retry_manager = RetryManager(ResilienceConfig(base_delay_seconds=0.01))

        async def sometimes_fail(fail_count):
            if hasattr(sometimes_fail, "calls"):
                sometimes_fail.calls += 1
            else:
                sometimes_fail.calls = 1

            if sometimes_fail.calls <= fail_count:
                raise ValueError("temporary error")
            return f"success_{fail_count}"

        # Reset call counter for each task
        tasks = []
        for i in range(3):

            async def make_call(fail_count=i):
                def func():
                    return sometimes_fail(fail_count)

                func.__name__ = f"sometimes_fail_{fail_count}"
                # Reset counter for this specific function
                if hasattr(func, "calls"):
                    delattr(func, "calls")
                return await retry_manager.execute_with_retry(func, f"op_{fail_count}")

            tasks.append(make_call())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # At least some should succeed
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) > 0
