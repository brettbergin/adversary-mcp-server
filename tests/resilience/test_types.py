"""Tests for resilience types and configuration."""

from adversary_mcp_server.resilience.types import (
    ErrorCategory,
    RecoveryAction,
    ResilienceConfig,
)


class TestErrorCategory:
    """Test ErrorCategory enum."""

    def test_error_category_values(self):
        """Test error category enum values."""
        assert ErrorCategory.NETWORK == "network"
        assert ErrorCategory.API_RATE_LIMIT == "api_rate_limit"
        assert ErrorCategory.API_QUOTA_EXCEEDED == "api_quota_exceeded"
        assert ErrorCategory.API_AUTHENTICATION == "api_authentication"
        assert ErrorCategory.API_SERVER_ERROR == "api_server_error"
        assert ErrorCategory.TIMEOUT == "timeout"
        assert ErrorCategory.RESOURCE_EXHAUSTED == "resource_exhausted"
        assert ErrorCategory.VALIDATION_ERROR == "validation_error"
        assert ErrorCategory.CONFIGURATION_ERROR == "configuration_error"
        assert ErrorCategory.UNKNOWN == "unknown"

    def test_error_category_membership(self):
        """Test error category membership."""
        categories = list(ErrorCategory)
        assert len(categories) == 10
        assert ErrorCategory.NETWORK in categories
        assert ErrorCategory.UNKNOWN in categories


class TestRecoveryAction:
    """Test RecoveryAction enum."""

    def test_recovery_action_values(self):
        """Test recovery action enum values."""
        assert RecoveryAction.RETRY == "retry"
        assert RecoveryAction.FALLBACK == "fallback"
        assert RecoveryAction.CIRCUIT_BREAK == "circuit_break"
        assert RecoveryAction.SKIP == "skip"
        assert RecoveryAction.FAIL == "fail"
        assert RecoveryAction.DEGRADE == "degrade"

    def test_recovery_action_membership(self):
        """Test recovery action membership."""
        actions = list(RecoveryAction)
        assert len(actions) == 6
        assert RecoveryAction.RETRY in actions
        assert RecoveryAction.FALLBACK in actions


class TestResilienceConfig:
    """Test ResilienceConfig dataclass."""

    def test_default_configuration(self):
        """Test default resilience configuration."""
        config = ResilienceConfig()

        # Circuit breaker settings
        assert config.enable_circuit_breaker
        assert config.failure_threshold == 5
        assert config.recovery_timeout_seconds == 60.0

        # Retry settings
        assert config.enable_retry
        assert config.max_retry_attempts == 3
        assert config.base_delay_seconds == 1.0
        assert config.max_delay_seconds == 60.0

        # Timeout settings
        assert config.llm_timeout_seconds == 120.0

        # Feature flags
        assert config.enable_graceful_degradation

    def test_custom_configuration(self):
        """Test custom resilience configuration."""
        config = ResilienceConfig(
            enable_circuit_breaker=False,
            failure_threshold=10,
            recovery_timeout_seconds=120.0,
            enable_retry=False,
            max_retry_attempts=5,
            base_delay_seconds=2.0,
            max_delay_seconds=60.0,
            llm_timeout_seconds=90.0,
            enable_graceful_degradation=False,
        )

        assert not config.enable_circuit_breaker
        assert config.failure_threshold == 10
        assert config.recovery_timeout_seconds == 120.0
        assert not config.enable_retry
        assert config.max_retry_attempts == 5
        assert config.base_delay_seconds == 2.0
        assert config.max_delay_seconds == 60.0
        assert config.llm_timeout_seconds == 90.0
        assert not config.enable_graceful_degradation

    def test_config_validation_valid_values(self):
        """Test configuration validation with valid values."""
        config = ResilienceConfig(
            failure_threshold=3,
            recovery_timeout_seconds=30.0,
            max_retry_attempts=2,
            base_delay_seconds=0.5,
            max_delay_seconds=10.0,
            llm_timeout_seconds=45.0,
        )

        # Should not raise any exceptions
        assert config.failure_threshold == 3
        assert config.recovery_timeout_seconds == 30.0

    def test_config_immutability(self):
        """Test that config fields can be modified (not frozen)."""
        config = ResilienceConfig()

        # Should be able to modify fields
        config.failure_threshold = 10
        assert config.failure_threshold == 10

        config.enable_retry = False
        assert not config.enable_retry

    def test_config_with_zero_values(self):
        """Test configuration with zero/minimal values."""
        config = ResilienceConfig(
            failure_threshold=1,
            recovery_timeout_seconds=0.1,
            max_retry_attempts=0,
            base_delay_seconds=0.0,
            max_delay_seconds=0.1,
            llm_timeout_seconds=1.0,
        )

        assert config.failure_threshold == 1
        assert config.recovery_timeout_seconds == 0.1
        assert config.max_retry_attempts == 0
        assert config.base_delay_seconds == 0.0
        assert config.max_delay_seconds == 0.1
        assert config.llm_timeout_seconds == 1.0

    def test_config_boolean_combinations(self):
        """Test various boolean flag combinations."""
        # All features disabled
        config1 = ResilienceConfig(
            enable_circuit_breaker=False,
            enable_retry=False,
            enable_graceful_degradation=False,
        )
        assert not config1.enable_circuit_breaker
        assert not config1.enable_retry
        assert not config1.enable_graceful_degradation

        # Only circuit breaker enabled
        config2 = ResilienceConfig(
            enable_circuit_breaker=True,
            enable_retry=False,
            enable_graceful_degradation=False,
        )
        assert config2.enable_circuit_breaker
        assert not config2.enable_retry
        assert not config2.enable_graceful_degradation

        # Only retry enabled
        config3 = ResilienceConfig(
            enable_circuit_breaker=False,
            enable_retry=True,
            enable_graceful_degradation=False,
        )
        assert not config3.enable_circuit_breaker
        assert config3.enable_retry
        assert not config3.enable_graceful_degradation

    def test_config_dataclass_properties(self):
        """Test that ResilienceConfig is a proper dataclass."""
        config = ResilienceConfig()

        # Should have dataclass fields
        assert hasattr(config, "__dataclass_fields__")

        # Should be able to compare instances
        config1 = ResilienceConfig(failure_threshold=5)
        config2 = ResilienceConfig(failure_threshold=5)
        config3 = ResilienceConfig(failure_threshold=10)

        assert config1 == config2
        assert config1 != config3

    def test_config_repr(self):
        """Test configuration string representation."""
        config = ResilienceConfig(failure_threshold=3, enable_retry=False)
        repr_str = repr(config)

        assert "ResilienceConfig" in repr_str
        assert "failure_threshold=3" in repr_str
        assert "enable_retry=False" in repr_str

    def test_config_field_types(self):
        """Test configuration field types."""
        config = ResilienceConfig()

        # Boolean fields
        assert isinstance(config.enable_circuit_breaker, bool)
        assert isinstance(config.enable_retry, bool)
        assert isinstance(config.enable_graceful_degradation, bool)

        # Integer fields
        assert isinstance(config.failure_threshold, int)
        assert isinstance(config.max_retry_attempts, int)
        assert isinstance(config.recovery_timeout_seconds, int)

        # Float fields
        assert isinstance(config.base_delay_seconds, float)
        assert isinstance(config.max_delay_seconds, float)
        assert isinstance(config.llm_timeout_seconds, float)

    def test_extreme_values(self):
        """Test configuration with extreme values."""
        # Very large values
        config_large = ResilienceConfig(
            failure_threshold=1000,
            recovery_timeout_seconds=3600.0,
            max_retry_attempts=100,
            base_delay_seconds=60.0,
            max_delay_seconds=600.0,
            llm_timeout_seconds=1800.0,
        )

        assert config_large.failure_threshold == 1000
        assert config_large.recovery_timeout_seconds == 3600.0

        # Very small values
        config_small = ResilienceConfig(
            failure_threshold=1,
            recovery_timeout_seconds=0.001,
            max_retry_attempts=1,
            base_delay_seconds=0.001,
            max_delay_seconds=0.1,
            llm_timeout_seconds=0.1,
        )

        assert config_small.failure_threshold == 1
        assert config_small.recovery_timeout_seconds == 0.001
