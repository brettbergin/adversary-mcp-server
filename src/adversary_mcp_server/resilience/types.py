"""Type definitions for resilience and error recovery system."""

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ErrorCategory(str, Enum):
    """Categories of errors for different handling strategies."""

    NETWORK = "network"
    API_RATE_LIMIT = "api_rate_limit"
    API_QUOTA_EXCEEDED = "api_quota_exceeded"
    API_AUTHENTICATION = "api_authentication"
    API_SERVER_ERROR = "api_server_error"
    TIMEOUT = "timeout"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    VALIDATION_ERROR = "validation_error"
    CONFIGURATION_ERROR = "configuration_error"
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    """Actions to take when recovering from errors."""

    RETRY = "retry"
    FALLBACK = "fallback"
    CIRCUIT_BREAK = "circuit_break"
    SKIP = "skip"
    FAIL = "fail"
    DEGRADE = "degrade"


class RetryStrategy(str, Enum):
    """Retry strategies for different types of failures."""

    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    JITTER = "jitter"
    NO_RETRY = "no_retry"


class CircuitBreakerState(str, Enum):
    """States of a circuit breaker."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit is open, requests fail fast
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class ResilienceConfig:
    """Configuration for resilience and error recovery."""

    # Circuit breaker settings
    enable_circuit_breaker: bool = True
    failure_threshold: int = 5  # Number of failures before opening circuit
    recovery_timeout_seconds: int = 60  # Time before trying half-open
    success_threshold: int = 3  # Successes needed to close circuit from half-open

    # Retry settings
    enable_retry: bool = True
    max_retry_attempts: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    backoff_multiplier: float = 2.0
    jitter_enabled: bool = True

    # Timeout settings
    default_timeout_seconds: float = 30.0
    llm_timeout_seconds: float = 120.0

    # Error handling
    enable_graceful_degradation: bool = True
    fallback_to_cache: bool = True
    skip_on_repeated_failures: bool = True

    # Rate limiting
    enable_rate_limiting: bool = True
    requests_per_minute: int = 100
    burst_limit: int = 10


@dataclass
class ErrorContext:
    """Context information for error handling."""

    error: Exception
    error_category: ErrorCategory
    operation: str
    attempt_number: int
    total_attempts: int
    start_time: float
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Get duration since start of operation."""
        return time.time() - self.start_time

    @property
    def is_final_attempt(self) -> bool:
        """Check if this is the final retry attempt."""
        return self.attempt_number >= self.total_attempts


@dataclass
class RecoveryResult:
    """Result of error recovery attempt."""

    success: bool
    action_taken: RecoveryAction
    result: Any = None
    fallback_used: bool = False
    retry_count: int = 0
    total_duration: float = 0.0
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker monitoring."""

    name: str
    state: CircuitBreakerState
    failure_count: int = 0
    success_count: int = 0
    total_requests: int = 0
    last_failure_time: float | None = None
    last_success_time: float | None = None
    state_change_time: float = field(default_factory=time.time)

    @property
    def failure_rate(self) -> float:
        """Calculate current failure rate."""
        if self.total_requests == 0:
            return 0.0
        return self.failure_count / self.total_requests

    @property
    def time_since_last_failure(self) -> float:
        """Time since last failure in seconds."""
        if self.last_failure_time is None:
            return float("inf")
        return time.time() - self.last_failure_time

    @property
    def time_in_current_state(self) -> float:
        """Time spent in current state in seconds."""
        return time.time() - self.state_change_time

    def to_dict(self) -> dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "total_requests": self.total_requests,
            "failure_rate": round(self.failure_rate * 100, 2),
            "time_since_last_failure": round(self.time_since_last_failure, 2),
            "time_in_current_state": round(self.time_in_current_state, 2),
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
        }


# Type aliases for callback functions
ErrorClassifier = Callable[[Exception], ErrorCategory]
FallbackFunction = Callable[..., Any]
RecoveryCallback = Callable[[ErrorContext], RecoveryResult | None]
