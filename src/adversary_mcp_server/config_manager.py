"""Enhanced configuration management system with environment variable support and profiles."""

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

import psutil

from .config import SecurityConfig, ValidationFallbackMode
from .logger import get_logger
from .security import sanitize_env_vars

logger = get_logger("config_manager")


class ConfigProfile(str, Enum):
    """Configuration profiles for different environments.

    Simplified to two main profiles:
    - DEVELOPMENT: Local development with lower resource usage
    - PRODUCTION: Production deployment with optimized settings
    """

    DEVELOPMENT = "development"
    PRODUCTION = "production"


class ResourceTier(str, Enum):
    """Resource allocation tiers based on system capabilities.

    Simplified to two tiers for easier management:
    - STANDARD: Normal systems (4+ GB RAM, 2+ cores)
    - HIGH_PERFORMANCE: High-end systems (16+ GB RAM, 8+ cores)
    """

    STANDARD = "standard"  # 4+ GB RAM, 2+ cores
    HIGH_PERFORMANCE = "high_performance"  # 16+ GB RAM, 8+ cores


@dataclass
class DynamicLimits:
    """Dynamic resource limits that auto-scale based on system capabilities.

    These settings are automatically adjusted based on:
    - System RAM and CPU cores (ResourceTier)
    - Configuration profile (DEVELOPMENT vs PRODUCTION)
    - Environment variable overrides

    Most users don't need to modify these directly.
    """

    # ========== CONCURRENCY LIMITS ==========
    # Automatically scaled based on CPU cores
    max_concurrent_scans: int = 8  # Parallel file scans (doubled)
    max_concurrent_batches: int = (
        12  # Parallel LLM batches (6x increase for much better throughput)
    )
    llm_max_batch_size: int = 15  # Files per LLM batch (increased from 8)

    # ========== TIMEOUT CONFIGURATION ==========
    # Prevents hanging operations
    scan_timeout_seconds: int = 300  # Per-file scan timeout
    batch_timeout_seconds: int = 180  # Per-batch processing timeout
    llm_request_timeout_seconds: int = 60  # LLM API call timeout
    recovery_timeout_seconds: int = 90  # Error recovery timeout

    # ========== LLM TOKEN LIMITS ==========
    # Controls LLM context window usage
    llm_max_findings: int = 99999  # Effectively unlimited findings per analysis
    llm_target_tokens: int = 80000  # Target token count
    llm_max_tokens: int = 100000  # Hard limit on tokens
    llm_max_code_length: int = 10000  # Max code snippet length

    # ========== RETRY & RESILIENCE ==========
    # Error handling and recovery
    max_retry_attempts: int = 3  # Retries for failed operations
    retry_base_delay: float = 1.0  # Initial retry delay (seconds)
    retry_max_delay: float = 60.0  # Max retry delay (seconds)
    circuit_breaker_failure_threshold: int = 5  # Failures before circuit opens
    circuit_breaker_recovery_timeout: int = 60  # Recovery time (seconds)

    # ========== STREAMING CONFIGURATION ==========
    # For processing large files
    stream_chunk_size: int = 8192  # Bytes per chunk
    stream_preview_size: int = 4096  # Preview size for large files
    stream_chunk_overlap: int = 200  # Overlap between chunks

    # ========== DEPRECATED/MOVED TO SecurityConfig ==========
    # These are now managed in SecurityConfig but kept for compatibility
    cache_max_size_mb: int = 100  # Use SecurityConfig.cache_max_size_mb
    cache_max_age_hours: int = 24  # Use SecurityConfig.cache_max_age_hours
    cache_cleanup_threshold: float = 0.8  # Internal only
    max_file_size_mb: int = 10  # Use SecurityConfig.max_file_size_mb
    max_content_size_mb: int = 10  # Same as max_file_size_mb


class ConfigManager:
    """Enhanced configuration manager with environment variables and resource detection."""

    def __init__(self, profile: ConfigProfile | None = None):
        """Initialize configuration manager.

        Args:
            profile: Configuration profile to use
        """
        self.profile = profile or self._detect_profile()
        self.resource_tier = self._detect_resource_tier()
        self.base_config = SecurityConfig()
        self.dynamic_limits = self._create_dynamic_limits()

        logger.info(
            f"ConfigManager initialized - Profile: {self.profile.value}, Tier: {self.resource_tier.value}"
        )

    def _detect_profile(self) -> ConfigProfile:
        """Detect configuration profile from environment.

        Checks ADVERSARY_PROFILE env var, or auto-detects:
        - PRODUCTION if PRODUCTION or DEPLOYMENT env vars are set
        - DEVELOPMENT otherwise (default for local development)
        """
        env_profile = os.getenv("ADVERSARY_PROFILE", "").lower()

        if env_profile in [p.value for p in ConfigProfile]:
            return ConfigProfile(env_profile)

        # Auto-detect based on environment
        if os.getenv("PRODUCTION") or os.getenv("DEPLOYMENT"):
            return ConfigProfile.PRODUCTION
        else:
            return ConfigProfile.DEVELOPMENT

    def _detect_resource_tier(self) -> ResourceTier:
        """Detect system resource tier for adaptive configuration.

        Simple detection:
        - HIGH_PERFORMANCE: 16+ GB RAM and 8+ CPU cores
        - STANDARD: Everything else (default)
        """
        try:
            memory_gb = psutil.virtual_memory().total / (1024**3)
            cpu_count = psutil.cpu_count(logical=True)

            if memory_gb >= 16 and cpu_count >= 8:
                return ResourceTier.HIGH_PERFORMANCE
            else:
                return ResourceTier.STANDARD

        except Exception as e:
            logger.warning(f"Failed to detect system resources: {e}")
            return ResourceTier.STANDARD

    def _create_dynamic_limits(self) -> DynamicLimits:
        """Create dynamic limits based on profile and resources."""
        limits = DynamicLimits()

        # Apply profile-specific defaults
        if self.profile == ConfigProfile.DEVELOPMENT:
            # Conservative settings for local development
            limits.max_concurrent_scans = 4
            limits.max_concurrent_batches = 6  # Increased for better dev experience
            limits.scan_timeout_seconds = 120
            limits.llm_max_batch_size = 8
            limits.cache_max_size_mb = 50

        elif self.profile == ConfigProfile.PRODUCTION:
            # Optimized settings for production
            limits.max_concurrent_scans = 16
            limits.max_concurrent_batches = 20  # Much higher for production workloads
            limits.scan_timeout_seconds = 300
            limits.llm_max_batch_size = 20
            limits.cache_max_size_mb = 200

        # Apply resource tier scaling
        self._apply_resource_scaling(limits)

        # Apply environment variable overrides
        self._apply_env_overrides(limits)

        return limits

    def _apply_resource_scaling(self, limits: DynamicLimits) -> None:
        """Scale limits based on detected system resources.

        HIGH_PERFORMANCE systems get 2x the concurrency limits.
        STANDARD systems use the base profile settings.
        """
        if self.resource_tier == ResourceTier.HIGH_PERFORMANCE:
            # Double concurrency for high-performance systems
            limits.max_concurrent_scans = limits.max_concurrent_scans * 2
            limits.max_concurrent_batches = limits.max_concurrent_batches * 2
            limits.llm_max_batch_size = min(20, limits.llm_max_batch_size * 2)
            limits.cache_max_size_mb = limits.cache_max_size_mb * 2
        # STANDARD tier uses base profile settings without modification

    def _apply_env_overrides(self, limits: DynamicLimits) -> None:
        """Apply environment variable overrides to limits."""
        # Cache settings
        limits.cache_max_age_hours = self._get_env_int(
            "ADVERSARY_CACHE_MAX_AGE_HOURS", limits.cache_max_age_hours
        )

        # Processing limits
        limits.max_file_size_mb = self._get_env_int(
            "ADVERSARY_MAX_FILE_SIZE_MB", limits.max_file_size_mb
        )
        limits.max_content_size_mb = self._get_env_int(
            "ADVERSARY_MAX_CONTENT_SIZE_MB", limits.max_content_size_mb
        )

        # Timeout settings
        limits.batch_timeout_seconds = self._get_env_int(
            "ADVERSARY_BATCH_TIMEOUT", limits.batch_timeout_seconds
        )
        limits.llm_request_timeout_seconds = self._get_env_int(
            "ADVERSARY_LLM_TIMEOUT", limits.llm_request_timeout_seconds
        )

        # LLM settings
        limits.llm_max_findings = self._get_env_int(
            "ADVERSARY_LLM_MAX_FINDINGS", limits.llm_max_findings
        )
        limits.llm_target_tokens = self._get_env_int(
            "ADVERSARY_LLM_TARGET_TOKENS", limits.llm_target_tokens
        )
        limits.llm_max_tokens = self._get_env_int(
            "ADVERSARY_LLM_MAX_TOKENS", limits.llm_max_tokens
        )
        limits.llm_max_code_length = self._get_env_int(
            "ADVERSARY_LLM_MAX_CODE_LENGTH", limits.llm_max_code_length
        )

        # Retry settings
        limits.max_retry_attempts = self._get_env_int(
            "ADVERSARY_MAX_RETRY_ATTEMPTS", limits.max_retry_attempts
        )
        limits.retry_base_delay = self._get_env_float(
            "ADVERSARY_RETRY_BASE_DELAY", limits.retry_base_delay
        )
        limits.retry_max_delay = self._get_env_float(
            "ADVERSARY_RETRY_MAX_DELAY", limits.retry_max_delay
        )

        # Circuit breaker settings
        limits.circuit_breaker_failure_threshold = self._get_env_int(
            "ADVERSARY_CIRCUIT_BREAKER_THRESHOLD",
            limits.circuit_breaker_failure_threshold,
        )
        limits.circuit_breaker_recovery_timeout = self._get_env_int(
            "ADVERSARY_CIRCUIT_BREAKER_RECOVERY",
            limits.circuit_breaker_recovery_timeout,
        )

    def _get_env_int(self, key: str, default: int) -> int:
        """Get integer value from environment variable."""
        try:
            value = os.getenv(key)
            return int(value) if value is not None else default
        except (ValueError, TypeError):
            logger.warning(f"Invalid integer value for {key}, using default: {default}")
            return default

    def _get_env_float(self, key: str, default: float) -> float:
        """Get float value from environment variable."""
        try:
            value = os.getenv(key)
            return float(value) if value is not None else default
        except (ValueError, TypeError):
            logger.warning(f"Invalid float value for {key}, using default: {default}")
            return default

    def _get_env_bool(self, key: str, default: bool) -> bool:
        """Get boolean value from environment variable."""
        value = os.getenv(key, "").lower()
        if value in ["true", "1", "yes", "on"]:
            return True
        elif value in ["false", "0", "no", "off"]:
            return False
        else:
            return default

    def get_security_config(self) -> SecurityConfig:
        """Get enhanced security configuration with environment overrides."""
        config = SecurityConfig()

        # Apply environment variable overrides
        config.enable_llm_analysis = self._get_env_bool(
            "ADVERSARY_ENABLE_LLM_ANALYSIS", config.enable_llm_analysis
        )
        config.enable_llm_validation = self._get_env_bool(
            "ADVERSARY_ENABLE_LLM_VALIDATION", config.enable_llm_validation
        )
        config.llm_provider = os.getenv("ADVERSARY_LLM_PROVIDER", config.llm_provider)
        config.llm_api_key = os.getenv("ADVERSARY_LLM_API_KEY", config.llm_api_key)
        config.llm_model = os.getenv("ADVERSARY_LLM_MODEL", config.llm_model)
        config.llm_temperature = self._get_env_float(
            "ADVERSARY_LLM_TEMPERATURE", config.llm_temperature
        )
        config.llm_max_tokens = self._get_env_int(
            "ADVERSARY_LLM_MAX_TOKENS", config.llm_max_tokens
        )
        config.llm_batch_size = self._get_env_int(
            "ADVERSARY_LLM_BATCH_SIZE", config.llm_batch_size
        )

        # Scanner configuration
        config.enable_semgrep_scanning = self._get_env_bool(
            "ADVERSARY_ENABLE_SEMGREP", config.enable_semgrep_scanning
        )

        # Semgrep configuration
        config.semgrep_config = os.getenv(
            "ADVERSARY_SEMGREP_CONFIG", config.semgrep_config
        )
        config.semgrep_rules = os.getenv(
            "ADVERSARY_SEMGREP_RULES", config.semgrep_rules
        )
        # Note: semgrep_api_key is managed through CLI keyring, not environment variables

        # Use dynamic limits
        config.max_file_size_mb = self.dynamic_limits.max_file_size_mb
        config.timeout_seconds = self.dynamic_limits.scan_timeout_seconds
        config.cache_max_size_mb = self.dynamic_limits.cache_max_size_mb
        config.cache_max_age_hours = self.dynamic_limits.cache_max_age_hours

        # Validation fallback configuration
        fallback_mode = os.getenv(
            "ADVERSARY_VALIDATION_FALLBACK_MODE", config.validation_fallback_mode.value
        )
        try:
            config.validation_fallback_mode = ValidationFallbackMode(fallback_mode)
        except ValueError:
            logger.warning(f"Invalid validation fallback mode: {fallback_mode}")

        config.fallback_confidence_threshold = self._get_env_float(
            "ADVERSARY_FALLBACK_CONFIDENCE_THRESHOLD",
            config.fallback_confidence_threshold,
        )
        config.high_severity_always_suspicious = self._get_env_bool(
            "ADVERSARY_HIGH_SEVERITY_SUSPICIOUS", config.high_severity_always_suspicious
        )

        return config

    def get_configuration_summary(self) -> dict[str, Any]:
        """Get comprehensive configuration summary."""
        config = self.get_security_config()

        return {
            # Profile information
            "profile": self.profile.value,
            "resource_tier": self.resource_tier.value,
            "system_info": {
                "memory_gb": round(psutil.virtual_memory().total / (1024**3), 1),
                "cpu_count": psutil.cpu_count(logical=True),
                "cpu_percent": psutil.cpu_percent(interval=1),
                "available_memory_gb": round(
                    psutil.virtual_memory().available / (1024**3), 1
                ),
            },
            # Security configuration
            "llm_analysis_enabled": config.enable_llm_analysis,
            "llm_validation_enabled": config.enable_llm_validation,
            "llm_provider": config.llm_provider,
            "llm_model": config.llm_model,
            "validation_fallback_mode": config.validation_fallback_mode.value,
            # Dynamic limits
            "cache_max_size_mb": self.dynamic_limits.cache_max_size_mb,
            "max_concurrent_scans": self.dynamic_limits.max_concurrent_scans,
            "max_concurrent_batches": self.dynamic_limits.max_concurrent_batches,
            "scan_timeout_seconds": self.dynamic_limits.scan_timeout_seconds,
            "llm_max_batch_size": self.dynamic_limits.llm_max_batch_size,
            "llm_target_tokens": self.dynamic_limits.llm_target_tokens,
            "llm_max_tokens": self.dynamic_limits.llm_max_tokens,
            # Environment overrides detected (sensitive values redacted)
            "env_overrides": sanitize_env_vars(
                {
                    key: value
                    for key, value in os.environ.items()
                    if key.startswith("ADVERSARY_")
                }
            ),
        }


# Global configuration manager instance
_config_manager: ConfigManager | None = None


def get_config_manager(profile: ConfigProfile | None = None) -> ConfigManager:
    """Get global configuration manager instance."""
    global _config_manager

    if _config_manager is None or (
        profile is not None and _config_manager.profile != profile
    ):
        _config_manager = ConfigManager(profile)

    return _config_manager


def reset_config_manager() -> None:
    """Reset global configuration manager (useful for testing)."""
    global _config_manager
    _config_manager = None
