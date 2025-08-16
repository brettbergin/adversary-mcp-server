"""Security configuration for Adversary MCP server."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class ValidationFallbackMode(str, Enum):
    """Validation fallback behavior when LLM is unavailable."""

    SECURITY_FIRST = "security_first"  # Default to suspicious for security findings
    OPTIMISTIC = "optimistic"  # Default to legitimate (original behavior)
    MIXED = "mixed"  # Use severity and confidence to decide


@dataclass
class SecurityConfig:
    """Security configuration for the adversary MCP server.

    Configuration is organized into logical groups:
    - Core Settings: Essential for basic operation
    - LLM Settings: AI-powered analysis (optional, with fallbacks)
    - Scanner Settings: Static analysis tools
    - Performance Settings: Resource limits (auto-scaled by ConfigManager)
    - Advanced Settings: Rarely need modification
    """

    # ========== CORE SETTINGS ==========
    # These control fundamental behavior of the security scanner

    # Severity threshold for filtering findings (low, medium, high, critical)
    # Only findings at or above this severity are reported
    severity_threshold: str = "medium"

    # Enable caching to improve performance for repeated scans
    # Automatically managed with safe defaults
    enable_caching: bool = True

    # Cache LLM API responses to reduce costs and improve speed
    # Safe to enable - responses are invalidated when prompts change
    cache_llm_responses: bool = True

    # ========== LLM SETTINGS ==========
    # Optional AI-powered analysis - system works without these

    # Enable LLM-based security analysis for finding vulnerabilities
    # Falls back to static analysis if disabled or unavailable
    enable_llm_analysis: bool = True

    # Enable LLM validation to reduce false positives
    # When disabled, all findings are considered legitimate
    enable_llm_validation: bool = True

    # LLM provider: "openai" or "anthropic" (auto-detected from API keys)
    llm_provider: str | None = None

    # API key for the selected provider (set via environment variables)
    llm_api_key: str | None = None

    # Model to use - if not set, interactive selection is offered
    llm_model: str | None = None

    # LLM generation parameters (safe defaults, rarely need adjustment)
    llm_temperature: float = 0.1  # Low temperature for consistent analysis
    llm_max_tokens: int = 4000  # Max tokens per response
    llm_batch_size: int = 10  # Files per batch (auto-scaled by resources)

    # ========== SCANNER SETTINGS ==========
    # Static analysis tool configuration

    # Enable Semgrep for rule-based vulnerability detection
    # Primary static analysis engine - recommended to keep enabled
    enable_semgrep_scanning: bool = True

    # Semgrep configuration (auto-detects from environment)
    semgrep_config: str | None = None  # Custom config path (optional)
    semgrep_rules: str | None = None  # Specific rules (default: auto)
    semgrep_api_key: str | None = None  # Semgrep API key (managed through keyring)

    # ========== EXPLOIT GENERATION ==========
    # Educational exploit generation settings

    # Enable generation of proof-of-concept exploits
    enable_exploit_generation: bool = True

    # Safety mode - ensures exploits are educational only
    # ALWAYS enabled in production for responsible disclosure
    exploit_safety_mode: bool = True

    # ========== PERFORMANCE SETTINGS ==========
    # Resource limits - automatically scaled by ConfigManager
    # These are overridden by DynamicLimits based on system resources

    max_file_size_mb: int = 10  # Max file size to scan
    timeout_seconds: int = 300  # Overall scan timeout
    cache_max_size_mb: int = 100  # Max cache size (auto-managed)
    cache_max_age_hours: int = 24  # Cache expiry (auto-cleaned)

    # ========== VALIDATION FALLBACK ==========
    # Behavior when LLM validation is unavailable

    # How to handle findings when LLM validation fails:
    # - SECURITY_FIRST: Assume findings are real (conservative)
    # - OPTIMISTIC: Assume findings are false positives
    # - MIXED: Use severity and confidence heuristics
    validation_fallback_mode: ValidationFallbackMode = (
        ValidationFallbackMode.SECURITY_FIRST
    )

    # Confidence threshold for SECURITY_FIRST mode (0.0-1.0)
    # Findings below this confidence are marked suspicious
    fallback_confidence_threshold: float = 0.7

    # Always treat CRITICAL/HIGH severity as suspicious when LLM unavailable
    # Ensures critical vulnerabilities aren't missed
    high_severity_always_suspicious: bool = True

    def validate_llm_configuration(self) -> tuple[bool, str]:
        """Validate LLM configuration.

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.enable_llm_analysis and not self.enable_llm_validation:
            # LLM disabled, so configuration is valid
            return True, ""

        if not self.llm_provider:
            return (
                False,
                "LLM provider not configured (must be 'openai' or 'anthropic')",
            )

        if self.llm_provider not in ["openai", "anthropic"]:
            return False, f"Invalid LLM provider: {self.llm_provider}"

        if not self.llm_api_key:
            return False, f"API key not configured for {self.llm_provider}"

        return True, ""

    def is_llm_analysis_available(self) -> bool:
        """Check if LLM analysis is available and properly configured.

        Returns:
            True if LLM analysis can be used
        """
        is_valid, _ = self.validate_llm_configuration()
        return is_valid and (self.enable_llm_analysis or self.enable_llm_validation)

    def get_configuration_summary(self) -> dict[str, Any]:
        """Get a summary of the current configuration.

        Returns:
            Dictionary with configuration summary
        """
        is_valid, error_message = self.validate_llm_configuration()
        return {
            "llm_analysis_enabled": self.enable_llm_analysis,
            "llm_validation_enabled": self.enable_llm_validation,
            "llm_analysis_available": self.is_llm_analysis_available(),
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "llm_configured": bool(self.llm_provider and self.llm_api_key),
            "llm_configuration_error": error_message if not is_valid else None,
            "llm_api_key_configured": bool(self.llm_api_key),
            "semgrep_scanning_enabled": self.enable_semgrep_scanning,
            "exploit_generation_enabled": self.enable_exploit_generation,
            "exploit_safety_mode": self.exploit_safety_mode,
            "severity_threshold": self.severity_threshold,
            "enable_caching": self.enable_caching,
            "validation_fallback_mode": self.validation_fallback_mode.value,
            "fallback_confidence_threshold": self.fallback_confidence_threshold,
            "high_severity_always_suspicious": self.high_severity_always_suspicious,
        }


def get_app_data_dir() -> Path:
    """Get the application data directory.

    Returns:
        Path to ~/.local/share/adversary-mcp-server where all application data is stored
    """
    return Path.home() / ".local" / "share" / "adversary-mcp-server"


def get_app_cache_dir() -> Path:
    """Get the application cache directory.

    Returns:
        Path to ~/.local/share/adversary-mcp-server/cache
    """
    return get_app_data_dir() / "cache"


def get_app_metrics_dir() -> Path:
    """Get the application metrics directory.

    Returns:
        Path to ~/.local/share/adversary-mcp-server/metrics
    """
    return get_app_data_dir() / "metrics"
