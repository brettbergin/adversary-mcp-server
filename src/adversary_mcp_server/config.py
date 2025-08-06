"""Security configuration for Adversary MCP server."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SecurityConfig:
    """Security configuration for the adversary MCP server."""

    # LLM Configuration
    enable_llm_analysis: bool = True  # Enable LLM-based security analysis
    enable_llm_validation: bool = True  # Enable LLM-based validation
    llm_provider: str | None = None  # "openai" or "anthropic"
    llm_api_key: str | None = None  # API key for the selected provider
    llm_model: str | None = None  # Model to use (provider-specific)
    llm_temperature: float = 0.1  # Temperature for LLM sampling
    llm_max_tokens: int = 4000  # Max tokens per LLM response
    llm_batch_size: int = 10  # Number of files to analyze per API call

    # Scanner Configuration
    enable_ast_scanning: bool = True
    enable_semgrep_scanning: bool = True
    enable_bandit_scanning: bool = True

    # Semgrep Configuration
    semgrep_config: str | None = None  # Path to custom semgrep config
    semgrep_rules: str | None = None  # Specific rules to use
    semgrep_timeout: int = 60  # Timeout for semgrep scans in seconds
    semgrep_api_key: str | None = None  # Semgrep API key for Pro features

    # Exploit Generation
    enable_exploit_generation: bool = True
    exploit_safety_mode: bool = True  # Limit exploit generation to safe examples

    # Analysis Configuration
    max_file_size_mb: int = 10
    max_scan_depth: int = 5
    timeout_seconds: int = 300

    # Rule Configuration
    custom_rules_path: str | None = None
    severity_threshold: str = "medium"  # low, medium, high, critical

    # Reporting Configuration
    include_exploit_examples: bool = True
    include_remediation_advice: bool = True
    verbose_output: bool = False

    # Caching Configuration
    enable_caching: bool = True
    cache_max_size_mb: int = 100  # Maximum cache size in MB
    cache_max_age_hours: int = 24  # Maximum cache age in hours
    cache_llm_responses: bool = True  # Cache LLM API responses

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
            "semgrep_api_key_configured": bool(self.semgrep_api_key),
            "ast_scanning_enabled": self.enable_ast_scanning,
            "exploit_generation_enabled": self.enable_exploit_generation,
            "exploit_safety_mode": self.exploit_safety_mode,
            "severity_threshold": self.severity_threshold,
            "enable_caching": self.enable_caching,
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
