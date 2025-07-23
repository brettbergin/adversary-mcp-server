"""Security configuration for Adversary MCP server."""

from dataclasses import dataclass
from typing import Any


@dataclass
class SecurityConfig:
    """Security configuration for the adversary MCP server."""

    # LLM Configuration (now client-based)
    enable_llm_analysis: bool = (
        True  # Enable LLM-based security analysis (uses client LLM)
    )

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

    def validate_llm_configuration(self) -> tuple[bool, str]:
        """Validate LLM configuration.

        Returns:
            Tuple of (is_valid, error_message)
        """
        # LLM analysis now uses client-side LLM, so always valid
        return True, ""

    def is_llm_analysis_available(self) -> bool:
        """Check if LLM analysis is available and properly configured.

        Returns:
            True if LLM analysis can be used (always true now since we use client LLM)
        """
        # LLM analysis now uses client-side LLM, so always available
        return True

    def get_configuration_summary(self) -> dict[str, Any]:
        """Get a summary of the current configuration.

        Returns:
            Dictionary with configuration summary
        """
        return {
            "llm_analysis_enabled": self.enable_llm_analysis,
            "llm_analysis_available": self.is_llm_analysis_available(),
            "llm_mode": "client_based",
            "semgrep_scanning_enabled": self.enable_semgrep_scanning,
            "semgrep_api_key_configured": bool(self.semgrep_api_key),
            "ast_scanning_enabled": self.enable_ast_scanning,
            "exploit_generation_enabled": self.enable_exploit_generation,
            "exploit_safety_mode": self.exploit_safety_mode,
            "severity_threshold": self.severity_threshold,
        }
