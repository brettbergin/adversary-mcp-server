"""Validator interfaces for security finding validation and enhancement."""

from typing import Protocol, runtime_checkable

from ..scanner.llm_validator import ValidationResult
from ..scanner.types import ThreatMatch


@runtime_checkable
class IValidator(Protocol):
    """Interface for validating security findings to reduce false positives.

    This interface defines the contract for validation systems that analyze
    security findings to determine their legitimacy, provide confidence scores,
    and enhance findings with additional context.
    """

    def validate_findings(
        self,
        findings: list[ThreatMatch],
        source_code: str,
        file_path: str,
        generate_exploits: bool = True,
    ) -> dict[str, ValidationResult]:
        """Validate a list of security findings for legitimacy.

        Args:
            findings: List of threat matches to validate
            source_code: Source code containing the potential vulnerabilities
            file_path: Path to the source file for context
            generate_exploits: Whether to generate proof-of-concept exploits

        Returns:
            Dictionary mapping finding UUID to validation result with
            confidence scores, reasoning, and potential exploit vectors
        """
        ...


@runtime_checkable
class ILLMValidator(Protocol):
    """Interface for LLM-based intelligent validation of security findings.

    This interface defines the contract for AI-powered validation that can
    analyze findings in context, generate exploitation vectors, and provide
    detailed reasoning for validation decisions.
    """

    def validate_findings(
        self,
        findings: list[ThreatMatch],
        source_code: str,
        file_path: str,
        generate_exploits: bool = True,
    ) -> dict[str, ValidationResult]:
        """Validate security findings using LLM analysis.

        Performs intelligent validation by:
        - Analyzing code context around findings
        - Generating confidence scores (0.0-1.0)
        - Creating exploitation vectors for legitimate findings
        - Providing detailed reasoning for validation decisions
        - Suggesting severity adjustments if appropriate

        Args:
            findings: List of threat matches to validate
            source_code: Source code containing the potential vulnerabilities
            file_path: Path to the source file for context
            generate_exploits: Whether to generate proof-of-concept exploits

        Returns:
            Dictionary mapping finding UUID to detailed validation result
        """
        ...
