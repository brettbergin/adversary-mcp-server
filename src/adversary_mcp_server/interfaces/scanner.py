"""Scanner interfaces for modular security scanning architecture."""

from pathlib import Path
from typing import Protocol, runtime_checkable

from ..scanner.scan_engine import EnhancedScanResult
from ..scanner.types import Severity, ThreatMatch


@runtime_checkable
class IScanEngine(Protocol):
    """Interface for the main scan engine that orchestrates security scanning.

    This interface defines the contract for comprehensive security scanning
    operations that combine multiple analysis engines (Semgrep, LLM) with
    validation and caching capabilities.
    """

    async def scan_file(
        self,
        file_path: Path,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Scan a single file for security vulnerabilities.

        Args:
            file_path: Path to the file to scan
            use_llm: Whether to use LLM analysis engine
            use_semgrep: Whether to use Semgrep static analysis
            use_validation: Whether to use LLM validation for findings
            severity_threshold: Minimum severity threshold for filtering results

        Returns:
            Enhanced scan result with threats, metadata, and statistics
        """
        ...

    async def scan_directory(
        self,
        directory_path: Path,
        recursive: bool = True,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> list[EnhancedScanResult]:
        """Scan a directory for security vulnerabilities.

        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories recursively
            use_llm: Whether to use LLM analysis engine
            use_semgrep: Whether to use Semgrep static analysis
            use_validation: Whether to use LLM validation for findings
            severity_threshold: Minimum severity threshold for filtering results

        Returns:
            List of enhanced scan results for all scanned files
        """
        ...

    async def scan_code(
        self,
        source_code: str,
        file_path: str,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Scan source code string for security vulnerabilities.

        Args:
            source_code: Source code content to analyze
            file_path: File path for language detection and context
            use_llm: Whether to use LLM analysis engine
            use_semgrep: Whether to use Semgrep static analysis
            use_validation: Whether to use LLM validation for findings
            severity_threshold: Minimum severity threshold for filtering results

        Returns:
            Enhanced scan result with threats, metadata, and statistics
        """
        ...


@runtime_checkable
class ISemgrepScanner(Protocol):
    """Interface for Semgrep-based static analysis scanning.

    This interface defines the contract for rule-based static analysis
    using the Semgrep engine for pattern matching and vulnerability detection.
    """

    async def scan_file(self, file_path: Path, language: str) -> list[ThreatMatch]:
        """Scan a file using Semgrep static analysis rules.

        Args:
            file_path: Path to the file to scan
            language: Programming language for rule selection

        Returns:
            List of threat matches found by Semgrep analysis
        """
        ...

    async def scan_directory(
        self, directory_path: Path, recursive: bool = True
    ) -> list[ThreatMatch]:
        """Scan a directory using Semgrep static analysis rules.

        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories recursively

        Returns:
            List of threat matches found by Semgrep analysis
        """
        ...

    async def scan_code(self, source_code: str, language: str) -> list[ThreatMatch]:
        """Scan source code string using Semgrep static analysis rules.

        Args:
            source_code: Source code content to analyze
            language: Programming language for rule selection

        Returns:
            List of threat matches found by Semgrep analysis
        """
        ...


@runtime_checkable
class ILLMScanner(Protocol):
    """Interface for LLM-based intelligent security analysis.

    This interface defines the contract for AI-powered security analysis
    that can identify business logic flaws, complex vulnerabilities, and
    context-aware security issues beyond pattern matching.
    """

    async def analyze_file(self, file_path: Path, language: str) -> list[ThreatMatch]:
        """Analyze a file using LLM-based security analysis.

        Args:
            file_path: Path to the file to analyze
            language: Programming language for analysis

        Returns:
            List of threat matches found by LLM analysis
        """
        ...

    async def analyze_directory(self, directory_path: Path) -> list[ThreatMatch]:
        """Analyze a directory using LLM-based security analysis.

        Args:
            directory_path: Path to the directory to analyze

        Returns:
            List of threat matches found by LLM analysis
        """
        ...

    async def analyze_code(
        self, source_code: str, file_path: str, language: str
    ) -> list[ThreatMatch]:
        """Analyze source code using LLM-based security analysis.

        Args:
            source_code: Source code content to analyze
            file_path: File path for context
            language: Programming language for analysis

        Returns:
            List of threat matches found by LLM analysis
        """
        ...
