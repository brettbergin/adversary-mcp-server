"""ScanRequest domain entity with validation and behavior."""

from dataclasses import dataclass

from ..exceptions import ValidationError
from ..value_objects.scan_context import ScanContext
from ..value_objects.severity_level import SeverityLevel


@dataclass
class ScanRequest:
    """
    Domain entity representing a security scan request with rich behavior and validation.

    Encapsulates all the information needed to execute a security scan operation,
    including configuration, context, and business rules. This entity enforces
    domain constraints and provides behavior for scan request processing.
    """

    context: ScanContext
    enable_semgrep: bool = True
    enable_llm: bool = True
    enable_validation: bool = True
    severity_threshold: SeverityLevel | None = None

    def __post_init__(self):
        """Validate scan request after initialization."""
        self._validate_request()

    @classmethod
    def for_file_scan(
        cls,
        file_path: str,
        requester: str = "unknown",
        enable_semgrep: bool = True,
        enable_llm: bool = True,
        enable_validation: bool = True,
        severity_threshold: str | None = None,
        **metadata_kwargs,
    ) -> "ScanRequest":
        """Create a scan request for a single file."""
        context = ScanContext.for_file(
            file_path, requester=requester, **metadata_kwargs
        )

        severity = None
        if severity_threshold:
            severity = SeverityLevel.from_string(severity_threshold)

        return cls(
            context=context,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
            severity_threshold=severity,
        )

    @classmethod
    def for_directory_scan(
        cls,
        directory_path: str,
        requester: str = "unknown",
        enable_semgrep: bool = True,
        enable_llm: bool = True,
        enable_validation: bool = True,
        severity_threshold: str | None = None,
        **metadata_kwargs,
    ) -> "ScanRequest":
        """Create a scan request for a directory."""
        context = ScanContext.for_directory(
            directory_path, requester=requester, **metadata_kwargs
        )

        severity = None
        if severity_threshold:
            severity = SeverityLevel.from_string(severity_threshold)

        return cls(
            context=context,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
            severity_threshold=severity,
        )

    @classmethod
    def for_code_scan(
        cls,
        code: str,
        language: str,
        requester: str = "unknown",
        enable_semgrep: bool = True,
        enable_llm: bool = True,
        enable_validation: bool = True,
        severity_threshold: str | None = None,
        **metadata_kwargs,
    ) -> "ScanRequest":
        """Create a scan request for a code snippet."""
        context = ScanContext.for_code_snippet(
            code, language, requester=requester, **metadata_kwargs
        )

        severity = None
        if severity_threshold:
            severity = SeverityLevel.from_string(severity_threshold)

        return cls(
            context=context,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
            severity_threshold=severity,
        )

    @classmethod
    def for_diff_scan(
        cls,
        source_branch: str,
        target_branch: str,
        working_directory: str,
        requester: str = "unknown",
        enable_semgrep: bool = True,
        enable_llm: bool = True,
        enable_validation: bool = True,
        severity_threshold: str | None = None,
        **metadata_kwargs,
    ) -> "ScanRequest":
        """Create a scan request for git diff scanning."""
        # For diff scans, we use the working directory as the target
        context = ScanContext.for_directory(
            working_directory, requester=requester, **metadata_kwargs
        )

        # Add diff-specific metadata
        context = ScanContext(
            target_path=context.target_path,
            metadata=context.metadata.with_tags(
                source_branch=source_branch,
                target_branch=target_branch,
                scan_type="diff",
            ),
            language=context.language,
            content=context.content,
        )

        severity = None
        if severity_threshold:
            severity = SeverityLevel.from_string(severity_threshold)

        return cls(
            context=context,
            enable_semgrep=enable_semgrep,
            enable_llm=enable_llm,
            enable_validation=enable_validation,
            severity_threshold=severity,
        )

    def _validate_request(self) -> None:
        """Validate the scan request according to business rules."""
        # At least one scanner must be enabled
        if not any([self.enable_semgrep, self.enable_llm]):
            raise ValidationError("At least one scanner must be enabled")

        # Code scans should enable LLM for better analysis
        if self.context.is_code_scan() and not self.enable_llm:
            # This is a warning, not an error
            pass

        # Validate scan permissions
        self.context.validate_scan_permissions()

    def get_effective_severity_threshold(self) -> SeverityLevel:
        """Get the effective severity threshold for this scan."""
        if self.severity_threshold is not None:
            return self.severity_threshold
        return SeverityLevel.get_default_threshold()

    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a specific scanner is enabled for this request."""
        scanner_map = {
            "semgrep": self.enable_semgrep,
            "llm": self.enable_llm,
            "validation": self.enable_validation,
        }
        return scanner_map.get(scanner_name.lower(), False)

    def get_enabled_scanners(self) -> list[str]:
        """Get list of enabled scanner names."""
        enabled = []
        if self.enable_semgrep:
            enabled.append("semgrep")
        if self.enable_llm:
            enabled.append("llm")
        if self.enable_validation:
            enabled.append("validation")
        return enabled

    def should_use_hybrid_scanning(self) -> bool:
        """Check if this request should use hybrid scanning (multiple scanners)."""
        return len(self.get_enabled_scanners()) > 1

    def requires_file_system_access(self) -> bool:
        """Check if this scan requires file system access."""
        return not self.context.is_code_scan()

    def get_scan_scope_description(self) -> str:
        """Get human-readable description of the scan scope."""
        if self.context.is_file_scan():
            return f"File: {self.context.target_path.name}"
        elif self.context.is_directory_scan():
            file_count = len(self.context.get_scannable_files())
            return f"Directory: {self.context.target_path.name} ({file_count} files)"
        elif self.context.is_code_scan():
            lines = (
                len(self.context.content.splitlines()) if self.context.content else 0
            )
            return f"Code Snippet: {self.context.language} ({lines} lines)"
        else:
            return "Unknown scan scope"

    def get_configuration_summary(self) -> dict[str, any]:
        """Get summary of scan configuration for logging/reporting."""
        return {
            "scan_type": self.context.metadata.scan_type,
            "scan_id": self.context.metadata.scan_id,
            "target": str(self.context.target_path),
            "language": self.context.language,
            "scanners": {
                "semgrep": self.enable_semgrep,
                "llm": self.enable_llm,
                "validation": self.enable_validation,
            },
            "severity_threshold": str(self.get_effective_severity_threshold()),
            "scope": self.get_scan_scope_description(),
            "requester": self.context.metadata.requester,
        }

    def with_updated_configuration(
        self,
        enable_semgrep: bool | None = None,
        enable_llm: bool | None = None,
        enable_validation: bool | None = None,
        severity_threshold: SeverityLevel | None = None,
    ) -> "ScanRequest":
        """Create a new scan request with updated configuration."""
        return ScanRequest(
            context=self.context,
            enable_semgrep=(
                enable_semgrep if enable_semgrep is not None else self.enable_semgrep
            ),
            enable_llm=enable_llm if enable_llm is not None else self.enable_llm,
            enable_validation=(
                enable_validation
                if enable_validation is not None
                else self.enable_validation
            ),
            severity_threshold=(
                severity_threshold
                if severity_threshold is not None
                else self.severity_threshold
            ),
        )

    def create_child_request_for_file(self, file_path: str) -> "ScanRequest":
        """Create a child scan request for a specific file (used in directory scans)."""
        if not self.context.is_directory_scan():
            raise ValueError("Can only create child requests from directory scans")

        # Create file context with same metadata as parent
        file_context = ScanContext.for_file(
            file_path,
            requester=self.context.metadata.requester,
            project_name=self.context.metadata.project_name,
            enable_semgrep=self.enable_semgrep,
            enable_llm=self.enable_llm,
            enable_validation=self.enable_validation,
            severity_threshold=str(self.get_effective_severity_threshold()),
            timeout_seconds=self.context.metadata.timeout_seconds,
            max_file_size_bytes=self.context.metadata.max_file_size_bytes,
        )

        return ScanRequest(
            context=file_context,
            enable_semgrep=self.enable_semgrep,
            enable_llm=self.enable_llm,
            enable_validation=self.enable_validation,
            severity_threshold=self.severity_threshold,
        )

    def estimate_scan_complexity(self) -> str:
        """Estimate the complexity of this scan for resource planning."""
        if self.context.is_code_scan():
            lines = (
                len(self.context.content.splitlines()) if self.context.content else 0
            )
            if lines < 50:
                return "low"
            elif lines < 200:
                return "medium"
            else:
                return "high"

        elif self.context.is_file_scan():
            try:
                size = self.context.target_path.get_size_bytes()
                if size < 10_000:  # 10KB
                    return "low"
                elif size < 100_000:  # 100KB
                    return "medium"
                else:
                    return "high"
            except (OSError, ValueError, TypeError):
                return "medium"

        elif self.context.is_directory_scan():
            file_count = len(self.context.get_scannable_files())
            if file_count < 10:
                return "low"
            elif file_count < 50:
                return "medium"
            else:
                return "high"

        return "medium"

    def is_comprehensive_scan(self) -> bool:
        """Check if this is a comprehensive scan (all scanners enabled)."""
        return self.enable_semgrep and self.enable_llm and self.enable_validation

    def requires_network_access(self) -> bool:
        """Check if this scan requires network access (LLM or validation)."""
        return self.enable_llm or self.enable_validation
