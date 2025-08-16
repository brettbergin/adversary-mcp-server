"""ScanMetadata value object for structured scan information."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class ScanMetadata:
    """
    Value object containing structured metadata about a security scan operation.

    Encapsulates scan configuration, timing information, and context
    that is used throughout the scanning process and result reporting.
    """

    scan_id: str
    scan_type: str  # "file", "directory", "code"
    timestamp: datetime
    requester: str

    # Configuration metadata
    enable_semgrep: bool = True
    enable_llm: bool = True
    enable_validation: bool = True
    severity_threshold: str = "medium"

    # Context metadata
    language: str | None = None
    project_name: str | None = None
    branch_name: str | None = None
    commit_hash: str | None = None

    # Execution metadata
    timeout_seconds: int = 300
    max_file_size_bytes: int = 1024 * 1024  # 1MB default

    # Custom metadata
    tags: dict[str, str] = field(default_factory=dict)
    custom_attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def for_file_scan(
        cls,
        requester: str = "unknown",
        language: str | None = None,
        project_name: str | None = None,
        **kwargs,
    ) -> "ScanMetadata":
        """Create metadata for a file scan operation."""
        return cls(
            scan_id=str(uuid4()),
            scan_type="file",
            timestamp=datetime.utcnow(),
            requester=requester,
            language=language,
            project_name=project_name,
            **kwargs,
        )

    @classmethod
    def for_directory_scan(
        cls, requester: str = "unknown", project_name: str | None = None, **kwargs
    ) -> "ScanMetadata":
        """Create metadata for a directory scan operation."""
        return cls(
            scan_id=str(uuid4()),
            scan_type="directory",
            timestamp=datetime.utcnow(),
            requester=requester,
            project_name=project_name,
            **kwargs,
        )

    @classmethod
    def for_code_scan(
        cls, language: str, requester: str = "unknown", **kwargs
    ) -> "ScanMetadata":
        """Create metadata for a code snippet scan operation."""
        return cls(
            scan_id=str(uuid4()),
            scan_type="code",
            timestamp=datetime.utcnow(),
            requester=requester,
            language=language,
            **kwargs,
        )

    @classmethod
    def for_diff_scan(
        cls,
        source_branch: str,
        target_branch: str,
        requester: str = "unknown",
        project_name: str | None = None,
        **kwargs,
    ) -> "ScanMetadata":
        """Create metadata for a git diff scan operation."""
        return cls(
            scan_id=str(uuid4()),
            scan_type="diff",
            timestamp=datetime.utcnow(),
            requester=requester,
            project_name=project_name,
            branch_name=target_branch,
            tags={
                "source_branch": source_branch,
                "target_branch": target_branch,
            },
            **kwargs,
        )

    def with_git_info(self, branch: str, commit: str) -> "ScanMetadata":
        """Create a new metadata instance with git information."""
        return ScanMetadata(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            timestamp=self.timestamp,
            requester=self.requester,
            enable_semgrep=self.enable_semgrep,
            enable_llm=self.enable_llm,
            enable_validation=self.enable_validation,
            severity_threshold=self.severity_threshold,
            language=self.language,
            project_name=self.project_name,
            branch_name=branch,
            commit_hash=commit,
            timeout_seconds=self.timeout_seconds,
            max_file_size_bytes=self.max_file_size_bytes,
            tags=self.tags,
            custom_attributes=self.custom_attributes,
        )

    def with_configuration(
        self,
        enable_semgrep: bool | None = None,
        enable_llm: bool | None = None,
        enable_validation: bool | None = None,
        severity_threshold: str | None = None,
        **kwargs,
    ) -> "ScanMetadata":
        """Create a new metadata instance with updated configuration."""
        return ScanMetadata(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            timestamp=self.timestamp,
            requester=self.requester,
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
            language=self.language,
            project_name=self.project_name,
            branch_name=self.branch_name,
            commit_hash=self.commit_hash,
            timeout_seconds=kwargs.get("timeout_seconds", self.timeout_seconds),
            max_file_size_bytes=kwargs.get(
                "max_file_size_bytes", self.max_file_size_bytes
            ),
            tags={**self.tags, **kwargs.get("tags", {})},
            custom_attributes={
                **self.custom_attributes,
                **kwargs.get("custom_attributes", {}),
            },
        )

    def with_tags(self, **tags) -> "ScanMetadata":
        """Create a new metadata instance with additional tags."""
        return ScanMetadata(
            scan_id=self.scan_id,
            scan_type=self.scan_type,
            timestamp=self.timestamp,
            requester=self.requester,
            enable_semgrep=self.enable_semgrep,
            enable_llm=self.enable_llm,
            enable_validation=self.enable_validation,
            severity_threshold=self.severity_threshold,
            language=self.language,
            project_name=self.project_name,
            branch_name=self.branch_name,
            commit_hash=self.commit_hash,
            timeout_seconds=self.timeout_seconds,
            max_file_size_bytes=self.max_file_size_bytes,
            tags={**self.tags, **tags},
            custom_attributes=self.custom_attributes,
        )

    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a specific scanner is enabled."""
        scanner_map = {
            "semgrep": self.enable_semgrep,
            "llm": self.enable_llm,
            "validation": self.enable_validation,
        }
        return scanner_map.get(scanner_name.lower(), False)

    def get_effective_timeout(self) -> int:
        """Get effective timeout considering scan type and configuration."""
        # Use default timeout if not specified
        timeout = self.timeout_seconds or 120  # Default 2 minutes

        if self.scan_type == "directory":
            # Directory scans need more time
            return max(timeout, 600)  # At least 10 minutes
        elif self.scan_type == "code":
            # Code scans are usually quick
            return min(timeout, 60)  # At most 1 minute
        else:
            return timeout

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp.isoformat(),
            "requester": self.requester,
            "configuration": {
                "enable_semgrep": self.enable_semgrep,
                "enable_llm": self.enable_llm,
                "enable_validation": self.enable_validation,
                "severity_threshold": self.severity_threshold,
                "timeout_seconds": self.timeout_seconds,
                "max_file_size_bytes": self.max_file_size_bytes,
            },
            "context": {
                "language": self.language,
                "project_name": self.project_name,
                "branch_name": self.branch_name,
                "commit_hash": self.commit_hash,
            },
            "tags": self.tags,
            "custom_attributes": self.custom_attributes,
        }
