"""ScanContext value object for security scanning operations."""

from dataclasses import dataclass

from .file_path import FilePath
from .scan_metadata import ScanMetadata


@dataclass(frozen=True)
class ScanContext:
    """
    Value object representing the complete context for a security scan operation.

    Encapsulates all the information needed to perform a scan, including
    target paths, metadata, and context information. This object is immutable
    and contains validation logic for scan parameters.
    """

    target_path: FilePath
    metadata: ScanMetadata
    language: str | None = None
    content: str | None = None  # For code snippet scans

    @classmethod
    def for_file(cls, file_path: str, **metadata_kwargs) -> "ScanContext":
        """Create scan context for a file scan operation."""
        target = FilePath.from_string(file_path)
        if not target.exists():
            raise ValueError(f"File does not exist: {file_path}")
        if not target.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        metadata = ScanMetadata.for_file_scan(**metadata_kwargs)
        language = cls._detect_language(target)

        # Load file content for LLM analysis when LLM is enabled
        content = None
        enable_llm = metadata_kwargs.get("enable_llm", False)
        if enable_llm:
            try:
                content = target.read_text()
            except Exception as e:
                # Log but don't fail - LLM adapter can still read the file
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to load file content for {file_path}: {e}")

        return cls(
            target_path=target, metadata=metadata, language=language, content=content
        )

    @classmethod
    def for_directory(cls, directory_path: str, **metadata_kwargs) -> "ScanContext":
        """Create scan context for a directory scan operation."""
        target = FilePath.from_string(directory_path)
        if not target.exists():
            raise ValueError(f"Directory does not exist: {directory_path}")
        if not target.is_directory():
            raise ValueError(f"Path is not a directory: {directory_path}")

        metadata = ScanMetadata.for_directory_scan(**metadata_kwargs)

        return cls(
            target_path=target,
            metadata=metadata,
            language=None,  # Directories don't have a single language
        )

    @classmethod
    def for_code_snippet(
        cls, code: str, language: str, **metadata_kwargs
    ) -> "ScanContext":
        """Create scan context for a code snippet scan operation."""
        if not code.strip():
            raise ValueError("Code snippet cannot be empty")
        if not language.strip():
            raise ValueError("Language must be specified for code snippets")

        # Create a virtual file path for code snippets
        target = FilePath.from_virtual(f"<snippet>.{language}")
        metadata = ScanMetadata.for_code_scan(language=language, **metadata_kwargs)

        return cls(
            target_path=target, metadata=metadata, language=language, content=code
        )

    def is_file_scan(self) -> bool:
        """Check if this is a file-based scan."""
        return (
            self.target_path is not None
            and self.target_path.is_file()
            and self.content is None
        )

    def is_directory_scan(self) -> bool:
        """Check if this is a directory-based scan."""
        return self.target_path is not None and self.target_path.is_directory()

    def is_code_scan(self) -> bool:
        """Check if this is a code snippet scan."""
        return self.content is not None

    def get_scannable_files(self) -> list[FilePath]:
        """Get list of files that should be scanned based on context."""
        if self.is_file_scan():
            return [self.target_path]
        elif self.is_directory_scan():
            return self.target_path.get_scannable_files()
        else:
            return []  # Code scans don't have physical files

    def validate_scan_permissions(self) -> None:
        """Validate that the scan can be performed safely."""
        if self.is_code_scan():
            return  # Code scans don't need file system permissions

        # Validate read permissions
        if not self.target_path.is_readable():
            raise PermissionError(f"No read permission for: {self.target_path}")

        # Validate we're not scanning sensitive system directories
        if self.target_path.is_sensitive_system_path():
            raise ValueError(f"Cannot scan sensitive system path: {self.target_path}")

    @staticmethod
    def _detect_language(file_path: FilePath) -> str | None:
        """Detect programming language from file extension."""
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".cs": "csharp",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".swift": "swift",
            ".kt": "kotlin",
            ".scala": "scala",
            ".sh": "bash",
            ".bash": "bash",
            ".zsh": "zsh",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".xml": "xml",
            ".html": "html",
            ".css": "css",
            ".sql": "sql",
        }

        return extension_map.get(file_path.suffix.lower())
