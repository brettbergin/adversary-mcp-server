"""FilePath value object with validation and normalization."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FilePath:
    """
    Value object representing a file system path with validation and normalization.

    Provides a rich interface for file path operations while ensuring
    paths are validated, normalized, and safe to use in security scanning context.
    """

    _path: Path
    _is_virtual: bool = False

    @classmethod
    def from_string(cls, path_str: str | Path) -> "FilePath":
        """Create FilePath from string or Path object, with validation and normalization."""
        # Convert Path object to string if needed
        if isinstance(path_str, Path):
            path_str = str(path_str)

        if not path_str.strip():
            raise ValueError("Path cannot be empty")

        # Normalize and resolve the path
        try:
            normalized_path = Path(path_str).expanduser().resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid path: {path_str}") from e

        return cls(_path=normalized_path, _is_virtual=False)

    @classmethod
    def from_virtual(cls, virtual_name: str) -> "FilePath":
        """Create a virtual FilePath for code snippets or temporary content."""
        if not virtual_name.strip():
            raise ValueError("Virtual path name cannot be empty")

        # Create a virtual path that won't exist on filesystem
        virtual_path = Path(f"<virtual>/{virtual_name}")
        return cls(_path=virtual_path, _is_virtual=True)

    @property
    def path(self) -> Path:
        """Get the underlying Path object."""
        return self._path

    @property
    def name(self) -> str:
        """Get the file name."""
        return self._path.name

    @property
    def suffix(self) -> str:
        """Get the file suffix/extension."""
        return self._path.suffix

    @property
    def parent(self) -> "FilePath":
        """Get the parent directory as FilePath."""
        return FilePath(self._path.parent, _is_virtual=self._is_virtual)

    def __str__(self) -> str:
        """String representation of the path."""
        return str(self._path)

    def __fspath__(self) -> str:
        """Support for os.fspath()."""
        return str(self._path)

    def exists(self) -> bool:
        """Check if the path exists on filesystem."""
        if self._is_virtual:
            return False
        return self._path.exists()

    def is_file(self) -> bool:
        """Check if path points to a file."""
        if self._is_virtual:
            return True  # Virtual paths are treated as files
        return self._path.is_file()

    def is_directory(self) -> bool:
        """Check if path points to a directory."""
        if self._is_virtual:
            return False  # Virtual paths cannot be directories
        return self._path.is_dir()

    def is_readable(self) -> bool:
        """Check if path is readable."""
        if self._is_virtual:
            return True  # Virtual paths are always readable
        return os.access(self._path, os.R_OK)

    def is_scannable_file(self) -> bool:
        """Check if this file should be included in security scans."""
        if self._is_virtual:
            return True

        if not self.is_file():
            return False

        # Skip binary files and common non-code files
        non_scannable_extensions = {
            ".pyc",
            ".pyo",
            ".pyd",  # Python compiled
            ".class",
            ".jar",  # Java compiled
            ".o",
            ".obj",
            ".so",
            ".dll",
            ".dylib",  # Compiled binaries
            ".exe",
            ".bin",  # Executables
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".svg",  # Images
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",  # Documents
            ".zip",
            ".tar",
            ".gz",
            ".rar",
            ".7z",  # Archives
            ".mp3",
            ".mp4",
            ".avi",
            ".mov",  # Media
            ".db",
            ".sqlite",
            ".sqlite3",  # Databases
            ".log",  # Log files (usually too large/noisy)
        }

        if self.suffix.lower() in non_scannable_extensions:
            return False

        # Skip hidden files and directories (starting with .)
        if self.name.startswith("."):
            return False

        return True

    def get_scannable_files(self) -> list["FilePath"]:
        """Get all scannable files in directory (recursive)."""
        if self._is_virtual or not self.is_directory():
            return []

        scannable_files = []
        try:
            for file_path in self._path.rglob("*"):
                if file_path.is_file():
                    file_obj = FilePath(file_path, _is_virtual=False)
                    if file_obj.is_scannable_file():
                        scannable_files.append(file_obj)
        except (PermissionError, OSError):
            # Skip directories we can't read
            pass

        return scannable_files

    def is_sensitive_system_path(self) -> bool:
        """Check if path is in sensitive system directories that shouldn't be scanned."""
        if self._is_virtual:
            return False

        sensitive_paths = [
            Path("/etc"),
            Path("/sys"),
            Path("/proc"),
            Path("/dev"),
            Path("/boot"),
            Path("/root"),
            Path.home() / ".ssh",
            Path.home() / ".gnupg",
        ]

        try:
            resolved_path = self._path.resolve()
            for sensitive in sensitive_paths:
                sensitive_resolved = sensitive.resolve()
                try:
                    resolved_path.relative_to(sensitive_resolved)
                    return True  # Path is under sensitive directory
                except ValueError:
                    continue  # Path is not under this sensitive directory
        except (OSError, RuntimeError):
            return True  # If we can't resolve, assume sensitive

        return False

    def relative_to_project_root(self, project_root: "FilePath") -> str:
        """Get path relative to project root for display purposes."""
        if self._is_virtual:
            return str(self._path)

        try:
            return str(self._path.relative_to(project_root._path))
        except ValueError:
            return str(self._path)  # Return absolute path if not under project root

    def read_text(self, encoding: str = "utf-8") -> str:
        """Read file content as text."""
        if self._is_virtual:
            raise ValueError("Cannot read virtual file path")

        try:
            return self._path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            # Try with different encodings
            for fallback_encoding in ["latin1", "cp1252"]:
                try:
                    return self._path.read_text(encoding=fallback_encoding)
                except UnicodeDecodeError:
                    continue
            raise ValueError(
                f"Could not decode file with any supported encoding: {self._path}"
            )

    def get_size_bytes(self) -> int:
        """Get file size in bytes."""
        if self._is_virtual:
            return 0

        try:
            return self._path.stat().st_size
        except OSError:
            return 0
