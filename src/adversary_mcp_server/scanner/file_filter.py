"""File filtering utilities for scanning operations."""

import mimetypes
from pathlib import Path
from typing import Any

try:
    import pathspec
except ImportError:
    pathspec = None

from ..logger import get_logger

logger = get_logger("file_filter")


class FileFilter:
    """File filtering utilities for smart file discovery and exclusion."""

    # Common binary file extensions to skip
    BINARY_EXTENSIONS = {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".jar",
        ".war",
        ".ear",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".svg",
        ".ico",
        ".tiff",
        ".webp",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".wav",
        ".ogg",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
    }

    # Common directories to exclude by default
    DEFAULT_EXCLUDE_DIRS = {
        ".git",
        ".svn",
        ".hg",
        ".bzr",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        ".npm",
        ".yarn",
        "build",
        "dist",
        "target",
        ".target",
        "coverage",
        "htmlcov",
        ".coverage",
        ".tox",
        ".venv",
        "venv",
        "env",
        ".env",
        "vendor",
        "Pods",
        ".gradle",
        ".idea",
        ".vscode",
        ".DS_Store",
        "Thumbs.db",
    }

    # Common file patterns to exclude
    DEFAULT_EXCLUDE_PATTERNS = {
        "*.log",
        "*.tmp",
        "*.temp",
        "*.cache",
        "*.lock",
        ".gitignore",
        ".gitattributes",
        ".editorconfig",
        "*.pid",
        "*.swp",
        "*.swo",
        "*~",
        "*.orig",
        "*.rej",
        ".DS_Store",
        "Thumbs.db",
        "*.min.js",
        "*.min.css",
        "package-lock.json",
        "yarn.lock",
        "Cargo.lock",
        "Pipfile.lock",
        "poetry.lock",
        "*.generated.*",
        "*.gen.*",
        "*_pb2.py",
        "*_pb2_grpc.py",
    }

    def __init__(
        self,
        root_path: Path,
        max_file_size_mb: int = 10,
        respect_gitignore: bool = True,
        custom_excludes: list[str] | None = None,
        custom_includes: list[str] | None = None,
    ):
        """Initialize file filter.

        Args:
            root_path: Root directory path for filtering
            max_file_size_mb: Maximum file size in MB to include
            respect_gitignore: Whether to respect .gitignore files
            custom_excludes: Additional exclusion patterns
            custom_includes: Additional inclusion patterns (overrides excludes)
        """
        self.root_path = root_path.resolve()
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.respect_gitignore = respect_gitignore
        self.custom_excludes = custom_excludes or []
        self.custom_includes = custom_includes or []

        # Initialize gitignore specs
        self.gitignore_specs: list[Any] = []
        if self.respect_gitignore and pathspec:
            self._load_gitignore_specs()

        logger.info(
            f"FileFilter initialized - root: {self.root_path}, "
            f"max_size: {max_file_size_mb}MB, gitignore: {respect_gitignore}"
        )

    def _load_gitignore_specs(self) -> None:
        """Load .gitignore and .semgrepignore specs from the directory tree."""
        if not pathspec:
            logger.warning("pathspec not available, gitignore filtering disabled")
            return

        gitignore_files = [".gitignore", ".semgrepignore"]

        # Walk up the directory tree to find all gitignore files
        current_path = self.root_path
        while current_path != current_path.parent:
            for ignore_file in gitignore_files:
                ignore_path = current_path / ignore_file
                if ignore_path.exists():
                    try:
                        with open(ignore_path, encoding="utf-8") as f:
                            patterns = f.read()
                        spec = pathspec.PathSpec.from_lines(
                            "gitwildmatch", patterns.splitlines()
                        )
                        self.gitignore_specs.append((spec, str(ignore_path)))
                        logger.debug(f"Loaded {ignore_file} from {ignore_path}")
                    except Exception as e:
                        logger.warning(f"Failed to load {ignore_path}: {e}")
            current_path = current_path.parent

        logger.info(f"Loaded {len(self.gitignore_specs)} gitignore specs")

    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if file is likely binary."""
        # Check by extension first (fast)
        if file_path.suffix.lower() in self.BINARY_EXTENSIONS:
            return True

        # Check by MIME type
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type:
            if not mime_type.startswith("text/") and mime_type != "application/json":
                return True

        # For small files, check content (limited sampling)
        try:
            if (
                file_path.stat().st_size > 1024 * 1024
            ):  # Skip content check for large files
                return False

            with open(file_path, "rb") as f:
                chunk = f.read(1024)  # Read first 1KB
                if b"\x00" in chunk:  # Null bytes indicate binary
                    return True
        except Exception:
            # If we can't read it, assume it's binary
            return True

        return False

    def _is_too_large(self, file_path: Path) -> bool:
        """Check if file exceeds size limit."""
        try:
            return file_path.stat().st_size > self.max_file_size_bytes
        except Exception:
            return True  # If we can't stat it, consider it too large

    def _matches_gitignore(self, file_path: Path) -> bool:
        """Check if file matches any gitignore pattern."""
        if not self.gitignore_specs:
            return False

        # Get relative path from root, ensuring both paths are resolved consistently
        try:
            resolved_file_path = file_path.resolve()
            resolved_root_path = self.root_path.resolve()
            rel_path = resolved_file_path.relative_to(resolved_root_path)
        except ValueError:
            # File is outside root path
            return False

        rel_path_str = str(rel_path).replace("\\", "/")  # Use forward slashes

        for spec, ignore_file in self.gitignore_specs:
            if spec.match_file(rel_path_str):
                logger.debug(f"File {file_path} excluded by {ignore_file}")
                return True

        return False

    def _matches_default_excludes(self, file_path: Path) -> bool:
        """Check if file matches default exclude patterns."""
        # Check directory exclusions
        for part in file_path.parts:
            if part in self.DEFAULT_EXCLUDE_DIRS:
                return True

        # Check file pattern exclusions
        if pathspec:
            default_spec = pathspec.PathSpec.from_lines(
                "gitwildmatch", self.DEFAULT_EXCLUDE_PATTERNS
            )
            try:
                resolved_file_path = file_path.resolve()
                resolved_root_path = self.root_path.resolve()
                rel_path = resolved_file_path.relative_to(resolved_root_path)
                if default_spec.match_file(str(rel_path).replace("\\", "/")):
                    return True
            except ValueError:
                pass

        return False

    def _matches_custom_patterns(
        self, file_path: Path, patterns: list[str], include: bool = False
    ) -> bool:
        """Check if file matches custom patterns."""
        if not patterns or not pathspec:
            return False

        try:
            resolved_file_path = file_path.resolve()
            resolved_root_path = self.root_path.resolve()
            rel_path = resolved_file_path.relative_to(resolved_root_path)
            rel_path_str = str(rel_path).replace("\\", "/")

            spec = pathspec.PathSpec.from_lines("gitwildmatch", patterns)
            matches = spec.match_file(rel_path_str)

            if matches:
                action = "included" if include else "excluded"
                pattern_type = "custom include" if include else "custom exclude"
                logger.debug(f"File {file_path} {action} by {pattern_type} pattern")

            return matches
        except ValueError:
            return False

    def should_include_file(self, file_path: Path) -> bool:
        """Determine if a file should be included in scanning.

        Args:
            file_path: Path to the file to check

        Returns:
            True if file should be included, False otherwise
        """
        # Convert to Path object if needed
        if isinstance(file_path, str):
            file_path = Path(file_path)

        # Must be a file
        if not file_path.is_file():
            return False

        # Check custom includes first (they override all exclusions)
        if self.custom_includes:
            if self._matches_custom_patterns(
                file_path, self.custom_includes, include=True
            ):
                logger.debug(f"File {file_path} force-included by custom pattern")
                return True

        # Check various exclusion criteria
        exclusion_checks = [
            (lambda: self._is_binary_file(file_path), "binary file"),
            (lambda: self._is_too_large(file_path), "file too large"),
            (lambda: self._matches_gitignore(file_path), "gitignore pattern"),
            (
                lambda: self._matches_default_excludes(file_path),
                "default exclude pattern",
            ),
            (
                lambda: self._matches_custom_patterns(file_path, self.custom_excludes),
                "custom exclude pattern",
            ),
        ]

        for check_func, reason in exclusion_checks:
            try:
                if check_func():
                    logger.debug(f"File {file_path} excluded: {reason}")
                    return False
            except Exception as e:
                logger.warning(f"Error checking {reason} for {file_path}: {e}")
                return False

        logger.debug(f"File {file_path} included for scanning")
        return True

    def filter_files(self, file_paths: list[Path]) -> list[Path]:
        """Filter a list of file paths.

        Args:
            file_paths: List of file paths to filter

        Returns:
            Filtered list of file paths
        """
        logger.info(f"Filtering {len(file_paths)} files")
        start_count = len(file_paths)

        filtered = [f for f in file_paths if self.should_include_file(f)]

        logger.info(f"File filtering complete: {start_count} -> {len(filtered)} files")
        return filtered

    def get_stats(self) -> dict[str, Any]:
        """Get filtering statistics.

        Returns:
            Dictionary with filtering statistics
        """
        return {
            "root_path": str(self.root_path),
            "max_file_size_mb": self.max_file_size_bytes // (1024 * 1024),
            "respect_gitignore": self.respect_gitignore,
            "gitignore_specs_loaded": len(self.gitignore_specs),
            "custom_excludes": len(self.custom_excludes),
            "custom_includes": len(self.custom_includes),
            "pathspec_available": pathspec is not None,
        }
