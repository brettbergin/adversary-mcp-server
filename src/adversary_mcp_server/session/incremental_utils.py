"""Utility functions for incremental analysis integration."""

import subprocess
from pathlib import Path
from typing import Any

from ..logger import get_logger

logger = get_logger("incremental_utils")


class GitChangeDetector:
    """Utility class for detecting file changes using git."""

    def __init__(self, project_root: Path):
        """Initialize with project root directory."""
        self.project_root = project_root.resolve()

    def get_changed_files_since_commit(self, commit_hash: str) -> list[Path]:
        """Get files changed since a specific commit."""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", f"{commit_hash}..HEAD"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True,
            )

            changed_files = []
            for line in result.stdout.strip().split("\n"):
                if line:  # Skip empty lines
                    file_path = self.project_root / line
                    if file_path.exists():
                        changed_files.append(file_path)

            logger.info(f"Found {len(changed_files)} changed files since {commit_hash}")
            return changed_files

        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Error detecting changed files: {e}")
            return []

    def get_changed_files_in_working_directory(self) -> list[Path]:
        """Get files changed in working directory (unstaged and staged)."""
        try:
            # Get both staged and unstaged changes
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True,
            )

            changed_files = []
            for line in result.stdout.strip().split("\n"):
                if line:  # Skip empty lines
                    file_path = self.project_root / line
                    if file_path.exists():
                        changed_files.append(file_path)

            logger.info(
                f"Found {len(changed_files)} changed files in working directory"
            )
            return changed_files

        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Error detecting working directory changes: {e}")
            return []

    def get_commit_info(self, commit_hash: str | None = None) -> dict[str, Any]:
        """Get commit information for context."""
        if not commit_hash:
            commit_hash = "HEAD"

        try:
            # Get commit info
            result = subprocess.run(
                ["git", "show", "--format=%H|%an|%ae|%s|%B", "--no-patch", commit_hash],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True,
            )

            lines = result.stdout.strip().split("\n")
            if lines:
                parts = lines[0].split("|", 4)
                if len(parts) >= 4:
                    return {
                        "hash": parts[0],
                        "author": parts[1],
                        "email": parts[2],
                        "subject": parts[3],
                        "message": parts[4] if len(parts) > 4 else parts[3],
                    }

            logger.warning(f"Could not parse commit info for {commit_hash}")
            return {}

        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed for commit {commit_hash}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Error getting commit info: {e}")
            return {}


def create_incremental_scan_context(
    changed_files: list[Path],
    commit_info: dict[str, Any] | None = None,
    diff_info: str | None = None,
) -> dict[str, Any]:
    """Create scan context for incremental analysis."""

    context = {
        "changed_files": [str(f) for f in changed_files],
        "change_count": len(changed_files),
        "analysis_type": "incremental",
    }

    if commit_info:
        context["commit_hash"] = commit_info.get("hash")
        context["author"] = commit_info.get("author")
        context["message"] = commit_info.get("message")

    if diff_info:
        context["diff_info"] = diff_info

    return context


def filter_security_relevant_changes(changed_files: list[Path]) -> list[Path]:
    """Filter changed files to focus on security-relevant files."""

    security_relevant_extensions = {
        ".py",
        ".js",
        ".ts",
        ".java",
        ".go",
        ".rs",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".php",
        ".rb",
        ".cs",
        ".swift",
        ".kt",
        ".scala",
        ".pl",
        ".sh",
        ".ps1",
        ".sql",
        ".yaml",
        ".yml",
        ".json",
        ".xml",
        ".conf",
        ".config",
        ".env",
    }

    security_relevant_patterns = {
        "auth",
        "login",
        "password",
        "token",
        "jwt",
        "session",
        "permission",
        "role",
        "admin",
        "user",
        "security",
        "crypto",
        "hash",
        "encrypt",
        "decrypt",
        "validate",
        "sanitize",
        "escape",
        "sql",
        "query",
        "database",
        "db",
        "api",
        "endpoint",
        "route",
        "controller",
        "middleware",
        "filter",
        "interceptor",
    }

    relevant_files = []

    for file_path in changed_files:
        # Check file extension
        if file_path.suffix.lower() in security_relevant_extensions:
            relevant_files.append(file_path)
            continue

        # Check file path for security keywords
        file_path_lower = str(file_path).lower()
        if any(pattern in file_path_lower for pattern in security_relevant_patterns):
            relevant_files.append(file_path)
            continue

    logger.info(
        f"Filtered {len(changed_files)} files to {len(relevant_files)} security-relevant files"
    )
    return relevant_files
