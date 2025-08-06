"""Content-based hashing for intelligent cache invalidation."""

import hashlib
import json
from pathlib import Path
from typing import Any

from ..logger import get_logger

logger = get_logger("content_hasher")


class ContentHasher:
    """Handles content-based hashing for cache keys."""

    def __init__(self, algorithm: str = "sha256"):
        """Initialize hasher with specified algorithm.

        Args:
            algorithm: Hashing algorithm to use (default: sha256)
        """
        self.algorithm = algorithm

    def hash_content(self, content: str) -> str:
        """Generate hash for file content.

        Args:
            content: File content to hash

        Returns:
            Hex digest of content hash
        """
        hasher = hashlib.new(self.algorithm)
        hasher.update(content.encode("utf-8"))
        return hasher.hexdigest()

    def hash_file(self, file_path: Path) -> str:
        """Generate hash for file content on disk.

        Args:
            file_path: Path to file to hash

        Returns:
            Hex digest of file content hash

        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file can't be read
        """
        try:
            with open(file_path, "rb") as f:
                hasher = hashlib.new(self.algorithm)
                # Read file in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
                return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash file {file_path}: {e}")
            raise

    def hash_metadata(self, metadata: dict[str, Any]) -> str:
        """Generate hash for metadata (scan options, configuration, etc.).

        Args:
            metadata: Dictionary of metadata to hash

        Returns:
            Hex digest of metadata hash
        """
        # Sort keys for consistent hashing
        sorted_metadata = json.dumps(metadata, sort_keys=True, default=str)
        return self.hash_content(sorted_metadata)

    def hash_llm_context(
        self,
        content: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> str:
        """Generate hash for LLM request context.

        Args:
            content: File content being analyzed
            model: LLM model name
            system_prompt: System prompt used
            user_prompt: User prompt template
            temperature: LLM temperature setting
            max_tokens: Maximum tokens for response

        Returns:
            Hex digest of LLM context hash
        """
        context = {
            "content_hash": self.hash_content(content),
            "model": model,
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        return self.hash_metadata(context)

    def hash_semgrep_context(
        self,
        content: str,
        language: str,
        rules: list[str] | None = None,
        config_path: str | None = None,
    ) -> str:
        """Generate hash for Semgrep scan context.

        Args:
            content: File content being scanned
            language: Programming language
            rules: List of specific rules to use
            config_path: Path to Semgrep configuration

        Returns:
            Hex digest of Semgrep context hash
        """
        context = {
            "content_hash": self.hash_content(content),
            "language": language,
            "rules": sorted(rules) if rules else None,
            "config_path": config_path,
        }
        return self.hash_metadata(context)

    def hash_validation_context(
        self,
        findings: list[Any],
        validator_model: str,
        confidence_threshold: float,
        additional_context: dict[str, Any] | None = None,
    ) -> str:
        """Generate hash for validation request context.

        Args:
            findings: List of findings to validate
            validator_model: LLM model used for validation
            confidence_threshold: Confidence threshold for validation
            additional_context: Additional context for validation

        Returns:
            Hex digest of validation context hash
        """
        # Hash findings data (excluding UUIDs which change)
        findings_data = []
        for finding in findings:
            if hasattr(finding, "to_dict"):
                finding_dict = finding.to_dict()
                # Remove UUID and timestamp fields that change between runs
                finding_dict.pop("uuid", None)
                finding_dict.pop("created_at", None)
                findings_data.append(finding_dict)
            else:
                findings_data.append(str(finding))

        context = {
            "findings_hash": self.hash_metadata({"findings": findings_data}),
            "validator_model": validator_model,
            "confidence_threshold": confidence_threshold,
            "additional_context": additional_context or {},
        }
        return self.hash_metadata(context)

    def compute_git_hash(self, repo_path: Path, file_path: Path) -> str | None:
        """Compute git hash for file if in git repository.

        Args:
            repo_path: Path to git repository root
            file_path: Path to file within repository

        Returns:
            Git hash of file if available, None otherwise
        """
        try:
            import subprocess

            # Get git hash for file
            result = subprocess.run(
                ["git", "hash-object", str(file_path)],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Git not available or file not in git repo
            return None

    def compute_hybrid_hash(
        self, file_path: Path, repo_path: Path | None = None
    ) -> str:
        """Compute hybrid hash using git hash if available, content hash otherwise.

        Args:
            file_path: Path to file to hash
            repo_path: Optional path to git repository root

        Returns:
            File hash (git hash preferred, content hash fallback)
        """
        # Try git hash first if repository path provided
        if repo_path:
            git_hash = self.compute_git_hash(repo_path, file_path)
            if git_hash:
                return f"git:{git_hash}"

        # Fallback to content hash
        content_hash = self.hash_file(file_path)
        return f"content:{content_hash}"
