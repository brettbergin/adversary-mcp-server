"""Git diff scanner for analyzing security vulnerabilities in code changes."""

import re
import subprocess
from pathlib import Path

from .logging_config import get_logger
from .scan_engine import EnhancedScanResult, ScanEngine
from .threat_engine import Language, LanguageSupport, Severity

logger = get_logger("diff_scanner")


class GitDiffError(Exception):
    """Exception raised when git diff operations fail."""

    pass


class DiffChunk:
    """Represents a chunk of changes in a git diff."""

    def __init__(
        self,
        file_path: str,
        old_start: int,
        old_count: int,
        new_start: int,
        new_count: int,
    ):
        self.file_path = file_path
        self.old_start = old_start
        self.old_count = old_count
        self.new_start = new_start
        self.new_count = new_count
        self.added_lines: list[tuple[int, str]] = []  # (line_number, content)
        self.removed_lines: list[tuple[int, str]] = []  # (line_number, content)
        self.context_lines: list[tuple[int, str]] = []  # (line_number, content)

    def add_line(self, line_type: str, line_number: int, content: str) -> None:
        """Add a line to the diff chunk."""
        if line_type == "+":
            self.added_lines.append((line_number, content))
        elif line_type == "-":
            self.removed_lines.append((line_number, content))
        else:
            self.context_lines.append((line_number, content))

    def get_changed_code(self) -> str:
        """Get the changed code as a single string."""
        lines = []

        # Add context lines for better analysis
        for _, content in self.context_lines:
            lines.append(content)

        # Add added lines (new code to scan)
        for _, content in self.added_lines:
            lines.append(content)

        return "\n".join(lines)

    def get_added_lines_with_minimal_context(self) -> str:
        """Get added lines with minimal context for better analysis.

        This includes only 1-2 context lines around changes, not all context,
        which is useful for LLM analysis while keeping the scope focused.
        """
        lines = []

        # Add minimal context (max 2 lines before changes)
        context_to_include = self.context_lines[:2] if self.context_lines else []
        for _, content in context_to_include:
            lines.append(f"// CONTEXT: {content}")

        # Add all added lines (these are what we're actually analyzing)
        for _, content in self.added_lines:
            lines.append(content)

        return "\n".join(lines)

    def get_added_lines_only(self) -> str:
        """Get only the added lines as a single string."""
        return "\n".join(content for _, content in self.added_lines)


class GitDiffParser:
    """Parser for git diff output."""

    def __init__(self):
        self.diff_header_pattern = re.compile(r"^diff --git a/(.*) b/(.*)$")
        self.chunk_header_pattern = re.compile(
            r"^@@\s*-(\d+)(?:,(\d+))?\s*\+(\d+)(?:,(\d+))?\s*@@"
        )
        self.file_header_pattern = re.compile(r"^(\+\+\+|---)\s+(.*)")

    def parse_diff(self, diff_output: str) -> dict[str, list[DiffChunk]]:
        """Parse git diff output into structured chunks.

        Args:
            diff_output: Raw git diff output

        Returns:
            Dictionary mapping file paths to lists of DiffChunk objects
        """
        chunks_by_file: dict[str, list[DiffChunk]] = {}
        current_file = None
        current_chunk = None
        old_line_num = 0
        new_line_num = 0

        for line in diff_output.split("\n"):
            # Check for file header
            diff_match = self.diff_header_pattern.match(line)
            if diff_match:
                current_file = diff_match.group(2)  # Use the 'b/' path (destination)
                chunks_by_file[current_file] = []
                continue

            # Check for chunk header
            chunk_match = self.chunk_header_pattern.match(line)
            if chunk_match and current_file:
                old_start = int(chunk_match.group(1))
                old_count = int(chunk_match.group(2) or "1")
                new_start = int(chunk_match.group(3))
                new_count = int(chunk_match.group(4) or "1")

                current_chunk = DiffChunk(
                    current_file, old_start, old_count, new_start, new_count
                )
                chunks_by_file[current_file].append(current_chunk)

                old_line_num = old_start
                new_line_num = new_start
                continue

            # Check for content lines
            if current_chunk and line:
                if line.startswith("+") and not line.startswith("+++"):
                    content = line[1:]  # Remove the '+' prefix
                    current_chunk.add_line("+", new_line_num, content)
                    new_line_num += 1
                elif line.startswith("-") and not line.startswith("---"):
                    content = line[1:]  # Remove the '-' prefix
                    current_chunk.add_line("-", old_line_num, content)
                    old_line_num += 1
                elif line.startswith(" "):
                    content = line[1:]  # Remove the ' ' prefix
                    current_chunk.add_line(" ", new_line_num, content)
                    old_line_num += 1
                    new_line_num += 1

        return chunks_by_file


class GitDiffScanner:
    """Scanner for analyzing security vulnerabilities in git diffs."""

    def __init__(
        self,
        scan_engine: ScanEngine | None = None,
        working_dir: Path | None = None,
    ):
        """Initialize the git diff scanner.

        Args:
            scan_engine: Scan engine for vulnerability detection
            working_dir: Working directory for git operations (defaults to current directory)
        """
        self.scan_engine = scan_engine or ScanEngine()
        self.working_dir = working_dir or Path.cwd()
        self.parser = GitDiffParser()

    def _run_git_command(self, args: list[str], working_dir: Path | None = None) -> str:
        """Run a git command and return its output.

        Args:
            args: Git command arguments
            working_dir: Working directory for git operations (uses self.working_dir if not specified)

        Returns:
            Command output as string

        Raises:
            GitDiffError: If the git command fails
        """
        target_dir = working_dir or self.working_dir
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=target_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise GitDiffError(f"Git command failed: {e.stderr.strip()}")
        except FileNotFoundError:
            raise GitDiffError(
                "Git command not found. Please ensure git is installed and in PATH."
            )

    def _validate_branches(
        self, source_branch: str, target_branch: str, working_dir: Path | None = None
    ) -> None:
        """Validate that the specified branches exist.

        Args:
            source_branch: Source branch name
            target_branch: Target branch name
            working_dir: Working directory for git operations (uses self.working_dir if not specified)

        Raises:
            GitDiffError: If either branch doesn't exist
        """
        try:
            # Check if source branch exists
            self._run_git_command(
                ["rev-parse", "--verify", f"{source_branch}^{{commit}}"], working_dir
            )

            # Check if target branch exists
            self._run_git_command(
                ["rev-parse", "--verify", f"{target_branch}^{{commit}}"], working_dir
            )

        except GitDiffError as e:
            raise GitDiffError(f"Branch validation failed: {e}")

    def _detect_language_from_path(self, file_path: str) -> Language | None:
        """Detect programming language from file path.

        Args:
            file_path: Path to the file

        Returns:
            Detected language or None if not supported for security scanning
        """
        extension = Path(file_path).suffix.lower()

        language_map = LanguageSupport.get_extension_to_language_map()
        detected_language = language_map.get(extension)

        # Diff scanner only scans code files, not documentation or config files
        if detected_language == Language.GENERIC:
            return None

        return detected_language

    def get_diff_changes(
        self, source_branch: str, target_branch: str, working_dir: Path | None = None
    ) -> dict[str, list[DiffChunk]]:
        """Get diff changes between two branches.

        Args:
            source_branch: Source branch (e.g., 'feature-branch')
            target_branch: Target branch (e.g., 'main')
            working_dir: Working directory for git operations (uses self.working_dir if not specified)

        Returns:
            Dictionary mapping file paths to lists of DiffChunk objects

        Raises:
            GitDiffError: If git operations fail
        """
        # Validate branches exist
        self._validate_branches(source_branch, target_branch, working_dir)

        # Get diff between branches
        diff_args = ["diff", f"{target_branch}...{source_branch}"]
        diff_output = self._run_git_command(diff_args, working_dir)

        if not diff_output.strip():
            logger.info(
                f"No differences found between {source_branch} and {target_branch}"
            )
            return {}

        # Parse the diff output
        return self.parser.parse_diff(diff_output)

    async def scan_diff(
        self,
        source_branch: str,
        target_branch: str,
        working_dir: Path | None = None,
        use_llm: bool = False,
        use_semgrep: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
    ) -> dict[str, list[EnhancedScanResult]]:
        """Scan security vulnerabilities in git diff changes.

        Args:
            source_branch: Source branch name
            target_branch: Target branch name
            working_dir: Working directory for git operations (uses self.working_dir if not specified)
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            use_rules: Whether to use rules-based scanner
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            Dictionary mapping file paths to lists of scan results

        Raises:
            GitDiffError: If git operations fail
        """
        # Get diff changes
        diff_changes = self.get_diff_changes(source_branch, target_branch, working_dir)

        if not diff_changes:
            return {}

        scan_results: dict[str, list[EnhancedScanResult]] = {}

        for file_path, chunks in diff_changes.items():
            # Skip non-code files
            language = self._detect_language_from_path(file_path)
            if not language:
                logger.debug(f"Skipping {file_path}: unsupported file type")
                continue

            # Combine only the newly added lines from all chunks
            all_added_code = []
            line_mapping = {}  # Map from combined code lines to original diff lines

            combined_line_num = 1
            for chunk in chunks:
                # Only scan newly added lines, not context
                added_code = chunk.get_added_lines_only()
                if added_code.strip():
                    all_added_code.append(added_code)

                    # Map line numbers for accurate reporting (only for added lines)
                    for i, (original_line_num, line_content) in enumerate(
                        chunk.added_lines
                    ):
                        if line_content.strip():  # Skip empty lines
                            line_mapping[combined_line_num] = original_line_num
                            combined_line_num += 1

            if not all_added_code:
                continue

            # Scan the combined added code (only new lines)
            full_added_code = "\n".join(all_added_code)

            try:
                scan_result = await self.scan_engine.scan_code(
                    source_code=full_added_code,
                    file_path=file_path,
                    language=language,
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    use_rules=use_rules,
                    severity_threshold=severity_threshold,
                )

                # Update line numbers to match original file
                for threat in scan_result.all_threats:
                    if threat.line_number in line_mapping:
                        threat.line_number = line_mapping[threat.line_number]

                scan_results[file_path] = [scan_result]
                logger.info(
                    f"Scanned {file_path}: found {len(scan_result.all_threats)} threats"
                )

            except Exception as e:
                logger.error(f"Failed to scan {file_path}: {e}")
                continue

        return scan_results

    def scan_diff_sync(
        self,
        source_branch: str,
        target_branch: str,
        working_dir: Path | None = None,
        use_llm: bool = False,
        use_semgrep: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
    ) -> dict[str, list[EnhancedScanResult]]:
        """Synchronous wrapper for scan_diff for testing and CLI usage."""
        import asyncio

        return asyncio.run(
            self.scan_diff(
                source_branch=source_branch,
                target_branch=target_branch,
                working_dir=working_dir,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_rules=use_rules,
                severity_threshold=severity_threshold,
            )
        )

    def get_diff_summary(
        self, source_branch: str, target_branch: str, working_dir: Path | None = None
    ) -> dict[str, any]:
        """Get a summary of the diff between two branches.

        Args:
            source_branch: Source branch name
            target_branch: Target branch name
            working_dir: Working directory for git operations (uses self.working_dir if not specified)

        Returns:
            Dictionary with diff summary information
        """
        try:
            diff_changes = self.get_diff_changes(
                source_branch, target_branch, working_dir
            )

            total_files = len(diff_changes)
            total_chunks = sum(len(chunks) for chunks in diff_changes.values())

            lines_added = 0
            lines_removed = 0
            supported_files = 0

            for file_path, chunks in diff_changes.items():
                if self._detect_language_from_path(file_path):
                    supported_files += 1

                for chunk in chunks:
                    lines_added += len(chunk.added_lines)
                    lines_removed += len(chunk.removed_lines)

            return {
                "source_branch": source_branch,
                "target_branch": target_branch,
                "total_files_changed": total_files,
                "supported_files": supported_files,
                "total_chunks": total_chunks,
                "lines_added": lines_added,
                "lines_removed": lines_removed,
                "scannable_files": [
                    file_path
                    for file_path in diff_changes.keys()
                    if self._detect_language_from_path(file_path)
                ],
            }

        except GitDiffError:
            return {
                "source_branch": source_branch,
                "target_branch": target_branch,
                "error": "Failed to get diff summary",
            }
