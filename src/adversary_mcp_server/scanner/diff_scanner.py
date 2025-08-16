"""Git diff scanner for analyzing security vulnerabilities in code changes."""

import asyncio
import re
import time
from pathlib import Path

from ..config_manager import get_config_manager
from ..logger import get_logger
from ..resilience import ErrorHandler, ResilienceConfig
from .scan_engine import EnhancedScanResult, ScanEngine
from .types import Severity

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

        logger.debug(
            f"Created DiffChunk for {file_path}: "
            f"old ({old_start}+{old_count}), new ({new_start}+{new_count})"
        )

    def add_line(self, line_type: str, line_number: int, content: str) -> None:
        """Add a line to the diff chunk."""
        if line_type == "+":
            self.added_lines.append((line_number, content))
            logger.debug(f"Added line (+) {line_number}: {content[:50]}...")
        elif line_type == "-":
            self.removed_lines.append((line_number, content))
            logger.debug(f"Removed line (-) {line_number}: {content[:50]}...")
        else:
            self.context_lines.append((line_number, content))

    def get_changed_code(self) -> str:
        """Get the changed code as a single string."""
        logger.debug(
            f"Getting changed code for {self.file_path}: "
            f"{len(self.context_lines)} context + {len(self.added_lines)} added lines"
        )

        lines = []

        # Add context lines for better analysis
        for _, content in self.context_lines:
            lines.append(content)

        # Add added lines (new code to scan)
        for _, content in self.added_lines:
            lines.append(content)

        result = "\n".join(lines)
        logger.debug(f"Combined changed code: {len(result)} characters")
        return result

    def get_added_lines_with_minimal_context(self) -> str:
        """Get added lines with minimal context for better analysis.

        This includes only 1-2 context lines around changes, not all context,
        which is useful for LLM analysis while keeping the scope focused.
        """
        file_path_abs = str(Path(self.file_path).resolve())
        logger.debug(f"Getting added lines with minimal context for {file_path_abs}")

        lines = []

        # Add minimal context (max 2 lines before changes)
        context_to_include = self.context_lines[:2] if self.context_lines else []
        logger.debug(f"Including {len(context_to_include)} context lines")

        for _, content in context_to_include:
            lines.append(f"// CONTEXT: {content}")

        # Add all added lines (these are what we're actually analyzing)
        for _, content in self.added_lines:
            lines.append(content)

        result = "\n".join(lines)
        logger.debug(f"Added lines with context: {len(result)} characters")
        return result

    def get_added_lines_only(self) -> str:
        """Get only the added lines as a single string."""
        logger.debug(
            f"Getting only added lines for {self.file_path}: {len(self.added_lines)} lines"
        )
        result = "\n".join(content for _, content in self.added_lines)
        logger.debug(f"Added lines only: {len(result)} characters")
        return result


class GitDiffParser:
    """Parser for git diff output."""

    def __init__(self):
        logger.debug("Initializing GitDiffParser with regex patterns")
        self.diff_header_pattern = re.compile(r"^diff --git a/(.*) b/(.*)$")
        self.chunk_header_pattern = re.compile(
            r"^@@\s*-(\d+)(?:,(\d+))?\s*\+(\d+)(?:,(\d+))?\s*@@"
        )
        self.file_header_pattern = re.compile(r"^(\+\+\+|---)\s+(.*)")
        logger.debug("GitDiffParser initialized successfully")

    def parse_diff(self, diff_output: str) -> dict[str, list[DiffChunk]]:
        """Parse git diff output into structured chunks.

        Args:
            diff_output: Raw git diff output

        Returns:
            Dictionary mapping file paths to lists of DiffChunk objects
        """
        logger.info("=== Starting diff parsing ===")
        logger.debug(f"Parsing diff output: {len(diff_output)} characters")

        chunks_by_file: dict[str, list[DiffChunk]] = {}
        current_file = None
        current_chunk = None
        old_line_num = 0
        new_line_num = 0

        lines = diff_output.split("\n")
        logger.debug(f"Diff contains {len(lines)} lines to parse")

        for line_idx, line in enumerate(lines):
            # Check for file header
            diff_match = self.diff_header_pattern.match(line)
            if diff_match:
                current_file = diff_match.group(2)  # Use the 'b/' path (destination)
                chunks_by_file[current_file] = []
                logger.info(f"Found file header: {current_file}")
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
                logger.debug(
                    f"Created chunk for {current_file}: "
                    f"old({old_start},{old_count}) new({new_start},{new_count})"
                )

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

        # Log parsing results
        total_chunks = sum(len(chunks) for chunks in chunks_by_file.values())
        logger.info(
            f"=== Diff parsing complete - {len(chunks_by_file)} files, {total_chunks} chunks ==="
        )

        for file_path, chunks in chunks_by_file.items():
            total_added = sum(len(chunk.added_lines) for chunk in chunks)
            total_removed = sum(len(chunk.removed_lines) for chunk in chunks)
            logger.debug(
                f"File {file_path}: {len(chunks)} chunks, +{total_added} -{total_removed} lines"
            )

        return chunks_by_file


class GitDiffScanner:
    """Scanner for analyzing security vulnerabilities in git diffs."""

    def __init__(
        self,
        scan_engine: ScanEngine | None = None,
        working_dir: Path | None = None,
        metrics_collector=None,
    ):
        """Initialize the git diff scanner.

        Args:
            scan_engine: Scan engine for vulnerability detection
            working_dir: Working directory for git operations (defaults to current directory)
            metrics_collector: Optional metrics collector for diff scanning analytics
        """
        logger.info("=== Initializing GitDiffScanner ===")
        self.scan_engine = scan_engine or ScanEngine()
        self.working_dir = working_dir or Path.cwd()
        self.parser = GitDiffParser()
        self.metrics_collector = metrics_collector
        self.config_manager = get_config_manager()

        # Initialize ErrorHandler for git command resilience
        resilience_config = ResilienceConfig(
            enable_circuit_breaker=True,
            failure_threshold=self.config_manager.dynamic_limits.circuit_breaker_failure_threshold,
            recovery_timeout_seconds=self.config_manager.dynamic_limits.circuit_breaker_recovery_timeout,
            enable_retry=True,
            max_retry_attempts=self.config_manager.dynamic_limits.max_retry_attempts,
            base_delay_seconds=self.config_manager.dynamic_limits.retry_base_delay,
            enable_graceful_degradation=True,
            default_timeout_seconds=float(
                self.config_manager.dynamic_limits.scan_timeout_seconds
            ),
        )
        self.error_handler = ErrorHandler(resilience_config, self.metrics_collector)

        logger.info(f"Working directory: {self.working_dir}")
        logger.debug("Scan engine, parser, and error handler initialized")
        logger.info("=== GitDiffScanner initialization complete ===")

    async def _run_git_command(
        self, args: list[str], working_dir: Path | None = None
    ) -> str:
        """Run a git command and return its output with resilience handling.

        Args:
            args: Git command arguments
            working_dir: Working directory for git operations (uses self.working_dir if not specified)

        Returns:
            Command output as string

        Raises:
            GitDiffError: If the git command fails
        """
        target_dir = working_dir or self.working_dir
        cmd = ["git"] + args
        command_str = " ".join(cmd)
        logger.debug(f"Executing git command: {command_str} in {target_dir}")

        # Record git operation start
        git_start_time = time.time()
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "git_operations_total",
                1,
                labels={"command": args[0] if args else "unknown", "status": "started"},
            )

        # Define the git operation for resilience handling
        async def git_operation():
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=target_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(
                        self.config_manager.dynamic_limits.scan_timeout_seconds
                    ),
                )
                if proc.returncode == 0:
                    return stdout.decode("utf-8")
                else:
                    error_msg = (
                        stderr.decode("utf-8").strip() if stderr else "Unknown error"
                    )
                    raise GitDiffError(f"Git command failed: {error_msg}")
            finally:
                if proc.returncode is None:
                    try:
                        proc.terminate()
                        await proc.wait()
                    except ProcessLookupError:
                        pass

        # Define fallback function for graceful degradation
        async def git_fallback(*args, **kwargs):
            logger.warning(f"Git service degraded for command: {' '.join(cmd)}")
            raise GitDiffError(f"Git command unavailable: {' '.join(cmd)}")

        try:
            # Execute with comprehensive error recovery
            recovery_result = await self.error_handler.execute_with_recovery(
                git_operation,
                operation_name=f"git_{'_'.join(args[:2])}",
                circuit_breaker_name="git_service",
                fallback_func=git_fallback,
            )

            if recovery_result.success:
                result = recovery_result.result
                git_duration = time.time() - git_start_time

                # Record successful git operation
                if self.metrics_collector:
                    self.metrics_collector.record_metric(
                        "git_operations_total",
                        1,
                        labels={
                            "command": args[0] if args else "unknown",
                            "status": "success",
                        },
                    )
                    self.metrics_collector.record_histogram(
                        "git_operation_duration_seconds",
                        git_duration,
                        labels={
                            "command": args[0] if args else "unknown",
                            "status": "success",
                        },
                    )
                    self.metrics_collector.record_metric(
                        "git_output_size_bytes", len(result)
                    )

                logger.debug(f"Git command successful: {len(result)} chars output")
                return result
            else:
                git_duration = time.time() - git_start_time
                error_msg = recovery_result.error_message or "Git service unavailable"

                # Record failed git operation
                if self.metrics_collector:
                    self.metrics_collector.record_metric(
                        "git_operations_total",
                        1,
                        labels={
                            "command": args[0] if args else "unknown",
                            "status": "failure",
                        },
                    )
                    self.metrics_collector.record_histogram(
                        "git_operation_duration_seconds",
                        git_duration,
                        labels={
                            "command": args[0] if args else "unknown",
                            "status": "failure",
                        },
                    )

                raise GitDiffError(f"Git command failed with recovery: {error_msg}")

        except FileNotFoundError:
            git_duration = time.time() - git_start_time

            # Record git not found error
            if self.metrics_collector:
                self.metrics_collector.record_metric(
                    "git_operations_total",
                    1,
                    labels={
                        "command": args[0] if args else "unknown",
                        "status": "not_found",
                    },
                )
                self.metrics_collector.record_histogram(
                    "git_operation_duration_seconds",
                    git_duration,
                    labels={
                        "command": args[0] if args else "unknown",
                        "status": "not_found",
                    },
                )

            logger.error("Git command not found in PATH")
            raise GitDiffError(
                "Git command not found. Please ensure git is installed and in PATH."
            )

    async def _validate_branches(
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
        logger.info(f"Validating branches: {source_branch} -> {target_branch}")

        try:
            # Check if source branch exists
            logger.debug(f"Validating source branch: {source_branch}")
            await self._run_git_command(
                ["rev-parse", "--verify", f"{source_branch}^{{commit}}"], working_dir
            )
            logger.debug(f"Source branch {source_branch} exists")

            # Check if target branch exists
            logger.debug(f"Validating target branch: {target_branch}")
            await self._run_git_command(
                ["rev-parse", "--verify", f"{target_branch}^{{commit}}"], working_dir
            )
            logger.debug(f"Target branch {target_branch} exists")

            logger.info("Branch validation successful")

        except GitDiffError as e:
            logger.error(f"Branch validation failed: {e}")
            raise GitDiffError(f"Branch validation failed: {e}")

    def _detect_language_from_path(self, file_path: str) -> str:
        """Detect programming language from file path using language mapping.

        Args:
            file_path: Path to the file

        Returns:
            Programming language name (e.g., 'python', 'javascript') or 'generic' for unknown
        """
        from .language_mapping import LanguageMapper

        detected_language = LanguageMapper.detect_language_from_extension(file_path)
        logger.debug(f"Language detected for {file_path}: {detected_language}")
        return detected_language

    async def get_diff_changes(
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
        diff_analysis_start_time = time.time()
        logger.info(f"=== Getting diff changes: {source_branch} -> {target_branch} ===")

        # Record diff analysis start
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "diff_analysis_operations_total",
                1,
                labels={"source_branch": source_branch, "target_branch": target_branch},
            )

        # Validate branches exist
        await self._validate_branches(source_branch, target_branch, working_dir)

        # Get diff between branches
        diff_args = ["diff", f"{target_branch}...{source_branch}"]
        logger.debug(f"Getting diff with command: git {' '.join(diff_args)}")
        diff_output = await self._run_git_command(diff_args, working_dir)

        if not diff_output.strip():
            logger.info(
                f"No differences found between {source_branch} and {target_branch}"
            )

            # Record no changes metric
            if self.metrics_collector:
                diff_duration = time.time() - diff_analysis_start_time
                self.metrics_collector.record_histogram(
                    "diff_analysis_duration_seconds",
                    diff_duration,
                    labels={"outcome": "no_changes"},
                )
                self.metrics_collector.record_metric("diff_analysis_files_changed", 0)

            return {}

        logger.info(f"Diff output received: {len(diff_output)} characters")

        # Parse the diff output
        logger.debug("Parsing diff output...")
        parse_start_time = time.time()
        changes = self.parser.parse_diff(diff_output)
        parse_duration = time.time() - parse_start_time

        # Record diff analysis metrics
        if self.metrics_collector:
            diff_duration = time.time() - diff_analysis_start_time
            total_chunks = sum(len(chunks) for chunks in changes.values())
            total_added_lines = sum(
                len(chunk.added_lines)
                for chunks in changes.values()
                for chunk in chunks
            )

            self.metrics_collector.record_histogram(
                "diff_analysis_duration_seconds",
                diff_duration,
                labels={"outcome": "changes_found"},
            )
            self.metrics_collector.record_histogram(
                "diff_parsing_duration_seconds", parse_duration
            )
            self.metrics_collector.record_metric(
                "diff_analysis_files_changed", len(changes)
            )
            self.metrics_collector.record_metric(
                "diff_analysis_chunks_total", total_chunks
            )
            self.metrics_collector.record_metric(
                "diff_analysis_added_lines_total", total_added_lines
            )
            self.metrics_collector.record_metric(
                "diff_output_size_bytes", len(diff_output)
            )

        logger.info(f"=== Diff changes retrieved - {len(changes)} files changed ===")
        return changes

    async def scan_diff(
        self,
        source_branch: str,
        target_branch: str,
        working_dir: Path | None = None,
        use_llm: bool = False,
        use_semgrep: bool = True,
        use_validation: bool = True,
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
            use_validation: Whether to use LLM validation to filter false positives
            use_rules: Whether to use rules-based scanner
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            Dictionary mapping file paths to lists of scan results

        Raises:
            GitDiffError: If git operations fail
        """
        diff_scan_start_time = time.time()
        logger.info(f"=== Starting diff scan: {source_branch} -> {target_branch} ===")
        logger.debug(
            f"Scan parameters - LLM: {use_llm}, Semgrep: {use_semgrep}, "
            f"Validation: {use_validation}, Rules: {use_rules}, Severity: {severity_threshold}"
        )

        # Record diff scan start
        if self.metrics_collector:
            self.metrics_collector.record_metric(
                "diff_scan_operations_total",
                1,
                labels={
                    "source_branch": source_branch,
                    "target_branch": target_branch,
                    "use_llm": str(use_llm),
                    "use_semgrep": str(use_semgrep),
                    "use_validation": str(use_validation),
                },
            )

        # Get diff changes
        logger.debug("Retrieving diff changes...")
        diff_changes = await self.get_diff_changes(
            source_branch, target_branch, working_dir
        )

        if not diff_changes:
            logger.info("No diff changes found - returning empty results")

            # Record no changes scan
            if self.metrics_collector:
                diff_scan_duration = time.time() - diff_scan_start_time
                self.metrics_collector.record_histogram(
                    "diff_scan_duration_seconds",
                    diff_scan_duration,
                    labels={"outcome": "no_changes"},
                )
                self.metrics_collector.record_metric("diff_scan_files_processed", 0)

            return {}

        logger.info(f"Processing {len(diff_changes)} changed files")
        scan_results: dict[str, list[EnhancedScanResult]] = {}

        files_processed = 0
        files_skipped = 0
        files_failed = 0
        total_threats_found = 0

        for file_path, chunks in diff_changes.items():
            file_path_abs = str(Path(file_path).resolve())
            logger.debug(f"Processing file: {file_path_abs}")

            # Get language (now always generic)
            language = self._detect_language_from_path(file_path)

            logger.info(f"Scanning {file_path_abs} as {language}")

            # Combine only the newly added lines from all chunks
            all_added_code = []
            line_mapping = {}  # Map from combined code lines to original diff lines
            total_added_lines = 0

            combined_line_num = 1
            for chunk_idx, chunk in enumerate(chunks):
                logger.debug(
                    f"Processing chunk {chunk_idx + 1}/{len(chunks)} for {file_path}"
                )

                # Only scan newly added lines, not context
                added_code = chunk.get_added_lines_only()
                if added_code.strip():
                    all_added_code.append(added_code)
                    chunk_added_lines = len(chunk.added_lines)
                    total_added_lines += chunk_added_lines
                    logger.debug(
                        f"Chunk {chunk_idx + 1}: {chunk_added_lines} added lines"
                    )

                    # Map line numbers for accurate reporting (only for added lines)
                    for i, (original_line_num, line_content) in enumerate(
                        chunk.added_lines
                    ):
                        if line_content.strip():  # Skip empty lines
                            line_mapping[combined_line_num] = original_line_num
                            combined_line_num += 1

            if not all_added_code:
                logger.debug(f"No added code to scan in {file_path_abs}")
                files_skipped += 1
                continue

            logger.info(f"Scanning {total_added_lines} added lines in {file_path_abs}")

            # Scan the combined added code (only new lines)
            full_added_code = "\n".join(all_added_code)
            logger.debug(f"Combined added code: {len(full_added_code)} characters")

            try:
                logger.debug(f"Calling scan_engine.scan_code for {file_path_abs}...")
                scan_result = await self.scan_engine.scan_code(
                    source_code=full_added_code,
                    file_path=file_path,
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    use_validation=use_validation,
                    severity_threshold=severity_threshold,
                )

                # Update line numbers to match original file
                original_threat_count = len(scan_result.all_threats)
                remapped_threats = 0

                for threat in scan_result.all_threats:
                    if threat.line_number in line_mapping:
                        old_line = threat.line_number
                        threat.line_number = line_mapping[threat.line_number]
                        logger.debug(
                            f"Remapped threat line number: {old_line} -> {threat.line_number}"
                        )
                        remapped_threats += 1

                scan_results[file_path] = [scan_result]
                threat_count = len(scan_result.all_threats)
                total_threats_found += threat_count
                files_processed += 1

                logger.info(
                    f"Scanned {file_path_abs}: {threat_count} threats found, "
                    f"{remapped_threats} line numbers remapped"
                )

            except Exception as e:
                logger.error(f"Failed to scan {file_path_abs}: {e}")
                logger.debug(f"Scan error details for {file_path_abs}", exc_info=True)
                files_failed += 1
                continue

        # Record diff scan completion metrics
        if self.metrics_collector:
            diff_scan_duration = time.time() - diff_scan_start_time

            self.metrics_collector.record_histogram(
                "diff_scan_duration_seconds",
                diff_scan_duration,
                labels={"outcome": "completed"},
            )
            self.metrics_collector.record_metric(
                "diff_scan_files_processed", files_processed
            )
            self.metrics_collector.record_metric(
                "diff_scan_files_skipped", files_skipped
            )
            self.metrics_collector.record_metric("diff_scan_files_failed", files_failed)
            self.metrics_collector.record_metric(
                "diff_scan_threats_found_total", total_threats_found
            )

            # Record scan performance metrics
            if diff_scan_duration > 0:
                files_per_second = len(diff_changes) / diff_scan_duration
                self.metrics_collector.record_histogram(
                    "diff_scan_files_per_second", files_per_second
                )

        logger.info(
            f"=== Diff scan complete - Processed: {files_processed}, "
            f"Skipped: {files_skipped}, Failed: {files_failed}, "
            f"Total threats: {total_threats_found} ==="
        )

        return scan_results

    def scan_diff_sync(
        self,
        source_branch: str,
        target_branch: str,
        working_dir: Path | None = None,
        use_llm: bool = False,
        use_semgrep: bool = True,
        use_validation: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
    ) -> dict[str, list[EnhancedScanResult]]:
        """Synchronous wrapper for scan_diff for testing and CLI usage."""
        logger.debug(
            f"Synchronous diff scan wrapper called: {source_branch} -> {target_branch}"
        )
        import asyncio

        return asyncio.run(
            self.scan_diff(
                source_branch=source_branch,
                target_branch=target_branch,
                working_dir=working_dir,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                use_rules=use_rules,
                severity_threshold=severity_threshold,
            )
        )

    async def get_diff_summary(
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
        logger.info(f"Getting diff summary: {source_branch} -> {target_branch}")

        try:
            diff_changes = await self.get_diff_changes(
                source_branch, target_branch, working_dir
            )

            total_files = len(diff_changes)
            total_chunks = sum(len(chunks) for chunks in diff_changes.values())

            lines_added = 0
            lines_removed = 0
            supported_files = 0
            scannable_files = []

            logger.debug(f"Processing {total_files} changed files for summary")

            for file_path, chunks in diff_changes.items():
                # All files are now considered supported
                supported_files += 1
                scannable_files.append(file_path)

                for chunk in chunks:
                    lines_added += len(chunk.added_lines)
                    lines_removed += len(chunk.removed_lines)

            summary = {
                "source_branch": source_branch,
                "target_branch": target_branch,
                "total_files_changed": total_files,
                "supported_files": supported_files,
                "total_chunks": total_chunks,
                "lines_added": lines_added,
                "lines_removed": lines_removed,
                "scannable_files": scannable_files,
            }

            logger.info(
                f"Diff summary - Files: {total_files}, Supported: {supported_files}, "
                f"Lines: +{lines_added} -{lines_removed}"
            )

            return summary

        except GitDiffError as e:
            logger.error(f"Failed to get diff summary: {e}")
            return {
                "source_branch": source_branch,
                "target_branch": target_branch,
                "error": "Failed to get diff summary",
            }
