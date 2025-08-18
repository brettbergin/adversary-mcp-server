"""LLM Session Manager for context-aware security analysis."""

import json
import time
from pathlib import Path
from typing import Any

from ..cache import CacheManager
from ..config import get_app_cache_dir
from ..database.models import AdversaryDatabase
from ..llm import LLMClient
from ..llm.llm_client import LLMResponse
from ..logger import get_logger
from .context_reuse import ContextReuseManager, SessionContextOptimizer
from .project_context import ProjectContext, ProjectContextBuilder
from .session_cache import SessionCache, TokenUsageOptimizer
from .session_cleanup import create_session_cleanup_service
from .session_persistence import SessionPersistenceStore
from .session_types import AnalysisSession, SecurityFinding, SessionState

logger = get_logger("llm_session_manager")


class LLMSessionManager:
    """
    Manages stateful LLM conversations for security analysis.

    This class transforms the traditional request-response pattern into
    a context-aware conversation where the LLM maintains understanding
    of the entire project structure and can perform cross-file analysis.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        max_context_tokens: int = 50000,
        session_timeout_seconds: int = 3600,
        cache_manager: CacheManager | None = None,
        enable_cleanup_automation: bool = True,
    ):
        """
        Initialize the session manager.

        Args:
            llm_client: The LLM client for API communication
            max_context_tokens: Maximum tokens to use for project context
            session_timeout_seconds: Session expiry time in seconds
            cache_manager: Optional cache manager for context and results
            enable_cleanup_automation: Whether to enable automated session cleanup
        """
        self.llm_client = llm_client
        self.max_context_tokens = max_context_tokens
        self.session_timeout_seconds = session_timeout_seconds
        self.context_builder = ProjectContextBuilder(max_context_tokens)

        # Initialize caching
        if cache_manager is None:
            cache_dir = get_app_cache_dir()
            cache_manager = CacheManager(cache_dir=cache_dir)

        self.session_cache = SessionCache(cache_manager)
        self.token_optimizer = TokenUsageOptimizer()

        # Context reuse and optimization
        self.context_reuse_manager = ContextReuseManager(cache_manager)
        self.session_context_optimizer = SessionContextOptimizer(
            self.context_reuse_manager
        )

        # Session persistence with scalability improvements
        database = AdversaryDatabase()
        self.session_store = SessionPersistenceStore(
            database=database,
            max_active_sessions=50,  # Configurable memory limit
            session_timeout_hours=6,  # Sessions expire after 6 hours
            cleanup_interval_minutes=30,  # Cleanup every 30 minutes
        )

        # Automated session cleanup service
        self.cleanup_service = None
        if enable_cleanup_automation:
            self.cleanup_service = create_session_cleanup_service(
                database=database,
                cleanup_interval_minutes=15,  # Clean every 15 minutes
                max_session_age_hours=24,  # Remove sessions older than 24 hours
                health_callback=self._session_health_callback,
            )

        logger.info(
            f"LLMSessionManager initialized with {max_context_tokens} token budget, "
            f"persistent sessions, scalability optimizations, and "
            f"{'automated cleanup' if enable_cleanup_automation else 'manual cleanup'} enabled"
        )

    async def create_session(
        self,
        project_root: Path,
        target_files: list[Path] | None = None,
        session_metadata: dict[str, Any] | None = None,
    ) -> AnalysisSession:
        """
        Create a new analysis session with project context.

        Args:
            project_root: Root directory of the project to analyze
            target_files: Specific files to focus on (optional)
            session_metadata: Additional metadata for the session

        Returns:
            Initialized analysis session
        """
        logger.info(f"Creating new analysis session for {project_root}")

        # Create session
        session = AnalysisSession(
            project_root=project_root,
            metadata=session_metadata or {},
        )
        session.update_state(SessionState.CONTEXT_LOADING)

        # Register session for context optimization
        analysis_focus = (
            session_metadata.get("analysis_focus", "general security analysis")
            if session_metadata
            else "general security analysis"
        )
        self.session_context_optimizer.register_session(
            session.session_id, project_root, analysis_focus
        )

        try:
            # Try to get cached project context first
            logger.info("Loading project context...")
            project_context = self.session_cache.get_cached_project_context(
                project_root
            )

            # Try to optimize context using reusable templates
            optimized_context = self.session_context_optimizer.optimize_session_context(
                session.session_id
            )

            if project_context is None:
                # Build new project context
                logger.info("Building new project context...")
                project_context = self.context_builder.build_context(
                    project_root, target_files
                )

                # Cache the context for future use
                self.session_cache.cache_project_context(project_root, project_context)
                self.session_cache._context_cache_misses += 1
            else:
                logger.info("Using cached project context")
                self.session_cache._context_cache_hits += 1

            session.project_context = {
                "context": project_context,
                "loaded_at": time.time(),
                "estimated_tokens": project_context.estimated_tokens,
                "cached": project_context is not None,
            }

            # Initialize conversation with project context
            context_prompt = self._create_initial_context_prompt(
                project_context, session.session_id
            )
            session.add_message("system", context_prompt, {"type": "project_context"})

            # Send context to LLM to establish understanding
            logger.info("Establishing project context with LLM...")
            await self._establish_context(session, project_context)

            # Update session state and persist
            session.update_state(SessionState.READY)
            self.session_store.store_session(session)

            logger.info(
                f"Session {session.session_id[:8]} created successfully. "
                f"Context: {len(project_context.key_files)} files, "
                f"~{project_context.estimated_tokens} tokens"
            )

            return session

        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            session.update_state(SessionState.ERROR)
            session.metadata["error"] = str(e)
            raise

    async def analyze_with_session(
        self,
        session_id: str,
        analysis_query: str,
        context_hint: str | None = None,
    ) -> list[SecurityFinding]:
        """
        Perform security analysis using established session context.

        Args:
            session_id: ID of the active session
            analysis_query: Specific security analysis query
            context_hint: Optional hint about what to focus on

        Returns:
            List of security findings
        """
        session = self._get_active_session(session_id)
        session.update_state(SessionState.ANALYZING)
        self.session_store.store_session(session)  # Persist state change

        try:
            logger.info(
                f"Analyzing with session {session_id[:8]}: {analysis_query[:100]}..."
            )

            # Check cache first
            project_context = session.project_context.get("context")
            if project_context:
                cached_result = self.session_cache.get_cached_analysis_result(
                    analysis_query, project_context
                )
                if cached_result:
                    logger.info("Using cached analysis result")
                    # Ensure cached results are SecurityFinding objects, not dicts
                    converted_results = []
                    for item in cached_result:
                        if isinstance(item, dict):
                            # Convert dict to SecurityFinding
                            finding = self._create_finding_from_data(item, session)
                            if finding:
                                converted_results.append(finding)
                        else:
                            # Already a SecurityFinding object
                            converted_results.append(item)
                    return converted_results

            # Create contextual analysis prompt
            full_query = self._create_analysis_query(
                analysis_query, context_hint, session
            )
            session.add_message("user", full_query, {"type": "analysis_request"})

            # Get LLM response
            response = await self._get_llm_response(session)
            session.add_message(
                "assistant", response.content, {"type": "analysis_response"}
            )

            # Parse findings from response
            findings = self._parse_findings_from_response(response.content, session)

            # Add findings to session
            for finding in findings:
                session.add_finding(finding)

            session.update_state(SessionState.READY)
            self.session_store.store_session(session)  # Persist session with findings

            # Cache the analysis result for future use
            if project_context and findings:
                self.session_cache.cache_analysis_result(
                    analysis_query, project_context, findings
                )

            logger.info(f"Analysis complete: {len(findings)} findings identified")
            return findings

        except Exception as e:
            logger.error(f"Analysis failed for session {session_id}: {e}")
            session.update_state(SessionState.ERROR)
            self.session_store.store_session(session)  # Persist error state
            raise

    async def continue_analysis(
        self,
        session_id: str,
        follow_up_query: str,
    ) -> list[SecurityFinding]:
        """
        Continue analysis with follow-up questions leveraging existing context.

        Args:
            session_id: ID of the active session
            follow_up_query: Follow-up question or analysis request

        Returns:
            Additional security findings
        """
        session = self._get_active_session(session_id)

        logger.info(f"Continuing analysis for session {session_id[:8]}")

        # Add follow-up message
        session.add_message("user", follow_up_query, {"type": "follow_up"})

        # Get response
        response = await self._get_llm_response(session)
        session.add_message(
            "assistant", response.content, {"type": "follow_up_response"}
        )

        # Parse any new findings
        findings = self._parse_findings_from_response(response.content, session)

        for finding in findings:
            session.add_finding(finding)

        logger.info(f"Follow-up complete: {len(findings)} additional findings")
        return findings

    def get_session_findings(self, session_id: str) -> list[SecurityFinding]:
        """Get all findings from a session."""
        session = self._get_active_session(session_id)
        return session.findings

    def get_session_status(self, session_id: str) -> dict[str, Any]:
        """Get session status and metadata."""
        session = self._get_active_session(session_id)
        return {
            "session_id": session.session_id,
            "state": session.state.value,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "project_root": str(session.project_root) if session.project_root else None,
            "findings_count": len(session.findings),
            "messages_count": len(session.messages),
            "estimated_tokens": session.project_context.get("estimated_tokens", 0),
            "metadata": session.metadata,
        }

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions and return count of cleaned up sessions."""
        return self.session_store.cleanup_expired_sessions()

    def close_session(self, session_id: str) -> None:
        """Manually close a session."""
        session = self.session_store.get_session(session_id)
        if session:
            logger.info(f"Closing session {session_id[:8]}")
            session.update_state(SessionState.COMPLETED)
            self.session_store.store_session(session)  # Update state
            self.session_store.remove_session(session_id)  # Then remove

    def _get_active_session(self, session_id: str) -> AnalysisSession:
        """Get active session or raise exception."""
        session = self.session_store.get_session(session_id)

        if not session:
            raise ValueError(f"Session {session_id} not found or expired")

        if session.state == SessionState.ERROR:
            raise ValueError(f"Session {session_id} is in error state")

        return session

    def _create_initial_context_prompt(
        self, project_context: ProjectContext, session_id: str = ""
    ) -> str:
        """Create the initial system prompt with project context, optimized for sliding window if needed."""

        # Check if we should optimize context for sliding window
        use_sliding_window = (
            session_id and self.token_optimizer.should_use_sliding_window(session_id)
        )

        if use_sliding_window:
            optimal_tokens = self.token_optimizer.get_optimal_context_size(session_id)
            # Optimize project context for sliding window
            optimized_context = (
                self.token_optimizer.optimize_context_for_sliding_window(
                    project_context,
                    current_focus="",  # No specific focus for initial context
                    max_tokens=optimal_tokens // 2,  # Reserve half for conversation
                )
            )

            logger.info(
                f"Applied sliding window optimization to project context: {optimized_context['estimated_tokens']} tokens"
            )

            # Record context token usage
            self.token_optimizer.record_token_usage(
                session_id,
                "sliding_window_context",
                optimized_context["estimated_tokens"],
                optimal_tokens // 2,
            )

            # Create optimized context prompt
            context_prompt = self._build_optimized_context_prompt(optimized_context)
            optimization_note = "\n\n[NOTE: Project context optimized for large codebase analysis using sliding window technique.]"
        else:
            # Use full context
            context_prompt = project_context.to_context_prompt()
            optimization_note = ""

        return f"""You are a senior security engineer analyzing a codebase for vulnerabilities.

{context_prompt}

## Your Role
I'll be asking you specific security questions about this codebase. You have the full context above, so:
1. Reference components by name when discussing vulnerabilities
2. Consider cross-file interactions and data flows
3. Analyze architectural security implications
4. Provide specific, actionable security findings
5. Consider the full context when assessing risk

You can reference any file, component, or module mentioned above by name without me having to repeat the code.{optimization_note}

Ready for security analysis questions about this codebase."""

    def _build_optimized_context_prompt(self, optimized_context: dict[str, Any]) -> str:
        """Build context prompt from optimized context data."""
        lines = []

        # Project overview
        lines.append(f"## Project: {optimized_context['project_root']}")
        lines.append(f"Type: {optimized_context['project_type']}")
        lines.append(f"Architecture: {optimized_context['architecture_summary']}")
        lines.append(f"Total Files: {optimized_context['total_files']}")
        lines.append(f"Languages: {', '.join(optimized_context['languages_used'])}")

        if optimized_context.get("focus_context"):
            lines.append(f"Current Focus: {optimized_context['focus_context']}")

        # Key files
        lines.append(f"\n## Key Files ({len(optimized_context['key_files'])} selected)")
        for file_info in optimized_context["key_files"]:
            lines.append(f"\n### {file_info['path']} ({file_info['language']})")
            if file_info["is_security_critical"]:
                lines.append("🔒 **SECURITY CRITICAL**")
            if file_info.get("truncated"):
                lines.append("⚠️ **Content truncated for context optimization**")
            lines.append(f"Security Relevance: {file_info['security_relevance']}")
            lines.append(f"Relevance Score: {file_info['relevance_score']:.2f}")
            lines.append("```" + file_info["language"])
            lines.append(file_info["content_preview"])
            lines.append("```")

        # Optimization metadata
        lines.append("\n## Context Optimization")
        lines.append(f"Estimated Tokens: {optimized_context['estimated_tokens']}")
        lines.append(
            f"Optimization Applied: {optimized_context['optimization_applied']}"
        )

        return "\n".join(lines)

    async def analyze_with_focused_context(
        self,
        session_id: str,
        focus_target: str,
        analysis_query: str,
    ) -> list[SecurityFinding]:
        """
        Analyze with focused sliding window context for specific files or modules.

        This method optimizes the context window to focus on a specific file or module
        while maintaining relevant project context, ideal for large codebases.

        Args:
            session_id: ID of the active session
            focus_target: File path or module to focus on
            analysis_query: Specific analysis question

        Returns:
            Security findings from focused analysis
        """
        session = self._get_active_session(session_id)

        logger.info(
            f"Starting focused analysis for {focus_target} in session {session_id[:8]}"
        )

        # Check if sliding window optimization should be applied
        use_sliding_window = self.token_optimizer.should_use_sliding_window(session_id)

        if use_sliding_window and session.project_context:
            # Create focused context for this specific analysis
            from .project_context import ProjectContext

            # Check if project_context is a ProjectContext object (not just a dict)
            if isinstance(session.project_context, ProjectContext):
                optimal_tokens = self.token_optimizer.get_optimal_context_size(
                    session_id
                )
                focused_context = (
                    self.token_optimizer.optimize_context_for_sliding_window(
                        session.project_context,
                        current_focus=focus_target,
                        max_tokens=optimal_tokens
                        // 3,  # Reserve more space for conversation
                    )
                )
            else:
                # Skip sliding window optimization if context is not ProjectContext object
                focused_context = session.project_context

            # Create focused context message
            focused_prompt = self._build_optimized_context_prompt(focused_context)
            focused_query = f"""
## Focused Analysis Context
Target: {focus_target}

{focused_prompt}

## Analysis Request
{analysis_query}

Please analyze the target with special attention to its interactions with the context provided above.
"""

            logger.info(
                f"Applied focused sliding window: {focused_context['estimated_tokens']} tokens for {focus_target}"
            )

            # Record focused context usage
            self.token_optimizer.record_token_usage(
                session_id,
                "focused_sliding_window",
                focused_context["estimated_tokens"],
                optimal_tokens // 3,
            )
        else:
            # Standard analysis without optimization
            focused_query = f"""
## Focused Analysis Request
Target: {focus_target}

{analysis_query}

Please analyze the specified target using the project context you already have.
"""

        # Add the focused analysis message
        session.add_message(
            "user",
            focused_query,
            {
                "type": "focused_analysis",
                "focus_target": focus_target,
                "sliding_window_used": use_sliding_window,
            },
        )

        # Get analysis response
        response = await self._get_llm_response(session)
        session.add_message(
            "assistant",
            response.content,
            {"type": "focused_analysis_response", "focus_target": focus_target},
        )

        # Parse findings from the focused analysis
        findings = self._parse_findings_from_response(response.content, session)

        # Add focus metadata to findings
        for finding in findings:
            finding.metadata.update(
                {
                    "focus_target": focus_target,
                    "focused_analysis": True,
                    "sliding_window_used": use_sliding_window,
                }
            )
            session.add_finding(finding)

        logger.info(
            f"Focused analysis complete: {len(findings)} findings for {focus_target}"
        )
        return findings

    async def analyze_changes_incrementally(
        self,
        session_id: str,
        changed_files: list[Path],
        commit_hash: str | None = None,
        change_context: dict[str, Any] | None = None,
    ) -> list[SecurityFinding]:
        """
        Analyze only changed files using existing session context for incremental analysis.

        This method leverages the session's established project context to analyze
        only the files that have changed, making it ideal for CI/CD pipelines and
        real-time development feedback.

        Args:
            session_id: ID of the active session
            changed_files: List of file paths that have changed
            commit_hash: Git commit hash for tracking
            change_context: Additional context about the changes (diff info, etc.)

        Returns:
            Security findings from the changed files
        """
        session = self._get_active_session(session_id)

        logger.info(
            f"Starting incremental analysis for {len(changed_files)} files in session {session_id[:8]}"
        )

        # Get incremental analysis metadata
        incremental_metadata = self.token_optimizer.get_incremental_analysis_metadata(
            session_id
        )

        # Build incremental analysis context
        analysis_context = self._build_incremental_context(
            changed_files, incremental_metadata, change_context
        )

        # Create incremental analysis query
        incremental_query = f"""
## Incremental Security Analysis
Changed Files: {len(changed_files)}
Commit: {commit_hash or 'working directory'}
Baseline Established: {incremental_metadata['baseline_established']}

{analysis_context}

## Analysis Instructions
Analyze only the changed files above for security vulnerabilities. Focus on:
1. New vulnerabilities introduced in the changes
2. Existing vulnerabilities that may have been modified
3. Security implications of the changes in the context of the overall project
4. Changes that might affect security boundaries or data flows

Use your existing project context to understand how these changes interact with the rest of the codebase.
"""

        # Add incremental analysis message
        session.add_message(
            "user",
            incremental_query,
            {
                "type": "incremental_analysis",
                "changed_files": [str(f) for f in changed_files],
                "commit_hash": commit_hash,
                "baseline_established": incremental_metadata["baseline_established"],
            },
        )

        # Get analysis response
        response = await self._get_llm_response(session)
        session.add_message(
            "assistant",
            response.content,
            {
                "type": "incremental_analysis_response",
                "changed_files": [str(f) for f in changed_files],
            },
        )

        # Parse findings from incremental analysis
        findings = self._parse_findings_from_response(response.content, session)

        # Add incremental metadata to findings
        for finding in findings:
            finding.metadata.update(
                {
                    "incremental_analysis": True,
                    "commit_hash": commit_hash,
                    "change_type": "modified",
                    "baseline_established": incremental_metadata[
                        "baseline_established"
                    ],
                }
            )
            session.add_finding(finding)

        # Record incremental analysis operation
        estimated_tokens = len(incremental_query) // 4 + len(response.content) // 4
        self.token_optimizer.record_incremental_analysis(
            session_id,
            "change_analysis",
            [str(f) for f in changed_files],
            commit_hash,
            len(findings),
            estimated_tokens,
        )

        logger.info(
            f"Incremental analysis complete: {len(findings)} findings from {len(changed_files)} changed files"
        )
        return findings

    def _build_incremental_context(
        self,
        changed_files: list[Path],
        incremental_metadata: dict[str, Any],
        change_context: dict[str, Any] | None = None,
    ) -> str:
        """Build context for incremental analysis."""
        context_lines = []

        # Analysis metadata
        if incremental_metadata["baseline_established"]:
            context_lines.append(
                "📊 **Baseline Analysis**: Project context already established"
            )
            if incremental_metadata["last_analysis_timestamp"]:
                last_analysis = time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(incremental_metadata["last_analysis_timestamp"]),
                )
                context_lines.append(f"🕒 **Last Analysis**: {last_analysis}")
        else:
            context_lines.append(
                "📊 **Baseline Analysis**: Not yet established - full context needed"
            )

        # Changed files
        context_lines.append(f"\n### Changed Files ({len(changed_files)})")
        for i, file_path in enumerate(changed_files, 1):
            context_lines.append(f"{i}. `{file_path}`")

            # Try to read file content with error handling
            try:
                if file_path.exists() and file_path.is_file():
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    # Limit content size for context
                    if len(content) > 5000:
                        content = (
                            content[:5000]
                            + "\n... [content truncated for incremental analysis]"
                        )

                    context_lines.append("\n**File Content:**")
                    context_lines.append(
                        f"```{file_path.suffix[1:] if file_path.suffix else 'text'}"
                    )
                    context_lines.append(content)
                    context_lines.append("```")
                else:
                    context_lines.append("   ⚠️ File not found or not readable")
            except Exception as e:
                context_lines.append(f"   ❌ Error reading file: {e}")

        # Add change context if provided
        if change_context:
            if change_context.get("diff_info"):
                context_lines.append("\n### Change Context")
                context_lines.append(f"Diff Info: {change_context['diff_info']}")

            if change_context.get("author"):
                context_lines.append(f"Author: {change_context['author']}")

            if change_context.get("message"):
                context_lines.append(f"Commit Message: {change_context['message']}")

        return "\n".join(context_lines)

    async def establish_incremental_baseline(
        self, session_id: str, target_files: list[Path] | None = None
    ) -> dict[str, Any]:
        """
        Establish a baseline for incremental analysis by analyzing the current state.

        This should be called once before starting incremental analysis to establish
        a known-good baseline that subsequent changes can be compared against.

        Args:
            session_id: ID of the active session
            target_files: Specific files to include in baseline (optional)

        Returns:
            Baseline metadata including analyzed files and findings count
        """
        session = self._get_active_session(session_id)

        logger.info(f"Establishing incremental baseline for session {session_id[:8]}")

        # Perform baseline analysis
        baseline_query = f"""
## Baseline Security Analysis
This is a baseline analysis to establish the current security state of the project.

Target Files: {len(target_files) if target_files else 'All project files'}

## Instructions
Analyze the current codebase for existing security vulnerabilities. This will serve as a baseline
for future incremental analysis. Focus on:
1. Identifying all existing security issues
2. Understanding the overall security posture
3. Establishing architectural security patterns
4. Creating a comprehensive security baseline

This analysis will be used as a reference point for detecting new vulnerabilities in future changes.
"""

        # Add baseline analysis message
        session.add_message(
            "user",
            baseline_query,
            {
                "type": "baseline_analysis",
                "target_files": (
                    [str(f) for f in target_files] if target_files else "all"
                ),
                "baseline_timestamp": time.time(),
            },
        )

        # Get baseline analysis response
        response = await self._get_llm_response(session)
        session.add_message(
            "assistant", response.content, {"type": "baseline_analysis_response"}
        )

        # Parse baseline findings
        baseline_findings = self._parse_findings_from_response(
            response.content, session
        )

        # Add baseline metadata to findings
        for finding in baseline_findings:
            finding.metadata.update(
                {
                    "baseline_finding": True,
                    "analysis_type": "baseline",
                    "baseline_timestamp": time.time(),
                }
            )
            session.add_finding(finding)

        # Record baseline establishment
        estimated_tokens = len(baseline_query) // 4 + len(response.content) // 4
        analyzed_files = (
            [str(f) for f in target_files] if target_files else ["all_project_files"]
        )

        self.token_optimizer.record_incremental_analysis(
            session_id,
            "baseline_establishment",
            analyzed_files,
            None,  # No specific commit for baseline
            len(baseline_findings),
            estimated_tokens,
        )

        baseline_metadata = {
            "baseline_established": True,
            "baseline_timestamp": time.time(),
            "baseline_findings_count": len(baseline_findings),
            "analyzed_files": analyzed_files,
            "session_id": session_id,
        }

        logger.info(
            f"Baseline established: {len(baseline_findings)} findings identified"
        )
        return baseline_metadata

    async def _establish_context(
        self, session: AnalysisSession, project_context: ProjectContext
    ) -> None:
        """Send initial context to LLM and get acknowledgment."""
        try:
            # Get initial response to establish context
            response = await self._get_llm_response(session)

            # Add LLM's acknowledgment to conversation
            session.add_message(
                "assistant", response.content, {"type": "context_acknowledgment"}
            )

            logger.debug(
                f"Context established. LLM response: {response.content[:200]}..."
            )

        except Exception as e:
            logger.warning(f"Failed to establish context, continuing anyway: {e}")

    def _create_analysis_query(
        self,
        query: str,
        context_hint: str | None,
        session: AnalysisSession,
    ) -> str:
        """Create a contextual analysis query."""
        parts = []

        if context_hint:
            parts.append(f"Focus area: {context_hint}")

        parts.append(f"Security Analysis Request: {query}")

        # Add context about previous findings if any
        if session.findings:
            parts.append(
                f"\\nNote: I've already identified {len(session.findings)} potential issues. "
                f"Please consider these in your analysis and avoid duplicates."
            )

        parts.append(
            "\\nPlease provide findings in JSON format with: "
            "rule_id, title, description, severity, file_path, line_number, "
            "code_snippet, confidence, cross_file_references, architectural_context, remediation_advice"
        )

        return "\\n".join(parts)

    async def _get_llm_response(self, session: AnalysisSession) -> LLMResponse:
        """Get response from LLM using session conversation history with sliding window optimization."""
        conversation = session.get_conversation_history()

        # Check if sliding window should be used
        use_sliding_window = self.token_optimizer.should_use_sliding_window(
            session.session_id
        )

        if use_sliding_window:
            # Apply sliding window to conversation history
            optimal_tokens = self.token_optimizer.get_optimal_context_size(
                session.session_id
            )
            conversation = self.token_optimizer.create_sliding_window(
                conversation,
                max_tokens=optimal_tokens
                // 2,  # Reserve half for context, half for conversation
                window_overlap=0.2,
            )

            logger.info(
                f"Applied sliding window: {len(conversation)} messages in context window"
            )

            # Record token usage for optimization
            estimated_conversation_tokens = sum(
                len(str(msg.get("content", ""))) // 4 for msg in conversation
            )
            self.token_optimizer.record_token_usage(
                session.session_id,
                "sliding_window_conversation",
                estimated_conversation_tokens,
                optimal_tokens // 2,
            )

        # For conversation-style APIs, we need to extract system and user messages
        system_messages = [msg for msg in conversation if msg["role"] == "system"]
        other_messages = [msg for msg in conversation if msg["role"] != "system"]

        # Combine system messages into one
        system_content = "\\n\\n".join(msg["content"] for msg in system_messages)

        # Create user prompt from conversation
        user_parts = []
        for msg in other_messages:
            if msg["role"] == "user":
                user_parts.append(f"User: {msg['content']}")
            elif msg["role"] == "assistant":
                user_parts.append(f"Assistant: {msg['content']}")

        user_content = "\\n\\n".join(user_parts)
        if not user_content:
            user_content = "Please acknowledge that you understand the project context and are ready for security analysis."

        # Add sliding window indicator to system prompt if used
        if use_sliding_window:
            system_content += "\n\n[NOTE: This conversation uses sliding window context management for optimal performance with large codebases.]"

        # Make LLM request
        response = await self.llm_client.complete(
            system_prompt=system_content,
            user_prompt=user_content,
            temperature=0.1,
            max_tokens=4000,
            response_format="text",  # Allow flexible responses
        )

        return response

    def _parse_findings_from_response(
        self,
        response_content: str,
        session: AnalysisSession,
    ) -> list[SecurityFinding]:
        """Parse security findings from LLM response."""
        findings = []

        try:
            # Try to extract JSON from response
            json_content = self._extract_json_from_response(response_content)

            if json_content:
                # Parse structured findings
                findings_data = json_content.get("findings", [])
                if not isinstance(findings_data, list):
                    findings_data = [findings_data]

                for finding_data in findings_data:
                    finding = self._create_finding_from_data(finding_data, session)
                    if finding:
                        findings.append(finding)

            # If no structured findings, try to parse natural language response
            if not findings:
                findings = self._parse_natural_language_findings(
                    response_content, session
                )

        except Exception as e:
            logger.warning(f"Failed to parse findings from response: {e}")
            # Create a generic finding from the response
            findings = [self._create_generic_finding(response_content, session)]

        return findings

    def _extract_json_from_response(self, content: str) -> dict[str, Any] | None:
        """Extract JSON content from LLM response."""
        try:
            # Try to find JSON in markdown code blocks
            if "```json" in content:
                start = content.find("```json") + 7
                end = content.find("```", start)
                if end > start:
                    json_str = content[start:end].strip()
                    return json.loads(json_str)

            # Try to find JSON without code blocks
            if content.strip().startswith("{") and content.strip().endswith("}"):
                return json.loads(content.strip())

            # Try to find JSON anywhere in the response
            start_idx = content.find("{")
            if start_idx >= 0:
                # Find matching closing brace
                brace_count = 0
                for i, char in enumerate(content[start_idx:], start_idx):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            json_str = content[start_idx : i + 1]
                            return json.loads(json_str)

        except (json.JSONDecodeError, ValueError) as e:
            logger.debug(f"No valid JSON found in response: {e}")

        return None

    def _create_finding_from_data(
        self,
        finding_data: dict[str, Any],
        session: AnalysisSession,
    ) -> SecurityFinding | None:
        """Create SecurityFinding from parsed data."""
        try:
            from ..scanner.types import Severity

            # Map severity string to enum
            severity_str = str(finding_data.get("severity", "medium")).lower()
            severity_map = {
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)

            finding = SecurityFinding(
                rule_id=str(finding_data.get("rule_id", "llm_session_finding")),
                rule_name=str(finding_data.get("title", "AI-Detected Security Issue")),
                description=str(finding_data.get("description", "")),
                severity=severity,
                file_path=str(finding_data.get("file_path", "")),
                line_number=int(finding_data.get("line_number", 1)),
                code_snippet=str(finding_data.get("code_snippet", "")),
                confidence=float(finding_data.get("confidence", 0.8)),
                cross_file_references=finding_data.get("cross_file_references", []),
                architectural_context=str(
                    finding_data.get("architectural_context", "")
                ),
                remediation_advice=str(finding_data.get("remediation_advice", "")),
                session_context={
                    "session_id": session.session_id,
                    "project_root": str(session.project_root),
                    "analysis_timestamp": time.time(),
                },
            )

            return finding

        except Exception as e:
            logger.warning(f"Failed to create finding from data: {e}")
            return None

    def _parse_natural_language_findings(
        self,
        content: str,
        session: AnalysisSession,
    ) -> list[SecurityFinding]:
        """Parse findings from natural language response."""
        # Simple heuristic parsing - could be enhanced with NLP
        findings = []

        # Look for vulnerability indicators
        vuln_indicators = [
            "vulnerability",
            "security issue",
            "potential risk",
            "exploit",
            "injection",
            "xss",
            "csrf",
            "authentication bypass",
            "sql injection",
        ]

        lines = content.split("\\n")
        current_finding = None

        for line in lines:
            line_lower = line.lower()

            # Check if line indicates a vulnerability
            if any(indicator in line_lower for indicator in vuln_indicators):
                if current_finding:
                    findings.append(current_finding)

                current_finding = SecurityFinding(
                    rule_id="llm_session_natural",
                    rule_name="AI-Detected Security Issue",
                    description=line.strip(),
                    confidence=0.7,
                    session_context={
                        "session_id": session.session_id,
                        "project_root": str(session.project_root),
                        "analysis_timestamp": time.time(),
                        "parsing_method": "natural_language",
                    },
                )
            elif current_finding and line.strip():
                # Add context to current finding
                current_finding.description += f" {line.strip()}"

        if current_finding:
            findings.append(current_finding)

        return findings

    def _create_generic_finding(
        self, content: str, session: AnalysisSession
    ) -> SecurityFinding:
        """Create a generic finding from response content."""
        return SecurityFinding(
            rule_id="llm_session_generic",
            rule_name="LLM Analysis Result",
            description=content[:500] + "..." if len(content) > 500 else content,
            confidence=0.5,
            session_context={
                "session_id": session.session_id,
                "project_root": str(session.project_root),
                "analysis_timestamp": time.time(),
                "parsing_method": "generic",
            },
        )

    # Cache management methods

    def get_cache_statistics(self) -> dict[str, Any]:
        """Get cache performance statistics."""
        return self.session_cache.get_cache_statistics()

    def warm_project_cache(self, project_root: Path) -> bool:
        """Pre-warm cache with project context."""
        return self.session_cache.warm_project_cache(project_root)

    def invalidate_project_cache(self, project_root: Path) -> None:
        """Invalidate cached project context."""
        self.session_cache.invalidate_project_cache(project_root)

    def optimize_cache_performance(self) -> None:
        """Optimize cache performance based on usage patterns."""
        self.session_cache.optimize_cache_usage()

    # Session management methods

    def list_active_sessions(self) -> list[str]:
        """Get list of active session IDs."""
        return self.session_store.list_active_sessions()

    def get_session_statistics(self) -> dict[str, Any]:
        """Get comprehensive session statistics."""
        session_stats = self.session_store.get_statistics()
        cache_stats = self.get_cache_statistics()

        return {
            "session_persistence": session_stats,
            "cache_performance": cache_stats,
            "session_timeout_seconds": self.session_timeout_seconds,
            "max_context_tokens": self.max_context_tokens,
        }

    def force_session_cleanup(self) -> int:
        """Force cleanup of expired sessions and return count cleaned up."""
        return self.cleanup_expired_sessions()

    def get_session_info(self, session_id: str) -> dict[str, Any] | None:
        """Get information about a specific session."""
        session = self.session_store.get_session(session_id)
        if not session:
            return None

        return {
            "session_id": session.session_id,
            "state": session.state.value,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "project_root": str(session.project_root) if session.project_root else None,
            "findings_count": len(session.findings),
            "messages_count": len(session.messages),
            "metadata": session.metadata,
        }

    async def start_cleanup_automation(self) -> None:
        """Start the automated session cleanup service."""
        if self.cleanup_service:
            await self.cleanup_service.start()
            logger.info("Automated session cleanup service started")
        else:
            logger.warning("Cleanup automation not enabled during initialization")

    async def stop_cleanup_automation(self) -> None:
        """Stop the automated session cleanup service."""
        if self.cleanup_service:
            await self.cleanup_service.stop()
            logger.info("Automated session cleanup service stopped")

    async def force_cleanup_now(self) -> dict[str, Any]:
        """Force immediate session cleanup and return detailed statistics."""
        if self.cleanup_service:
            return await self.cleanup_service.force_cleanup()
        else:
            # Fall back to manual cleanup
            cleaned = self.session_store.cleanup_expired_sessions()
            return {
                "expired_sessions_cleaned": cleaned,
                "orphaned_sessions_cleaned": 0,
                "database_vacuumed": False,
                "duration_seconds": 0.0,
                "errors": [],
                "source": "manual_fallback",
            }

    def get_cleanup_status(self) -> dict[str, Any]:
        """Get status of the cleanup automation service."""
        if self.cleanup_service:
            status = self.cleanup_service.get_status()
            status["automation_enabled"] = True
            return status
        else:
            return {
                "automation_enabled": False,
                "running": False,
                "metrics": {"cleanup_runs": 0, "sessions_cleaned": 0},
                "message": "Cleanup automation disabled during initialization",
            }

    def _session_health_callback(self, health_data: dict[str, Any]) -> None:
        """
        Health monitoring callback for session cleanup operations.

        This method is called by the cleanup service to report health metrics.
        Subclasses can override this to implement custom monitoring.
        """
        cleanup_stats = health_data.get("cleanup_stats", {})
        metrics = health_data.get("metrics", {})

        # Log significant cleanup events
        expired_cleaned = cleanup_stats.get("expired_sessions_cleaned", 0)
        orphaned_cleaned = cleanup_stats.get("orphaned_sessions_cleaned", 0)
        total_cleaned = expired_cleaned + orphaned_cleaned

        if total_cleaned > 0:
            logger.info(
                f"Session cleanup completed: {expired_cleaned} expired, "
                f"{orphaned_cleaned} orphaned sessions cleaned"
            )

        # Log errors
        errors = cleanup_stats.get("errors", [])
        if errors:
            logger.error(f"Session cleanup errors: {errors}")

        # Log health warnings
        error_rate = metrics.get("error_rate", 0.0)
        if error_rate > 0.1:  # More than 10% error rate
            logger.warning(f"High session cleanup error rate: {error_rate:.2%}")

        # Optional: Send metrics to external monitoring systems
        # This is where you could integrate with Prometheus, DataDog, etc.
        # Example: self._send_to_monitoring_system(health_data)
