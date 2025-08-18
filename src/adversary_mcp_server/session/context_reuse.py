"""Context reuse and template management for session optimization."""

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..cache import CacheKey, CacheManager, CacheType
from ..logger import get_logger

if TYPE_CHECKING:
    from .project_context import ProjectContext

logger = get_logger("context_reuse")


class ContextReuseManager:
    """Manages context reuse and template creation across sessions."""

    def __init__(self, cache_manager: CacheManager):
        """Initialize the context reuse manager."""
        self.cache_manager = cache_manager
        self.hasher = cache_manager.get_hasher()
        logger.info("ContextReuseManager initialized")

    def create_reusable_context_template(
        self, project_context: "ProjectContext", session_patterns: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a reusable context template that can be shared across sessions.

        This template captures the most commonly accessed parts of a project context
        and optimizes them for reuse across multiple analysis sessions.
        """

        # Analyze session patterns to identify frequently accessed files
        frequently_accessed = set()
        security_critical_files = set()

        for pattern_data in session_patterns.values():
            accessed_files = pattern_data.get("accessed_files", [])
            frequently_accessed.update(accessed_files)

            critical_files = pattern_data.get("security_critical_files", [])
            security_critical_files.update(critical_files)

        # Create optimized template
        template = {
            "template_id": f"tpl_{hash(str(project_context.project_root))}_v1",
            "project_root": str(project_context.project_root),
            "project_type": project_context.project_type,
            "architecture_summary": project_context.architecture_summary,
            "total_files": project_context.total_files,
            "languages_used": list(project_context.languages_used),
            "template_created": time.time(),
            "template_version": 1,
            # Core files that are accessed frequently
            "core_files": [],
            # Security-critical files that should always be included
            "security_critical_files": [],
            # Architectural patterns and common security concerns
            "security_patterns": self._extract_security_patterns(project_context),
            # Common analysis contexts for reuse
            "common_contexts": self._build_common_contexts(
                project_context, session_patterns
            ),
            # Template metadata
            "usage_frequency": 0,
            "last_used": time.time(),
            "sessions_using_template": set(),
        }

        # Add frequently accessed core files
        for file in project_context.key_files:
            if (
                str(file.path) in frequently_accessed
                or file.is_security_critical
                or str(file.path) in security_critical_files
            ):

                template["core_files"].append(
                    {
                        "path": str(file.path),
                        "language": file.language,
                        "security_relevance": file.security_relevance,
                        "content_preview": file.content_preview[
                            :2000
                        ],  # Truncate for template
                        "is_security_critical": file.is_security_critical,
                        "priority_score": file.priority_score,
                    }
                )

        # Limit template size for performance
        template["core_files"] = template["core_files"][:20]  # Top 20 files

        return template

    def _extract_security_patterns(
        self, project_context: "ProjectContext"
    ) -> dict[str, Any]:
        """Extract common security patterns from project context."""
        patterns = {
            "authentication_patterns": [],
            "data_flow_patterns": [],
            "api_patterns": [],
            "database_patterns": [],
        }

        # Analyze key files for security patterns
        for file in project_context.key_files:
            file_content = file.content_preview.lower()
            file_path = str(file.path).lower()

            # Authentication patterns
            if any(
                auth_keyword in file_content or auth_keyword in file_path
                for auth_keyword in ["auth", "login", "session", "jwt", "token"]
            ):
                patterns["authentication_patterns"].append(
                    {
                        "file": str(file.path),
                        "type": "authentication_component",
                        "relevance": file.security_relevance,
                    }
                )

            # API patterns
            if any(
                api_keyword in file_content or api_keyword in file_path
                for api_keyword in ["api", "endpoint", "route", "controller"]
            ):
                patterns["api_patterns"].append(
                    {
                        "file": str(file.path),
                        "type": "api_component",
                        "relevance": file.security_relevance,
                    }
                )

            # Database patterns
            if any(
                db_keyword in file_content or db_keyword in file_path
                for db_keyword in ["sql", "database", "query", "model"]
            ):
                patterns["database_patterns"].append(
                    {
                        "file": str(file.path),
                        "type": "database_component",
                        "relevance": file.security_relevance,
                    }
                )

        return patterns

    def _build_common_contexts(
        self, project_context: "ProjectContext", session_patterns: dict[str, Any]
    ) -> dict[str, str]:
        """Build common analysis contexts that can be reused."""

        contexts = {}

        # General security context
        contexts[
            "general_security"
        ] = f"""
## Project Security Overview
Type: {project_context.project_type}
Architecture: {project_context.architecture_summary}
Languages: {', '.join(project_context.languages_used)}

This project has been analyzed for common security patterns and vulnerabilities.
Focus areas include authentication, data validation, and secure communication.
"""

        # Authentication context
        auth_files = [
            f
            for f in project_context.key_files
            if any(
                keyword in str(f.path).lower()
                for keyword in ["auth", "login", "session"]
            )
        ]

        if auth_files:
            contexts[
                "authentication_analysis"
            ] = f"""
## Authentication Security Context
The project implements authentication through {len(auth_files)} key components:
{chr(10).join(f"- {f.path}" for f in auth_files[:5])}

Focus on authentication bypasses, session management, and access control vulnerabilities.
"""

        # API security context
        api_files = [
            f
            for f in project_context.key_files
            if any(
                keyword in str(f.path).lower()
                for keyword in ["api", "endpoint", "route"]
            )
        ]

        if api_files:
            contexts[
                "api_security_analysis"
            ] = f"""
## API Security Context
The project exposes APIs through {len(api_files)} components:
{chr(10).join(f"- {f.path}" for f in api_files[:5])}

Focus on input validation, authorization, rate limiting, and injection vulnerabilities.
"""

        return contexts

    def get_reusable_context_for_session(
        self, project_root: Path, analysis_focus: str, session_id: str
    ) -> dict[str, Any] | None:
        """Get reusable context template optimized for the session's focus."""

        # Try to get cached template
        template_key = f"context_template_{hash(str(project_root))}"

        try:
            cache_key = CacheKey(
                cache_type=CacheType.PROJECT_CONTEXT,
                content_hash=self.hasher.hash_content(template_key),
                metadata={"template_type": "reusable_context"},
            )

            cached_template = self.cache_manager.get(cache_key)
            if cached_template:
                # Update usage statistics
                cached_template["usage_frequency"] += 1
                cached_template["last_used"] = time.time()
                cached_template["sessions_using_template"].add(session_id)

                # Customize template for current analysis focus
                customized_template = self._customize_template_for_focus(
                    cached_template, analysis_focus
                )

                logger.info(f"Reused context template for session {session_id[:8]}")
                return customized_template

        except Exception as e:
            logger.warning(f"Failed to retrieve reusable context template: {e}")

        return None

    def _customize_template_for_focus(
        self, template: dict[str, Any], analysis_focus: str
    ) -> dict[str, Any]:
        """Customize a context template for specific analysis focus."""

        customized = template.copy()
        focus_lower = analysis_focus.lower()

        # Select relevant context based on focus
        if "auth" in focus_lower or "login" in focus_lower:
            if "authentication_analysis" in template["common_contexts"]:
                customized["focused_context"] = template["common_contexts"][
                    "authentication_analysis"
                ]
        elif "api" in focus_lower or "endpoint" in focus_lower:
            if "api_security_analysis" in template["common_contexts"]:
                customized["focused_context"] = template["common_contexts"][
                    "api_security_analysis"
                ]
        else:
            customized["focused_context"] = template["common_contexts"].get(
                "general_security", ""
            )

        # Filter core files based on focus
        if "auth" in focus_lower:
            customized["focused_files"] = [
                f
                for f in template["core_files"]
                if any(
                    keyword in f["path"].lower()
                    for keyword in ["auth", "login", "session"]
                )
            ]
        elif "api" in focus_lower:
            customized["focused_files"] = [
                f
                for f in template["core_files"]
                if any(
                    keyword in f["path"].lower()
                    for keyword in ["api", "endpoint", "route", "controller"]
                )
            ]
        else:
            customized["focused_files"] = template["core_files"][
                :10
            ]  # Top 10 for general

        customized["customization_applied"] = True
        customized["focus_area"] = analysis_focus

        return customized

    def cache_reusable_context_template(
        self, project_root: Path, template: dict[str, Any]
    ) -> None:
        """Cache a reusable context template for future sessions."""

        try:
            template_key = f"context_template_{hash(str(project_root))}"

            cache_key = CacheKey(
                cache_type=CacheType.PROJECT_CONTEXT,
                content_hash=self.hasher.hash_content(template_key),
                metadata={"template_type": "reusable_context"},
            )

            # Cache for 24 hours by default
            self.cache_manager.put(cache_key, template, ttl_hours=24)

            logger.info(f"Cached reusable context template for {project_root}")

        except Exception as e:
            logger.warning(f"Failed to cache reusable context template: {e}")

    def get_context_reuse_statistics(self) -> dict[str, Any]:
        """Get statistics about context reuse across sessions."""

        # This would be enhanced with actual tracking data
        return {
            "templates_created": 0,  # Would track actual templates
            "templates_reused": 0,
            "context_reuse_ratio": 0.0,
            "average_template_age": 0,
            "most_reused_patterns": [],
            "session_efficiency_improvement": "0%",
        }


class SessionContextOptimizer:
    """Optimizes context sharing and reuse across multiple sessions."""

    def __init__(self, context_reuse_manager: ContextReuseManager):
        """Initialize with context reuse manager."""
        self.context_reuse_manager = context_reuse_manager
        self.active_sessions: dict[str, dict[str, Any]] = {}
        logger.info("SessionContextOptimizer initialized")

    def register_session(
        self, session_id: str, project_root: Path, analysis_focus: str
    ) -> None:
        """Register a new session for context optimization tracking."""
        self.active_sessions[session_id] = {
            "project_root": project_root,
            "analysis_focus": analysis_focus,
            "start_time": time.time(),
            "context_reused": False,
            "template_used": None,
        }

        logger.debug(f"Registered session {session_id[:8]} for context optimization")

    def optimize_session_context(self, session_id: str) -> dict[str, Any] | None:
        """Optimize context for a session using reusable templates."""
        if session_id not in self.active_sessions:
            logger.warning(f"Session {session_id} not registered for optimization")
            return None

        session_info = self.active_sessions[session_id]

        # Try to get reusable context
        reusable_context = self.context_reuse_manager.get_reusable_context_for_session(
            project_root=session_info["project_root"],
            analysis_focus=session_info["analysis_focus"],
            session_id=session_id,
        )

        if reusable_context:
            session_info["context_reused"] = True
            session_info["template_used"] = reusable_context["template_id"]

            logger.info(
                f"Optimized context for session {session_id[:8]} using template {reusable_context['template_id']}"
            )
            return reusable_context

        logger.debug(f"No reusable context available for session {session_id[:8]}")
        return None

    def track_session_completion(self, session_id: str, findings_count: int) -> None:
        """Track session completion for optimization metrics."""
        if session_id in self.active_sessions:
            session_info = self.active_sessions[session_id]
            session_info["completion_time"] = time.time()
            session_info["findings_count"] = findings_count
            session_info["duration"] = (
                session_info["completion_time"] - session_info["start_time"]
            )

            logger.debug(
                f"Session {session_id[:8]} completed: {findings_count} findings, {session_info['duration']:.2f}s"
            )

    def get_optimization_metrics(self) -> dict[str, Any]:
        """Get context optimization performance metrics."""
        if not self.active_sessions:
            return {"sessions_tracked": 0, "optimization_enabled": True}

        completed_sessions = [
            s for s in self.active_sessions.values() if "completion_time" in s
        ]
        reused_context_sessions = [s for s in completed_sessions if s["context_reused"]]

        metrics = {
            "sessions_tracked": len(self.active_sessions),
            "completed_sessions": len(completed_sessions),
            "context_reuse_rate": (
                len(reused_context_sessions) / len(completed_sessions)
                if completed_sessions
                else 0
            ),
            "optimization_enabled": True,
        }

        if completed_sessions:
            avg_duration = sum(s["duration"] for s in completed_sessions) / len(
                completed_sessions
            )
            metrics["average_session_duration"] = avg_duration

            if reused_context_sessions:
                reused_avg_duration = sum(
                    s["duration"] for s in reused_context_sessions
                ) / len(reused_context_sessions)
                metrics["optimized_session_duration"] = reused_avg_duration
                metrics["performance_improvement"] = (
                    f"{((avg_duration - reused_avg_duration) / avg_duration * 100):.1f}%"
                )

        return metrics
