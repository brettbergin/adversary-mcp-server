"""Caching layer for LLM sessions and project contexts."""

import hashlib
import time
from pathlib import Path
from typing import Any

from ..cache import CacheKey, CacheManager, CacheType
from ..logger import get_logger
from .project_context import ProjectContext

logger = get_logger("session_cache")


class SessionCache:
    """
    Intelligent caching for LLM sessions and project contexts.

    This cache enables reuse of:
    - Project context analysis
    - Session conversation history
    - Analysis results
    - Token usage optimization
    - Session-aware analysis results
    """

    def __init__(self, cache_manager: CacheManager):
        """Initialize with cache manager."""
        self.cache_manager = cache_manager
        self.hasher = cache_manager.get_hasher()
        self._context_cache_hits = 0
        self._context_cache_misses = 0
        self._analysis_cache_hits = 0
        self._analysis_cache_misses = 0

    def cache_project_context(
        self,
        project_root: Path,
        context: ProjectContext,
        cache_duration_hours: int = 24,
    ) -> None:
        """Cache project context for reuse."""
        try:
            # Create cache key based on project characteristics
            project_signature = self._create_project_signature(project_root)

            cache_key = CacheKey(
                cache_type=CacheType.PROJECT_CONTEXT,
                content_hash=project_signature,
                metadata_hash=self.hasher.hash_content(str(context.estimated_tokens)),
            )

            # Serialize context for caching
            context_data = {
                "project_root": str(context.project_root),
                "project_type": context.project_type,
                "structure_overview": context.structure_overview,
                "key_files": [
                    self._serialize_project_file(f) for f in context.key_files
                ],
                "security_modules": context.security_modules,
                "entry_points": context.entry_points,
                "dependencies": context.dependencies,
                "architecture_summary": context.architecture_summary,
                "total_files": context.total_files,
                "total_size_bytes": context.total_size_bytes,
                "languages_used": list(context.languages_used),
                "estimated_tokens": context.estimated_tokens,
                "cached_at": time.time(),
            }

            # Cache for specified duration
            cache_expiry = cache_duration_hours * 3600
            self.cache_manager.put(cache_key, context_data, cache_expiry)

            logger.info(
                f"Cached project context for {project_root} (valid for {cache_duration_hours}h)"
            )

        except Exception as e:
            logger.warning(f"Failed to cache project context: {e}")

    def get_cached_project_context(
        self,
        project_root: Path,
        max_age_hours: int = 24,
    ) -> ProjectContext | None:
        """Retrieve cached project context if valid."""
        try:
            project_signature = self._create_project_signature(project_root)

            # Search for any cached context with matching content hash
            # We can't know the exact metadata hash without the context, so we search by prefix
            cache_prefix = f"{CacheType.PROJECT_CONTEXT.value}:{project_signature}"

            # Find all cache entries that match this project
            for cache_key_str, entry in self.cache_manager._cache.items():
                if cache_key_str.startswith(cache_prefix):
                    cached_data = entry.data

                    # Check cache age
                    cached_at = cached_data.get("cached_at", 0)
                    age_hours = (time.time() - cached_at) / 3600

                    if age_hours <= max_age_hours:
                        # Valid cache entry found
                        return self._deserialize_project_context(cached_data)

            logger.debug(f"No cached context found for {project_root}")
            return None

        except Exception as e:
            logger.warning(f"Failed to retrieve cached project context: {e}")
            return None

    def cache_session_analysis(
        self,
        session_id: str,
        analysis_query: str,
        findings: list[dict[str, Any]],
        cache_duration_hours: int = 6,
    ) -> None:
        """Cache analysis results for a session."""
        try:
            # Create cache key for this specific analysis
            query_hash = self.hasher.hash_content(analysis_query)

            cache_key = CacheKey(
                cache_type=CacheType.ANALYSIS_RESULT,
                content_hash=session_id,
                metadata_hash=query_hash,
            )

            cache_data = {
                "session_id": session_id,
                "analysis_query": analysis_query,
                "findings": findings,
                "cached_at": time.time(),
                "findings_count": len(findings),
            }

            cache_expiry = cache_duration_hours * 3600
            self.cache_manager.put(cache_key, cache_data, cache_expiry)

            logger.debug(f"Cached analysis results for session {session_id[:8]}")

        except Exception as e:
            logger.warning(f"Failed to cache analysis results: {e}")

    def get_cached_session_analysis(
        self,
        session_id: str,
        analysis_query: str,
        max_age_hours: int = 6,
    ) -> list[dict[str, Any]] | None:
        """Get cached analysis results."""
        try:
            query_hash = self.hasher.hash_content(analysis_query)

            cache_key = CacheKey(
                cache_type=CacheType.ANALYSIS_RESULT,
                content_hash=session_id,
                metadata_hash=query_hash,
            )

            cached_data = self.cache_manager.get(cache_key)

            if not cached_data:
                return None

            # Check age
            cached_at = cached_data.get("cached_at", 0)
            age_hours = (time.time() - cached_at) / 3600

            if age_hours > max_age_hours:
                return None

            findings = cached_data.get("findings", [])
            logger.debug(f"Using cached analysis results ({len(findings)} findings)")

            return findings

        except Exception as e:
            logger.warning(f"Failed to retrieve cached analysis: {e}")
            return None

    def invalidate_project_cache(self, project_root: Path) -> None:
        """Invalidate cached data for a project."""
        try:
            project_signature = self._create_project_signature(project_root)

            # This would require cache manager enhancement to support pattern deletion
            # For now, we'll just log the invalidation
            logger.info(f"Invalidating cache for project {project_root}")

        except Exception as e:
            logger.warning(f"Failed to invalidate project cache: {e}")

    def _create_project_signature(self, project_root: Path) -> str:
        """Create a signature for project caching."""
        # Include project path, modification times of key files, and structure
        signature_parts = [str(project_root)]

        try:
            # Add project structure indicators
            key_files = [
                "package.json",
                "pyproject.toml",
                "requirements.txt",
                "Cargo.toml",
                "pom.xml",
                "build.gradle",
                ".git/config",
            ]

            for key_file in key_files:
                file_path = project_root / key_file
                if file_path.exists():
                    # Include file modification time in signature
                    mtime = file_path.stat().st_mtime
                    signature_parts.append(f"{key_file}:{mtime}")

            # Add directory structure hash (top-level directories)
            dirs = sorted(
                [
                    d.name
                    for d in project_root.iterdir()
                    if d.is_dir() and not d.name.startswith(".")
                ]
            )
            signature_parts.append(f"dirs:{','.join(dirs)}")

        except Exception as e:
            logger.debug(f"Error creating project signature: {e}")
            # Fall back to just the path
            pass

        # Hash the signature
        signature_str = "|".join(signature_parts)
        return hashlib.sha256(signature_str.encode()).hexdigest()[:16]

    def _serialize_project_file(self, project_file) -> dict[str, Any]:
        """Serialize ProjectFile for caching."""
        return {
            "path": str(project_file.path),
            "language": project_file.language,
            "size_bytes": project_file.size_bytes,
            "priority_score": project_file.priority_score,
            "security_relevance": project_file.security_relevance,
            "content_preview": project_file.content_preview,
            "is_entry_point": project_file.is_entry_point,
            "is_config": project_file.is_config,
            "is_security_critical": project_file.is_security_critical,
        }

    def _deserialize_project_context(
        self, cached_data: dict[str, Any]
    ) -> ProjectContext:
        """Deserialize cached data back to ProjectContext."""
        from .project_context import ProjectContext, ProjectFile

        # Reconstruct key files
        key_files = []
        for file_data in cached_data.get("key_files", []):
            project_file = ProjectFile(
                path=Path(file_data["path"]),
                language=file_data["language"],
                size_bytes=file_data["size_bytes"],
                priority_score=file_data["priority_score"],
                security_relevance=file_data["security_relevance"],
                content_preview=file_data["content_preview"],
                is_entry_point=file_data["is_entry_point"],
                is_config=file_data["is_config"],
                is_security_critical=file_data["is_security_critical"],
            )
            key_files.append(project_file)

        # Reconstruct ProjectContext
        context = ProjectContext(
            project_root=Path(cached_data["project_root"]),
            project_type=cached_data["project_type"],
            structure_overview=cached_data["structure_overview"],
            key_files=key_files,
            security_modules=cached_data["security_modules"],
            entry_points=cached_data["entry_points"],
            dependencies=cached_data["dependencies"],
            architecture_summary=cached_data["architecture_summary"],
            total_files=cached_data["total_files"],
            total_size_bytes=cached_data["total_size_bytes"],
            languages_used=set(cached_data["languages_used"]),
            estimated_tokens=cached_data["estimated_tokens"],
        )

        return context

    def cache_analysis_result(
        self,
        analysis_query: str,
        project_context: ProjectContext,
        analysis_result: list[Any],
        cache_duration_hours: int = 12,
    ) -> None:
        """Cache session-aware analysis results for reuse."""
        try:
            # Create cache key based on query and project context
            query_hash = self.hasher.hash_content(analysis_query)
            context_hash = self.hasher.hash_content(
                f"{project_context.project_root}:{project_context.estimated_tokens}"
            )

            cache_key = CacheKey(
                cache_type=CacheType.LLM_RESPONSE,
                content_hash=query_hash,
                metadata_hash=context_hash,
            )

            # Serialize analysis result
            cache_data = {
                "analysis_result": analysis_result,
                "query": analysis_query,
                "project_root": str(project_context.project_root),
                "cached_at": time.time(),
            }

            # Cache for specified duration
            cache_expiry_seconds = cache_duration_hours * 3600
            self.cache_manager.put(cache_key, cache_data, cache_expiry_seconds)

            logger.debug(
                f"Cached session analysis result for query: {analysis_query[:50]}..."
            )

        except Exception as e:
            logger.warning(f"Failed to cache analysis result: {e}")

    def get_cached_analysis_result(
        self,
        analysis_query: str,
        project_context: ProjectContext,
        max_age_hours: int = 12,
    ) -> list[Any] | None:
        """Retrieve cached analysis result if available and fresh."""
        try:
            # Create same cache key as used for caching
            query_hash = self.hasher.hash_content(analysis_query)
            context_hash = self.hasher.hash_content(
                f"{project_context.project_root}:{project_context.estimated_tokens}"
            )

            cache_key = CacheKey(
                cache_type=CacheType.LLM_RESPONSE,
                content_hash=query_hash,
                metadata_hash=context_hash,
            )

            cached_data = self.cache_manager.get(cache_key)
            if cached_data:
                # Check if cache is still fresh
                cached_at = cached_data.get("cached_at", 0)
                max_age_seconds = max_age_hours * 3600

                if (time.time() - cached_at) < max_age_seconds:
                    self._analysis_cache_hits += 1
                    logger.debug(
                        f"Analysis cache hit for query: {analysis_query[:50]}..."
                    )
                    return cached_data["analysis_result"]
                else:
                    logger.debug("Analysis cache entry expired")

            self._analysis_cache_misses += 1
            return None

        except Exception as e:
            logger.warning(f"Failed to retrieve cached analysis result: {e}")
            self._analysis_cache_misses += 1
            return None

    def warm_project_cache(self, project_root: Path) -> bool:
        """Pre-warm cache with project context to improve performance."""
        try:
            logger.info(f"Warming cache for project: {project_root}")

            # Check if already cached
            if self.get_cached_project_context(project_root):
                logger.debug("Project context already cached")
                return True

            # Build project context in background
            from .project_context import ProjectContextBuilder

            builder = ProjectContextBuilder()
            context = builder.build_context(project_root)

            # Cache the context
            self.cache_project_context(project_root, context)

            logger.info(f"Successfully warmed cache for project: {project_root}")
            return True

        except Exception as e:
            logger.warning(f"Failed to warm project cache: {e}")
            return False

    def get_cache_statistics(self) -> dict[str, Any]:
        """Get cache performance statistics."""
        total_context_requests = self._context_cache_hits + self._context_cache_misses
        total_analysis_requests = (
            self._analysis_cache_hits + self._analysis_cache_misses
        )

        context_hit_rate = (
            self._context_cache_hits / total_context_requests
            if total_context_requests > 0
            else 0
        )

        analysis_hit_rate = (
            self._analysis_cache_hits / total_analysis_requests
            if total_analysis_requests > 0
            else 0
        )

        return {
            "context_cache": {
                "hits": self._context_cache_hits,
                "misses": self._context_cache_misses,
                "hit_rate": context_hit_rate,
            },
            "analysis_cache": {
                "hits": self._analysis_cache_hits,
                "misses": self._analysis_cache_misses,
                "hit_rate": analysis_hit_rate,
            },
            "cache_manager_stats": getattr(
                self.cache_manager, "get_stats", lambda: {}
            )(),
        }

    def optimize_cache_usage(self) -> None:
        """Optimize cache usage based on access patterns."""
        try:
            stats = self.get_cache_statistics()

            # Log cache performance
            logger.info(
                f"Cache performance - Context hit rate: {stats['context_cache']['hit_rate']:.2%}, "
                f"Analysis hit rate: {stats['analysis_cache']['hit_rate']:.2%}"
            )

            # Implement cache optimization strategies based on hit rates
            if stats["context_cache"]["hit_rate"] < 0.3:
                logger.info(
                    "Low context cache hit rate - consider pre-warming frequently used projects"
                )

            if stats["analysis_cache"]["hit_rate"] < 0.2:
                logger.info(
                    "Low analysis cache hit rate - consider adjusting cache duration or query patterns"
                )

        except Exception as e:
            logger.warning(f"Failed to optimize cache usage: {e}")


class TokenUsageOptimizer:
    """Optimizes token usage across sessions."""

    def __init__(self):
        """Initialize optimizer."""
        self.token_usage_history: dict[str, list[dict[str, Any]]] = {}

    def record_token_usage(
        self,
        session_id: str,
        operation: str,
        tokens_used: int,
        tokens_available: int,
    ) -> None:
        """Record token usage for optimization."""
        if session_id not in self.token_usage_history:
            self.token_usage_history[session_id] = []

        usage_record = {
            "operation": operation,
            "tokens_used": tokens_used,
            "tokens_available": tokens_available,
            "utilization": (
                tokens_used / tokens_available if tokens_available > 0 else 0
            ),
            "timestamp": time.time(),
        }

        self.token_usage_history[session_id].append(usage_record)

        # Keep only recent history
        cutoff_time = time.time() - (24 * 3600)  # 24 hours
        self.token_usage_history[session_id] = [
            record
            for record in self.token_usage_history[session_id]
            if record["timestamp"] > cutoff_time
        ]

    def get_optimal_context_size(self, session_id: str) -> int:
        """Get optimal context size based on usage history."""
        if session_id not in self.token_usage_history:
            return 50000  # Default

        history = self.token_usage_history[session_id]
        if not history:
            return 50000

        # Calculate average utilization
        avg_utilization = sum(r["utilization"] for r in history) / len(history)

        # Adjust context size based on utilization
        if avg_utilization > 0.9:
            return 75000  # Increase for high utilization
        elif avg_utilization < 0.5:
            return 30000  # Decrease for low utilization
        else:
            return 50000  # Keep default

    def should_use_sliding_window(self, session_id: str) -> bool:
        """Determine if sliding window should be used."""
        optimal_size = self.get_optimal_context_size(session_id)
        return optimal_size > 60000  # Use sliding window for large contexts

    def create_sliding_window(
        self,
        conversation_history: list[dict[str, Any]],
        max_tokens: int,
        window_overlap: float = 0.2,
    ) -> list[dict[str, Any]]:
        """
        Create a sliding window of conversation history to fit token budget.

        Args:
            conversation_history: Full conversation history
            max_tokens: Maximum tokens for the window
            window_overlap: Overlap ratio between windows (0.0-0.5)

        Returns:
            Windowed conversation history that fits in token budget
        """
        if not conversation_history:
            return []

        # Estimate tokens for each message
        messages_with_tokens = []
        for msg in conversation_history:
            content = str(msg.get("content", ""))
            estimated_tokens = len(content) // 4  # Rough estimate: 1 token per 4 chars
            messages_with_tokens.append({**msg, "estimated_tokens": estimated_tokens})

        # Always keep the latest system message and most recent messages
        windowed_messages = []
        total_tokens = 0

        # Start from the most recent messages and work backwards
        for msg in reversed(messages_with_tokens):
            msg_tokens = msg["estimated_tokens"]

            # Always include system messages and recent critical messages
            if (
                msg.get("role") == "system"
                or total_tokens + msg_tokens <= max_tokens * 0.8
            ):  # Reserve 20% buffer
                windowed_messages.insert(0, msg)
                total_tokens += msg_tokens
            else:
                break

        # Ensure we have at least the system context and last few exchanges
        if len(windowed_messages) < 3 and len(messages_with_tokens) >= 3:
            # Emergency fallback: keep last 3 messages regardless of size
            windowed_messages = messages_with_tokens[-3:]

        return windowed_messages

    def optimize_context_for_sliding_window(
        self, project_context: "ProjectContext", current_focus: str, max_tokens: int
    ) -> dict[str, Any]:
        """
        Optimize project context for sliding window usage.

        Args:
            project_context: Full project context
            current_focus: Current analysis focus (file path or module)
            max_tokens: Token budget for context

        Returns:
            Optimized context dictionary
        """

        optimized_context = {
            "project_root": str(project_context.project_root),
            "project_type": project_context.project_type,
            "architecture_summary": project_context.architecture_summary,
            "total_files": project_context.total_files,
            "languages_used": list(project_context.languages_used),
        }

        # Prioritize files based on current focus
        relevant_files = []
        focus_path = Path(current_focus) if current_focus else None

        # Calculate relevance scores for files
        for file in project_context.key_files:
            relevance_score = file.priority_score

            # Boost relevance for files related to current focus
            if focus_path:
                if file.path == focus_path:
                    relevance_score += 0.5  # Current file gets highest priority
                elif str(focus_path.parent) in str(file.path):
                    relevance_score += 0.3  # Same directory
                elif focus_path.suffix == file.path.suffix:
                    relevance_score += 0.1  # Same file type

            # Boost security-critical files
            if file.is_security_critical:
                relevance_score += 0.2

            relevant_files.append((file, relevance_score))

        # Sort by relevance and fit within token budget
        relevant_files.sort(key=lambda x: x[1], reverse=True)

        selected_files = []
        used_tokens = len(str(optimized_context)) // 4  # Base context tokens

        for file, relevance in relevant_files:
            file_tokens = len(file.content_preview) // 4
            if used_tokens + file_tokens <= max_tokens * 0.9:  # Leave 10% buffer
                selected_files.append(
                    {
                        "path": str(file.path),
                        "language": file.language,
                        "security_relevance": file.security_relevance,
                        "content_preview": file.content_preview,
                        "is_security_critical": file.is_security_critical,
                        "relevance_score": relevance,
                    }
                )
                used_tokens += file_tokens
            else:
                # Truncate content if file is highly relevant
                if relevance > 0.8:
                    available_tokens = max_tokens - used_tokens - 100  # Small buffer
                    truncated_content = file.content_preview[: available_tokens * 4]
                    selected_files.append(
                        {
                            "path": str(file.path),
                            "language": file.language,
                            "security_relevance": file.security_relevance,
                            "content_preview": truncated_content + "... [truncated]",
                            "is_security_critical": file.is_security_critical,
                            "relevance_score": relevance,
                            "truncated": True,
                        }
                    )
                break

        optimized_context["key_files"] = selected_files
        optimized_context["estimated_tokens"] = used_tokens
        optimized_context["optimization_applied"] = True
        optimized_context["focus_context"] = current_focus

        return optimized_context

    def get_incremental_analysis_metadata(self, session_id: str) -> dict[str, Any]:
        """Get metadata for incremental analysis tracking."""
        if session_id not in self.token_usage_history:
            return {
                "last_analysis_timestamp": None,
                "analyzed_files": set(),
                "analyzed_commit_hash": None,
                "baseline_established": False,
            }

        # Extract incremental analysis data from history
        history = self.token_usage_history[session_id]
        incremental_ops = [
            r for r in history if r["operation"].startswith("incremental_")
        ]

        if not incremental_ops:
            return {
                "last_analysis_timestamp": None,
                "analyzed_files": set(),
                "analyzed_commit_hash": None,
                "baseline_established": False,
            }

        latest_op = max(incremental_ops, key=lambda x: x["timestamp"])
        return latest_op.get(
            "metadata",
            {
                "last_analysis_timestamp": latest_op["timestamp"],
                "analyzed_files": set(),
                "analyzed_commit_hash": None,
                "baseline_established": True,
            },
        )

    def record_incremental_analysis(
        self,
        session_id: str,
        operation_type: str,
        analyzed_files: list[str],
        commit_hash: str | None = None,
        findings_count: int = 0,
        tokens_used: int = 0,
    ) -> None:
        """Record incremental analysis operation for tracking."""
        if session_id not in self.token_usage_history:
            self.token_usage_history[session_id] = []

        metadata = {
            "last_analysis_timestamp": time.time(),
            "analyzed_files": set(analyzed_files),
            "analyzed_commit_hash": commit_hash,
            "baseline_established": True,
            "findings_count": findings_count,
            "file_count": len(analyzed_files),
        }

        usage_record = {
            "operation": f"incremental_{operation_type}",
            "tokens_used": tokens_used,
            "tokens_available": self.get_optimal_context_size(session_id),
            "utilization": (
                tokens_used / self.get_optimal_context_size(session_id)
                if self.get_optimal_context_size(session_id) > 0
                else 0
            ),
            "timestamp": time.time(),
            "metadata": metadata,
        }

        self.token_usage_history[session_id].append(usage_record)

        # Keep only recent history
        cutoff_time = time.time() - (24 * 3600)  # 24 hours
        self.token_usage_history[session_id] = [
            record
            for record in self.token_usage_history[session_id]
            if record["timestamp"] > cutoff_time
        ]
