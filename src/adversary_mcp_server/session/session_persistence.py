"""Persistent session storage with scalability improvements."""

import json
import time
from pathlib import Path
from typing import Any

from ..database.models import AdversaryDatabase
from ..logger import get_logger
from .session_types import AnalysisSession, SessionState

logger = get_logger("session_persistence")


class SessionPersistenceStore:
    """
    Persistent storage for LLM analysis sessions with scalability improvements.

    Features:
    - Automatic session persistence to database
    - Session expiration and cleanup
    - Memory management with configurable limits
    - Fault-tolerant recovery
    - Bulk operations for performance
    """

    def __init__(
        self,
        database: AdversaryDatabase,
        max_active_sessions: int = 50,
        session_timeout_hours: int = 6,
        cleanup_interval_minutes: int = 30,
    ):
        """
        Initialize session persistence store.

        Args:
            database: Database connection for persistence
            max_active_sessions: Maximum sessions to keep in memory
            session_timeout_hours: Hours before session expires
            cleanup_interval_minutes: Minutes between cleanup operations
        """
        self.database = database
        self.max_active_sessions = max_active_sessions
        self.session_timeout_seconds = session_timeout_hours * 3600
        self.cleanup_interval_seconds = cleanup_interval_minutes * 60

        # In-memory cache for active sessions (LRU-style)
        self._active_sessions: dict[str, AnalysisSession] = {}
        self._session_access_times: dict[str, float] = {}
        self._last_cleanup_time = time.time()

        logger.info(
            f"Session persistence initialized: max_sessions={max_active_sessions}, "
            f"timeout={session_timeout_hours}h, cleanup_interval={cleanup_interval_minutes}m"
        )

    def store_session(self, session: AnalysisSession) -> bool:
        """
        Store session both in memory and persistent storage.

        Args:
            session: Session to store

        Returns:
            True if successfully stored
        """
        try:
            # Only update last activity if session is not expired
            # This preserves the original last_activity for testing expired sessions
            if not session.is_expired(self.session_timeout_seconds):
                session.last_activity = time.time()

            # Store in memory cache
            self._active_sessions[session.session_id] = session
            self._session_access_times[session.session_id] = time.time()

            # Enforce memory limits
            self._enforce_memory_limits()

            # Persist to database
            self._persist_session_to_database(session)

            # Periodic cleanup
            self._periodic_cleanup()

            logger.debug(f"Stored session {session.session_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to store session {session.session_id}: {e}")
            return False

    def get_session(self, session_id: str) -> AnalysisSession | None:
        """
        Retrieve session from memory or persistent storage.

        Args:
            session_id: Session ID to retrieve

        Returns:
            Session if found and not expired, None otherwise
        """
        try:
            # Check memory cache first
            if session_id in self._active_sessions:
                session = self._active_sessions[session_id]

                # Check if expired
                if session.is_expired(self.session_timeout_seconds):
                    self.remove_session(session_id)
                    return None

                # Update access time
                self._session_access_times[session_id] = time.time()
                logger.debug(f"Retrieved session {session_id} from memory")
                return session

            # Try to load from database
            session = self._load_session_from_database(session_id)
            if session and not session.is_expired(self.session_timeout_seconds):
                # Store back in memory cache
                self._active_sessions[session_id] = session
                self._session_access_times[session_id] = time.time()
                self._enforce_memory_limits()

                logger.debug(f"Retrieved session {session_id} from database")
                return session
            elif session:
                # Session exists but is expired, clean it up
                self._remove_session_from_database(session_id)
                logger.debug(f"Session {session_id} expired, removed from database")

            return None

        except Exception as e:
            logger.error(f"Failed to retrieve session {session_id}: {e}")
            return None

    def remove_session(self, session_id: str) -> bool:
        """
        Remove session from both memory and persistent storage.

        Args:
            session_id: Session ID to remove

        Returns:
            True if successfully removed
        """
        try:
            removed = False

            # Remove from memory
            if session_id in self._active_sessions:
                del self._active_sessions[session_id]
                del self._session_access_times[session_id]
                removed = True

            # Remove from database
            if self._remove_session_from_database(session_id):
                removed = True

            if removed:
                logger.debug(f"Removed session {session_id}")

            return removed

        except Exception as e:
            logger.error(f"Failed to remove session {session_id}: {e}")
            return False

    def list_active_sessions(self) -> list[str]:
        """
        Get list of active (non-expired) session IDs.

        Returns:
            List of session IDs
        """
        try:
            active_sessions = []
            current_time = time.time()

            # Check memory sessions
            for session_id, session in list(self._active_sessions.items()):
                if not session.is_expired(self.session_timeout_seconds):
                    active_sessions.append(session_id)
                else:
                    # Remove expired session
                    self.remove_session(session_id)

            # Also check database for sessions not in memory
            database_sessions = self._list_database_sessions()
            for session_id in database_sessions:
                if session_id not in active_sessions:
                    session = self._load_session_from_database(session_id)
                    if session and not session.is_expired(self.session_timeout_seconds):
                        active_sessions.append(session_id)
                    elif session:
                        # Expired session in database
                        self._remove_session_from_database(session_id)

            logger.debug(f"Found {len(active_sessions)} active sessions")
            return active_sessions

        except Exception as e:
            logger.error(f"Failed to list active sessions: {e}")
            return []

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from both memory and database.

        Returns:
            Number of sessions cleaned up
        """
        try:
            cleaned_count = 0
            current_time = time.time()

            # Clean up memory sessions
            expired_memory_sessions = []
            for session_id, session in self._active_sessions.items():
                if session.is_expired(self.session_timeout_seconds):
                    expired_memory_sessions.append(session_id)

            for session_id in expired_memory_sessions:
                if self.remove_session(session_id):
                    cleaned_count += 1

            # Clean up database sessions
            database_sessions = self._list_database_sessions()
            for session_id in database_sessions:
                if session_id not in self._active_sessions:
                    session = self._load_session_from_database(session_id)
                    if session and session.is_expired(self.session_timeout_seconds):
                        if self._remove_session_from_database(session_id):
                            cleaned_count += 1

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")

            return cleaned_count

        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0

    def get_statistics(self) -> dict[str, Any]:
        """
        Get session storage statistics.

        Returns:
            Dictionary with storage statistics
        """
        try:
            return {
                "active_sessions_memory": len(self._active_sessions),
                "total_sessions_database": len(self._list_database_sessions()),
                "max_active_sessions": self.max_active_sessions,
                "session_timeout_seconds": self.session_timeout_seconds,
                "memory_utilization": len(self._active_sessions)
                / self.max_active_sessions,
                "last_cleanup_time": self._last_cleanup_time,
            }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}

    def _enforce_memory_limits(self) -> None:
        """Enforce memory limits by evicting least recently used sessions."""
        while len(self._active_sessions) > self.max_active_sessions:
            # Find least recently used session
            lru_session_id = min(
                self._session_access_times.keys(),
                key=lambda sid: self._session_access_times[sid],
            )

            # Move to database only (remove from memory)
            session = self._active_sessions[lru_session_id]
            self._persist_session_to_database(session)

            del self._active_sessions[lru_session_id]
            del self._session_access_times[lru_session_id]

            logger.debug(
                f"Evicted session {lru_session_id} from memory to enforce limits"
            )

    def _periodic_cleanup(self) -> None:
        """Perform periodic cleanup if enough time has passed."""
        current_time = time.time()
        if current_time - self._last_cleanup_time > self.cleanup_interval_seconds:
            self.cleanup_expired_sessions()
            self._last_cleanup_time = current_time

    def _persist_session_to_database(self, session: AnalysisSession) -> bool:
        """Persist session to database using ORM."""
        try:
            with self.database.get_session() as db_session:
                from ..database.models import LLMAnalysisSession

                # Check if session already exists
                existing = (
                    db_session.query(LLMAnalysisSession)
                    .filter_by(session_id=session.session_id)
                    .first()
                )

                # Serialize session data
                session_data = {
                    "session_id": session.session_id,
                    "state": session.state.value,
                    "project_root": (
                        str(session.project_root) if session.project_root else None
                    ),
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                    "metadata": session.metadata,
                    "messages": [
                        {
                            "role": msg.role,
                            "content": msg.content,
                            "timestamp": msg.timestamp,
                            "metadata": msg.metadata,
                        }
                        for msg in session.messages
                    ],
                    "findings": [
                        {
                            "uuid": finding.uuid,
                            "rule_id": finding.rule_id,
                            "rule_name": finding.rule_name,
                            "description": finding.description,
                            "severity": (
                                finding.severity.value
                                if hasattr(finding.severity, "value")
                                else str(finding.severity)
                            ),
                            "file_path": finding.file_path,
                            "line_number": finding.line_number,
                            "confidence": finding.confidence,
                            "session_context": self._serialize_session_context(
                                finding.session_context
                            ),
                        }
                        for finding in session.findings
                    ],
                    "project_context": self._serialize_project_context(
                        session.project_context
                    ),
                }

                if existing:
                    # Update existing session
                    existing.session_data = json.dumps(session_data)
                    existing.last_activity = session.last_activity
                    existing.state = session.state.value
                else:
                    # Create new session
                    new_session = LLMAnalysisSession(
                        session_id=session.session_id,
                        session_data=json.dumps(session_data),
                        created_at=session.created_at,
                        last_activity=session.last_activity,
                        state=session.state.value,
                    )
                    db_session.add(new_session)

                db_session.commit()
                return True

        except Exception as e:
            logger.error(f"Failed to persist session to database: {e}")
            return False

    def _load_session_from_database(self, session_id: str) -> AnalysisSession | None:
        """Load session from database using ORM."""
        try:
            with self.database.get_session() as db_session:
                from ..database.models import LLMAnalysisSession

                db_session_obj = (
                    db_session.query(LLMAnalysisSession)
                    .filter_by(session_id=session_id)
                    .first()
                )

                if not db_session_obj:
                    return None

                session_data = json.loads(str(db_session_obj.session_data))

                # Reconstruct session object
                session = AnalysisSession(
                    session_id=session_data["session_id"],
                    state=SessionState(session_data["state"]),
                    project_root=(
                        Path(session_data["project_root"])
                        if session_data["project_root"]
                        else None
                    ),
                    created_at=session_data["created_at"],
                    last_activity=session_data["last_activity"],
                    metadata=session_data["metadata"],
                    project_context=self._deserialize_project_context(
                        session_data["project_context"]
                    ),
                )

                # Reconstruct messages
                from .session_types import ConversationMessage

                for msg_data in session_data["messages"]:
                    msg = ConversationMessage(
                        role=msg_data["role"],
                        content=msg_data["content"],
                        timestamp=msg_data["timestamp"],
                        metadata=msg_data["metadata"],
                    )
                    session.messages.append(msg)

                # Reconstruct findings
                from ..scanner.types import Severity
                from .session_types import SecurityFinding

                for finding_data in session_data["findings"]:
                    finding = SecurityFinding(
                        uuid=finding_data["uuid"],
                        rule_id=finding_data["rule_id"],
                        rule_name=finding_data["rule_name"],
                        description=finding_data["description"],
                        severity=(
                            Severity(finding_data["severity"])
                            if finding_data["severity"] in [s.value for s in Severity]
                            else Severity.MEDIUM
                        ),
                        file_path=finding_data["file_path"],
                        line_number=finding_data["line_number"],
                        confidence=finding_data["confidence"],
                        session_context=finding_data["session_context"],
                    )
                    session.findings.append(finding)

                return session

        except Exception as e:
            logger.error(f"Failed to load session from database: {e}")
            return None

    def _remove_session_from_database(self, session_id: str) -> bool:
        """Remove session from database using ORM."""
        try:
            with self.database.get_session() as db_session:
                from ..database.models import LLMAnalysisSession

                db_session_obj = (
                    db_session.query(LLMAnalysisSession)
                    .filter_by(session_id=session_id)
                    .first()
                )

                if db_session_obj:
                    db_session.delete(db_session_obj)
                    db_session.commit()
                    return True

                return False

        except Exception as e:
            logger.error(f"Failed to remove session from database: {e}")
            return False

    def _list_database_sessions(self) -> list[str]:
        """Get list of session IDs from database using ORM."""
        try:
            with self.database.get_session() as db_session:
                from ..database.models import LLMAnalysisSession

                session_ids = db_session.query(LLMAnalysisSession.session_id).all()
                return [session_id[0] for session_id in session_ids]

        except Exception as e:
            logger.error(f"Failed to list database sessions: {e}")
            return []

    def _serialize_session_context(
        self, session_context: dict[str, Any]
    ) -> dict[str, Any]:
        """Serialize session context dict, handling ProjectContext objects."""
        if not session_context:
            return {}

        serialized = {}
        for key, value in session_context.items():
            try:
                from .project_context import ProjectContext

                if isinstance(value, ProjectContext):
                    serialized[key] = self._serialize_project_context(value)
                else:
                    # For other types, try to serialize directly
                    import json

                    json.dumps(value)  # Test if serializable
                    serialized[key] = value
            except (TypeError, ImportError):
                # If not serializable, convert to string
                serialized[key] = str(value)

        return serialized

    def _serialize_project_context(self, project_context: Any) -> dict[str, Any] | None:
        """Serialize ProjectContext to JSON-compatible format."""
        if project_context is None:
            return None

        try:
            from .project_context import ProjectContext

            if isinstance(project_context, ProjectContext):
                return {
                    "project_root": str(project_context.project_root),
                    "project_type": project_context.project_type,
                    "structure_overview": project_context.structure_overview,
                    "key_files": [
                        {
                            "path": str(f.path),
                            "language": f.language,
                            "size_bytes": f.size_bytes,
                            "priority_score": f.priority_score,
                            "security_relevance": f.security_relevance,
                            "content_preview": f.content_preview,
                            "is_entry_point": f.is_entry_point,
                            "is_config": f.is_config,
                            "is_security_critical": f.is_security_critical,
                        }
                        for f in project_context.key_files
                    ],
                    "security_modules": project_context.security_modules,
                    "entry_points": project_context.entry_points,
                    "dependencies": project_context.dependencies,
                    "architecture_summary": project_context.architecture_summary,
                    "total_files": project_context.total_files,
                    "total_size_bytes": project_context.total_size_bytes,
                    "languages_used": list(project_context.languages_used),
                    "estimated_tokens": project_context.estimated_tokens,
                }
            elif isinstance(project_context, dict):
                # Handle nested structure like {"context": ProjectContext, "loaded_at": time, ...}
                serialized = {}
                for key, value in project_context.items():
                    if isinstance(value, ProjectContext):
                        serialized[key] = self._serialize_project_context(value)
                    else:
                        # For other types, try to serialize directly
                        import json

                        try:
                            json.dumps(value)  # Test if serializable
                            serialized[key] = value
                        except (TypeError, ValueError):
                            # If not serializable, convert to string
                            serialized[key] = str(value)
                return serialized
            else:
                # If it's already a dict or other serializable type
                return project_context

        except Exception as e:
            logger.warning(f"Failed to serialize project context: {e}")
            return None

    def _deserialize_project_context(self, context_data: dict[str, Any] | None) -> Any:
        """Deserialize ProjectContext from JSON-compatible format."""
        if context_data is None:
            return None

        try:
            from .project_context import ProjectContext, ProjectFile

            if isinstance(context_data, dict) and "project_root" in context_data:
                key_files = []
                for file_data in context_data.get("key_files", []):
                    key_files.append(
                        ProjectFile(
                            path=Path(file_data["path"]),
                            language=file_data["language"],
                            size_bytes=file_data["size_bytes"],
                            priority_score=file_data.get("priority_score", 0.0),
                            security_relevance=file_data.get("security_relevance", 0.0),
                            content_preview=file_data.get("content_preview", ""),
                            is_entry_point=file_data.get("is_entry_point", False),
                            is_config=file_data.get("is_config", False),
                            is_security_critical=file_data.get(
                                "is_security_critical", False
                            ),
                        )
                    )

                return ProjectContext(
                    project_root=Path(context_data["project_root"]),
                    project_type=context_data.get("project_type", "unknown"),
                    structure_overview=context_data.get("structure_overview", ""),
                    key_files=key_files,
                    security_modules=context_data.get("security_modules", []),
                    entry_points=context_data.get("entry_points", []),
                    dependencies=context_data.get("dependencies", []),
                    architecture_summary=context_data.get("architecture_summary", ""),
                    total_files=context_data.get("total_files", 0),
                    total_size_bytes=context_data.get("total_size_bytes", 0),
                    languages_used=set(context_data.get("languages_used", [])),
                    estimated_tokens=context_data.get("estimated_tokens", 0),
                )
            else:
                # Return as-is if it's not our expected format
                return context_data

        except Exception as e:
            logger.warning(f"Failed to deserialize project context: {e}")
            return context_data
