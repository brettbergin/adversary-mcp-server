"""Automated session cleanup service with scheduling and monitoring."""

import asyncio
import time
from collections.abc import Callable
from typing import Any

from ..database.models import AdversaryDatabase
from ..logger import get_logger
from .session_persistence import SessionPersistenceStore

logger = get_logger("session_cleanup")


class SessionCleanupMetrics:
    """Metrics collection for session cleanup operations."""

    def __init__(self):
        self.cleanup_runs: int = 0
        self.sessions_cleaned: int = 0
        self.cleanup_errors: int = 0
        self.last_cleanup_time: float | None = None
        self.last_cleanup_duration: float | None = None
        self.average_cleanup_duration: float = 0.0
        self.total_cleanup_time: float = 0.0

    def record_cleanup(
        self, duration_seconds: float, sessions_cleaned: int, had_error: bool = False
    ) -> None:
        """Record cleanup operation metrics."""
        self.cleanup_runs += 1
        self.sessions_cleaned += sessions_cleaned
        self.last_cleanup_time = time.time()
        self.last_cleanup_duration = duration_seconds
        self.total_cleanup_time += duration_seconds
        self.average_cleanup_duration = self.total_cleanup_time / self.cleanup_runs

        if had_error:
            self.cleanup_errors += 1

    def get_stats(self) -> dict[str, Any]:
        """Get cleanup statistics."""
        return {
            "cleanup_runs": self.cleanup_runs,
            "sessions_cleaned": self.sessions_cleaned,
            "cleanup_errors": self.cleanup_errors,
            "last_cleanup_time": self.last_cleanup_time,
            "last_cleanup_duration": self.last_cleanup_duration,
            "average_cleanup_duration": self.average_cleanup_duration,
            "error_rate": self.cleanup_errors / max(1, self.cleanup_runs),
        }


class SessionCleanupConfig:
    """Configuration for session cleanup automation."""

    def __init__(
        self,
        cleanup_interval_minutes: int = 15,
        max_session_age_hours: int = 24,
        orphaned_session_age_hours: int = 1,
        max_cleanup_duration_minutes: int = 5,
        enable_database_vacuum: bool = True,
        vacuum_interval_hours: int = 24,
        enable_health_monitoring: bool = True,
    ):
        self.cleanup_interval_minutes = cleanup_interval_minutes
        self.max_session_age_hours = max_session_age_hours
        self.orphaned_session_age_hours = orphaned_session_age_hours
        self.max_cleanup_duration_minutes = max_cleanup_duration_minutes
        self.enable_database_vacuum = enable_database_vacuum
        self.vacuum_interval_hours = vacuum_interval_hours
        self.enable_health_monitoring = enable_health_monitoring

    @property
    def cleanup_interval_seconds(self) -> float:
        """Get cleanup interval in seconds."""
        return self.cleanup_interval_minutes * 60

    @property
    def max_session_age_seconds(self) -> float:
        """Get max session age in seconds."""
        return self.max_session_age_hours * 3600

    @property
    def orphaned_session_age_seconds(self) -> float:
        """Get orphaned session age in seconds."""
        return self.orphaned_session_age_hours * 3600

    @property
    def vacuum_interval_seconds(self) -> float:
        """Get vacuum interval in seconds."""
        return self.vacuum_interval_hours * 3600


class SessionCleanupService:
    """
    Automated session cleanup service with comprehensive management.

    Features:
    - Scheduled cleanup operations
    - Orphaned session detection and removal
    - Database maintenance (VACUUM operations)
    - Health monitoring and metrics
    - Configurable cleanup policies
    - Graceful shutdown support
    """

    def __init__(
        self,
        session_store: SessionPersistenceStore,
        database: AdversaryDatabase,
        config: SessionCleanupConfig | None = None,
        health_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.session_store = session_store
        self.database = database
        self.config = config or SessionCleanupConfig()
        self.health_callback = health_callback

        self.metrics = SessionCleanupMetrics()
        self._cleanup_task: asyncio.Task | None = None
        self._running = False
        self._last_vacuum_time = 0.0

        logger.info(
            f"Session cleanup service initialized: "
            f"interval={self.config.cleanup_interval_minutes}m, "
            f"max_age={self.config.max_session_age_hours}h"
        )

    async def start(self) -> None:
        """Start the automated cleanup service."""
        if self._running:
            logger.warning("Session cleanup service is already running")
            return

        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Session cleanup service started")

    async def stop(self) -> None:
        """Stop the automated cleanup service gracefully."""
        if not self._running:
            return

        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

        logger.info("Session cleanup service stopped")

    async def force_cleanup(self) -> dict[str, Any]:
        """Force an immediate cleanup operation."""
        logger.info("Forcing immediate session cleanup")
        return await self._perform_cleanup()

    async def _cleanup_loop(self) -> None:
        """Main cleanup loop that runs continuously."""
        try:
            while self._running:
                try:
                    await self._perform_cleanup()
                    await asyncio.sleep(self.config.cleanup_interval_seconds)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in cleanup loop: {e}")
                    self.metrics.cleanup_errors += 1
                    # Wait a bit before retrying on error
                    await asyncio.sleep(60)
        except asyncio.CancelledError:
            logger.debug("Cleanup loop cancelled")

    async def _perform_cleanup(self) -> dict[str, Any]:
        """Perform comprehensive session cleanup."""
        start_time = time.time()
        cleanup_stats = {
            "expired_sessions_cleaned": 0,
            "orphaned_sessions_cleaned": 0,
            "database_vacuumed": False,
            "duration_seconds": 0.0,
            "errors": [],
        }

        try:
            # Clean expired sessions from session store
            expired_cleaned = self.session_store.cleanup_expired_sessions()
            cleanup_stats["expired_sessions_cleaned"] = expired_cleaned

            # Clean orphaned sessions from database
            orphaned_cleaned = await self._cleanup_orphaned_sessions()
            cleanup_stats["orphaned_sessions_cleaned"] = orphaned_cleaned

            # Periodic database vacuum
            if self.config.enable_database_vacuum:
                vacuum_performed = await self._maybe_vacuum_database()
                cleanup_stats["database_vacuumed"] = vacuum_performed

            duration = time.time() - start_time
            cleanup_stats["duration_seconds"] = duration

            total_cleaned = expired_cleaned + orphaned_cleaned
            self.metrics.record_cleanup(duration, total_cleaned)

            if total_cleaned > 0 or cleanup_stats["database_vacuumed"]:
                logger.info(
                    f"Cleanup completed: {expired_cleaned} expired, "
                    f"{orphaned_cleaned} orphaned, vacuum: {cleanup_stats['database_vacuumed']}, "
                    f"duration: {duration:.2f}s"
                )

            # Health monitoring callback
            if self.config.enable_health_monitoring and self.health_callback:
                health_data = {
                    "cleanup_stats": cleanup_stats,
                    "metrics": self.metrics.get_stats(),
                    "session_store_stats": self.session_store.get_statistics(),
                }
                self.health_callback(health_data)

        except Exception as e:
            duration = time.time() - start_time
            cleanup_stats["duration_seconds"] = duration
            cleanup_stats["errors"].append(str(e))
            self.metrics.record_cleanup(duration, 0, had_error=True)
            logger.error(f"Cleanup operation failed: {e}")

        return cleanup_stats

    async def _cleanup_orphaned_sessions(self) -> int:
        """Clean up orphaned sessions that are no longer accessible."""
        try:
            with self.database.get_session() as db_session:
                from ..database.models import LLMAnalysisSession

                # Find sessions older than the orphaned threshold
                cutoff_time = time.time() - self.config.orphaned_session_age_seconds

                orphaned_sessions = (
                    db_session.query(LLMAnalysisSession)
                    .filter(LLMAnalysisSession.last_activity < cutoff_time)
                    .all()
                )

                cleaned_count = 0
                for session in orphaned_sessions:
                    try:
                        # Remove from session store first
                        self.session_store.remove_session(str(session.session_id))
                        # Remove from database
                        db_session.delete(session)
                        cleaned_count += 1
                    except Exception as e:
                        logger.warning(
                            f"Failed to clean orphaned session {session.session_id}: {e}"
                        )

                if cleaned_count > 0:
                    db_session.commit()
                    logger.debug(f"Cleaned {cleaned_count} orphaned sessions")

                return cleaned_count

        except Exception as e:
            logger.error(f"Failed to cleanup orphaned sessions: {e}")
            return 0

    async def _maybe_vacuum_database(self) -> bool:
        """Perform database vacuum if enough time has passed."""
        current_time = time.time()
        if current_time - self._last_vacuum_time < self.config.vacuum_interval_seconds:
            return False

        try:
            # Run VACUUM in a separate thread to avoid blocking
            def vacuum_database():
                # Create a direct connection for VACUUM (can't be run in transaction)
                import sqlite3

                conn = sqlite3.connect(str(self.database.db_path))
                try:
                    conn.execute("VACUUM")
                    conn.commit()
                finally:
                    conn.close()

            await asyncio.get_event_loop().run_in_executor(None, vacuum_database)
            self._last_vacuum_time = current_time
            logger.info("Database VACUUM completed")
            return True

        except Exception as e:
            logger.error(f"Database VACUUM failed: {e}")
            return False

    def get_status(self) -> dict[str, Any]:
        """Get comprehensive status of the cleanup service."""
        return {
            "running": self._running,
            "config": {
                "cleanup_interval_minutes": self.config.cleanup_interval_minutes,
                "max_session_age_hours": self.config.max_session_age_hours,
                "orphaned_session_age_hours": self.config.orphaned_session_age_hours,
                "database_vacuum_enabled": self.config.enable_database_vacuum,
                "vacuum_interval_hours": self.config.vacuum_interval_hours,
            },
            "metrics": self.metrics.get_stats(),
            "last_vacuum_time": self._last_vacuum_time,
            "next_cleanup_eta": (
                self.metrics.last_cleanup_time
                + self.config.cleanup_interval_seconds
                - time.time()
                if self.metrics.last_cleanup_time
                else 0
            ),
        }


# Factory function for easy service creation
def create_session_cleanup_service(
    database: AdversaryDatabase,
    cleanup_interval_minutes: int = 15,
    max_session_age_hours: int = 24,
    health_callback: Callable[[dict[str, Any]], None] | None = None,
) -> SessionCleanupService:
    """
    Create a session cleanup service with reasonable defaults.

    Args:
        database: Database connection
        cleanup_interval_minutes: How often to run cleanup (default: 15 minutes)
        max_session_age_hours: Maximum age before session cleanup (default: 24 hours)
        health_callback: Optional callback for health monitoring

    Returns:
        Configured SessionCleanupService
    """
    # Create session store
    session_store = SessionPersistenceStore(
        database=database,
        max_active_sessions=50,
        session_timeout_hours=max_session_age_hours,
        cleanup_interval_minutes=cleanup_interval_minutes,
    )

    # Create cleanup config
    config = SessionCleanupConfig(
        cleanup_interval_minutes=cleanup_interval_minutes,
        max_session_age_hours=max_session_age_hours,
        orphaned_session_age_hours=1,  # Clean orphaned sessions after 1 hour
        enable_database_vacuum=True,
        vacuum_interval_hours=24,  # VACUUM once per day
    )

    return SessionCleanupService(
        session_store=session_store,
        database=database,
        config=config,
        health_callback=health_callback,
    )
