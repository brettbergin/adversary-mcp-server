"""Tests for automated session cleanup service."""

import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from adversary_mcp_server.database.models import AdversaryDatabase
from adversary_mcp_server.session.session_cleanup import (
    SessionCleanupConfig,
    SessionCleanupMetrics,
    SessionCleanupService,
    create_session_cleanup_service,
)
from adversary_mcp_server.session.session_persistence import SessionPersistenceStore
from adversary_mcp_server.session.session_types import AnalysisSession, SessionState


class TestSessionCleanupMetrics:
    """Test session cleanup metrics collection."""

    def test_metrics_initialization(self):
        """Test metrics are initialized correctly."""
        metrics = SessionCleanupMetrics()
        assert metrics.cleanup_runs == 0
        assert metrics.sessions_cleaned == 0
        assert metrics.cleanup_errors == 0
        assert metrics.last_cleanup_time is None
        assert metrics.average_cleanup_duration == 0.0

    def test_record_cleanup_success(self):
        """Test recording successful cleanup operations."""
        metrics = SessionCleanupMetrics()

        # Record first cleanup
        metrics.record_cleanup(1.5, 3)
        assert metrics.cleanup_runs == 1
        assert metrics.sessions_cleaned == 3
        assert metrics.cleanup_errors == 0
        assert metrics.last_cleanup_duration == 1.5
        assert metrics.average_cleanup_duration == 1.5

        # Record second cleanup
        metrics.record_cleanup(2.0, 2)
        assert metrics.cleanup_runs == 2
        assert metrics.sessions_cleaned == 5
        assert metrics.average_cleanup_duration == 1.75  # (1.5 + 2.0) / 2

    def test_record_cleanup_with_error(self):
        """Test recording cleanup operations with errors."""
        metrics = SessionCleanupMetrics()

        metrics.record_cleanup(1.0, 1, had_error=True)
        assert metrics.cleanup_runs == 1
        assert metrics.cleanup_errors == 1

        stats = metrics.get_stats()
        assert stats["error_rate"] == 1.0

    def test_get_stats(self):
        """Test getting comprehensive statistics."""
        metrics = SessionCleanupMetrics()
        metrics.record_cleanup(1.0, 5)

        stats = metrics.get_stats()
        assert stats["cleanup_runs"] == 1
        assert stats["sessions_cleaned"] == 5
        assert stats["cleanup_errors"] == 0
        assert stats["error_rate"] == 0.0
        assert "last_cleanup_time" in stats
        assert "last_cleanup_duration" in stats


class TestSessionCleanupConfig:
    """Test session cleanup configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SessionCleanupConfig()
        assert config.cleanup_interval_minutes == 15
        assert config.max_session_age_hours == 24
        assert config.orphaned_session_age_hours == 1
        assert config.enable_database_vacuum is True
        assert config.vacuum_interval_hours == 24

    def test_custom_config(self):
        """Test custom configuration values."""
        config = SessionCleanupConfig(
            cleanup_interval_minutes=30,
            max_session_age_hours=12,
            orphaned_session_age_hours=2,
            enable_database_vacuum=False,
        )
        assert config.cleanup_interval_minutes == 30
        assert config.max_session_age_hours == 12
        assert config.orphaned_session_age_hours == 2
        assert config.enable_database_vacuum is False

    def test_time_conversions(self):
        """Test time unit conversions."""
        config = SessionCleanupConfig(
            cleanup_interval_minutes=30,
            max_session_age_hours=12,
            vacuum_interval_hours=48,
        )
        assert config.cleanup_interval_seconds == 1800  # 30 * 60
        assert config.max_session_age_seconds == 43200  # 12 * 3600
        assert config.vacuum_interval_seconds == 172800  # 48 * 3600


class TestSessionCleanupService:
    """Test automated session cleanup service."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)
        yield db_path
        # Cleanup
        if db_path.exists():
            db_path.unlink()

    @pytest.fixture
    def database(self, temp_db_path):
        """Create test database."""
        return AdversaryDatabase(temp_db_path)

    @pytest.fixture
    def session_store(self, database):
        """Create session persistence store."""
        return SessionPersistenceStore(
            database=database,
            max_active_sessions=5,
            session_timeout_hours=1,
            cleanup_interval_minutes=1,
        )

    @pytest.fixture
    def cleanup_config(self):
        """Create test cleanup configuration."""
        return SessionCleanupConfig(
            cleanup_interval_minutes=1,  # Fast cleanup for testing
            max_session_age_hours=1,
            orphaned_session_age_hours=1,
            enable_database_vacuum=True,
            vacuum_interval_hours=1,
        )

    @pytest.fixture
    def cleanup_service(self, session_store, database, cleanup_config):
        """Create cleanup service."""
        return SessionCleanupService(
            session_store=session_store,
            database=database,
            config=cleanup_config,
        )

    def test_service_initialization(self, cleanup_service):
        """Test service initializes correctly."""
        assert not cleanup_service._running
        assert cleanup_service._cleanup_task is None
        assert cleanup_service.metrics.cleanup_runs == 0

    @pytest.mark.asyncio
    async def test_start_stop_service(self, cleanup_service):
        """Test starting and stopping the service."""
        # Start service
        await cleanup_service.start()
        assert cleanup_service._running
        assert cleanup_service._cleanup_task is not None

        # Stop service
        await cleanup_service.stop()
        assert not cleanup_service._running
        assert cleanup_service._cleanup_task is None

    @pytest.mark.asyncio
    async def test_force_cleanup(self, cleanup_service, session_store):
        """Test forcing immediate cleanup."""
        # Create an expired session
        expired_session = AnalysisSession()
        expired_session.update_state(SessionState.READY)
        expired_session.last_activity = time.time() - 7200  # 2 hours ago
        session_store.store_session(expired_session)

        # Force cleanup
        cleanup_stats = await cleanup_service.force_cleanup()

        assert "expired_sessions_cleaned" in cleanup_stats
        assert "duration_seconds" in cleanup_stats
        assert cleanup_stats["expired_sessions_cleaned"] >= 1

    @pytest.mark.asyncio
    async def test_cleanup_orphaned_sessions(self, cleanup_service, database):
        """Test cleanup of orphaned sessions from database."""
        # Create orphaned session directly in database
        with database.get_session() as db_session:
            from adversary_mcp_server.database.models import LLMAnalysisSession

            orphaned_session = LLMAnalysisSession(
                session_id="orphaned-test-session",
                session_data='{"test": "data"}',
                created_at=time.time() - 7200,
                last_activity=time.time() - 7200,  # 2 hours ago
                state="ready",
            )
            db_session.add(orphaned_session)
            db_session.commit()

        # Run cleanup
        orphaned_count = await cleanup_service._cleanup_orphaned_sessions()
        assert orphaned_count >= 1

        # Verify session was removed
        with database.get_session() as db_session:
            from adversary_mcp_server.database.models import LLMAnalysisSession

            remaining = (
                db_session.query(LLMAnalysisSession)
                .filter_by(session_id="orphaned-test-session")
                .first()
            )
            assert remaining is None

    @pytest.mark.asyncio
    async def test_database_vacuum(self, cleanup_service):
        """Test database vacuum operation."""
        # Force last vacuum time to be old
        cleanup_service._last_vacuum_time = time.time() - 86400  # 24 hours ago

        vacuum_performed = await cleanup_service._maybe_vacuum_database()
        assert vacuum_performed is True
        assert cleanup_service._last_vacuum_time > time.time() - 10  # Recent

    @pytest.mark.asyncio
    async def test_vacuum_skip_when_recent(self, cleanup_service):
        """Test vacuum is skipped when recently performed."""
        # Set recent vacuum time (30 minutes ago, less than 1 hour interval)
        cleanup_service._last_vacuum_time = time.time() - 1800  # 30 minutes ago

        vacuum_performed = await cleanup_service._maybe_vacuum_database()
        assert vacuum_performed is False

    def test_get_status(self, cleanup_service):
        """Test getting service status."""
        status = cleanup_service.get_status()

        assert "running" in status
        assert "config" in status
        assert "metrics" in status
        assert "last_vacuum_time" in status
        assert "next_cleanup_eta" in status

        # Check config details
        config = status["config"]
        assert "cleanup_interval_minutes" in config
        assert "max_session_age_hours" in config
        assert "database_vacuum_enabled" in config

    @pytest.mark.asyncio
    async def test_health_callback(self, session_store, database, cleanup_config):
        """Test health monitoring callback."""
        health_data = None

        def health_callback(data):
            nonlocal health_data
            health_data = data

        service = SessionCleanupService(
            session_store=session_store,
            database=database,
            config=cleanup_config,
            health_callback=health_callback,
        )

        # Force cleanup to trigger health callback
        await service.force_cleanup()

        assert health_data is not None
        assert "cleanup_stats" in health_data
        assert "metrics" in health_data
        assert "session_store_stats" in health_data

    @pytest.mark.asyncio
    async def test_cleanup_loop_error_handling(
        self, session_store, database, cleanup_config
    ):
        """Test error handling in cleanup loop."""
        # Mock session store to raise an error
        original_cleanup = session_store.cleanup_expired_sessions
        session_store.cleanup_expired_sessions = MagicMock(
            side_effect=Exception("Test error")
        )

        service = SessionCleanupService(
            session_store=session_store,
            database=database,
            config=cleanup_config,
        )

        # Run cleanup and expect error to be handled
        cleanup_stats = await service._perform_cleanup()

        assert len(cleanup_stats["errors"]) > 0
        assert "Test error" in cleanup_stats["errors"][0]
        assert service.metrics.cleanup_errors > 0

        # Restore original method
        session_store.cleanup_expired_sessions = original_cleanup


class TestFactoryFunction:
    """Test factory function for creating cleanup service."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)
        yield db_path
        # Cleanup
        if db_path.exists():
            db_path.unlink()

    @pytest.fixture
    def database(self, temp_db_path):
        """Create test database."""
        return AdversaryDatabase(temp_db_path)

    def test_create_session_cleanup_service(self, database):
        """Test factory function creates service with defaults."""
        service = create_session_cleanup_service(database)

        assert isinstance(service, SessionCleanupService)
        assert service.config.cleanup_interval_minutes == 15
        assert service.config.max_session_age_hours == 24
        assert service.config.enable_database_vacuum is True

    def test_create_session_cleanup_service_custom(self, database):
        """Test factory function with custom parameters."""
        health_callback = MagicMock()

        service = create_session_cleanup_service(
            database=database,
            cleanup_interval_minutes=30,
            max_session_age_hours=12,
            health_callback=health_callback,
        )

        assert service.config.cleanup_interval_minutes == 30
        assert service.config.max_session_age_hours == 12
        assert service.health_callback is health_callback
