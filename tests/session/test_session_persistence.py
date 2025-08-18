"""Tests for session persistence and scalability improvements."""

import tempfile
import time
from pathlib import Path

import pytest

from adversary_mcp_server.database.models import AdversaryDatabase
from adversary_mcp_server.session.session_persistence import SessionPersistenceStore
from adversary_mcp_server.session.session_types import AnalysisSession, SessionState


class TestSessionPersistence:
    """Test session persistence functionality."""

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
    def session_store(self, temp_db_path):
        """Create a session persistence store for testing."""
        database = AdversaryDatabase(temp_db_path)
        return SessionPersistenceStore(
            database=database,
            max_active_sessions=5,  # Small limit for testing
            session_timeout_hours=1,
            cleanup_interval_minutes=1,
        )

    @pytest.fixture
    def sample_session(self):
        """Create a sample analysis session."""
        session = AnalysisSession(
            project_root=Path("/test/project"),
            metadata={"test": "data"},
        )
        session.update_state(SessionState.READY)
        return session

    def test_store_and_retrieve_session(self, session_store, sample_session):
        """Test basic session storage and retrieval."""
        # Store session
        assert session_store.store_session(sample_session) is True

        # Retrieve session
        retrieved = session_store.get_session(sample_session.session_id)
        assert retrieved is not None
        assert retrieved.session_id == sample_session.session_id
        assert retrieved.state == SessionState.READY
        assert retrieved.project_root == Path("/test/project")
        assert retrieved.metadata["test"] == "data"

    def test_session_expiration(self, session_store):
        """Test session expiration logic."""
        # Create an expired session
        expired_session = AnalysisSession()
        expired_session.update_state(SessionState.READY)
        # Set last_activity to 2 hours ago AFTER state update
        expired_session.last_activity = time.time() - 7200  # 2 hours ago

        # Store it
        session_store.store_session(expired_session)

        # Try to retrieve - should return None due to expiration
        retrieved = session_store.get_session(expired_session.session_id)
        assert retrieved is None

    def test_memory_limit_enforcement(self, session_store):
        """Test that memory limits are enforced."""
        sessions = []

        # Create more sessions than the limit
        for i in range(7):  # Limit is 5
            session = AnalysisSession(metadata={"index": i})
            session.update_state(SessionState.READY)
            sessions.append(session)
            session_store.store_session(session)

        # Check statistics
        stats = session_store.get_statistics()
        assert stats["active_sessions_memory"] <= stats["max_active_sessions"]

        # All sessions should still be retrievable (some from database)
        for session in sessions:
            retrieved = session_store.get_session(session.session_id)
            assert retrieved is not None

    def test_cleanup_expired_sessions(self, session_store):
        """Test cleanup of expired sessions."""
        # Create mix of active and expired sessions
        active_session = AnalysisSession()
        active_session.update_state(SessionState.READY)

        expired_session = AnalysisSession()
        expired_session.update_state(SessionState.READY)
        # Set last_activity to 2 hours ago AFTER state update
        expired_session.last_activity = time.time() - 7200  # 2 hours ago

        # Store both
        session_store.store_session(active_session)
        session_store.store_session(expired_session)

        # Run cleanup
        cleaned_count = session_store.cleanup_expired_sessions()
        assert cleaned_count >= 1  # At least the expired one

        # Active session should still exist
        assert session_store.get_session(active_session.session_id) is not None

        # Expired session should be gone
        assert session_store.get_session(expired_session.session_id) is None

    def test_session_update_persistence(self, session_store, sample_session):
        """Test that session updates are persisted."""
        # Store initial session
        session_store.store_session(sample_session)

        # Modify session
        sample_session.add_message("user", "test message")
        sample_session.metadata["updated"] = True
        sample_session.update_state(SessionState.ANALYZING)

        # Store updated session
        session_store.store_session(sample_session)

        # Retrieve and verify changes persisted
        retrieved = session_store.get_session(sample_session.session_id)
        assert retrieved.state == SessionState.ANALYZING
        assert len(retrieved.messages) == 1
        assert retrieved.messages[0].content == "test message"
        assert retrieved.metadata["updated"] is True

    def test_list_active_sessions(self, session_store):
        """Test listing active sessions."""
        sessions = []

        # Create multiple sessions
        for i in range(3):
            session = AnalysisSession(metadata={"index": i})
            session.update_state(SessionState.READY)
            sessions.append(session)
            session_store.store_session(session)

        # List active sessions
        active_session_ids = session_store.list_active_sessions()
        assert len(active_session_ids) == 3

        for session in sessions:
            assert session.session_id in active_session_ids

    def test_session_removal(self, session_store, sample_session):
        """Test session removal."""
        # Store session
        session_store.store_session(sample_session)
        assert session_store.get_session(sample_session.session_id) is not None

        # Remove session
        assert session_store.remove_session(sample_session.session_id) is True

        # Verify it's gone
        assert session_store.get_session(sample_session.session_id) is None

        # Removing non-existent session should return False
        assert session_store.remove_session("non-existent") is False

    def test_database_persistence_across_restarts(self, temp_db_path, sample_session):
        """Test that sessions persist across database reconnections."""
        # Create first store and save session
        database1 = AdversaryDatabase(temp_db_path)
        store1 = SessionPersistenceStore(database1, max_active_sessions=5)
        store1.store_session(sample_session)

        # Create second store (simulating restart)
        database2 = AdversaryDatabase(temp_db_path)
        store2 = SessionPersistenceStore(database2, max_active_sessions=5)

        # Session should still be retrievable
        retrieved = store2.get_session(sample_session.session_id)
        assert retrieved is not None
        assert retrieved.session_id == sample_session.session_id
        assert retrieved.state == sample_session.state

    def test_statistics(self, session_store, sample_session):
        """Test session statistics."""
        # Initially empty
        stats = session_store.get_statistics()
        assert stats["active_sessions_memory"] == 0
        assert stats["total_sessions_database"] == 0

        # Add session
        session_store.store_session(sample_session)

        # Check updated statistics
        stats = session_store.get_statistics()
        assert stats["active_sessions_memory"] == 1
        assert stats["total_sessions_database"] == 1
        assert stats["memory_utilization"] > 0
