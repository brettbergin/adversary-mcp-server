"""Additional tests for session persistence to improve coverage."""

import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.database.models import AdversaryDatabase
from adversary_mcp_server.scanner.types import Severity
from adversary_mcp_server.session.session_persistence import SessionPersistenceStore
from adversary_mcp_server.session.session_types import (
    AnalysisSession,
    ConversationMessage,
    SecurityFinding,
    SessionState,
)


class TestSessionPersistenceCoverage:
    """Additional tests to improve coverage of session persistence."""

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
            max_active_sessions=3,
            session_timeout_hours=1,
            cleanup_interval_minutes=1,
        )

    def test_store_session_exception_handling(self, session_store):
        """Test exception handling in store_session."""
        session = AnalysisSession()
        session.update_state(SessionState.READY)

        # Mock database persistence to raise exception
        with patch.object(
            session_store,
            "_persist_session_to_database",
            side_effect=Exception("DB Error"),
        ):
            result = session_store.store_session(session)
            assert result is False

    def test_get_session_exception_handling(self, session_store):
        """Test exception handling in get_session."""
        # Mock _active_sessions to raise exception
        with patch.object(
            session_store, "_active_sessions", side_effect=Exception("Memory Error")
        ):
            result = session_store.get_session("test_id")
            assert result is None

    def test_remove_session_exception_handling(self, session_store):
        """Test exception handling in remove_session."""
        # Test case where exception occurs during the removal process
        with patch.object(
            session_store, "_active_sessions", side_effect=Exception("Memory Error")
        ):
            result = session_store.remove_session("test_id")
            assert result is False

    def test_list_active_sessions_exception_handling(self, session_store):
        """Test exception handling in list_active_sessions."""
        with patch.object(
            session_store, "_active_sessions", side_effect=Exception("Memory Error")
        ):
            result = session_store.list_active_sessions()
            assert result == []

    def test_cleanup_expired_sessions_exception_handling(self, session_store):
        """Test exception handling in cleanup_expired_sessions."""
        with patch.object(
            session_store, "_active_sessions", side_effect=Exception("Memory Error")
        ):
            result = session_store.cleanup_expired_sessions()
            assert result == 0

    def test_get_statistics_exception_handling(self, session_store):
        """Test exception handling in get_statistics."""
        with patch.object(
            session_store, "_list_database_sessions", side_effect=Exception("DB Error")
        ):
            result = session_store.get_statistics()
            assert result == {}

    def test_list_active_sessions_with_database_cleanup(self, session_store):
        """Test list_active_sessions with database session cleanup."""
        # Create a session that will be expired
        expired_session = AnalysisSession()
        expired_session.update_state(SessionState.READY)
        expired_session.last_activity = time.time() - 7200  # 2 hours ago

        # Store it so it's in database but not active memory
        session_store.store_session(expired_session)
        # Clear from memory to simulate it being only in database
        session_store._active_sessions.clear()
        session_store._session_access_times.clear()

        # Mock database session list to return our expired session
        with patch.object(
            session_store,
            "_list_database_sessions",
            return_value=[expired_session.session_id],
        ):
            # Mock load to return the expired session
            with patch.object(
                session_store,
                "_load_session_from_database",
                return_value=expired_session,
            ):
                active_sessions = session_store.list_active_sessions()
                # Should be empty because session is expired and should be removed
                assert len(active_sessions) == 0

    def test_cleanup_expired_sessions_database_only(self, session_store):
        """Test cleanup of expired sessions that are only in database."""
        # Create expired session
        expired_session = AnalysisSession()
        expired_session.update_state(SessionState.READY)
        expired_session.last_activity = time.time() - 7200  # 2 hours ago

        # Store it then clear from memory
        session_store.store_session(expired_session)
        session_store._active_sessions.clear()
        session_store._session_access_times.clear()

        # Mock database methods
        with patch.object(
            session_store,
            "_list_database_sessions",
            return_value=[expired_session.session_id],
        ):
            with patch.object(
                session_store,
                "_load_session_from_database",
                return_value=expired_session,
            ):
                with patch.object(
                    session_store, "_remove_session_from_database", return_value=True
                ) as mock_remove:
                    cleaned_count = session_store.cleanup_expired_sessions()
                    assert cleaned_count >= 1
                    mock_remove.assert_called_with(expired_session.session_id)

    def test_persist_session_to_database_exception(self, session_store):
        """Test exception handling in _persist_session_to_database."""
        session = AnalysisSession()
        session.update_state(SessionState.READY)

        # Mock database session to raise exception
        with patch.object(
            session_store.database,
            "get_session",
            side_effect=Exception("DB Connection Error"),
        ):
            result = session_store._persist_session_to_database(session)
            assert result is False

    def test_load_session_from_database_exception(self, session_store):
        """Test exception handling in _load_session_from_database."""
        with patch.object(
            session_store.database,
            "get_session",
            side_effect=Exception("DB Connection Error"),
        ):
            result = session_store._load_session_from_database("test_id")
            assert result is None

    def test_load_session_from_database_no_session(self, session_store):
        """Test loading non-existent session from database."""
        # Mock database session that returns None
        mock_db_session = Mock()
        mock_query = Mock()
        mock_query.filter_by.return_value.first.return_value = None
        mock_db_session.query.return_value = mock_query

        with patch.object(
            session_store.database, "get_session", return_value=mock_db_session
        ):
            result = session_store._load_session_from_database("nonexistent")
            assert result is None

    def test_remove_session_from_database_exception(self, session_store):
        """Test exception handling in _remove_session_from_database."""
        with patch.object(
            session_store.database,
            "get_session",
            side_effect=Exception("DB Connection Error"),
        ):
            result = session_store._remove_session_from_database("test_id")
            assert result is False

    def test_remove_session_from_database_no_session(self, session_store):
        """Test removing non-existent session from database."""
        # Mock database session that returns None for the query
        mock_db_session = Mock()
        mock_query = Mock()
        mock_query.filter_by.return_value.first.return_value = None
        mock_db_session.query.return_value = mock_query

        with patch.object(
            session_store.database, "get_session", return_value=mock_db_session
        ):
            result = session_store._remove_session_from_database("nonexistent")
            assert result is False

    def test_list_database_sessions_exception(self, session_store):
        """Test exception handling in _list_database_sessions."""
        with patch.object(
            session_store.database,
            "get_session",
            side_effect=Exception("DB Connection Error"),
        ):
            result = session_store._list_database_sessions()
            assert result == []

    def test_serialize_session_context_with_project_context(self, session_store):
        """Test serialization of session context with ProjectContext."""
        # Mock ProjectContext class
        mock_project_context = Mock()
        mock_project_context.__class__.__name__ = "ProjectContext"

        session_context = {
            "project": mock_project_context,
            "timestamp": time.time(),
            "serializable_data": {"key": "value"},
        }

        with patch.object(
            session_store,
            "_serialize_project_context",
            return_value={"serialized": "context"},
        ):
            result = session_store._serialize_session_context(session_context)

            assert "timestamp" in result
            assert "serializable_data" in result
            assert result["serializable_data"] == {"key": "value"}

    def test_serialize_session_context_non_serializable(self, session_store):
        """Test serialization of session context with non-serializable data."""

        # Create non-serializable object
        class NonSerializable:
            def __init__(self):
                self.data = "test"

        session_context = {"non_serializable": NonSerializable(), "normal_data": "test"}

        result = session_store._serialize_session_context(session_context)

        assert "normal_data" in result
        assert result["normal_data"] == "test"
        # Non-serializable should be converted to string
        assert "non_serializable" in result
        assert isinstance(result["non_serializable"], str)

    def test_serialize_session_context_empty(self, session_store):
        """Test serialization of empty session context."""
        result = session_store._serialize_session_context(None)
        assert result == {}

        result = session_store._serialize_session_context({})
        assert result == {}

    def test_serialize_project_context_with_dict_nested(self, session_store):
        """Test serialization of project context with nested dict structure."""
        # Create a dict with nested ProjectContext (simulated)
        context_dict = {"loaded_at": time.time(), "serializable_data": {"key": "value"}}

        # Test serialization of dict that's not a ProjectContext
        result = session_store._serialize_project_context(context_dict)

        assert "loaded_at" in result
        assert "serializable_data" in result
        assert result["serializable_data"] == {"key": "value"}

    def test_serialize_project_context_serialization_error(self, session_store):
        """Test serialization error handling in _serialize_project_context."""
        # Create a dict that will cause serialization issues
        problematic_data = {"data": object()}  # Non-serializable

        # Mock json.dumps to raise TypeError for non-serializable object
        with patch("json.dumps", side_effect=TypeError("Not serializable")):
            result = session_store._serialize_project_context(problematic_data)
            # Should convert to string representation
            assert isinstance(result["data"], str)

    def test_serialize_project_context_exception(self, session_store):
        """Test exception handling in _serialize_project_context."""
        # Mock to raise general exception
        with patch("adversary_mcp_server.session.session_persistence.logger"):
            # Use a context that will cause an ImportError when checking ProjectContext
            result = session_store._serialize_project_context("invalid_context")
            assert result == "invalid_context"

    def test_deserialize_project_context_none(self, session_store):
        """Test deserialization of None project context."""
        result = session_store._deserialize_project_context(None)
        assert result is None

    def test_deserialize_project_context_exception(self, session_store):
        """Test exception handling in _deserialize_project_context."""
        context_data = {"project_root": "/test"}

        # Mock to raise ImportError when importing ProjectContext
        with patch("adversary_mcp_server.session.session_persistence.logger"):
            # This should trigger the exception handler
            with patch(
                "builtins.__import__", side_effect=ImportError("Module not found")
            ):
                result = session_store._deserialize_project_context(context_data)
                # Should return the original data when deserialization fails
                assert result == context_data

    def test_deserialize_project_context_not_expected_format(self, session_store):
        """Test deserialization of project context that's not in expected format."""
        # Data without project_root key
        context_data = {"some_other_field": "value"}

        result = session_store._deserialize_project_context(context_data)
        # Should return as-is if not in expected format
        assert result == context_data

    def test_periodic_cleanup_triggers(self, session_store):
        """Test that periodic cleanup triggers when interval passes."""
        # Set last cleanup time to be old enough to trigger cleanup
        session_store._last_cleanup_time = time.time() - 3700  # Over an hour ago

        # Create an expired session to clean up
        expired_session = AnalysisSession()
        expired_session.update_state(SessionState.READY)
        expired_session.last_activity = time.time() - 7200  # 2 hours ago
        session_store._active_sessions[expired_session.session_id] = expired_session
        session_store._session_access_times[expired_session.session_id] = (
            time.time() - 7200
        )

        # Call periodic cleanup
        initial_cleanup_time = session_store._last_cleanup_time
        session_store._periodic_cleanup()

        # Cleanup time should be updated
        assert session_store._last_cleanup_time > initial_cleanup_time

    def test_session_with_findings_and_messages_serialization(self, session_store):
        """Test serialization of session with findings and messages."""
        session = AnalysisSession()
        session.update_state(SessionState.READY)

        # Add message
        message = ConversationMessage(
            role="user", content="Test message", metadata={"test": "data"}
        )
        session.messages.append(message)

        # Add finding
        finding = SecurityFinding(
            uuid="test-finding",
            rule_id="test-rule",
            rule_name="Test Rule",
            description="Test finding",
            severity=Severity.HIGH,
            file_path="/test/file.py",
            line_number=10,
            confidence=0.9,
            session_context={"test": "context"},
        )
        session.findings.append(finding)

        # Store and retrieve
        assert session_store.store_session(session) is True
        retrieved = session_store.get_session(session.session_id)

        assert retrieved is not None
        assert len(retrieved.messages) == 1
        assert retrieved.messages[0].content == "Test message"
        assert len(retrieved.findings) == 1
        assert retrieved.findings[0].rule_id == "test-rule"

    def test_get_session_expired_cleanup(self, session_store):
        """Test that expired sessions are cleaned up when retrieved."""
        # Create expired session
        expired_session = AnalysisSession()
        expired_session.update_state(SessionState.READY)
        expired_session.last_activity = time.time() - 7200  # 2 hours ago

        # Add to memory cache directly
        session_store._active_sessions[expired_session.session_id] = expired_session
        session_store._session_access_times[expired_session.session_id] = time.time()

        # Try to get it - should be cleaned up and return None
        result = session_store.get_session(expired_session.session_id)
        assert result is None

        # Should be removed from memory
        assert expired_session.session_id not in session_store._active_sessions

    def test_memory_enforcement_with_lru(self, session_store):
        """Test that LRU eviction works correctly."""
        sessions = []

        # Create sessions up to the limit
        for i in range(session_store.max_active_sessions):
            session = AnalysisSession(metadata={"index": i})
            session.update_state(SessionState.READY)
            sessions.append(session)
            session_store.store_session(session)
            time.sleep(0.01)  # Small delay to ensure different access times

        # Access the first session to make it more recently used
        session_store.get_session(sessions[0].session_id)

        # Add one more session to trigger eviction
        new_session = AnalysisSession(metadata={"index": "new"})
        new_session.update_state(SessionState.READY)
        session_store.store_session(new_session)

        # First session should still be in memory (was accessed recently)
        assert sessions[0].session_id in session_store._active_sessions
        # New session should be in memory
        assert new_session.session_id in session_store._active_sessions
        # Memory should not exceed limit
        assert len(session_store._active_sessions) <= session_store.max_active_sessions
