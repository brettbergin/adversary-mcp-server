"""Tests for hot-reload functionality."""

import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import yaml

from adversary_mcp_server.hot_reload import (
    HotReloadService,
    RuleFileHandler,
    create_hot_reload_service,
)
from adversary_mcp_server.threat_engine import ThreatEngine


class TestRuleFileHandler:
    """Test the file system event handler."""

    def test_on_modified_yaml_file(self):
        """Test handling of YAML file modification events."""
        mock_service = Mock()
        handler = RuleFileHandler(mock_service)

        # Mock file modification event
        mock_event = Mock()
        mock_event.is_directory = False
        mock_event.src_path = "/path/to/rules.yaml"

        handler.on_modified(mock_event)

        # Should queue reload for YAML files
        mock_service.queue_reload.assert_called_once()
        call_args = mock_service.queue_reload.call_args[0]
        assert call_args[0] == Path("/path/to/rules.yaml")

    def test_on_modified_non_yaml_file(self):
        """Test handling of non-YAML file modification events."""
        mock_service = Mock()
        handler = RuleFileHandler(mock_service)

        # Mock file modification event for non-YAML file
        mock_event = Mock()
        mock_event.is_directory = False
        mock_event.src_path = "/path/to/script.py"

        handler.on_modified(mock_event)

        # Should not queue reload for non-YAML files
        mock_service.queue_reload.assert_not_called()

    def test_on_modified_directory(self):
        """Test handling of directory modification events."""
        mock_service = Mock()
        handler = RuleFileHandler(mock_service)

        # Mock directory modification event
        mock_event = Mock()
        mock_event.is_directory = True
        mock_event.src_path = "/path/to/directory"

        handler.on_modified(mock_event)

        # Should not queue reload for directories
        mock_service.queue_reload.assert_not_called()

    def test_on_created_yaml_file(self):
        """Test handling of YAML file creation events."""
        mock_service = Mock()
        handler = RuleFileHandler(mock_service)

        # Mock file creation event
        mock_event = Mock()
        mock_event.is_directory = False
        mock_event.src_path = "/path/to/new_rules.yml"

        handler.on_created(mock_event)

        # Should queue reload for new YAML files
        mock_service.queue_reload.assert_called_once()
        call_args = mock_service.queue_reload.call_args[0]
        assert call_args[0] == Path("/path/to/new_rules.yml")

    def test_on_deleted_yaml_file(self):
        """Test handling of YAML file deletion events."""
        mock_service = Mock()
        handler = RuleFileHandler(mock_service)

        # Mock file deletion event
        mock_event = Mock()
        mock_event.is_directory = False
        mock_event.src_path = "/path/to/deleted_rules.yaml"

        handler.on_deleted(mock_event)

        # Should queue reload when YAML files are deleted
        mock_service.queue_reload.assert_called_once()
        call_args = mock_service.queue_reload.call_args[0]
        assert call_args[0] == Path("/path/to/deleted_rules.yaml")


class TestHotReloadService:
    """Test the hot-reload service."""

    def test_init_with_custom_directories(self):
        """Test initialization with custom watch directories."""
        mock_engine = Mock()
        custom_dirs = [Path("/custom/dir1"), Path("/custom/dir2")]

        service = HotReloadService(mock_engine, custom_dirs)

        assert service.threat_engine == mock_engine
        assert (
            len(service.watch_directories) >= 2
        )  # Custom dirs + auto-detected builtin dir
        assert Path("/custom/dir1") in service.watch_directories
        assert Path("/custom/dir2") in service.watch_directories

    def test_init_auto_detect_builtin_dir(self):
        """Test auto-detection of built-in rules directory."""
        mock_engine = Mock()

        # Since the real builtin rules directory exists in this project,
        # just test that some directories are detected
        service = HotReloadService(mock_engine)

        # Should have auto-detected builtin directory (the rules/ directory exists)
        assert len(service.watch_directories) > 0

        # Verify that at least one directory path contains "rules"
        rule_dirs = [str(d) for d in service.watch_directories if "rules" in str(d)]
        assert len(rule_dirs) > 0

    def test_add_watch_directory(self):
        """Test adding a watch directory."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Create temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            new_dir = Path(tmp_dir)

            # Add watch directory
            service.add_watch_directory(new_dir)

            # Should be added to watch list
            assert new_dir in service.watch_directories

    def test_add_watch_directory_already_running(self):
        """Test adding a watch directory when service is already running."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Mock the observer
        mock_observer = Mock()
        service.observer = mock_observer
        service.is_running = True

        # Create temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            new_dir = Path(tmp_dir)

            # Add watch directory
            service.add_watch_directory(new_dir)

            # Should schedule the new directory
            mock_observer.schedule.assert_called_once()

    def test_remove_watch_directory(self):
        """Test removing a watch directory."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Create temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            watch_dir = Path(tmp_dir)
            service.watch_directories.append(watch_dir)

            # Remove watch directory
            service.remove_watch_directory(watch_dir)

            # Should be removed from watch list
            assert watch_dir not in service.watch_directories

    def test_start_service(self):
        """Test starting the hot-reload service."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Mock the observer
        mock_observer = Mock()
        service.observer = mock_observer

        # Add a temporary directory to watch
        with tempfile.TemporaryDirectory() as tmp_dir:
            watch_dir = Path(tmp_dir)
            service.watch_directories.append(watch_dir)

            # Start service
            service.start()

            # Should start observer and schedule directories
            mock_observer.start.assert_called_once()
            mock_observer.schedule.assert_called()
            assert service.is_running is True

    def test_stop_service(self):
        """Test stopping the hot-reload service."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Mock the observer
        mock_observer = Mock()
        service.observer = mock_observer
        service.is_running = True

        # Stop service
        service.stop()

        # Should stop observer
        mock_observer.stop.assert_called_once()
        mock_observer.join.assert_called_once()
        assert service.is_running is False

    def test_queue_reload(self):
        """Test queuing a file for reload."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Mock the reload method
        service._maybe_perform_reload = Mock()

        file_path = Path("/path/to/rules.yaml")
        service.queue_reload(file_path)

        # Should add file to pending reloads
        assert file_path in service.pending_reloads
        service._maybe_perform_reload.assert_called_once()

    def test_maybe_perform_reload_debounce(self):
        """Test debouncing of reload operations."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)
        service.reload_debounce_seconds = 0.1

        # Mock the perform reload method with side effect to update last_reload_time
        def mock_perform_reload():
            service.last_reload_time = time.time()
            service.pending_reloads.clear()

        service._perform_reload = Mock(side_effect=mock_perform_reload)

        # Add pending reload
        service.pending_reloads.add(Path("/path/to/rules.yaml"))

        # First call should trigger reload (no previous reload)
        service._maybe_perform_reload()
        service._perform_reload.assert_called_once()

        # Reset mock
        service._perform_reload.reset_mock()

        # Immediate second call should not trigger reload (debounce)
        service.pending_reloads.add(Path("/path/to/rules2.yaml"))
        service._maybe_perform_reload()
        service._perform_reload.assert_not_called()

    def test_perform_reload_success(self):
        """Test successful reload operation."""
        mock_engine = Mock()
        mock_engine.get_rule_statistics.return_value = {"total_rules": 5}
        service = HotReloadService(mock_engine)

        # Add pending reloads
        file1 = Path("/path/to/rules1.yaml")
        file2 = Path("/path/to/rules2.yaml")
        service.pending_reloads.add(file1)
        service.pending_reloads.add(file2)

        # Perform reload
        service._perform_reload()

        # Should reload engine and update statistics
        mock_engine.reload_rules.assert_called_once()
        assert service.reload_count == 1
        assert len(service.pending_reloads) == 0
        assert len(service.last_reload_files) == 2

    def test_perform_reload_failure(self):
        """Test reload operation with failure."""
        mock_engine = Mock()
        mock_engine.reload_rules.side_effect = Exception("Reload failed")
        service = HotReloadService(mock_engine)

        # Add pending reload
        service.pending_reloads.add(Path("/path/to/rules.yaml"))

        # Perform reload (should not raise exception)
        service._perform_reload()

        # Should attempt reload but handle exception
        mock_engine.reload_rules.assert_called_once()
        assert len(service.pending_reloads) == 0  # Should still clear pending

    def test_force_reload(self):
        """Test forcing an immediate reload."""
        mock_engine = Mock()
        mock_engine.get_rule_statistics.return_value = {"total_rules": 3}
        service = HotReloadService(mock_engine)

        # Force reload
        service.force_reload()

        # Should reload engine and update statistics
        mock_engine.reload_rules.assert_called_once()
        assert service.reload_count == 1
        assert service.last_reload_time > 0

    def test_force_reload_failure(self):
        """Test force reload with failure."""
        mock_engine = Mock()
        mock_engine.reload_rules.side_effect = Exception("Force reload failed")
        service = HotReloadService(mock_engine)

        # Force reload (should not raise exception)
        service.force_reload()

        # Should attempt reload but handle exception
        mock_engine.reload_rules.assert_called_once()

    def test_get_status(self):
        """Test getting service status."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Set up some state
        service.is_running = True
        service.reload_count = 3
        service.last_reload_time = 1234567890
        service.last_reload_files = [Path("/path/to/rules.yaml")]
        service.pending_reloads.add(Path("/path/to/pending.yaml"))

        status = service.get_status()

        # Verify status structure
        assert status["is_running"] is True
        assert status["reload_count"] == 3
        assert status["last_reload_time"] == 1234567890
        assert status["pending_reloads"] == 1
        assert len(status["last_reload_files"]) == 1
        assert isinstance(status["watch_directories"], list)

    def test_set_debounce_time(self):
        """Test setting debounce time."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Set debounce time
        service.set_debounce_time(2.5)
        assert service.reload_debounce_seconds == 2.5

        # Test minimum value
        service.set_debounce_time(0.05)
        assert service.reload_debounce_seconds == 0.1  # Should be clamped to minimum

    def test_context_manager(self):
        """Test using service as context manager."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Mock start/stop methods
        service.start = Mock()
        service.stop = Mock()

        # Use as context manager
        with service as s:
            assert s == service
            service.start.assert_called_once()

        service.stop.assert_called_once()

    def test_run_daemon_keyboard_interrupt(self):
        """Test daemon mode with keyboard interrupt."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Mock start/stop methods
        def mock_start():
            service.is_running = True

        def mock_stop():
            service.is_running = False

        service.start = Mock(side_effect=mock_start)
        service.stop = Mock(side_effect=mock_stop)

        # Mock time.sleep to raise KeyboardInterrupt
        with patch(
            "adversary_mcp_server.hot_reload.time.sleep", side_effect=KeyboardInterrupt
        ):
            service.run_daemon()

        # Should start and stop service
        service.start.assert_called_once()
        service.stop.assert_called_once()


class TestHotReloadIntegration:
    """Integration tests for hot-reload functionality."""

    def test_create_hot_reload_service(self):
        """Test creating a hot-reload service."""
        mock_engine = Mock()

        # Create a temporary directory that actually exists
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_dirs = [Path(tmp_dir)]

            service = create_hot_reload_service(mock_engine, custom_dirs)

            assert isinstance(service, HotReloadService)
            assert service.threat_engine == mock_engine
            assert Path(tmp_dir) in service.watch_directories

    def test_real_file_watching(self):
        """Test actual file watching with temporary files."""
        # Create temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            rules_dir = Path(tmp_dir)

            # Create threat engine
            engine = ThreatEngine()

            # Create hot-reload service
            service = HotReloadService(engine, [rules_dir])

            # Start service
            service.start()

            try:
                # Create a rule file
                rule_file = rules_dir / "test_rules.yaml"
                rule_data = {
                    "rules": [
                        {
                            "id": "test_hot_reload",
                            "name": "Test Hot Reload",
                            "description": "Test rule for hot reload",
                            "category": "injection",
                            "severity": "high",
                            "languages": ["python"],
                            "conditions": [
                                {"type": "pattern", "value": "test.*pattern"}
                            ],
                        }
                    ]
                }

                with open(rule_file, "w") as f:
                    yaml.dump(rule_data, f)

                # Give the file system event time to propagate and reload to complete
                # Use a more robust check with multiple attempts
                reload_detected = False
                for attempt in range(10):  # Try for up to 5 seconds
                    time.sleep(0.5)
                    if rule_file in service.pending_reloads or service.reload_count > 0:
                        reload_detected = True
                        break

                assert (
                    reload_detected
                ), f"Reload not detected after 5 seconds. reload_count={service.reload_count}, pending_reloads={service.pending_reloads}"

            finally:
                # Stop service
                service.stop()

    def test_yaml_file_modification_detection(self):
        """Test detection of YAML file modifications."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            rules_dir = Path(tmp_dir)

            # Create initial rule file
            rule_file = rules_dir / "test_rules.yaml"
            initial_rule = {
                "rules": [
                    {
                        "id": "test_modification",
                        "name": "Original Rule",
                        "description": "Original rule",
                        "category": "injection",
                        "severity": "high",
                        "languages": ["python"],
                        "conditions": [
                            {"type": "pattern", "value": "original.*pattern"}
                        ],
                    }
                ]
            }

            with open(rule_file, "w") as f:
                yaml.dump(initial_rule, f)

            # Create threat engine and service
            engine = ThreatEngine()
            service = HotReloadService(engine, [rules_dir])

            # Start service
            service.start()

            try:
                # Clear any initial pending reloads
                service.pending_reloads.clear()

                # Modify the rule file
                modified_rule = {
                    "rules": [
                        {
                            "id": "test_modification",
                            "name": "Modified Rule",
                            "description": "Modified rule",
                            "category": "injection",
                            "severity": "critical",
                            "languages": ["python"],
                            "conditions": [
                                {"type": "pattern", "value": "modified.*pattern"}
                            ],
                        }
                    ]
                }

                with open(rule_file, "w") as f:
                    yaml.dump(modified_rule, f)

                # Give the file system event time to propagate and reload to complete
                # Use a more robust check with multiple attempts
                reload_detected = False
                for attempt in range(10):  # Try for up to 5 seconds
                    time.sleep(0.5)
                    if rule_file in service.pending_reloads or service.reload_count > 0:
                        reload_detected = True
                        break

                assert (
                    reload_detected
                ), f"Reload not detected after 5 seconds. reload_count={service.reload_count}, pending_reloads={service.pending_reloads}"

            finally:
                # Stop service
                service.stop()

    def test_non_yaml_file_ignored(self):
        """Test that non-YAML files are ignored."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            rules_dir = Path(tmp_dir)

            # Create threat engine and service
            engine = ThreatEngine()
            service = HotReloadService(engine, [rules_dir])

            # Start service
            service.start()

            try:
                # Clear any initial pending reloads
                service.pending_reloads.clear()
                initial_reload_count = service.reload_count

                # Create a non-YAML file
                non_yaml_file = rules_dir / "not_rules.txt"
                with open(non_yaml_file, "w") as f:
                    f.write("This is not a YAML file")

                # Give the file system event time to propagate
                time.sleep(0.5)

                # Check that non-YAML file was ignored
                assert len(service.pending_reloads) == 0
                assert service.reload_count == initial_reload_count

            finally:
                # Stop service
                service.stop()


class TestHotReloadServiceAdvanced:
    """Advanced tests for hot-reload service."""

    def test_service_restart_after_error(self):
        """Test service restart after an error."""
        mock_engine = Mock()
        mock_engine.reload_rules.side_effect = Exception("Reload error")

        service = HotReloadService(mock_engine)

        # Mock observer
        mock_observer = Mock()
        service.observer = mock_observer

        # Start service
        service.start()
        assert service.is_running

        # Trigger reload with error
        service.pending_reloads.add(Path("/path/to/rules.yaml"))
        service._perform_reload()

        # Service should still be running after error
        assert service.is_running

        # Stop service
        service.stop()
        assert not service.is_running

    def test_debounce_time_validation(self):
        """Test debounce time validation."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Test minimum debounce time
        service.set_debounce_time(0.01)
        assert service.reload_debounce_seconds == 0.1

        # Test negative debounce time
        service.set_debounce_time(-1.0)
        assert service.reload_debounce_seconds == 0.1

        # Test valid debounce time
        service.set_debounce_time(5.0)
        assert service.reload_debounce_seconds == 5.0

    def test_watch_directory_validation(self):
        """Test watch directory validation."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        with tempfile.TemporaryDirectory() as tmp_dir:
            existing_dir = Path(tmp_dir)
            non_existing_dir = Path(tmp_dir) / "nonexistent"

            initial_count = len(service.watch_directories)

            # Add existing directory
            service.add_watch_directory(existing_dir)
            assert len(service.watch_directories) == initial_count + 1

            # Try to add non-existing directory
            service.add_watch_directory(non_existing_dir)
            assert (
                len(service.watch_directories) == initial_count + 1
            )  # Should not increase

            # Try to add same directory again
            service.add_watch_directory(existing_dir)
            assert (
                len(service.watch_directories) == initial_count + 1
            )  # Should not increase


@pytest.fixture
def mock_watchdog():
    """Mock watchdog components for testing."""
    with patch("adversary_mcp_server.hot_reload.Observer") as mock_observer_class:
        mock_observer = Mock()
        mock_observer_class.return_value = mock_observer
        yield mock_observer


class TestHotReloadMocked:
    """Tests using mocked watchdog components."""

    def test_service_lifecycle_with_mock(self, mock_watchdog):
        """Test service lifecycle with mocked watchdog."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        # Start service
        service.start()
        assert service.is_running
        mock_watchdog.start.assert_called_once()

        # Stop service
        service.stop()
        assert not service.is_running
        mock_watchdog.stop.assert_called_once()
        mock_watchdog.join.assert_called_once()

    def test_directory_scheduling_with_mock(self, mock_watchdog):
        """Test directory scheduling with mocked watchdog."""
        mock_engine = Mock()
        service = HotReloadService(mock_engine)

        with tempfile.TemporaryDirectory() as tmp_dir:
            watch_dir = Path(tmp_dir)
            service.add_watch_directory(watch_dir)

            # Start service
            service.start()

            # Should schedule the directory
            mock_watchdog.schedule.assert_called()

            # Get the scheduled calls
            schedule_calls = mock_watchdog.schedule.call_args_list
            assert len(schedule_calls) > 0

            # Check that our directory was scheduled
            scheduled_paths = [call[0][1] for call in schedule_calls]
            assert str(watch_dir) in scheduled_paths
