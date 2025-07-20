"""Hot-reload service for monitoring rule files and auto-reloading them."""

import time
from pathlib import Path

from watchdog.events import (
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from .threat_engine import ThreatEngine, get_user_rules_directory


class RuleFileHandler(FileSystemEventHandler):
    """File system event handler for rule files."""

    def __init__(self, hot_reload_service: "HotReloadService"):
        self.hot_reload_service = hot_reload_service
        self.rule_extensions = {".yaml", ".yml"}

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        if file_path.suffix in self.rule_extensions:
            self.hot_reload_service.queue_reload(file_path)

    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        if file_path.suffix in self.rule_extensions:
            self.hot_reload_service.queue_reload(file_path)

    def on_deleted(self, event):
        """Handle file deletion events."""
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        if file_path.suffix in self.rule_extensions:
            self.hot_reload_service.queue_reload(file_path)


class HotReloadService:
    """Service for monitoring rule files and auto-reloading them."""

    def __init__(
        self,
        threat_engine: ThreatEngine,
        watch_directories: list[Path] | None = None,
    ):
        """Initialize the hot-reload service.

        Args:
            threat_engine: ThreatEngine instance to reload rules into
            watch_directories: Directories to watch for rule file changes (defaults to user rules dir)
        """
        self.threat_engine = threat_engine
        self.watch_directories = watch_directories or []
        self.observer = Observer()
        self.event_handler = RuleFileHandler(self)
        self.is_running = False

        # Queue for pending reloads (to avoid rapid successive reloads)
        self.pending_reloads: set[Path] = set()
        self.last_reload_time = 0
        self.reload_debounce_seconds = 1.0  # Wait 1 second between reloads

        # Statistics
        self.reload_count = 0
        self.last_reload_files: list[Path] = []

        # Auto-detect user rules directory if no custom directories provided
        if not self.watch_directories:
            user_rules_dir = get_user_rules_directory()
            if user_rules_dir.exists():
                self.watch_directories.append(user_rules_dir)
                print(f"Auto-detected user rules directory: {user_rules_dir}")

    def add_watch_directory(self, directory: Path) -> None:
        """Add a directory to watch for rule file changes.

        Args:
            directory: Directory to watch
        """
        if directory.exists() and directory not in self.watch_directories:
            self.watch_directories.append(directory)

            # If already running, add the new directory to the observer
            if self.is_running:
                self.observer.schedule(
                    self.event_handler, str(directory), recursive=True
                )

    def remove_watch_directory(self, directory: Path) -> None:
        """Remove a directory from watching.

        Args:
            directory: Directory to stop watching
        """
        if directory in self.watch_directories:
            self.watch_directories.remove(directory)

            # If running, we need to restart the observer to remove the watch
            if self.is_running:
                self.stop()
                self.start()

    def start(self) -> None:
        """Start the hot-reload service."""
        if self.is_running:
            return

        # Schedule all watch directories
        for directory in self.watch_directories:
            if directory.exists():
                self.observer.schedule(
                    self.event_handler, str(directory), recursive=True
                )

        self.observer.start()
        self.is_running = True
        print(
            f"🔄 Hot-reload service started, watching {len(self.watch_directories)} directories"
        )

    def stop(self) -> None:
        """Stop the hot-reload service."""
        if not self.is_running:
            return

        self.observer.stop()
        self.observer.join()
        self.is_running = False
        print("🛑 Hot-reload service stopped")

    def queue_reload(self, file_path: Path) -> None:
        """Queue a file for reload.

        Args:
            file_path: Path to the file that changed
        """
        self.pending_reloads.add(file_path)
        print(f"📝 Queued reload for: {file_path}")

        # Check if we should perform the reload now
        self._maybe_perform_reload()

    def _maybe_perform_reload(self) -> None:
        """Perform reload if debounce time has passed."""
        current_time = time.time()

        # Check if enough time has passed since last reload
        if (current_time - self.last_reload_time) >= self.reload_debounce_seconds:
            if self.pending_reloads:
                self._perform_reload()

    def _perform_reload(self) -> None:
        """Perform the actual reload of rules."""
        try:
            files_to_reload = list(self.pending_reloads)
            self.pending_reloads.clear()

            print(f"🔄 Reloading {len(files_to_reload)} rule files...")

            # Record files for statistics
            self.last_reload_files = files_to_reload

            # Reload all rules
            self.threat_engine.reload_rules()

            # Update statistics
            self.reload_count += 1
            self.last_reload_time = time.time()

            stats = self.threat_engine.get_rule_statistics()
            print(f"✅ Reloaded {stats['total_rules']} rules successfully")

        except Exception as e:
            print(f"❌ Failed to reload rules: {e}")

    def force_reload(self) -> None:
        """Force an immediate reload of all rules."""
        print("🔄 Forcing immediate reload of all rules...")
        try:
            self.threat_engine.reload_rules()
            self.reload_count += 1
            self.last_reload_time = time.time()

            stats = self.threat_engine.get_rule_statistics()
            print(f"✅ Force reloaded {stats['total_rules']} rules successfully")

        except Exception as e:
            print(f"❌ Failed to force reload rules: {e}")

    def get_status(self) -> dict[str, any]:
        """Get the current status of the hot-reload service.

        Returns:
            Dictionary with service status information
        """
        return {
            "is_running": self.is_running,
            "watch_directories": [str(d) for d in self.watch_directories],
            "pending_reloads": len(self.pending_reloads),
            "reload_count": self.reload_count,
            "last_reload_time": self.last_reload_time,
            "last_reload_files": [str(f) for f in self.last_reload_files],
            "debounce_seconds": self.reload_debounce_seconds,
        }

    def set_debounce_time(self, seconds: float) -> None:
        """Set the debounce time for reloads.

        Args:
            seconds: Number of seconds to wait between reloads
        """
        self.reload_debounce_seconds = max(0.1, seconds)
        print(f"🔧 Set reload debounce time to {self.reload_debounce_seconds} seconds")

    def run_daemon(self) -> None:
        """Run the hot-reload service as a daemon.

        This will start the service and run indefinitely until interrupted.
        """
        try:
            self.start()
            print("🚀 Hot-reload daemon started. Press Ctrl+C to stop.")

            while self.is_running:
                time.sleep(1)

                # Check for pending reloads
                if self.pending_reloads:
                    self._maybe_perform_reload()

        except KeyboardInterrupt:
            print("\n🛑 Shutting down hot-reload daemon...")
            self.stop()
        except Exception as e:
            print(f"❌ Hot-reload daemon error: {e}")
            self.stop()

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


def create_hot_reload_service(
    threat_engine: ThreatEngine, custom_dirs: list[Path] | None = None
) -> HotReloadService:
    """Create and configure a hot-reload service.

    Args:
        threat_engine: ThreatEngine instance to reload rules into
        custom_dirs: Additional directories to watch

    Returns:
        Configured HotReloadService instance
    """
    service = HotReloadService(threat_engine)

    # Add custom directories if provided
    if custom_dirs:
        for directory in custom_dirs:
            service.add_watch_directory(directory)

    return service
