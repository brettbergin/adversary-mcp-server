"""Centralized logging configuration for Adversary MCP server."""

import logging
import logging.handlers
from pathlib import Path
from typing import Any


class AdversaryLogger:
    """Centralized logger for Adversary MCP server with file rotation."""

    _instance = None
    _initialized = False

    def __new__(cls, test_mode: bool = False) -> "AdversaryLogger":
        """Ensure singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, test_mode: bool = False) -> None:
        """Initialize the logger (only once).

        Args:
            test_mode: If True, use test-specific log file
        """
        if self._initialized:
            return

        self._initialized = True
        self.log_dir = (
            Path.home() / ".local" / "share" / "adversary-mcp-server" / "logs"
        )

        # Use different log file for tests
        if test_mode:
            self.log_file = self.log_dir / "test-adversary.log"
        else:
            self.log_file = self.log_dir / "adversary-mcp.log"

        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Set up logging
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Set up the logging configuration with file rotation."""
        # Create logger
        self.logger = logging.getLogger("adversary_mcp")

        # Clear existing handlers to avoid duplicates
        self.logger.handlers.clear()

        # Create file handler with rotation (5MB max, keep 5 backups)
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_file,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)

        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(filename)s::%(funcName)s::%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Set formatter for handlers
        file_handler.setFormatter(formatter)

        # Add handlers to logger
        self.logger.addHandler(file_handler)

        # Prevent propagation to root logger
        self.logger.propagate = False

        # ALSO CAPTURE MCP FRAMEWORK LOGGING
        # Set up root logger to capture all MCP server framework logs
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        # Add our file handler to root logger to capture MCP framework logs
        root_logger.addHandler(file_handler)

        # Capture specific MCP-related loggers
        mcp_loggers = ["mcp", "mcp.server", "mcp.types", "anyio", "starlette"]
        for logger_name in mcp_loggers:
            mcp_logger = logging.getLogger(logger_name)
            mcp_logger.setLevel(logging.DEBUG)
            mcp_logger.addHandler(file_handler)
            mcp_logger.propagate = False

        # Log initialization
        self.logger.info("Adversary MCP logging system initialized")
        self.logger.info(f"Log file: {self.log_file}")
        self.logger.info("MCP framework logging enabled")

    def get_logger(self, name: str | None = None) -> logging.Logger:
        """Get a logger instance.

        Args:
            name: Optional logger name (will be appended to 'adversary_mcp')

        Returns:
            Logger instance
        """
        if name:
            logger_name = f"adversary_mcp.{name}"
        else:
            logger_name = "adversary_mcp"

        return logging.getLogger(logger_name)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log an info message."""
        self.logger.info(message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log a warning message."""
        self.logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log an error message."""
        self.logger.error(message, **kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log a debug message."""
        self.logger.debug(message, **kwargs)

    def exception(self, message: str, **kwargs: Any) -> None:
        """Log an exception with traceback."""
        self.logger.exception(message, **kwargs)

    def set_log_level(self, level: str) -> None:
        """Set the logging level.

        Args:
            level: Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        """
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.setLevel(numeric_level)

        # Update file handler level
        for handler in self.logger.handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                handler.setLevel(numeric_level)

    def get_log_file_path(self) -> Path:
        """Get the path to the current log file.

        Returns:
            Path to the log file
        """
        return self.log_file

    def get_log_stats(self) -> dict[str, Any]:
        """Get statistics about the log files.

        Returns:
            Dictionary with log file statistics
        """
        current_size = 0
        total_size = 0
        backup_files = []

        try:
            if self.log_file.exists():
                current_size = self.log_file.stat().st_size
                total_size = current_size

            # Find backup files
            for i in range(1, 6):  # Check for .1 to .5 backup files
                backup_file = Path(f"{self.log_file}.{i}")
                if backup_file.exists():
                    backup_size = backup_file.stat().st_size
                    backup_files.append({"file": str(backup_file), "size": backup_size})
                    total_size += backup_size

        except OSError:
            pass  # Ignore file system errors

        stats = {
            "log_file": str(self.log_file),
            "log_dir": str(self.log_dir),
            "current_size": current_size,
            "backup_files": backup_files,
            "total_size": total_size,
        }

        return stats

    @classmethod
    def reset_for_tests(cls) -> None:
        """Reset the logger singleton for test isolation."""
        cls._instance = None
        cls._initialized = False


# Global logger instance
_logger_instance = AdversaryLogger()


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Optional logger name

    Returns:
        Logger instance
    """
    return _logger_instance.get_logger(name)


def log_info(message: str, **kwargs: Any) -> None:
    """Log an info message."""
    _logger_instance.info(message, **kwargs)


def log_warning(message: str, **kwargs: Any) -> None:
    """Log a warning message."""
    _logger_instance.warning(message, **kwargs)


def log_error(message: str, **kwargs: Any) -> None:
    """Log an error message."""
    _logger_instance.error(message, **kwargs)


def log_debug(message: str, **kwargs: Any) -> None:
    """Log a debug message."""
    _logger_instance.debug(message, **kwargs)


def log_exception(message: str, **kwargs: Any) -> None:
    """Log an exception with traceback."""
    _logger_instance.exception(message, **kwargs)


def set_log_level(level: str) -> None:
    """Set the logging level."""
    _logger_instance.set_log_level(level)


def get_log_stats() -> dict[str, Any]:
    """Get log statistics."""
    return _logger_instance.get_log_stats()


def setup_test_logging() -> None:
    """Set up logging for tests with a separate log file."""
    global _logger_instance
    AdversaryLogger.reset_for_tests()
    _logger_instance = AdversaryLogger(test_mode=True)
