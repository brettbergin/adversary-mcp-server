"""Tests for logger module."""

import logging

from adversary_mcp_server.logger import get_log_stats, get_logger, set_log_level


class TestGetLogger:
    """Test logger creation and configuration."""

    def test_get_logger_basic(self):
        """Test basic logger creation."""
        logger = get_logger("test_module")

        assert isinstance(logger, logging.Logger)
        assert logger.name == "adversary_mcp.test_module"

    def test_get_logger_different_modules(self):
        """Test logger creation for different modules."""
        logger1 = get_logger("module1")
        logger2 = get_logger("module2")

        assert logger1.name == "adversary_mcp.module1"
        assert logger2.name == "adversary_mcp.module2"
        assert logger1 != logger2

    def test_get_logger_same_module_returns_same_logger(self):
        """Test that requesting the same module logger returns the same instance."""
        logger1 = get_logger("same_module")
        logger2 = get_logger("same_module")

        assert logger1 is logger2

    def test_get_logger_empty_name(self):
        """Test logger creation with empty name."""
        logger = get_logger("")
        assert logger.name == "adversary_mcp"

    def test_get_logger_none_name(self):
        """Test logger creation with None name."""
        logger = get_logger(None)
        assert logger.name == "adversary_mcp"

    def test_get_logger_nested_module(self):
        """Test logger creation for nested module names."""
        logger = get_logger("domain.entities.scan_result")
        assert logger.name == "adversary_mcp.domain.entities.scan_result"


class TestLoggerConfiguration:
    """Test logging configuration functionality."""

    def test_set_log_level_valid_levels(self):
        """Test setting valid log levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in valid_levels:
            # This should not raise any exceptions
            set_log_level(level)

            # Verify that we can still create a logger
            logger = get_logger("test_level")
            assert isinstance(logger, logging.Logger)

    def test_get_log_stats(self):
        """Test getting log statistics."""
        stats = get_log_stats()

        assert isinstance(stats, dict)
        # Log stats should have some basic structure
        # The exact structure depends on implementation


class TestLoggerUsage:
    """Test actual logger usage patterns."""

    def test_logger_methods_exist(self):
        """Test that logger has expected methods."""
        logger = get_logger("test_methods")

        assert hasattr(logger, "debug")
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")
        assert hasattr(logger, "critical")
        assert hasattr(logger, "exception")

    def test_logger_level_methods_work(self):
        """Test that logger methods can be called without error."""
        logger = get_logger("test_level_methods")

        # These should not raise exceptions
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")

    def test_logger_string_formatting(self):
        """Test that logger supports string formatting."""
        logger = get_logger("test_formatting")

        # These should not raise exceptions
        logger.info("Message with %s", "parameter")
        logger.info("Message with %d items", 5)
        logger.info("Message with multiple %s and %d", "params", 10)

    def test_logger_exception_handling(self):
        """Test logger exception handling."""
        logger = get_logger("test_exceptions")

        try:
            raise ValueError("Test exception")
        except ValueError:
            # This should not raise an exception
            logger.exception("Caught exception")

    def test_logger_with_extra_data(self):
        """Test logger with extra contextual data."""
        logger = get_logger("test_extra")

        # This should not raise exceptions
        logger.info("Message with extra data", extra={"key": "value"})
        logger.error(
            "Error with context", extra={"module": "test", "action": "testing"}
        )
