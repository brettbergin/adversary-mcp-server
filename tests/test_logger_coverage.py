"""Tests for logger module to increase coverage."""

import logging

from adversary_mcp_server.logger import get_logger


class TestLoggerCoverage:
    """Test logger module for coverage."""

    def test_get_logger_basic(self):
        """Test get_logger basic functionality."""
        logger = get_logger("test_logger")

        # Should return a logger instance
        assert isinstance(logger, logging.Logger)
        assert logger.name == "adversary_mcp.test_logger"

    def test_get_logger_different_names(self):
        """Test get_logger with different names."""
        logger1 = get_logger("logger1")
        logger2 = get_logger("logger2")

        assert logger1.name == "adversary_mcp.logger1"
        assert logger2.name == "adversary_mcp.logger2"
        assert logger1 != logger2

    def test_get_logger_same_name(self):
        """Test get_logger returns same instance for same name."""
        logger1 = get_logger("same_name")
        logger2 = get_logger("same_name")

        # Should be the same logger instance
        assert logger1 is logger2
