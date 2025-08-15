"""Simple tests for sync_main module to increase coverage."""

from unittest.mock import MagicMock, patch

from adversary_mcp_server import sync_main


class TestSyncMainSimple:
    """Simple tests for sync_main to increase coverage."""

    def test_main_keyboard_interrupt(self):
        """Test main function handles KeyboardInterrupt correctly."""
        with (
            patch("adversary_mcp_server.sync_main.asyncio.run") as mock_run,
            patch("truststore.inject_into_ssl"),
            patch("sys.exit") as mock_exit,
            patch("builtins.print") as mock_print,
        ):

            # Simulate KeyboardInterrupt
            mock_run.side_effect = KeyboardInterrupt()

            # Call main
            sync_main.main()

            # Verify shutdown message and clean exit
            mock_print.assert_called_once_with("\nServer shutdown requested")
            mock_exit.assert_called_once_with(0)

    def test_main_server_exception(self):
        """Test main function handles server exceptions correctly."""
        with (
            patch("adversary_mcp_server.sync_main.asyncio.run") as mock_run,
            patch("truststore.inject_into_ssl"),
            patch("sys.exit") as mock_exit,
            patch("logging.getLogger") as mock_get_logger,
        ):

            # Configure mocks
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger
            server_error = Exception("Server startup failed")
            mock_run.side_effect = server_error

            # Call main
            sync_main.main()

            # Verify error logging and error exit
            mock_logger.error.assert_called_once()
            assert (
                "Server error: Server startup failed"
                in mock_logger.error.call_args[0][0]
            )
            mock_exit.assert_called_once_with(1)

    def test_truststore_injection_failure(self):
        """Test main function handles truststore injection failure."""
        with (
            patch("adversary_mcp_server.sync_main.asyncio.run") as mock_run,
            patch(
                "truststore.inject_into_ssl", side_effect=Exception("Truststore error")
            ),
            patch("sys.exit") as mock_exit,
            patch("logging.getLogger") as mock_get_logger,
        ):

            # Configure mocks
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger
            mock_run.side_effect = KeyboardInterrupt()  # Normal exit after error

            # Call main
            sync_main.main()

            # Verify truststore error was logged
            mock_logger.error.assert_called_once()
            assert "Failed to inject truststore" in mock_logger.error.call_args[0][0]

            # Should still exit normally due to KeyboardInterrupt
            mock_exit.assert_called_once_with(0)

    def test_truststore_injection_success(self):
        """Test main function with successful truststore injection."""
        with (
            patch("adversary_mcp_server.sync_main.asyncio.run") as mock_run,
            patch("truststore.inject_into_ssl") as mock_truststore,
            patch("sys.exit") as mock_exit,
        ):

            # Configure to exit normally
            mock_run.side_effect = KeyboardInterrupt()

            # Call main
            sync_main.main()

            # Verify truststore was called
            mock_truststore.assert_called_once()
            mock_exit.assert_called_once_with(0)

    def test_asyncio_run_called(self):
        """Test that asyncio.run is called with a coroutine."""
        with (
            patch("adversary_mcp_server.sync_main.asyncio.run") as mock_run,
            patch("truststore.inject_into_ssl"),
            patch("sys.exit"),
        ):

            mock_run.side_effect = KeyboardInterrupt()

            # Call main
            sync_main.main()

            # Verify asyncio.run was called
            mock_run.assert_called_once()

            # The argument should be a coroutine
            args, kwargs = mock_run.call_args
            assert len(args) == 1
            # The argument should be a coroutine object (can't easily test the content)
