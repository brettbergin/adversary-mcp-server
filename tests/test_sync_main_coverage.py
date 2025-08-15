"""Tests for sync_main module to increase coverage."""

from unittest.mock import patch

import pytest

from adversary_mcp_server.sync_main import main


class TestSyncMain:
    """Test sync_main module coverage."""

    def test_main_basic_execution(self):
        """Test main function basic execution path."""
        # Mock asyncio.run to prevent actual server startup
        with patch("adversary_mcp_server.sync_main.asyncio.run") as mock_run:
            mock_run.side_effect = KeyboardInterrupt()

            with patch("builtins.print") as mock_print:
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
                mock_print.assert_called_with("\nServer shutdown requested")

    def test_main_keyboard_interrupt(self):
        """Test main function with keyboard interrupt."""
        with patch("adversary_mcp_server.sync_main.asyncio.run") as mock_run:
            mock_run.side_effect = KeyboardInterrupt()

            with patch("builtins.print") as mock_print:
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
                mock_print.assert_called_with("\nServer shutdown requested")

    def test_main_server_exception(self):
        """Test main function with server exception."""
        with patch("adversary_mcp_server.sync_main.asyncio.run") as mock_run:
            mock_run.side_effect = Exception("Server error")

            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_sync_main_module_attributes(self):
        """Test sync_main module has expected attributes."""
        from adversary_mcp_server import sync_main

        # Check that main function exists
        assert hasattr(sync_main, "main")
        assert callable(sync_main.main)
