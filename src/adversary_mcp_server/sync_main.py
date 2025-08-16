"""
Synchronous entry point wrapper for Clean Architecture MCP server.

This module provides a synchronous main() function that properly handles
the async execution of the Clean Architecture MCP server.
"""

import asyncio
import sys


def main() -> None:
    """
    Synchronous main entry point for Clean Architecture MCP server.

    This function properly handles the async execution of the MCP server.
    """
    # SSL truststore injection for corporate environments (e.g., Netskope)
    try:
        import truststore

        truststore.inject_into_ssl()
    except ImportError:
        # Truststore not available - will use system SSL configuration
        pass
    except Exception as e:
        import logging

        logger = logging.getLogger(__name__)
        logger.error(f"Failed to inject truststore into SSL context: {e}")

    async def async_main() -> None:
        """Run the Clean Architecture MCP server."""
        from .application.mcp_server import CleanMCPServer

        server = CleanMCPServer()
        await server.run()

    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nServer shutdown requested")
        sys.exit(0)
    except Exception as e:
        import logging

        logger = logging.getLogger(__name__)
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
