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
    # Initialize logger early to capture all MCP server activity
    from .logger import get_logger

    logger = get_logger("mcp_server")
    logger.info("[+] Starting Adversary MCP Server")
    logger.info(f"Log level: {logger.getEffectiveLevel()}")

    # SSL truststore injection for corporate environments (e.g., Netskope)
    try:
        import truststore

        truststore.inject_into_ssl()
        logger.info(
            "[+] SSL truststore injection successful (corporate environment support enabled)"
        )
    except ImportError:
        # Truststore not available - will use system SSL configuration
        logger.debug("Truststore not available - using system SSL configuration")
    except Exception as e:
        logger.error(f"Failed to inject truststore into SSL context: {e}")

    async def async_main() -> None:
        """Run the Clean Architecture MCP server."""
        from .application.mcp_server import CleanMCPServer

        logger.info("Initializing Clean Architecture MCP Server")
        server = CleanMCPServer()
        logger.info("Starting MCP server - ready to accept tool invocations")
        await server.run()

    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Server shutdown requested via keyboard interrupt")
        print("\nServer shutdown requested")
        sys.exit(0)
    except Exception as e:
        logger.error(f"[-] Server error: {e}")
        logger.exception("Full error details:")
        sys.exit(1)


if __name__ == "__main__":
    main()
