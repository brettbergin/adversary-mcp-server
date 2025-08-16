"""Application layer for the adversary MCP server.

This package contains application services, orchestration logic, and
coordination between the domain layer and infrastructure layer while keeping
business logic separate from technical concerns.

For Clean Architecture components, use:
- application.services.scan_application_service for main application services
- application.mcp_server for Clean Architecture MCP server
- application.cli.clean_cli for Clean Architecture CLI

DEPRECATED: bootstrap module contains legacy dependency injection configuration.
"""

# NOTE: bootstrap imports removed to avoid legacy interface dependencies
# Import bootstrap explicitly if needed for legacy code

__all__ = [
    # Clean Architecture exports can be added here if needed
]
