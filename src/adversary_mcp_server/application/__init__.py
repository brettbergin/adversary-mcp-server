"""Application layer for the adversary MCP server.

This package contains application services, orchestration logic, and
dependency injection configuration. The application layer coordinates
between the domain layer and infrastructure layer while keeping
business logic separate from technical concerns.
"""

from .bootstrap import configure_container, create_configured_container

__all__ = [
    "configure_container",
    "create_configured_container",
]
