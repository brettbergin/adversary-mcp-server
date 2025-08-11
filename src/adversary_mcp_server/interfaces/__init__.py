"""Interfaces for dependency injection and modular architecture.

This package contains all service interfaces that define contracts for the
adversary MCP server components. Using Protocol classes enables:

- Dependency injection with type safety
- Easy testing with mock implementations
- Modular architecture with clear boundaries
- Interface segregation principle compliance
"""

from .cache import ICacheManager
from .credentials import ICredentialManager
from .metrics import IMetricsCollector
from .scanner import ILLMScanner, IScanEngine, ISemgrepScanner
from .validator import ILLMValidator, IValidator

__all__ = [
    "ICacheManager",
    "ICredentialManager",
    "IMetricsCollector",
    "IScanEngine",
    "ISemgrepScanner",
    "ILLMScanner",
    "IValidator",
    "ILLMValidator",
]
