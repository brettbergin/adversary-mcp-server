"""Domain-specific exceptions for the adversary MCP server."""


class DomainError(Exception):
    """Base exception for all domain errors."""

    pass


class ScanError(DomainError):
    """Exception raised when a scan operation fails."""

    pass


class ValidationError(DomainError):
    """Exception raised when validation fails."""

    pass


class AggregationError(DomainError):
    """Exception raised when threat aggregation fails."""

    pass


class SecurityError(DomainError):
    """Exception raised for security-related errors."""

    pass


class ConfigurationError(DomainError):
    """Exception raised for configuration-related errors."""

    pass
