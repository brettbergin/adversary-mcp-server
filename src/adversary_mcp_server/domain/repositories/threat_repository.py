"""Abstract repository interface for threat persistence."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from ..entities.threat_match import ThreatMatch
from ..value_objects.severity_level import SeverityLevel


class IThreatRepository(ABC):
    """
    Abstract repository interface for threat data persistence.

    Defines the contract for storing and retrieving threat information,
    false positive markings, and threat analytics without coupling
    the domain to specific storage implementations.
    """

    @abstractmethod
    async def save_threat(self, threat: ThreatMatch, scan_id: str) -> str:
        """
        Save a threat and associate it with a scan.

        Args:
            threat: The threat to save
            scan_id: ID of the scan this threat belongs to

        Returns:
            Unique identifier for the saved threat

        Raises:
            RepositoryError: If saving fails
        """
        pass

    @abstractmethod
    async def get_threat(self, threat_uuid: str) -> ThreatMatch | None:
        """
        Retrieve a threat by its UUID.

        Args:
            threat_uuid: UUID of the threat

        Returns:
            The threat if found, None otherwise

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_threats_by_scan(self, scan_id: str) -> list[ThreatMatch]:
        """
        Retrieve all threats for a specific scan.

        Args:
            scan_id: ID of the scan

        Returns:
            List of threats found in the scan

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_threats_by_file(self, file_path: str) -> list[ThreatMatch]:
        """
        Retrieve all threats for a specific file.

        Args:
            file_path: Path to the file

        Returns:
            List of threats found in the file

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_threats_by_rule(self, rule_id: str) -> list[ThreatMatch]:
        """
        Retrieve all threats detected by a specific rule.

        Args:
            rule_id: ID of the detection rule

        Returns:
            List of threats detected by the rule

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_threats_by_severity(
        self, min_severity: SeverityLevel, max_severity: SeverityLevel | None = None
    ) -> list[ThreatMatch]:
        """
        Retrieve threats within a severity range.

        Args:
            min_severity: Minimum severity level
            max_severity: Maximum severity level (if None, no upper limit)

        Returns:
            List of threats within the severity range

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def mark_false_positive(
        self, threat_uuid: str, marked_by: str, reason: str = ""
    ) -> bool:
        """
        Mark a threat as a false positive.

        Args:
            threat_uuid: UUID of the threat to mark
            marked_by: Identifier of who marked it as false positive
            reason: Optional reason for marking as false positive

        Returns:
            True if marking was successful, False if threat not found

        Raises:
            RepositoryError: If marking fails
        """
        pass

    @abstractmethod
    async def unmark_false_positive(self, threat_uuid: str) -> bool:
        """
        Remove false positive marking from a threat.

        Args:
            threat_uuid: UUID of the threat to unmark

        Returns:
            True if unmarking was successful, False if threat not found

        Raises:
            RepositoryError: If unmarking fails
        """
        pass

    @abstractmethod
    async def get_false_positives(self) -> list[ThreatMatch]:
        """
        Retrieve all threats marked as false positives.

        Returns:
            List of threats marked as false positives

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_threat_by_fingerprint(self, fingerprint: str) -> ThreatMatch | None:
        """
        Retrieve a threat by its fingerprint.

        Used for persistence of UUIDs and false positive markings
        across multiple scans of the same code.

        Args:
            fingerprint: Fingerprint of the threat

        Returns:
            The threat if found, None otherwise

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_threat_analytics(
        self, start_date: datetime | None = None, end_date: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get analytics about threats over time.

        Args:
            start_date: Optional start date for analytics
            end_date: Optional end date for analytics

        Returns:
            Dictionary containing threat analytics

        Raises:
            RepositoryError: If analytics calculation fails
        """
        pass

    @abstractmethod
    async def get_top_threat_categories(
        self,
        limit: int = 10,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[tuple[str, int]]:
        """
        Get most common threat categories.

        Args:
            limit: Maximum number of categories to return
            start_date: Optional start date for analysis
            end_date: Optional end date for analysis

        Returns:
            List of tuples (category, count) sorted by frequency

        Raises:
            RepositoryError: If analysis fails
        """
        pass

    @abstractmethod
    async def get_threat_trends(
        self, days: int = 30
    ) -> dict[str, list[tuple[datetime, int]]]:
        """
        Get threat detection trends over time.

        Args:
            days: Number of days to analyze

        Returns:
            Dictionary mapping severity levels to time series data

        Raises:
            RepositoryError: If trend analysis fails
        """
        pass

    @abstractmethod
    async def cleanup_old_threats(self, retention_days: int) -> int:
        """
        Clean up threat data older than specified retention period.

        Args:
            retention_days: Number of days to retain threat data

        Returns:
            Number of threats cleaned up

        Raises:
            RepositoryError: If cleanup fails
        """
        pass

    @abstractmethod
    async def bulk_save_threats(
        self, threats: list[ThreatMatch], scan_id: str
    ) -> list[str]:
        """
        Save multiple threats in a single operation.

        Args:
            threats: List of threats to save
            scan_id: ID of the scan these threats belong to

        Returns:
            List of unique identifiers for the saved threats

        Raises:
            RepositoryError: If bulk saving fails
        """
        pass


# Repository-specific exceptions


class RepositoryError(Exception):
    """Base exception for repository operations."""

    pass


class ThreatNotFoundError(RepositoryError):
    """Exception raised when a threat is not found."""

    pass


class ScanNotFoundError(RepositoryError):
    """Exception raised when a scan is not found."""

    pass


class DuplicateThreatError(RepositoryError):
    """Exception raised when attempting to save a duplicate threat."""

    pass
