"""Abstract repository interface for scan persistence."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from ..entities.scan_request import ScanRequest
from ..entities.scan_result import ScanResult


class IScanRepository(ABC):
    """
    Abstract repository interface for scan data persistence.

    Defines the contract for storing and retrieving scan requests,
    results, and related metadata without coupling the domain
    to specific storage implementations.
    """

    @abstractmethod
    async def save_scan_request(self, request: ScanRequest) -> str:
        """
        Save a scan request and return its ID.

        Args:
            request: The scan request to save

        Returns:
            Unique identifier for the saved scan request

        Raises:
            RepositoryError: If saving fails
        """
        pass

    @abstractmethod
    async def get_scan_request(self, scan_id: str) -> ScanRequest | None:
        """
        Retrieve a scan request by ID.

        Args:
            scan_id: Unique identifier of the scan request

        Returns:
            The scan request if found, None otherwise

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def save_scan_result(self, result: ScanResult) -> str:
        """
        Save a scan result and return its ID.

        Args:
            result: The scan result to save

        Returns:
            Unique identifier for the saved scan result

        Raises:
            RepositoryError: If saving fails
        """
        pass

    @abstractmethod
    async def get_scan_result(self, scan_id: str) -> ScanResult | None:
        """
        Retrieve a scan result by scan ID.

        Args:
            scan_id: Unique identifier of the scan

        Returns:
            The scan result if found, None otherwise

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_scan_results_by_target(self, target_path: str) -> list[ScanResult]:
        """
        Retrieve scan results for a specific target path.

        Args:
            target_path: Path that was scanned

        Returns:
            List of scan results for the target

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_scan_results_by_requester(self, requester: str) -> list[ScanResult]:
        """
        Retrieve scan results for a specific requester.

        Args:
            requester: Name/ID of the requester

        Returns:
            List of scan results for the requester

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_scan_results_in_date_range(
        self, start_date: datetime, end_date: datetime
    ) -> list[ScanResult]:
        """
        Retrieve scan results within a date range.

        Args:
            start_date: Start of date range (inclusive)
            end_date: End of date range (inclusive)

        Returns:
            List of scan results in the date range

        Raises:
            RepositoryError: If retrieval fails
        """
        pass

    @abstractmethod
    async def delete_scan_data(self, scan_id: str) -> bool:
        """
        Delete all data for a specific scan.

        Args:
            scan_id: Unique identifier of the scan to delete

        Returns:
            True if deletion was successful, False if scan not found

        Raises:
            RepositoryError: If deletion fails
        """
        pass

    @abstractmethod
    async def get_scan_statistics(
        self, start_date: datetime | None = None, end_date: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get aggregate statistics about scans.

        Args:
            start_date: Optional start date for statistics
            end_date: Optional end date for statistics

        Returns:
            Dictionary containing scan statistics

        Raises:
            RepositoryError: If statistics calculation fails
        """
        pass

    @abstractmethod
    async def cleanup_old_scans(self, retention_days: int) -> int:
        """
        Clean up scan data older than specified retention period.

        Args:
            retention_days: Number of days to retain scan data

        Returns:
            Number of scans cleaned up

        Raises:
            RepositoryError: If cleanup fails
        """
        pass
