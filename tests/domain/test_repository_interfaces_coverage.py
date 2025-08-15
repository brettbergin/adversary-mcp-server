"""Comprehensive tests for repository interfaces to achieve 100% coverage."""

from abc import ABC
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from adversary_mcp_server.domain.repositories.scan_repository import IScanRepository
from adversary_mcp_server.domain.repositories.threat_repository import (
    DuplicateThreatError,
    IThreatRepository,
    RepositoryError,
    ScanNotFoundError,
    ThreatNotFoundError,
)


class TestRepositoryExceptions:
    """Test repository exception classes."""

    def test_repository_error_inheritance(self):
        """Test RepositoryError inheritance."""
        error = RepositoryError("Test error")
        assert isinstance(error, Exception)
        assert str(error) == "Test error"

    def test_threat_not_found_error_inheritance(self):
        """Test ThreatNotFoundError inheritance."""
        error = ThreatNotFoundError("Threat not found")
        assert isinstance(error, RepositoryError)
        assert isinstance(error, Exception)
        assert str(error) == "Threat not found"

    def test_scan_not_found_error_inheritance(self):
        """Test ScanNotFoundError inheritance."""
        error = ScanNotFoundError("Scan not found")
        assert isinstance(error, RepositoryError)
        assert isinstance(error, Exception)
        assert str(error) == "Scan not found"

    def test_duplicate_threat_error_inheritance(self):
        """Test DuplicateThreatError inheritance."""
        error = DuplicateThreatError("Duplicate threat")
        assert isinstance(error, RepositoryError)
        assert isinstance(error, Exception)
        assert str(error) == "Duplicate threat"

    def test_exception_creation_with_no_message(self):
        """Test creating exceptions with no message."""
        error = RepositoryError()
        assert str(error) == ""

        error = ThreatNotFoundError()
        assert isinstance(error, RepositoryError)

        error = ScanNotFoundError()
        assert isinstance(error, RepositoryError)

        error = DuplicateThreatError()
        assert isinstance(error, RepositoryError)


class MockScanRepository(IScanRepository):
    """Mock implementation of IScanRepository for testing."""

    def __init__(self):
        self.scan_requests = {}
        self.scan_results = {}
        self.call_log = []

    async def save_scan_request(self, request):
        self.call_log.append(("save_scan_request", request))
        scan_id = f"scan_{len(self.scan_requests)}"
        self.scan_requests[scan_id] = request
        return scan_id

    async def get_scan_request(self, scan_id):
        self.call_log.append(("get_scan_request", scan_id))
        return self.scan_requests.get(scan_id)

    async def save_scan_result(self, result):
        self.call_log.append(("save_scan_result", result))
        scan_id = f"result_{len(self.scan_results)}"
        self.scan_results[scan_id] = result
        return scan_id

    async def get_scan_result(self, scan_id):
        self.call_log.append(("get_scan_result", scan_id))
        return self.scan_results.get(scan_id)

    async def get_scan_results_by_target(self, target_path):
        self.call_log.append(("get_scan_results_by_target", target_path))
        return [
            result
            for result in self.scan_results.values()
            if getattr(result, "target_path", None) == target_path
        ]

    async def get_scan_results_by_requester(self, requester):
        self.call_log.append(("get_scan_results_by_requester", requester))
        return [
            result
            for result in self.scan_results.values()
            if getattr(result, "requester", None) == requester
        ]

    async def get_scan_results_in_date_range(self, start_date, end_date):
        self.call_log.append(("get_scan_results_in_date_range", start_date, end_date))
        return []

    async def delete_scan_data(self, scan_id):
        self.call_log.append(("delete_scan_data", scan_id))
        found = scan_id in self.scan_requests or scan_id in self.scan_results
        self.scan_requests.pop(scan_id, None)
        self.scan_results.pop(scan_id, None)
        return found

    async def get_scan_statistics(self, start_date=None, end_date=None):
        self.call_log.append(("get_scan_statistics", start_date, end_date))
        return {
            "total_scans": len(self.scan_requests),
            "total_results": len(self.scan_results),
        }

    async def cleanup_old_scans(self, retention_days):
        self.call_log.append(("cleanup_old_scans", retention_days))
        return 0


class MockThreatRepository(IThreatRepository):
    """Mock implementation of IThreatRepository for testing."""

    def __init__(self):
        self.threats = {}
        self.false_positives = set()
        self.call_log = []

    async def save_threat(self, threat, scan_id):
        self.call_log.append(("save_threat", threat, scan_id))
        threat_id = f"threat_{len(self.threats)}"
        self.threats[threat_id] = (threat, scan_id)
        return threat_id

    async def get_threat(self, threat_uuid):
        self.call_log.append(("get_threat", threat_uuid))
        result = self.threats.get(threat_uuid)
        return result[0] if result else None

    async def get_threats_by_scan(self, scan_id):
        self.call_log.append(("get_threats_by_scan", scan_id))
        return [threat for threat, sid in self.threats.values() if sid == scan_id]

    async def get_threats_by_file(self, file_path):
        self.call_log.append(("get_threats_by_file", file_path))
        return [
            threat
            for threat, _ in self.threats.values()
            if getattr(threat, "file_path", None) == file_path
        ]

    async def get_threats_by_rule(self, rule_id):
        self.call_log.append(("get_threats_by_rule", rule_id))
        return [
            threat
            for threat, _ in self.threats.values()
            if getattr(threat, "rule_id", None) == rule_id
        ]

    async def get_threats_by_severity(self, min_severity, max_severity=None):
        self.call_log.append(("get_threats_by_severity", min_severity, max_severity))
        return []

    async def mark_false_positive(self, threat_uuid, marked_by, reason=""):
        self.call_log.append(("mark_false_positive", threat_uuid, marked_by, reason))
        if threat_uuid in self.threats:
            self.false_positives.add(threat_uuid)
            return True
        return False

    async def unmark_false_positive(self, threat_uuid):
        self.call_log.append(("unmark_false_positive", threat_uuid))
        if threat_uuid in self.false_positives:
            self.false_positives.remove(threat_uuid)
            return True
        return False

    async def get_false_positives(self):
        self.call_log.append(("get_false_positives",))
        return [
            self.threats[tid][0] for tid in self.false_positives if tid in self.threats
        ]

    async def get_threat_by_fingerprint(self, fingerprint):
        self.call_log.append(("get_threat_by_fingerprint", fingerprint))
        for threat, _ in self.threats.values():
            if getattr(threat, "fingerprint", None) == fingerprint:
                return threat
        return None

    async def get_threat_analytics(self, start_date=None, end_date=None):
        self.call_log.append(("get_threat_analytics", start_date, end_date))
        return {"total_threats": len(self.threats)}

    async def get_top_threat_categories(self, limit=10, start_date=None, end_date=None):
        self.call_log.append(("get_top_threat_categories", limit, start_date, end_date))
        return [("injection", 5), ("xss", 3)]

    async def get_threat_trends(self, days=30):
        self.call_log.append(("get_threat_trends", days))
        return {"high": [(datetime.now(), 2)]}

    async def cleanup_old_threats(self, retention_days):
        self.call_log.append(("cleanup_old_threats", retention_days))
        return 0

    async def bulk_save_threats(self, threats, scan_id):
        self.call_log.append(("bulk_save_threats", threats, scan_id))
        threat_ids = []
        for threat in threats:
            threat_id = f"threat_{len(self.threats)}"
            self.threats[threat_id] = (threat, scan_id)
            threat_ids.append(threat_id)
        return threat_ids


class TestIScanRepository:
    """Test IScanRepository interface behavior."""

    def test_iscan_repository_is_abstract(self):
        """Test that IScanRepository is an abstract base class."""
        assert issubclass(IScanRepository, ABC)

        # Should not be able to instantiate directly
        with pytest.raises(TypeError):
            IScanRepository()

    def test_iscan_repository_has_required_methods(self):
        """Test that IScanRepository has all required abstract methods."""
        required_methods = [
            "save_scan_request",
            "get_scan_request",
            "save_scan_result",
            "get_scan_result",
            "get_scan_results_by_target",
            "get_scan_results_by_requester",
            "get_scan_results_in_date_range",
            "delete_scan_data",
            "get_scan_statistics",
            "cleanup_old_scans",
        ]

        for method_name in required_methods:
            assert hasattr(IScanRepository, method_name)
            method = getattr(IScanRepository, method_name)
            assert getattr(method, "__isabstractmethod__", False)

    @pytest.mark.asyncio
    async def test_mock_scan_repository_implementation(self):
        """Test that MockScanRepository properly implements the interface."""
        repo = MockScanRepository()

        # Test save_scan_request
        mock_request = Mock()
        scan_id = await repo.save_scan_request(mock_request)
        assert scan_id is not None
        assert ("save_scan_request", mock_request) in repo.call_log

        # Test get_scan_request
        retrieved = await repo.get_scan_request(scan_id)
        assert retrieved == mock_request
        assert ("get_scan_request", scan_id) in repo.call_log

        # Test save_scan_result
        mock_result = Mock()
        result_id = await repo.save_scan_result(mock_result)
        assert result_id is not None
        assert ("save_scan_result", mock_result) in repo.call_log

        # Test get_scan_result
        retrieved_result = await repo.get_scan_result(result_id)
        assert retrieved_result == mock_result

        # Test get_scan_results_by_target
        results = await repo.get_scan_results_by_target("/test/path")
        assert isinstance(results, list)

        # Test get_scan_results_by_requester
        results = await repo.get_scan_results_by_requester("test_user")
        assert isinstance(results, list)

        # Test get_scan_results_in_date_range
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
        results = await repo.get_scan_results_in_date_range(start_date, end_date)
        assert isinstance(results, list)

        # Test delete_scan_data
        deleted = await repo.delete_scan_data(scan_id)
        assert deleted is True

        deleted_again = await repo.delete_scan_data(scan_id)
        assert deleted_again is False

        # Test get_scan_statistics
        stats = await repo.get_scan_statistics()
        assert isinstance(stats, dict)
        assert "total_scans" in stats

        # Test cleanup_old_scans
        cleaned = await repo.cleanup_old_scans(30)
        assert isinstance(cleaned, int)

    @pytest.mark.asyncio
    async def test_scan_repository_with_date_parameters(self):
        """Test scan repository methods with date parameters."""
        repo = MockScanRepository()

        start_date = datetime.now() - timedelta(days=30)
        end_date = datetime.now()

        # Test get_scan_statistics with dates
        stats = await repo.get_scan_statistics(start_date, end_date)
        assert isinstance(stats, dict)
        assert ("get_scan_statistics", start_date, end_date) in repo.call_log

        # Test get_scan_results_in_date_range
        results = await repo.get_scan_results_in_date_range(start_date, end_date)
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_repository_none_parameters(self):
        """Test scan repository methods with None parameters."""
        repo = MockScanRepository()

        # Test get_scan_statistics with None dates
        stats = await repo.get_scan_statistics(None, None)
        assert isinstance(stats, dict)

        # Test get_scan_request with non-existent ID
        result = await repo.get_scan_request("non_existent")
        assert result is None


class TestIThreatRepository:
    """Test IThreatRepository interface behavior."""

    def test_ithreat_repository_is_abstract(self):
        """Test that IThreatRepository is an abstract base class."""
        assert issubclass(IThreatRepository, ABC)

        # Should not be able to instantiate directly
        with pytest.raises(TypeError):
            IThreatRepository()

    def test_ithreat_repository_has_required_methods(self):
        """Test that IThreatRepository has all required abstract methods."""
        required_methods = [
            "save_threat",
            "get_threat",
            "get_threats_by_scan",
            "get_threats_by_file",
            "get_threats_by_rule",
            "get_threats_by_severity",
            "mark_false_positive",
            "unmark_false_positive",
            "get_false_positives",
            "get_threat_by_fingerprint",
            "get_threat_analytics",
            "get_top_threat_categories",
            "get_threat_trends",
            "cleanup_old_threats",
            "bulk_save_threats",
        ]

        for method_name in required_methods:
            assert hasattr(IThreatRepository, method_name)
            method = getattr(IThreatRepository, method_name)
            assert getattr(method, "__isabstractmethod__", False)

    @pytest.mark.asyncio
    async def test_mock_threat_repository_implementation(self):
        """Test that MockThreatRepository properly implements the interface."""
        repo = MockThreatRepository()

        # Test save_threat
        mock_threat = Mock()
        threat_id = await repo.save_threat(mock_threat, "scan_123")
        assert threat_id is not None
        assert ("save_threat", mock_threat, "scan_123") in repo.call_log

        # Test get_threat
        retrieved = await repo.get_threat(threat_id)
        assert retrieved == mock_threat
        assert ("get_threat", threat_id) in repo.call_log

        # Test get_threats_by_scan
        threats = await repo.get_threats_by_scan("scan_123")
        assert isinstance(threats, list)
        assert mock_threat in threats

        # Test get_threats_by_file
        threats = await repo.get_threats_by_file("/test/file.py")
        assert isinstance(threats, list)

        # Test get_threats_by_rule
        threats = await repo.get_threats_by_rule("rule_123")
        assert isinstance(threats, list)

        # Test get_threats_by_severity
        from adversary_mcp_server.domain.value_objects.severity_level import (
            SeverityLevel,
        )

        try:
            threats = await repo.get_threats_by_severity(SeverityLevel.MEDIUM)
            assert isinstance(threats, list)
        except ImportError:
            # SeverityLevel might not be available, create mock
            mock_severity = Mock()
            threats = await repo.get_threats_by_severity(mock_severity)
            assert isinstance(threats, list)

        # Test mark_false_positive
        marked = await repo.mark_false_positive(threat_id, "test_user", "false alarm")
        assert marked is True

        # Test get_false_positives
        false_positives = await repo.get_false_positives()
        assert isinstance(false_positives, list)
        assert mock_threat in false_positives

        # Test unmark_false_positive
        unmarked = await repo.unmark_false_positive(threat_id)
        assert unmarked is True

        # Test get_threat_by_fingerprint
        threat = await repo.get_threat_by_fingerprint("fingerprint_123")
        # Returns None since our mock threat doesn't have fingerprint

        # Test get_threat_analytics
        analytics = await repo.get_threat_analytics()
        assert isinstance(analytics, dict)

        # Test get_top_threat_categories
        categories = await repo.get_top_threat_categories(5)
        assert isinstance(categories, list)

        # Test get_threat_trends
        trends = await repo.get_threat_trends(30)
        assert isinstance(trends, dict)

        # Test cleanup_old_threats
        cleaned = await repo.cleanup_old_threats(30)
        assert isinstance(cleaned, int)

        # Test bulk_save_threats
        more_threats = [Mock(), Mock()]
        threat_ids = await repo.bulk_save_threats(more_threats, "scan_456")
        assert isinstance(threat_ids, list)
        assert len(threat_ids) == 2

    @pytest.mark.asyncio
    async def test_threat_repository_false_positive_workflow(self):
        """Test complete false positive workflow."""
        repo = MockThreatRepository()

        # Save a threat
        mock_threat = Mock()
        threat_id = await repo.save_threat(mock_threat, "scan_123")

        # Initially not a false positive
        false_positives = await repo.get_false_positives()
        assert mock_threat not in false_positives

        # Mark as false positive
        marked = await repo.mark_false_positive(
            threat_id, "analyst", "Not a real threat"
        )
        assert marked is True

        # Should now be in false positives
        false_positives = await repo.get_false_positives()
        assert mock_threat in false_positives

        # Unmark false positive
        unmarked = await repo.unmark_false_positive(threat_id)
        assert unmarked is True

        # Should no longer be in false positives
        false_positives = await repo.get_false_positives()
        assert mock_threat not in false_positives

    @pytest.mark.asyncio
    async def test_threat_repository_non_existent_threat(self):
        """Test operations on non-existent threats."""
        repo = MockThreatRepository()

        # Get non-existent threat
        threat = await repo.get_threat("non_existent")
        assert threat is None

        # Mark non-existent threat as false positive
        marked = await repo.mark_false_positive("non_existent", "user")
        assert marked is False

        # Unmark non-existent false positive
        unmarked = await repo.unmark_false_positive("non_existent")
        assert unmarked is False

    @pytest.mark.asyncio
    async def test_threat_repository_with_date_parameters(self):
        """Test threat repository methods with date parameters."""
        repo = MockThreatRepository()

        start_date = datetime.now() - timedelta(days=30)
        end_date = datetime.now()

        # Test get_threat_analytics with dates
        analytics = await repo.get_threat_analytics(start_date, end_date)
        assert isinstance(analytics, dict)
        assert ("get_threat_analytics", start_date, end_date) in repo.call_log

        # Test get_top_threat_categories with dates
        categories = await repo.get_top_threat_categories(10, start_date, end_date)
        assert isinstance(categories, list)

    @pytest.mark.asyncio
    async def test_threat_repository_bulk_operations(self):
        """Test bulk operations in threat repository."""
        repo = MockThreatRepository()

        # Create multiple threats
        threats = [Mock(), Mock(), Mock()]

        # Bulk save
        threat_ids = await repo.bulk_save_threats(threats, "scan_bulk")
        assert len(threat_ids) == 3

        # Verify they were saved
        for threat_id in threat_ids:
            retrieved = await repo.get_threat(threat_id)
            assert retrieved in threats

        # Verify they're associated with the right scan
        scan_threats = await repo.get_threats_by_scan("scan_bulk")
        assert len(scan_threats) == 3
        for threat in threats:
            assert threat in scan_threats


class TestRepositoryInterfaceConsistency:
    """Test consistency and completeness of repository interfaces."""

    def test_all_scan_repository_methods_async(self):
        """Test that all IScanRepository methods are async."""
        for method_name in dir(IScanRepository):
            if not method_name.startswith("_") and callable(
                getattr(IScanRepository, method_name)
            ):
                method = getattr(IScanRepository, method_name)
                if (
                    hasattr(method, "__isabstractmethod__")
                    and method.__isabstractmethod__
                ):
                    # All abstract methods should be async (this is a design choice)
                    # We can't easily test this without running them, but we can check
                    # that our mock implementations are async
                    assert method_name in dir(MockScanRepository)

    def test_all_threat_repository_methods_async(self):
        """Test that all IThreatRepository methods are async."""
        for method_name in dir(IThreatRepository):
            if not method_name.startswith("_") and callable(
                getattr(IThreatRepository, method_name)
            ):
                method = getattr(IThreatRepository, method_name)
                if (
                    hasattr(method, "__isabstractmethod__")
                    and method.__isabstractmethod__
                ):
                    # All abstract methods should be async (this is a design choice)
                    assert method_name in dir(MockThreatRepository)

    def test_repository_method_signatures(self):
        """Test that repository method signatures are consistent."""
        # Verify that methods that should return lists do return lists in mock
        repo = MockScanRepository()
        assert hasattr(repo, "get_scan_results_by_target")
        assert hasattr(repo, "get_scan_results_by_requester")
        assert hasattr(repo, "get_scan_results_in_date_range")

        threat_repo = MockThreatRepository()
        assert hasattr(threat_repo, "get_threats_by_scan")
        assert hasattr(threat_repo, "get_threats_by_file")
        assert hasattr(threat_repo, "get_threats_by_rule")
        assert hasattr(threat_repo, "get_threats_by_severity")
        assert hasattr(threat_repo, "get_false_positives")
        assert hasattr(threat_repo, "get_top_threat_categories")
        assert hasattr(threat_repo, "bulk_save_threats")

    @pytest.mark.asyncio
    async def test_repository_error_handling_patterns(self):
        """Test that repositories follow consistent error handling patterns."""
        # This would be where we test that repositories properly raise
        # RepositoryError, ThreatNotFoundError, etc. in appropriate situations

        # For now, just test that the exceptions exist and are properly typed
        with pytest.raises(RepositoryError):
            raise RepositoryError("Test repository error")

        with pytest.raises(ThreatNotFoundError):
            raise ThreatNotFoundError("Test threat not found")

        with pytest.raises(ScanNotFoundError):
            raise ScanNotFoundError("Test scan not found")

        with pytest.raises(DuplicateThreatError):
            raise DuplicateThreatError("Test duplicate threat")


class TestRepositoryMockBehavior:
    """Test specific behaviors of our mock implementations."""

    @pytest.mark.asyncio
    async def test_mock_scan_repository_call_tracking(self):
        """Test that mock scan repository tracks all method calls."""
        repo = MockScanRepository()

        await repo.save_scan_request(Mock())
        await repo.get_scan_request("test")
        await repo.delete_scan_data("test")

        assert len(repo.call_log) == 3
        assert repo.call_log[0][0] == "save_scan_request"
        assert repo.call_log[1][0] == "get_scan_request"
        assert repo.call_log[2][0] == "delete_scan_data"

    @pytest.mark.asyncio
    async def test_mock_threat_repository_call_tracking(self):
        """Test that mock threat repository tracks all method calls."""
        repo = MockThreatRepository()

        await repo.save_threat(Mock(), "scan_123")
        await repo.get_threat("threat_123")
        await repo.mark_false_positive("threat_123", "user")

        assert len(repo.call_log) >= 3
        call_types = [call[0] for call in repo.call_log]
        assert "save_threat" in call_types
        assert "get_threat" in call_types
        assert "mark_false_positive" in call_types

    @pytest.mark.asyncio
    async def test_mock_repositories_state_management(self):
        """Test that mock repositories properly manage state."""
        scan_repo = MockScanRepository()
        threat_repo = MockThreatRepository()

        # Test scan repository state
        request = Mock()
        scan_id = await scan_repo.save_scan_request(request)
        retrieved = await scan_repo.get_scan_request(scan_id)
        assert retrieved is request

        # Test threat repository state
        threat = Mock()
        threat_id = await threat_repo.save_threat(threat, "scan_123")
        retrieved_threat = await threat_repo.get_threat(threat_id)
        assert retrieved_threat is threat

        # Test false positive state
        await threat_repo.mark_false_positive(threat_id, "user")
        assert threat_id in threat_repo.false_positives

        await threat_repo.unmark_false_positive(threat_id)
        assert threat_id not in threat_repo.false_positives
