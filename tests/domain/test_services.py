"""Comprehensive tests for domain services."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock

import pytest

from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.interfaces import (
    ConfigurationError,
    IScanStrategy,
    IValidationStrategy,
    SecurityError,
    ValidationError,
)
from adversary_mcp_server.domain.services.scan_orchestrator import ScanOrchestrator
from adversary_mcp_server.domain.services.threat_aggregator import (
    FingerprintBasedAggregationStrategy,
    HybridAggregationStrategy,
    ProximityBasedAggregationStrategy,
    ThreatAggregator,
)
from adversary_mcp_server.domain.services.validation_service import ValidationService
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class TestScanOrchestrator:
    """Test ScanOrchestrator service."""

    @pytest.fixture
    def orchestrator(self):
        """Create ScanOrchestrator instance."""
        return ScanOrchestrator()

    @pytest.fixture
    def mock_scan_strategy(self):
        """Create mock scan strategy."""
        strategy = Mock(spec=IScanStrategy)
        strategy.get_strategy_name.return_value = "mock_semgrep"
        strategy.can_scan.return_value = True
        strategy.execute_scan = AsyncMock()
        return strategy

    @pytest.fixture
    def mock_validation_strategy(self):
        """Create mock validation strategy."""
        strategy = Mock(spec=IValidationStrategy)
        strategy.get_strategy_name.return_value = "mock_llm_validator"
        strategy.can_validate.return_value = True
        strategy.validate_threats = AsyncMock()
        return strategy

    @pytest.fixture
    def sample_scan_request(self):
        """Create sample scan request."""
        file_path = FilePath.from_virtual("test.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        return ScanRequest(context=context)

    @pytest.fixture
    def sample_threat(self):
        """Create sample threat."""
        return ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test vulnerability",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=FilePath.from_string("/home/user/test.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.8),
        )

    def test_register_scan_strategy(self, orchestrator, mock_scan_strategy):
        """Test registering scan strategy."""
        orchestrator.register_scan_strategy(mock_scan_strategy)

        strategies = orchestrator.get_registered_strategies()
        assert "mock_semgrep" in strategies["scan_strategies"]

    def test_register_validation_strategy(self, orchestrator, mock_validation_strategy):
        """Test registering validation strategy."""
        orchestrator.register_validation_strategy(mock_validation_strategy)

        strategies = orchestrator.get_registered_strategies()
        assert "mock_llm_validator" in strategies["validation_strategies"]

    def test_set_threat_aggregator(self, orchestrator):
        """Test setting threat aggregator."""
        aggregator = Mock()
        aggregator.get_aggregation_strategy_name.return_value = "hybrid"

        orchestrator.set_threat_aggregator(aggregator)

        strategies = orchestrator.get_registered_strategies()
        assert strategies["threat_aggregator"] == ["hybrid"]

    @pytest.mark.asyncio
    async def test_execute_scan_no_strategies(self, orchestrator, sample_scan_request):
        """Test executing scan with no strategies raises error."""
        with pytest.raises(
            ConfigurationError, match="No registered strategies can scan"
        ):
            await orchestrator.execute_scan(sample_scan_request)

    @pytest.mark.asyncio
    async def test_execute_scan_successful(
        self, orchestrator, mock_scan_strategy, sample_scan_request, sample_threat
    ):
        """Test successful scan execution."""
        # Setup mock strategy to return a result
        mock_result = ScanResult.create_from_threats(
            request=sample_scan_request,
            threats=[sample_threat],
            scan_metadata={"scanner": "mock_semgrep"},
        )
        mock_scan_strategy.execute_scan.return_value = mock_result

        orchestrator.register_scan_strategy(mock_scan_strategy)

        result = await orchestrator.execute_scan(sample_scan_request)

        assert result is not None
        assert len(result.threats) == 1
        assert result.threats[0] == sample_threat
        mock_scan_strategy.execute_scan.assert_called_once_with(sample_scan_request)

    @pytest.mark.asyncio
    async def test_execute_scan_with_validation(
        self,
        orchestrator,
        mock_scan_strategy,
        mock_validation_strategy,
        sample_scan_request,
        sample_threat,
    ):
        """Test scan execution with validation."""
        # Setup mock strategy to return a result
        mock_result = ScanResult.create_from_threats(
            request=sample_scan_request,
            threats=[sample_threat],
            scan_metadata={"scanner": "mock_semgrep"},
        )
        mock_scan_strategy.execute_scan.return_value = mock_result

        # Setup validation to return filtered threats
        validated_threat = sample_threat.update_confidence(ConfidenceScore(0.9))
        mock_validation_strategy.validate_threats.return_value = [validated_threat]

        orchestrator.register_scan_strategy(mock_scan_strategy)
        orchestrator.register_validation_strategy(mock_validation_strategy)

        result = await orchestrator.execute_scan(sample_scan_request)

        assert result is not None
        assert len(result.threats) == 1
        assert result.threats[0].confidence == ConfidenceScore(0.9)
        mock_validation_strategy.validate_threats.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_scan_strategy_failure(
        self, orchestrator, mock_scan_strategy, sample_scan_request
    ):
        """Test scan execution with strategy failure."""
        # Setup mock strategy to fail
        mock_scan_strategy.execute_scan.side_effect = Exception("Strategy failed")

        orchestrator.register_scan_strategy(mock_scan_strategy)

        result = await orchestrator.execute_scan(sample_scan_request)

        # Should return empty result instead of failing
        assert result is not None
        assert len(result.threats) == 0

    def test_can_execute_scan(
        self, orchestrator, mock_scan_strategy, sample_scan_request
    ):
        """Test can_execute_scan method."""
        # No strategies - cannot execute
        assert not orchestrator.can_execute_scan(sample_scan_request)

        # With strategy - can execute
        orchestrator.register_scan_strategy(mock_scan_strategy)
        assert orchestrator.can_execute_scan(sample_scan_request)

    @pytest.mark.asyncio
    async def test_severity_filtering(
        self, orchestrator, mock_scan_strategy, sample_scan_request
    ):
        """Test severity filtering."""
        # Create threats with different severities
        high_threat = ThreatMatch(
            rule_id="high-rule",
            rule_name="High Rule",
            description="High severity",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=FilePath.from_string("/home/user/test.py"),
            line_number=42,
            column_number=10,
            code_snippet="test",
            confidence=ConfidenceScore(0.8),
        )

        low_threat = ThreatMatch(
            rule_id="low-rule",
            rule_name="Low Rule",
            description="Low severity",
            category="disclosure",
            severity=SeverityLevel.from_string("low"),
            file_path=FilePath.from_string("/home/user/test.py"),
            line_number=50,
            column_number=5,
            code_snippet="test",
            confidence=ConfidenceScore(0.6),
        )

        mock_result = ScanResult.create_from_threats(
            request=sample_scan_request,
            threats=[high_threat, low_threat],
            scan_metadata={},
        )
        mock_scan_strategy.execute_scan.return_value = mock_result

        # Set high severity threshold
        high_threshold_request = ScanRequest(
            context=sample_scan_request.context,
            severity_threshold=SeverityLevel.from_string("high"),
        )

        orchestrator.register_scan_strategy(mock_scan_strategy)

        result = await orchestrator.execute_scan(high_threshold_request)

        # Should only include high severity threat
        assert len(result.threats) == 1
        assert result.threats[0].severity == SeverityLevel.from_string("high")


class TestThreatAggregator:
    """Test ThreatAggregator service and strategies."""

    def test_proximity_based_strategy(self):
        """Test ProximityBasedAggregationStrategy."""
        strategy = ProximityBasedAggregationStrategy(proximity_threshold=3)

        assert strategy.get_strategy_name() == "proximity_based(threshold=3)"

        # Create threats at different distances
        threat1 = ThreatMatch(
            rule_id="rule-1",
            rule_name="Rule 1",
            description="Test",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=FilePath.from_string("/test.py"),
            line_number=10,
            column_number=1,
            code_snippet="test",
            confidence=ConfidenceScore(0.8),
        )

        threat2 = ThreatMatch(
            rule_id="rule-2",
            rule_name="Rule 2",
            description="Test",
            category="injection",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("/test.py"),
            line_number=12,  # Within threshold
            column_number=1,
            code_snippet="test",
            confidence=ConfidenceScore(0.7),
        )

        threat3 = ThreatMatch(
            rule_id="rule-3",
            rule_name="Rule 3",
            description="Test",
            category="injection",
            severity=SeverityLevel.from_string("low"),
            file_path=FilePath.from_string("/test.py"),
            line_number=20,  # Outside threshold
            column_number=1,
            code_snippet="test",
            confidence=ConfidenceScore(0.6),
        )

        threats = [threat1, threat2, threat3]
        merged = strategy.merge_similar_threats(threats)

        # Should merge threat1 and threat2, keep threat3 separate
        assert len(merged) == 2

    def test_fingerprint_based_strategy(self):
        """Test FingerprintBasedAggregationStrategy."""
        strategy = FingerprintBasedAggregationStrategy()

        assert strategy.get_strategy_name() == "fingerprint_based"

        # Create threats with same fingerprint
        threat1 = ThreatMatch(
            rule_id="rule-1",
            rule_name="Rule 1",
            description="Test",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=FilePath.from_string("/test.py"),
            line_number=10,
            column_number=1,
            code_snippet="test",
            confidence=ConfidenceScore(0.8),
        )

        # Identical threat (different rule_id)
        threat2 = ThreatMatch(
            rule_id="rule-2",
            rule_name="Rule 2",
            description="Test",
            category="injection",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("/test.py"),
            line_number=10,
            column_number=1,
            code_snippet="test",
            confidence=ConfidenceScore(0.7),
        )

        threats = [threat1, threat2]
        merged = strategy.merge_similar_threats(threats)

        # Should merge into single threat with higher confidence
        assert len(merged) == 1
        assert merged[0].confidence == ConfidenceScore(0.8)

    def test_hybrid_strategy(self):
        """Test HybridAggregationStrategy."""
        strategy = HybridAggregationStrategy(proximity_threshold=5)

        assert "hybrid" in strategy.get_strategy_name()
        assert "proximity_threshold=5" in strategy.get_strategy_name()

        # Create mix of threats for testing
        threats = [
            ThreatMatch(
                rule_id="rule-1",
                rule_name="Rule 1",
                description="Test",
                category="injection",
                severity=SeverityLevel.from_string("high"),
                file_path=FilePath.from_string("/test.py"),
                line_number=10,
                column_number=1,
                code_snippet="test",
                confidence=ConfidenceScore(0.8),
            ),
            # Duplicate fingerprint
            ThreatMatch(
                rule_id="rule-2",
                rule_name="Rule 2",
                description="Test",
                category="injection",
                severity=SeverityLevel.from_string("medium"),
                file_path=FilePath.from_string("/test.py"),
                line_number=10,
                column_number=1,
                code_snippet="test",
                confidence=ConfidenceScore(0.7),
            ),
            # Close proximity
            ThreatMatch(
                rule_id="rule-3",
                rule_name="Rule 3",
                description="Test",
                category="injection",
                severity=SeverityLevel.from_string("low"),
                file_path=FilePath.from_string("/test.py"),
                line_number=12,
                column_number=1,
                code_snippet="different test",
                confidence=ConfidenceScore(0.6),
            ),
        ]

        merged = strategy.merge_similar_threats(threats)

        # Should apply both fingerprint and proximity merging
        assert len(merged) <= len(threats)

    def test_threat_aggregator_with_strategy(self):
        """Test ThreatAggregator with different strategies."""
        aggregator = ThreatAggregator()

        # Test default strategy
        assert isinstance(aggregator.strategy, HybridAggregationStrategy)

        # Test setting different strategy
        proximity_strategy = ProximityBasedAggregationStrategy(proximity_threshold=10)
        aggregator.set_strategy(proximity_strategy)

        assert aggregator.strategy == proximity_strategy
        assert (
            aggregator.get_aggregation_strategy_name()
            == "proximity_based(threshold=10)"
        )

    def test_threat_aggregator_statistics(self):
        """Test ThreatAggregator statistics."""
        aggregator = ThreatAggregator()

        # Create test threats
        threats_group1 = [
            ThreatMatch(
                rule_id="rule-1",
                rule_name="Rule 1",
                description="Test",
                category="injection",
                severity=SeverityLevel.from_string("high"),
                file_path=FilePath.from_string("/test.py"),
                line_number=10,
                column_number=1,
                code_snippet="test",
                confidence=ConfidenceScore(0.8),
            )
        ]

        threats_group2 = [
            ThreatMatch(
                rule_id="rule-2",
                rule_name="Rule 2",
                description="Test",
                category="xss",
                severity=SeverityLevel.from_string("medium"),
                file_path=FilePath.from_string("/test.py"),
                line_number=20,
                column_number=1,
                code_snippet="test",
                confidence=ConfidenceScore(0.7),
            )
        ]

        result = aggregator.aggregate_threats([threats_group1, threats_group2])

        stats = aggregator.get_statistics(original_count=2, final_count=len(result))

        assert stats["original_threat_count"] == 2
        assert stats["final_threat_count"] == len(result)
        assert stats["threats_merged"] == 2 - len(result)
        assert "strategy" in stats


class TestValidationService:
    """Test ValidationService."""

    @pytest.fixture
    def validation_service(self):
        """Create ValidationService instance."""
        return ValidationService()

    @pytest.fixture
    def sample_scan_request(self):
        """Create sample scan request."""
        file_path = FilePath.from_virtual("test.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        return ScanRequest(context=context)

    @pytest.fixture
    def sample_threat(self):
        """Create sample threat."""
        return ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test vulnerability",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=FilePath.from_string("/home/user/test.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.8),
        )

    def test_validate_scan_request_valid(self, validation_service, sample_scan_request):
        """Test validating valid scan request."""
        # Should not raise any exceptions
        validation_service.validate_scan_request(sample_scan_request)

    def test_validate_scan_request_invalid_no_scanners(self, validation_service):
        """Test validating scan request with no scanners enabled."""
        file_path = FilePath.from_virtual("test.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        with pytest.raises(
            ValidationError, match="At least one scanner must be enabled"
        ):
            invalid_request = ScanRequest(
                context=context, enable_semgrep=False, enable_llm=False
            )
            validation_service.validate_scan_request(invalid_request)

    def test_validate_scan_request_validation_without_llm(self, validation_service):
        """Test validating scan request with validation but no LLM (should succeed)."""
        file_path = FilePath.from_virtual("test.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        # This should now succeed - validation can work independently of LLM scanning
        valid_request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=True,
        )
        # Should not raise any exceptions
        validation_service.validate_scan_request(valid_request)

    def test_validate_threat_data_valid(self, validation_service, sample_threat):
        """Test validating valid threat data."""
        # Should not raise any exceptions
        validation_service.validate_threat_data(sample_threat)

    def test_validate_threat_data_invalid_line_number(self, validation_service):
        """Test that invalid line number is caught at entity level."""
        # Entity validation should prevent creation of threat with invalid line number
        with pytest.raises(ValidationError, match="Line number must be positive"):
            ThreatMatch(
                rule_id="test-rule-001",
                rule_name="Test Rule",
                description="Test vulnerability",
                category="injection",
                severity=SeverityLevel.from_string("high"),
                file_path=FilePath.from_string("/home/user/test.py"),
                line_number=0,  # Invalid
                column_number=10,
                code_snippet="test code",
                confidence=ConfidenceScore(0.8),
            )

    def test_validate_scan_result_valid(
        self, validation_service, sample_scan_request, sample_threat
    ):
        """Test validating valid scan result."""
        result = ScanResult.create_from_threats(
            request=sample_scan_request, threats=[sample_threat], scan_metadata={}
        )

        # Should not raise any exceptions
        validation_service.validate_scan_result(result)

    def test_enforce_security_constraints_valid(
        self, validation_service, sample_scan_request
    ):
        """Test enforcing security constraints on valid request."""
        # Should not raise any exceptions
        validation_service.enforce_security_constraints(sample_scan_request.context)

    def test_enforce_security_constraints_blocked_path(self, validation_service):
        """Test enforcing security constraints on blocked path."""
        blocked_path = FilePath.from_string("/home/user/.ssh/id_rsa")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=blocked_path, metadata=metadata)

        with pytest.raises(SecurityError, match="Scanning blocked path"):
            validation_service.enforce_security_constraints(context)

    def test_update_security_constraints(self, validation_service):
        """Test updating security constraints."""
        original_constraints = validation_service.get_security_constraints()

        validation_service.update_security_constraints(
            max_file_size_bytes=5 * 1024 * 1024,  # 5MB
            additional_blocked_patterns={r".*\.secret$"},
        )

        updated_constraints = validation_service.get_security_constraints()

        assert updated_constraints["max_file_size_bytes"] == 5 * 1024 * 1024
        assert r".*\.secret$" in updated_constraints["blocked_path_patterns"]

    def test_code_scan_constraints(self, validation_service):
        """Test code scan size constraints."""
        # Create large code content
        large_content = "print('test')\n" * 2000  # Exceeds default limit

        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="code",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(
            target_path=None, metadata=metadata, content=large_content
        )

        with pytest.raises(SecurityError, match="Code snippet too large"):
            validation_service.enforce_security_constraints(context)
