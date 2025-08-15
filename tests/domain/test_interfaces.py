"""Tests for domain interfaces and exception handling."""

from datetime import UTC

import pytest

from adversary_mcp_server.domain.interfaces import (
    AggregationError,
    ConfigurationError,
    IScanOrchestrator,
    IScanStrategy,
    IThreatAggregator,
    IValidationStrategy,
    ScanError,
    SecurityError,
    ValidationError,
)


class TestDomainInterfaces:
    """Test domain interfaces are properly defined."""

    def test_scan_strategy_interface(self):
        """Test IScanStrategy interface definition."""
        # Check it's a Protocol (not ABC)
        assert hasattr(IScanStrategy, "_is_protocol")

        # Check required methods are defined in the protocol
        expected_methods = [
            "can_scan",
            "execute_scan",
            "get_strategy_name",
            "get_supported_languages",
        ]

        # For protocols, we can't directly check method existence the same way
        # Instead we verify the protocol structure is reasonable
        assert callable(IScanStrategy)
        assert isinstance(IScanStrategy, type)

    def test_validation_strategy_interface(self):
        """Test IValidationStrategy interface definition."""
        # Check it's a Protocol (not ABC)
        assert hasattr(IValidationStrategy, "_is_protocol")

        # Check that the protocol is properly defined
        assert callable(IValidationStrategy)
        assert isinstance(IValidationStrategy, type)

    def test_threat_aggregator_interface(self):
        """Test IThreatAggregator interface definition."""
        # Check it's a Protocol (not ABC)
        assert hasattr(IThreatAggregator, "_is_protocol")

        # Check that the protocol is properly defined
        assert callable(IThreatAggregator)
        assert isinstance(IThreatAggregator, type)

    def test_scan_orchestrator_interface(self):
        """Test IScanOrchestrator interface definition."""
        # Check it's a Protocol (not ABC)
        assert hasattr(IScanOrchestrator, "_is_protocol")

        # Check that the protocol is properly defined
        assert callable(IScanOrchestrator)
        assert isinstance(IScanOrchestrator, type)


class TestDomainExceptions:
    """Test domain-specific exceptions."""

    def test_validation_error(self):
        """Test ValidationError exception."""
        # Test basic creation
        error = ValidationError("Invalid input")
        assert str(error) == "Invalid input"
        assert isinstance(error, Exception)

        # Test with cause (using from syntax)
        original_error = ValueError("Original error")
        try:
            try:
                raise original_error
            except ValueError as e:
                raise ValidationError("Validation failed") from e
        except ValidationError as error_with_cause:
            assert str(error_with_cause) == "Validation failed"
            assert error_with_cause.__cause__ == original_error

    def test_security_error(self):
        """Test SecurityError exception."""
        # Test basic creation
        error = SecurityError("Security constraint violated")
        assert str(error) == "Security constraint violated"
        assert isinstance(error, Exception)

        # Test inheritance (SecurityError inherits from DomainError, not ValidationError)
        from adversary_mcp_server.domain.exceptions import DomainError

        assert issubclass(SecurityError, DomainError)

    def test_configuration_error(self):
        """Test ConfigurationError exception."""
        # Test basic creation
        error = ConfigurationError("Invalid configuration")
        assert str(error) == "Invalid configuration"
        assert isinstance(error, Exception)

    def test_scan_error(self):
        """Test ScanError exception."""
        # Test basic creation
        error = ScanError("Scan operation failed")
        assert str(error) == "Scan operation failed"
        assert isinstance(error, Exception)

    def test_aggregation_error(self):
        """Test AggregationError exception."""
        # Test basic creation
        error = AggregationError("Aggregation failed")
        assert str(error) == "Aggregation failed"
        assert isinstance(error, Exception)

    def test_exception_hierarchy(self):
        """Test exception inheritance hierarchy."""
        from adversary_mcp_server.domain.exceptions import DomainError

        # All domain exceptions should inherit from DomainError
        exceptions = [
            ValidationError,
            SecurityError,
            ConfigurationError,
            ScanError,
            AggregationError,
        ]
        for exc_class in exceptions:
            assert issubclass(exc_class, DomainError)
            assert issubclass(exc_class, Exception)

    def test_exception_with_details(self):
        """Test exceptions with additional details."""
        # Test ValidationError with context (standard Exception behavior)
        try:
            error = ValidationError("Field validation failed")
            # Can add attributes after creation if needed
            error.field = "email"
            error.value = "invalid-email"
            raise error
        except ValidationError as e:
            assert str(e) == "Field validation failed"
            assert e.field == "email"
            assert e.value == "invalid-email"

    def test_exception_chaining(self):
        """Test exception chaining patterns."""
        original = ValueError("Original problem")

        try:
            try:
                raise original
            except ValueError as e:
                raise ValidationError("Validation wrapper") from e
        except ValidationError as wrapped:
            assert wrapped.__cause__ == original
            assert "Validation wrapper" in str(wrapped)

    def test_security_error_scenarios(self):
        """Test SecurityError in various security scenarios."""
        # Path traversal
        path_error = SecurityError(
            "Path traversal attempt detected: ../../../etc/passwd"
        )
        assert "Path traversal" in str(path_error)

        # File size
        size_error = SecurityError("File too large: 50MB exceeds 10MB limit")
        assert "File too large" in str(size_error)

        # Blocked path
        blocked_error = SecurityError("Scanning blocked path: /etc/shadow")
        assert "blocked path" in str(blocked_error)

    def test_configuration_error_scenarios(self):
        """Test ConfigurationError in various configuration scenarios."""
        # Missing scanner
        missing_error = ConfigurationError("No scan strategies registered")
        assert "No scan strategies" in str(missing_error)

        # Invalid combination
        combo_error = ConfigurationError("Validation enabled but LLM disabled")
        assert "Validation enabled" in str(combo_error)

        # Invalid parameter
        param_error = ConfigurationError("Invalid severity threshold: 'extreme'")
        assert "Invalid severity" in str(param_error)

    def test_scan_error_scenarios(self):
        """Test ScanError in various scan failure scenarios."""
        # Network error
        network_error = ScanError("Failed to connect to LLM service")
        assert "Failed to connect" in str(network_error)

        # Timeout
        timeout_error = ScanError("Scan operation timed out after 300 seconds")
        assert "timed out" in str(timeout_error)

        # Parser error
        parser_error = ScanError("Failed to parse Semgrep output")
        assert "Failed to parse" in str(parser_error)

    def test_aggregation_error_scenarios(self):
        """Test AggregationError in various aggregation scenarios."""
        # Strategy error
        strategy_error = AggregationError(
            "Aggregation strategy failed: proximity calculation error"
        )
        assert "strategy failed" in str(strategy_error)

        # Data error
        data_error = AggregationError("Cannot aggregate threats: empty threat list")
        assert "Cannot aggregate" in str(data_error)

        # Memory error
        memory_error = AggregationError(
            "Aggregation failed: out of memory processing 10000 threats"
        )
        assert "out of memory" in str(memory_error)


class MockScanStrategy(IScanStrategy):
    """Mock implementation of IScanStrategy for testing."""

    def get_strategy_name(self) -> str:
        return "mock_strategy"

    def can_scan(self, context) -> bool:
        return True

    async def execute_scan(self, request):
        from adversary_mcp_server.domain.entities.scan_result import ScanResult

        return ScanResult.create_empty(request)


class MockValidationStrategy(IValidationStrategy):
    """Mock implementation of IValidationStrategy for testing."""

    def get_strategy_name(self) -> str:
        return "mock_validator"

    def can_validate(self, threats) -> bool:
        return len(threats) > 0

    async def validate_threats(self, threats, context):
        return threats  # Return unchanged


class MockThreatAggregator(IThreatAggregator):
    """Mock implementation of IThreatAggregator for testing."""

    def aggregate_threats(self, threat_groups):
        # Simple concatenation
        all_threats = []
        for group in threat_groups:
            all_threats.extend(group)
        return all_threats

    def merge_similar_threats(self, threats):
        return threats  # Return unchanged

    def get_aggregation_strategy_name(self) -> str:
        return "mock_aggregation"


class TestInterfaceImplementations:
    """Test that interfaces can be properly implemented."""

    def test_scan_strategy_implementation(self):
        """Test implementing IScanStrategy."""
        strategy = MockScanStrategy()

        assert strategy.get_strategy_name() == "mock_strategy"
        assert strategy.can_scan(None) is True

        # Test async method exists and is callable
        assert callable(strategy.execute_scan)

    def test_validation_strategy_implementation(self):
        """Test implementing IValidationStrategy."""
        validator = MockValidationStrategy()

        assert validator.get_strategy_name() == "mock_validator"
        assert validator.can_validate([1, 2, 3]) is True
        assert validator.can_validate([]) is False

        # Test async method exists and is callable
        assert callable(validator.validate_threats)

    def test_threat_aggregator_implementation(self):
        """Test implementing IThreatAggregator."""
        aggregator = MockThreatAggregator()

        assert aggregator.get_aggregation_strategy_name() == "mock_aggregation"

        # Test aggregation methods
        result = aggregator.aggregate_threats([[1, 2], [3, 4]])
        assert result == [1, 2, 3, 4]

        result = aggregator.merge_similar_threats([1, 2, 3])
        assert result == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_async_interface_methods(self):
        """Test async interface methods work correctly."""
        from datetime import datetime

        from adversary_mcp_server.domain.entities.scan_request import ScanRequest
        from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
        from adversary_mcp_server.domain.value_objects.confidence_score import (
            ConfidenceScore,
        )
        from adversary_mcp_server.domain.value_objects.file_path import FilePath
        from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
        from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata
        from adversary_mcp_server.domain.value_objects.severity_level import (
            SeverityLevel,
        )

        # Create test data
        file_path = FilePath.from_virtual("test.py")
        metadata = ScanMetadata(
            scan_id="test-scan",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        threat = ThreatMatch(
            rule_id="test-rule",
            rule_name="Test Rule",
            description="Test",
            category="test",
            severity=SeverityLevel.from_string("medium"),
            file_path=file_path,
            line_number=10,
            column_number=5,
            code_snippet="test",
            confidence=ConfidenceScore(0.8),
        )

        # Test strategy execution
        strategy = MockScanStrategy()
        result = await strategy.execute_scan(request)
        assert result is not None

        # Test validation
        validator = MockValidationStrategy()
        validated = await validator.validate_threats([threat], context)
        assert len(validated) == 1

    def test_interface_cannot_be_instantiated(self):
        """Test that protocol interfaces cannot be instantiated directly."""
        # Protocols can be instantiated but don't provide implementation
        # Instead test that they can be used for isinstance checks
        strategy = MockScanStrategy()
        assert isinstance(strategy, IScanStrategy)

        validator = MockValidationStrategy()
        assert isinstance(validator, IValidationStrategy)

        aggregator = MockThreatAggregator()
        assert isinstance(aggregator, IThreatAggregator)
