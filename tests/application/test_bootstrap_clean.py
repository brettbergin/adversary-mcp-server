"""Tests for simplified Clean Architecture bootstrap."""

from unittest.mock import Mock, patch

from adversary_mcp_server.application.bootstrap_clean import CleanArchitectureBootstrap
from adversary_mcp_server.domain.interfaces import IScanStrategy, IValidationStrategy
from adversary_mcp_server.domain.services.scan_orchestrator import ScanOrchestrator
from adversary_mcp_server.domain.services.threat_aggregator import ThreatAggregator
from adversary_mcp_server.domain.services.validation_service import ValidationService


class TestCleanArchitectureBootstrap:
    """Test cases for simplified CleanArchitectureBootstrap."""

    def setup_method(self):
        """Set up test fixtures."""
        # Clear cache before each test to ensure isolation
        CleanArchitectureBootstrap.clear_cache()

    def test_get_threat_aggregator(self):
        """Test getting threat aggregator."""
        aggregator = CleanArchitectureBootstrap.get_threat_aggregator()

        assert isinstance(aggregator, ThreatAggregator)

        # Test caching - should return same instance
        aggregator2 = CleanArchitectureBootstrap.get_threat_aggregator()
        assert aggregator is aggregator2

    def test_get_validation_service(self):
        """Test getting validation service."""
        service = CleanArchitectureBootstrap.get_validation_service()

        assert isinstance(service, ValidationService)

        # Test caching
        service2 = CleanArchitectureBootstrap.get_validation_service()
        assert service is service2

    @patch("adversary_mcp_server.application.bootstrap_clean.SemgrepScanStrategy")
    @patch("adversary_mcp_server.application.bootstrap_clean.LLMScanStrategy")
    def test_get_scan_strategies_success(
        self, mock_llm_strategy, mock_semgrep_strategy
    ):
        """Test getting scan strategies when both are available."""
        # Setup mocks
        mock_semgrep_instance = Mock(spec=IScanStrategy)
        mock_llm_instance = Mock(spec=IScanStrategy)
        mock_semgrep_strategy.return_value = mock_semgrep_instance
        mock_llm_strategy.return_value = mock_llm_instance

        strategies = CleanArchitectureBootstrap.get_scan_strategies()

        assert len(strategies) == 2
        assert mock_semgrep_instance in strategies
        assert mock_llm_instance in strategies

        # Test caching
        strategies2 = CleanArchitectureBootstrap.get_scan_strategies()
        assert strategies is strategies2

    @patch("adversary_mcp_server.application.bootstrap_clean.SemgrepScanStrategy")
    @patch("adversary_mcp_server.application.bootstrap_clean.LLMScanStrategy")
    def test_get_scan_strategies_failures(
        self, mock_llm_strategy, mock_semgrep_strategy
    ):
        """Test getting scan strategies when some fail to initialize."""
        # Setup mocks - Semgrep fails, LLM succeeds
        mock_llm_instance = Mock(spec=IScanStrategy)
        mock_semgrep_strategy.side_effect = Exception("Semgrep not available")
        mock_llm_strategy.return_value = mock_llm_instance

        strategies = CleanArchitectureBootstrap.get_scan_strategies()

        assert len(strategies) == 1
        assert mock_llm_instance in strategies

    @patch("adversary_mcp_server.application.bootstrap_clean.SemgrepScanStrategy")
    @patch("adversary_mcp_server.application.bootstrap_clean.LLMScanStrategy")
    def test_get_scan_strategies_all_fail(
        self, mock_llm_strategy, mock_semgrep_strategy
    ):
        """Test getting scan strategies when all fail to initialize."""
        # Setup mocks - both fail
        mock_semgrep_strategy.side_effect = Exception("Semgrep not available")
        mock_llm_strategy.side_effect = Exception("LLM not available")

        strategies = CleanArchitectureBootstrap.get_scan_strategies()

        assert len(strategies) == 0
        assert strategies == []

    @patch("adversary_mcp_server.application.bootstrap_clean.LLMValidationStrategy")
    def test_get_validation_strategies_success(self, mock_llm_validation):
        """Test getting validation strategies when LLM validation is available."""
        # Setup mock
        mock_validation_instance = Mock(spec=IValidationStrategy)
        mock_llm_validation.return_value = mock_validation_instance

        strategies = CleanArchitectureBootstrap.get_validation_strategies()

        assert len(strategies) == 1
        assert mock_validation_instance in strategies

        # Test caching
        strategies2 = CleanArchitectureBootstrap.get_validation_strategies()
        assert strategies is strategies2

    @patch("adversary_mcp_server.application.bootstrap_clean.LLMValidationStrategy")
    def test_get_validation_strategies_failure(self, mock_llm_validation):
        """Test getting validation strategies when LLM validation fails."""
        # Setup mock to fail
        mock_llm_validation.side_effect = Exception("LLM validation not available")

        strategies = CleanArchitectureBootstrap.get_validation_strategies()

        assert len(strategies) == 0
        assert strategies == []

    def test_get_scan_orchestrator(self):
        """Test getting scan orchestrator."""
        orchestrator = CleanArchitectureBootstrap.get_scan_orchestrator()

        assert isinstance(orchestrator, ScanOrchestrator)

        # Test caching
        orchestrator2 = CleanArchitectureBootstrap.get_scan_orchestrator()
        assert orchestrator is orchestrator2

    def test_create_for_testing(self):
        """Test creating orchestrator for testing with custom strategies."""
        # Create mock strategies
        mock_scan_strategies = [Mock(spec=IScanStrategy), Mock(spec=IScanStrategy)]
        mock_validation_strategies = [Mock(spec=IValidationStrategy)]

        # Create orchestrator with custom strategies
        orchestrator = CleanArchitectureBootstrap.create_for_testing(
            scan_strategies=mock_scan_strategies,
            validation_strategies=mock_validation_strategies,
        )

        assert isinstance(orchestrator, ScanOrchestrator)
        # Note: The exact checking of internal state depends on orchestrator implementation
        # We can verify it was created successfully

    def test_create_for_testing_with_defaults(self):
        """Test creating orchestrator for testing with default strategies."""
        # Create orchestrator using defaults
        orchestrator = CleanArchitectureBootstrap.create_for_testing()

        assert isinstance(orchestrator, ScanOrchestrator)

    def test_clear_cache(self):
        """Test cache clearing functionality."""
        # Get some cached instances
        aggregator1 = CleanArchitectureBootstrap.get_threat_aggregator()
        service1 = CleanArchitectureBootstrap.get_validation_service()

        # Clear cache
        CleanArchitectureBootstrap.clear_cache()

        # Get instances again - should be different due to cache clear
        aggregator2 = CleanArchitectureBootstrap.get_threat_aggregator()
        service2 = CleanArchitectureBootstrap.get_validation_service()

        # Since we cleared cache, new instances should be created
        assert aggregator1 is not aggregator2
        assert service1 is not service2

    @patch("adversary_mcp_server.application.bootstrap_clean.SemgrepScanStrategy")
    @patch("adversary_mcp_server.application.bootstrap_clean.LLMScanStrategy")
    def test_full_integration_flow(self, mock_llm_strategy, mock_semgrep_strategy):
        """Test full integration flow with all services."""
        # Setup successful mocks
        mock_semgrep_instance = Mock(spec=IScanStrategy)
        mock_llm_instance = Mock(spec=IScanStrategy)
        mock_semgrep_strategy.return_value = mock_semgrep_instance
        mock_llm_strategy.return_value = mock_llm_instance

        # Get all services
        scan_strategies = CleanArchitectureBootstrap.get_scan_strategies()
        validation_strategies = CleanArchitectureBootstrap.get_validation_strategies()
        orchestrator = CleanArchitectureBootstrap.get_scan_orchestrator()
        aggregator = CleanArchitectureBootstrap.get_threat_aggregator()
        validation_service = CleanArchitectureBootstrap.get_validation_service()

        # Verify all services are properly configured
        assert len(scan_strategies) == 2
        assert isinstance(orchestrator, ScanOrchestrator)
        assert isinstance(aggregator, ThreatAggregator)
        assert isinstance(validation_service, ValidationService)

    def test_error_handling_in_strategy_creation(self):
        """Test that strategy creation errors are handled gracefully."""
        # Test that _create_strategy_safely handles exceptions properly
        from adversary_mcp_server.application.bootstrap_clean import (
            _create_strategy_safely,
        )

        # Mock a class that raises an exception
        class FailingStrategy:
            def __init__(self):
                raise RuntimeError("Strategy initialization failed")

        result = _create_strategy_safely(FailingStrategy, "test_strategy")
        assert result is None

    def test_successful_strategy_creation(self):
        """Test successful strategy creation."""
        from adversary_mcp_server.application.bootstrap_clean import (
            _create_strategy_safely,
        )

        # Mock a successful strategy
        class SuccessfulStrategy:
            def __init__(self):
                pass

        result = _create_strategy_safely(SuccessfulStrategy, "test_strategy")
        assert isinstance(result, SuccessfulStrategy)
