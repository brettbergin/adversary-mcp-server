"""Tests for Clean Architecture bootstrap."""

from unittest.mock import Mock, patch

from adversary_mcp_server.application.bootstrap_clean import CleanArchitectureBootstrap
from adversary_mcp_server.domain.interfaces import IScanStrategy, IValidationStrategy
from adversary_mcp_server.domain.services.scan_orchestrator import ScanOrchestrator
from adversary_mcp_server.domain.services.threat_aggregator import ThreatAggregator
from adversary_mcp_server.domain.services.validation_service import ValidationService


class TestCleanArchitectureBootstrap:
    """Test cases for CleanArchitectureBootstrap."""

    def setup_method(self):
        """Set up test fixtures."""
        self.bootstrap = CleanArchitectureBootstrap()

    def test_init(self):
        """Test bootstrap initialization."""
        assert self.bootstrap._scan_strategies is None
        assert self.bootstrap._validation_strategies is None
        assert self.bootstrap._scan_orchestrator is None
        assert self.bootstrap._threat_aggregator is None
        assert self.bootstrap._validation_service is None

    def test_get_threat_aggregator(self):
        """Test getting threat aggregator."""
        aggregator = self.bootstrap.get_threat_aggregator()

        assert isinstance(aggregator, ThreatAggregator)
        assert self.bootstrap._threat_aggregator is aggregator

        # Test caching - should return same instance
        aggregator2 = self.bootstrap.get_threat_aggregator()
        assert aggregator is aggregator2

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

        strategies = self.bootstrap.get_scan_strategies()

        assert len(strategies) == 2
        assert mock_semgrep_instance in strategies
        assert mock_llm_instance in strategies
        assert self.bootstrap._scan_strategies is strategies

        # Test caching
        strategies2 = self.bootstrap.get_scan_strategies()
        assert strategies is strategies2

    @patch("adversary_mcp_server.application.bootstrap_clean.SemgrepScanStrategy")
    @patch("adversary_mcp_server.application.bootstrap_clean.LLMScanStrategy")
    def test_get_scan_strategies_semgrep_fails(
        self, mock_llm_strategy, mock_semgrep_strategy
    ):
        """Test getting scan strategies when Semgrep fails to initialize."""
        # Setup mocks - Semgrep fails, LLM succeeds
        mock_llm_instance = Mock(spec=IScanStrategy)
        mock_semgrep_strategy.side_effect = Exception("Semgrep not available")
        mock_llm_strategy.return_value = mock_llm_instance

        strategies = self.bootstrap.get_scan_strategies()

        assert len(strategies) == 1
        assert mock_llm_instance in strategies

    @patch("adversary_mcp_server.application.bootstrap_clean.SemgrepScanStrategy")
    @patch("adversary_mcp_server.application.bootstrap_clean.LLMScanStrategy")
    def test_get_scan_strategies_llm_fails(
        self, mock_llm_strategy, mock_semgrep_strategy
    ):
        """Test getting scan strategies when LLM fails to initialize."""
        # Setup mocks - Semgrep succeeds, LLM fails
        mock_semgrep_instance = Mock(spec=IScanStrategy)
        mock_semgrep_strategy.return_value = mock_semgrep_instance
        mock_llm_strategy.side_effect = Exception("LLM not available")

        strategies = self.bootstrap.get_scan_strategies()

        assert len(strategies) == 1
        assert mock_semgrep_instance in strategies

    @patch("adversary_mcp_server.application.bootstrap_clean.SemgrepScanStrategy")
    @patch("adversary_mcp_server.application.bootstrap_clean.LLMScanStrategy")
    def test_get_scan_strategies_both_fail(
        self, mock_llm_strategy, mock_semgrep_strategy
    ):
        """Test getting scan strategies when both fail to initialize."""
        # Setup mocks - both fail
        mock_semgrep_strategy.side_effect = Exception("Semgrep not available")
        mock_llm_strategy.side_effect = Exception("LLM not available")

        strategies = self.bootstrap.get_scan_strategies()

        assert len(strategies) == 0
        assert strategies == []

    @patch("adversary_mcp_server.application.bootstrap_clean.LLMValidationStrategy")
    def test_get_validation_strategies_success(self, mock_llm_validation):
        """Test getting validation strategies when LLM validation is available."""
        # Setup mock
        mock_validation_instance = Mock(spec=IValidationStrategy)
        mock_llm_validation.return_value = mock_validation_instance

        strategies = self.bootstrap.get_validation_strategies()

        assert len(strategies) == 1
        assert mock_validation_instance in strategies
        assert self.bootstrap._validation_strategies is strategies

        # Test caching
        strategies2 = self.bootstrap.get_validation_strategies()
        assert strategies is strategies2

    @patch("adversary_mcp_server.application.bootstrap_clean.LLMValidationStrategy")
    def test_get_validation_strategies_llm_fails(self, mock_llm_validation):
        """Test getting validation strategies when LLM validation fails."""
        # Setup mock to fail
        mock_llm_validation.side_effect = Exception("LLM validation not available")

        strategies = self.bootstrap.get_validation_strategies()

        assert len(strategies) == 0
        assert strategies == []

    def test_get_scan_orchestrator(self):
        """Test getting scan orchestrator."""
        # Mock the scan strategies
        mock_strategies = [Mock(spec=IScanStrategy), Mock(spec=IScanStrategy)]
        self.bootstrap._scan_strategies = mock_strategies
        self.bootstrap._validation_strategies = []

        orchestrator = self.bootstrap.get_scan_orchestrator()

        assert isinstance(orchestrator, ScanOrchestrator)
        assert self.bootstrap._scan_orchestrator is orchestrator

        # Test caching
        orchestrator2 = self.bootstrap.get_scan_orchestrator()
        assert orchestrator is orchestrator2

    def test_get_validation_service(self):
        """Test getting validation service."""
        service = self.bootstrap.get_validation_service()

        assert isinstance(service, ValidationService)
        assert self.bootstrap._validation_service is service

        # Test caching
        service2 = self.bootstrap.get_validation_service()
        assert service is service2

    def test_get_validation_service_no_strategies(self):
        """Test getting validation service with no strategies."""
        service = self.bootstrap.get_validation_service()

        assert isinstance(service, ValidationService)

    def test_create_with_mock_strategies(self):
        """Test creating bootstrap with mock strategies."""
        # Create mock strategies
        mock_scan_strategies = [Mock(spec=IScanStrategy), Mock(spec=IScanStrategy)]
        mock_validation_strategies = [Mock(spec=IValidationStrategy)]

        # Create bootstrap with mocks
        mock_bootstrap = self.bootstrap.create_with_mock_strategies(
            scan_strategies=mock_scan_strategies,
            validation_strategies=mock_validation_strategies,
        )

        assert isinstance(mock_bootstrap, CleanArchitectureBootstrap)
        assert mock_bootstrap._scan_strategies == mock_scan_strategies
        assert mock_bootstrap._validation_strategies == mock_validation_strategies

        # Test that strategies are returned correctly
        assert mock_bootstrap.get_scan_strategies() == mock_scan_strategies
        assert mock_bootstrap.get_validation_strategies() == mock_validation_strategies

    def test_create_with_mock_strategies_no_validation(self):
        """Test creating bootstrap with mock scan strategies only."""
        mock_scan_strategies = [Mock(spec=IScanStrategy)]

        mock_bootstrap = self.bootstrap.create_with_mock_strategies(
            scan_strategies=mock_scan_strategies
        )

        assert mock_bootstrap._scan_strategies == mock_scan_strategies
        assert mock_bootstrap._validation_strategies == []

    def test_integration_scan_orchestrator_with_strategies(self):
        """Test integration between scan orchestrator and strategies."""
        # Create mock strategies with proper interface
        mock_strategy1 = Mock(spec=IScanStrategy)
        mock_strategy1.get_strategy_name.return_value = "strategy1"
        mock_strategy2 = Mock(spec=IScanStrategy)
        mock_strategy2.get_strategy_name.return_value = "strategy2"

        # Use mock strategies
        self.bootstrap._scan_strategies = [mock_strategy1, mock_strategy2]
        self.bootstrap._validation_strategies = []

        orchestrator = self.bootstrap.get_scan_orchestrator()

        # Verify orchestrator has the strategies
        assert len(orchestrator._scan_strategies) == 2
        assert mock_strategy1 in orchestrator._scan_strategies
        assert mock_strategy2 in orchestrator._scan_strategies

    def test_integration_validation_service_with_strategies(self):
        """Test integration between validation service and strategies."""
        # ValidationService doesn't take strategies in constructor, just test creation
        service = self.bootstrap.get_validation_service()

        # Verify service is created properly
        assert isinstance(service, ValidationService)

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
        scan_strategies = self.bootstrap.get_scan_strategies()
        validation_strategies = self.bootstrap.get_validation_strategies()
        orchestrator = self.bootstrap.get_scan_orchestrator()
        aggregator = self.bootstrap.get_threat_aggregator()
        validation_service = self.bootstrap.get_validation_service()

        # Verify all services are properly configured
        assert len(scan_strategies) == 2
        assert isinstance(orchestrator, ScanOrchestrator)
        assert isinstance(aggregator, ThreatAggregator)
        assert isinstance(validation_service, ValidationService)

        # Verify orchestrator uses the strategies
        assert len(orchestrator._scan_strategies) == len(scan_strategies)

    def test_lazy_initialization(self):
        """Test that services are lazily initialized."""
        # Initially, all services should be None
        assert self.bootstrap._scan_strategies is None
        assert self.bootstrap._validation_strategies is None
        assert self.bootstrap._scan_orchestrator is None
        assert self.bootstrap._threat_aggregator is None
        assert self.bootstrap._validation_service is None

        # After getting threat aggregator, only it should be initialized
        aggregator = self.bootstrap.get_threat_aggregator()
        assert self.bootstrap._threat_aggregator is not None
        assert self.bootstrap._scan_orchestrator is None
        assert self.bootstrap._validation_service is None

    def test_bootstrap_state_isolation(self):
        """Test that different bootstrap instances don't share state."""
        bootstrap1 = CleanArchitectureBootstrap()
        bootstrap2 = CleanArchitectureBootstrap()

        # Configure one with mock strategies
        mock_strategies = [Mock(spec=IScanStrategy)]
        bootstrap1._scan_strategies = mock_strategies

        # Other should still be uninitialized
        assert bootstrap2._scan_strategies is None

        # Services should be independent
        aggregator1 = bootstrap1.get_threat_aggregator()
        aggregator2 = bootstrap2.get_threat_aggregator()
        assert aggregator1 is not aggregator2

    def test_create_with_mock_preserves_original(self):
        """Test that create_with_mock_strategies doesn't modify original bootstrap."""
        original_bootstrap = CleanArchitectureBootstrap()
        mock_strategies = [Mock(spec=IScanStrategy)]

        # Create new bootstrap with mocks
        mock_bootstrap = original_bootstrap.create_with_mock_strategies(mock_strategies)

        # Original should be unchanged
        assert original_bootstrap._scan_strategies is None
        # New one should have mock strategies
        assert mock_bootstrap._scan_strategies == mock_strategies

        # They should be different instances
        assert original_bootstrap is not mock_bootstrap

    def test_empty_strategies_handling(self):
        """Test handling of empty strategy lists."""
        # Set empty strategies
        self.bootstrap._scan_strategies = []
        self.bootstrap._validation_strategies = []

        # Services should still be created successfully
        orchestrator = self.bootstrap.get_scan_orchestrator()
        validation_service = self.bootstrap.get_validation_service()

        assert isinstance(orchestrator, ScanOrchestrator)
        assert isinstance(validation_service, ValidationService)
        assert len(orchestrator._scan_strategies) == 0
        assert len(orchestrator._validation_strategies) == 0
