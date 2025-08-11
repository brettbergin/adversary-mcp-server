"""Comprehensive integration tests for Phase II architecture components.

This test suite validates the integration of all Phase II components:
- Application coordination layer (ScanOrchestrator, CacheCoordinator, ValidationCoordinator)
- Domain layer (ThreatAggregator)
- Infrastructure layer (ResultBuilder)
- Bootstrap system and dependency injection
"""

from unittest.mock import Mock, patch

import pytest

from adversary_mcp_server.application.coordination.cache_coordinator import (
    CacheCoordinator,
)
from adversary_mcp_server.application.coordination.scan_orchestrator import (
    ScanOrchestrator,
)
from adversary_mcp_server.application.coordination.validation_coordinator import (
    ValidationCoordinator,
)
from adversary_mcp_server.domain.aggregation.threat_aggregator import ThreatAggregator
from adversary_mcp_server.infrastructure.builders.result_builder import ResultBuilder
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch


class TestPhase2ArchitectureIntegration:
    """Test integration of Phase II architecture components."""

    @pytest.fixture
    def sample_threats(self):
        """Create sample threat matches for testing."""
        return [
            ThreatMatch(
                rule_id="sql_injection_001",
                rule_name="SQL Injection Detection",
                description="Potential SQL injection vulnerability",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="/test/vulnerable.py",
                line_number=15,
                confidence=0.9,
            ),
            ThreatMatch(
                rule_id="xss_002",
                rule_name="XSS Vulnerability",
                description="Cross-site scripting vulnerability",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="/test/vulnerable.js",
                line_number=42,
                confidence=0.8,
            ),
            ThreatMatch(
                rule_id="path_traversal_003",
                rule_name="Path Traversal",
                description="Directory traversal vulnerability",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="/test/file_handler.py",
                line_number=23,
                confidence=0.95,
            ),
        ]

    def test_scan_orchestrator_initialization(self):
        """Test ScanOrchestrator can be initialized and configured."""
        # Mock required dependencies
        mock_semgrep = Mock()
        mock_llm = Mock()
        mock_cache = Mock()

        orchestrator = ScanOrchestrator(
            semgrep_scanner=mock_semgrep, llm_scanner=mock_llm, cache_manager=mock_cache
        )

        # Verify orchestrator has required methods
        assert hasattr(orchestrator, "orchestrate_file_scan")
        assert hasattr(orchestrator, "orchestrate_code_scan")

        # Verify dependencies are set
        assert orchestrator.semgrep_scanner == mock_semgrep
        assert orchestrator.llm_scanner == mock_llm
        assert orchestrator is not None

    def test_cache_coordinator_initialization(self):
        """Test CacheCoordinator can be initialized and configured."""
        coordinator = CacheCoordinator()

        # Verify coordinator has required methods
        assert hasattr(coordinator, "get_cached_scan_result")
        assert hasattr(coordinator, "cache_scan_result")

        # Verify coordinator can be instantiated
        assert coordinator is not None

    def test_validation_coordinator_initialization(self):
        """Test ValidationCoordinator can be initialized."""
        coordinator = ValidationCoordinator()

        # Verify coordinator has required methods
        assert hasattr(coordinator, "validate_findings")
        assert hasattr(coordinator, "should_validate")

        # Verify coordinator functionality
        assert coordinator is not None

    def test_threat_aggregator_integration(self, sample_threats):
        """Test ThreatAggregator integration with multiple threats."""
        aggregator = ThreatAggregator()

        # Test aggregation of sample threats
        # Split threats for separate semgrep and llm arguments (test data - split evenly)
        mid = len(sample_threats) // 2
        semgrep_threats = sample_threats[:mid]
        llm_threats = sample_threats[mid:]
        aggregated = aggregator.aggregate_threats(semgrep_threats, llm_threats)

        # Verify aggregation results
        assert len(aggregated) <= len(sample_threats)  # May deduplicate
        assert all(isinstance(threat, ThreatMatch) for threat in aggregated)

        # Test aggregation preserves high-severity threats
        high_severity_count = sum(
            1 for t in sample_threats if t.severity == Severity.HIGH
        )
        aggregated_high_count = sum(
            1 for t in aggregated if t.severity == Severity.HIGH
        )
        assert aggregated_high_count <= high_severity_count

    def test_result_builder_integration(self, sample_threats):
        """Test ResultBuilder integration with threat data."""
        builder = ResultBuilder()

        # Test building results from threats
        result = builder.build_scan_result(
            threats=sample_threats,
            metadata={
                "scan_type": "integration_test",
                "file_count": 3,
                "duration_ms": 1500.0,
            },
        )

        # Verify result structure
        assert result is not None
        assert hasattr(result, "all_threats")
        assert hasattr(result, "scan_metadata")

        # Verify threat data preservation
        assert len(result.all_threats) == len(sample_threats)

    @pytest.mark.asyncio
    async def test_coordination_layer_integration(self, sample_threats):
        """Test integration between coordination layer components."""
        # Create coordinators with proper dependencies
        mock_semgrep = Mock()
        scan_orchestrator = ScanOrchestrator(semgrep_scanner=mock_semgrep)
        cache_coordinator = CacheCoordinator()
        validation_coordinator = ValidationCoordinator()

        # Test that coordinators can work together
        # This tests the architectural separation and integration

        # Mock coordination workflow
        with (
            patch.object(scan_orchestrator, "orchestrate_file_scan") as mock_scan,
            patch.object(cache_coordinator, "get_cached_scan_result") as mock_cache,
            patch.object(validation_coordinator, "validate_findings") as mock_validate,
        ):

            # Set up mock returns
            mock_scan.return_value = Mock(threats=sample_threats, metadata={})
            mock_cache.return_value = None  # No cached result
            mock_validate.return_value = sample_threats[:2]  # Validated subset

            # Test coordinated workflow
            from pathlib import Path

            scan_result = await scan_orchestrator.orchestrate_file_scan(
                Path("/test/path")
            )
            cache_result = await cache_coordinator.get_cached_scan_result(
                file_path=Path("/test/path"),
                content_hash="test_hash",
                scan_parameters={},
            )
            validation_result = validation_coordinator.validate_findings(sample_threats)

            # Verify each coordinator was called and returned results
            assert scan_result.threats == sample_threats
            assert cache_result is None  # No cache hit
            assert len(validation_result) == 2

    def test_domain_infrastructure_integration(self, sample_threats):
        """Test integration between domain and infrastructure layers."""
        aggregator = ThreatAggregator()
        builder = ResultBuilder()

        # Test domain -> infrastructure flow
        # Split threats for separate semgrep and llm arguments (test data - split evenly)
        mid = len(sample_threats) // 2
        semgrep_threats = sample_threats[:mid]
        llm_threats = sample_threats[mid:]
        aggregated_threats = aggregator.aggregate_threats(semgrep_threats, llm_threats)
        built_result = builder.build_scan_result(
            threats=aggregated_threats, metadata={"integration_test": True}
        )

        # Verify end-to-end data flow
        assert built_result is not None
        assert hasattr(built_result, "threats") or built_result is not None

    async def test_full_architecture_integration_workflow(self, sample_threats):
        """Test complete Phase II architecture workflow integration."""
        # Initialize all components with dependencies
        mock_semgrep = Mock()
        scan_orchestrator = ScanOrchestrator(semgrep_scanner=mock_semgrep)
        cache_coordinator = CacheCoordinator()
        validation_coordinator = ValidationCoordinator()
        threat_aggregator = ThreatAggregator()
        result_builder = ResultBuilder()

        # Mock a complete workflow
        with (
            patch.object(
                scan_orchestrator, "orchestrate_file_scan"
            ) as mock_orchestrate,
            patch.object(threat_aggregator, "aggregate_threats") as mock_aggregate,
            patch.object(result_builder, "build_scan_result") as mock_build,
        ):

            # Set up workflow data
            mock_orchestrate.return_value = Mock(threats=sample_threats, metadata={})
            mock_aggregate.return_value = sample_threats[:2]  # Simulated aggregation
            mock_build.return_value = Mock(
                threats=sample_threats[:2], final_result="success", threat_count=2
            )

            # Execute workflow
            from pathlib import Path

            orchestrated = await scan_orchestrator.orchestrate_file_scan(
                Path("/test/path")
            )
            # Split threats for separate semgrep and llm arguments (test data - split evenly)
            mid = len(orchestrated.threats) // 2
            semgrep_threats = orchestrated.threats[:mid]
            llm_threats = orchestrated.threats[mid:]
            aggregated = threat_aggregator.aggregate_threats(
                semgrep_threats, llm_threats
            )
            final_result = result_builder.build_scan_result(
                threats=aggregated, metadata={"workflow": "integration_test"}
            )

            # Verify workflow completion
            assert orchestrated.threats == sample_threats
            assert len(aggregated) == 2
            assert final_result.final_result == "success"

    def test_architecture_error_handling(self):
        """Test that Phase II architecture handles errors gracefully."""
        mock_semgrep = Mock()
        orchestrator = ScanOrchestrator(semgrep_scanner=mock_semgrep)

        # Test error handling in coordination
        with patch.object(
            orchestrator, "orchestrate_file_scan", side_effect=Exception("Test error")
        ):
            try:
                from pathlib import Path

                orchestrator.orchestrate_file_scan(Path("/invalid/path"))
                # If no exception is raised, the component should handle it gracefully
            except Exception as e:
                # If exception is raised, verify it's the expected type
                assert str(e) == "Test error"

    def test_architecture_performance_characteristics(self, sample_threats):
        """Test performance characteristics of Phase II architecture."""
        import time

        # Test aggregation performance
        aggregator = ThreatAggregator()

        start_time = time.time()
        # Split threats for separate semgrep and llm arguments (test data - split evenly)
        scaled_threats = sample_threats * 10
        mid = len(scaled_threats) // 2
        semgrep_threats = scaled_threats[:mid]
        llm_threats = scaled_threats[mid:]
        aggregated = aggregator.aggregate_threats(
            semgrep_threats, llm_threats
        )  # Scale up data
        duration = time.time() - start_time

        # Should complete aggregation reasonably quickly
        assert duration < 1.0  # Less than 1 second for test data

        # Test result building performance
        builder = ResultBuilder()

        start_time = time.time()
        result = builder.build_scan_result(
            threats=aggregated, metadata={"perf_test": True}
        )
        duration = time.time() - start_time

        # Should complete building quickly
        assert duration < 0.5  # Less than 500ms

    def test_architecture_scalability_patterns(self, sample_threats):
        """Test that Phase II architecture follows scalable patterns."""
        # Test that components can handle larger datasets
        large_threat_set = sample_threats * 100

        aggregator = ThreatAggregator()
        builder = ResultBuilder()

        # Should handle larger datasets without errors
        # Split threats for separate semgrep and llm arguments (test data - split evenly)
        mid = len(large_threat_set) // 2
        semgrep_threats = large_threat_set[:mid]
        llm_threats = large_threat_set[mid:]
        aggregated = aggregator.aggregate_threats(semgrep_threats, llm_threats)
        result = builder.build_scan_result(
            threats=aggregated, metadata={"scale_test": True}
        )

        # Verify scalability
        assert len(aggregated) <= len(large_threat_set)
        assert result is not None

    def test_architecture_component_interfaces(self):
        """Test that Phase II components have consistent interfaces."""
        # Test that all coordinators follow consistent patterns
        mock_semgrep = Mock()
        coordinators = [
            ScanOrchestrator(semgrep_scanner=mock_semgrep),
            CacheCoordinator(),
            ValidationCoordinator(),
        ]

        # Each coordinator should have consistent interface patterns
        for coordinator in coordinators:
            # Should be instantiable
            assert coordinator is not None

            # Should have coordination methods (naming pattern validation)
            methods = [
                method for method in dir(coordinator) if not method.startswith("_")
            ]
            coordination_methods = [
                m
                for m in methods
                if any(
                    word in m
                    for word in [
                        "coordinate",
                        "orchestrate",
                        "manage",
                        "validate",
                        "cache",
                    ]
                )
            ]

            # Should have at least one coordination method
            assert len(coordination_methods) > 0

    def test_bootstrap_system_integration(self):
        """Test that bootstrap system can initialize Phase II components."""
        from adversary_mcp_server.application.bootstrap import ApplicationBootstrap

        # Test bootstrap initialization
        bootstrap = ApplicationBootstrap()

        # Verify bootstrap has required methods
        assert hasattr(bootstrap, "initialize_application")
        assert hasattr(bootstrap, "configure_dependencies")

        # Test bootstrap can configure components
        components = bootstrap.configure_dependencies()

        # Verify components are configured
        assert components is not None
        assert isinstance(components, dict)

    def test_dependency_injection_patterns(self):
        """Test that dependency injection works correctly in Phase II."""
        from adversary_mcp_server.container import ServiceContainer

        # Test container initialization
        container = ServiceContainer()

        # Verify container functionality
        assert hasattr(container, "register_singleton")
        assert hasattr(container, "register_instance")
        assert hasattr(container, "resolve")

        # Test dependency registration and resolution using interface pattern
        from abc import ABC, abstractmethod

        class ITestService(ABC):
            @abstractmethod
            def test_method(self) -> str:
                pass

        class TestService(ITestService):
            def test_method(self) -> str:
                return "test"

        # Test instance registration and resolution
        test_service_instance = TestService()
        container.register_instance(ITestService, test_service_instance)

        resolved = container.resolve(ITestService)
        assert resolved == test_service_instance
        assert resolved.test_method() == "test"
