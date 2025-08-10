"""Tests for the dependency injection container."""

from typing import Protocol
from unittest.mock import Mock

import pytest

from adversary_mcp_server.container import ServiceContainer, ServiceLifetime


# Test interfaces for dependency injection testing
class ITestService(Protocol):
    def get_value(self) -> str: ...


class ITestDependency(Protocol):
    def get_dependency_value(self) -> str: ...


class ITestDisposable(Protocol):
    async def dispose(self) -> None: ...


# Test implementations
class TestService:
    def __init__(self, dependency: ITestDependency):
        self.dependency = dependency
        self.creation_count = getattr(TestService, "_creation_count", 0) + 1
        TestService._creation_count = self.creation_count

    def get_value(self) -> str:
        return f"service-{self.creation_count}"


class TestDependency:
    def __init__(self):
        self.creation_count = getattr(TestDependency, "_creation_count", 0) + 1
        TestDependency._creation_count = self.creation_count

    def get_dependency_value(self) -> str:
        return f"dependency-{self.creation_count}"


class TestServiceNoDeps:
    def __init__(self):
        self.creation_count = getattr(TestServiceNoDeps, "_creation_count", 0) + 1
        TestServiceNoDeps._creation_count = self.creation_count

    def get_value(self) -> str:
        return f"no-deps-{self.creation_count}"


class TestDisposableService:
    def __init__(self):
        self.disposed = False
        self.creation_count = getattr(TestDisposableService, "_creation_count", 0) + 1
        TestDisposableService._creation_count = self.creation_count

    async def dispose(self) -> None:
        self.disposed = True


@pytest.fixture
def container():
    """Create a fresh container for each test."""
    # Reset creation counters
    for cls in [TestService, TestDependency, TestServiceNoDeps, TestDisposableService]:
        if hasattr(cls, "_creation_count"):
            cls._creation_count = 0

    return ServiceContainer()


class TestServiceContainer:
    """Test the ServiceContainer functionality."""

    def test_container_initialization(self):
        """Test that container initializes correctly."""
        container = ServiceContainer()
        assert len(container.get_registered_services()) == 0
        assert str(container) == "ServiceContainer(services=0, singletons=0)"

    def test_register_singleton(self, container):
        """Test singleton service registration."""
        container.register_singleton(ITestDependency, TestDependency)

        assert container.is_registered(ITestDependency)
        registration = container.get_registration(ITestDependency)
        assert registration.lifetime == ServiceLifetime.SINGLETON
        assert registration.implementation == TestDependency

    def test_register_scoped(self, container):
        """Test scoped service registration."""
        container.register_scoped(ITestService, TestService)

        registration = container.get_registration(ITestService)
        assert registration.lifetime == ServiceLifetime.SCOPED

    def test_register_transient(self, container):
        """Test transient service registration."""
        container.register_transient(ITestService, TestService)

        registration = container.get_registration(ITestService)
        assert registration.lifetime == ServiceLifetime.TRANSIENT

    def test_register_instance(self, container):
        """Test instance registration."""
        instance = TestServiceNoDeps()
        container.register_instance(ITestService, instance)

        resolved = container.resolve(ITestService)
        assert resolved is instance  # Exact same instance

    def test_register_factory(self, container):
        """Test factory registration."""

        def create_service() -> ITestService:
            return TestServiceNoDeps()

        container.register_factory(ITestService, create_service)

        registration = container.get_registration(ITestService)
        assert registration.factory is create_service

    def test_singleton_lifetime(self, container):
        """Test that singleton services return the same instance."""
        container.register_singleton(ITestDependency, TestDependency)

        instance1 = container.resolve(ITestDependency)
        instance2 = container.resolve(ITestDependency)

        assert instance1 is instance2  # Exact same object
        assert instance1.creation_count == 1  # Only created once

    def test_scoped_lifetime(self, container):
        """Test that scoped services return new instances."""
        container.register_scoped(ITestDependency, TestDependency)

        instance1 = container.resolve(ITestDependency)
        instance2 = container.resolve(ITestDependency)

        assert instance1 is not instance2  # Different objects
        assert instance1.creation_count == 1
        assert instance2.creation_count == 2

    def test_transient_lifetime(self, container):
        """Test that transient services return new instances."""
        container.register_transient(ITestDependency, TestDependency)

        instance1 = container.resolve(ITestDependency)
        instance2 = container.resolve(ITestDependency)

        assert instance1 is not instance2  # Different objects
        assert instance1.creation_count == 1
        assert instance2.creation_count == 2

    def test_dependency_injection(self, container):
        """Test that dependencies are automatically injected."""
        container.register_singleton(ITestDependency, TestDependency)
        container.register_scoped(ITestService, TestService)

        service = container.resolve(ITestService)

        assert isinstance(service, TestService)
        assert isinstance(service.dependency, TestDependency)
        assert service.get_value() == "service-1"
        assert service.dependency.get_dependency_value() == "dependency-1"

    def test_factory_with_dependencies(self, container):
        """Test factory functions with dependency injection."""
        container.register_singleton(ITestDependency, TestDependency)

        def create_service(dependency: ITestDependency) -> ITestService:
            service = TestService.__new__(TestService)
            service.dependency = dependency
            service.creation_count = 99  # Custom value to verify factory was used
            return service

        container.register_factory(ITestService, create_service)

        service = container.resolve(ITestService)
        assert service.creation_count == 99  # Confirms factory was used
        assert isinstance(service.dependency, TestDependency)

    def test_unregistered_service_error(self, container):
        """Test that resolving unregistered service raises error."""
        with pytest.raises(ValueError, match="Service ITestService is not registered"):
            container.resolve(ITestService)

    def test_circular_dependency_detection(self, container):
        """Test that circular dependencies are detected."""

        # Create classes with circular dependencies
        class ServiceA:
            def __init__(self, b):
                self.b = b

        class ServiceB:
            def __init__(self, a: "ServiceA"):  # Forward reference string
                self.a = a

        # Manually set type annotations for proper detection
        ServiceA.__init__.__annotations__ = {"b": "ServiceB"}
        ServiceB.__init__.__annotations__ = {"a": "ServiceA"}

        container.register_singleton(ServiceA, ServiceA)
        container.register_singleton(ServiceB, ServiceB)

        # Register the actual types for resolution
        import sys

        current_module = sys.modules[__name__]
        current_module.ServiceA = ServiceA
        current_module.ServiceB = ServiceB

        # Update annotations to use actual types
        ServiceA.__init__.__annotations__ = {"b": ServiceB}
        ServiceB.__init__.__annotations__ = {"a": ServiceA}

        with pytest.raises(RuntimeError, match="Circular dependency detected"):
            container.resolve(ServiceA)

    def test_clear_singletons(self, container):
        """Test that singleton clearing works correctly."""
        container.register_singleton(ITestDependency, TestDependency)

        # Create instance
        instance1 = container.resolve(ITestDependency)
        assert instance1.creation_count == 1

        # Clear and resolve again
        container.clear_singletons()
        instance2 = container.resolve(ITestDependency)

        assert instance1 is not instance2  # Different instances
        assert instance2.creation_count == 2  # New instance created

    @pytest.mark.asyncio
    async def test_async_disposal(self, container):
        """Test async disposal of services."""
        container.register_singleton(ITestDisposable, TestDisposableService)

        service = container.resolve(ITestDisposable)
        assert not service.disposed

        await container.dispose_async()

        assert service.disposed  # Should be disposed
        assert len(container._singletons) == 0  # Singletons cleared

    def test_service_without_type_hints(self, container):
        """Test handling of services without proper type hints."""

        class ServiceNoHints:
            def __init__(self, param="default"):  # No type hint but has default
                self.param = param

        container.register_scoped(ITestService, ServiceNoHints)

        # Should create instance but warn about missing type hint
        service = container.resolve(ITestService)
        assert isinstance(service, ServiceNoHints)
        assert service.param == "default"

    def test_get_registered_services(self, container):
        """Test getting all registered services."""
        container.register_singleton(ITestDependency, TestDependency)
        container.register_scoped(ITestService, TestService)

        services = container.get_registered_services()

        assert len(services) == 2
        assert ITestDependency in services
        assert ITestService in services
        assert services[ITestDependency].lifetime == ServiceLifetime.SINGLETON
        assert services[ITestService].lifetime == ServiceLifetime.SCOPED


class TestContainerPerformance:
    """Test container performance characteristics."""

    def test_singleton_performance(self, container):
        """Test that singleton resolution is fast after first creation."""
        container.register_singleton(ITestDependency, TestDependency)

        # First resolution (creates instance)
        instance1 = container.resolve(ITestDependency)

        # Subsequent resolutions should be very fast (just dictionary lookup)
        for _ in range(100):
            instance = container.resolve(ITestDependency)
            assert instance is instance1  # Same instance every time

    def test_complex_dependency_graph(self, container):
        """Test resolution of complex dependency graph."""

        # Create a dependency chain: ServiceA -> ServiceB -> ServiceC
        class ServiceC:
            def __init__(self):
                self.value = "C"

        class ServiceB:
            def __init__(self, c: ServiceC):
                self.c = c
                self.value = "B"

        class ServiceA:
            def __init__(self, b: ServiceB, c: ServiceC):
                self.b = b
                self.c = c  # Also depends on C directly
                self.value = "A"

        container.register_singleton(ServiceC, ServiceC)
        container.register_singleton(ServiceB, ServiceB)
        container.register_singleton(ServiceA, ServiceA)

        service_a = container.resolve(ServiceA)

        # Verify entire dependency graph was resolved
        assert service_a.value == "A"
        assert service_a.b.value == "B"
        assert service_a.c.value == "C"
        assert service_a.b.c is service_a.c  # Same instance of C used


class TestContainerIntegration:
    """Integration tests for container with real-world scenarios."""

    def test_mock_service_replacement(self, container):
        """Test replacing services with mocks for testing."""
        # Register real service
        container.register_singleton(ITestDependency, TestDependency)
        container.register_scoped(ITestService, TestService)

        # Replace with mock for testing
        mock_dependency = Mock(spec=ITestDependency)
        mock_dependency.get_dependency_value.return_value = "mocked"

        container.register_instance(ITestDependency, mock_dependency)

        service = container.resolve(ITestService)
        result = service.dependency.get_dependency_value()

        assert result == "mocked"
        mock_dependency.get_dependency_value.assert_called_once()

    def test_container_as_service_locator(self, container):
        """Test using container as a service locator pattern."""
        # Register all services
        container.register_singleton(ITestDependency, TestDependency)
        container.register_scoped(ITestService, TestService)

        # Simulate service locator usage
        services = {}
        services["dependency"] = container.resolve(ITestDependency)
        services["service"] = container.resolve(ITestService)

        assert isinstance(services["dependency"], TestDependency)
        assert isinstance(services["service"], TestService)
        assert services["service"].dependency is services["dependency"]

    def test_container_lifecycle_management(self, container):
        """Test complete container lifecycle."""
        # Setup phase
        container.register_singleton(ITestDependency, TestDependency)
        container.register_scoped(ITestService, TestService)

        # Usage phase
        instance1 = container.resolve(ITestService)
        instance2 = container.resolve(ITestService)

        assert instance1 is not instance2  # Scoped services are different
        assert (
            instance1.dependency is instance2.dependency
        )  # But share singleton dependency

        # Cleanup phase
        container.clear_singletons()

        # Post-cleanup verification
        instance3 = container.resolve(ITestService)
        assert instance3.dependency is not instance1.dependency  # New singleton created
