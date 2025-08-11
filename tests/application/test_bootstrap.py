"""Tests for dependency injection bootstrap."""

from pathlib import Path
from unittest.mock import Mock, patch

from adversary_mcp_server.application.bootstrap import (
    _create_cache_manager,
    _create_metrics_collector,
    configure_container,
    create_configured_container,
)
from adversary_mcp_server.container import ServiceContainer
from adversary_mcp_server.interfaces import (
    ICacheManager,
    ICredentialManager,
    ILLMScanner,
    IMetricsCollector,
    IScanEngine,
    ISemgrepScanner,
    IValidator,
)


class TestBootstrap:
    """Test bootstrap functionality."""

    def test_configure_container(self):
        """Test container configuration."""
        container = ServiceContainer()

        # Mock credential manager to avoid actual credential loading
        with patch(
            "adversary_mcp_server.application.bootstrap.get_credential_manager"
        ) as mock_get_cred:
            mock_credential_manager = Mock()
            mock_get_cred.return_value = mock_credential_manager

            configure_container(container)

        # Verify all expected services are registered
        services = container.get_registered_services()

        assert ICredentialManager in services
        assert ICacheManager in services
        assert IMetricsCollector in services
        assert ISemgrepScanner in services
        assert ILLMScanner in services
        assert IValidator in services
        assert IScanEngine in services

    def test_create_configured_container(self):
        """Test creating and configuring a new container."""
        with patch(
            "adversary_mcp_server.application.bootstrap.get_credential_manager"
        ) as mock_get_cred:
            mock_credential_manager = Mock()
            mock_get_cred.return_value = mock_credential_manager

            container = create_configured_container()

        assert isinstance(container, ServiceContainer)
        assert len(container.get_registered_services()) > 0

    def test_create_cache_manager_with_config(self):
        """Test cache manager factory with configuration."""
        mock_credential_manager = Mock()
        mock_metrics_collector = Mock()

        # Mock config with cache settings
        mock_config = Mock()
        mock_config.cache_size_mb = 200
        mock_config.cache_ttl_seconds = 7200
        mock_credential_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.application.bootstrap.get_app_cache_dir"
        ) as mock_cache_dir:
            mock_cache_dir.return_value = Path("/tmp/test_cache")

            with patch(
                "adversary_mcp_server.application.bootstrap.CacheManager"
            ) as mock_cache_cls:
                mock_cache_manager = Mock()
                mock_cache_cls.return_value = mock_cache_manager

                result = _create_cache_manager(
                    mock_credential_manager, mock_metrics_collector
                )

        # Verify cache manager was created with config values
        mock_cache_cls.assert_called_once()
        call_kwargs = mock_cache_cls.call_args[1]
        assert call_kwargs["max_size_mb"] == 200
        assert call_kwargs["max_age_hours"] == 2  # 7200 seconds / 3600 = 2 hours
        assert call_kwargs["metrics_collector"] == mock_metrics_collector

    def test_create_cache_manager_config_failure(self):
        """Test cache manager factory with config loading failure."""
        mock_credential_manager = Mock()
        mock_credential_manager.load_config.side_effect = Exception("Config error")
        mock_metrics_collector = Mock()

        with patch(
            "adversary_mcp_server.application.bootstrap.get_app_cache_dir"
        ) as mock_cache_dir:
            mock_cache_dir.return_value = Path("/tmp/test_cache")

            with patch(
                "adversary_mcp_server.application.bootstrap.CacheManager"
            ) as mock_cache_cls:
                mock_cache_manager = Mock()
                mock_cache_cls.return_value = mock_cache_manager

                result = _create_cache_manager(
                    mock_credential_manager, mock_metrics_collector
                )

        # Should fall back to defaults
        mock_cache_cls.assert_called_once()
        call_kwargs = mock_cache_cls.call_args[1]
        assert call_kwargs["max_size_mb"] == 100  # Default
        assert call_kwargs["max_age_hours"] == 1  # Default (1 hour)

    def test_create_metrics_collector_with_config(self):
        """Test metrics collector factory with configuration."""
        mock_credential_manager = Mock()

        # Mock config with monitoring settings
        mock_config = Mock()
        mock_monitoring_config = Mock()
        mock_config.monitoring = mock_monitoring_config
        mock_credential_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.application.bootstrap.UnifiedMetricsCollector"
        ) as mock_metrics_cls:
            mock_metrics_collector = Mock()
            mock_metrics_cls.return_value = mock_metrics_collector

            result = _create_metrics_collector(mock_credential_manager)

        # Verify metrics collector was created with monitoring config
        mock_metrics_cls.assert_called_once_with(mock_monitoring_config)

    def test_create_metrics_collector_config_failure(self):
        """Test metrics collector factory with config loading failure."""
        mock_credential_manager = Mock()
        mock_credential_manager.load_config.side_effect = Exception("Config error")

        with patch(
            "adversary_mcp_server.application.bootstrap.UnifiedMetricsCollector"
        ) as mock_metrics_cls:
            mock_metrics_collector = Mock()
            mock_metrics_cls.return_value = mock_metrics_collector

            with patch(
                "adversary_mcp_server.application.bootstrap.MonitoringConfig"
            ) as mock_config_cls:
                mock_default_config = Mock()
                mock_config_cls.return_value = mock_default_config

                result = _create_metrics_collector(mock_credential_manager)

        # Should fall back to default config
        mock_config_cls.assert_called_once()
        mock_metrics_cls.assert_called_once_with(mock_default_config)

    def test_create_metrics_collector_no_monitoring_config(self):
        """Test metrics collector factory with no monitoring config."""
        mock_credential_manager = Mock()

        # Config with no monitoring attribute
        mock_config = Mock()
        del mock_config.monitoring  # Remove monitoring attribute
        mock_credential_manager.load_config.return_value = mock_config

        with patch(
            "adversary_mcp_server.application.bootstrap.UnifiedMetricsCollector"
        ) as mock_metrics_cls:
            mock_metrics_collector = Mock()
            mock_metrics_cls.return_value = mock_metrics_collector

            with patch(
                "adversary_mcp_server.application.bootstrap.MonitoringConfig"
            ) as mock_config_cls:
                mock_default_config = Mock()
                mock_config_cls.return_value = mock_default_config

                result = _create_metrics_collector(mock_credential_manager)

        # Should create default monitoring config
        mock_config_cls.assert_called_once()
        mock_metrics_cls.assert_called_once_with(mock_default_config)


class TestBootstrapEdgeCases:
    """Test edge cases and error conditions."""

    def test_configure_container_with_custom_config_dir(self, tmp_path):
        """Test container configuration with custom config directory."""
        container = ServiceContainer()
        custom_config_dir = tmp_path / "custom_config"

        with patch(
            "adversary_mcp_server.application.bootstrap.get_credential_manager"
        ) as mock_get_cred:
            mock_credential_manager = Mock()
            mock_get_cred.return_value = mock_credential_manager

            configure_container(container, custom_config_dir)

        # Verify credential manager was called with custom config dir
        mock_get_cred.assert_called_once_with(custom_config_dir)

    def test_create_configured_container_with_config_dir(self, tmp_path):
        """Test creating container with custom config directory."""
        custom_config_dir = tmp_path / "custom_config"

        with patch(
            "adversary_mcp_server.application.bootstrap.get_credential_manager"
        ) as mock_get_cred:
            mock_credential_manager = Mock()
            mock_get_cred.return_value = mock_credential_manager

            container = create_configured_container(custom_config_dir)

        mock_get_cred.assert_called_once_with(custom_config_dir)
