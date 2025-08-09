"""Tests for ModelCatalogService."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.llm.model_catalog import ModelCatalogService
from adversary_mcp_server.llm.model_types import (
    ModelCapability,
    ModelCatalogConfig,
    ModelCategory,
    ModelFilter,
    ModelInfo,
    ModelProvider,
)


@pytest.fixture
def mock_pricing_manager():
    """Mock pricing manager with test data."""
    pricing_manager = Mock()
    pricing_manager.get_model_pricing.return_value = {
        "prompt_tokens_per_1k": 0.01,
        "completion_tokens_per_1k": 0.02,
        "currency": "USD",
        "description": "Test model",
    }
    pricing_manager.pricing_data = {
        "pricing_models": {
            "gpt-3.5-turbo": {
                "display_name": "GPT-3.5 Turbo",
                "prompt_tokens_per_1k": 0.001,
                "completion_tokens_per_1k": 0.002,
                "currency": "USD",
                "description": "Fast and efficient model",
                "category": "latest",
                "capabilities": ["chat", "fast"],
                "max_context_tokens": 4096,
                "speed_rating": "fast",
                "quality_rating": "good",
                "is_available": True,
                "is_deprecated": False,
                "best_for": ["general", "speed"],
                "notes": ["Recommended for most use cases"],
            },
            "claude-3-5-sonnet-20241022": {
                "display_name": "Claude 3.5 Sonnet",
                "prompt_tokens_per_1k": 0.003,
                "completion_tokens_per_1k": 0.015,
                "currency": "USD",
                "description": "Latest Claude flagship model",
                "category": "latest",
                "capabilities": ["chat", "code", "analysis"],
                "max_context_tokens": 200000,
                "speed_rating": "medium",
                "quality_rating": "excellent",
                "is_available": True,
                "is_deprecated": False,
                "best_for": ["quality", "code"],
                "notes": ["Best for complex tasks"],
            },
        }
    }
    return pricing_manager


@pytest.fixture
def catalog_service(mock_pricing_manager):
    """Create a ModelCatalogService for testing."""
    config = ModelCatalogConfig()
    with patch(
        "adversary_mcp_server.llm.model_catalog.PricingManager",
        return_value=mock_pricing_manager,
    ):
        return ModelCatalogService(config)


@pytest.fixture
def sample_models():
    """Sample ModelInfo objects for testing."""
    return [
        ModelInfo(
            id="gpt-3.5-turbo",
            display_name="GPT-3.5 Turbo",
            provider=ModelProvider.OPENAI,
            prompt_tokens_per_1k=0.001,
            completion_tokens_per_1k=0.002,
            category=ModelCategory.LATEST,
            capabilities=[ModelCapability.CHAT, ModelCapability.FAST],
            speed_rating="fast",
            quality_rating="good",
        ),
        ModelInfo(
            id="claude-3-5-sonnet-20241022",
            display_name="Claude 3.5 Sonnet",
            provider=ModelProvider.ANTHROPIC,
            prompt_tokens_per_1k=0.003,
            completion_tokens_per_1k=0.015,
            category=ModelCategory.LATEST,
            capabilities=[ModelCapability.CHAT, ModelCapability.CODE],
            speed_rating="medium",
            quality_rating="excellent",
        ),
        ModelInfo(
            id="gpt-4-deprecated",
            display_name="GPT-4 (Deprecated)",
            provider=ModelProvider.OPENAI,
            prompt_tokens_per_1k=0.03,
            completion_tokens_per_1k=0.06,
            category=ModelCategory.LEGACY,
            is_deprecated=True,
        ),
        ModelInfo(
            id="claude-unavailable",
            display_name="Claude Unavailable",
            provider=ModelProvider.ANTHROPIC,
            prompt_tokens_per_1k=0.01,
            completion_tokens_per_1k=0.03,
            category=ModelCategory.BUDGET,
            is_available=False,
        ),
    ]


class TestModelCatalogService:
    """Test ModelCatalogService functionality."""

    def test_init_default_config(self):
        """Test initialization with default configuration."""
        with patch("adversary_mcp_server.llm.model_catalog.PricingManager"):
            service = ModelCatalogService()
            assert service.config is not None
            assert service.pricing_manager is not None
            assert service._model_cache == {}
            assert service._cache_timestamp is None

    def test_init_custom_config(self):
        """Test initialization with custom configuration."""
        config = ModelCatalogConfig(cache_duration_hours=12)
        with patch("adversary_mcp_server.llm.model_catalog.PricingManager"):
            service = ModelCatalogService(config)
            assert service.config.cache_duration_hours == 12

    @pytest.mark.asyncio
    async def test_get_available_models_empty_cache(self, catalog_service):
        """Test getting available models with empty cache."""
        with patch.object(catalog_service, "_refresh_model_cache") as mock_refresh:
            await catalog_service.get_available_models()
            mock_refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_available_models_with_provider_filter(
        self, catalog_service, sample_models
    ):
        """Test getting models filtered by provider."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()
        # Disable deprecated filtering to get both models
        catalog_service.config.exclude_deprecated = False
        catalog_service.config.exclude_unavailable = False

        openai_models = await catalog_service.get_available_models(
            provider=ModelProvider.OPENAI
        )
        assert len(openai_models) == 2  # gpt-3.5-turbo and gpt-4-deprecated
        assert all(m.provider == ModelProvider.OPENAI for m in openai_models)

    @pytest.mark.asyncio
    async def test_get_available_models_exclude_deprecated(
        self, catalog_service, sample_models
    ):
        """Test excluding deprecated models."""
        catalog_service.config.exclude_deprecated = True
        catalog_service.config.exclude_unavailable = (
            False  # Allow unavailable for this test
        )
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        models = await catalog_service.get_available_models()
        assert len(models) == 3  # Should exclude gpt-4-deprecated
        assert all(not m.is_deprecated for m in models)

    @pytest.mark.asyncio
    async def test_get_available_models_exclude_unavailable(
        self, catalog_service, sample_models
    ):
        """Test excluding unavailable models."""
        catalog_service.config.exclude_unavailable = True
        catalog_service.config.exclude_deprecated = (
            False  # Allow deprecated for this test
        )
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        models = await catalog_service.get_available_models()
        assert len(models) == 3  # Should exclude claude-unavailable
        assert all(m.is_available for m in models)

    @pytest.mark.asyncio
    async def test_get_models_by_category(self, catalog_service, sample_models):
        """Test filtering models by category."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        latest_models = await catalog_service.get_models_by_category(
            ModelCategory.LATEST
        )
        assert len(latest_models) == 2  # gpt-3.5-turbo and claude-3-5-sonnet-20241022
        assert all(model.category == ModelCategory.LATEST for model in latest_models)

    @pytest.mark.asyncio
    async def test_get_models_by_filter(self, catalog_service, sample_models):
        """Test filtering models with ModelFilter."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        model_filter = ModelFilter(
            provider=ModelProvider.OPENAI,
            max_prompt_cost=0.005,
            capabilities=[ModelCapability.FAST],
        )

        filtered_models = await catalog_service.get_models_by_filter(model_filter)
        assert len(filtered_models) == 1
        assert filtered_models[0].id == "gpt-3.5-turbo"

    @pytest.mark.asyncio
    async def test_get_recommended_models_budget(self, catalog_service, sample_models):
        """Test getting budget recommendations."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        budget_models = await catalog_service.get_recommended_models("budget")
        # Should find gpt-3.5-turbo (low cost) and claude-unavailable (budget category)
        assert len(budget_models) <= 5
        assert all(
            m.category == ModelCategory.BUDGET or m.prompt_tokens_per_1k <= 0.002
            for m in budget_models
        )

    @pytest.mark.asyncio
    async def test_get_recommended_models_speed(self, catalog_service, sample_models):
        """Test getting speed recommendations."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        speed_models = await catalog_service.get_recommended_models("speed")
        assert len(speed_models) <= 5
        fast_models = [
            m
            for m in speed_models
            if m.speed_rating == "fast"
            or ModelCapability.FAST in (m.capabilities or [])
        ]
        assert len(fast_models) > 0

    @pytest.mark.asyncio
    async def test_get_recommended_models_quality(self, catalog_service, sample_models):
        """Test getting quality recommendations."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        quality_models = await catalog_service.get_recommended_models("quality")
        assert len(quality_models) <= 5
        excellent_models = [
            m
            for m in quality_models
            if m.quality_rating == "excellent"
            or m.category in [ModelCategory.LATEST, ModelCategory.SPECIALIZED]
        ]
        assert len(excellent_models) > 0

    @pytest.mark.asyncio
    async def test_get_recommended_models_code(self, catalog_service, sample_models):
        """Test getting code recommendations."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        code_models = await catalog_service.get_recommended_models("code")
        assert len(code_models) <= 5
        code_capable = [
            m
            for m in code_models
            if ModelCapability.CODE in (m.capabilities or [])
            or "code" in m.description.lower()
        ]
        assert len(code_capable) > 0

    @pytest.mark.asyncio
    async def test_get_recommended_models_general(self, catalog_service, sample_models):
        """Test getting general recommendations."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        general_models = await catalog_service.get_recommended_models("general")
        # Should return mix of latest, budget, and specialized
        assert len(general_models) > 0

    @pytest.mark.asyncio
    async def test_get_model_by_id_cache_stale(self, catalog_service):
        """Test getting model by ID with stale cache."""
        with (
            patch.object(catalog_service, "_is_cache_stale", return_value=True),
            patch.object(catalog_service, "_refresh_model_cache") as mock_refresh,
        ):
            result = await catalog_service.get_model_by_id("test-model")
            mock_refresh.assert_called_once()
            assert result is None  # Not found in empty cache

    @pytest.mark.asyncio
    async def test_get_model_by_id_found(self, catalog_service, sample_models):
        """Test getting existing model by ID."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        model = await catalog_service.get_model_by_id("gpt-3.5-turbo")
        assert model is not None
        assert model.id == "gpt-3.5-turbo"

    def test_get_categorized_models(self, catalog_service, sample_models):
        """Test organizing models by category."""
        categorized = catalog_service.get_categorized_models(sample_models)

        assert ModelCategory.LATEST in categorized
        assert ModelCategory.LEGACY in categorized
        assert ModelCategory.BUDGET in categorized
        # Note: SPECIALIZED category not present in current sample models

        # Check sorting within categories
        for category_models in categorized.values():
            assert len(category_models) > 0

    @pytest.mark.asyncio
    async def test_refresh_model_cache_api_success(self, catalog_service):
        """Test successful model cache refresh with API calls."""
        mock_openai_models = [
            ModelInfo(
                id="gpt-4",
                display_name="GPT-4",
                provider=ModelProvider.OPENAI,
                prompt_tokens_per_1k=0.03,
                completion_tokens_per_1k=0.06,
            )
        ]
        mock_anthropic_models = [
            ModelInfo(
                id="claude-3-sonnet",
                display_name="Claude 3 Sonnet",
                provider=ModelProvider.ANTHROPIC,
                prompt_tokens_per_1k=0.003,
                completion_tokens_per_1k=0.015,
            )
        ]
        mock_fallback_models = []

        with (
            patch.object(
                catalog_service, "_fetch_openai_models", return_value=mock_openai_models
            ),
            patch.object(
                catalog_service,
                "_fetch_anthropic_models",
                return_value=mock_anthropic_models,
            ),
            patch.object(
                catalog_service,
                "_load_fallback_models",
                return_value=mock_fallback_models,
            ),
        ):
            await catalog_service._refresh_model_cache()

            assert len(catalog_service._model_cache) == 2
            assert "gpt-4" in catalog_service._model_cache
            assert "claude-3-sonnet" in catalog_service._model_cache

    @pytest.mark.asyncio
    async def test_refresh_model_cache_api_failure(
        self, catalog_service, mock_pricing_manager
    ):
        """Test model cache refresh with API failures, falling back to pricing config."""
        fallback_models = [
            ModelInfo(
                id="gpt-3.5-turbo",
                display_name="GPT-3.5 Turbo",
                provider=ModelProvider.OPENAI,
                prompt_tokens_per_1k=0.001,
                completion_tokens_per_1k=0.002,
            )
        ]

        with (
            patch.object(
                catalog_service,
                "_fetch_openai_models",
                side_effect=Exception("API Error"),
            ),
            patch.object(
                catalog_service,
                "_fetch_anthropic_models",
                side_effect=Exception("API Error"),
            ),
            patch.object(
                catalog_service, "_load_fallback_models", return_value=fallback_models
            ),
        ):
            await catalog_service._refresh_model_cache()

            assert len(catalog_service._model_cache) == 1
            assert "gpt-3.5-turbo" in catalog_service._model_cache

    @pytest.mark.asyncio
    async def test_fetch_openai_models_success(self, catalog_service):
        """Test successful OpenAI API fetch."""
        mock_response_data = {
            "data": [
                {"id": "gpt-3.5-turbo", "created": 1677610602},
                {
                    "id": "text-embedding-ada-002",
                    "created": 1671217299,
                },  # Should be filtered out
                {"id": "gpt-4", "created": 1687882411},
            ]
        }

        # Create proper async context manager mock
        class MockResponse:
            def __init__(self, status, json_data):
                self.status = status
                self._json_data = json_data

            async def json(self):
                return self._json_data

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        class MockClientSession:
            def __init__(self, timeout=None):
                pass

            def get(self, url, headers=None):
                return MockResponse(200, mock_response_data)

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        with (
            patch("aiohttp.ClientSession", MockClientSession),
            patch.object(
                catalog_service, "_get_openai_api_key", return_value="test-key"
            ),
        ):
            models = await catalog_service._fetch_openai_models()

            # Should get 2 models (excluding embedding model)
            assert len(models) == 2
            assert all(m.provider == ModelProvider.OPENAI for m in models)

    @pytest.mark.asyncio
    async def test_fetch_openai_models_http_error(self, catalog_service):
        """Test OpenAI API HTTP error handling."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_session.get.return_value.__aenter__.return_value = mock_response

        with (
            patch("aiohttp.ClientSession", return_value=mock_session),
            patch.object(
                catalog_service, "_get_openai_api_key", return_value="test-key"
            ),
        ):
            models = await catalog_service._fetch_openai_models()
            assert models == []

    @pytest.mark.asyncio
    async def test_fetch_anthropic_models_success(self, catalog_service):
        """Test successful Anthropic API fetch."""
        mock_response_data = {
            "data": [
                {
                    "id": "claude-3-5-sonnet-20241022",
                    "display_name": "Claude 3.5 Sonnet",
                    "created_at": "2024-10-22T00:00:00Z",
                },
                {
                    "id": "claude-3-sonnet-20240229",
                    "display_name": "Claude 3 Sonnet",
                    "created_at": "2024-02-29T00:00:00Z",
                },
            ]
        }

        # Create proper async context manager mock
        class MockResponse:
            def __init__(self, status, json_data):
                self.status = status
                self._json_data = json_data

            async def json(self):
                return self._json_data

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        class MockClientSession:
            def __init__(self, timeout=None):
                pass

            def get(self, url, headers=None):
                return MockResponse(200, mock_response_data)

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        with (
            patch("aiohttp.ClientSession", MockClientSession),
            patch.object(
                catalog_service, "_get_anthropic_api_key", return_value="test-key"
            ),
        ):
            models = await catalog_service._fetch_anthropic_models()

            assert len(models) == 2
            assert all(m.provider == ModelProvider.ANTHROPIC for m in models)

    @pytest.mark.asyncio
    async def test_fetch_anthropic_models_exception(self, catalog_service):
        """Test Anthropic API exception handling."""
        with patch("aiohttp.ClientSession", side_effect=Exception("Network error")):
            models = await catalog_service._fetch_anthropic_models()
            assert models == []

    def test_parse_openai_models(self, catalog_service):
        """Test parsing OpenAI API response."""
        api_data = {
            "data": [
                {"id": "gpt-3.5-turbo", "created": 1677610602},
                {"id": "text-embedding-ada-002"},  # Should be filtered out
                {"id": "gpt-4", "created": "invalid"},  # Invalid timestamp
            ]
        }

        models = catalog_service._parse_openai_models(api_data)

        # Should get 2 chat models
        assert len(models) == 2
        chat_models = [m for m in models if "gpt" in m.id.lower()]
        assert len(chat_models) == 2

    def test_parse_anthropic_models(self, catalog_service):
        """Test parsing Anthropic API response."""
        api_data = {
            "data": [
                {
                    "id": "claude-3-5-sonnet-20241022",
                    "display_name": "Claude 3.5 Sonnet",
                    "created_at": "2024-10-22T00:00:00Z",
                },
                {
                    "id": "claude-3-sonnet-20240229",
                    "created_at": "invalid-date",  # Invalid date
                },
            ]
        }

        models = catalog_service._parse_anthropic_models(api_data)
        assert len(models) == 2
        assert all("claude" in m.id.lower() for m in models)

    def test_load_fallback_models(self, catalog_service, mock_pricing_manager):
        """Test loading fallback models from pricing config."""
        models = catalog_service._load_fallback_models()

        # Should load models from mock pricing data
        assert len(models) == 2
        model_ids = {m.id for m in models}
        assert "gpt-3.5-turbo" in model_ids
        assert "claude-3-5-sonnet-20241022" in model_ids

    def test_load_fallback_models_exception(self, catalog_service):
        """Test fallback model loading with exception."""
        catalog_service.pricing_manager.pricing_data = None
        models = catalog_service._load_fallback_models()
        assert models == []

    def test_is_cache_stale_no_timestamp(self, catalog_service):
        """Test cache staleness check with no timestamp."""
        assert catalog_service._is_cache_stale() is True

    def test_is_cache_stale_fresh_cache(self, catalog_service):
        """Test cache staleness check with fresh cache."""
        catalog_service._cache_timestamp = datetime.now()
        assert catalog_service._is_cache_stale() is False

    def test_is_cache_stale_old_cache(self, catalog_service):
        """Test cache staleness check with old cache."""
        # Set timestamp to 25 hours ago (older than default 24 hour cache)
        catalog_service._cache_timestamp = datetime.now() - timedelta(hours=25)
        assert catalog_service._is_cache_stale() is True

    def test_is_chat_model_openai(self, catalog_service):
        """Test OpenAI chat model detection."""
        # Should be chat models
        assert (
            catalog_service._is_chat_model("gpt-3.5-turbo", ModelProvider.OPENAI)
            is True
        )
        assert catalog_service._is_chat_model("gpt-4", ModelProvider.OPENAI) is True
        assert (
            catalog_service._is_chat_model("text-davinci-003", ModelProvider.OPENAI)
            is True
        )

        # Should not be chat models
        assert (
            catalog_service._is_chat_model(
                "text-embedding-ada-002", ModelProvider.OPENAI
            )
            is False
        )
        assert (
            catalog_service._is_chat_model("whisper-1", ModelProvider.OPENAI) is False
        )
        assert catalog_service._is_chat_model("dall-e-3", ModelProvider.OPENAI) is False

    def test_is_chat_model_anthropic(self, catalog_service):
        """Test Anthropic chat model detection."""
        assert (
            catalog_service._is_chat_model(
                "claude-3-5-sonnet-20241022", ModelProvider.ANTHROPIC
            )
            is True
        )
        assert (
            catalog_service._is_chat_model("claude-2.1", ModelProvider.ANTHROPIC)
            is True
        )
        assert (
            catalog_service._is_chat_model("other-model", ModelProvider.ANTHROPIC)
            is False
        )

    def test_determine_provider(self, catalog_service):
        """Test provider determination from model ID."""
        assert (
            catalog_service._determine_provider("gpt-3.5-turbo") == ModelProvider.OPENAI
        )
        assert (
            catalog_service._determine_provider("text-davinci-003")
            == ModelProvider.OPENAI
        )
        assert (
            catalog_service._determine_provider("claude-3-opus")
            == ModelProvider.ANTHROPIC
        )
        assert catalog_service._determine_provider("unknown-model") is None

    @patch("adversary_mcp_server.credentials.get_credential_manager")
    def test_get_openai_api_key_success(self, mock_get_cred_manager, catalog_service):
        """Test successful OpenAI API key retrieval."""
        mock_cred_manager = Mock()
        mock_cred_manager.get_llm_api_key.return_value = "test-openai-key"
        mock_get_cred_manager.return_value = mock_cred_manager

        key = catalog_service._get_openai_api_key()
        assert key == "test-openai-key"
        mock_cred_manager.get_llm_api_key.assert_called_with("openai")

    @patch("adversary_mcp_server.credentials.get_credential_manager")
    def test_get_openai_api_key_exception(self, mock_get_cred_manager, catalog_service):
        """Test OpenAI API key retrieval with exception."""
        mock_get_cred_manager.side_effect = Exception("Credential error")

        key = catalog_service._get_openai_api_key()
        assert key == ""

    @patch("adversary_mcp_server.credentials.get_credential_manager")
    def test_get_anthropic_api_key_success(
        self, mock_get_cred_manager, catalog_service
    ):
        """Test successful Anthropic API key retrieval."""
        mock_cred_manager = Mock()
        mock_cred_manager.get_llm_api_key.return_value = "test-anthropic-key"
        mock_get_cred_manager.return_value = mock_cred_manager

        key = catalog_service._get_anthropic_api_key()
        assert key == "test-anthropic-key"
        mock_cred_manager.get_llm_api_key.assert_called_with("anthropic")

    @patch("adversary_mcp_server.credentials.get_credential_manager")
    def test_get_anthropic_api_key_none_returned(
        self, mock_get_cred_manager, catalog_service
    ):
        """Test Anthropic API key retrieval returning None."""
        mock_cred_manager = Mock()
        mock_cred_manager.get_llm_api_key.return_value = None
        mock_get_cred_manager.return_value = mock_cred_manager

        key = catalog_service._get_anthropic_api_key()
        assert key == ""

    @pytest.mark.asyncio
    async def test_force_refresh_models(self, catalog_service, sample_models):
        """Test forcing model cache refresh."""
        # Setup initial cache
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        with patch.object(catalog_service, "_refresh_model_cache") as mock_refresh:
            await catalog_service.get_available_models(force_refresh=True)
            mock_refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_model_sorting(self, catalog_service, sample_models):
        """Test model sorting in get_available_models."""
        catalog_service._model_cache = {m.id: m for m in sample_models}
        catalog_service._cache_timestamp = datetime.now()

        # Models should be sorted by category, then by cost (descending)
        models = await catalog_service.get_available_models()

        # Verify sorting - should not throw exception
        assert isinstance(models, list)

    def test_empty_api_response_handling(self, catalog_service):
        """Test handling of empty API responses."""
        empty_api_data = {"data": []}

        openai_models = catalog_service._parse_openai_models(empty_api_data)
        assert openai_models == []

        anthropic_models = catalog_service._parse_anthropic_models(empty_api_data)
        assert anthropic_models == []

    def test_invalid_pricing_data_handling(self, catalog_service):
        """Test handling of invalid pricing data."""
        catalog_service.pricing_manager.pricing_data = {
            "pricing_models": {
                "invalid-model": {
                    # Missing required fields
                    "display_name": "Invalid Model",
                }
            }
        }

        # Should handle gracefully and return empty list
        models = catalog_service._load_fallback_models()
        assert models == []
