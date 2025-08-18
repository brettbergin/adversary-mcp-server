"""Model catalog service for dynamic LLM model discovery and management."""

from datetime import datetime, timedelta
from typing import Any

import aiohttp

from ..logger import get_logger
from .model_types import (
    ModelCapability,
    ModelCatalogConfig,
    ModelCategory,
    ModelFilter,
    ModelInfo,
    ModelProvider,
)
from .pricing_manager import PricingManager

logger = get_logger("model_catalog")


class ModelCatalogService:
    """Service for discovering and managing LLM models from multiple providers."""

    def __init__(self, config: ModelCatalogConfig | None = None):
        """Initialize the model catalog service.

        Args:
            config: Configuration for model catalog operations
        """
        self.config = config or ModelCatalogConfig()
        self.pricing_manager = PricingManager()

        # Cache for storing discovered models
        self._model_cache: dict[str, ModelInfo] = {}
        self._cache_timestamp: datetime | None = None

        # API endpoints
        self._openai_models_url = "https://api.openai.com/v1/models"
        self._anthropic_models_url = "https://api.anthropic.com/v1/models"

    async def get_available_models(
        self, provider: ModelProvider | None = None, force_refresh: bool = False
    ) -> list[ModelInfo]:
        """Get all available models, optionally filtered by provider.

        Args:
            provider: Specific provider to get models for
            force_refresh: Force refresh of cached models

        Returns:
            List of available models
        """
        if force_refresh or self._is_cache_stale():
            await self._refresh_model_cache()

        models = list(self._model_cache.values())

        if provider:
            models = [m for m in models if m.provider == provider]

        # Filter out deprecated/unavailable models if configured
        if self.config.exclude_deprecated:
            models = [m for m in models if not m.is_deprecated]

        if self.config.exclude_unavailable:
            models = [m for m in models if m.is_available]

        return sorted(models, key=lambda m: (m.category.value, -m.prompt_tokens_per_1k))

    async def get_models_by_category(self, category: ModelCategory) -> list[ModelInfo]:
        """Get models filtered by category.

        Args:
            category: Model category to filter by

        Returns:
            List of models in the specified category
        """
        models = await self.get_available_models()
        return [m for m in models if m.category == category]

    async def get_models_by_filter(self, model_filter: ModelFilter) -> list[ModelInfo]:
        """Get models matching filter criteria.

        Args:
            model_filter: Filter criteria

        Returns:
            List of models matching the filter
        """
        models = await self.get_available_models()
        return [m for m in models if model_filter.matches(m)]

    async def get_recommended_models(
        self, use_case: str = "general"
    ) -> list[ModelInfo]:
        """Get recommended models for a specific use case.

        Args:
            use_case: Use case ("general", "budget", "speed", "quality", "code")

        Returns:
            List of recommended models
        """
        models = await self.get_available_models()

        if use_case == "budget":
            # Sort by cost, prefer budget category
            return sorted(
                [
                    m
                    for m in models
                    if m.category == ModelCategory.BUDGET
                    or m.prompt_tokens_per_1k <= 0.002
                ],
                key=lambda m: m.prompt_tokens_per_1k,
            )[:5]

        elif use_case == "speed":
            # Prefer fast models
            fast_models = [
                m
                for m in models
                if m.speed_rating == "fast"
                or ModelCapability.FAST in (m.capabilities or [])
            ]
            return fast_models[:5]

        elif use_case == "quality":
            # Prefer latest and specialized models
            quality_models = [
                m
                for m in models
                if m.quality_rating == "excellent"
                or m.category in [ModelCategory.LATEST, ModelCategory.SPECIALIZED]
            ]
            return quality_models[:5]

        elif use_case == "code":
            # Prefer models good for code analysis
            code_models = [
                m
                for m in models
                if ModelCapability.CODE in (m.capabilities or [])
                or "code" in m.description.lower()
            ]
            return code_models[:5]

        else:  # general
            # Return a mix of latest and reliable models
            latest = [m for m in models if m.category == ModelCategory.LATEST][:2]
            budget = [m for m in models if m.category == ModelCategory.BUDGET][:2]
            specialized = [
                m for m in models if m.category == ModelCategory.SPECIALIZED
            ][:1]
            return latest + budget + specialized

    async def get_model_by_id(self, model_id: str) -> ModelInfo | None:
        """Get a specific model by its ID.

        Args:
            model_id: Model identifier

        Returns:
            Model info or None if not found
        """
        if self._is_cache_stale():
            await self._refresh_model_cache()

        return self._model_cache.get(model_id)

    def get_categorized_models(
        self, models: list[ModelInfo]
    ) -> dict[ModelCategory, list[ModelInfo]]:
        """Organize models by category.

        Args:
            models: List of models to categorize

        Returns:
            Dictionary mapping categories to model lists
        """
        categorized = {}
        for model in models:
            if model.category not in categorized:
                categorized[model.category] = []
            categorized[model.category].append(model)

        # Sort within each category
        for category in categorized:
            categorized[category] = sorted(
                categorized[category],
                key=lambda m: (m.prompt_tokens_per_1k, m.display_name),
            )

        return categorized

    async def _refresh_model_cache(self) -> None:
        """Refresh the model cache by fetching from APIs and fallback sources."""
        logger.info("Refreshing model cache...")

        # Try to fetch from APIs first
        api_models = {}

        try:
            # Fetch OpenAI models
            openai_models = await self._fetch_openai_models()
            api_models.update({m.id: m for m in openai_models})
            logger.info(f"Fetched {len(openai_models)} models from OpenAI API")
        except Exception as e:
            logger.warning(f"Failed to fetch OpenAI models: {e}")

        try:
            # Fetch Anthropic models
            anthropic_models = await self._fetch_anthropic_models()
            api_models.update({m.id: m for m in anthropic_models})
            logger.info(f"Fetched {len(anthropic_models)} models from Anthropic API")
        except Exception as e:
            logger.warning(f"Failed to fetch Anthropic models: {e}")

        # Load fallback models from pricing config
        fallback_models = self._load_fallback_models()
        logger.info(
            f"Loaded {len(fallback_models)} fallback models from pricing config"
        )

        # Merge API models with fallback, preferring API data but filling gaps
        merged_models = {}

        # Start with fallback models
        for model in fallback_models:
            merged_models[model.id] = model

        # Override/supplement with API models
        for model_id, api_model in api_models.items():
            if model_id in merged_models:
                # Merge API data with fallback data
                fallback_model = merged_models[model_id]
                api_model.description = (
                    api_model.description or fallback_model.description
                )
                api_model.category = fallback_model.category  # Trust our categorization
                api_model.capabilities = fallback_model.capabilities
                api_model.best_for = fallback_model.best_for
                api_model.notes = fallback_model.notes
                api_model.speed_rating = fallback_model.speed_rating
                api_model.quality_rating = fallback_model.quality_rating

            merged_models[model_id] = api_model

        self._model_cache = merged_models
        self._cache_timestamp = datetime.now()

        logger.info(f"Model cache refreshed with {len(merged_models)} total models")

    async def _fetch_openai_models(self) -> list[ModelInfo]:
        """Fetch models from OpenAI API."""
        try:
            timeout = aiohttp.ClientTimeout(total=self.config.openai_api_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"Authorization": f"Bearer {self._get_openai_api_key()}"}

                async with session.get(
                    self._openai_models_url, headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_openai_models(data)
                    else:
                        logger.error(f"OpenAI API returned status {response.status}")
                        return []

        except Exception as e:
            logger.error(f"Error fetching OpenAI models: {e}")
            return []

    async def _fetch_anthropic_models(self) -> list[ModelInfo]:
        """Fetch models from Anthropic API."""
        try:
            timeout = aiohttp.ClientTimeout(total=self.config.anthropic_api_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {
                    "x-api-key": self._get_anthropic_api_key(),
                    "anthropic-version": "2023-06-01",
                }

                async with session.get(
                    self._anthropic_models_url, headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_anthropic_models(data)
                    else:
                        logger.error(f"Anthropic API returned status {response.status}")
                        return []

        except Exception as e:
            logger.error(f"Error fetching Anthropic models: {e}")
            return []

    def _parse_openai_models(self, api_data: dict[str, Any]) -> list[ModelInfo]:
        """Parse OpenAI API response into ModelInfo objects."""
        models = []

        for model_data in api_data.get("data", []):
            model_id = model_data.get("id", "")

            # Filter to chat models only
            if not self._is_chat_model(model_id, ModelProvider.OPENAI):
                continue

            # Get pricing from pricing manager
            pricing = self.pricing_manager.get_model_pricing(model_id)

            # Parse creation date
            created_at = None
            if model_data.get("created"):
                try:
                    created_at = datetime.fromtimestamp(model_data["created"])
                except (ValueError, TypeError):
                    pass

            model = ModelInfo(
                id=model_id,
                display_name=model_data.get("id", model_id),
                provider=ModelProvider.OPENAI,
                prompt_tokens_per_1k=pricing["prompt_tokens_per_1k"],
                completion_tokens_per_1k=pricing["completion_tokens_per_1k"],
                currency=pricing.get("currency", "USD"),
                description=pricing.get("description", ""),
                created_at=created_at,
                is_available=True,
                is_deprecated=False,
            )

            models.append(model)

        return models

    def _parse_anthropic_models(self, api_data: dict[str, Any]) -> list[ModelInfo]:
        """Parse Anthropic API response into ModelInfo objects."""
        models = []

        for model_data in api_data.get("data", []):
            model_id = model_data.get("id", "")

            # Get pricing from pricing manager
            pricing = self.pricing_manager.get_model_pricing(model_id)

            # Parse creation date
            created_at = None
            if model_data.get("created_at"):
                try:
                    created_at = datetime.fromisoformat(
                        model_data["created_at"].replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass

            model = ModelInfo(
                id=model_id,
                display_name=model_data.get("display_name", model_id),
                provider=ModelProvider.ANTHROPIC,
                prompt_tokens_per_1k=pricing["prompt_tokens_per_1k"],
                completion_tokens_per_1k=pricing["completion_tokens_per_1k"],
                currency=pricing.get("currency", "USD"),
                description=pricing.get("description", ""),
                created_at=created_at,
                is_available=True,
                is_deprecated=False,
            )

            models.append(model)

        return models

    def _load_fallback_models(self) -> list[ModelInfo]:
        """Load models from the pricing configuration as fallback."""
        models = []

        try:
            # Load enhanced pricing config
            pricing_data = self.pricing_manager.pricing_data

            for model_id, pricing_info in pricing_data.get(
                "pricing_models", {}
            ).items():
                # Determine provider from model ID
                provider = self._determine_provider(model_id)
                if not provider:
                    continue

                model = ModelInfo(
                    id=model_id,
                    display_name=pricing_info.get("display_name", model_id),
                    provider=provider,
                    prompt_tokens_per_1k=pricing_info["prompt_tokens_per_1k"],
                    completion_tokens_per_1k=pricing_info["completion_tokens_per_1k"],
                    currency=pricing_info.get("currency", "USD"),
                    description=pricing_info.get("description", ""),
                    category=ModelCategory(pricing_info.get("category", "legacy")),
                    capabilities=[
                        ModelCapability(cap)
                        for cap in pricing_info.get("capabilities", ["chat"])
                    ],
                    max_context_tokens=pricing_info.get("max_context_tokens"),
                    speed_rating=pricing_info.get("speed_rating", "medium"),
                    quality_rating=pricing_info.get("quality_rating", "good"),
                    is_available=pricing_info.get("is_available", True),
                    is_deprecated=pricing_info.get("is_deprecated", False),
                    best_for=pricing_info.get("best_for", []),
                    notes=pricing_info.get("notes", []),
                )

                models.append(model)

        except Exception as e:
            logger.error(f"Error loading fallback models: {e}")

        return models

    def _is_cache_stale(self) -> bool:
        """Check if the model cache needs refreshing."""
        if not self._cache_timestamp:
            return True

        age = datetime.now() - self._cache_timestamp
        max_age = timedelta(hours=self.config.cache_duration_hours)

        return age > max_age

    def _is_chat_model(self, model_id: str, provider: ModelProvider) -> bool:
        """Determine if a model is suitable for chat/completion tasks."""
        # OpenAI model filtering
        if provider == ModelProvider.OPENAI:
            chat_keywords = ["gpt", "turbo", "davinci"]
            exclude_keywords = [
                "embed",
                "whisper",
                "tts",
                "dall-e",
                "search",
                "similarity",
                "edit",
            ]

            model_lower = model_id.lower()

            # Must have chat keywords
            has_chat_keywords = any(keyword in model_lower for keyword in chat_keywords)

            # Must not have exclude keywords
            has_exclude_keywords = any(
                keyword in model_lower for keyword in exclude_keywords
            )

            return has_chat_keywords and not has_exclude_keywords

        # Anthropic models are generally all chat models
        elif provider == ModelProvider.ANTHROPIC:
            return "claude" in model_id.lower()

        return False

    def _determine_provider(self, model_id: str) -> ModelProvider | None:
        """Determine provider from model ID."""
        model_lower = model_id.lower()

        if any(
            keyword in model_lower
            for keyword in ["gpt", "davinci", "text-", "code-", "o3", "o4"]
        ):
            return ModelProvider.OPENAI
        elif "claude" in model_lower:
            return ModelProvider.ANTHROPIC

        return None

    def _get_openai_api_key(self) -> str:
        """Get OpenAI API key from credential manager."""
        try:
            from ..credentials import get_credential_manager

            cred_manager = get_credential_manager()
            return cred_manager.get_llm_api_key("openai") or ""
        except Exception:
            return ""

    def _get_anthropic_api_key(self) -> str:
        """Get Anthropic API key from credential manager."""
        try:
            from ..credentials import get_credential_manager

            cred_manager = get_credential_manager()
            return cred_manager.get_llm_api_key("anthropic") or ""
        except Exception:
            return ""
