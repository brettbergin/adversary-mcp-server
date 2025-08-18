"""LLM pricing management for cost estimation."""

import json
from pathlib import Path
from typing import Any

from ..logger import get_logger

logger = get_logger("pricing_manager")


class PricingManager:
    """Manages LLM model pricing configuration and cost calculations."""

    def __init__(self, config_path: str | Path | None = None):
        """Initialize pricing manager.

        Args:
            config_path: Path to pricing configuration file. If None, uses default location.
        """
        if config_path is None:
            config_path = Path(__file__).parent / "pricing_config.json"

        self.config_path = Path(config_path)
        self.pricing_data: dict[str, Any] = {}
        self._load_pricing_config()

    def _load_pricing_config(self) -> None:
        """Load pricing configuration from JSON file."""
        try:
            if not self.config_path.exists():
                logger.warning(
                    f"Pricing config not found at {self.config_path}, using defaults"
                )
                self._create_default_config()
                return

            with open(self.config_path, encoding="utf-8") as f:
                self.pricing_data = json.load(f)
                logger.debug(f"Loaded pricing config from {self.config_path}")
                logger.debug(
                    f"Supported models: {list(self.pricing_data.get('pricing_models', {}).keys())}"
                )

        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load pricing config from {self.config_path}: {e}")
            logger.warning("Falling back to hardcoded default pricing")
            self._create_default_config()

    def _create_default_config(self) -> None:
        """Create default pricing configuration."""
        self.pricing_data = {
            "pricing_models": {
                "gpt-4": {
                    "prompt_tokens_per_1k": 0.01,
                    "completion_tokens_per_1k": 0.03,
                    "currency": "USD",
                    "description": "GPT-4 default pricing",
                }
            },
            "default_pricing": {
                "prompt_tokens_per_1k": 0.01,
                "completion_tokens_per_1k": 0.03,
                "currency": "USD",
                "description": "Default pricing for unknown models",
            },
            "metadata": {
                "last_updated": "2025-01-09",
                "version": "1.0",
                "source": "Default configuration",
            },
        }
        logger.debug("Created default pricing configuration")

    def get_model_pricing(self, model_name: str) -> dict[str, Any]:
        """Get pricing information for a specific model.

        Args:
            model_name: Name of the LLM model

        Returns:
            Dictionary with pricing information
        """
        pricing_models = self.pricing_data.get("pricing_models", {})

        # Try exact match first
        if model_name in pricing_models:
            logger.debug(f"Found exact pricing match for model: {model_name}")
            return pricing_models[model_name]

        # Try partial matches for model variants (e.g., "gpt-4-0314" matches "gpt-4")
        for config_model, pricing in pricing_models.items():
            if model_name.startswith(config_model):
                logger.debug(
                    f"Found partial pricing match: {model_name} -> {config_model}"
                )
                return pricing

        # Fall back to default pricing
        default_pricing = self.pricing_data.get(
            "default_pricing",
            {
                "prompt_tokens_per_1k": 0.01,
                "completion_tokens_per_1k": 0.03,
                "currency": "USD",
                "description": "Default pricing",
            },
        )

        logger.warning(
            f"No pricing found for model {model_name}, using default pricing"
        )
        return default_pricing

    def calculate_cost(
        self, model_name: str, prompt_tokens: int, completion_tokens: int
    ) -> dict[str, Any]:
        """Calculate cost for token usage.

        Args:
            model_name: Name of the LLM model used
            prompt_tokens: Number of prompt tokens consumed
            completion_tokens: Number of completion tokens generated

        Returns:
            Dictionary with cost breakdown
        """
        pricing = self.get_model_pricing(model_name)

        prompt_cost = (prompt_tokens * pricing["prompt_tokens_per_1k"]) / 1000
        completion_cost = (
            completion_tokens * pricing["completion_tokens_per_1k"]
        ) / 1000
        total_cost = prompt_cost + completion_cost

        cost_breakdown = {
            "prompt_cost": round(prompt_cost, 6),
            "completion_cost": round(completion_cost, 6),
            "total_cost": round(total_cost, 6),
            "currency": pricing.get("currency", "USD"),
            "model": model_name,
            "pricing_source": pricing.get("description", "Unknown"),
            "tokens": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }

        logger.debug(
            f"Cost calculation for {model_name}: "
            f"{prompt_tokens} prompt + {completion_tokens} completion tokens = "
            f"${total_cost:.6f} {pricing.get('currency', 'USD')}"
        )

        return cost_breakdown

    def get_supported_models(self) -> list[str]:
        """Get list of models with configured pricing.

        Returns:
            List of supported model names
        """
        return list(self.pricing_data.get("pricing_models", {}).keys())

    def get_models_by_provider(
        self, provider: str, available_only: bool = True
    ) -> list[dict[str, Any]]:
        """Get list of models for a specific provider.

        Args:
            provider: Provider name ('openai', 'anthropic')
            available_only: Only return available models (not deprecated)

        Returns:
            List of model info dictionaries with id, display_name, category, etc.
        """
        models = []
        pricing_models = self.pricing_data.get("pricing_models", {})

        for model_id, model_info in pricing_models.items():
            # Determine provider from model ID
            model_provider = self._determine_model_provider(model_id)

            if model_provider != provider.lower():
                continue

            # Filter out unavailable/deprecated models if requested
            if available_only:
                if not model_info.get("is_available", True):
                    continue
                if model_info.get("is_deprecated", False):
                    continue

            models.append(
                {
                    "id": model_id,
                    "display_name": model_info.get("display_name", model_id),
                    "category": model_info.get("category", "legacy"),
                    "description": model_info.get("description", ""),
                    "capabilities": model_info.get("capabilities", []),
                    "best_for": model_info.get("best_for", []),
                    "notes": model_info.get("notes", []),
                    "speed_rating": model_info.get("speed_rating", "medium"),
                    "quality_rating": model_info.get("quality_rating", "good"),
                    "prompt_tokens_per_1k": model_info["prompt_tokens_per_1k"],
                    "completion_tokens_per_1k": model_info["completion_tokens_per_1k"],
                    "currency": model_info.get("currency", "USD"),
                }
            )

        # Sort by category priority (latest > specialized > budget > legacy)
        category_priority = {"latest": 0, "specialized": 1, "budget": 2, "legacy": 3}
        models.sort(key=lambda m: (category_priority.get(m["category"], 4), m["id"]))

        return models

    def _determine_model_provider(self, model_id: str) -> str:
        """Determine provider from model ID.

        Args:
            model_id: Model identifier

        Returns:
            Provider name ('openai', 'anthropic', or 'unknown')
        """
        model_lower = model_id.lower()

        # OpenAI patterns
        if any(
            keyword in model_lower
            for keyword in ["gpt", "davinci", "text-", "code-", "o3", "o4"]
        ):
            return "openai"
        # Anthropic patterns
        elif "claude" in model_lower:
            return "anthropic"

        return "unknown"

    def estimate_cost_for_usage_scenario(
        self, model_id: str, scenario: str = "typical"
    ) -> dict[str, Any]:
        """Estimate cost for common usage scenarios.

        Args:
            model_id: Model identifier
            scenario: Usage scenario ('light', 'typical', 'heavy')

        Returns:
            Dictionary with cost estimates for the scenario
        """
        pricing = self.get_model_pricing(model_id)

        # Define usage scenarios (prompt tokens, completion tokens per request, requests per day)
        scenarios = {
            "light": {
                "prompt_tokens": 500,
                "completion_tokens": 200,
                "requests_per_day": 10,
            },
            "typical": {
                "prompt_tokens": 1500,
                "completion_tokens": 600,
                "requests_per_day": 50,
            },
            "heavy": {
                "prompt_tokens": 3000,
                "completion_tokens": 1200,
                "requests_per_day": 200,
            },
        }

        if scenario not in scenarios:
            scenario = "typical"

        usage = scenarios[scenario]

        # Calculate costs
        prompt_cost_per_request = (
            usage["prompt_tokens"] * pricing["prompt_tokens_per_1k"]
        ) / 1000
        completion_cost_per_request = (
            usage["completion_tokens"] * pricing["completion_tokens_per_1k"]
        ) / 1000
        cost_per_request = prompt_cost_per_request + completion_cost_per_request

        daily_cost = cost_per_request * usage["requests_per_day"]
        monthly_cost = daily_cost * 30

        return {
            "scenario": scenario,
            "cost_per_request": round(cost_per_request, 4),
            "daily_cost": round(daily_cost, 2),
            "monthly_cost": round(monthly_cost, 2),
            "currency": pricing.get("currency", "USD"),
            "usage_details": {
                "prompt_tokens_per_request": usage["prompt_tokens"],
                "completion_tokens_per_request": usage["completion_tokens"],
                "requests_per_day": usage["requests_per_day"],
            },
        }

    def get_config_metadata(self) -> dict[str, Any]:
        """Get metadata about the pricing configuration.

        Returns:
            Dictionary with configuration metadata
        """
        return self.pricing_data.get("metadata", {})

    def refresh_config(self) -> bool:
        """Reload pricing configuration from file.

        Returns:
            True if successful, False otherwise
        """
        try:
            self._load_pricing_config()
            logger.info("Pricing configuration refreshed successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to refresh pricing configuration: {e}")
            return False

    def validate_config(self) -> list[str]:
        """Validate the current pricing configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        if not isinstance(self.pricing_data, dict):
            errors.append("Pricing data must be a dictionary")
            return errors

        # Check required sections
        required_sections = ["pricing_models", "default_pricing"]
        for section in required_sections:
            if section not in self.pricing_data:
                errors.append(f"Missing required section: {section}")

        # Validate pricing models
        pricing_models = self.pricing_data.get("pricing_models", {})
        if not isinstance(pricing_models, dict):
            errors.append("pricing_models must be a dictionary")
        else:
            for model_name, pricing in pricing_models.items():
                if not isinstance(pricing, dict):
                    errors.append(f"Pricing for {model_name} must be a dictionary")
                    continue

                required_fields = ["prompt_tokens_per_1k", "completion_tokens_per_1k"]
                for field in required_fields:
                    if field not in pricing:
                        errors.append(f"Missing {field} for model {model_name}")
                    elif (
                        not isinstance(pricing[field], int | float)
                        or pricing[field] < 0
                    ):
                        errors.append(
                            f"Invalid {field} for model {model_name}: must be non-negative number"
                        )

        # Validate default pricing
        default_pricing = self.pricing_data.get("default_pricing", {})
        if not isinstance(default_pricing, dict):
            errors.append("default_pricing must be a dictionary")
        else:
            required_fields = ["prompt_tokens_per_1k", "completion_tokens_per_1k"]
            for field in required_fields:
                if field not in default_pricing:
                    errors.append(f"Missing {field} in default_pricing")
                elif (
                    not isinstance(default_pricing[field], int | float)
                    or default_pricing[field] < 0
                ):
                    errors.append(
                        f"Invalid {field} in default_pricing: must be non-negative number"
                    )

        if not errors:
            logger.debug("Pricing configuration validation passed")
        else:
            logger.warning(f"Pricing configuration validation failed: {errors}")

        return errors
