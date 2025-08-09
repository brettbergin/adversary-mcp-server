"""Model types and data structures for LLM model management."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class ModelProvider(Enum):
    """LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class ModelCategory(Enum):
    """Model categories for organization."""

    LATEST = "latest"
    BUDGET = "budget"
    SPECIALIZED = "specialized"
    LEGACY = "legacy"


class ModelCapability(Enum):
    """Model capabilities."""

    CHAT = "chat"
    CODE = "code"
    ANALYSIS = "analysis"
    REASONING = "reasoning"
    FAST = "fast"
    HIGH_CONTEXT = "high_context"


@dataclass
class ModelInfo:
    """Comprehensive model information."""

    # Basic identification
    id: str
    display_name: str
    provider: ModelProvider

    # Pricing information
    prompt_tokens_per_1k: float
    completion_tokens_per_1k: float
    currency: str = "USD"

    # Capabilities and metadata
    description: str = ""
    category: ModelCategory = ModelCategory.LEGACY
    capabilities: list[ModelCapability] | None = None
    max_context_tokens: int | None = None

    # Performance characteristics
    speed_rating: str = "medium"  # "fast", "medium", "slow"
    quality_rating: str = "good"  # "excellent", "good", "basic"

    # Availability and versioning
    created_at: datetime | None = None
    is_available: bool = True
    is_deprecated: bool = False

    # Additional metadata
    best_for: list[str] | None = None
    notes: list[str] | None = None

    def __post_init__(self):
        """Initialize default values."""
        if self.capabilities is None:
            self.capabilities = [ModelCapability.CHAT]
        if self.best_for is None:
            self.best_for = []
        if self.notes is None:
            self.notes = []

    @property
    def cost_description(self) -> str:
        """Human-readable cost description."""
        return f"${self.prompt_tokens_per_1k:.3f} / ${self.completion_tokens_per_1k:.3f} per 1k tokens"

    @property
    def provider_name(self) -> str:
        """Formatted provider name."""
        return self.provider.value.title()

    @property
    def category_display(self) -> str:
        """Formatted category for display."""
        category_emojis = {
            ModelCategory.LATEST: "🚀",
            ModelCategory.BUDGET: "💰",
            ModelCategory.SPECIALIZED: "🎯",
            ModelCategory.LEGACY: "📚",
        }
        return f"{category_emojis.get(self.category, '')} {self.category.value.title()}"

    @property
    def capability_tags(self) -> list[str]:
        """Formatted capability tags."""
        capability_formats = {
            ModelCapability.CHAT: "💬 Chat",
            ModelCapability.CODE: "💻 Code",
            ModelCapability.ANALYSIS: "🔍 Analysis",
            ModelCapability.REASONING: "🧠 Reasoning",
            ModelCapability.FAST: "⚡ Fast",
            ModelCapability.HIGH_CONTEXT: "📄 Large Context",
        }
        return [
            capability_formats.get(cap, cap.value) for cap in (self.capabilities or [])
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "display_name": self.display_name,
            "provider": self.provider.value,
            "prompt_tokens_per_1k": self.prompt_tokens_per_1k,
            "completion_tokens_per_1k": self.completion_tokens_per_1k,
            "currency": self.currency,
            "description": self.description,
            "category": self.category.value,
            "capabilities": [cap.value for cap in (self.capabilities or [])],
            "max_context_tokens": self.max_context_tokens,
            "speed_rating": self.speed_rating,
            "quality_rating": self.quality_rating,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_available": self.is_available,
            "is_deprecated": self.is_deprecated,
            "best_for": self.best_for,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelInfo":
        """Create ModelInfo from dictionary."""
        capabilities = None
        if data.get("capabilities"):
            capabilities = [ModelCapability(cap) for cap in data["capabilities"]]

        created_at = None
        if data.get("created_at"):
            try:
                created_at = datetime.fromisoformat(
                    data["created_at"].replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass

        return cls(
            id=data["id"],
            display_name=data["display_name"],
            provider=ModelProvider(data["provider"]),
            prompt_tokens_per_1k=data["prompt_tokens_per_1k"],
            completion_tokens_per_1k=data["completion_tokens_per_1k"],
            currency=data.get("currency", "USD"),
            description=data.get("description", ""),
            category=ModelCategory(data.get("category", "legacy")),
            capabilities=capabilities,
            max_context_tokens=data.get("max_context_tokens"),
            speed_rating=data.get("speed_rating", "medium"),
            quality_rating=data.get("quality_rating", "good"),
            created_at=created_at,
            is_available=data.get("is_available", True),
            is_deprecated=data.get("is_deprecated", False),
            best_for=data.get("best_for", []),
            notes=data.get("notes", []),
        )


@dataclass
class ModelCatalogConfig:
    """Configuration for model catalog operations."""

    # API settings
    openai_api_timeout: float = 10.0
    anthropic_api_timeout: float = 10.0

    # Caching settings
    cache_duration_hours: int = 24
    enable_api_fallback: bool = True

    # Filtering settings
    exclude_deprecated: bool = True
    exclude_unavailable: bool = True

    # Display settings
    max_models_per_category: int = 10
    show_pricing: bool = True
    show_capabilities: bool = True


@dataclass
class ModelFilter:
    """Filter criteria for model selection."""

    provider: ModelProvider | None = None
    category: ModelCategory | None = None
    max_prompt_cost: float | None = None
    max_completion_cost: float | None = None
    min_context_tokens: int | None = None
    capabilities: list[ModelCapability] | None = None
    speed_rating: str | None = None
    quality_rating: str | None = None

    def matches(self, model: ModelInfo) -> bool:
        """Check if model matches filter criteria."""
        if self.provider and model.provider != self.provider:
            return False

        if self.category and model.category != self.category:
            return False

        if self.max_prompt_cost and model.prompt_tokens_per_1k > self.max_prompt_cost:
            return False

        if (
            self.max_completion_cost
            and model.completion_tokens_per_1k > self.max_completion_cost
        ):
            return False

        if self.min_context_tokens and (
            not model.max_context_tokens
            or model.max_context_tokens < self.min_context_tokens
        ):
            return False

        if self.capabilities:
            model_caps = set(model.capabilities or [])
            required_caps = set(self.capabilities)
            if not required_caps.issubset(model_caps):
                return False

        if self.speed_rating and model.speed_rating != self.speed_rating:
            return False

        if self.quality_rating and model.quality_rating != self.quality_rating:
            return False

        return True
