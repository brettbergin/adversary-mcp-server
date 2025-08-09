"""Interactive model selection interface using questionary."""

from typing import Any

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..logger import get_logger
from .model_catalog import ModelCatalogService
from .model_types import ModelCategory, ModelFilter, ModelInfo, ModelProvider

logger = get_logger("model_selector")
console = Console()


class InteractiveModelSelector:
    """Interactive model selection interface."""

    def __init__(self, catalog_service: ModelCatalogService | None = None):
        """Initialize the model selector.

        Args:
            catalog_service: Model catalog service instance
        """
        self.catalog_service = catalog_service or ModelCatalogService()

    async def select_model(
        self,
        provider: ModelProvider | None = None,
        show_categories: bool = True,
        show_recommendations: bool = True,
    ) -> ModelInfo | None:
        """Interactively select a model.

        Args:
            provider: Filter by specific provider
            show_categories: Show models organized by categories
            show_recommendations: Show recommended models first

        Returns:
            Selected model or None if cancelled
        """
        try:
            console.print("\n🤖 [bold]Select LLM Model[/bold]")
            console.print("Loading available models...", style="dim")

            # Get available models
            models = await self.catalog_service.get_available_models(provider=provider)

            if not models:
                console.print(
                    "❌ No models available. Please check your API keys.", style="red"
                )
                return None

            # Show selection interface
            if show_recommendations:
                choice = await self._show_recommendation_menu(models)
                if choice == "custom":
                    return await self._show_custom_selection(models, show_categories)
                elif choice == "view_all":
                    return await self._show_all_models_selection(
                        models, show_categories
                    )
                elif choice and choice.startswith("rec_"):
                    model_id = choice[4:]  # Remove 'rec_' prefix
                    return await self.catalog_service.get_model_by_id(model_id)

            # Show all models if no recommendations or user chose to view all
            return await self._show_all_models_selection(models, show_categories)

        except KeyboardInterrupt:
            console.print("\n❌ Model selection cancelled.", style="yellow")
            return None
        except Exception as e:
            logger.error(f"Error in model selection: {e}")
            console.print(f"❌ Error during model selection: {e}", style="red")
            return None

    async def _show_recommendation_menu(self, models: list[ModelInfo]) -> str | None:
        """Show quick recommendation menu."""
        console.print("\n💡 [bold]Quick Recommendations[/bold]")

        # Get different recommendation types
        general_recs = await self.catalog_service.get_recommended_models("general")
        budget_recs = await self.catalog_service.get_recommended_models("budget")
        speed_recs = await self.catalog_service.get_recommended_models("speed")
        quality_recs = await self.catalog_service.get_recommended_models("quality")

        # Build choices
        choices: list[questionary.Separator | questionary.Choice] = []

        # Top general recommendations
        if general_recs:
            choices.append(
                questionary.Separator("🚀 Recommended for Security Scanning")
            )
            for model in general_recs[:3]:
                choice_text = f"{model.display_name} - {model.cost_description} - {model.description[:60]}..."
                choices.append(questionary.Choice(choice_text, value=f"rec_{model.id}"))

        # Quick access options
        choices.extend(
            [
                questionary.Separator("⚡ Quick Options"),
                questionary.Choice("💰 Budget-friendly models", value="budget"),
                questionary.Choice("🏎️  Fastest models", value="speed"),
                questionary.Choice("🏆 Highest quality models", value="quality"),
                questionary.Separator("📋 Browse All"),
                questionary.Choice("🔍 View all models by category", value="view_all"),
                questionary.Choice("🎛️  Custom filtering", value="custom"),
            ]
        )

        return questionary.select(
            "Choose a model or browse options:",
            choices=choices,
            style=self._get_questionary_style(),
        ).ask()

    async def _show_custom_selection(
        self, models: list[ModelInfo], show_categories: bool
    ) -> ModelInfo | None:
        """Show custom filtering interface."""
        console.print("\n🎛️  [bold]Custom Model Filtering[/bold]")

        # Provider filter
        provider_choice = questionary.select(
            "Filter by provider:",
            choices=["Any provider", "OpenAI only", "Anthropic only"],
        ).ask()

        provider_filter = None
        if provider_choice == "OpenAI only":
            provider_filter = ModelProvider.OPENAI
        elif provider_choice == "Anthropic only":
            provider_filter = ModelProvider.ANTHROPIC

        # Category filter
        category_choice = questionary.select(
            "Filter by category:",
            choices=[
                "All categories",
                "🚀 Latest models",
                "💰 Budget models",
                "🎯 Specialized models",
                "📚 Legacy models",
            ],
        ).ask()

        category_filter = None
        if category_choice == "🚀 Latest models":
            category_filter = ModelCategory.LATEST
        elif category_choice == "💰 Budget models":
            category_filter = ModelCategory.BUDGET
        elif category_choice == "🎯 Specialized models":
            category_filter = ModelCategory.SPECIALIZED
        elif category_choice == "📚 Legacy models":
            category_filter = ModelCategory.LEGACY

        # Cost filter
        cost_choice = questionary.select(
            "Filter by cost (prompt tokens):",
            choices=[
                "Any cost",
                "Under $0.001/1k (Ultra budget)",
                "Under $0.005/1k (Budget)",
                "Under $0.010/1k (Medium)",
                "Any cost",
            ],
        ).ask()

        max_cost = None
        if cost_choice == "Under $0.001/1k (Ultra budget)":
            max_cost = 0.001
        elif cost_choice == "Under $0.005/1k (Budget)":
            max_cost = 0.005
        elif cost_choice == "Under $0.010/1k (Medium)":
            max_cost = 0.010

        # Apply filters
        model_filter = ModelFilter(
            provider=provider_filter, category=category_filter, max_prompt_cost=max_cost
        )

        filtered_models = await self.catalog_service.get_models_by_filter(model_filter)

        if not filtered_models:
            console.print("❌ No models match your criteria.", style="red")
            return None

        return await self._show_model_list_selection(filtered_models, "Filtered Models")

    async def _show_all_models_selection(
        self, models: list[ModelInfo], show_categories: bool
    ) -> ModelInfo | None:
        """Show all models organized by category."""
        if show_categories:
            return await self._show_categorized_selection(models)
        else:
            return await self._show_model_list_selection(models, "All Models")

    async def _show_categorized_selection(
        self, models: list[ModelInfo]
    ) -> ModelInfo | None:
        """Show models organized by categories."""
        console.print("\n📋 [bold]Models by Category[/bold]")

        categorized = self.catalog_service.get_categorized_models(models)

        # Build category choices
        category_choices = []
        for category, category_models in categorized.items():
            emoji = (
                "🚀"
                if category == ModelCategory.LATEST
                else (
                    "💰"
                    if category == ModelCategory.BUDGET
                    else "🎯" if category == ModelCategory.SPECIALIZED else "📚"
                )
            )
            choice_text = (
                f"{emoji} {category.value.title()} ({len(category_models)} models)"
            )
            category_choices.append(questionary.Choice(choice_text, value=category))

        selected_category = questionary.select(
            "Select a category to browse:",
            choices=category_choices,
            style=self._get_questionary_style(),
        ).ask()

        if not selected_category:
            return None

        category_models = categorized[selected_category]
        return await self._show_model_list_selection(
            category_models, f"{selected_category.value.title()} Models"
        )

    async def _show_model_list_selection(
        self, models: list[ModelInfo], title: str
    ) -> ModelInfo | None:
        """Show a list of models for selection."""
        console.print(f"\n📋 [bold]{title}[/bold]")

        # Display models table first
        self._display_models_table(models)

        # Build selection choices
        choices = []
        for model in models:
            # Format choice text with key information
            choice_text = f"{model.display_name} ({model.provider_name}) - {model.cost_description}"
            if model.max_context_tokens:
                choice_text += f" - {model.max_context_tokens//1000}k context"

            choices.append(questionary.Choice(choice_text, value=model.id))

        selected_id = questionary.select(
            f"Select from {len(models)} available models:",
            choices=choices,
            style=self._get_questionary_style(),
        ).ask()

        if not selected_id:
            return None

        # Get and display selected model details
        selected_model = await self.catalog_service.get_model_by_id(selected_id)
        if selected_model:
            self._display_model_details(selected_model)

            # Confirm selection
            confirmed = questionary.confirm(
                f"Use {selected_model.display_name}?",
                style=self._get_questionary_style(),
            ).ask()

            if confirmed:
                return selected_model

        return None

    def _display_models_table(self, models: list[ModelInfo]) -> None:
        """Display a table of models."""
        table = Table(
            title="Available Models", show_header=True, header_style="bold magenta"
        )

        table.add_column("Model", style="cyan", no_wrap=True)
        table.add_column("Provider", style="green")
        table.add_column("Category", style="blue")
        table.add_column("Cost/1k", style="yellow")
        table.add_column("Speed", style="red")
        table.add_column("Context", style="magenta")
        table.add_column("Best For", style="dim")

        for model in models[:15]:  # Limit to first 15 to avoid overwhelming
            category_emoji = (
                "🚀"
                if model.category == ModelCategory.LATEST
                else (
                    "💰"
                    if model.category == ModelCategory.BUDGET
                    else "🎯" if model.category == ModelCategory.SPECIALIZED else "📚"
                )
            )

            speed_emoji = (
                "⚡"
                if model.speed_rating == "fast"
                else "🐌" if model.speed_rating == "slow" else "⚖️"
            )

            context = (
                f"{model.max_context_tokens//1000}k"
                if model.max_context_tokens
                else "N/A"
            )

            best_for = ", ".join(model.best_for[:2]) if model.best_for else "General"
            if model.best_for and len(model.best_for) > 2:
                best_for += "..."

            table.add_row(
                model.display_name,
                model.provider_name,
                f"{category_emoji} {model.category.value}",
                f"${model.prompt_tokens_per_1k:.3f}/${model.completion_tokens_per_1k:.3f}",
                f"{speed_emoji} {model.speed_rating}",
                context,
                best_for,
            )

        if len(models) > 15:
            table.add_row(
                "...", "...", "...", "...", "...", "...", f"({len(models)-15} more)"
            )

        console.print(table)

    def _display_model_details(self, model: ModelInfo) -> None:
        """Display detailed information about a model."""
        # Create rich content
        content = []

        # Basic info
        content.append(f"[bold]{model.display_name}[/bold] ({model.provider_name})")
        content.append(f"[dim]{model.description}[/dim]")
        content.append("")

        # Pricing
        content.append(f"💰 [bold]Pricing:[/bold] {model.cost_description}")

        # Performance
        speed_emoji = (
            "⚡"
            if model.speed_rating == "fast"
            else "🐌" if model.speed_rating == "slow" else "⚖️"
        )
        quality_emoji = (
            "🏆"
            if model.quality_rating == "excellent"
            else "👍" if model.quality_rating == "good" else "👌"
        )
        content.append(
            f"🏎️  [bold]Speed:[/bold] {speed_emoji} {model.speed_rating.title()}"
        )
        content.append(
            f"⭐ [bold]Quality:[/bold] {quality_emoji} {model.quality_rating.title()}"
        )

        # Context
        if model.max_context_tokens:
            content.append(
                f"📄 [bold]Context:[/bold] {model.max_context_tokens:,} tokens"
            )

        # Capabilities
        if model.capabilities:
            caps_text = " ".join(model.capability_tags)
            content.append(f"🛠️  [bold]Capabilities:[/bold] {caps_text}")

        # Best for
        if model.best_for:
            content.append(f"✨ [bold]Best for:[/bold] {', '.join(model.best_for)}")

        # Notes
        if model.notes:
            content.append("")
            content.append("[bold]Notes:[/bold]")
            for note in model.notes:
                content.append(f"  • {note}")

        panel = Panel("\n".join(content), title="Model Details", border_style="blue")
        console.print(panel)

    def _get_questionary_style(self) -> Any:
        """Get consistent questionary styling."""
        return questionary.Style(
            [
                ("question", "fg:#ff0066 bold"),
                ("answer", "fg:#44ff00 bold"),
                ("pointer", "fg:#ff0066 bold"),
                ("highlighted", "fg:#ff0066 bold"),
                ("selected", "fg:#44ff00"),
                ("separator", "fg:#cc5454"),
                ("instruction", "fg:#999999"),
                ("text", ""),
            ]
        )


async def select_model_interactive(
    provider: ModelProvider | None = None,
    show_categories: bool = True,
    show_recommendations: bool = True,
) -> ModelInfo | None:
    """Convenience function for interactive model selection.

    Args:
        provider: Filter by specific provider
        show_categories: Show models organized by categories
        show_recommendations: Show recommended models first

    Returns:
        Selected model or None if cancelled
    """
    selector = InteractiveModelSelector()
    return await selector.select_model(
        provider=provider,
        show_categories=show_categories,
        show_recommendations=show_recommendations,
    )
