"""Tests for LLM model selector module."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.llm.model_selector import (
    InteractiveModelSelector,
    select_model_interactive,
)
from adversary_mcp_server.llm.model_types import ModelCategory, ModelInfo, ModelProvider


@pytest.fixture
def mock_model_info():
    """Create mock ModelInfo objects for testing."""
    from adversary_mcp_server.llm.model_types import ModelCapability

    return [
        ModelInfo(
            id="gpt-4",
            display_name="GPT-4",
            provider=ModelProvider.OPENAI,
            prompt_tokens_per_1k=0.03,
            completion_tokens_per_1k=0.06,
            category=ModelCategory.LATEST,
            description="Most capable GPT model",
            max_context_tokens=8192,
            speed_rating="medium",
            quality_rating="excellent",
            capabilities=[ModelCapability.CHAT, ModelCapability.ANALYSIS],
            best_for=["analysis", "writing"],
            notes=["High quality responses"],
        ),
        ModelInfo(
            id="gpt-3.5-turbo",
            display_name="GPT-3.5 Turbo",
            provider=ModelProvider.OPENAI,
            prompt_tokens_per_1k=0.001,
            completion_tokens_per_1k=0.002,
            category=ModelCategory.BUDGET,
            description="Fast and efficient model",
            max_context_tokens=4096,
            speed_rating="fast",
            quality_rating="good",
            capabilities=[ModelCapability.CHAT, ModelCapability.FAST],
            best_for=["quick responses"],
            notes=["Budget friendly"],
        ),
        ModelInfo(
            id="claude-3-opus",
            display_name="Claude 3 Opus",
            provider=ModelProvider.ANTHROPIC,
            prompt_tokens_per_1k=0.015,
            completion_tokens_per_1k=0.075,
            category=ModelCategory.LATEST,
            description="Most powerful Claude model",
            max_context_tokens=200000,
            speed_rating="medium",
            quality_rating="excellent",
            capabilities=[
                ModelCapability.CHAT,
                ModelCapability.ANALYSIS,
                ModelCapability.HIGH_CONTEXT,
            ],
            best_for=["complex analysis", "long documents"],
            notes=["Excellent reasoning"],
        ),
    ]


class TestInteractiveModelSelector:
    """Test InteractiveModelSelector class."""

    def setup_method(self):
        """Setup test fixtures."""
        self.mock_catalog = Mock()
        self.selector = InteractiveModelSelector(catalog_service=self.mock_catalog)

    def test_initialization_with_catalog(self):
        """Test initialization with provided catalog service."""
        selector = InteractiveModelSelector(catalog_service=self.mock_catalog)
        assert selector.catalog_service is self.mock_catalog

    def test_initialization_without_catalog(self):
        """Test initialization without catalog service creates default."""
        with patch(
            "adversary_mcp_server.llm.model_selector.ModelCatalogService"
        ) as mock_service:
            selector = InteractiveModelSelector()
            mock_service.assert_called_once()

    @pytest.mark.asyncio
    async def test_select_model_no_models_available(self, mock_model_info):
        """Test select_model when no models are available."""
        self.mock_catalog.get_available_models = AsyncMock(return_value=[])

        with patch("adversary_mcp_server.llm.model_selector.console") as mock_console:
            result = await self.selector.select_model()

            assert result is None
            mock_console.print.assert_any_call(
                "❌ No models available. Please check your API keys.", style="red"
            )

    @pytest.mark.asyncio
    async def test_select_model_keyboard_interrupt(self, mock_model_info):
        """Test select_model handles keyboard interrupt."""
        self.mock_catalog.get_available_models = AsyncMock(
            side_effect=KeyboardInterrupt()
        )

        with patch("adversary_mcp_server.llm.model_selector.console") as mock_console:
            result = await self.selector.select_model()

            assert result is None
            mock_console.print.assert_any_call(
                "\n❌ Model selection cancelled.", style="yellow"
            )

    @pytest.mark.asyncio
    async def test_select_model_exception_handling(self, mock_model_info):
        """Test select_model handles general exceptions."""
        self.mock_catalog.get_available_models = AsyncMock(
            side_effect=Exception("Test error")
        )

        with patch("adversary_mcp_server.llm.model_selector.console") as mock_console:
            result = await self.selector.select_model()

            assert result is None
            mock_console.print.assert_any_call(
                "❌ Error during model selection: Test error", style="red"
            )

    @pytest.mark.asyncio
    async def test_show_recommendation_menu(self, mock_model_info):
        """Test _show_recommendation_menu builds correct choices."""
        # Setup mock returns
        self.mock_catalog.get_recommended_models = AsyncMock(
            return_value=mock_model_info[:2]
        )

        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Separator = Mock()
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = "rec_gpt-4"

            result = await self.selector._show_recommendation_menu(mock_model_info)

            assert result == "rec_gpt-4"
            # Verify questionary.select was called
            mock_questionary.select.assert_called_once()

    @pytest.mark.asyncio
    async def test_show_recommendation_menu_no_recommendations(self, mock_model_info):
        """Test _show_recommendation_menu with no recommendations."""
        self.mock_catalog.get_recommended_models = AsyncMock(return_value=[])

        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Separator = Mock()
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = "custom"

            result = await self.selector._show_recommendation_menu(mock_model_info)

            assert result == "custom"

    @pytest.mark.asyncio
    async def test_show_custom_selection_all_filters(self, mock_model_info):
        """Test _show_custom_selection with various filter combinations."""
        # Mock questionary responses
        responses = [
            "OpenAI only",  # provider choice
            "🚀 Latest models",  # category choice
            "Under $0.005/1k (Budget)",  # cost choice
        ]

        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.select.return_value.ask.side_effect = responses

            self.mock_catalog.get_models_by_filter = AsyncMock(
                return_value=mock_model_info[:1]
            )

            with patch.object(
                self.selector,
                "_show_model_list_selection",
                return_value=mock_model_info[0],
            ) as mock_list:
                result = await self.selector._show_custom_selection(
                    mock_model_info, True
                )

                assert result == mock_model_info[0]

                # Verify filter was created correctly
                call_args = self.mock_catalog.get_models_by_filter.call_args[0][0]
                assert call_args.provider == ModelProvider.OPENAI
                assert call_args.category == ModelCategory.LATEST
                assert call_args.max_prompt_cost == 0.005

    @pytest.mark.asyncio
    async def test_show_custom_selection_no_matches(self, mock_model_info):
        """Test _show_custom_selection when no models match filters."""
        responses = ["Any provider", "All categories", "Any cost"]

        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.select.return_value.ask.side_effect = responses

            self.mock_catalog.get_models_by_filter = AsyncMock(return_value=[])

            with patch(
                "adversary_mcp_server.llm.model_selector.console"
            ) as mock_console:
                result = await self.selector._show_custom_selection(
                    mock_model_info, True
                )

                assert result is None
                mock_console.print.assert_any_call(
                    "❌ No models match your criteria.", style="red"
                )

    @pytest.mark.asyncio
    async def test_show_all_models_selection_with_categories(self, mock_model_info):
        """Test _show_all_models_selection with categories enabled."""
        with patch.object(
            self.selector,
            "_show_categorized_selection",
            return_value=mock_model_info[0],
        ) as mock_cat:
            result = await self.selector._show_all_models_selection(
                mock_model_info, True
            )

            assert result == mock_model_info[0]
            mock_cat.assert_called_once_with(mock_model_info)

    @pytest.mark.asyncio
    async def test_show_all_models_selection_without_categories(self, mock_model_info):
        """Test _show_all_models_selection without categories."""
        with patch.object(
            self.selector, "_show_model_list_selection", return_value=mock_model_info[0]
        ) as mock_list:
            result = await self.selector._show_all_models_selection(
                mock_model_info, False
            )

            assert result == mock_model_info[0]
            mock_list.assert_called_once_with(mock_model_info, "All Models")

    @pytest.mark.asyncio
    async def test_show_categorized_selection(self, mock_model_info):
        """Test _show_categorized_selection functionality."""
        # Mock categorized models
        categorized = {
            ModelCategory.LATEST: [mock_model_info[0], mock_model_info[2]],
            ModelCategory.BUDGET: [mock_model_info[1]],
        }
        self.mock_catalog.get_categorized_models.return_value = categorized

        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = ModelCategory.LATEST

            with patch.object(
                self.selector,
                "_show_model_list_selection",
                return_value=mock_model_info[0],
            ) as mock_list:
                result = await self.selector._show_categorized_selection(
                    mock_model_info
                )

                assert result == mock_model_info[0]
                mock_list.assert_called_once_with(
                    [mock_model_info[0], mock_model_info[2]], "Latest Models"
                )

    @pytest.mark.asyncio
    async def test_show_categorized_selection_cancelled(self, mock_model_info):
        """Test _show_categorized_selection when user cancels."""
        categorized = {ModelCategory.LATEST: mock_model_info}
        self.mock_catalog.get_categorized_models.return_value = categorized

        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = None

            result = await self.selector._show_categorized_selection(mock_model_info)
            assert result is None

    @pytest.mark.asyncio
    async def test_show_model_list_selection_confirmed(self, mock_model_info):
        """Test _show_model_list_selection with confirmed selection."""
        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = "gpt-4"
            mock_questionary.confirm.return_value.ask.return_value = True

            self.mock_catalog.get_model_by_id = AsyncMock(
                return_value=mock_model_info[0]
            )

            with (
                patch.object(self.selector, "_display_models_table") as mock_table,
                patch.object(self.selector, "_display_model_details") as mock_details,
            ):

                result = await self.selector._show_model_list_selection(
                    mock_model_info, "Test Models"
                )

                assert result == mock_model_info[0]
                mock_table.assert_called_once_with(mock_model_info)
                mock_details.assert_called_once_with(mock_model_info[0])

    @pytest.mark.asyncio
    async def test_show_model_list_selection_not_confirmed(self, mock_model_info):
        """Test _show_model_list_selection with declined confirmation."""
        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = "gpt-4"
            mock_questionary.confirm.return_value.ask.return_value = False

            self.mock_catalog.get_model_by_id = AsyncMock(
                return_value=mock_model_info[0]
            )

            with (
                patch.object(self.selector, "_display_models_table"),
                patch.object(self.selector, "_display_model_details"),
            ):

                result = await self.selector._show_model_list_selection(
                    mock_model_info, "Test Models"
                )
                assert result is None

    @pytest.mark.asyncio
    async def test_show_model_list_selection_cancelled(self, mock_model_info):
        """Test _show_model_list_selection when user cancels selection."""
        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = None

            with patch.object(self.selector, "_display_models_table"):
                result = await self.selector._show_model_list_selection(
                    mock_model_info, "Test Models"
                )
                assert result is None

    def test_display_models_table(self, mock_model_info):
        """Test _display_models_table creates proper table."""
        with (
            patch("adversary_mcp_server.llm.model_selector.Table") as mock_table,
            patch("adversary_mcp_server.llm.model_selector.console") as mock_console,
        ):

            mock_table_instance = Mock()
            mock_table.return_value = mock_table_instance

            self.selector._display_models_table(mock_model_info)

            # Verify table was created and columns added
            mock_table.assert_called_once()
            assert mock_table_instance.add_column.call_count == 7  # 7 columns
            assert mock_table_instance.add_row.call_count == len(mock_model_info)
            mock_console.print.assert_called_once_with(mock_table_instance)

    def test_display_models_table_truncated(self, mock_model_info):
        """Test _display_models_table truncates long lists."""
        # Create a list with more than 15 models
        long_model_list = mock_model_info * 6  # 18 models

        with (
            patch("adversary_mcp_server.llm.model_selector.Table") as mock_table,
            patch("adversary_mcp_server.llm.model_selector.console"),
        ):

            mock_table_instance = Mock()
            mock_table.return_value = mock_table_instance

            self.selector._display_models_table(long_model_list)

            # Should have 15 models + 1 "..." row
            assert mock_table_instance.add_row.call_count == 16

    def test_display_model_details(self, mock_model_info):
        """Test _display_model_details creates proper panel."""
        model = mock_model_info[0]

        with (
            patch("adversary_mcp_server.llm.model_selector.Panel") as mock_panel,
            patch("adversary_mcp_server.llm.model_selector.console") as mock_console,
        ):

            mock_panel_instance = Mock()
            mock_panel.return_value = mock_panel_instance

            self.selector._display_model_details(model)

            # Verify panel was created with content
            mock_panel.assert_called_once()
            call_args = mock_panel.call_args[0][0]

            # Check that key information is included
            assert model.display_name in call_args
            assert model.description in call_args
            assert model.cost_description in call_args

            mock_console.print.assert_called_once_with(mock_panel_instance)

    def test_display_model_details_with_all_fields(self, mock_model_info):
        """Test _display_model_details with all optional fields."""
        model = mock_model_info[0]  # This model has all fields populated

        with (
            patch("adversary_mcp_server.llm.model_selector.Panel") as mock_panel,
            patch("adversary_mcp_server.llm.model_selector.console"),
        ):

            self.selector._display_model_details(model)

            call_args = mock_panel.call_args[0][0]

            # Verify all sections are included
            assert "Pricing:" in call_args
            assert "Speed:" in call_args
            assert "Quality:" in call_args
            assert "Context:" in call_args
            assert "Capabilities:" in call_args
            assert "Best for:" in call_args
            assert "Notes:" in call_args

    def test_get_questionary_style(self):
        """Test _get_questionary_style returns valid style."""
        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_style = Mock()
            mock_questionary.Style.return_value = mock_style

            result = self.selector._get_questionary_style()

            assert result == mock_style
            mock_questionary.Style.assert_called_once()

            # Verify style configuration was passed
            style_config = mock_questionary.Style.call_args[0][0]
            assert isinstance(style_config, list)
            assert len(style_config) > 0


class TestSelectModelInteractive:
    """Test the select_model_interactive convenience function."""

    @pytest.mark.asyncio
    async def test_select_model_interactive_default_args(self, mock_model_info):
        """Test select_model_interactive with default arguments."""
        with patch(
            "adversary_mcp_server.llm.model_selector.InteractiveModelSelector"
        ) as mock_selector_class:
            mock_selector = Mock()
            mock_selector.select_model = AsyncMock(return_value=mock_model_info[0])
            mock_selector_class.return_value = mock_selector

            result = await select_model_interactive()

            assert result == mock_model_info[0]
            mock_selector.select_model.assert_called_once_with(
                provider=None,
                show_categories=True,
                show_recommendations=True,
            )

    @pytest.mark.asyncio
    async def test_select_model_interactive_custom_args(self, mock_model_info):
        """Test select_model_interactive with custom arguments."""
        with patch(
            "adversary_mcp_server.llm.model_selector.InteractiveModelSelector"
        ) as mock_selector_class:
            mock_selector = Mock()
            mock_selector.select_model = AsyncMock(return_value=mock_model_info[1])
            mock_selector_class.return_value = mock_selector

            result = await select_model_interactive(
                provider=ModelProvider.OPENAI,
                show_categories=False,
                show_recommendations=False,
            )

            assert result == mock_model_info[1]
            mock_selector.select_model.assert_called_once_with(
                provider=ModelProvider.OPENAI,
                show_categories=False,
                show_recommendations=False,
            )


class TestModelSelectorIntegration:
    """Integration tests for model selector."""

    @pytest.mark.asyncio
    async def test_full_recommendation_flow(self, mock_model_info):
        """Test complete recommendation flow."""
        mock_catalog = Mock()
        mock_catalog.get_available_models = AsyncMock(return_value=mock_model_info)
        mock_catalog.get_recommended_models = AsyncMock(
            return_value=mock_model_info[:2]
        )
        mock_catalog.get_model_by_id = AsyncMock(return_value=mock_model_info[0])

        selector = InteractiveModelSelector(catalog_service=mock_catalog)

        # Mock questionary to select a recommendation
        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Separator = Mock()
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = "rec_gpt-4"

            with patch("adversary_mcp_server.llm.model_selector.console"):
                result = await selector.select_model(show_recommendations=True)

                assert result == mock_model_info[0]
                mock_catalog.get_model_by_id.assert_called_once_with("gpt-4")

    @pytest.mark.asyncio
    async def test_full_custom_filter_flow(self, mock_model_info):
        """Test complete custom filtering flow."""
        mock_catalog = Mock()
        mock_catalog.get_available_models = AsyncMock(return_value=mock_model_info)
        mock_catalog.get_recommended_models = AsyncMock(
            return_value=mock_model_info[:2]
        )
        mock_catalog.get_models_by_filter = AsyncMock(return_value=[mock_model_info[1]])
        mock_catalog.get_model_by_id = AsyncMock(return_value=mock_model_info[1])

        selector = InteractiveModelSelector(catalog_service=mock_catalog)

        # Mock questionary responses for recommendation menu -> custom
        recommendation_responses = ["custom"]

        # Mock responses for custom filtering
        custom_responses = [
            "OpenAI only",
            "💰 Budget models",
            "Under $0.005/1k (Budget)",
        ]

        # Mock responses for model selection
        selection_responses = ["gpt-3.5-turbo"]
        confirmation_responses = [True]

        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Separator = Mock()
            mock_questionary.Choice = Mock()

            # Setup different mock responses for different call patterns
            select_mock = Mock()
            confirm_mock = Mock()

            select_mock.ask.side_effect = (
                recommendation_responses + custom_responses + selection_responses
            )
            confirm_mock.ask.side_effect = confirmation_responses

            mock_questionary.select.return_value = select_mock
            mock_questionary.confirm.return_value = confirm_mock

            with (
                patch("adversary_mcp_server.llm.model_selector.console"),
                patch.object(selector, "_display_models_table"),
                patch.object(selector, "_display_model_details"),
            ):

                result = await selector.select_model(show_recommendations=True)

                assert result == mock_model_info[1]
                # Verify filter was applied
                mock_catalog.get_models_by_filter.assert_called_once()


class TestErrorHandling:
    """Test error handling scenarios."""

    @pytest.mark.asyncio
    async def test_catalog_service_error_in_get_available_models(self):
        """Test handling of catalog service errors."""
        mock_catalog = Mock()
        mock_catalog.get_available_models = AsyncMock(
            side_effect=Exception("Catalog error")
        )

        selector = InteractiveModelSelector(catalog_service=mock_catalog)

        with patch("adversary_mcp_server.llm.model_selector.console") as mock_console:
            result = await selector.select_model()

            assert result is None
            mock_console.print.assert_any_call(
                "❌ Error during model selection: Catalog error", style="red"
            )

    @pytest.mark.asyncio
    async def test_model_not_found_in_selection(self, mock_model_info):
        """Test handling when selected model is not found."""
        mock_catalog = Mock()
        mock_catalog.get_available_models = AsyncMock(return_value=mock_model_info)
        mock_catalog.get_model_by_id = AsyncMock(return_value=None)

        selector = InteractiveModelSelector(catalog_service=mock_catalog)

        with patch(
            "adversary_mcp_server.llm.model_selector.questionary"
        ) as mock_questionary:
            mock_questionary.Choice = Mock()
            mock_questionary.select.return_value.ask.return_value = "nonexistent-model"

            with (
                patch.object(selector, "_display_models_table"),
                patch("adversary_mcp_server.llm.model_selector.console"),
            ):

                result = await selector._show_model_list_selection(
                    mock_model_info, "Test"
                )
                assert result is None
