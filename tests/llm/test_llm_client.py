"""Tests for LLM client functionality."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Import before setting up mocks
from adversary_mcp_server.llm import (
    AnthropicClient,
    LLMProvider,
    OpenAIClient,
    create_llm_client,
)
from adversary_mcp_server.llm.llm_client import (
    LLMAPIError,
    LLMClientError,
    LLMRateLimitError,
    LLMResponse,
)


class TestLLMClient:
    """Test abstract LLM client functionality."""

    def test_validate_json_response_valid(self):
        """Test JSON response validation with valid JSON."""
        client = OpenAIClient("test-key")
        valid_json = '{"test": "value"}'
        result = client.validate_json_response(valid_json)
        assert result == {"test": "value"}

    def test_validate_json_response_with_markdown(self):
        """Test JSON response validation with markdown code blocks."""
        client = OpenAIClient("test-key")
        markdown_json = '```json\n{"test": "value"}\n```'
        result = client.validate_json_response(markdown_json)
        assert result == {"test": "value"}

    def test_validate_json_response_invalid(self):
        """Test JSON response validation with invalid JSON."""
        client = OpenAIClient("test-key")
        invalid_json = '{"test": invalid}'
        with pytest.raises(LLMClientError, match="Invalid JSON response"):
            client.validate_json_response(invalid_json)


class TestOpenAIClient:
    """Test OpenAI client implementation."""

    def test_init(self):
        """Test OpenAI client initialization."""
        client = OpenAIClient("test-key")
        assert client.api_key == "test-key"
        assert client.model == "gpt-4-turbo-preview"

    def test_init_with_custom_model(self):
        """Test OpenAI client initialization with custom model."""
        client = OpenAIClient("test-key", model="gpt-4")
        assert client.api_key == "test-key"
        assert client.model == "gpt-4"

    def test_get_default_model(self):
        """Test getting default model."""
        client = OpenAIClient("test-key")
        assert client.get_default_model() == "gpt-4-turbo-preview"

    @pytest.mark.asyncio
    async def test_complete_success(self):
        """Test successful completion request."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Test response"
        mock_response.model = "gpt-4-turbo-preview"
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 20
        mock_response.usage.total_tokens = 30

        # Mock the openai module
        mock_openai = MagicMock()
        mock_client = AsyncMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        with patch.dict("sys.modules", {"openai": mock_openai}):
            client = OpenAIClient("test-key")
            response = await client.complete(
                system_prompt="System prompt", user_prompt="User prompt"
            )

            assert isinstance(response, LLMResponse)
            assert response.content == "Test response"
            assert response.model == "gpt-4-turbo-preview"
            assert response.usage["total_tokens"] == 30

    @pytest.mark.asyncio
    async def test_complete_rate_limit_error(self):
        """Test rate limit handling."""
        mock_openai = MagicMock()
        mock_client = AsyncMock()
        mock_openai.AsyncOpenAI.return_value = mock_client

        # Create proper exception classes that inherit from Exception
        class MockRateLimitError(Exception):
            pass

        class MockAPIError(Exception):
            pass

        mock_openai.RateLimitError = MockRateLimitError
        mock_openai.APIError = MockAPIError
        mock_client.chat.completions.create.side_effect = MockRateLimitError(
            "Rate limited"
        )

        with patch.dict("sys.modules", {"openai": mock_openai}):
            client = OpenAIClient("test-key")
            with pytest.raises(LLMRateLimitError):
                await client.complete("System", "User")

    @pytest.mark.asyncio
    async def test_complete_api_error(self):
        """Test API error handling."""
        mock_openai = MagicMock()
        mock_client = AsyncMock()
        mock_openai.AsyncOpenAI.return_value = mock_client

        # Create proper exception classes that inherit from Exception
        class MockAPIError(Exception):
            pass

        class MockRateLimitError(Exception):
            pass

        mock_openai.APIError = MockAPIError
        mock_openai.RateLimitError = MockRateLimitError
        mock_client.chat.completions.create.side_effect = MockAPIError("API error")

        with patch.dict("sys.modules", {"openai": mock_openai}):
            client = OpenAIClient("test-key")
            with pytest.raises(LLMAPIError):
                await client.complete("System", "User")

    @pytest.mark.asyncio
    async def test_complete_missing_openai(self):
        """Test behavior when OpenAI library is not installed."""
        # Mock ImportError when trying to import openai
        with patch("builtins.__import__") as mock_import:

            def import_side_effect(name, *args, **kwargs):
                if name == "openai":
                    raise ImportError("No module named 'openai'")
                return __import__(name, *args, **kwargs)

            mock_import.side_effect = import_side_effect

            client = OpenAIClient("test-key")
            with pytest.raises(
                LLMClientError, match="OpenAI client library not installed"
            ):
                await client.complete("System", "User")


class TestAnthropicClient:
    """Test Anthropic client implementation."""

    def test_init(self):
        """Test Anthropic client initialization."""
        client = AnthropicClient("test-key")
        assert client.api_key == "test-key"
        assert client.model == "claude-3-5-sonnet-20241022"

    def test_get_default_model(self):
        """Test getting default model."""
        client = AnthropicClient("test-key")
        assert client.get_default_model() == "claude-3-5-sonnet-20241022"

    @pytest.mark.asyncio
    async def test_complete_success(self):
        """Test successful completion request."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = "Test response"
        mock_response.model = "claude-3-5-sonnet-20241022"
        mock_response.usage.input_tokens = 10
        mock_response.usage.output_tokens = 20

        # Mock the anthropic module
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_anthropic.AsyncAnthropic.return_value = mock_client
        mock_client.messages.create.return_value = mock_response

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            client = AnthropicClient("test-key")
            response = await client.complete(
                system_prompt="System prompt", user_prompt="User prompt"
            )

            assert isinstance(response, LLMResponse)
            assert response.content == "Test response"
            assert response.model == "claude-3-5-sonnet-20241022"
            assert response.usage["total_tokens"] == 30

    @pytest.mark.asyncio
    async def test_complete_with_json_format(self):
        """Test completion with JSON format request."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = "Test response"
        mock_response.model = "claude-3-5-sonnet-20241022"
        mock_response.usage.input_tokens = 10
        mock_response.usage.output_tokens = 20

        # Mock the anthropic module
        mock_anthropic = MagicMock()
        mock_client = AsyncMock()
        mock_anthropic.AsyncAnthropic.return_value = mock_client
        mock_client.messages.create.return_value = mock_response

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            client = AnthropicClient("test-key")
            await client.complete(
                system_prompt="System prompt",
                user_prompt="User prompt",
                response_format="json",
            )

            # Verify JSON instruction was added to user prompt
            call_args = mock_client.messages.create.call_args
            messages = call_args[1]["messages"]
            assert "Please respond with valid JSON only." in messages[0]["content"]

    @pytest.mark.asyncio
    async def test_complete_missing_anthropic(self):
        """Test behavior when Anthropic library is not installed."""
        # Mock ImportError when trying to import anthropic
        with patch("builtins.__import__") as mock_import:

            def import_side_effect(name, *args, **kwargs):
                if name == "anthropic":
                    raise ImportError("No module named 'anthropic'")
                return __import__(name, *args, **kwargs)

            mock_import.side_effect = import_side_effect

            client = AnthropicClient("test-key")
            with pytest.raises(
                LLMClientError, match="Anthropic client library not installed"
            ):
                await client.complete("System", "User")


class TestRetryLogic:
    """Test retry logic for LLM clients."""

    @pytest.mark.asyncio
    async def test_complete_with_retry_success_first_attempt(self):
        """Test retry logic succeeds on first attempt."""
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})

        client = OpenAIClient("test-key")
        with patch.object(
            client, "complete", return_value=mock_response
        ) as mock_complete:
            result = await client.complete_with_retry("System", "User")

            assert result == mock_response
            assert mock_complete.call_count == 1

    @pytest.mark.asyncio
    async def test_complete_with_retry_rate_limit_then_success(self):
        """Test retry logic handles rate limit then succeeds."""
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})

        client = OpenAIClient("test-key")
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = [
                LLMRateLimitError("Rate limited"),
                mock_response,
            ]

            with patch("asyncio.sleep") as mock_sleep:
                result = await client.complete_with_retry(
                    "System", "User", retry_delay=0.1
                )

                assert result == mock_response
                assert mock_complete.call_count == 2
                mock_sleep.assert_called_once_with(0.1)

    @pytest.mark.asyncio
    async def test_complete_with_retry_max_retries_exceeded(self):
        """Test retry logic fails after max retries."""
        client = OpenAIClient("test-key")
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = LLMRateLimitError("Rate limited")

            with patch("asyncio.sleep"):
                with pytest.raises(LLMRateLimitError):
                    await client.complete_with_retry(
                        "System", "User", max_retries=2, retry_delay=0.1
                    )

                assert mock_complete.call_count == 2


class TestLLMClientFactory:
    """Test LLM client factory function."""

    def test_create_openai_client(self):
        """Test creating OpenAI client."""
        client = create_llm_client(LLMProvider.OPENAI, "test-key")
        assert isinstance(client, OpenAIClient)
        assert client.api_key == "test-key"

    def test_create_anthropic_client(self):
        """Test creating Anthropic client."""
        client = create_llm_client(LLMProvider.ANTHROPIC, "test-key")
        assert isinstance(client, AnthropicClient)
        assert client.api_key == "test-key"

    def test_create_client_with_custom_model(self):
        """Test creating client with custom model."""
        client = create_llm_client(LLMProvider.OPENAI, "test-key", model="gpt-4")
        assert client.model == "gpt-4"

    def test_create_client_unsupported_provider(self):
        """Test creating client with unsupported provider."""
        with pytest.raises(ValueError, match="Unsupported LLM provider"):
            create_llm_client("unsupported", "test-key")


class TestLLMProvider:
    """Test LLM provider enum."""

    def test_provider_values(self):
        """Test provider enum values."""
        assert LLMProvider.OPENAI == "openai"
        assert LLMProvider.ANTHROPIC == "anthropic"

    def test_provider_creation(self):
        """Test creating provider from string."""
        provider = LLMProvider("openai")
        assert provider == LLMProvider.OPENAI


class TestLLMResponse:
    """Test LLM response data class."""

    def test_llm_response_creation(self):
        """Test creating LLM response."""
        response = LLMResponse(
            content="test content",
            model="test-model",
            usage={"tokens": 100},
            raw_response={"raw": "data"},
        )

        assert response.content == "test content"
        assert response.model == "test-model"
        assert response.usage == {"tokens": 100}
        assert response.raw_response == {"raw": "data"}

    def test_llm_response_without_raw(self):
        """Test creating LLM response without raw response."""
        response = LLMResponse(
            content="test content", model="test-model", usage={"tokens": 100}
        )

        assert response.raw_response is None

    def test_llm_response_with_cost_breakdown(self):
        """Test LLM response with cost breakdown."""
        cost_breakdown = {
            "prompt_cost": 0.01,
            "completion_cost": 0.02,
            "total_cost": 0.03,
            "currency": "USD",
        }
        response = LLMResponse(
            content="test content",
            model="test-model",
            usage={"tokens": 100},
            cost_breakdown=cost_breakdown,
        )

        assert response.cost_breakdown == cost_breakdown


class TestLLMExceptionHandling:
    """Test LLM exception classes."""

    def test_llm_client_error(self):
        """Test LLMClientError exception."""
        error = LLMClientError("Test error")
        assert str(error) == "Test error"

    def test_llm_api_error(self):
        """Test LLMAPIError exception."""
        error = LLMAPIError("API error")
        assert str(error) == "API error"

    def test_llm_rate_limit_error(self):
        """Test LLMRateLimitError exception."""
        error = LLMRateLimitError("Rate limit exceeded")
        assert str(error) == "Rate limit exceeded"


class TestLLMClientEdgeCases:
    """Test edge cases for LLM client functionality."""

    def test_validate_json_response_empty_string(self):
        """Test JSON validation with empty string."""
        client = OpenAIClient("test-key")
        with pytest.raises(LLMClientError, match="Invalid JSON response"):
            client.validate_json_response("")

    def test_validate_json_response_whitespace_only(self):
        """Test JSON validation with whitespace only."""
        client = OpenAIClient("test-key")
        with pytest.raises(LLMClientError, match="Invalid JSON response"):
            client.validate_json_response("   \n  \t  ")

    def test_validate_json_response_code_block_only(self):
        """Test JSON validation with code block only."""
        client = OpenAIClient("test-key")
        markdown_json = """```json
{"test": "value"}
```"""
        result = client.validate_json_response(markdown_json)
        assert result == {"test": "value"}

    @pytest.mark.asyncio
    async def test_complete_with_retry_api_error_retries(self):
        """Test retry logic with API errors (does retry)."""
        client = OpenAIClient("test-key")
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = LLMAPIError("API error")

            with patch("asyncio.sleep") as mock_sleep:
                with pytest.raises(LLMAPIError):
                    await client.complete_with_retry("System", "User", max_retries=3)

                # Should retry for API errors
                assert mock_complete.call_count == 3
                # Should have exponential backoff delays
                assert mock_sleep.call_count == 2

    @pytest.mark.asyncio
    async def test_complete_with_retry_zero_delay(self):
        """Test retry logic with zero delay."""
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})

        client = OpenAIClient("test-key")
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = [
                LLMRateLimitError("Rate limited"),
                mock_response,
            ]

            with patch("asyncio.sleep") as mock_sleep:
                result = await client.complete_with_retry(
                    "System", "User", retry_delay=0.0
                )

                assert result == mock_response
                mock_sleep.assert_called_once_with(0.0)

    def test_create_client_with_none_provider(self):
        """Test creating client with None provider."""
        with pytest.raises(ValueError, match="Unsupported LLM provider"):
            create_llm_client(None, "test-key")
