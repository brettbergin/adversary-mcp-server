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
    LLMQuotaError,
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
                    "System", "User", retry_delay=0.1, use_jitter=False
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
                        "System",
                        "User",
                        max_retries=2,
                        retry_delay=0.1,
                        use_jitter=False,
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
                    await client.complete_with_retry(
                        "System", "User", max_retries=3, use_jitter=False
                    )

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
                    "System", "User", retry_delay=0.0, use_jitter=False
                )

                assert result == mock_response
                mock_sleep.assert_called_once_with(0.0)

    def test_create_client_with_none_provider(self):
        """Test creating client with None provider."""
        with pytest.raises(ValueError, match="Unsupported LLM provider"):
            create_llm_client(None, "test-key")


class TestLLMMetricsRecording:
    """Test LLM metrics recording functionality."""

    def test_record_llm_metrics_with_metrics_collector(self):
        """Test metrics recording when collector is available."""
        from unittest.mock import MagicMock

        client = OpenAIClient("test-key")
        mock_collector = MagicMock()
        client.metrics_collector = mock_collector

        usage_data = {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}

        client._record_llm_metrics(
            provider="openai",
            model="gpt-4",
            usage_data=usage_data,
            duration=1.5,
            success=True,
        )

        mock_collector.record_llm_request.assert_called_once_with(
            provider="openai",
            model="gpt-4",
            tokens_used=30,
            duration_ms=1.5,
            success=True,
        )

    def test_record_llm_metrics_without_total_tokens(self):
        """Test metrics recording when total_tokens is missing."""
        from unittest.mock import MagicMock

        client = OpenAIClient("test-key")
        mock_collector = MagicMock()
        client.metrics_collector = mock_collector

        usage_data = {
            "prompt_tokens": 15,
            "completion_tokens": 25,
            # total_tokens missing
        }

        client._record_llm_metrics(
            provider="openai",
            model="gpt-4",
            usage_data=usage_data,
            duration=2.0,
            success=True,
        )

        # Should calculate total from prompt + completion
        mock_collector.record_llm_request.assert_called_once_with(
            provider="openai",
            model="gpt-4",
            tokens_used=40,  # 15 + 25
            duration_ms=2.0,
            success=True,
        )

    def test_record_llm_metrics_collector_error(self):
        """Test metrics recording when collector raises exception."""
        from unittest.mock import MagicMock

        client = OpenAIClient("test-key")
        mock_collector = MagicMock()
        mock_collector.record_llm_request.side_effect = Exception("Metrics error")
        client.metrics_collector = mock_collector

        usage_data = {"total_tokens": 30}

        # Should not raise exception, just log warning
        client._record_llm_metrics(
            provider="openai",
            model="gpt-4",
            usage_data=usage_data,
            duration=1.0,
            success=True,
        )

    def test_record_llm_metrics_no_collector(self):
        """Test metrics recording when no collector is set."""
        client = OpenAIClient("test-key")
        client.metrics_collector = None

        # Should not raise exception
        client._record_llm_metrics(
            provider="openai",
            model="gpt-4",
            usage_data={"total_tokens": 30},
            duration=1.0,
            success=True,
        )


class TestStreamingRetryLogic:
    """Test streaming completion retry logic."""

    @pytest.mark.asyncio
    async def test_complete_streaming_with_retry_success_first_attempt(self):
        """Test streaming retry logic succeeds on first attempt."""
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})

        client = OpenAIClient("test-key")
        with patch.object(
            client, "complete_streaming", return_value=mock_response
        ) as mock_streaming:
            result = await client.complete_streaming_with_retry("System", "User")

            assert result == mock_response
            assert mock_streaming.call_count == 1

    @pytest.mark.asyncio
    async def test_complete_streaming_with_retry_rate_limit_then_success(self):
        """Test streaming retry logic handles rate limit then succeeds."""
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})

        client = OpenAIClient("test-key")
        with patch.object(client, "complete_streaming") as mock_streaming:
            mock_streaming.side_effect = [
                LLMRateLimitError("Rate limited"),
                mock_response,
            ]

            with patch("asyncio.sleep") as mock_sleep:
                result = await client.complete_streaming_with_retry(
                    "System", "User", retry_delay=0.1, use_jitter=False
                )

                assert result == mock_response
                assert mock_streaming.call_count == 2
                mock_sleep.assert_called_once_with(0.1)

    @pytest.mark.asyncio
    async def test_complete_streaming_with_retry_api_error_retries(self):
        """Test streaming retry logic with API errors."""
        client = OpenAIClient("test-key")
        with patch.object(client, "complete_streaming") as mock_streaming:
            mock_streaming.side_effect = LLMAPIError("API error")

            with patch("asyncio.sleep") as mock_sleep:
                with pytest.raises(LLMAPIError):
                    await client.complete_streaming_with_retry(
                        "System", "User", max_retries=3, use_jitter=False
                    )

                # Should retry for API errors
                assert mock_streaming.call_count == 3
                # Should have exponential backoff delays
                assert mock_sleep.call_count == 2

    @pytest.mark.asyncio
    async def test_complete_streaming_with_retry_client_error_no_retry(self):
        """Test streaming retry logic with client errors (no retry)."""
        client = OpenAIClient("test-key")
        with patch.object(client, "complete_streaming") as mock_streaming:
            mock_streaming.side_effect = LLMClientError("Client error")

            with pytest.raises(LLMClientError):
                await client.complete_streaming_with_retry("System", "User")

            # Should not retry for client errors
            assert mock_streaming.call_count == 1

    @pytest.mark.asyncio
    async def test_complete_streaming_with_retry_max_retries_exceeded(self):
        """Test streaming retry logic fails after max retries."""
        client = OpenAIClient("test-key")
        with patch.object(client, "complete_streaming") as mock_streaming:
            mock_streaming.side_effect = LLMRateLimitError("Rate limited")

            with patch("asyncio.sleep"):
                with pytest.raises(LLMRateLimitError):
                    await client.complete_streaming_with_retry(
                        "System",
                        "User",
                        max_retries=2,
                        retry_delay=0.1,
                        use_jitter=False,
                    )

                assert mock_streaming.call_count == 2

    @pytest.mark.asyncio
    async def test_complete_streaming_with_retry_logs_success_after_failure(self):
        """Test streaming retry logic logs success after initial failure."""
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})

        client = OpenAIClient("test-key")
        with patch.object(client, "complete_streaming") as mock_streaming:
            mock_streaming.side_effect = [
                LLMRateLimitError("Rate limited"),
                mock_response,
            ]

            with patch("asyncio.sleep"):
                with patch("adversary_mcp_server.llm.llm_client.logger") as mock_logger:
                    result = await client.complete_streaming_with_retry(
                        "System", "User", retry_delay=0.1, use_jitter=False
                    )

                    assert result == mock_response
                    # Should log success info since attempt > 0
                    mock_logger.info.assert_called()
                    info_calls = [
                        call
                        for call in mock_logger.info.call_args_list
                        if "successful on attempt 2" in str(call)
                    ]
                    assert len(info_calls) > 0


class TestLLMClientErrorHandling:
    """Test specific error handling scenarios."""

    @pytest.mark.asyncio
    async def test_complete_with_retry_client_error_no_retry(self):
        """Test complete_with_retry does not retry client errors."""
        client = OpenAIClient("test-key")
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = LLMClientError("Client error")

            with pytest.raises(LLMClientError):
                await client.complete_with_retry("System", "User")

            # Should not retry for client errors
            assert mock_complete.call_count == 1


class TestQuotaErrorHandling:
    """Test quota error handling and non-retriable behavior."""

    @pytest.mark.asyncio
    async def test_openai_quota_error_detection_insufficient_quota(self):
        """Test OpenAI quota error detection for insufficient_quota."""
        mock_openai = MagicMock()
        mock_client = AsyncMock()
        mock_openai.AsyncOpenAI.return_value = mock_client

        # Create proper exception classes that inherit from Exception
        class MockRateLimitError(Exception):
            def __str__(self):
                return "Error code: 429 - {'error': {'type': 'insufficient_quota', 'code': 'insufficient_quota'}}"

        mock_openai.RateLimitError = MockRateLimitError
        mock_openai.APIError = Exception  # Add this to prevent other issues
        mock_client.chat.completions.create.side_effect = MockRateLimitError()

        with patch.dict("sys.modules", {"openai": mock_openai}):
            client = OpenAIClient("test-key")
            with pytest.raises(
                LLMQuotaError, match="OpenAI quota exceeded - check billing"
            ):
                await client.complete("System", "User")

    @pytest.mark.asyncio
    async def test_openai_quota_error_detection_quota_in_lowercase(self):
        """Test OpenAI quota error detection for 'quota' in lowercase."""
        mock_openai = MagicMock()
        mock_client = AsyncMock()
        mock_openai.AsyncOpenAI.return_value = mock_client

        class MockRateLimitError(Exception):
            def __str__(self):
                return "Error code: 429 - quota limit exceeded"

        mock_openai.RateLimitError = MockRateLimitError
        mock_openai.APIError = Exception
        mock_client.chat.completions.create.side_effect = MockRateLimitError()

        with patch.dict("sys.modules", {"openai": mock_openai}):
            client = OpenAIClient("test-key")
            with pytest.raises(
                LLMQuotaError, match="OpenAI quota exceeded - check billing"
            ):
                await client.complete("System", "User")

    @pytest.mark.asyncio
    async def test_openai_true_rate_limit_error_still_works(self):
        """Test OpenAI true rate limit errors (without quota) still raise LLMRateLimitError."""
        mock_openai = MagicMock()
        mock_client = AsyncMock()
        mock_openai.AsyncOpenAI.return_value = mock_client

        class MockRateLimitError(Exception):
            def __str__(self):
                return "Error code: 429 - Too many requests, please try again later"

        mock_openai.RateLimitError = MockRateLimitError
        mock_openai.APIError = Exception
        mock_client.chat.completions.create.side_effect = MockRateLimitError()

        with patch.dict("sys.modules", {"openai": mock_openai}):
            client = OpenAIClient("test-key")
            with pytest.raises(LLMRateLimitError, match="OpenAI rate limit exceeded"):
                await client.complete("System", "User")

    @pytest.mark.asyncio
    async def test_openai_streaming_quota_error_detection(self):
        """Test OpenAI streaming quota error detection."""
        mock_openai = MagicMock()
        mock_client = AsyncMock()
        mock_openai.AsyncOpenAI.return_value = mock_client

        class MockRateLimitError(Exception):
            def __str__(self):
                return "Error code: 429 - {'error': {'type': 'insufficient_quota'}}"

        mock_openai.RateLimitError = MockRateLimitError
        mock_openai.APIError = Exception
        mock_client.chat.completions.create.side_effect = MockRateLimitError()

        with patch.dict("sys.modules", {"openai": mock_openai}):
            client = OpenAIClient("test-key")
            with pytest.raises(
                LLMQuotaError, match="OpenAI quota exceeded - check billing"
            ):
                await client.complete_streaming("System", "User")

    @pytest.mark.asyncio
    async def test_quota_error_no_retry_in_complete_with_retry(self):
        """Test quota errors are not retried in complete_with_retry."""
        client = OpenAIClient("test-key")
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = LLMQuotaError("Quota exceeded")

            with pytest.raises(LLMQuotaError, match="Quota exceeded"):
                await client.complete_with_retry("System", "User", max_retries=3)

            # Should fail immediately, no retries
            assert mock_complete.call_count == 1

    @pytest.mark.asyncio
    async def test_quota_error_no_retry_in_streaming_with_retry(self):
        """Test quota errors are not retried in complete_streaming_with_retry."""
        client = OpenAIClient("test-key")
        with patch.object(client, "complete_streaming") as mock_streaming:
            mock_streaming.side_effect = LLMQuotaError("Quota exceeded")

            with pytest.raises(LLMQuotaError, match="Quota exceeded"):
                await client.complete_streaming_with_retry(
                    "System", "User", max_retries=3
                )

            # Should fail immediately, no retries
            assert mock_streaming.call_count == 1

    @pytest.mark.asyncio
    async def test_retry_with_jitter_and_max_delay(self):
        """Test retry logic with jitter and maximum delay cap."""
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})

        client = OpenAIClient("test-key")
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = [
                LLMRateLimitError("Rate limited"),
                LLMRateLimitError("Rate limited"),
                mock_response,
            ]

            with patch("asyncio.sleep") as mock_sleep:
                with patch(
                    "random.random", return_value=0.5
                ) as mock_random:  # Fixed jitter for testing
                    result = await client.complete_with_retry(
                        "System",
                        "User",
                        max_retries=3,
                        retry_delay=2.0,
                        max_delay=3.0,  # Cap delay at 3 seconds
                        use_jitter=True,
                    )

                    assert result == mock_response
                    assert mock_complete.call_count == 3

                    # Check delay calculations with jitter and max_delay cap
                    # First retry: min(2.0 * 2^0, 3.0) * (0.5 + 0.5 * 0.5) = min(2.0, 3.0) * 0.75 = 1.5
                    # Second retry: min(2.0 * 2^1, 3.0) * (0.5 + 0.5 * 0.5) = min(4.0, 3.0) * 0.75 = 2.25
                    expected_calls = [pytest.approx(1.5), pytest.approx(2.25)]
                    actual_calls = [call[0][0] for call in mock_sleep.call_args_list]
                    assert actual_calls == expected_calls

    @pytest.mark.asyncio
    async def test_retry_without_jitter(self):
        """Test retry logic without jitter."""
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})

        client = OpenAIClient("test-key")
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = [
                LLMRateLimitError("Rate limited"),
                LLMRateLimitError("Rate limited"),
                mock_response,
            ]

            with patch("asyncio.sleep") as mock_sleep:
                result = await client.complete_with_retry(
                    "System",
                    "User",
                    max_retries=3,
                    retry_delay=1.0,
                    use_jitter=False,  # Disable jitter
                )

                assert result == mock_response
                assert mock_complete.call_count == 3

                # Check exact exponential backoff without jitter
                # First retry: 1.0 * 2^0 = 1.0
                # Second retry: 1.0 * 2^1 = 2.0
                expected_calls = [1.0, 2.0]
                actual_calls = [call[0][0] for call in mock_sleep.call_args_list]
                assert actual_calls == expected_calls

    def test_llm_quota_error_exception(self):
        """Test LLMQuotaError exception class."""
        error = LLMQuotaError("Quota exceeded")
        assert str(error) == "Quota exceeded"
        assert isinstance(error, LLMClientError)

    @pytest.mark.asyncio
    async def test_mixed_error_handling_quota_then_rate_limit(self):
        """Test handling mixed error types - quota errors should not retry, rate limits should."""
        client = OpenAIClient("test-key")

        # Test quota error first (should fail immediately)
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = LLMQuotaError("Quota exceeded")

            with pytest.raises(LLMQuotaError):
                await client.complete_with_retry("System", "User", max_retries=3)

            assert mock_complete.call_count == 1

        # Reset mock for second test
        mock_complete.reset_mock()

        # Test rate limit error (should retry)
        mock_response = LLMResponse("content", "model", {"total_tokens": 30})
        with patch.object(client, "complete") as mock_complete:
            mock_complete.side_effect = [
                LLMRateLimitError("Rate limited"),
                mock_response,
            ]

            with patch("asyncio.sleep"):
                result = await client.complete_with_retry(
                    "System", "User", max_retries=3, use_jitter=False
                )
                assert result == mock_response
                assert mock_complete.call_count == 2
