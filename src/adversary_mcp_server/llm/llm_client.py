"""Abstract LLM client for unified AI provider integration."""

import asyncio
import json
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from ..logger import get_logger
from .pricing_manager import PricingManager

if TYPE_CHECKING:
    from ..interfaces import IMetricsCollector

logger = get_logger("llm_client")


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"


@dataclass
class LLMResponse:
    """Standardized response from LLM providers."""

    content: str
    model: str
    usage: dict[str, int]  # tokens used, etc.
    raw_response: Any | None = None
    cost_breakdown: dict[str, Any] | None = None  # cost information from PricingManager


class LLMClientError(Exception):
    """Base exception for LLM client errors."""

    pass


class LLMAPIError(LLMClientError):
    """Exception for API-related errors."""

    pass


class LLMRateLimitError(LLMClientError):
    """Exception for rate limit errors."""

    pass


class LLMQuotaError(LLMClientError):
    """Exception for quota/billing limit errors (non-retriable)."""

    pass


class LLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        metrics_collector: "IMetricsCollector | None" = None,
    ):
        """Initialize LLM client.

        Args:
            api_key: API key for the provider
            model: Model to use (provider-specific)
            metrics_collector: Optional metrics collector for LLM usage tracking
        """
        self.api_key = api_key
        self.model = model or self.get_default_model()
        self.pricing_manager = PricingManager()
        self.metrics_collector = metrics_collector
        logger.info(f"Initializing {self.__class__.__name__} with model: {self.model}")
        logger.debug(
            f"Pricing manager initialized with {len(self.pricing_manager.get_supported_models())} supported models"
        )

    def _record_llm_metrics(
        self,
        provider: str,
        model: str,
        usage_data: dict[str, Any],
        duration: float,
        success: bool,
    ) -> None:
        """Record LLM request metrics if metrics collector is available.

        Args:
            provider: LLM provider name (openai, anthropic)
            model: Model name used
            usage_data: Usage data from LLM response
            duration: Request duration in seconds
            success: Whether request was successful
        """
        if self.metrics_collector and usage_data:
            # Extract total tokens from usage data
            total_tokens = usage_data.get("total_tokens", 0)
            if not total_tokens:
                # Calculate from prompt + completion tokens if total not available
                prompt_tokens = usage_data.get("prompt_tokens", 0)
                completion_tokens = usage_data.get("completion_tokens", 0)
                total_tokens = prompt_tokens + completion_tokens

            # Record the metrics
            try:
                self.metrics_collector.record_llm_request(
                    provider=provider,
                    model=model,
                    tokens_used=total_tokens,
                    duration_ms=duration,
                    success=success,
                )
                logger.debug(
                    f"Recorded LLM metrics: {provider}/{model}, "
                    f"{total_tokens} tokens, {duration:.2f}s, "
                    f"success={success}"
                )
            except Exception as e:
                logger.warning(f"Failed to record LLM metrics: {e}")

    @abstractmethod
    def get_default_model(self) -> str:
        """Get the default model for this provider."""
        pass

    @abstractmethod
    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        response_format: str = "json",
    ) -> LLMResponse:
        """Make a completion request to the LLM.

        Args:
            system_prompt: System prompt for the LLM
            user_prompt: User prompt for the LLM
            temperature: Temperature for sampling (0.0 = deterministic)
            max_tokens: Maximum tokens in response
            response_format: Expected response format ("json" or "text")

        Returns:
            LLMResponse with the completion

        Raises:
            LLMAPIError: If the API request fails
            LLMRateLimitError: If rate limited
        """
        pass

    @abstractmethod
    async def complete_streaming(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        response_format: str = "json",
    ) -> LLMResponse:
        """Make a streaming completion request to the LLM for faster time-to-first-token.

        Args:
            system_prompt: System prompt for the LLM
            user_prompt: User prompt for the LLM
            temperature: Temperature for sampling (0.0 = deterministic)
            max_tokens: Maximum tokens in response
            response_format: Expected response format ("json" or "text")

        Returns:
            LLMResponse with the complete streamed response

        Raises:
            LLMAPIError: If the API request fails
            LLMRateLimitError: If rate limited
        """
        pass

    def validate_json_response(self, response_text: str) -> dict[str, Any]:
        """Validate and parse JSON response.

        Args:
            response_text: Raw response text

        Returns:
            Parsed JSON dictionary

        Raises:
            LLMClientError: If response is not valid JSON
        """
        try:
            # Handle potential markdown code blocks
            if response_text.strip().startswith("```"):
                lines = response_text.strip().split("\n")
                # Remove first and last lines if they're code block markers
                if lines[0].startswith("```") and lines[-1] == "```":
                    response_text = "\n".join(lines[1:-1])

            return json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response text: {response_text[:500]}...")
            raise LLMClientError(f"Invalid JSON response: {e}")

    async def complete_with_retry(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        response_format: str = "json",
        max_retries: int = 3,
        retry_delay: float = 1.0,
        max_delay: float = 60.0,
        use_jitter: bool = True,
    ) -> LLMResponse:
        """Complete with automatic retry on failure.

        Args:
            system_prompt: System prompt for the LLM
            user_prompt: User prompt for the LLM
            temperature: Temperature for sampling
            max_tokens: Maximum tokens in response
            response_format: Expected response format
            max_retries: Maximum number of retry attempts
            retry_delay: Base delay between retries (exponential backoff)
            max_delay: Maximum delay cap to prevent excessive waits
            use_jitter: Add randomization to prevent thundering herd

        Returns:
            LLMResponse with the completion

        Raises:
            LLMAPIError: If all retries fail
            LLMQuotaError: If quota exceeded (non-retriable)
        """
        logger.debug(
            f"Starting completion with retry - max_retries: {max_retries}, "
            f"retry_delay: {retry_delay}s"
        )

        last_error = None
        start_time = asyncio.get_event_loop().time()

        for attempt in range(max_retries):
            try:
                logger.debug(f"Attempt {attempt + 1}/{max_retries} for completion")
                result = await self.complete(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    response_format=response_format,
                )

                elapsed_time = asyncio.get_event_loop().time() - start_time
                if attempt > 0:
                    logger.info(
                        f"Completion successful on attempt {attempt + 1}, "
                        f"total time: {elapsed_time:.2f}s"
                    )
                return result

            except LLMQuotaError as e:
                # Quota errors are non-retriable - fail immediately
                logger.error(
                    f"Quota error on attempt {attempt + 1} - not retrying: {e}"
                )
                raise

            except LLMRateLimitError as e:
                last_error = e
                if attempt < max_retries - 1:
                    delay = min(
                        retry_delay * (2**attempt), max_delay
                    )  # Exponential backoff with cap
                    if use_jitter:
                        delay = delay * (
                            0.5 + random.random() * 0.5  # noqa: S311
                        )  # Add 50% jitter
                    logger.warning(
                        f"Rate limited on attempt {attempt + 1}/{max_retries}, "
                        f"retrying in {delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"Rate limit exceeded after {max_retries} attempts: {e}"
                    )
                    raise

            except LLMAPIError as e:
                last_error = e
                if attempt < max_retries - 1:
                    delay = min(
                        retry_delay * (2**attempt), max_delay
                    )  # Exponential backoff with cap
                    if use_jitter:
                        delay = delay * (
                            0.5 + random.random() * 0.5  # noqa: S311
                        )  # Add 50% jitter
                    logger.warning(
                        f"API error on attempt {attempt + 1}/{max_retries}, "
                        f"retrying in {delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"API error after {max_retries} attempts: {e}")
                    raise

            except LLMClientError as e:
                # Client errors are typically not retryable
                logger.error(
                    f"Client error on attempt {attempt + 1}, not retrying: {e}"
                )
                raise

        # Should not reach here, but just in case
        total_time = asyncio.get_event_loop().time() - start_time
        logger.error(f"All {max_retries} attempts failed in {total_time:.2f}s")
        raise LLMAPIError(f"Failed after {max_retries} attempts: {last_error}")

    async def complete_streaming_with_retry(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        response_format: str = "json",
        max_retries: int = 3,
        retry_delay: float = 1.0,
        max_delay: float = 60.0,
        use_jitter: bool = True,
    ) -> LLMResponse:
        """Complete with streaming and automatic retry on failure.

        Args:
            system_prompt: System prompt for the LLM
            user_prompt: User prompt for the LLM
            temperature: Temperature for sampling
            max_tokens: Maximum tokens in response
            response_format: Expected response format
            max_retries: Maximum number of retry attempts
            retry_delay: Base delay between retries (exponential backoff)
            max_delay: Maximum delay cap to prevent excessive waits
            use_jitter: Add randomization to prevent thundering herd

        Returns:
            LLMResponse with the completion

        Raises:
            LLMAPIError: If all retries fail
            LLMQuotaError: If quota exceeded (non-retriable)
        """
        logger.debug(
            f"Starting streaming completion with retry - max_retries: {max_retries}, "
            f"retry_delay: {retry_delay}s"
        )

        last_error = None
        start_time = asyncio.get_event_loop().time()

        for attempt in range(max_retries):
            try:
                logger.debug(
                    f"Streaming attempt {attempt + 1}/{max_retries} for completion"
                )
                result = await self.complete_streaming(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    response_format=response_format,
                )

                elapsed_time = asyncio.get_event_loop().time() - start_time
                if attempt > 0:
                    logger.info(
                        f"Streaming completion successful on attempt {attempt + 1}, "
                        f"total time: {elapsed_time:.2f}s"
                    )
                return result

            except LLMQuotaError as e:
                # Quota errors are non-retriable - fail immediately
                logger.error(
                    f"Quota error on streaming attempt {attempt + 1} - not retrying: {e}"
                )
                raise

            except LLMRateLimitError as e:
                last_error = e
                if attempt < max_retries - 1:
                    delay = min(
                        retry_delay * (2**attempt), max_delay
                    )  # Exponential backoff with cap
                    if use_jitter:
                        delay = delay * (
                            0.5 + random.random() * 0.5  # noqa: S311
                        )  # Add 50% jitter
                    logger.warning(
                        f"Rate limited on streaming attempt {attempt + 1}/{max_retries}, "
                        f"retrying in {delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"Rate limit exceeded after {max_retries} streaming attempts: {e}"
                    )
                    raise

            except LLMAPIError as e:
                last_error = e
                if attempt < max_retries - 1:
                    delay = min(
                        retry_delay * (2**attempt), max_delay
                    )  # Exponential backoff with cap
                    if use_jitter:
                        delay = delay * (
                            0.5 + random.random() * 0.5  # noqa: S311
                        )  # Add 50% jitter
                    logger.warning(
                        f"API error on streaming attempt {attempt + 1}/{max_retries}, "
                        f"retrying in {delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"API error after {max_retries} streaming attempts: {e}"
                    )
                    raise

            except LLMClientError as e:
                # Client errors are typically not retryable
                logger.error(
                    f"Client error on streaming attempt {attempt + 1}, not retrying: {e}"
                )
                raise

        # Should not reach here, but just in case
        total_time = asyncio.get_event_loop().time() - start_time
        logger.error(
            f"All {max_retries} streaming attempts failed in {total_time:.2f}s"
        )
        raise LLMAPIError(
            f"Failed after {max_retries} streaming attempts: {last_error}"
        )


class OpenAIClient(LLMClient):
    """OpenAI API client implementation."""

    def get_default_model(self) -> str:
        """Get the default OpenAI model."""
        return "gpt-4-turbo-preview"

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        response_format: str = "json",
    ) -> LLMResponse:
        """Make a completion request to OpenAI."""
        try:
            import openai
        except ImportError:
            raise LLMClientError(
                "OpenAI client library not installed. Run: uv pip install openai"
            )

        logger.info(f"Making OpenAI completion request with model: {self.model}")
        logger.debug(
            f"Request parameters - Temperature: {temperature}, Max tokens: {max_tokens}, Format: {response_format}"
        )
        logger.debug(
            f"System prompt length: {len(system_prompt)} chars, User prompt length: {len(user_prompt)} chars"
        )

        # Estimate token usage
        estimated_input_tokens = (len(system_prompt) + len(user_prompt)) // 4
        logger.debug(f"Estimated input tokens: ~{estimated_input_tokens}")

        client = openai.AsyncOpenAI(api_key=self.api_key)

        start_time = asyncio.get_event_loop().time()
        try:
            # Prepare messages
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            # Make the request
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            # Add response format if JSON expected
            if response_format == "json":
                kwargs["response_format"] = {"type": "json_object"}

            response = await client.chat.completions.create(**kwargs)  # type: ignore[call-overload]

            # Extract content
            content = response.choices[0].message.content

            # Extract usage information
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }

            logger.info(
                f"OpenAI completion successful. Tokens used: {usage['total_tokens']} "
                f"(prompt: {usage['prompt_tokens']}, completion: {usage['completion_tokens']})"
            )
            logger.debug(
                f"Response model: {response.model}, Content length: {len(content)} chars"
            )

            # Calculate cost using pricing manager
            cost_breakdown = self.pricing_manager.calculate_cost(
                model_name=response.model,
                prompt_tokens=usage["prompt_tokens"],
                completion_tokens=usage["completion_tokens"],
            )
            logger.debug(
                f"Cost calculation: ${cost_breakdown['total_cost']:.6f} "
                f"{cost_breakdown['currency']} "
                f"(pricing: {cost_breakdown['pricing_source']})"
            )

            # Record LLM metrics if collector is available
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="openai",
                model=response.model,
                usage_data=usage,
                duration=duration,
                success=True,
            )

            return LLMResponse(
                content=content,
                model=response.model,
                usage=usage,
                raw_response=response,
                cost_breakdown=cost_breakdown,
            )

        except openai.RateLimitError as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="openai",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )

            # Check if this is a quota error (non-retriable) vs rate limit (retriable)
            error_str = str(e)
            if "insufficient_quota" in error_str or "quota" in error_str.lower():
                logger.error(f"OpenAI quota exceeded (non-retriable): {e}")
                raise LLMQuotaError(f"OpenAI quota exceeded - check billing: {e}")
            else:
                logger.error(f"OpenAI rate limit error (retriable): {e}")
                raise LLMRateLimitError(f"OpenAI rate limit exceeded: {e}")
        except openai.APIError as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="openai",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"OpenAI API error: {e}")
            raise LLMAPIError(f"OpenAI API error: {e}")
        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="openai",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"Unexpected OpenAI error: {e}")
            raise LLMClientError(f"Unexpected error in OpenAI client: {e}")

    async def complete_streaming(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        response_format: str = "json",
    ) -> LLMResponse:
        """Make a streaming completion request to OpenAI for faster time-to-first-token."""
        try:
            import openai
        except ImportError:
            raise LLMClientError(
                "OpenAI client library not installed. Run: uv pip install openai"
            )

        logger.debug(
            f"Making streaming OpenAI completion request with model: {self.model}"
        )
        logger.debug(
            f"Request parameters - Temperature: {temperature}, Max tokens: {max_tokens}, Format: {response_format}"
        )

        # Estimate token usage
        estimated_input_tokens = (len(system_prompt) + len(user_prompt)) // 4
        logger.debug(f"Estimated input tokens: ~{estimated_input_tokens}")

        client = openai.AsyncOpenAI(api_key=self.api_key)

        start_time = asyncio.get_event_loop().time()
        try:
            # Prepare messages
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            # Make the streaming request
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,  # Enable streaming
            }

            # Add response format if JSON expected
            if response_format == "json":
                kwargs["response_format"] = {"type": "json_object"}

            # Collect streamed response
            content_chunks = []
            usage_data = {}
            response_model = self.model

            stream = await client.chat.completions.create(**kwargs)  # type: ignore[call-overload]

            async for chunk in stream:
                if chunk.choices[0].delta.content:
                    content_chunks.append(chunk.choices[0].delta.content)

                # Get final usage from the last chunk
                if hasattr(chunk, "usage") and chunk.usage:
                    usage_data = {
                        "prompt_tokens": chunk.usage.prompt_tokens,
                        "completion_tokens": chunk.usage.completion_tokens,
                        "total_tokens": chunk.usage.total_tokens,
                    }

                # Get the model name from chunk if available
                if hasattr(chunk, "model") and chunk.model:
                    response_model = chunk.model

            # Combine all content chunks
            content = "".join(content_chunks)

            # If we didn't get usage data from streaming, estimate it
            if not usage_data:
                completion_tokens = len(content) // 4  # Rough estimate
                usage_data = {
                    "prompt_tokens": estimated_input_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": estimated_input_tokens + completion_tokens,
                }
                logger.debug("Using estimated token usage for streaming response")

            logger.info(
                f"OpenAI streaming completion successful. Tokens used: {usage_data['total_tokens']} "
                f"(prompt: {usage_data['prompt_tokens']}, completion: {usage_data['completion_tokens']})"
            )
            logger.debug(
                f"Response model: {response_model}, Content length: {len(content)} chars"
            )

            # Calculate cost using pricing manager
            cost_breakdown = self.pricing_manager.calculate_cost(
                model_name=response_model,
                prompt_tokens=usage_data["prompt_tokens"],
                completion_tokens=usage_data["completion_tokens"],
            )
            logger.debug(
                f"Cost calculation: ${cost_breakdown['total_cost']:.6f} "
                f"{cost_breakdown['currency']} "
                f"(pricing: {cost_breakdown['pricing_source']})"
            )

            # Record LLM metrics if collector is available
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="openai",
                model=response_model,
                usage_data=usage_data,
                duration=duration,
                success=True,
            )

            return LLMResponse(
                content=content,
                model=response_model,
                usage=usage_data,
                raw_response=None,  # No single response object for streaming
                cost_breakdown=cost_breakdown,
            )

        except openai.RateLimitError as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="openai",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )

            # Check if this is a quota error (non-retriable) vs rate limit (retriable)
            error_str = str(e)
            if "insufficient_quota" in error_str or "quota" in error_str.lower():
                logger.error(
                    f"OpenAI quota exceeded during streaming (non-retriable): {e}"
                )
                raise LLMQuotaError(f"OpenAI quota exceeded - check billing: {e}")
            else:
                logger.error(
                    f"OpenAI rate limit error during streaming (retriable): {e}"
                )
                raise LLMRateLimitError(f"OpenAI rate limit exceeded: {e}")
        except openai.APIError as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="openai",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"OpenAI API error during streaming: {e}")
            raise LLMAPIError(f"OpenAI API error: {e}")
        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="openai",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"Unexpected OpenAI streaming error: {e}")
            raise LLMClientError(f"Unexpected error in OpenAI streaming client: {e}")


class AnthropicClient(LLMClient):
    """Anthropic API client implementation."""

    def get_default_model(self) -> str:
        """Get the default Anthropic model."""
        return "claude-3-5-sonnet-20241022"

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        response_format: str = "json",
    ) -> LLMResponse:
        """Make a completion request to Anthropic."""
        try:
            import anthropic
        except ImportError:
            raise LLMClientError(
                "Anthropic client library not installed. Run: pip install anthropic"
            )

        logger.info(f"Making Anthropic completion request with model: {self.model}")
        logger.debug(
            f"Request parameters - Temperature: {temperature}, Max tokens: {max_tokens}, Format: {response_format}"
        )
        logger.debug(
            f"System prompt length: {len(system_prompt)} chars, User prompt length: {len(user_prompt)} chars"
        )

        # Estimate token usage
        estimated_input_tokens = (len(system_prompt) + len(user_prompt)) // 4
        logger.debug(f"Estimated input tokens: ~{estimated_input_tokens}")

        client = anthropic.AsyncAnthropic(api_key=self.api_key)

        start_time = asyncio.get_event_loop().time()
        try:
            # Combine prompts for Anthropic format
            # Add JSON instruction if needed
            full_user_prompt = user_prompt
            if response_format == "json":
                full_user_prompt += "\n\nPlease respond with valid JSON only."

            # Make the request
            response = await client.messages.create(
                model=self.model,
                system=system_prompt,
                messages=[{"role": "user", "content": full_user_prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
            )

            # Extract content
            content = response.content[0].text

            # Calculate usage
            usage = {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens
                + response.usage.output_tokens,
            }

            logger.info(
                f"Anthropic completion successful. Tokens used: {usage['total_tokens']} "
                f"(input: {usage['prompt_tokens']}, output: {usage['completion_tokens']})"
            )
            logger.debug(
                f"Response model: {response.model}, Content length: {len(content)} chars"
            )

            # Calculate cost using pricing manager
            cost_breakdown = self.pricing_manager.calculate_cost(
                model_name=response.model,
                prompt_tokens=usage["prompt_tokens"],
                completion_tokens=usage["completion_tokens"],
            )
            logger.debug(
                f"Cost calculation: ${cost_breakdown['total_cost']:.6f} "
                f"{cost_breakdown['currency']} "
                f"(pricing: {cost_breakdown['pricing_source']})"
            )

            # Record LLM metrics if collector is available
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="anthropic",
                model=response.model,
                usage_data=usage,
                duration=duration,
                success=True,
            )

            return LLMResponse(
                content=content,
                model=response.model,
                usage=usage,
                raw_response=response,
                cost_breakdown=cost_breakdown,
            )

        except anthropic.RateLimitError as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="anthropic",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"Anthropic rate limit error: {e}")
            raise LLMRateLimitError(f"Anthropic rate limit exceeded: {e}")
        except anthropic.APIError as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="anthropic",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"Anthropic API error: {e}")
            raise LLMAPIError(f"Anthropic API error: {e}")
        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="anthropic",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"Unexpected Anthropic error: {e}")
            raise LLMClientError(f"Unexpected error in Anthropic client: {e}")

    async def complete_streaming(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        response_format: str = "json",
    ) -> LLMResponse:
        """Make a streaming completion request to Anthropic for faster time-to-first-token."""
        try:
            import anthropic
        except ImportError:
            raise LLMClientError(
                "Anthropic client library not installed. Run: uv pip install anthropic"
            )

        logger.debug(
            f"Making streaming Anthropic completion request with model: {self.model}"
        )
        logger.debug(
            f"Request parameters - Temperature: {temperature}, Max tokens: {max_tokens}, Format: {response_format}"
        )

        # Estimate token usage
        estimated_input_tokens = (len(system_prompt) + len(user_prompt)) // 4
        logger.debug(f"Estimated input tokens: ~{estimated_input_tokens}")

        client = anthropic.AsyncAnthropic(api_key=self.api_key)

        start_time = asyncio.get_event_loop().time()
        try:
            # Prepare the user prompt with JSON instruction if needed
            formatted_user_prompt = user_prompt
            if response_format == "json":
                formatted_user_prompt += "\n\nPlease respond with valid JSON only."

            # Make the streaming request
            kwargs = {
                "model": self.model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "system": system_prompt,
                "messages": [{"role": "user", "content": formatted_user_prompt}],
                "stream": True,  # Enable streaming
            }

            # Collect streamed response
            content_chunks = []
            usage_data = {}
            response_model = self.model

            stream = await client.messages.create(**kwargs)  # type: ignore[call-overload]

            async for chunk in stream:
                # Handle different types of streaming events
                if chunk.type == "content_block_delta":
                    if hasattr(chunk.delta, "text") and chunk.delta.text:
                        content_chunks.append(chunk.delta.text)
                elif chunk.type == "message_delta":
                    # Get usage information from message_delta events
                    if hasattr(chunk, "usage") and chunk.usage:
                        usage_data = {
                            "prompt_tokens": getattr(chunk.usage, "input_tokens", 0),
                            "completion_tokens": getattr(
                                chunk.usage, "output_tokens", 0
                            ),
                            "total_tokens": getattr(chunk.usage, "input_tokens", 0)
                            + getattr(chunk.usage, "output_tokens", 0),
                        }

            # Combine all content chunks
            content = "".join(content_chunks)

            # If we didn't get usage data from streaming, estimate it
            if not usage_data:
                completion_tokens = len(content) // 4  # Rough estimate
                usage_data = {
                    "prompt_tokens": estimated_input_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": estimated_input_tokens + completion_tokens,
                }
                logger.debug(
                    "Using estimated token usage for Anthropic streaming response"
                )

            logger.info(
                f"Anthropic streaming completion successful. Tokens used: {usage_data['total_tokens']} "
                f"(prompt: {usage_data['prompt_tokens']}, completion: {usage_data['completion_tokens']})"
            )
            logger.debug(
                f"Response model: {response_model}, Content length: {len(content)} chars"
            )

            # Calculate cost using pricing manager
            cost_breakdown = self.pricing_manager.calculate_cost(
                model_name=response_model,
                prompt_tokens=usage_data["prompt_tokens"],
                completion_tokens=usage_data["completion_tokens"],
            )
            logger.debug(
                f"Cost calculation: ${cost_breakdown['total_cost']:.6f} "
                f"{cost_breakdown['currency']} "
                f"(pricing: {cost_breakdown['pricing_source']})"
            )

            # Record LLM metrics if collector is available
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="anthropic",
                model=response_model,
                usage_data=usage_data,
                duration=duration,
                success=True,
            )

            return LLMResponse(
                content=content,
                model=response_model,
                usage=usage_data,
                raw_response=None,  # No single response object for streaming
                cost_breakdown=cost_breakdown,
            )

        except anthropic.RateLimitError as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="anthropic",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"Anthropic rate limit error during streaming: {e}")
            raise LLMRateLimitError(f"Anthropic rate limit exceeded: {e}")
        except anthropic.APIError as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="anthropic",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"Anthropic API error during streaming: {e}")
            raise LLMAPIError(f"Anthropic API error: {e}")
        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            self._record_llm_metrics(
                provider="anthropic",
                model=self.model,
                usage_data={},
                duration=duration,
                success=False,
            )
            logger.error(f"Unexpected Anthropic streaming error: {e}")
            raise LLMClientError(f"Unexpected error in Anthropic streaming client: {e}")


def create_llm_client(
    provider: LLMProvider,
    api_key: str,
    model: str | None = None,
    metrics_collector: "IMetricsCollector | None" = None,
) -> LLMClient:
    """Factory function to create LLM client based on provider.

    Args:
        provider: LLM provider to use
        api_key: API key for the provider
        model: Optional model override
        metrics_collector: Optional metrics collector for LLM usage tracking

    Returns:
        Configured LLM client instance

    Raises:
        ValueError: If provider is not supported
    """
    logger.info(f"Creating LLM client for provider: {provider}")
    logger.debug(
        f"Model: {model or 'default'}, API key length: {len(api_key) if api_key else 0}"
    )

    try:
        if provider == LLMProvider.OPENAI:
            client = OpenAIClient(
                api_key=api_key, model=model, metrics_collector=metrics_collector
            )
            logger.info(
                f"Successfully created OpenAI client with model: {client.model}"
            )
            return client
        elif provider == LLMProvider.ANTHROPIC:
            client = AnthropicClient(
                api_key=api_key, model=model, metrics_collector=metrics_collector
            )
            logger.info(
                f"Successfully created Anthropic client with model: {client.model}"
            )
            return client
        else:
            logger.error(f"Unsupported LLM provider: {provider}")
            raise ValueError(f"Unsupported LLM provider: {provider}")
    except Exception as e:
        logger.error(f"Failed to create LLM client for {provider}: {e}")
        raise
