"""Tests for token estimator."""

from adversary_mcp_server.batch.token_estimator import TokenEstimator
from adversary_mcp_server.batch.types import Language


class TestTokenEstimator:
    """Test TokenEstimator class."""

    def test_initialization(self):
        """Test token estimator initialization."""
        estimator = TokenEstimator()

        assert estimator._cache == {}
        assert Language.PYTHON in estimator.LANGUAGE_TOKEN_RATIOS
        assert "gpt-4" in estimator.MODEL_MULTIPLIERS

    def test_estimate_tokens_basic(self):
        """Test basic token estimation."""
        estimator = TokenEstimator()

        content = "def hello_world():\n    print('Hello, World!')"
        tokens = estimator.estimate_tokens(content, Language.PYTHON)

        assert isinstance(tokens, int)
        assert tokens > 0

    def test_estimate_tokens_different_languages(self):
        """Test token estimation for different languages."""
        estimator = TokenEstimator()
        content = "function test() { return 42; }"

        python_tokens = estimator.estimate_tokens(content, Language.PYTHON)
        js_tokens = estimator.estimate_tokens(content, Language.JAVASCRIPT)
        java_tokens = estimator.estimate_tokens(content, Language.JAVA)

        # Different languages should produce different token estimates
        assert isinstance(python_tokens, int)
        assert isinstance(js_tokens, int)
        assert isinstance(java_tokens, int)

    def test_estimate_tokens_with_model(self):
        """Test token estimation with specific model."""
        estimator = TokenEstimator()
        content = "print('test')"

        gpt4_tokens = estimator.estimate_tokens(content, Language.PYTHON, "gpt-4")
        claude_tokens = estimator.estimate_tokens(
            content, Language.PYTHON, "claude-3-5-sonnet"
        )

        assert isinstance(gpt4_tokens, int)
        assert isinstance(claude_tokens, int)

    def test_estimate_tokens_empty_content(self):
        """Test token estimation with empty content."""
        estimator = TokenEstimator()

        tokens = estimator.estimate_tokens("", Language.PYTHON)

        assert tokens == 0

    def test_estimate_tokens_caching(self):
        """Test that token estimation uses caching."""
        estimator = TokenEstimator()
        content = "test content"

        # First call should populate cache
        tokens1 = estimator.estimate_tokens(content, Language.PYTHON)
        cache_size_after_first = len(estimator._cache)

        # Second call should use cache
        tokens2 = estimator.estimate_tokens(content, Language.PYTHON)
        cache_size_after_second = len(estimator._cache)

        assert tokens1 == tokens2
        assert cache_size_after_first == cache_size_after_second

    def test_language_token_ratios(self):
        """Test that all languages have token ratios."""
        estimator = TokenEstimator()

        for language in Language:
            assert language in estimator.LANGUAGE_TOKEN_RATIOS
            assert isinstance(estimator.LANGUAGE_TOKEN_RATIOS[language], float)
            assert estimator.LANGUAGE_TOKEN_RATIOS[language] > 0

    def test_model_multipliers(self):
        """Test model multipliers."""
        estimator = TokenEstimator()

        for model, multiplier in estimator.MODEL_MULTIPLIERS.items():
            assert isinstance(multiplier, int | float)
            assert multiplier > 0

    def test_estimate_tokens_large_content(self):
        """Test token estimation with large content."""
        estimator = TokenEstimator()

        # Create large content
        large_content = "def function():\n    pass\n" * 1000
        tokens = estimator.estimate_tokens(large_content, Language.PYTHON)

        assert isinstance(tokens, int)
        assert tokens > 1000  # Should be substantial for large content

    def test_estimate_prompt_tokens(self):
        """Test prompt token estimation."""
        estimator = TokenEstimator()

        prompt = "Analyze this code for security issues"
        content = "print('hello')"

        tokens = estimator.estimate_prompt_tokens(prompt, content, Language.PYTHON)

        assert isinstance(tokens, int)
        assert tokens > 0

    def test_estimate_response_tokens(self):
        """Test response token estimation."""
        estimator = TokenEstimator()

        findings_count = 5
        complexity = "medium"

        tokens = estimator.estimate_response_tokens(findings_count, complexity)

        assert isinstance(tokens, int)
        assert tokens > 0

    def test_estimate_total_request_tokens(self):
        """Test total request token estimation."""
        estimator = TokenEstimator()

        content = "def test(): pass"
        system_prompt = "You are a security analyzer"
        user_prompt_template = "Analyze this code for vulnerabilities: "
        max_findings = 3

        total_tokens = estimator.estimate_total_request_tokens(
            content, Language.PYTHON, system_prompt, user_prompt_template, max_findings
        )

        assert isinstance(total_tokens, int)
        assert total_tokens > 0

    def test_clear_cache(self):
        """Test clearing the cache."""
        estimator = TokenEstimator()

        # Add something to cache
        estimator.estimate_tokens("test", Language.PYTHON)
        assert len(estimator._cache) > 0

        estimator.clear_cache()
        assert len(estimator._cache) == 0

    def test_get_cache_stats(self):
        """Test getting cache statistics."""
        estimator = TokenEstimator()

        # Add some items to cache
        estimator.estimate_tokens("test1", Language.PYTHON)
        estimator.estimate_tokens("test2", Language.PYTHON)

        stats = estimator.get_cache_stats()

        assert isinstance(stats, dict)
        assert "cache_size" in stats
        assert stats["cache_size"] == 2
