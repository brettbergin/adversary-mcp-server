"""Token estimation for efficient batch sizing."""

import re

from ..logger import get_logger
from .types import Language

logger = get_logger("token_estimator")


class TokenEstimator:
    """Estimates token count for different types of content and LLM models."""

    # Average tokens per character for different languages
    LANGUAGE_TOKEN_RATIOS = {
        Language.PYTHON: 0.30,  # Python is more verbose
        Language.JAVASCRIPT: 0.25,  # JS has shorter syntax
        Language.TYPESCRIPT: 0.25,  # Similar to JS
        Language.JAVA: 0.35,  # Java is quite verbose
        Language.CSHARP: 0.35,  # Similar to Java
        Language.CPP: 0.28,  # C++ is moderately dense
        Language.C: 0.22,  # C is more compact
        Language.GO: 0.25,  # Go is clean and compact
        Language.RUST: 0.30,  # Rust can be verbose
        Language.PHP: 0.28,  # PHP is moderately verbose
        Language.RUBY: 0.27,  # Ruby is expressive
        Language.KOTLIN: 0.32,  # Similar to Java but more concise
        Language.SWIFT: 0.30,  # Swift is moderately verbose
        Language.GENERIC: 0.27,  # Default ratio
    }

    # Model-specific token multipliers
    MODEL_MULTIPLIERS = {
        "gpt-4": 1.0,
        "gpt-4-turbo": 1.0,
        "gpt-4o": 1.0,
        "gpt-3.5-turbo": 1.0,
        "claude-3-5-sonnet": 1.1,  # Slightly different tokenization
        "claude-3-5-haiku": 1.1,
        "claude-3-opus": 1.1,
    }

    def __init__(self):
        """Initialize token estimator."""
        self._cache: dict[str, int] = {}
        logger.debug("TokenEstimator initialized")

    def estimate_tokens(
        self,
        content: str,
        language: Language = Language.GENERIC,
        model: str | None = None,
    ) -> int:
        """Estimate token count for content.

        Args:
            content: Text content to analyze
            language: Programming language
            model: LLM model name for model-specific adjustments

        Returns:
            Estimated token count
        """
        if not content.strip():
            return 0

        # Check cache
        cache_key = f"{hash(content)}:{language.value}:{model or 'default'}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Basic character-based estimation
        char_count = len(content)

        # Apply language-specific ratio
        base_tokens = char_count * self.LANGUAGE_TOKEN_RATIOS.get(language, 0.27)

        # Apply code-specific adjustments
        tokens = self._apply_code_adjustments(content, base_tokens, language)

        # Apply model-specific multiplier
        if model:
            multiplier = self.MODEL_MULTIPLIERS.get(model.lower(), 1.0)
            tokens *= multiplier

        # Round to integer
        estimated_tokens = max(1, int(tokens))

        # Cache result
        self._cache[cache_key] = estimated_tokens

        return estimated_tokens

    def _apply_code_adjustments(
        self, content: str, base_tokens: float, language: Language
    ) -> float:
        """Apply code-specific adjustments to token estimate.

        Args:
            content: Code content
            base_tokens: Base token estimate
            language: Programming language

        Returns:
            Adjusted token count
        """
        # Count different types of content

        # Comments reduce token density
        comment_ratio = self._count_comments(content, language) / len(content)

        # Whitespace and empty lines
        whitespace_ratio = len(re.findall(r"\s", content)) / len(content)

        # String literals (usually token-dense)
        string_ratio = self._count_strings(content, language) / len(content)

        # Keywords and identifiers
        keyword_ratio = self._count_keywords(content, language) / len(content)

        # Apply adjustments
        adjustment_factor = 1.0

        # Comments typically have lower token density
        adjustment_factor -= comment_ratio * 0.2

        # Excessive whitespace reduces density
        if whitespace_ratio > 0.4:
            adjustment_factor -= (whitespace_ratio - 0.4) * 0.3

        # String literals are token-dense
        adjustment_factor += string_ratio * 0.3

        # Keywords are typically single tokens
        adjustment_factor += keyword_ratio * 0.1

        # Ensure reasonable bounds
        adjustment_factor = max(0.5, min(1.5, adjustment_factor))

        return base_tokens * adjustment_factor

    def _count_comments(self, content: str, language: Language) -> int:
        """Count comment characters in content.

        Args:
            content: Code content
            language: Programming language

        Returns:
            Number of comment characters
        """
        comment_chars = 0

        if language in [Language.PYTHON, Language.RUBY]:
            # Python/Ruby-style comments
            for line in content.split("\n"):
                if "#" in line:
                    comment_start = line.find("#")
                    # Check if it's in a string
                    before_hash = line[:comment_start]
                    single_quotes = before_hash.count("'") - before_hash.count("\\'")
                    double_quotes = before_hash.count('"') - before_hash.count('\\"')

                    # Simple check: if odd number of quotes, probably in string
                    if single_quotes % 2 == 0 and double_quotes % 2 == 0:
                        comment_chars += len(line) - comment_start

        elif language in [
            Language.JAVASCRIPT,
            Language.TYPESCRIPT,
            Language.JAVA,
            Language.CSHARP,
            Language.CPP,
            Language.C,
            Language.GO,
            Language.RUST,
            Language.KOTLIN,
            Language.SWIFT,
            Language.PHP,
        ]:
            # C-style comments
            # Single-line comments
            for line in content.split("\n"):
                if "//" in line:
                    comment_start = line.find("//")
                    comment_chars += len(line) - comment_start

            # Multi-line comments (simple approximation)
            multiline_comments = re.findall(r"/\*.*?\*/", content, re.DOTALL)
            for comment in multiline_comments:
                comment_chars += len(comment)

        return comment_chars

    def _count_strings(self, content: str, language: Language) -> int:
        """Count string literal characters in content.

        Args:
            content: Code content
            language: Programming language

        Returns:
            Number of string literal characters
        """
        string_chars = 0

        # Simple regex patterns for string literals
        if language == Language.PYTHON:
            # Python strings (including triple quotes)
            patterns = [
                r'""".*?"""',
                r"'''.*?'''",
                r'"(?:[^"\\]|\\.)*"',
                r"'(?:[^'\\]|\\.)*'",
            ]
        else:
            # Most other languages
            patterns = [r'"(?:[^"\\]|\\.)*"', r"'(?:[^'\\]|\\.)*'"]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                string_chars += len(match)

        return string_chars

    def _count_keywords(self, content: str, language: Language) -> int:
        """Count programming language keywords.

        Args:
            content: Code content
            language: Programming language

        Returns:
            Number of keyword characters
        """
        # Define common keywords per language
        keywords = {
            Language.PYTHON: [
                "def",
                "class",
                "if",
                "else",
                "elif",
                "for",
                "while",
                "try",
                "except",
                "finally",
                "with",
                "import",
                "from",
                "as",
                "return",
                "yield",
                "lambda",
                "and",
                "or",
                "not",
                "in",
                "is",
                "True",
                "False",
            ],
            Language.JAVASCRIPT: [
                "function",
                "var",
                "let",
                "const",
                "if",
                "else",
                "for",
                "while",
                "do",
                "switch",
                "case",
                "default",
                "try",
                "catch",
                "finally",
                "return",
                "async",
                "await",
                "class",
                "extends",
                "import",
                "export",
            ],
            Language.JAVA: [
                "public",
                "private",
                "protected",
                "static",
                "final",
                "class",
                "interface",
                "extends",
                "implements",
                "if",
                "else",
                "for",
                "while",
                "do",
                "switch",
                "case",
                "default",
                "try",
                "catch",
                "finally",
                "return",
                "throw",
                "throws",
                "new",
                "this",
                "super",
            ],
        }

        lang_keywords = keywords.get(language, [])
        if not lang_keywords:
            return 0

        keyword_chars = 0
        for keyword in lang_keywords:
            # Use word boundaries to match whole keywords only
            pattern = r"\b" + re.escape(keyword) + r"\b"
            matches = re.findall(pattern, content, re.IGNORECASE)
            keyword_chars += len(matches) * len(keyword)

        return keyword_chars

    def estimate_prompt_tokens(
        self, system_prompt: str, user_prompt: str, model: str | None = None
    ) -> int:
        """Estimate tokens for prompt components.

        Args:
            system_prompt: System prompt text
            user_prompt: User prompt text
            model: LLM model name

        Returns:
            Estimated total prompt tokens
        """
        system_tokens = self.estimate_tokens(system_prompt, Language.GENERIC, model)
        user_tokens = self.estimate_tokens(user_prompt, Language.GENERIC, model)

        # Add overhead for message structure
        overhead_tokens = 10  # Approximate overhead for message formatting

        return system_tokens + user_tokens + overhead_tokens

    def estimate_response_tokens(
        self, max_findings: int, detailed_analysis: bool = True
    ) -> int:
        """Estimate tokens for expected response.

        Args:
            max_findings: Maximum number of findings expected
            detailed_analysis: Whether analysis includes detailed explanations

        Returns:
            Estimated response tokens
        """
        # Handle None max_findings (unlimited) by using a reasonable default for estimation
        effective_max_findings = max_findings if max_findings is not None else 50

        if effective_max_findings == 0:
            return 50  # Minimal response

        # Base tokens per finding
        base_tokens_per_finding = 100 if detailed_analysis else 50

        # JSON structure overhead
        json_overhead = 20 + (effective_max_findings * 10)

        # Response envelope
        response_overhead = 30

        total_tokens = (
            effective_max_findings * base_tokens_per_finding
            + json_overhead
            + response_overhead
        )

        return total_tokens

    def estimate_total_request_tokens(
        self,
        content: str,
        language: Language,
        system_prompt: str,
        user_prompt_template: str,
        max_findings: int | None = None,
        model: str | None = None,
    ) -> int:
        """Estimate total tokens for a complete analysis request.

        Args:
            content: Code content to analyze
            language: Programming language
            system_prompt: System prompt
            user_prompt_template: User prompt template (before content insertion)
            max_findings: Maximum findings expected
            model: LLM model name

        Returns:
            Estimated total tokens for request + response
        """
        # Estimate content tokens
        content_tokens = self.estimate_tokens(content, language, model)

        # Estimate full user prompt (template + content)
        full_user_prompt = user_prompt_template + content
        prompt_tokens = self.estimate_prompt_tokens(
            system_prompt, full_user_prompt, model
        )

        # Estimate response tokens (use a reasonable default for unlimited scans)
        response_tokens = self.estimate_response_tokens(max_findings or 50)

        return prompt_tokens + response_tokens

    def clear_cache(self) -> None:
        """Clear the token estimation cache."""
        self._cache.clear()
        logger.debug("Token estimation cache cleared")

    def get_cache_stats(self) -> dict:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            "cache_size": len(self._cache),
            "cache_hit_ratio": "Not tracked",  # Could be implemented if needed
        }
