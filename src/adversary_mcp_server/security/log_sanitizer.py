"""Sensitive data sanitization for logging."""

import re
from typing import Any

# Patterns for sensitive data that should be redacted in logs
SENSITIVE_PATTERNS = [
    # API Keys - more comprehensive patterns
    (
        re.compile(
            r'(["\']?)api[_-]?key(["\']?)\s*[:=]\s*(["\']?)([a-zA-Z0-9_-]{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1api_key\2: \3[REDACTED]\5",
    ),
    (
        re.compile(
            r'(["\']?)semgrep[_-]?api[_-]?key(["\']?)\s*[:=]\s*(["\']?)([a-zA-Z0-9_-]{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1semgrep_api_key\2=\3[REDACTED]\5",
    ),
    (
        re.compile(
            r'(["\']?)llm[_-]?api[_-]?key(["\']?)\s*[:=]\s*(["\']?)([a-zA-Z0-9_-]{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1llm_api_key\2: \3[REDACTED]\5",
    ),
    # Tokens
    (
        re.compile(
            r'(["\']?)token(["\']?)\s*[:=]\s*(["\']?)([a-zA-Z0-9_-]{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1token\2: \3[REDACTED]\5",
    ),
    (
        re.compile(
            r'(["\']?)access[_-]?token(["\']?)\s*[:=]\s*(["\']?)([a-zA-Z0-9_-]{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1access_token\2=\3[REDACTED]\5",
    ),
    (
        re.compile(
            r'(["\']?)bearer[_-]?token(["\']?)\s*[:=]\s*(["\']?)([a-zA-Z0-9_-]{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1bearer_token\2: \3[REDACTED]\5",
    ),
    # Bearer tokens in values
    (
        re.compile(
            r'(["\']?)Bearer\s+([a-zA-Z0-9_-]{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1Bearer [REDACTED]\3",
    ),
    # Passwords
    (
        re.compile(
            r'(["\']?)password(["\']?)\s*[:=]\s*(["\']?)([^\s"\']{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1password\2: \3[REDACTED]\5",
    ),
    (
        re.compile(
            r'(["\']?)pass(["\']?)\s*[:=]\s*(["\']?)([^\s"\']{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1pass\2=\3[REDACTED]\5",
    ),
    # Generic secrets
    (
        re.compile(
            r'(["\']?)(secret[_\w]*)(["\']?)\s*[:=]\s*(["\']?)([a-zA-Z0-9_-]{3,})(["\']?)',
            re.IGNORECASE,
        ),
        r"\1\2\3: \4[REDACTED]\6",
    ),
    # OpenAI-style keys
    (re.compile(r"sk-[a-zA-Z0-9]{48}", re.IGNORECASE), "[REDACTED-OPENAI-KEY]"),
    # JWT tokens (basic detection)
    (
        re.compile(
            r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", re.IGNORECASE
        ),
        "[REDACTED-JWT]",
    ),
    # Private keys
    (
        re.compile(
            r"-----BEGIN[A-Z\s]*PRIVATE KEY-----.*?-----END[A-Z\s]*PRIVATE KEY-----",
            re.IGNORECASE | re.DOTALL,
        ),
        "[REDACTED-PRIVATE-KEY]",
    ),
    (
        re.compile(
            r"-----BEGIN[A-Z\s]*PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        "[REDACTED-PRIVATE-KEY]",
    ),
]

# Environment variable names that should have values redacted
SENSITIVE_ENV_VARS = {
    "ADVERSARY_SEMGREP_API_KEY",
    "ADVERSARY_LLM_API_KEY",
    "ADVERSARY_OPENAI_API_KEY",
    "ADVERSARY_ANTHROPIC_API_KEY",
    "ADVERSARY_SECRET",
    "ADVERSARY_TOKEN",
    "ADVERSARY_PASSWORD",
    "API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SEMGREP_API_KEY",
}


def sanitize_for_logging(data: Any) -> str:
    """Sanitize sensitive data for safe logging.

    This function takes any data (string, dict, list, etc.) and returns a
    string representation with sensitive information redacted.

    Args:
        data: The data to sanitize (can be dict, list, string, or any serializable type)

    Returns:
        String representation with sensitive data redacted

    Example:
        >>> sanitize_for_logging({"api_key": "sk-abc123", "file": "test.py"})
        "{'api_key': '[REDACTED]', 'file': 'test.py'}"
    """
    if data is None:
        return "None"

    # Convert to string representation
    if isinstance(data, str):
        text = data
    else:
        text = str(data)

    # Apply all sensitive patterns
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)

    return text


def sanitize_dict_for_logging(data: dict[str, Any]) -> dict[str, Any]:
    """Sanitize a dictionary for safe logging, preserving structure.

    This creates a new dictionary with the same structure but sensitive
    values replaced with [REDACTED].

    Args:
        data: Dictionary to sanitize

    Returns:
        New dictionary with sensitive values redacted

    Example:
        >>> sanitize_dict_for_logging({"api_key": "sk-abc123", "file": "test.py"})
        {"api_key": "[REDACTED]", "file": "test.py"}
    """
    if not isinstance(data, dict):
        return data

    sanitized = {}
    for key, value in data.items():
        key_lower = key.lower()

        # Check if this is a sensitive key
        is_sensitive_key = any(
            sensitive_word in key_lower
            for sensitive_word in ["api_key", "token", "password", "secret", "key"]
        )

        if is_sensitive_key:
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict_for_logging(value)
        elif isinstance(value, list):
            sanitized[key] = [
                (
                    sanitize_dict_for_logging(item)
                    if isinstance(item, dict)
                    else sanitize_for_logging(item)
                )
                for item in value
            ]
        elif isinstance(value, str):
            sanitized[key] = sanitize_for_logging(value)
        else:
            sanitized[key] = value

    return sanitized


def sanitize_env_vars(env_dict: dict[str, str]) -> dict[str, str]:
    """Sanitize environment variables for logging.

    Args:
        env_dict: Dictionary of environment variables

    Returns:
        Dictionary with sensitive environment variables redacted
    """
    sanitized = {}
    for key, value in env_dict.items():
        if key in SENSITIVE_ENV_VARS or any(
            sensitive in key.upper()
            for sensitive in ["API_KEY", "TOKEN", "SECRET", "PASSWORD"]
        ):
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = value
    return sanitized
