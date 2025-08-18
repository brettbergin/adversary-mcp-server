"""Comprehensive input validation to prevent security issues."""

import os
import re
from enum import Enum
from pathlib import Path
from typing import Any

from ..scanner.language_mapping import LanguageMapper


class SecurityError(Exception):
    """Exception raised when input validation detects a security issue."""

    pass


class SeverityThreshold(str, Enum):
    """Valid severity threshold values."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InputValidator:
    """Comprehensive input validation to prevent security vulnerabilities."""

    # Patterns for dangerous inputs
    PATH_TRAVERSAL_PATTERN = re.compile(r"\.\.[/\\]|\.\.\\|\.\./")
    COMMAND_INJECTION_PATTERN = re.compile(r"[;&|`$(){}]")
    SQL_INJECTION_PATTERN = re.compile(
        r"('|\"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b)",
        re.IGNORECASE,
    )
    NULL_BYTE_PATTERN = re.compile(r"\x00")

    # Allowed file extensions for scanning
    ALLOWED_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".c",
        ".cpp",
        ".cc",
        ".cxx",
        ".h",
        ".hpp",
        ".cs",
        ".php",
        ".rb",
        ".go",
        ".rs",
        ".kt",
        ".swift",
        ".scala",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        ".sql",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".vue",
        ".svelte",
        ".dockerfile",
        ".makefile",
        ".cmake",
        ".gradle",
        ".pom",
        ".sbt",
    }

    @staticmethod
    def validate_file_path(path: str, allowed_dirs: list[Path] | None = None) -> Path:
        """Validate and sanitize file paths.

        Args:
            path: The file path to validate
            allowed_dirs: Optional list of allowed parent directories

        Returns:
            Validated Path object

        Raises:
            SecurityError: If path contains security issues
            FileNotFoundError: If file doesn't exist
            ValueError: If path is not a file
        """
        # Check for null bytes
        if InputValidator.NULL_BYTE_PATTERN.search(path):
            raise SecurityError("Null bytes detected in file path")

        # Check for path traversal attempts
        if InputValidator.PATH_TRAVERSAL_PATTERN.search(path):
            raise SecurityError("Path traversal attempt detected")

        # Convert to Path and resolve to get absolute path
        try:
            safe_path = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise SecurityError(f"Invalid file path: {e}")

        # Ensure within allowed directories if specified
        if allowed_dirs:
            if not any(safe_path.is_relative_to(d.resolve()) for d in allowed_dirs):
                raise SecurityError("File path outside allowed directories")

        # Check file exists
        if not safe_path.exists():
            raise FileNotFoundError(f"File not found: {safe_path}")

        # Ensure it's a file, not a directory
        if not safe_path.is_file():
            raise ValueError(f"Path is not a file: {safe_path}")

        return safe_path

    @staticmethod
    def validate_directory_path(
        path: str, allowed_dirs: list[Path] | None = None
    ) -> Path:
        """Validate directory paths for scanning.

        Args:
            path: The directory path to validate
            allowed_dirs: Optional list of allowed parent directories

        Returns:
            Validated Path object

        Raises:
            SecurityError: If path contains security issues
            FileNotFoundError: If directory doesn't exist
            ValueError: If path is not a directory
        """
        # Check for null bytes
        if InputValidator.NULL_BYTE_PATTERN.search(path):
            raise SecurityError("Null bytes detected in directory path")

        # Check for path traversal attempts
        if InputValidator.PATH_TRAVERSAL_PATTERN.search(path):
            raise SecurityError("Path traversal attempt detected")

        # Convert to Path and resolve
        try:
            safe_path = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise SecurityError(f"Invalid directory path: {e}")

        # Ensure within allowed directories if specified
        if allowed_dirs:
            if not any(safe_path.is_relative_to(d.resolve()) for d in allowed_dirs):
                raise SecurityError("Directory path outside allowed directories")

        # Check directory exists
        if not safe_path.exists():
            raise FileNotFoundError(f"Directory not found: {safe_path}")

        # Ensure it's a directory
        if not safe_path.is_dir():
            raise ValueError(f"Path is not a directory: {safe_path}")

        return safe_path

    @staticmethod
    def validate_severity_threshold(severity: str) -> str:
        """Validate severity threshold parameter.

        Args:
            severity: The severity string to validate

        Returns:
            Validated severity string (lowercase)

        Raises:
            ValueError: If severity is invalid
        """
        if not isinstance(severity, str):
            raise ValueError("Severity must be a string")

        severity = severity.lower().strip()

        if severity not in [s.value for s in SeverityThreshold]:
            valid_values = [s.value for s in SeverityThreshold]
            raise ValueError(
                f"Invalid severity '{severity}'. Must be one of: {valid_values}"
            )

        return severity

    @staticmethod
    def validate_boolean_param(param: Any, param_name: str) -> bool:
        """Validate boolean parameters from MCP requests.

        Args:
            param: The parameter to validate
            param_name: Name of the parameter for error messages

        Returns:
            Validated boolean value

        Raises:
            ValueError: If parameter is not a valid boolean
        """
        if isinstance(param, bool):
            return param

        if isinstance(param, str):
            param_lower = param.lower().strip()
            if param_lower in ("true", "1", "yes", "on", "enabled"):
                return True
            elif param_lower in ("false", "0", "no", "off", "disabled"):
                return False

        raise ValueError(f"Invalid boolean value for {param_name}: {param}")

    @staticmethod
    def validate_integer_param(
        param: Any, param_name: str, min_val: int = 0, max_val: int = 10000
    ) -> int:
        """Validate integer parameters with bounds checking.

        Args:
            param: The parameter to validate
            param_name: Name of the parameter for error messages
            min_val: Minimum allowed value
            max_val: Maximum allowed value

        Returns:
            Validated integer value

        Raises:
            ValueError: If parameter is not a valid integer or out of bounds
        """
        if isinstance(param, int):
            value = param
        elif isinstance(param, str):
            try:
                value = int(param.strip())
            except ValueError:
                raise ValueError(f"Invalid integer value for {param_name}: {param}")
        else:
            raise ValueError(
                f"Invalid type for {param_name}: expected int, got {type(param)}"
            )

        if value < min_val or value > max_val:
            raise ValueError(
                f"{param_name} must be between {min_val} and {max_val}, got {value}"
            )

        return value

    @staticmethod
    def validate_string_param(
        param: Any,
        param_name: str,
        max_length: int = 1000,
        allowed_chars_pattern: str | None = None,
    ) -> str:
        """Validate string parameters with length and character restrictions.

        Args:
            param: The parameter to validate
            param_name: Name of the parameter for error messages
            max_length: Maximum allowed string length
            allowed_chars_pattern: Optional regex pattern for allowed characters

        Returns:
            Validated string value

        Raises:
            ValueError: If parameter is invalid
            SecurityError: If parameter contains dangerous patterns
        """
        if not isinstance(param, str):
            raise ValueError(f"{param_name} must be a string, got {type(param)}")

        # Check length
        if len(param) > max_length:
            raise ValueError(f"{param_name} too long: {len(param)} > {max_length}")

        # Check for null bytes
        if InputValidator.NULL_BYTE_PATTERN.search(param):
            raise SecurityError(f"Null bytes detected in {param_name}")

        # Check for command injection patterns
        if InputValidator.COMMAND_INJECTION_PATTERN.search(param):
            raise SecurityError(f"Command injection pattern detected in {param_name}")

        # Check for SQL injection patterns
        if InputValidator.SQL_INJECTION_PATTERN.search(param):
            raise SecurityError(f"SQL injection pattern detected in {param_name}")

        # Check allowed characters if pattern provided
        if allowed_chars_pattern and not re.match(allowed_chars_pattern, param):
            raise ValueError(f"{param_name} contains invalid characters")

        return param.strip()

    @staticmethod
    def validate_code_content(code: str, max_length: int = 1000000) -> str:
        """Validate code content for scanning.

        Args:
            code: The code content to validate
            max_length: Maximum allowed code length

        Returns:
            Validated code string

        Raises:
            ValueError: If code is invalid
            SecurityError: If code contains dangerous patterns
        """
        if not isinstance(code, str):
            raise ValueError("Code content must be a string")

        # Check length
        if len(code) > max_length:
            raise ValueError(f"Code content too long: {len(code)} > {max_length}")

        # Check for null bytes
        if InputValidator.NULL_BYTE_PATTERN.search(code):
            raise SecurityError("Null bytes detected in code content")

        return code

    @staticmethod
    def validate_language(language: str) -> str:
        """Validate programming language parameter.

        Args:
            language: The programming language to validate

        Returns:
            Validated language string

        Raises:
            ValueError: If language is invalid
            SecurityError: If language contains dangerous patterns
        """
        if not isinstance(language, str):
            raise ValueError("Language must be a string")

        # Check for null bytes and dangerous patterns
        if InputValidator.NULL_BYTE_PATTERN.search(language):
            raise SecurityError("Null bytes detected in language parameter")

        if InputValidator.COMMAND_INJECTION_PATTERN.search(language):
            raise SecurityError(
                "Command injection pattern detected in language parameter"
            )

        # Validate against supported languages using LanguageMapper
        language = language.lower().strip()

        if not LanguageMapper.is_supported_language(language):
            supported_languages = LanguageMapper.get_supported_languages()
            raise ValueError(
                f"Unsupported language: {language}. Supported languages: {supported_languages[:10]}..."
            )

        return language

    @staticmethod
    def validate_mcp_arguments(
        arguments: dict[str, Any], tool_name: str | None = None
    ) -> dict[str, Any]:
        """Validate arguments from MCP tool calls.

        Args:
            arguments: Dictionary of MCP tool arguments
            tool_name: Name of the MCP tool being called (for context-aware validation)

        Returns:
            Validated and sanitized arguments dictionary

        Raises:
            ValueError: If arguments are invalid
            SecurityError: If arguments contain dangerous content
        """
        if not isinstance(arguments, dict):
            raise ValueError("Arguments must be a dictionary")

        validated = {}

        # Validate each argument based on its key
        for key, value in arguments.items():
            key_lower = key.lower()

            if "path" in key_lower:
                # File or directory path - use tool context for smart validation
                if key_lower.endswith("file_path"):
                    # Explicitly file path
                    validated[key] = str(InputValidator.validate_file_path(str(value)))
                elif key_lower == "path":
                    # Context-aware path validation based on tool name
                    if tool_name in ("adv_scan_folder", "adv_diff_scan"):
                        # These tools expect directory paths
                        validated[key] = str(
                            InputValidator.validate_directory_path(str(value))
                        )
                    elif tool_name in ("adv_scan_file",):
                        # File scanning tools expect file paths
                        validated[key] = str(
                            InputValidator.validate_file_path(str(value))
                        )
                    else:
                        # Default to file path validation for other tools
                        validated[key] = str(
                            InputValidator.validate_file_path(str(value))
                        )
                else:
                    # Other path-related parameters default to directory validation
                    validated[key] = str(
                        InputValidator.validate_directory_path(str(value))
                    )

            elif key_lower in ("severity", "severity_threshold"):
                validated[key] = InputValidator.validate_severity_threshold(str(value))

            elif key_lower in (
                "use_validation",
                "use_llm",
                "use_semgrep",
                "recursive",
                "include_exploits",
                "verbose",
            ):
                validated[key] = InputValidator.validate_boolean_param(value, key)

            elif key_lower in ("timeout", "max_findings", "limit"):
                validated[key] = InputValidator.validate_integer_param(value, key)

            elif key_lower == "content":
                validated[key] = InputValidator.validate_code_content(str(value))

            elif key_lower == "language":
                validated[key] = InputValidator.validate_language(str(value))

            elif key_lower in (
                "source_branch",
                "target_branch",
            ):
                validated[key] = InputValidator.validate_string_param(
                    str(value), key, 200, r"^[a-zA-Z0-9_.-]+$"
                )

            elif key_lower == "output_format":
                # Validate against allowed output formats
                allowed_formats = ["json", "markdown", "csv", "txt"]
                format_value = str(value).lower().strip()
                if format_value not in allowed_formats:
                    raise ValueError(
                        f"Invalid output format '{format_value}'. Must be one of: {allowed_formats}"
                    )
                validated[key] = format_value

            elif key_lower == "output_file":
                # Validate output file path (allow non-existent files for writing)
                validated[key] = InputValidator.validate_string_param(
                    str(value), key, 500, r"^[a-zA-Z0-9\s\.\-_/\\:]+$"
                )

            elif key_lower == "finding_uuid":
                # UUIDs need different pattern (allow hyphens)
                validated[key] = InputValidator.validate_string_param(
                    str(value), key, 100, r"^[a-fA-F0-9-]+$"
                )

            elif key_lower in ("reason", "marked_by"):
                # Allow more characters for human-readable text
                validated[key] = InputValidator.validate_string_param(
                    str(value), key, 500, r"^[a-zA-Z0-9\s\.,!?\-_()]+$"
                )

            elif key_lower in ("adversary_file_path", "input_file"):
                # File path validation
                validated[key] = str(InputValidator.validate_file_path(str(value)))

            else:
                # Generic string validation for unknown parameters
                if isinstance(value, str):
                    validated[key] = InputValidator.validate_string_param(value, key)
                else:
                    validated[key] = value

        return validated

    @staticmethod
    def sanitize_input(input_text: str | None) -> str:
        """Sanitize input by removing dangerous characters.

        Args:
            input_text: The input text to sanitize

        Returns:
            Sanitized string with null bytes and dangerous patterns removed

        Raises:
            TypeError: If input is not a string or None
        """
        if input_text is None:
            return ""

        if not isinstance(input_text, str):
            # Convert to string if possible
            input_text = str(input_text)

        # Remove null bytes
        sanitized = InputValidator.NULL_BYTE_PATTERN.sub("", input_text)

        # Note: We don't remove command injection patterns here as they might be legitimate
        # in code content. This method focuses on basic sanitization.

        return sanitized

    @staticmethod
    def get_allowed_scan_directories() -> list[Path]:
        """Get list of allowed directories for scanning.

        This helps prevent scanning sensitive system directories.

        Returns:
            List of allowed Path objects
        """
        home = Path.home()
        cwd = Path.cwd()

        allowed_dirs = [
            home / "Documents",
            home / "Desktop",
            home / "Downloads",
            home / "Code",
            home / "code",
            home / "Projects",
            home / "projects",
            home / "workspace",
            home / "Workspace",
            cwd,
        ]

        # Add common development directories if they exist
        dev_dirs = [
            Path("/opt"),
            Path("/usr/local/src"),
            Path("/home") / os.getenv("USER", "user"),
            Path("/Users") / os.getenv("USER", "user"),
        ]

        for dir_path in dev_dirs:
            if dir_path.exists() and dir_path.is_dir():
                allowed_dirs.append(dir_path)

        return [d for d in allowed_dirs if d.exists() and d.is_dir()]
