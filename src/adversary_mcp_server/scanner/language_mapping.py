"""
Shared language mapping utilities for consistent language detection across scanners.
"""

from pathlib import Path


class LanguageMapper:
    """Utility class for consistent language mapping across all scanners."""

    # Comprehensive extension-to-language mapping
    EXTENSION_TO_LANGUAGE: dict[str, str] = {
        # Common languages
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".php": "php",
        ".php3": "php",
        ".php4": "php",
        ".php5": "php",
        ".phtml": "php",
        ".rb": "ruby",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".cs": "csharp",
        ".rs": "rust",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".scala": "scala",
        ".sc": "scala",
        ".swift": "swift",
        ".m": "objc",
        ".mm": "objcpp",
        ".pl": "perl",
        ".pm": "perl",
        ".lua": "lua",
        ".r": "r",
        ".R": "r",
        ".dart": "dart",
        ".ex": "elixir",
        ".exs": "elixir",
        ".erl": "erlang",
        ".hrl": "erlang",
        ".hs": "haskell",
        ".lhs": "haskell",
        ".clj": "clojure",
        ".cljs": "clojure",
        ".cljc": "clojure",
        ".fs": "fsharp",
        ".fsx": "fsharp",
        ".fsi": "fsharp",
        ".ml": "ocaml",
        ".mli": "ocaml",
        ".nim": "nim",
        ".nims": "nim",
        ".cr": "crystal",
        ".zig": "zig",
        ".d": "d",
        ".jl": "julia",
        ".rkt": "racket",
        ".scm": "scheme",
        ".lisp": "lisp",
        ".lsp": "lisp",
        # Shell scripting
        ".sh": "bash",
        ".bash": "bash",
        ".zsh": "bash",
        ".fish": "bash",
        ".ps1": "powershell",
        ".psm1": "powershell",
        ".psd1": "powershell",
        ".bat": "batch",
        ".cmd": "batch",
        # Web technologies
        ".html": "html",
        ".htm": "html",
        ".xhtml": "html",
        ".css": "css",
        ".scss": "scss",
        ".sass": "sass",
        ".less": "less",
        ".vue": "vue",
        ".svelte": "svelte",
        # Data formats
        ".json": "json",
        ".jsonc": "json",
        ".json5": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
        ".xml": "xml",
        ".xsd": "xml",
        ".xsl": "xml",
        ".xslt": "xml",
        ".csv": "csv",
        ".ini": "ini",
        ".cfg": "ini",
        ".conf": "ini",
        ".properties": "properties",
        # Database
        ".sql": "sql",
        # Configuration and Infrastructure
        ".dockerfile": "dockerfile",
        ".dockerignore": "dockerfile",
        ".tf": "terraform",
        ".tfvars": "terraform",
        ".hcl": "terraform",
        ".mk": "makefile",
        ".cmake": "cmake",
        ".gradle": "gradle",
        ".sbt": "scala",
        # Other
        ".graphql": "graphql",
        ".gql": "graphql",
        ".proto": "protobuf",
        ".avsc": "json",
        ".thrift": "thrift",
        ".sol": "solidity",
        ".move": "move",
    }

    # Language-to-extension mapping (reverse lookup)
    LANGUAGE_TO_EXTENSION: dict[str, str] = {
        # Common languages
        "python": ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "java": ".java",
        "go": ".go",
        "php": ".php",
        "ruby": ".rb",
        "c": ".c",
        "cpp": ".cpp",
        "c++": ".cpp",
        "cxx": ".cpp",
        "csharp": ".cs",
        "c#": ".cs",
        "rust": ".rs",
        "kotlin": ".kt",
        "scala": ".scala",
        "swift": ".swift",
        "objective-c": ".m",
        "objc": ".m",
        "objcpp": ".mm",
        "perl": ".pl",
        "lua": ".lua",
        "r": ".r",
        "matlab": ".m",
        "dart": ".dart",
        "elixir": ".ex",
        "erlang": ".erl",
        "haskell": ".hs",
        "clojure": ".clj",
        "f#": ".fs",
        "fsharp": ".fs",
        "ocaml": ".ml",
        "nim": ".nim",
        "crystal": ".cr",
        "zig": ".zig",
        "d": ".d",
        "julia": ".jl",
        "racket": ".rkt",
        "scheme": ".scm",
        "common-lisp": ".lisp",
        "lisp": ".lisp",
        # Shell scripting
        "bash": ".sh",
        "shell": ".sh",
        "sh": ".sh",
        "zsh": ".zsh",
        "fish": ".fish",
        "powershell": ".ps1",
        "batch": ".bat",
        # Web technologies
        "html": ".html",
        "css": ".css",
        "scss": ".scss",
        "sass": ".sass",
        "less": ".less",
        "vue": ".vue",
        "svelte": ".svelte",
        "jsx": ".jsx",
        "tsx": ".tsx",
        # Data formats
        "json": ".json",
        "yaml": ".yaml",
        "yml": ".yml",
        "toml": ".toml",
        "xml": ".xml",
        "csv": ".csv",
        # Database
        "sql": ".sql",
        "mysql": ".sql",
        "postgresql": ".sql",
        "sqlite": ".sql",
        # Configuration
        "dockerfile": ".dockerfile",
        "makefile": ".mk",
        "cmake": ".cmake",
        # Other
        "graphql": ".graphql",
        "proto": ".proto",
        "protobuf": ".proto",
        "avro": ".avsc",
        "thrift": ".thrift",
        "generic": ".txt",
    }

    @classmethod
    def detect_language_from_extension(cls, file_path: str | Path) -> str:
        """Detect programming language from file extension.

        Args:
            file_path: File path (string or Path object)

        Returns:
            Language name, defaults to 'generic' for unknown extensions
        """
        if isinstance(file_path, str):
            file_path = Path(file_path)

        extension = file_path.suffix.lower()
        return cls.EXTENSION_TO_LANGUAGE.get(extension, "generic")

    @classmethod
    def get_extension_for_language(cls, language: str | None) -> str:
        """Get file extension for language.

        Args:
            language: Programming language identifier

        Returns:
            File extension for the language, defaults to '.txt' for unknown languages
        """
        if not language:
            return ".txt"

        # Handle both string and object types (for backward compatibility)
        if hasattr(language, "value"):
            language_str = language.value
        elif hasattr(language, "lower"):
            language_str = language
        else:
            language_str = str(language)

        return cls.LANGUAGE_TO_EXTENSION.get(language_str.lower(), ".txt")

    @classmethod
    def is_supported_language(cls, language: str) -> bool:
        """Check if a language is supported.

        Args:
            language: Language name to check

        Returns:
            True if language is supported, False otherwise
        """
        if not language:
            return False
        return language.lower() in cls.LANGUAGE_TO_EXTENSION

    @classmethod
    def is_supported_extension(cls, extension: str) -> bool:
        """Check if a file extension is supported.

        Args:
            extension: File extension to check (with or without leading dot)

        Returns:
            True if extension is supported, False otherwise
        """
        if not extension:
            return False

        # Ensure extension starts with dot
        if not extension.startswith("."):
            extension = "." + extension

        return extension.lower() in cls.EXTENSION_TO_LANGUAGE

    @classmethod
    def get_supported_languages(cls) -> list[str]:
        """Get list of all supported languages.

        Returns:
            Sorted list of supported language names
        """
        return sorted(cls.LANGUAGE_TO_EXTENSION.keys())

    @classmethod
    def get_supported_extensions(cls) -> list[str]:
        """Get list of all supported file extensions.

        Returns:
            Sorted list of supported file extensions
        """
        return sorted(cls.EXTENSION_TO_LANGUAGE.keys())
