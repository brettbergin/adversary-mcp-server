"""
Shared language mapping utilities for consistent language detection across scanners.
"""

from pathlib import Path

# Common binary file extensions to skip
BINARY_EXTENSIONS: set[str] = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".jar",
    ".war",
    ".ear",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".tiff",
    ".webp",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".wmv",
    ".flv",
    ".wav",
    ".ogg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
}

# Common directories to exclude by default
DEFAULT_EXCLUDE_DIRS: set[str] = {
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    ".npm",
    ".yarn",
    "build",
    "dist",
    "target",
    ".target",
    "coverage",
    "htmlcov",
    ".coverage",
    ".tox",
    ".venv",
    "venv",
    "env",
    ".env",
    "virtualenv",
    ".virtualenv",
    "pyenv",
    ".pyenv",
    # Additional virtual environment patterns
    "venv3",
    "venv2",
    ".python-version",
    "site-packages",
    "lib/python3.9",
    "lib/python3.10",
    "lib/python3.11",
    "lib/python3.12",
    "pyvenv.cfg",
    "vendor",
    "Pods",
    ".gradle",
    ".idea",
    ".vscode",
    ".DS_Store",
    "Thumbs.db",
}

# Common file patterns to exclude
DEFAULT_EXCLUDE_PATTERNS: set[str] = {
    "*.log",
    "*.tmp",
    "*.temp",
    "*.cache",
    "*.lock",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    "*.pid",
    "*.swp",
    "*.swo",
    "*~",
    "*.orig",
    "*.rej",
    ".DS_Store",
    "Thumbs.db",
    "*.min.js",
    "*.min.css",
    "package-lock.json",
    "yarn.lock",
    # Adversary MCP server output files
    "adversary*.json",
    ".adversary*.json",
    "adversary*.md",
    ".adversary*.md",
    "adversary*.csv",
    ".adversary*.csv",
    "Cargo.lock",
    "Pipfile.lock",
    "poetry.lock",
    "*.generated.*",
    "*.gen.*",
    "*_pb2.py",
    "*_pb2_grpc.py",
    # Virtual environment files
    "pyvenv.cfg",
    "*.pth",
    "RECORD",
    "INSTALLER",
    "METADATA",
    "WHEEL",
    "*.dist-info/*",
    "*.egg-info/*",
    # Documentation files (often contain code examples that cause false positives)
    "*.md",
    "*.MD",
    "*.markdown",
    "*.MARKDOWN",
    "*.rst",
    "*.RST",
    "README.txt",
    "readme.txt",
    "CHANGELOG.txt",
    "changelog.txt",
    "LICENSE.txt",
    "license.txt",
    "AUTHORS.txt",
    "authors.txt",
    "CONTRIBUTORS.txt",
    "contributors.txt",
    # Adversary MCP server output files (prevent scanning our own output)
    "adversary.*",
    ".adversary.*",
    "*.adversary.json",
    "*.adversary.md",
    "*.adversary.csv",
}

# Blocked paths for security - used by validation service
BLOCKED_PATH_PATTERNS: set[str] = {
    r".*\.git/.*",
    r".*\.ssh/.*",
    r".*\.gnupg/.*",
    r".*/proc/.*",
    r".*/sys/.*",
    r".*/dev/.*",
    r".*\.env$",
    r".*\.key$",
    r".*\.pem$",
    r".*password.*",
    r".*secret.*",
}

# Extensions that are considered source code for deeper analysis
ANALYZABLE_SOURCE_EXTENSIONS: set[str] = {
    # Python
    ".py",
    # JavaScript/TypeScript
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    # Java and JVM languages
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".sc",
    # C/C++
    ".c",
    ".cpp",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".hxx",
    # .NET languages
    ".cs",
    ".fs",
    ".fsx",
    ".fsi",
    # System languages
    ".go",
    ".rs",
    ".zig",
    ".d",
    ".swift",
    ".m",
    ".mm",
    # Functional languages
    ".hs",
    ".lhs",
    ".clj",
    ".cljs",
    ".cljc",
    ".ml",
    ".mli",
    ".ex",
    ".exs",
    ".erl",
    ".hrl",
    ".jl",
    ".rkt",
    ".scm",
    ".lisp",
    ".lsp",
    # Dynamic languages
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".phtml",
    ".rb",
    ".pl",
    ".pm",
    ".lua",
    ".r",
    ".R",
    ".dart",
    ".nim",
    ".nims",
    ".cr",
    # Shell scripting
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".psm1",
    ".psd1",
    ".bat",
    ".cmd",
    # Web technologies
    ".html",
    ".htm",
    ".xhtml",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".vue",
    ".svelte",
    # Configuration and data formats (for security analysis)
    ".json",
    ".jsonc",
    ".json5",
    ".yaml",
    ".yml",
    ".toml",
    ".xml",
    ".xsd",
    ".xsl",
    ".xslt",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    # Database
    ".sql",
    # Infrastructure as Code
    ".dockerfile",
    ".dockerignore",
    ".tf",
    ".tfvars",
    ".hcl",
    ".mk",
    ".cmake",
    ".gradle",
    ".sbt",
    # Other specialized languages
    ".graphql",
    ".gql",
    ".proto",
    ".avsc",
    ".thrift",
    ".sol",
    ".move",
}

# Indicators that suggest a path belongs to a Python virtual environment
VENV_INDICATORS: list[str] = [
    ".venv",
    "venv",
    "env",
    ".env",
    "virtualenv",
    ".virtualenv",
    "site-packages",
    "lib/python",
    "pyvenv.cfg",
]

# Common project root indicators used across scanners
PROJECT_ROOT_INDICATORS: list[str] = [
    ".git",
    ".hg",
    ".svn",
    ".bzr",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "composer.json",
    "go.mod",
    ".project",
    "Makefile",
    "CMakeLists.txt",
    "mix.exs",
    "pubspec.yaml",
    "Package.swift",
]


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
        # Infrastructure and deployment
        "terraform": ".tf",
        "hcl": ".hcl",
        "gradle": ".gradle",
        # Blockchain and smart contracts
        "solidity": ".sol",
        "move": ".move",
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

    @classmethod
    def find_project_root(cls, file_path: Path) -> Path:
        """Find project root by looking for common project indicators.

        This method provides centralized project root detection logic
        used across all scanners to ensure consistency.

        Args:
            file_path: File or directory path to start search from

        Returns:
            Path to project root, or file's parent if no indicators found
        """
        current = file_path.parent if file_path.is_file() else file_path

        while current.parent != current:
            if any(
                (current / indicator).exists() for indicator in PROJECT_ROOT_INDICATORS
            ):
                return current
            current = current.parent

        # If no project root found, use the file's parent directory
        return file_path.parent if file_path.is_file() else file_path

    @classmethod
    def is_virtual_environment_path(cls, file_path: Path) -> bool:
        """Check if a path belongs to a Python virtual environment.

        Args:
            file_path: Path to check

        Returns:
            True if path appears to be in a virtual environment
        """
        path_str = str(file_path).lower()
        return any(indicator in path_str for indicator in VENV_INDICATORS)

    @classmethod
    def get_security_analysis_hints(cls, language: str) -> str:
        """Get language-specific security analysis hints for LLM scanning.

        Args:
            language: Programming language identifier

        Returns:
            Security-focused analysis hints for the language
        """
        security_hints = {
            "python": "Focus on Flask/Django security, SQL injection, XSS, pickle deserialization, path traversal, and Python-specific vulnerabilities like eval() misuse",
            "javascript": "Focus on XSS, prototype pollution, NPM vulnerabilities, Node.js security, injection attacks, and client-side security issues",
            "typescript": "Focus on type safety bypasses, XSS, TypeScript-specific security issues, and potential runtime type coercion vulnerabilities",
            "java": "Focus on deserialization vulnerabilities, injection flaws, Spring security issues, XML external entity (XXE), and Java-specific memory leaks",
            "go": "Focus on Go-specific vulnerabilities, race conditions, memory safety, goroutine leaks, and unsafe package usage",
            "php": "Focus on PHP-specific vulnerabilities, file inclusion attacks, SQL injection, XSS, session security, and unsafe deserialization",
            "ruby": "Focus on Ruby on Rails security, mass assignment, SQL injection, XSS, and unsafe YAML/code evaluation",
            "rust": "Focus on unsafe code blocks, memory safety violations, concurrency issues, and potential panic conditions",
            "c": "Focus on buffer overflows, memory management, format string vulnerabilities, and integer overflow/underflow",
            "cpp": "Focus on memory corruption, buffer overflows, use-after-free, RAII violations, and unsafe pointer operations",
            "csharp": "Focus on .NET security, SQL injection, XSS, deserialization attacks, and unsafe code blocks",
            "kotlin": "Focus on null safety bypasses, Java interop security issues, and Android-specific vulnerabilities if applicable",
            "swift": "Focus on memory safety, optional unwrapping issues, and iOS/macOS-specific security patterns",
            "scala": "Focus on JVM security issues, functional programming pitfalls, and Akka/concurrency security",
            "bash": "Focus on command injection, path traversal, privilege escalation, and unsafe shell expansions",
            "powershell": "Focus on code injection, execution policy bypasses, and Windows-specific security issues",
            "sql": "Focus on SQL injection, privilege escalation, and database-specific security misconfigurations",
            "yaml": "Focus on YAML injection, unsafe deserialization, and configuration security issues",
            "json": "Focus on JSON injection, parser vulnerabilities, and configuration exposure risks",
            "xml": "Focus on XXE attacks, XML injection, and schema validation bypasses",
            "html": "Focus on XSS, CSRF, clickjacking, and client-side security vulnerabilities",
            "css": "Focus on CSS injection, data exfiltration through CSS, and UI redressing attacks",
            "dockerfile": "Focus on privilege escalation, secrets exposure, and container security misconfigurations",
            "terraform": "Focus on infrastructure security, secrets management, and cloud security misconfigurations",
            "solidity": "Focus on smart contract vulnerabilities, reentrancy attacks, integer overflow, and gas optimization issues",
        }

        return security_hints.get(
            language.lower(),
            "Perform comprehensive security analysis focusing on common vulnerability patterns",
        )
