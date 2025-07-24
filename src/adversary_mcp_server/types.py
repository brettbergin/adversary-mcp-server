"""Core data types for security vulnerability detection."""

import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Security vulnerability severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    """Security vulnerability categories."""

    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTO = "crypto"
    CRYPTOGRAPHY = "cryptography"
    CONFIGURATION = "configuration"
    VALIDATION = "validation"
    LOGGING = "logging"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    XSS = "xss"
    IDOR = "idor"
    RCE = "rce"
    LFI = "lfi"
    DISCLOSURE = "disclosure"
    ACCESS_CONTROL = "access_control"
    TYPE_SAFETY = "type_safety"
    SECRETS = "secrets"
    DOS = "dos"
    CSRF = "csrf"
    PATH_TRAVERSAL = "path_traversal"
    REDIRECT = "redirect"
    HEADERS = "headers"
    SESSION = "session"
    FILE_UPLOAD = "file_upload"
    XXE = "xxe"
    CLICKJACKING = "clickjacking"
    MISC = "misc"  # Generic category for miscellaneous threats


class Language(str, Enum):
    """Supported programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    HTML = "html"
    CSS = "css"
    JSON = "json"
    YAML = "yaml"
    XML = "xml"
    PHP = "php"
    SHELL = "shell"
    DOCKERFILE = "dockerfile"
    GO = "go"
    RUBY = "ruby"
    JAVA = "java"
    CSHARP = "csharp"
    SQL = "sql"
    TERRAFORM = "terraform"
    GENERIC = "generic"  # For unknown file types


class LanguageSupport:
    """Centralized language support configuration.

    This class contains all language-related mappings and configurations
    in one place to avoid duplication across modules.
    """

    # Central configuration: Language -> (primary_extension, [all_extensions])
    _LANGUAGE_CONFIG = {
        Language.PYTHON: (".py", [".py", ".pyw", ".pyx"]),
        Language.JAVASCRIPT: (".js", [".js", ".jsx", ".mjs", ".cjs"]),
        Language.TYPESCRIPT: (".ts", [".ts", ".tsx", ".mts", ".cts"]),
        Language.HTML: (
            ".html",
            [
                ".html",
                ".htm",
                ".ejs",
                ".handlebars",
                ".hbs",
                ".mustache",
                ".vue",
                ".svelte",
            ],
        ),
        Language.CSS: (".css", [".css", ".scss", ".sass", ".less", ".stylus"]),
        Language.JSON: (".json", [".json", ".jsonc", ".json5"]),
        Language.YAML: (".yaml", [".yaml", ".yml"]),
        Language.XML: (".xml", [".xml", ".xsl", ".xslt", ".svg", ".rss", ".atom"]),
        Language.PHP: (
            ".php",
            [".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"],
        ),
        Language.SHELL: (".sh", [".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh"]),
        Language.DOCKERFILE: (".dockerfile", [".dockerfile", "Dockerfile"]),
        Language.GO: (".go", [".go"]),
        Language.RUBY: (".rb", [".rb", ".rbw", ".rake", ".gemspec"]),
        Language.JAVA: (".java", [".java", ".groovy", ".gradle"]),
        Language.CSHARP: (".cs", [".cs", ".csx", ".vb"]),
        Language.SQL: (".sql", [".sql", ".psql", ".mysql", ".sqlite", ".plsql"]),
        Language.TERRAFORM: (".tf", [".tf", ".tfvars", ".hcl"]),
        Language.GENERIC: (
            ".txt",
            [
                ".txt",
                ".md",
                ".cfg",
                ".conf",
                ".ini",
                ".env",
                ".toml",
                ".log",
                ".properties",
            ],
        ),
    }

    @classmethod
    def get_supported_languages(cls) -> list[Language]:
        """Get list of all supported languages."""
        return list(cls._LANGUAGE_CONFIG.keys())

    @classmethod
    def get_extension_to_language_map(cls) -> dict[str, Language]:
        """Get mapping from file extensions to languages."""
        extension_map = {}
        for language, (_, extensions) in cls._LANGUAGE_CONFIG.items():
            for ext in extensions:
                # Handle special case for Dockerfile without extension
                if ext == "Dockerfile":
                    extension_map["dockerfile"] = language  # lowercase for matching
                else:
                    extension_map[ext] = language
        return extension_map

    @classmethod
    def get_language_to_extension_map(cls) -> dict[Language, str]:
        """Get mapping from languages to their primary file extensions."""
        return {
            language: primary_ext
            for language, (primary_ext, _) in cls._LANGUAGE_CONFIG.items()
        }

    @classmethod
    def detect_language(cls, file_path: str | Path) -> Language:
        """Detect language from file path."""
        path = Path(file_path)

        # Handle special case for Dockerfile
        if path.name.lower() in ["dockerfile", "containerfile"]:
            return Language.DOCKERFILE

        extension = path.suffix.lower()
        extension_map = cls.get_extension_to_language_map()

        return extension_map.get(extension, Language.GENERIC)

    @classmethod
    def get_extensions_for_language(cls, language: Language) -> list[str]:
        """Get all file extensions for a specific language."""
        if language in cls._LANGUAGE_CONFIG:
            return cls._LANGUAGE_CONFIG[language][1].copy()
        return []

    @classmethod
    def get_primary_extension(cls, language: Language) -> str:
        """Get the primary file extension for a language."""
        if language in cls._LANGUAGE_CONFIG:
            return cls._LANGUAGE_CONFIG[language][0]
        return ".txt"

    @classmethod
    def get_language_enum_values(cls) -> list[str]:
        """Get list of language enum values for API schemas."""
        return [lang.value for lang in cls.get_supported_languages()]


@dataclass
class ThreatMatch:
    """A detected security threat."""

    # Required fields
    rule_id: str
    rule_name: str
    description: str
    category: Category
    severity: Severity
    file_path: str
    line_number: int

    # Optional fields with defaults
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    column_number: int = 0
    code_snippet: str = ""
    function_name: str | None = None
    exploit_examples: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe_id: str | None = None
    owasp_category: str | None = None
    confidence: float = 1.0  # 0.0 to 1.0
    source: str = "rules"  # Scanner source: "rules", "semgrep", "llm"
    is_false_positive: bool = False  # False positive tracking
