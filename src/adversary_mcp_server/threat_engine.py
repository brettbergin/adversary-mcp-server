"""Threat Pattern Engine for security vulnerability detection."""

import re
import shutil
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, field_validator

from .logging_config import get_logger

logger = get_logger("threat_engine")


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


class MatchCondition(BaseModel):
    """A condition that must be met for a rule to match."""

    type: str  # "ast_node", "pattern", "function_call", "import", "variable"
    value: str | list[str] | dict[str, Any]
    case_sensitive: bool = True
    multiline: bool = False

    @field_validator("type")
    @classmethod
    def validate_type(cls, v):
        valid_types = [
            "ast_node",
            "pattern",
            "function_call",
            "import",
            "variable",
            "regex",
        ]
        if v not in valid_types:
            raise ValueError(f"Invalid condition type: {v}")
        return v


class ExploitTemplate(BaseModel):
    """Template for generating exploit examples."""

    type: str  # "curl", "python", "javascript", "shell"
    template: str
    parameters: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    @field_validator("type")
    @classmethod
    def validate_type(cls, v):
        valid_types = ["curl", "python", "javascript", "typescript", "shell", "payload"]
        if v not in valid_types:
            raise ValueError(f"Invalid exploit type: {v}")
        return v


class ThreatRule(BaseModel):
    """A security threat detection rule."""

    id: str
    name: str
    description: str
    category: Category
    severity: Severity
    languages: list[Language]

    # Matching conditions
    conditions: list[MatchCondition]

    # Exploit information
    exploit_templates: list[ExploitTemplate] = field(default_factory=list)

    # Remediation
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    # Metadata
    cwe_id: str | None = None
    owasp_category: str | None = None
    tags: list[str] = field(default_factory=list)

    @field_validator("id")
    @classmethod
    def validate_id(cls, v):
        if not re.match(r"^[a-z0-9_-]+$", v):
            raise ValueError(
                "Rule ID must contain only lowercase letters, numbers, underscores, and hyphens"
            )
        return v


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


def get_user_rules_directory() -> Path:
    """Get the user's rules directory, creating it if it doesn't exist.

    Returns:
        Path to the user's rules directory (~/.local/share/adversary-mcp-server/rules)
    """
    config_dir = Path.home() / ".local" / "share" / "adversary-mcp-server"
    rules_dir = config_dir / "rules"

    # Create the rules directory structure if it doesn't exist
    rules_dir.mkdir(parents=True, exist_ok=True)

    # Create subdirectories
    (rules_dir / "built-in").mkdir(exist_ok=True)
    (rules_dir / "custom").mkdir(exist_ok=True)
    (rules_dir / "organization").mkdir(exist_ok=True)
    (rules_dir / "templates").mkdir(exist_ok=True)

    return rules_dir


def get_builtin_rules_directory() -> Path:
    """Get the built-in rules directory in the user's config.

    Returns:
        Path to the built-in rules directory
    """
    return get_user_rules_directory() / "built-in"


def initialize_user_rules_directory() -> None:
    """Initialize the user's rules directory with built-in rules and templates.

    This function:
    1. Creates the rules directory structure
    2. Copies built-in rules from the package to user config
    3. Creates rule templates
    """
    user_rules_dir = get_user_rules_directory()
    builtin_rules_dir = user_rules_dir / "built-in"
    templates_dir = user_rules_dir / "templates"

    # Get the package's rules directory (where the shipped rules are)
    # Try multiple locations to find the packaged rules
    possible_package_rules_dirs = [
        # In development mode (repo structure)
        Path(__file__).parent.parent.parent / "rules",
        # In installed package (site-packages/rules - same level as adversary_mcp_server)
        Path(__file__).parent.parent / "rules",
        # Alternative installed package location
        Path(__file__).parent / "rules",
    ]

    package_rules_dir = None
    for rules_dir in possible_package_rules_dirs:
        if rules_dir.exists():
            package_rules_dir = rules_dir
            break

    if not package_rules_dir:
        logger.warning("Could not find packaged rules directory")
        return

    # Copy built-in rules from package to user config (if they exist and user doesn't have them or if package version is newer)
    package_builtin_dir = package_rules_dir / "built-in"
    if package_builtin_dir.exists():
        for rule_file in package_builtin_dir.glob("*.yaml"):
            user_rule_file = builtin_rules_dir / rule_file.name
            should_copy = False

            if not user_rule_file.exists():
                should_copy = True
            else:
                # Check if package version is newer than user version
                package_stat = rule_file.stat()
                user_stat = user_rule_file.stat()
                if (
                    package_stat.st_mtime > user_stat.st_mtime
                    or package_stat.st_size != user_stat.st_size
                ):
                    should_copy = True

            if should_copy:
                shutil.copy2(rule_file, user_rule_file)

    # Copy templates
    package_templates_dir = package_rules_dir / "templates"
    if package_templates_dir.exists():
        for template_file in package_templates_dir.glob("*.yaml"):
            user_template_file = templates_dir / template_file.name
            should_copy = False

            if not user_template_file.exists():
                should_copy = True
            else:
                # Check if package version is newer than user version
                package_stat = template_file.stat()
                user_stat = user_template_file.stat()
                if (
                    package_stat.st_mtime > user_stat.st_mtime
                    or package_stat.st_size != user_stat.st_size
                ):
                    should_copy = True

            if should_copy:
                shutil.copy2(template_file, user_template_file)


class ThreatEngine:
    """Engine for loading and executing threat detection rules."""

    def __init__(
        self,
        rules_dir: Path | None = None,
        custom_rules_dirs: list[Path] | None = None,
    ):
        """Initialize the threat engine.

        Args:
            rules_dir: Primary directory containing YAML rule files (defaults to user config)
            custom_rules_dirs: Additional directories for custom rules
        """
        self.rules: dict[str, ThreatRule] = {}
        self.rules_by_language: dict[Language, list[ThreatRule]] = {
            Language.PYTHON: [],
            Language.JAVASCRIPT: [],
            Language.TYPESCRIPT: [],
            Language.HTML: [],
            Language.CSS: [],
            Language.JSON: [],
            Language.YAML: [],
            Language.XML: [],
            Language.PHP: [],
            Language.SHELL: [],
            Language.DOCKERFILE: [],
            Language.GO: [],
            Language.RUBY: [],
            Language.JAVA: [],
            Language.CSHARP: [],
            Language.SQL: [],
            Language.TERRAFORM: [],
            Language.GENERIC: [],
        }
        self.loaded_rule_files: set[Path] = set()
        # Track which file each rule was loaded from
        self.rule_source_files: dict[str, Path] = {}

        # Initialize user rules directory if it doesn't exist
        initialize_user_rules_directory()

        # Default to user's rules directory if none provided
        if rules_dir is None:
            rules_dir = get_user_rules_directory()

        # Load rules in order of priority: built-in -> organization -> custom -> provided
        self._load_builtin_rules()

        # Load from user rule directories by default
        user_rules_dir = get_user_rules_directory()

        # Load organization rules (medium priority)
        organization_rules_dir = user_rules_dir / "organization"
        if organization_rules_dir.exists():
            self.load_rules_from_directory(organization_rules_dir)

        # Load custom rules (high priority)
        custom_rules_dir = user_rules_dir / "custom"
        if custom_rules_dir.exists():
            self.load_rules_from_directory(custom_rules_dir)

        # Load from additional custom directories
        if custom_rules_dirs:
            for custom_dir in custom_rules_dirs:
                if custom_dir.exists():
                    self.load_rules_from_directory(custom_dir)

        # Load from provided rules directory (if different from user config)
        if rules_dir and rules_dir != get_user_rules_directory():
            self.load_rules_from_directory(rules_dir)

    def load_rules_from_directory(self, rules_dir: Path) -> None:
        """Load threat rules from YAML files in a directory.

        Args:
            rules_dir: Directory containing YAML rule files
        """
        if not rules_dir.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

        for rule_file in rules_dir.glob("*.yaml"):
            self.load_rules_from_file(rule_file)

        for rule_file in rules_dir.glob("*.yml"):
            self.load_rules_from_file(rule_file)

    def load_rules_from_file(self, rule_file: Path) -> None:
        """Load threat rules from a YAML file.

        Args:
            rule_file: Path to YAML file containing rules
        """
        try:
            with open(rule_file) as f:
                data = yaml.safe_load(f)

            if "rules" not in data:
                raise ValueError(f"No 'rules' section found in {rule_file}")

            rules_loaded = 0
            for rule_data in data["rules"]:
                rule = ThreatRule(**rule_data)
                self.add_rule(rule, source_file=rule_file)
                rules_loaded += 1

            self.loaded_rule_files.add(rule_file)

        except Exception as e:
            raise ValueError(f"Failed to load rules from {rule_file}: {e}")

    def add_rule(self, rule: ThreatRule, source_file: Path | None = None) -> None:
        """Add a threat rule to the engine.

        Args:
            rule: The threat rule to add
            source_file: Path to the file this rule was loaded from (optional)
        """
        self.rules[rule.id] = rule

        # Track source file
        if source_file:
            self.rule_source_files[rule.id] = source_file

        # Index by language
        for language in rule.languages:
            if language not in self.rules_by_language:
                self.rules_by_language[language] = []
            self.rules_by_language[language].append(rule)

    def get_rules_for_language(self, language: Language) -> list[ThreatRule]:
        """Get all rules that apply to a specific language.

        Args:
            language: Programming language

        Returns:
            List of applicable threat rules
        """
        return self.rules_by_language.get(language, [])

    def get_rule_by_id(self, rule_id: str) -> ThreatRule | None:
        """Get a rule by its ID.

        Args:
            rule_id: Rule identifier

        Returns:
            The rule if found, None otherwise
        """
        return self.rules.get(rule_id)

    def get_rule_details(self, rule_id: str) -> dict[str, Any] | None:
        """Get detailed information about a rule.

        Args:
            rule_id: Rule identifier

        Returns:
            Dictionary with rule details if found, None otherwise
        """
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return None

        return {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "category": rule.category.value,
            "severity": rule.severity.value,
            "languages": [lang.value for lang in rule.languages],
            "conditions": [{"type": c.type, "value": c.value} for c in rule.conditions],
            "exploit_templates": [
                {
                    "type": t.type,
                    "template": t.template,
                    "description": t.description,
                    "parameters": t.parameters,
                }
                for t in rule.exploit_templates
            ],
            "remediation": rule.remediation,
            "references": rule.references,
            "cwe_id": rule.cwe_id,
            "owasp_category": rule.owasp_category,
            "tags": rule.tags,
        }

    def get_rules_by_category(self, category: Category) -> list[ThreatRule]:
        """Get all rules in a specific category.

        Args:
            category: Security category

        Returns:
            List of rules in the category
        """
        return [rule for rule in self.rules.values() if rule.category == category]

    def get_rules_by_severity(self, min_severity: Severity) -> list[ThreatRule]:
        """Get all rules with severity >= min_severity.

        Args:
            min_severity: Minimum severity level

        Returns:
            List of rules meeting the severity threshold
        """
        severity_order = [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        min_index = severity_order.index(min_severity)

        return [
            rule
            for rule in self.rules.values()
            if severity_order.index(rule.severity) >= min_index
        ]

    def _load_builtin_rules(self) -> None:
        """Load built-in rules from YAML files, fallback to hardcoded if not found."""
        builtin_rules_dir = get_builtin_rules_directory()

        rules_loaded = False
        if builtin_rules_dir.exists():
            try:
                # Try to load from YAML files first
                for rule_file in builtin_rules_dir.glob("*.yaml"):
                    self.load_rules_from_file(rule_file)
                    rules_loaded = True

                for rule_file in builtin_rules_dir.glob("*.yml"):
                    self.load_rules_from_file(rule_file)
                    rules_loaded = True

            except Exception as e:
                logger.warning(f"Failed to load built-in rules from YAML: {e}")
                logger.info("Falling back to hardcoded rules...")
                rules_loaded = False

        # Fallback to hardcoded rules if YAML loading failed or no files found
        if not rules_loaded:
            self._load_default_rules()

    def _load_default_rules(self) -> None:
        """Load default security rules."""
        # Python rules
        python_rules = [
            ThreatRule(
                id="python_sql_injection",
                name="SQL Injection",
                description="Direct string concatenation in SQL queries",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                languages=[Language.PYTHON],
                conditions=[
                    MatchCondition(
                        type="pattern", value="cursor\\.execute\\(.*\\+.*\\)"
                    ),
                    MatchCondition(type="pattern", value="cursor\\.execute\\(.*%.*\\)"),
                    MatchCondition(type="pattern", value=".*=.*['\"].*\\+.*['\"].*"),
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="payload",
                        template="' OR '1'='1' --",
                        description="Basic SQL injection payload",
                    )
                ],
                remediation="Use parameterized queries or prepared statements",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
            ),
            ThreatRule(
                id="python_command_injection",
                name="Command Injection",
                description="User input passed to shell commands",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                languages=[Language.PYTHON],
                conditions=[
                    MatchCondition(
                        type="function_call",
                        value=[
                            "os.system",
                            "subprocess.call",
                            "subprocess.run",
                            "os.popen",
                        ],
                    )
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="payload",
                        template="; cat /etc/passwd",
                        description="Command injection to read sensitive files",
                    )
                ],
                remediation="Use subprocess with shell=False and validate input",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                cwe_id="CWE-78",
            ),
            ThreatRule(
                id="python_pickle_deserialize",
                name="Unsafe Pickle Deserialization",
                description="Pickle deserialization of untrusted data",
                category=Category.DESERIALIZATION,
                severity=Severity.CRITICAL,
                languages=[Language.PYTHON],
                conditions=[
                    MatchCondition(
                        type="function_call",
                        value=[
                            "pickle.loads",
                            "pickle.load",
                            "cPickle.loads",
                            "cPickle.load",
                        ],
                    )
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="python",
                        template="import pickle; pickle.loads(b'cos\\nsystem\\n(S\\'whoami\\'\\ntR.')",
                        description="Pickle payload for command execution",
                    )
                ],
                remediation="Use safe serialization formats like JSON",
                references=[
                    "https://docs.python.org/3/library/pickle.html#restriction"
                ],
                cwe_id="CWE-502",
            ),
        ]

        # JavaScript/TypeScript rules
        js_rules = [
            ThreatRule(
                id="js_xss_dom",
                name="DOM-based XSS",
                description="User input inserted directly into DOM without sanitization",
                category=Category.XSS,
                severity=Severity.HIGH,
                languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
                conditions=[
                    MatchCondition(type="pattern", value="innerHTML\\s*=.*"),
                    MatchCondition(type="pattern", value="outerHTML\\s*=.*"),
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="payload",
                        template="<script>alert('XSS')</script>",
                        description="Basic XSS payload",
                    )
                ],
                remediation="Use textContent or proper sanitization libraries",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                cwe_id="CWE-79",
            ),
            ThreatRule(
                id="js_eval_injection",
                name="Code Injection via eval()",
                description="User input passed to eval() function",
                category=Category.INJECTION,
                severity=Severity.CRITICAL,
                languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
                conditions=[
                    MatchCondition(
                        type="function_call",
                        value=["eval", "Function", "setTimeout", "setInterval"],
                    )
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="javascript",
                        template="eval('alert(\"Injected code\")')",
                        description="Code injection via eval",
                    )
                ],
                remediation="Never use eval() with user input. Use JSON.parse() for data",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval"
                ],
                cwe_id="CWE-94",
            ),
        ]

        # Add all default rules (mark as built-in/hardcoded)
        for rule in python_rules + js_rules:
            # Use a special path to indicate these are hardcoded rules
            self.add_rule(rule, source_file=Path("<built-in>"))

    def validate_rule(self, rule: ThreatRule) -> list[str]:
        """Validate a threat rule for correctness.

        Args:
            rule: The rule to validate

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        if not rule.id:
            errors.append("Rule ID is required")
        if not rule.name:
            errors.append("Rule name is required")
        if not rule.description:
            errors.append("Rule description is required")
        if not rule.conditions:
            errors.append("At least one condition is required")

        # Check condition validity
        for i, condition in enumerate(rule.conditions):
            if condition.type == "regex":
                try:
                    re.compile(condition.value)
                except re.error as e:
                    errors.append(f"Invalid regex in condition {i}: {e}")

        return errors

    def export_rules_to_yaml(self, output_file: Path) -> None:
        """Export all rules to a YAML file.

        Args:
            output_file: Path to output YAML file
        """
        rules_data = {
            "rules": [rule.model_dump(mode="json") for rule in self.rules.values()]
        }

        with open(output_file, "w") as f:
            yaml.dump(rules_data, f, default_flow_style=False, sort_keys=False)

    def list_rules(
        self,
        category: str | None = None,
        min_severity: Severity | None = None,
        language: Language | None = None,
    ) -> list[dict[str, Any]]:
        """List all loaded rules with basic information, optionally filtered.

        Args:
            category: Filter by category (optional)
            min_severity: Filter by minimum severity (optional)
            language: Filter by language (optional)

        Returns:
            List of rule summaries
        """
        filtered_rules = list(self.rules.values())

        # Apply category filter
        if category:
            filtered_rules = [
                rule for rule in filtered_rules if rule.category.value == category
            ]

        # Apply severity filter
        if min_severity:
            severity_order = [
                Severity.LOW,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            ]
            min_index = severity_order.index(min_severity)
            filtered_rules = [
                rule
                for rule in filtered_rules
                if severity_order.index(rule.severity) >= min_index
            ]

        # Apply language filter
        if language:
            filtered_rules = [
                rule for rule in filtered_rules if language in rule.languages
            ]

        return [
            {
                "id": rule.id,
                "name": rule.name,
                "category": rule.category.value,
                "severity": rule.severity.value,
                "languages": [lang.value for lang in rule.languages],
                "description": (
                    rule.description[:100] + "..."
                    if len(rule.description) > 100
                    else rule.description
                ),
                "source_file": str(self.rule_source_files.get(rule.id, "Unknown")),
            }
            for rule in filtered_rules
        ]

    def reload_rules(self) -> None:
        """Reload all rules from their source files."""
        # Clear existing rules
        self.rules.clear()
        for lang_rules in self.rules_by_language.values():
            lang_rules.clear()
        self.rule_source_files.clear()

        # Reload from files
        files_to_reload = list(self.loaded_rule_files)
        self.loaded_rule_files.clear()

        # Re-load built-in rules first
        self._load_builtin_rules()

        # Then reload any additional files
        for rule_file in files_to_reload:
            if rule_file.exists():
                try:
                    self.load_rules_from_file(rule_file)
                except Exception as e:
                    logger.warning(f"Failed to reload {rule_file}: {e}")

    def import_rules_from_file(
        self, import_file: Path, target_dir: Path | None = None
    ) -> None:
        """Import rules from an external file.

        Args:
            import_file: File to import rules from
            target_dir: Directory to copy the file to (optional)
        """
        if not import_file.exists():
            raise FileNotFoundError(f"Import file not found: {import_file}")

        # Validate the file first
        temp_engine = ThreatEngine()
        temp_engine.load_rules_from_file(import_file)

        # If target directory specified, copy the file
        if target_dir:
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / import_file.name

            shutil.copy2(import_file, target_file)

            # Load from the new location
            self.load_rules_from_file(target_file)
        else:
            # Load directly from source
            self.load_rules_from_file(import_file)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by its ID.

        Args:
            rule_id: Rule identifier to remove

        Returns:
            True if rule was removed, False if not found
        """
        if rule_id not in self.rules:
            return False

        rule = self.rules[rule_id]

        # Remove from main collection
        del self.rules[rule_id]

        # Remove from source file mapping
        if rule_id in self.rule_source_files:
            del self.rule_source_files[rule_id]

        # Remove from language indices
        for language in rule.languages:
            if language in self.rules_by_language:
                self.rules_by_language[language] = [
                    r for r in self.rules_by_language[language] if r.id != rule_id
                ]

        return True

    def get_rule_statistics(self) -> dict[str, Any]:
        """Get statistics about loaded rules.

        Returns:
            Dictionary with rule statistics
        """
        total_rules = len(self.rules)

        # Count by category
        category_counts = {}
        for rule in self.rules.values():
            category = rule.category.value
            category_counts[category] = category_counts.get(category, 0) + 1

        # Count by severity
        severity_counts = {}
        for rule in self.rules.values():
            severity = rule.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Count by language
        language_counts = {}
        for language, rules in self.rules_by_language.items():
            language_counts[language.value] = len(rules)

        return {
            "total_rules": total_rules,
            "categories": category_counts,
            "severities": severity_counts,
            "languages": language_counts,
            "loaded_files": len(self.loaded_rule_files),
            "rule_files": [str(f) for f in self.loaded_rule_files],
        }

    def validate_all_rules(self) -> dict[str, list[str]]:
        """Validate all loaded rules.

        Returns:
            Dictionary mapping rule IDs to validation errors
        """
        validation_results = {}

        for rule_id, rule in self.rules.items():
            errors = self.validate_rule(rule)
            if errors:
                validation_results[rule_id] = errors

        return validation_results

    def find_rules_by_pattern(self, pattern: str) -> list[ThreatRule]:
        """Find rules that match a search pattern.

        Args:
            pattern: Search pattern (regex) to match against rule names and descriptions

        Returns:
            List of matching rules
        """
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return []

        matching_rules = []
        for rule in self.rules.values():
            if (
                regex.search(rule.name)
                or regex.search(rule.description)
                or regex.search(rule.id)
            ):
                matching_rules.append(rule)

        return matching_rules
