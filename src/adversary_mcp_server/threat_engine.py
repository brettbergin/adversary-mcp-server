"""Threat Pattern Engine for security vulnerability detection."""

import os
import re
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import yaml
from pydantic import BaseModel, field_validator


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


class Language(str, Enum):
    """Supported programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"


class MatchCondition(BaseModel):
    """A condition that must be met for a rule to match."""

    type: str  # "ast_node", "pattern", "function_call", "import", "variable"
    value: Union[str, List[str], Dict[str, Any]]
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
    parameters: Dict[str, Any] = field(default_factory=dict)
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
    languages: List[Language]

    # Matching conditions
    conditions: List[MatchCondition]

    # Exploit information
    exploit_templates: List[ExploitTemplate] = field(default_factory=list)

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Metadata
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tags: List[str] = field(default_factory=list)

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

    rule_id: str
    rule_name: str
    description: str
    category: Category
    severity: Severity

    # Location information
    file_path: str
    line_number: int
    column_number: int = 0

    # Code context
    code_snippet: str = ""
    function_name: Optional[str] = None

    # Exploit information
    exploit_examples: List[str] = field(default_factory=list)

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Metadata
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0


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
    package_rules_dir = Path(__file__).parent.parent.parent / "rules"

    # Copy built-in rules from package to user config (if they exist and user doesn't have them)
    if package_rules_dir.exists():
        package_builtin_dir = package_rules_dir / "built-in"
        if package_builtin_dir.exists():
            for rule_file in package_builtin_dir.glob("*.yaml"):
                user_rule_file = builtin_rules_dir / rule_file.name
                if not user_rule_file.exists():
                    shutil.copy2(rule_file, user_rule_file)
                    print(f"Copied built-in rule: {rule_file.name}")

        # Copy templates
        package_templates_dir = package_rules_dir / "templates"
        if package_templates_dir.exists():
            for template_file in package_templates_dir.glob("*.yaml"):
                user_template_file = templates_dir / template_file.name
                if not user_template_file.exists():
                    shutil.copy2(template_file, user_template_file)
                    print(f"Copied rule template: {template_file.name}")


class ThreatEngine:
    """Engine for loading and executing threat detection rules."""

    def __init__(
        self,
        rules_dir: Optional[Path] = None,
        custom_rules_dirs: Optional[List[Path]] = None,
    ):
        """Initialize the threat engine.

        Args:
            rules_dir: Primary directory containing YAML rule files (defaults to user config)
            custom_rules_dirs: Additional directories for custom rules
        """
        self.rules: Dict[str, ThreatRule] = {}
        self.rules_by_language: Dict[Language, List[ThreatRule]] = {
            Language.PYTHON: [],
            Language.JAVASCRIPT: [],
            Language.TYPESCRIPT: [],
        }
        self.loaded_rule_files: Set[Path] = set()
        # Track which file each rule was loaded from
        self.rule_source_files: Dict[str, Path] = {}

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
            with open(rule_file, "r") as f:
                data = yaml.safe_load(f)

            if "rules" not in data:
                raise ValueError(f"No 'rules' section found in {rule_file}")

            rules_loaded = 0
            for rule_data in data["rules"]:
                rule = ThreatRule(**rule_data)
                self.add_rule(rule, source_file=rule_file)
                rules_loaded += 1

            self.loaded_rule_files.add(rule_file)
            print(f"Loaded {rules_loaded} rules from {rule_file}")

        except Exception as e:
            raise ValueError(f"Failed to load rules from {rule_file}: {e}")

    def add_rule(self, rule: ThreatRule, source_file: Optional[Path] = None) -> None:
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

    def get_rules_for_language(self, language: Language) -> List[ThreatRule]:
        """Get all rules that apply to a specific language.

        Args:
            language: Programming language

        Returns:
            List of applicable threat rules
        """
        return self.rules_by_language.get(language, [])

    def get_rule_by_id(self, rule_id: str) -> Optional[ThreatRule]:
        """Get a rule by its ID.

        Args:
            rule_id: Rule identifier

        Returns:
            The rule if found, None otherwise
        """
        return self.rules.get(rule_id)

    def get_rules_by_category(self, category: Category) -> List[ThreatRule]:
        """Get all rules in a specific category.

        Args:
            category: Security category

        Returns:
            List of rules in the category
        """
        return [rule for rule in self.rules.values() if rule.category == category]

    def get_rules_by_severity(self, min_severity: Severity) -> List[ThreatRule]:
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
                print(f"Warning: Failed to load built-in rules from YAML: {e}")
                print("Falling back to hardcoded rules...")
                rules_loaded = False

        # Fallback to hardcoded rules if YAML loading failed or no files found
        if not rules_loaded:
            print("Loading hardcoded built-in rules...")
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

    def validate_rule(self, rule: ThreatRule) -> List[str]:
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

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all loaded rules with basic information.

        Returns:
            List of rule summaries
        """
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
            for rule in self.rules.values()
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
                    print(f"Warning: Failed to reload {rule_file}: {e}")

    def import_rules_from_file(
        self, import_file: Path, target_dir: Optional[Path] = None
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

            import shutil

            shutil.copy2(import_file, target_file)
            print(f"Copied rule file to {target_file}")

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

    def get_rule_statistics(self) -> Dict[str, Any]:
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

    def validate_all_rules(self) -> Dict[str, List[str]]:
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

    def find_rules_by_pattern(self, pattern: str) -> List[ThreatRule]:
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
