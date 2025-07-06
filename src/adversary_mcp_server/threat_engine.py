"""Threat Pattern Engine for security vulnerability detection."""

import re
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
    
    @field_validator('type')
    @classmethod
    def validate_type(cls, v):
        valid_types = ["ast_node", "pattern", "function_call", "import", "variable", "regex"]
        if v not in valid_types:
            raise ValueError(f"Invalid condition type: {v}")
        return v


class ExploitTemplate(BaseModel):
    """Template for generating exploit examples."""
    type: str  # "curl", "python", "javascript", "shell"
    template: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    
    @field_validator('type')
    @classmethod
    def validate_type(cls, v):
        valid_types = ["curl", "python", "javascript", "shell", "payload"]
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
    
    @field_validator('id')
    @classmethod
    def validate_id(cls, v):
        if not re.match(r'^[a-z0-9_-]+$', v):
            raise ValueError("Rule ID must contain only lowercase letters, numbers, underscores, and hyphens")
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


class ThreatEngine:
    """Engine for loading and executing threat detection rules."""
    
    def __init__(self, rules_dir: Optional[Path] = None):
        """Initialize the threat engine.
        
        Args:
            rules_dir: Directory containing YAML rule files
        """
        self.rules: Dict[str, ThreatRule] = {}
        self.rules_by_language: Dict[Language, List[ThreatRule]] = {
            Language.PYTHON: [],
            Language.JAVASCRIPT: [],
            Language.TYPESCRIPT: []
        }
        
        if rules_dir:
            self.load_rules_from_directory(rules_dir)
        else:
            self._load_default_rules()
    
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
            with open(rule_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if 'rules' not in data:
                raise ValueError(f"No 'rules' section found in {rule_file}")
            
            for rule_data in data['rules']:
                rule = ThreatRule(**rule_data)
                self.add_rule(rule)
                
        except Exception as e:
            raise ValueError(f"Failed to load rules from {rule_file}: {e}")
    
    def add_rule(self, rule: ThreatRule) -> None:
        """Add a threat rule to the engine.
        
        Args:
            rule: The threat rule to add
        """
        self.rules[rule.id] = rule
        
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
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_index = severity_order.index(min_severity)
        
        return [
            rule for rule in self.rules.values()
            if severity_order.index(rule.severity) >= min_index
        ]
    
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
                        type="pattern",
                        value="cursor\\.execute\\(.*\\+.*\\)"
                    ),
                    MatchCondition(
                        type="pattern", 
                        value="cursor\\.execute\\(.*%.*\\)"
                    ),
                    MatchCondition(
                        type="pattern",
                        value=".*=.*['\"].*\\+.*['\"].*"
                    )
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="payload",
                        template="' OR '1'='1' --",
                        description="Basic SQL injection payload"
                    )
                ],
                remediation="Use parameterized queries or prepared statements",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection"
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
                        value=["os.system", "subprocess.call", "subprocess.run", "os.popen"]
                    )
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="payload",
                        template="; cat /etc/passwd",
                        description="Command injection to read sensitive files"
                    )
                ],
                remediation="Use subprocess with shell=False and validate input",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                cwe_id="CWE-78"
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
                        value=["pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"]
                    )
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="python",
                        template="import pickle; pickle.loads(b'cos\\nsystem\\n(S\\'whoami\\'\\ntR.')",
                        description="Pickle payload for command execution"
                    )
                ],
                remediation="Use safe serialization formats like JSON",
                references=["https://docs.python.org/3/library/pickle.html#restriction"],
                cwe_id="CWE-502"
            )
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
                    MatchCondition(
                        type="pattern",
                        value="innerHTML\\s*=.*"
                    ),
                    MatchCondition(
                        type="pattern",
                        value="outerHTML\\s*=.*"
                    )
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="payload",
                        template="<script>alert('XSS')</script>",
                        description="Basic XSS payload"
                    )
                ],
                remediation="Use textContent or proper sanitization libraries",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                cwe_id="CWE-79"
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
                        value=["eval", "Function", "setTimeout", "setInterval"]
                    )
                ],
                exploit_templates=[
                    ExploitTemplate(
                        type="javascript",
                        template="eval('alert(\"Injected code\")')",
                        description="Code injection via eval"
                    )
                ],
                remediation="Never use eval() with user input. Use JSON.parse() for data",
                references=["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval"],
                cwe_id="CWE-94"
            )
        ]
        
        # Add all default rules
        for rule in python_rules + js_rules:
            self.add_rule(rule)
    
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
            "rules": [rule.dict() for rule in self.rules.values()]
        }
        
        with open(output_file, 'w') as f:
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
                "description": rule.description[:100] + "..." if len(rule.description) > 100 else rule.description
            }
            for rule in self.rules.values()
        ] 