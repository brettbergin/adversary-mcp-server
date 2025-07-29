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

    def get_fingerprint(self) -> str:
        """Generate a unique fingerprint for this finding.

        Used to identify the same logical finding across multiple scans
        to preserve UUIDs and false positive markings.

        Returns:
            Unique fingerprint string based on rule_id, file_path, and line_number
        """

        # Normalize file path to handle relative vs absolute paths
        normalized_path = str(Path(self.file_path).resolve())
        return f"{self.rule_id}:{normalized_path}:{self.line_number}"
