"""LLM-based security analyzer for detecting code vulnerabilities using AI."""

import json
from dataclasses import dataclass
from typing import Any

from .credential_manager import CredentialManager
from .logging_config import get_logger
from .threat_engine import Category, Language, Severity, ThreatMatch

logger = get_logger("llm_scanner")


class LLMAnalysisError(Exception):
    """Exception raised when LLM analysis fails."""

    pass


@dataclass
class LLMSecurityFinding:
    """Represents a security finding from LLM analysis."""

    finding_type: str
    severity: str
    description: str
    line_number: int
    code_snippet: str
    explanation: str
    recommendation: str
    confidence: float
    cwe_id: str | None = None
    owasp_category: str | None = None

    def to_threat_match(self, file_path: str) -> ThreatMatch:
        """Convert to ThreatMatch for compatibility with existing code.

        Args:
            file_path: Path to the analyzed file

        Returns:
            ThreatMatch object
        """
        # Map severity string to enum
        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

        # Map finding type to category (simplified mapping)
        category_map = {
            "sql_injection": Category.INJECTION,
            "command_injection": Category.INJECTION,
            "xss": Category.XSS,
            "cross_site_scripting": Category.XSS,
            "deserialization": Category.DESERIALIZATION,
            "path_traversal": Category.PATH_TRAVERSAL,
            "directory_traversal": Category.PATH_TRAVERSAL,
            "lfi": Category.LFI,
            "local_file_inclusion": Category.LFI,
            "hardcoded_credential": Category.SECRETS,
            "hardcoded_credentials": Category.SECRETS,
            "hardcoded_password": Category.SECRETS,
            "hardcoded_secret": Category.SECRETS,
            "weak_crypto": Category.CRYPTOGRAPHY,
            "weak_cryptography": Category.CRYPTOGRAPHY,
            "crypto": Category.CRYPTOGRAPHY,
            "cryptography": Category.CRYPTOGRAPHY,
            "csrf": Category.CSRF,
            "cross_site_request_forgery": Category.CSRF,
            "authentication": Category.AUTHENTICATION,
            "authorization": Category.AUTHORIZATION,
            "access_control": Category.ACCESS_CONTROL,
            "validation": Category.VALIDATION,
            "input_validation": Category.VALIDATION,
            "logging": Category.LOGGING,
            "ssrf": Category.SSRF,
            "server_side_request_forgery": Category.SSRF,
            "idor": Category.IDOR,
            "insecure_direct_object_reference": Category.IDOR,
            "rce": Category.RCE,
            "remote_code_execution": Category.RCE,
            "code_injection": Category.RCE,
            "disclosure": Category.DISCLOSURE,
            "information_disclosure": Category.DISCLOSURE,
            "dos": Category.DOS,
            "denial_of_service": Category.DOS,
            "redirect": Category.REDIRECT,
            "open_redirect": Category.REDIRECT,
            "headers": Category.HEADERS,
            "security_headers": Category.HEADERS,
            "session": Category.SESSION,
            "session_management": Category.SESSION,
            "file_upload": Category.FILE_UPLOAD,
            "upload": Category.FILE_UPLOAD,
            "configuration": Category.CONFIGURATION,
            "config": Category.CONFIGURATION,
            "type_safety": Category.TYPE_SAFETY,
        }

        # Get category, defaulting to MISC if not found
        category = category_map.get(self.finding_type.lower(), Category.MISC)

        severity = severity_map.get(self.severity.lower(), Severity.MEDIUM)

        return ThreatMatch(
            rule_id=f"llm_{self.finding_type}",
            rule_name=self.finding_type.replace("_", " ").title(),
            description=self.description,
            category=category,
            severity=severity,
            file_path=file_path,
            line_number=self.line_number,
            code_snippet=self.code_snippet,
            confidence=self.confidence,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            source="llm",  # LLM scanner
        )


@dataclass
class LLMAnalysisPrompt:
    """Represents a prompt for LLM analysis."""

    system_prompt: str
    user_prompt: str
    file_path: str
    language: Language
    max_findings: int = 20

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "file_path": self.file_path,
            "language": self.language.value,
            "max_findings": self.max_findings,
        }


class LLMScanner:
    """LLM-based security scanner that generates prompts for client LLMs."""

    def __init__(self, credential_manager: CredentialManager):
        """Initialize the LLM security analyzer.

        Args:
            credential_manager: Credential manager for configuration
        """
        self.credential_manager = credential_manager
        self.config = credential_manager.load_config()

    def is_available(self) -> bool:
        """Check if LLM analysis is available.

        Returns:
            True if LLM analysis is available (always true now since we use client LLM)
        """
        return True

    def create_analysis_prompt(
        self,
        source_code: str,
        file_path: str,
        language: Language,
        max_findings: int = 20,
    ) -> LLMAnalysisPrompt:
        """Create analysis prompt for the given code.

        Args:
            source_code: Source code to analyze
            file_path: Path to the source file
            language: Programming language
            max_findings: Maximum number of findings to return

        Returns:
            LLMAnalysisPrompt object
        """
        system_prompt = self._get_system_prompt()
        user_prompt = self._create_user_prompt(source_code, language, max_findings)

        return LLMAnalysisPrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            file_path=file_path,
            language=language,
            max_findings=max_findings,
        )

    def parse_analysis_response(
        self, response_text: str, file_path: str
    ) -> list[LLMSecurityFinding]:
        """Parse the LLM response into security findings.

        Args:
            response_text: Raw response from LLM
            file_path: Path to the analyzed file

        Returns:
            List of LLMSecurityFinding objects
        """
        try:
            # Try to parse as JSON first
            data = json.loads(response_text)

            findings = []
            for finding_data in data.get("findings", []):
                try:
                    # Validate and convert line number
                    line_number = int(finding_data.get("line_number", 1))
                    if line_number < 1:
                        line_number = 1

                    # Validate confidence
                    confidence = float(finding_data.get("confidence", 0.5))
                    if not (0.0 <= confidence <= 1.0):
                        confidence = 0.5

                    finding = LLMSecurityFinding(
                        finding_type=finding_data.get("type", "unknown"),
                        severity=finding_data.get("severity", "medium"),
                        description=finding_data.get("description", ""),
                        line_number=line_number,
                        code_snippet=finding_data.get("code_snippet", ""),
                        explanation=finding_data.get("explanation", ""),
                        recommendation=finding_data.get("recommendation", ""),
                        confidence=confidence,
                        cwe_id=finding_data.get("cwe_id"),
                        owasp_category=finding_data.get("owasp_category"),
                    )
                    findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to parse finding: {e}")
                    continue

            return findings

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            raise LLMAnalysisError(f"Invalid JSON response from LLM: {e}")
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            raise LLMAnalysisError(f"Error parsing LLM response: {e}")

    def _get_system_prompt(self) -> str:
        """Get the system prompt for security analysis.

        Returns:
            System prompt string
        """
        return """You are a senior security engineer performing static code analysis.
Your task is to analyze code for security vulnerabilities and provide detailed, actionable findings.

Guidelines:
1. Focus on real security issues, not code style or minor concerns
2. Provide specific line numbers and code snippets
3. Include detailed explanations of why something is vulnerable
4. Offer concrete remediation advice
5. Assign appropriate severity levels (low, medium, high, critical)
6. Be precise about vulnerability types and CWE mappings
7. Avoid false positives - only report genuine security concerns
8. Consider the full context of the code when making assessments

Response format: JSON object with "findings" array containing security issues.
Each finding should have: type, severity, description, line_number, code_snippet, explanation, recommendation, confidence, cwe_id (optional), owasp_category (optional).

Vulnerability types to look for:
- SQL injection, Command injection, Code injection
- Cross-site scripting (XSS)
- Path traversal, Directory traversal
- Deserialization vulnerabilities
- Hardcoded credentials, API keys
- Weak cryptography, insecure random numbers
- Input validation issues
- Authentication/authorization bypasses
- Session management flaws
- CSRF vulnerabilities
- Information disclosure
- Logic errors with security implications
- Memory safety issues (buffer overflows, etc.)
- Race conditions
- Denial of service vulnerabilities"""

    def _create_user_prompt(
        self, source_code: str, language: Language, max_findings: int
    ) -> str:
        """Create user prompt for the given code.

        Args:
            source_code: Source code to analyze
            language: Programming language
            max_findings: Maximum number of findings

        Returns:
            Formatted prompt string
        """
        # Truncate very long code to fit in token limits
        max_code_length = 8000  # Leave room for prompt and response
        if len(source_code) > max_code_length:
            source_code = (
                source_code[:max_code_length] + "\n... [truncated for analysis]"
            )

        prompt = f"""Analyze the following {language.value} code for security vulnerabilities:

```{language.value}
{source_code}
```

Please provide up to {max_findings} security findings in JSON format.

Requirements:
- Focus on genuine security vulnerabilities
- Provide specific line numbers (1-indexed)
- Include the vulnerable code snippet
- Explain why each finding is a security risk
- Suggest specific remediation steps
- Assign confidence scores (0.0-1.0)
- Map to CWE IDs where applicable
- Classify by OWASP categories where relevant

Response format:
{{
  "findings": [
    {{
      "type": "vulnerability_type",
      "severity": "low|medium|high|critical",
      "description": "brief description",
      "line_number": 42,
      "code_snippet": "vulnerable code",
      "explanation": "detailed explanation",
      "recommendation": "how to fix",
      "confidence": 0.9,
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021"
    }}
  ]
}}"""

        return prompt

    def analyze_code(
        self,
        source_code: str,
        file_path: str,
        language: Language,
        max_findings: int = 20,
    ) -> list[LLMSecurityFinding]:
        """Analyze code for security vulnerabilities.

        For client-based LLM integration, this method returns empty list
        since actual analysis is done by the client's LLM.

        Args:
            source_code: Source code to analyze
            file_path: Path to the source file
            language: Programming language
            max_findings: Maximum number of findings to return

        Returns:
            Empty list (client-based LLM doesn't do analysis here)
        """
        # In client-based approach, we don't perform actual analysis
        # The client gets prompts via create_analysis_prompt() and processes them
        return []

    def batch_analyze_code(
        self,
        code_samples: list[tuple[str, str, Language]],
        max_findings_per_sample: int = 20,
    ) -> list[list[LLMSecurityFinding]]:
        """Analyze multiple code samples.

        Args:
            code_samples: List of (code, file_path, language) tuples
            max_findings_per_sample: Maximum findings per sample

        Returns:
            List of findings lists (one per sample)
        """
        results = []
        for code, file_path, language in code_samples:
            # For client-based approach, return empty results
            results.append([])
        return results

    def get_analysis_stats(self) -> dict[str, Any]:
        """Get analysis statistics.

        Returns:
            Dictionary with analysis stats
        """
        return {
            "total_analyses": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "average_findings_per_analysis": 0.0,
            "supported_languages": ["python", "javascript", "typescript"],
            "client_based": True,
        }
