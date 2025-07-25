"""LLM-based security analyzer for detecting code vulnerabilities using AI."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .credential_manager import CredentialManager
from .logging_config import get_logger
from .types import Category, Language, Severity, ThreatMatch

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
    file_path: str = ""  # Path to the file containing this finding
    cwe_id: str | None = None
    owasp_category: str | None = None

    def to_threat_match(self, file_path: str | None = None) -> ThreatMatch:
        """Convert to ThreatMatch for compatibility with existing code.

        Args:
            file_path: Path to the analyzed file (optional if finding has file_path)

        Returns:
            ThreatMatch object
        """
        # Use provided file_path or fall back to the finding's file_path
        effective_file_path = file_path or self.file_path
        if not effective_file_path:
            raise ValueError(
                "file_path must be provided either as parameter or in finding"
            )
        logger.debug(
            f"Converting LLMSecurityFinding to ThreatMatch: {self.finding_type} ({self.severity})"
        )

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
        if self.finding_type.lower() not in category_map:
            logger.debug(
                f"Unknown finding type '{self.finding_type}', mapping to MISC category"
            )

        severity = severity_map.get(self.severity.lower(), Severity.MEDIUM)
        if self.severity.lower() not in severity_map:
            logger.debug(f"Unknown severity '{self.severity}', mapping to MEDIUM")

        threat_match = ThreatMatch(
            rule_id=f"llm_{self.finding_type}",
            rule_name=self.finding_type.replace("_", " ").title(),
            description=self.description,
            category=category,
            severity=severity,
            file_path=effective_file_path,
            line_number=self.line_number,
            code_snippet=self.code_snippet,
            confidence=self.confidence,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            source="llm",  # LLM scanner
        )

        logger.debug(
            f"Successfully created ThreatMatch: {threat_match.rule_id} at line {threat_match.line_number}"
        )
        return threat_match


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
        file_path_abs = str(Path(self.file_path).resolve())
        logger.debug(f"Converting LLMAnalysisPrompt to dict for {file_path_abs}")
        result = {
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "file_path": self.file_path,
            "language": self.language.value,
            "max_findings": self.max_findings,
        }
        logger.debug(f"LLMAnalysisPrompt dict created with keys: {list(result.keys())}")
        return result


class LLMScanner:
    """LLM-based security scanner that generates prompts for client LLMs."""

    def __init__(self, credential_manager: CredentialManager):
        """Initialize the LLM security analyzer.

        Args:
            credential_manager: Credential manager for configuration
        """
        logger.info("Initializing LLMScanner")
        self.credential_manager = credential_manager
        try:
            self.config = credential_manager.load_config()
            logger.debug(
                f"LLMScanner configuration loaded successfully: {type(self.config)}"
            )
        except Exception as e:
            logger.error(f"Failed to load configuration in LLMScanner: {e}")
            raise

    def is_available(self) -> bool:
        """Check if LLM analysis is available.

        Returns:
            True if LLM analysis is available (always true now since we use client LLM)
        """
        logger.debug(
            "LLMScanner.is_available() called - returning True (client-based LLM)"
        )
        return True

    def get_status(self) -> dict[str, Any]:
        """Get LLM status information (for consistency with semgrep scanner).

        Returns:
            Dict containing LLM status information
        """
        return {
            "available": True,
            "version": "client-based",
            "installation_status": "available",
            "mode": "client-based",
            "description": "Uses client-side LLM for analysis",
        }

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
        file_path_abs = str(Path(file_path).resolve())
        logger.info(f"Creating analysis prompt for {file_path_abs} ({language.value})")
        logger.debug(
            f"Source code length: {len(source_code)} characters, max_findings: {max_findings}"
        )

        try:
            system_prompt = self._get_system_prompt()
            logger.debug(
                f"System prompt created, length: {len(system_prompt)} characters"
            )

            user_prompt = self._create_user_prompt(source_code, language, max_findings)
            logger.debug(f"User prompt created, length: {len(user_prompt)} characters")

            prompt = LLMAnalysisPrompt(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                file_path=file_path,
                language=language,
                max_findings=max_findings,
            )
            logger.info(f"Successfully created analysis prompt for {file_path_abs}")
            return prompt
        except Exception as e:
            logger.error(f"Failed to create analysis prompt for {file_path_abs}: {e}")
            raise

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
        file_path_abs = str(Path(file_path).resolve())
        logger.info(f"Parsing LLM analysis response for {file_path_abs}")
        logger.debug(f"Response text length: {len(response_text)} characters")

        if not response_text or not response_text.strip():
            logger.warning(f"Empty or whitespace-only response for {file_path_abs}")
            return []

        try:
            # Try to parse as JSON first
            logger.debug("Attempting to parse response as JSON")
            data = json.loads(response_text)
            logger.debug(
                f"Successfully parsed JSON, data keys: {list(data.keys()) if isinstance(data, dict) else type(data)}"
            )

            findings = []
            raw_findings = data.get("findings", [])
            logger.info(f"Found {len(raw_findings)} raw findings in response")

            for i, finding_data in enumerate(raw_findings):
                logger.debug(f"Processing finding {i+1}/{len(raw_findings)}")
                try:
                    # Validate and convert line number
                    line_number = int(finding_data.get("line_number", 1))
                    if line_number < 1:
                        logger.debug(f"Invalid line number {line_number}, setting to 1")
                        line_number = 1

                    # Validate confidence
                    confidence = float(finding_data.get("confidence", 0.5))
                    if not (0.0 <= confidence <= 1.0):
                        logger.debug(f"Invalid confidence {confidence}, setting to 0.5")
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
                    logger.debug(
                        f"Successfully created finding: {finding.finding_type} ({finding.severity})"
                    )
                except Exception as e:
                    logger.warning(f"Failed to parse finding {i+1}: {e}")
                    logger.debug(f"Failed finding data: {finding_data}")
                    continue

            logger.info(
                f"Successfully parsed {len(findings)} valid findings from {len(raw_findings)} raw findings"
            )
            return findings

        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to parse LLM response as JSON for {file_path_abs}: {e}"
            )
            logger.debug(
                f"Response text preview (first 500 chars): {response_text[:500]}"
            )
            raise LLMAnalysisError(f"Invalid JSON response from LLM: {e}")
        except Exception as e:
            logger.error(f"Error parsing LLM response for {file_path_abs}: {e}")
            logger.debug(
                f"Response text preview (first 500 chars): {response_text[:500]}"
            )
            raise LLMAnalysisError(f"Error parsing LLM response: {e}")

    def _get_system_prompt(self) -> str:
        """Get the system prompt for security analysis.

        Returns:
            System prompt string
        """
        logger.debug("Generating system prompt for LLM analysis")
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
        logger.debug(
            f"Creating user prompt for {language.value} code, max_findings: {max_findings}"
        )

        # Truncate very long code to fit in token limits
        max_code_length = 8000  # Leave room for prompt and response
        original_length = len(source_code)
        if len(source_code) > max_code_length:
            logger.debug(
                f"Truncating code from {original_length} to {max_code_length} characters"
            )
            source_code = (
                source_code[:max_code_length] + "\n... [truncated for analysis]"
            )
        else:
            logger.debug(
                f"Code length {original_length} is within limit, no truncation needed"
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

        logger.debug(f"Generated user prompt, final length: {len(prompt)} characters")
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
        file_path_abs = str(Path(file_path).resolve())
        logger.info(f"analyze_code called for {file_path_abs} ({language.value})")
        logger.debug(
            "Client-based LLM approach - returning empty list (analysis done by client)"
        )
        # In client-based approach, we don't perform actual analysis
        # The client gets prompts via create_analysis_prompt() and processes them
        return []

    async def analyze_file(
        self,
        file_path,
        language: Language,
        max_findings: int = 20,
    ) -> list[LLMSecurityFinding]:
        """Analyze a single file for security vulnerabilities.

        For client-based LLM integration, this method returns empty list
        since actual analysis is done by the client's LLM.

        Args:
            file_path: Path to the file to analyze
            language: Programming language
            max_findings: Maximum number of findings to return

        Returns:
            Empty list (client-based LLM doesn't do analysis here)
        """
        file_path_abs = str(Path(file_path).resolve())
        logger.info(f"analyze_file called for {file_path_abs} ({language.value})")
        logger.debug(
            "Client-based LLM approach - returning empty list (analysis done by client)"
        )
        # In client-based approach, we don't perform actual analysis
        # The client gets prompts via create_analysis_prompt() and processes them
        return []

    async def analyze_directory(
        self,
        directory_path,
        recursive: bool = True,
        max_files: int | None = None,
        max_findings_per_file: int = 20,
    ) -> list[LLMSecurityFinding]:
        """Analyze an entire directory for security vulnerabilities.

        For client-based LLM integration, this method returns empty list
        since actual analysis is done by the client's LLM.

        Args:
            directory_path: Path to the directory to analyze
            recursive: Whether to scan subdirectories
            max_files: Maximum number of files to analyze
            max_findings_per_file: Maximum number of findings per file

        Returns:
            Empty list (client-based LLM doesn't do analysis here)
        """
        logger.info(
            f"analyze_directory called for {directory_path} (recursive={recursive})"
        )
        logger.debug(
            "Client-based LLM approach - returning empty list (analysis done by client)"
        )
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
        logger.info(f"batch_analyze_code called with {len(code_samples)} samples")
        logger.debug(
            "Client-based LLM approach - returning empty results for all samples"
        )

        results = []
        for i, (code, file_path, language) in enumerate(code_samples):
            logger.debug(
                f"Processing sample {i+1}/{len(code_samples)}: {file_path} ({language.value})"
            )
            # For client-based approach, return empty results
            results.append([])

        logger.info(f"Completed batch analysis for {len(code_samples)} samples")
        return results

    def get_analysis_stats(self) -> dict[str, Any]:
        """Get analysis statistics.

        Returns:
            Dictionary with analysis stats
        """
        logger.debug("get_analysis_stats called")
        stats = {
            "total_analyses": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "average_findings_per_analysis": 0.0,
            "supported_languages": ["python", "javascript", "typescript"],
            "client_based": True,
        }
        logger.debug(f"Returning stats: {stats}")
        return stats
