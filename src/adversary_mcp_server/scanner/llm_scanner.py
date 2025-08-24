"""LLM-based security analyzer for detecting code vulnerabilities using AI."""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import get_version
from ..batch import (
    BatchConfig,
    BatchProcessor,
    BatchStrategy,
    FileAnalysisContext,
    Language,
)
from ..cache import CacheKey, CacheManager, CacheType
from ..config import get_app_cache_dir
from ..config_manager import get_config_manager
from ..credentials import CredentialManager
from ..llm import LLMClient, LLMProvider, create_llm_client
from ..logger import get_logger
from ..resilience import ErrorHandler, ResilienceConfig
from ..session import LLMSessionManager
from .language_mapping import ANALYZABLE_SOURCE_EXTENSIONS, LanguageMapper
from .types import Category, Severity, ThreatMatch

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
    max_findings: int | None = field(
        default_factory=lambda: get_config_manager().dynamic_limits.llm_max_findings
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        file_path_abs = str(Path(self.file_path).resolve())
        logger.debug(f"Converting LLMAnalysisPrompt to dict for {file_path_abs}")
        result = {
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "file_path": self.file_path,
            "max_findings": self.max_findings,
        }
        logger.debug(f"LLMAnalysisPrompt dict created with keys: {list(result.keys())}")
        return result


class LLMScanner:
    """LLM-based security scanner that uses AI for vulnerability detection.

    This scanner supports both legacy analysis methods and new session-aware analysis.
    Session-aware analysis provides better context and cross-file vulnerability detection.
    """

    def __init__(
        self,
        credential_manager: CredentialManager,
        cache_manager: CacheManager | None = None,
        metrics_collector=None,
        enable_sessions: bool = True,
        max_context_tokens: int = 50000,
        session_timeout_seconds: int = 3600,
    ):
        """Initialize the LLM security analyzer.

        Args:
            credential_manager: Credential manager for configuration
            cache_manager: Optional cache manager for intelligent caching
            metrics_collector: Optional metrics collector for performance tracking
        """
        logger.info("Initializing LLMScanner")
        self.credential_manager = credential_manager
        self.llm_client: LLMClient | None = None
        self.cache_manager = cache_manager
        self.metrics_collector = metrics_collector
        self.config_manager = get_config_manager()
        self.dynamic_limits = self.config_manager.dynamic_limits

        # Session-aware analysis capabilities
        self.enable_sessions = enable_sessions
        self.max_context_tokens = max_context_tokens
        self.session_timeout_seconds = session_timeout_seconds
        self.session_manager: LLMSessionManager | None = None

        try:
            self.config = credential_manager.load_config()
            logger.debug(
                f"LLMScanner configuration loaded successfully: {type(self.config)}"
            )

            # Initialize cache manager if not provided
            if cache_manager is None and self.config.enable_caching:
                cache_dir = get_app_cache_dir()
                self.cache_manager = CacheManager(
                    cache_dir=cache_dir,
                    max_size_mb=self.config.cache_max_size_mb,
                    max_age_hours=self.config.cache_max_age_hours,
                )
                logger.info(f"Initialized cache manager at {cache_dir}")

            # Initialize intelligent batch processor with dynamic configuration
            # Provider-specific scaling with resource-aware limits
            base_batch_size = self.config_manager.dynamic_limits.llm_max_batch_size
            target_tokens = self.config_manager.dynamic_limits.llm_target_tokens
            max_tokens = self.config_manager.dynamic_limits.llm_max_tokens

            if self.config.llm_provider == "anthropic":
                # Scale down for Anthropic rate limiting
                max_batch_size = max(1, base_batch_size // 2)
                target_tokens = int(target_tokens * 0.5)
                max_tokens = int(max_tokens * 0.6)
            elif self.config.llm_provider == "openai":
                # Use standard limits for OpenAI
                max_batch_size = base_batch_size
            else:
                # Use configuration batch size for other providers
                max_batch_size = getattr(self.config, "llm_batch_size", base_batch_size)

            batch_config = BatchConfig(
                strategy=BatchStrategy.ADAPTIVE_TOKEN_OPTIMIZED,  # Use new optimized strategy
                min_batch_size=1,
                max_batch_size=max_batch_size,
                target_tokens_per_batch=target_tokens,
                max_tokens_per_batch=max_tokens,
                batch_timeout_seconds=self.config_manager.dynamic_limits.batch_timeout_seconds,
                max_concurrent_batches=self.config_manager.dynamic_limits.max_concurrent_batches,
                group_by_language=True,
                group_by_complexity=True,
            )
            self.batch_processor = BatchProcessor(
                batch_config, self.metrics_collector, self.cache_manager
            )
            logger.info(
                f"Initialized BatchProcessor for {self.config.llm_provider or 'unknown'} provider - "
                f"max_batch_size: {max_batch_size}, target_tokens: {target_tokens}"
            )

            # Initialize ErrorHandler for comprehensive resilience
            # Disable retry for Anthropic provider as it has built-in retry logic
            enable_retry = self.config.llm_provider != "anthropic"
            resilience_config = ResilienceConfig(
                enable_circuit_breaker=True,
                failure_threshold=self.config_manager.dynamic_limits.circuit_breaker_failure_threshold,
                recovery_timeout_seconds=self.config_manager.dynamic_limits.circuit_breaker_recovery_timeout,
                enable_retry=enable_retry,
                max_retry_attempts=(
                    self.config_manager.dynamic_limits.max_retry_attempts
                    if enable_retry
                    else 0
                ),
                base_delay_seconds=self.config_manager.dynamic_limits.retry_base_delay,
                max_delay_seconds=self.config_manager.dynamic_limits.retry_max_delay,
                enable_graceful_degradation=True,
                llm_timeout_seconds=float(
                    self.config_manager.dynamic_limits.llm_request_timeout_seconds
                ),
            )
            self.error_handler = ErrorHandler(resilience_config)
            logger.info("Initialized ErrorHandler with circuit breaker and retry logic")

            # Initialize LLM client if configured
            if self.config.llm_provider and self.config.llm_api_key:
                logger.info(
                    f"Initializing LLM client for provider: {self.config.llm_provider}"
                )
                self.llm_client = create_llm_client(
                    provider=LLMProvider(self.config.llm_provider),
                    api_key=self.config.llm_api_key,
                    model=self.config.llm_model,
                    metrics_collector=self.metrics_collector,
                )
                logger.info("LLM client initialized successfully")

                # Initialize session manager if sessions are enabled
                if self.enable_sessions:
                    try:
                        self.session_manager = LLMSessionManager(
                            llm_client=self.llm_client,
                            max_context_tokens=self.max_context_tokens,
                            session_timeout_seconds=self.session_timeout_seconds,
                            cache_manager=self.cache_manager,  # Share cache manager with session manager
                        )
                        logger.info(
                            "Session-aware analysis enabled with shared caching"
                        )
                    except Exception as e:
                        logger.warning(f"Failed to initialize session manager: {e}")
                        logger.info("Falling back to legacy analysis")
            else:
                logger.warning(
                    "LLM provider not configured - advanced security analysis will be unavailable",
                    extra={
                        "llm_provider": getattr(self.config, "llm_provider", None),
                        "has_api_key": bool(getattr(self.config, "llm_api_key", None)),
                        "security_impact": "high",
                        "component": "llm_scanner",
                        "action": "falling_back_to_static_analysis",
                    },
                )

        except (ValueError, TypeError, ImportError, RuntimeError) as e:
            logger.error(
                "Failed to initialize LLMScanner - security analysis will be unavailable",
                extra={
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "llm_provider": getattr(self.config, "llm_provider", "unknown"),
                    "llm_model": getattr(self.config, "llm_model", "unknown"),
                    "has_api_key": bool(getattr(self.config, "llm_api_key", None)),
                    "security_impact": "critical",
                    "component": "llm_scanner",
                },
            )
            raise

    def get_circuit_breaker_stats(self) -> dict:
        """Get circuit breaker statistics for debugging."""
        return self.error_handler.get_circuit_breaker_stats()

    def is_session_aware_available(self) -> bool:
        """Check if session-aware analysis is available."""
        return self.session_manager is not None

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions and return count of cleaned sessions."""
        if self.session_manager:
            return self.session_manager.cleanup_expired_sessions()
        return 0

    def is_available(self) -> bool:
        """Check if LLM analysis is available.

        Returns:
            True if LLM analysis is available
        """
        available = (
            self.llm_client is not None and self.config.is_llm_analysis_available()
        )
        logger.debug(f"LLMScanner.is_available() called - returning {available}")
        return available

    def get_status(self) -> dict[str, Any]:
        """Get LLM status information (for consistency with semgrep scanner).

        Returns:
            Dict containing LLM status information
        """
        return {
            "available": self.is_available(),
            "version": get_version(),
            "installation_status": self.is_available(),
            "mode": f"{self.config.llm_provider or 'none'}",
            "description": f"Uses {self.config.llm_provider or 'no'} LLM for analysis",
            "model": self.config.llm_model if self.config.llm_provider else None,
        }

    def create_analysis_prompt(
        self,
        source_code: str,
        file_path: str,
        language: str,
        max_findings: int | None = None,
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
        logger.info(f"Creating analysis prompt for {file_path_abs} ({language})")
        logger.debug(
            f"Source code length: {len(source_code)} characters, max_findings: {max_findings}"
        )

        try:
            system_prompt = self._get_system_prompt()
            logger.debug(
                f"System prompt created, length: {len(system_prompt)} characters"
            )

            user_prompt = self._create_user_prompt(
                source_code, language, max_findings or 50
            )
            logger.debug(f"User prompt created, length: {len(user_prompt)} characters")

            prompt = LLMAnalysisPrompt(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                file_path=file_path,
                max_findings=max_findings,
            )
            logger.info(f"Successfully created analysis prompt for {file_path_abs}")
            return prompt
        except Exception as e:
            logger.error(f"Failed to create analysis prompt for {file_path_abs}: {e}")
            raise

    def _strip_markdown_code_blocks(self, response_text: str) -> str:
        """Strip markdown code blocks from JSON responses.

        LLMs often wrap JSON responses in ```json ... ``` blocks,
        but our parser expects raw JSON.

        Args:
            response_text: Raw response that may contain markdown

        Returns:
            Clean JSON string
        """
        # Remove common markdown code block patterns
        response_text = response_text.strip()

        # Handle ```json ... ``` pattern
        if response_text.startswith("```json"):
            response_text = response_text[7:]  # Remove ```json
        elif response_text.startswith("```"):
            response_text = response_text[3:]  # Remove ```

        # Remove trailing ```
        if response_text.endswith("```"):
            response_text = response_text[:-3]

        return response_text.strip()

    def _sanitize_json_string(self, json_str: str) -> str:
        """Sanitize JSON string to fix common escape sequence issues.

        Args:
            json_str: Raw JSON string that may contain invalid escape sequences

        Returns:
            Sanitized JSON string
        """
        import re

        # Fix common invalid escape sequences in string values
        # This regex finds string values and fixes invalid escapes within them
        def fix_string_escapes(match):
            string_content = match.group(1)
            # Fix invalid escape sequences while preserving valid ones
            string_content = re.sub(
                r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', r"\\\\", string_content
            )
            return f'"{string_content}"'

        # Apply the fix to all string values in the JSON
        sanitized = re.sub(r'"([^"\\]*(\\.[^"\\]*)*)"', fix_string_escapes, json_str)
        return sanitized

    def _robust_json_parse(self, json_str: str) -> dict:
        """Parse JSON with error recovery for malformed content.

        Args:
            json_str: JSON string to parse

        Returns:
            Parsed JSON data

        Raises:
            ValueError: If JSON cannot be parsed after recovery attempts
        """
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.warning(f"Initial JSON parse failed: {e}")

            # Try to fix common JSON issues
            recovery_attempts = [
                # Attempt 1: Fix trailing commas
                lambda s: re.sub(r",(\s*[}\]])", r"\1", s),
                # Attempt 2: Fix unescaped quotes in strings
                lambda s: re.sub(r'(?<!\\)"(?=.*".*:)', r'\\"', s),
                # Attempt 3: Fix missing quotes around property names
                lambda s: re.sub(
                    r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1"\2":', s
                ),
                # Attempt 4: Extract first valid JSON object
                lambda s: self._extract_first_json_object(s),
            ]

            for i, fix_func in enumerate(recovery_attempts):
                try:
                    fixed_json = fix_func(json_str)
                    if fixed_json and fixed_json != json_str:
                        result = json.loads(fixed_json)
                        logger.info(f"JSON recovery successful with attempt {i+1}")
                        return result
                except (json.JSONDecodeError, AttributeError):
                    continue

            # If all recovery attempts fail, raise the original error
            logger.error(f"All JSON recovery attempts failed for: {json_str[:200]}...")
            raise e

    def _extract_first_json_object(self, text: str) -> str:
        """Extract the first complete JSON object from text."""
        brace_count = 0
        start_idx = -1

        for i, char in enumerate(text):
            if char == "{":
                if start_idx == -1:
                    start_idx = i
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0 and start_idx != -1:
                    return text[start_idx : i + 1]

        return text  # Return original if no complete object found

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
            # Strip markdown code blocks first
            clean_response = self._strip_markdown_code_blocks(response_text)
            # Sanitize JSON to fix escape sequence issues
            clean_response = self._sanitize_json_string(clean_response)
            logger.debug("Attempting to parse response as JSON")
            data = self._robust_json_parse(clean_response)
            logger.debug(
                f"Successfully parsed JSON, data keys: {list(data.keys()) if isinstance(data, dict) else type(data)}"
            )

            findings: list[LLMSecurityFinding] = []
            raw_findings = data.get("findings", [])

            # Handle case where LLM returns nested vulnerabilities structure
            if raw_findings and len(raw_findings) == 1:
                single_finding = raw_findings[0]
                if "description" in single_finding and isinstance(
                    single_finding["description"], str
                ):
                    # Check if description contains JSON with vulnerabilities
                    desc = single_finding["description"].strip()
                    if desc.startswith("```json") or desc.startswith("{"):
                        try:
                            # Extract and parse nested JSON
                            clean_desc = self._strip_markdown_code_blocks(desc)
                            nested_data = self._robust_json_parse(clean_desc)
                            if "vulnerabilities" in nested_data:
                                logger.info(
                                    f"Found nested vulnerabilities structure with {len(nested_data['vulnerabilities'])} items"
                                )
                                # Convert vulnerabilities to findings format
                                raw_findings = []
                                for vuln in nested_data["vulnerabilities"]:
                                    finding_dict = {
                                        "type": vuln.get(
                                            "title", vuln.get("rule_id", "unknown")
                                        ),
                                        "severity": vuln.get(
                                            "severity", "medium"
                                        ).lower(),
                                        "description": vuln.get("description", ""),
                                        "line_number": vuln.get("line_number", 1),
                                        "code_snippet": vuln.get("code_snippet", ""),
                                        "explanation": vuln.get("description", ""),
                                        "recommendation": vuln.get(
                                            "remediation_advice", ""
                                        ),
                                        "confidence": 0.8,  # Default high confidence
                                        "cwe_id": vuln.get("cwe_id"),
                                        "owasp_category": vuln.get("owasp_category"),
                                    }
                                    raw_findings.append(finding_dict)
                        except Exception as e:
                            logger.warning(
                                f"Failed to parse nested JSON structure: {e}"
                            )

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
        return """You are a senior security engineer performing comprehensive static code analysis.
Your task is to thoroughly analyze code for security vulnerabilities and provide detailed, actionable findings.

Analysis Approach:
1. Be comprehensive - analyze every function, class, and code pattern
2. Look for both obvious and subtle security issues
3. Consider attack scenarios and exploit potential
4. Examine data flow and trust boundaries
5. Check for proper input validation and sanitization
6. Review error handling and information disclosure
7. Assess cryptographic implementations and key management
8. Evaluate authentication and authorization mechanisms

Guidelines:
1. Report EVERY security issue you find, no matter how minor
2. Each distinct vulnerability should be a separate finding - DO NOT combine or summarize similar issues
3. Provide specific line numbers and vulnerable code snippets
4. Include detailed explanations of exploitability
5. Offer concrete remediation steps
6. Assign appropriate severity levels (low, medium, high, critical)
7. Map to CWE IDs and OWASP categories when applicable
8. Be thorough - it's better to report a potential issue than miss a real vulnerability
9. Consider the full context and data flow when making assessments
10. Aim for comprehensive coverage - find 5-15 distinct vulnerabilities in vulnerable code

Response format: JSON object with "findings" array containing security issues.
Each finding should have: type, severity, description, file_path,line_number, code_snippet, explanation, recommendation, confidence, cwe_id (optional), owasp_category (optional).

CRITICAL: Always include a "file_path" field in each finding to specify exactly which file contains the vulnerability. This is required for proper tracking and deduplication.

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
        self, source_code: str, language: str, max_findings: int
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
            f"Creating user prompt for {language} code, max_findings: {max_findings}"
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

        prompt = f"""Perform a comprehensive security analysis of the following {language} code:

```{language}
{source_code}
```

Please provide ALL security findings you discover in JSON format. Be thorough and comprehensive in your analysis.

Security Analysis Requirements:
- Examine EVERY function, method, and code block for potential security issues
- Look for both obvious vulnerabilities and subtle security concerns
- Consider data flow, input validation, output encoding, and error handling
- Analyze authentication, authorization, and session management
- Check for injection vulnerabilities (SQL, command, code, XSS, etc.)
- Review cryptographic implementations and key management
- Assess file operations, network calls, and external system interactions
- Evaluate business logic for potential security bypasses
- Consider information disclosure through error messages or logs
- Check for race conditions, memory safety issues, and DoS vectors

Technical Requirements:
- Provide specific line numbers (1-indexed, exactly as they appear in the source code)
- Include the vulnerable code snippet for each finding
- Explain the security risk and potential exploitation
- Suggest specific remediation steps
- Assign confidence scores (0.0-1.0) based on certainty
- Map to CWE IDs where applicable
- Classify by OWASP categories where relevant
- IMPORTANT: Line numbers must match the exact line numbers in the provided source code (1-indexed)

Response format:
{{
  "findings": [
    {{
      "file_path": "path/to/file.ext",
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
}}

CRITICAL: Each finding MUST include the "file_path" field with the exact file path being analyzed."""

        logger.debug(f"Generated user prompt, final length: {len(prompt)} characters")
        return prompt

    def analyze_code(
        self,
        source_code: str,
        file_path: str,
        language: str,
        max_findings: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Analyze code for security vulnerabilities.

        Args:
            source_code: Source code to analyze
            file_path: Path to the source file
            language: Programming language
            max_findings: Maximum number of findings to return

        Returns:
            List of security findings
        """
        file_path_abs = str(Path(file_path).resolve())
        logger.info(f"analyze_code called for {file_path_abs} ({language})")

        if not self.llm_client:
            logger.warning("LLM client not initialized, returning empty list")
            return []

        # Run async analysis in sync context
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            # Create new event loop if none exists
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(
            self._analyze_code_async(source_code, file_path, language, max_findings)
        )

    async def _analyze_code_async(
        self,
        source_code: str,
        file_path: str,
        language: str,
        max_findings: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Async implementation of code analysis with intelligent caching.

        Args:
            source_code: Source code to analyze
            file_path: Path to the source file
            language: Programming language
            max_findings: Maximum number of findings to return

        Returns:
            List of security findings
        """
        analysis_start_time = time.time()

        if not self.llm_client:
            # Record LLM not available
            if self.metrics_collector:
                self.metrics_collector.record_metric(
                    "llm_analysis_total",
                    1,
                    labels={"status": "client_unavailable", "language": language},
                )
            return []

        # Check cache first if enabled
        cached_result = None
        cache_key = None

        if self.cache_manager and self.config.cache_llm_responses:
            try:
                # Generate cache key based on content and analysis context
                hasher = self.cache_manager.get_hasher()
                content_hash = hasher.hash_content(source_code)
                context_hash = hasher.hash_llm_context(
                    content=source_code,
                    model=self.config.llm_model or "default",
                    system_prompt=self._get_system_prompt(),
                    user_prompt=self._create_user_prompt(
                        source_code, language, max_findings or 50
                    ),
                    temperature=self.config.llm_temperature,
                    max_tokens=self.config.llm_max_tokens,
                )

                cache_key = CacheKey(
                    cache_type=CacheType.LLM_RESPONSE,
                    content_hash=content_hash,
                    metadata_hash=context_hash,
                )

                cached_result = self.cache_manager.get(cache_key)
                if cached_result:
                    logger.info(f"Cache hit for LLM analysis: {file_path}")
                    # Convert cached serializable findings back to LLMSecurityFinding objects
                    findings = []
                    for cached_finding in cached_result.get("findings", []):
                        if isinstance(cached_finding, dict):
                            finding = LLMSecurityFinding(**cached_finding)
                            findings.append(finding)
                    return findings
                else:
                    logger.debug(f"Cache miss for LLM analysis: {file_path}")

            except Exception as e:
                logger.warning(f"Cache lookup failed for {file_path}: {e}")

        try:
            # Create prompts
            system_prompt = self._get_system_prompt()
            user_prompt = self._create_user_prompt(
                source_code, language, max_findings or 50
            )

            logger.debug(f"Sending analysis request to LLM for {file_path}")

            # Make LLM request with comprehensive error handling and circuit breaker
            # Use streaming for faster time-to-first-token and better performance
            async def llm_call():
                return await self.llm_client.complete_streaming_with_retry(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=self.config.llm_temperature,
                    max_tokens=self.config.llm_max_tokens,
                    response_format="json",
                )

            # Create a fallback function that returns cached results if available
            async def llm_fallback(*args, **kwargs):
                logger.warning(
                    f"LLM service degraded, attempting fallback for {file_path}"
                )
                # Try to find any cached result for similar content
                if self.cache_manager:
                    # Could implement more sophisticated fallback logic here
                    pass
                # Return empty findings as graceful degradation
                return type(
                    "Response",
                    (),
                    {
                        "content": '{"findings": []}',
                        "model": self.config.llm_model or "fallback",
                        "usage": {},
                    },
                )()

            # Execute with comprehensive error recovery for all providers
            recovery_result = await self.error_handler.execute_with_recovery(
                llm_call,
                operation_name=f"llm_analysis_{Path(file_path).name}",
                circuit_breaker_name="llm_service",
                fallback_func=llm_fallback,
            )

            if recovery_result.success:
                response = recovery_result.result
            else:
                # If recovery failed completely, use fallback result or raise exception
                if recovery_result.result:
                    response = recovery_result.result
                else:
                    error_msg = (
                        recovery_result.error_message or "LLM service unavailable"
                    )
                    raise LLMAnalysisError(
                        f"Analysis failed with recovery: {error_msg}"
                    )

            logger.info(f"LLM analysis completed for {file_path}, parsing response")

            # Debug: Log response content for comparison
            logger.error(f"[NON_SESSION] Response length: {len(response.content)}")
            logger.error(f"[NON_SESSION] Response preview: {response.content[:500]}...")

            # Parse response
            findings = self.parse_analysis_response(response.content, file_path)

            # Cache the result if caching is enabled
            if (
                self.cache_manager
                and self.config.cache_llm_responses
                and cache_key
                and findings
            ):
                try:
                    # Convert findings to serializable format
                    serializable_findings: list[dict[str, Any]] = []
                    for finding in findings:
                        if hasattr(finding, "__dict__"):
                            serializable_findings.append(finding.__dict__)
                        else:
                            # Convert string findings to dict format
                            serializable_findings.append({"finding": str(finding)})

                    cache_data = {
                        "findings": serializable_findings,
                        "response_metadata": {
                            "model": response.model,
                            "usage": response.usage,
                            "file_path": file_path,
                            "language": language,
                        },
                    }

                    # Cache for 24 hours by default
                    cache_expiry_seconds = self.config.cache_max_age_hours * 3600
                    self.cache_manager.put(cache_key, cache_data, cache_expiry_seconds)
                    logger.debug(f"Cached LLM analysis result for {file_path}")

                except Exception as e:
                    logger.warning(f"Failed to cache LLM result for {file_path}: {e}")

            logger.info(f"Parsed {len(findings)} findings from LLM response")

            # Record successful analysis metrics
            if self.metrics_collector:
                analysis_duration = time.time() - analysis_start_time
                self.metrics_collector.record_histogram(
                    "llm_analysis_duration_seconds",
                    analysis_duration,
                    labels={"language": language, "status": "success"},
                )
                self.metrics_collector.record_metric(
                    "llm_analysis_total",
                    1,
                    labels={"status": "success", "language": language},
                )
                self.metrics_collector.record_metric(
                    "llm_findings_total", len(findings), labels={"language": language}
                )
                # Record token usage if available
                if hasattr(response, "usage") and response.usage:
                    usage = response.usage
                    if hasattr(usage, "total_tokens"):
                        self.metrics_collector.record_metric(
                            "llm_tokens_consumed_total",
                            usage.total_tokens,
                            labels={
                                "provider": response.model,
                                "operation": "analysis",
                            },
                        )
                    if hasattr(usage, "prompt_tokens"):
                        self.metrics_collector.record_metric(
                            "llm_prompt_tokens_total",
                            usage.prompt_tokens,
                            labels={
                                "provider": response.model,
                                "operation": "analysis",
                            },
                        )

            return findings

        except Exception as e:
            logger.error(f"LLM analysis failed for {file_path}: {e}")

            # Record failure metrics
            if self.metrics_collector:
                analysis_duration = time.time() - analysis_start_time
                self.metrics_collector.record_histogram(
                    "llm_analysis_duration_seconds",
                    analysis_duration,
                    labels={"language": language, "status": "failed"},
                )
                self.metrics_collector.record_metric(
                    "llm_analysis_total",
                    1,
                    labels={"status": "failed", "language": language},
                )

            raise LLMAnalysisError(f"Analysis failed: {e}")

    # Removed analyze_code_resilient method - using LLM client's built-in retry instead

    async def analyze_file(
        self,
        file_path,
        language: str,
        max_findings: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Analyze a single file for security vulnerabilities.

        Args:
            file_path: Path to the file to analyze
            language: Programming language
            max_findings: Maximum number of findings to return

        Returns:
            List of security findings
        """
        file_path_abs = str(Path(file_path).resolve())
        logger.info(f"analyze_file called for {file_path_abs} ({language})")

        if not self.llm_client:
            logger.warning("LLM client not initialized, returning empty list")
            return []

        try:
            # Read file content
            with open(file_path, encoding="utf-8") as f:
                source_code = f.read()

            # Analyze the code
            return await self._analyze_code_async(
                source_code, str(file_path), language, max_findings
            )

        except Exception as e:
            logger.error(f"Failed to analyze file {file_path}: {e}")
            raise LLMAnalysisError(f"File analysis failed: {e}")

    async def analyze_directory(
        self,
        directory_path,
        recursive: bool = True,
        max_findings_per_file: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Analyze an entire directory for security vulnerabilities.

        Args:
            directory_path: Path to the directory to analyze
            recursive: Whether to scan subdirectories
            max_findings_per_file: Maximum number of findings per file

        Returns:
            List of security findings across all files
        """
        logger.info(
            f"analyze_directory called for {directory_path} (recursive={recursive})"
        )

        if not self.llm_client:
            logger.warning("LLM client not initialized, returning empty list")
            return []

        try:
            # Use FileFilter for consistent filtering logic
            from ..scanner.file_filter import FileFilter

            directory_path = Path(directory_path)

            # Initialize file filter with smart exclusions
            config = self.credential_manager.load_config()
            file_filter = FileFilter(
                root_path=directory_path,
                max_file_size_mb=config.max_file_size_mb,
                respect_gitignore=True,
            )

            # Discover all files first
            all_files = []
            pattern = "**/*" if recursive else "*"
            for file_path in directory_path.glob(pattern):
                if file_path.is_file():
                    all_files.append(file_path)

            logger.info(f"Discovered {len(all_files)} total files")

            # Apply smart filtering (same logic as scan_engine)
            filtered_files = file_filter.filter_files(all_files)

            # Then apply analyzable file filtering
            files_to_analyze = []
            for file_path in filtered_files:
                if self._is_analyzable_file(file_path):
                    files_to_analyze.append(file_path)

            logger.info(
                f"After filtering: {len(files_to_analyze)} files to analyze "
                f"(filtered out {len(all_files) - len(files_to_analyze)} files - "
                f"gitignore, binary, too large, non-source, etc.)"
            )

            # Safety check for large file counts
            if len(files_to_analyze) > 100:
                logger.warning(
                    f"Large number of files to analyze: {len(files_to_analyze)}. "
                    f"This may take considerable time and API usage."
                )

            if len(files_to_analyze) > 1000:
                logger.warning(
                    f"Very large directory scan: {len(files_to_analyze)} files. "
                    f"Consider using more specific filtering or scanning subdirectories individually."
                )

            if not files_to_analyze:
                logger.info("No analyzable files found after filtering")
                return []

            # Batch process files
            all_findings = []
            batch_size = self.config.llm_batch_size
            total_batches = (len(files_to_analyze) + batch_size - 1) // batch_size

            logger.info(
                f"Will process {len(files_to_analyze)} files in {total_batches} batches"
            )

            for i in range(0, len(files_to_analyze), batch_size):
                batch = files_to_analyze[i : i + batch_size]
                batch_num = i // batch_size + 1
                logger.info(
                    f"Processing batch {batch_num}/{total_batches}: {len(batch)} files"
                )

                # Analyze files in batch
                batch_findings = await self._analyze_batch_async(
                    batch, max_findings_per_file
                )
                all_findings.extend(batch_findings)

                # Progress logging for large scans
                if total_batches > 5:
                    logger.info(
                        f"Batch {batch_num}/{total_batches} complete. "
                        f"Found {len(batch_findings)} findings in this batch. "
                        f"Total findings so far: {len(all_findings)}"
                    )

            logger.info(
                f"Directory analysis complete: {len(all_findings)} total findings "
                f"from {len(files_to_analyze)} files in {total_batches} batches"
            )
            return all_findings

        except Exception as e:
            logger.error(f"Failed to analyze directory {directory_path}: {e}")
            raise LLMAnalysisError(f"Directory analysis failed: {e}")

    async def analyze_files(
        self,
        file_paths: list[Path],
        max_findings_per_file: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Analyze a pre-filtered list of files for security vulnerabilities.

        This method accepts a list of files that have already been filtered by the caller,
        avoiding the need to re-discover and re-filter files. This is more efficient
        and ensures consistent filtering logic across the application.

        Args:
            file_paths: List of Path objects to analyze (already filtered)
            max_findings_per_file: Maximum number of findings per file

        Returns:
            List of security findings across all files
        """
        logger.info(f"analyze_files called for {len(file_paths)} pre-filtered files")

        if not self.llm_client:
            logger.warning("LLM client not initialized, returning empty list")
            return []

        if not file_paths:
            logger.info("No files provided for analysis")
            return []

        try:
            # Filter to only analyzable files (apply file extension check)
            files_to_analyze = []
            for file_path in file_paths:
                if self._is_analyzable_file(file_path):
                    files_to_analyze.append(file_path)

            logger.info(
                f"After analyzable file filtering: {len(files_to_analyze)} files to analyze "
                f"(filtered out {len(file_paths) - len(files_to_analyze)} non-source files)"
            )

            if not files_to_analyze:
                logger.info("No analyzable files found after filtering")
                return []

            # Safety check for large file counts
            if len(files_to_analyze) > 100:
                logger.warning(
                    f"Large number of files to analyze: {len(files_to_analyze)}. "
                    f"This may take considerable time and API usage."
                )

            # Batch process files
            all_findings = []
            batch_size = self.config.llm_batch_size
            total_batches = (len(files_to_analyze) + batch_size - 1) // batch_size

            logger.info(
                f"Will process {len(files_to_analyze)} files in {total_batches} batches"
            )

            for i in range(0, len(files_to_analyze), batch_size):
                batch = files_to_analyze[i : i + batch_size]
                batch_num = i // batch_size + 1
                logger.info(
                    f"Processing batch {batch_num}/{total_batches}: {len(batch)} files"
                )

                # Analyze files in batch
                batch_findings = await self._analyze_batch_async(
                    batch, max_findings_per_file
                )
                all_findings.extend(batch_findings)

                # Progress logging for large scans
                if total_batches > 5:
                    logger.info(
                        f"Batch {batch_num}/{total_batches} complete. "
                        f"Found {len(batch_findings)} findings in this batch. "
                        f"Total findings so far: {len(all_findings)}"
                    )

            logger.info(
                f"File list analysis complete: {len(all_findings)} total findings "
                f"from {len(files_to_analyze)} files in {total_batches} batches"
            )
            return all_findings

        except Exception as e:
            logger.error(f"Failed to analyze file list: {e}")
            raise LLMAnalysisError(f"File list analysis failed: {e}")

    async def _analyze_batch_async(
        self,
        file_paths: list[Path],
        max_findings_per_file: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Analyze a batch of files efficiently with true parallel processing.

        Args:
            file_paths: List of file paths to analyze
            max_findings_per_file: Maximum findings per file

        Returns:
            List of security findings across all files in batch
        """
        if not self.llm_client:
            return []

        # For small to medium batches, use parallel individual analysis for better performance
        if len(file_paths) <= 25:
            logger.info(
                f"Using parallel individual analysis for {len(file_paths)} files"
            )
            return await self._analyze_files_in_parallel(
                file_paths, max_findings_per_file
            )

        logger.info(f"Starting batch processor analysis for {len(file_paths)} files")

        # Step 1: Collect and preprocess all file content
        file_content_data = await self._collect_file_content(file_paths)
        if not file_content_data:
            return []

        # Step 2: Create file analysis contexts for intelligent batch processing
        file_contexts = []
        for file_data in file_content_data:
            # Map language string to Language enum
            language_map = {
                "python": Language.PYTHON,
                "javascript": Language.JAVASCRIPT,
                "typescript": Language.TYPESCRIPT,
                "java": Language.JAVA,
                "go": Language.GO,
                "rust": Language.RUST,
                "php": Language.PHP,
                "ruby": Language.RUBY,
                "c": Language.C,
                "cpp": Language.CPP,
                "csharp": Language.CSHARP,
                "kotlin": Language.KOTLIN,
                "swift": Language.SWIFT,
            }

            language = language_map.get(file_data["language"], Language.GENERIC)

            # Create file analysis context
            context = self.batch_processor.create_file_context(
                file_path=Path(file_data["file_path"]),
                content=file_data["content"],
                language=language,
                priority=file_data.get("priority", 0),
            )
            file_contexts.append(context)

        # Step 3: Create intelligent batches using the batch processor
        batches = self.batch_processor.create_batches(
            file_contexts, model=getattr(self.config, "llm_model", None)
        )
        logger.info(f"Created {len(batches)} intelligent batches using BatchProcessor")

        # Step 4: Process batches using the batch processor
        async def process_batch_func(
            batch_contexts: list[FileAnalysisContext],
        ) -> list[LLMSecurityFinding]:
            """Process a batch of file contexts."""
            # Convert contexts back to the format expected by existing code
            batch_content = []
            for context in batch_contexts:
                batch_content.append(
                    {
                        "file_path": str(context.file_path),
                        "language": context.language.value,
                        "content": context.content,
                        "size": context.file_size_bytes,
                        "complexity": context.complexity_score,
                    }
                )

            return await self._process_single_batch(
                batch_content, max_findings_per_file or 50, 0
            )

        def progress_callback(completed: int, total: int):
            """Progress callback for batch processing."""
            logger.info(
                f"Batch processing progress: {completed}/{total} batches completed"
            )

        # Process all batches with intelligent concurrency control
        batch_results = await self.batch_processor.process_batches(
            batches, process_batch_func, progress_callback
        )

        # Flatten results
        all_findings = []
        for batch_findings in batch_results:
            if batch_findings:  # Filter out None results from failed batches
                all_findings.extend(batch_findings)

        # Log batch processing metrics and circuit breaker stats
        metrics = self.batch_processor.get_metrics()
        cb_stats = self.get_circuit_breaker_stats()

        logger.info(f"Batch processing completed: {metrics.to_dict()}")
        logger.info(f"Circuit breaker stats: {cb_stats}")
        logger.info(
            f"Batch analysis complete: {len(all_findings)} total findings from {len(file_paths)} files"
        )
        return all_findings

    async def _analyze_files_in_parallel(
        self,
        file_paths: list[Path],
        max_findings_per_file: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Analyze files in parallel for better performance with small batches.

        Args:
            file_paths: List of file paths to analyze
            max_findings_per_file: Maximum findings per file

        Returns:
            List of security findings from all files
        """
        logger.info(f"Analyzing {len(file_paths)} files in parallel")

        async def analyze_single_file(file_path: Path) -> list[LLMSecurityFinding]:
            """Analyze a single file and return findings."""
            try:
                language = self._detect_language(file_path)
                return await self.analyze_file(
                    file_path, language, max_findings_per_file
                )
            except Exception as e:
                logger.warning(f"Failed to analyze {file_path}: {e}")
                return []

        # Run all file analyses concurrently
        start_time = time.time()
        file_tasks = [analyze_single_file(file_path) for file_path in file_paths]

        # Use semaphore to limit concurrent API calls
        max_concurrent = min(
            10, len(file_paths)
        )  # Increased to 10 concurrent calls for better throughput
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_semaphore(task):
            async with semaphore:
                return await task

        # Execute with concurrency limit
        results = await asyncio.gather(
            *[analyze_with_semaphore(task) for task in file_tasks],
            return_exceptions=True,
        )

        # Collect all findings from successful analyses
        all_findings = []
        successful_analyses = 0

        for i, result in enumerate(results):
            if isinstance(result, list):  # Successful result
                all_findings.extend(result)
                successful_analyses += 1
            elif isinstance(result, Exception):
                logger.warning(f"File analysis failed for {file_paths[i]}: {result}")

        elapsed_time = time.time() - start_time
        logger.info(
            f"Parallel analysis completed: {successful_analyses}/{len(file_paths)} files, "
            f"{len(all_findings)} findings, {elapsed_time:.2f}s "
            f"({len(file_paths)/elapsed_time:.2f} files/sec)"
        )

        return all_findings

    async def _collect_file_content(self, file_paths: list[Path]) -> list[dict]:
        """Collect and preprocess file content with metadata for optimization.

        Args:
            file_paths: List of file paths to read

        Returns:
            List of file content dictionaries with metadata
        """
        file_content_data = []

        for file_path in file_paths:
            try:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()

                # Skip empty files
                if not content.strip():
                    logger.debug(f"Skipping empty file: {file_path}")
                    continue

                language = self._detect_language(file_path)
                file_size = len(content)

                # Truncate very large files but preserve structure
                if file_size > 12000:  # Increased limit for batch processing
                    content = self._smart_truncate_content(content, 12000)
                    logger.debug(
                        f"Truncated large file {file_path} from {file_size} to {len(content)} chars"
                    )

                file_content_data.append(
                    {
                        "file_path": str(file_path),
                        "language": language,
                        "content": content,
                        "size": len(content),
                        "priority": 0.5,  # Default priority
                        "original_size": file_size,
                    }
                )

            except Exception as e:
                logger.warning(f"Failed to read {file_path}: {e}")

        logger.debug(
            f"Successfully collected content from {len(file_content_data)} files"
        )
        return file_content_data

    def _smart_truncate_content(self, content: str, max_length: int) -> str:
        """Intelligently truncate content while preserving structure.

        Args:
            content: Original content
            max_length: Maximum length to truncate to

        Returns:
            Truncated content with preserved structure
        """
        if len(content) <= max_length:
            return content

        # Try to find a good breaking point (end of function, class, etc.)
        lines = content.split("\n")
        accumulated_length = 0
        truncate_point = 0

        for i, line in enumerate(lines):
            line_length = len(line) + 1  # +1 for newline
            if accumulated_length + line_length > max_length * 0.8:  # Leave some buffer
                # Look for natural breaking points
                if any(
                    marker in line
                    for marker in ["def ", "class ", "function ", "}", "end"]
                ):
                    truncate_point = i + 1
                    break
                elif not line.strip():  # Empty line is also a good break
                    truncate_point = i
                    break
            accumulated_length += line_length
            truncate_point = i

        truncated_content = "\n".join(lines[:truncate_point])
        return truncated_content + "\n... [truncated for analysis]"

    async def _process_single_batch(
        self, batch_content: list[dict], max_findings_per_file: int, batch_number: int
    ) -> list[LLMSecurityFinding]:
        """Process a single optimized batch with enhanced error handling.

        Args:
            batch_content: List of file content dictionaries
            max_findings_per_file: Maximum findings per file
            batch_number: Batch number for logging

        Returns:
            List of security findings
        """
        # Create optimized batch analysis prompt
        system_prompt = self._get_enhanced_batch_system_prompt(batch_content)
        user_prompt = self._create_enhanced_batch_user_prompt(
            batch_content, max_findings_per_file
        )

        # Estimate token usage for this batch
        total_chars = sum(len(fc["content"]) for fc in batch_content)
        estimated_tokens = (
            total_chars // 4 + len(system_prompt) // 4 + len(user_prompt) // 4
        )

        file_paths = [fc["file_path"] for fc in batch_content]
        languages = list({fc["language"] for fc in batch_content})

        logger.info(
            f"Batch {batch_number}: {len(batch_content)} files, "
            f"~{estimated_tokens} tokens, languages: {languages}"
        )

        # Define the batch operation for resilience handling
        # Use streaming for faster time-to-first-token and better batch performance
        async def batch_operation():
            response = await self.llm_client.complete_streaming_with_retry(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=self.config.llm_temperature,
                max_tokens=min(
                    self.config.llm_max_tokens, 8000
                ),  # Conservative for batch
                response_format="json",
            )
            return response

        # Define fallback function for graceful degradation
        async def batch_fallback(*args, **kwargs):
            logger.warning(
                f"LLM service degraded during batch {batch_number}, falling back to individual analysis"
            )
            return await self._fallback_individual_analysis(
                batch_content, max_findings_per_file
            )

        # Execute batch with comprehensive error recovery
        recovery_result = await self.error_handler.execute_with_recovery(
            batch_operation,
            operation_name=f"llm_batch_{batch_number}",
            circuit_breaker_name="llm_batch_service",
            fallback_func=batch_fallback,
        )

        if recovery_result.success:
            # Parse batch response with enhanced error handling
            findings = self._parse_enhanced_batch_response(
                recovery_result.result.content, batch_content
            )
            logger.info(
                f"Batch {batch_number} completed: {len(findings)} findings from "
                f"{len(batch_content)} files - SUCCESS"
            )
            return findings
        else:
            # Fallback was used, result should already be findings list
            findings = recovery_result.result or []
            logger.info(
                f"Batch {batch_number} completed via fallback: {len(findings)} findings from "
                f"{len(batch_content)} files"
            )
            return findings

    async def _fallback_individual_analysis(
        self, batch_content: list[dict], max_findings_per_file: int
    ) -> list[LLMSecurityFinding]:
        """Fallback to individual file analysis when batch processing fails.

        Args:
            batch_content: List of file content dictionaries
            max_findings_per_file: Maximum findings per file

        Returns:
            List of security findings from individual analysis
        """
        findings = []

        # Process files in parallel for better performance in fallback mode
        async def analyze_single_file(file_info):
            try:
                return await self._analyze_code_async(
                    file_info["content"],
                    file_info["file_path"],
                    file_info["language"],
                    max_findings_per_file,
                )
            except Exception as e:
                logger.warning(
                    f"Individual analysis failed for {file_info['file_path']}: {e}"
                )
                return []

        # Run all file analyses in parallel
        file_analysis_tasks = [
            analyze_single_file(file_info) for file_info in batch_content
        ]
        file_results = await asyncio.gather(
            *file_analysis_tasks, return_exceptions=True
        )

        # Collect all findings from successful analyses
        for result in file_results:
            if isinstance(result, list):  # Successful result
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.warning(f"File analysis failed: {result}")

        logger.info(f"Fallback analysis completed: {len(findings)} findings")
        return findings

    def _is_analyzable_file(self, file_path: Path) -> bool:
        """Check if a file should be analyzed.

        Args:
            file_path: Path to check

        Returns:
            True if file should be analyzed
        """
        return file_path.suffix.lower() in ANALYZABLE_SOURCE_EXTENSIONS

    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension using shared mapper.

        Args:
            file_path: File path

        Returns:
            Language name, defaults to 'generic' for unknown extensions
        """
        return LanguageMapper.detect_language_from_extension(file_path)

    def _create_batch_user_prompt(
        self, batch_content: list[dict[str, str]], max_findings_per_file: int
    ) -> str:
        """Create user prompt for batch analysis.

        Args:
            batch_content: List of file content dictionaries
            max_findings_per_file: Maximum findings per file

        Returns:
            Formatted prompt string
        """
        prompt_parts = ["Analyze the following files for security vulnerabilities:\n"]

        for i, file_info in enumerate(batch_content, 1):
            prompt_parts.append(
                f"\n=== File {i}: {file_info['file_path']} ({file_info['language']}) ===\n"
            )
            prompt_parts.append(
                f"IMPORTANT: All findings for this file MUST include file_path=\"{file_info['file_path']}\""
            )
            prompt_parts.append(
                f"```{file_info['language']}\n{file_info['content']}\n```"
            )

        prompt_parts.append(
            "\n\nProvide ALL security findings you discover for each file."
        )
        prompt_parts.append(
            """
Requirements:
- Focus on genuine security vulnerabilities
- Provide specific line numbers (1-indexed, exactly as they appear in the source code)
- Include the vulnerable code snippet
- IMPORTANT: Line numbers must match the exact line numbers in the provided source code (1-indexed)
- CRITICAL: Each finding MUST include the exact file_path as shown above for the file containing the vulnerability

Response format:
{
  "findings": [
    {
      "file_path": "/path/to/file",
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
    }
  ]
}"""
        )

        return "\n".join(prompt_parts)

    def _parse_batch_response(
        self, response_text: str, batch_content: list[dict[str, str]]
    ) -> list[LLMSecurityFinding]:
        """Parse batch analysis response.

        Args:
            response_text: Raw response from LLM
            batch_content: Original batch content for reference

        Returns:
            List of security findings
        """
        try:
            # Strip markdown code blocks first
            clean_response = self._strip_markdown_code_blocks(response_text)
            # Sanitize JSON to fix escape sequence issues
            clean_response = self._sanitize_json_string(clean_response)
            data = self._robust_json_parse(clean_response)
            findings = []

            for finding_data in data.get("findings", []):
                try:
                    # Ensure file_path is included in finding
                    file_path = finding_data.get("file_path", "")
                    if not file_path:
                        # Try to determine file from context (line number + code snippet)
                        code_snippet = finding_data.get("code_snippet", "").strip()
                        line_number = int(finding_data.get("line_number", 0))

                        # Search for the code snippet in batch files
                        matched_file = None
                        for fc in batch_content:
                            if code_snippet and code_snippet in fc["content"]:
                                # Verify line number if possible
                                lines = fc["content"].split("\n")
                                if line_number > 0 and line_number <= len(lines):
                                    if code_snippet in lines[line_number - 1]:
                                        matched_file = fc["file_path"]
                                        logger.debug(
                                            f"Matched finding to {matched_file} by line {line_number} + code snippet"
                                        )
                                        break
                                else:
                                    matched_file = fc["file_path"]
                                    logger.debug(
                                        f"Matched finding to {matched_file} by code snippet only"
                                    )
                                    break

                        if matched_file:
                            file_path = matched_file
                            logger.warning(
                                f"LLM didn't provide file_path, matched to {file_path}"
                            )
                        else:
                            # Fall back to first file if we can't determine the file but have batch content
                            if batch_content:
                                file_path = batch_content[0]["file_path"]
                                logger.warning(
                                    f"LLM didn't provide file_path, falling back to first file: {file_path}"
                                )
                            else:
                                # Skip this finding if we truly can't determine the file
                                logger.error(
                                    f"Cannot determine file for finding: {finding_data.get('type', 'unknown')}"
                                )
                                continue  # Skip this finding

                    # Validate file path before creating finding
                    from pathlib import Path

                    if not file_path or Path(file_path).is_dir():
                        logger.error(f"Invalid file_path for finding: {file_path}")
                        continue  # Skip this finding

                    finding = LLMSecurityFinding(
                        finding_type=finding_data.get("type", "unknown"),
                        severity=finding_data.get("severity", "medium"),
                        description=finding_data.get("description", ""),
                        line_number=max(1, int(finding_data.get("line_number", 1))),
                        code_snippet=finding_data.get("code_snippet", ""),
                        explanation=finding_data.get("explanation", ""),
                        recommendation=finding_data.get("recommendation", ""),
                        confidence=float(finding_data.get("confidence", 0.5)),
                        file_path=file_path,
                        cwe_id=finding_data.get("cwe_id"),
                        owasp_category=finding_data.get("owasp_category"),
                    )
                    findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to parse batch finding: {e}")

            return findings

        except Exception as e:
            logger.error(f"Failed to parse batch response: {e}")
            return []

    def _get_enhanced_batch_system_prompt(self, batch_content: list[dict]) -> str:
        """Get enhanced system prompt for optimized batch analysis.

        Args:
            batch_content: List of file content dictionaries with metadata

        Returns:
            Enhanced system prompt string
        """
        languages = {fc["language"] for fc in batch_content}
        file_count = len(batch_content)

        return f"""You are a senior security engineer performing static code analysis on {file_count} files.
Your task is to analyze code for security vulnerabilities across multiple files and provide detailed, actionable findings.

Target languages: {', '.join(languages)}
Analysis scope: Cross-file vulnerabilities, individual file issues, and architectural security concerns

Guidelines:
1. Focus on real security issues, not code style or minor concerns
2. Consider cross-file relationships and data flow between files
3. Provide specific line numbers and code snippets for each file
4. Include detailed explanations of why something is vulnerable
5. Offer concrete remediation advice
6. Assign appropriate severity levels (low, medium, high, critical)
7. Be precise about vulnerability types and CWE mappings
8. Avoid false positives - only report genuine security concerns
9. Consider the full context of the codebase when making assessments
10. Look for patterns across files that might indicate systemic issues

Response format: JSON object with "findings" array containing security issues.
Each finding should have: file_path, type, severity, description, line_number, code_snippet, explanation, recommendation, confidence, cwe_id (optional), owasp_category (optional).

CRITICAL: The "file_path" field is MANDATORY for every finding. Use the exact file path from the analysis above to specify which file contains each vulnerability. This is essential for proper issue tracking and deduplication.

Priority vulnerability types to look for:
- Authentication/authorization bypasses across modules
- SQL injection, Command injection, Code injection
- Cross-site scripting (XSS) and CSRF vulnerabilities
- Path traversal and directory traversal
- Deserialization vulnerabilities
- Hardcoded credentials, API keys, secrets
- Weak cryptography and insecure random numbers
- Input validation issues and injection flaws
- Session management and state handling flaws
- Information disclosure and data leakage
- Logic errors with security implications
- Race conditions and concurrency issues
- Denial of service vulnerabilities
- Configuration and deployment security issues"""

    def _create_enhanced_batch_user_prompt(
        self, batch_content: list[dict], max_findings_per_file: int
    ) -> str:
        """Create enhanced user prompt for optimized batch analysis.

        Args:
            batch_content: List of file content dictionaries with metadata
            max_findings_per_file: Maximum findings per file

        Returns:
            Enhanced formatted prompt string
        """
        # Group files by language for better organization
        files_by_language = {}
        for file_info in batch_content:
            lang = file_info["language"]
            if lang not in files_by_language:
                files_by_language[lang] = []
            files_by_language[lang].append(file_info)

        prompt_parts = [
            "Analyze the following codebase files for security vulnerabilities:\n"
        ]

        # Add language-grouped sections
        for language, files in files_by_language.items():
            prompt_parts.append(f"\n## {language.upper()} Files ({len(files)} files)\n")

            for i, file_info in enumerate(files, 1):
                complexity_indicator = (
                    "complex"
                    if file_info["complexity"] > 0.7
                    else "moderate" if file_info["complexity"] > 0.3 else "simple"
                )
                size_indicator = f"{file_info['size']} chars"

                prompt_parts.append(f"\n### File {i}: {file_info['file_path']}")
                prompt_parts.append(
                    f"Language: {file_info['language']}, Size: {size_indicator}, Complexity: {complexity_indicator}\n"
                )
                prompt_parts.append(
                    f"```{file_info['language']}\n{file_info['content']}\n```\n"
                )

        total_files = len(batch_content)

        prompt_parts.append(
            f"""\n\n## Analysis Requirements

Provide ALL security findings you discover across all files.

**Critical Requirements:**
- Focus on genuine security vulnerabilities, not code quality issues
- Provide specific line numbers (1-indexed, exactly as they appear in the source code)
- Include the vulnerable code snippet for each finding
- Consider relationships between files (shared functions, data flow, etc.)
- Prioritize high-impact vulnerabilities that could lead to compromise
- IMPORTANT: Line numbers must match the exact line numbers in the provided source code (1-indexed)

**Analysis Priority:**
1. Critical vulnerabilities (RCE, authentication bypass, etc.)
2. High-impact data exposure or injection flaws
3. Cross-file security architectural issues
4. Medium-impact vulnerabilities with clear attack vectors
5. Low-impact issues with security implications

**Response format:**
```json
{{
  "findings": [
    {{
      "file_path": "/exact/path/from/above",
      "type": "vulnerability_type",
      "severity": "low|medium|high|critical",
      "description": "brief description",
      "line_number": 42,
      "code_snippet": "vulnerable code line",
      "explanation": "detailed explanation of the vulnerability",
      "recommendation": "specific steps to fix",
      "confidence": 0.9,
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021"
    }}
  ],
  "analysis_summary": {{
    "total_files_analyzed": {total_files},
    "files_with_findings": 0,
    "critical_findings": 0,
    "high_findings": 0,
    "cross_file_issues_detected": false
  }}
}}
```"""
        )

        return "\n".join(prompt_parts)

    def _parse_enhanced_batch_response(
        self, response_text: str, batch_content: list[dict]
    ) -> list[LLMSecurityFinding]:
        """Parse enhanced batch analysis response with better error handling.

        Args:
            response_text: Raw response from LLM
            batch_content: Original batch content for reference

        Returns:
            List of security findings
        """
        try:
            # Strip markdown code blocks first
            clean_response = self._strip_markdown_code_blocks(response_text)
            # Sanitize JSON to fix escape sequence issues
            clean_response = self._sanitize_json_string(clean_response)
            data = self._robust_json_parse(clean_response)
            findings = []

            # Extract summary information if available
            summary = data.get("analysis_summary", {})
            if summary:
                logger.info(f"Batch analysis summary: {summary}")

            for finding_data in data.get("findings", []):
                try:
                    # Validate file_path is in the batch
                    file_path = finding_data.get("file_path", "")

                    # Handle missing or invalid file path
                    if not file_path:
                        logger.error(
                            f"LLM returned finding without file_path: {finding_data}"
                        )
                        # Use code snippet matching logic
                        file_path = ""

                    if not file_path or not any(
                        fc["file_path"] == file_path for fc in batch_content
                    ):
                        # Try to match by filename if full path doesn't match
                        matched_file = None
                        if file_path:
                            file_name = (
                                file_path.split("/")[-1]
                                if "/" in file_path
                                else file_path
                            )
                            for fc in batch_content:
                                if fc["file_path"].endswith(file_name):
                                    matched_file = fc["file_path"]
                                    logger.debug(
                                        f"Matched file by name: {file_name} -> {matched_file}"
                                    )
                                    break

                        # If filename matching failed, try code snippet matching
                        if not matched_file:
                            code_snippet = finding_data.get("code_snippet", "").strip()
                            line_number = int(finding_data.get("line_number", 0))

                            for fc in batch_content:
                                if code_snippet and code_snippet in fc["content"]:
                                    # Verify line number if possible
                                    lines = fc["content"].split("\n")
                                    if line_number > 0 and line_number <= len(lines):
                                        if code_snippet in lines[line_number - 1]:
                                            matched_file = fc["file_path"]
                                            logger.debug(
                                                f"Matched finding to {matched_file} by line {line_number} + code snippet"
                                            )
                                            break
                                    else:
                                        matched_file = fc["file_path"]
                                        logger.debug(
                                            f"Matched finding to {matched_file} by code snippet only"
                                        )
                                        break

                        if matched_file:
                            file_path = matched_file
                            logger.warning(
                                f"File path corrected from '{finding_data.get('file_path', '')}' to '{file_path}'"
                            )
                        else:
                            # Generate unique placeholder for unmatchable findings instead of dropping them
                            import uuid

                            original_path = finding_data.get("file_path", "")
                            placeholder_name = f"<unknown-file-{uuid.uuid4().hex[:8]}>"
                            file_path = placeholder_name
                            logger.warning(
                                f"Cannot match file for finding '{finding_data.get('type', 'unknown')}' "
                                f"(original: '{original_path}'), using placeholder: {placeholder_name}"
                            )

                    # Enhanced validation
                    line_number = max(1, int(finding_data.get("line_number", 1)))
                    confidence = max(
                        0.0, min(1.0, float(finding_data.get("confidence", 0.5)))
                    )

                    # Validate file path before creating finding
                    from pathlib import Path

                    if not file_path:
                        logger.error("Finding has empty file_path, skipping")
                        continue  # Skip this finding

                    # Allow placeholder files (they start with <unknown-file-)
                    if (
                        not file_path.startswith("<unknown-file-")
                        and Path(file_path).exists()
                        and Path(file_path).is_dir()
                    ):
                        logger.error(
                            f"file_path points to directory, not file: {file_path}"
                        )
                        continue  # Skip this finding

                    finding = LLMSecurityFinding(
                        finding_type=finding_data.get("type", "unknown"),
                        severity=finding_data.get("severity", "medium"),
                        description=finding_data.get("description", ""),
                        line_number=line_number,
                        code_snippet=finding_data.get("code_snippet", ""),
                        explanation=finding_data.get("explanation", ""),
                        recommendation=finding_data.get("recommendation", ""),
                        confidence=confidence,
                        file_path=file_path,
                        cwe_id=finding_data.get("cwe_id"),
                        owasp_category=finding_data.get("owasp_category"),
                    )
                    findings.append(finding)

                except Exception as e:
                    logger.warning(f"Failed to parse enhanced batch finding: {e}")

            logger.info(
                f"Enhanced batch parsing: {len(findings)} valid findings extracted"
            )
            return findings

        except Exception as e:
            logger.error(f"Failed to parse enhanced batch response: {e}")
            # Fall back to original batch parsing method
            return self._parse_batch_response(response_text, batch_content)

    def batch_analyze_code(
        self,
        code_samples: list[tuple[str, str, str]],
        max_findings_per_sample: int | None = None,
    ) -> list[list[LLMSecurityFinding]]:
        """Analyze multiple code samples.

        Args:
            code_samples: List of (code, file_path, language) tuples
            max_findings_per_sample: Maximum findings per sample

        Returns:
            List of findings lists (one per sample)
        """
        logger.info(f"batch_analyze_code called with {len(code_samples)} samples")

        if not self.llm_client:
            logger.warning("LLM client not initialized, returning empty results")
            return [[] for _ in code_samples]

        # Run async batch analysis in sync context
        try:
            # Try to get current event loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If there's already a running loop, we need to use asyncio.run in a thread
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self._batch_analyze_code_async(
                            code_samples, max_findings_per_sample
                        ),
                    )
                    return future.result()
            else:
                return loop.run_until_complete(
                    self._batch_analyze_code_async(
                        code_samples, max_findings_per_sample
                    )
                )
        except RuntimeError:
            # No event loop exists, create one
            return asyncio.run(
                self._batch_analyze_code_async(code_samples, max_findings_per_sample)
            )

    async def _batch_analyze_code_async(
        self,
        code_samples: list[tuple[str, str, str]],
        max_findings_per_sample: int | None = None,
    ) -> list[list[LLMSecurityFinding]]:
        """Async implementation of batch code analysis.

        Args:
            code_samples: List of (code, file_path, language) tuples
            max_findings_per_sample: Maximum findings per sample

        Returns:
            List of findings lists (one per sample)
        """
        # Create batch content
        batch_content = []
        for code, file_path, language in code_samples:
            batch_content.append(
                {"file_path": file_path, "language": language, "content": code}
            )

        # Analyze as batch
        all_findings = await self._analyze_batch_async(
            [Path(bc["file_path"]) for bc in batch_content], max_findings_per_sample
        )

        # Group findings by file
        results = []
        for code, file_path, language in code_samples:
            file_findings = [f for f in all_findings if f.file_path == file_path]
            results.append(file_findings)

        return results

    # Session-aware analysis methods

    async def analyze_project_with_session(
        self,
        project_root: Path,
        target_files: list[Path] | None = None,
        analysis_focus: str = "comprehensive security analysis",
        max_findings: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """
        Analyze a project using session-aware context for better cross-file vulnerability detection.

        This method provides enhanced analysis by maintaining context across files,
        enabling detection of architectural vulnerabilities and attack chains.

        Args:
            project_root: Root directory of the project
            target_files: Specific files to focus on (optional)
            analysis_focus: Type of analysis to perform
            max_findings: Maximum total findings to return

        Returns:
            List of security findings with enhanced context
        """
        if not self.session_manager:
            logger.warning(
                "Session manager not available, falling back to legacy directory analysis"
            )
            return await self.analyze_directory(
                str(project_root), max_findings_per_file=max_findings
            )

        logger.info(f"Starting session-aware project analysis of {project_root}")

        session = None
        try:
            # Create analysis session
            session = await self.session_manager.create_session(
                project_root=project_root,
                target_files=target_files,
                session_metadata={
                    "analysis_focus": analysis_focus,
                    "scanner_type": "llm_enhanced",
                    "max_findings": max_findings,
                },
            )

            # Perform comprehensive analysis with session context
            findings = await self._perform_session_analysis(
                session.session_id, max_findings or 50
            )

            logger.info(
                f"Session-aware project analysis complete: {len(findings)} findings"
            )
            return findings

        except Exception as e:
            logger.error(f"Session-aware project analysis failed: {e}")
            # Fallback to legacy analysis
            logger.info("Falling back to legacy directory analysis")
            return await self.analyze_directory(
                str(project_root), max_findings_per_file=max_findings
            )
        finally:
            # Always cleanup session if it was created
            if session and self.session_manager:
                self.session_manager.close_session(session.session_id)

    async def analyze_file_with_context(
        self,
        file_path: Path,
        project_root: Path | None = None,
        context_hint: str | None = None,
        max_findings: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """
        Analyze a specific file with project context for enhanced detection.

        Args:
            file_path: File to analyze
            project_root: Project root for context (auto-detected if None)
            context_hint: Hint about what to focus on
            max_findings: Maximum findings to return

        Returns:
            List of security findings with context
        """
        if not self.session_manager:
            logger.error(
                "[SESSION_DEBUG] Session manager not available, falling back to legacy file analysis"
            )
            language = self._detect_language(file_path)
            return await self.analyze_file(file_path, language, max_findings)

        # Auto-detect project root if not provided
        if project_root is None:
            project_root = self._find_project_root(file_path)

        logger.info(f"Analyzing {file_path} with session context from {project_root}")

        session = None
        try:
            # Create session focused on this file
            session = await self.session_manager.create_session(
                project_root=project_root,
                target_files=[file_path],
                session_metadata={
                    "analysis_type": "focused_file",
                    "target_file": str(file_path),
                    "context_hint": context_hint,
                },
            )

            # Analyze the specific file with context - include actual file content
            language = self._detect_language(file_path)

            # Read the file content with line numbers
            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    file_lines = f.readlines()

                # Format content with line numbers
                numbered_content = ""
                for i, line in enumerate(file_lines, 1):
                    numbered_content += f"{i:4d} | {line}"

                query = f"""Analyze {file_path.name} ({language}) for security vulnerabilities.

## File Content with Line Numbers:
```{language}
{numbered_content}```

Please analyze the above code for security vulnerabilities. Provide the EXACT line number where each vulnerability occurs."""

                if context_hint:
                    query += f"\n\nAdditional context: {context_hint}"

            except Exception as e:
                logger.warning(f"Failed to read file content for {file_path}: {e}")
                # Fallback to original query without content
                query = f"Analyze {file_path.name} ({language}) for security vulnerabilities"
                if context_hint:
                    query += f". {context_hint}"

            session_findings = await self.session_manager.analyze_with_session(
                session_id=session.session_id,
                analysis_query=query,
                context_hint=context_hint,
            )

            # Convert session findings to LLMSecurityFinding objects
            findings = []
            for i, finding in enumerate(session_findings):
                logger.debug(
                    f"[LLM_FINDING_DEBUG] Converting SecurityFinding {i+1}: rule_id='{finding.rule_id}', line_number={finding.line_number}"
                )

                llm_finding = LLMSecurityFinding(
                    finding_type=finding.rule_id,
                    severity=(
                        finding.severity.value
                        if hasattr(finding.severity, "value")
                        else str(finding.severity)
                    ),
                    description=finding.description,
                    line_number=finding.line_number,
                    code_snippet=finding.code_snippet,
                    explanation=finding.description,
                    recommendation=getattr(
                        finding, "remediation", "Review and fix this vulnerability"
                    ),
                    confidence=finding.confidence,
                    file_path=str(file_path),
                    cwe_id=getattr(finding, "cwe_id", None),
                    owasp_category=getattr(finding, "owasp_category", None),
                )

                logger.debug(
                    f"[LLM_FINDING_DEBUG] Created LLMSecurityFinding {i+1}: finding_type='{llm_finding.finding_type}', line_number={llm_finding.line_number}"
                )
                findings.append(llm_finding)

            logger.info(
                f"File analysis with context complete: {len(findings)} findings"
            )
            return findings

        except Exception as e:
            logger.error(f"[FALLBACK] File analysis with context failed: {e}")
            logger.error(f"[FALLBACK] Falling back to legacy analysis for {file_path}")
            # Fallback to legacy analysis
            language = self._detect_language(file_path)
            return await self.analyze_file(file_path, language, max_findings)
        finally:
            if session and self.session_manager:
                self.session_manager.close_session(session.session_id)

    async def analyze_code_with_context(
        self,
        code_content: str,
        language: str,
        file_name: str = "code_snippet",
        context_hint: str | None = None,
        max_findings: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """
        Analyze code content with minimal context.

        Args:
            code_content: Code to analyze
            language: Programming language
            file_name: Name for the code snippet
            context_hint: Analysis focus hint
            max_findings: Maximum findings to return

        Returns:
            List of security findings
        """
        if not self.session_manager:
            logger.warning(
                "Session manager not available, falling back to legacy code analysis"
            )
            return await self._analyze_code_async(
                code_content, file_name, language, max_findings
            )

        logger.info(f"Analyzing {language} code snippet with session context")

        session = None
        try:
            # Create temporary session for code analysis
            session = await self.session_manager.create_session(
                project_root=Path.cwd(),  # Use current directory as fallback
                target_files=[],  # No specific files
                session_metadata={
                    "analysis_type": "code_snippet",
                    "language": language,
                    "file_name": file_name,
                },
            )

            # Analyze code with session context
            query = f"""
Analyze this {language} code for security vulnerabilities:

File: {file_name}
```{language}
{code_content}
```

{context_hint if context_hint else "Focus on common security vulnerabilities for this language."}
"""

            session_findings = await self.session_manager.analyze_with_session(
                session_id=session.session_id,
                analysis_query=query,
                context_hint=context_hint,
            )

            # Convert to LLMSecurityFinding objects
            findings = []
            for finding in session_findings:
                llm_finding = LLMSecurityFinding(
                    finding_type=finding.rule_id,
                    severity=(
                        finding.severity.value
                        if hasattr(finding.severity, "value")
                        else str(finding.severity)
                    ),
                    description=finding.description,
                    line_number=finding.line_number,
                    code_snippet=finding.code_snippet,
                    explanation=finding.description,
                    recommendation=getattr(
                        finding, "remediation", "Review and fix this vulnerability"
                    ),
                    confidence=finding.confidence,
                    file_path=file_name,
                    cwe_id=getattr(finding, "cwe_id", None),
                    owasp_category=getattr(finding, "owasp_category", None),
                )
                findings.append(llm_finding)

            return findings

        except Exception as e:
            logger.error(f"Code analysis with context failed: {e}")
            # Fallback to legacy analysis
            return await self._analyze_code_async(
                code_content, file_name, language, max_findings
            )
        finally:
            if session and self.session_manager:
                self.session_manager.close_session(session.session_id)

    def _find_project_root(self, file_path: Path) -> Path:
        """Find project root by looking for common project indicators."""
        current = file_path.parent
        while current.parent != current:
            if any(
                (current / indicator).exists()
                for indicator in [
                    ".git",
                    "package.json",
                    "pyproject.toml",
                    "requirements.txt",
                    ".project",
                ]
            ):
                return current
            current = current.parent
        # Fallback to file's parent directory
        return file_path.parent

    async def _perform_session_analysis(
        self, session_id: str, max_findings: int
    ) -> list[LLMSecurityFinding]:
        """Perform comprehensive security analysis using the session."""
        all_session_findings = []

        # Phase 1: General security analysis
        findings = await self.session_manager.analyze_with_session(
            session_id=session_id,
            analysis_query="""
Perform a comprehensive security analysis of this codebase. Look for:

1. Authentication and authorization vulnerabilities
2. Input validation issues and injection flaws
3. Cross-site scripting (XSS) vulnerabilities
4. Cross-site request forgery (CSRF) issues
5. SQL injection and database security
6. File upload and path traversal vulnerabilities
7. Session management issues
8. Cryptographic implementation problems
9. Information disclosure risks
10. Business logic flaws

Focus on real, exploitable vulnerabilities with high confidence.
""",
        )
        all_session_findings.extend(findings)

        # Phase 2: Architectural analysis (if we have findings to build on)
        # When max_findings is None (unlimited), always do architectural analysis
        threshold = (max_findings // 2) if max_findings is not None else 25
        if len(all_session_findings) < threshold:
            arch_findings = await self.session_manager.continue_analysis(
                session_id=session_id,
                follow_up_query="""
Now analyze the overall architecture for security issues:

1. Are there any trust boundary violations?
2. How does data flow between components - any risks?
3. Are authentication/authorization consistently applied?
4. Any privilege escalation opportunities?
5. Configuration and deployment security issues?
6. Third-party dependency risks?

Focus on systemic and architectural vulnerabilities.
""",
            )
            all_session_findings.extend(arch_findings)

        # Convert session findings to LLMSecurityFinding objects
        llm_findings = []
        for finding in all_session_findings:
            llm_finding = LLMSecurityFinding(
                finding_type=finding.rule_id,
                severity=(
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity)
                ),
                description=finding.description,
                line_number=finding.line_number,
                code_snippet=finding.code_snippet,
                explanation=finding.description,
                recommendation=getattr(
                    finding, "remediation", "Review and fix this vulnerability"
                ),
                confidence=finding.confidence,
                file_path=getattr(finding, "file_path", ""),
                cwe_id=getattr(finding, "cwe_id", None),
                owasp_category=getattr(finding, "owasp_category", None),
            )
            llm_findings.append(llm_finding)

        return llm_findings

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
            "session_aware_available": self.is_session_aware_available(),
        }
        logger.debug(f"Returning stats: {stats}")
        return stats
