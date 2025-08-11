"""LLM-based security analyzer for detecting code vulnerabilities using AI."""

import asyncio
import json
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
    max_findings: int = field(
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
    """LLM-based security scanner that uses AI for vulnerability detection."""

    def __init__(
        self,
        credential_manager: CredentialManager,
        cache_manager: CacheManager | None = None,
        metrics_collector=None,
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
                strategy=BatchStrategy.DYNAMIC_SIZE,
                min_batch_size=1,
                max_batch_size=max_batch_size,
                target_tokens_per_batch=target_tokens,
                max_tokens_per_batch=max_tokens,
                batch_timeout_seconds=self.config_manager.dynamic_limits.batch_timeout_seconds,
                max_concurrent_batches=self.config_manager.dynamic_limits.max_concurrent_batches,
                group_by_language=True,
                group_by_complexity=True,
            )
            self.batch_processor = BatchProcessor(batch_config, self.metrics_collector)
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
        logger.info(f"Creating analysis prompt for {file_path_abs} ({language})")
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
            logger.debug("Attempting to parse response as JSON")
            data = json.loads(clean_response)
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

        prompt = f"""Analyze the following {language} code for security vulnerabilities:

```{language}
{source_code}
```

Please provide up to {max_findings} security findings in JSON format.

Requirements:
- Focus on genuine security vulnerabilities
- Provide specific line numbers (1-indexed, exactly as they appear in the source code)
- Include the vulnerable code snippet
- Explain why each finding is a security risk
- Suggest specific remediation steps
- Assign confidence scores (0.0-1.0)
- Map to CWE IDs where applicable
- Classify by OWASP categories where relevant
- IMPORTANT: Line numbers must match the exact line numbers in the provided source code (1-indexed)

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
        language: str,
        max_findings: int = 20,
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
        max_findings: int = 20,
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
                        source_code, language, max_findings
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
            user_prompt = self._create_user_prompt(source_code, language, max_findings)

            logger.debug(f"Sending analysis request to LLM for {file_path}")

            # Make LLM request with comprehensive error handling and circuit breaker
            async def llm_call():
                return await self.llm_client.complete_with_retry(
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
        max_findings: int = 20,
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
        max_findings_per_file: int = 20,
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
        max_findings_per_file: int = 20,
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
        max_findings_per_file: int = 20,
    ) -> list[LLMSecurityFinding]:
        """Analyze a batch of files efficiently with advanced optimization.

        Args:
            file_paths: List of file paths to analyze
            max_findings_per_file: Maximum findings per file

        Returns:
            List of security findings across all files in batch
        """
        if not self.llm_client:
            return []

        logger.info(f"Starting optimized batch analysis for {len(file_paths)} files")

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
                batch_content, max_findings_per_file, 0
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
        async def batch_operation():
            response = await self.llm_client.complete_with_retry(
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

        for file_info in batch_content:
            try:
                file_findings = await self._analyze_code_async(
                    file_info["content"],
                    file_info["file_path"],
                    file_info["language"],
                    max_findings_per_file,
                )
                findings.extend(file_findings)

            except Exception as e:
                logger.warning(
                    f"Individual analysis failed for {file_info['file_path']}: {e}"
                )

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
                f"```{file_info['language']}\n{file_info['content']}\n```"
            )

        prompt_parts.append(
            f"\n\nProvide up to {max_findings_per_file} security findings per file."
        )
        prompt_parts.append(
            """
Requirements:
- Focus on genuine security vulnerabilities
- Provide specific line numbers (1-indexed, exactly as they appear in the source code)
- Include the vulnerable code snippet
- IMPORTANT: Line numbers must match the exact line numbers in the provided source code (1-indexed)

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
            data = json.loads(clean_response)
            findings = []

            for finding_data in data.get("findings", []):
                try:
                    # Ensure file_path is included in finding
                    file_path = finding_data.get("file_path", "")
                    if not file_path and batch_content:
                        # Default to first file if not specified
                        file_path = batch_content[0]["file_path"]

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
        total_findings_limit = max_findings_per_file * total_files

        prompt_parts.append(
            f"""\n\n## Analysis Requirements

Provide up to {total_findings_limit} security findings total (max {max_findings_per_file} per file).

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
            data = json.loads(clean_response)
            findings = []

            # Extract summary information if available
            summary = data.get("analysis_summary", {})
            if summary:
                logger.info(f"Batch analysis summary: {summary}")

            for finding_data in data.get("findings", []):
                try:
                    # Validate file_path is in the batch
                    file_path = finding_data.get("file_path", "")
                    if not any(fc["file_path"] == file_path for fc in batch_content):
                        # Try to match by filename if full path doesn't match
                        file_name = (
                            file_path.split("/")[-1] if "/" in file_path else file_path
                        )
                        matched_file = None
                        for fc in batch_content:
                            if fc["file_path"].endswith(file_name):
                                matched_file = fc["file_path"]
                                break

                        if matched_file:
                            file_path = matched_file
                            logger.debug(
                                f"Matched file by name: {file_name} -> {file_path}"
                            )
                        else:
                            logger.warning(
                                f"Finding references unknown file: {file_path}"
                            )
                            continue

                    # Enhanced validation
                    line_number = max(1, int(finding_data.get("line_number", 1)))
                    confidence = max(
                        0.0, min(1.0, float(finding_data.get("confidence", 0.5)))
                    )

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
        max_findings_per_sample: int = 20,
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
