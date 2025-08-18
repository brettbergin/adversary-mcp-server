import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from ..cache import CacheKey, CacheManager, CacheType
from ..cache.config_tracker import ConfigurationTracker
from ..config import get_app_cache_dir
from ..config_manager import get_config_manager
from ..credentials import CredentialManager
from ..logger import get_logger
from ..resilience import ErrorHandler, ResilienceConfig
from .language_mapping import LanguageMapper
from .types import Category, Severity, ThreatMatch

logger = get_logger("semgrep_scanner")


class SemgrepError(Exception):
    """Custom exception for Semgrep-related errors."""

    pass


# Module-level availability check for compatibility
try:
    import subprocess

    # First priority: Check the virtual environment where this Python is running
    python_exe_path = Path(sys.executable)
    venv_semgrep = python_exe_path.parent / "semgrep"

    possible_paths = [str(venv_semgrep), "semgrep"]

    _SEMGREP_AVAILABLE = False
    for semgrep_path in possible_paths:
        try:
            result = subprocess.run(
                [semgrep_path, "--version"], capture_output=True, timeout=5
            )
            if result.returncode == 0:
                _SEMGREP_AVAILABLE = True
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

except (OSError, subprocess.SubprocessError, PermissionError) as e:
    logger.debug(f"Error checking semgrep availability: {e}")
    _SEMGREP_AVAILABLE = False


class OptimizedSemgrepScanner:
    """Optimized Semgrep scanner using async subprocess for MCP servers."""

    def __init__(
        self,
        config: str = "auto",
        cache_ttl: int = 300,
        threat_engine=None,
        credential_manager: CredentialManager | None = None,
        cache_manager: CacheManager | None = None,
        metrics_collector=None,
    ):
        """Initialize scanner.

        Args:
            config: Semgrep config to use
            cache_ttl: Cache time-to-live in seconds (default 5 minutes)
            threat_engine: Threat engine (for compatibility, unused)
            credential_manager: Credential manager for configuration
            cache_manager: Optional advanced cache manager
            metrics_collector: Optional metrics collector for performance tracking
        """
        self.config = config
        self.cache_ttl = cache_ttl
        self._semgrep_path = None

        self.threat_engine = threat_engine
        self.credential_manager = credential_manager
        self.cache_manager = cache_manager
        self.metrics_collector = metrics_collector
        self.config_manager = get_config_manager()

        # Initialize advanced cache manager if not provided
        if cache_manager is None and self.credential_manager is not None:
            try:
                config_obj = self.credential_manager.load_config()
                if config_obj.enable_caching:
                    cache_dir = get_app_cache_dir()
                    self.cache_manager = CacheManager(
                        cache_dir=cache_dir,
                        max_size_mb=self.config_manager.dynamic_limits.cache_max_size_mb,
                        max_age_hours=self.config_manager.dynamic_limits.cache_max_age_hours,
                    )
                    logger.info(
                        f"Initialized advanced cache manager for Semgrep at {cache_dir}"
                    )
            except (OSError, ValueError, ImportError) as e:
                logger.warning(
                    "Failed to initialize advanced cache manager - caching disabled for semgrep",
                    extra={
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "cache_dir": str(cache_dir),
                        "performance_impact": "medium",
                        "component": "semgrep_scanner",
                    },
                )

        # Initialize ErrorHandler for Semgrep resilience
        resilience_config = ResilienceConfig(
            enable_circuit_breaker=True,
            failure_threshold=self.config_manager.dynamic_limits.circuit_breaker_failure_threshold,
            recovery_timeout_seconds=self.config_manager.dynamic_limits.circuit_breaker_recovery_timeout,
            enable_retry=True,
            max_retry_attempts=max(
                1, self.config_manager.dynamic_limits.max_retry_attempts - 1
            ),  # Conservative retries for subprocess calls
            base_delay_seconds=self.config_manager.dynamic_limits.retry_base_delay,
            enable_graceful_degradation=True,
        )
        self.error_handler = ErrorHandler(resilience_config)
        logger.info("Initialized ErrorHandler for Semgrep resilience")

        # Initialize configuration tracker for cache invalidation
        self.config_tracker = None
        if self.cache_manager:
            try:
                self.config_tracker = ConfigurationTracker(self.cache_manager)
                logger.info("Initialized configuration tracker for cache invalidation")
            except Exception as e:
                logger.warning(f"Failed to initialize configuration tracker: {e}")

        # Initialize pro user status tracking
        self._pro_status = {
            "is_pro_user": None,  # None = unknown, True/False = determined
            "subscription_type": None,
            "user_id": None,
            "rules_available": 0,
            "authentication_status": "unknown",
            "last_updated": None,
        }

    def _extract_and_store_pro_status(self, semgrep_result: dict[str, Any]) -> None:
        """Extract pro user information from Semgrep API response."""
        try:
            import time

            # Check for user information in response
            user_info = semgrep_result.get("user", {})
            errors = semgrep_result.get("errors", [])

            # Update pro status based on response
            if user_info:
                subscription = user_info.get("subscription_type", "").lower()
                self._pro_status.update(
                    {
                        "is_pro_user": subscription in ["pro", "team", "enterprise"],
                        "subscription_type": subscription,
                        "user_id": user_info.get("id"),
                        "authentication_status": "authenticated",
                        "last_updated": int(time.time()),
                    }
                )
            elif any("auth" in str(error).lower() for error in errors):
                self._pro_status.update(
                    {
                        "is_pro_user": False,
                        "authentication_status": "failed",
                        "last_updated": int(time.time()),
                    }
                )
            else:
                # No user info but no auth errors = likely anonymous/free
                self._pro_status.update(
                    {
                        "is_pro_user": False,
                        "authentication_status": "anonymous",
                        "last_updated": int(time.time()),
                    }
                )

            # Count available rules if present
            rules = semgrep_result.get("rules", [])
            if rules:
                self._pro_status["rules_available"] = len(rules)

            logger.debug(f"Updated Semgrep pro status: {self._pro_status}")

        except Exception as e:
            logger.warning(
                f"Failed to extract pro user status from Semgrep response: {e}"
            )

    def get_pro_status(self) -> dict[str, Any]:
        """Get current pro user status information."""
        return self._pro_status.copy()

    async def validate_api_token(self) -> dict[str, Any]:
        """Test API token validity by calling Semgrep with authentication info.

        Returns:
            Dictionary with validation results including auth status and user info
        """
        try:
            semgrep_path = await self._find_semgrep()

            # Use a simple command that requires authentication to test the token
            cmd = [
                semgrep_path,
                "--version",
                "--json",
            ]

            # Run with API token environment
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._get_clean_env(),
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            finally:
                if proc.returncode is None:
                    try:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                    except (TimeoutError, ProcessLookupError):
                        pass

            if proc.returncode == 0:
                # Try to get user info with a minimal scan command
                test_cmd = [
                    semgrep_path,
                    "--config=auto",
                    "--json",
                    "--dryrun",  # Don't actually run rules
                    "--no-git-ignore",
                ]

                # Create a temporary test input
                test_proc = await asyncio.create_subprocess_exec(
                    *test_cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=self._get_clean_env(),
                )

                try:
                    test_stdout, test_stderr = await asyncio.wait_for(
                        test_proc.communicate(input=b"print('test')"), timeout=15
                    )
                finally:
                    if test_proc.returncode is None:
                        try:
                            test_proc.terminate()
                            await asyncio.wait_for(test_proc.wait(), timeout=5.0)
                        except (TimeoutError, ProcessLookupError):
                            pass

                # Parse response for authentication info
                validation_result = {
                    "valid": True,
                    "semgrep_available": True,
                    "authentication_status": "unknown",
                    "user_type": "unknown",
                    "error_message": None,
                }

                if test_proc.returncode == 0:
                    try:
                        result = json.loads(test_stdout.decode())
                        self._extract_and_store_pro_status(result)
                        pro_status = self.get_pro_status()

                        validation_result.update(
                            {
                                "authentication_status": pro_status[
                                    "authentication_status"
                                ],
                                "user_type": (
                                    "pro" if pro_status["is_pro_user"] else "free"
                                ),
                                "subscription_type": pro_status.get(
                                    "subscription_type"
                                ),
                                "rules_available": pro_status.get("rules_available", 0),
                            }
                        )
                    except json.JSONDecodeError:
                        validation_result["authentication_status"] = (
                            "response_parse_error"
                        )
                else:
                    error_msg = test_stderr.decode() if test_stderr else "Unknown error"
                    if "auth" in error_msg.lower() or "token" in error_msg.lower():
                        validation_result.update(
                            {
                                "authentication_status": "failed",
                                "user_type": "unauthenticated",
                                "error_message": error_msg,
                            }
                        )
                    else:
                        validation_result["error_message"] = error_msg

                logger.info(f"API token validation complete: {validation_result}")
                return validation_result

            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.warning(
                    f"Semgrep not available for token validation: {error_msg}"
                )
                return {
                    "valid": False,
                    "semgrep_available": False,
                    "authentication_status": "semgrep_unavailable",
                    "error_message": error_msg,
                }

        except Exception as e:
            logger.error(f"API token validation failed: {e}")
            return {
                "valid": False,
                "semgrep_available": False,
                "authentication_status": "validation_error",
                "error_message": str(e),
            }

    async def _find_semgrep(self) -> str:
        """Find semgrep executable path (cached)."""
        if self._semgrep_path:
            return self._semgrep_path

        # First priority: Check the virtual environment where this Python is running
        python_exe_path = Path(sys.executable)
        venv_semgrep = python_exe_path.parent / "semgrep"

        # Check common locations, prioritizing current virtual environment
        possible_paths = [
            str(venv_semgrep),  # Same venv as current Python
            "semgrep",  # PATH
            ".venv/bin/semgrep",  # local venv (relative)
            "/usr/local/bin/semgrep",  # homebrew
            "/opt/homebrew/bin/semgrep",  # ARM homebrew
        ]

        for path in possible_paths:
            try:
                proc = await asyncio.create_subprocess_exec(
                    path,
                    "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                    if proc.returncode == 0:
                        self._semgrep_path = path
                        logger.info(f"Found Semgrep at: {path}")
                        return path
                finally:
                    # Ensure process is terminated
                    if proc.returncode is None:
                        try:
                            proc.terminate()
                            await proc.wait()
                        except ProcessLookupError:
                            pass
            except (TimeoutError, FileNotFoundError):
                continue

        raise RuntimeError("Semgrep not found in PATH or common locations")

    def _map_semgrep_severity(self, severity: str) -> Severity:
        """Map Semgrep severity to our severity enum."""
        severity_lower = severity.lower()

        if severity_lower == "error" or severity_lower == "critical":
            return Severity.CRITICAL
        elif severity_lower == "warning" or severity_lower == "high":
            return Severity.HIGH
        elif severity_lower == "info" or severity_lower == "medium":
            return Severity.MEDIUM
        elif severity_lower == "low":
            return Severity.LOW
        else:
            return Severity.LOW

    def _map_semgrep_category(self, rule_id: str, message: str) -> Category:
        """Map Semgrep rule to our category enum based on rule ID and message."""
        # Convert to lowercase for easier matching
        rule_lower = rule_id.lower()
        message_lower = message.lower()
        combined = f"{rule_lower} {message_lower}"

        # Security category mapping based on common patterns
        if any(keyword in combined for keyword in ["sql", "injection", "sqli"]):
            return Category.INJECTION
        elif any(keyword in combined for keyword in ["xss", "cross-site", "script"]):
            return Category.XSS
        elif any(
            keyword in combined for keyword in ["auth", "login", "password", "jwt"]
        ):
            return Category.AUTHENTICATION
        elif any(keyword in combined for keyword in ["crypto", "hash", "encrypt"]):
            return Category.CRYPTOGRAPHY
        elif any(keyword in combined for keyword in ["deserial", "pickle", "unpack"]):
            return Category.DESERIALIZATION
        elif any(keyword in combined for keyword in ["ssrf", "request-forgery"]):
            return Category.SSRF
        elif any(keyword in combined for keyword in ["path", "traversal", "directory"]):
            return Category.PATH_TRAVERSAL
        elif any(keyword in combined for keyword in ["csrf", "cross-site-request"]):
            return Category.CSRF
        elif any(
            keyword in combined
            for keyword in ["rce", "code-execution", "command", "eval", "execute"]
        ):
            return Category.RCE
        elif any(keyword in combined for keyword in ["dos", "denial-of-service"]):
            return Category.DOS
        elif any(
            keyword in combined for keyword in ["secret", "key", "token", "credential"]
        ):
            return Category.SECRETS
        elif any(keyword in combined for keyword in ["config", "setting"]):
            return Category.CONFIGURATION
        elif any(keyword in combined for keyword in ["valid", "input", "sanitiz"]):
            return Category.VALIDATION
        elif any(keyword in combined for keyword in ["log", "trace"]):
            return Category.LOGGING
        else:
            return Category.VALIDATION

    def _convert_semgrep_finding_to_threat(
        self, finding: dict[str, Any], file_path: str
    ) -> ThreatMatch:
        """Convert a Semgrep finding to a ThreatMatch."""
        try:
            # Extract basic information
            rule_id = finding.get("check_id", "semgrep_unknown")

            # Add debug logging to understand actual Semgrep JSON structure
            logger.debug(
                f"Processing Semgrep finding: rule_id={rule_id}, keys={list(finding.keys())}"
            )

            # Improve message extraction - try multiple possible locations
            message = (
                finding.get("message")
                or finding.get("extra", {}).get("message")
                or finding.get("metadata", {}).get("message")
                or self._create_descriptive_message_from_rule_id(rule_id)
            )

            # Extract location information
            start_info = finding.get("start", {})
            line_number = start_info.get("line", 1)
            column_number = start_info.get("col", 1)

            # Extract code snippet
            lines = finding.get("extra", {}).get("lines", "")
            code_snippet = lines.strip() if lines else ""

            # Map severity and category
            semgrep_severity = (
                finding.get("metadata", {}).get("severity")
                or finding.get("extra", {}).get("severity")
                or finding.get("severity", "WARNING")
            )

            severity = self._map_semgrep_severity(semgrep_severity)
            category = self._map_semgrep_category(rule_id, message)

            # Calculate dynamic confidence score
            confidence = self._calculate_confidence_score(
                rule_id=rule_id,
                severity=severity,
                category=category,
                code_snippet=code_snippet,
                file_path=file_path,
            )

            # Create threat match
            threat = ThreatMatch(
                rule_id=f"semgrep-{rule_id}",
                rule_name=f"Semgrep: {rule_id}",
                description=message,
                category=category,
                severity=severity,
                file_path=file_path,
                line_number=line_number,
                column_number=column_number,
                code_snippet=code_snippet,
                confidence=confidence,
                source="semgrep",
            )

            # Add metadata if available
            metadata = finding.get("metadata") or finding.get("extra", {}).get(
                "metadata"
            )
            if metadata:
                # Extract CWE if available
                if "cwe" in metadata:
                    cwe_data = metadata["cwe"]
                    if isinstance(cwe_data, list):
                        threat.cwe_id = cwe_data[0] if cwe_data else None
                    else:
                        threat.cwe_id = cwe_data
                # Extract OWASP category if available
                if "owasp" in metadata:
                    threat.owasp_category = metadata["owasp"]
                # Extract references if available
                if "references" in metadata:
                    threat.references = metadata["references"]

            return threat

        except Exception as e:
            # Return a minimal threat match for failed conversions
            return ThreatMatch(
                rule_id="semgrep_conversion_error",
                rule_name="Semgrep Finding Conversion Error",
                description=f"Failed to convert Semgrep finding: {str(e)}",
                category=Category.MISC,
                severity=Severity.LOW,
                file_path=file_path,
                line_number=1,
                source="semgrep",
            )

    def _filter_by_severity(
        self, threats: list[ThreatMatch], min_severity: Severity
    ) -> list[ThreatMatch]:
        """Filter threats by minimum severity level."""
        severity_order = [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        min_index = severity_order.index(min_severity)

        return [
            threat
            for threat in threats
            if severity_order.index(threat.severity) >= min_index
        ]

    async def scan_code(
        self,
        source_code: str,
        file_path: str,
        language: str,
        config: str | None = None,
        rules: str | None = None,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan source code for vulnerabilities with optimizations.

        Args:
            source_code: The source code to scan
            file_path: Logical file path (for reporting)
            language: Programming language
            config: Semgrep config to use (ignored, uses instance config)
            rules: Custom rules string or file path (ignored)
            severity_threshold: Minimum severity threshold

        Returns:
            List of ThreatMatch objects
        """
        # Check for configuration changes and invalidate cache if needed
        if self.config_tracker:
            current_config = {
                "semgrep_config": config or self.config,
                "rules": rules,
                "severity_threshold": (
                    severity_threshold.value if severity_threshold else None
                ),
            }
            self.config_tracker.check_and_invalidate_on_config_change(current_config)

        # Check cache first
        cached_threats = await self._get_cached_scan_result(
            source_code, file_path, language, config, rules, severity_threshold
        )
        if cached_threats is not None:
            logger.debug(f"Cache hit for {file_path}")
            return cached_threats

        # Perform scan with resilience protection
        start_time = time.time()

        # Define the scan operation for resilience handling
        async def scan_operation():
            language_str = language
            raw_findings = await self._perform_scan(
                source_code, file_path, language_str
            )
            return raw_findings

        # Define fallback function for graceful degradation
        async def scan_fallback(*args, **kwargs):
            logger.warning(
                "Semgrep service degraded - static security analysis unavailable",
                extra={
                    "file_path": file_path,
                    "file_size": len(source_code) if source_code else 0,
                    "scan_type": "code_analysis",
                    "fallback_action": "returning_empty_results",
                    "security_impact": "high",
                    "component": "semgrep_scanner",
                },
            )
            return []

        # Execute scan with comprehensive error recovery
        recovery_result = await self.error_handler.execute_with_recovery(
            scan_operation,
            operation_name=f"semgrep_scan_{Path(file_path).name}",
            circuit_breaker_name="semgrep_service",
            fallback_func=scan_fallback,
        )

        if recovery_result.success:
            raw_findings = recovery_result.result
        else:
            # Fallback was used or complete failure
            raw_findings = recovery_result.result or []

        scan_time = time.time() - start_time
        logger.info(f"Code scan completed in {scan_time:.2f}s for {file_path}")

        # Record scan metrics
        if self.metrics_collector:
            self.metrics_collector.record_histogram(
                "semgrep_scan_duration_seconds",
                scan_time,
                labels={"operation": "code", "language": language},
            )
            self.metrics_collector.record_metric(
                "semgrep_scans_total",
                1,
                labels={
                    "operation": "code",
                    "status": "success" if recovery_result.success else "fallback",
                },
            )
            self.metrics_collector.record_metric(
                "semgrep_findings_total",
                len(raw_findings),
                labels={"operation": "code", "language": language},
            )

        # Convert raw findings to ThreatMatch objects
        threats = []
        for finding in raw_findings:
            try:
                threat = self._convert_semgrep_finding_to_threat(finding, file_path)
                threats.append(threat)
            except Exception as e:
                logger.warning(f"Failed to convert finding to threat: {e}")

        # Apply severity filtering if specified
        if severity_threshold:
            threats = self._filter_by_severity(threats, severity_threshold)

        # Cache the final processed results only if not from fallback
        if not getattr(recovery_result, "fallback_used", False):
            await self._cache_scan_result(
                threats,
                source_code,
                file_path,
                language,
                config,
                rules,
                severity_threshold,
            )
        else:
            logger.warning(
                f"Scan used fallback for {file_path}, skipping cache to prevent corruption"
            )

        return threats

    async def scan_file(
        self,
        file_path: str,
        language: str,
        config: str | None = None,
        rules: str | None = None,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan a file using the optimized Semgrep approach.

        Args:
            file_path: Path to the file to scan
            language: Programming language
            config: Semgrep config to use (ignored, uses instance config)
            rules: Custom rules string or file path (ignored)
            severity_threshold: Minimum severity threshold

        Returns:
            List of detected threats
        """
        # Check for configuration changes and invalidate cache if needed
        if self.config_tracker:
            current_config = {
                "semgrep_config": config or self.config,
                "rules": rules,
                "severity_threshold": (
                    severity_threshold.value if severity_threshold else None
                ),
            }
            self.config_tracker.check_and_invalidate_on_config_change(current_config)

        # Check if Semgrep is available first (return empty if not available)
        if not self.is_available():
            return []

        # Check if file exists (only when Semgrep is available)
        if not os.path.isfile(file_path):
            raise SemgrepError(f"File not found: {file_path}")

        try:
            # Read file content
            with open(file_path, encoding="utf-8") as f:
                source_code = f.read()
        except UnicodeDecodeError:
            # Skip binary files
            return []

        # Check cache first
        cached_threats = await self._get_cached_scan_result(
            source_code, file_path, language, config, rules, severity_threshold
        )
        if cached_threats is not None:
            logger.debug(f"Cache hit for {file_path}")
            return cached_threats

        # Perform scan with resilience protection
        start_time = time.time()

        # Define the scan operation for resilience handling
        async def scan_operation():
            language_str = language
            raw_findings = await self._perform_scan(
                source_code, file_path, language_str
            )
            return raw_findings

        # Define fallback function for graceful degradation
        async def scan_fallback(*args, **kwargs):
            logger.warning(
                f"Semgrep service degraded during file scan, returning empty results for {file_path}"
            )
            return []

        # Execute scan with comprehensive error recovery
        recovery_result = await self.error_handler.execute_with_recovery(
            scan_operation,
            operation_name=f"semgrep_file_scan_{Path(file_path).name}",
            circuit_breaker_name="semgrep_service",
            fallback_func=scan_fallback,
        )

        if recovery_result.success:
            raw_findings = recovery_result.result
        else:
            # Fallback was used or complete failure
            raw_findings = recovery_result.result or []

        scan_time = time.time() - start_time
        logger.info(f"File scan completed in {scan_time:.2f}s for {file_path}")

        # Record scan metrics
        if self.metrics_collector:
            self.metrics_collector.record_histogram(
                "semgrep_scan_duration_seconds",
                scan_time,
                labels={"operation": "file", "language": language},
            )
            self.metrics_collector.record_metric(
                "semgrep_scans_total",
                1,
                labels={
                    "operation": "file",
                    "status": "success" if recovery_result.success else "fallback",
                },
            )
            self.metrics_collector.record_metric(
                "semgrep_findings_total",
                len(raw_findings),
                labels={"operation": "file", "language": language},
            )

        # Convert raw findings to ThreatMatch objects
        threats = []
        for finding in raw_findings:
            try:
                threat = self._convert_semgrep_finding_to_threat(finding, file_path)
                threats.append(threat)
            except Exception as e:
                logger.warning(f"Failed to convert finding to threat: {e}")

        # Apply severity filtering if specified
        if severity_threshold:
            threats = self._filter_by_severity(threats, severity_threshold)

        # Cache the final processed results only if not from fallback
        if not getattr(recovery_result, "fallback_used", False):
            await self._cache_scan_result(
                threats,
                source_code,
                file_path,
                language,
                config,
                rules,
                severity_threshold,
            )
        else:
            logger.warning(
                f"Scan used fallback for {file_path}, skipping cache to prevent corruption"
            )

        return threats

    async def scan_directory(
        self,
        directory_path: str,
        config: str | None = None,
        rules: str | None = None,
        recursive: bool = True,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan a directory using the optimized Semgrep approach.

        Args:
            directory_path: Path to the directory to scan
            config: Semgrep config to use (ignored, uses instance config)
            rules: Custom rules string or file path (ignored)
            recursive: Whether to scan recursively (always True with Semgrep)
            severity_threshold: Minimum severity threshold

        Returns:
            List of detected threats across all files
        """
        # Check for configuration changes and invalidate cache if needed
        if self.config_tracker:
            current_config = {
                "semgrep_config": config or self.config,
                "rules": rules,
                "severity_threshold": (
                    severity_threshold.value if severity_threshold else None
                ),
            }
            self.config_tracker.check_and_invalidate_on_config_change(current_config)

        # Check if Semgrep is available first (return empty if not available)
        if not self.is_available():
            return []

        # Check if directory exists (only when Semgrep is available)
        if not os.path.isdir(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # Check cache first
        cached_threats = await self._get_cached_scan_result(
            directory_path,
            directory_path,
            "directory",
            config,
            rules,
            severity_threshold,
        )
        if cached_threats is not None:
            logger.debug(f"Cache hit for directory {directory_path}")
            return cached_threats

        # Perform scan with resilience protection
        start_time = time.time()

        # Define the scan operation for resilience handling
        async def scan_operation():
            raw_findings = await self._perform_directory_scan(directory_path, recursive)
            return raw_findings

        # Define fallback function for graceful degradation
        async def scan_fallback(*args, **kwargs):
            logger.warning(
                f"Semgrep service degraded during directory scan, returning empty results for {directory_path}"
            )
            return []

        # Execute scan with comprehensive error recovery
        recovery_result = await self.error_handler.execute_with_recovery(
            scan_operation,
            operation_name=f"semgrep_dir_scan_{Path(directory_path).name}",
            circuit_breaker_name="semgrep_service",
            fallback_func=scan_fallback,
        )

        if recovery_result.success:
            raw_findings = recovery_result.result
        else:
            # Fallback was used or complete failure
            raw_findings = recovery_result.result or []

        scan_time = time.time() - start_time
        logger.info(
            f"Directory scan completed in {scan_time:.2f}s for {directory_path}"
        )

        # Convert raw findings to ThreatMatch objects
        threats = []
        files_with_findings = set()

        for finding in raw_findings:
            try:
                file_path = finding.get("path", directory_path)
                files_with_findings.add(file_path)
                threat = self._convert_semgrep_finding_to_threat(finding, file_path)
                threats.append(threat)
            except Exception as e:
                logger.warning(f"Failed to convert finding to threat: {e}")

        logger.info(f"Findings span {len(files_with_findings)} file(s)")

        # Apply severity filtering if specified
        if severity_threshold:
            before_count = len(threats)
            threats = self._filter_by_severity(threats, severity_threshold)
            logger.info(f"Severity filtering: {before_count} → {len(threats)} threats")

        # Cache the final processed results only if not from fallback
        if not getattr(recovery_result, "fallback_used", False):
            await self._cache_scan_result(
                threats,
                directory_path,
                directory_path,
                "directory",
                config,
                rules,
                severity_threshold,
            )
        else:
            logger.warning(
                f"Scan used fallback for {directory_path}, skipping cache to prevent corruption"
            )

        return threats

    def _get_directory_hash(self, directory_path: str) -> str:
        """Generate hash for directory (based on modification time)."""
        try:
            # Use directory modification time as a simple hash
            stat = os.stat(directory_path)
            mtime = stat.st_mtime
            return hashlib.sha256(f"{directory_path}:{mtime}".encode()).hexdigest()
        except OSError:
            # Fallback to current timestamp
            return hashlib.sha256(
                f"{directory_path}:{time.time()}".encode()
            ).hexdigest()

    async def _perform_scan(
        self, source_code: str, file_path: str, language: str | None
    ) -> list[dict[str, Any]]:
        """Perform the actual scan using async subprocess with streaming support."""

        # Find semgrep executable
        semgrep_path = await self._find_semgrep()

        # For large content, try stdin streaming first, fallback to temp file
        use_stdin = len(source_code) > 50000  # Use stdin for content > 50KB

        if use_stdin:
            logger.debug("Using stdin streaming for large content")
            return await self._perform_scan_stdin(source_code, file_path, language)
        else:
            logger.debug("Using temp file for small content")
            return await self._perform_scan_tempfile(source_code, file_path, language)

    async def _perform_scan_stdin(
        self, source_code: str, file_path: str, language: str | None
    ) -> list[dict[str, Any]]:
        """Perform scan using stdin streaming."""
        semgrep_path = await self._find_semgrep()

        # Get file extension for language detection
        extension = Path(file_path).suffix or self._get_extension_for_language(language)

        try:
            # Prepare command for stdin input
            cmd = [
                semgrep_path,
                f"--config={self.config}",
                "--json",
                "--quiet",
                "--disable-version-check",
                "--exclude=**/adversary.*",
                "--exclude=**/.adversary.*",
                "-",  # Read from stdin
            ]

            # Only add --lang for pattern-based scanning, not config-based scanning
            # Config-based scanning (like --config=auto) auto-detects language

            # Run scan with stdin
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._get_clean_env(),
            )

            # Write to stdin and wait for completion
            try:
                stdout, stderr = await proc.communicate(
                    input=source_code.encode("utf-8")
                )
            finally:
                # Ensure process is terminated
                if proc.returncode is None:
                    try:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                    except (TimeoutError, ProcessLookupError):
                        pass

            if proc.returncode == 0:
                # Parse results
                result = json.loads(stdout.decode())
                findings = result.get("results", [])

                # Extract and store pro user information
                self._extract_and_store_pro_status(result)

                # Update file paths to logical path
                for finding in findings:
                    finding["path"] = file_path

                return findings
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.warning(f"Semgrep stdin scan failed: {error_msg}")
                return []

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep stdin output: {e}")
            return []
        except Exception as e:
            logger.error(f"Stdin scan failed: {e}")
            return []

    async def _perform_scan_tempfile(
        self, source_code: str, file_path: str, language: str | None
    ) -> list[dict[str, Any]]:
        """Perform scan using temporary file (fallback method)."""
        semgrep_path = await self._find_semgrep()

        # Create temp file with proper extension
        extension = Path(file_path).suffix or self._get_extension_for_language(language)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=extension, delete=False
        ) as temp_file:
            temp_file.write(source_code)
            temp_file_path = temp_file.name

        try:
            # Prepare command
            cmd = [
                semgrep_path,
                f"--config={self.config}",
                "--json",
                "--quiet",  # Reduce output noise
                "--disable-version-check",  # Faster startup
                "--exclude=**/adversary.*",
                "--exclude=**/.adversary.*",
                temp_file_path,
            ]

            # Run scan with async subprocess
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._get_clean_env(),
            )

            # Wait for completion
            try:
                stdout, stderr = await proc.communicate()
            finally:
                # Ensure process is terminated
                if proc.returncode is None:
                    try:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                    except (TimeoutError, ProcessLookupError):
                        pass

            if proc.returncode == 0:
                # Parse results
                result = json.loads(stdout.decode())
                findings = result.get("results", [])

                # Extract and store pro user information
                self._extract_and_store_pro_status(result)

                # Update file paths to logical path
                for finding in findings:
                    finding["path"] = file_path

                return findings
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                return []

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            return []

        finally:
            # Clean up temp file
            try:
                os.unlink(temp_file_path)
            except OSError:
                pass

    async def _perform_directory_scan(
        self, directory_path: str, recursive: bool = True
    ) -> list[dict[str, Any]]:
        """Perform directory scan using async subprocess with Semgrep's native directory support."""

        # Find semgrep executable
        semgrep_path = await self._find_semgrep()

        try:
            # Prepare command for directory scanning
            cmd = [
                semgrep_path,
                f"--config={self.config}",
                "--json",
                "--quiet",  # Reduce output noise
                "--disable-version-check",  # Faster startup
                "--exclude=**/adversary.*",
                "--exclude=**/.adversary.*",
            ]

            # Add recursive flag if needed (Semgrep is recursive by default)
            if not recursive:
                cmd.append("--max-depth=1")

            # Add the directory path
            cmd.append(directory_path)

            # Run scan with async subprocess
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._get_clean_env(),
            )

            # Wait for completion
            try:
                stdout, stderr = await proc.communicate()
            finally:
                # Ensure process is terminated
                if proc.returncode is None:
                    try:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                    except (TimeoutError, ProcessLookupError):
                        pass

            if proc.returncode == 0:
                # Parse results
                result = json.loads(stdout.decode())
                findings = result.get("results", [])

                # Extract and store pro user information
                self._extract_and_store_pro_status(result)

                logger.info(f"Semgrep found {len(findings)} findings in directory")
                return findings
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                return []

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            return []

    def _get_extension_for_language(self, language: str | None) -> str:
        """Get file extension for language using shared language mapper.

        Args:
            language: Programming language identifier

        Returns:
            File extension for the language, or '.txt' for unknown languages
        """
        return LanguageMapper.get_extension_for_language(language)

    def _calculate_confidence_score(
        self,
        rule_id: str,
        severity: Severity,
        category: Category,
        code_snippet: str,
        file_path: str,
    ) -> float:
        """Calculate dynamic confidence score for a Semgrep finding.

        Args:
            rule_id: Semgrep rule identifier
            severity: Finding severity
            code_snippet: Code snippet containing the finding
            file_path: Path to the file with the finding

        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = 0.7  # Start with reasonable base confidence

        # Adjust based on rule quality indicators
        if "experimental" in rule_id.lower():
            base_confidence -= 0.2
        elif "owasp" in rule_id.lower() or "cwe" in rule_id.lower():
            base_confidence += 0.1
        elif "security" in rule_id.lower():
            base_confidence += 0.05

        # Adjust based on severity (higher severity = higher confidence in rule quality)
        severity_adjustments = {
            Severity.CRITICAL: 0.15,
            Severity.HIGH: 0.1,
            Severity.MEDIUM: 0.05,
            Severity.LOW: -0.05,
        }
        base_confidence += severity_adjustments.get(severity, 0.0)

        # Adjust based on category reliability
        high_confidence_categories = {
            Category.INJECTION,
            Category.AUTHENTICATION,
            Category.CRYPTO,
            Category.SECRETS,
            Category.RCE,
        }
        if category in high_confidence_categories:
            base_confidence += 0.1

        # Context-based adjustments
        if code_snippet:
            # More confidence if we have actual code context
            base_confidence += 0.05

            # Higher confidence for common vulnerable patterns
            vulnerable_patterns = [
                "password",
                "secret",
                "key",
                "token",
                "sql",
                "exec",
                "eval",
                "system",
                "shell",
                "md5",
                "sha1",
            ]
            if any(pattern in code_snippet.lower() for pattern in vulnerable_patterns):
                base_confidence += 0.05

        # File context adjustments
        if file_path:
            # Higher confidence for security-critical file patterns
            critical_paths = [
                "auth",
                "login",
                "security",
                "admin",
                "config",
                "password",
                "key",
                "secret",
                "api",
            ]
            if any(pattern in file_path.lower() for pattern in critical_paths):
                base_confidence += 0.05

        # Ensure confidence stays within valid range
        return max(0.1, min(0.95, base_confidence))

    def _get_clean_env(self) -> dict[str, str]:
        """Get clean environment for subprocess using credential manager."""
        env = os.environ.copy()

        # Remove potentially conflicting vars
        for key in list(env.keys()):
            if key.startswith("SEMGREP_") and "METRICS" in key:
                del env[key]

        # Set optimizations
        env["SEMGREP_USER_AGENT_APPEND"] = "adversary-mcp-server"

        # Set API token from credential manager or preserve environment token
        if self.credential_manager:
            try:
                api_key = self.credential_manager.get_semgrep_api_key()
                if api_key:
                    env["SEMGREP_APP_TOKEN"] = api_key
                else:
                    # If credential manager exists but returns None, remove env token
                    # This indicates the credential manager wants no token to be used
                    env.pop("SEMGREP_APP_TOKEN", None)
            except Exception:
                # If credential manager fails, preserve existing environment token
                pass
        # If no credential manager, preserve existing environment token (if any)

        return env

    def clear_cache(self):
        """Clear the result cache."""
        if self.cache_manager:
            self.cache_manager.clear()
            logger.info("Cache cleared")
        else:
            logger.warning("No cache manager available to clear")

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        if self.cache_manager:
            return self.cache_manager.get_stats().to_dict()
        else:
            return {
                "cache_size": 0,
                "cache_ttl": self.cache_ttl,
                "entries": [],
                "error": "No cache manager available",
            }

    def is_available(self) -> bool:
        """Check if Semgrep is available (compatibility method)."""
        # Respect the module-level availability check (handles both normal operation and test mocking)
        # When _SEMGREP_AVAILABLE is True (either naturally or mocked), return True
        # When _SEMGREP_AVAILABLE is False (either naturally or mocked), return False
        return _SEMGREP_AVAILABLE

    def get_status(self) -> dict[str, Any]:
        """Get Semgrep status information (compatibility method)."""
        # Use the same virtual environment detection logic
        python_exe_path = Path(sys.executable)
        venv_semgrep = python_exe_path.parent / "semgrep"

        possible_paths = [str(venv_semgrep), "semgrep"]

        for semgrep_path in possible_paths:
            try:
                import subprocess

                result = subprocess.run(
                    [semgrep_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    version = result.stdout.strip()
                    return {
                        "available": True,
                        "version": version,
                        "installation_status": "available",
                        "has_pro_features": False,  # Conservative assumption
                        "semgrep_path": semgrep_path,
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        # If no semgrep found in any location
        return {
            "available": False,
            "error": "Semgrep not found in PATH",
            "installation_status": "not_installed",
            "installation_guidance": "Install semgrep: pip install semgrep",
        }

    def _get_semgrep_env_info(self) -> dict[str, Any]:
        """Get Semgrep environment information using credential manager."""
        has_token = False
        if self.credential_manager:
            has_token = self.credential_manager.get_semgrep_api_key() is not None

        return {
            "has_token": "true" if has_token else "false",
            "semgrep_user_agent": "adversary-mcp-server",
        }

    def _get_file_extension(self, language: str) -> str:
        """Get file extension for language (compatibility method)."""
        return self._get_extension_for_language(language)

    def _extension_to_language(self, extension: str) -> str:
        """Convert file extension to Semgrep language identifier using shared mapper.

        Args:
            extension: File extension (e.g., '.py', '.js')

        Returns:
            Semgrep language identifier, defaults to 'generic' for unknown extensions
        """
        return LanguageMapper.detect_language_from_extension(extension)

    async def _get_cached_scan_result(
        self,
        source_code: str,
        file_path: str,
        language: str,
        config: str | None,
        rules: str | None,
        severity_threshold: Severity | None,
    ) -> list[ThreatMatch] | None:
        """Get cached scan result using advanced cache manager."""
        if not self.cache_manager:
            return None

        try:
            config_obj = self.credential_manager.load_config()
            if not config_obj.enable_caching:
                return None

            hasher = self.cache_manager.get_hasher()

            # Create cache key based on content and scan parameters
            content_hash = hasher.hash_content(source_code)
            scan_context = {
                "file_path": file_path,
                "language": language,
                "semgrep_config": config or self.config,
                "custom_rules": rules,
                "severity_threshold": (
                    severity_threshold.value if severity_threshold else None
                ),
            }
            metadata_hash = hasher.hash_semgrep_context(
                content=source_code,
                language=language,
                rules=[rules] if rules else None,
                config_path=config or self.config,
            )

            cache_key = CacheKey(
                cache_type=CacheType.SEMGREP_RESULT,
                content_hash=content_hash,
                metadata_hash=metadata_hash,
            )

            cached_data = self.cache_manager.get(cache_key)
            if cached_data and isinstance(cached_data, list):
                # Deserialize cached threat matches
                threats = []
                for threat_data in cached_data:
                    if isinstance(threat_data, dict):
                        # Reconstruct ThreatMatch from cached data
                        threat = ThreatMatch(
                            rule_id=threat_data.get("rule_id", ""),
                            rule_name=threat_data.get("rule_name", ""),
                            description=threat_data.get("description", ""),
                            category=Category(threat_data.get("category", "MISC")),
                            severity=Severity(threat_data.get("severity", "MEDIUM")),
                            file_path=threat_data.get("file_path", file_path),
                            line_number=threat_data.get("line_number", 0),
                            code_snippet=threat_data.get("code_snippet", ""),
                            confidence=threat_data.get("confidence", 1.0),
                            cwe_id=threat_data.get("cwe_id"),
                            owasp_category=threat_data.get("owasp_category"),
                            source=threat_data.get("source", "semgrep"),
                        )
                        threats.append(threat)
                return threats

        except Exception as e:
            logger.warning(f"Failed to retrieve cached Semgrep result: {e}")

        return None

    def _create_descriptive_message_from_rule_id(self, rule_id: str) -> str:
        """Create a descriptive message from the Semgrep rule ID when message is missing.

        Args:
            rule_id: The Semgrep rule identifier

        Returns:
            A human-readable description based on the rule ID
        """
        if not rule_id or rule_id == "semgrep_unknown":
            return "Semgrep security finding"

        # Try to extract meaningful parts from the rule ID
        rule_parts = rule_id.split(".")

        # Look for common security patterns in rule ID
        if "dangerous-eval" in rule_id:
            return "Dangerous use of eval() function detected"
        elif "sql-injection" in rule_id or "sqli" in rule_id:
            return "Potential SQL injection vulnerability detected"
        elif "xss" in rule_id or "cross-site" in rule_id:
            return "Potential cross-site scripting (XSS) vulnerability detected"
        elif "hardcoded" in rule_id and (
            "password" in rule_id or "secret" in rule_id or "key" in rule_id
        ):
            return "Hardcoded secret or credential detected"
        elif "command-injection" in rule_id or "code-injection" in rule_id:
            return "Potential command/code injection vulnerability detected"
        elif "path-traversal" in rule_id or "directory-traversal" in rule_id:
            return "Potential path traversal vulnerability detected"
        elif "crypto" in rule_id and "weak" in rule_id:
            return "Weak cryptographic implementation detected"
        elif "auth" in rule_id or "authentication" in rule_id:
            return "Authentication security issue detected"
        elif "csrf" in rule_id:
            return "Potential CSRF vulnerability detected"
        elif "ssrf" in rule_id:
            return "Potential SSRF vulnerability detected"
        elif "deserialization" in rule_id or "pickle" in rule_id:
            return "Insecure deserialization detected"
        elif "regex" in rule_id and ("dos" in rule_id or "redos" in rule_id):
            return "Regular expression denial of service (ReDoS) detected"
        else:
            # Generic fallback based on rule structure
            if len(rule_parts) >= 2:
                # Extract the last meaningful part of the rule name
                rule_name = rule_parts[-1].replace("-", " ").replace("_", " ").title()
                return f"Security issue detected: {rule_name}"
            else:
                return f"Security issue detected by rule: {rule_id}"

    async def _cache_scan_result(
        self,
        threats: list[ThreatMatch],
        source_code: str,
        file_path: str,
        language: str,
        config: str | None,
        rules: str | None,
        severity_threshold: Severity | None,
    ) -> None:
        """Cache scan result using advanced cache manager."""
        if not self.cache_manager:
            return

        try:
            config_obj = self.credential_manager.load_config()
            if not config_obj.enable_caching:
                return

            hasher = self.cache_manager.get_hasher()

            # Create same cache key as used for retrieval
            content_hash = hasher.hash_content(source_code)
            scan_context = {
                "file_path": file_path,
                "language": language,
                "semgrep_config": config or self.config,
                "custom_rules": rules,
                "severity_threshold": (
                    severity_threshold.value if severity_threshold else None
                ),
            }
            metadata_hash = hasher.hash_semgrep_context(
                content=source_code,
                language=language,
                rules=[rules] if rules else None,
                config_path=config or self.config,
            )

            cache_key = CacheKey(
                cache_type=CacheType.SEMGREP_RESULT,
                content_hash=content_hash,
                metadata_hash=metadata_hash,
            )

            # Serialize threats for caching
            serialized_threats = []
            for threat in threats:
                threat_data = {
                    "rule_id": threat.rule_id,
                    "rule_name": threat.rule_name,
                    "description": threat.description,
                    "category": threat.category.value,
                    "severity": threat.severity.value,
                    "file_path": threat.file_path,
                    "line_number": threat.line_number,
                    "code_snippet": threat.code_snippet,
                    "confidence": threat.confidence,
                    "cwe_id": threat.cwe_id,
                    "owasp_category": threat.owasp_category,
                    "source": threat.source,
                }
                serialized_threats.append(threat_data)

            # Cache for longer duration than LLM responses (Semgrep results are more stable)
            cache_expiry_seconds = (
                config_obj.cache_max_age_hours * 3600
            )  # Full duration
            self.cache_manager.put(cache_key, serialized_threats, cache_expiry_seconds)

            logger.debug(f"Cached Semgrep scan result for {file_path}")

        except Exception as e:
            logger.warning(f"Failed to cache Semgrep scan result: {e}")


# Compatibility alias for existing code
SemgrepScanner = OptimizedSemgrepScanner
