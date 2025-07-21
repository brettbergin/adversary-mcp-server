"""Semgrep scanner for static code analysis and vulnerability detection."""

import json
import logging
import os
import subprocess
import tempfile
from typing import Any

from .threat_engine import Category, Language, Severity, ThreatEngine, ThreatMatch

logger = logging.getLogger(__name__)


class SemgrepError(Exception):
    """Exception raised when Semgrep scanning fails."""

    pass


class SemgrepScanner:
    """Scanner that uses Semgrep for static code analysis."""

    def __init__(self, threat_engine: ThreatEngine):
        """Initialize Semgrep scanner.

        Args:
            threat_engine: ThreatEngine instance for result formatting
        """
        self.threat_engine = threat_engine
        self._semgrep_available = self._check_semgrep_available()

    def _check_semgrep_available(self) -> bool:
        """Check if Semgrep is available in the system.

        Returns:
            True if Semgrep is available, False otherwise
        """
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            logger.warning("Semgrep not found in PATH. Semgrep scanning disabled.")
            return False

    def is_available(self) -> bool:
        """Check if Semgrep scanning is available.

        Returns:
            True if Semgrep is available, False otherwise
        """
        return self._semgrep_available

    def _get_semgrep_env(self) -> dict[str, str]:
        """Get environment variables for Semgrep execution.

        Returns:
            Environment variables including SEMGREP_APP_TOKEN if available
        """
        env = os.environ.copy()

        # Check for Semgrep App token for Pro features
        if "SEMGREP_APP_TOKEN" in env:
            logger.info("Semgrep App token detected - using Pro features")
        else:
            logger.info("Using free Semgrep version")

        return env

    def _map_semgrep_severity(self, severity: str) -> Severity:
        """Map Semgrep severity to our Severity enum.

        Args:
            severity: Semgrep severity string

        Returns:
            Mapped Severity enum value
        """
        severity_lower = severity.lower()
        if severity_lower in ("error", "critical"):
            return Severity.CRITICAL
        elif severity_lower == "warning":
            return Severity.HIGH
        elif severity_lower == "info":
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _map_semgrep_category(self, rule_id: str, message: str) -> Category:
        """Map Semgrep finding to our Category enum.

        Args:
            rule_id: Semgrep rule identifier
            message: Semgrep finding message

        Returns:
            Mapped Category enum value
        """
        rule_id_lower = rule_id.lower()

        # Security category mappings based on common Semgrep rule patterns
        if any(keyword in rule_id_lower for keyword in ["sql", "injection", "sqli"]):
            return Category.INJECTION
        elif any(keyword in rule_id_lower for keyword in ["xss", "cross-site"]):
            return Category.XSS
        elif any(keyword in rule_id_lower for keyword in ["auth", "jwt", "token"]):
            return Category.AUTHENTICATION
        elif any(keyword in rule_id_lower for keyword in ["crypto", "hash", "encrypt"]):
            return Category.CRYPTOGRAPHY
        elif any(
            keyword in rule_id_lower for keyword in ["path", "traversal", "directory"]
        ):
            return Category.PATH_TRAVERSAL
        elif any(
            keyword in rule_id_lower for keyword in ["rce", "command", "exec", "eval"]
        ):
            return Category.RCE
        elif any(keyword in rule_id_lower for keyword in ["ssrf", "request"]):
            return Category.SSRF
        elif any(
            keyword in rule_id_lower for keyword in ["deserial", "pickle", "yaml"]
        ):
            return Category.DESERIALIZATION
        elif any(keyword in rule_id_lower for keyword in ["secret", "key", "password"]):
            return Category.SECRETS
        elif any(
            keyword in rule_id_lower for keyword in ["csrf", "cross-site-request"]
        ):
            return Category.CSRF
        elif any(keyword in rule_id_lower for keyword in ["dos", "denial", "regex"]):
            return Category.DOS
        elif any(
            keyword in rule_id_lower for keyword in ["config", "debug", "setting"]
        ):
            return Category.CONFIGURATION
        elif any(keyword in rule_id_lower for keyword in ["log", "logging"]):
            return Category.LOGGING
        elif any(keyword in rule_id_lower for keyword in ["valid", "input", "sanitiz"]):
            return Category.VALIDATION
        else:
            # Default category for security findings
            return Category.VALIDATION

    def _convert_semgrep_finding_to_threat(
        self, finding: dict[str, Any], file_path: str
    ) -> ThreatMatch:
        """Convert a Semgrep finding to ThreatMatch format.

        Args:
            finding: Semgrep finding dictionary
            file_path: Path to the file being scanned

        Returns:
            ThreatMatch instance
        """
        rule_id = finding.get("check_id", "semgrep-unknown")
        message = finding.get("message", "Security issue detected by Semgrep")
        # Extract severity from multiple possible locations in semgrep output
        severity_str = (
            finding.get("metadata", {}).get("severity")
            or finding.get("extra", {}).get("severity")
            or finding.get("severity")
            or "info"  # Default fallback
        )
        severity = self._map_semgrep_severity(severity_str)
        category = self._map_semgrep_category(rule_id, message)

        # Extract location information
        start_line = finding.get("start", {}).get("line", 1)

        # Extract code snippet
        code_snippet = finding.get("extra", {}).get("lines", "")
        if not code_snippet:
            # Fallback to message if no code snippet available
            code_snippet = message

        # Build references
        references = []
        if "metadata" in finding and "references" in finding["metadata"]:
            references = finding["metadata"]["references"]

        # Handle CWE ID - convert list to string
        cwe_data = finding.get("metadata", {}).get("cwe", [])
        cwe_id = cwe_data[0] if isinstance(cwe_data, list) and cwe_data else None

        return ThreatMatch(
            rule_id=f"semgrep-{rule_id}",
            rule_name=f"Semgrep: {rule_id}",
            description=message,
            category=category,
            severity=severity,
            file_path=file_path,
            line_number=start_line,
            code_snippet=code_snippet,
            confidence=0.9,  # High confidence for Semgrep findings
            remediation=finding.get("metadata", {}).get("fix", ""),
            references=references,
            cwe_id=cwe_id,
            owasp_category=finding.get("metadata", {}).get("owasp", ""),
            source="semgrep",  # Semgrep scanner
        )

    def scan_code(
        self,
        source_code: str,
        file_path: str,
        language: Language,
        config: str | None = None,
        rules: str | None = None,
        timeout: int = 60,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan source code using Semgrep.

        Args:
            source_code: Source code to scan
            file_path: Path to the file (for context)
            language: Programming language
            config: Semgrep config to use (default: auto)
            rules: Specific rules to use
            timeout: Timeout in seconds
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            List of ThreatMatch instances

        Raises:
            SemgrepError: If Semgrep scanning fails
        """
        if not self._semgrep_available:
            logger.warning("Semgrep not available, skipping Semgrep scan")
            return []

        try:
            # Create temporary file for scanning
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=self._get_file_extension(language),
                delete=False,
            ) as tmp_file:
                tmp_file.write(source_code)
                tmp_file_path = tmp_file.name

            try:
                # Build Semgrep command
                cmd = ["semgrep", "--json", "--quiet"]

                # Add configuration
                if config:
                    cmd.extend(["--config", config])
                elif rules:
                    cmd.extend(["--config", rules])
                else:
                    # Use auto config for security rules
                    cmd.extend(["--config", "auto"])

                # Add target file
                cmd.append(tmp_file_path)

                # Execute Semgrep
                env = self._get_semgrep_env()
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                )

                # Parse results
                threats = []
                if result.stdout:
                    try:
                        semgrep_output = json.loads(result.stdout)
                        findings = semgrep_output.get("results", [])

                        for finding in findings:
                            try:
                                threat = self._convert_semgrep_finding_to_threat(
                                    finding, file_path
                                )
                                threats.append(threat)
                            except Exception as e:
                                logger.warning(
                                    f"Failed to convert Semgrep finding: {e}"
                                )

                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse Semgrep JSON output: {e}")

                # Log any errors from stderr
                if result.stderr:
                    logger.debug(f"Semgrep stderr: {result.stderr}")

                # Apply severity filtering if specified
                if severity_threshold:
                    threats = self._filter_by_severity(threats, severity_threshold)

                logger.info(f"Semgrep found {len(threats)} security issues")
                return threats

            finally:
                # Clean up temporary file
                try:
                    os.unlink(tmp_file_path)
                except OSError:
                    pass

        except subprocess.TimeoutExpired:
            raise SemgrepError(f"Semgrep scan timed out after {timeout} seconds")
        except Exception as e:
            raise SemgrepError(f"Semgrep scan failed: {e}")

    def scan_file(
        self,
        file_path: str,
        language: Language,
        config: str | None = None,
        rules: str | None = None,
        timeout: int = 60,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan a file using Semgrep.

        Args:
            file_path: Path to file to scan
            language: Programming language
            config: Semgrep config to use
            rules: Specific rules to use
            timeout: Timeout in seconds
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            List of ThreatMatch instances

        Raises:
            SemgrepError: If file scanning fails
        """
        if not self._semgrep_available:
            logger.warning("Semgrep not available, skipping Semgrep scan")
            return []

        try:
            # Read file content
            with open(file_path, encoding="utf-8") as f:
                source_code = f.read()

            return self.scan_code(
                source_code=source_code,
                file_path=file_path,
                language=language,
                config=config,
                rules=rules,
                timeout=timeout,
                severity_threshold=severity_threshold,
            )

        except Exception as e:
            raise SemgrepError(f"Failed to scan file {file_path}: {e}")

    def _get_file_extension(self, language: Language) -> str:
        """Get appropriate file extension for language.

        Args:
            language: Programming language

        Returns:
            File extension including dot
        """
        extension_map = {
            Language.PYTHON: ".py",
            Language.JAVASCRIPT: ".js",
            Language.TYPESCRIPT: ".ts",
        }
        return extension_map.get(language, ".txt")

    def _filter_by_severity(
        self,
        threats: list[ThreatMatch],
        min_severity: Severity,
    ) -> list[ThreatMatch]:
        """Filter threats by minimum severity level.

        Args:
            threats: List of threats to filter
            min_severity: Minimum severity level

        Returns:
            Filtered list of threats
        """
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

    def scan_directory(
        self,
        directory_path: str,
        config: str | None = None,
        rules: str | None = None,
        timeout: int = 120,
        recursive: bool = True,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan entire directory using Semgrep efficiently.

        Args:
            directory_path: Path to directory to scan
            config: Semgrep config to use (default: auto)
            rules: Specific rules to use
            timeout: Timeout in seconds (default: 120 for directories)
            recursive: Whether to scan subdirectories
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            List of ThreatMatch instances for all files in directory

        Raises:
            SemgrepError: If directory scanning fails
        """
        if not self._semgrep_available:
            logger.warning("Semgrep not available, skipping Semgrep directory scan")
            return []

        try:
            # Build Semgrep command for directory scanning
            cmd = ["semgrep", "--json", "--quiet"]

            # Add configuration
            if config:
                cmd.extend(["--config", config])
            elif rules:
                cmd.extend(["--config", rules])
            else:
                # Use auto config for comprehensive scanning
                cmd.extend(["--config", "auto"])

            # Add directory path
            cmd.append(directory_path)

            logger.info(f"Running Semgrep directory scan: {' '.join(cmd)}")

            # Run Semgrep on entire directory
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,  # Don't raise on non-zero exit
            )

            # Parse results
            if result.stdout:
                try:
                    semgrep_output = json.loads(result.stdout)
                    findings = semgrep_output.get("results", [])

                    logger.info(
                        f"Semgrep found {len(findings)} security issues in directory"
                    )

                    threats = []
                    for finding in findings:
                        try:
                            # Extract file path from Semgrep finding
                            finding_file_path = finding.get("path", "unknown")
                            threat = self._convert_semgrep_finding_to_threat(
                                finding, finding_file_path
                            )
                            threats.append(threat)
                        except Exception as e:
                            logger.warning(
                                f"Failed to convert Semgrep finding to threat: {e}"
                            )
                            continue

                    # Apply severity filtering if specified
                    if severity_threshold:
                        threats = self._filter_by_severity(threats, severity_threshold)

                    return threats

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Semgrep JSON output: {e}")
                    return []
            else:
                logger.info("Semgrep found 0 security issues in directory")
                return []

        except subprocess.TimeoutExpired:
            raise SemgrepError(
                f"Semgrep directory scan timed out after {timeout} seconds"
            )
        except Exception as e:
            raise SemgrepError(f"Semgrep directory scan failed: {e}")
