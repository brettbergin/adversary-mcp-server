import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Import necessary types for compatibility
from .types import Category, Language, Severity, ThreatMatch


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

except Exception:
    _SEMGREP_AVAILABLE = False


@dataclass
class ScanResult:
    """Cached scan result."""

    findings: list[dict[str, Any]]
    timestamp: float
    file_hash: str


class OptimizedSemgrepScanner:
    """Optimized Semgrep scanner using async subprocess for MCP servers."""

    def __init__(
        self,
        config: str = "auto",
        cache_ttl: int = 300,
        threat_engine=None,
        credential_manager=None,
    ):
        """Initialize scanner.

        Args:
            config: Semgrep config to use
            cache_ttl: Cache time-to-live in seconds (default 5 minutes)
            threat_engine: Threat engine (for compatibility, unused)
            credential_manager: Credential manager (for compatibility, unused)
        """
        self.config = config
        self.cache_ttl = cache_ttl
        self._cache: dict[str, ScanResult] = {}
        self._semgrep_path = None

        # Store for compatibility with old interface
        self.threat_engine = threat_engine
        self.credential_manager = credential_manager

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
                await asyncio.wait_for(proc.wait(), timeout=5)
                if proc.returncode == 0:
                    self._semgrep_path = path
                    print(f"🔍 Found Semgrep at: {path}")
                    return path
            except (FileNotFoundError, asyncio.TimeoutError):
                continue

        raise RuntimeError("Semgrep not found in PATH or common locations")

    def _get_cache_key(
        self, source_code: str, file_path: str, language: str | None
    ) -> str:
        """Generate cache key for scan."""
        content = f"{source_code}|{file_path}|{language}|{self.config}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_file_hash(self, source_code: str) -> str:
        """Generate hash for file content."""
        return hashlib.sha256(source_code.encode()).hexdigest()

    def _is_cache_valid(self, result: ScanResult, current_hash: str) -> bool:
        """Check if cached result is still valid."""
        current_time = time.time()
        return (
            current_time - result.timestamp < self.cache_ttl
            and result.file_hash == current_hash
        )

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
            message = finding.get("message", "Semgrep security finding")

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
                confidence=0.9,  # Semgrep findings are generally high confidence
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
        language: Language,
        config: str | None = None,
        rules: str | None = None,
        timeout: int = 60,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan source code for vulnerabilities with optimizations.

        Args:
            source_code: The source code to scan
            file_path: Logical file path (for reporting)
            language: Programming language
            config: Semgrep config to use (ignored, uses instance config)
            rules: Custom rules string or file path (ignored)
            timeout: Timeout in seconds
            severity_threshold: Minimum severity threshold

        Returns:
            List of ThreatMatch objects
        """
        # Check cache first
        cache_key = self._get_cache_key(source_code, file_path, language.value)
        file_hash = self._get_file_hash(source_code)

        if cache_key in self._cache:
            cached_result = self._cache[cache_key]
            if self._is_cache_valid(cached_result, file_hash):
                print(f"📋 Cache hit for {file_path}")
                # Convert cached findings to ThreatMatch objects
                threats = []
                for finding in cached_result.findings:
                    threat = self._convert_semgrep_finding_to_threat(finding, file_path)
                    threats.append(threat)

                # Apply severity filtering if specified
                if severity_threshold:
                    threats = self._filter_by_severity(threats, severity_threshold)

                return threats

        # Perform scan directly
        start_time = time.time()
        try:
            language_str = (
                language.value if hasattr(language, "value") else str(language)
            )
            raw_findings = await self._perform_scan(
                source_code, file_path, language_str, timeout
            )
            scan_time = time.time() - start_time
            print(f"⚡ Code scan completed in {scan_time:.2f}s for {file_path}")

            # Cache the raw findings
            self._cache[cache_key] = ScanResult(
                findings=raw_findings, timestamp=time.time(), file_hash=file_hash
            )

            # Convert raw findings to ThreatMatch objects
            threats = []
            for finding in raw_findings:
                try:
                    threat = self._convert_semgrep_finding_to_threat(finding, file_path)
                    threats.append(threat)
                except Exception as e:
                    print(f"Warning: Failed to convert finding to threat: {e}")

            # Apply severity filtering if specified
            if severity_threshold:
                threats = self._filter_by_severity(threats, severity_threshold)

            return threats

        except Exception as e:
            scan_time = time.time() - start_time
            print(f"❌ Code scan failed after {scan_time:.2f}s: {e}")
            return []

    async def scan_file(
        self,
        file_path: str,
        language: Language,
        config: str | None = None,
        rules: str | None = None,
        timeout: int = 60,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan a file using the optimized Semgrep approach.

        Args:
            file_path: Path to the file to scan
            language: Programming language
            config: Semgrep config to use (ignored, uses instance config)
            rules: Custom rules string or file path (ignored)
            timeout: Timeout in seconds
            severity_threshold: Minimum severity threshold

        Returns:
            List of detected threats
        """
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

        # Check cache first (independent caching for file scans)
        cache_key = self._get_cache_key(source_code, file_path, language.value)
        file_hash = self._get_file_hash(source_code)

        if cache_key in self._cache:
            cached_result = self._cache[cache_key]
            if self._is_cache_valid(cached_result, file_hash):
                print(f"📋 Cache hit for {file_path}")
                # Convert cached findings to ThreatMatch objects
                threats = []
                for finding in cached_result.findings:
                    threat = self._convert_semgrep_finding_to_threat(finding, file_path)
                    threats.append(threat)

                # Apply severity filtering if specified
                if severity_threshold:
                    threats = self._filter_by_severity(threats, severity_threshold)

                return threats

        # Perform scan directly (independent of scan_code)
        start_time = time.time()
        try:
            language_str = (
                language.value if hasattr(language, "value") else str(language)
            )
            raw_findings = await self._perform_scan(
                source_code, file_path, language_str, timeout
            )
            scan_time = time.time() - start_time
            print(f"⚡ File scan completed in {scan_time:.2f}s for {file_path}")

            # Cache the raw findings
            self._cache[cache_key] = ScanResult(
                findings=raw_findings, timestamp=time.time(), file_hash=file_hash
            )

            # Convert raw findings to ThreatMatch objects
            threats = []
            for finding in raw_findings:
                try:
                    threat = self._convert_semgrep_finding_to_threat(finding, file_path)
                    threats.append(threat)
                except Exception as e:
                    print(f"Warning: Failed to convert finding to threat: {e}")

            # Apply severity filtering if specified
            if severity_threshold:
                threats = self._filter_by_severity(threats, severity_threshold)

            return threats

        except Exception as e:
            scan_time = time.time() - start_time
            print(f"❌ File scan failed after {scan_time:.2f}s: {e}")
            return []

    async def scan_directory(
        self,
        directory_path: str,
        config: str | None = None,
        rules: str | None = None,
        timeout: int = 120,
        recursive: bool = True,
        severity_threshold: Severity | None = None,
    ) -> list[ThreatMatch]:
        """Scan a directory using the optimized Semgrep approach.

        Args:
            directory_path: Path to the directory to scan
            config: Semgrep config to use (ignored, uses instance config)
            rules: Custom rules string or file path (ignored)
            timeout: Timeout in seconds
            recursive: Whether to scan recursively (always True with Semgrep)
            severity_threshold: Minimum severity threshold

        Returns:
            List of detected threats across all files
        """
        # Check if Semgrep is available first (return empty if not available)
        if not self.is_available():
            return []

        # Check if directory exists (only when Semgrep is available)
        if not os.path.isdir(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # Check cache first (use directory path as key)
        cache_key = self._get_cache_key("", directory_path, "directory")
        # For directories, we use modification time as a simple hash
        dir_hash = self._get_directory_hash(directory_path)

        if cache_key in self._cache:
            cached_result = self._cache[cache_key]
            if self._is_cache_valid(cached_result, dir_hash):
                print(f"📋 Cache hit for directory {directory_path}")
                # Convert cached findings to ThreatMatch objects
                threats = []
                for finding in cached_result.findings:
                    file_path = finding.get("path", directory_path)
                    threat = self._convert_semgrep_finding_to_threat(finding, file_path)
                    threats.append(threat)

                # Apply severity filtering if specified
                if severity_threshold:
                    threats = self._filter_by_severity(threats, severity_threshold)

                return threats

        # Perform scan directly on directory (independent of other scan methods)
        start_time = time.time()
        try:
            raw_findings = await self._perform_directory_scan(
                directory_path, timeout, recursive
            )
            scan_time = time.time() - start_time
            print(
                f"⚡ Directory scan completed in {scan_time:.2f}s for {directory_path}"
            )

            # Cache the raw findings
            self._cache[cache_key] = ScanResult(
                findings=raw_findings, timestamp=time.time(), file_hash=dir_hash
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
                    print(f"Warning: Failed to convert finding to threat: {e}")

            print(f"📊 Findings span {len(files_with_findings)} file(s)")

            # Apply severity filtering if specified
            if severity_threshold:
                before_count = len(threats)
                threats = self._filter_by_severity(threats, severity_threshold)
                print(f"🔽 Severity filtering: {before_count} → {len(threats)} threats")

            return threats

        except Exception as e:
            scan_time = time.time() - start_time
            print(f"❌ Directory scan failed after {scan_time:.2f}s: {e}")
            return []

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
        self, source_code: str, file_path: str, language: str | None, timeout: int
    ) -> list[dict[str, Any]]:
        """Perform the actual scan using async subprocess."""

        # Find semgrep executable
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
                temp_file_path,
            ]

            # Run scan with async subprocess
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._get_clean_env(),
            )

            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            if proc.returncode == 0:
                # Parse results
                result = json.loads(stdout.decode())
                findings = result.get("results", [])

                # Update file paths to logical path
                for finding in findings:
                    finding["path"] = file_path

                return findings
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                return []

        except asyncio.TimeoutError:
            print(f"⏰ Scan timed out after {timeout}s")
            if proc:
                proc.kill()
                await proc.wait()
            return []

        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse Semgrep output: {e}")
            return []

        finally:
            # Clean up temp file
            try:
                os.unlink(temp_file_path)
            except OSError:
                pass

    async def _perform_directory_scan(
        self, directory_path: str, timeout: int, recursive: bool = True
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

            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            if proc.returncode == 0:
                # Parse results
                result = json.loads(stdout.decode())
                findings = result.get("results", [])

                print(f"🔍 Semgrep found {len(findings)} findings in directory")
                return findings
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                return []

        except asyncio.TimeoutError:
            print(f"⏰ Directory scan timed out after {timeout}s")
            if proc:
                proc.kill()
                await proc.wait()
            return []

        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse Semgrep output: {e}")
            return []

    def _get_extension_for_language(self, language: str | None) -> str:
        """Get file extension for language."""
        if not language:
            return ".py"

        ext_map = {
            "python": ".py",
            "javascript": ".js",
            "typescript": ".ts",
            "java": ".java",
            "go": ".go",
            "php": ".php",
            "ruby": ".rb",
            "c": ".c",
            "cpp": ".cpp",
            "csharp": ".cs",
        }
        return ext_map.get(language.lower(), ".py")

    def _get_clean_env(self) -> dict[str, str]:
        """Get clean environment for subprocess using credential manager."""
        env = os.environ.copy()

        # Remove potentially conflicting vars
        for key in list(env.keys()):
            if key.startswith("SEMGREP_") and "METRICS" in key:
                del env[key]

        # Set optimizations
        env["SEMGREP_USER_AGENT_APPEND"] = "adversary-mcp-server"

        # Set API token from credential manager (remove env var fallback)
        if self.credential_manager:
            api_key = self.credential_manager.get_semgrep_api_key()
            if api_key:
                env["SEMGREP_APP_TOKEN"] = api_key
            else:
                # Remove any existing env var token to force credential manager usage
                env.pop("SEMGREP_APP_TOKEN", None)

        return env

    def clear_cache(self):
        """Clear the result cache."""
        self._cache.clear()
        print("🗑️Cache cleared")

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {
            "cache_size": len(self._cache),
            "cache_ttl": self.cache_ttl,
            "entries": [
                {
                    "key": key[:16] + "...",
                    "findings_count": len(result.findings),
                    "age_seconds": time.time() - result.timestamp,
                }
                for key, result in self._cache.items()
            ],
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

    def _get_file_extension(self, language: Language) -> str:
        """Get file extension for language (compatibility method)."""
        return self._get_extension_for_language(
            language.value if hasattr(language, "value") else str(language)
        )


# Compatibility alias for existing code
SemgrepScanner = OptimizedSemgrepScanner
