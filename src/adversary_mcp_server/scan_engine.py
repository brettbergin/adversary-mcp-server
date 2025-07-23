"""Enhanced scanner that combines AST-based rules with LLM analysis for comprehensive security scanning."""

from pathlib import Path
from typing import Any

from .ast_scanner import ASTScanner
from .credential_manager import CredentialManager
from .false_positive_manager import FalsePositiveManager
from .llm_scanner import LLMScanner
from .logging_config import get_logger
from .semgrep_scanner import SemgrepScanner
from .threat_engine import (
    Language,
    LanguageSupport,
    Severity,
    ThreatEngine,
    ThreatMatch,
)

logger = get_logger("scan_engine")


class EnhancedScanResult:
    """Result of enhanced scanning combining rules and LLM analysis."""

    def __init__(
        self,
        file_path: str,
        language: Language,
        rules_threats: list[ThreatMatch],
        llm_threats: list[ThreatMatch],
        semgrep_threats: list[ThreatMatch],
        scan_metadata: dict[str, Any],
    ):
        """Initialize enhanced scan result.

        Args:
            file_path: Path to the scanned file
            language: Programming language
            rules_threats: Threats found by rules engine
            llm_threats: Threats found by LLM analysis
            semgrep_threats: Threats found by Semgrep analysis
            scan_metadata: Metadata about the scan
        """
        self.file_path = file_path
        self.language = language
        self.rules_threats = rules_threats
        self.llm_threats = llm_threats
        self.semgrep_threats = semgrep_threats
        self.scan_metadata = scan_metadata

        # Combine and deduplicate threats
        self.all_threats = self._combine_threats()

        # Calculate statistics
        self.stats = self._calculate_stats()

    def _combine_threats(self) -> list[ThreatMatch]:
        """Combine and deduplicate threats from all sources.

        Returns:
            Combined list of unique threats
        """
        combined = []
        seen_threats = set()

        # Add rules-based threats first (they're more precise)
        for threat in self.rules_threats:
            threat_key = (threat.rule_id, threat.line_number, threat.code_snippet)
            if threat_key not in seen_threats:
                combined.append(threat)
                seen_threats.add(threat_key)

        # Add Semgrep threats next (they're also quite precise)
        for threat in self.semgrep_threats:
            # Check for similar threats (same line, similar category)
            is_duplicate = False
            for existing in combined:
                if (
                    abs(threat.line_number - existing.line_number) <= 2
                    and threat.category == existing.category
                ):
                    is_duplicate = True
                    break

            if not is_duplicate:
                combined.append(threat)

        # Add LLM threats that don't duplicate other findings
        for threat in self.llm_threats:
            # Check for similar threats (same line, similar category)
            is_duplicate = False
            for existing in combined:
                if (
                    abs(threat.line_number - existing.line_number) <= 2
                    and threat.category == existing.category
                ):
                    is_duplicate = True
                    break

            if not is_duplicate:
                combined.append(threat)

        # Sort by line number and severity
        combined.sort(key=lambda t: (t.line_number, t.severity.value))

        return combined

    def _calculate_stats(self) -> dict[str, Any]:
        """Calculate scan statistics.

        Returns:
            Dictionary with scan statistics
        """
        return {
            "total_threats": len(self.all_threats),
            "rules_threats": len(self.rules_threats),
            "llm_threats": len(self.llm_threats),
            "semgrep_threats": len(self.semgrep_threats),
            "unique_threats": len(self.all_threats),
            "severity_counts": self._count_by_severity(),
            "category_counts": self._count_by_category(),
            "sources": {
                "rules_engine": len(self.rules_threats) > 0,
                "llm_analysis": len(self.llm_threats) > 0,
                "semgrep_analysis": len(self.semgrep_threats) > 0,
            },
        }

    def _count_by_severity(self) -> dict[str, int]:
        """Count threats by severity level."""
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for threat in self.all_threats:
            counts[threat.severity.value] += 1
        return counts

    def _count_by_category(self) -> dict[str, int]:
        """Count threats by category."""
        counts = {}
        for threat in self.all_threats:
            category = threat.category.value
            counts[category] = counts.get(category, 0) + 1
        return counts

    def get_high_confidence_threats(
        self, min_confidence: float = 0.8
    ) -> list[ThreatMatch]:
        """Get threats with high confidence scores.

        Args:
            min_confidence: Minimum confidence threshold

        Returns:
            List of high-confidence threats
        """
        return [t for t in self.all_threats if t.confidence >= min_confidence]

    def get_critical_threats(self) -> list[ThreatMatch]:
        """Get critical severity threats.

        Returns:
            List of critical threats
        """
        return [t for t in self.all_threats if t.severity == Severity.CRITICAL]


class ScanEngine:
    """Scan engine combining AST-based rules with LLM analysis."""

    def __init__(
        self,
        threat_engine: ThreatEngine | None = None,
        credential_manager: CredentialManager | None = None,
        enable_llm_analysis: bool = False,
    ):
        """Initialize enhanced scanner.

        Args:
            threat_engine: Threat engine for rules-based scanning
            credential_manager: Credential manager for configuration
            enable_llm_analysis: Whether to enable LLM analysis
        """
        self.threat_engine = threat_engine or ThreatEngine()
        self.credential_manager = credential_manager or CredentialManager()
        self.false_positive_manager = FalsePositiveManager()

        # Set LLM analysis based on parameter
        self.enable_llm_analysis = enable_llm_analysis

        # Initialize AST scanner
        self.ast_scanner = ASTScanner(self.threat_engine)

        # Initialize Semgrep scanner
        self.semgrep_scanner = SemgrepScanner(
            self.threat_engine, self.credential_manager
        )

        # Check if Semgrep scanning is enabled in config
        config = self.credential_manager.load_config()
        self.enable_semgrep_analysis = (
            config.enable_semgrep_scanning and self.semgrep_scanner.is_available()
        )

        if not self.semgrep_scanner.is_available():
            logger.warning(
                "Semgrep not available - install semgrep for enhanced analysis"
            )

        # Initialize LLM analyzer if enabled
        self.llm_analyzer = None
        if self.enable_llm_analysis:
            self.llm_analyzer = LLMScanner(self.credential_manager)
            if not self.llm_analyzer.is_available():
                logger.warning(
                    "LLM analysis requested but not available - API key not configured"
                )
                self.enable_llm_analysis = False

    def scan_code_sync(
        self,
        source_code: str,
        file_path: str,
        language: Language,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Synchronous wrapper for scan_code for CLI usage."""
        import asyncio

        return asyncio.run(
            self.scan_code(
                source_code=source_code,
                file_path=file_path,
                language=language,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_rules=use_rules,
                severity_threshold=severity_threshold,
            )
        )

    def scan_directory_sync(
        self,
        directory_path: Path,
        recursive: bool = True,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
        max_files: int | None = None,
    ) -> list[EnhancedScanResult]:
        """Synchronous wrapper for scan_directory for CLI usage."""
        import asyncio

        return asyncio.run(
            self.scan_directory(
                directory_path=directory_path,
                recursive=recursive,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_rules=use_rules,
                severity_threshold=severity_threshold,
                max_files=max_files,
            )
        )

    def scan_file_sync(
        self,
        file_path: Path,
        language: Language | None = None,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Synchronous wrapper for scan_file for CLI usage."""
        import asyncio

        return asyncio.run(
            self.scan_file(
                file_path=file_path,
                language=language,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_rules=use_rules,
                severity_threshold=severity_threshold,
            )
        )

    async def scan_code(
        self,
        source_code: str,
        file_path: str,
        language: Language,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Scan source code using rules, Semgrep, and LLM analysis.

        Args:
            source_code: Source code to scan
            file_path: Path to the source file
            language: Programming language
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            use_rules: Whether to use rules-based scanner
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            Enhanced scan result
        """
        logger.info(f"=== SCAN_CODE START for {file_path} ===")
        scan_metadata = {
            "file_path": file_path,
            "language": language.value,
            "use_llm": use_llm and self.enable_llm_analysis,
            "use_semgrep": use_semgrep and self.enable_semgrep_analysis,
            "use_rules": use_rules,
            "source_lines": len(source_code.split("\n")),
            "source_size": len(source_code),
        }

        # Perform AST-based rules scanning if enabled
        rules_threats = []
        if use_rules:
            logger.info(f"Starting rules-based scanning for {file_path}")
            # Skip AST scanning for generic files to avoid hangs
            if language == Language.GENERIC:
                logger.info(f"Skipping AST scanning for generic file: {file_path}")
                scan_metadata["rules_scan_success"] = True
                scan_metadata["rules_scan_reason"] = "skipped_generic_file"
            else:
                try:
                    rules_threats = self.ast_scanner.scan_code(
                        source_code, file_path, language
                    )
                    scan_metadata["rules_scan_success"] = True
                    scan_metadata["rules_scan_reason"] = "analysis_completed"
                except Exception as e:
                    logger.error(f"Rules-based scan failed for {file_path}: {e}")
                    scan_metadata["rules_scan_success"] = False
                    scan_metadata["rules_scan_error"] = str(e)
                    scan_metadata["rules_scan_reason"] = "scan_failed"
        else:
            scan_metadata["rules_scan_success"] = False
            scan_metadata["rules_scan_reason"] = "disabled"

        # Perform Semgrep scanning if enabled
        semgrep_threats = []
        semgrep_status = self.semgrep_scanner.get_status()
        scan_metadata["semgrep_status"] = semgrep_status

        if use_semgrep and self.enable_semgrep_analysis:
            if not semgrep_status["available"]:
                # Semgrep not available - provide detailed status
                scan_metadata.update(
                    {
                        "semgrep_scan_success": False,
                        "semgrep_scan_error": semgrep_status["error"],
                        "semgrep_scan_reason": "semgrep_not_available",
                        "semgrep_installation_status": semgrep_status[
                            "installation_status"
                        ],
                        "semgrep_installation_guidance": semgrep_status[
                            "installation_guidance"
                        ],
                    }
                )
                logger.warning(
                    f"Semgrep not available for file scan: {semgrep_status['error']}"
                )
            else:
                try:
                    config = self.credential_manager.load_config()
                    semgrep_threats = await self.semgrep_scanner.scan_code(
                        source_code=source_code,
                        file_path=file_path,
                        language=language,
                        config=config.semgrep_config,
                        rules=config.semgrep_rules,
                        timeout=config.semgrep_timeout,
                        severity_threshold=severity_threshold,
                    )
                    scan_metadata.update(
                        {
                            "semgrep_scan_success": True,
                            "semgrep_scan_reason": "analysis_completed",
                            "semgrep_version": semgrep_status["version"],
                            "semgrep_has_pro_features": semgrep_status[
                                "has_pro_features"
                            ],
                        }
                    )
                except Exception as e:
                    logger.error(f"Semgrep scan failed for {file_path}: {e}")
                    scan_metadata.update(
                        {
                            "semgrep_scan_success": False,
                            "semgrep_scan_error": str(e),
                            "semgrep_scan_reason": "scan_failed",
                            "semgrep_version": semgrep_status["version"],
                        }
                    )
        else:
            scan_metadata.update(
                {
                    "semgrep_scan_success": False,
                    "semgrep_scan_reason": (
                        "disabled" if not use_semgrep else "not_available"
                    ),
                }
            )

        # Store LLM analysis prompt if enabled
        llm_threats = []
        llm_analysis_prompt = None
        if use_llm and self.enable_llm_analysis and self.llm_analyzer:
            try:
                # Create analysis prompt
                llm_analysis_prompt = self.llm_analyzer.create_analysis_prompt(
                    source_code, file_path, language
                )
                scan_metadata["llm_analysis_prompt"] = llm_analysis_prompt.to_dict()

                # Try to analyze the code (in client-based mode, this returns empty list)
                llm_findings = self.llm_analyzer.analyze_code(
                    source_code, file_path, language
                )
                # Convert LLM findings to threats
                for finding in llm_findings:
                    threat = finding.to_threat_match(file_path)
                    llm_threats.append(threat)
                scan_metadata["llm_scan_success"] = True
                scan_metadata["llm_scan_reason"] = "analysis_completed"

            except Exception as e:
                logger.error(
                    f"Failed to create LLM analysis prompt for {file_path}: {e}"
                )
                scan_metadata["llm_scan_success"] = False
                scan_metadata["llm_scan_error"] = str(e)
                scan_metadata["llm_scan_reason"] = "prompt_creation_failed"
        else:
            scan_metadata["llm_scan_success"] = False
            scan_metadata["llm_scan_reason"] = (
                "disabled" if not use_llm else "not_available"
            )

        # Filter by severity threshold if specified
        if severity_threshold:
            rules_threats = self._filter_by_severity(rules_threats, severity_threshold)
            llm_threats = self._filter_by_severity(llm_threats, severity_threshold)
            semgrep_threats = self._filter_by_severity(
                semgrep_threats, severity_threshold
            )

        # Apply false positive filtering
        rules_threats = self.false_positive_manager.filter_false_positives(
            rules_threats
        )
        llm_threats = self.false_positive_manager.filter_false_positives(llm_threats)
        semgrep_threats = self.false_positive_manager.filter_false_positives(
            semgrep_threats
        )

        return EnhancedScanResult(
            file_path=file_path,
            language=language,
            rules_threats=rules_threats,
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=scan_metadata,
        )

    async def scan_file(
        self,
        file_path: Path,
        language: Language | None = None,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Scan a single file using enhanced scanning.

        Args:
            file_path: Path to the file to scan
            language: Programming language (auto-detected if not provided)
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            use_rules: Whether to use rules-based scanner
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            Enhanced scan result
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read file content
        logger.info(f" SCAN_FILE:Reading file content: {file_path}")
        try:
            with open(file_path, encoding="utf-8") as f:
                source_code = f.read()
        except UnicodeDecodeError:
            logger.warning(f"Skipping binary file: {file_path}")
            # Skip binary files
            return EnhancedScanResult(
                file_path=str(file_path),
                language=language or Language.PYTHON,
                rules_threats=[],
                llm_threats=[],
                semgrep_threats=[],
                scan_metadata={
                    "file_path": str(file_path),
                    "error": "Binary file or encoding error",
                    "rules_scan_success": False,
                    "llm_scan_success": False,
                    "semgrep_scan_success": False,
                },
            )

        logger.info(f"File read successfully, {len(source_code)} characters")

        # Detect language if not provided
        if language is None:
            logger.info(f"Detecting language for: {file_path}")
            language = self._detect_language(file_path)
            logger.info(f"Detected language: {language}")

        logger.info(f"Calling scan_code for {file_path} with language {language}")
        return await self.scan_code(
            source_code=source_code,
            file_path=str(file_path),
            language=language,
            use_llm=use_llm,
            use_semgrep=use_semgrep,
            use_rules=use_rules,
            severity_threshold=severity_threshold,
        )

    async def scan_directory(
        self,
        directory_path: Path,
        recursive: bool = True,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_rules: bool = True,
        severity_threshold: Severity | None = None,
        max_files: int | None = None,
    ) -> list[EnhancedScanResult]:
        """Scan a directory using enhanced scanning with optimized semgrep usage.

        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            use_rules: Whether to use rules-based scanner
            severity_threshold: Minimum severity threshold for filtering
            max_files: Maximum number of files to scan

        Returns:
            List of enhanced scan results
        """
        if not directory_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        logger.info(f"SCAN_FOLDER: Scanning directory: {directory_path}")

        # Get supported file extensions from centralized language support
        supported_extensions = LanguageSupport.get_extension_to_language_map()

        # Find all files to scan
        files_to_scan = []
        pattern = "**/*" if recursive else "*"

        for file_path in directory_path.glob(pattern):
            if file_path.is_file() and file_path.suffix in supported_extensions:
                files_to_scan.append(file_path)

                if max_files and len(files_to_scan) >= max_files:
                    break

        logger.info(f"Found {len(files_to_scan)} files to scan")

        # Run Semgrep once for the entire directory if enabled
        directory_semgrep_threats = {}  # Map file_path -> list[ThreatMatch]
        semgrep_scan_metadata = {}

        if use_semgrep and self.enable_semgrep_analysis:
            semgrep_status = self.semgrep_scanner.get_status()
            if semgrep_status["available"]:
                try:
                    logger.info("Running single Semgrep scan for entire directory")
                    config = self.credential_manager.load_config()

                    # Use semgrep's directory scanning capability
                    all_semgrep_threats = await self.semgrep_scanner.scan_directory(
                        directory_path=str(directory_path),
                        config=config.semgrep_config,
                        rules=config.semgrep_rules,
                        timeout=config.semgrep_timeout,
                        recursive=recursive,
                        severity_threshold=severity_threshold,
                    )

                    # Group threats by file path
                    for threat in all_semgrep_threats:
                        file_path = threat.file_path
                        if file_path not in directory_semgrep_threats:
                            directory_semgrep_threats[file_path] = []
                        directory_semgrep_threats[file_path].append(threat)

                    logger.info(
                        f"Semgrep found {len(all_semgrep_threats)} threats across {len(directory_semgrep_threats)} files"
                    )

                    semgrep_scan_metadata = {
                        "semgrep_scan_success": True,
                        "semgrep_scan_reason": "directory_analysis_completed",
                        "semgrep_version": semgrep_status["version"],
                        "semgrep_has_pro_features": semgrep_status["has_pro_features"],
                        "semgrep_total_threats": len(all_semgrep_threats),
                        "semgrep_files_with_threats": len(directory_semgrep_threats),
                    }

                except Exception as e:
                    logger.error(f"Directory Semgrep scan failed: {e}")
                    semgrep_scan_metadata = {
                        "semgrep_scan_success": False,
                        "semgrep_scan_error": str(e),
                        "semgrep_scan_reason": "directory_scan_failed",
                        "semgrep_version": semgrep_status["version"],
                    }
            else:
                logger.warning(
                    f"Semgrep not available for directory scan: {semgrep_status['error']}"
                )
                semgrep_scan_metadata = {
                    "semgrep_scan_success": False,
                    "semgrep_scan_error": semgrep_status["error"],
                    "semgrep_scan_reason": "semgrep_not_available",
                    "semgrep_installation_status": semgrep_status[
                        "installation_status"
                    ],
                    "semgrep_installation_guidance": semgrep_status[
                        "installation_guidance"
                    ],
                }
        else:
            semgrep_scan_metadata = {
                "semgrep_scan_success": False,
                "semgrep_scan_reason": (
                    "disabled" if not use_semgrep else "not_available"
                ),
            }

        # Now scan each file individually for rules and LLM analysis only
        results = []
        for i, file_path in enumerate(files_to_scan):
            try:
                logger.info(f"Scanning file {i+1}/{len(files_to_scan)}: {file_path}")

                # Read file content
                try:
                    with open(file_path, encoding="utf-8") as f:
                        source_code = f.read()
                except UnicodeDecodeError:
                    logger.warning(f"Skipping binary file: {file_path}")
                    # Create error result for binary file
                    error_result = EnhancedScanResult(
                        file_path=str(file_path),
                        language=Language.GENERIC,
                        rules_threats=[],
                        llm_threats=[],
                        semgrep_threats=[],
                        scan_metadata={
                            "file_path": str(file_path),
                            "error": "Binary file or encoding error",
                            "directory_scan": True,
                            "rules_scan_success": False,
                            "llm_scan_success": False,
                            **semgrep_scan_metadata,
                        },
                    )
                    results.append(error_result)
                    continue

                # Detect language
                language = self._detect_language(file_path)

                # Get semgrep threats for this file from directory scan
                file_semgrep_threats = directory_semgrep_threats.get(str(file_path), [])

                # Run rules and LLM analysis only (skip semgrep since we did it at directory level)
                result = await self.scan_code(
                    source_code=source_code,
                    file_path=str(file_path),
                    language=language,
                    use_llm=use_llm,
                    use_semgrep=False,  # Skip semgrep - we already have results
                    use_rules=use_rules,
                    severity_threshold=severity_threshold,
                )

                # Replace the empty semgrep results with directory scan results
                result.semgrep_threats = file_semgrep_threats

                # Update scan metadata to reflect directory semgrep scan
                result.scan_metadata.update(semgrep_scan_metadata)
                result.scan_metadata["directory_scan"] = True
                result.scan_metadata["semgrep_source"] = "directory_scan"

                # Recalculate combined threats and stats with actual semgrep data
                result.all_threats = result._combine_threats()
                result.stats = result._calculate_stats()

                results.append(result)
                logger.info(
                    f"Completed scanning file {i+1}/{len(files_to_scan)}: {file_path}"
                )

            except Exception as e:
                logger.error(f"Failed to scan {file_path}: {e}")
                # Create error result with consistent structure
                error_result = EnhancedScanResult(
                    file_path=str(file_path),
                    language=Language.GENERIC,  # Default for failed detection
                    rules_threats=[],
                    llm_threats=[],
                    semgrep_threats=[],
                    scan_metadata={
                        "file_path": str(file_path),
                        "error": str(e),
                        "directory_scan": True,
                        "rules_scan_success": False,
                        "llm_scan_success": False,
                        **semgrep_scan_metadata,
                    },
                )
                results.append(error_result)

        logger.info(f"Directory scan completed. Processed {len(results)} files")
        return results

    def _detect_language(self, file_path: Path) -> Language:
        """Detect programming language from file extension.

        Args:
            file_path: Path to the file

        Returns:
            Detected language
        """
        return LanguageSupport.detect_language(file_path)

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

    def get_scanner_stats(self) -> dict[str, Any]:
        """Get statistics about the enhanced scanner.

        Returns:
            Dictionary with scanner statistics
        """
        return {
            "ast_scanner_available": self.ast_scanner is not None,
            "llm_analyzer_available": self.llm_analyzer is not None
            and self.llm_analyzer.is_available(),
            "semgrep_scanner_available": self.semgrep_scanner.is_available(),
            "llm_analysis_enabled": self.enable_llm_analysis,
            "semgrep_analysis_enabled": self.enable_semgrep_analysis,
            "threat_engine_stats": self.threat_engine.get_rule_statistics(),
            "llm_stats": (
                self.llm_analyzer.get_analysis_stats() if self.llm_analyzer else None
            ),
        }

    def set_llm_enabled(self, enabled: bool) -> None:
        """Enable or disable LLM analysis.

        Args:
            enabled: Whether to enable LLM analysis
        """
        if enabled and not self.llm_analyzer:
            self.llm_analyzer = LLMScanner(self.credential_manager)

        self.enable_llm_analysis = enabled and (
            self.llm_analyzer is not None and self.llm_analyzer.is_available()
        )

    def reload_configuration(self) -> None:
        """Reload configuration and reinitialize components."""
        # Reload threat engine rules
        self.threat_engine.reload_rules()

        # Reinitialize LLM analyzer with new configuration
        if self.enable_llm_analysis:
            self.llm_analyzer = LLMScanner(self.credential_manager)
            if not self.llm_analyzer.is_available():
                logger.warning(
                    "LLM analysis disabled after reload - API key not configured"
                )
                self.enable_llm_analysis = False
