"""Enhanced scanner that combines Semgrep and LLM analysis for comprehensive security scanning."""

from pathlib import Path
from typing import Any

from .credential_manager import CredentialManager
from .false_positive_manager import FalsePositiveManager
from .llm_scanner import LLMScanner
from .logging_config import get_logger
from .semgrep_scanner import SemgrepScanner
from .types import Language, LanguageSupport, Severity, ThreatMatch

logger = get_logger("scan_engine")


class EnhancedScanResult:
    """Result of enhanced scanning combining Semgrep and LLM analysis."""

    def __init__(
        self,
        file_path: str,
        language: Language,
        llm_threats: list[ThreatMatch],
        semgrep_threats: list[ThreatMatch],
        scan_metadata: dict[str, Any],
    ):
        """Initialize enhanced scan result.

        Args:
            file_path: Path to the scanned file
            language: Programming language
            llm_threats: Threats found by LLM analysis
            semgrep_threats: Threats found by Semgrep analysis
            scan_metadata: Metadata about the scan
        """
        self.file_path = file_path
        self.language = language
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

        # Add Semgrep threats first (they're quite precise)
        for threat in self.semgrep_threats:
            combined.append(threat)

        # Add LLM threats that don't duplicate Semgrep findings
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
            "llm_threats": len(self.llm_threats),
            "semgrep_threats": len(self.semgrep_threats),
            "unique_threats": len(self.all_threats),
            "severity_counts": self._count_by_severity(),
            "category_counts": self._count_by_category(),
            "sources": {
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
    """Scan engine combining Semgrep and LLM analysis."""

    def __init__(
        self,
        credential_manager: CredentialManager | None = None,
        enable_llm_analysis: bool = True,
        enable_semgrep_analysis: bool = True,
    ):
        """Initialize enhanced scanner.

        Args:
            credential_manager: Credential manager for configuration
            enable_llm_analysis: Whether to enable LLM analysis
            enable_semgrep_analysis: Whether to enable Semgrep analysis
        """
        logger.info("=== Initializing ScanEngine ===")
        self.credential_manager = credential_manager or CredentialManager()
        self.false_positive_manager = FalsePositiveManager()
        logger.debug("Initialized core components")

        # Set analysis parameters
        self.enable_llm_analysis = enable_llm_analysis
        self.enable_semgrep_analysis = enable_semgrep_analysis
        logger.info(f"LLM analysis enabled: {self.enable_llm_analysis}")
        logger.info(f"Semgrep analysis enabled: {self.enable_semgrep_analysis}")

        # Initialize Semgrep scanner
        logger.debug("Initializing Semgrep scanner...")
        self.semgrep_scanner = SemgrepScanner(
            credential_manager=self.credential_manager
        )

        # Check if Semgrep scanning is available and enabled
        config = self.credential_manager.load_config()
        self.enable_semgrep_analysis = (
            self.enable_semgrep_analysis
            and config.enable_semgrep_scanning
            and self.semgrep_scanner.is_available()
        )
        logger.info(f"Semgrep analysis enabled: {self.enable_semgrep_analysis}")

        if not self.semgrep_scanner.is_available():
            logger.warning(
                "Semgrep not available - install semgrep for enhanced analysis"
            )

        # Initialize LLM analyzer if enabled
        self.llm_analyzer = None
        if self.enable_llm_analysis:
            logger.debug("Initializing LLM analyzer...")
            self.llm_analyzer = LLMScanner(self.credential_manager)
            if not self.llm_analyzer.is_available():
                logger.warning(
                    "LLM analysis requested but not available - API key not configured"
                )
                self.enable_llm_analysis = False
            else:
                logger.info("LLM analyzer initialized successfully")
        else:
            logger.debug("LLM analysis disabled")

        logger.info("=== ScanEngine initialization complete ===")

    def _detect_language(self, file_path: Path) -> Language:
        """Detect programming language from file extension.

        Args:
            file_path: Path to the file

        Returns:
            Detected language
        """
        language = LanguageSupport.detect_language(file_path)
        logger.debug(f"Language detection: {file_path.suffix} -> {language.value}")
        return language

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
        logger.debug(
            f"Filtering {len(threats)} threats by severity >= {min_severity.value}"
        )

        severity_order = [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        min_index = severity_order.index(min_severity)

        filtered = [
            threat
            for threat in threats
            if severity_order.index(threat.severity) >= min_index
        ]

        logger.debug(
            f"Severity filtering result: {len(threats)} -> {len(filtered)} threats"
        )
        return filtered

    def get_scanner_stats(self) -> dict[str, Any]:
        """Get statistics about the enhanced scanner.

        Returns:
            Dictionary with scanner statistics
        """
        logger.debug("Generating scanner statistics...")

        stats = {
            "llm_analyzer_available": self.llm_analyzer is not None
            and self.llm_analyzer.is_available(),
            "semgrep_scanner_available": self.semgrep_scanner.is_available(),
            "llm_analysis_enabled": self.enable_llm_analysis,
            "semgrep_analysis_enabled": self.enable_semgrep_analysis,
            "llm_stats": (
                self.llm_analyzer.get_analysis_stats() if self.llm_analyzer else None
            ),
        }

        logger.debug(
            f"Scanner stats generated - "
            f"LLM: {stats['llm_analyzer_available']}, "
            f"Semgrep: {stats['semgrep_scanner_available']}"
        )

        return stats

    def set_llm_enabled(self, enabled: bool) -> None:
        """Enable or disable LLM analysis.

        Args:
            enabled: Whether to enable LLM analysis
        """
        logger.info(f"Setting LLM analysis enabled: {enabled}")

        if enabled and not self.llm_analyzer:
            logger.debug("Creating new LLM analyzer...")
            self.llm_analyzer = LLMScanner(self.credential_manager)

        old_state = self.enable_llm_analysis
        self.enable_llm_analysis = enabled and (
            self.llm_analyzer is not None and self.llm_analyzer.is_available()
        )

        if old_state != self.enable_llm_analysis:
            logger.info(
                f"LLM analysis state changed: {old_state} -> {self.enable_llm_analysis}"
            )
        else:
            logger.debug("LLM analysis state unchanged")

    def reload_configuration(self) -> None:
        """Reload configuration and reinitialize components."""
        logger.info("Reloading scanner configuration...")

        # Reinitialize LLM analyzer with new configuration
        if self.enable_llm_analysis:
            logger.debug("Reinitializing LLM analyzer...")
            self.llm_analyzer = LLMScanner(self.credential_manager)
            if not self.llm_analyzer.is_available():
                logger.warning(
                    "LLM analysis disabled after reload - API key not configured"
                )
                self.enable_llm_analysis = False
            else:
                logger.info("LLM analyzer reinitialized successfully")

        logger.info("Scanner configuration reload complete")

    def scan_code_sync(
        self,
        source_code: str,
        file_path: str,
        language: Language,
        use_llm: bool = True,
        use_semgrep: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Synchronous wrapper for scan_code for CLI usage."""
        logger.debug(f"Synchronous code scan wrapper called for: {file_path}")
        import asyncio

        return asyncio.run(
            self.scan_code(
                source_code=source_code,
                file_path=file_path,
                language=language,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                severity_threshold=severity_threshold,
            )
        )

    def scan_directory_sync(
        self,
        directory_path: Path,
        recursive: bool = True,
        use_llm: bool = True,
        use_semgrep: bool = True,
        severity_threshold: Severity | None = None,
        max_files: int | None = None,
    ) -> list[EnhancedScanResult]:
        """Synchronous wrapper for scan_directory for CLI usage."""
        logger.debug(f"Synchronous directory scan wrapper called for: {directory_path}")
        import asyncio

        return asyncio.run(
            self.scan_directory(
                directory_path=directory_path,
                recursive=recursive,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
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
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Synchronous wrapper for scan_file for CLI usage."""
        logger.debug(f"Synchronous file scan wrapper called for: {file_path}")
        import asyncio

        return asyncio.run(
            self.scan_file(
                file_path=file_path,
                language=language,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
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
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Scan source code using Semgrep and LLM analysis.

        Args:
            source_code: Source code to scan
            file_path: Path to the source file
            language: Programming language
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            Enhanced scan result
        """
        logger.info(f"=== Starting code scan for {file_path} ===")
        logger.debug(
            f"Scan parameters - Language: {language.value}, "
            f"LLM: {use_llm}, Semgrep: {use_semgrep}, "
            f"Severity threshold: {severity_threshold}"
        )

        scan_metadata = {
            "file_path": file_path,
            "language": language.value,
            "use_llm": use_llm and self.enable_llm_analysis,
            "use_semgrep": use_semgrep and self.enable_semgrep_analysis,
            "source_lines": len(source_code.split("\n")),
            "source_size": len(source_code),
        }
        logger.info(
            f"Source code stats - Lines: {scan_metadata['source_lines']}, "
            f"Size: {scan_metadata['source_size']} chars"
        )

        # Initialize threat lists
        llm_threats = []
        semgrep_threats = []

        # Perform Semgrep scanning if enabled
        semgrep_threats = []
        logger.debug("Checking Semgrep status...")
        semgrep_status = self.semgrep_scanner.get_status()
        scan_metadata["semgrep_status"] = semgrep_status
        logger.debug(f"Semgrep status: {semgrep_status}")

        if use_semgrep and self.enable_semgrep_analysis:
            if not semgrep_status["available"]:
                # Semgrep not available - provide detailed status
                logger.warning(f"Semgrep not available: {semgrep_status['error']}")
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
            else:
                logger.info("Starting Semgrep scanning...")
                try:
                    config = self.credential_manager.load_config()
                    logger.debug("Calling Semgrep scanner...")
                    semgrep_threats = await self.semgrep_scanner.scan_code(
                        source_code=source_code,
                        file_path=file_path,
                        language=language,
                        config=config.semgrep_config,
                        rules=config.semgrep_rules,
                        timeout=config.semgrep_timeout,
                        severity_threshold=severity_threshold,
                    )
                    logger.info(
                        f"Semgrep scan completed - found {len(semgrep_threats)} threats"
                    )
                    scan_metadata.update(
                        {
                            "semgrep_scan_success": True,
                            "semgrep_scan_reason": "analysis_completed",
                            "semgrep_version": semgrep_status["version"],
                            "semgrep_has_pro_features": semgrep_status.get(
                                "has_pro_features", False
                            ),
                        }
                    )
                except Exception as e:
                    logger.error(f"Semgrep scan failed for {file_path}: {e}")
                    logger.debug("Semgrep scan error details", exc_info=True)
                    scan_metadata.update(
                        {
                            "semgrep_scan_success": False,
                            "semgrep_scan_error": str(e),
                            "semgrep_scan_reason": "scan_failed",
                            "semgrep_version": semgrep_status["version"],
                        }
                    )
        else:
            if not use_semgrep:
                reason = "skipped_intentionally"
                logger.debug(
                    "Semgrep scanning skipped (already completed at directory level to avoid duplication)"
                )
            else:
                reason = "not_available"
                logger.debug("Semgrep scanning not available")
            scan_metadata.update(
                {
                    "semgrep_scan_success": False,
                    "semgrep_scan_reason": reason,
                }
            )

        # Store LLM analysis prompt if enabled
        llm_threats = []
        llm_analysis_prompt = None
        if use_llm and self.enable_llm_analysis and self.llm_analyzer:
            logger.info("Starting LLM analysis...")
            try:
                logger.debug("Creating LLM analysis prompt...")
                # Create analysis prompt
                llm_analysis_prompt = self.llm_analyzer.create_analysis_prompt(
                    source_code, file_path, language
                )
                scan_metadata["llm_analysis_prompt"] = llm_analysis_prompt.to_dict()

                # Try to analyze the code (in client-based mode, this returns empty list)
                logger.debug("Calling LLM analyzer...")
                llm_findings = self.llm_analyzer.analyze_code(
                    source_code, file_path, language
                )
                # Convert LLM findings to threats
                for finding in llm_findings:
                    threat = finding.to_threat_match(file_path)
                    llm_threats.append(threat)
                logger.info(
                    f"LLM analysis completed - found {len(llm_threats)} threats"
                )
                scan_metadata["llm_scan_success"] = True
                scan_metadata["llm_scan_reason"] = "analysis_completed"

            except Exception as e:
                logger.error(
                    f"Failed to create LLM analysis prompt for {file_path}: {e}"
                )
                logger.debug("LLM analysis error details", exc_info=True)
                scan_metadata["llm_scan_success"] = False
                scan_metadata["llm_scan_error"] = str(e)
                scan_metadata["llm_scan_reason"] = "prompt_creation_failed"
        else:
            if not use_llm:
                reason = "disabled_by_user"
                logger.debug("LLM analysis disabled by user request")
            else:
                reason = "not_available"
                logger.debug("LLM analysis not available - no API key configured")
            scan_metadata["llm_scan_success"] = False
            scan_metadata["llm_scan_reason"] = reason

        # Filter by severity threshold if specified
        original_counts = {
            "semgrep": len(semgrep_threats),
            "llm": len(llm_threats),
        }

        if severity_threshold:
            logger.info(f"Applying severity filter: {severity_threshold.value}")
            llm_threats = self._filter_by_severity(llm_threats, severity_threshold)
            semgrep_threats = self._filter_by_severity(
                semgrep_threats, severity_threshold
            )

            filtered_counts = {
                "semgrep": len(semgrep_threats),
                "llm": len(llm_threats),
            }

            logger.info(
                f"Severity filtering results - "
                f"Semgrep: {original_counts['semgrep']} -> {filtered_counts['semgrep']}, "
                f"LLM: {original_counts['llm']} -> {filtered_counts['llm']}"
            )

        # # Apply false positive filtering
        # logger.debug("Applying false positive filtering...")
        # original_total = len(llm_threats) + len(semgrep_threats)
        # llm_threats = self.false_positive_manager.filter_false_positives(llm_threats)
        # semgrep_threats = self.false_positive_manager.filter_false_positives(
        #     semgrep_threats
        # )
        # final_total = len(llm_threats) + len(semgrep_threats)

        # if original_total != final_total:
        #     logger.info(
        #         f"False positive filtering: {original_total} -> {final_total} threats"
        #     )

        result = EnhancedScanResult(
            file_path=file_path,
            language=language,
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=scan_metadata,
        )

        logger.info(
            f"=== Code scan complete for {file_path} - "
            f"Total threats: {len(result.all_threats)} ==="
        )

        return result

    async def scan_file(
        self,
        file_path: Path,
        language: Language | None = None,
        use_llm: bool = True,
        use_semgrep: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Scan a single file using enhanced scanning.

        Args:
            file_path: Path to the file to scan
            language: Programming language (auto-detected if not provided)
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            Enhanced scan result
        """
        logger.info(f"=== Starting file scan: {file_path} ===")

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")

        # Detect language if not provided
        if language is None:
            logger.debug(f"Detecting language for: {file_path}")
            language = self._detect_language(file_path)
            logger.info(f"Detected language: {language.value}")
        else:
            logger.debug(f"Using provided language: {language.value}")

        scan_metadata = {
            "file_path": str(file_path),
            "language": language.value,
            "use_llm": use_llm and self.enable_llm_analysis,
            "use_semgrep": use_semgrep and self.enable_semgrep_analysis,
        }

        # Initialize threat lists
        rules_threats = []
        semgrep_threats = []
        llm_threats = []

        # Perform Semgrep scanning if enabled
        logger.debug("Checking Semgrep status...")
        semgrep_status = self.semgrep_scanner.get_status()
        scan_metadata["semgrep_status"] = semgrep_status
        logger.debug(f"Semgrep status: {semgrep_status}")

        if use_semgrep and self.enable_semgrep_analysis:
            if not semgrep_status["available"]:
                # Semgrep not available - provide detailed status
                logger.warning(f"Semgrep not available: {semgrep_status['error']}")
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
            else:
                logger.info("Starting Semgrep scanning...")
                try:
                    config = self.credential_manager.load_config()
                    logger.debug("Calling Semgrep scanner...")
                    semgrep_threats = await self.semgrep_scanner.scan_file(
                        file_path=str(file_path),
                        config=config.semgrep_config,
                        rules=config.semgrep_rules,
                        timeout=config.semgrep_timeout,
                        severity_threshold=severity_threshold,
                    )
                    logger.info(
                        f"Semgrep scan completed - found {len(semgrep_threats)} threats"
                    )
                    scan_metadata.update(
                        {
                            "semgrep_scan_success": True,
                            "semgrep_scan_reason": "analysis_completed",
                            "semgrep_version": semgrep_status["version"],
                            "semgrep_has_pro_features": semgrep_status.get(
                                "has_pro_features", False
                            ),
                        }
                    )
                except Exception as e:
                    logger.error(f"Semgrep scan failed for {file_path}: {e}")
                    logger.debug("Semgrep scan error details", exc_info=True)
                    scan_metadata.update(
                        {
                            "semgrep_scan_success": False,
                            "semgrep_scan_error": str(e),
                            "semgrep_scan_reason": "scan_failed",
                            "semgrep_version": semgrep_status["version"],
                        }
                    )
        else:
            if not use_semgrep:
                reason = "disabled_by_user"
                logger.debug("Semgrep scanning disabled by user request")
            else:
                reason = "not_available"
                logger.debug("Semgrep scanning not available")
            scan_metadata.update(
                {
                    "semgrep_scan_success": False,
                    "semgrep_scan_reason": reason,
                }
            )

        # Perform LLM analysis if enabled
        if use_llm and self.enable_llm_analysis and self.llm_analyzer:
            logger.info("Starting LLM analysis...")
            try:
                logger.debug("Calling LLM analyzer for file...")
                llm_findings = await self.llm_analyzer.analyze_file(
                    file_path=file_path, language=language
                )
                # Convert LLM findings to threats
                for finding in llm_findings:
                    threat = finding.to_threat_match(str(file_path))
                    llm_threats.append(threat)
                logger.info(
                    f"LLM analysis completed - found {len(llm_threats)} threats"
                )
                scan_metadata["llm_scan_success"] = True
                scan_metadata["llm_scan_reason"] = "analysis_completed"

            except Exception as e:
                logger.error(f"LLM analysis failed for {file_path}: {e}")
                logger.debug("LLM analysis error details", exc_info=True)
                scan_metadata["llm_scan_success"] = False
                scan_metadata["llm_scan_error"] = str(e)
                scan_metadata["llm_scan_reason"] = "analysis_failed"
        else:
            if not use_llm:
                reason = "disabled_by_user"
                logger.debug("LLM analysis disabled by user request")
            else:
                reason = "not_available"
                logger.debug("LLM analysis not available - no API key configured")
            scan_metadata["llm_scan_success"] = False
            scan_metadata["llm_scan_reason"] = reason

        # Filter by severity threshold if specified
        if severity_threshold:
            rules_threats = self._filter_by_severity(rules_threats, severity_threshold)
            llm_threats = self._filter_by_severity(llm_threats, severity_threshold)
            semgrep_threats = self._filter_by_severity(
                semgrep_threats, severity_threshold
            )

        result = EnhancedScanResult(
            file_path=str(file_path),
            language=language,
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=scan_metadata,
        )

        logger.info(
            f"=== File scan complete for {file_path} - "
            f"Total threats: {len(result.all_threats)} ==="
        )

        return result

    async def scan_directory(
        self,
        directory_path: Path,
        recursive: bool = True,
        use_llm: bool = True,
        use_semgrep: bool = True,
        severity_threshold: Severity | None = None,
        max_files: int | None = None,
    ) -> list[EnhancedScanResult]:
        """Scan a directory using enhanced scanning with optimized approach.

        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            severity_threshold: Minimum severity threshold for filtering
            max_files: Maximum number of files to scan

        Returns:
            List of enhanced scan results
        """
        logger.info(f"=== Starting directory scan: {directory_path} ===")
        logger.debug(
            f"Directory scan parameters - Recursive: {recursive}, "
            f"Max files: {max_files}, LLM: {use_llm}, "
            f"Semgrep: {use_semgrep}"
        )

        if not directory_path.exists():
            logger.error(f"Directory not found: {directory_path}")
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # Get supported file extensions from centralized language support
        supported_extensions = LanguageSupport.get_extension_to_language_map()
        logger.debug(f"Supported extensions: {len(supported_extensions)} types")

        # Find all files to scan
        files_to_scan = []
        pattern = "**/*" if recursive else "*"
        logger.debug(f"Scanning for files with pattern: {pattern}")

        for file_path in directory_path.glob(pattern):
            if file_path.is_file() and file_path.suffix in supported_extensions:
                files_to_scan.append(file_path)

                if max_files and len(files_to_scan) >= max_files:
                    logger.info(f"Reached max file limit: {max_files}")
                    break

        logger.info(f"Found {len(files_to_scan)} files to scan")

        # Perform Semgrep scanning once for entire directory if enabled
        directory_semgrep_threats = {}  # Map file_path -> list[ThreatMatch]
        semgrep_scan_metadata = {}

        if use_semgrep and self.enable_semgrep_analysis:
            logger.info("Starting directory-level Semgrep scan...")
            semgrep_status = self.semgrep_scanner.get_status()
            if semgrep_status["available"]:
                try:
                    logger.debug("Running single Semgrep scan for entire directory")
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
                        f"Directory Semgrep scan complete: found {len(all_semgrep_threats)} threats across {len(directory_semgrep_threats)} files"
                    )
                    logger.info(
                        f"✅ Semgrep optimization: Scanned entire directory once instead of {len(files_to_scan)} individual scans"
                    )

                    semgrep_scan_metadata = {
                        "semgrep_scan_success": True,
                        "semgrep_scan_reason": "directory_analysis_completed",
                        "semgrep_version": semgrep_status["version"],
                        "semgrep_has_pro_features": semgrep_status.get(
                            "has_pro_features", False
                        ),
                        "semgrep_total_threats": len(all_semgrep_threats),
                        "semgrep_files_with_threats": len(directory_semgrep_threats),
                    }

                except Exception as e:
                    logger.error(f"Directory Semgrep scan failed: {e}")
                    logger.debug("Directory Semgrep scan error details", exc_info=True)
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
            if not use_semgrep:
                reason = "disabled_by_user"
                logger.info("Directory Semgrep scan disabled by user request")
            else:
                reason = "not_available"
                logger.warning(
                    "Directory Semgrep scan unavailable - Semgrep not found or not configured"
                )
            semgrep_scan_metadata = {
                "semgrep_scan_success": False,
                "semgrep_scan_reason": reason,
            }

        # Perform LLM analysis for entire directory if enabled
        directory_llm_threats = {}  # Map file_path -> list[ThreatMatch]
        llm_scan_metadata = {}

        if use_llm and self.enable_llm_analysis and self.llm_analyzer:
            logger.info("Starting directory-level LLM analysis...")
            try:
                logger.debug("Calling LLM analyzer for entire directory...")
                all_llm_findings = await self.llm_analyzer.analyze_directory(
                    directory_path=directory_path,
                    recursive=recursive,
                    max_files=max_files,
                )

                # Convert LLM findings to threats and group by file
                all_llm_threats = []
                for finding in all_llm_findings:
                    threat = finding.to_threat_match(finding.file_path)
                    all_llm_threats.append(threat)
                    file_path = finding.file_path
                    if file_path not in directory_llm_threats:
                        directory_llm_threats[file_path] = []
                    directory_llm_threats[file_path].append(threat)

                logger.info(
                    f"Directory LLM analysis complete: found {len(all_llm_threats)} threats across {len(directory_llm_threats)} files"
                )

                llm_scan_metadata = {
                    "llm_scan_success": True,
                    "llm_scan_reason": "directory_analysis_completed",
                    "llm_total_threats": len(all_llm_threats),
                    "llm_files_with_threats": len(directory_llm_threats),
                }

            except Exception as e:
                logger.error(f"Directory LLM analysis failed: {e}")
                logger.debug("Directory LLM analysis error details", exc_info=True)
                llm_scan_metadata = {
                    "llm_scan_success": False,
                    "llm_scan_error": str(e),
                    "llm_scan_reason": "directory_analysis_failed",
                }
        else:
            if not use_llm:
                reason = "disabled_by_user"
                logger.info("Directory LLM analysis disabled by user request")
            else:
                reason = "not_available"
                logger.warning(
                    "Directory LLM analysis unavailable - no API key configured"
                )
            llm_scan_metadata = {
                "llm_scan_success": False,
                "llm_scan_reason": reason,
            }

        # Process each file for rules-based analysis and collect results
        logger.info(
            f"Processing {len(files_to_scan)} files for rules analysis and result compilation..."
        )
        results = []
        successful_scans = 0
        failed_scans = 0

        for i, file_path in enumerate(files_to_scan):
            try:
                logger.debug(f"Processing file {i+1}/{len(files_to_scan)}: {file_path}")

                # Detect language
                language = self._detect_language(file_path)

                # Get threats for this file from directory scans
                file_semgrep_threats = directory_semgrep_threats.get(str(file_path), [])
                file_llm_threats = directory_llm_threats.get(str(file_path), [])
                logger.debug(
                    f"File {file_path.name}: {len(file_semgrep_threats)} Semgrep threats, "
                    f"{len(file_llm_threats)} LLM threats from directory scans"
                )

                # Initialize file scan metadata
                scan_metadata: dict[str, Any] = {
                    "file_path": str(file_path),
                    "language": language.value,
                    "use_llm": use_llm and self.enable_llm_analysis,
                    "use_semgrep": use_semgrep and self.enable_semgrep_analysis,
                    "directory_scan": True,
                    "semgrep_source": "directory_scan",
                    "llm_source": "directory_scan",
                }

                # Add directory scan metadata
                scan_metadata.update(semgrep_scan_metadata)
                scan_metadata.update(llm_scan_metadata)

                # Initialize rules_threats as empty (AST scanning removed)
                rules_threats = []

                # Filter by severity threshold if specified
                if severity_threshold:
                    rules_threats = self._filter_by_severity(
                        rules_threats, severity_threshold
                    )
                    file_llm_threats = self._filter_by_severity(
                        file_llm_threats, severity_threshold
                    )
                    file_semgrep_threats = self._filter_by_severity(
                        file_semgrep_threats, severity_threshold
                    )

                # Create result for this file
                result = EnhancedScanResult(
                    file_path=str(file_path),
                    language=language,
                    llm_threats=file_llm_threats,
                    semgrep_threats=file_semgrep_threats,
                    scan_metadata=scan_metadata,
                )

                results.append(result)
                successful_scans += 1

                if (i + 1) % 10 == 0:  # Log progress every 10 files
                    logger.info(f"Progress: {i+1}/{len(files_to_scan)} files processed")

            except Exception as e:
                logger.error(f"Failed to process {file_path}: {e}")
                logger.debug(
                    f"File processing error details for {file_path}", exc_info=True
                )
                # Create error result with consistent structure
                error_result = EnhancedScanResult(
                    file_path=str(file_path),
                    language=Language.GENERIC,  # Default for failed detection
                    llm_threats=[],
                    semgrep_threats=[],
                    scan_metadata={
                        "file_path": str(file_path),
                        "error": str(e),
                        "directory_scan": True,
                        "rules_scan_success": False,
                        **semgrep_scan_metadata,
                        **llm_scan_metadata,
                    },
                )
                results.append(error_result)
                failed_scans += 1

        logger.info(
            f"=== Directory scan complete - Processed {len(results)} files "
            f"(Success: {successful_scans}, Failed: {failed_scans}) ==="
        )
        return results
