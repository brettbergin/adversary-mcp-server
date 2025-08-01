"""Enhanced scanner that combines Semgrep and LLM analysis for comprehensive security scanning."""

import asyncio
import os
from pathlib import Path
from typing import Any

from ..credentials import CredentialManager
from ..logger import get_logger
from .file_filter import FileFilter
from .llm_scanner import LLMScanner
from .llm_validator import LLMValidator
from .semgrep_scanner import SemgrepScanner
from .streaming_utils import StreamingFileReader, is_file_too_large
from .types import Severity, ThreatMatch

logger = get_logger("scan_engine")


class EnhancedScanResult:
    """Result of enhanced scanning combining Semgrep and LLM analysis."""

    def __init__(
        self,
        file_path: str,
        llm_threats: list[ThreatMatch],
        semgrep_threats: list[ThreatMatch],
        scan_metadata: dict[str, Any],
        validation_results: dict[str, Any] | None = None,
    ):
        """Initialize enhanced scan result.

        Args:
            file_path: Path to the scanned file
            llm_threats: Threats found by LLM analysis
            semgrep_threats: Threats found by Semgrep analysis
            scan_metadata: Metadata about the scan
            validation_results: Optional validation results from LLM validator
        """
        self.file_path = file_path
        # Auto-detect language from file path
        self.language = self._detect_language_from_path(file_path)
        self.llm_threats = llm_threats
        self.semgrep_threats = semgrep_threats
        self.scan_metadata = scan_metadata
        self.validation_results = validation_results or {}

        # Combine and deduplicate threats
        self.all_threats = self._combine_threats()

        # Calculate statistics
        self.stats = self._calculate_stats()

    def _detect_language_from_path(self, file_path: str) -> str:
        """Simple language detection for compatibility (not used for actual analysis).

        Args:
            file_path: Path to the file

        Returns:
            Generic language string (not used for actual analysis)
        """
        # Simplified: return generic for all files since semgrep handles language detection internally
        # and we don't want users to think about language selection
        return "generic"

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
        enable_llm_validation: bool = True,
    ):
        """Initialize enhanced scanner.

        Args:
            credential_manager: Credential manager for configuration
            enable_llm_analysis: Whether to enable LLM analysis
            enable_semgrep_analysis: Whether to enable Semgrep analysis
            enable_llm_validation: Whether to enable LLM validation of findings
        """
        logger.info("=== Initializing ScanEngine ===")
        self.credential_manager = credential_manager or CredentialManager()
        logger.debug("Initialized core components")

        # Set analysis parameters
        self.enable_llm_analysis = enable_llm_analysis
        self.enable_semgrep_analysis = enable_semgrep_analysis
        self.enable_llm_validation = enable_llm_validation
        logger.info(f"LLM analysis enabled: {self.enable_llm_analysis}")
        logger.info(f"Semgrep analysis enabled: {self.enable_semgrep_analysis}")
        logger.info(f"LLM validation enabled: {self.enable_llm_validation}")

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

        # Initialize LLM validator if enabled
        self.llm_validator = None
        if self.enable_llm_validation:
            logger.debug("Initializing LLM validator...")
            self.llm_validator = LLMValidator(self.credential_manager)
            logger.info("LLM validator initialized successfully")
        else:
            logger.debug("LLM validation disabled")

        logger.info("=== ScanEngine initialization complete ===")

    def _detect_language(self, file_path: Path) -> str:
        """Simple language detection for compatibility (semgrep handles this internally).

        Args:
            file_path: Path to the file

        Returns:
            Generic language string (not used for actual analysis)
        """
        # Simplified: return generic for all files since semgrep handles language detection internally
        # and we don't want users to think about language selection
        return "generic"

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
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Synchronous wrapper for scan_code for CLI usage with auto-detected language."""
        file_path_abs = str(Path(file_path).resolve())
        logger.debug(f"Synchronous code scan wrapper called for: {file_path_abs}")
        import asyncio

        return asyncio.run(
            self.scan_code(
                source_code=source_code,
                file_path=file_path,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                severity_threshold=severity_threshold,
            )
        )

    def scan_directory_sync(
        self,
        directory_path: Path,
        recursive: bool = True,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> list[EnhancedScanResult]:
        """Synchronous wrapper for scan_directory for CLI usage."""
        directory_path_abs = str(Path(directory_path).resolve())
        logger.debug(
            f"Synchronous directory scan wrapper called for: {directory_path_abs}"
        )
        import asyncio

        return asyncio.run(
            self.scan_directory(
                directory_path=directory_path,
                recursive=recursive,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                severity_threshold=severity_threshold,
            )
        )

    def scan_file_sync(
        self,
        file_path: Path,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Synchronous wrapper for scan_file for CLI usage with auto-detected language."""
        file_path_abs = str(Path(file_path).resolve())
        logger.debug(f"Synchronous file scan wrapper called for: {file_path_abs}")
        import asyncio

        return asyncio.run(
            self.scan_file(
                file_path=file_path,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                severity_threshold=severity_threshold,
            )
        )

    async def scan_code(
        self,
        source_code: str,
        file_path: str,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Scan source code using Semgrep and LLM analysis with auto-detected language.

        Args:
            source_code: Source code to scan
            file_path: Path to the source file (used for language auto-detection)
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            use_validation: Whether to use LLM validation for findings
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            Enhanced scan result
        """
        file_path_abs = str(Path(file_path).resolve())

        # Auto-detect language from file path
        language = self._detect_language(Path(file_path))

        logger.info(f"=== Starting code scan for {file_path_abs} ===")
        logger.debug(
            f"Scan parameters - Language: {language} (auto-detected), "
            f"LLM: {use_llm}, Semgrep: {use_semgrep}, "
            f"Severity threshold: {severity_threshold}"
        )

        scan_metadata = {
            "file_path": file_path,
            "language": language,
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

        # Store LLM status for consistency with semgrep
        if self.llm_analyzer:
            llm_status = self.llm_analyzer.get_status()
            scan_metadata["llm_status"] = llm_status
            logger.debug(f"LLM status: {llm_status}")
        else:
            scan_metadata["llm_status"] = {
                "available": False,
                "installation_status": "not_initialized",
                "description": "LLM analyzer not initialized",
            }

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
                    logger.error(f"Semgrep scan failed for {file_path_abs}: {e}")
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

        # Apply LLM validation if enabled
        validation_results = {}
        if use_validation and self.enable_llm_validation and self.llm_validator:
            # Combine all threats for validation
            all_threats_for_validation = llm_threats + semgrep_threats

            if all_threats_for_validation:
                logger.info(
                    f"Validating {len(all_threats_for_validation)} findings with LLM validator"
                )
                try:
                    validation_results = self.llm_validator.validate_findings(
                        findings=all_threats_for_validation,
                        source_code=source_code,
                        file_path=file_path,
                        generate_exploits=True,
                    )

                    # Filter false positives based on validation
                    llm_threats = self.llm_validator.filter_false_positives(
                        llm_threats, validation_results
                    )
                    semgrep_threats = self.llm_validator.filter_false_positives(
                        semgrep_threats, validation_results
                    )

                    # Add validation stats to metadata
                    scan_metadata["llm_validation_success"] = True
                    scan_metadata["llm_validation_stats"] = (
                        self.llm_validator.get_validation_stats(validation_results)
                    )
                    logger.info(
                        f"Validation complete - filtered to {len(llm_threats) + len(semgrep_threats)} legitimate findings"
                    )

                except Exception as e:
                    logger.error(f"LLM validation failed: {e}")
                    scan_metadata["llm_validation_success"] = False
                    scan_metadata["llm_validation_error"] = str(e)
        else:
            scan_metadata["llm_validation_success"] = False
            if not use_validation:
                scan_metadata["llm_validation_reason"] = "disabled"
            elif not self.enable_llm_validation:
                scan_metadata["llm_validation_reason"] = "disabled"
            else:
                scan_metadata["llm_validation_reason"] = "not_available"

        result = EnhancedScanResult(
            file_path=file_path,
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=scan_metadata,
            validation_results=validation_results,
        )

        logger.info(
            f"=== Code scan complete for {file_path} - "
            f"Total threats: {len(result.all_threats)} ==="
        )

        return result

    async def scan_file(
        self,
        file_path: Path,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Scan a single file using enhanced scanning with auto-detected language.

        Args:
            file_path: Path to the file to scan (used for language auto-detection)
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            use_validation: Whether to use LLM validation for findings
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            Enhanced scan result
        """
        file_path_abs = str(Path(file_path).resolve())
        logger.info(f"=== Starting file scan: {file_path_abs} ===")

        if not file_path.exists():
            logger.error(f"File not found: {file_path_abs}")
            raise FileNotFoundError(f"File not found: {file_path}")

        # Auto-detect language from file extension
        logger.debug(f"Auto-detecting language for: {file_path_abs}")
        language = self._detect_language(file_path)
        logger.info(f"Detected language: {language}")

        scan_metadata = {
            "file_path": str(file_path),
            "language": language,
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

        # Store LLM status for consistency with semgrep
        if self.llm_analyzer:
            llm_status = self.llm_analyzer.get_status()
            scan_metadata["llm_status"] = llm_status
            logger.debug(f"LLM status: {llm_status}")
        else:
            scan_metadata["llm_status"] = {
                "available": False,
                "installation_status": "not_initialized",
                "description": "LLM analyzer not initialized",
            }

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
                    logger.error(f"Semgrep scan failed for {file_path_abs}: {e}")
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
                logger.error(f"LLM analysis failed for {file_path_abs}: {e}")
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

        # Apply LLM validation if enabled
        validation_results = {}
        if use_validation and self.enable_llm_validation and self.llm_validator:
            # Combine all threats for validation
            all_threats_for_validation = llm_threats + semgrep_threats

            if all_threats_for_validation:
                logger.info(
                    f"Validating {len(all_threats_for_validation)} findings with LLM validator"
                )
                try:
                    # Read file content for validation
                    with open(file_path, encoding="utf-8") as f:
                        source_code = f.read()

                    validation_results = self.llm_validator.validate_findings(
                        findings=all_threats_for_validation,
                        source_code=source_code,
                        file_path=str(file_path),
                        generate_exploits=True,
                    )

                    # Filter false positives based on validation
                    llm_threats = self.llm_validator.filter_false_positives(
                        llm_threats, validation_results
                    )
                    semgrep_threats = self.llm_validator.filter_false_positives(
                        semgrep_threats, validation_results
                    )

                    # Add validation stats to metadata
                    scan_metadata["llm_validation_success"] = True
                    scan_metadata["llm_validation_stats"] = (
                        self.llm_validator.get_validation_stats(validation_results)
                    )
                    logger.info(
                        f"Validation complete - filtered to {len(llm_threats) + len(semgrep_threats)} legitimate findings"
                    )

                except Exception as e:
                    logger.error(f"LLM validation failed: {e}")
                    scan_metadata["llm_validation_success"] = False
                    scan_metadata["llm_validation_error"] = str(e)
        else:
            scan_metadata["llm_validation_success"] = False
            if not use_validation:
                scan_metadata["llm_validation_reason"] = "disabled"
            elif not self.enable_llm_validation:
                scan_metadata["llm_validation_reason"] = "disabled"
            else:
                scan_metadata["llm_validation_reason"] = "not_available"

        result = EnhancedScanResult(
            file_path=str(file_path),
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=scan_metadata,
            validation_results=validation_results,
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
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> list[EnhancedScanResult]:
        """Scan a directory using enhanced scanning with optimized approach.

        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            use_validation: Whether to use LLM validation for findings
            severity_threshold: Minimum severity threshold for filtering

        Returns:
            List of enhanced scan results
        """
        directory_path_obj = Path(directory_path).resolve()
        directory_path_abs = str(directory_path_obj)
        logger.info(f"=== Starting directory scan: {directory_path_abs} ===")
        logger.debug(
            f"Directory scan parameters - Recursive: {recursive}, "
            f"LLM: {use_llm}, Semgrep: {use_semgrep}"
        )

        if not directory_path_obj.exists():
            logger.error(f"Directory not found: {directory_path_abs}")
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # Initialize file filter with smart exclusions
        config = self.credential_manager.load_config()
        file_filter = FileFilter(
            root_path=directory_path_obj,
            max_file_size_mb=config.max_file_size_mb,
            respect_gitignore=True,
        )

        # Find all files to scan with intelligent filtering
        all_files = []
        pattern = "**/*" if recursive else "*"
        logger.debug(f"Discovering files with pattern: {pattern}")

        for file_path in directory_path_obj.glob(pattern):
            if file_path.is_file():
                all_files.append(file_path)

        logger.info(f"Discovered {len(all_files)} total files")

        # Apply smart filtering
        files_to_scan = file_filter.filter_files(all_files)

        logger.info(f"After filtering: {len(files_to_scan)} files to scan")
        if len(all_files) > len(files_to_scan):
            logger.info(
                f"Filtered out {len(all_files) - len(files_to_scan)} files (.gitignore, binary, too large, etc.)"
            )

        # Perform Semgrep scanning once for entire directory if enabled
        directory_semgrep_threats = {}  # Map file_path -> list[ThreatMatch]
        semgrep_scan_metadata = {}

        # Always get semgrep status for metadata consistency
        semgrep_status = self.semgrep_scanner.get_status()

        if use_semgrep and self.enable_semgrep_analysis:
            logger.info("Starting directory-level Semgrep scan...")
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
                )

                # Convert LLM findings to threats and group by file
                all_llm_threats = []
                for finding in all_llm_findings:
                    threat = finding.to_threat_match(finding.file_path)
                    all_llm_threats.append(threat)
                    file_path = finding.file_path
                    logger.debug(f"Processing LLM finding for file: {file_path}")
                    if file_path not in directory_llm_threats:
                        directory_llm_threats[file_path] = []
                    directory_llm_threats[file_path].append(threat)
                    logger.debug(
                        f"Added threat to directory_llm_threats[{file_path}], now has {len(directory_llm_threats[file_path])} threats"
                    )

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

        # Process files in parallel with concurrency control
        logger.info(f"Processing {len(files_to_scan)} files in parallel...")

        # Handle case when no files to scan
        if not files_to_scan:
            logger.info("No files to scan after filtering")
            return []

        # Create a semaphore to limit concurrent operations
        cpu_count = os.cpu_count() or 4  # Default to 4 if cpu_count returns None
        max_workers = min(32, cpu_count + 4, len(files_to_scan))
        semaphore = asyncio.Semaphore(max_workers)
        logger.info(f"Using {max_workers} parallel workers")

        # Create tasks for parallel processing
        tasks = []
        for file_path in files_to_scan:
            task = self._process_single_file(
                file_path=file_path,
                directory_semgrep_threats=directory_semgrep_threats,
                directory_llm_threats=directory_llm_threats,
                semgrep_scan_metadata=semgrep_scan_metadata,
                llm_scan_metadata=llm_scan_metadata,
                semgrep_status=semgrep_status,
                use_llm=use_llm,
                use_semgrep=use_semgrep,
                use_validation=use_validation,
                severity_threshold=severity_threshold,
                semaphore=semaphore,
            )
            tasks.append(task)

        # Execute tasks in batches to avoid overwhelming memory
        batch_size = min(max_workers * 2, 50)  # Process in batches
        final_results: list[EnhancedScanResult] = []
        successful_scans = 0
        failed_scans = 0

        logger.info(f"Processing {len(tasks)} tasks in batches of {batch_size}")

        for i in range(0, len(tasks), batch_size):
            batch_tasks = tasks[i : i + batch_size]
            batch_files = files_to_scan[i : i + batch_size]

            logger.debug(
                f"Processing batch {i//batch_size + 1}: files {i+1}-{min(i+batch_size, len(tasks))}"
            )

            # Execute current batch
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            # Process batch results
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to process file {batch_files[j]}: {result}")
                    failed_scans += 1
                    # Create error result
                    error_result = EnhancedScanResult(
                        file_path=str(batch_files[j]),
                        llm_threats=[],
                        semgrep_threats=[],
                        scan_metadata={
                            "file_path": str(batch_files[j]),
                            "error": str(result),
                            "directory_scan": True,
                            "parallel_processing": True,
                            "batch_processing": True,
                            **semgrep_scan_metadata,
                            **llm_scan_metadata,
                        },
                    )
                    final_results.append(error_result)
                elif isinstance(result, EnhancedScanResult):
                    successful_scans += 1
                    final_results.append(result)
                else:
                    # This shouldn't happen, but handle it gracefully
                    logger.warning(
                        f"Unexpected result type for {batch_files[j]}: {type(result)}"
                    )
                    failed_scans += 1

            # Log progress after each batch
            logger.info(
                f"Completed batch {i//batch_size + 1}/{(len(tasks) + batch_size - 1)//batch_size}"
            )

            # Optional: Yield results incrementally (for future streaming support)
            # This could be expanded to yield batches to the caller

        logger.info(
            f"=== Parallel directory scan complete - Processed {len(final_results)} files "
            f"(Success: {successful_scans}, Failed: {failed_scans}) in {(len(tasks) + batch_size - 1)//batch_size} batches ==="
        )
        return final_results

    async def _process_single_file(
        self,
        file_path: Path,
        directory_semgrep_threats: dict[str, list[ThreatMatch]],
        directory_llm_threats: dict[str, list[ThreatMatch]],
        semgrep_scan_metadata: dict[str, Any],
        llm_scan_metadata: dict[str, Any],
        semgrep_status: dict[str, Any],
        use_llm: bool,
        use_semgrep: bool,
        use_validation: bool,
        severity_threshold: Severity | None,
        semaphore: asyncio.Semaphore,
    ) -> EnhancedScanResult:
        """Process a single file for scanning (used in parallel processing).

        Args:
            file_path: Path to the file to process
            directory_semgrep_threats: Threats found by directory-level Semgrep scan
            directory_llm_threats: Threats found by directory-level LLM scan
            semgrep_scan_metadata: Metadata from Semgrep scan
            llm_scan_metadata: Metadata from LLM scan
            semgrep_status: Semgrep status information
            use_llm: Whether LLM analysis is enabled
            use_semgrep: Whether Semgrep analysis is enabled
            use_validation: Whether LLM validation is enabled
            severity_threshold: Minimum severity threshold
            semaphore: Semaphore for concurrency control

        Returns:
            EnhancedScanResult for the file
        """
        async with semaphore:  # Limit concurrent operations
            file_path_abs = str(Path(file_path).resolve())
            logger.debug(f"Processing file: {file_path_abs}")

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
                "language": language,
                "use_llm": use_llm and self.enable_llm_analysis,
                "use_semgrep": use_semgrep and self.enable_semgrep_analysis,
                "directory_scan": True,
                "parallel_processing": True,
                "semgrep_source": "directory_scan",
                "llm_source": "directory_scan",
            }

            # Add directory scan metadata
            scan_metadata.update(semgrep_scan_metadata)
            scan_metadata.update(llm_scan_metadata)

            # Add semgrep status
            scan_metadata["semgrep_status"] = semgrep_status

            # Add LLM status for consistency
            if self.llm_analyzer:
                llm_status = self.llm_analyzer.get_status()
                scan_metadata["llm_status"] = llm_status
            else:
                scan_metadata["llm_status"] = {
                    "available": False,
                    "installation_status": "not_initialized",
                    "description": "LLM analyzer not initialized",
                }

            # Filter by severity threshold if specified
            if severity_threshold:
                file_llm_threats = self._filter_by_severity(
                    file_llm_threats, severity_threshold
                )
                file_semgrep_threats = self._filter_by_severity(
                    file_semgrep_threats, severity_threshold
                )

            # Apply LLM validation if enabled
            validation_results = {}
            if use_validation and self.enable_llm_validation and self.llm_validator:
                # Combine all threats for validation
                all_threats_for_validation = file_llm_threats + file_semgrep_threats

                if all_threats_for_validation:
                    logger.debug(
                        f"Validating {len(all_threats_for_validation)} findings for {file_path.name}"
                    )
                    try:
                        # Use streaming for large files, regular read for small files
                        config = self.credential_manager.load_config()
                        if is_file_too_large(
                            file_path, max_size_mb=config.max_file_size_mb
                        ):
                            logger.debug(
                                f"Using streaming read for large file: {file_path}"
                            )
                            streaming_reader = StreamingFileReader()
                            source_code = await streaming_reader.get_file_preview(
                                file_path,
                                preview_size=10000,  # 10KB preview for validation
                            )
                        else:
                            # Read small files normally
                            with open(file_path, encoding="utf-8") as f:
                                source_code = f.read()

                        validation_results = self.llm_validator.validate_findings(
                            findings=all_threats_for_validation,
                            source_code=source_code,
                            file_path=str(file_path),
                            generate_exploits=True,
                        )

                        # Filter false positives based on validation
                        file_llm_threats = self.llm_validator.filter_false_positives(
                            file_llm_threats, validation_results
                        )
                        file_semgrep_threats = (
                            self.llm_validator.filter_false_positives(
                                file_semgrep_threats, validation_results
                            )
                        )

                        # Add validation stats to metadata
                        scan_metadata["llm_validation_success"] = True
                        scan_metadata["llm_validation_stats"] = (
                            self.llm_validator.get_validation_stats(validation_results)
                        )

                    except Exception as e:
                        logger.debug(f"LLM validation failed for {file_path.name}: {e}")
                        scan_metadata["llm_validation_success"] = False
                        scan_metadata["llm_validation_error"] = str(e)
            else:
                scan_metadata["llm_validation_success"] = False
                if not use_validation:
                    scan_metadata["llm_validation_reason"] = "disabled"
                elif not self.enable_llm_validation:
                    scan_metadata["llm_validation_reason"] = "disabled"
                else:
                    scan_metadata["llm_validation_reason"] = "not_available"

            # Create result for this file
            result = EnhancedScanResult(
                file_path=str(file_path),
                llm_threats=file_llm_threats,
                semgrep_threats=file_semgrep_threats,
                scan_metadata=scan_metadata,
                validation_results=validation_results,
            )

            return result

    async def scan_directory_streaming(
        self,
        directory_path: Path,
        recursive: bool = True,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
        batch_size: int = 10,
    ):
        """Streaming version of scan_directory that yields results in batches.

        This method yields EnhancedScanResult objects as they are completed,
        allowing for progressive processing of large directories without
        accumulating all results in memory.

        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            use_llm: Whether to use LLM analysis
            use_semgrep: Whether to use Semgrep analysis
            use_validation: Whether to use LLM validation for findings
            severity_threshold: Minimum severity threshold for filtering
            batch_size: Number of files to process in each batch

        Yields:
            EnhancedScanResult objects as they are completed
        """
        directory_path_obj = Path(directory_path).resolve()
        directory_path_abs = str(directory_path_obj)
        logger.info(f"=== Starting streaming directory scan: {directory_path_abs} ===")
        logger.debug(
            f"Streaming scan parameters - Recursive: {recursive}, "
            f"Batch size: {batch_size}, LLM: {use_llm}, Semgrep: {use_semgrep}"
        )

        if not directory_path_obj.exists():
            logger.error(f"Directory not found: {directory_path_abs}")
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # Initialize file filter with smart exclusions
        config = self.credential_manager.load_config()
        file_filter = FileFilter(
            root_path=directory_path_obj,
            max_file_size_mb=config.max_file_size_mb,
            respect_gitignore=True,
        )

        # Find all files to scan with intelligent filtering
        all_files = []
        pattern = "**/*" if recursive else "*"
        logger.debug(f"Discovering files with pattern: {pattern}")

        for file_path in directory_path_obj.glob(pattern):
            if file_path.is_file():
                all_files.append(file_path)

        logger.info(f"Discovered {len(all_files)} total files")

        # Apply smart filtering
        files_to_scan = file_filter.filter_files(all_files)

        logger.info(f"After filtering: {len(files_to_scan)} files to scan")
        if len(all_files) > len(files_to_scan):
            logger.info(
                f"Filtered out {len(all_files) - len(files_to_scan)} files (.gitignore, binary, too large, etc.)"
            )

        # Handle case when no files to scan
        if not files_to_scan:
            logger.info("No files to scan after filtering")
            return

        # Perform directory-level Semgrep and LLM scans (same as regular scan_directory)
        # ... (This would contain the same directory-level scanning logic)

        # For simplicity in this implementation, we'll process files without
        # directory-level pre-scanning and yield results as they complete

        # Create a semaphore to limit concurrent operations
        cpu_count = os.cpu_count() or 4  # Default to 4 if cpu_count returns None
        max_workers = min(32, cpu_count + 4, len(files_to_scan))
        semaphore = asyncio.Semaphore(max_workers)
        logger.info(f"Using {max_workers} parallel workers for streaming scan")

        # Process files in batches and yield results
        successful_scans = 0
        failed_scans = 0

        for i in range(0, len(files_to_scan), batch_size):
            batch_files = files_to_scan[i : i + batch_size]
            logger.debug(
                f"Processing streaming batch: files {i+1}-{min(i+batch_size, len(files_to_scan))}"
            )

            # Create tasks for this batch
            batch_tasks = []
            for file_path in batch_files:
                # For streaming, we'll do individual file scans (simpler implementation)
                task = self.scan_file(
                    file_path=file_path,
                    use_llm=use_llm,
                    use_semgrep=use_semgrep,
                    use_validation=use_validation,
                    severity_threshold=severity_threshold,
                )
                batch_tasks.append(task)

            # Execute batch and yield results as they complete
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to process file {batch_files[j]}: {result}")
                    failed_scans += 1
                    # Create error result
                    error_result = EnhancedScanResult(
                        file_path=str(batch_files[j]),
                        llm_threats=[],
                        semgrep_threats=[],
                        scan_metadata={
                            "file_path": str(batch_files[j]),
                            "error": str(result),
                            "streaming_scan": True,
                            "batch_processing": True,
                        },
                    )
                    yield error_result
                else:
                    successful_scans += 1
                    yield result

            # Log progress after each batch
            logger.debug(
                f"Streamed batch {i//batch_size + 1}/{(len(files_to_scan) + batch_size - 1)//batch_size}"
            )

        logger.info(
            f"=== Streaming directory scan complete - Processed {successful_scans + failed_scans} files "
            f"(Success: {successful_scans}, Failed: {failed_scans}) ==="
        )
