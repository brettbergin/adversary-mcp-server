"""Enhanced scanner that combines Semgrep and LLM analysis for comprehensive security scanning."""

import asyncio
import os
import time
from pathlib import Path
from typing import Any

from ..cache import CacheKey, CacheManager, CacheType, SerializableThreatMatch
from ..config import get_app_cache_dir
from ..config_manager import get_config_manager
from ..credentials import CredentialManager, get_credential_manager
from ..database.models import AdversaryDatabase
from ..logger import get_logger
from ..monitoring import MetricsCollector
from ..resilience import ErrorHandler, ResilienceConfig
from ..telemetry.integration import MetricsCollectionOrchestrator
from ..telemetry.service import TelemetryService
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
        llm_usage_stats: dict[str, Any] | None = None,
    ):
        """Initialize enhanced scan result.

        Args:
            file_path: Path to the scanned file
            llm_threats: Threats found by LLM analysis
            semgrep_threats: Threats found by Semgrep analysis
            scan_metadata: Metadata about the scan
            validation_results: Optional validation results from LLM validator
            llm_usage_stats: Optional LLM usage statistics (tokens, cost, etc.)
        """
        self.file_path = file_path
        # Auto-detect language from file path
        self.language = self._detect_language_from_path(file_path)
        self.llm_threats = llm_threats
        self.semgrep_threats = semgrep_threats
        self.scan_metadata = scan_metadata
        self.validation_results = validation_results or {}
        self.llm_usage_stats = llm_usage_stats or self._create_default_usage_stats()

        # Combine and deduplicate threats
        self.all_threats = self._combine_threats()

        # Calculate statistics
        self.stats = self._calculate_stats()

    def _create_default_usage_stats(self) -> dict[str, Any]:
        """Create default LLM usage statistics structure.

        Returns:
            Dictionary with default usage statistics
        """
        return {
            "analysis": {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_cost": 0.0,
                "currency": "USD",
                "api_calls": 0,
                "models_used": [],
            },
            "validation": {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_cost": 0.0,
                "currency": "USD",
                "api_calls": 0,
                "models_used": [],
            },
            "combined": {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_cost": 0.0,
                "currency": "USD",
                "api_calls": 0,
                "models_used": [],
            },
        }

    def _detect_language_from_path(self, file_path: str) -> str:
        """Detect programming language from file extension using shared mapper.

        Args:
            file_path: Path to the file

        Returns:
            Programming language name (e.g., 'typescript', 'python', 'javascript')
        """
        from .language_mapping import LanguageMapper

        return LanguageMapper.detect_language_from_extension(file_path)

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
            # Handle both string categories and enum categories
            if hasattr(threat.category, "value"):
                category = threat.category.value
            else:
                category = str(threat.category)
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

    def add_llm_usage(self, usage_type: str, cost_breakdown: dict[str, Any]) -> None:
        """Add LLM usage data to statistics.

        Args:
            usage_type: Type of usage ('analysis' or 'validation')
            cost_breakdown: Cost breakdown from PricingManager
        """
        if usage_type not in self.llm_usage_stats:
            logger.warning(f"Unknown usage type: {usage_type}")
            return

        usage_section = self.llm_usage_stats[usage_type]
        tokens = cost_breakdown.get("tokens", {})

        # Add to specific section
        usage_section["total_tokens"] += tokens.get("total_tokens", 0)
        usage_section["prompt_tokens"] += tokens.get("prompt_tokens", 0)
        usage_section["completion_tokens"] += tokens.get("completion_tokens", 0)
        usage_section["total_cost"] += cost_breakdown.get("total_cost", 0.0)
        usage_section["api_calls"] += 1

        model = cost_breakdown.get("model")
        if model and model not in usage_section["models_used"]:
            usage_section["models_used"].append(model)

        # Update combined totals
        combined = self.llm_usage_stats["combined"]
        combined["total_tokens"] += tokens.get("total_tokens", 0)
        combined["prompt_tokens"] += tokens.get("prompt_tokens", 0)
        combined["completion_tokens"] += tokens.get("completion_tokens", 0)
        combined["total_cost"] += cost_breakdown.get("total_cost", 0.0)
        combined["api_calls"] += 1

        if model and model not in combined["models_used"]:
            combined["models_used"].append(model)

        logger.debug(
            f"Added {usage_type} usage: {tokens.get('total_tokens', 0)} tokens, "
            f"${cost_breakdown.get('total_cost', 0.0):.6f}"
        )

    def get_validation_summary(self) -> dict[str, Any]:
        """Get validation summary for this scan result.

        Returns:
            Dictionary with validation statistics and metadata
        """
        # Check if validation was performed
        validation_enabled = self.scan_metadata.get("llm_validation_success", False)

        if not validation_enabled or not self.validation_results:
            return {
                "enabled": False,
                "total_findings_reviewed": 0,
                "legitimate_findings": 0,
                "false_positives_filtered": 0,
                "false_positive_rate": 0.0,
                "average_confidence": 0.0,
                "validation_errors": 0,
                "status": self.scan_metadata.get("llm_validation_reason", "disabled"),
            }

        # Calculate validation statistics from validation_results
        total_reviewed = len(self.validation_results)
        legitimate = sum(1 for v in self.validation_results.values() if v.is_legitimate)
        false_positives = total_reviewed - legitimate

        # Calculate average confidence
        avg_confidence = 0.0
        if total_reviewed > 0:
            avg_confidence = (
                sum(v.confidence for v in self.validation_results.values())
                / total_reviewed
            )

        # Count validation errors
        validation_errors = sum(
            1 for v in self.validation_results.values() if v.validation_error
        )

        return {
            "enabled": True,
            "total_findings_reviewed": total_reviewed,
            "legitimate_findings": legitimate,
            "false_positives_filtered": false_positives,
            "false_positive_rate": (
                false_positives / total_reviewed if total_reviewed > 0 else 0.0
            ),
            "average_confidence": round(avg_confidence, 3),
            "validation_errors": validation_errors,
            "status": "completed",
        }


class ScanEngine:
    """Scan engine combining Semgrep and LLM analysis."""

    def __init__(
        self,
        credential_manager: CredentialManager | None = None,
        cache_manager: CacheManager | None = None,
        metrics_collector: MetricsCollector | None = None,
        metrics_orchestrator: MetricsCollectionOrchestrator | None = None,
        enable_llm_analysis: bool = True,
        enable_semgrep_analysis: bool = True,
        enable_llm_validation: bool = True,
    ):
        """Initialize enhanced scanner.

        Args:
            credential_manager: Credential manager for configuration
            cache_manager: Optional cache manager for scan results
            metrics_collector: Optional legacy metrics collector for performance monitoring
            metrics_orchestrator: Optional telemetry orchestrator for comprehensive tracking
            enable_llm_analysis: Whether to enable LLM analysis
            enable_semgrep_analysis: Whether to enable Semgrep analysis
            enable_llm_validation: Whether to enable LLM validation of findings
        """
        logger.info("=== Initializing ScanEngine ===")
        self.credential_manager = credential_manager or get_credential_manager()
        self.cache_manager = cache_manager
        self.metrics_collector = metrics_collector
        self.config_manager = get_config_manager()

        # Initialize telemetry system
        self.metrics_orchestrator = metrics_orchestrator
        if self.metrics_orchestrator is None:
            try:
                db = AdversaryDatabase()
                telemetry_service = TelemetryService(db)
                self.metrics_orchestrator = MetricsCollectionOrchestrator(
                    telemetry_service
                )
                logger.debug("Initialized telemetry system for scan engine")
            except Exception as e:
                logger.warning(f"Failed to initialize telemetry system: {e}")
                self.metrics_orchestrator = None

        logger.debug("Initialized core components")

        # Load configuration
        config = self.credential_manager.load_config()

        # Initialize cache manager if not provided (be robust to mocked configs)
        try:
            enable_caching_flag = bool(getattr(config, "enable_caching", True))
        except Exception:
            enable_caching_flag = True

        if cache_manager is None and enable_caching_flag:
            cache_dir = get_app_cache_dir()
            # Use dynamic limits for cache configuration
            max_size_mb_num = self.config_manager.dynamic_limits.cache_max_size_mb
            max_age_hours_num = self.config_manager.dynamic_limits.cache_max_age_hours

            self.cache_manager = CacheManager(
                cache_dir=cache_dir,
                max_size_mb=max_size_mb_num,
                max_age_hours=max_age_hours_num,
                metrics_collector=self.metrics_collector,
            )
            logger.info(f"Initialized cache manager for scan engine at {cache_dir}")

        # Initialize ErrorHandler for scan engine resilience
        resilience_config = ResilienceConfig(
            enable_circuit_breaker=True,
            failure_threshold=self.config_manager.dynamic_limits.circuit_breaker_failure_threshold,
            recovery_timeout_seconds=self.config_manager.dynamic_limits.recovery_timeout_seconds,
            enable_retry=True,
            max_retry_attempts=self.config_manager.dynamic_limits.max_retry_attempts,
            base_delay_seconds=self.config_manager.dynamic_limits.retry_base_delay,
            enable_graceful_degradation=True,
        )
        self.error_handler = ErrorHandler(resilience_config)
        logger.info("Initialized ErrorHandler for scan engine resilience")

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
            credential_manager=self.credential_manager,
            metrics_collector=self.metrics_collector,
        )

        # Check if Semgrep scanning is available and enabled
        self.enable_semgrep_analysis = (
            self.enable_semgrep_analysis
            and bool(getattr(config, "enable_semgrep_scanning", True))
            and self.semgrep_scanner.is_available()
        )
        logger.info(f"Semgrep analysis enabled: {self.enable_semgrep_analysis}")

        if not self.semgrep_scanner.is_available():
            logger.warning(
                "Semgrep not available - install semgrep for enhanced analysis"
            )

        # Initialize LLM analyzer if enabled - pass shared cache manager
        self.llm_analyzer = None
        if self.enable_llm_analysis:
            logger.debug("Initializing LLM analyzer...")
            self.llm_analyzer = LLMScanner(
                self.credential_manager, self.cache_manager, self.metrics_collector
            )
            if not self.llm_analyzer.is_available():
                logger.warning(
                    "LLM analysis requested but not available - API key not configured"
                )
                self.enable_llm_analysis = False
            else:
                logger.info("LLM analyzer initialized successfully")
        else:
            logger.debug("LLM analysis disabled")

        # Initialize LLM validator if enabled - pass shared cache manager
        self.llm_validator = None
        if self.enable_llm_validation:
            logger.debug("Initializing LLM validator...")
            self.llm_validator = LLMValidator(
                self.credential_manager, self.cache_manager, self.metrics_collector
            )
            logger.info("LLM validator initialized successfully")
        else:
            logger.debug("LLM validation disabled")

        logger.info("=== ScanEngine initialization complete ===")

    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension using language mapping.

        Args:
            file_path: Path to the file

        Returns:
            Programming language name (e.g., 'python', 'javascript') or 'generic' for unknown
        """
        from .language_mapping import LanguageMapper

        detected_language = LanguageMapper.detect_language_from_extension(file_path)
        logger.debug(f"Language detected for {file_path}: {detected_language}")
        return detected_language

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

    def _apply_validation_filter(
        self,
        threats: list[ThreatMatch],
        validation_results: dict[str, Any],
        confidence_threshold: float = 0.7,
    ) -> list[ThreatMatch]:
        """Filter threats using validation results without relying on external return values.

        Keeps threats that are either not present in validation results or explicitly
        marked legitimate with sufficient confidence.
        """
        if not threats or not validation_results:
            return threats

        filtered: list[ThreatMatch] = []
        for threat in threats:
            threat_uuid = getattr(threat, "uuid", None)
            if threat_uuid is None:
                filtered.append(threat)
                continue

            validation = validation_results.get(threat_uuid)
            if validation is None:
                filtered.append(threat)
                continue

            is_legitimate = getattr(validation, "is_legitimate", True)
            confidence = getattr(validation, "confidence", 1.0)
            if is_legitimate and confidence >= confidence_threshold:
                filtered.append(threat)

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
            self.llm_analyzer = LLMScanner(
                self.credential_manager, self.cache_manager, self.metrics_collector
            )

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
            self.llm_analyzer = LLMScanner(
                self.credential_manager, self.cache_manager, self.metrics_collector
            )
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
        scan_start_time = time.time()
        file_path_abs = str(Path(file_path).resolve())

        # Record scan start (legacy metrics)
        if self.metrics_collector:
            self.metrics_collector.record_scan_start("code", file_count=1)

        # Use telemetry context manager for comprehensive tracking
        if self.metrics_orchestrator:
            logger.debug("Using metrics orchestrator for code scan tracking")
            with self.metrics_orchestrator.track_scan_execution(
                trigger_source="scan_engine",
                scan_type="code",
                target_path=file_path_abs,
                semgrep_enabled=use_semgrep,
                llm_enabled=use_llm,
                validation_enabled=use_validation,
                file_count=1,
            ) as scan_context:
                logger.debug(
                    "Scan context created, executing scan with telemetry tracking"
                )
                return await self._scan_code_with_context(
                    scan_context,
                    source_code,
                    file_path_abs,
                    use_llm,
                    use_semgrep,
                    use_validation,
                    severity_threshold,
                )
        else:
            # Fallback without telemetry tracking
            logger.debug(
                "No metrics orchestrator available, executing scan without telemetry"
            )
            return await self._scan_code_with_context(
                None,
                source_code,
                file_path_abs,
                use_llm,
                use_semgrep,
                use_validation,
                severity_threshold,
            )

    async def _scan_code_with_context(
        self,
        scan_context,
        source_code: str,
        file_path: str,
        use_llm: bool,
        use_semgrep: bool,
        use_validation: bool,
        severity_threshold: Severity | None,
    ) -> EnhancedScanResult:
        """Internal scan code implementation with telemetry context."""
        scan_start_time = time.time()
        file_path_abs = str(Path(file_path).resolve())

        # Check cache first if enabled
        cached_result = await self._get_cached_scan_result(
            source_code,
            file_path_abs,
            use_llm,
            use_semgrep,
            use_validation,
            severity_threshold,
        )
        if cached_result:
            logger.info(f"Cache hit for scan: {file_path_abs}")
            return cached_result

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
                        severity_threshold=severity_threshold,
                    )
                    logger.info(
                        f"Semgrep scan completed - found {len(semgrep_threats)} threats"
                    )

                    # Record individual threat findings in telemetry
                    for threat in semgrep_threats:
                        scan_context.add_threat_finding(threat, "semgrep")

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

        # Perform LLM analysis if enabled
        llm_threats = []
        if use_llm and self.enable_llm_analysis and self.llm_analyzer:
            logger.info("Starting LLM analysis...")
            try:
                logger.debug("Calling LLM analyzer for code analysis...")
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

                # Record individual threat findings in telemetry
                for threat in llm_threats:
                    scan_context.add_threat_finding(threat, "llm")

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
            elif not self.enable_llm_analysis:
                reason = "disabled_in_config"
                logger.debug("LLM analysis disabled in configuration")
            elif not self.llm_analyzer:
                reason = "not_initialized"
                logger.debug("LLM analyzer not initialized")
            else:
                reason = "not_available"
                logger.debug("LLM analysis not available - check configuration")
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

        # Debug logging for validation conditions
        logger.debug("Validation conditions check:")
        logger.debug(f"  use_validation: {use_validation}")
        logger.debug(f"  self.enable_llm_validation: {self.enable_llm_validation}")
        logger.debug(f"  self.llm_validator: {self.llm_validator is not None}")
        logger.debug(f"  self.llm_validator type: {type(self.llm_validator)}")

        if use_validation and self.enable_llm_validation and self.llm_validator:
            # Combine all threats for validation
            all_threats_for_validation = llm_threats + semgrep_threats

            if all_threats_for_validation:
                # Check if validator is fully functional or using fallback
                if self.llm_validator.is_fully_functional():
                    logger.info(
                        f"Validating {len(all_threats_for_validation)} findings with LLM validator (full mode)"
                    )
                    scan_metadata["llm_validation_mode"] = "full"
                else:
                    logger.info(
                        f"Validating {len(all_threats_for_validation)} findings with LLM validator (fallback mode)"
                    )
                    scan_metadata["llm_validation_mode"] = "fallback"
                try:
                    validation_results = (
                        await self.llm_validator._validate_findings_async(
                            findings=all_threats_for_validation,
                            source_code=source_code,
                            file_path=file_path,
                            generate_exploits=True,
                        )
                    )

                    # Store validation results in scan context for atomic database updates
                    if (
                        "scan_context" in locals()
                        and scan_context
                        and validation_results
                    ):
                        scan_context.set_validation_results(validation_results)

                    # Filter false positives based on validation
                    # Call validator (for side effects/mocking in tests) and use its return if valid,
                    # otherwise fall back to internal filter for robustness
                    try:
                        llm_filtered = self.llm_validator.filter_false_positives(
                            llm_threats, validation_results
                        )
                    except Exception:
                        llm_filtered = None

                    if isinstance(llm_filtered, list):
                        llm_threats = llm_filtered
                    else:
                        llm_threats = self._apply_validation_filter(
                            llm_threats, validation_results
                        )

                    try:
                        semgrep_filtered = self.llm_validator.filter_false_positives(
                            semgrep_threats, validation_results
                        )
                    except Exception:
                        semgrep_filtered = None

                    if isinstance(semgrep_filtered, list):
                        semgrep_threats = semgrep_filtered
                    else:
                        semgrep_threats = self._apply_validation_filter(
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
            logger.debug("Validation conditions not met - entering else clause")
            scan_metadata["llm_validation_success"] = False
            if not use_validation:
                logger.debug("Reason: use_validation=False")
                scan_metadata["llm_validation_reason"] = "disabled"
            elif not self.enable_llm_validation:
                logger.debug("Reason: self.enable_llm_validation=False")
                scan_metadata["llm_validation_reason"] = "disabled"
            else:
                logger.debug("Reason: self.llm_validator is None or falsy")
                scan_metadata["llm_validation_reason"] = "not_available"

        # Create enhanced scan result with LLM usage tracking
        result = EnhancedScanResult(
            file_path=file_path,
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=scan_metadata,
            validation_results=validation_results,
            llm_usage_stats=None,  # Will be populated by LLM components
        )

        # Cache the scan result if caching is enabled
        await self._cache_scan_result(
            result,
            source_code,
            file_path_abs,
            use_llm,
            use_semgrep,
            use_validation,
            severity_threshold,
        )

        logger.info(
            f"=== Code scan complete for {file_path} - "
            f"Total threats: {len(result.all_threats)} ==="
        )

        # Record scan completion
        if self.metrics_collector:
            duration = time.time() - scan_start_time
            self.metrics_collector.record_scan_completion(
                "code", duration, success=True, findings_count=len(result.all_threats)
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
        scan_start_time = time.time()
        file_path_abs = str(Path(file_path).resolve())
        logger.info(f"=== Starting file scan: {file_path_abs} ===")
        logger.info(
            f"SCAN ENGINE DEBUG: use_validation={use_validation}, type={type(use_validation)}"
        )

        if not file_path.exists():
            logger.error(f"File not found: {file_path_abs}")
            raise FileNotFoundError(f"File not found: {file_path}")

        # Record scan start
        if self.metrics_collector:
            self.metrics_collector.record_scan_start("file", file_count=1)

        # Use telemetry context manager for comprehensive tracking
        if self.metrics_orchestrator:
            with self.metrics_orchestrator.track_scan_execution(
                trigger_source="scan_engine",
                scan_type="file",
                target_path=file_path_abs,
                semgrep_enabled=use_semgrep,
                llm_enabled=use_llm,
                validation_enabled=use_validation,
                file_count=1,
            ) as scan_context:
                return await self._scan_file_with_context(
                    scan_context,
                    file_path,
                    file_path_abs,
                    use_llm,
                    use_semgrep,
                    use_validation,
                    severity_threshold,
                )
        else:
            # Fallback without telemetry tracking
            return await self._scan_file_with_context(
                None,
                file_path,
                file_path_abs,
                use_llm,
                use_semgrep,
                use_validation,
                severity_threshold,
            )

    async def _scan_file_with_context(
        self,
        scan_context,
        file_path: Path,
        file_path_abs: str,
        use_llm: bool,
        use_semgrep: bool,
        use_validation: bool,
        severity_threshold: Severity | None,
    ) -> EnhancedScanResult:
        """Internal scan file implementation with telemetry context."""
        scan_start_time = time.time()
        # Check cache if available
        cache_key = None
        cached_result = None
        if self.cache_manager:
            # Read file content for hashing
            try:
                file_content = file_path.read_text(encoding="utf-8", errors="replace")
                # Create cache key with scan parameters
                content_hash = self.cache_manager.get_hasher().hash_content(
                    file_content
                )
                metadata = {
                    "use_llm": use_llm and self.enable_llm_analysis,
                    "use_semgrep": use_semgrep and self.enable_semgrep_analysis,
                    "use_validation": use_validation and self.enable_llm_validation,
                    "severity_threshold": (
                        str(severity_threshold) if severity_threshold else None
                    ),
                }
                metadata_hash = self.cache_manager.get_hasher().hash_metadata(metadata)

                from ..cache.types import CacheKey, CacheType

                cache_key = CacheKey(
                    cache_type=CacheType.FILE_ANALYSIS,
                    content_hash=content_hash,
                    metadata_hash=metadata_hash,
                )

                cached_result = self.cache_manager.get(cache_key)
                if cached_result:
                    logger.info(f"Cache hit for file scan: {file_path_abs}")
                    # Add cache metadata to result
                    cached_result.scan_metadata["cache_hit"] = True
                    cached_result.scan_metadata["cache_key"] = str(cache_key)
                    return cached_result
                else:
                    logger.debug(f"Cache miss for file scan: {file_path_abs}")

            except Exception as e:
                logger.warning(f"Cache check failed for {file_path_abs}: {e}")
                cache_key = None

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
                        severity_threshold=severity_threshold,
                    )
                    logger.info(
                        f"Semgrep scan completed - found {len(semgrep_threats)} threats"
                    )

                    # Record individual threat findings in telemetry
                    for threat in semgrep_threats:
                        scan_context.add_threat_finding(threat, "semgrep")

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

                # Record individual threat findings in telemetry
                for threat in llm_threats:
                    scan_context.add_threat_finding(threat, "llm")

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
            elif not self.enable_llm_analysis:
                reason = "disabled_in_config"
                logger.debug("LLM analysis disabled in configuration")
            elif not self.llm_analyzer:
                reason = "not_initialized"
                logger.debug("LLM analyzer not initialized")
            else:
                reason = "not_available"
                logger.debug("LLM analysis not available - check configuration")
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
                # Check if validator is fully functional or using fallback
                if self.llm_validator.is_fully_functional():
                    logger.info(
                        f"Validating {len(all_threats_for_validation)} findings with LLM validator (full mode)"
                    )
                    scan_metadata["llm_validation_mode"] = "full"
                else:
                    logger.info(
                        f"Validating {len(all_threats_for_validation)} findings with LLM validator (fallback mode)"
                    )
                    scan_metadata["llm_validation_mode"] = "fallback"
                # Read file content for validation
                source_code = ""
                try:
                    reader = StreamingFileReader()
                    chunks = []
                    async for chunk in reader.read_file_async(file_path):
                        chunks.append(chunk)
                    source_code = "".join(chunks)
                except Exception as e:
                    logger.error(f"Failed to read file content for validation: {e}")
                    scan_metadata["llm_validation_success"] = False
                    scan_metadata["llm_validation_error"] = (
                        f"File reading failed: {str(e)}"
                    )
                    # Continue with empty source_code for validation

                # Perform validation
                validation_results = {}  # Initialize to avoid NameError
                if source_code or True:  # Allow validation even if file reading failed
                    try:
                        validation_results = (
                            await self.llm_validator._validate_findings_async(
                                findings=all_threats_for_validation,
                                source_code=source_code,
                                file_path=str(file_path),
                                generate_exploits=True,
                            )
                        )
                        logger.debug(
                            f"Validation completed with {len(validation_results)} results"
                        )

                        # Store validation results in scan context for atomic database updates
                        if (
                            "scan_context" in locals()
                            and scan_context
                            and validation_results
                        ):
                            scan_context.set_validation_results(validation_results)
                    except Exception as e:
                        logger.error(f"LLM validation processing failed: {e}")
                        scan_metadata["llm_validation_success"] = False
                        scan_metadata["llm_validation_error"] = (
                            f"Validation processing failed: {str(e)}"
                        )
                        # Keep validation_results as empty dict for graceful handling
                        validation_results = {}

                    # Apply filtering if validation was successful
                    if validation_results:
                        try:
                            # Filter LLM threats
                            try:
                                llm_filtered = (
                                    self.llm_validator.filter_false_positives(
                                        llm_threats, validation_results
                                    )
                                )
                            except Exception:
                                llm_filtered = None

                            if isinstance(llm_filtered, list):
                                llm_threats = llm_filtered
                            else:
                                llm_threats = self._apply_validation_filter(
                                    llm_threats, validation_results
                                )

                            # Filter Semgrep threats
                            try:
                                semgrep_filtered = (
                                    self.llm_validator.filter_false_positives(
                                        semgrep_threats, validation_results
                                    )
                                )
                            except Exception:
                                semgrep_filtered = None

                            if isinstance(semgrep_filtered, list):
                                semgrep_threats = semgrep_filtered
                            else:
                                semgrep_threats = self._apply_validation_filter(
                                    semgrep_threats, validation_results
                                )

                            logger.info(
                                f"Validation filtering complete - filtered to {len(llm_threats) + len(semgrep_threats)} legitimate findings"
                            )
                        except Exception as e:
                            logger.error(f"Validation filtering failed: {e}")
                            # Don't reset validation_results here - preserve them for the result

                    # Add validation stats to metadata (separate try-catch to avoid losing validation_results)
                    try:
                        if validation_results and self.llm_validator:
                            scan_metadata["llm_validation_success"] = True
                            scan_metadata["llm_validation_stats"] = (
                                self.llm_validator.get_validation_stats(
                                    validation_results
                                )
                            )
                        else:
                            scan_metadata["llm_validation_success"] = False
                    except Exception as e:
                        logger.error(f"Failed to generate validation stats: {e}")
                        scan_metadata["llm_validation_success"] = (
                            True  # Still successful, just no stats
                        )
                        scan_metadata["llm_validation_stats_error"] = str(e)
        else:
            logger.debug("Validation conditions not met - entering else clause")
            scan_metadata["llm_validation_success"] = False
            if not use_validation:
                logger.debug("Reason: use_validation=False")
                scan_metadata["llm_validation_reason"] = "disabled"
            elif not self.enable_llm_validation:
                logger.debug("Reason: self.enable_llm_validation=False")
                scan_metadata["llm_validation_reason"] = "disabled"
            else:
                logger.debug("Reason: self.llm_validator is None or falsy")
                scan_metadata["llm_validation_reason"] = "not_available"

        result = EnhancedScanResult(
            file_path=str(file_path),
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=scan_metadata,
            validation_results=validation_results,
            llm_usage_stats=None,  # Will be populated by LLM components
        )

        logger.info(
            f"=== File scan complete for {file_path} - "
            f"Total threats: {len(result.all_threats)} ==="
        )

        # Record scan completion
        if self.metrics_collector:
            duration = time.time() - scan_start_time
            self.metrics_collector.record_scan_completion(
                "file", duration, success=True, findings_count=len(result.all_threats)
            )

        # Update telemetry context with scan results
        if scan_context:
            # Extract timing from metadata (if available)
            if result.scan_metadata.get("semgrep_duration_ms"):
                scan_context.semgrep_duration = result.scan_metadata[
                    "semgrep_duration_ms"
                ]
            if result.scan_metadata.get("llm_duration_ms"):
                scan_context.llm_duration = result.scan_metadata["llm_duration_ms"]
            if result.scan_metadata.get("validation_duration_ms"):
                scan_context.validation_duration = result.scan_metadata[
                    "validation_duration_ms"
                ]
            if result.scan_metadata.get("cache_lookup_ms"):
                scan_context.cache_lookup_duration = result.scan_metadata[
                    "cache_lookup_ms"
                ]

            # Update result counts
            scan_context.threats_found = len(result.all_threats)
            scan_context.threats_validated = sum(
                1 for t in result.all_threats if hasattr(t, "validated") and t.validated
            )
            scan_context.false_positives_filtered = result.scan_metadata.get(
                "false_positives_filtered", 0
            )

            # Mark cache hit if applicable
            if result.scan_metadata.get("cache_hit", False):
                scan_context.mark_cache_hit()

        # Store result in cache if available
        if self.cache_manager and cache_key:
            try:
                # Add cache metadata to the result before storing
                result.scan_metadata["cache_hit"] = False
                result.scan_metadata["cache_key"] = str(cache_key)

                self.cache_manager.put(cache_key, result)
                logger.debug(f"Cached scan result for: {file_path_abs}")
            except Exception as e:
                logger.warning(f"Failed to cache scan result for {file_path_abs}: {e}")

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
            raise FileNotFoundError(f"Directory not found: {directory_path_abs}")

        # Use telemetry context manager for comprehensive tracking
        if self.metrics_orchestrator:
            logger.debug("Using metrics orchestrator for directory scan tracking")
            with self.metrics_orchestrator.track_scan_execution(
                trigger_source="scan_engine",
                scan_type="directory",
                target_path=directory_path_abs,
                semgrep_enabled=use_semgrep,
                llm_enabled=use_llm,
                validation_enabled=use_validation,
                file_count=0,  # Will be updated when files are discovered
            ) as scan_context:
                logger.debug(
                    "Scan context created for directory scan with telemetry tracking"
                )

                # Continue with directory scan logic - scan_context is now available for threat recording
                return await self._execute_directory_scan(
                    directory_path_obj,
                    scan_context,
                    recursive,
                    use_llm,
                    use_semgrep,
                    use_validation,
                    severity_threshold,
                )
        else:
            # Fallback without telemetry tracking - use None as scan_context
            logger.debug(
                "No metrics orchestrator available, running directory scan without telemetry"
            )
            return await self._execute_directory_scan(
                directory_path_obj,
                None,
                recursive,
                use_llm,
                use_semgrep,
                use_validation,
                severity_threshold,
            )

    async def _execute_directory_scan(
        self,
        directory_path_obj: Path,
        scan_context,  # Can be None if telemetry is not available
        recursive: bool,
        use_llm: bool,
        use_semgrep: bool,
        use_validation: bool,
        severity_threshold: Severity | None,
    ) -> list[EnhancedScanResult]:
        """Execute directory scan with optional telemetry tracking."""
        directory_path_abs = str(directory_path_obj)

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
                        directory_path=directory_path_abs,
                        config=config.semgrep_config,
                        rules=config.semgrep_rules,
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

                    # Record individual threat findings in telemetry using scan context
                    if scan_context:
                        for threat in all_semgrep_threats:
                            scan_context.add_threat_finding(threat, "semgrep")

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
                logger.debug(
                    f"Calling LLM analyzer for {len(files_to_scan)} filtered files..."
                )
                all_llm_findings = await self.llm_analyzer.analyze_files(
                    file_paths=files_to_scan,
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

                # Record individual threat findings in telemetry using scan context
                if scan_context:
                    for threat in all_llm_threats:
                        scan_context.add_threat_finding(threat, "llm")

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

        # Return directory-level scan results directly
        logger.info(
            "=== Directory scan complete - returning directory-level results ==="
        )

        # Combine all threats from directory scans
        all_threats = []
        all_threats.extend(
            all_semgrep_threats if "all_semgrep_threats" in locals() else []
        )
        all_threats.extend(
            all_llm_threats if "all_llm_threats" in locals() and use_llm else []
        )

        # Build file information for proper metrics
        files_with_threats = set()
        for threat in all_threats:
            if hasattr(threat, "file_path"):
                files_with_threats.add(threat.file_path)

        # Create file information list for JSON metrics
        files_info = []
        for file_path in files_to_scan:
            file_threat_count = sum(
                1
                for t in all_threats
                if hasattr(t, "file_path") and t.file_path == str(file_path)
            )
            files_info.append(
                {
                    "file_path": str(file_path),
                    "language": (
                        self._detect_language(file_path)
                        if file_path.exists()
                        else "generic"
                    ),
                    "threat_count": file_threat_count,
                    "issues_identified": file_threat_count > 0,
                }
            )

        # Initialize validation results
        validation_results = None

        # LLM validation step - same logic as file scanning
        if use_validation and self.enable_llm_validation and self.llm_validator:
            # Combine all threats for validation
            all_threats_for_validation = all_threats

            if all_threats_for_validation:
                # Check if validator is fully functional or using fallback
                if self.llm_validator.is_fully_functional():
                    logger.info(
                        f"Validating {len(all_threats_for_validation)} findings with LLM validator (full mode) for directory scan"
                    )
                    semgrep_scan_metadata["llm_validation_mode"] = "full"
                else:
                    logger.info(
                        f"Validating {len(all_threats_for_validation)} findings with LLM validator (fallback mode) for directory scan"
                    )
                    semgrep_scan_metadata["llm_validation_mode"] = "fallback"
                try:
                    # For directory scans, we need to read the directory contents for context
                    # Create a concatenated source code context from all relevant files
                    directory_context = f"Directory scan of: {directory_path_abs}\n"
                    directory_context += (
                        f"Files scanned: {len(files_to_scan)} files\n\n"
                    )

                    # Add sample content from files with threats for context
                    context_files_added = 0
                    max_context_files = 5  # Limit context to avoid huge payloads
                    for file_path in files_to_scan:
                        if context_files_added >= max_context_files:
                            break
                        file_threat_count = sum(
                            1
                            for t in all_threats
                            if hasattr(t, "file_path") and t.file_path == str(file_path)
                        )
                        if file_threat_count > 0:
                            try:
                                file_content = file_path.read_text(
                                    encoding="utf-8", errors="replace"
                                )
                                directory_context += (
                                    f"=== {file_path.name} ===\n{file_content}\n\n"
                                )
                                context_files_added += 1
                            except Exception as e:
                                logger.debug(
                                    f"Could not read {file_path} for validation context: {e}"
                                )

                    validation_results = (
                        await self.llm_validator._validate_findings_async(
                            findings=all_threats_for_validation,
                            source_code=directory_context,
                            file_path=directory_path_abs,
                            generate_exploits=True,
                        )
                    )

                    # Store validation results in scan context for atomic database updates
                    if (
                        "scan_context" in locals()
                        and scan_context
                        and validation_results
                    ):
                        scan_context.set_validation_results(validation_results)

                    # Filter false positives based on validation
                    if "all_llm_threats" in locals():
                        try:
                            llm_filtered = self.llm_validator.filter_false_positives(
                                all_llm_threats, validation_results
                            )
                        except Exception:
                            llm_filtered = None

                        if isinstance(llm_filtered, list):
                            all_llm_threats = llm_filtered
                        else:
                            all_llm_threats = self._apply_validation_filter(
                                all_llm_threats, validation_results
                            )

                    if "all_semgrep_threats" in locals():
                        try:
                            semgrep_filtered = (
                                self.llm_validator.filter_false_positives(
                                    all_semgrep_threats, validation_results
                                )
                            )
                        except Exception:
                            semgrep_filtered = None

                        if isinstance(semgrep_filtered, list):
                            all_semgrep_threats = semgrep_filtered
                        else:
                            all_semgrep_threats = self._apply_validation_filter(
                                all_semgrep_threats, validation_results
                            )

                    # Update combined threats list after filtering
                    all_threats = []
                    all_threats.extend(
                        all_semgrep_threats if "all_semgrep_threats" in locals() else []
                    )
                    all_threats.extend(
                        all_llm_threats
                        if "all_llm_threats" in locals() and use_llm
                        else []
                    )

                    # Add validation stats to metadata
                    semgrep_scan_metadata["llm_validation_success"] = True
                    semgrep_scan_metadata["llm_validation_stats"] = (
                        self.llm_validator.get_validation_stats(validation_results)
                    )
                    logger.info(
                        f"Directory validation complete - filtered to {len(all_threats)} legitimate findings"
                    )

                except Exception as e:
                    logger.error(f"Directory LLM validation failed: {e}")
                    semgrep_scan_metadata["llm_validation_success"] = False
                    semgrep_scan_metadata["llm_validation_error"] = str(e)
            else:
                # No threats to validate
                semgrep_scan_metadata["llm_validation_success"] = True
                semgrep_scan_metadata["llm_validation_reason"] = (
                    "no_threats_to_validate"
                )
        else:
            logger.debug(
                "Directory validation conditions not met - entering else clause"
            )
            semgrep_scan_metadata["llm_validation_success"] = False
            if not use_validation:
                logger.debug("Reason: use_validation=False")
                semgrep_scan_metadata["llm_validation_reason"] = "disabled"
            elif not self.enable_llm_validation:
                logger.debug("Reason: self.enable_llm_validation=False")
                semgrep_scan_metadata["llm_validation_reason"] = "disabled"
            else:
                logger.debug("Reason: self.llm_validator is None or falsy")
                semgrep_scan_metadata["llm_validation_reason"] = "not_available"

        # Recalculate files with threats after validation filtering
        files_with_threats = set()
        for threat in all_threats:
            if hasattr(threat, "file_path"):
                files_with_threats.add(threat.file_path)

        # Update files_info with new threat counts after validation
        for file_info in files_info:
            file_path_str = file_info["file_path"]
            file_threat_count = sum(
                1
                for t in all_threats
                if hasattr(t, "file_path") and t.file_path == file_path_str
            )
            file_info["threat_count"] = file_threat_count
            file_info["issues_identified"] = file_threat_count > 0

        # Create single directory-level result
        directory_result = EnhancedScanResult(
            file_path=directory_path_abs,
            semgrep_threats=(
                all_semgrep_threats if "all_semgrep_threats" in locals() else []
            ),
            llm_threats=(
                all_llm_threats if "all_llm_threats" in locals() and use_llm else []
            ),
            validation_results=validation_results,
            scan_metadata={
                "directory_path": directory_path_abs,
                "directory_scan": True,
                "total_files_discovered": len(all_files),
                "files_filtered_for_scan": len(files_to_scan),
                "files_with_threats": len(files_with_threats),
                "files_clean": len(files_to_scan) - len(files_with_threats),
                "total_threats_found": len(all_threats),
                "scan_type": "directory_level",
                "directory_files_info": files_info,  # For proper JSON metrics
                **semgrep_scan_metadata,
                **llm_scan_metadata,
            },
            llm_usage_stats=None,  # TODO: Add LLM usage stats if needed
        )

        logger.info(f"Directory scan found {len(all_threats)} total threats")
        return [directory_result]

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
                    # Check if validator is fully functional or using fallback
                    if self.llm_validator.is_fully_functional():
                        logger.debug(
                            f"Validating {len(all_threats_for_validation)} findings for {file_path.name} (full mode)"
                        )
                        scan_metadata["llm_validation_mode"] = "full"
                    else:
                        logger.debug(
                            f"Validating {len(all_threats_for_validation)} findings for {file_path.name} (fallback mode)"
                        )
                        scan_metadata["llm_validation_mode"] = "fallback"
                    try:
                        # Use streaming for large files, regular read for small files
                        config = self.credential_manager.load_config()
                        try:
                            max_file_size_config = getattr(
                                config, "max_file_size_mb", 10
                            )
                            max_file_size_num = (
                                int(max_file_size_config)
                                if max_file_size_config is not None
                                else 10
                            )
                        except Exception:
                            max_file_size_num = 10
                        if is_file_too_large(file_path, max_size_mb=max_file_size_num):
                            logger.debug(
                                f"Using streaming read for large file: {file_path}"
                            )
                            streaming_reader = StreamingFileReader()
                            source_code = await streaming_reader.get_file_preview(
                                file_path,
                                preview_size=10000,  # 10KB preview for validation
                            )
                        else:
                            # Read small files using streaming reader
                            reader = StreamingFileReader()
                            chunks = []
                            async for chunk in reader.read_file_async(file_path):
                                chunks.append(chunk)
                            source_code = "".join(chunks)

                        validation_results = (
                            await self.llm_validator._validate_findings_async(
                                findings=all_threats_for_validation,
                                source_code=source_code,
                                file_path=str(file_path),
                                generate_exploits=True,
                            )
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
                llm_usage_stats=None,  # Will be populated by LLM components
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
            raise FileNotFoundError(f"Directory not found: {directory_path_abs}")

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
        try:
            cpu_count_val = os.cpu_count() or 4
        except Exception:
            cpu_count_val = 4
        max_workers = min(32, int(cpu_count_val) + 4, len(files_to_scan))
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
                        llm_usage_stats=None,
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

    async def _get_cached_scan_result(
        self,
        source_code: str,
        file_path: str,
        use_llm: bool,
        use_semgrep: bool,
        use_validation: bool,
        severity_threshold: Severity | None,
    ) -> EnhancedScanResult | None:
        """Get cached scan result if available."""
        if not self.cache_manager:
            return None

        try:
            config = self.credential_manager.load_config()
            if not config.enable_caching:
                return None

            hasher = self.cache_manager.get_hasher()

            # Create cache key based on content and scan parameters
            content_hash = hasher.hash_content(source_code)
            scan_context = {
                "file_path": file_path,
                "use_llm": use_llm,
                "use_semgrep": use_semgrep,
                "use_validation": use_validation,
                "severity_threshold": (
                    severity_threshold.value if severity_threshold else None
                ),
                "semgrep_config": config.semgrep_config,
                "semgrep_rules": config.semgrep_rules,
                "llm_model": config.llm_model,
            }
            metadata_hash = hasher.hash_metadata(scan_context)

            cache_key = CacheKey(
                cache_type=CacheType.FILE_ANALYSIS,
                content_hash=content_hash,
                metadata_hash=metadata_hash,
            )

            cached_data = self.cache_manager.get(cache_key)
            if cached_data and isinstance(cached_data, dict):
                # Reconstruct EnhancedScanResult from cached data
                return self._deserialize_scan_result(cached_data)

        except Exception as e:
            logger.warning(f"Failed to retrieve cached scan result: {e}")

        return None

    async def _cache_scan_result(
        self,
        result: EnhancedScanResult,
        source_code: str,
        file_path: str,
        use_llm: bool,
        use_semgrep: bool,
        use_validation: bool,
        severity_threshold: Severity | None,
    ) -> None:
        """Cache scan result for future use."""
        if not self.cache_manager:
            return

        try:
            config = self.credential_manager.load_config()
            if not config.enable_caching:
                return

            hasher = self.cache_manager.get_hasher()

            # Create same cache key as used for retrieval
            content_hash = hasher.hash_content(source_code)
            scan_context = {
                "file_path": file_path,
                "use_llm": use_llm,
                "use_semgrep": use_semgrep,
                "use_validation": use_validation,
                "severity_threshold": (
                    severity_threshold.value if severity_threshold else None
                ),
                "semgrep_config": config.semgrep_config,
                "semgrep_rules": config.semgrep_rules,
                "llm_model": config.llm_model,
            }
            metadata_hash = hasher.hash_metadata(scan_context)

            cache_key = CacheKey(
                cache_type=CacheType.FILE_ANALYSIS,
                content_hash=content_hash,
                metadata_hash=metadata_hash,
            )

            # Serialize scan result for caching
            serialized_result = self._serialize_scan_result(result)

            # Cache for shorter duration than LLM responses (scan results can change with rule updates)
            cache_expiry_seconds = (
                config.cache_max_age_hours * 1800
            )  # Half the normal duration
            self.cache_manager.put(cache_key, serialized_result, cache_expiry_seconds)

            logger.debug(f"Cached scan result for {file_path}")

        except Exception as e:
            logger.warning(f"Failed to cache scan result: {e}")

    def _serialize_scan_result(self, result: EnhancedScanResult) -> dict:
        """Serialize EnhancedScanResult for caching."""
        return {
            "file_path": result.file_path,
            "language": result.language,
            "llm_threats": [
                SerializableThreatMatch.from_infrastructure_threat_match(
                    threat
                ).to_dict()
                for threat in result.llm_threats
            ],
            "semgrep_threats": [
                SerializableThreatMatch.from_infrastructure_threat_match(
                    threat
                ).to_dict()
                for threat in result.semgrep_threats
            ],
            "scan_metadata": result.scan_metadata,
            "validation_results": result.validation_results,
            "stats": result.stats,
            "llm_usage_stats": result.llm_usage_stats,
        }

    def _deserialize_scan_result(self, cached_data: dict) -> EnhancedScanResult:
        """Deserialize cached data back to EnhancedScanResult."""
        # Reconstruct threat matches as infrastructure objects
        llm_threats = [
            SerializableThreatMatch.from_dict(
                threat_data
            ).to_infrastructure_threat_match()
            for threat_data in cached_data.get("llm_threats", [])
        ]
        semgrep_threats = [
            SerializableThreatMatch.from_dict(
                threat_data
            ).to_infrastructure_threat_match()
            for threat_data in cached_data.get("semgrep_threats", [])
        ]

        # Create EnhancedScanResult
        result = EnhancedScanResult(
            file_path=cached_data["file_path"],
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=cached_data.get("scan_metadata", {}),
            validation_results=cached_data.get("validation_results", {}),
            llm_usage_stats=cached_data.get("llm_usage_stats"),
        )

        # Manually set computed properties that might not recompute correctly
        if "stats" in cached_data:
            result.stats = cached_data["stats"]

        return result

    def clear_cache(self) -> None:
        """Clear all caches used by the scan engine."""
        logger.info("Clearing scan engine caches...")

        # Clear main cache manager
        if self.cache_manager:
            self.cache_manager.clear()

        # Clear semgrep scanner cache
        if self.semgrep_scanner:
            self.semgrep_scanner.clear_cache()

        # Clear LLM analyzer cache if available
        if self.llm_analyzer and hasattr(self.llm_analyzer, "clear_cache"):
            self.llm_analyzer.clear_cache()

        # Clear token estimator cache if available
        if self.llm_analyzer and hasattr(self.llm_analyzer, "token_estimator"):
            if hasattr(self.llm_analyzer.token_estimator, "clear_cache"):
                self.llm_analyzer.token_estimator.clear_cache()

        logger.info("Scan engine caches cleared successfully")
