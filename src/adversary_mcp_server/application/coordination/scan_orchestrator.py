"""Scan orchestration for coordinating security analysis workflows."""

import asyncio
import time
from pathlib import Path

from ...domain.aggregation.threat_aggregator import ThreatAggregator
from ...infrastructure.builders.result_builder import ResultBuilder
from ...interfaces import (
    ICacheManager,
    ILLMScanner,
    IMetricsCollector,
    ISemgrepScanner,
    IValidator,
)
from ...logger import get_logger
from ...scanner.language_mapping import LanguageMapper
from ...scanner.scan_engine import EnhancedScanResult
from ...scanner.types import Severity, ThreatMatch
from .cache_coordinator import CacheCoordinator
from .validation_coordinator import ValidationCoordinator

logger = get_logger("scan_orchestrator")


class ScanOrchestrator:
    """Orchestrates security scanning workflows with multiple analysis engines."""

    def __init__(
        self,
        semgrep_scanner: ISemgrepScanner,
        llm_scanner: ILLMScanner | None = None,
        validator: IValidator | None = None,
        cache_manager: ICacheManager | None = None,
        metrics_collector: IMetricsCollector | None = None,
        threat_aggregator: ThreatAggregator | None = None,
        result_builder: ResultBuilder | None = None,
        validation_coordinator: ValidationCoordinator | None = None,
        cache_coordinator: CacheCoordinator | None = None,
    ):
        """Initialize the scan orchestrator."""
        self.semgrep_scanner = semgrep_scanner
        self.llm_scanner = llm_scanner
        self.validator = validator
        self.cache_manager = cache_manager
        self.metrics_collector = metrics_collector

        # Initialize coordinators and builders
        self.threat_aggregator = threat_aggregator or ThreatAggregator()
        self.result_builder = result_builder or ResultBuilder()
        self.validation_coordinator = validation_coordinator or ValidationCoordinator(
            validator
        )
        self.cache_coordinator = cache_coordinator or CacheCoordinator(cache_manager)

        logger.debug(
            f"ScanOrchestrator initialized - "
            f"semgrep: {semgrep_scanner is not None}, "
            f"llm: {llm_scanner is not None}, "
            f"validator: {validator is not None}, "
            f"cache: {cache_manager is not None}"
        )

    async def orchestrate_code_scan(
        self,
        code: str,
        language: str | None = None,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Orchestrate a complete code analysis workflow."""
        logger.info(f"Starting code scan - language: {language}")
        start_time = time.time()

        # Build scan parameters
        scan_parameters = {
            "use_llm": use_llm and self.llm_scanner is not None,
            "use_semgrep": use_semgrep,
            "use_validation": use_validation,
            "language": language,
            "severity_threshold": (
                str(severity_threshold) if severity_threshold else None
            ),
        }

        # Check cache first
        cache_key = self.cache_coordinator.create_cache_key_for_code(
            code, scan_parameters
        )
        if not cache_key:
            logger.debug("No cache key generated, proceeding without cache")
        else:
            cached_result = self.cache_coordinator.get_cached_code_result(cache_key)
            if cached_result:
                logger.info("Cache hit for code scan")
                return cached_result
            else:
                logger.debug("Cache miss for code scan")

        # Execute scans in parallel
        # Normalize use_llm to bool
        use_llm_param = scan_parameters["use_llm"]
        use_llm_bool = bool(use_llm_param) if use_llm_param is not None else False

        semgrep_threats, llm_threats = await self._execute_parallel_scans(
            code=code,
            language=language,
            use_llm=use_llm_bool,
            use_semgrep=use_semgrep,
        )

        # Apply severity filtering
        if severity_threshold:
            semgrep_threats = self._filter_by_severity(
                semgrep_threats, severity_threshold
            )
            llm_threats = self._filter_by_severity(llm_threats, severity_threshold)

        # Aggregate threats
        aggregated_threats = self.threat_aggregator.aggregate_threats(
            semgrep_threats, llm_threats
        )

        # Execute validation
        validation_results = {}
        if use_validation and self.validation_coordinator.should_validate(
            use_validation, True, aggregated_threats
        ):
            try:
                validation_results = self.validation_coordinator.validate_findings(
                    findings=aggregated_threats,
                    file_content=code,
                )

                # Filter false positives
                semgrep_threats = self.validation_coordinator.filter_false_positives(
                    semgrep_threats, validation_results
                )
                llm_threats = self.validation_coordinator.filter_false_positives(
                    llm_threats, validation_results
                )
                aggregated_threats = self.threat_aggregator.aggregate_threats(
                    semgrep_threats, llm_threats
                )
            except Exception as e:
                logger.error(f"Validation failed: {e}")

        # Build scan metadata
        scan_duration_ms = (time.time() - start_time) * 1000
        scan_metadata = self.result_builder.build_scan_metadata(
            scan_type="code",
            language=language or "unknown",
            use_llm=use_llm_bool,
            use_semgrep=use_semgrep,
            use_validation=use_validation,
            scan_duration_ms=scan_duration_ms,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        # Add validation metadata
        validation_metadata = self.validation_coordinator.build_validation_metadata(
            use_validation, True, validation_results
        )
        scan_metadata.update(validation_metadata)

        # Build result
        result = self.result_builder.build_enhanced_result(
            file_path="<code_snippet>",
            semgrep_threats=semgrep_threats,
            llm_threats=llm_threats,
            aggregated_threats=aggregated_threats,
            scan_metadata=scan_metadata,
            validation_results=validation_results,
        )

        # Cache result
        if not cache_key:
            logger.debug("No cache key available, skipping result caching")
        else:
            self.cache_coordinator.cache_code_result(cache_key, result)
            logger.debug("Cached code scan result")

        logger.info(
            f"Code scan completed - {len(aggregated_threats)} threats found "
            f"in {scan_duration_ms:.2f}ms"
        )

        return result

    async def orchestrate_file_scan(
        self,
        file_path: Path,
        use_llm: bool = True,
        use_semgrep: bool = True,
        use_validation: bool = True,
        severity_threshold: Severity | None = None,
    ) -> EnhancedScanResult:
        """Orchestrate a complete file analysis workflow."""
        logger.info(f"Starting file scan: {file_path}")
        start_time = time.time()

        # Read file content
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            raise

        # Detect language
        language = self._detect_language_from_file(file_path)

        # Build scan parameters
        scan_parameters = {
            "use_llm": use_llm and self.llm_scanner is not None,
            "use_semgrep": use_semgrep,
            "use_validation": use_validation,
            "language": language,
            "severity_threshold": (
                str(severity_threshold) if severity_threshold else None
            ),
        }

        # Check cache
        content_hash = self.cache_coordinator.create_content_hash(content)
        cached_result = await self.cache_coordinator.get_cached_scan_result(
            file_path, content_hash, scan_parameters
        )
        if cached_result:
            logger.info(f"Cache hit for file scan: {file_path}")
            return cached_result

        # Execute scans in parallel
        # Normalize use_llm to bool
        use_llm_param = scan_parameters["use_llm"]
        use_llm_bool = bool(use_llm_param) if use_llm_param is not None else False

        semgrep_threats, llm_threats = await self._execute_parallel_scans(
            content=content,
            file_path=file_path,
            language=language,
            use_llm=use_llm_bool,
            use_semgrep=use_semgrep,
        )

        # Apply severity filtering
        if severity_threshold:
            semgrep_threats = self._filter_by_severity(
                semgrep_threats, severity_threshold
            )
            llm_threats = self._filter_by_severity(llm_threats, severity_threshold)

        # Aggregate threats
        aggregated_threats = self.threat_aggregator.aggregate_threats(
            semgrep_threats, llm_threats
        )

        # Execute validation
        validation_results = {}
        if use_validation and self.validation_coordinator.should_validate(
            use_validation, True, aggregated_threats
        ):
            try:
                validation_results = self.validation_coordinator.validate_findings(
                    findings=aggregated_threats,
                    file_content=content,
                    file_path=file_path,
                    preview_size=10000,
                )

                # Filter false positives
                semgrep_threats = self.validation_coordinator.filter_false_positives(
                    semgrep_threats, validation_results
                )
                llm_threats = self.validation_coordinator.filter_false_positives(
                    llm_threats, validation_results
                )
                aggregated_threats = self.threat_aggregator.aggregate_threats(
                    semgrep_threats, llm_threats
                )
            except Exception as e:
                logger.error(f"Validation failed for {file_path}: {e}")

        # Build scan metadata
        scan_duration_ms = (time.time() - start_time) * 1000
        scan_metadata = self.result_builder.build_scan_metadata(
            scan_type="file",
            language=language or "unknown",
            use_llm=use_llm_bool,
            use_semgrep=use_semgrep,
            use_validation=use_validation,
            scan_duration_ms=scan_duration_ms,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            file_size_bytes=len(content.encode("utf-8")),
        )

        # Add validation metadata
        validation_metadata = self.validation_coordinator.build_validation_metadata(
            use_validation, True, validation_results
        )
        scan_metadata.update(validation_metadata)

        # Build result
        result = self.result_builder.build_enhanced_result(
            file_path=str(file_path),
            semgrep_threats=semgrep_threats,
            llm_threats=llm_threats,
            aggregated_threats=aggregated_threats,
            scan_metadata=scan_metadata,
            validation_results=validation_results,
        )

        # Cache result
        await self.cache_coordinator.cache_scan_result(
            file_path, result, content_hash, scan_parameters
        )

        logger.info(
            f"File scan completed: {file_path} - {len(aggregated_threats)} threats found "
            f"in {scan_duration_ms:.2f}ms"
        )

        return result

    async def _execute_parallel_scans(
        self,
        content: str | None = None,
        code: str | None = None,
        file_path: Path | None = None,
        language: str | None = None,
        use_llm: bool = True,
        use_semgrep: bool = True,
    ) -> tuple[list[ThreatMatch], list[ThreatMatch]]:
        """Execute Semgrep and LLM scans in parallel."""
        tasks = []

        # Prepare scan content
        scan_content = content or code or ""

        # Semgrep scan task
        if use_semgrep:
            if file_path:
                semgrep_task = asyncio.create_task(
                    self._run_semgrep_file_scan(file_path, language)
                )
            else:
                semgrep_task = asyncio.create_task(
                    self._run_semgrep_code_scan(scan_content, language)
                )
            tasks.append(("semgrep", semgrep_task))

        # LLM scan task
        if use_llm and self.llm_scanner:
            if file_path:
                llm_task = asyncio.create_task(
                    self._run_llm_file_scan(file_path, scan_content, language)
                )
            else:
                llm_task = asyncio.create_task(
                    self._run_llm_code_scan(scan_content, language)
                )
            tasks.append(("llm", llm_task))

        # Execute tasks and collect results
        semgrep_threats = []
        llm_threats = []

        if tasks:
            results = await asyncio.gather(
                *[task for _, task in tasks], return_exceptions=True
            )

            for (scan_type, _), result in zip(tasks, results, strict=False):
                if isinstance(result, Exception):
                    logger.error(f"{scan_type} scan failed: {result}")
                    continue

                if scan_type == "semgrep":
                    semgrep_threats = result
                elif scan_type == "llm":
                    llm_threats = result

        logger.debug(
            f"Parallel scans completed - Semgrep: {len(semgrep_threats)}, "
            f"LLM: {len(llm_threats)}"
        )

        return semgrep_threats, llm_threats

    def _get_extension_from_language(self, language: str | None) -> str:
        """Get file extension from language name for scanner language detection."""
        from ...scanner.language_mapping import LanguageMapper

        return LanguageMapper.get_extension_for_language(language)

    async def _run_semgrep_file_scan(
        self, file_path: Path, language: str | None
    ) -> list[ThreatMatch]:
        """Run Semgrep scan on a file."""
        return await self.semgrep_scanner.scan_file(file_path, language or "unknown")

    async def _run_semgrep_code_scan(
        self, code: str, language: str | None
    ) -> list[ThreatMatch]:
        """Run Semgrep scan on code."""
        return await self.semgrep_scanner.scan_code(code, language or "unknown")

    async def _run_llm_file_scan(
        self, file_path: Path, content: str, language: str | None
    ) -> list[ThreatMatch]:
        """Run LLM scan on a file."""
        return await self.llm_scanner.analyze_file(file_path, language or "unknown")

    async def _run_llm_code_scan(
        self, code: str, language: str | None
    ) -> list[ThreatMatch]:
        """Run LLM scan on code."""
        # Use a temporary file path for context
        file_extension = self._get_extension_from_language(language)
        temp_file_path = f"<code>{file_extension}"
        return await self.llm_scanner.analyze_code(
            code, temp_file_path, language or "unknown"
        )

    def _filter_by_severity(
        self, threats: list[ThreatMatch], severity_threshold: Severity
    ) -> list[ThreatMatch]:
        """Filter threats by minimum severity level."""
        severity_order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }

        threshold_value = severity_order.get(severity_threshold, 1)

        return [
            threat
            for threat in threats
            if severity_order.get(threat.severity, 1) >= threshold_value
        ]

    def _detect_language_from_file(self, file_path: Path) -> str | None:
        """Detect programming language from file extension using shared mapper."""
        detected = LanguageMapper.detect_language_from_extension(file_path)
        return detected if detected != "generic" else None
