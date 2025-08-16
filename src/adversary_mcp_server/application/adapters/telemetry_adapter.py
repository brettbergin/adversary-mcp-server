"""Telemetry adapter for extracting metrics from domain objects."""

from typing import Any

from adversary_mcp_server.application.adapters.input_models import (
    MetadataInput,
    safe_convert_to_input_model,
)
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.logger import get_logger

logger = get_logger("telemetry_adapter")


class TelemetryAdapter:
    """
    Adapter for recording telemetry from domain scan operations.

    This adapter bridges the gap between the Clean Architecture domain layer
    and the telemetry system, allowing comprehensive metrics collection from
    domain scan results and threat matches.
    """

    def __init__(self, telemetry_service=None):
        """Initialize the telemetry adapter."""
        # For Clean Architecture, telemetry is handled through proper domain interfaces
        # This adapter provides a clean interface for future telemetry integration
        self._telemetry_service = telemetry_service

        # Only initialize telemetry if explicitly provided (dependency injection)
        if not self._telemetry_service:
            logger.debug(
                "No telemetry service provided - telemetry disabled for this adapter"
            )
            self._telemetry_service = None

    def record_scan_completion(self, scan_result: ScanResult):
        """Record scan completion event and individual threat detections."""
        if not self._telemetry_service:
            return

        try:
            # Extract basic scan information
            scan_id = scan_result.scan_id or "unknown"
            metadata = scan_result.metadata

            # Record main scan event
            # Convert metadata to type-safe input model
            safe_metadata = (
                safe_convert_to_input_model(metadata, MetadataInput)
                if metadata
                else MetadataInput()
            )

            self._telemetry_service.record_scan_event(
                scan_id=scan_id,
                scan_type=safe_metadata.scan_type,
                target_path=str(safe_metadata.target_info.get("path", "unknown")),
                language=safe_metadata.target_info.get("language", "unknown"),
                threats_found=len(scan_result.threats),
                duration_ms=safe_metadata.execution_stats.get("total_duration_ms", 0),
                success=True,
            )

            # Record individual threat detections
            for threat in scan_result.threats:
                self.record_threat_detection(threat, scan_id)

        except Exception as e:
            logger.error(f"Failed to record scan completion: {e}")

    def record_threat_detection(self, threat: ThreatMatch, scan_id: str):
        """Record individual threat detection."""
        if not self._telemetry_service or not threat:
            return

        try:
            self._telemetry_service.record_threat_detection(
                scan_id=scan_id,
                rule_id=threat.rule_id,
                rule_name=threat.rule_name,
                category=threat.category,
                severity=str(threat.severity),
                file_path=str(threat.file_path),
                line_number=threat.line_number,
                confidence=threat.confidence.get_value(),
                scanner=threat.source_scanner,
                is_false_positive=threat.is_false_positive,
            )
        except Exception as e:
            logger.error(f"Failed to record threat detection: {e}")

    def record_scan_performance(self, scan_result: ScanResult):
        """Record performance metrics from scan result."""
        if not self._telemetry_service:
            return

        try:
            metadata = scan_result.metadata
            if not metadata:
                return

            # Convert metadata to type-safe input model
            safe_metadata = (
                safe_convert_to_input_model(metadata, MetadataInput)
                if metadata
                else MetadataInput()
            )
            execution_stats = safe_metadata.execution_stats
            target_info = safe_metadata.target_info

            # Build component timings
            component_timings = {}
            for key, value in execution_stats.items():
                if isinstance(value, int | float):
                    component_timings[key] = value

            self._telemetry_service.record_performance_metrics(
                scan_id=scan_result.scan_id or "unknown",
                total_duration_ms=execution_stats.get("total_duration_ms", 0),
                component_timings=component_timings,
                file_size_bytes=target_info.get("size", 0),
                threat_count=len(scan_result.threats),
            )
        except Exception as e:
            logger.error(f"Failed to record scan performance: {e}")

    def record_validation_results(
        self,
        original_threats: list[ThreatMatch],
        validated_threats: list[ThreatMatch],
        scan_id: str,
    ):
        """Record validation results comparing original vs validated threats."""
        if not self._telemetry_service:
            return

        try:
            if not original_threats and not validated_threats:
                return

            original_count = len(original_threats or [])
            validated_count = len(validated_threats or [])
            false_positive_count = original_count - validated_count

            # Count confidence improvements and severity adjustments
            confidence_improvements = 0
            severity_adjustments = 0

            if original_threats and validated_threats:
                # Create lookup by rule_id for comparison
                original_by_id = {t.rule_id: t for t in original_threats}
                validated_by_id = {t.rule_id: t for t in validated_threats}

                for rule_id, validated_threat in validated_by_id.items():
                    if rule_id in original_by_id:
                        original_threat = original_by_id[rule_id]

                        # Check confidence improvement
                        if (
                            validated_threat.confidence.get_value()
                            > original_threat.confidence.get_value()
                        ):
                            confidence_improvements += 1

                        # Check severity adjustment
                        if str(validated_threat.severity) != str(
                            original_threat.severity
                        ):
                            severity_adjustments += 1

            self._telemetry_service.record_validation_event(
                scan_id=scan_id,
                original_threat_count=original_count,
                validated_threat_count=validated_count,
                false_positive_count=false_positive_count,
                confidence_improvements=confidence_improvements,
                severity_adjustments=severity_adjustments,
            )
        except Exception as e:
            logger.error(f"Failed to record validation results: {e}")


class DomainTelemetryAdapter:
    """
    Adapter for extracting telemetry data from domain objects.

    This adapter bridges the gap between the Clean Architecture domain layer
    and the legacy telemetry system, ensuring that metrics collection continues
    to work while using the new domain objects.
    """

    def extract_scan_metrics(self, result: ScanResult) -> dict[str, Any]:
        """Extract comprehensive scan metrics from domain ScanResult."""

        scan_metadata = result.scan_request.context.metadata
        statistics = result.get_statistics()

        base_metrics = {
            # Scan identification
            "scan_id": scan_metadata.scan_id,
            "scan_type": scan_metadata.scan_type,
            "timestamp": scan_metadata.timestamp.isoformat(),
            "requester": scan_metadata.requester,
            # Target information
            "target_path": str(result.scan_request.context.target_path),
            "language": result.scan_request.context.language,
            "file_size_bytes": self._get_file_size(result),
            # Configuration
            "scanners_enabled": {
                "semgrep": result.scan_request.enable_semgrep,
                "llm": result.scan_request.enable_llm,
                "validation": result.scan_request.enable_validation,
            },
            "severity_threshold": (
                str(result.scan_request.severity_threshold)
                if result.scan_request.severity_threshold
                else None
            ),
            "timeout_seconds": scan_metadata.timeout_seconds,
            # Results summary
            "total_threats": statistics["total_threats"],
            "threats_by_severity": statistics["by_severity"],
            "threats_by_category": statistics["by_category"],
            "scanners_used": result.get_active_scanners(),
            # Quality metrics
            "has_critical_threats": result.has_critical_threats(),
            "high_confidence_threats": len(
                result.filter_by_confidence(ConfidenceScore(0.8)).threats
            ),
            "validated_threats": len(
                [t for t in result.threats if "validation" in t.source_scanner]
            ),
            "false_positives": len([t for t in result.threats if t.is_false_positive]),
            # Performance metrics (from scan metadata)
            "scan_duration_ms": result.scan_metadata.get("scan_duration_ms", 0),
            "semgrep_duration_ms": result.scan_metadata.get("semgrep_duration_ms", 0),
            "llm_duration_ms": result.scan_metadata.get("llm_duration_ms", 0),
            "validation_duration_ms": result.scan_metadata.get(
                "validation_duration_ms", 0
            ),
        }

        # Add scanner-specific metrics
        base_metrics.update(self._extract_scanner_metrics(result))

        # Add validation metrics if available
        validation_metrics = self._extract_validation_metrics(result)
        if validation_metrics:
            base_metrics["validation"] = validation_metrics

        return base_metrics

    def extract_threat_metrics(
        self, threats: list[ThreatMatch]
    ) -> list[dict[str, Any]]:
        """Extract detailed metrics for each threat."""
        threat_metrics = []

        for threat in threats:
            metrics = {
                # Identification
                "rule_id": threat.rule_id,
                "rule_name": threat.rule_name,
                "fingerprint": threat.get_fingerprint(),
                # Classification
                "severity": str(threat.severity),
                "severity_numeric": threat.severity.get_numeric_value(),
                "category": threat.category,
                "confidence": threat.confidence.get_decimal(),
                "confidence_level": threat.confidence.get_quality_level(),
                # Location
                "file_path": str(threat.file_path),
                "line_number": threat.line_number,
                "column_number": threat.column_number,
                # Source
                "source_scanner": threat.source_scanner,
                "is_validated": "validated_by" in threat.metadata,
                "is_false_positive": threat.is_false_positive,
                # Quality indicators
                "has_exploit_examples": len(threat.exploit_examples) > 0,
                "has_remediation": len(threat.remediation_advice) > 0,
                "code_snippet_length": (
                    len(threat.code_snippet) if threat.code_snippet else 0
                ),
            }

            # Add scanner-specific metadata
            if threat.source_scanner == "semgrep":
                metrics.update(self._extract_semgrep_threat_metrics(threat))
            elif threat.source_scanner == "llm":
                metrics.update(self._extract_llm_threat_metrics(threat))

            threat_metrics.append(metrics)

        return threat_metrics

    def extract_performance_metrics(self, result: ScanResult) -> dict[str, Any]:
        """Extract performance-specific metrics."""
        scan_metadata = result.scan_metadata

        return {
            "total_scan_time_ms": scan_metadata.get("scan_duration_ms", 0),
            "scanner_performance": {
                "semgrep": {
                    "duration_ms": scan_metadata.get("semgrep_duration_ms", 0),
                    "threats_found": len(
                        [t for t in result.threats if t.source_scanner == "semgrep"]
                    ),
                    "enabled": result.scan_request.enable_semgrep,
                },
                "llm": {
                    "duration_ms": scan_metadata.get("llm_duration_ms", 0),
                    "threats_found": len(
                        [t for t in result.threats if t.source_scanner == "llm"]
                    ),
                    "enabled": result.scan_request.enable_llm,
                },
            },
            "validation_performance": {
                "duration_ms": scan_metadata.get("validation_duration_ms", 0),
                "threats_validated": len(
                    [t for t in result.threats if "validated_by" in t.metadata]
                ),
                "false_positives_found": len(
                    [t for t in result.threats if t.is_false_positive]
                ),
                "enabled": result.scan_request.enable_validation,
            },
            "throughput": {
                "threats_per_second": self._calculate_throughput(result),
                "lines_scanned": self._estimate_lines_scanned(result),
                "files_processed": self._count_files_processed(result),
            },
        }

    def extract_quality_metrics(self, result: ScanResult) -> dict[str, Any]:
        """Extract code quality and security metrics."""
        threats = result.threats

        if not threats:
            return {
                "security_score": 100.0,
                "quality_rating": "A",
                "risk_level": "low",
                "confidence_distribution": {},
                "severity_distribution": {},
            }

        # Calculate security score (higher is better)
        critical_count = len(result.get_threats_by_severity("critical"))
        high_count = len(result.get_threats_by_severity("high"))
        medium_count = len(result.get_threats_by_severity("medium"))
        low_count = len(result.get_threats_by_severity("low"))

        # Weighted security score (0-100)
        security_score = max(
            0,
            100
            - (
                critical_count * 25
                + high_count * 15
                + medium_count * 10
                + low_count * 5
            ),
        )

        # Quality rating based on score
        if security_score >= 90:
            quality_rating = "A"
        elif security_score >= 80:
            quality_rating = "B"
        elif security_score >= 70:
            quality_rating = "C"
        elif security_score >= 60:
            quality_rating = "D"
        else:
            quality_rating = "F"

        # Risk level
        if critical_count > 0:
            risk_level = "critical"
        elif high_count > 0:
            risk_level = "high"
        elif medium_count > 0:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Confidence distribution
        confidence_ranges = {
            "very_low": len([t for t in threats if t.confidence.is_very_low()]),
            "low": len([t for t in threats if t.confidence.is_low()]),
            "medium": len([t for t in threats if t.confidence.is_medium()]),
            "high": len([t for t in threats if t.confidence.is_high()]),
            "very_high": len([t for t in threats if t.confidence.is_very_high()]),
        }

        return {
            "security_score": security_score,
            "quality_rating": quality_rating,
            "risk_level": risk_level,
            "confidence_distribution": confidence_ranges,
            "severity_distribution": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            },
            "average_confidence": sum(t.confidence.get_decimal() for t in threats)
            / len(threats),
            "actionable_threats": len(
                [t for t in threats if t.confidence.is_actionable()]
            ),
        }

    def _extract_scanner_metrics(self, result: ScanResult) -> dict[str, Any]:
        """Extract scanner-specific metrics."""
        scanner_metrics = {}

        for scanner in result.get_active_scanners():
            scanner_threats = [t for t in result.threats if t.source_scanner == scanner]

            scanner_metrics[f"{scanner}_metrics"] = {
                "threats_found": len(scanner_threats),
                "average_confidence": (
                    sum(t.confidence.get_decimal() for t in scanner_threats)
                    / len(scanner_threats)
                    if scanner_threats
                    else 0.0
                ),
                "severity_breakdown": {
                    severity: len(
                        [t for t in scanner_threats if str(t.severity) == severity]
                    )
                    for severity in ["critical", "high", "medium", "low"]
                },
                "category_breakdown": self._get_category_breakdown(scanner_threats),
            }

        return scanner_metrics

    def _extract_validation_metrics(self, result: ScanResult) -> dict[str, Any] | None:
        """Extract validation-specific metrics."""
        if not result.scan_request.enable_validation:
            return None

        validated_threats = [t for t in result.threats if "validated_by" in t.metadata]
        false_positives = [t for t in validated_threats if t.is_false_positive]

        if not validated_threats:
            return None

        return {
            "total_validated": len(validated_threats),
            "false_positives_detected": len(false_positives),
            "false_positive_rate": len(false_positives) / len(validated_threats),
            "average_validation_confidence": (
                sum(t.confidence.get_decimal() for t in validated_threats)
                / len(validated_threats)
            ),
            "validation_accuracy": 1.0
            - (len(false_positives) / len(validated_threats)),
        }

    def _extract_semgrep_threat_metrics(self, threat: ThreatMatch) -> dict[str, Any]:
        """Extract Semgrep-specific threat metrics."""
        return {
            "semgrep_rule_id": threat.metadata.get("semgrep_rule_id", ""),
            "semgrep_severity": threat.metadata.get("semgrep_severity", ""),
            "rule_confidence": "high",  # Semgrep rules are generally high confidence
        }

    def _extract_llm_threat_metrics(self, threat: ThreatMatch) -> dict[str, Any]:
        """Extract LLM-specific threat metrics."""
        return {
            "llm_analysis": threat.metadata.get("llm_analysis", False),
            "reasoning_length": len(threat.metadata.get("reasoning", "")),
            "has_remediation": len(threat.metadata.get("remediation", "")) > 0,
            "llm_confidence": threat.confidence.get_decimal(),
        }

    def _get_file_size(self, result: ScanResult) -> int | None:
        """Get file size if available."""
        if result.scan_request.context.content:
            return len(result.scan_request.context.content.encode("utf-8"))

        target_path = result.scan_request.context.target_path
        if target_path and target_path.exists() and target_path.is_file():
            return target_path.get_size_bytes()

        return None

    def _get_category_breakdown(self, threats: list[ThreatMatch]) -> dict[str, int]:
        """Get breakdown of threats by category."""
        categories = {}
        for threat in threats:
            categories[threat.category] = categories.get(threat.category, 0) + 1
        return categories

    def _calculate_throughput(self, result: ScanResult) -> float:
        """Calculate threats detected per second."""
        duration_ms = result.scan_metadata.get("scan_duration_ms", 0)
        if duration_ms == 0:
            return 0.0

        duration_s = duration_ms / 1000.0
        return len(result.threats) / duration_s

    def _estimate_lines_scanned(self, result: ScanResult) -> int:
        """Estimate number of lines scanned."""
        if result.scan_request.context.content:
            return result.scan_request.context.content.count("\n") + 1

        # For file/directory scans, this would need file system access
        # Return 0 for now - could be enhanced with actual line counting
        return 0

    def _count_files_processed(self, result: ScanResult) -> int:
        """Count number of files processed."""
        if result.scan_request.context.metadata.scan_type == "code":
            return 1
        elif result.scan_request.context.metadata.scan_type == "file":
            return 1
        else:
            # For directory scans, count unique file paths in threats
            file_paths = set()
            for threat in result.threats:
                file_paths.add(str(threat.file_path))
            return len(file_paths) if file_paths else 1
