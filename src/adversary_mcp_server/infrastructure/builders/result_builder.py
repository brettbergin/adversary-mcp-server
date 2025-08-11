"""Result building and statistics calculation for scan operations.

This module provides comprehensive result building functionality including
statistics calculation, metadata construction, and validation summaries.
"""

from typing import Any

from ...logger import get_logger
from ...scanner.llm_validator import ValidationResult
from ...scanner.scan_engine import EnhancedScanResult
from ...scanner.types import Severity, ThreatMatch

logger = get_logger("result_builder")


class ResultBuilder:
    """Builder for creating comprehensive scan results with statistics and metadata.

    This class handles:
    - Statistics calculation (severity, category distributions)
    - Metadata construction for scan operations
    - Validation summary generation
    - LLM usage tracking and reporting
    - High-confidence and critical threat filtering
    """

    def build_enhanced_result(
        self,
        file_path: str,
        semgrep_threats: list[ThreatMatch],
        llm_threats: list[ThreatMatch],
        aggregated_threats: list[ThreatMatch],
        scan_metadata: dict[str, Any],
        validation_results: dict[str, ValidationResult] = None,
        llm_usage_stats: dict[str, Any] = None,
    ) -> EnhancedScanResult:
        """Build a comprehensive enhanced scan result.

        Args:
            file_path: Path to the scanned file
            semgrep_threats: Threats found by Semgrep analysis
            llm_threats: Threats found by LLM analysis
            aggregated_threats: Final aggregated and deduplicated threats
            scan_metadata: Metadata about the scan operation
            validation_results: Optional validation results from LLM validator
            llm_usage_stats: Optional LLM usage statistics

        Returns:
            Complete EnhancedScanResult with all statistics and metadata
        """
        logger.debug(f"Building enhanced result for {file_path}")

        # Ensure validation results and LLM usage stats have defaults
        if validation_results is None:
            validation_results = {}
        if llm_usage_stats is None:
            llm_usage_stats = self._create_default_llm_usage_stats()

        # Create the enhanced result object
        result = EnhancedScanResult(
            file_path=file_path,
            llm_threats=llm_threats,
            semgrep_threats=semgrep_threats,
            scan_metadata=scan_metadata,
            validation_results=validation_results,
            llm_usage_stats=llm_usage_stats,
        )

        # Set the aggregated threats (this would normally be done in EnhancedScanResult)
        result.all_threats = aggregated_threats

        logger.info(
            f"Built result for {file_path}: {len(aggregated_threats)} total threats, "
            f"{len(semgrep_threats)} from Semgrep, {len(llm_threats)} from LLM"
        )

        return result

    def calculate_threat_statistics(self, threats: list[ThreatMatch]) -> dict[str, Any]:
        """Calculate comprehensive statistics for a list of threats.

        Args:
            threats: List of threats to analyze

        Returns:
            Dictionary containing various threat statistics
        """
        if not threats:
            return {
                "total_threats": 0,
                "severity_counts": {"low": 0, "medium": 0, "high": 0, "critical": 0},
                "category_counts": {},
                "high_confidence_count": 0,
                "critical_count": 0,
            }

        severity_counts = self._count_by_severity(threats)
        category_counts = self._count_by_category(threats)
        high_confidence_count = len(self.get_high_confidence_threats(threats))
        critical_count = len(self.get_critical_threats(threats))

        return {
            "total_threats": len(threats),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "high_confidence_count": high_confidence_count,
            "critical_count": critical_count,
        }

    def _count_by_severity(self, threats: list[ThreatMatch]) -> dict[str, int]:
        """Count threats by severity level.

        Args:
            threats: List of threats to count

        Returns:
            Dictionary mapping severity levels to counts
        """
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        for threat in threats:
            severity_value = threat.severity.value.lower()
            if severity_value in counts:
                counts[severity_value] += 1
            else:
                logger.warning(f"Unknown severity level: {severity_value}")

        return counts

    def _count_by_category(self, threats: list[ThreatMatch]) -> dict[str, int]:
        """Count threats by category.

        Args:
            threats: List of threats to count

        Returns:
            Dictionary mapping categories to counts
        """
        counts = {}

        for threat in threats:
            # Handle both string categories and enum categories
            if hasattr(threat.category, "value"):
                category = threat.category.value
            else:
                category = str(threat.category)

            counts[category] = counts.get(category, 0) + 1

        return counts

    def get_high_confidence_threats(
        self, threats: list[ThreatMatch], min_confidence: float = 0.8
    ) -> list[ThreatMatch]:
        """Filter threats by confidence score.

        Args:
            threats: List of threats to filter
            min_confidence: Minimum confidence threshold

        Returns:
            List of high-confidence threats
        """
        return [
            threat
            for threat in threats
            if getattr(threat, "confidence", 1.0) >= min_confidence
        ]

    def get_critical_threats(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """Filter threats by critical severity.

        Args:
            threats: List of threats to filter

        Returns:
            List of critical severity threats
        """
        return [threat for threat in threats if threat.severity == Severity.CRITICAL]

    def build_validation_summary(
        self,
        validation_results: dict[str, ValidationResult],
        scan_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Build comprehensive validation summary.

        Args:
            validation_results: Results from LLM validation
            scan_metadata: Scan metadata for validation status

        Returns:
            Dictionary with validation statistics and status
        """
        # Check if validation was performed
        validation_enabled = scan_metadata.get("llm_validation_success", False)

        if not validation_enabled or not validation_results:
            return {
                "enabled": False,
                "total_findings_reviewed": 0,
                "legitimate_findings": 0,
                "false_positives_filtered": 0,
                "false_positive_rate": 0.0,
                "average_confidence": 0.0,
                "validation_errors": 0,
                "status": scan_metadata.get("llm_validation_reason", "disabled"),
            }

        return self._calculate_validation_statistics(validation_results)

    def _calculate_validation_statistics(
        self, validation_results: dict[str, ValidationResult]
    ) -> dict[str, Any]:
        """Calculate detailed validation statistics.

        Args:
            validation_results: Validation results to analyze

        Returns:
            Dictionary with detailed validation statistics
        """
        total_reviewed = len(validation_results)
        legitimate = sum(1 for v in validation_results.values() if v.is_legitimate)
        false_positives = total_reviewed - legitimate

        # Calculate average confidence
        avg_confidence = 0.0
        if total_reviewed > 0:
            avg_confidence = (
                sum(v.confidence for v in validation_results.values()) / total_reviewed
            )

        # Count validation errors
        validation_errors = sum(
            1
            for v in validation_results.values()
            if getattr(v, "validation_error", False)
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

    def build_scan_metadata(
        self,
        scan_type: str,
        language: str,
        use_llm: bool,
        use_semgrep: bool,
        use_validation: bool,
        scan_duration_ms: float,
        **additional_metadata: Any,
    ) -> dict[str, Any]:
        """Build comprehensive scan metadata.

        Args:
            scan_type: Type of scan performed (file, directory, code)
            language: Detected or specified language
            use_llm: Whether LLM analysis was used
            use_semgrep: Whether Semgrep analysis was used
            use_validation: Whether LLM validation was used
            scan_duration_ms: Total scan duration in milliseconds
            **additional_metadata: Additional metadata to include

        Returns:
            Dictionary with comprehensive scan metadata
        """
        metadata = {
            "scan_type": scan_type,
            "language": language,
            "engines_used": {
                "llm_analysis": use_llm,
                "semgrep_analysis": use_semgrep,
            },
            "validation_enabled": use_validation,
            "scan_duration_ms": round(scan_duration_ms, 2),
            "timestamp": additional_metadata.get("timestamp"),
        }

        # Add any additional metadata
        metadata.update(additional_metadata)

        return metadata

    def _create_default_llm_usage_stats(self) -> dict[str, Any]:
        """Create default LLM usage statistics structure.

        Returns:
            Dictionary with default LLM usage stats
        """
        return {
            "analysis": {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_cost": 0.0,
                "api_calls": 0,
                "models_used": [],
            },
            "validation": {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_cost": 0.0,
                "api_calls": 0,
                "models_used": [],
            },
        }

    def add_llm_usage_to_stats(
        self,
        usage_stats: dict[str, Any],
        usage_type: str,
        cost_breakdown: dict[str, Any],
    ) -> None:
        """Add LLM usage data to existing statistics.

        Args:
            usage_stats: Existing usage statistics to update
            usage_type: Type of usage ('analysis' or 'validation')
            cost_breakdown: Cost breakdown from PricingManager
        """
        if usage_type not in usage_stats:
            logger.warning(f"Unknown usage type: {usage_type}")
            return

        usage_section = usage_stats[usage_type]
        tokens = cost_breakdown.get("tokens", {})

        # Update token counts
        usage_section["total_tokens"] += tokens.get("total_tokens", 0)
        usage_section["prompt_tokens"] += tokens.get("prompt_tokens", 0)
        usage_section["completion_tokens"] += tokens.get("completion_tokens", 0)
        usage_section["total_cost"] += cost_breakdown.get("total_cost", 0.0)
        usage_section["api_calls"] += 1

        # Track models used
        model = cost_breakdown.get("model")
        if model and model not in usage_section["models_used"]:
            usage_section["models_used"].append(model)

    def build_scan_result(
        self,
        threats: list[ThreatMatch],
        metadata: dict[str, Any],
        file_path: str = "<unknown>",
    ) -> EnhancedScanResult:
        """Backwards compatibility method for build_scan_result.

        This method provides compatibility with the old interface while
        internally calling the new build_enhanced_result method.

        Args:
            threats: List of all threats (will be split for semgrep/llm)
            metadata: Scan metadata
            file_path: Path to the scanned file

        Returns:
            Enhanced scan result
        """
        # Split threats evenly between semgrep and llm for compatibility
        # In real usage, these would come from separate scanners
        mid = len(threats) // 2
        semgrep_threats = threats[:mid]
        llm_threats = threats[mid:]

        return self.build_enhanced_result(
            file_path=file_path,
            semgrep_threats=semgrep_threats,
            llm_threats=llm_threats,
            aggregated_threats=threats,  # All threats as aggregated
            scan_metadata=metadata,
            validation_results=None,
            llm_usage_stats=None,
        )
