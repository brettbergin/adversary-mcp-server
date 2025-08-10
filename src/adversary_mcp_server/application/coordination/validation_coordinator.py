"""Validation coordination for LLM-based finding validation."""

from pathlib import Path
from typing import Any

from ...interfaces.validator import IValidator
from ...logger import get_logger
from ...scanner.language_mapping import LanguageMapper
from ...scanner.types import ThreatMatch

logger = get_logger("validation_coordinator")


class ValidationCoordinator:
    """Coordinates LLM validation of security findings."""

    def __init__(self, validator: IValidator | None = None):
        """Initialize the validation coordinator."""
        self.validator = validator
        logger.debug(
            f"ValidationCoordinator initialized with validator: {validator is not None}"
        )

    def should_validate(
        self,
        use_validation: bool,
        enable_llm_validation: bool,
        threats: list[ThreatMatch],
    ) -> bool:
        """Determine if validation should be performed."""
        should_validate = (
            use_validation
            and enable_llm_validation
            and self.validator is not None
            and bool(threats)
        )

        if not should_validate:
            logger.debug(
                f"Validation skipped - use_validation: {use_validation}, "
                f"enable_llm_validation: {enable_llm_validation}, "
                f"validator: {self.validator is not None}, "
                f"threats: {len(threats) if threats else 0}"
            )

        return should_validate

    def validate_findings(
        self,
        findings: list[ThreatMatch],
        file_content: str | None = None,
        file_path: Path | None = None,
        preview_size: int = 10000,
    ) -> dict[str, Any]:
        """Validate security findings using LLM analysis."""
        if not self.validator:
            raise ValueError("No validator available for validation")

        if not findings:
            return {}

        logger.info(f"Validating {len(findings)} findings with LLM validator")

        try:
            # Prepare file content if needed
            validation_content = None
            if file_content and preview_size:
                validation_content = file_content[:preview_size]

            # Perform validation
            validation_results = self.validator.validate_findings(
                findings=findings,
                source_code=validation_content or "",
                file_path=str(file_path) if file_path else "",
            )

            logger.debug(f"Validation completed for {len(validation_results)} findings")
            return validation_results

        except Exception as e:
            logger.error(f"LLM validation failed: {e}")
            raise

    def filter_false_positives(
        self,
        threats: list[ThreatMatch],
        validation_results: dict[str, Any],
        confidence_threshold: float = 0.7,
    ) -> list[ThreatMatch]:
        """Filter out false positives based on validation results."""
        if not validation_results or not threats:
            return threats

        filtered_threats = []
        false_positives = 0

        for threat in threats:
            # Get validation result for this threat
            validation = validation_results.get(threat.id)

            if validation is None:
                # No validation result - keep the threat
                filtered_threats.append(threat)
                continue

            # Check if this is a legitimate finding
            is_legitimate = getattr(validation, "is_legitimate", True)
            confidence = getattr(validation, "confidence", 1.0)

            if is_legitimate and confidence >= confidence_threshold:
                filtered_threats.append(threat)
            else:
                false_positives += 1
                logger.debug(
                    f"Filtered false positive: {threat.rule_id} "
                    f"(confidence: {confidence:.2f})"
                )

        if false_positives > 0:
            logger.info(
                f"Filtered {false_positives} false positives, "
                f"{len(filtered_threats)} threats remain"
            )

        return filtered_threats

    def build_validation_metadata(
        self,
        use_validation: bool,
        enable_llm_validation: bool,
        validation_results: dict[str, Any],
        validation_error: str | None = None,
    ) -> dict[str, Any]:
        """Build validation metadata for scan results."""
        metadata = {}

        # Determine validation status
        validation_performed = bool(validation_results)

        if validation_performed and not validation_error:
            metadata["llm_validation_success"] = True
            if self.validator:
                metadata["llm_validation_stats"] = self.validator.get_validation_stats(
                    validation_results
                )
        else:
            metadata["llm_validation_success"] = False

            if validation_error:
                metadata["llm_validation_error"] = validation_error
            elif not use_validation:
                metadata["llm_validation_reason"] = "disabled"
            elif not enable_llm_validation:
                metadata["llm_validation_reason"] = "disabled"
            elif not self.validator:
                metadata["llm_validation_reason"] = "not_available"

        return metadata

    def get_validation_stats(
        self, validation_results: dict[str, Any]
    ) -> dict[str, Any]:
        """Get validation statistics from results."""
        if not validation_results:
            return {
                "total_findings_reviewed": 0,
                "legitimate_findings": 0,
                "false_positives_filtered": 0,
                "false_positive_rate": 0.0,
                "average_confidence": 0.0,
                "validation_errors": 0,
            }

        total_reviewed = len(validation_results)
        legitimate = sum(
            1 for v in validation_results.values() if getattr(v, "is_legitimate", True)
        )
        false_positives = total_reviewed - legitimate

        # Calculate average confidence
        confidences = [
            getattr(v, "confidence", 1.0) for v in validation_results.values()
        ]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        # Count validation errors
        validation_errors = sum(
            1
            for v in validation_results.values()
            if getattr(v, "validation_error", False)
        )

        return {
            "total_findings_reviewed": total_reviewed,
            "legitimate_findings": legitimate,
            "false_positives_filtered": false_positives,
            "false_positive_rate": (
                false_positives / total_reviewed if total_reviewed > 0 else 0.0
            ),
            "average_confidence": round(avg_confidence, 3),
            "validation_errors": validation_errors,
        }

    def _detect_language(self, file_path: Path | None) -> str | None:
        """Detect programming language from file path using shared mapper."""
        if not file_path:
            return None
        detected = LanguageMapper.detect_language_from_extension(file_path)
        return detected if detected != "generic" else None
