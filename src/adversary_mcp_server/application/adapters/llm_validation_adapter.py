"""Adapter for LLMValidator to implement domain IValidationStrategy interface."""

import asyncio
from typing import Any

from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.interfaces import IValidationStrategy
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.logger import get_logger
from adversary_mcp_server.scanner.llm_validator import LLMValidator

logger = get_logger("llm_validation_adapter")


class LLMValidationStrategy(IValidationStrategy):
    """
    Adapter that wraps LLMValidator to implement the domain IValidationStrategy interface.

    This adapter enables the domain layer to use LLM-powered validation for false positive
    reduction while maintaining clean separation between domain logic and infrastructure.
    """

    def __init__(self, llm_validator: LLMValidator | None = None):
        """Initialize the adapter with an optional LLMValidator instance."""
        if llm_validator:
            self._validator = llm_validator
        else:
            # Try to initialize with default dependencies
            try:
                from adversary_mcp_server.credentials import get_credential_manager

                credential_manager = get_credential_manager()
                self._validator = LLMValidator(credential_manager)
            except Exception as e:
                logger.warning(f"Could not initialize LLMValidator: {e}")
                self._validator = None
        self._default_confidence_threshold = ConfidenceScore(0.7)

    def get_strategy_name(self) -> str:
        """Get the name of this validation strategy."""
        return "llm_validation"

    def can_validate(self, threats: list[ThreatMatch]) -> bool:
        """
        Check if this strategy can validate the given threats.

        LLM validation can process most threats, but has practical limits.
        """
        # Check if validator is available
        if self._validator is None:
            return False

        # Can validate if we have threats to process
        if not threats:
            return False

        # Check if we have too many threats (performance limit)
        if len(threats) > 100:  # Practical limit for LLM processing
            return False

        # LLM validation works best with code context
        has_code_context = any(threat.code_snippet for threat in threats)

        return has_code_context

    async def validate_threats(
        self, threats: list[ThreatMatch], context: ScanContext
    ) -> list[ThreatMatch]:
        """
        Validate threats using LLM analysis to reduce false positives.

        This method:
        1. Converts domain threats to validation input format
        2. Executes LLM validation
        3. Updates threat confidence scores based on validation results
        4. Filters out low-confidence threats
        """
        if not threats or self._validator is None:
            return threats

        try:
            # Execute LLM validation directly with domain objects
            validation_results = await self._execute_validation(threats, context)

            # Update threat confidence based on validation results
            validated_threats = self._apply_validation_results(
                threats, validation_results
            )

            # Filter threats based on confidence threshold
            high_confidence_threats = self._filter_by_confidence(validated_threats)

            return high_confidence_threats

        except Exception as e:
            # If validation fails, return original threats with warning
            print(f"Warning: LLM validation failed, returning original threats: {e}")
            return threats

    async def _execute_validation(
        self, threats: list[ThreatMatch], context: ScanContext
    ) -> dict[str, Any]:
        """Execute LLM validation using infrastructure layer."""
        # Extract parameters for validate_findings
        source_code = context.content or ""
        file_path = str(context.target_path) if context.target_path else "unknown.py"

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._validator.validate_findings(
                findings=threats,
                source_code=source_code,
                file_path=file_path,
                generate_exploits=False,  # Conservative default for validation
            ),
        )

    def _apply_validation_results(
        self, threats: list[ThreatMatch], validation_results: dict[str, Any]
    ) -> list[ThreatMatch]:
        """Apply validation results to update threat confidence scores."""
        # validation_results is a dict[str, ValidationResult] mapping finding UUID to validation result
        validated_threats = []

        for threat in threats:
            validation_result = validation_results.get(threat.uuid)

            if validation_result:
                # validation_result is a ValidationResult object
                # Update confidence based on validation
                new_confidence = ConfidenceScore(
                    min(1.0, max(0.0, validation_result.confidence))
                )

                # Update threat with new confidence
                updated_threat = threat.update_confidence(new_confidence)

                # Add validation metadata
                validation_metadata = {
                    "validated_by": "llm",
                    "validation_confidence": new_confidence.get_decimal(),
                    "validation_reasoning": validation_result.reasoning,
                    "is_false_positive": not validation_result.is_legitimate,
                    "validation_notes": validation_result.exploitation_vector or "",
                }

                # Mark as false positive if validation determined it
                if not validation_result.is_legitimate:
                    updated_threat = updated_threat.mark_as_false_positive(
                        reason="LLM validation determined this is a false positive"
                    )

                # Update metadata
                combined_metadata = {**threat.metadata, **validation_metadata}
                updated_threat = updated_threat.add_metadata(validation_metadata)

                validated_threats.append(updated_threat)
            else:
                # No validation result - keep original threat but with lower confidence
                penalized_confidence = threat.confidence.penalize(
                    0.1
                )  # Small penalty for no validation
                updated_threat = threat.update_confidence(penalized_confidence)
                validated_threats.append(updated_threat)

        return validated_threats

    def _filter_by_confidence(self, threats: list[ThreatMatch]) -> list[ThreatMatch]:
        """Filter threats based on confidence threshold."""
        return [
            threat
            for threat in threats
            if threat.confidence.meets_threshold(self._default_confidence_threshold)
            and not threat.is_false_positive
        ]

    def set_confidence_threshold(self, threshold: ConfidenceScore) -> None:
        """Set the confidence threshold for filtering validated threats."""
        self._default_confidence_threshold = threshold

    def get_confidence_threshold(self) -> float:
        """Get the current confidence threshold."""
        return self._default_confidence_threshold.get_decimal()

    def get_validation_statistics(
        self, original_threats: list[ThreatMatch], validated_threats: list[ThreatMatch]
    ) -> dict[str, Any]:
        """Get statistics about the validation process."""
        original_count = len(original_threats)
        validated_count = len(validated_threats)
        false_positives = len([t for t in validated_threats if t.is_false_positive])

        return {
            "original_threat_count": original_count,
            "validated_threat_count": validated_count,
            "false_positives_detected": false_positives,
            "reduction_percentage": (
                ((original_count - validated_count) / original_count * 100)
                if original_count > 0
                else 0
            ),
            "validation_strategy": self.get_strategy_name(),
            "confidence_threshold": self._default_confidence_threshold.get_percentage(),
        }
