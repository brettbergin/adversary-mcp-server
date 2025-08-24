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
        logger.info(
            f"LLM validation strategy called with {len(threats)} threats, validator available: {self._validator is not None}"
        )
        if not threats or self._validator is None:
            if self._validator is None:
                logger.info("Validation skipped: LLM validator not available")
            else:
                logger.info("Validation skipped: no threats to validate")
            return threats

        try:
            logger.info(f"Starting validation of {len(threats)} threats")
            for threat in threats:
                logger.debug(
                    f"Pre-validation threat: {threat.rule_id} ({threat.source_scanner}) - confidence: {threat.confidence.get_percentage()}%"
                )

            # Execute LLM validation directly with domain objects
            validation_results = await self._execute_validation(threats, context)
            logger.info(
                f"Validation execution completed, got {len(validation_results)} results"
            )

            # Update threat confidence based on validation results
            validated_threats = self._apply_validation_results(
                threats, validation_results
            )
            logger.info(
                f"After applying validation results: {len(validated_threats)} threats"
            )

            # Filter threats based on confidence threshold
            high_confidence_threats = self._filter_by_confidence(validated_threats)
            logger.info(
                f"After confidence filtering: {len(high_confidence_threats)} threats"
            )

            # Record validation metadata
            self._record_validation_metadata(
                threats, validated_threats, high_confidence_threats, context
            )

            return high_confidence_threats

        except Exception as e:
            # If validation fails, return original threats with warning
            logger.warning(f"LLM validation failed, returning original threats: {e}")
            import traceback

            logger.debug(f"Validation exception traceback: {traceback.format_exc()}")
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
        threshold = self._default_confidence_threshold

        logger.info(
            f"Filtering {len(threats)} threats with confidence threshold {threshold.get_percentage()}%"
        )

        filtered_threats = []
        confidence_filtered_count = 0
        false_positive_filtered_count = 0

        for threat in threats:
            # Log detailed threat info for debugging
            logger.debug(
                f"Processing threat {threat.rule_id} ({threat.source_scanner}) - "
                f"confidence: {threat.confidence.get_percentage()}%, "
                f"is_false_positive: {threat.is_false_positive}"
            )

            # Check confidence threshold
            if not threat.confidence.meets_threshold(threshold):
                confidence_filtered_count += 1
                logger.warning(
                    f"Filtering threat {threat.rule_id} ({threat.source_scanner}) - "
                    f"confidence {threat.confidence.get_percentage()}% below threshold {threshold.get_percentage()}%"
                )
                continue

            # Check false positive status
            if threat.is_false_positive:
                false_positive_filtered_count += 1
                logger.warning(
                    f"Filtering threat {threat.rule_id} ({threat.source_scanner}) - marked as false positive"
                )
                continue

            # Threat passes all filters
            logger.debug(
                f"Keeping threat {threat.rule_id} ({threat.source_scanner}) - "
                f"confidence {threat.confidence.get_percentage()}%, not false positive"
            )
            filtered_threats.append(threat)

        logger.info(
            f"Validation filtering results: {len(filtered_threats)}/{len(threats)} threats kept, "
            f"{confidence_filtered_count} filtered by confidence, "
            f"{false_positive_filtered_count} filtered as false positives"
        )

        return filtered_threats

    def _record_validation_metadata(
        self,
        original_threats: list[ThreatMatch],
        validated_threats: list[ThreatMatch],
        final_threats: list[ThreatMatch],
        context: ScanContext,
    ) -> None:
        """Record validation metadata for debugging and transparency."""
        false_positives_count = len(
            [t for t in validated_threats if t.is_false_positive]
        )
        confidence_filtered_count = (
            len(validated_threats) - len(final_threats) - false_positives_count
        )

        # Extract unique scanners from original threats
        active_scanners = set()
        for threat in original_threats:
            scanner_parts = threat.source_scanner.split("+")
            active_scanners.update(scanner_parts)

        validation_metadata = {
            "validation_applied": True,
            "validation_stats": {
                "original_threat_count": len(original_threats),
                "validated_threat_count": len(validated_threats),
                "final_threat_count": len(final_threats),
                "false_positives_filtered": false_positives_count,
                "confidence_filtered": confidence_filtered_count,
                "validation_filter_rate": (
                    1.0 - (len(final_threats) / len(original_threats))
                    if original_threats
                    else 0.0
                ),
                "active_scanners_original": sorted(active_scanners),
                "confidence_threshold": self._default_confidence_threshold.get_percentage(),
            },
        }

        logger.info(f"Validation completed: {validation_metadata['validation_stats']}")

        # Log detailed breakdown for debugging
        original_scanners = [t.source_scanner for t in original_threats]
        validated_scanners = [t.source_scanner for t in validated_threats]
        final_scanners = [t.source_scanner for t in final_threats]

        logger.debug(
            f"Original threats by scanner: {dict(sorted({s: original_scanners.count(s) for s in set(original_scanners)}.items()))}"
        )
        logger.debug(
            f"Validated threats by scanner: {dict(sorted({s: validated_scanners.count(s) for s in set(validated_scanners)}.items()))}"
        )
        logger.debug(
            f"Final threats by scanner: {dict(sorted({s: final_scanners.count(s) for s in set(final_scanners)}.items()))}"
        )

        # Store validation metadata in a global dict keyed by scan_id for retrieval
        # This works around the frozen dataclass limitation
        scan_id = context.metadata.scan_id
        logger.debug(f"Storing validation metadata for scan_id: {scan_id}")
        if not hasattr(self.__class__, "_validation_metadata_cache"):
            self.__class__._validation_metadata_cache = {}
        self.__class__._validation_metadata_cache[scan_id] = validation_metadata
        logger.debug(
            f"Validation cache now has {len(self.__class__._validation_metadata_cache)} entries"
        )

        # Also store in module-level cache as backup
        if not hasattr(self.__class__, "_module_validation_cache"):
            self.__class__._module_validation_cache = {}
        self.__class__._module_validation_cache[scan_id] = validation_metadata

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
