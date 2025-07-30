"""LLM-based validator for security findings to reduce false positives and generate exploitation analysis."""

import json
from dataclasses import dataclass
from typing import Any

from ..credentials import CredentialManager
from ..logger import get_logger
from .exploit_generator import ExploitGenerator
from .types import Severity, ThreatMatch

logger = get_logger("llm_validator")


class LLMValidationError(Exception):
    """Exception raised when LLM validation fails."""

    pass


@dataclass
class ValidationResult:
    """Result of LLM validation for a security finding."""

    finding_uuid: str
    is_legitimate: bool
    confidence: float  # 0.0 to 1.0
    reasoning: str
    exploitation_vector: str | None = None
    exploit_poc: list[str] | None = None
    remediation_advice: str | None = None
    severity_adjustment: Severity | None = None  # If severity should be adjusted
    validation_error: str | None = None  # If validation failed

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "finding_uuid": self.finding_uuid,
            "is_legitimate": self.is_legitimate,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "exploitation_vector": self.exploitation_vector,
            "exploit_poc": self.exploit_poc,
            "remediation_advice": self.remediation_advice,
            "severity_adjustment": (
                self.severity_adjustment.value if self.severity_adjustment else None
            ),
            "validation_error": self.validation_error,
        }


@dataclass
class ValidationPrompt:
    """Represents a prompt for LLM validation."""

    system_prompt: str
    user_prompt: str
    findings: list[ThreatMatch]
    source_code: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "findings_count": len(self.findings),
            "source_code_size": len(self.source_code),
        }


class LLMValidator:
    """LLM-based validator for security findings."""

    def __init__(self, credential_manager: CredentialManager):
        """Initialize the LLM validator.

        Args:
            credential_manager: Credential manager for configuration
        """
        logger.info("Initializing LLMValidator")
        self.credential_manager = credential_manager
        self.config = credential_manager.load_config()
        self.exploit_generator = ExploitGenerator(credential_manager)
        logger.debug("LLMValidator initialized successfully")

    def validate_findings(
        self,
        findings: list[ThreatMatch],
        source_code: str,
        file_path: str,
        generate_exploits: bool = True,
    ) -> dict[str, ValidationResult]:
        """Validate a list of security findings.

        Args:
            findings: List of threat matches to validate
            source_code: Source code containing the vulnerabilities
            file_path: Path to the source file
            generate_exploits: Whether to generate exploit POCs

        Returns:
            Dictionary mapping finding UUID to validation result
        """
        logger.info(f"Validating {len(findings)} findings for {file_path}")

        if not findings:
            logger.debug("No findings to validate")
            return {}

        validation_results = {}

        # In client-based approach, we create prompts but don't execute
        # The actual validation happens on the client side
        for finding in findings:
            logger.debug(f"Processing finding {finding.uuid}: {finding.rule_name}")

            # Create a placeholder result indicating validation is pending
            validation_results[finding.uuid] = ValidationResult(
                finding_uuid=finding.uuid,
                is_legitimate=True,  # Default to legitimate until proven otherwise
                confidence=0.5,  # Medium confidence as placeholder
                reasoning="Client-based validation pending",
                exploitation_vector=None,
                exploit_poc=None,
                remediation_advice=None,
                severity_adjustment=None,
                validation_error=None,
            )

            # Generate exploit POC if requested
            if generate_exploits and self.exploit_generator.is_llm_available():
                try:
                    logger.debug(f"Generating exploit POC for finding {finding.uuid}")
                    exploit_poc = self.exploit_generator.generate_exploits(
                        finding,
                        source_code,
                        use_llm=False,  # Use template-based for now
                    )
                    if exploit_poc:
                        validation_results[finding.uuid].exploit_poc = exploit_poc
                        logger.debug(f"Generated {len(exploit_poc)} exploit POCs")
                except Exception as e:
                    logger.warning(f"Failed to generate exploit POC: {e}")

        logger.info(f"Validation complete for {len(validation_results)} findings")
        return validation_results

    def create_validation_prompt(
        self, findings: list[ThreatMatch], source_code: str, file_path: str
    ) -> ValidationPrompt:
        """Create validation prompt for LLM.

        Args:
            findings: List of findings to validate
            source_code: Source code to analyze
            file_path: Path to the source file

        Returns:
            ValidationPrompt object
        """
        logger.debug(f"Creating validation prompt for {len(findings)} findings")

        system_prompt = self._create_system_prompt()
        user_prompt = self._create_user_prompt(findings, source_code, file_path)

        prompt = ValidationPrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            findings=findings,
            source_code=source_code,
        )

        logger.debug("Validation prompt created successfully")
        return prompt

    def parse_validation_response(
        self, response_text: str, findings: list[ThreatMatch]
    ) -> dict[str, ValidationResult]:
        """Parse LLM validation response.

        Args:
            response_text: Raw response from LLM
            findings: Original findings being validated

        Returns:
            Dictionary mapping finding UUID to validation result
        """
        logger.debug(f"Parsing validation response for {len(findings)} findings")

        if not response_text or not response_text.strip():
            logger.warning("Empty validation response")
            return {}

        try:
            # Parse JSON response
            data = json.loads(response_text)
            validations = data.get("validations", [])

            results = {}
            finding_map = {f.uuid: f for f in findings}

            for validation_data in validations:
                finding_uuid = validation_data.get("finding_uuid")
                if not finding_uuid or finding_uuid not in finding_map:
                    logger.warning(
                        f"Unknown finding UUID in validation: {finding_uuid}"
                    )
                    continue

                # Parse severity adjustment if present
                severity_adjustment = None
                if "severity_adjustment" in validation_data:
                    try:
                        severity_adjustment = Severity(
                            validation_data["severity_adjustment"]
                        )
                    except ValueError:
                        logger.warning(
                            f"Invalid severity adjustment: {validation_data['severity_adjustment']}"
                        )

                result = ValidationResult(
                    finding_uuid=finding_uuid,
                    is_legitimate=validation_data.get("is_legitimate", True),
                    confidence=float(validation_data.get("confidence", 0.5)),
                    reasoning=validation_data.get("reasoning", ""),
                    exploitation_vector=validation_data.get("exploitation_vector"),
                    exploit_poc=validation_data.get("exploit_poc", []),
                    remediation_advice=validation_data.get("remediation_advice"),
                    severity_adjustment=severity_adjustment,
                    validation_error=None,
                )

                results[finding_uuid] = result
                logger.debug(
                    f"Parsed validation for {finding_uuid}: legitimate={result.is_legitimate}"
                )

            logger.info(f"Successfully parsed {len(results)} validation results")
            return results

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse validation response as JSON: {e}")
            raise LLMValidationError(f"Invalid JSON response: {e}")
        except Exception as e:
            logger.error(f"Error parsing validation response: {e}")
            raise LLMValidationError(f"Error parsing response: {e}")

    def _create_system_prompt(self) -> str:
        """Create system prompt for validation.

        Returns:
            System prompt string
        """
        return """You are a senior security engineer performing vulnerability validation.
Your task is to analyze security findings and determine if they are legitimate vulnerabilities or false positives.

For each finding, you should:
1. Analyze the code context to understand the vulnerability
2. Determine if the finding is a legitimate security issue
3. Assess the exploitability and real-world impact
4. Provide confidence in your assessment (0.0 to 1.0)
5. Explain your reasoning clearly
6. If legitimate, describe the exploitation vector
7. Suggest remediation if the finding is valid
8. Recommend severity adjustment if the current severity is incorrect

Consider factors like:
- Input validation and sanitization
- Authentication and authorization checks
- Framework-provided protections
- Environmental context (is this test code, example code, etc.)
- Actual exploitability vs theoretical vulnerability
- Business logic and application context

Be thorough but practical - focus on real security impact."""

    def _create_user_prompt(
        self, findings: list[ThreatMatch], source_code: str, file_path: str
    ) -> str:
        """Create user prompt for validation.

        Args:
            findings: Findings to validate
            source_code: Source code context
            file_path: File path

        Returns:
            User prompt string
        """
        # Truncate very long code
        max_code_length = 10000
        if len(source_code) > max_code_length:
            source_code = (
                source_code[:max_code_length] + "\n... [truncated for analysis]"
            )

        findings_json = []
        for finding in findings:
            findings_json.append(
                {
                    "uuid": finding.uuid,
                    "rule_name": finding.rule_name,
                    "description": finding.description,
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "line_number": finding.line_number,
                    "code_snippet": finding.code_snippet,
                    "confidence": finding.confidence,
                }
            )

        prompt = f"""Validate the following security findings for the file {file_path}:

**Source Code:**
```
{source_code}
```

**Security Findings to Validate:**
{json.dumps(findings_json, indent=2)}

For each finding, determine if it's a legitimate vulnerability or a false positive.

Response format:
{{
  "validations": [
    {{
      "finding_uuid": "uuid-here",
      "is_legitimate": true/false,
      "confidence": 0.9,
      "reasoning": "Detailed explanation of why this is/isn't a real vulnerability",
      "exploitation_vector": "How an attacker could exploit this (if legitimate)",
      "remediation_advice": "How to fix this vulnerability (if legitimate)",
      "severity_adjustment": "high/medium/low/critical (only if current severity is wrong)"
    }}
  ]
}}

Be specific and consider the full context when making determinations."""

        return prompt

    def filter_false_positives(
        self,
        findings: list[ThreatMatch],
        validation_results: dict[str, ValidationResult],
        confidence_threshold: float = 0.7,
    ) -> list[ThreatMatch]:
        """Filter out false positives based on validation results.

        Args:
            findings: Original findings
            validation_results: Validation results
            confidence_threshold: Minimum confidence to consider a finding legitimate

        Returns:
            Filtered list of legitimate findings
        """
        logger.debug(
            f"Filtering {len(findings)} findings with confidence threshold {confidence_threshold}"
        )

        legitimate_findings = []

        for finding in findings:
            validation = validation_results.get(finding.uuid)

            # If no validation result, keep the finding (fail-open)
            if not validation:
                logger.debug(f"No validation for {finding.uuid}, keeping finding")
                legitimate_findings.append(finding)
                continue

            # Check if legitimate with sufficient confidence
            if (
                validation.is_legitimate
                and validation.confidence >= confidence_threshold
            ):
                # Apply severity adjustment if recommended
                if validation.severity_adjustment:
                    logger.info(
                        f"Adjusting severity for {finding.uuid} from {finding.severity} to {validation.severity_adjustment}"
                    )
                    finding.severity = validation.severity_adjustment

                # Add validation metadata to finding
                finding.remediation = (
                    validation.remediation_advice or finding.remediation
                )
                if validation.exploit_poc:
                    finding.exploit_examples.extend(validation.exploit_poc)

                legitimate_findings.append(finding)
                logger.debug(f"Finding {finding.uuid} validated as legitimate")
            else:
                logger.info(
                    f"Filtering out finding {finding.uuid} as false positive (legitimate={validation.is_legitimate}, confidence={validation.confidence})"
                )

        logger.info(
            f"Filtered {len(findings)} findings to {len(legitimate_findings)} legitimate findings"
        )
        return legitimate_findings

    def get_validation_stats(
        self, validation_results: dict[str, ValidationResult]
    ) -> dict[str, Any]:
        """Get statistics about validation results.

        Args:
            validation_results: Validation results

        Returns:
            Dictionary with validation statistics
        """
        total = len(validation_results)
        legitimate = sum(1 for v in validation_results.values() if v.is_legitimate)
        false_positives = total - legitimate
        avg_confidence = (
            sum(v.confidence for v in validation_results.values()) / total
            if total > 0
            else 0
        )

        stats = {
            "total_validated": total,
            "legitimate_findings": legitimate,
            "false_positives": false_positives,
            "false_positive_rate": false_positives / total if total > 0 else 0,
            "average_confidence": avg_confidence,
            "validation_errors": sum(
                1 for v in validation_results.values() if v.validation_error
            ),
        }

        logger.debug(f"Validation stats: {stats}")
        return stats
