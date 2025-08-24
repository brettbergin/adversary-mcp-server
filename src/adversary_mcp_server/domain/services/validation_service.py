"""ValidationService domain service with business validation rules."""

import logging
import re

from ...scanner.language_mapping import (
    ANALYZABLE_SOURCE_EXTENSIONS,
    BLOCKED_PATH_PATTERNS,
)
from ..entities.scan_request import ScanRequest
from ..entities.scan_result import ScanResult
from ..entities.threat_match import ThreatMatch
from ..interfaces import IValidationService, SecurityError, ValidationError
from ..value_objects.scan_context import ScanContext

logger = logging.getLogger(__name__)


class ValidationService(IValidationService):
    """
    Domain service providing business validation rules for security scanning.

    Enforces business rules, validates data consistency, and ensures security
    constraints are met throughout the scanning process. Contains pure domain
    logic without infrastructure dependencies.
    """

    def __init__(self):
        # Security constraints
        self._max_file_size_bytes = 10 * 1024 * 1024  # 10MB
        self._max_directory_files = 1000
        self._max_code_snippet_lines = 1000

        # Blocked paths for security (use shared constants)
        self._blocked_path_patterns = BLOCKED_PATH_PATTERNS.copy()

        # Allowed file extensions for scanning (use shared constants)
        self._allowed_extensions = ANALYZABLE_SOURCE_EXTENSIONS.copy()

        # Required threat fields
        self._required_threat_fields = {
            "rule_id",
            "rule_name",
            "description",
            "category",
            "severity",
            "file_path",
            "line_number",
        }

    def validate_scan_request(self, request: ScanRequest) -> None:
        """
        Validate a scan request according to business rules.

        Args:
            request: The scan request to validate

        Raises:
            ValidationError: If the request violates business rules
            SecurityError: If security constraints are violated
        """
        try:
            # Validate scan context
            self._validate_scan_context(request.context)

            # Validate configuration consistency
            self._validate_scan_configuration(request)

            # Enforce security constraints
            self.enforce_security_constraints(request.context)

            # Validate scanner configuration
            self._validate_scanner_configuration(request)

            logger.debug(
                f"Scan request validation passed for: {request.context.metadata.scan_id}"
            )

        except (ValidationError, SecurityError):
            raise
        except Exception as e:
            raise ValidationError(f"Scan request validation failed: {e}") from e

    def validate_threat_data(self, threat: ThreatMatch) -> None:
        """
        Validate threat data for consistency and completeness.

        Args:
            threat: The threat to validate

        Raises:
            ValidationError: If the threat data is invalid
        """
        try:
            # Check required fields
            self._validate_required_threat_fields(threat)

            # Validate threat data types and ranges
            self._validate_threat_data_types(threat)

            # Validate threat consistency
            self._validate_threat_consistency(threat)

            # Validate security-related fields
            self._validate_threat_security_fields(threat)

            logger.debug(f"Threat validation passed for: {threat.uuid}")

        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Threat validation failed: {e}") from e

    def validate_scan_result(self, result: ScanResult) -> None:
        """
        Validate a scan result for consistency and completeness.

        Args:
            result: The scan result to validate

        Raises:
            ValidationError: If the result is invalid
        """
        try:
            # Validate each threat in the result
            for threat in result.threats:
                self.validate_threat_data(threat)

            # Validate result consistency
            self._validate_result_consistency(result)

            # Validate result metadata
            self._validate_result_metadata(result)

            # Validate threat relationships
            self._validate_threat_relationships(result.threats)

            logger.debug(
                f"Scan result validation passed for: {result.request.context.metadata.scan_id}"
            )

        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Scan result validation failed: {e}") from e

    def enforce_security_constraints(self, context: ScanContext) -> None:
        """
        Enforce security constraints for scan operations.

        Args:
            context: The scan context to check

        Raises:
            SecurityError: If security constraints are violated
        """
        try:
            # Check for blocked paths
            self._check_blocked_paths(context)

            # Validate file size constraints
            self._check_file_size_constraints(context)

            # Validate directory size constraints
            self._check_directory_constraints(context)

            # Check code snippet constraints
            self._check_code_snippet_constraints(context)

            # Validate file extensions
            self._check_file_extensions(context)

            logger.debug(f"Security constraints passed for: {context.target_path}")

        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError(f"Security constraint enforcement failed: {e}") from e

    def _validate_scan_context(self, context: ScanContext) -> None:
        """Validate scan context for basic consistency."""
        if not context.target_path:
            raise ValidationError("Scan context must have a target path")

        if not context.metadata:
            raise ValidationError("Scan context must have metadata")

        if not context.metadata.scan_id:
            raise ValidationError("Scan metadata must have a scan ID")

        # Validate scan type consistency
        if context.is_file_scan() and not context.target_path.is_file():
            raise ValidationError("File scan context must target a file")

        if context.is_directory_scan() and not context.target_path.is_directory():
            raise ValidationError("Directory scan context must target a directory")

        if context.is_code_scan() and not context.content:
            raise ValidationError("Code scan context must have content")

    def _validate_scan_configuration(self, request: ScanRequest) -> None:
        """Validate scan configuration for consistency."""
        # At least one scanner must be enabled
        if not any([request.enable_semgrep, request.enable_llm]):
            raise ValidationError("At least one scanner must be enabled")

        # Check timeout constraints
        timeout = request.context.metadata.get_effective_timeout()
        if timeout <= 0:
            raise ValidationError("Scan timeout must be positive")

        if timeout > 3600:  # 1 hour max
            raise ValidationError("Scan timeout cannot exceed 1 hour")

    def _validate_scanner_configuration(self, request: ScanRequest) -> None:
        """Validate scanner-specific configuration."""
        # Code scans should prefer LLM analysis
        if request.context.is_code_scan() and not request.enable_llm:
            logger.warning("Code scans are more effective with LLM analysis enabled")

        # Large directory scans should use Semgrep for efficiency
        if request.context.is_directory_scan():
            scannable_files = request.context.get_scannable_files()
            if len(scannable_files) > 50 and not request.enable_semgrep:
                logger.warning(
                    "Large directory scans are more efficient with Semgrep enabled"
                )

    def _validate_required_threat_fields(self, threat: ThreatMatch) -> None:
        """Validate that all required threat fields are present."""
        missing_fields = []

        if not threat.rule_id or not threat.rule_id.strip():
            missing_fields.append("rule_id")

        if not threat.rule_name or not threat.rule_name.strip():
            missing_fields.append("rule_name")

        if not threat.description or not threat.description.strip():
            missing_fields.append("description")

        if not threat.category or not threat.category.strip():
            missing_fields.append("category")

        if not threat.file_path:
            missing_fields.append("file_path")

        if missing_fields:
            raise ValidationError(f"Threat missing required fields: {missing_fields}")

    def _validate_threat_data_types(self, threat: ThreatMatch) -> None:
        """Validate threat data types and ranges."""
        # Line number validation
        if threat.line_number < 1:
            raise ValidationError("Line number must be positive")

        if threat.line_number > 1_000_000:  # Reasonable upper limit
            raise ValidationError("Line number is unreasonably large")

        # Column number validation
        if threat.column_number < 0:
            raise ValidationError("Column number cannot be negative")

        # Confidence validation
        if not (0.0 <= threat.confidence.get_decimal() <= 1.0):
            raise ValidationError("Confidence must be between 0.0 and 1.0")

        # UUID validation
        if not threat.uuid or len(threat.uuid) < 10:
            raise ValidationError("Invalid threat UUID")

    def _validate_threat_consistency(self, threat: ThreatMatch) -> None:
        """Validate threat internal consistency."""
        # Source validation
        valid_sources = {"semgrep", "llm", "rules", "unknown"}
        source_parts = set(threat.source_scanner.split("+"))

        if not source_parts.issubset(valid_sources):
            invalid_sources = source_parts - valid_sources
            raise ValidationError(f"Invalid threat sources: {invalid_sources}")

        # Code snippet validation
        if threat.code_snippet and len(threat.code_snippet) > 10_000:
            raise ValidationError("Code snippet is too large (max 10,000 characters)")

        # CWE ID validation
        if threat.cwe_id and not re.match(r"^CWE-\d+$", threat.cwe_id):
            raise ValidationError(f"Invalid CWE ID format: {threat.cwe_id}")

    def _validate_threat_security_fields(self, threat: ThreatMatch) -> None:
        """Validate security-related threat fields."""
        # Check for potential information disclosure in threat data
        sensitive_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
        ]

        fields_to_check = [threat.description, threat.code_snippet, threat.remediation]

        for field in fields_to_check:
            if field:
                for pattern in sensitive_patterns:
                    if re.search(pattern, field, re.IGNORECASE):
                        logger.warning(
                            f"Potential sensitive data in threat {threat.uuid}"
                        )
                        break

    def _validate_result_consistency(self, result: ScanResult) -> None:
        """Validate scan result consistency."""
        # Check that all threats belong to the scan
        scan_id = result.request.context.metadata.scan_id

        for threat in result.threats:
            # Threats should be from scannable files
            if result.request.context.is_file_scan():
                expected_path = str(result.request.context.target_path)
                if str(threat.file_path) != expected_path:
                    logger.warning(
                        f"Threat file path {threat.file_path} doesn't match scan target {expected_path}"
                    )

    def _validate_result_metadata(self, result: ScanResult) -> None:
        """Validate scan result metadata."""
        if not result.scan_metadata:
            raise ValidationError("Scan result must have metadata")

        # Check for required metadata fields
        required_fields = ["scan_id"]
        for field in required_fields:
            if field not in result.scan_metadata:
                raise ValidationError(
                    f"Scan result metadata missing required field: {field}"
                )

        # Validate timestamp
        if not result.completed_at:
            raise ValidationError("Scan result must have completion timestamp")

    def _validate_threat_relationships(self, threats: list[ThreatMatch]) -> None:
        """Validate relationships between threats."""
        # Check for duplicate UUIDs
        uuids = [threat.uuid for threat in threats]
        if len(set(uuids)) != len(uuids):
            duplicate_uuids = [uuid for uuid in uuids if uuids.count(uuid) > 1]
            raise ValidationError(
                f"Duplicate threat UUIDs found: {set(duplicate_uuids)}"
            )

        # Check for suspicious patterns
        if len(threats) > 1000:
            logger.warning(f"Very large number of threats found: {len(threats)}")

    def _check_blocked_paths(self, context: ScanContext) -> None:
        """Check if the scan path is blocked for security reasons."""
        path_str = str(context.target_path)

        for pattern in self._blocked_path_patterns:
            if re.match(pattern, path_str, re.IGNORECASE):
                raise SecurityError(f"Scanning blocked path: {path_str}")

    def _check_file_size_constraints(self, context: ScanContext) -> None:
        """Check file size constraints."""
        if context.is_file_scan():
            try:
                file_size = context.target_path.get_size_bytes()
                if file_size > self._max_file_size_bytes:
                    raise SecurityError(
                        f"File too large: {file_size} bytes (max: {self._max_file_size_bytes})"
                    )
            except Exception:
                # If we can't get file size, allow the scan to continue
                pass

    def _check_directory_constraints(self, context: ScanContext) -> None:
        """Check directory size constraints."""
        if context.is_directory_scan():
            try:
                scannable_files = context.get_scannable_files()
                if len(scannable_files) > self._max_directory_files:
                    raise SecurityError(
                        f"Directory too large: {len(scannable_files)} files (max: {self._max_directory_files})"
                    )
            except Exception:
                # If we can't enumerate files, allow the scan to continue
                pass

    def _check_code_snippet_constraints(self, context: ScanContext) -> None:
        """Check code snippet size constraints."""
        if context.is_code_scan() and context.content:
            lines = context.content.count("\n") + 1
            if lines > self._max_code_snippet_lines:
                raise SecurityError(
                    f"Code snippet too large: {lines} lines (max: {self._max_code_snippet_lines})"
                )

    def _check_file_extensions(self, context: ScanContext) -> None:
        """Check if file extensions are allowed for scanning."""
        if context.is_file_scan():
            extension = context.target_path.suffix.lower()
            if extension and extension not in self._allowed_extensions:
                logger.warning(
                    f"Scanning file with non-standard extension: {extension}"
                )

    def update_security_constraints(
        self,
        max_file_size_bytes: int | None = None,
        max_directory_files: int | None = None,
        max_code_snippet_lines: int | None = None,
        additional_blocked_patterns: set[str] | None = None,
    ) -> None:
        """Update security constraints (for configuration purposes)."""
        if max_file_size_bytes is not None:
            self._max_file_size_bytes = max_file_size_bytes

        if max_directory_files is not None:
            self._max_directory_files = max_directory_files

        if max_code_snippet_lines is not None:
            self._max_code_snippet_lines = max_code_snippet_lines

        if additional_blocked_patterns:
            self._blocked_path_patterns.update(additional_blocked_patterns)

        logger.info("Security constraints updated")

    def get_security_constraints(self) -> dict:
        """Get current security constraints."""
        return {
            "max_file_size_bytes": self._max_file_size_bytes,
            "max_directory_files": self._max_directory_files,
            "max_code_snippet_lines": self._max_code_snippet_lines,
            "blocked_path_patterns": list(self._blocked_path_patterns),
            "allowed_extensions": list(self._allowed_extensions),
        }
