"""Comprehensive result formatting utilities for adversary scan results.

This module provides unified JSON formatting for both MCP and CLI output to ensure
consistent rich metadata, validation details, and scan summaries across all entry points.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..logger import get_logger
from .false_positive_manager import FalsePositiveManager
from .scan_engine import EnhancedScanResult

logger = get_logger("result_formatter")


class ScanResultFormatter:
    """Unified formatter for comprehensive scan result JSON output."""

    def __init__(self, working_directory: str = "."):
        """Initialize formatter with working directory for false positive tracking.

        Args:
            working_directory: Working directory path for .adversary.json location
        """
        self.working_directory = working_directory

    def format_directory_results_json(
        self,
        scan_results: list[EnhancedScanResult],
        scan_target: str,
        scan_type: str = "directory",
    ) -> str:
        """Format directory scan results as comprehensive JSON.

        Args:
            scan_results: List of enhanced scan results
            scan_target: Target directory/file that was scanned
            scan_type: Type of scan performed (directory, file, diff)

        Returns:
            JSON formatted comprehensive scan results
        """
        logger.debug(
            f"Formatting {len(scan_results)} scan results as comprehensive JSON"
        )

        # Combine all threats with comprehensive metadata
        all_threats = []
        files_scanned = []

        for scan_result in scan_results:
            # Track files scanned
            files_scanned.append(
                {
                    "file_path": scan_result.file_path,
                    "language": scan_result.language,
                    "threat_count": (
                        len(scan_result.all_threats)
                        if hasattr(scan_result, "all_threats")
                        and isinstance(scan_result.all_threats, list)
                        else 0
                    ),
                    "issues_identified": bool(scan_result.all_threats),
                }
            )

            # Process each threat with full metadata
            for threat in scan_result.all_threats:
                # Get false positive information
                adversary_file_path = str(
                    Path(self.working_directory) / ".adversary.json"
                )
                project_fp_manager = FalsePositiveManager(
                    adversary_file_path=adversary_file_path
                )
                false_positive_data = project_fp_manager.get_false_positive_details(
                    threat.uuid
                )

                # Get validation details for this specific threat
                validation_result = (
                    scan_result.validation_results.get(threat.uuid)
                    if hasattr(scan_result, "validation_results")
                    else None
                )
                validation_data = {
                    "was_validated": validation_result is not None,
                    "validation_confidence": (
                        validation_result.confidence if validation_result else None
                    ),
                    "validation_reasoning": (
                        validation_result.reasoning if validation_result else None
                    ),
                    "validation_status": (
                        "legitimate"
                        if validation_result and validation_result.is_legitimate
                        else (
                            "false_positive"
                            if validation_result and not validation_result.is_legitimate
                            else "not_validated"
                        )
                    ),
                    "exploitation_vector": (
                        validation_result.exploitation_vector
                        if validation_result
                        else None
                    ),
                    "remediation_advice": (
                        validation_result.remediation_advice
                        if validation_result
                        else None
                    ),
                }

                # Build comprehensive threat data
                threat_data = {
                    "uuid": threat.uuid,
                    "rule_id": threat.rule_id,
                    "rule_name": threat.rule_name,
                    "description": threat.description,
                    "category": threat.category.value,
                    "severity": threat.severity.value,
                    "file_path": threat.file_path,
                    "line_number": threat.line_number,
                    "end_line_number": getattr(
                        threat, "end_line_number", threat.line_number
                    ),
                    "code_snippet": threat.code_snippet,
                    "confidence": threat.confidence,
                    "source": getattr(threat, "source", "rules"),
                    "cwe_id": getattr(threat, "cwe_id", []),
                    "owasp_category": getattr(threat, "owasp_category", ""),
                    "remediation": getattr(threat, "remediation", ""),
                    "references": getattr(threat, "references", []),
                    "exploit_examples": getattr(threat, "exploit_examples", []),
                    "is_false_positive": false_positive_data is not None,
                    "false_positive_metadata": false_positive_data,
                    "validation": validation_data,
                }

                all_threats.append(threat_data)

        # Calculate comprehensive statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for threat in all_threats:
            severity_counts[threat["severity"]] += 1

        # Add validation summary aggregation
        validation_summary = self._aggregate_validation_stats(scan_results)

        # Build comprehensive result structure
        result_data = {
            "scan_metadata": {
                "target": scan_target,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "scan_type": scan_type,
                "total_threats": len(all_threats),
                "files_scanned": len(files_scanned),
            },
            "validation_summary": validation_summary,
            "scanner_execution_summary": {
                "semgrep_scanner": self._get_semgrep_summary(scan_results),
                "llm_scanner": {
                    "files_processed": len(
                        [
                            f
                            for f in scan_results
                            if f.scan_metadata.get("llm_scan_success", False)
                        ]
                    ),
                    "files_failed": len(
                        [
                            f
                            for f in scan_results
                            if not f.scan_metadata.get("llm_scan_success", False)
                            and f.scan_metadata.get("llm_scan_reason")
                            not in ["disabled", "not_available"]
                        ]
                    ),
                    "total_threats": sum(
                        f.stats.get("llm_threats", 0) for f in scan_results
                    ),
                },
            },
            "statistics": {
                "total_threats": len(all_threats),
                "severity_counts": severity_counts,
                "files_with_threats": len(
                    [f for f in files_scanned if f["issues_identified"]]
                ),
                "files_clean": len(
                    [f for f in files_scanned if not f["issues_identified"]]
                ),
            },
            "files_scanned": files_scanned,
            "threats": all_threats,
        }

        return json.dumps(result_data, indent=2)

    def format_single_file_results_json(
        self,
        scan_result: EnhancedScanResult,
        scan_target: str,
    ) -> str:
        """Format single file scan results as comprehensive JSON.

        Args:
            scan_result: Enhanced scan result for a single file
            scan_target: Target file that was scanned

        Returns:
            JSON formatted comprehensive scan results
        """
        logger.debug("Formatting single file scan result as comprehensive JSON")

        # Convert single result to list for consistency with directory formatter
        return self.format_directory_results_json(
            [scan_result], scan_target, scan_type="file"
        )

    def format_diff_results_json(
        self,
        scan_results: dict[str, list[EnhancedScanResult]],
        diff_summary: dict[str, Any],
        scan_target: str,
    ) -> str:
        """Format git diff scan results as comprehensive JSON.

        Args:
            scan_results: Dictionary mapping file paths to lists of scan results
            diff_summary: Summary of git diff information
            scan_target: Target description (e.g., "main...feature-branch")

        Returns:
            JSON formatted comprehensive diff scan results
        """
        logger.debug(
            f"Formatting diff scan results for {len(scan_results)} files as comprehensive JSON"
        )

        # Flatten scan results into a single list
        flattened_results = []
        for file_path, file_scan_results in scan_results.items():
            flattened_results.extend(file_scan_results)

        # Use base formatter with diff-specific metadata
        result_json = self.format_directory_results_json(
            flattened_results, scan_target, scan_type="diff"
        )

        # Parse and enhance with diff-specific information
        result_data = json.loads(result_json)

        # Add diff summary information
        result_data["diff_summary"] = diff_summary
        result_data["scan_metadata"]["files_changed"] = len(scan_results)

        # Add per-file diff information
        result_data["files_changed"] = []
        for file_path, file_scan_results in scan_results.items():
            file_info = {
                "file_path": file_path,
                "scan_results_count": len(file_scan_results),
                "total_threats": sum(len(sr.all_threats) for sr in file_scan_results),
                "has_threats": any(sr.all_threats for sr in file_scan_results),
            }
            result_data["files_changed"].append(file_info)

        return json.dumps(result_data, indent=2)

    def _aggregate_validation_stats(
        self, scan_results: list[EnhancedScanResult]
    ) -> dict[str, Any]:
        """Aggregate validation statistics across multiple scan results.

        Args:
            scan_results: List of enhanced scan results to aggregate

        Returns:
            Dictionary with aggregated validation statistics
        """
        if not scan_results:
            return {
                "enabled": False,
                "total_findings_reviewed": 0,
                "legitimate_findings": 0,
                "false_positives_filtered": 0,
                "false_positive_rate": 0.0,
                "average_confidence": 0.0,
                "validation_errors": 0,
                "status": "no_results",
            }

        # Check if any validation was performed
        any_validation_enabled = any(
            result.scan_metadata.get("llm_validation_success", False)
            for result in scan_results
        )

        if not any_validation_enabled:
            # Find the most common reason for no validation
            reasons = [
                result.scan_metadata.get("llm_validation_reason", "unknown")
                for result in scan_results
            ]
            most_common_reason = (
                max(set(reasons), key=reasons.count) if reasons else "unknown"
            )

            return {
                "enabled": False,
                "total_findings_reviewed": 0,
                "legitimate_findings": 0,
                "false_positives_filtered": 0,
                "false_positive_rate": 0.0,
                "average_confidence": 0.0,
                "validation_errors": 0,
                "status": "disabled",
                "reason": most_common_reason,
            }

        # Aggregate validation statistics
        total_reviewed = 0
        legitimate = 0
        false_positives = 0
        confidence_scores = []
        validation_errors = 0

        for result in scan_results:
            if hasattr(result, "validation_results") and result.validation_results:
                for threat_uuid, validation_result in result.validation_results.items():
                    total_reviewed += 1
                    if validation_result.is_legitimate:
                        legitimate += 1
                    else:
                        false_positives += 1
                    if validation_result.confidence is not None:
                        confidence_scores.append(validation_result.confidence)

            # Count validation errors
            validation_errors += result.scan_metadata.get("validation_errors", 0)

        avg_confidence = (
            sum(confidence_scores) / len(confidence_scores)
            if confidence_scores
            else 0.0
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

    def _get_semgrep_summary(
        self, scan_results: list[EnhancedScanResult]
    ) -> dict[str, Any]:
        """Get Semgrep execution summary from scan results.

        Args:
            scan_results: List of enhanced scan results

        Returns:
            Dictionary with Semgrep execution summary
        """
        files_processed = len(
            [
                f
                for f in scan_results
                if f.scan_metadata.get("semgrep_scan_success", False)
            ]
        )

        files_failed = len(
            [
                f
                for f in scan_results
                if not f.scan_metadata.get("semgrep_scan_success", False)
                and f.scan_metadata.get("semgrep_scan_reason")
                not in ["disabled", "not_available"]
            ]
        )

        total_threats = sum(f.stats.get("semgrep_threats", 0) for f in scan_results)

        return {
            "files_processed": files_processed,
            "files_failed": files_failed,
            "total_threats": total_threats,
        }
