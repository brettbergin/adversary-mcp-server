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
            # Safely access attributes that may be missing on mocks
            file_path = getattr(scan_result, "file_path", "")
            if not isinstance(file_path, str):
                try:
                    file_path = str(file_path)
                except Exception:
                    file_path = ""
            language = getattr(scan_result, "language", "generic")
            if not isinstance(language, str):
                try:
                    language = str(language)
                except Exception:
                    language = "generic"
            threats_list = []
            try:
                if hasattr(scan_result, "all_threats") and isinstance(
                    scan_result.all_threats, list
                ):
                    threats_list = scan_result.all_threats
            except Exception:
                threats_list = []

            # Track files scanned
            files_scanned.append(
                {
                    "file_path": file_path,
                    "language": language,
                    "threat_count": len(threats_list),
                    "issues_identified": bool(threats_list),
                }
            )

            # Process each threat with full metadata
            for threat in threats_list:
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

                # Get validation details for this specific threat (robust to mocks)
                validation_map = getattr(scan_result, "validation_results", None)
                if isinstance(validation_map, dict):
                    validation_result = validation_map.get(threat.uuid)
                else:
                    validation_result = None

                # Ignore non-ValidationResult objects (e.g., mocks)
                if (
                    validation_result is not None
                    and validation_result.__class__.__name__ != "ValidationResult"
                ):
                    validation_result = None
                validation_data = {
                    "was_validated": bool(validation_result),
                    "validation_confidence": (
                        float(getattr(validation_result, "confidence", 0.0))
                        if (
                            validation_result
                            and isinstance(
                                getattr(validation_result, "confidence", None),
                                int | float,
                            )
                        )
                        else None
                    ),
                    "validation_reasoning": (
                        str(getattr(validation_result, "reasoning", ""))
                        if (
                            validation_result
                            and isinstance(
                                getattr(validation_result, "reasoning", None), str
                            )
                        )
                        else None
                    ),
                    "validation_status": (
                        "legitimate"
                        if (getattr(validation_result, "is_legitimate", False))
                        else (
                            "false_positive"
                            if validation_result is not None
                            and not getattr(validation_result, "is_legitimate", True)
                            else "not_validated"
                        )
                    ),
                    "exploitation_vector": (
                        str(getattr(validation_result, "exploitation_vector", ""))
                        if (
                            validation_result
                            and isinstance(
                                getattr(validation_result, "exploitation_vector", None),
                                str,
                            )
                        )
                        else None
                    ),
                    "remediation_advice": (
                        str(getattr(validation_result, "remediation_advice", ""))
                        if (
                            validation_result
                            and isinstance(
                                getattr(validation_result, "remediation_advice", None),
                                str,
                            )
                        )
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

    def format_single_file_results_markdown(
        self,
        scan_result: EnhancedScanResult,
        scan_target: str,
    ) -> str:
        """Format single file scan results as markdown.

        Args:
            scan_result: Enhanced scan result for a single file
            scan_target: Target file that was scanned

        Returns:
            Markdown formatted scan results
        """
        logger.debug("Formatting single file scan result as markdown")
        return self.format_directory_results_markdown(
            [scan_result], scan_target, scan_type="file"
        )

    def format_directory_results_markdown(
        self,
        scan_results: list[EnhancedScanResult],
        scan_target: str,
        scan_type: str = "directory",
    ) -> str:
        """Format directory scan results as markdown.

        Args:
            scan_results: List of enhanced scan results
            scan_target: Target directory/file that was scanned
            scan_type: Type of scan performed (directory, file, diff)

        Returns:
            Markdown formatted scan results
        """
        logger.debug(f"Formatting {len(scan_results)} scan results as markdown")

        # Build markdown content
        md_lines = []
        md_lines.append("# Adversary Security Scan Report")
        md_lines.append(f"\n**Scan Target:** `{scan_target}`")
        md_lines.append(f"**Scan Type:** {scan_type}")
        md_lines.append(
            f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        md_lines.append("")

        # Collect all threats
        all_threats = []
        files_with_issues = 0

        for scan_result in scan_results:
            if scan_result.all_threats:
                files_with_issues += 1
                all_threats.extend(scan_result.all_threats)

        # Summary statistics
        md_lines.append("## Summary")
        md_lines.append("")
        md_lines.append(f"- **Files Scanned:** {len(scan_results)}")
        md_lines.append(f"- **Files with Issues:** {files_with_issues}")
        md_lines.append(f"- **Total Threats Found:** {len(all_threats)}")

        # Count by severity (robust to lowercase enum values)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for threat in all_threats:
            sev_val = str(getattr(threat.severity, "value", threat.severity)).lower()
            if sev_val in severity_counts:
                severity_counts[sev_val] += 1

        md_lines.append("")
        md_lines.append("### Threat Breakdown by Severity")
        md_lines.append("")
        md_lines.append("| Severity | Count |")
        md_lines.append("|----------|-------|")
        for severity, count in severity_counts.items():
            if count > 0:
                md_lines.append(f"| {severity.upper()} | {count} |")

        # Detailed findings
        if all_threats:
            md_lines.append("")
            md_lines.append("## Detailed Findings")
            md_lines.append("")

            # Group threats by file
            threats_by_file = {}
            for scan_result in scan_results:
                if scan_result.all_threats:
                    threats_by_file[scan_result.file_path] = scan_result.all_threats

            for file_path, threats in threats_by_file.items():
                md_lines.append(f"### File: `{file_path}`")
                md_lines.append("")

                for threat in threats:
                    # Threat header
                    sev_val = str(
                        getattr(threat.severity, "value", threat.severity)
                    ).lower()
                    severity_emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🔵",
                    }.get(sev_val, "⚪")

                    md_lines.append(
                        f"#### {severity_emoji} {sev_val.upper()}: {threat.rule_name}"
                    )
                    md_lines.append("")
                    end_line = getattr(threat, "end_line_number", threat.line_number)
                    line_range = f"{threat.line_number}" + (
                        f"-{end_line}" if end_line != threat.line_number else ""
                    )
                    md_lines.append(f"**Location:** `{file_path}:{line_range}`")
                    md_lines.append(f"**Description:** {threat.description}")
                    md_lines.append("")

                    # Code snippet if available
                    matched_content = getattr(threat, "matched_content", "")
                    if matched_content:
                        md_lines.append("**Vulnerable Code:**")
                        md_lines.append("```")
                        md_lines.append(str(matched_content).strip())
                        md_lines.append("```")
                        md_lines.append("")

                    # Remediation if available
                    if threat.remediation:
                        md_lines.append("**Remediation:**")
                        md_lines.append(threat.remediation)
                        md_lines.append("")

                    md_lines.append("---")
                    md_lines.append("")

        else:
            md_lines.append("")
            md_lines.append("## ✅ No Security Threats Detected")
            md_lines.append("")
            md_lines.append(
                "The scan completed successfully with no security vulnerabilities found."
            )

        # Validation summary if available
        validation_stats = self._aggregate_validation_stats(scan_results)
        if validation_stats["enabled"]:
            md_lines.append("")
            md_lines.append("## Validation Summary")
            md_lines.append("")
            md_lines.append(
                f"- **Findings Reviewed:** {validation_stats['total_findings_reviewed']}"
            )
            md_lines.append(
                f"- **Legitimate Findings:** {validation_stats['legitimate_findings']}"
            )
            md_lines.append(
                f"- **False Positives Filtered:** {validation_stats['false_positives_filtered']}"
            )
            if validation_stats["total_findings_reviewed"] > 0:
                md_lines.append(
                    f"- **False Positive Rate:** {validation_stats['false_positive_rate']:.1%}"
                )
                md_lines.append(
                    f"- **Average Confidence:** {validation_stats['average_confidence']:.1%}"
                )

        md_lines.append("")
        md_lines.append("---")
        md_lines.append("*Generated by Adversary MCP Security Scanner*")

        return "\n".join(md_lines)

    def format_diff_results_markdown(
        self,
        scan_results: dict[str, list[EnhancedScanResult]],
        diff_summary: dict[str, Any],
        scan_target: str,
    ) -> str:
        """Format git diff scan results as markdown.

        Args:
            scan_results: Dictionary mapping file paths to lists of scan results
            diff_summary: Summary of git diff information
            scan_target: Target description (e.g., "main...feature-branch")

        Returns:
            Markdown formatted diff scan results
        """
        logger.debug(
            f"Formatting diff scan results for {len(scan_results)} files as markdown"
        )

        # Flatten scan results into a single list
        flattened_results = []
        for file_path, file_scan_results in scan_results.items():
            flattened_results.extend(file_scan_results)

        # Start with base markdown
        md_content = self.format_directory_results_markdown(
            flattened_results, scan_target, scan_type="diff"
        )

        # Add diff-specific information
        md_lines = md_content.split("\n")

        # Find where to insert diff summary (after scan type)
        for i, line in enumerate(md_lines):
            if line.startswith("**Scan Date:**"):
                # Insert diff summary after scan date
                diff_info = []
                diff_info.append("")
                diff_info.append("### Git Diff Information")
                diff_info.append(f"- **Files Changed:** {len(scan_results)}")
                if diff_summary:
                    if "source_branch" in diff_summary:
                        diff_info.append(
                            f"- **Source Branch:** `{diff_summary['source_branch']}`"
                        )
                    if "target_branch" in diff_summary:
                        diff_info.append(
                            f"- **Target Branch:** `{diff_summary['target_branch']}`"
                        )
                md_lines[i + 1 : i + 1] = diff_info
                break

        return "\n".join(md_lines)

    def format_code_results_markdown(
        self,
        scan_result: EnhancedScanResult,
        scan_target: str = "code",
    ) -> str:
        """Format code scan results as markdown.

        Args:
            scan_result: Enhanced scan result for code
            scan_target: Description of scanned code

        Returns:
            Markdown formatted scan results
        """
        logger.debug("Formatting code scan result as markdown")
        return self.format_single_file_results_markdown(scan_result, scan_target)

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
        any_validation_enabled = False
        for result in scan_results:
            try:
                scan_md = getattr(result, "scan_metadata", {})
                if isinstance(scan_md, dict) and scan_md.get(
                    "llm_validation_success", False
                ):
                    any_validation_enabled = True
                    break
            except Exception as e:
                logger.debug(f"Error checking validation status for scan result: {e}")
                continue

        if not any_validation_enabled:
            # Find the most common reason for no validation
            reasons = []
            for result in scan_results:
                try:
                    scan_md = getattr(result, "scan_metadata", {})
                    if isinstance(scan_md, dict):
                        reasons.append(scan_md.get("llm_validation_reason", "unknown"))
                    else:
                        reasons.append("unknown")
                except Exception:
                    reasons.append("unknown")
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
                valres = getattr(result, "validation_results", None)
                if isinstance(valres, dict):
                    items_iter = valres.items()
                else:
                    items_iter = []
                for threat_uuid, validation_result in items_iter:
                    total_reviewed += 1
                    if getattr(validation_result, "is_legitimate", False):
                        legitimate += 1
                    else:
                        false_positives += 1
                    confidence_val = getattr(validation_result, "confidence", None)
                    if confidence_val is not None:
                        confidence_scores.append(confidence_val)

            # Count validation errors
            try:
                validation_errors += int(
                    result.scan_metadata.get("validation_errors", 0)
                )
            except Exception:
                pass

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
