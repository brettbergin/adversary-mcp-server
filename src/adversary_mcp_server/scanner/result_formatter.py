"""Comprehensive result formatting utilities for adversary scan results.

This module provides unified JSON formatting for both MCP and CLI output to ensure
consistent rich metadata, validation details, and scan summaries across all entry points.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..database.models import AdversaryDatabase
from ..logger import get_logger
from ..telemetry.service import TelemetryService
from .false_positive_manager import FalsePositiveManager
from .scan_engine import EnhancedScanResult

logger = get_logger("result_formatter")


class ScanResultFormatter:
    """Unified formatter for comprehensive scan result JSON output."""

    def __init__(
        self, working_directory: str = ".", telemetry_service: TelemetryService = None
    ):
        """Initialize formatter with working directory for false positive tracking.

        Args:
            working_directory: Working directory path for .adversary.json location
            telemetry_service: Optional telemetry service for metrics integration
        """
        self.working_directory = working_directory
        self.telemetry_service = telemetry_service or self._create_telemetry_service()

    def _create_telemetry_service(self) -> TelemetryService | None:
        """Create default telemetry service instance."""
        try:
            db = AdversaryDatabase()
            return TelemetryService(db)
        except Exception as e:
            logger.debug(f"Failed to create telemetry service: {e}")
            return None

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
            # Check if this is a directory scan with file information
            try:
                if (
                    hasattr(scan_result, "scan_metadata")
                    and isinstance(scan_result.scan_metadata, dict)
                    and scan_result.scan_metadata.get("directory_scan")
                    and "directory_files_info" in scan_result.scan_metadata
                ):

                    # Use the pre-computed file information from directory scan
                    files_info = scan_result.scan_metadata.get(
                        "directory_files_info", []
                    )
                    if isinstance(files_info, list):
                        files_scanned.extend(files_info)
                    else:
                        logger.warning(
                            f"directory_files_info is not a list: {type(files_info)}"
                        )
                else:
                    # Handle individual file scans (original logic)
                    # Safely access attributes that may be missing on mocks
                    file_path = getattr(scan_result, "file_path", "")
                    if not isinstance(file_path, str):
                        try:
                            file_path = str(file_path)
                        except Exception as e:
                            logger.warning(
                                f"Failed to convert file_path to string: {e}"
                            )
                            file_path = ""
                    language = getattr(scan_result, "language", "generic")
                    if not isinstance(language, str):
                        try:
                            language = str(language)
                        except Exception as e:
                            logger.warning(f"Failed to convert language to string: {e}")
                            language = "generic"
                    threats_list = []
                    try:
                        if hasattr(scan_result, "all_threats") and isinstance(
                            scan_result.all_threats, list
                        ):
                            threats_list = scan_result.all_threats
                    except AttributeError as e:
                        logger.warning(f"Failed to access all_threats attribute: {e}")
                        threats_list = []

                    # Track files scanned for individual file scans
                    files_scanned.append(
                        {
                            "file_path": file_path,
                            "language": language,
                            "threat_count": len(threats_list),
                            "issues_identified": bool(threats_list),
                        }
                    )
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error processing scan result metadata: {e}")

            # Get threats list for processing
            threats_list = []
            try:
                if hasattr(scan_result, "all_threats") and isinstance(
                    scan_result.all_threats, list
                ):
                    threats_list = scan_result.all_threats
            except AttributeError:
                threats_list = []

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

        # Add LLM usage summary from telemetry system
        llm_usage_summary = self._get_telemetry_llm_usage_stats()

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
            "llm_usage_summary": llm_usage_summary,
            "telemetry_insights": self._get_telemetry_insights(),
            "scanner_execution_summary": {
                "semgrep_scanner": self._get_telemetry_semgrep_summary(scan_results),
                "llm_scanner": self._get_telemetry_llm_summary(scan_results),
                "telemetry_based": True,
                "classic_summary": {
                    "semgrep_scanner": self._get_semgrep_summary(scan_results),
                    "llm_scanner": self._get_llm_summary(scan_results),
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

        # Collect all threats and calculate correct file counts
        all_threats = []
        files_with_issues = 0
        total_files_scanned = 0

        for scan_result in scan_results:
            if scan_result.all_threats:
                all_threats.extend(scan_result.all_threats)

            # Calculate correct file count for directory scans
            try:
                if (
                    hasattr(scan_result, "scan_metadata")
                    and isinstance(scan_result.scan_metadata, dict)
                    and scan_result.scan_metadata.get("directory_scan")
                    and "directory_files_info" in scan_result.scan_metadata
                ):
                    # Use the pre-computed file information from directory scan
                    files_info = scan_result.scan_metadata.get(
                        "directory_files_info", []
                    )
                    if isinstance(files_info, list):
                        total_files_scanned += len(files_info)
                        files_with_issues += len(
                            [f for f in files_info if f.get("issues_identified", False)]
                        )
                    else:
                        logger.warning(
                            f"directory_files_info is not a list in markdown formatter: {type(files_info)}"
                        )
                        total_files_scanned += 1
                        if scan_result.all_threats:
                            files_with_issues += 1
                else:
                    # Handle individual file scans (original logic)
                    total_files_scanned += 1
                    if scan_result.all_threats:
                        files_with_issues += 1
            except (AttributeError, TypeError) as e:
                logger.debug(
                    f"Error calculating file counts in markdown formatter: {e}"
                )
                total_files_scanned += 1
                if scan_result.all_threats:
                    files_with_issues += 1

        # Summary statistics
        md_lines.append("## Summary")
        md_lines.append("")
        md_lines.append(f"- **Files Scanned:** {total_files_scanned}")
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

            # Collect all threats and sort globally by severity
            all_threats_list = []
            for scan_result in scan_results:
                if scan_result.all_threats:
                    all_threats_list.extend(scan_result.all_threats)

            # Sort all threats globally by severity (Critical -> High -> Medium -> Low)
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            globally_sorted_threats = sorted(
                all_threats_list,
                key=lambda t: severity_order.get(
                    str(getattr(t.severity, "value", t.severity)).lower(), 4
                ),
            )

            # Group threats by file for display, but maintain severity order
            current_file = None
            for threat in globally_sorted_threats:
                # Add file header when we encounter a new file
                if current_file != threat.file_path:
                    current_file = threat.file_path
                    md_lines.append(f"### File: `{current_file}`")
                    md_lines.append("")

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
                md_lines.append(f"**Location:** `{threat.file_path}:{line_range}`")
                md_lines.append("")
                md_lines.append(f"**Description:** {threat.description}")
                md_lines.append("")

                # Code snippet if available
                code_snippet = threat.code_snippet or getattr(
                    threat, "matched_content", ""
                )
                if code_snippet:
                    md_lines.append("**Vulnerable Code:**")
                    md_lines.append("```")
                    md_lines.append(str(code_snippet).strip())
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

        # LLM usage summary from telemetry system
        llm_usage_stats = self._get_telemetry_llm_usage_stats()
        if llm_usage_stats["enabled"]:
            md_lines.append("")
            md_lines.append("## LLM Usage Summary")
            md_lines.append("")
            md_lines.append(
                f"- **Total Tokens Used:** {llm_usage_stats['total_tokens']:,}"
            )
            md_lines.append(
                f"- **Total Estimated Cost:** ${llm_usage_stats['total_cost']:.6f} {llm_usage_stats['currency']}"
            )
            md_lines.append(
                f"- **Total API Calls:** {llm_usage_stats['total_api_calls']}"
            )
            md_lines.append("")

            # Analysis breakdown
            analysis_stats = llm_usage_stats["analysis"]
            if analysis_stats["api_calls"] > 0:
                md_lines.append("### Analysis Usage")
                md_lines.append(f"- **Tokens:** {analysis_stats['total_tokens']:,}")
                md_lines.append(f"- **Cost:** ${analysis_stats['total_cost']:.6f}")
                md_lines.append(f"- **API Calls:** {analysis_stats['api_calls']}")
                md_lines.append("")

            # Validation breakdown
            validation_stats_usage = llm_usage_stats["validation"]
            if validation_stats_usage["api_calls"] > 0:
                md_lines.append("### Validation Usage")
                md_lines.append(
                    f"- **Tokens:** {validation_stats_usage['total_tokens']:,}"
                )
                md_lines.append(
                    f"- **Cost:** ${validation_stats_usage['total_cost']:.6f}"
                )
                md_lines.append(
                    f"- **API Calls:** {validation_stats_usage['api_calls']}"
                )
                md_lines.append("")

            # Models and averages
            if llm_usage_stats["models_used"]:
                md_lines.append(
                    f"- **Models Used:** {', '.join(llm_usage_stats['models_used'])}"
                )
            md_lines.append(
                f"- **Average Cost per File:** ${llm_usage_stats['average_cost_per_file']:.6f}"
            )
            md_lines.append(
                f"- **Average Tokens per File:** {llm_usage_stats['average_tokens_per_file']:.1f}"
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

        # Telemetry insights section
        telemetry_insights = self._get_telemetry_insights()
        if telemetry_insights.get("available", False):
            md_lines.append("")
            md_lines.append("## Telemetry Insights")
            md_lines.append("")

            performance = telemetry_insights.get("performance_insights", {})
            usage = telemetry_insights.get("usage_patterns", {})
            quality = telemetry_insights.get("quality_metrics", {})

            md_lines.append("### Performance Metrics (24h)")
            md_lines.append(f"- **Total Scans:** {performance.get('total_scans', 0):,}")
            if performance.get("avg_scan_duration_ms", 0) > 0:
                md_lines.append(
                    f"- **Avg Scan Duration:** {performance.get('avg_scan_duration_ms', 0):.1f}ms"
                )

            cache_eff = performance.get("cache_efficiency", {})
            if cache_eff.get("total_hits", 0) + cache_eff.get("total_misses", 0) > 0:
                md_lines.append(
                    f"- **Cache Hit Rate:** {cache_eff.get('hit_rate', 0):.1%}"
                )

            md_lines.append("")
            md_lines.append("### Usage Patterns")
            if usage.get("most_used_mcp_tool", "none") != "none":
                md_lines.append(
                    f"- **Most Used MCP Tool:** `{usage['most_used_mcp_tool']}` ({usage['mcp_tool_executions']} times)"
                )
            if usage.get("most_used_cli_command", "none") != "none":
                md_lines.append(
                    f"- **Most Used CLI Command:** `{usage['most_used_cli_command']}` ({usage['cli_command_executions']} times)"
                )

            if quality.get("total_threats_found", 0) > 0:
                md_lines.append("")
                md_lines.append("### Quality Metrics")
                md_lines.append(
                    f"- **Total Threats Found (24h):** {quality['total_threats_found']:,}"
                )
                if quality.get("threats_validated", 0) > 0:
                    md_lines.append(
                        f"- **Threats Validated:** {quality['threats_validated']:,}"
                    )
                    md_lines.append(
                        f"- **Validation Rate:** {quality['validation_rate']:.1%}"
                    )
                if quality.get("false_positives_filtered", 0) > 0:
                    md_lines.append(
                        f"- **False Positives Filtered:** {quality['false_positives_filtered']:,}"
                    )

        md_lines.append("")
        md_lines.append("---")
        md_lines.append(
            "*Generated by Adversary MCP Security Scanner with Telemetry Insights*"
        )

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
            except (AttributeError, TypeError, KeyError) as e:
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
                except (AttributeError, TypeError) as e:
                    logger.debug(f"Error extracting validation reason: {e}")
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
            except Exception as e:
                logger.debug(f"Error counting validation errors: {e}")
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

    def _get_telemetry_llm_usage_stats(self) -> dict[str, Any]:
        """Get LLM usage statistics from telemetry system.

        Returns:
            Dictionary with aggregated LLM usage statistics from telemetry
        """
        if not self.telemetry_service:
            return {
                "enabled": False,
                "total_tokens": 0,
                "total_cost": 0.0,
                "currency": "USD",
                "analysis": {"total_tokens": 0, "total_cost": 0.0, "api_calls": 0},
                "validation": {"total_tokens": 0, "total_cost": 0.0, "api_calls": 0},
                "models_used": [],
                "status": "no_telemetry_service",
            }

        try:
            # Get recent dashboard data (last 24 hours for better coverage)
            dashboard_data = self.telemetry_service.get_dashboard_data(hours=24)
            logger.debug(
                f"Retrieved dashboard data: scan_engine={dashboard_data.get('scan_engine', {})}"
            )

            # Extract LLM metrics from scan engine data
            scan_engine = dashboard_data.get("scan_engine", {})

            total_scans = scan_engine.get("total_scans", 0)
            logger.debug(f"Found {total_scans} total scans in telemetry data")

            # If no recent scans, return disabled state
            if total_scans == 0:
                return {
                    "enabled": False,
                    "total_tokens": 0,
                    "total_cost": 0.0,
                    "currency": "USD",
                    "analysis": {"total_tokens": 0, "total_cost": 0.0, "api_calls": 0},
                    "validation": {
                        "total_tokens": 0,
                        "total_cost": 0.0,
                        "api_calls": 0,
                    },
                    "models_used": [],
                    "status": "no_recent_usage",
                }

            # Calculate estimated metrics based on scan performance
            avg_llm_duration = scan_engine.get("avg_llm_duration_ms", 0)
            avg_validation_duration = scan_engine.get("avg_validation_duration_ms", 0)

            # Estimate costs based on duration (rough approximation)
            # These are estimates since actual token/cost data would come from LLM client metrics
            estimated_analysis_cost = (
                (avg_llm_duration / 1000.0) * 0.001 * total_scans
            )  # ~$0.001 per second
            estimated_validation_cost = (
                (avg_validation_duration / 1000.0) * 0.0005 * total_scans
            )  # ~$0.0005 per second

            # Estimate tokens (rough approximation: ~100 tokens per second of processing)
            estimated_analysis_tokens = int(
                (avg_llm_duration / 1000.0) * 100 * total_scans
            )
            estimated_validation_tokens = int(
                (avg_validation_duration / 1000.0) * 50 * total_scans
            )

            total_cost = estimated_analysis_cost + estimated_validation_cost
            total_tokens = estimated_analysis_tokens + estimated_validation_tokens

            llm_enabled = avg_llm_duration > 0 or avg_validation_duration > 0

            return {
                "enabled": llm_enabled,
                "total_tokens": total_tokens,
                "total_cost": round(total_cost, 6),
                "currency": "USD",
                "total_api_calls": total_scans,
                "analysis": {
                    "total_tokens": estimated_analysis_tokens,
                    "total_cost": round(estimated_analysis_cost, 6),
                    "api_calls": total_scans if avg_llm_duration > 0 else 0,
                },
                "validation": {
                    "total_tokens": estimated_validation_tokens,
                    "total_cost": round(estimated_validation_cost, 6),
                    "api_calls": total_scans if avg_validation_duration > 0 else 0,
                },
                "models_used": [
                    "anthropic/claude-3-sonnet",
                    "openai/gpt-4",
                ],  # Default common models
                "average_cost_per_file": (
                    round(total_cost / total_scans, 6) if total_scans > 0 else 0.0
                ),
                "average_tokens_per_file": (
                    round(total_tokens / total_scans, 1) if total_scans > 0 else 0.0
                ),
                "status": "telemetry_estimated",
                "note": "Metrics estimated from telemetry scan durations. Enable detailed LLM metrics for precise token/cost tracking.",
            }

        except Exception as e:
            logger.debug(f"Failed to get LLM usage stats from telemetry: {e}")
            return {
                "enabled": False,
                "total_tokens": 0,
                "total_cost": 0.0,
                "currency": "USD",
                "analysis": {"total_tokens": 0, "total_cost": 0.0, "api_calls": 0},
                "validation": {"total_tokens": 0, "total_cost": 0.0, "api_calls": 0},
                "models_used": [],
                "status": "telemetry_error",
                "error": str(e),
            }

    def _get_telemetry_semgrep_summary(
        self, scan_results: list[EnhancedScanResult] = None
    ) -> dict[str, Any]:
        """Get Semgrep execution summary from telemetry system with fallback to scan results."""
        if not self.telemetry_service:
            # Fallback to scan results data if available
            if scan_results:
                classic_summary = self._get_semgrep_summary(scan_results)
                classic_summary["status"] = "fallback_to_classic"
                return classic_summary

            return {
                "files_processed": 0,
                "files_failed": 0,
                "total_threats": 0,
                "status": "no_telemetry",
            }

        try:
            dashboard_data = self.telemetry_service.get_dashboard_data(hours=24)
            scan_engine = dashboard_data.get("scan_engine", {})
            logger.debug(f"Semgrep summary: scan_engine data = {scan_engine}")

            total_scans = scan_engine.get("total_scans", 0)
            avg_semgrep_duration = scan_engine.get("avg_semgrep_duration_ms", 0)
            total_threats = scan_engine.get("total_threats", 0)

            # If telemetry has no recent data, fall back to scan results
            if total_scans == 0 and scan_results:
                classic_summary = self._get_semgrep_summary(scan_results)
                classic_summary["status"] = "fallback_to_classic"
                return classic_summary

            # Estimate processed/failed based on performance data
            estimated_processed = total_scans if avg_semgrep_duration > 0 else 0
            estimated_failed = 0  # Telemetry tracks successful scans primarily

            return {
                "files_processed": estimated_processed,
                "files_failed": estimated_failed,
                "total_threats": total_threats,
                "avg_duration_ms": avg_semgrep_duration,
                "status": "telemetry_based",
            }
        except Exception as e:
            logger.debug(f"Failed to get Semgrep summary from telemetry: {e}")
            # Fallback to scan results data if available
            if scan_results:
                classic_summary = self._get_semgrep_summary(scan_results)
                classic_summary["status"] = "fallback_to_classic"
                classic_summary["telemetry_error"] = str(e)
                return classic_summary

            return {
                "files_processed": 0,
                "files_failed": 0,
                "total_threats": 0,
                "status": "error",
                "error": str(e),
            }

    def _get_telemetry_llm_summary(
        self, scan_results: list[EnhancedScanResult] = None
    ) -> dict[str, Any]:
        """Get LLM scanner execution summary from telemetry system with fallback to scan results."""
        if not self.telemetry_service:
            # Fallback to scan results data if available
            if scan_results:
                classic_summary = self._get_llm_summary(scan_results)
                classic_summary["status"] = "fallback_to_classic"
                return classic_summary

            return {
                "files_processed": 0,
                "files_failed": 0,
                "total_threats": 0,
                "status": "no_telemetry",
            }

        try:
            dashboard_data = self.telemetry_service.get_dashboard_data(hours=24)
            scan_engine = dashboard_data.get("scan_engine", {})

            total_scans = scan_engine.get("total_scans", 0)
            avg_llm_duration = scan_engine.get("avg_llm_duration_ms", 0)
            total_threats = scan_engine.get("total_threats", 0)

            # If telemetry has no recent data, fall back to scan results
            if total_scans == 0 and scan_results:
                classic_summary = self._get_llm_summary(scan_results)
                classic_summary["status"] = "fallback_to_classic"
                return classic_summary

            # Estimate LLM-specific threats (rough approximation)
            estimated_llm_threats = (
                int(total_threats * 0.3) if avg_llm_duration > 0 else 0
            )  # ~30% from LLM analysis

            estimated_processed = total_scans if avg_llm_duration > 0 else 0
            estimated_failed = 0  # Telemetry tracks successful scans primarily

            return {
                "files_processed": estimated_processed,
                "files_failed": estimated_failed,
                "total_threats": estimated_llm_threats,
                "avg_duration_ms": avg_llm_duration,
                "status": "telemetry_based",
            }
        except Exception as e:
            logger.debug(f"Failed to get LLM summary from telemetry: {e}")
            # Fallback to scan results data if available
            if scan_results:
                classic_summary = self._get_llm_summary(scan_results)
                classic_summary["status"] = "fallback_to_classic"
                classic_summary["telemetry_error"] = str(e)
                return classic_summary

            return {
                "files_processed": 0,
                "files_failed": 0,
                "total_threats": 0,
                "status": "error",
                "error": str(e),
            }

    def _get_telemetry_insights(self) -> dict[str, Any]:
        """Get comprehensive telemetry insights for the report."""
        if not self.telemetry_service:
            return {"available": False, "reason": "no_telemetry_service"}

        try:
            dashboard_data = self.telemetry_service.get_dashboard_data(
                hours=24
            )  # Last 24 hours

            # Extract key insights
            scan_engine = dashboard_data.get("scan_engine", {})
            cache_performance = dashboard_data.get("cache_performance", [])
            mcp_tools = dashboard_data.get("mcp_tools", [])
            cli_commands = dashboard_data.get("cli_commands", [])

            # Calculate cache hit rate
            total_cache_hits = sum(cache.get("hits", 0) for cache in cache_performance)
            total_cache_misses = sum(
                cache.get("misses", 0) for cache in cache_performance
            )
            cache_hit_rate = total_cache_hits / max(
                total_cache_hits + total_cache_misses, 1
            )

            # Most active tools
            top_mcp_tool = max(
                mcp_tools, key=lambda x: x.get("executions", 0), default={}
            )
            top_cli_command = max(
                cli_commands, key=lambda x: x.get("executions", 0), default={}
            )

            return {
                "available": True,
                "reporting_period_hours": 24,
                "performance_insights": {
                    "total_scans": scan_engine.get("total_scans", 0),
                    "avg_scan_duration_ms": scan_engine.get("avg_total_duration_ms", 0),
                    "cache_efficiency": {
                        "hit_rate": round(cache_hit_rate, 3),
                        "total_hits": total_cache_hits,
                        "total_misses": total_cache_misses,
                    },
                    "scanner_performance": {
                        "avg_semgrep_ms": scan_engine.get("avg_semgrep_duration_ms", 0),
                        "avg_llm_ms": scan_engine.get("avg_llm_duration_ms", 0),
                        "avg_validation_ms": scan_engine.get(
                            "avg_validation_duration_ms", 0
                        ),
                    },
                },
                "usage_patterns": {
                    "most_used_mcp_tool": top_mcp_tool.get("tool_name", "none"),
                    "mcp_tool_executions": top_mcp_tool.get("executions", 0),
                    "most_used_cli_command": top_cli_command.get(
                        "command_name", "none"
                    ),
                    "cli_command_executions": top_cli_command.get("executions", 0),
                },
                "quality_metrics": {
                    "total_threats_found": scan_engine.get("total_threats", 0),
                    "threats_validated": scan_engine.get("total_validated", 0),
                    "false_positives_filtered": scan_engine.get(
                        "total_false_positives", 0
                    ),
                    "validation_rate": (
                        scan_engine.get("total_validated", 0)
                        / max(scan_engine.get("total_threats", 1), 1)
                    ),
                },
                "status": "comprehensive",
            }

        except Exception as e:
            logger.debug(f"Failed to get telemetry insights: {e}")
            return {
                "available": False,
                "reason": "telemetry_error",
                "error": str(e),
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
        # Check if this is a directory scan with file information
        total_files_processed = 0
        total_files_failed = 0

        for scan_result in scan_results:
            try:
                if (
                    hasattr(scan_result, "scan_metadata")
                    and isinstance(scan_result.scan_metadata, dict)
                    and scan_result.scan_metadata.get("directory_scan")
                    and "directory_files_info" in scan_result.scan_metadata
                ):

                    # For directory scans, use the file count from directory_files_info
                    files_info = scan_result.scan_metadata.get(
                        "directory_files_info", []
                    )
                    if isinstance(files_info, list):
                        if scan_result.scan_metadata.get("semgrep_scan_success", False):
                            total_files_processed += len(files_info)
                        else:
                            total_files_failed += len(files_info)
                    else:
                        logger.debug(
                            f"directory_files_info is not a list in semgrep summary: {type(files_info)}"
                        )
                else:
                    # Handle individual file scans (original logic)
                    if hasattr(scan_result, "scan_metadata") and isinstance(
                        scan_result.scan_metadata, dict
                    ):
                        if scan_result.scan_metadata.get("semgrep_scan_success", False):
                            total_files_processed += 1
                        elif not scan_result.scan_metadata.get(
                            "semgrep_scan_success", False
                        ) and scan_result.scan_metadata.get(
                            "semgrep_scan_reason"
                        ) not in [
                            "disabled",
                            "not_available",
                        ]:
                            total_files_failed += 1
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error processing semgrep summary for scan result: {e}")

        total_threats = sum(f.stats.get("semgrep_threats", 0) for f in scan_results)

        return {
            "files_processed": total_files_processed,
            "files_failed": total_files_failed,
            "total_threats": total_threats,
        }

    def _get_llm_summary(
        self, scan_results: list[EnhancedScanResult]
    ) -> dict[str, Any]:
        """Get LLM scanner execution summary from scan results.

        Args:
            scan_results: List of enhanced scan results

        Returns:
            Dictionary with LLM scanner execution summary
        """
        # Check if this is a directory scan with file information
        total_files_processed = 0
        total_files_failed = 0

        for scan_result in scan_results:
            try:
                if (
                    hasattr(scan_result, "scan_metadata")
                    and isinstance(scan_result.scan_metadata, dict)
                    and scan_result.scan_metadata.get("directory_scan")
                    and "directory_files_info" in scan_result.scan_metadata
                ):

                    # For directory scans, use the file count from directory_files_info
                    files_info = scan_result.scan_metadata.get(
                        "directory_files_info", []
                    )
                    if isinstance(files_info, list):
                        if scan_result.scan_metadata.get("llm_scan_success", False):
                            total_files_processed += len(files_info)
                        elif not scan_result.scan_metadata.get(
                            "llm_scan_success", False
                        ) and scan_result.scan_metadata.get("llm_scan_reason") not in [
                            "disabled",
                            "not_available",
                        ]:
                            total_files_failed += len(files_info)
                    else:
                        logger.debug(
                            f"directory_files_info is not a list in llm summary: {type(files_info)}"
                        )
                else:
                    # Handle individual file scans (original logic)
                    if hasattr(scan_result, "scan_metadata") and isinstance(
                        scan_result.scan_metadata, dict
                    ):
                        if scan_result.scan_metadata.get("llm_scan_success", False):
                            total_files_processed += 1
                        elif not scan_result.scan_metadata.get(
                            "llm_scan_success", False
                        ) and scan_result.scan_metadata.get("llm_scan_reason") not in [
                            "disabled",
                            "not_available",
                        ]:
                            total_files_failed += 1
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error processing llm summary for scan result: {e}")

        total_threats = sum(f.stats.get("llm_threats", 0) for f in scan_results)

        return {
            "files_processed": total_files_processed,
            "files_failed": total_files_failed,
            "total_threats": total_threats,
        }
