"""Result formatter for domain ScanResult objects with Clean Architecture."""

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class DomainScanResultFormatter:
    """
    Clean Architecture result formatter that works with domain objects.

    This formatter replaces the legacy ScanResultFormatter with a clean implementation
    that operates on domain entities and value objects.
    """

    def __init__(self, include_metadata: bool = True, include_exploits: bool = False):
        """
        Initialize the domain result formatter.

        Args:
            include_metadata: Whether to include detailed metadata
            include_exploits: Whether to include exploit examples (security consideration)
        """
        self.include_metadata = include_metadata
        self.include_exploits = include_exploits

    def format_json(self, result: ScanResult) -> str:
        """Format scan result as JSON string with proper control character handling."""
        formatted_data = self.format_dict(result)
        return json.dumps(
            formatted_data,
            indent=2,
            ensure_ascii=False,
            separators=(",", ": "),
            default=self._json_serializer,
        )

    def _json_serializer(self, obj):
        """Custom JSON serializer with explicit handling for domain objects."""
        # Handle domain objects with to_dict methods
        if hasattr(obj, "to_dict") and callable(obj.to_dict):
            return obj.to_dict()

        # Handle datetime objects
        elif isinstance(obj, datetime | date):
            return obj.isoformat()

        # Handle Path objects
        elif isinstance(obj, Path | type(Path())):
            return str(obj)

        # Handle domain value objects with string representation
        elif hasattr(obj, "__str__"):
            text = str(obj)
            # Sanitize control characters that break JSON
            return self._sanitize_for_json(text)

        else:
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def _sanitize_for_json(self, text: str) -> str:
        """Remove control characters that break JSON parsing."""
        if not isinstance(text, str):
            return str(text)

        # Remove problematic control characters using built-in string methods
        # Keep normal whitespace (\t, \n, \r) which json.dumps handles properly
        result = []
        for char in text:
            char_code = ord(char)
            # Allow normal chars (32+), and common whitespace (9, 10, 13)
            if char_code >= 32 or char_code in (9, 10, 13):
                result.append(char)
            # Skip other control characters (0-8, 11, 12, 14-31)

        return "".join(result)

    def format_dict(self, result: ScanResult) -> dict[str, Any]:
        """Format scan result as dictionary."""
        return {
            "scan_metadata": self._format_scan_metadata(result),
            "summary": self._format_summary(result),
            "statistics": self._format_statistics(result),
            "threats": self._format_threats(result.threats),
            "validation_info": self._format_validation_info(result),
            "scanner_execution_summary": self._format_scanner_execution_summary(result),
        }

    def format_markdown(self, result: ScanResult) -> str:
        """Format scan result as Markdown."""
        lines = []

        # Header
        lines.append("# Security Scan Report")
        lines.append("")

        # Scan metadata
        metadata = result.request.context.metadata
        lines.append("## Scan Information")
        lines.append(f"- **Scan ID**: {metadata.scan_id}")
        lines.append(f"- **Target**: {result.request.context.target_path}")
        lines.append(f"- **Type**: {metadata.scan_type}")
        lines.append(f"- **Timestamp**: {metadata.timestamp.isoformat()}")
        lines.append(f"- **Requester**: {metadata.requester}")
        lines.append("")

        # Summary
        stats = result.get_statistics()
        lines.append("## Summary")
        lines.append(f"- **Total Threats**: {stats['total_threats']}")
        lines.append(f"- **Critical**: {stats['by_severity'].get('critical', 0)}")
        lines.append(f"- **High**: {stats['by_severity'].get('high', 0)}")
        lines.append(f"- **Medium**: {stats['by_severity'].get('medium', 0)}")
        lines.append(f"- **Low**: {stats['by_severity'].get('low', 0)}")
        lines.append("")

        # Threats
        if result.threats:
            lines.append("## Threats Found")
            lines.append("")

            for i, threat in enumerate(result.threats, 1):
                lines.append(f"### {i}. {threat.rule_name}")
                lines.append(f"- **Severity**: {threat.severity}")
                lines.append(f"- **Category**: {threat.category}")
                lines.append(
                    f"- **Confidence**: {threat.confidence.get_percentage():.1f}%"
                )
                lines.append(f"- **File**: {threat.file_path}:{threat.line_number}")
                lines.append(f"- **Description**: {threat.description}")

                if threat.code_snippet:
                    lines.append("- **Code**:")
                    lines.append("```")
                    lines.append(threat.code_snippet)
                    lines.append("```")

                if hasattr(threat, "remediation_advice"):
                    lines.append("- **Remediation**:")
                    for advice in threat.remediation_advice:
                        lines.append(f"  - {advice}")

                lines.append("")
        else:
            lines.append("## No Threats Found")
            lines.append("No security vulnerabilities were detected in this scan.")
            lines.append("")

        return "\n".join(lines)

    def format_csv(self, result: ScanResult) -> str:
        """Format scan result as CSV."""
        lines = []

        # Header
        header = [
            "rule_id",
            "rule_name",
            "severity",
            "category",
            "confidence",
            "file_path",
            "line_number",
            "column_number",
            "description",
            "source_scanner",
            "is_false_positive",
        ]
        lines.append(",".join(header))

        # Threats
        for threat in result.threats:
            row = [
                self._escape_csv(threat.rule_id),
                self._escape_csv(threat.rule_name),
                str(threat.severity),
                self._escape_csv(threat.category),
                f"{threat.confidence.get_percentage():.1f}%",
                self._escape_csv(str(threat.file_path)),
                str(threat.line_number),
                str(threat.column_number),
                self._escape_csv(threat.description),
                self._escape_csv(threat.source_scanner),
                str(threat.is_false_positive),
            ]
            lines.append(",".join(row))

        return "\n".join(lines)

    def _format_scan_metadata(self, result: ScanResult) -> dict[str, Any]:
        """Format scan metadata."""
        metadata = result.request.context.metadata

        base_metadata = {
            "scan_id": metadata.scan_id,
            "scan_type": metadata.scan_type,
            "timestamp": metadata.timestamp.isoformat(),
            "requester": metadata.requester,
            "target_path": str(result.request.context.target_path),
            "language": result.request.context.language,
            "scanners_enabled": {
                "semgrep": result.request.enable_semgrep,
                "llm": result.request.enable_llm,
                "validation": result.request.enable_validation,
            },
            "scanners_used": result.get_active_scanners(),
            "severity_threshold": (
                str(result.request.severity_threshold)
                if result.request.severity_threshold
                else None
            ),
        }

        if self.include_metadata:
            base_metadata.update(
                {
                    "timeout_seconds": (
                        str(metadata.timeout_seconds)
                        if metadata.timeout_seconds
                        else None
                    ),
                    "project_name": metadata.project_name,
                    "additional_metadata": result.scan_metadata,
                }
            )

        return base_metadata

    def _format_summary(self, result: ScanResult) -> dict[str, Any]:
        """Format scan summary."""
        return {
            "total_threats": len(result.threats),
            "threat_count_by_severity": {
                severity: len(
                    result.get_threats_by_severity(SeverityLevel.from_string(severity))
                )
                for severity in ["critical", "high", "medium", "low"]
            },
            "threat_categories": list(result.get_threat_categories()),
            "has_critical_threats": result.has_critical_threats(),
            "is_empty": result.is_empty(),
            "high_confidence_threats": len(
                result.filter_by_confidence(ConfidenceScore(0.8)).threats
            ),
            "validated_threats": len(
                [t for t in result.threats if "validation" in t.source_scanner]
            ),
        }

    def _format_statistics(self, result: ScanResult) -> dict[str, Any]:
        """Format detailed statistics."""
        stats = result.get_statistics()

        # Add scanner-specific statistics
        scanner_stats = {}
        for scanner in result.get_active_scanners():
            scanner_threats = [t for t in result.threats if t.source_scanner == scanner]
            scanner_stats[scanner] = {
                "threats_found": len(scanner_threats),
                "avg_confidence": (
                    sum(t.confidence.get_decimal() for t in scanner_threats)
                    / len(scanner_threats)
                    if scanner_threats
                    else 0.0
                ),
            }

        stats["by_scanner"] = scanner_stats
        return stats

    def _format_threats(self, threats: list[ThreatMatch]) -> list[dict[str, Any]]:
        """Format list of threats."""
        formatted_threats = []

        for threat in threats:
            threat_data = {
                "uuid": threat.uuid,  # Required for false positive tracking
                "rule_id": self._sanitize_for_json(threat.rule_id),
                "rule_name": self._sanitize_for_json(threat.rule_name),
                "description": self._sanitize_for_json(threat.description),
                "category": self._sanitize_for_json(threat.category),
                "severity": str(threat.severity),
                "confidence": {
                    "score": threat.confidence.get_decimal(),
                    "percentage": threat.confidence.get_percentage(),
                    "level": threat.confidence.get_quality_level(),
                },
                "location": {
                    "file_path": str(threat.file_path),
                    "line_number": threat.line_number,
                    "column_number": threat.column_number,
                },
                "code_snippet": self._sanitize_for_json(threat.code_snippet),
                "source_scanner": self._sanitize_for_json(threat.source_scanner),
                "fingerprint": self._sanitize_for_json(threat.get_fingerprint()),
                "is_false_positive": threat.is_false_positive,
            }

            # Domain ThreatMatch doesn't have false_positive_reason
            # if threat.false_positive_reason:
            #     threat_data["false_positive_reason"] = threat.false_positive_reason

            if threat.remediation:
                threat_data["remediation_advice"] = self._sanitize_for_json(
                    threat.remediation
                )

            if self.include_exploits and threat.exploit_examples:
                threat_data["exploit_examples"] = threat.exploit_examples

            if self.include_metadata:
                threat_data["metadata"] = (
                    {}
                )  # Domain ThreatMatch doesn't have metadata field

            formatted_threats.append(threat_data)

        return formatted_threats

    def _format_validation_info(self, result: ScanResult) -> dict[str, Any] | None:
        """Format validation information if available."""
        validated_threats = [
            t for t in result.threats if "validation" in t.source_scanner
        ]

        if not validated_threats:
            return None

        false_positives = [t for t in validated_threats if t.is_false_positive]

        return {
            "validation_enabled": result.request.enable_validation,
            "total_threats_validated": len(validated_threats),
            "false_positives_detected": len(false_positives),
            "false_positive_rate": (
                len(false_positives) / len(validated_threats)
                if validated_threats
                else 0
            ),
            "average_validation_confidence": (
                sum(t.confidence.get_decimal() for t in validated_threats)
                / len(validated_threats)
                if validated_threats
                else 0.0
            ),
        }

    def _format_scanner_execution_summary(self, result: ScanResult) -> dict[str, Any]:
        """Format scanner execution summary."""
        active_scanners = result.get_active_scanners()

        summary = {"total_scanners_used": len(active_scanners), "scanners": {}}

        for scanner in active_scanners:
            scanner_threats = [t for t in result.threats if t.source_scanner == scanner]
            summary["scanners"][scanner] = {
                "status": "completed",
                "threats_found": len(scanner_threats),
                "execution_time_ms": result.scan_metadata.get(
                    f"{scanner}_duration_ms", 0
                ),
            }

        return summary

    def _escape_csv(self, value: str) -> str:
        """Escape value for CSV format."""
        if '"' in value or "," in value or "\n" in value:
            return f'"{value.replace('"', '""')}"'
        return value
