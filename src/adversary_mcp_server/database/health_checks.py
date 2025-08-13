"""Database health checks and automated validation system."""

import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from .models import (
    AdversaryDatabase,
    CacheOperationMetric,
    CLICommandExecution,
    MCPToolExecution,
    ScanEngineExecution,
    SystemHealth,
    ThreatFinding,
)

logger = logging.getLogger(__name__)


class DatabaseHealthChecker:
    """Automated database health checks and validation system."""

    def __init__(self, db: AdversaryDatabase):
        self.db = db

    def run_comprehensive_health_check(self) -> dict[str, Any]:
        """Run all health checks and return comprehensive results.

        Returns:
            Dict with health check results, issues found, and recommendations
        """
        logger.info("Starting comprehensive database health check")

        health_results = {
            "timestamp": time.time(),
            "datetime": datetime.now(UTC).isoformat(),
            "overall_health": "unknown",
            "total_issues": 0,
            "critical_issues": 0,
            "warning_issues": 0,
            "info_issues": 0,
            "checks": {},
            "recommendations": [],
        }

        with self.db.get_session() as session:
            try:
                # Data consistency checks
                health_results["checks"]["data_consistency"] = (
                    self._check_data_consistency(session)
                )

                # Database performance checks
                health_results["checks"]["performance"] = (
                    self._check_database_performance(session)
                )

                # Table integrity checks
                health_results["checks"]["table_integrity"] = (
                    self._check_table_integrity(session)
                )

                # Data volume checks
                health_results["checks"]["data_volume"] = self._check_data_volume(
                    session
                )

                # Cache health checks
                health_results["checks"]["cache_health"] = self._check_cache_health(
                    session
                )

                # Orphaned records checks
                health_results["checks"]["orphaned_records"] = (
                    self._check_orphaned_records(session)
                )

                # Calculate overall health metrics
                self._calculate_overall_health(health_results)

                logger.info(
                    f"Health check completed: {health_results['overall_health']} - {health_results['total_issues']} issues found"
                )
                return health_results

            except Exception as e:
                logger.error(f"Health check failed: {e}")
                health_results["overall_health"] = "critical"
                health_results["error"] = str(e)
                health_results["critical_issues"] = 1
                health_results["total_issues"] = 1
                return health_results

    def _check_data_consistency(self, session: Session) -> dict[str, Any]:
        """Check data consistency between summary fields and detail records."""
        logger.debug("Checking data consistency")

        issues = []

        # Check MCP tool execution consistency
        mcp_inconsistent = (
            session.query(func.count(MCPToolExecution.id))
            .filter(
                MCPToolExecution.findings_count
                != session.query(func.coalesce(func.count(ThreatFinding.id), 0))
                .select_from(ScanEngineExecution)
                .outerjoin(
                    ThreatFinding, ScanEngineExecution.scan_id == ThreatFinding.scan_id
                )
                .filter(ScanEngineExecution.scan_id == MCPToolExecution.session_id)
                .scalar_subquery()
            )
            .scalar()
        )

        if mcp_inconsistent > 0:
            issues.append(
                {
                    "severity": "warning",
                    "type": "data_consistency",
                    "table": "MCPToolExecution",
                    "description": f"{mcp_inconsistent} MCP tool executions have inconsistent findings_count",
                    "recommendation": "Run 'adversary-mcp-cli migrate-data' to fix inconsistencies",
                }
            )

        # Check scan engine execution consistency
        scan_inconsistent = (
            session.query(func.count(ScanEngineExecution.id))
            .filter(
                ScanEngineExecution.threats_found
                != session.query(func.coalesce(func.count(ThreatFinding.id), 0))
                .filter(ThreatFinding.scan_id == ScanEngineExecution.scan_id)
                .scalar_subquery()
            )
            .scalar()
        )

        if scan_inconsistent > 0:
            issues.append(
                {
                    "severity": "critical",
                    "type": "data_consistency",
                    "table": "ScanEngineExecution",
                    "description": f"{scan_inconsistent} scan executions have inconsistent threats_found counts",
                    "recommendation": "Run 'adversary-mcp-cli migrate-data' immediately to fix critical inconsistencies",
                }
            )

        # Check for negative counts (data corruption indicator)
        negative_findings = (
            session.query(func.count())
            .filter(func.coalesce(MCPToolExecution.findings_count, 0) < 0)
            .scalar()
        )

        negative_threats = (
            session.query(func.count())
            .filter(func.coalesce(ScanEngineExecution.threats_found, 0) < 0)
            .scalar()
        )

        if negative_findings > 0 or negative_threats > 0:
            issues.append(
                {
                    "severity": "critical",
                    "type": "data_corruption",
                    "description": f"Found negative counts: {negative_findings} findings, {negative_threats} threats",
                    "recommendation": "Investigate data corruption and run migration to fix",
                }
            )

        return {
            "status": (
                "healthy"
                if not issues
                else (
                    "warning"
                    if all(i["severity"] != "critical" for i in issues)
                    else "critical"
                )
            ),
            "issues_found": len(issues),
            "issues": issues,
        }

    def _check_database_performance(self, session: Session) -> dict[str, Any]:
        """Check database performance metrics and potential bottlenecks."""
        logger.debug("Checking database performance")

        issues = []
        metrics = {}

        try:
            # Check database file size
            if self.db.db_path.exists():
                db_size_mb = self.db.db_path.stat().st_size / (1024 * 1024)
                metrics["db_size_mb"] = db_size_mb

                if db_size_mb > 1000:  # 1GB
                    issues.append(
                        {
                            "severity": "warning",
                            "type": "database_size",
                            "description": f"Database size is large: {db_size_mb:.1f}MB",
                            "recommendation": "Consider archiving old data or optimizing database",
                        }
                    )

            # Check for slow queries (approximate by checking record counts)
            total_threat_findings = session.query(func.count(ThreatFinding.id)).scalar()
            metrics["total_threat_findings"] = total_threat_findings

            if total_threat_findings > 100000:  # 100k records
                issues.append(
                    {
                        "severity": "info",
                        "type": "large_dataset",
                        "description": f"Large threat findings dataset: {total_threat_findings:,} records",
                        "recommendation": "Monitor query performance and consider indexing optimization",
                    }
                )

            # Check for unfinished executions (potential hanging operations)
            unfinished_mcp = (
                session.query(func.count(MCPToolExecution.id))
                .filter(MCPToolExecution.execution_end.is_(None))
                .scalar()
            )

            unfinished_cli = (
                session.query(func.count(CLICommandExecution.id))
                .filter(CLICommandExecution.execution_end.is_(None))
                .scalar()
            )

            unfinished_scans = (
                session.query(func.count(ScanEngineExecution.id))
                .filter(ScanEngineExecution.execution_end.is_(None))
                .scalar()
            )

            metrics.update(
                {
                    "unfinished_mcp_executions": unfinished_mcp,
                    "unfinished_cli_executions": unfinished_cli,
                    "unfinished_scan_executions": unfinished_scans,
                }
            )

            total_unfinished = unfinished_mcp + unfinished_cli + unfinished_scans
            if total_unfinished > 10:
                issues.append(
                    {
                        "severity": "warning",
                        "type": "unfinished_operations",
                        "description": f"Many unfinished operations: {total_unfinished} (MCP: {unfinished_mcp}, CLI: {unfinished_cli}, Scans: {unfinished_scans})",
                        "recommendation": "Investigate hanging operations and consider cleanup",
                    }
                )

        except Exception as e:
            issues.append(
                {
                    "severity": "critical",
                    "type": "performance_check_failed",
                    "description": f"Performance check failed: {str(e)}",
                    "recommendation": "Investigate database connectivity and integrity",
                }
            )

        return {
            "status": (
                "healthy"
                if not issues
                else (
                    "warning"
                    if all(i["severity"] != "critical" for i in issues)
                    else "critical"
                )
            ),
            "issues_found": len(issues),
            "issues": issues,
            "metrics": metrics,
        }

    def _check_table_integrity(self, session: Session) -> dict[str, Any]:
        """Check table integrity and foreign key constraints."""
        logger.debug("Checking table integrity")

        issues = []

        try:
            # Check for orphaned threat findings (scan_id references non-existent scan)
            orphaned_threats = (
                session.query(func.count(ThreatFinding.id))
                .filter(
                    ~ThreatFinding.scan_id.in_(
                        session.query(ScanEngineExecution.scan_id)
                    )
                )
                .scalar()
            )

            if orphaned_threats > 0:
                issues.append(
                    {
                        "severity": "critical",
                        "type": "referential_integrity",
                        "description": f"{orphaned_threats} threat findings reference non-existent scan executions",
                        "recommendation": "Clean up orphaned threat findings or restore missing scan executions",
                    }
                )

            # Check for duplicate UUIDs in threat findings
            duplicate_uuids = (
                session.query(
                    ThreatFinding.finding_uuid,
                    func.count(ThreatFinding.id).label("count"),
                )
                .group_by(ThreatFinding.finding_uuid)
                .having(func.count(ThreatFinding.id) > 1)
                .count()
            )

            if duplicate_uuids > 0:
                issues.append(
                    {
                        "severity": "critical",
                        "type": "data_integrity",
                        "description": f"{duplicate_uuids} duplicate threat finding UUIDs found",
                        "recommendation": "Investigate and resolve UUID duplication",
                    }
                )

            # Check for null required fields
            null_checks = [
                (MCPToolExecution, "tool_name"),
                (ScanEngineExecution, "scan_id"),
                (ThreatFinding, "finding_uuid"),
                (ThreatFinding, "file_path"),
            ]

            for model, field in null_checks:
                null_count = (
                    session.query(func.count(model.id))
                    .filter(getattr(model, field).is_(None))
                    .scalar()
                )

                if null_count > 0:
                    issues.append(
                        {
                            "severity": "critical",
                            "type": "null_constraint_violation",
                            "description": f"{null_count} records in {model.__tablename__} have null {field}",
                            "recommendation": f"Fix null values in {model.__tablename__}.{field}",
                        }
                    )

        except Exception as e:
            issues.append(
                {
                    "severity": "critical",
                    "type": "integrity_check_failed",
                    "description": f"Table integrity check failed: {str(e)}",
                    "recommendation": "Investigate database schema and data integrity",
                }
            )

        return {
            "status": "healthy" if not issues else "critical",
            "issues_found": len(issues),
            "issues": issues,
        }

    def _check_data_volume(self, session: Session) -> dict[str, Any]:
        """Check data volume and growth patterns."""
        logger.debug("Checking data volume")

        issues = []
        metrics = {}

        try:
            # Get record counts for all tables
            table_counts = {
                "mcp_tool_executions": session.query(
                    func.count(MCPToolExecution.id)
                ).scalar(),
                "cli_command_executions": session.query(
                    func.count(CLICommandExecution.id)
                ).scalar(),
                "scan_executions": session.query(
                    func.count(ScanEngineExecution.id)
                ).scalar(),
                "threat_findings": session.query(func.count(ThreatFinding.id)).scalar(),
                "system_health_snapshots": session.query(
                    func.count(SystemHealth.id)
                ).scalar(),
                "cache_operation_metrics": session.query(
                    func.count(CacheOperationMetric.id)
                ).scalar(),
            }

            metrics.update(table_counts)

            # Check for extremely high record counts
            high_count_thresholds = {
                "threat_findings": 50000,
                "cache_operation_metrics": 100000,
                "system_health_snapshots": 10000,
            }

            for table, count in table_counts.items():
                if (
                    table in high_count_thresholds
                    and count > high_count_thresholds[table]
                ):
                    issues.append(
                        {
                            "severity": "info",
                            "type": "high_data_volume",
                            "description": f"{table} has high record count: {count:,}",
                            "recommendation": f"Consider archiving old {table} data",
                        }
                    )

            # Check recent growth rate (last 24 hours)
            recent_timestamp = time.time() - (24 * 3600)

            recent_threats = (
                session.query(func.count(ThreatFinding.id))
                .filter(ThreatFinding.timestamp > recent_timestamp)
                .scalar()
            )

            metrics["recent_threats_24h"] = recent_threats

            if recent_threats > 1000:
                issues.append(
                    {
                        "severity": "info",
                        "type": "high_growth_rate",
                        "description": f"High threat finding creation rate: {recent_threats} in last 24h",
                        "recommendation": "Monitor for unusual scanning activity",
                    }
                )

        except Exception as e:
            issues.append(
                {
                    "severity": "warning",
                    "type": "volume_check_failed",
                    "description": f"Data volume check failed: {str(e)}",
                    "recommendation": "Investigate database query capabilities",
                }
            )

        return {
            "status": "healthy" if not issues else "info",
            "issues_found": len(issues),
            "issues": issues,
            "metrics": metrics,
        }

    def _check_cache_health(self, session: Session) -> dict[str, Any]:
        """Check cache performance and health metrics."""
        logger.debug("Checking cache health")

        issues = []
        metrics = {}

        try:
            # Get recent cache metrics (last hour)
            recent_timestamp = time.time() - 3600

            cache_stats = (
                session.query(
                    CacheOperationMetric.cache_name,
                    func.sum(
                        case((CacheOperationMetric.operation_type == "hit", 1), else_=0)
                    ).label("hits"),
                    func.sum(
                        case(
                            (CacheOperationMetric.operation_type == "miss", 1), else_=0
                        )
                    ).label("misses"),
                    func.avg(CacheOperationMetric.access_time_ms).label(
                        "avg_access_time"
                    ),
                )
                .filter(CacheOperationMetric.timestamp > recent_timestamp)
                .group_by(CacheOperationMetric.cache_name)
                .all()
            )

            cache_health = {}
            for cache_name, hits, misses, avg_time in cache_stats:
                total_ops = (hits or 0) + (misses or 0)
                hit_rate = (hits or 0) / max(total_ops, 1)

                cache_health[cache_name] = {
                    "hit_rate": hit_rate,
                    "total_operations": total_ops,
                    "avg_access_time_ms": float(avg_time or 0),
                }

                # Check for poor hit rates
                if total_ops > 10 and hit_rate < 0.3:  # Less than 30% hit rate
                    issues.append(
                        {
                            "severity": "warning",
                            "type": "poor_cache_performance",
                            "description": f"{cache_name} cache has low hit rate: {hit_rate:.1%}",
                            "recommendation": f"Investigate {cache_name} cache efficiency",
                        }
                    )

                # Check for slow cache access
                if avg_time and avg_time > 100:  # More than 100ms average
                    issues.append(
                        {
                            "severity": "warning",
                            "type": "slow_cache_access",
                            "description": f"{cache_name} cache has slow access time: {avg_time:.1f}ms",
                            "recommendation": f"Investigate {cache_name} cache performance bottlenecks",
                        }
                    )

            metrics["cache_health"] = cache_health

        except Exception as e:
            issues.append(
                {
                    "severity": "warning",
                    "type": "cache_check_failed",
                    "description": f"Cache health check failed: {str(e)}",
                    "recommendation": "Investigate cache metrics collection",
                }
            )

        return {
            "status": "healthy" if not issues else "warning",
            "issues_found": len(issues),
            "issues": issues,
            "metrics": metrics,
        }

    def _check_orphaned_records(self, session: Session) -> dict[str, Any]:
        """Check for orphaned records and cleanup opportunities."""
        logger.debug("Checking for orphaned records")

        issues = []
        cleanup_opportunities = []

        try:
            # Check for old system health snapshots (older than 30 days)
            old_timestamp = time.time() - (30 * 24 * 3600)
            old_health_snapshots = (
                session.query(func.count(SystemHealth.id))
                .filter(SystemHealth.timestamp < old_timestamp)
                .scalar()
            )

            if old_health_snapshots > 100:
                cleanup_opportunities.append(
                    {
                        "type": "old_health_snapshots",
                        "count": old_health_snapshots,
                        "description": f"{old_health_snapshots} system health snapshots older than 30 days",
                        "recommendation": "Archive or delete old health snapshots",
                    }
                )

            # Check for old cache operation metrics (older than 7 days)
            old_cache_timestamp = time.time() - (7 * 24 * 3600)
            old_cache_metrics = (
                session.query(func.count(CacheOperationMetric.id))
                .filter(CacheOperationMetric.timestamp < old_cache_timestamp)
                .scalar()
            )

            if old_cache_metrics > 1000:
                cleanup_opportunities.append(
                    {
                        "type": "old_cache_metrics",
                        "count": old_cache_metrics,
                        "description": f"{old_cache_metrics} cache metrics older than 7 days",
                        "recommendation": "Archive or delete old cache metrics",
                    }
                )

            # Check for executions without end times (potential cleanup candidates)
            very_old_timestamp = time.time() - (24 * 3600)  # 24 hours ago

            old_unfinished_scans = (
                session.query(func.count(ScanEngineExecution.id))
                .filter(
                    ScanEngineExecution.execution_end.is_(None),
                    ScanEngineExecution.execution_start < very_old_timestamp,
                )
                .scalar()
            )

            if old_unfinished_scans > 0:
                issues.append(
                    {
                        "severity": "warning",
                        "type": "stale_unfinished_operations",
                        "description": f"{old_unfinished_scans} scan executions started >24h ago but never finished",
                        "recommendation": "Mark old unfinished operations as failed or investigate hanging processes",
                    }
                )

        except Exception as e:
            issues.append(
                {
                    "severity": "warning",
                    "type": "orphan_check_failed",
                    "description": f"Orphaned records check failed: {str(e)}",
                    "recommendation": "Investigate database query capabilities",
                }
            )

        return {
            "status": "healthy" if not issues else "warning",
            "issues_found": len(issues),
            "issues": issues,
            "cleanup_opportunities": cleanup_opportunities,
        }

    def _calculate_overall_health(self, health_results: dict[str, Any]):
        """Calculate overall health status based on all check results."""
        critical_issues = 0
        warning_issues = 0
        info_issues = 0

        for check_name, check_results in health_results["checks"].items():
            if "issues" in check_results:
                for issue in check_results["issues"]:
                    if issue["severity"] == "critical":
                        critical_issues += 1
                    elif issue["severity"] == "warning":
                        warning_issues += 1
                    elif issue["severity"] == "info":
                        info_issues += 1

        health_results["critical_issues"] = critical_issues
        health_results["warning_issues"] = warning_issues
        health_results["info_issues"] = info_issues
        health_results["total_issues"] = critical_issues + warning_issues + info_issues

        # Determine overall health
        if critical_issues > 0:
            health_results["overall_health"] = "critical"
            health_results["recommendations"].append(
                "Address critical issues immediately"
            )
        elif warning_issues > 5:
            health_results["overall_health"] = "warning"
            health_results["recommendations"].append(
                "Address warning issues to prevent future problems"
            )
        elif warning_issues > 0:
            health_results["overall_health"] = "fair"
            health_results["recommendations"].append(
                "Consider addressing warning issues during maintenance"
            )
        else:
            health_results["overall_health"] = "healthy"
            health_results["recommendations"].append(
                "Database is healthy - continue regular monitoring"
            )

        # Add general recommendations based on findings
        if health_results["total_issues"] > 0:
            health_results["recommendations"].append(
                "Run 'adversary-mcp-cli validate-data' for detailed consistency checks"
            )
            health_results["recommendations"].append(
                "Consider running 'adversary-mcp-cli migrate-data' if inconsistencies found"
            )


def run_health_check(db_path: str = None) -> dict[str, Any]:
    """Run comprehensive database health check.

    Args:
        db_path: Optional path to database file. If None, uses default location.

    Returns:
        Dict with health check results
    """
    # Initialize database
    if db_path:
        db = AdversaryDatabase(Path(db_path))
    else:
        db = AdversaryDatabase()

    # Run health checks
    health_checker = DatabaseHealthChecker(db)
    return health_checker.run_comprehensive_health_check()
