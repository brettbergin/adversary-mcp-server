"""Migration monitoring and automated recommendation system."""

import logging
import time
from datetime import UTC, datetime
from typing import Any, cast

from ..database.health_checks import DatabaseHealthChecker
from ..database.migrations import DataMigrationManager
from ..database.models import AdversaryDatabase
from .database_migration import DatabaseMigrationManager

logger = logging.getLogger(__name__)


class MigrationRecommendationEngine:
    """Analyzes system state and provides automated migration recommendations."""

    def __init__(self, db: AdversaryDatabase):
        self.db = db
        self.health_checker = DatabaseHealthChecker(db)
        self.data_manager = DataMigrationManager(db)
        self.legacy_manager = DatabaseMigrationManager(db.db_path)

    def analyze_and_recommend(self) -> dict[str, Any]:
        """Analyze system state and provide comprehensive migration recommendations.

        Returns:
            Dict with analysis results and prioritized recommendations
        """
        logger.info("Starting migration recommendation analysis")

        analysis_start = time.time()

        analysis = {
            "timestamp": time.time(),
            "datetime": datetime.now(UTC).isoformat(),
            "analysis_duration": 0,
            "system_health": {},
            "data_consistency": {},
            "legacy_files": {},
            "recommendations": [],
            "priority_actions": [],
            "maintenance_schedule": {},
        }

        try:
            # 1. Health assessment
            analysis["system_health"] = self._assess_system_health()

            # 2. Data consistency analysis
            analysis["data_consistency"] = self._analyze_data_consistency()

            # 3. Legacy files analysis
            analysis["legacy_files"] = self._analyze_legacy_files()

            # 4. Generate recommendations
            analysis["recommendations"] = self._generate_recommendations(analysis)

            # 5. Prioritize actions
            recommendations = analysis["recommendations"]
            if isinstance(recommendations, list):
                analysis["priority_actions"] = self._prioritize_actions(recommendations)
            else:
                analysis["priority_actions"] = []

            # 6. Create maintenance schedule
            analysis["maintenance_schedule"] = self._create_maintenance_schedule(
                analysis
            )

            analysis["analysis_duration"] = time.time() - analysis_start

            logger.info(
                f"Migration recommendation analysis completed in {analysis['analysis_duration']:.2f}s"
            )
            return analysis

        except Exception as e:
            logger.error(f"Migration recommendation analysis failed: {e}")
            analysis["analysis_duration"] = time.time() - analysis_start
            analysis["error"] = str(e)
            return analysis

    def _assess_system_health(self) -> dict[str, Any]:
        """Assess overall system health."""
        logger.debug("Assessing system health")

        try:
            health_results = self.health_checker.run_comprehensive_health_check()

            return {
                "status": health_results["overall_health"],
                "critical_issues": health_results["critical_issues"],
                "warning_issues": health_results["warning_issues"],
                "info_issues": health_results["info_issues"],
                "total_issues": health_results["total_issues"],
                "checks": health_results["checks"],
                "success": True,
            }

        except Exception as e:
            logger.error(f"Health assessment failed: {e}")
            return {
                "status": "unknown",
                "success": False,
                "error": str(e),
            }

    def _analyze_data_consistency(self) -> dict[str, Any]:
        """Analyze data consistency across tables."""
        logger.debug("Analyzing data consistency")

        try:
            validation_results = self.data_manager.validate_data_consistency()

            return {
                "consistent": validation_results["data_consistent"],
                "total_inconsistencies": validation_results["total_inconsistencies"],
                "validation_details": validation_results,
                "success": validation_results["validation_success"],
            }

        except Exception as e:
            logger.error(f"Data consistency analysis failed: {e}")
            return {
                "consistent": False,
                "success": False,
                "error": str(e),
            }

    def _analyze_legacy_files(self) -> dict[str, Any]:
        """Analyze legacy file migration needs."""
        logger.debug("Analyzing legacy files")

        try:
            check_results = self.legacy_manager.check_migration_needed()

            return {
                "migration_needed": check_results["migration_needed"],
                "legacy_sqlite_files": len(
                    check_results.get("legacy_sqlite_files", [])
                ),
                "json_metrics_files": len(check_results.get("json_metrics_files", [])),
                "estimated_records": check_results.get("estimated_records", 0),
                "target_db_exists": check_results.get("target_db_exists", False),
                "success": True,
            }

        except Exception as e:
            logger.error(f"Legacy files analysis failed: {e}")
            return {
                "migration_needed": False,
                "success": False,
                "error": str(e),
            }

    def _generate_recommendations(
        self, analysis: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Generate prioritized recommendations based on analysis."""
        recommendations = []

        # Critical health issues
        health = analysis.get("system_health", {})
        if health.get("critical_issues", 0) > 0:
            recommendations.append(
                {
                    "type": "critical_health",
                    "priority": "critical",
                    "title": "Address Critical Health Issues",
                    "description": f"System has {health['critical_issues']} critical health issues requiring immediate attention",
                    "action": "Run 'adversary-mcp-cli health-check --detailed' to see specific issues",
                    "estimated_time": "5-30 minutes",
                    "risk_level": "high",
                    "automated": False,
                }
            )

        # Data consistency issues
        data_consistency = analysis.get("data_consistency", {})
        if not data_consistency.get("consistent", True):
            inconsistencies = data_consistency.get("total_inconsistencies", 0)
            recommendations.append(
                {
                    "type": "data_consistency",
                    "priority": "high",
                    "title": "Fix Data Inconsistencies",
                    "description": f"Found {inconsistencies} data inconsistencies between summary fields and actual records",
                    "action": "Run 'adversary-mcp-cli migrate-data' to fix inconsistencies",
                    "estimated_time": "2-10 minutes",
                    "risk_level": "medium",
                    "automated": True,
                    "command": "adversary-mcp-cli migrate-data",
                }
            )

        # Legacy file migration
        legacy = analysis.get("legacy_files", {})
        if legacy.get("migration_needed", False):
            total_files = legacy.get("legacy_sqlite_files", 0) + legacy.get(
                "json_metrics_files", 0
            )
            recommendations.append(
                {
                    "type": "legacy_migration",
                    "priority": "medium",
                    "title": "Migrate Legacy Files",
                    "description": f"Found {total_files} legacy files that should be migrated to unified database",
                    "action": "Run 'adversary-mcp-cli migrate-legacy' to consolidate legacy files",
                    "estimated_time": "5-15 minutes",
                    "risk_level": "low",
                    "automated": True,
                    "command": "adversary-mcp-cli migrate-legacy",
                    "estimated_records": legacy.get("estimated_records", 0),
                }
            )

        # Performance optimization
        if health.get("warning_issues", 0) > 5:
            recommendations.append(
                {
                    "type": "performance_optimization",
                    "priority": "medium",
                    "title": "Database Performance Optimization",
                    "description": "Multiple performance warnings detected - database may benefit from optimization",
                    "action": "Consider running cleanup operations or archiving old data",
                    "estimated_time": "10-30 minutes",
                    "risk_level": "low",
                    "automated": False,
                }
            )

        # Constraint installation
        if (
            data_consistency.get("consistent", True)
            and not self._constraints_installed()
        ):
            recommendations.append(
                {
                    "type": "constraint_installation",
                    "priority": "low",
                    "title": "Install Database Constraints",
                    "description": "Install constraints and triggers to prevent future data inconsistencies",
                    "action": "Install application-level constraints and triggers",
                    "estimated_time": "1-2 minutes",
                    "risk_level": "very_low",
                    "automated": True,
                }
            )

        # Regular maintenance
        if health.get("status") == "healthy":
            recommendations.append(
                {
                    "type": "regular_maintenance",
                    "priority": "low",
                    "title": "Schedule Regular Health Checks",
                    "description": "System is healthy - consider scheduling regular maintenance",
                    "action": "Set up automated health monitoring",
                    "estimated_time": "5 minutes setup",
                    "risk_level": "none",
                    "automated": False,
                }
            )

        return recommendations

    def _prioritize_actions(
        self, recommendations: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Prioritize actions based on risk and impact."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        # Sort by priority, then by automated capability
        sorted_recommendations = sorted(
            recommendations,
            key=lambda x: (
                priority_order.get(x["priority"], 99),
                not x.get(
                    "automated", False
                ),  # Automated actions first within priority
                x.get("risk_level", "unknown"),
            ),
        )

        # Add execution order
        priority_actions = []
        for i, rec in enumerate(sorted_recommendations, 1):
            action = rec.copy()
            action["execution_order"] = i

            # Add dependencies
            if rec["type"] == "constraint_installation":
                action["dependencies"] = ["data_consistency"]
            elif rec["type"] == "performance_optimization":
                action["dependencies"] = ["data_consistency", "legacy_migration"]
            else:
                action["dependencies"] = []

            priority_actions.append(action)

        return priority_actions

    def _create_maintenance_schedule(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Create recommended maintenance schedule."""
        health_status = analysis.get("system_health", {}).get("status", "unknown")

        # Base schedule on current health status
        if health_status == "critical":
            schedule = {
                "immediate": ["health_check", "data_consistency_fix"],
                "daily": ["health_check"],
                "weekly": ["data_validation", "cleanup_check"],
                "monthly": ["full_migration_check", "performance_review"],
            }
        elif health_status in ["warning", "fair"]:
            schedule = {
                "immediate": ["data_consistency_fix"],
                "weekly": ["health_check", "data_validation"],
                "monthly": ["cleanup_operations", "performance_review"],
                "quarterly": ["full_system_review"],
            }
        else:  # healthy
            schedule = {
                "monthly": ["health_check", "data_validation"],
                "quarterly": ["cleanup_operations", "performance_review"],
                "annually": ["full_system_audit"],
            }

        # Add specific recommendations based on analysis
        recommendations = analysis.get("recommendations", [])
        automated_recommendations = [
            r for r in recommendations if r.get("automated", False)
        ]

        if automated_recommendations:
            schedule["automated_available"] = cast(
                Any,
                [
                    {
                        "command": r.get("command", ""),
                        "type": r["type"],
                        "safe_to_automate": r["risk_level"]
                        in ["low", "very_low", "none"],
                    }
                    for r in automated_recommendations
                ],
            )

        return schedule

    def _constraints_installed(self) -> bool:
        """Check if database constraints are installed."""
        try:
            from ..database.constraints import DatabaseConstraintManager

            constraint_manager = DatabaseConstraintManager(self.db)
            validation = constraint_manager.validate_constraints()
            return (
                validation.get("validation_success", False)
                and len(validation.get("triggers_active", [])) > 0
            )
        except Exception:
            return False

    def get_automated_migration_plan(self) -> dict[str, Any]:
        """Generate a fully automated migration plan for safe operations."""
        logger.info("Generating automated migration plan")

        analysis = self.analyze_and_recommend()

        automated_plan = {
            "safe_to_execute": True,
            "plan_created": time.time(),
            "estimated_total_time": 0,
            "commands": [],
            "warnings": [],
            "manual_steps": [],
        }

        # Filter for automated, low-risk recommendations
        priority_actions = analysis.get("priority_actions", [])
        if isinstance(priority_actions, list):
            safe_actions = [
                r
                for r in priority_actions
                if r.get("automated", False)
                and r.get("risk_level") in ["low", "very_low", "none"]
            ]
        else:
            safe_actions = []

        # Build command sequence
        for action in safe_actions:
            if "command" in action:
                automated_plan["commands"].append(
                    {
                        "command": action["command"],
                        "description": action["title"],
                        "estimated_time": action.get("estimated_time", "unknown"),
                        "type": action["type"],
                    }
                )

                # Extract time estimate
                time_str = action.get("estimated_time", "0 minutes")
                if isinstance(time_str, str):
                    try:
                        minutes = int(time_str.split()[0].split("-")[0])
                        if isinstance(
                            automated_plan["estimated_total_time"], int | float
                        ):
                            automated_plan["estimated_total_time"] += minutes
                    except (ValueError, IndexError):
                        pass

        # Add warnings for risky operations
        recommendations = analysis.get("recommendations", [])
        if isinstance(recommendations, list):
            risky_actions = [
                r for r in recommendations if r.get("risk_level") in ["high", "medium"]
            ]
        else:
            risky_actions = []

        for action in risky_actions:
            automated_plan["warnings"].append(
                {
                    "title": action["title"],
                    "risk": action["risk_level"],
                    "requires_manual": True,
                }
            )

            automated_plan["manual_steps"].append(
                {
                    "action": action["action"],
                    "description": action["description"],
                    "priority": action["priority"],
                }
            )

        # Determine overall safety
        if analysis.get("system_health", {}).get("critical_issues", 0) > 0:
            automated_plan["safe_to_execute"] = False
            automated_plan["warnings"].append(
                {
                    "title": "Critical health issues detected",
                    "risk": "high",
                    "requires_manual": True,
                }
            )

        return automated_plan


def analyze_migration_needs(db_path: str = None) -> dict[str, Any]:
    """Analyze migration needs and provide recommendations.

    Args:
        db_path: Optional path to database file. If None, uses default location.

    Returns:
        Dict with analysis and recommendations
    """
    from pathlib import Path

    # Initialize database
    if db_path:
        db = AdversaryDatabase(Path(db_path))
    else:
        db = AdversaryDatabase()

    # Run analysis
    recommendation_engine = MigrationRecommendationEngine(db)
    return recommendation_engine.analyze_and_recommend()


def get_automated_plan(db_path: str = None) -> dict[str, Any]:
    """Get automated migration plan for safe operations.

    Args:
        db_path: Optional path to database file. If None, uses default location.

    Returns:
        Dict with automated migration plan
    """
    from pathlib import Path

    # Initialize database
    if db_path:
        db = AdversaryDatabase(Path(db_path))
    else:
        db = AdversaryDatabase()

    # Generate plan
    recommendation_engine = MigrationRecommendationEngine(db)
    return recommendation_engine.get_automated_migration_plan()


class MigrationMonitor:
    """Monitors migration operations and tracks metrics."""

    def __init__(self, db: AdversaryDatabase):
        self.db = db
        self.start_time = time.time()
        self.metrics = {
            "start_time": self.start_time,
            "operations": [],
            "errors": [],
            "warnings": [],
            "performance": {},
        }

    def start_operation(self, operation_type: str, description: str = None) -> str:
        """Start tracking a migration operation."""
        operations = self.metrics["operations"]
        operations_count = len(operations) if isinstance(operations, list) else 0
        operation_id = f"op_{operations_count}_{int(time.time() * 1000)}"

        operation = {
            "id": operation_id,
            "type": operation_type,
            "description": description or operation_type,
            "start_time": time.time(),
            "end_time": None,
            "duration": None,
            "success": None,
            "records_processed": 0,
            "details": {},
        }

        self.metrics["operations"].append(operation)
        logger.info(f"Started migration operation: {operation_type} ({operation_id})")

        return operation_id

    def end_operation(
        self,
        operation_id: str,
        success: bool,
        records_processed: int = 0,
        details: dict = None,
    ):
        """End tracking a migration operation."""
        for operation in self.metrics["operations"]:
            if operation["id"] == operation_id:
                operation["end_time"] = time.time()
                operation["duration"] = operation["end_time"] - operation["start_time"]
                operation["success"] = success
                operation["records_processed"] = records_processed
                operation["details"] = details or {}

                logger.info(
                    f"Completed migration operation: {operation['type']} "
                    f"({operation_id}) - Success: {success}, Duration: {operation['duration']:.2f}s"
                )
                break

    def add_error(
        self, operation_id: str, error_message: str, error_details: dict = None
    ):
        """Add error to monitoring metrics."""
        error = {
            "operation_id": operation_id,
            "timestamp": time.time(),
            "message": error_message,
            "details": error_details or {},
        }

        self.metrics["errors"].append(error)
        logger.error(f"Migration error in {operation_id}: {error_message}")

    def add_warning(
        self, operation_id: str, warning_message: str, warning_details: dict = None
    ):
        """Add warning to monitoring metrics."""
        warning = {
            "operation_id": operation_id,
            "timestamp": time.time(),
            "message": warning_message,
            "details": warning_details or {},
        }

        self.metrics["warnings"].append(warning)
        logger.warning(f"Migration warning in {operation_id}: {warning_message}")

    def get_summary(self) -> dict[str, Any]:
        """Get migration monitoring summary."""
        end_time = time.time()

        # Calculate performance metrics
        operations = self.metrics["operations"]
        total_operations = len(operations) if isinstance(operations, list) else 0
        successful_operations = (
            len([op for op in operations if op.get("success") is True])
            if isinstance(operations, list)
            else 0
        )
        failed_operations = (
            len([op for op in operations if op.get("success") is False])
            if isinstance(operations, list)
            else 0
        )
        total_records = (
            sum(op.get("records_processed", 0) for op in operations)
            if isinstance(operations, list)
            else 0
        )

        average_duration = 0
        if total_operations > 0 and isinstance(operations, list):
            durations = [
                op.get("duration", 0) for op in operations if op.get("duration")
            ]
            if durations:
                average_duration = sum(durations) / len(durations)

        summary = {
            "session_start": self.start_time,
            "session_end": end_time,
            "total_session_duration": end_time - self.start_time,
            "total_operations": total_operations,
            "successful_operations": successful_operations,
            "failed_operations": failed_operations,
            "success_rate": successful_operations / max(total_operations, 1),
            "total_records_processed": total_records,
            "average_operation_duration": average_duration,
            "total_errors": (
                len(self.metrics["errors"])
                if isinstance(self.metrics["errors"], list)
                else 0
            ),
            "total_warnings": (
                len(self.metrics["warnings"])
                if isinstance(self.metrics["warnings"], list)
                else 0
            ),
            "performance_rating": self._calculate_performance_rating(),
        }

        return summary

    def _calculate_performance_rating(self) -> str:
        """Calculate performance rating based on metrics."""
        operations = self.metrics["operations"]
        if not isinstance(operations, list):
            return "no_data"

        total_ops = len(operations)
        if total_ops == 0:
            return "no_data"

        success_rate = (
            len([op for op in operations if op.get("success") is True]) / total_ops
        )
        errors = self.metrics["errors"]
        error_rate = (len(errors) if isinstance(errors, list) else 0) / total_ops

        if success_rate >= 0.95 and error_rate < 0.05:
            return "excellent"
        elif success_rate >= 0.90 and error_rate < 0.10:
            return "good"
        elif success_rate >= 0.80 and error_rate < 0.20:
            return "fair"
        else:
            return "poor"
