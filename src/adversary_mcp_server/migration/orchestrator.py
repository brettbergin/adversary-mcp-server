"""Unified migration orchestrator to handle complex migration workflows."""

import logging
import time
from pathlib import Path
from typing import Any

from ..database.constraints import DatabaseConstraintManager
from ..database.health_checks import DatabaseHealthChecker
from ..database.migrations import DataMigrationManager
from ..database.models import AdversaryDatabase
from .database_migration import DatabaseMigrationManager

logger = logging.getLogger(__name__)


class MigrationOrchestrator:
    """Orchestrates complex migration workflows with dependency checking and rollback."""

    def __init__(self, target_db_path: Path = None):
        """Initialize migration orchestrator.

        Args:
            target_db_path: Path to target database (default: standard location)
        """
        self.target_db_path = target_db_path
        self.db = (
            AdversaryDatabase(target_db_path) if target_db_path else AdversaryDatabase()
        )

        # Initialize migration managers
        self.legacy_manager = DatabaseMigrationManager(target_db_path)
        self.data_manager = DataMigrationManager(self.db)
        self.constraint_manager = DatabaseConstraintManager(self.db)
        self.health_checker = DatabaseHealthChecker(self.db)

    def run_complete_migration(
        self,
        backup: bool = True,
        skip_legacy: bool = False,
        skip_constraints: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Run complete migration workflow with proper dependency ordering.

        Args:
            backup: Create backups before migration
            skip_legacy: Skip legacy system migration
            skip_constraints: Skip constraint installation
            dry_run: Show what would be done without making changes

        Returns:
            Dict with comprehensive migration results
        """
        logger.info("=== Starting Complete Migration Workflow ===")

        start_time = time.time()
        results = {
            "workflow_started": start_time,
            "dry_run": dry_run,
            "phases": {},
            "overall_success": True,
            "errors": [],
            "warnings": [],
        }

        try:
            # Phase 1: Pre-migration health check
            logger.info("Phase 1: Pre-migration health assessment")
            results["phases"][
                "pre_health_check"
            ] = self._run_pre_migration_health_check()

            if not results["phases"]["pre_health_check"]["success"]:
                results["overall_success"] = False
                results["errors"].append("Pre-migration health check failed")

            # Phase 2: Legacy system migration (if needed)
            if not skip_legacy:
                logger.info("Phase 2: Legacy system migration")
                results["phases"]["legacy_migration"] = self._run_legacy_migration(
                    backup, dry_run
                )

                if not results["phases"]["legacy_migration"]["success"] and not dry_run:
                    results["overall_success"] = False
                    results["errors"].append("Legacy migration failed")

            # Phase 3: Data consistency migration
            logger.info("Phase 3: Data consistency migration")
            results["phases"]["data_migration"] = self._run_data_consistency_migration(
                dry_run
            )

            if not results["phases"]["data_migration"]["success"] and not dry_run:
                results["overall_success"] = False
                results["errors"].append("Data consistency migration failed")

            # Phase 4: Install constraints and triggers (if not dry run)
            if not skip_constraints and not dry_run:
                logger.info("Phase 4: Installing database constraints")
                results["phases"][
                    "constraint_installation"
                ] = self._install_constraints()

                if not results["phases"]["constraint_installation"]["success"]:
                    results["warnings"].append("Constraint installation had issues")

            # Phase 5: Post-migration validation
            logger.info("Phase 5: Post-migration validation")
            results["phases"]["post_validation"] = self._run_post_migration_validation()

            if not results["phases"]["post_validation"]["success"]:
                results["overall_success"] = False
                results["errors"].append("Post-migration validation failed")

            # Calculate totals
            end_time = time.time()
            results["workflow_completed"] = end_time
            results["total_duration"] = end_time - start_time
            results["summary"] = self._generate_migration_summary(results)

            logger.info(
                f"Complete migration workflow finished: success={results['overall_success']}"
            )
            return results

        except Exception as e:
            logger.error(f"Migration workflow failed: {e}", exc_info=True)
            results["overall_success"] = False
            results["workflow_error"] = str(e)
            results["workflow_completed"] = time.time()
            results["total_duration"] = time.time() - start_time
            return results

    def _run_pre_migration_health_check(self) -> dict[str, Any]:
        """Run pre-migration health assessment."""
        try:
            health_results = self.health_checker.run_comprehensive_health_check()
            return {
                "success": True,
                "health_status": health_results["overall_health"],
                "critical_issues": health_results["critical_issues"],
                "warning_issues": health_results["warning_issues"],
                "recommendations": health_results.get("recommendations", []),
            }
        except Exception as e:
            logger.error(f"Pre-migration health check failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def _run_legacy_migration(self, backup: bool, dry_run: bool) -> dict[str, Any]:
        """Run legacy system migration if needed."""
        try:
            # Check if legacy migration is needed
            check_results = self.legacy_manager.check_migration_needed()

            if not check_results["migration_needed"]:
                return {
                    "success": True,
                    "skipped": True,
                    "reason": "No legacy files found",
                }

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "legacy_files_found": len(check_results["legacy_sqlite_files"])
                    + len(check_results["json_metrics_files"]),
                    "estimated_records": check_results["estimated_records"],
                }

            # Run actual legacy migration
            migration_results = self.legacy_manager.run_full_migration(backup=backup)

            return {
                "success": not bool(migration_results.get("errors")),
                "records_migrated": migration_results.get("records_migrated", 0),
                "files_processed": (
                    len(migration_results.get("legacy_sqlite_files", []))
                    + len(migration_results.get("json_metrics_files", []))
                ),
                "duration": migration_results.get("duration_seconds", 0),
                "backup_created": migration_results.get("backup_created", False),
                "errors": migration_results.get("errors", []),
                "warnings": migration_results.get("warnings", []),
            }

        except Exception as e:
            logger.error(f"Legacy migration failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def _run_data_consistency_migration(self, dry_run: bool) -> dict[str, Any]:
        """Run data consistency migration."""
        try:
            # First validate to see what needs fixing
            validation_results = self.data_manager.validate_data_consistency()

            if not validation_results["validation_success"]:
                return {
                    "success": False,
                    "error": validation_results.get("error", "Validation failed"),
                }

            total_inconsistencies = validation_results["total_inconsistencies"]

            if total_inconsistencies == 0:
                return {
                    "success": True,
                    "skipped": True,
                    "reason": "No data inconsistencies found",
                }

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "inconsistencies_found": total_inconsistencies,
                    "tables_affected": self._count_affected_tables(validation_results),
                }

            # Run actual data migration
            migration_results = self.data_manager.fix_summary_field_inconsistencies()

            return {
                "success": migration_results["migration_success"],
                "records_fixed": migration_results["total_records_fixed"],
                "mcp_fixes": migration_results["mcp_tool_fixes"]["records_updated"],
                "cli_fixes": migration_results["cli_command_fixes"]["records_updated"],
                "scan_fixes": migration_results["scan_engine_fixes"]["records_updated"],
                "error": migration_results.get("error"),
            }

        except Exception as e:
            logger.error(f"Data consistency migration failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def _install_constraints(self) -> dict[str, Any]:
        """Install database constraints and triggers."""
        try:
            constraint_results = (
                self.constraint_manager.install_data_consistency_constraints()
            )

            return {
                "success": constraint_results["installation_success"],
                "constraints_installed": len(
                    constraint_results["constraints_installed"]
                ),
                "triggers_installed": len(constraint_results["triggers_installed"]),
                "errors": constraint_results.get("errors", []),
            }

        except Exception as e:
            logger.error(f"Constraint installation failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def _run_post_migration_validation(self) -> dict[str, Any]:
        """Run post-migration validation and health check."""
        try:
            # Validate data consistency
            validation_results = self.data_manager.validate_data_consistency()

            # Run health check
            health_results = self.health_checker.run_comprehensive_health_check()

            return {
                "success": validation_results["validation_success"],
                "data_consistent": validation_results.get("data_consistent", False),
                "remaining_inconsistencies": validation_results.get(
                    "total_inconsistencies", 0
                ),
                "health_status": health_results["overall_health"],
                "critical_issues": health_results["critical_issues"],
                "warning_issues": health_results["warning_issues"],
            }

        except Exception as e:
            logger.error(f"Post-migration validation failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def _count_affected_tables(self, validation_results: dict[str, Any]) -> int:
        """Count number of tables with inconsistencies."""
        affected_tables = 0
        for key, value in validation_results.items():
            if isinstance(value, dict) and value.get("inconsistencies_found", 0) > 0:
                affected_tables += 1
        return affected_tables

    def _generate_migration_summary(self, results: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive migration summary."""
        summary = {
            "overall_success": results["overall_success"],
            "total_duration_seconds": results["total_duration"],
            "phases_completed": len(results["phases"]),
            "total_errors": len(results["errors"]),
            "total_warnings": len(results["warnings"]),
        }

        # Aggregate statistics from all phases
        total_records_processed = 0
        total_files_processed = 0

        for phase_name, phase_results in results["phases"].items():
            if "records_migrated" in phase_results:
                total_records_processed += phase_results["records_migrated"]
            if "records_fixed" in phase_results:
                total_records_processed += phase_results["records_fixed"]
            if "files_processed" in phase_results:
                total_files_processed += phase_results["files_processed"]

        summary.update(
            {
                "total_records_processed": total_records_processed,
                "total_files_processed": total_files_processed,
            }
        )

        # Determine overall health after migration
        post_validation = results["phases"].get("post_validation", {})
        if post_validation:
            summary["final_health_status"] = post_validation.get(
                "health_status", "unknown"
            )
            summary["final_data_consistency"] = post_validation.get(
                "data_consistent", False
            )

        return summary

    def rollback_migration(self, backup_path: Path) -> dict[str, Any]:
        """Rollback migration from backup (emergency recovery).

        Args:
            backup_path: Path to backup directory

        Returns:
            Dict with rollback results
        """
        logger.info(f"=== Starting Migration Rollback from {backup_path} ===")

        try:
            import shutil

            rollback_results = {
                "success": False,
                "files_restored": [],
                "errors": [],
            }

            # Verify backup exists
            if not backup_path.exists():
                raise ValueError(f"Backup directory does not exist: {backup_path}")

            # Close current database connections
            self.db.close()

            # Restore cache directory
            cache_backup = backup_path / "cache"
            if cache_backup.exists():
                # Copy individual files from cache backup
                for cache_file in cache_backup.glob("*"):
                    if cache_file.is_file():
                        target_file = self.db.db_path.parent / cache_file.name
                        try:
                            shutil.copy2(str(cache_file), str(target_file))
                        except (OSError, PermissionError) as e:
                            logger.warning(
                                f"Failed to restore cache file {cache_file.name}: {e}"
                            )
                rollback_results["files_restored"].append("cache")

            # Restore metrics directory
            metrics_backup = backup_path / "metrics"
            if metrics_backup.exists():
                try:
                    from ..config import get_app_metrics_dir

                    metrics_target = get_app_metrics_dir()
                    metrics_target.mkdir(parents=True, exist_ok=True)

                    # Copy individual files from metrics backup
                    for metrics_file in metrics_backup.glob("*"):
                        if metrics_file.is_file():
                            target_file = metrics_target / metrics_file.name
                            shutil.copy2(str(metrics_file), str(target_file))

                    rollback_results["files_restored"].append("metrics")
                except (OSError, PermissionError) as e:
                    logger.warning(f"Failed to restore metrics files: {e}")
                    rollback_results["errors"].append(f"Metrics restore: {str(e)}")

            rollback_results["success"] = True
            files_restored = rollback_results.get("files_restored", [])
            files_count = len(files_restored) if isinstance(files_restored, list) else 0
            logger.info(
                f"Migration rollback completed: {files_count} directories restored"
            )

            return rollback_results

        except Exception as e:
            logger.error(f"Migration rollback failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "files_restored": rollback_results.get("files_restored", []),
            }


def run_complete_migration(
    target_db_path: str = None,
    backup: bool = True,
    skip_legacy: bool = False,
    skip_constraints: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run complete migration workflow.

    Args:
        target_db_path: Target database path
        backup: Create backups before migration
        skip_legacy: Skip legacy system migration
        skip_constraints: Skip constraint installation
        dry_run: Show what would be done without making changes

    Returns:
        Dict with migration results
    """
    target_path = Path(target_db_path) if target_db_path else None
    orchestrator = MigrationOrchestrator(target_path)

    return orchestrator.run_complete_migration(
        backup=backup,
        skip_legacy=skip_legacy,
        skip_constraints=skip_constraints,
        dry_run=dry_run,
    )
