"""Database migration utilities for fixing data consistency issues."""

import logging
import time
from pathlib import Path
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import (
    AdversaryDatabase,
    CLICommandExecution,
    MCPToolExecution,
    ScanEngineExecution,
    ThreatFinding,
)

logger = logging.getLogger(__name__)


class DataMigrationManager:
    """Manages database migrations and data consistency fixes."""

    def __init__(self, db: AdversaryDatabase):
        self.db = db

    def fix_summary_field_inconsistencies(self) -> dict[str, Any]:
        """Fix inconsistencies between summary fields and actual threat findings.

        Returns:
            Dict with migration statistics and results
        """
        logger.info("Starting data migration to fix summary field inconsistencies")

        with self.db.get_session() as session:
            try:
                # Fix MCP Tool execution findings_count
                mcp_fixes = self._fix_mcp_tool_findings_count(session)

                # Fix CLI Command execution findings_count
                cli_fixes = self._fix_cli_command_findings_count(session)

                # Fix Scan Engine execution threats_found
                scan_fixes = self._fix_scan_engine_threats_found(session)

                # Commit all fixes
                session.commit()

                results = {
                    "migration_success": True,
                    "mcp_tool_fixes": mcp_fixes,
                    "cli_command_fixes": cli_fixes,
                    "scan_engine_fixes": scan_fixes,
                    "total_records_fixed": mcp_fixes["records_updated"]
                    + cli_fixes["records_updated"]
                    + scan_fixes["records_updated"],
                }

                logger.info(
                    f"Data migration completed successfully: {results['total_records_fixed']} total records fixed"
                )
                return results

            except Exception as e:
                session.rollback()
                logger.error(f"Data migration failed: {e}")
                return {
                    "migration_success": False,
                    "error": str(e),
                    "total_records_fixed": 0,
                }

    def _fix_mcp_tool_findings_count(self, session: Session) -> dict[str, Any]:
        """Fix MCP tool execution findings_count fields."""
        logger.debug("Fixing MCP tool execution findings_count fields")

        # Get actual findings count for each MCP tool execution
        # We need to join through ScanEngineExecution to get to ThreatFinding
        mcp_actual_counts = (
            session.query(
                MCPToolExecution.id,
                func.coalesce(func.count(ThreatFinding.id), 0).label(
                    "actual_findings_count"
                ),
            )
            .outerjoin(
                ScanEngineExecution,
                MCPToolExecution.session_id == ScanEngineExecution.scan_id,
            )
            .outerjoin(
                ThreatFinding, ScanEngineExecution.scan_id == ThreatFinding.scan_id
            )
            .group_by(MCPToolExecution.id)
            .all()
        )

        records_checked = len(mcp_actual_counts)
        records_updated = 0
        inconsistencies_found = 0

        for execution_id, actual_count in mcp_actual_counts:
            # Get current stored count
            execution = (
                session.query(MCPToolExecution).filter_by(id=execution_id).first()
            )
            if execution and execution.findings_count != actual_count:
                inconsistencies_found += 1
                logger.debug(
                    f"MCP Tool {execution_id}: stored={execution.findings_count}, actual={actual_count}"
                )
                execution.findings_count = actual_count
                records_updated += 1

        return {
            "table": "MCPToolExecution",
            "records_checked": records_checked,
            "inconsistencies_found": inconsistencies_found,
            "records_updated": records_updated,
        }

    def _fix_cli_command_findings_count(self, session: Session) -> dict[str, Any]:
        """Fix CLI command execution findings_count fields."""
        logger.debug("Fixing CLI command execution findings_count fields")

        # Get actual findings count for each CLI command execution
        # Note: CLI commands don't directly create scan executions in current schema,
        # so we'll check if there are any associated scan executions by matching timing
        cli_actual_counts = (
            session.query(
                CLICommandExecution.id,
                func.coalesce(func.count(ThreatFinding.id), 0).label(
                    "actual_findings_count"
                ),
            )
            .outerjoin(
                ScanEngineExecution,
                # Match CLI commands to scans that happened within 5 seconds
                func.abs(
                    CLICommandExecution.execution_start
                    - ScanEngineExecution.execution_start
                )
                < 5,
            )
            .outerjoin(
                ThreatFinding, ScanEngineExecution.scan_id == ThreatFinding.scan_id
            )
            .group_by(CLICommandExecution.id)
            .all()
        )

        records_checked = len(cli_actual_counts)
        records_updated = 0
        inconsistencies_found = 0

        for execution_id, actual_count in cli_actual_counts:
            # Get current stored count
            execution = (
                session.query(CLICommandExecution).filter_by(id=execution_id).first()
            )
            if execution and execution.findings_count != actual_count:
                inconsistencies_found += 1
                logger.debug(
                    f"CLI Command {execution_id}: stored={execution.findings_count}, actual={actual_count}"
                )
                execution.findings_count = actual_count
                records_updated += 1

        return {
            "table": "CLICommandExecution",
            "records_checked": records_checked,
            "inconsistencies_found": inconsistencies_found,
            "records_updated": records_updated,
        }

    def _fix_scan_engine_threats_found(self, session: Session) -> dict[str, Any]:
        """Fix scan engine execution threats_found fields."""
        logger.debug("Fixing scan engine execution threats_found fields")

        # Get actual threats count for each scan execution
        scan_actual_counts = (
            session.query(
                ScanEngineExecution.scan_id,
                func.count(ThreatFinding.id).label("actual_threats_count"),
            )
            .outerjoin(
                ThreatFinding, ScanEngineExecution.scan_id == ThreatFinding.scan_id
            )
            .group_by(ScanEngineExecution.scan_id)
            .all()
        )

        records_checked = len(scan_actual_counts)
        records_updated = 0
        inconsistencies_found = 0

        for scan_id, actual_count in scan_actual_counts:
            # Get current stored count
            execution = (
                session.query(ScanEngineExecution).filter_by(scan_id=scan_id).first()
            )
            if execution and execution.threats_found != actual_count:
                inconsistencies_found += 1
                logger.debug(
                    f"Scan Engine {scan_id}: stored={execution.threats_found}, actual={actual_count}"
                )
                execution.threats_found = actual_count
                records_updated += 1

        return {
            "table": "ScanEngineExecution",
            "records_checked": records_checked,
            "inconsistencies_found": inconsistencies_found,
            "records_updated": records_updated,
        }

    def validate_data_consistency(self) -> dict[str, Any]:
        """Validate current data consistency across all tables.

        Returns:
            Dict with validation results and any inconsistencies found
        """
        logger.info("Validating data consistency across telemetry tables")

        with self.db.get_session() as session:
            try:
                # Validate MCP tool executions
                mcp_validation = self._validate_mcp_tool_consistency(session)

                # Validate CLI command executions
                cli_validation = self._validate_cli_command_consistency(session)

                # Validate scan engine executions
                scan_validation = self._validate_scan_engine_consistency(session)

                total_inconsistencies = (
                    mcp_validation["inconsistencies_found"]
                    + cli_validation["inconsistencies_found"]
                    + scan_validation["inconsistencies_found"]
                )

                return {
                    "validation_success": True,
                    "total_inconsistencies": total_inconsistencies,
                    "data_consistent": total_inconsistencies == 0,
                    "mcp_tool_validation": mcp_validation,
                    "cli_command_validation": cli_validation,
                    "scan_engine_validation": scan_validation,
                }

            except Exception as e:
                logger.error(f"Data consistency validation failed: {e}")
                return {
                    "validation_success": False,
                    "error": str(e),
                    "data_consistent": False,
                }

    def _validate_mcp_tool_consistency(self, session: Session) -> dict[str, Any]:
        """Validate MCP tool execution findings_count consistency."""
        inconsistent_records = (
            session.query(MCPToolExecution)
            .filter(
                MCPToolExecution.findings_count
                != session.query(func.count(ThreatFinding.id))
                .select_from(ScanEngineExecution)
                .outerjoin(
                    ThreatFinding, ScanEngineExecution.scan_id == ThreatFinding.scan_id
                )
                .filter(ScanEngineExecution.scan_id == MCPToolExecution.session_id)
                .scalar_subquery()
            )
            .all()
        )

        return {
            "table": "MCPToolExecution",
            "records_checked": session.query(MCPToolExecution).count(),
            "inconsistencies_found": len(inconsistent_records),
            "inconsistent_records": [
                {
                    "id": record.id,
                    "tool_name": record.tool_name,
                    "stored_count": record.findings_count,
                }
                for record in inconsistent_records
            ],
        }

    def _validate_cli_command_consistency(self, session: Session) -> dict[str, Any]:
        """Validate CLI command execution findings_count consistency."""
        # Note: CLI validation is more complex due to indirect relationship
        # For now, just check if any CLI commands have non-zero findings_count
        # without corresponding threat findings

        total_records = session.query(CLICommandExecution).count()

        # Simple validation: check for CLI commands with findings_count > 0
        # but no nearby scan executions
        potentially_inconsistent = (
            session.query(CLICommandExecution)
            .filter(CLICommandExecution.findings_count > 0)
            .all()
        )

        return {
            "table": "CLICommandExecution",
            "records_checked": total_records,
            "inconsistencies_found": len(potentially_inconsistent),
            "note": "CLI validation simplified due to indirect relationship with threat findings",
        }

    def _validate_scan_engine_consistency(self, session: Session) -> dict[str, Any]:
        """Validate scan engine execution threats_found consistency."""
        inconsistent_records = (
            session.query(ScanEngineExecution)
            .filter(
                ScanEngineExecution.threats_found
                != session.query(func.count(ThreatFinding.id))
                .filter(ThreatFinding.scan_id == ScanEngineExecution.scan_id)
                .scalar_subquery()
            )
            .all()
        )

        return {
            "table": "ScanEngineExecution",
            "records_checked": session.query(ScanEngineExecution).count(),
            "inconsistencies_found": len(inconsistent_records),
            "inconsistent_records": [
                {
                    "scan_id": record.scan_id,
                    "scan_type": record.scan_type,
                    "stored_count": record.threats_found,
                }
                for record in inconsistent_records
            ],
        }

    def cleanup_orphaned_records(self) -> dict[str, Any]:
        """Clean up orphaned records in the database.

        Returns:
            Dict with cleanup statistics and results
        """
        logger.info("Starting orphaned records cleanup")

        with self.db.get_session() as session:
            try:
                cleanup_results = {
                    "cleanup_success": True,
                    "orphaned_threats_deleted": 0,
                    "stale_executions_marked_failed": 0,
                    "total_records_cleaned": 0,
                }

                # Delete orphaned threat findings
                orphaned_threats = session.query(ThreatFinding).filter(
                    ~ThreatFinding.scan_id.in_(
                        session.query(ScanEngineExecution.scan_id)
                    )
                )

                orphaned_count = orphaned_threats.count()
                if orphaned_count > 0:
                    logger.info(f"Deleting {orphaned_count} orphaned threat findings")
                    orphaned_threats.delete(synchronize_session=False)
                    cleanup_results["orphaned_threats_deleted"] = orphaned_count

                # Commit orphaned records deletion
                session.commit()

                cleanup_results["total_records_cleaned"] = cleanup_results[
                    "orphaned_threats_deleted"
                ]

                logger.info(
                    f"Orphaned records cleanup completed: {cleanup_results['total_records_cleaned']} records cleaned"
                )
                return cleanup_results

            except Exception as e:
                session.rollback()
                logger.error(f"Orphaned records cleanup failed: {e}")
                return {
                    "cleanup_success": False,
                    "error": str(e),
                    "total_records_cleaned": 0,
                }

    def mark_stale_executions_as_failed(self) -> dict[str, Any]:
        """Mark stale/hanging executions as failed.

        Returns:
            Dict with cleanup statistics and results
        """
        logger.info("Starting stale executions cleanup")

        # Define what constitutes "stale" (older than 24 hours without completion)
        stale_threshold = time.time() - (24 * 3600)

        with self.db.get_session() as session:
            try:
                cleanup_results = {
                    "cleanup_success": True,
                    "stale_mcp_executions": 0,
                    "stale_cli_executions": 0,
                    "stale_scan_executions": 0,
                    "total_executions_fixed": 0,
                }

                # Mark stale MCP tool executions as failed
                stale_mcp = session.query(MCPToolExecution).filter(
                    MCPToolExecution.execution_end.is_(None),
                    MCPToolExecution.execution_start < stale_threshold,
                )

                stale_mcp_count = stale_mcp.count()
                if stale_mcp_count > 0:
                    logger.info(
                        f"Marking {stale_mcp_count} stale MCP executions as failed"
                    )
                    stale_mcp.update(
                        {
                            "execution_end": time.time(),
                            "success": False,
                            "error_message": "Marked as failed due to stale execution (no completion after 24h)",
                        }
                    )
                    cleanup_results["stale_mcp_executions"] = stale_mcp_count

                # Mark stale CLI command executions as failed
                stale_cli = session.query(CLICommandExecution).filter(
                    CLICommandExecution.execution_end.is_(None),
                    CLICommandExecution.execution_start < stale_threshold,
                )

                stale_cli_count = stale_cli.count()
                if stale_cli_count > 0:
                    logger.info(
                        f"Marking {stale_cli_count} stale CLI executions as failed"
                    )
                    stale_cli.update(
                        {
                            "execution_end": time.time(),
                            "exit_code": 1,  # Failed exit code
                        }
                    )
                    cleanup_results["stale_cli_executions"] = stale_cli_count

                # Mark stale scan engine executions as failed
                stale_scans = session.query(ScanEngineExecution).filter(
                    ScanEngineExecution.execution_end.is_(None),
                    ScanEngineExecution.execution_start < stale_threshold,
                )

                stale_scans_count = stale_scans.count()
                if stale_scans_count > 0:
                    logger.info(
                        f"Marking {stale_scans_count} stale scan executions as failed"
                    )
                    stale_scans.update(
                        {
                            "execution_end": time.time(),
                            "success": False,
                            "error_message": "Marked as failed due to stale execution (no completion after 24h)",
                        }
                    )
                    cleanup_results["stale_scan_executions"] = stale_scans_count

                # Commit all updates
                session.commit()

                cleanup_results["total_executions_fixed"] = (
                    cleanup_results["stale_mcp_executions"]
                    + cleanup_results["stale_cli_executions"]
                    + cleanup_results["stale_scan_executions"]
                )

                logger.info(
                    f"Stale executions cleanup completed: {cleanup_results['total_executions_fixed']} executions marked as failed"
                )
                return cleanup_results

            except Exception as e:
                session.rollback()
                logger.error(f"Stale executions cleanup failed: {e}")
                return {
                    "cleanup_success": False,
                    "error": str(e),
                    "total_executions_fixed": 0,
                }


def run_data_migration(db_path: str = None) -> dict[str, Any]:
    """Run data migration to fix summary field inconsistencies.

    Args:
        db_path: Optional path to database file. If None, uses default location.

    Returns:
        Dict with migration results
    """
    from pathlib import Path

    # Initialize database
    if db_path:
        db = AdversaryDatabase(Path(db_path))
    else:
        db = AdversaryDatabase()

    # Run migration
    migration_manager = DataMigrationManager(db)
    return migration_manager.fix_summary_field_inconsistencies()


def validate_data_consistency(db_path: str = None) -> dict[str, Any]:
    """Validate data consistency across telemetry tables.

    Args:
        db_path: Optional path to database file. If None, uses default location.

    Returns:
        Dict with validation results
    """
    # Initialize database
    if db_path:
        db = AdversaryDatabase(Path(db_path))
    else:
        db = AdversaryDatabase()

    # Run validation
    migration_manager = DataMigrationManager(db)
    return migration_manager.validate_data_consistency()


def cleanup_orphaned_records(db_path: str = None) -> dict[str, Any]:
    """Clean up orphaned records in the database.

    Args:
        db_path: Optional path to database file. If None, uses default location.

    Returns:
        Dict with cleanup results
    """
    # Initialize database
    if db_path:
        db = AdversaryDatabase(Path(db_path))
    else:
        db = AdversaryDatabase()

    # Run cleanup
    migration_manager = DataMigrationManager(db)
    return migration_manager.cleanup_orphaned_records()


def mark_stale_executions_as_failed(db_path: str = None) -> dict[str, Any]:
    """Mark stale/hanging executions as failed.

    Args:
        db_path: Optional path to database file. If None, uses default location.

    Returns:
        Dict with cleanup results
    """
    # Initialize database
    if db_path:
        db = AdversaryDatabase(Path(db_path))
    else:
        db = AdversaryDatabase()

    # Run cleanup
    migration_manager = DataMigrationManager(db)
    return migration_manager.mark_stale_executions_as_failed()
