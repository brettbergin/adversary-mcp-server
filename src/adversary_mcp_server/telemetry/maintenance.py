"""Database maintenance utilities for telemetry system optimization."""

import time
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from ..logger import get_logger

logger = get_logger("telemetry.maintenance")


class DatabaseMaintenanceManager:
    """Manager for database maintenance and optimization operations."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.engine = None
        self.SessionLocal = None
        if self.db_path.exists():
            self._initialize_engine()

    def run_maintenance(self, operations: list[str] | None = None) -> dict[str, Any]:
        """Run comprehensive database maintenance."""
        operations = operations or [
            "analyze",
            "vacuum",
            "integrity_check",
            "index_check",
        ]

        results = {
            "started_at": time.time(),
            "operations": {},
            "database_size_before": 0,
            "database_size_after": 0,
            "maintenance_duration": 0,
        }

        # Get initial database size
        if self.db_path.exists():
            results["database_size_before"] = self.db_path.stat().st_size

        logger.info(f"Starting database maintenance on {self.db_path}")

        # Run each maintenance operation
        for operation in operations:
            try:
                if operation == "analyze":
                    results["operations"]["analyze"] = self._run_analyze()
                elif operation == "vacuum":
                    results["operations"]["vacuum"] = self._run_vacuum()
                elif operation == "integrity_check":
                    results["operations"][
                        "integrity_check"
                    ] = self._run_integrity_check()
                elif operation == "index_check":
                    results["operations"]["index_check"] = self._check_indexes()
                elif operation == "cleanup":
                    results["operations"]["cleanup"] = self._cleanup_old_data()
                else:
                    logger.warning(f"Unknown maintenance operation: {operation}")

            except Exception as e:
                logger.error(f"Failed to run {operation}: {e}")
                results["operations"][operation] = {"success": False, "error": str(e)}

        # Get final database size
        if self.db_path.exists():
            results["database_size_after"] = self.db_path.stat().st_size

        results["completed_at"] = time.time()

        # Type assertions for arithmetic operations to fix MyPy object arithmetic errors
        started_at = results["started_at"]
        completed_at = results["completed_at"]
        size_before = results["database_size_before"]
        size_after = results["database_size_after"]

        assert isinstance(
            started_at, int | float
        ), f"started_at should be numeric, got {type(started_at)}"
        assert isinstance(
            completed_at, int | float
        ), f"completed_at should be numeric, got {type(completed_at)}"
        assert isinstance(
            size_before, int
        ), f"size_before should be int, got {type(size_before)}"
        assert isinstance(
            size_after, int
        ), f"size_after should be int, got {type(size_after)}"

        results["maintenance_duration"] = completed_at - started_at
        results["size_reduction_bytes"] = size_before - size_after
        results["size_reduction_percent"] = (
            ((size_before - size_after) / size_before) * 100 if size_before > 0 else 0
        )

        logger.info(
            f"Database maintenance completed in {results['maintenance_duration']:.2f}s"
        )
        logger.info(
            f"Size change: {results['size_reduction_bytes']} bytes ({results['size_reduction_percent']:.1f}%)"
        )

        return results

    def _initialize_engine(self) -> None:
        """Initialize SQLAlchemy engine for the database."""
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=False,
            connect_args={"check_same_thread": False},
        )
        self.SessionLocal = sessionmaker(bind=self.engine)

    def _run_analyze(self) -> dict[str, Any]:
        """Update database statistics for query optimization."""
        start_time = time.time()

        if not self.engine:
            return {
                "success": False,
                "error": "Database engine not initialized",
                "duration": 0,
                "tables_analyzed": 0,
            }

        try:
            with self.engine.connect() as conn:
                # Run global ANALYZE first
                conn.execute(text("ANALYZE"))

                # Use SQLAlchemy Inspector for safe schema introspection
                inspector = inspect(conn)
                table_names = inspector.get_table_names()

                # Analyze each table using safe identifier quoting
                valid_tables = []
                for table_name in table_names:
                    try:
                        # Use SQLAlchemy's built-in identifier quoting for safety
                        quoted_table = conn.dialect.identifier_preparer.quote(
                            table_name
                        )
                        conn.execute(text(f"ANALYZE {quoted_table}"))
                        valid_tables.append(table_name)
                    except Exception as e:
                        # Skip problematic tables but continue with others
                        logger.debug(f"Failed to analyze table {table_name}: {e}")
                        continue

                conn.commit()

            duration = time.time() - start_time
            return {
                "success": True,
                "duration": duration,
                "tables_analyzed": len(valid_tables),
                "description": "Updated query planner statistics",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "duration": time.time() - start_time,
                "tables_analyzed": 0,
            }

    def _run_vacuum(self) -> dict[str, Any]:
        """Reclaim unused space and defragment database."""
        start_time = time.time()

        if not self.engine:
            return {
                "success": False,
                "error": "Database engine not initialized",
                "duration": 0,
            }

        size_before = self.db_path.stat().st_size if self.db_path.exists() else 0

        try:
            with self.engine.connect() as conn:
                # Full vacuum to reclaim space
                conn.execute(text("VACUUM"))
                conn.commit()

            size_after = self.db_path.stat().st_size if self.db_path.exists() else 0
            duration = time.time() - start_time
            space_reclaimed = size_before - size_after

            return {
                "success": True,
                "duration": duration,
                "size_before_bytes": size_before,
                "size_after_bytes": size_after,
                "space_reclaimed_bytes": space_reclaimed,
                "space_reclaimed_percent": (
                    (space_reclaimed / size_before * 100) if size_before > 0 else 0
                ),
                "description": "Reclaimed unused space and defragmented database",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "duration": time.time() - start_time,
            }

    def _run_integrity_check(self) -> dict[str, Any]:
        """Check database integrity."""
        start_time = time.time()

        if not self.engine:
            return {
                "success": False,
                "error": "Database engine not initialized",
                "duration": 0,
            }

        try:
            with self.engine.connect() as conn:
                # Quick integrity check
                quick_result = conn.execute(text("PRAGMA quick_check"))
                quick_check_result = quick_result.fetchone()[0]

                issues = []
                if quick_check_result != "ok":
                    # Run full integrity check if quick check fails
                    integrity_result = conn.execute(text("PRAGMA integrity_check"))
                    integrity_results = integrity_result.fetchall()
                    issues = [row[0] for row in integrity_results if row[0] != "ok"]

            duration = time.time() - start_time
            return {
                "success": len(issues) == 0,
                "duration": duration,
                "quick_check_result": quick_check_result,
                "issues_found": len(issues),
                "issues": issues[:10],  # Limit to first 10 issues
                "description": f'Database integrity check {"passed" if len(issues) == 0 else "failed"}',
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "duration": time.time() - start_time,
                "issues_found": 0,
                "issues": [],
            }

    def _check_indexes(self) -> dict[str, Any]:
        """Check and analyze database indexes."""
        start_time = time.time()

        if not self.engine:
            return {
                "success": False,
                "error": "Database engine not initialized",
                "duration": 0,
            }

        try:
            with self.engine.connect() as conn:
                # Use SQLAlchemy Inspector for safe schema introspection
                inspector = inspect(conn)
                table_names = inspector.get_table_names()

                index_stats = []
                for table_name in table_names:
                    try:
                        # Get indexes for this table using Inspector
                        table_indexes = inspector.get_indexes(table_name)

                        for index_info in table_indexes:
                            index_name = index_info["name"]

                            # Get index usage statistics (approximation)
                            quoted_table = conn.dialect.identifier_preparer.quote(
                                table_name
                            )
                            plan_result = conn.execute(
                                text(f"EXPLAIN QUERY PLAN SELECT * FROM {quoted_table}")
                            )
                            query_plan = plan_result.fetchall()

                            uses_index = any(
                                "USING INDEX" in str(step) for step in query_plan
                            )

                            index_stats.append(
                                {
                                    "name": index_name,
                                    "table": table_name,
                                    "columns": index_info["column_names"],
                                    "unique": index_info["unique"],
                                    "appears_used": uses_index,
                                }
                            )
                    except Exception as e:
                        # Skip problematic tables but continue with others
                        logger.debug(
                            f"Failed to check indexes for table {table_name}: {e}"
                        )
                        continue

            duration = time.time() - start_time
            total_indexes = len(index_stats)
            used_indexes = sum(1 for idx in index_stats if idx["appears_used"])

            return {
                "success": True,
                "duration": duration,
                "total_indexes": total_indexes,
                "used_indexes": used_indexes,
                "unused_indexes": total_indexes - used_indexes,
                "index_details": index_stats,
                "description": f"Analyzed {total_indexes} indexes, {used_indexes} appear to be used",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "duration": time.time() - start_time,
            }

    def _cleanup_old_data(self, days_to_keep: int = 90) -> dict[str, Any]:
        """Clean up old telemetry data."""
        start_time = time.time()
        cutoff_timestamp = time.time() - (days_to_keep * 24 * 3600)

        tables_to_clean = [
            ("mcp_tool_executions", "execution_start"),
            ("cli_command_executions", "execution_start"),
            ("cache_operation_metrics", "timestamp"),
            ("scan_executions", "execution_start"),
            ("threat_findings", "timestamp"),
            ("system_health", "timestamp"),
        ]

        cleanup_results = {}
        total_deleted = 0

        if not self.engine:
            return {
                "success": False,
                "error": "Database engine not initialized",
                "duration": 0,
                "total_records_deleted": 0,
            }

        try:
            with self.engine.connect() as conn:
                inspector = inspect(conn)
                existing_tables = inspector.get_table_names()

                for table_name, timestamp_column in tables_to_clean:
                    try:
                        # Check if table exists using Inspector
                        if table_name not in existing_tables:
                            cleanup_results[table_name] = {
                                "records_deleted": 0,
                                "success": True,
                            }
                            continue

                        # Use quoted identifiers for safety
                        quoted_table = conn.dialect.identifier_preparer.quote(
                            table_name
                        )
                        quoted_column = conn.dialect.identifier_preparer.quote(
                            timestamp_column
                        )

                        # Count records to be deleted
                        count_result = conn.execute(
                            text(
                                f"SELECT COUNT(*) FROM {quoted_table} WHERE {quoted_column} < :cutoff"
                            ),
                            {"cutoff": cutoff_timestamp},
                        )
                        count_to_delete = count_result.fetchone()[0]

                        if count_to_delete > 0:
                            # Delete old records
                            conn.execute(
                                text(
                                    f"DELETE FROM {quoted_table} WHERE {quoted_column} < :cutoff"
                                ),
                                {"cutoff": cutoff_timestamp},
                            )

                        cleanup_results[table_name] = {
                            "records_deleted": count_to_delete,
                            "success": True,
                        }
                        total_deleted += count_to_delete

                    except Exception as e:
                        cleanup_results[table_name] = {
                            "records_deleted": 0,
                            "success": False,
                            "error": str(e),
                        }

                conn.commit()

            duration = time.time() - start_time
            return {
                "success": True,
                "duration": duration,
                "total_records_deleted": total_deleted,
                "cutoff_days": days_to_keep,
                "cutoff_timestamp": cutoff_timestamp,
                "table_results": cleanup_results,
                "description": f"Cleaned up {total_deleted} old records older than {days_to_keep} days",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "duration": time.time() - start_time,
                "total_records_deleted": 0,
            }

    # Removed _get_connection method - now using SQLAlchemy engine directly

    def get_database_info(self) -> dict[str, Any]:
        """Get comprehensive database information."""
        if not self.db_path.exists():
            return {"exists": False}

        info = {
            "exists": True,
            "path": str(self.db_path),
            "size_bytes": self.db_path.stat().st_size,
            "size_mb": self.db_path.stat().st_size / (1024 * 1024),
            "modified_time": self.db_path.stat().st_mtime,
        }

        try:
            if not self.engine:
                self._initialize_engine()

            with self.engine.connect() as conn:
                # Get SQLite version and settings
                result = conn.execute(text("SELECT sqlite_version()"))
                info["sqlite_version"] = result.fetchone()[0]

                # Get pragma settings
                pragmas = [
                    "page_size",
                    "cache_size",
                    "synchronous",
                    "journal_mode",
                    "temp_store",
                    "locking_mode",
                    "auto_vacuum",
                ]

                info["settings"] = {}
                for pragma in pragmas:
                    # PRAGMA commands are safe system commands
                    pragma_result = conn.execute(text(f"PRAGMA {pragma}"))
                    pragma_row = pragma_result.fetchone()
                    info["settings"][pragma] = pragma_row[0] if pragma_row else None

                # Get table information using Inspector
                inspector = inspect(conn)
                table_names = inspector.get_table_names()

                info["tables"] = {}
                for table_name in table_names:
                    try:
                        # Get table columns for additional info
                        columns = inspector.get_columns(table_name)

                        # Get row count safely
                        quoted_table = conn.dialect.identifier_preparer.quote(
                            table_name
                        )
                        count_result = conn.execute(
                            text(f"SELECT COUNT(*) FROM {quoted_table}")
                        )
                        row_count = count_result.fetchone()[0]

                        info["tables"][table_name] = {
                            "row_count": row_count,
                            "column_count": len(columns),
                            "columns": [col["name"] for col in columns],
                        }
                    except Exception as e:
                        # Skip problematic tables but continue with others
                        logger.debug(f"Failed to get info for table {table_name}: {e}")
                        continue

                info["total_records"] = sum(
                    t["row_count"] for t in info["tables"].values()
                )

                # Get index information using Inspector
                total_indexes = 0
                for table_name in table_names:
                    try:
                        table_indexes = inspector.get_indexes(table_name)
                        total_indexes += len(table_indexes)
                    except Exception as e:
                        logger.debug(
                            f"Failed to get indexes for table {table_name}: {e}"
                        )
                        continue

                info["index_count"] = total_indexes

        except Exception as e:
            info["error"] = str(e)

        return info


def run_database_maintenance(
    db_path: Path = None, operations: list[str] = None
) -> dict[str, Any]:
    """Run database maintenance operations."""
    if db_path is None:
        db_path = Path.home() / ".local/share/adversary-mcp-server/cache/adversary.db"

    manager = DatabaseMaintenanceManager(db_path)
    return manager.run_maintenance(operations)


def get_maintenance_recommendations(db_info: dict[str, Any]) -> list[str]:
    """Get maintenance recommendations based on database info."""
    recommendations = []

    # Check if database info indicates failure
    if db_info.get("success") is False:
        return []  # No recommendations for failed database info

    # Only check exists if it's explicitly set to False
    if db_info.get("exists") is False:
        return ["Database does not exist"]

    # Size-based recommendations
    size_mb = db_info.get("size_mb", 0)
    # Also check file_size_bytes for different test data formats
    file_size_bytes = db_info.get("file_size_bytes", 0)
    if file_size_bytes > 0:
        size_mb = file_size_bytes / (1024 * 1024)

    if size_mb > 100:
        recommendations.append(
            "Database is large (>100MB) - consider running VACUUM to reclaim space"
        )

    # Record count recommendations - support multiple data formats
    total_records = db_info.get("total_records", 0)
    total_rows = db_info.get("total_rows", 0)
    if total_rows > 0:
        total_records = total_rows

    if total_records > 100000:
        recommendations.append(
            "High record count (>100k) - consider cleanup of old data"
        )

    # Index analysis recommendations
    table_count = db_info.get("table_count", len(db_info.get("tables", {})))
    index_count = db_info.get("index_count", 0)

    # Recommend index analysis if few indexes relative to tables
    if table_count > 5 and index_count < (table_count * 0.5):
        recommendations.append(
            "Few indexes relative to table count - consider index analysis"
        )

    # Settings recommendations
    settings = db_info.get("settings", {})
    if settings.get("auto_vacuum") == 0:
        recommendations.append(
            "Auto-vacuum disabled - consider enabling or running manual VACUUM"
        )

    if settings.get("synchronous") == 2:  # FULL
        recommendations.append(
            "Synchronous mode is FULL - consider NORMAL for better performance"
        )

    if not recommendations:
        recommendations.append("Database appears to be in good condition")

    return recommendations
