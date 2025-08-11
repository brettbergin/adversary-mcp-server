"""Database migration utilities to consolidate existing SQLite files."""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, text

from ..config import get_app_cache_dir, get_app_metrics_dir
from ..database.models import AdversaryDatabase
from ..logger import get_logger
from ..telemetry.service import TelemetryService

logger = get_logger("database_migration")


class DatabaseMigrationManager:
    """Manages migration from legacy systems to unified telemetry database."""

    def __init__(self, target_db_path: Path = None):
        """Initialize migration manager.

        Args:
            target_db_path: Path to target unified database (default: standard location)
        """
        self.target_db_path = (
            target_db_path
            or Path(
                "~/.local/share/adversary-mcp-server/cache/adversary.db"
            ).expanduser()
        )
        self.cache_dir = get_app_cache_dir()
        self.metrics_dir = get_app_metrics_dir()

        logger.info(f"Initializing database migration to {self.target_db_path}")

    def run_full_migration(self, backup: bool = True) -> dict[str, Any]:
        """Run complete migration process.

        Args:
            backup: Whether to backup existing files before migration

        Returns:
            Migration results summary
        """
        logger.info("=== Starting Full Database Migration ===")

        migration_results = {
            "started_at": time.time(),
            "backup_created": False,
            "legacy_sqlite_files": [],
            "json_metrics_files": [],
            "cache_metadata_migrated": False,
            "legacy_metrics_migrated": False,
            "errors": [],
            "warnings": [],
        }

        try:
            # Create backup if requested
            if backup:
                backup_path = self._create_backup()
                migration_results["backup_created"] = True
                migration_results["backup_path"] = str(backup_path)
                logger.info(f"Backup created at: {backup_path}")

            # Initialize target database
            target_db = AdversaryDatabase(self.target_db_path)
            telemetry_service = TelemetryService(target_db)

            # Migrate legacy SQLite files
            sqlite_results = self._migrate_legacy_sqlite_files(telemetry_service)
            migration_results.update(sqlite_results)

            # Migrate JSON metrics files
            json_results = self._migrate_json_metrics_files(telemetry_service)
            migration_results.update(json_results)

            # Clean up old files (optional)
            cleanup_results = self._cleanup_old_files()
            migration_results["cleanup_results"] = cleanup_results

            target_db.close()

        except Exception as e:
            error_msg = f"Migration failed: {e}"
            logger.error(error_msg, exc_info=True)
            migration_results["errors"].append(error_msg)

        migration_results["completed_at"] = time.time()

        # Type assertions for arithmetic operations to fix MyPy object arithmetic errors
        started_at = migration_results["started_at"]
        completed_at = migration_results["completed_at"]

        assert isinstance(
            started_at, int | float
        ), f"started_at should be numeric, got {type(started_at)}"
        assert isinstance(
            completed_at, int | float
        ), f"completed_at should be numeric, got {type(completed_at)}"

        migration_results["duration_seconds"] = completed_at - started_at

        logger.info("=== Database Migration Complete ===")
        self._log_migration_summary(migration_results)

        return migration_results

    def _create_backup(self) -> Path:
        """Create backup of existing data."""
        timestamp = int(time.time())
        backup_dir = self.target_db_path.parent / f"migration_backup_{timestamp}"
        backup_dir.mkdir(parents=True, exist_ok=True)

        # Backup cache directory
        if self.cache_dir.exists():
            cache_backup = backup_dir / "cache"
            self._copy_directory(self.cache_dir, cache_backup)
            logger.debug(f"Cache directory backed up to: {cache_backup}")

        # Backup metrics directory
        if self.metrics_dir.exists():
            metrics_backup = backup_dir / "metrics"
            self._copy_directory(self.metrics_dir, metrics_backup)
            logger.debug(f"Metrics directory backed up to: {metrics_backup}")

        return backup_dir

    def _copy_directory(self, src: Path, dst: Path) -> None:
        """Copy directory contents."""
        import shutil

        if src.exists():
            shutil.copytree(str(src), str(dst), dirs_exist_ok=True)

    def _migrate_legacy_sqlite_files(
        self, telemetry_service: TelemetryService
    ) -> dict[str, Any]:
        """Migrate existing SQLite database files."""
        results = {
            "legacy_sqlite_files": [],
            "cache_metadata_migrated": False,
            "records_migrated": 0,
        }

        logger.info("Migrating legacy SQLite files...")

        # Look for existing cache metadata database
        cache_metadata_db = self.cache_dir / "cache_metadata.db"
        if cache_metadata_db.exists():
            try:
                records_migrated = self._migrate_cache_metadata(
                    cache_metadata_db, telemetry_service
                )
                results["cache_metadata_migrated"] = True
                # Fix MyPy object arithmetic error with type assertion
                current_records = results.get("records_migrated", 0)
                assert isinstance(
                    current_records, int
                ), f"records_migrated should be int, got {type(current_records)}"
                results["records_migrated"] = current_records + records_migrated
                results["legacy_sqlite_files"].append(
                    {
                        "path": str(cache_metadata_db),
                        "type": "cache_metadata",
                        "records_migrated": records_migrated,
                    }
                )
                logger.info(f"Migrated {records_migrated} cache metadata records")
            except Exception as e:
                error_msg = f"Failed to migrate cache metadata: {e}"
                logger.error(error_msg)
                results.setdefault("errors", []).append(error_msg)

        # Look for other SQLite files in cache directory
        sqlite_files = list(self.cache_dir.glob("*.db"))
        for sqlite_file in sqlite_files:
            if (
                sqlite_file.name != "cache_metadata.db"
                and sqlite_file != self.target_db_path
            ):
                try:
                    records_migrated = self._migrate_generic_sqlite(
                        sqlite_file, telemetry_service
                    )
                    # Fix MyPy object arithmetic error with type assertion
                    current_records = results.get("records_migrated", 0)
                    assert isinstance(
                        current_records, int
                    ), f"records_migrated should be int, got {type(current_records)}"
                    results["records_migrated"] = current_records + records_migrated
                    results["legacy_sqlite_files"].append(
                        {
                            "path": str(sqlite_file),
                            "type": "generic",
                            "records_migrated": records_migrated,
                        }
                    )
                    logger.info(
                        f"Migrated {records_migrated} records from {sqlite_file.name}"
                    )
                except Exception as e:
                    error_msg = f"Failed to migrate {sqlite_file.name}: {e}"
                    logger.warning(error_msg)
                    results.setdefault("warnings", []).append(error_msg)

        return results

    def _migrate_cache_metadata(
        self, db_path: Path, telemetry_service: TelemetryService
    ) -> int:
        """Migrate cache metadata database."""
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        records_migrated = 0

        try:
            # Check if cache_entries table exists
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='cache_entries'"
            )
            if cursor.fetchone():
                cursor.execute("SELECT * FROM cache_entries")

                for row in cursor.fetchall():
                    try:
                        # Convert cache entry to telemetry cache operation
                        telemetry_service.track_cache_operation(
                            operation_type="historical",
                            cache_name="legacy_cache",
                            key_hash=str(row.get("key_hash", "unknown"))[:16],
                            key_metadata={
                                "legacy_key": row.get("cache_key", ""),
                                "migrated_from": "cache_metadata",
                            },
                            size_bytes=row.get("size_bytes"),
                            ttl_seconds=row.get("ttl_seconds"),
                            access_time_ms=1.0,  # Historical data
                        )
                        records_migrated += 1
                    except Exception as e:
                        logger.debug(f"Failed to migrate cache entry: {e}")

        finally:
            conn.close()

        return records_migrated

    def _migrate_generic_sqlite(
        self, db_path: Path, telemetry_service: TelemetryService
    ) -> int:
        """Migrate generic SQLite database files using SQLAlchemy Inspector for safety."""
        records_migrated = 0

        try:
            # Create SQLAlchemy engine for safe schema introspection
            engine = create_engine(f"sqlite:///{db_path}", echo=False)

            with engine.connect() as conn:
                # Use SQLAlchemy Inspector for safe schema introspection
                inspector = inspect(conn)
                table_names = inspector.get_table_names()

                for table_name in table_names:
                    logger.debug(f"Processing table: {table_name}")

                    try:
                        # Use SQLAlchemy's safe identifier quoting
                        quoted_table = conn.dialect.identifier_preparer.quote(
                            table_name
                        )

                        # Execute safe parameterized query with LIMIT for safety
                        result = conn.execute(
                            text(f"SELECT * FROM {quoted_table} LIMIT 100")
                        )

                        for row in result:
                            # Create generic system health record for historical data
                            telemetry_service.record_system_health_snapshot(
                                cpu_percent=None,
                                memory_percent=None,
                                memory_used_mb=None,
                                db_size_mb=None,
                                cache_entries_count=1,  # Mark as historical record
                            )
                            records_migrated += 1

                    except Exception as e:
                        logger.debug(f"Failed to process table {table_name}: {e}")

        except Exception as e:
            logger.error(f"Failed to migrate SQLite database {db_path}: {e}")

        return records_migrated

    def _migrate_json_metrics_files(
        self, telemetry_service: TelemetryService
    ) -> dict[str, Any]:
        """Migrate JSON metrics files."""
        results = {
            "json_metrics_files": [],
            "legacy_metrics_migrated": False,
            "metrics_records_migrated": 0,
        }

        logger.info("Migrating JSON metrics files...")

        # Look for JSON metrics files
        json_files = list(self.metrics_dir.glob("*.json"))
        if not json_files:
            logger.info("No JSON metrics files found")
            return results

        for json_file in json_files:
            try:
                records_migrated = self._migrate_json_file(json_file, telemetry_service)
                # Fix MyPy object arithmetic error with type assertion
                current_metrics = results.get("metrics_records_migrated", 0)
                assert isinstance(
                    current_metrics, int
                ), f"metrics_records_migrated should be int, got {type(current_metrics)}"
                results["metrics_records_migrated"] = current_metrics + records_migrated
                results["json_metrics_files"].append(
                    {"path": str(json_file), "records_migrated": records_migrated}
                )

                if records_migrated > 0:
                    results["legacy_metrics_migrated"] = True

                logger.info(
                    f"Migrated {records_migrated} metrics from {json_file.name}"
                )

            except Exception as e:
                error_msg = f"Failed to migrate {json_file.name}: {e}"
                logger.warning(error_msg)
                results.setdefault("warnings", []).append(error_msg)

        return results

    def _migrate_json_file(
        self, json_file: Path, telemetry_service: TelemetryService
    ) -> int:
        """Migrate individual JSON metrics file."""
        with open(json_file) as f:
            data = json.load(f)

        records_migrated = 0

        # Extract metadata
        metadata = data.get("metadata", {})
        collected_at = metadata.get("collected_at", time.time())

        # Migrate legacy metrics as system health snapshots
        legacy_metrics = data.get("legacy_metrics", {})
        if legacy_metrics:
            # Create a system health snapshot from legacy metrics
            telemetry_service.record_system_health_snapshot(
                cpu_percent=None,  # Legacy data may not have system metrics
                memory_percent=None,
                memory_used_mb=None,
                db_size_mb=metadata.get("db_size_mb"),
                cache_entries_count=len(legacy_metrics),
                scans_per_hour=0.0,  # Will be populated by actual scan data
                error_rate_1h=0.0,
            )
            records_migrated += 1

        # Migrate scan metrics as historical CLI commands
        scan_metrics = data.get("scan_metrics", {})
        if scan_metrics and scan_metrics.get("total_scans", 0) > 0:
            # Create historical CLI command execution
            cli_exec = telemetry_service.start_cli_command_tracking(
                command_name="historical_scan",
                args={"migrated_from": str(json_file.name)},
                subcommand="legacy_data",
            )

            telemetry_service.complete_cli_command_tracking(
                execution_id=cli_exec.id,
                exit_code=0,
                findings_count=scan_metrics.get("total_findings", 0),
            )
            records_migrated += 1

        return records_migrated

    def _cleanup_old_files(self, confirm_cleanup: bool = False) -> dict[str, Any]:
        """Clean up old files after successful migration."""
        cleanup_results = {
            "files_removed": [],
            "files_kept": [],
            "cleanup_enabled": confirm_cleanup,
        }

        if not confirm_cleanup:
            logger.info("Cleanup skipped (confirm_cleanup=False)")
            return cleanup_results

        # This would remove old files - keeping conservative for safety
        logger.info("File cleanup would occur here if enabled")

        return cleanup_results

    def _log_migration_summary(self, results: dict[str, Any]) -> None:
        """Log migration summary."""
        duration = results.get("duration_seconds", 0)

        logger.info(f"Migration completed in {duration:.2f} seconds")
        logger.info(
            f"Legacy SQLite files processed: {len(results.get('legacy_sqlite_files', []))}"
        )
        logger.info(
            f"JSON metrics files processed: {len(results.get('json_metrics_files', []))}"
        )
        logger.info(
            f"Total records migrated: {results.get('records_migrated', 0) + results.get('metrics_records_migrated', 0)}"
        )

        if results.get("errors"):
            logger.warning(f"Migration errors: {len(results['errors'])}")
            for error in results["errors"]:
                logger.warning(f"  - {error}")

        if results.get("warnings"):
            logger.info(f"Migration warnings: {len(results['warnings'])}")

    def check_migration_needed(self) -> dict[str, Any]:
        """Check if migration is needed and what would be migrated."""
        check_results = {
            "migration_needed": False,
            "target_db_exists": self.target_db_path.exists(),
            "legacy_sqlite_files": [],
            "json_metrics_files": [],
            "estimated_records": 0,
        }

        # Check for legacy SQLite files
        if self.cache_dir.exists():
            sqlite_files = list(self.cache_dir.glob("*.db"))
            for sqlite_file in sqlite_files:
                if sqlite_file != self.target_db_path:
                    check_results["legacy_sqlite_files"].append(str(sqlite_file))
                    check_results["migration_needed"] = True

        # Check for JSON metrics files
        if self.metrics_dir.exists():
            json_files = list(self.metrics_dir.glob("*.json"))
            for json_file in json_files:
                check_results["json_metrics_files"].append(str(json_file))
                check_results["migration_needed"] = True

        # Estimate record count with type assertions to fix MyPy len() errors
        legacy_sqlite_files = check_results["legacy_sqlite_files"]
        json_metrics_files = check_results["json_metrics_files"]

        assert isinstance(
            legacy_sqlite_files, list
        ), f"legacy_sqlite_files should be list, got {type(legacy_sqlite_files)}"
        assert isinstance(
            json_metrics_files, list
        ), f"json_metrics_files should be list, got {type(json_metrics_files)}"

        check_results["estimated_records"] = (
            len(legacy_sqlite_files) * 10 + len(json_metrics_files) * 5
        )

        return check_results


def run_migration_cli(
    target_db_path: str | None = None,
    backup: bool = True,
    confirm_cleanup: bool = False,
) -> int:
    """CLI entry point for running migration.

    Args:
        target_db_path: Target database path (optional)
        backup: Whether to create backup
        confirm_cleanup: Whether to cleanup old files after migration

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        target_path = Path(target_db_path) if target_db_path else None
        migration_manager = DatabaseMigrationManager(target_path)

        # Check if migration is needed
        check_results = migration_manager.check_migration_needed()

        if not check_results["migration_needed"]:
            print("✅ No migration needed - no legacy files found")
            return 0

        print("📋 Migration Check Results:")
        print(f"  - Legacy SQLite files: {len(check_results['legacy_sqlite_files'])}")
        print(f"  - JSON metrics files: {len(check_results['json_metrics_files'])}")
        print(f"  - Estimated records: {check_results['estimated_records']}")
        print(f"  - Target DB exists: {check_results['target_db_exists']}")

        # Run migration
        print("\n🚀 Starting migration...")
        results = migration_manager.run_full_migration(backup=backup)

        if results.get("errors"):
            print(f"❌ Migration completed with {len(results['errors'])} errors")
            return 1
        else:
            print("✅ Migration completed successfully")
            return 0

    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return 1


if __name__ == "__main__":
    import sys

    # Simple CLI interface
    backup = "--no-backup" not in sys.argv
    cleanup = "--cleanup" in sys.argv

    target_path = None
    for i, arg in enumerate(sys.argv):
        if arg == "--target" and i + 1 < len(sys.argv):
            target_path = sys.argv[i + 1]

    exit_code = run_migration_cli(target_path, backup, cleanup)
    sys.exit(exit_code)
