# Database Migration Guide

## Overview

The Adversary MCP Server uses a sophisticated multi-layered database migration system designed to handle different types of data transitions while maintaining data integrity and system reliability.

## Migration Architecture

### 1. Legacy System Migration (`migration/database_migration.py`)

**Purpose**: Migrates from old SQLite files and JSON metrics to the unified telemetry database

**Key Components**:
- `DatabaseMigrationManager` - Main orchestration class
- Automatic backup creation with timestamp
- Legacy SQLite file consolidation
- JSON metrics migration
- Safety checks and rollback capabilities

**When to Use**: 
- Upgrading from older versions with separate SQLite files
- Consolidating scattered metrics data
- Initial system migration

### 2. Data Consistency Migration (`database/migrations.py`)

**Purpose**: Fixes inconsistencies between summary fields and actual threat findings

**Key Components**:
- `DataMigrationManager` - Handles data consistency fixes
- Summary field validation and correction
- Orphaned record cleanup
- Stale execution marking

**When to Use**:
- After system updates that change data relationships
- When summary counts don't match actual records
- Regular maintenance operations

### 3. Database Constraints & Triggers (`database/constraints.py`)

**Purpose**: Prevents future data inconsistencies through application-level constraints

**Key Components**:
- `DatabaseConstraintManager` - Manages constraints and triggers
- SQLAlchemy event listeners
- Automatic count maintenance
- Foreign key validation

**When to Use**:
- After major schema changes
- To prevent future data inconsistencies
- During initial system setup

### 4. Health Monitoring (`database/health_checks.py`)

**Purpose**: Continuous monitoring and validation of database health

**Key Components**:
- `DatabaseHealthChecker` - Comprehensive health validation
- Performance monitoring
- Data integrity checks
- Automated recommendations

**When to Use**:
- Regular system monitoring
- Pre-migration assessment
- Post-migration validation

## Migration Procedures

### Complete System Migration (New Installation)

**Automated Approach (Recommended):**
```bash
# 1. Analyze migration requirements
adversary-mcp-cli migration-analysis

# 2. Run complete migration workflow
adversary-mcp-cli migrate-all --dry-run  # First, see what would be done
adversary-mcp-cli migrate-all            # Execute the migration
```

**Manual Step-by-Step Approach:**
```bash
# 1. Check if migration is needed
adversary-mcp-cli health-check

# 2. Run legacy system migration (if needed)
adversary-mcp-cli migrate-legacy --dry-run  # Preview changes
adversary-mcp-cli migrate-legacy            # Execute migration

# 3. Fix data consistency issues
adversary-mcp-cli migrate-data --dry-run    # Preview changes
adversary-mcp-cli migrate-data              # Execute migration

# 4. Install constraints and triggers (automated in migrate-all)
python -c "from adversary_mcp_server.database.constraints import install_database_constraints; install_database_constraints()"

# 5. Validate final state
adversary-mcp-cli validate-data
adversary-mcp-cli health-check
```

### Data Consistency Fix (Maintenance)

```bash
# 1. Check current data state
adversary-mcp-cli validate-data

# 2. Run data migration
adversary-mcp-cli migrate-data

# 3. Verify fixes
adversary-mcp-cli validate-data
```

### Health Check and Monitoring

```bash
# Migration needs analysis with recommendations
adversary-mcp-cli migration-analysis

# Get automated migration plan
adversary-mcp-cli migration-analysis --automated-plan

# Comprehensive health assessment
adversary-mcp-cli health-check

# Detailed health information
adversary-mcp-cli health-check --detailed

# Data validation only
adversary-mcp-cli validate-data

# Cache and performance status
adversary-mcp-cli status
```

## Migration Safety Features

### Automatic Backups
- All migrations create timestamped backups in `migration_backup_{timestamp}/`
- Backups include both cache and metrics directories
- Backups are preserved until manual cleanup

### Transaction Safety
- All migrations use database transactions
- Automatic rollback on any error
- Session management prevents partial updates

### Validation Loops
- Pre-migration assessment with `check_migration_needed()`
- Post-migration validation with comprehensive checks
- Error recovery with detailed logging

### Progress Tracking
- All migration operations tracked in telemetry
- Detailed statistics and timing information
- Success/failure metrics for monitoring

## Troubleshooting Common Issues

### Migration Fails with "Foreign Key Constraint"
```bash
# Check foreign key status
sqlite3 ~/.local/share/adversary-mcp-server/cache/adversary.db "PRAGMA foreign_keys;"

# Disable temporarily if needed (not recommended)
# Fix root cause with data consistency migration instead
adversary-mcp-cli migrate-data
```

### Summary Counts Don't Match Actual Records
```bash
# Run data consistency migration
adversary-mcp-cli migrate-data

# Check specific inconsistencies
adversary-mcp-cli validate-data
```

### Large Database Performance Issues
```bash
# Check database size and metrics
adversary-mcp-cli health-check

# Clean up old records if recommended
# (This will be automated in future versions)
```

### Orphaned Records Found
```bash
# Run cleanup migration
python -c "
from adversary_mcp_server.database.migrations import cleanup_orphaned_records
print(cleanup_orphaned_records())
"
```

## Best Practices

### Pre-Migration
1. **Always run health check first**: `adversary-mcp-cli health-check`
2. **Check available disk space**: Ensure 2x database size available for backups
3. **Stop active scanning operations**: Prevent data corruption during migration
4. **Review migration logs**: Check for any warnings or previous issues

### During Migration
1. **Monitor progress**: Use `-v` flag for verbose output where available
2. **Don't interrupt**: Allow migrations to complete fully
3. **Watch for errors**: Address any constraint violations immediately
4. **Verify each step**: Run validation after each major migration phase

### Post-Migration
1. **Validate data integrity**: `adversary-mcp-cli validate-data`
2. **Run health check**: `adversary-mcp-cli health-check`
3. **Test system functionality**: Run a small scan to verify operation
4. **Monitor performance**: Check for any degradation in scan times
5. **Schedule regular health checks**: Add to maintenance routine

### Emergency Recovery
If a migration fails catastrophically:

1. **Stop all operations immediately**
2. **Restore from backup**:
   ```bash
   # Find backup directory
   ls ~/.local/share/adversary-mcp-server/cache/migration_backup_*
   
   # Restore from most recent backup
   cp -r migration_backup_*/cache/* ~/.local/share/adversary-mcp-server/cache/
   cp -r migration_backup_*/metrics/* ~/.local/share/adversary-mcp-server/metrics/
   ```
3. **Investigate root cause** before re-attempting
4. **Consider manual data repair** if backups are unavailable

## Migration Monitoring

### Telemetry Integration
All migration operations are automatically tracked:
- Migration start/end times
- Records processed and updated
- Error counts and details
- Performance metrics

### Health Scoring
The system provides automated health assessment:
- **Healthy**: No issues found, system operating normally
- **Fair**: Minor warnings, consider maintenance
- **Warning**: Multiple issues found, schedule maintenance
- **Critical**: Immediate attention required, system may be unstable

### Automated Recommendations
Based on health checks, the system provides specific recommendations:
- Data consistency fixes needed
- Performance optimization suggestions
- Cleanup opportunities
- Constraint installation requirements

## API Reference

### Key Functions

#### Legacy Migration
```python
from adversary_mcp_server.migration.database_migration import DatabaseMigrationManager

manager = DatabaseMigrationManager()
results = manager.run_full_migration(backup=True)
```

#### Data Consistency Migration
```python
from adversary_mcp_server.database.migrations import DataMigrationManager, AdversaryDatabase

db = AdversaryDatabase()
manager = DataMigrationManager(db)
results = manager.fix_summary_field_inconsistencies()
```

#### Health Monitoring
```python
from adversary_mcp_server.database.health_checks import DatabaseHealthChecker, AdversaryDatabase

db = AdversaryDatabase()
checker = DatabaseHealthChecker(db)
health = checker.run_comprehensive_health_check()
```

#### Constraint Management
```python
from adversary_mcp_server.database.constraints import DatabaseConstraintManager, AdversaryDatabase

db = AdversaryDatabase()
manager = DatabaseConstraintManager(db)
results = manager.install_data_consistency_constraints()
```

## Version Compatibility

### Current Version (1.10.4)
- Full multi-layered migration support
- Automatic constraint enforcement
- Comprehensive health monitoring
- CLI integration for all operations

### Upgrade Paths
- **From < 1.9.0**: Run legacy system migration first
- **From 1.9.0-1.10.3**: Run data consistency migration only
- **From 1.10.4+**: Use health-check driven maintenance

## CLI Commands Reference

### Migration Commands

- `adversary-mcp-cli migration-analysis` - Analyze migration needs and get recommendations
- `adversary-mcp-cli migrate-all` - Complete migration workflow with dependency checking  
- `adversary-mcp-cli migrate-legacy` - Migrate legacy SQLite files and JSON metrics
- `adversary-mcp-cli migrate-data` - Fix data consistency issues
- `adversary-mcp-cli validate-data` - Check data integrity
- `adversary-mcp-cli health-check` - Comprehensive health assessment

### Command Options

All migration commands support these options:
- `--dry-run` - Preview changes without making modifications
- `--force` - Skip confirmation prompts
- `--backup/--no-backup` - Control backup creation (default: enabled)
- `--json-output` - Output results in JSON format

### Command Examples

```bash
# Get migration recommendations
adversary-mcp-cli migration-analysis

# Generate automated migration plan
adversary-mcp-cli migration-analysis --automated-plan

# Preview complete migration
adversary-mcp-cli migrate-all --dry-run

# Run complete migration with confirmation
adversary-mcp-cli migrate-all

# Force migration without prompts
adversary-mcp-cli migrate-all --force --no-backup

# Get detailed health information as JSON
adversary-mcp-cli health-check --detailed --json-output

# Preview data consistency fixes
adversary-mcp-cli migrate-data --dry-run

# Preview legacy file migration
adversary-mcp-cli migrate-legacy --dry-run --target-db /custom/path/db.sqlite
```

## Support and Debugging

### Enable Debug Logging
```bash
export ADVERSARY_LOG_LEVEL=DEBUG
adversary-mcp-cli migrate-data
```

### Manual Database Inspection
```bash
sqlite3 ~/.local/share/adversary-mcp-server/cache/adversary.db
.tables
.schema
```

### Common SQL Queries for Debugging
```sql
-- Check summary field consistency
SELECT 
  (SELECT COUNT(*) FROM threat_findings tf WHERE tf.scan_id = se.scan_id) as actual_threats,
  se.threats_found as recorded_threats
FROM scan_executions se 
WHERE actual_threats != recorded_threats;

-- Find orphaned records
SELECT * FROM threat_findings tf 
WHERE NOT EXISTS (
  SELECT 1 FROM scan_executions se WHERE se.scan_id = tf.scan_id
);

-- Check for negative counts
SELECT * FROM scan_executions WHERE threats_found < 0;
SELECT * FROM mcp_tool_executions WHERE findings_count < 0;
```