"""SQLAlchemy ORM models for comprehensive telemetry and monitoring."""

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker
from sqlalchemy.types import VARCHAR, TypeDecorator


class Base(DeclarativeBase):
    """SQLAlchemy declarative base class."""

    pass


class JSONType(TypeDecorator):
    """SQLAlchemy type for storing JSON data."""

    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value


# === COMPREHENSIVE TELEMETRY MODELS ===


class CacheEntry(Base):
    """SQLAlchemy ORM model for cache entries."""

    __tablename__ = "cache_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(255), unique=True, nullable=False, index=True)
    cache_type = Column(String(50), nullable=False, index=True)
    content_hash = Column(String(64), nullable=False, index=True)
    data_size_bytes = Column(Integer, nullable=False)
    access_count = Column(Integer, nullable=False, default=0)
    last_accessed = Column(Float, nullable=False, index=True)
    created_at = Column(Float, nullable=False, index=True)
    expires_at = Column(Float, nullable=True, index=True)
    cache_metadata = Column(
        JSONType, nullable=True
    )  # Renamed to avoid reserved 'metadata' attribute

    __table_args__ = (
        Index("idx_cache_type_accessed", "cache_type", "last_accessed"),
        Index("idx_expires_at", "expires_at"),
    )

    def __repr__(self):
        return f"<CacheEntry(key={self.key}, type={self.cache_type})>"


class MCPToolExecution(Base):
    """Track all MCP tool executions and performance."""

    __tablename__ = "mcp_tool_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_name = Column(
        String(100), nullable=False, index=True
    )  # 'adv_scan_file', 'adv_scan_folder', etc.
    session_id = Column(String(36), nullable=False, index=True)  # Track user sessions
    request_params = Column(JSONType, nullable=False)  # Tool parameters
    execution_start = Column(Float, nullable=False, index=True)
    execution_end = Column(Float, nullable=True)
    success = Column(Boolean, nullable=False, default=True, index=True)
    error_message = Column(Text, nullable=True)
    findings_count = Column(Integer, nullable=False, default=0)
    validation_enabled = Column(Boolean, nullable=False, default=False)
    llm_enabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_tool_session_time", "tool_name", "session_id", "execution_start"),
        Index("idx_success_time", "success", "execution_start"),
    )

    def __repr__(self):
        return f"<MCPToolExecution(tool={self.tool_name}, success={self.success})>"


class CLICommandExecution(Base):
    """Track all CLI command executions and performance."""

    __tablename__ = "cli_command_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    command_name = Column(
        String(100), nullable=False, index=True
    )  # 'scan', 'configure', 'status'
    subcommand = Column(
        String(100), nullable=True, index=True
    )  # file path or directory
    args = Column(JSONType, nullable=False)  # Command line arguments
    execution_start = Column(Float, nullable=False, index=True)
    execution_end = Column(Float, nullable=True)
    exit_code = Column(Integer, nullable=False, default=0, index=True)
    stdout_lines = Column(Integer, nullable=False, default=0)
    stderr_lines = Column(Integer, nullable=False, default=0)
    findings_count = Column(Integer, nullable=False, default=0)
    validation_enabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_command_exit_time", "command_name", "exit_code", "execution_start"),
        Index("idx_subcommand_time", "subcommand", "execution_start"),
    )

    def __repr__(self):
        return f"<CLICommandExecution(command={self.command_name}, exit_code={self.exit_code})>"


class CacheOperationMetric(Base):
    """Comprehensive cache operation tracking."""

    __tablename__ = "cache_operations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    operation_type = Column(
        String(20), nullable=False, index=True
    )  # 'hit', 'miss', 'set', 'evict', 'cleanup'
    cache_name = Column(
        String(50), nullable=False, index=True
    )  # 'scan_results', 'semgrep_cache', 'llm_analysis'
    key_hash = Column(String(64), nullable=False, index=True)
    key_metadata = Column(JSONType, nullable=True)  # File path, language, etc.
    size_bytes = Column(Integer, nullable=True)
    ttl_seconds = Column(Integer, nullable=True)
    access_time_ms = Column(Float, nullable=True)  # Time to retrieve/store
    eviction_reason = Column(
        String(50), nullable=True
    )  # 'ttl_expired', 'lru', 'manual'
    timestamp = Column(Float, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_cache_operation_type", "cache_name", "operation_type"),
        Index("idx_cache_timestamp", "cache_name", "timestamp"),
    )

    def __repr__(self):
        return (
            f"<CacheOperationMetric(cache={self.cache_name}, op={self.operation_type})>"
        )


class ScanEngineExecution(Base):
    """Detailed scan engine execution tracking."""

    __tablename__ = "scan_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)
    trigger_source = Column(
        String(20), nullable=False, index=True
    )  # 'mcp_tool', 'cli', 'api'
    scan_type = Column(
        String(20), nullable=False, index=True
    )  # 'file', 'directory', 'code', 'diff'
    target_path = Column(Text, nullable=False)
    file_count = Column(Integer, nullable=False, default=1)
    language_detected = Column(String(50), nullable=True, index=True)
    file_size_bytes = Column(Integer, nullable=True)

    # Timing breakdown
    total_duration_ms = Column(Float, nullable=True)
    semgrep_duration_ms = Column(Float, nullable=True)
    llm_duration_ms = Column(Float, nullable=True)
    validation_duration_ms = Column(Float, nullable=True)
    cache_lookup_ms = Column(Float, nullable=True)

    # Results
    threats_found = Column(Integer, nullable=False, default=0)
    threats_validated = Column(Integer, nullable=False, default=0)
    false_positives_filtered = Column(Integer, nullable=False, default=0)
    cache_hit = Column(Boolean, nullable=False, default=False, index=True)

    # Configuration
    semgrep_enabled = Column(Boolean, nullable=False, default=True)
    llm_enabled = Column(Boolean, nullable=False, default=False)
    validation_enabled = Column(Boolean, nullable=False, default=False)

    execution_start = Column(Float, nullable=False, index=True)
    execution_end = Column(Float, nullable=True)
    success = Column(Boolean, nullable=False, default=True, index=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_scan_source_type", "trigger_source", "scan_type"),
        Index("idx_scan_language_time", "language_detected", "execution_start"),
        Index("idx_scan_success_time", "success", "execution_start"),
    )

    def __repr__(self):
        return f"<ScanEngineExecution(scan_id={self.scan_id}, type={self.scan_type})>"


class ThreatFinding(Base):
    """Individual threat findings with full context."""

    __tablename__ = "threat_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(
        String(36), ForeignKey("scan_executions.scan_id"), nullable=False, index=True
    )
    finding_uuid = Column(String(36), unique=True, nullable=False, index=True)

    # Detection details
    scanner_source = Column(String(20), nullable=False, index=True)  # 'semgrep', 'llm'
    rule_id = Column(String(100), nullable=True, index=True)
    category = Column(
        String(50), nullable=False, index=True
    )  # 'injection', 'xss', 'crypto', etc.
    severity = Column(
        String(20), nullable=False, index=True
    )  # 'low', 'medium', 'high', 'critical'
    confidence = Column(Float, nullable=True)  # 0.0-1.0 for validation confidence

    # Location details
    file_path = Column(Text, nullable=False)
    line_start = Column(Integer, nullable=False)
    line_end = Column(Integer, nullable=False)
    column_start = Column(Integer, nullable=True)
    column_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)

    # Finding details
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    references = Column(JSONType, nullable=True)  # CWE, OWASP references

    # Validation and false positive tracking
    is_validated = Column(Boolean, nullable=False, default=False, index=True)
    is_false_positive = Column(Boolean, nullable=False, default=False, index=True)
    validation_reason = Column(Text, nullable=True)
    marked_by = Column(String(100), nullable=True)

    timestamp = Column(Float, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    # Relationship
    scan_execution = relationship("ScanEngineExecution", backref="findings")

    __table_args__ = (
        Index("idx_finding_category_severity", "category", "severity"),
        Index("idx_finding_scanner_validation", "scanner_source", "is_validated"),
        Index("idx_finding_file_line", "file_path", "line_start"),
    )

    def __repr__(self):
        return f"<ThreatFinding(uuid={self.finding_uuid}, category={self.category})>"


class SystemHealth(Base):
    """System health and performance snapshots."""

    __tablename__ = "system_health"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)

    # System metrics
    cpu_percent = Column(Float, nullable=True)
    memory_percent = Column(Float, nullable=True)
    memory_used_mb = Column(Float, nullable=True)
    disk_usage_percent = Column(Float, nullable=True)

    # Database metrics
    db_size_mb = Column(Float, nullable=True)
    db_connections = Column(Integer, nullable=True)

    # Cache metrics
    cache_size_mb = Column(Float, nullable=True)
    cache_hit_rate_1h = Column(Float, nullable=True)
    cache_entries_count = Column(Integer, nullable=True)

    # Performance metrics
    avg_scan_duration_1h = Column(Float, nullable=True)
    scans_per_hour = Column(Float, nullable=True)
    error_rate_1h = Column(Float, nullable=True)

    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (Index("idx_health_timestamp", "timestamp"),)

    def __repr__(self):
        return f"<SystemHealth(timestamp={self.timestamp})>"


class LLMAnalysisSession(Base):
    """Persistent storage for LLM analysis sessions."""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), nullable=False, unique=True, index=True)

    # Session metadata
    state = Column(String(20), nullable=False, index=True)
    created_at = Column(Float, nullable=False, index=True)
    last_activity = Column(Float, nullable=False, index=True)

    # Session data (JSON serialized)
    session_data = Column(Text, nullable=False)

    # Optimization indexes
    __table_args__ = (
        Index("idx_session_activity", "last_activity"),
        Index("idx_session_state", "state"),
        Index("idx_session_created", "created_at"),
    )

    def __repr__(self):
        return f"<LLMAnalysisSession(session_id={self.session_id}, state={self.state})>"


# === UNIFIED DATABASE ===


class AdversaryDatabase:
    """Consolidated SQLAlchemy database for all telemetry and metrics."""

    def __init__(
        self,
        db_path: Path = Path("~/.local/share/adversary-mcp-server/cache/adversary.db"),
    ):
        self.db_path = db_path.expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create SQLAlchemy engine with optimizations
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=False,  # Set to True for SQL debugging
            pool_pre_ping=True,
            connect_args={
                "check_same_thread": False,
                "timeout": 30,
                "isolation_level": None,
            },
        )

        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=True, bind=self.engine
        )

        # Create all tables
        Base.metadata.create_all(bind=self.engine)

        # Set secure database file permissions (owner read/write only)
        if self.db_path.exists():
            import os

            os.chmod(self.db_path, 0o600)

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    def close(self):
        """Close database connections."""
        self.engine.dispose()
