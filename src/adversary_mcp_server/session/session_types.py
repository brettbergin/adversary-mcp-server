"""Type definitions for LLM session management."""

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..scanner.types import Severity


class SessionState(str, Enum):
    """State of an analysis session."""

    INITIALIZING = "initializing"
    CONTEXT_LOADING = "context_loading"
    READY = "ready"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class SecurityFinding:
    """Enhanced security finding with session context."""

    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    rule_name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    file_path: str = ""
    line_number: int = 1
    code_snippet: str = ""
    confidence: float = 0.5
    session_context: dict[str, Any] = field(default_factory=dict)
    cross_file_references: list[str] = field(default_factory=list)
    architectural_context: str = ""
    remediation_advice: str = ""

    def to_threat_match(self):
        """Convert to domain ThreatMatch with session metadata."""
        from ..domain.entities.threat_match import ThreatMatch as DomainThreatMatch

        # Provide fallback for empty file path and description
        file_path = self.file_path if self.file_path else "unknown_file"
        description = (
            self.description if self.description else "Security finding detected"
        )

        return DomainThreatMatch.create_llm_threat(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=description,
            category="misc",  # Could be enhanced based on finding type
            severity=(
                self.severity.value
                if hasattr(self.severity, "value")
                else str(self.severity)
            ),
            file_path=file_path,
            line_number=self.line_number,
            confidence=self.confidence,
            code_snippet=self.code_snippet,
        ).add_metadata(
            {
                "cross_file_references": self.cross_file_references,
                "architectural_context": self.architectural_context,
                "session_context": self.session_context,
                "remediation_advice": self.remediation_advice,
            }
        )


@dataclass
class ConversationMessage:
    """A message in the LLM conversation."""

    role: str  # "system", "user", "assistant"
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API calls."""
        return {
            "role": self.role,
            "content": self.content,
        }


@dataclass
class AnalysisSession:
    """Represents a stateful LLM analysis session."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: SessionState = SessionState.INITIALIZING
    messages: list[ConversationMessage] = field(default_factory=list)
    project_root: Path | None = None
    project_context: dict[str, Any] = field(default_factory=dict)
    findings: list[SecurityFinding] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_message(
        self, role: str, content: str, metadata: dict[str, Any] | None = None
    ) -> None:
        """Add a message to the conversation."""
        message = ConversationMessage(
            role=role, content=content, metadata=metadata or {}
        )
        self.messages.append(message)
        self.last_activity = time.time()

    def get_conversation_history(self) -> list[dict[str, Any]]:
        """Get conversation history for LLM API calls."""
        return [msg.to_dict() for msg in self.messages]

    def is_expired(self, max_age_seconds: int = 3600) -> bool:
        """Check if session has expired."""
        return (time.time() - self.last_activity) > max_age_seconds

    def update_state(self, new_state: SessionState) -> None:
        """Update session state and activity timestamp."""
        self.state = new_state
        self.last_activity = time.time()

    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a security finding to the session."""
        finding.session_context["session_id"] = self.session_id
        self.findings.append(finding)
        self.last_activity = time.time()
