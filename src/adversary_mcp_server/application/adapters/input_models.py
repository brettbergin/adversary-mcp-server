"""Input models for scanner adapters to ensure type safety.

This module defines Pydantic models for all external scanner inputs,
eliminating the need for getattr/hasattr calls and providing proper type safety.
"""

from typing import Any

from pydantic import BaseModel, Field, validator

from adversary_mcp_server.scanner.types import Category, Severity


class SemgrepScanResultInput(BaseModel):
    """Input model for Semgrep scanner results."""

    rule_id: str
    rule_name: str
    description: str
    category: str | Category
    severity: str | Severity
    file_path: str
    line_number: int
    column_number: int | None = 0
    code_snippet: str | None = ""
    function_name: str | None = None
    exploit_examples: list[str] | None = Field(default_factory=lambda: [])
    remediation: str | None = ""
    references: list[str] | None = Field(default_factory=lambda: [])
    cwe_id: str | None = None
    owasp_category: str | None = None
    confidence: float | None = 0.8
    source: str | None = "semgrep"
    is_false_positive: bool | None = False

    @validator("severity", pre=True)
    def normalize_severity(cls, v):
        """Normalize severity values from various formats."""
        if hasattr(v, "value"):
            return v.value
        return str(v).lower()

    @validator("category", pre=True)
    def normalize_category(cls, v):
        """Normalize category values from various formats."""
        if hasattr(v, "value"):
            return v.value
        category_str = str(v).lower()
        # Remove 'category.' prefix if present
        return category_str.replace("category.", "")


class LLMScanResultInput(BaseModel):
    """Input model for LLM scanner results."""

    rule_id: str
    rule_name: str
    description: str
    category: str | Category
    severity: str | Severity
    file_path: str
    line_number: int
    column_number: int | None = 0
    code_snippet: str | None = ""
    function_name: str | None = None
    exploit_examples: list[str] | None = Field(default_factory=lambda: [])
    remediation: str | None = ""
    references: list[str] | None = Field(default_factory=lambda: [])
    cwe_id: str | None = None
    owasp_category: str | None = None
    confidence: float | None = 0.75
    source: str | None = "llm"
    is_false_positive: bool | None = False

    @validator("severity", pre=True)
    def normalize_severity(cls, v):
        """Normalize severity values from various formats."""
        if hasattr(v, "value"):
            return v.value
        return str(v).lower()

    @validator("category", pre=True)
    def normalize_category(cls, v):
        """Normalize category values from various formats."""
        if hasattr(v, "value"):
            return v.value
        category_str = str(v).lower()
        # Remove 'category.' prefix if present
        return category_str.replace("category.", "")


class MetadataInput(BaseModel):
    """Input model for scan metadata to avoid getattr calls."""

    scan_type: str | None = "unknown"
    target_info: dict | None = Field(default_factory=lambda: {})
    execution_stats: dict | None = Field(default_factory=lambda: {})

    @validator("target_info", pre=True)
    def ensure_target_info_dict(cls, v):
        """Ensure target_info is always a dict."""
        return v if isinstance(v, dict) else {}

    @validator("execution_stats", pre=True)
    def ensure_execution_stats_dict(cls, v):
        """Ensure execution_stats is always a dict."""
        return v if isinstance(v, dict) else {}


class TelemetryInput(BaseModel):
    """Input model for telemetry data to avoid getattr calls."""

    category: str | None = "unknown"
    severity: str | None = "medium"
    file_path: str | None = ""
    line_start: int | None = 0
    line_end: int | None = 0
    title: str | None = "Security Finding"
    rule_id: str | None = None
    confidence: float | None = None
    column_start: int | None = None
    column_end: int | None = None
    code_snippet: str | None = None
    description: str | None = None
    remediation: str | None = None
    references: list[str] | None = None
    is_validated: bool | None = False
    is_false_positive: bool | None = False
    validation_reason: str | None = None


class ValidationResultInput(BaseModel):
    """Input model for validation results to avoid getattr calls."""

    confidence: float | None = 0.0
    reasoning: str | None = ""
    is_legitimate: bool | None = False
    exploitation_vector: str | None = ""
    remediation_advice: str | None = ""


class CacheStatsInput(BaseModel):
    """Input model for cache statistics."""

    hit_count: int = 0
    miss_count: int = 0
    total_size_bytes: int = 0
    total_entries: int = 0
    error_count: int = 0


def safe_convert_to_input_model(obj: Any, model_class: type[BaseModel]) -> BaseModel:
    """Safely convert an object to a Pydantic input model.

    Args:
        obj: The object to convert (can be dict, dataclass, or any object)
        model_class: The Pydantic model class to convert to

    Returns:
        Instance of the Pydantic model
    """
    if isinstance(obj, dict):
        return model_class(**obj)
    elif hasattr(obj, "__dict__"):
        return model_class(**obj.__dict__)
    else:
        # For objects without __dict__, try to extract fields manually
        data = {}
        for field_name in model_class.__fields__.keys():
            if hasattr(obj, field_name):
                data[field_name] = getattr(obj, field_name)
        return model_class(**data)
