"""Domain value objects package.

Value objects are immutable objects that represent concepts without identity.
They encapsulate validation rules and provide behavior related to their data.
"""

from .confidence_score import ConfidenceScore
from .false_positive_info import FalsePositiveInfo
from .file_path import FilePath
from .scan_context import ScanContext
from .scan_metadata import ScanMetadata
from .scan_type import ScanType
from .severity_level import SeverityLevel

__all__ = [
    "ConfidenceScore",
    "FalsePositiveInfo",
    "FilePath",
    "ScanContext",
    "ScanMetadata",
    "ScanType",
    "SeverityLevel",
]
