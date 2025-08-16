"""ScanType enumeration for different types of security scans."""

from enum import Enum


class ScanType(Enum):
    """Enumeration of supported scan types."""

    FILE = "file"
    DIRECTORY = "directory"
    CODE = "code"
    DIFF = "diff"

    def __str__(self) -> str:
        """Return the string value of the scan type."""
        return self.value

    @classmethod
    def from_string(cls, value: str) -> "ScanType":
        """Create ScanType from string value."""
        for scan_type in cls:
            if scan_type.value == value.lower():
                return scan_type
        raise ValueError(f"Invalid scan type: {value}")

    def is_file_based(self) -> bool:
        """Check if this scan type operates on files."""
        return self in (ScanType.FILE, ScanType.DIRECTORY, ScanType.DIFF)

    def is_content_based(self) -> bool:
        """Check if this scan type operates on code content."""
        return self == ScanType.CODE

    def requires_file_system(self) -> bool:
        """Check if this scan type requires file system access."""
        return self != ScanType.CODE
