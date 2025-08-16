"""SeverityLevel value object with comparison and ordering logic."""

from dataclasses import dataclass
from enum import IntEnum


class SeverityValue(IntEnum):
    """Numeric values for severity levels to enable ordering."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class SeverityLevel:
    """
    Value object representing security vulnerability severity with rich comparison logic.

    Provides ordering, threshold checking, and business logic around severity levels
    while maintaining immutability and validation.
    """

    value: SeverityValue

    # Class constants for common severity levels
    LOW = None
    MEDIUM = None
    HIGH = None
    CRITICAL = None

    @classmethod
    def from_string(cls, severity_str: str) -> "SeverityLevel":
        """Create SeverityLevel from string representation."""
        if not severity_str or not isinstance(severity_str, str):
            raise ValueError("Severity string cannot be empty")

        severity_map = {
            "low": SeverityValue.LOW,
            "medium": SeverityValue.MEDIUM,
            "high": SeverityValue.HIGH,
            "critical": SeverityValue.CRITICAL,
        }

        normalized = severity_str.lower().strip()
        if normalized not in severity_map:
            raise ValueError(
                f"Invalid severity level: {severity_str}. Must be one of: {list(severity_map.keys())}"
            )

        return cls(severity_map[normalized])

    @classmethod
    def from_numeric(cls, numeric_value: int) -> "SeverityLevel":
        """Create SeverityLevel from numeric value (1-4)."""
        try:
            return cls(SeverityValue(numeric_value))
        except ValueError:
            raise ValueError(
                f"Invalid numeric severity: {numeric_value}. Must be 1-4 (LOW-CRITICAL)"
            )

    def __str__(self) -> str:
        """String representation of severity level."""
        return self.value.name.lower()

    def __repr__(self) -> str:
        """Detailed representation for debugging."""
        return f"SeverityLevel({self.value.name})"

    def __eq__(self, other: object) -> bool:
        """Check equality with another SeverityLevel."""
        if not isinstance(other, SeverityLevel):
            return False
        return self.value == other.value

    def __lt__(self, other: "SeverityLevel") -> bool:
        """Check if this severity is less than another."""
        if not isinstance(other, SeverityLevel):
            raise TypeError(f"Cannot compare SeverityLevel with {type(other)}")
        return self.value < other.value

    def __le__(self, other: "SeverityLevel") -> bool:
        """Check if this severity is less than or equal to another."""
        if not isinstance(other, SeverityLevel):
            raise TypeError(f"Cannot compare SeverityLevel with {type(other)}")
        return self.value <= other.value

    def __gt__(self, other: "SeverityLevel") -> bool:
        """Check if this severity is greater than another."""
        if not isinstance(other, SeverityLevel):
            raise TypeError(f"Cannot compare SeverityLevel with {type(other)}")
        return self.value > other.value

    def __ge__(self, other: "SeverityLevel") -> bool:
        """Check if this severity is greater than or equal to another."""
        if not isinstance(other, SeverityLevel):
            raise TypeError(f"Cannot compare SeverityLevel with {type(other)}")
        return self.value >= other.value

    def __hash__(self) -> int:
        """Hash function for use in sets and dictionaries."""
        return hash(self.value)

    def meets_threshold(self, threshold: "SeverityLevel") -> bool:
        """Check if this severity meets or exceeds the given threshold."""
        return self >= threshold

    def is_low(self) -> bool:
        """Check if this is a low severity."""
        return self.value == SeverityValue.LOW

    def is_medium(self) -> bool:
        """Check if this is a medium severity."""
        return self.value == SeverityValue.MEDIUM

    def is_high(self) -> bool:
        """Check if this is a high severity."""
        return self.value == SeverityValue.HIGH

    def is_critical(self) -> bool:
        """Check if this is a critical severity."""
        return self.value == SeverityValue.CRITICAL

    def is_actionable(self) -> bool:
        """Check if this severity level requires immediate action (HIGH or CRITICAL)."""
        return self.value >= SeverityValue.HIGH

    def get_numeric_value(self) -> int:
        """Get the numeric value of this severity level."""
        return self.value.value

    def get_display_name(self) -> str:
        """Get user-friendly display name."""
        return self.value.name.title()

    def get_priority_weight(self) -> float:
        """Get weight for priority calculations (0.0-1.0)."""
        weights = {
            SeverityValue.LOW: 0.25,
            SeverityValue.MEDIUM: 0.50,
            SeverityValue.HIGH: 0.75,
            SeverityValue.CRITICAL: 1.0,
        }
        return weights[self.value]

    def escalate(self) -> "SeverityLevel":
        """Return next higher severity level, or self if already CRITICAL."""
        if self.value == SeverityValue.CRITICAL:
            return self  # Already at maximum severity

        next_value = SeverityValue(self.value.value + 1)
        return SeverityLevel(next_value)

    def deescalate(self) -> "SeverityLevel":
        """Return next lower severity level, or self if already LOW."""
        if self.value == SeverityValue.LOW:
            return self  # Already at minimum severity

        prev_value = SeverityValue(self.value.value - 1)
        return SeverityLevel(prev_value)

    @classmethod
    def get_all_levels(cls) -> list["SeverityLevel"]:
        """Get all severity levels in order from LOW to CRITICAL."""
        return [
            cls(SeverityValue.LOW),
            cls(SeverityValue.MEDIUM),
            cls(SeverityValue.HIGH),
            cls(SeverityValue.CRITICAL),
        ]

    @classmethod
    def get_default_threshold(cls) -> "SeverityLevel":
        """Get the default severity threshold for scanning."""
        return cls(SeverityValue.MEDIUM)


# Initialize class constants
SeverityLevel.LOW = SeverityLevel(SeverityValue.LOW)
SeverityLevel.MEDIUM = SeverityLevel(SeverityValue.MEDIUM)
SeverityLevel.HIGH = SeverityLevel(SeverityValue.HIGH)
SeverityLevel.CRITICAL = SeverityLevel(SeverityValue.CRITICAL)
