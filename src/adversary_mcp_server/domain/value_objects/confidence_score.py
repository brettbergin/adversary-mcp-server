"""ConfidenceScore value object with threshold operations."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfidenceScore:
    """
    Value object representing a confidence score with validation and threshold operations.

    Used throughout the system to represent confidence levels for validation results,
    threat detections, and other probabilistic assessments. Provides rich comparison
    logic and threshold checking operations.
    """

    value: float

    # Class constants for common confidence levels
    VERY_LOW = None  # 0.2
    LOW = None  # 0.4
    MEDIUM = None  # 0.6
    HIGH = None  # 0.8
    VERY_HIGH = None  # 0.9
    CERTAIN = None  # 1.0

    def __post_init__(self):
        """Validate confidence score range after initialization."""
        if not isinstance(self.value, int | float):
            raise TypeError(f"Confidence score must be numeric, got {type(self.value)}")

        if not (0.0 <= self.value <= 1.0):
            raise ValueError(
                f"Confidence score must be between 0.0 and 1.0, got {self.value}"
            )

    @classmethod
    def from_percentage(cls, percentage: int | float) -> "ConfidenceScore":
        """Create ConfidenceScore from percentage (0-100)."""
        if not isinstance(percentage, int | float):
            raise TypeError(f"Percentage must be numeric, got {type(percentage)}")

        if not (0 <= percentage <= 100):
            raise ValueError(f"Percentage must be between 0 and 100, got {percentage}")

        return cls(percentage / 100.0)

    @classmethod
    def from_ratio(cls, correct: int, total: int) -> "ConfidenceScore":
        """Create ConfidenceScore from success ratio."""
        if not isinstance(correct, int) or not isinstance(total, int):
            raise TypeError("Both correct and total must be integers")

        if correct < 0 or total <= 0:
            raise ValueError("Correct must be non-negative and total must be positive")

        if correct > total:
            raise ValueError("Correct count cannot exceed total count")

        return cls(correct / total)

    @classmethod
    def certain(cls) -> "ConfidenceScore":
        """Create a confidence score representing absolute certainty."""
        return cls(1.0)

    @classmethod
    def uncertain(cls) -> "ConfidenceScore":
        """Create a confidence score representing complete uncertainty."""
        return cls(0.0)

    @classmethod
    def default_threshold(cls) -> "ConfidenceScore":
        """Get the default confidence threshold for validation."""
        return cls(0.7)  # 70% confidence threshold

    def __str__(self) -> str:
        """String representation as percentage."""
        return f"{self.value * 100:.1f}%"

    def __repr__(self) -> str:
        """Detailed representation for debugging."""
        return f"ConfidenceScore({self.value})"

    def __eq__(self, other: object) -> bool:
        """Check equality with another ConfidenceScore."""
        if not isinstance(other, ConfidenceScore):
            return False
        return abs(self.value - other.value) < 1e-9  # Float comparison with tolerance

    def __lt__(self, other: "ConfidenceScore") -> bool:
        """Check if this confidence is less than another."""
        if not isinstance(other, ConfidenceScore):
            raise TypeError(f"Cannot compare ConfidenceScore with {type(other)}")
        return self.value < other.value

    def __le__(self, other: "ConfidenceScore") -> bool:
        """Check if this confidence is less than or equal to another."""
        if not isinstance(other, ConfidenceScore):
            raise TypeError(f"Cannot compare ConfidenceScore with {type(other)}")
        return self.value <= other.value

    def __gt__(self, other: "ConfidenceScore") -> bool:
        """Check if this confidence is greater than another."""
        if not isinstance(other, ConfidenceScore):
            raise TypeError(f"Cannot compare ConfidenceScore with {type(other)}")
        return self.value > other.value

    def __ge__(self, other: "ConfidenceScore") -> bool:
        """Check if this confidence is greater than or equal to another."""
        if not isinstance(other, ConfidenceScore):
            raise TypeError(f"Cannot compare ConfidenceScore with {type(other)}")
        return self.value >= other.value

    def __hash__(self) -> int:
        """Hash function for use in sets and dictionaries."""
        return hash(
            round(self.value, 9)
        )  # Round to avoid floating point precision issues

    def meets_threshold(self, threshold: "ConfidenceScore") -> bool:
        """Check if this confidence meets or exceeds the given threshold."""
        return self >= threshold

    def fails_threshold(self, threshold: "ConfidenceScore") -> bool:
        """Check if this confidence fails to meet the given threshold."""
        return self < threshold

    def is_very_low(self) -> bool:
        """Check if this is very low confidence (< 0.3)."""
        return self.value < 0.3

    def is_low(self) -> bool:
        """Check if this is low confidence (0.3 <= x < 0.5)."""
        return 0.3 <= self.value < 0.5

    def is_medium(self) -> bool:
        """Check if this is medium confidence (0.5 <= x < 0.7)."""
        return 0.5 <= self.value < 0.7

    def is_high(self) -> bool:
        """Check if this is high confidence (0.7 <= x < 0.9)."""
        return 0.7 <= self.value < 0.9

    def is_very_high(self) -> bool:
        """Check if this is very high confidence (>= 0.9)."""
        return self.value >= 0.9

    def is_actionable(self) -> bool:
        """Check if this confidence level is high enough to take action."""
        return self.meets_threshold(ConfidenceScore.default_threshold())

    def is_certain(self) -> bool:
        """Check if this represents absolute certainty."""
        return abs(self.value - 1.0) < 1e-9

    def is_uncertain(self) -> bool:
        """Check if this represents complete uncertainty."""
        return abs(self.value) < 1e-9

    def get_percentage(self) -> float:
        """Get confidence as percentage (0.0-100.0)."""
        return self.value * 100.0

    def get_decimal(self) -> float:
        """Get confidence as decimal (0.0-1.0)."""
        return self.value

    def get_quality_level(self) -> str:
        """Get human-readable quality level."""
        if self.is_very_low():
            return "Very Low"
        elif self.is_low():
            return "Low"
        elif self.is_medium():
            return "Medium"
        elif self.is_high():
            return "High"
        elif self.is_very_high():
            return "Very High"
        else:
            return "Unknown"

    def invert(self) -> "ConfidenceScore":
        """Get the inverse confidence score (1.0 - value)."""
        return ConfidenceScore(1.0 - self.value)

    def adjust(self, factor: float) -> "ConfidenceScore":
        """Adjust confidence by a multiplicative factor, clamped to [0.0, 1.0]."""
        if not isinstance(factor, int | float):
            raise TypeError(f"Adjustment factor must be numeric, got {type(factor)}")

        if factor < 0:
            raise ValueError(f"Adjustment factor cannot be negative, got {factor}")

        new_value = min(1.0, max(0.0, self.value * factor))
        return ConfidenceScore(new_value)

    def boost(self, amount: float) -> "ConfidenceScore":
        """Boost confidence by adding amount, clamped to [0.0, 1.0]."""
        if not isinstance(amount, int | float):
            raise TypeError(f"Boost amount must be numeric, got {type(amount)}")

        new_value = min(1.0, max(0.0, self.value + amount))
        return ConfidenceScore(new_value)

    def penalize(self, amount: float) -> "ConfidenceScore":
        """Penalize confidence by subtracting amount, clamped to [0.0, 1.0]."""
        if not isinstance(amount, int | float):
            raise TypeError(f"Penalty amount must be numeric, got {type(amount)}")

        if amount < 0:
            raise ValueError(f"Penalty amount cannot be negative, got {amount}")

        new_value = min(1.0, max(0.0, self.value - amount))
        return ConfidenceScore(new_value)

    def combine_with(
        self, other: "ConfidenceScore", weight: float = 0.5
    ) -> "ConfidenceScore":
        """Combine this confidence with another using weighted average."""
        if not isinstance(other, ConfidenceScore):
            raise TypeError(f"Cannot combine with {type(other)}")

        if not isinstance(weight, int | float):
            raise TypeError(f"Weight must be numeric, got {type(weight)}")

        if not (0.0 <= weight <= 1.0):
            raise ValueError(f"Weight must be between 0.0 and 1.0, got {weight}")

        combined_value = (self.value * weight) + (other.value * (1.0 - weight))
        return ConfidenceScore(combined_value)

    @classmethod
    def aggregate(
        cls, scores: list["ConfidenceScore"], method: str = "average"
    ) -> "ConfidenceScore":
        """Aggregate multiple confidence scores using specified method."""
        if not scores:
            raise ValueError("Cannot aggregate empty list of scores")

        if not all(isinstance(score, ConfidenceScore) for score in scores):
            raise TypeError("All items must be ConfidenceScore instances")

        values = [score.value for score in scores]

        if method == "average":
            result = sum(values) / len(values)
        elif method == "min":
            result = min(values)
        elif method == "max":
            result = max(values)
        elif method == "median":
            sorted_values = sorted(values)
            n = len(sorted_values)
            if n % 2 == 0:
                result = (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
            else:
                result = sorted_values[n // 2]
        else:
            raise ValueError(f"Unknown aggregation method: {method}")

        return cls(result)


# Initialize class constants
ConfidenceScore.VERY_LOW = ConfidenceScore(0.2)
ConfidenceScore.LOW = ConfidenceScore(0.4)
ConfidenceScore.MEDIUM = ConfidenceScore(0.6)
ConfidenceScore.HIGH = ConfidenceScore(0.8)
ConfidenceScore.VERY_HIGH = ConfidenceScore(0.9)
ConfidenceScore.CERTAIN = ConfidenceScore(1.0)
