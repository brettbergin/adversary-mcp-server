"""Comprehensive tests for ConfidenceScore value object to achieve 100% coverage."""

import pytest

from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore


class TestConfidenceScoreInitialization:
    """Test ConfidenceScore initialization and validation."""

    def test_valid_initialization(self):
        """Test creating ConfidenceScore with valid values."""
        score = ConfidenceScore(0.5)
        assert score.value == 0.5

        score = ConfidenceScore(0.0)
        assert score.value == 0.0

        score = ConfidenceScore(1.0)
        assert score.value == 1.0

    def test_initialization_with_int(self):
        """Test creating ConfidenceScore with integer values."""
        score = ConfidenceScore(0)
        assert score.value == 0.0

        score = ConfidenceScore(1)
        assert score.value == 1.0

    def test_invalid_type_initialization(self):
        """Test that invalid types raise TypeError."""
        with pytest.raises(TypeError, match="Confidence score must be numeric"):
            ConfidenceScore("0.5")

        with pytest.raises(TypeError, match="Confidence score must be numeric"):
            ConfidenceScore(None)

        with pytest.raises(TypeError, match="Confidence score must be numeric"):
            ConfidenceScore([0.5])

    def test_out_of_range_initialization(self):
        """Test that out-of-range values raise ValueError."""
        with pytest.raises(
            ValueError, match="Confidence score must be between 0.0 and 1.0"
        ):
            ConfidenceScore(-0.1)

        with pytest.raises(
            ValueError, match="Confidence score must be between 0.0 and 1.0"
        ):
            ConfidenceScore(1.1)

        with pytest.raises(
            ValueError, match="Confidence score must be between 0.0 and 1.0"
        ):
            ConfidenceScore(2.0)

    def test_frozen_dataclass(self):
        """Test that ConfidenceScore is immutable."""
        score = ConfidenceScore(0.5)
        with pytest.raises(AttributeError):
            score.value = 0.8


class TestConfidenceScoreClassMethods:
    """Test ConfidenceScore class methods and factory methods."""

    def test_from_percentage_valid(self):
        """Test creating ConfidenceScore from valid percentages."""
        score = ConfidenceScore.from_percentage(50)
        assert score.value == 0.5

        score = ConfidenceScore.from_percentage(0)
        assert score.value == 0.0

        score = ConfidenceScore.from_percentage(100)
        assert score.value == 1.0

        score = ConfidenceScore.from_percentage(75.5)
        assert score.value == 0.755

    def test_from_percentage_invalid_type(self):
        """Test from_percentage with invalid types."""
        with pytest.raises(TypeError, match="Percentage must be numeric"):
            ConfidenceScore.from_percentage("50")

        with pytest.raises(TypeError, match="Percentage must be numeric"):
            ConfidenceScore.from_percentage(None)

    def test_from_percentage_out_of_range(self):
        """Test from_percentage with out-of-range values."""
        with pytest.raises(ValueError, match="Percentage must be between 0 and 100"):
            ConfidenceScore.from_percentage(-10)

        with pytest.raises(ValueError, match="Percentage must be between 0 and 100"):
            ConfidenceScore.from_percentage(110)

    def test_from_ratio_valid(self):
        """Test creating ConfidenceScore from valid ratios."""
        score = ConfidenceScore.from_ratio(1, 2)
        assert score.value == 0.5

        score = ConfidenceScore.from_ratio(0, 1)
        assert score.value == 0.0

        score = ConfidenceScore.from_ratio(10, 10)
        assert score.value == 1.0

        score = ConfidenceScore.from_ratio(3, 4)
        assert score.value == 0.75

    def test_from_ratio_invalid_type(self):
        """Test from_ratio with invalid types."""
        with pytest.raises(TypeError, match="Both correct and total must be integers"):
            ConfidenceScore.from_ratio(1.5, 2)

        with pytest.raises(TypeError, match="Both correct and total must be integers"):
            ConfidenceScore.from_ratio(1, 2.0)

        with pytest.raises(TypeError, match="Both correct and total must be integers"):
            ConfidenceScore.from_ratio("1", 2)

    def test_from_ratio_invalid_values(self):
        """Test from_ratio with invalid values."""
        with pytest.raises(
            ValueError, match="Correct must be non-negative and total must be positive"
        ):
            ConfidenceScore.from_ratio(-1, 2)

        with pytest.raises(
            ValueError, match="Correct must be non-negative and total must be positive"
        ):
            ConfidenceScore.from_ratio(1, 0)

        with pytest.raises(
            ValueError, match="Correct must be non-negative and total must be positive"
        ):
            ConfidenceScore.from_ratio(1, -1)

        with pytest.raises(ValueError, match="Correct count cannot exceed total count"):
            ConfidenceScore.from_ratio(5, 3)

    def test_certain_factory(self):
        """Test certain() factory method."""
        score = ConfidenceScore.certain()
        assert score.value == 1.0
        assert score.is_certain()

    def test_uncertain_factory(self):
        """Test uncertain() factory method."""
        score = ConfidenceScore.uncertain()
        assert score.value == 0.0
        assert score.is_uncertain()

    def test_default_threshold_factory(self):
        """Test default_threshold() factory method."""
        threshold = ConfidenceScore.default_threshold()
        assert threshold.value == 0.7


class TestConfidenceScoreComparison:
    """Test ConfidenceScore comparison operations."""

    def test_equality(self):
        """Test equality comparison."""
        score1 = ConfidenceScore(0.5)
        score2 = ConfidenceScore(0.5)
        score3 = ConfidenceScore(0.6)

        assert score1 == score2
        assert score1 != score3
        assert not (score1 == score3)

    def test_equality_with_float_tolerance(self):
        """Test equality with floating point tolerance."""
        score1 = ConfidenceScore(0.1 + 0.2)  # 0.30000000000000004
        score2 = ConfidenceScore(0.3)

        # Should be equal due to tolerance
        assert score1 == score2

    def test_equality_with_other_types(self):
        """Test equality with non-ConfidenceScore objects."""
        score = ConfidenceScore(0.5)
        assert score != 0.5
        assert score != "0.5"
        assert score is not None

    def test_less_than(self):
        """Test less than comparison."""
        low = ConfidenceScore(0.3)
        high = ConfidenceScore(0.7)

        assert low < high
        assert not (high < low)
        assert not (low < low)

    def test_less_than_invalid_type(self):
        """Test less than with invalid types."""
        score = ConfidenceScore(0.5)
        with pytest.raises(TypeError, match="Cannot compare ConfidenceScore with"):
            assert score < 0.5

        with pytest.raises(TypeError, match="Cannot compare ConfidenceScore with"):
            assert score < "0.5"

    def test_less_equal(self):
        """Test less than or equal comparison."""
        low = ConfidenceScore(0.3)
        high = ConfidenceScore(0.7)
        equal = ConfidenceScore(0.3)

        assert low <= high
        assert low <= equal
        assert not (high <= low)

    def test_less_equal_invalid_type(self):
        """Test less than or equal with invalid types."""
        score = ConfidenceScore(0.5)
        with pytest.raises(TypeError, match="Cannot compare ConfidenceScore with"):
            assert score <= 0.5

    def test_greater_than(self):
        """Test greater than comparison."""
        low = ConfidenceScore(0.3)
        high = ConfidenceScore(0.7)

        assert high > low
        assert not (low > high)
        assert not (low > low)

    def test_greater_than_invalid_type(self):
        """Test greater than with invalid types."""
        score = ConfidenceScore(0.5)
        with pytest.raises(TypeError, match="Cannot compare ConfidenceScore with"):
            assert score > 0.5

    def test_greater_equal(self):
        """Test greater than or equal comparison."""
        low = ConfidenceScore(0.3)
        high = ConfidenceScore(0.7)
        equal = ConfidenceScore(0.7)

        assert high >= low
        assert high >= equal
        assert not (low >= high)

    def test_greater_equal_invalid_type(self):
        """Test greater than or equal with invalid types."""
        score = ConfidenceScore(0.5)
        with pytest.raises(TypeError, match="Cannot compare ConfidenceScore with"):
            assert score >= 0.5


class TestConfidenceScoreStringMethods:
    """Test ConfidenceScore string representation methods."""

    def test_str_representation(self):
        """Test string representation as percentage."""
        score = ConfidenceScore(0.5)
        assert str(score) == "50.0%"

        score = ConfidenceScore(0.75)
        assert str(score) == "75.0%"

        score = ConfidenceScore(0.0)
        assert str(score) == "0.0%"

        score = ConfidenceScore(1.0)
        assert str(score) == "100.0%"

    def test_repr_representation(self):
        """Test detailed representation for debugging."""
        score = ConfidenceScore(0.5)
        assert repr(score) == "ConfidenceScore(0.5)"

        score = ConfidenceScore(0.75)
        assert repr(score) == "ConfidenceScore(0.75)"


class TestConfidenceScoreHash:
    """Test ConfidenceScore hash functionality."""

    def test_hash_consistency(self):
        """Test that equal scores have equal hashes."""
        score1 = ConfidenceScore(0.5)
        score2 = ConfidenceScore(0.5)

        assert hash(score1) == hash(score2)

    def test_hash_in_set(self):
        """Test using ConfidenceScore in sets."""
        scores = {
            ConfidenceScore(0.1),
            ConfidenceScore(0.5),
            ConfidenceScore(0.9),
            ConfidenceScore(0.5),  # Duplicate
        }

        assert len(scores) == 3  # Duplicate should be removed

    def test_hash_as_dict_key(self):
        """Test using ConfidenceScore as dictionary keys."""
        confidence_map = {
            ConfidenceScore(0.1): "low",
            ConfidenceScore(0.5): "medium",
            ConfidenceScore(0.9): "high",
        }

        assert confidence_map[ConfidenceScore(0.5)] == "medium"


class TestConfidenceScoreThreshold:
    """Test ConfidenceScore threshold operations."""

    def test_meets_threshold(self):
        """Test meets_threshold method."""
        score = ConfidenceScore(0.8)
        threshold = ConfidenceScore(0.7)

        assert score.meets_threshold(threshold) is True

        score = ConfidenceScore(0.6)
        assert score.meets_threshold(threshold) is False

        score = ConfidenceScore(0.7)
        assert score.meets_threshold(threshold) is True  # Equal should meet

    def test_fails_threshold(self):
        """Test fails_threshold method."""
        score = ConfidenceScore(0.6)
        threshold = ConfidenceScore(0.7)

        assert score.fails_threshold(threshold) is True

        score = ConfidenceScore(0.8)
        assert score.fails_threshold(threshold) is False

        score = ConfidenceScore(0.7)
        assert score.fails_threshold(threshold) is False  # Equal should not fail


class TestConfidenceScoreCategories:
    """Test ConfidenceScore category methods."""

    def test_is_very_low(self):
        """Test is_very_low method."""
        assert ConfidenceScore(0.1).is_very_low() is True
        assert ConfidenceScore(0.29).is_very_low() is True
        assert ConfidenceScore(0.3).is_very_low() is False
        assert ConfidenceScore(0.5).is_very_low() is False

    def test_is_low(self):
        """Test is_low method."""
        assert ConfidenceScore(0.29).is_low() is False
        assert ConfidenceScore(0.3).is_low() is True
        assert ConfidenceScore(0.4).is_low() is True
        assert ConfidenceScore(0.49).is_low() is True
        assert ConfidenceScore(0.5).is_low() is False

    def test_is_medium(self):
        """Test is_medium method."""
        assert ConfidenceScore(0.49).is_medium() is False
        assert ConfidenceScore(0.5).is_medium() is True
        assert ConfidenceScore(0.6).is_medium() is True
        assert ConfidenceScore(0.69).is_medium() is True
        assert ConfidenceScore(0.7).is_medium() is False

    def test_is_high(self):
        """Test is_high method."""
        assert ConfidenceScore(0.69).is_high() is False
        assert ConfidenceScore(0.7).is_high() is True
        assert ConfidenceScore(0.8).is_high() is True
        assert ConfidenceScore(0.89).is_high() is True
        assert ConfidenceScore(0.9).is_high() is False

    def test_is_very_high(self):
        """Test is_very_high method."""
        assert ConfidenceScore(0.89).is_very_high() is False
        assert ConfidenceScore(0.9).is_very_high() is True
        assert ConfidenceScore(0.95).is_very_high() is True
        assert ConfidenceScore(1.0).is_very_high() is True

    def test_is_actionable(self):
        """Test is_actionable method."""
        assert ConfidenceScore(0.6).is_actionable() is False
        assert ConfidenceScore(0.7).is_actionable() is True
        assert ConfidenceScore(0.8).is_actionable() is True

    def test_is_certain(self):
        """Test is_certain method."""
        assert ConfidenceScore(0.99).is_certain() is False
        assert ConfidenceScore(1.0).is_certain() is True

    def test_is_uncertain(self):
        """Test is_uncertain method."""
        assert ConfidenceScore(0.01).is_uncertain() is False
        assert ConfidenceScore(0.0).is_uncertain() is True


class TestConfidenceScoreUtilities:
    """Test ConfidenceScore utility methods."""

    def test_get_percentage(self):
        """Test get_percentage method."""
        assert ConfidenceScore(0.5).get_percentage() == 50.0
        assert ConfidenceScore(0.75).get_percentage() == 75.0
        assert ConfidenceScore(1.0).get_percentage() == 100.0

    def test_get_decimal(self):
        """Test get_decimal method."""
        assert ConfidenceScore(0.5).get_decimal() == 0.5
        assert ConfidenceScore(0.75).get_decimal() == 0.75

    def test_get_quality_level(self):
        """Test get_quality_level method."""
        assert ConfidenceScore(0.1).get_quality_level() == "Very Low"
        assert ConfidenceScore(0.4).get_quality_level() == "Low"
        assert ConfidenceScore(0.6).get_quality_level() == "Medium"
        assert ConfidenceScore(0.8).get_quality_level() == "High"
        assert ConfidenceScore(0.95).get_quality_level() == "Very High"

    def test_invert(self):
        """Test invert method."""
        score = ConfidenceScore(0.3)
        inverted = score.invert()
        assert inverted.value == 0.7

        score = ConfidenceScore(1.0)
        inverted = score.invert()
        assert inverted.value == 0.0


class TestConfidenceScoreAdjustment:
    """Test ConfidenceScore adjustment methods."""

    def test_adjust_valid(self):
        """Test adjust method with valid factors."""
        score = ConfidenceScore(0.5)

        adjusted = score.adjust(2.0)
        assert adjusted.value == 1.0  # Clamped to 1.0

        adjusted = score.adjust(0.5)
        assert adjusted.value == 0.25

        adjusted = score.adjust(1.0)
        assert adjusted.value == 0.5

    def test_adjust_invalid_type(self):
        """Test adjust method with invalid types."""
        score = ConfidenceScore(0.5)

        with pytest.raises(TypeError, match="Adjustment factor must be numeric"):
            score.adjust("2.0")

    def test_adjust_negative_factor(self):
        """Test adjust method with negative factors."""
        score = ConfidenceScore(0.5)

        with pytest.raises(ValueError, match="Adjustment factor cannot be negative"):
            score.adjust(-0.5)

    def test_boost_valid(self):
        """Test boost method with valid amounts."""
        score = ConfidenceScore(0.5)

        boosted = score.boost(0.3)
        assert boosted.value == 0.8

        boosted = score.boost(0.8)
        assert boosted.value == 1.0  # Clamped to 1.0

        boosted = score.boost(0.0)
        assert boosted.value == 0.5

    def test_boost_invalid_type(self):
        """Test boost method with invalid types."""
        score = ConfidenceScore(0.5)

        with pytest.raises(TypeError, match="Boost amount must be numeric"):
            score.boost("0.3")

    def test_boost_negative_amount(self):
        """Test boost method with negative amounts."""
        score = ConfidenceScore(0.5)

        # Negative boost should work (becomes penalize)
        boosted = score.boost(-0.2)
        assert boosted.value == 0.3

    def test_penalize_valid(self):
        """Test penalize method with valid amounts."""
        score = ConfidenceScore(0.5)

        penalized = score.penalize(0.2)
        assert penalized.value == 0.3

        penalized = score.penalize(0.8)
        assert penalized.value == 0.0  # Clamped to 0.0

        penalized = score.penalize(0.0)
        assert penalized.value == 0.5

    def test_penalize_invalid_type(self):
        """Test penalize method with invalid types."""
        score = ConfidenceScore(0.5)

        with pytest.raises(TypeError, match="Penalty amount must be numeric"):
            score.penalize("0.2")

    def test_penalize_negative_amount(self):
        """Test penalize method with negative amounts."""
        score = ConfidenceScore(0.5)

        with pytest.raises(ValueError, match="Penalty amount cannot be negative"):
            score.penalize(-0.2)


class TestConfidenceScoreCombination:
    """Test ConfidenceScore combination methods."""

    def test_combine_with_valid(self):
        """Test combine_with method with valid inputs."""
        score1 = ConfidenceScore(0.6)
        score2 = ConfidenceScore(0.8)

        # Default weight 0.5 (equal weighting)
        combined = score1.combine_with(score2)
        assert combined.value == 0.7

        # Weight 0.7 (favor first score)
        combined = score1.combine_with(score2, 0.7)
        assert combined.value == 0.66

        # Weight 0.0 (use only second score)
        combined = score1.combine_with(score2, 0.0)
        assert combined.value == 0.8

    def test_combine_with_invalid_type(self):
        """Test combine_with method with invalid types."""
        score = ConfidenceScore(0.5)

        with pytest.raises(TypeError, match="Cannot combine with"):
            score.combine_with(0.5)

        with pytest.raises(TypeError, match="Weight must be numeric"):
            score.combine_with(ConfidenceScore(0.6), "0.5")

    def test_combine_with_invalid_weight(self):
        """Test combine_with method with invalid weights."""
        score1 = ConfidenceScore(0.5)
        score2 = ConfidenceScore(0.6)

        with pytest.raises(ValueError, match="Weight must be between 0.0 and 1.0"):
            score1.combine_with(score2, -0.1)

        with pytest.raises(ValueError, match="Weight must be between 0.0 and 1.0"):
            score1.combine_with(score2, 1.1)


class TestConfidenceScoreAggregation:
    """Test ConfidenceScore aggregation methods."""

    def test_aggregate_average(self):
        """Test aggregate method with average."""
        scores = [ConfidenceScore(0.4), ConfidenceScore(0.6), ConfidenceScore(0.8)]

        result = ConfidenceScore.aggregate(scores, "average")
        assert result.value == 0.6

    def test_aggregate_min(self):
        """Test aggregate method with min."""
        scores = [ConfidenceScore(0.4), ConfidenceScore(0.6), ConfidenceScore(0.8)]

        result = ConfidenceScore.aggregate(scores, "min")
        assert result.value == 0.4

    def test_aggregate_max(self):
        """Test aggregate method with max."""
        scores = [ConfidenceScore(0.4), ConfidenceScore(0.6), ConfidenceScore(0.8)]

        result = ConfidenceScore.aggregate(scores, "max")
        assert result.value == 0.8

    def test_aggregate_median_odd(self):
        """Test aggregate method with median (odd number of scores)."""
        scores = [ConfidenceScore(0.4), ConfidenceScore(0.6), ConfidenceScore(0.8)]

        result = ConfidenceScore.aggregate(scores, "median")
        assert result.value == 0.6

    def test_aggregate_median_even(self):
        """Test aggregate method with median (even number of scores)."""
        scores = [
            ConfidenceScore(0.4),
            ConfidenceScore(0.6),
            ConfidenceScore(0.7),
            ConfidenceScore(0.8),
        ]

        result = ConfidenceScore.aggregate(scores, "median")
        assert (
            abs(result.value - 0.65) < 1e-10
        )  # (0.6 + 0.7) / 2, handle floating point precision

    def test_aggregate_empty_list(self):
        """Test aggregate method with empty list."""
        with pytest.raises(ValueError, match="Cannot aggregate empty list"):
            ConfidenceScore.aggregate([])

    def test_aggregate_invalid_items(self):
        """Test aggregate method with invalid items."""
        with pytest.raises(
            TypeError, match="All items must be ConfidenceScore instances"
        ):
            ConfidenceScore.aggregate([ConfidenceScore(0.5), 0.6])

    def test_aggregate_unknown_method(self):
        """Test aggregate method with unknown method."""
        scores = [ConfidenceScore(0.5)]

        with pytest.raises(ValueError, match="Unknown aggregation method"):
            ConfidenceScore.aggregate(scores, "unknown")


class TestConfidenceScoreClassConstants:
    """Test ConfidenceScore class constants."""

    def test_class_constants_values(self):
        """Test that class constants have correct values."""
        assert ConfidenceScore.VERY_LOW.value == 0.2
        assert ConfidenceScore.LOW.value == 0.4
        assert ConfidenceScore.MEDIUM.value == 0.6
        assert ConfidenceScore.HIGH.value == 0.8
        assert ConfidenceScore.VERY_HIGH.value == 0.9
        assert ConfidenceScore.CERTAIN.value == 1.0

    def test_class_constants_types(self):
        """Test that class constants are ConfidenceScore instances."""
        assert isinstance(ConfidenceScore.VERY_LOW, ConfidenceScore)
        assert isinstance(ConfidenceScore.LOW, ConfidenceScore)
        assert isinstance(ConfidenceScore.MEDIUM, ConfidenceScore)
        assert isinstance(ConfidenceScore.HIGH, ConfidenceScore)
        assert isinstance(ConfidenceScore.VERY_HIGH, ConfidenceScore)
        assert isinstance(ConfidenceScore.CERTAIN, ConfidenceScore)

    def test_class_constants_categories(self):
        """Test that class constants match their category methods."""
        # This tests the boundary cases
        assert ConfidenceScore.VERY_LOW.is_very_low() is True
        assert ConfidenceScore.LOW.is_low() is True
        assert ConfidenceScore.MEDIUM.is_medium() is True
        assert ConfidenceScore.HIGH.is_high() is True
        assert ConfidenceScore.VERY_HIGH.is_very_high() is True
        assert ConfidenceScore.CERTAIN.is_certain() is True


class TestConfidenceScoreIntegration:
    """Integration tests for ConfidenceScore usage patterns."""

    def test_validation_workflow(self):
        """Test typical validation workflow."""
        # Create scores from different sources
        llm_score = ConfidenceScore.from_percentage(75)
        ratio_score = ConfidenceScore.from_ratio(8, 10)

        # Combine them
        combined = llm_score.combine_with(ratio_score, 0.6)

        # Check if actionable
        threshold = ConfidenceScore.default_threshold()
        assert combined.meets_threshold(threshold)
        assert combined.is_actionable()

    def test_scoring_pipeline(self):
        """Test a complete scoring pipeline."""
        initial_scores = [
            ConfidenceScore.from_percentage(60),
            ConfidenceScore.from_percentage(80),
            ConfidenceScore.from_percentage(70),
        ]

        # Aggregate
        avg_score = ConfidenceScore.aggregate(initial_scores, "average")
        assert avg_score.get_percentage() == 70.0

        # Boost based on additional evidence
        boosted = avg_score.boost(0.1)
        assert boosted.get_percentage() == 80.0

        # Check final quality
        assert boosted.get_quality_level() == "High"
        assert boosted.is_actionable()

    def test_threshold_comparison_matrix(self):
        """Test comprehensive threshold comparison matrix."""
        thresholds = [
            ConfidenceScore.VERY_LOW,
            ConfidenceScore.LOW,
            ConfidenceScore.MEDIUM,
            ConfidenceScore.HIGH,
            ConfidenceScore.VERY_HIGH,
        ]

        test_score = ConfidenceScore.MEDIUM

        # Test meets_threshold
        assert test_score.meets_threshold(ConfidenceScore.VERY_LOW)
        assert test_score.meets_threshold(ConfidenceScore.LOW)
        assert test_score.meets_threshold(ConfidenceScore.MEDIUM)
        assert test_score.fails_threshold(ConfidenceScore.HIGH)
        assert test_score.fails_threshold(ConfidenceScore.VERY_HIGH)
