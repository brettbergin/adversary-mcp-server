"""Tests for PricingManager module."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from adversary_mcp_server.llm.pricing_manager import PricingManager


class TestPricingManager:
    """Test cases for PricingManager."""

    def test_init_with_default_config(self):
        """Test initialization with default config path."""
        manager = PricingManager()
        assert manager.config_path.name == "pricing_config.json"
        assert isinstance(manager.pricing_data, dict)

    def test_init_with_custom_config_path(self):
        """Test initialization with custom config path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "custom_pricing.json"
            manager = PricingManager(config_path)
            assert manager.config_path == config_path

    def test_load_valid_config(self):
        """Test loading a valid configuration file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            config_data = {
                "pricing_models": {
                    "gpt-4": {
                        "prompt_tokens_per_1k": 0.01,
                        "completion_tokens_per_1k": 0.03,
                        "currency": "USD",
                        "description": "GPT-4 model",
                    }
                },
                "default_pricing": {
                    "prompt_tokens_per_1k": 0.01,
                    "completion_tokens_per_1k": 0.03,
                    "currency": "USD",
                },
            }
            json.dump(config_data, f)
            f.flush()

            manager = PricingManager(f.name)
            assert "gpt-4" in manager.pricing_data["pricing_models"]
            Path(f.name).unlink()  # cleanup

    def test_load_nonexistent_config(self):
        """Test behavior when config file doesn't exist."""
        nonexistent_path = Path("/nonexistent/path/pricing.json")
        manager = PricingManager(nonexistent_path)

        # Should create default config
        assert "pricing_models" in manager.pricing_data
        assert "default_pricing" in manager.pricing_data

    def test_load_invalid_json_config(self):
        """Test behavior with invalid JSON config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content {")
            f.flush()

            manager = PricingManager(f.name)
            # Should fall back to default config
            assert "pricing_models" in manager.pricing_data
            Path(f.name).unlink()  # cleanup

    def test_get_model_pricing_exact_match(self):
        """Test getting pricing for exact model match."""
        manager = PricingManager()
        # Use a model that exists in default config
        pricing = manager.get_model_pricing("gpt-4")

        assert "prompt_tokens_per_1k" in pricing
        assert "completion_tokens_per_1k" in pricing
        assert isinstance(pricing["prompt_tokens_per_1k"], int | float)

    def test_get_model_pricing_partial_match(self):
        """Test getting pricing for partial model match."""
        manager = PricingManager()
        # Test partial match (e.g., gpt-4-0314 should match gpt-4)
        pricing = manager.get_model_pricing("gpt-4-0314-preview")

        assert "prompt_tokens_per_1k" in pricing
        assert "completion_tokens_per_1k" in pricing

    def test_get_model_pricing_no_match(self):
        """Test getting pricing for unknown model."""
        manager = PricingManager()
        pricing = manager.get_model_pricing("unknown-model-xyz")

        # Should return default pricing
        assert "prompt_tokens_per_1k" in pricing
        assert "completion_tokens_per_1k" in pricing
        assert pricing.get("description", "").lower().find("default") >= 0

    def test_calculate_cost_basic(self):
        """Test basic cost calculation."""
        manager = PricingManager()

        cost_breakdown = manager.calculate_cost("gpt-4", 1000, 500)

        assert "prompt_cost" in cost_breakdown
        assert "completion_cost" in cost_breakdown
        assert "total_cost" in cost_breakdown
        assert "currency" in cost_breakdown
        assert "model" in cost_breakdown
        assert "tokens" in cost_breakdown

        assert cost_breakdown["model"] == "gpt-4"
        assert cost_breakdown["tokens"]["prompt_tokens"] == 1000
        assert cost_breakdown["tokens"]["completion_tokens"] == 500
        assert cost_breakdown["tokens"]["total_tokens"] == 1500
        assert cost_breakdown["total_cost"] > 0

    def test_calculate_cost_zero_tokens(self):
        """Test cost calculation with zero tokens."""
        manager = PricingManager()

        cost_breakdown = manager.calculate_cost("gpt-4", 0, 0)

        assert cost_breakdown["prompt_cost"] == 0.0
        assert cost_breakdown["completion_cost"] == 0.0
        assert cost_breakdown["total_cost"] == 0.0
        assert cost_breakdown["tokens"]["total_tokens"] == 0

    def test_calculate_cost_unknown_model(self):
        """Test cost calculation for unknown model."""
        manager = PricingManager()

        cost_breakdown = manager.calculate_cost("unknown-model", 1000, 500)

        assert cost_breakdown["model"] == "unknown-model"
        assert cost_breakdown["total_cost"] > 0
        # Should use default pricing

    def test_get_supported_models(self):
        """Test getting list of supported models."""
        manager = PricingManager()
        models = manager.get_supported_models()

        assert isinstance(models, list)
        assert len(models) > 0
        # Should contain some common models from default config
        assert any("gpt" in model.lower() for model in models)

    def test_get_config_metadata(self):
        """Test getting configuration metadata."""
        manager = PricingManager()
        metadata = manager.get_config_metadata()

        assert isinstance(metadata, dict)
        # May be empty if no metadata section, that's fine

    def test_refresh_config(self):
        """Test refreshing configuration."""
        manager = PricingManager()

        # Should succeed even if config file doesn't exist
        result = manager.refresh_config()
        assert isinstance(result, bool)

    def test_refresh_config_with_error(self):
        """Test refresh config with error condition."""
        manager = PricingManager()

        # Mock the _load_pricing_config to raise an exception
        with patch.object(
            manager, "_load_pricing_config", side_effect=Exception("Mock error")
        ):
            result = manager.refresh_config()
            assert result is False

    def test_validate_config_valid(self):
        """Test validation of valid configuration."""
        manager = PricingManager()
        errors = manager.validate_config()

        # Should have no errors for default config
        assert isinstance(errors, list)

    def test_validate_config_invalid_structure(self):
        """Test validation with invalid structure."""
        manager = PricingManager()
        manager.pricing_data = "invalid_structure"  # Not a dict

        errors = manager.validate_config()
        assert len(errors) > 0
        assert any("dictionary" in error.lower() for error in errors)

    def test_validate_config_missing_sections(self):
        """Test validation with missing required sections."""
        manager = PricingManager()
        manager.pricing_data = {}  # Missing required sections

        errors = manager.validate_config()
        assert len(errors) > 0
        assert any("pricing_models" in error for error in errors)
        assert any("default_pricing" in error for error in errors)

    def test_validate_config_invalid_pricing_models(self):
        """Test validation with invalid pricing models."""
        manager = PricingManager()
        manager.pricing_data = {
            "pricing_models": "not_a_dict",
            "default_pricing": {
                "prompt_tokens_per_1k": 0.01,
                "completion_tokens_per_1k": 0.03,
            },
        }

        errors = manager.validate_config()
        assert len(errors) > 0
        assert any("pricing_models must be a dictionary" in error for error in errors)

    def test_validate_config_invalid_model_pricing(self):
        """Test validation with invalid model pricing structure."""
        manager = PricingManager()
        manager.pricing_data = {
            "pricing_models": {"test_model": "not_a_dict"},
            "default_pricing": {
                "prompt_tokens_per_1k": 0.01,
                "completion_tokens_per_1k": 0.03,
            },
        }

        errors = manager.validate_config()
        assert len(errors) > 0
        assert any("test_model must be a dictionary" in error for error in errors)

    def test_validate_config_missing_required_fields(self):
        """Test validation with missing required pricing fields."""
        manager = PricingManager()
        manager.pricing_data = {
            "pricing_models": {
                "test_model": {
                    "prompt_tokens_per_1k": 0.01
                    # Missing completion_tokens_per_1k
                }
            },
            "default_pricing": {
                "prompt_tokens_per_1k": 0.01,
                "completion_tokens_per_1k": 0.03,
            },
        }

        errors = manager.validate_config()
        assert len(errors) > 0
        assert any(
            "completion_tokens_per_1k" in error and "test_model" in error
            for error in errors
        )

    def test_validate_config_invalid_pricing_values(self):
        """Test validation with invalid pricing values."""
        manager = PricingManager()
        manager.pricing_data = {
            "pricing_models": {
                "test_model": {
                    "prompt_tokens_per_1k": -0.01,  # Negative value
                    "completion_tokens_per_1k": "invalid",  # Non-numeric
                }
            },
            "default_pricing": {
                "prompt_tokens_per_1k": 0.01,
                "completion_tokens_per_1k": 0.03,
            },
        }

        errors = manager.validate_config()
        assert len(errors) > 0
        assert any(
            "prompt_tokens_per_1k" in error and "non-negative" in error
            for error in errors
        )
        assert any(
            "completion_tokens_per_1k" in error and "non-negative" in error
            for error in errors
        )

    def test_validate_config_invalid_default_pricing(self):
        """Test validation with invalid default pricing."""
        manager = PricingManager()
        manager.pricing_data = {"pricing_models": {}, "default_pricing": "not_a_dict"}

        errors = manager.validate_config()
        assert len(errors) > 0
        assert any("default_pricing must be a dictionary" in error for error in errors)

    def test_cost_calculation_precision(self):
        """Test cost calculation precision and rounding."""
        manager = PricingManager()

        # Test with precise values
        cost_breakdown = manager.calculate_cost("gpt-4", 1, 1)

        # All costs should be properly rounded
        assert isinstance(cost_breakdown["prompt_cost"], float)
        assert isinstance(cost_breakdown["completion_cost"], float)
        assert isinstance(cost_breakdown["total_cost"], float)

        # Total should equal sum of parts
        expected_total = (
            cost_breakdown["prompt_cost"] + cost_breakdown["completion_cost"]
        )
        assert abs(cost_breakdown["total_cost"] - expected_total) < 0.000001

    def test_create_default_config_structure(self):
        """Test that default config has proper structure."""
        manager = PricingManager()
        manager._create_default_config()

        # Check required structure
        assert "pricing_models" in manager.pricing_data
        assert "default_pricing" in manager.pricing_data
        assert "metadata" in manager.pricing_data

        # Validate default pricing structure
        default_pricing = manager.pricing_data["default_pricing"]
        assert "prompt_tokens_per_1k" in default_pricing
        assert "completion_tokens_per_1k" in default_pricing
        assert "currency" in default_pricing
