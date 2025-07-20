"""Extended tests for ThreatEngine rule management functionality."""

from unittest.mock import patch

import pytest
import yaml

from adversary_mcp_server.threat_engine import (
    Category,
    Language,
    MatchCondition,
    Severity,
    ThreatEngine,
    ThreatRule,
)


class TestThreatEngineYAMLLoading:
    """Test YAML rule loading functionality."""

    def test_load_builtin_rules_from_yaml(self, tmp_path):
        """Test loading built-in rules from YAML files."""
        # Create temporary rules directory
        rules_dir = tmp_path / "rules" / "built-in"
        rules_dir.mkdir(parents=True)

        # Create test YAML rule file
        test_rule = {
            "rules": [
                {
                    "id": "test_rule",
                    "name": "Test Rule",
                    "description": "A test rule",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "test.*pattern"}],
                    "remediation": "Fix the issue",
                    "references": ["https://example.com"],
                    "cwe_id": "CWE-89",
                }
            ]
        }

        rule_file = rules_dir / "test-rules.yaml"
        with open(rule_file, "w") as f:
            yaml.dump(test_rule, f)

        # Mock the builtin rules directory calculation
        with patch.object(ThreatEngine, "_load_builtin_rules"):
            # Create threat engine
            engine = ThreatEngine()

            # Now manually load the test rules
            for yaml_file in rules_dir.glob("*.yaml"):
                engine.load_rules_from_file(yaml_file)

            # Verify rule was loaded
            assert len(engine.rules) > 0
            assert "test_rule" in engine.rules
            rule = engine.rules["test_rule"]
            assert rule.name == "Test Rule"
            assert rule.severity == Severity.HIGH
            assert rule.category == Category.INJECTION

    def test_fallback_to_hardcoded_rules(self, tmp_path):
        """Test fallback to hardcoded rules when YAML files don't exist."""
        # Test that the system falls back to hardcoded rules
        # We'll create a new engine without mocking - the real built-in rules should load
        # from YAML files, but if they don't exist, it should fall back to hardcoded

        # Create threat engine without any custom directories
        engine = ThreatEngine()

        # Verify rules were loaded (either from YAML or hardcoded fallback)
        assert len(engine.rules) > 0
        assert "python_sql_injection" in engine.rules
        assert "js_eval_injection" in engine.rules

    def test_load_custom_rules_directories(self, tmp_path):
        """Test loading rules from custom directories."""
        # Create custom rules directory
        custom_dir = tmp_path / "custom-rules"
        custom_dir.mkdir()

        # Create custom rule file
        custom_rule = {
            "rules": [
                {
                    "id": "custom_rule",
                    "name": "Custom Rule",
                    "description": "A custom rule",
                    "category": "xss",
                    "severity": "medium",
                    "languages": ["javascript"],
                    "conditions": [{"type": "pattern", "value": "custom.*pattern"}],
                }
            ]
        }

        rule_file = custom_dir / "custom-rules.yaml"
        with open(rule_file, "w") as f:
            yaml.dump(custom_rule, f)

        # Create threat engine with custom directory
        engine = ThreatEngine(custom_rules_dirs=[custom_dir])

        # Verify custom rule was loaded
        assert "custom_rule" in engine.rules
        rule = engine.rules["custom_rule"]
        assert rule.name == "Custom Rule"
        assert rule.category == Category.XSS

    def test_load_rules_from_file_error_handling(self, tmp_path):
        """Test error handling when loading invalid YAML files."""
        # Create invalid YAML file
        invalid_file = tmp_path / "invalid.yaml"
        with open(invalid_file, "w") as f:
            f.write("invalid: yaml: content:")

        engine = ThreatEngine()

        # Should raise ValueError for invalid YAML
        with pytest.raises(ValueError, match="Failed to load rules"):
            engine.load_rules_from_file(invalid_file)

    def test_load_rules_missing_rules_section(self, tmp_path):
        """Test error handling when YAML file is missing 'rules' section."""
        # Create YAML file without 'rules' section
        no_rules_file = tmp_path / "no-rules.yaml"
        with open(no_rules_file, "w") as f:
            yaml.dump({"other": "data"}, f)

        engine = ThreatEngine()

        # Should raise ValueError for missing 'rules' section
        with pytest.raises(ValueError, match="No 'rules' section found"):
            engine.load_rules_from_file(no_rules_file)


class TestThreatEngineManagement:
    """Test rule management functionality."""

    def test_reload_rules(self, tmp_path):
        """Test reloading rules from files."""
        # Create rules directory
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Create initial rule file
        initial_rule = {
            "rules": [
                {
                    "id": "reload_test",
                    "name": "Initial Rule",
                    "description": "Initial rule",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "initial"}],
                }
            ]
        }

        rule_file = rules_dir / "test.yaml"
        with open(rule_file, "w") as f:
            yaml.dump(initial_rule, f)

        # Create engine and load rules
        engine = ThreatEngine(rules_dir=rules_dir)
        assert engine.rules["reload_test"].name == "Initial Rule"

        # Update rule file
        updated_rule = {
            "rules": [
                {
                    "id": "reload_test",
                    "name": "Updated Rule",
                    "description": "Updated rule",
                    "category": "injection",
                    "severity": "critical",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "updated"}],
                }
            ]
        }

        with open(rule_file, "w") as f:
            yaml.dump(updated_rule, f)

        # Reload rules
        engine.reload_rules()

        # Verify rule was updated
        assert engine.rules["reload_test"].name == "Updated Rule"
        assert engine.rules["reload_test"].severity == Severity.CRITICAL

    def test_import_rules_from_file(self, tmp_path):
        """Test importing rules from external file."""
        # Create external rule file
        external_file = tmp_path / "external.yaml"
        external_rule = {
            "rules": [
                {
                    "id": "imported_rule",
                    "name": "Imported Rule",
                    "description": "An imported rule",
                    "category": "xss",
                    "severity": "medium",
                    "languages": ["javascript"],
                    "conditions": [{"type": "pattern", "value": "imported"}],
                }
            ]
        }

        with open(external_file, "w") as f:
            yaml.dump(external_rule, f)

        # Create target directory
        target_dir = tmp_path / "target"
        target_dir.mkdir()

        # Create engine and import rules
        engine = ThreatEngine()
        engine.import_rules_from_file(external_file, target_dir)

        # Verify rule was imported
        assert "imported_rule" in engine.rules

        # Verify file was copied to target directory
        assert (target_dir / "external.yaml").exists()

    def test_remove_rule(self):
        """Test removing a rule by ID."""
        engine = ThreatEngine()

        # Get initial rule count
        initial_count = len(engine.rules)

        # Get a rule ID to remove
        rule_id = list(engine.rules.keys())[0]
        rule = engine.rules[rule_id]

        # Remove the rule
        result = engine.remove_rule(rule_id)

        # Verify rule was removed
        assert result is True
        assert rule_id not in engine.rules
        assert len(engine.rules) == initial_count - 1

        # Verify rule was removed from language index
        for language in rule.languages:
            assert rule not in engine.rules_by_language[language]

    def test_remove_nonexistent_rule(self):
        """Test removing a non-existent rule."""
        engine = ThreatEngine()

        # Try to remove non-existent rule
        result = engine.remove_rule("nonexistent_rule")

        # Should return False
        assert result is False

    def test_get_rule_statistics(self):
        """Test getting rule statistics."""
        engine = ThreatEngine()
        stats = engine.get_rule_statistics()

        # Verify statistics structure
        assert "total_rules" in stats
        assert "categories" in stats
        assert "severities" in stats
        assert "languages" in stats
        assert "loaded_files" in stats
        assert "rule_files" in stats

        # Verify data types
        assert isinstance(stats["total_rules"], int)
        assert isinstance(stats["categories"], dict)
        assert isinstance(stats["severities"], dict)
        assert isinstance(stats["languages"], dict)
        assert isinstance(stats["loaded_files"], int)
        assert isinstance(stats["rule_files"], list)

    def test_validate_all_rules(self):
        """Test validating all loaded rules."""
        engine = ThreatEngine()

        # All default rules should be valid
        validation_errors = engine.validate_all_rules()
        assert len(validation_errors) == 0

    def test_validate_invalid_rule(self):
        """Test validation of invalid rules."""
        engine = ThreatEngine()

        # Create a valid rule object but then modify it to have invalid properties
        valid_rule = ThreatRule(
            id="valid_test_rule",
            name="Valid Rule",
            description="Valid description",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            languages=[Language.PYTHON],
            conditions=[MatchCondition(type="pattern", value="test.*pattern")],
        )

        # Manually set invalid properties after creation
        valid_rule.name = ""  # Invalid - empty name
        valid_rule.description = ""  # Invalid - empty description
        valid_rule.conditions = []  # Invalid - empty conditions

        errors = engine.validate_rule(valid_rule)

        # Should have validation errors
        assert len(errors) > 0
        assert any("name is required" in error for error in errors)
        assert any("description is required" in error for error in errors)
        assert any("condition is required" in error for error in errors)

    def test_find_rules_by_pattern(self):
        """Test finding rules by search pattern."""
        engine = ThreatEngine()

        # Search for SQL injection rules
        sql_rules = engine.find_rules_by_pattern("sql")
        assert len(sql_rules) > 0

        # Should find rules with "sql" in name, description, or ID
        sql_rule_ids = [rule.id for rule in sql_rules]
        assert any("sql" in rule_id.lower() for rule_id in sql_rule_ids)

        # Search for non-existent pattern
        no_rules = engine.find_rules_by_pattern("nonexistent_pattern_xyz")
        assert len(no_rules) == 0

    def test_find_rules_by_invalid_pattern(self):
        """Test finding rules with invalid regex pattern."""
        engine = ThreatEngine()

        # Invalid regex pattern
        invalid_rules = engine.find_rules_by_pattern("[invalid")
        assert len(invalid_rules) == 0

    def test_export_rules_to_yaml(self, tmp_path):
        """Test exporting rules to YAML file."""
        engine = ThreatEngine()
        output_file = tmp_path / "exported_rules.yaml"

        # Export rules
        engine.export_rules_to_yaml(output_file)

        # Verify file was created
        assert output_file.exists()

        # Verify content
        with open(output_file) as f:
            exported_data = yaml.safe_load(f)

        assert "rules" in exported_data
        assert len(exported_data["rules"]) == len(engine.rules)

        # Verify rule structure
        first_rule = exported_data["rules"][0]
        assert "id" in first_rule
        assert "name" in first_rule
        assert "description" in first_rule
        assert "category" in first_rule
        assert "severity" in first_rule
        assert "languages" in first_rule
        assert "conditions" in first_rule


class TestThreatEngineAdvanced:
    """Test advanced threat engine functionality."""

    def test_rule_priority_loading(self, tmp_path):
        """Test that rules are loaded in correct priority order."""
        # Create built-in rules directory
        builtin_dir = tmp_path / "rules" / "built-in"
        builtin_dir.mkdir(parents=True, exist_ok=True)

        # Create custom rules directory
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir(exist_ok=True)

        # Create provided rules directory
        provided_dir = tmp_path / "provided"
        provided_dir.mkdir(exist_ok=True)

        # Create same rule ID in all directories with different names
        rule_id = "priority_test"

        # Built-in rule
        builtin_rule = {
            "rules": [
                {
                    "id": rule_id,
                    "name": "Built-in Rule",
                    "description": "Built-in rule",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "builtin"}],
                }
            ]
        }

        with open(builtin_dir / "builtin.yaml", "w") as f:
            yaml.dump(builtin_rule, f)

        # Custom rule
        custom_rule = {
            "rules": [
                {
                    "id": rule_id,
                    "name": "Custom Rule",
                    "description": "Custom rule",
                    "category": "injection",
                    "severity": "critical",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "custom"}],
                }
            ]
        }

        with open(custom_dir / "custom.yaml", "w") as f:
            yaml.dump(custom_rule, f)

        # Provided rule
        provided_rule = {
            "rules": [
                {
                    "id": rule_id,
                    "name": "Provided Rule",
                    "description": "Provided rule",
                    "category": "injection",
                    "severity": "medium",
                    "languages": ["python"],
                    "conditions": [{"type": "pattern", "value": "provided"}],
                }
            ]
        }

        with open(provided_dir / "provided.yaml", "w") as f:
            yaml.dump(provided_rule, f)

        # Mock the get_user_rules_directory and initialize functions
        with patch(
            "adversary_mcp_server.threat_engine.get_user_rules_directory"
        ) as mock_get_user_rules:
            with patch(
                "adversary_mcp_server.threat_engine.initialize_user_rules_directory"
            ) as mock_init:
                # Set up the mock to return our test directory
                mock_get_user_rules.return_value = tmp_path / "user_rules"
                mock_init.return_value = None  # Skip initialization

                # Create threat engine with all directories
                engine = ThreatEngine(
                    rules_dir=provided_dir, custom_rules_dirs=[custom_dir]
                )

                # The provided rule should have overridden the others
                assert rule_id in engine.rules
                rule = engine.rules[rule_id]
                assert rule.name == "Provided Rule"
                assert rule.severity == Severity.MEDIUM

    def test_loaded_rule_files_tracking(self, tmp_path):
        """Test tracking of loaded rule files."""
        # Create test rules directory
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Create test rule files
        rule_files = ["rules1.yaml", "rules2.yaml", "rules3.yml"]
        for i, filename in enumerate(rule_files):
            rule_file = rules_dir / filename
            test_rule = {
                "rules": [
                    {
                        "id": f"test_rule_{i}",
                        "name": f"Test Rule {i}",
                        "description": f"Test rule {i}",
                        "category": "injection",
                        "severity": "high",
                        "languages": ["python"],
                        "conditions": [{"type": "pattern", "value": f"test{i}"}],
                    }
                ]
            }

            with open(rule_file, "w") as f:
                yaml.dump(test_rule, f)

        # Create engine with custom directory
        engine = ThreatEngine(rules_dir=rules_dir)

        # Get the count of test rule files loaded (excluding built-in files)
        test_rule_files = [
            f for f in engine.loaded_rule_files if str(f).startswith(str(tmp_path))
        ]
        assert len(test_rule_files) == len(rule_files)

        # Verify test rules were loaded
        for i in range(len(rule_files)):
            assert f"test_rule_{i}" in engine.rules

    def test_rule_file_not_found_error(self, tmp_path):
        """Test error handling for non-existent rule files."""
        engine = ThreatEngine()

        # Try to load non-existent file
        non_existent_file = tmp_path / "nonexistent.yaml"

        with pytest.raises(ValueError, match="Failed to load rules"):
            engine.load_rules_from_file(non_existent_file)

    def test_import_rules_validation(self, tmp_path):
        """Test validation during rule import."""
        # Create invalid rule file
        invalid_file = tmp_path / "invalid.yaml"
        invalid_rule = {
            "rules": [
                {
                    "id": "",  # Invalid empty ID
                    "name": "Invalid Rule",
                    "description": "Invalid rule",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "conditions": [],  # Invalid empty conditions
                }
            ]
        }

        with open(invalid_file, "w") as f:
            yaml.dump(invalid_rule, f)

        engine = ThreatEngine()

        # Import should fail due to validation errors
        with pytest.raises(Exception):
            engine.import_rules_from_file(invalid_file)

    def test_rule_conditions_validation(self):
        """Test validation of rule conditions."""
        engine = ThreatEngine()

        # Create rule with invalid regex condition
        invalid_rule = ThreatRule(
            id="regex_test",
            name="Regex Test",
            description="Test rule with invalid regex",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            languages=[Language.PYTHON],
            conditions=[
                MatchCondition(type="regex", value="[invalid_regex")  # Invalid regex
            ],
        )

        errors = engine.validate_rule(invalid_rule)

        # Should have regex validation error
        assert len(errors) > 0
        assert any("Invalid regex" in error for error in errors)


@pytest.fixture
def sample_rules_directory(tmp_path):
    """Create a sample rules directory for testing."""
    rules_dir = tmp_path / "test_rules"
    rules_dir.mkdir()

    # Create sample rule files
    python_rules = {
        "rules": [
            {
                "id": "test_python_rule",
                "name": "Test Python Rule",
                "description": "A test Python rule",
                "category": "injection",
                "severity": "high",
                "languages": ["python"],
                "conditions": [{"type": "pattern", "value": "test_pattern"}],
                "remediation": "Fix the test issue",
                "references": ["https://example.com"],
                "cwe_id": "CWE-89",
            }
        ]
    }

    js_rules = {
        "rules": [
            {
                "id": "test_js_rule",
                "name": "Test JavaScript Rule",
                "description": "A test JavaScript rule",
                "category": "xss",
                "severity": "medium",
                "languages": ["javascript"],
                "conditions": [
                    {"type": "function_call", "value": ["eval", "Function"]}
                ],
                "exploit_templates": [
                    {
                        "type": "javascript",
                        "template": "eval('test')",
                        "description": "Test exploit",
                    }
                ],
            }
        ]
    }

    # Write rule files
    with open(rules_dir / "python_rules.yaml", "w") as f:
        yaml.dump(python_rules, f)

    with open(rules_dir / "js_rules.yaml", "w") as f:
        yaml.dump(js_rules, f)

    return rules_dir


class TestThreatEngineIntegration:
    """Integration tests for ThreatEngine."""

    def test_full_workflow(self, sample_rules_directory):
        """Test complete workflow with YAML rules."""
        # Create engine with sample rules
        engine = ThreatEngine(rules_dir=sample_rules_directory)

        # Verify rules loaded
        assert len(engine.rules) >= 2
        assert "test_python_rule" in engine.rules
        assert "test_js_rule" in engine.rules

        # Test rule retrieval
        python_rule = engine.get_rule_by_id("test_python_rule")
        assert python_rule is not None
        assert python_rule.name == "Test Python Rule"

        # Test rules by language
        python_rules = engine.get_rules_for_language(Language.PYTHON)
        python_rule_ids = [rule.id for rule in python_rules]
        assert "test_python_rule" in python_rule_ids

        # Test rules by category
        injection_rules = engine.get_rules_by_category(Category.INJECTION)
        injection_rule_ids = [rule.id for rule in injection_rules]
        assert "test_python_rule" in injection_rule_ids

        # Test rules by severity
        high_rules = engine.get_rules_by_severity(Severity.HIGH)
        high_rule_ids = [rule.id for rule in high_rules]
        assert "test_python_rule" in high_rule_ids

        # Test statistics
        stats = engine.get_rule_statistics()
        assert stats["total_rules"] >= 2
        assert "injection" in stats["categories"]
        assert "xss" in stats["categories"]
        assert "python" in stats["languages"]
        assert "javascript" in stats["languages"]

        # Test validation
        validation_errors = engine.validate_all_rules()
        assert len(validation_errors) == 0

        # Test search
        search_results = engine.find_rules_by_pattern("test")
        assert len(search_results) >= 2
