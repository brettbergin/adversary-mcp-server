"""Tests for the threat engine component."""

import pytest

from adversary_mcp_server.threat_engine import (
    Category,
    ExploitTemplate,
    Language,
    MatchCondition,
    Severity,
    ThreatEngine,
    ThreatRule,
)


class TestThreatEngine:
    """Test cases for the ThreatEngine class."""

    def test_init(self):
        """Test ThreatEngine initialization."""
        engine = ThreatEngine()
        assert isinstance(engine.rules, dict)
        assert len(engine.rules) > 0  # Should have default rules

    def test_get_rules_for_language(self):
        """Test getting rules for a specific language."""
        engine = ThreatEngine()

        python_rules = engine.get_rules_for_language(Language.PYTHON)
        assert len(python_rules) > 0

        js_rules = engine.get_rules_for_language(Language.JAVASCRIPT)
        assert len(js_rules) > 0

    def test_get_rules_by_severity(self):
        """Test filtering rules by severity."""
        engine = ThreatEngine()

        high_rules = engine.get_rules_by_severity(Severity.HIGH)
        critical_rules = engine.get_rules_by_severity(Severity.CRITICAL)

        # Critical rules should be a subset of high+ rules
        assert len(critical_rules) <= len(high_rules)

    def test_get_rules_by_category(self):
        """Test filtering rules by category."""
        engine = ThreatEngine()

        injection_rules = engine.get_rules_by_category(Category.INJECTION)
        assert len(injection_rules) > 0

    def test_add_custom_rule(self):
        """Test adding a custom rule."""
        engine = ThreatEngine()

        custom_rule = ThreatRule(
            id="test_rule",
            name="Test Rule",
            description="A test rule",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            languages=[Language.PYTHON],
            conditions=[MatchCondition(type="pattern", value="test_pattern")],
            remediation="Fix the test issue",
        )

        engine.add_rule(custom_rule)

        # Verify rule was added
        assert engine.get_rule_by_id("test_rule") is not None
        assert len(engine.get_rules_for_language(Language.PYTHON)) > 0

    def test_rule_validation(self):
        """Test rule validation."""
        engine = ThreatEngine()

        # Valid rule
        valid_rule = ThreatRule(
            id="valid_rule",
            name="Valid Rule",
            description="A valid rule",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            languages=[Language.PYTHON],
            conditions=[MatchCondition(type="pattern", value="valid_pattern")],
        )

        errors = engine.validate_rule(valid_rule)
        assert len(errors) == 0

        # Invalid rule (no conditions)
        invalid_rule = ThreatRule(
            id="invalid_rule",
            name="Invalid Rule",
            description="An invalid rule",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            languages=[Language.PYTHON],
            conditions=[],
        )

        errors = engine.validate_rule(invalid_rule)
        assert len(errors) > 0

    def test_list_rules(self):
        """Test listing rules."""
        engine = ThreatEngine()

        rules = engine.list_rules()
        assert len(rules) > 0

        # Check rule structure
        for rule in rules:
            assert "id" in rule
            assert "name" in rule
            assert "category" in rule
            assert "severity" in rule
            assert "languages" in rule
            assert "description" in rule


class TestThreatRule:
    """Test cases for the ThreatRule class."""

    def test_rule_creation(self):
        """Test creating a threat rule."""
        rule = ThreatRule(
            id="test_sql_injection",
            name="SQL Injection",
            description="Test SQL injection rule",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            languages=[Language.PYTHON],
            conditions=[
                MatchCondition(type="pattern", value="cursor\\.execute\\(.*\\+.*\\)")
            ],
            exploit_templates=[
                ExploitTemplate(
                    type="payload",
                    template="' OR '1'='1' --",
                    description="Basic SQL injection",
                )
            ],
            remediation="Use parameterized queries",
            cwe_id="CWE-89",
        )

        assert rule.id == "test_sql_injection"
        assert rule.name == "SQL Injection"
        assert rule.category == Category.INJECTION
        assert rule.severity == Severity.HIGH
        assert Language.PYTHON in rule.languages
        assert len(rule.conditions) == 1
        assert len(rule.exploit_templates) == 1

    def test_rule_id_validation(self):
        """Test rule ID validation."""
        # Valid IDs
        valid_ids = ["valid_rule", "test-rule", "rule123", "a"]
        for rule_id in valid_ids:
            rule = ThreatRule(
                id=rule_id,
                name="Test Rule",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                languages=[Language.PYTHON],
                conditions=[MatchCondition(type="pattern", value="test")],
            )
            assert rule.id == rule_id

        # Invalid IDs should raise validation errors
        invalid_ids = ["Invalid Rule", "rule.test", "rule@test", "RULE"]
        for rule_id in invalid_ids:
            with pytest.raises(ValueError):
                ThreatRule(
                    id=rule_id,
                    name="Test Rule",
                    description="Test",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    languages=[Language.PYTHON],
                    conditions=[MatchCondition(type="pattern", value="test")],
                )


class TestMatchCondition:
    """Test cases for the MatchCondition class."""

    def test_condition_types(self):
        """Test different condition types."""
        # Pattern condition
        pattern_condition = MatchCondition(type="pattern", value="test.*pattern")
        assert pattern_condition.type == "pattern"

        # Function call condition
        func_condition = MatchCondition(
            type="function_call", value=["os.system", "subprocess.call"]
        )
        assert func_condition.type == "function_call"

        # Regex condition
        regex_condition = MatchCondition(type="regex", value="\\d+")
        assert regex_condition.type == "regex"

    def test_invalid_condition_type(self):
        """Test invalid condition types."""
        with pytest.raises(ValueError):
            MatchCondition(type="invalid_type", value="test")


class TestExploitTemplate:
    """Test cases for the ExploitTemplate class."""

    def test_template_creation(self):
        """Test creating exploit templates."""
        template = ExploitTemplate(
            type="payload",
            template="' OR '1'='1' --",
            description="Basic SQL injection payload",
        )

        assert template.type == "payload"
        assert template.template == "' OR '1'='1' --"
        assert template.description == "Basic SQL injection payload"

    def test_template_types(self):
        """Test different template types."""
        types = ["curl", "python", "javascript", "shell", "payload"]

        for template_type in types:
            template = ExploitTemplate(
                type=template_type, template="test template", description="Test"
            )
            assert template.type == template_type

    def test_invalid_template_type(self):
        """Test invalid template types."""
        with pytest.raises(ValueError):
            ExploitTemplate(type="invalid_type", template="test", description="Test")
