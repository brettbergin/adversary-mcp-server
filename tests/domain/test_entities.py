"""Comprehensive tests for domain entities."""

from datetime import UTC, datetime

import pytest

from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.exceptions import ValidationError
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class TestScanRequest:
    """Test ScanRequest entity."""

    def test_creation_with_defaults(self):
        """Test creating ScanRequest with default values."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        request = ScanRequest(context=context)

        assert request.context == context
        assert request.enable_semgrep is True  # Default
        assert request.enable_llm is True  # Default
        assert request.enable_validation is True  # Default
        assert request.severity_threshold is None  # Default is None
        assert request.get_effective_severity_threshold() == SeverityLevel.from_string(
            "medium"
        )  # Effective default

    def test_creation_with_custom_settings(self):
        """Test creating ScanRequest with custom settings."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        request = ScanRequest(
            context=context,
            enable_semgrep=False,
            enable_llm=True,
            enable_validation=False,
            severity_threshold=SeverityLevel.from_string("high"),
        )

        assert request.enable_semgrep is False
        assert request.enable_llm is True
        assert request.enable_validation is False
        assert request.severity_threshold == SeverityLevel.from_string("high")

    def test_valid_configuration_validation_without_llm(self):
        """Test that validation can be enabled without LLM scanner (separation of concerns)."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        # This should now succeed - validation can work on Semgrep-only results
        request = ScanRequest(context=context, enable_llm=False, enable_validation=True)
        assert request.enable_semgrep is True  # Default to True
        assert request.enable_llm is False
        assert request.enable_validation is True

    def test_invalid_configuration_no_scanners(self):
        """Test that at least one scanner must be enabled."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        with pytest.raises(
            ValidationError, match="At least one scanner must be enabled"
        ):
            ScanRequest(context=context, enable_semgrep=False, enable_llm=False)

    def test_is_comprehensive_scan(self):
        """Test is_comprehensive_scan method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        # Comprehensive scan (all enabled)
        comprehensive_request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=True,
        )
        assert comprehensive_request.is_comprehensive_scan()

        # Not comprehensive (validation disabled)
        partial_request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=True,
            enable_validation=False,
        )
        assert not partial_request.is_comprehensive_scan()

    def test_requires_network_access(self):
        """Test requires_network_access method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        # With LLM enabled
        llm_request = ScanRequest(context=context, enable_llm=True)
        assert llm_request.requires_network_access()

        # Only Semgrep
        semgrep_only_request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=False,
        )
        assert not semgrep_only_request.requires_network_access()

    def test_get_effective_severity_threshold(self):
        """Test get_effective_severity_threshold method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        # Custom threshold
        request = ScanRequest(
            context=context, severity_threshold=SeverityLevel.from_string("critical")
        )
        assert request.get_effective_severity_threshold() == SeverityLevel.from_string(
            "critical"
        )

        # Default threshold
        default_request = ScanRequest(context=context)
        assert (
            default_request.get_effective_severity_threshold()
            == SeverityLevel.from_string("medium")
        )

    def test_get_configuration_summary(self):
        """Test get_configuration_summary method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)

        request = ScanRequest(
            context=context,
            enable_semgrep=True,
            enable_llm=False,
            enable_validation=False,
            severity_threshold=SeverityLevel.from_string("high"),
        )

        summary = request.get_configuration_summary()

        assert summary["scanners"]["semgrep"] is True
        assert summary["scanners"]["llm"] is False
        assert summary["scanners"]["validation"] is False
        assert summary["severity_threshold"] == "high"
        assert summary["scan_type"] == "file"
        assert summary["requester"] == "test-user"
        assert summary["scan_id"] == "test-scan-123"


class TestThreatMatch:
    """Test ThreatMatch entity."""

    def test_creation_with_required_fields(self):
        """Test creating ThreatMatch with required fields."""
        threat = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test SQL Injection Rule",
            description="Detects SQL injection vulnerabilities",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="SELECT * FROM users WHERE id = 'user_id_value'",
            confidence=ConfidenceScore(0.85),
        )

        assert threat.rule_id == "test-rule-001"
        assert threat.rule_name == "Test SQL Injection Rule"
        assert threat.description == "Detects SQL injection vulnerabilities"
        assert threat.category == "injection"
        assert threat.severity == SeverityLevel.from_string("high")
        assert threat.file_path == FilePath.from_string("examples/vulnerable_python.py")
        assert threat.line_number == 42
        assert threat.column_number == 10
        assert threat.code_snippet == "SELECT * FROM users WHERE id = 'user_id_value'"
        assert threat.confidence == ConfidenceScore(0.85)
        assert threat.uuid is not None  # Auto-generated

    def test_creation_with_optional_fields(self):
        """Test creating ThreatMatch with optional fields."""
        threat = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test SQL Injection Rule",
            description="Detects SQL injection vulnerabilities",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="SELECT * FROM users WHERE id = 'user_id_value'",
            confidence=ConfidenceScore(0.85),
            function_name="get_user",
            exploit_examples=["'; DROP TABLE users; --"],
            remediation="Use parameterized queries",
            references=["https://owasp.org/sql-injection"],
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            source_scanner="semgrep",
            is_false_positive=False,
        )

        assert threat.function_name == "get_user"
        assert threat.exploit_examples == ["'; DROP TABLE users; --"]
        assert threat.remediation == "Use parameterized queries"
        assert threat.references == ["https://owasp.org/sql-injection"]
        assert threat.cwe_id == "CWE-89"
        assert threat.owasp_category == "A03:2021 - Injection"
        assert threat.source_scanner == "semgrep"
        assert threat.is_false_positive is False

    def test_invalid_line_number(self):
        """Test that invalid line number raises ValidationError."""
        with pytest.raises(ValidationError, match="Line number must be positive"):
            ThreatMatch(
                rule_id="test-rule-001",
                rule_name="Test Rule",
                description="Test description",
                category="test",
                severity=SeverityLevel.from_string("medium"),
                file_path=FilePath.from_string("examples/vulnerable_python.py"),
                line_number=0,  # Invalid
                column_number=10,
                code_snippet="test code",
                confidence=ConfidenceScore(0.5),
            )

    def test_invalid_column_number(self):
        """Test that invalid column number raises ValidationError."""
        with pytest.raises(ValidationError, match="Column number cannot be negative"):
            ThreatMatch(
                rule_id="test-rule-001",
                rule_name="Test Rule",
                description="Test description",
                category="test",
                severity=SeverityLevel.from_string("medium"),
                file_path=FilePath.from_string("examples/vulnerable_python.py"),
                line_number=10,
                column_number=-1,  # Invalid
                code_snippet="test code",
                confidence=ConfidenceScore(0.5),
            )

    def test_get_fingerprint(self):
        """Test get_fingerprint method."""
        threat = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test description",
            category="test",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.5),
        )

        fingerprint = threat.get_fingerprint()

        # Fingerprint should be deterministic and include key fields
        assert isinstance(fingerprint, str)
        assert len(fingerprint) > 0

        # Same threat should have same fingerprint
        threat2 = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test description",
            category="test",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.5),
        )

        assert threat.get_fingerprint() == threat2.get_fingerprint()

    def test_merge_with(self):
        """Test merge_with method."""
        threat1 = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test description",
            category="test",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.5),
            source_scanner="semgrep",
        )

        threat2 = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Another Test Rule",
            description="Another description",
            category="test",
            severity=SeverityLevel.from_string("high"),  # Higher severity
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=43,  # Close line
            column_number=5,
            code_snippet="more test code",
            confidence=ConfidenceScore(0.8),  # Higher confidence
            source_scanner="llm",
            exploit_examples=["example exploit"],
        )

        merged = threat1.merge_with(threat2)

        # Should keep higher severity and confidence
        assert merged.severity == SeverityLevel.from_string("high")
        assert merged.confidence == ConfidenceScore(0.8)

        # Should combine sources
        assert "semgrep" in merged.source_scanner
        assert "llm" in merged.source_scanner

        # Should combine exploit examples
        assert "example exploit" in merged.exploit_examples

    def test_add_exploit_example(self):
        """Test add_exploit_example method."""
        threat = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test description",
            category="test",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.5),
        )

        updated_threat = threat.add_exploit_example("'; DROP TABLE users; --")

        assert "'; DROP TABLE users; --" in updated_threat.exploit_examples
        assert len(updated_threat.exploit_examples) == 1

        # Original threat should be unchanged (immutable)
        assert len(threat.exploit_examples) == 0

    def test_update_confidence(self):
        """Test update_confidence method."""
        threat = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test description",
            category="test",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.5),
        )

        updated_threat = threat.update_confidence(ConfidenceScore(0.9))

        assert updated_threat.confidence == ConfidenceScore(0.9)

        # Original threat should be unchanged (immutable)
        assert threat.confidence == ConfidenceScore(0.5)

    def test_mark_false_positive(self):
        """Test mark_false_positive method."""
        threat = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test description",
            category="test",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.5),
        )

        marked_threat = threat.mark_false_positive()

        assert marked_threat.is_false_positive is True

        # Original threat should be unchanged (immutable)
        assert threat.is_false_positive is False

    def test_is_similar_to(self):
        """Test is_similar_to method."""
        threat1 = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test description",
            category="injection",
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=42,
            column_number=10,
            code_snippet="test code",
            confidence=ConfidenceScore(0.5),
        )

        # Similar threat (same file, close line, same category)
        threat2 = ThreatMatch(
            rule_id="test-rule-002",
            rule_name="Another Rule",
            description="Another description",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=44,  # Close line
            column_number=15,
            code_snippet="different code",
            confidence=ConfidenceScore(0.8),
        )

        # Different threat (different category)
        threat3 = ThreatMatch(
            rule_id="test-rule-003",
            rule_name="XSS Rule",
            description="XSS description",
            category="xss",  # Different category
            severity=SeverityLevel.from_string("medium"),
            file_path=FilePath.from_string("examples/vulnerable_python.py"),
            line_number=43,
            column_number=10,
            code_snippet="xss code",
            confidence=ConfidenceScore(0.6),
        )

        assert threat1.is_similar_to(threat2, proximity_threshold=5)
        assert not threat1.is_similar_to(threat3, proximity_threshold=5)


class TestScanResult:
    """Test ScanResult entity."""

    def test_create_from_threats(self):
        """Test creating ScanResult from threats."""
        # Create a scan request
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Create some threats
        threats = [
            ThreatMatch(
                rule_id="test-rule-001",
                rule_name="SQL Injection Rule",
                description="SQL injection",
                category="injection",
                severity=SeverityLevel.from_string("high"),
                file_path=file_path,
                line_number=42,
                column_number=10,
                code_snippet="SELECT * FROM users",
                confidence=ConfidenceScore(0.9),
            ),
            ThreatMatch(
                rule_id="test-rule-002",
                rule_name="XSS Rule",
                description="XSS vulnerability",
                category="xss",
                severity=SeverityLevel.from_string("medium"),
                file_path=file_path,
                line_number=85,
                column_number=5,
                code_snippet="document.innerHTML = userInput",
                confidence=ConfidenceScore(0.7),
            ),
        ]

        scan_metadata = {
            "scan_duration_ms": 1500,
            "files_processed": 1,
            "scanner_versions": {"semgrep": "1.0.0"},
        }

        result = ScanResult.create_from_threats(
            request=request,
            threats=threats,
            scan_metadata=scan_metadata,
            validation_applied=True,
        )

        assert result.request == request
        assert len(result.threats) == 2
        assert result.scan_metadata == scan_metadata
        assert result.validation_applied is True
        assert result.completed_at is not None

    def test_create_empty(self):
        """Test creating empty ScanResult."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        result = ScanResult.create_empty(request)

        assert result.request == request
        assert len(result.threats) == 0
        assert result.validation_applied is False
        assert result.completed_at is not None

    def test_get_statistics(self):
        """Test get_statistics method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        threats = [
            ThreatMatch(
                rule_id="test-rule-001",
                rule_name="Critical Rule",
                description="Critical issue",
                category="injection",
                severity=SeverityLevel.from_string("critical"),
                file_path=file_path,
                line_number=42,
                column_number=10,
                code_snippet="test",
                confidence=ConfidenceScore(0.9),
            ),
            ThreatMatch(
                rule_id="test-rule-002",
                rule_name="High Rule",
                description="High issue",
                category="xss",
                severity=SeverityLevel.from_string("high"),
                file_path=file_path,
                line_number=85,
                column_number=5,
                code_snippet="test",
                confidence=ConfidenceScore(0.8),
            ),
            ThreatMatch(
                rule_id="test-rule-003",
                rule_name="Medium Rule",
                description="Medium issue",
                category="disclosure",
                severity=SeverityLevel.from_string("medium"),
                file_path=file_path,
                line_number=120,
                column_number=15,
                code_snippet="test",
                confidence=ConfidenceScore(0.6),
            ),
        ]

        result = ScanResult.create_from_threats(
            request=request, threats=threats, scan_metadata={}
        )

        stats = result.get_statistics()

        assert stats["total_threats"] == 3
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["medium"] == 1
        assert stats["by_severity"].get("low", 0) == 0
        assert stats["files_scanned"] == 1

    def test_get_threats_by_severity(self):
        """Test get_threats_by_severity method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        threats = [
            ThreatMatch(
                rule_id="test-rule-001",
                rule_name="Critical Rule",
                description="Critical issue",
                category="injection",
                severity=SeverityLevel.from_string("critical"),
                file_path=file_path,
                line_number=42,
                column_number=10,
                code_snippet="test",
                confidence=ConfidenceScore(0.9),
            ),
            ThreatMatch(
                rule_id="test-rule-002",
                rule_name="High Rule",
                description="High issue",
                category="xss",
                severity=SeverityLevel.from_string("high"),
                file_path=file_path,
                line_number=85,
                column_number=5,
                code_snippet="test",
                confidence=ConfidenceScore(0.8),
            ),
        ]

        result = ScanResult.create_from_threats(
            request=request, threats=threats, scan_metadata={}
        )

        critical_threats = result.get_threats_by_severity(
            SeverityLevel.from_string("critical")
        )
        high_threats = result.get_threats_by_severity(SeverityLevel.from_string("high"))

        assert len(critical_threats) == 1
        assert critical_threats[0].rule_id == "test-rule-001"

        assert len(high_threats) == 1
        assert high_threats[0].rule_id == "test-rule-002"

    def test_get_threats_by_category(self):
        """Test get_threats_by_category method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        threats = [
            ThreatMatch(
                rule_id="test-rule-001",
                rule_name="SQL Rule",
                description="SQL injection",
                category="injection",
                severity=SeverityLevel.from_string("high"),
                file_path=file_path,
                line_number=42,
                column_number=10,
                code_snippet="test",
                confidence=ConfidenceScore(0.9),
            ),
            ThreatMatch(
                rule_id="test-rule-002",
                rule_name="XSS Rule",
                description="XSS vulnerability",
                category="xss",
                severity=SeverityLevel.from_string("medium"),
                file_path=file_path,
                line_number=85,
                column_number=5,
                code_snippet="test",
                confidence=ConfidenceScore(0.7),
            ),
        ]

        result = ScanResult.create_from_threats(
            request=request, threats=threats, scan_metadata={}
        )

        injection_threats = result.get_threats_by_category("injection")
        xss_threats = result.get_threats_by_category("xss")

        assert len(injection_threats) == 1
        assert injection_threats[0].rule_id == "test-rule-001"

        assert len(xss_threats) == 1
        assert xss_threats[0].rule_id == "test-rule-002"

    def test_filter_by_confidence(self):
        """Test filter_by_confidence method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        threats = [
            ThreatMatch(
                rule_id="test-rule-001",
                rule_name="High Confidence Rule",
                description="High confidence issue",
                category="injection",
                severity=SeverityLevel.from_string("high"),
                file_path=file_path,
                line_number=42,
                column_number=10,
                code_snippet="test",
                confidence=ConfidenceScore(0.9),  # High confidence
            ),
            ThreatMatch(
                rule_id="test-rule-002",
                rule_name="Low Confidence Rule",
                description="Low confidence issue",
                category="xss",
                severity=SeverityLevel.from_string("medium"),
                file_path=file_path,
                line_number=85,
                column_number=5,
                code_snippet="test",
                confidence=ConfidenceScore(0.3),  # Low confidence
            ),
        ]

        result = ScanResult.create_from_threats(
            request=request, threats=threats, scan_metadata={}
        )

        high_confidence_result = result.filter_by_confidence(ConfidenceScore(0.7))

        assert len(high_confidence_result.threats) == 1
        assert high_confidence_result.threats[0].rule_id == "test-rule-001"

    def test_has_critical_threats(self):
        """Test has_critical_threats method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Result with critical threat
        critical_threat = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Critical Rule",
            description="Critical issue",
            category="injection",
            severity=SeverityLevel.from_string("critical"),
            file_path=file_path,
            line_number=42,
            column_number=10,
            code_snippet="test",
            confidence=ConfidenceScore(0.9),
        )

        result_with_critical = ScanResult.create_from_threats(
            request=request, threats=[critical_threat], scan_metadata={}
        )

        assert result_with_critical.has_critical_threats()

        # Result without critical threat
        medium_threat = ThreatMatch(
            rule_id="test-rule-002",
            rule_name="Medium Rule",
            description="Medium issue",
            category="xss",
            severity=SeverityLevel.from_string("medium"),
            file_path=file_path,
            line_number=85,
            column_number=5,
            code_snippet="test",
            confidence=ConfidenceScore(0.7),
        )

        result_without_critical = ScanResult.create_from_threats(
            request=request, threats=[medium_threat], scan_metadata={}
        )

        assert not result_without_critical.has_critical_threats()

    def test_is_empty(self):
        """Test is_empty method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            scan_type="file",
            timestamp=datetime.now(UTC),
            requester="test-user",
        )
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Empty result
        empty_result = ScanResult.create_empty(request)
        assert empty_result.is_empty()

        # Non-empty result
        threat = ThreatMatch(
            rule_id="test-rule-001",
            rule_name="Test Rule",
            description="Test issue",
            category="test",
            severity=SeverityLevel.from_string("medium"),
            file_path=file_path,
            line_number=42,
            column_number=10,
            code_snippet="test",
            confidence=ConfidenceScore(0.7),
        )

        non_empty_result = ScanResult.create_from_threats(
            request=request, threats=[threat], scan_metadata={}
        )

        assert not non_empty_result.is_empty()
