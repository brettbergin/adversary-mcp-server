"""Focused tests to improve coverage for ScanResult entity methods."""

import pytest

from adversary_mcp_server.domain.entities.scan_request import ScanRequest
from adversary_mcp_server.domain.entities.scan_result import ScanResult
from adversary_mcp_server.domain.entities.threat_match import ThreatMatch
from adversary_mcp_server.domain.value_objects.confidence_score import ConfidenceScore
from adversary_mcp_server.domain.value_objects.file_path import FilePath
from adversary_mcp_server.domain.value_objects.scan_context import ScanContext
from adversary_mcp_server.domain.value_objects.scan_metadata import ScanMetadata
from adversary_mcp_server.domain.value_objects.severity_level import SeverityLevel


class TestScanResultFocused:
    """Tests targeting uncovered code paths in ScanResult."""

    def test_add_threat_method(self):
        """Test add_threat method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Start with empty result
        result = ScanResult.create_empty(request)
        assert len(result.threats) == 0

        # Add a threat
        threat = ThreatMatch(
            rule_id="new-threat",
            rule_name="New Threat",
            description="Newly added threat",
            category="disclosure",
            severity=SeverityLevel.from_string("low"),
            file_path=file_path,
            line_number=15,
            column_number=3,
            code_snippet="password = 'secret'",
            confidence=ConfidenceScore(0.6),
        )

        new_result = result.add_threat(threat)

        # Original should be unchanged
        assert len(result.threats) == 0
        # New result should have the threat
        assert len(new_result.threats) == 1
        assert new_result.threats[0] == threat

    def test_add_threats_method(self):
        """Test add_threats method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Start with empty result
        result = ScanResult.create_empty(request)

        # Add multiple threats
        threats = [
            ThreatMatch(
                rule_id="threat1",
                rule_name="Threat 1",
                description="First threat",
                category="injection",
                severity=SeverityLevel.from_string("high"),
                file_path=file_path,
                line_number=10,
                column_number=1,
                code_snippet="sql injection",
                confidence=ConfidenceScore(0.8),
            ),
            ThreatMatch(
                rule_id="threat2",
                rule_name="Threat 2",
                description="Second threat",
                category="xss",
                severity=SeverityLevel.from_string("medium"),
                file_path=file_path,
                line_number=20,
                column_number=5,
                code_snippet="xss vulnerability",
                confidence=ConfidenceScore(0.7),
            ),
        ]

        new_result = result.add_threats(threats)

        # Original should be unchanged
        assert len(result.threats) == 0
        # New result should have both threats
        assert len(new_result.threats) == 2

    def test_add_threats_empty_list(self):
        """Test add_threats method with empty list."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        result = ScanResult.create_empty(request)

        # Adding empty list should return same result
        new_result = result.add_threats([])
        assert new_result is result  # Should return same instance

    def test_apply_validation_results_method(self):
        """Test apply_validation_results method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Original threat
        original_threat = ThreatMatch(
            rule_id="original",
            rule_name="Original Threat",
            description="Original threat",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=file_path,
            line_number=10,
            column_number=1,
            code_snippet="original code",
            confidence=ConfidenceScore(0.7),
        )

        result = ScanResult.create_from_threats(request, [original_threat])

        # Validated threat with same fingerprint
        validated_threat = ThreatMatch(
            rule_id="validated",
            rule_name="Validated Threat",
            description="Validated threat",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=file_path,
            line_number=10,  # Same location = same fingerprint
            column_number=1,
            code_snippet="validated code",
            confidence=ConfidenceScore(0.9),  # Higher confidence
        )

        validated_result = result.apply_validation_results([validated_threat])

        assert validated_result.validation_applied is True
        assert len(validated_result.threats) == 1
        assert validated_result.threats[0].rule_id == "validated"

    def test_merge_with_method(self):
        """Test merge_with method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # First result
        threat1 = ThreatMatch(
            rule_id="threat1",
            rule_name="Threat 1",
            description="First threat",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=file_path,
            line_number=10,
            column_number=1,
            code_snippet="threat 1 code",
            confidence=ConfidenceScore(0.8),
        )
        result1 = ScanResult.create_from_threats(request, [threat1])

        # Second result with different threat
        threat2 = ThreatMatch(
            rule_id="threat2",
            rule_name="Threat 2",
            description="Second threat",
            category="xss",
            severity=SeverityLevel.from_string("medium"),
            file_path=file_path,
            line_number=20,
            column_number=1,
            code_snippet="threat 2 code",
            confidence=ConfidenceScore(0.7),
        )
        result2 = ScanResult.create_from_threats(request, [threat2])

        # Merge results
        merged = result1.merge_with(result2)

        assert len(merged.threats) == 2
        threat_ids = {t.rule_id for t in merged.threats}
        assert "threat1" in threat_ids
        assert "threat2" in threat_ids

    def test_merge_with_same_scan_id_error(self):
        """Test merge_with method with different scan IDs."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")

        # Different metadata with different scan IDs
        metadata1 = ScanMetadata.for_file_scan(requester="user1")
        metadata2 = ScanMetadata.for_file_scan(requester="user2")

        context1 = ScanContext(target_path=file_path, metadata=metadata1)
        context2 = ScanContext(target_path=file_path, metadata=metadata2)

        request1 = ScanRequest(context=context1)
        request2 = ScanRequest(context=context2)

        result1 = ScanResult.create_empty(request1)
        result2 = ScanResult.create_empty(request2)

        # Should raise error for different scan IDs
        with pytest.raises(
            ValueError, match="Cannot merge scan results from different scan operations"
        ):
            result1.merge_with(result2)

    def test_get_overall_risk_score_method(self):
        """Test get_overall_risk_score method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Empty result
        empty_result = ScanResult.create_empty(request)
        assert empty_result.get_overall_risk_score() == 0.0

        # Result with threats
        threats = [
            ThreatMatch(
                rule_id="high-risk",
                rule_name="High Risk",
                description="High risk threat",
                category="injection",
                severity=SeverityLevel.from_string("critical"),
                file_path=file_path,
                line_number=10,
                column_number=1,
                code_snippet="critical code",
                confidence=ConfidenceScore(0.9),
            ),
            ThreatMatch(
                rule_id="low-risk",
                rule_name="Low Risk",
                description="Low risk threat",
                category="info",
                severity=SeverityLevel.from_string("low"),
                file_path=file_path,
                line_number=20,
                column_number=1,
                code_snippet="low priority code",
                confidence=ConfidenceScore(0.5),
            ),
        ]

        result = ScanResult.create_from_threats(request, threats)
        risk_score = result.get_overall_risk_score()

        assert 0.0 <= risk_score <= 10.0
        assert risk_score > 0  # Should be positive with threats

    def test_get_security_posture_method(self):
        """Test get_security_posture method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Clean result
        clean_result = ScanResult.create_empty(request)
        posture = clean_result.get_security_posture()
        assert posture in ["Excellent", "Good", "Fair", "Poor", "Critical"]

        # Critical threat
        critical_threat = ThreatMatch(
            rule_id="critical",
            rule_name="Critical Threat",
            description="Critical issue",
            category="injection",
            severity=SeverityLevel.from_string("critical"),
            file_path=file_path,
            line_number=10,
            column_number=1,
            code_snippet="critical code",
            confidence=ConfidenceScore(0.9),
        )

        critical_result = ScanResult.create_from_threats(request, [critical_threat])
        critical_posture = critical_result.get_security_posture()
        assert critical_posture == "Critical"

    def test_needs_immediate_attention_method(self):
        """Test needs_immediate_attention method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        # Clean result
        clean_result = ScanResult.create_empty(request)
        assert clean_result.needs_immediate_attention() is False

        # Critical threat
        critical_threat = ThreatMatch(
            rule_id="critical",
            rule_name="Critical Threat",
            description="Critical issue",
            category="injection",
            severity=SeverityLevel.from_string("critical"),
            file_path=file_path,
            line_number=10,
            column_number=1,
            code_snippet="critical code",
            confidence=ConfidenceScore(0.9),
        )

        critical_result = ScanResult.create_from_threats(request, [critical_threat])
        assert critical_result.needs_immediate_attention() is True

    def test_clear_caches_method(self):
        """Test clear_caches method."""
        file_path = FilePath.from_string("examples/vulnerable_python.py")
        metadata = ScanMetadata.for_file_scan(requester="test-user")
        context = ScanContext(target_path=file_path, metadata=metadata)
        request = ScanRequest(context=context)

        threat = ThreatMatch(
            rule_id="cache-test",
            rule_name="Cache Test",
            description="Testing cache clearing",
            category="injection",
            severity=SeverityLevel.from_string("high"),
            file_path=file_path,
            line_number=10,
            column_number=1,
            code_snippet="cache test code",
            confidence=ConfidenceScore(0.8),
        )

        result = ScanResult.create_from_threats(request, [threat])

        # Access cached properties to populate caches
        stats = result.get_statistics()
        threats_by_file = result.get_threats_by_file()
        high_priority = result.get_high_priority_threats()

        # Clear caches
        result.clear_caches()

        # Accessing again should recompute (no way to directly test cache state,
        # but this ensures the method doesn't crash)
        new_stats = result.get_statistics()
        assert new_stats is not None
