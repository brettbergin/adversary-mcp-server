import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from adversary_mcp_server.scanner.scan_engine import EnhancedScanResult
from adversary_mcp_server.scanner.types import Category, Severity, ThreatMatch
from adversary_mcp_server.server import AdversaryMCPServer, AdversaryToolError


def _make_result_with_threat(file_path: str = "test.py") -> EnhancedScanResult:
    threat = ThreatMatch(
        rule_id="eval_usage",
        rule_name="Eval Usage",
        description="Use of eval()",
        category=Category.INJECTION,
        severity=Severity.HIGH,
        file_path=file_path,
        line_number=5,
        code_snippet="eval(x)",
    )
    result = EnhancedScanResult(
        file_path=file_path,
        llm_threats=[],
        semgrep_threats=[threat],
        scan_metadata={
            "rules_scan_success": True,
            "semgrep_scan_success": True,
            "llm_scan_success": False,
            "semgrep_status": {"available": True, "version": "1.0.0"},
            "source_lines": 10,
        },
    )
    return result


@pytest.mark.asyncio
async def test_handle_scan_code_markdown_and_invalid_output():
    server = AdversaryMCPServer()
    result_obj = _make_result_with_threat("input.code")

    with patch.object(server.scan_engine, "scan_code", return_value=result_obj):
        with tempfile.TemporaryDirectory() as tmp:
            ok_args = {
                "content": "print('hi')",
                "path": tmp,
                "use_llm": False,
                "use_semgrep": False,
                "output_format": "markdown",
            }
            out = await server._handle_scan_code(ok_args)
            assert out and out[0].type == "text"
            assert "Format:" in out[0].text and "markdown" in out[0].text

        bad_args = {
            "content": "print('hi')",
            "output_format": "xml",
        }
        with pytest.raises(AdversaryToolError):
            await server._handle_scan_code(bad_args)


@pytest.mark.asyncio
async def test_handle_scan_file_markdown_and_invalid_output(tmp_path: Path):
    server = AdversaryMCPServer()
    test_file = tmp_path / "x.py"
    test_file.write_text("print('hi')")
    result_obj = _make_result_with_threat(str(test_file))

    with patch.object(server.scan_engine, "scan_file", return_value=result_obj):
        ok_args = {
            "path": str(test_file),
            "use_llm": False,
            "use_semgrep": False,
            "output_format": "markdown",
        }
        out = await server._handle_scan_file(ok_args)
        assert out and out[0].type == "text"
        assert "Format:" in out[0].text and "markdown" in out[0].text

        bad_args = {
            "path": str(test_file),
            "output_format": "xml",
        }
        with pytest.raises(AdversaryToolError):
            await server._handle_scan_file(bad_args)


@pytest.mark.asyncio
async def test_handle_scan_directory_markdown_llm_and_invalid_output(tmp_path: Path):
    server = AdversaryMCPServer()
    result_obj = _make_result_with_threat(str(tmp_path / "a.py"))

    with patch.object(server.scan_engine, "scan_directory", return_value=[result_obj]):
        ok_args = {
            "path": str(tmp_path),
            "recursive": True,
            "use_llm": True,
            "use_semgrep": False,
            "output_format": "markdown",
        }
        out = await server._handle_scan_directory(ok_args)
        assert out and out[0].type == "text"
        assert "Format:" in out[0].text and "markdown" in out[0].text
        assert "LLM analysis prompts" in out[0].text

        bad_args = {
            "path": str(tmp_path),
            "output_format": "xml",
        }
        with pytest.raises(AdversaryToolError):
            await server._handle_scan_directory(bad_args)


@pytest.mark.asyncio
async def test_handle_diff_scan_markdown_and_invalid_output(tmp_path: Path):
    server = AdversaryMCPServer()

    mock_diff_summary = {
        "source_branch": "feature",
        "target_branch": "main",
        "total_files_changed": 1,
        "supported_files": 1,
        "lines_added": 1,
        "lines_removed": 0,
        "scannable_files": ["test.py"],
    }

    result_obj = _make_result_with_threat("test.py")
    scan_results = {"test.py": [result_obj]}

    server.diff_scanner.get_diff_summary = AsyncMock(return_value=mock_diff_summary)
    server.diff_scanner.scan_diff = AsyncMock(return_value=scan_results)

    ok_args = {
        "source_branch": "feature",
        "target_branch": "main",
        "path": str(tmp_path),
        "use_llm": False,
        "use_semgrep": False,
        "include_exploits": False,
        "output_format": "markdown",
    }
    # Bypass git repo check for test temp directory
    with patch.object(server, "_validate_git_directory_path", return_value=tmp_path):
        out = await server._handle_diff_scan(ok_args)
    assert out and out[0].type == "text"
    assert "Format:" in out[0].text and "markdown" in out[0].text

    bad_args = {
        "source_branch": "feature",
        "target_branch": "main",
        "path": str(tmp_path),
        "output_format": "xml",
    }
    with pytest.raises(AdversaryToolError):
        await server._handle_diff_scan(bad_args)


def test_save_scan_results_json_with_invalid_json():
    server = AdversaryMCPServer()
    with tempfile.TemporaryDirectory() as tmp:
        # invalid json should be written unchanged
        saved = server._save_scan_results_json("not-json", tmp)
        assert saved is not None
        p = Path(saved)
        assert p.exists() and p.read_text() == "not-json"


def test_aggregate_validation_stats_paths():
    server = AdversaryMCPServer()

    # Empty results
    stats = server._aggregate_validation_stats([])
    assert stats["enabled"] is False and stats["status"] == "no_results"

    # No validation enabled, with reasons
    res1 = EnhancedScanResult(
        file_path="f.py",
        llm_threats=[],
        semgrep_threats=[],
        scan_metadata={
            "llm_validation_success": False,
            "llm_validation_reason": "disabled",
        },
    )
    stats2 = server._aggregate_validation_stats([res1])
    assert stats2["enabled"] is False and stats2["status"] == "disabled"

    # With validation results
    threat = ThreatMatch(
        rule_id="r1",
        rule_name="R1",
        description="d",
        category=Category.INJECTION,
        severity=Severity.LOW,
        file_path="f.py",
        line_number=1,
    )
    val_obj = SimpleNamespace(
        is_legitimate=True,
        confidence=0.9,
        validation_error=False,
    )
    res2 = EnhancedScanResult(
        file_path="f.py",
        llm_threats=[],
        semgrep_threats=[threat],
        scan_metadata={"llm_validation_success": True},
    )
    res2.validation_results = {threat.uuid: val_obj}
    stats3 = server._aggregate_validation_stats([res2])
    assert stats3["enabled"] is True and stats3["total_findings_reviewed"] == 1


def test_format_scanner_status_semgrep_unavailable():
    server = AdversaryMCPServer()
    res = EnhancedScanResult(
        file_path="f.py",
        llm_threats=[],
        semgrep_threats=[],
        scan_metadata={
            "semgrep_status": {
                "available": False,
                "error": "not installed",
                "installation_guidance": "brew install semgrep",
            }
        },
    )
    text = server._format_scanner_status([res])
    assert "Not Available" in text and "brew install" in text


def test_add_llm_exploit_prompts_success_and_error():
    server = AdversaryMCPServer()
    threat = ThreatMatch(
        rule_id="r1",
        rule_name="R1",
        description="d",
        category=Category.INJECTION,
        severity=Severity.MEDIUM,
        file_path="f.py",
        line_number=1,
    )
    # Success
    with patch.object(
        server.exploit_generator,
        "create_exploit_prompt",
        return_value=SimpleNamespace(system_prompt="sys", user_prompt="user"),
    ):
        text = server._add_llm_exploit_prompts([threat], "code")
        assert "LLM Exploit Generation" in text and "sys" in text and "user" in text

    # Error path
    with patch.object(
        server.exploit_generator, "create_exploit_prompt", side_effect=Exception("x")
    ):
        text = server._add_llm_exploit_prompts([threat], "code")
        assert "Failed to create exploit prompt" in text
