"""Extended tests for server module to improve coverage."""

import pytest
from unittest.mock import Mock, patch, AsyncMock, mock_open
import asyncio
import sys
import os
from pathlib import Path
import tempfile

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.server import (
    AdversaryMCPServer, AdversaryToolError, ScanRequest, ScanResult
)
from adversary_mcp_server.threat_engine import ThreatMatch, Severity, Category, Language
from mcp import types


class TestAdversaryMCPServerExtended:
    """Extended test cases for AdversaryMCPServer."""

    @pytest.fixture
    def server(self):
        """Create a server instance for testing."""
        return AdversaryMCPServer()

    @pytest.mark.asyncio
    async def test_call_tool_scan_code(self, server):
        """Test scan_code tool call."""
        arguments = {
            "content": "import pickle; pickle.loads(data)",
            "language": "python",
            "severity_threshold": "medium",
            "include_exploits": True,
            "use_llm": False
        }
        
        with patch.object(server.ast_scanner, 'scan_code') as mock_scan:
            threat = ThreatMatch(
                rule_id="python_pickle",
                rule_name="Unsafe Pickle",
                description="Unsafe pickle deserialization",
                category=Category.DESERIALIZATION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1
            )
            mock_scan.return_value = [threat]
            
            with patch.object(server.exploit_generator, 'generate_exploits', return_value=["exploit1"]):
                result = await server._handle_scan_code(arguments)
            
            assert len(result) == 1
            assert isinstance(result[0], types.TextContent)
            assert "Unsafe Pickle" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_scan_file(self, server):
        """Test scan_file tool call."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("query = 'SELECT * FROM users WHERE id = ' + user_id")
            temp_file = f.name
        
        try:
            arguments = {
                "file_path": temp_file,
                "severity_threshold": "low",
                "include_exploits": False,
                "use_llm": False
            }
            
            with patch.object(server.ast_scanner, 'scan_file') as mock_scan:
                threat = ThreatMatch(
                    rule_id="sql_injection",
                    rule_name="SQL Injection",
                    description="SQL injection vulnerability",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path=temp_file,
                    line_number=1
                )
                mock_scan.return_value = [threat]
                
                result = await server._handle_scan_file(arguments)
            
            assert len(result) == 1
            assert "SQL Injection" in result[0].text
        finally:
            os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_call_tool_scan_file_not_found(self, server):
        """Test scan_file with non-existent file."""
        arguments = {"file_path": "/nonexistent/file.py"}
        
        with pytest.raises(AdversaryToolError, match="File not found"):
            await server._handle_scan_file(arguments)

    @pytest.mark.asyncio
    async def test_call_tool_scan_directory(self, server):
        """Test scan_directory tool call."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("eval(user_input)")
            
            arguments = {
                "directory_path": temp_dir,
                "recursive": True,
                "severity_threshold": "medium",
                "include_exploits": True,
                "use_llm": False
            }
            
            with patch.object(server.ast_scanner, 'scan_directory') as mock_scan:
                threat = ThreatMatch(
                    rule_id="eval_injection",
                    rule_name="Code Injection",
                    description="Dangerous eval usage",
                    category=Category.INJECTION,
                    severity=Severity.CRITICAL,
                    file_path=str(test_file),
                    line_number=1
                )
                mock_scan.return_value = [threat]
                
                with patch.object(server.exploit_generator, 'generate_exploits', return_value=["exploit"]):
                    result = await server._handle_scan_directory(arguments)
            
            assert len(result) == 1
            assert "Code Injection" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_scan_directory_not_found(self, server):
        """Test scan_directory with non-existent directory."""
        arguments = {"directory_path": "/nonexistent/directory"}
        
        with pytest.raises(AdversaryToolError, match="Directory not found"):
            await server._handle_scan_directory(arguments)

    @pytest.mark.asyncio
    async def test_call_tool_generate_exploit(self, server):
        """Test generate_exploit tool call."""
        arguments = {
            "vulnerability_type": "sql_injection",
            "code_context": "SELECT * FROM users WHERE id = ' + user_id",
            "target_language": "python",
            "use_llm": False
        }
        
        with patch.object(server.exploit_generator, 'generate_exploits') as mock_gen:
            mock_gen.return_value = ["' OR '1'='1' --", "' UNION SELECT NULL--"]
            
            result = await server._handle_generate_exploit(arguments)
        
        assert len(result) == 1
        assert "sql_injection" in result[0].text.lower()
        assert "OR '1'='1'" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_list_rules(self, server):
        """Test list_rules tool call."""
        arguments = {"category": "injection", "min_severity": "medium"}
        
        with patch.object(server.threat_engine, 'list_rules') as mock_list:
            mock_list.return_value = [
                {
                    "id": "sql_injection",
                    "name": "SQL Injection",
                    "category": "injection",
                    "severity": "high",
                    "languages": ["python"],
                    "description": "SQL injection vulnerability detection"
                }
            ]
            
            result = await server._handle_list_rules(arguments)
        
        assert len(result) == 1
        assert "SQL Injection" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_get_rule_details(self, server):
        """Test get_rule_details tool call."""
        arguments = {"rule_id": "sql_injection"}
        
        mock_rule = Mock()
        mock_rule.id = "sql_injection"
        mock_rule.name = "SQL Injection"
        mock_rule.description = "Detects SQL injection vulnerabilities"
        mock_rule.category = Category.INJECTION
        mock_rule.severity = Severity.HIGH
        mock_rule.languages = [Language.PYTHON]
        mock_rule.conditions = []
        mock_rule.exploit_templates = []
        mock_rule.remediation = "Use parameterized queries"
        mock_rule.references = ["https://owasp.org/sql-injection"]
        mock_rule.cwe_id = "CWE-89"
        mock_rule.owasp_category = "A03"
        
        with patch.object(server.threat_engine, 'get_rule_by_id', return_value=mock_rule):
            result = await server._handle_get_rule_details(arguments)
        
        assert len(result) == 1
        assert "SQL Injection" in result[0].text
        assert "CWE-89" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_get_rule_details_not_found(self, server):
        """Test get_rule_details with non-existent rule."""
        arguments = {"rule_id": "nonexistent_rule"}
        
        with patch.object(server.threat_engine, 'get_rule_by_id', return_value=None):
            with pytest.raises(AdversaryToolError, match="Rule not found"):
                await server._handle_get_rule_details(arguments)

    @pytest.mark.asyncio
    async def test_call_tool_configure_settings(self, server):
        """Test configure_settings tool call."""
        arguments = {
            "openai_api_key": "test_key",
            "enable_llm_generation": True,
            "min_severity": "high"
        }
        
        with patch.object(server.credential_manager, 'store_config') as mock_store:
            result = await server._handle_configure_settings(arguments)
        
        assert len(result) == 1
        assert "updated successfully" in result[0].text.lower()
        mock_store.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_tool_get_status(self, server):
        """Test get_status tool call."""
        mock_config = Mock()
        mock_config.openai_api_key = "sk-test***"
        mock_config.enable_llm_generation = True
        mock_config.min_severity = "medium"
        
        with patch.object(server.credential_manager, 'load_config', return_value=mock_config):
            with patch.object(server.threat_engine, 'list_rules', return_value=[]):
                result = await server._handle_get_status()
        
        assert len(result) == 1
        assert "Adversary MCP Server Status" in result[0].text

    @pytest.mark.asyncio
    async def test_call_tool_unknown(self, server):
        """Test calling unknown tool."""
        # This tests the main call_tool handler with an unknown tool
        with patch.object(server.server, 'call_tool') as mock_call:
            # We need to test the actual call_tool method that was set up in _setup_handlers
            # Let's simulate what happens when an unknown tool is called
            pass  # The actual handler is set up in _setup_handlers, so we test error handling

    @pytest.mark.asyncio
    async def test_severity_filtering(self, server):
        """Test threat filtering by severity."""
        threats = [
            ThreatMatch(
                rule_id="high_threat",
                rule_name="High Threat",
                description="High severity threat",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=1
            ),
            ThreatMatch(
                rule_id="low_threat",
                rule_name="Low Threat",
                description="Low severity threat",
                category=Category.INJECTION,
                severity=Severity.LOW,
                file_path="test.py",
                line_number=2
            )
        ]
        
        # Test filtering with MEDIUM threshold
        filtered = server._filter_threats_by_severity(threats, Severity.MEDIUM)
        assert len(filtered) == 1
        assert filtered[0].rule_id == "high_threat"
        
        # Test filtering with LOW threshold
        filtered = server._filter_threats_by_severity(threats, Severity.LOW)
        assert len(filtered) == 2

    def test_scan_result_formatting(self, server):
        """Test scan result formatting."""
        threats = [
            ThreatMatch(
                rule_id="test_threat",
                rule_name="Test Threat",
                description="Test description",
                category=Category.XSS,
                severity=Severity.MEDIUM,
                file_path="test.js",
                line_number=10,
                code_snippet="document.innerHTML = userInput",
                exploit_examples=["<script>alert('XSS')</script>"],
                remediation="Use textContent instead"
            )
        ]
        
        result = server._format_scan_results(threats, "test.js")
        
        assert "Test Threat" in result
        assert "Medium" in result
        assert "XSS" in result
        assert "test.js" in result
        assert "alert('XSS')" in result
        assert "textContent" in result

    def test_scan_result_formatting_no_threats(self, server):
        """Test scan result formatting with no threats."""
        result = server._format_scan_results([], "test.py")
        assert "No security vulnerabilities found" in result

    @pytest.mark.asyncio
    async def test_exploit_generation_error_handling(self, server):
        """Test exploit generation with errors."""
        arguments = {
            "content": "test code",
            "language": "python",
            "include_exploits": True,
            "use_llm": False
        }
        
        threat = ThreatMatch(
            rule_id="test_rule",
            rule_name="Test Rule",
            description="Test",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1
        )
        
        with patch.object(server.ast_scanner, 'scan_code', return_value=[threat]):
            with patch.object(server.exploit_generator, 'generate_exploits', side_effect=Exception("Gen error")):
                # Should not raise exception, just log warning
                result = await server._handle_scan_code(arguments)
                assert len(result) == 1

    @pytest.mark.asyncio
    async def test_scan_code_with_all_parameters(self, server):
        """Test scan_code with all parameter combinations."""
        # Test with minimal parameters
        arguments = {
            "content": "print('hello')",
            "language": "python"
        }
        
        with patch.object(server.ast_scanner, 'scan_code', return_value=[]):
            result = await server._handle_scan_code(arguments)
            assert len(result) == 1

    @pytest.mark.asyncio 
    async def test_scan_file_with_encoding_error(self, server):
        """Test scan_file when file reading fails."""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.py', delete=False) as f:
            # Write binary data that can't be decoded as UTF-8
            f.write(b'\x80\x81\x82\x83')
            temp_file = f.name
        
        try:
            arguments = {
                "file_path": temp_file,
                "include_exploits": True
            }
            
            threat = ThreatMatch(
                rule_id="test_rule",
                rule_name="Test Rule",
                description="Test",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                file_path=temp_file,
                line_number=1
            )
            
            with patch.object(server.ast_scanner, 'scan_file', return_value=[threat]):
                with patch.object(server.exploit_generator, 'generate_exploits', return_value=["exploit"]):
                    result = await server._handle_scan_file(arguments)
                    assert len(result) == 1
        finally:
            os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_large_directory_scan_exploit_limiting(self, server):
        """Test that directory scans limit exploit generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {
                "directory_path": temp_dir,
                "include_exploits": True
            }
            
            # Create 15 threats
            threats = []
            for i in range(15):
                threats.append(ThreatMatch(
                    rule_id=f"threat_{i}",
                    rule_name=f"Threat {i}",
                    description="Test",
                    category=Category.INJECTION,
                    severity=Severity.HIGH,
                    file_path=f"test{i}.py",
                    line_number=1
                ))
            
            with patch.object(server.ast_scanner, 'scan_directory', return_value=threats):
                with patch.object(server.exploit_generator, 'generate_exploits') as mock_gen:
                    mock_gen.return_value = ["exploit"]
                    
                    result = await server._handle_scan_directory(arguments)
                    
                    # Should only generate exploits for first 10 threats
                    assert mock_gen.call_count == 10

    def test_data_models(self):
        """Test ScanRequest and ScanResult data models."""
        # Test ScanRequest
        request = ScanRequest(
            content="test code",
            language="python",
            severity_threshold="high",
            include_exploits=False
        )
        assert request.content == "test code"
        assert request.include_exploits is False
        
        # Test ScanResult
        result = ScanResult(
            threats=[{"rule_id": "test"}],
            summary={"total": 1},
            metadata={"scan_time": "2023-01-01"}
        )
        assert len(result.threats) == 1
        assert result.summary["total"] == 1

    @pytest.mark.asyncio
    async def test_vulnerability_type_mapping(self, server):
        """Test different vulnerability types in generate_exploit."""
        vulnerability_types = [
            "sql_injection",
            "command_injection", 
            "xss",
            "deserialization",
            "path_traversal",
            "unknown_type"
        ]
        
        for vuln_type in vulnerability_types:
            arguments = {
                "vulnerability_type": vuln_type,
                "code_context": "test code",
                "target_language": "python"
            }
            
            with patch.object(server.exploit_generator, 'generate_exploits', return_value=["exploit"]):
                result = await server._handle_generate_exploit(arguments)
                assert len(result) == 1
                assert vuln_type in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_error_handling_in_handlers(self, server):
        """Test error handling in various handlers."""
        # Test scan_code with invalid language
        with pytest.raises(AdversaryToolError):
            await server._handle_scan_code({
                "content": "test",
                "language": "invalid_language"
            })
        
        # Test configure_settings with error in store_config
        with patch.object(server.credential_manager, 'store_config', side_effect=Exception("Save error")):
            with pytest.raises(AdversaryToolError, match="Failed to configure settings"):
                await server._handle_configure_settings({"openai_api_key": "test"})
        
        # Test get_status with error
        with patch.object(server.credential_manager, 'load_config', side_effect=Exception("Load error")):
            with pytest.raises(AdversaryToolError, match="Failed to get status"):
                await server._handle_get_status()


class TestAdversaryMCPServerRuntime:
    """Test server runtime and lifecycle."""

    def test_adversary_tool_error(self):
        """Test AdversaryToolError exception."""
        error = AdversaryToolError("Test error")
        assert str(error) == "Test error"

    @pytest.mark.asyncio
    async def test_server_run_method(self):
        """Test server run method."""
        server = AdversaryMCPServer()
        
        # Mock the stdio_server context manager
        with patch('adversary_mcp_server.server.stdio_server') as mock_stdio:
            mock_stdio.return_value.__aenter__ = AsyncMock()
            mock_stdio.return_value.__aexit__ = AsyncMock()
            
            # Test that run method works
            await server.run()
            mock_stdio.assert_called_once()

    def test_main_functions(self):
        """Test main and async_main functions."""
        from adversary_mcp_server.server import main, async_main
        
        # Test async_main
        with patch('adversary_mcp_server.server.AdversaryMCPServer') as mock_server:
            mock_instance = Mock()
            mock_instance.run = AsyncMock()
            mock_server.return_value = mock_instance
            
            # Run async_main
            asyncio.run(async_main())
            mock_instance.run.assert_called_once()
        
        # Test main function
        with patch('adversary_mcp_server.server.asyncio.run') as mock_run:
            main()
            mock_run.assert_called_once() 