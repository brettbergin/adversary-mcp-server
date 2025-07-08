"""LLM-based security analyzer for detecting code vulnerabilities using AI."""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import openai
from openai import OpenAI

from .credential_manager import CredentialManager, SecurityConfig
from .threat_engine import Category, Language, Severity, ThreatMatch

logger = logging.getLogger(__name__)


class LLMAnalysisError(Exception):
    """Exception raised when LLM analysis fails."""
    pass


class LLMSecurityFinding:
    """A security finding from LLM analysis."""
    
    def __init__(
        self,
        finding_type: str,
        severity: str,
        description: str,
        line_number: int,
        code_snippet: str,
        explanation: str,
        recommendation: str,
        confidence: float,
        cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
    ):
        """Initialize LLM security finding.
        
        Args:
            finding_type: Type of security issue (e.g., 'sql_injection', 'xss')
            severity: Severity level (low, medium, high, critical)
            description: Brief description of the issue
            line_number: Line number where issue was found
            code_snippet: Code snippet containing the issue
            explanation: Detailed explanation of the vulnerability
            recommendation: Remediation recommendation
            confidence: Confidence level (0.0 to 1.0)
            cwe_id: CWE identifier if applicable
            owasp_category: OWASP category if applicable
        """
        self.finding_type = finding_type
        self.severity = severity
        self.description = description
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.explanation = explanation
        self.recommendation = recommendation
        self.confidence = confidence
        self.cwe_id = cwe_id
        self.owasp_category = owasp_category
    
    def to_threat_match(self, file_path: str) -> ThreatMatch:
        """Convert to ThreatMatch for integration with existing system.
        
        Args:
            file_path: Path to the source file
            
        Returns:
            ThreatMatch object
        """
        # Map finding types to categories
        type_to_category = {
            'sql_injection': Category.INJECTION,
            'command_injection': Category.INJECTION,
            'xss': Category.XSS,
            'deserialization': Category.DESERIALIZATION,
            'path_traversal': Category.LFI,
            'file_inclusion': Category.LFI,
            'lfi': Category.LFI,
            'rfi': Category.LFI,
            'hardcoded_credential': Category.SECRETS,
            'weak_crypto': Category.CRYPTOGRAPHY,
            'insecure_random': Category.CRYPTOGRAPHY,
            'improper_input_validation': Category.VALIDATION,
            'information_disclosure': Category.DISCLOSURE,
            'session_fixation': Category.SESSION,
            'csrf': Category.CSRF,
            'clickjacking': Category.CLICKJACKING,
            'race_condition': Category.INJECTION,  # No specific category, use closest
            'dos': Category.DOS,
            'buffer_overflow': Category.INJECTION,  # No specific category, use closest
            'integer_overflow': Category.INJECTION,  # No specific category, use closest
            'format_string': Category.INJECTION,  # No specific category, use closest
            'use_after_free': Category.INJECTION,  # No specific category, use closest
            'null_pointer_dereference': Category.INJECTION,  # No specific category, use closest
            'uninitialized_variable': Category.INJECTION,  # No specific category, use closest
            'logic_error': Category.VALIDATION,  # No specific category, use closest
            'authentication_bypass': Category.AUTHENTICATION,
            'authorization_bypass': Category.AUTHORIZATION,
            'privilege_escalation': Category.ACCESS_CONTROL,
            'ssrf': Category.SSRF,
            'xxe': Category.XXE,
            'redirect': Category.REDIRECT,
            'file_upload': Category.FILE_UPLOAD,
            'header_injection': Category.HEADERS,
            'rce': Category.RCE,
            'idor': Category.IDOR,
        }
        
        # Map severity strings to enum
        severity_map = {
            'low': Severity.LOW,
            'medium': Severity.MEDIUM,
            'high': Severity.HIGH,
            'critical': Severity.CRITICAL
        }
        
        category = type_to_category.get(self.finding_type.lower(), Category.INJECTION)
        severity = severity_map.get(self.severity.lower(), Severity.MEDIUM)
        
        return ThreatMatch(
            rule_id=f"llm_{self.finding_type}",
            rule_name=f"LLM: {self.finding_type.replace('_', ' ').title()}",
            description=self.description,
            category=category,
            severity=severity,
            file_path=file_path,
            line_number=self.line_number,
            code_snippet=self.code_snippet,
            function_name=None,
            exploit_examples=[],
            remediation=self.recommendation,
            references=[],
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            confidence=self.confidence,
        )


class LLMSecurityAnalyzer:
    """LLM-based security analyzer using OpenAI."""
    
    def __init__(self, credential_manager: CredentialManager):
        """Initialize the LLM security analyzer.
        
        Args:
            credential_manager: Credential manager for configuration
        """
        self.credential_manager = credential_manager
        self.config = credential_manager.load_config()
        self.client = None
        
        if self.config.openai_api_key:
            self.client = OpenAI(api_key=self.config.openai_api_key)
        else:
            logger.warning("OpenAI API key not configured. LLM analysis disabled.")
    
    def is_available(self) -> bool:
        """Check if LLM analysis is available.
        
        Returns:
            True if LLM analysis is available
        """
        return self.client is not None and bool(self.config.openai_api_key)
    
    def analyze_code(
        self, 
        source_code: str, 
        file_path: str, 
        language: Language,
        max_findings: int = 20
    ) -> List[LLMSecurityFinding]:
        """Analyze code for security vulnerabilities using LLM.
        
        Args:
            source_code: Source code to analyze
            file_path: Path to the source file
            language: Programming language
            max_findings: Maximum number of findings to return
            
        Returns:
            List of LLM security findings
            
        Raises:
            LLMAnalysisError: If analysis fails
        """
        if not self.is_available():
            raise LLMAnalysisError("LLM analysis not available - API key not configured")
        
        try:
            prompt = self._create_analysis_prompt(source_code, language, max_findings)
            
            response = self.client.chat.completions.create(
                model=self.config.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt(),
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                max_tokens=self.config.openai_max_tokens,
                temperature=0.1,  # Low temperature for more consistent analysis
                response_format={"type": "json_object"}
            )
            
            response_text = response.choices[0].message.content
            return self._parse_analysis_response(response_text, file_path)
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            raise LLMAnalysisError(f"LLM analysis failed: {e}")
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for security analysis.
        
        Returns:
            System prompt string
        """
        return """You are a senior security engineer performing static code analysis. 
Your task is to analyze code for security vulnerabilities and provide detailed, actionable findings.

Guidelines:
1. Focus on real security issues, not code style or minor concerns
2. Provide specific line numbers and code snippets
3. Include detailed explanations of why something is vulnerable
4. Offer concrete remediation advice
5. Assign appropriate severity levels (low, medium, high, critical)
6. Be precise about vulnerability types and CWE mappings
7. Avoid false positives - only report genuine security concerns
8. Consider the full context of the code when making assessments

Response format: JSON object with "findings" array containing security issues.
Each finding should have: type, severity, description, line_number, code_snippet, explanation, recommendation, confidence, cwe_id (optional), owasp_category (optional).

Vulnerability types to look for:
- SQL injection, Command injection, Code injection
- Cross-site scripting (XSS)
- Path traversal, Directory traversal
- Deserialization vulnerabilities
- Hardcoded credentials, API keys
- Weak cryptography, insecure random numbers
- Input validation issues
- Authentication/authorization bypasses
- Session management flaws
- CSRF vulnerabilities
- Information disclosure
- Logic errors with security implications
- Memory safety issues (buffer overflows, etc.)
- Race conditions
- Denial of service vulnerabilities"""
    
    def _create_analysis_prompt(self, source_code: str, language: Language, max_findings: int) -> str:
        """Create analysis prompt for the given code.
        
        Args:
            source_code: Source code to analyze
            language: Programming language
            max_findings: Maximum number of findings
            
        Returns:
            Formatted prompt string
        """
        # Truncate very long code to fit in token limits
        max_code_length = 8000  # Leave room for prompt and response
        if len(source_code) > max_code_length:
            source_code = source_code[:max_code_length] + "\n... [truncated for analysis]"
        
        prompt = f"""Analyze the following {language.value} code for security vulnerabilities:

```{language.value}
{source_code}
```

Please provide up to {max_findings} security findings in JSON format.

Requirements:
- Focus on genuine security vulnerabilities
- Provide specific line numbers (1-indexed)
- Include the vulnerable code snippet
- Explain why each finding is a security risk
- Suggest specific remediation steps
- Assign confidence scores (0.0-1.0)
- Map to CWE IDs where applicable
- Classify by OWASP categories where relevant

Response format:
{{
  "findings": [
    {{
      "type": "vulnerability_type",
      "severity": "low|medium|high|critical",
      "description": "brief description",
      "line_number": 42,
      "code_snippet": "vulnerable code",
      "explanation": "detailed explanation",
      "recommendation": "how to fix",
      "confidence": 0.9,
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021"
    }}
  ]
}}"""
        
        return prompt
    
    def _parse_analysis_response(self, response_text: str, file_path: str) -> List[LLMSecurityFinding]:
        """Parse LLM analysis response into security findings.
        
        Args:
            response_text: JSON response from LLM
            file_path: Path to the analyzed file
            
        Returns:
            List of LLM security findings
        """
        try:
            response_data = json.loads(response_text)
            findings = []
            
            if "findings" not in response_data:
                logger.warning("No 'findings' key in LLM response")
                return findings
            
            for finding_data in response_data["findings"]:
                try:
                    # Validate and convert line_number to int
                    line_number = finding_data.get("line_number", 1)
                    if not isinstance(line_number, int):
                        # Try to convert to int, skip if it fails
                        try:
                            line_number = int(line_number)
                        except (ValueError, TypeError):
                            logger.warning(f"Invalid line_number in finding: {line_number}")
                            continue
                    
                    # Validate and convert confidence to float
                    confidence = finding_data.get("confidence", 0.5)
                    if not isinstance(confidence, (int, float)):
                        try:
                            confidence = float(confidence)
                        except (ValueError, TypeError):
                            logger.warning(f"Invalid confidence in finding: {confidence}")
                            continue
                    
                    finding = LLMSecurityFinding(
                        finding_type=finding_data.get("type", "unknown"),
                        severity=finding_data.get("severity", "medium"),
                        description=finding_data.get("description", ""),
                        line_number=line_number,
                        code_snippet=finding_data.get("code_snippet", ""),
                        explanation=finding_data.get("explanation", ""),
                        recommendation=finding_data.get("recommendation", ""),
                        confidence=confidence,
                        cwe_id=finding_data.get("cwe_id"),
                        owasp_category=finding_data.get("owasp_category"),
                    )
                    findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to parse finding: {e}")
                    continue
            
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            raise LLMAnalysisError(f"Invalid JSON response from LLM: {e}")
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            raise LLMAnalysisError(f"Error parsing LLM response: {e}")
    
    def batch_analyze_code(
        self, 
        code_chunks: List[Tuple[str, str, Language]], 
        max_findings_per_chunk: int = 10
    ) -> List[LLMSecurityFinding]:
        """Analyze multiple code chunks in batch.
        
        Args:
            code_chunks: List of (source_code, file_path, language) tuples
            max_findings_per_chunk: Maximum findings per chunk
            
        Returns:
            List of all security findings
        """
        all_findings = []
        
        for source_code, file_path, language in code_chunks:
            try:
                findings = self.analyze_code(
                    source_code, file_path, language, max_findings_per_chunk
                )
                all_findings.extend(findings)
            except LLMAnalysisError as e:
                logger.warning(f"Failed to analyze {file_path}: {e}")
                continue
        
        return all_findings
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get statistics about LLM analysis capabilities.
        
        Returns:
            Dictionary with analysis statistics
        """
        return {
            "available": self.is_available(),
            "model": self.config.openai_model if self.is_available() else None,
            "max_tokens": self.config.openai_max_tokens,
            "api_key_configured": bool(self.config.openai_api_key),
            "supported_languages": [lang.value for lang in Language],
        } 