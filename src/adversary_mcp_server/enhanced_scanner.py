"""Enhanced scanner that combines AST-based rules with LLM analysis for comprehensive security scanning."""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ast_scanner import ASTScanner
from .credential_manager import CredentialManager
from .llm_security_analyzer import LLMAnalysisError, LLMSecurityAnalyzer
from .threat_engine import Language, Severity, ThreatEngine, ThreatMatch

logger = logging.getLogger(__name__)


class EnhancedScanResult:
    """Result of enhanced scanning combining rules and LLM analysis."""
    
    def __init__(
        self,
        file_path: str,
        language: Language,
        rules_threats: List[ThreatMatch],
        llm_threats: List[ThreatMatch],
        scan_metadata: Dict[str, Any],
    ):
        """Initialize enhanced scan result.
        
        Args:
            file_path: Path to the scanned file
            language: Programming language
            rules_threats: Threats found by rules engine
            llm_threats: Threats found by LLM analysis
            scan_metadata: Metadata about the scan
        """
        self.file_path = file_path
        self.language = language
        self.rules_threats = rules_threats
        self.llm_threats = llm_threats
        self.scan_metadata = scan_metadata
        
        # Combine and deduplicate threats
        self.all_threats = self._combine_threats()
        
        # Calculate statistics
        self.stats = self._calculate_stats()
    
    def _combine_threats(self) -> List[ThreatMatch]:
        """Combine and deduplicate threats from both sources.
        
        Returns:
            Combined list of unique threats
        """
        combined = []
        seen_threats = set()
        
        # Add rules-based threats first (they're more precise)
        for threat in self.rules_threats:
            threat_key = (threat.rule_id, threat.line_number, threat.code_snippet)
            if threat_key not in seen_threats:
                combined.append(threat)
                seen_threats.add(threat_key)
        
        # Add LLM threats that don't duplicate rules-based findings
        for threat in self.llm_threats:
            # Check for similar threats (same line, similar category)
            is_duplicate = False
            for existing in combined:
                if (abs(threat.line_number - existing.line_number) <= 2 and
                    threat.category == existing.category):
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                combined.append(threat)
        
        # Sort by line number and severity
        combined.sort(key=lambda t: (t.line_number, t.severity.value))
        
        return combined
    
    def _calculate_stats(self) -> Dict[str, Any]:
        """Calculate scan statistics.
        
        Returns:
            Dictionary with scan statistics
        """
        return {
            'total_threats': len(self.all_threats),
            'rules_threats': len(self.rules_threats),
            'llm_threats': len(self.llm_threats),
            'unique_threats': len(self.all_threats),
            'severity_counts': self._count_by_severity(),
            'category_counts': self._count_by_category(),
            'sources': {
                'rules_engine': len(self.rules_threats) > 0,
                'llm_analysis': len(self.llm_threats) > 0,
            }
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count threats by severity level."""
        counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for threat in self.all_threats:
            counts[threat.severity.value] += 1
        return counts
    
    def _count_by_category(self) -> Dict[str, int]:
        """Count threats by category."""
        counts = {}
        for threat in self.all_threats:
            category = threat.category.value
            counts[category] = counts.get(category, 0) + 1
        return counts
    
    def get_high_confidence_threats(self, min_confidence: float = 0.8) -> List[ThreatMatch]:
        """Get threats with high confidence scores.
        
        Args:
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of high-confidence threats
        """
        return [t for t in self.all_threats if t.confidence >= min_confidence]
    
    def get_critical_threats(self) -> List[ThreatMatch]:
        """Get critical severity threats.
        
        Returns:
            List of critical threats
        """
        return [t for t in self.all_threats if t.severity == Severity.CRITICAL]


class EnhancedScanner:
    """Enhanced scanner combining AST-based rules with LLM analysis."""
    
    def __init__(
        self,
        threat_engine: Optional[ThreatEngine] = None,
        credential_manager: Optional[CredentialManager] = None,
        enable_llm_analysis: bool = True,
    ):
        """Initialize enhanced scanner.
        
        Args:
            threat_engine: Threat engine for rules-based scanning
            credential_manager: Credential manager for configuration
            enable_llm_analysis: Whether to enable LLM analysis
        """
        self.threat_engine = threat_engine or ThreatEngine()
        self.credential_manager = credential_manager or CredentialManager()
        self.enable_llm_analysis = enable_llm_analysis
        
        # Initialize AST scanner
        self.ast_scanner = ASTScanner(self.threat_engine)
        
        # Initialize LLM analyzer if enabled
        self.llm_analyzer = None
        if self.enable_llm_analysis:
            self.llm_analyzer = LLMSecurityAnalyzer(self.credential_manager)
            if not self.llm_analyzer.is_available():
                logger.warning("LLM analysis requested but not available - API key not configured")
                self.enable_llm_analysis = False
    
    def scan_code(
        self,
        source_code: str,
        file_path: str,
        language: Language,
        use_llm: bool = True,
        severity_threshold: Optional[Severity] = None,
    ) -> EnhancedScanResult:
        """Scan source code using both rules and LLM analysis.
        
        Args:
            source_code: Source code to scan
            file_path: Path to the source file
            language: Programming language
            use_llm: Whether to use LLM analysis
            severity_threshold: Minimum severity threshold for filtering
            
        Returns:
            Enhanced scan result
        """
        scan_metadata = {
            'file_path': file_path,
            'language': language.value,
            'use_llm': use_llm and self.enable_llm_analysis,
            'source_lines': len(source_code.split('\n')),
            'source_size': len(source_code),
        }
        
        # Perform AST-based rules scanning
        rules_threats = []
        try:
            rules_threats = self.ast_scanner.scan_code(source_code, file_path, language)
            scan_metadata['rules_scan_success'] = True
        except Exception as e:
            logger.error(f"Rules-based scan failed for {file_path}: {e}")
            scan_metadata['rules_scan_success'] = False
            scan_metadata['rules_scan_error'] = str(e)
        
        # Perform LLM analysis if enabled
        llm_threats = []
        if use_llm and self.enable_llm_analysis and self.llm_analyzer:
            try:
                llm_findings = self.llm_analyzer.analyze_code(source_code, file_path, language)
                llm_threats = [finding.to_threat_match(file_path) for finding in llm_findings]
                scan_metadata['llm_scan_success'] = True
                scan_metadata['llm_findings_count'] = len(llm_findings)
            except LLMAnalysisError as e:
                logger.warning(f"LLM analysis failed for {file_path}: {e}")
                scan_metadata['llm_scan_success'] = False
                scan_metadata['llm_scan_error'] = str(e)
            except Exception as e:
                logger.error(f"Unexpected error in LLM analysis for {file_path}: {e}")
                scan_metadata['llm_scan_success'] = False
                scan_metadata['llm_scan_error'] = str(e)
        else:
            scan_metadata['llm_scan_success'] = False
            scan_metadata['llm_scan_reason'] = 'disabled' if not use_llm else 'not_available'
        
        # Filter by severity threshold if specified
        if severity_threshold:
            rules_threats = self._filter_by_severity(rules_threats, severity_threshold)
            llm_threats = self._filter_by_severity(llm_threats, severity_threshold)
        
        return EnhancedScanResult(
            file_path=file_path,
            language=language,
            rules_threats=rules_threats,
            llm_threats=llm_threats,
            scan_metadata=scan_metadata,
        )
    
    def scan_file(
        self,
        file_path: Path,
        language: Optional[Language] = None,
        use_llm: bool = True,
        severity_threshold: Optional[Severity] = None,
    ) -> EnhancedScanResult:
        """Scan a single file using enhanced scanning.
        
        Args:
            file_path: Path to the file to scan
            language: Programming language (auto-detected if not provided)
            use_llm: Whether to use LLM analysis
            severity_threshold: Minimum severity threshold for filtering
            
        Returns:
            Enhanced scan result
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except UnicodeDecodeError:
            # Skip binary files
            return EnhancedScanResult(
                file_path=str(file_path),
                language=language or Language.PYTHON,
                rules_threats=[],
                llm_threats=[],
                scan_metadata={
                    'file_path': str(file_path),
                    'error': 'Binary file or encoding error',
                    'rules_scan_success': False,
                    'llm_scan_success': False,
                }
            )
        
        # Detect language if not provided
        if language is None:
            language = self._detect_language(file_path)
        
        return self.scan_code(
            source_code=source_code,
            file_path=str(file_path),
            language=language,
            use_llm=use_llm,
            severity_threshold=severity_threshold,
        )
    
    def scan_directory(
        self,
        directory_path: Path,
        recursive: bool = True,
        use_llm: bool = True,
        severity_threshold: Optional[Severity] = None,
        max_files: Optional[int] = None,
    ) -> List[EnhancedScanResult]:
        """Scan a directory using enhanced scanning.
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            use_llm: Whether to use LLM analysis
            severity_threshold: Minimum severity threshold for filtering
            max_files: Maximum number of files to scan
            
        Returns:
            List of enhanced scan results
        """
        if not directory_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        # Find supported files
        supported_extensions = {
            '.py': Language.PYTHON,
            '.js': Language.JAVASCRIPT,
            '.ts': Language.TYPESCRIPT,
            '.jsx': Language.JAVASCRIPT,
            '.tsx': Language.TYPESCRIPT,
        }
        
        files_to_scan = []
        pattern = "**/*" if recursive else "*"
        
        for file_path in directory_path.glob(pattern):
            if file_path.is_file() and file_path.suffix in supported_extensions:
                files_to_scan.append((file_path, supported_extensions[file_path.suffix]))
                
                if max_files and len(files_to_scan) >= max_files:
                    break
        
        # Scan files
        results = []
        for file_path, language in files_to_scan:
            try:
                result = self.scan_file(
                    file_path=file_path,
                    language=language,
                    use_llm=use_llm,
                    severity_threshold=severity_threshold,
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to scan {file_path}: {e}")
                # Create error result
                results.append(EnhancedScanResult(
                    file_path=str(file_path),
                    language=language,
                    rules_threats=[],
                    llm_threats=[],
                    scan_metadata={
                        'file_path': str(file_path),
                        'error': str(e),
                        'rules_scan_success': False,
                        'llm_scan_success': False,
                    }
                ))
        
        return results
    
    def _detect_language(self, file_path: Path) -> Language:
        """Detect programming language from file extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Detected language
        """
        extension = file_path.suffix.lower()
        
        if extension == '.py':
            return Language.PYTHON
        elif extension in ['.js', '.jsx']:
            return Language.JAVASCRIPT
        elif extension in ['.ts', '.tsx']:
            return Language.TYPESCRIPT
        else:
            # Default to Python
            return Language.PYTHON
    
    def _filter_by_severity(
        self,
        threats: List[ThreatMatch],
        min_severity: Severity,
    ) -> List[ThreatMatch]:
        """Filter threats by minimum severity level.
        
        Args:
            threats: List of threats to filter
            min_severity: Minimum severity level
            
        Returns:
            Filtered list of threats
        """
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_index = severity_order.index(min_severity)
        
        return [
            threat for threat in threats
            if severity_order.index(threat.severity) >= min_index
        ]
    
    def get_scanner_stats(self) -> Dict[str, Any]:
        """Get statistics about the enhanced scanner.
        
        Returns:
            Dictionary with scanner statistics
        """
        return {
            'ast_scanner_available': self.ast_scanner is not None,
            'llm_analyzer_available': self.llm_analyzer is not None and self.llm_analyzer.is_available(),
            'llm_analysis_enabled': self.enable_llm_analysis,
            'threat_engine_stats': self.threat_engine.get_rule_statistics(),
            'llm_stats': self.llm_analyzer.get_analysis_stats() if self.llm_analyzer else None,
        }
    
    def set_llm_enabled(self, enabled: bool) -> None:
        """Enable or disable LLM analysis.
        
        Args:
            enabled: Whether to enable LLM analysis
        """
        if enabled and not self.llm_analyzer:
            self.llm_analyzer = LLMSecurityAnalyzer(self.credential_manager)
        
        self.enable_llm_analysis = enabled and (
            self.llm_analyzer is not None and self.llm_analyzer.is_available()
        )
    
    def reload_configuration(self) -> None:
        """Reload configuration and reinitialize components."""
        # Reload threat engine rules
        self.threat_engine.reload_rules()
        
        # Reinitialize LLM analyzer with new configuration
        if self.enable_llm_analysis:
            self.llm_analyzer = LLMSecurityAnalyzer(self.credential_manager)
            if not self.llm_analyzer.is_available():
                logger.warning("LLM analysis disabled after reload - API key not configured")
                self.enable_llm_analysis = False 