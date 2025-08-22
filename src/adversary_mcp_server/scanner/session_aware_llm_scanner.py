"""Session-aware LLM scanner that leverages context for better analysis."""

import asyncio
from pathlib import Path

from ..credentials import CredentialManager
from ..llm import LLMProvider, create_llm_client
from ..logger import get_logger
from ..session import LLMSessionManager
from .llm_scanner import LLMSecurityFinding
from .types import ThreatMatch

logger = get_logger("session_aware_llm_scanner")


class SessionAwareLLMScanner:
    """
    Enhanced LLM scanner that maintains context across analysis sessions.

    This scanner transforms individual file analysis into project-wide
    contextual analysis, enabling detection of cross-file vulnerabilities
    and architectural security issues.
    """

    def __init__(
        self,
        credential_manager: CredentialManager,
        max_context_tokens: int = 50000,
        session_timeout_seconds: int = 3600,
    ):
        """Initialize the session-aware scanner."""
        self.credential_manager = credential_manager
        self.config = credential_manager.load_config()
        self.session_manager: LLMSessionManager | None = None
        self.max_context_tokens = max_context_tokens
        self.session_timeout_seconds = session_timeout_seconds

        # Initialize LLM client if available
        self._initialize_llm_client()

        logger.info("SessionAwareLLMScanner initialized")

    def _initialize_llm_client(self) -> None:
        """Initialize LLM client and session manager."""
        try:
            if self.config.llm_provider and self.config.llm_api_key:
                llm_client = create_llm_client(
                    provider=LLMProvider(self.config.llm_provider),
                    api_key=self.config.llm_api_key,
                    model=self.config.llm_model,
                )

                self.session_manager = LLMSessionManager(
                    llm_client=llm_client,
                    max_context_tokens=self.max_context_tokens,
                    session_timeout_seconds=self.session_timeout_seconds,
                )

                logger.info(f"LLM client initialized for {self.config.llm_provider}")
            else:
                logger.warning("LLM not configured, session-aware analysis unavailable")

        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            self.session_manager = None

    def is_available(self) -> bool:
        """Check if session-aware analysis is available."""
        return self.session_manager is not None

    async def analyze_project_with_session(
        self,
        project_root: Path,
        target_files: list[Path] | None = None,
        analysis_focus: str = "comprehensive security analysis",
    ) -> list[ThreatMatch]:
        """
        Analyze a project using session-aware context.

        Args:
            project_root: Root directory of the project
            target_files: Specific files to focus on (optional)
            analysis_focus: Type of analysis to perform

        Returns:
            List of threat matches found
        """
        if not self.session_manager:
            logger.warning(
                "Session manager not available, falling back to legacy analysis"
            )
            return []

        logger.info(f"Starting session-aware analysis of {project_root}")

        session = None
        try:
            # Create analysis session
            session = await self.session_manager.create_session(
                project_root=project_root,
                target_files=target_files,
                session_metadata={
                    "analysis_focus": analysis_focus,
                    "scanner_type": "session_aware_llm",
                },
            )

            # Perform comprehensive analysis
            findings = await self._perform_comprehensive_analysis(session.session_id)

            # Convert to ThreatMatch objects
            threat_matches = []
            for finding in findings:
                threat_match = finding.to_threat_match()
                threat_matches.append(threat_match)

            logger.info(
                f"Session-aware analysis complete: {len(threat_matches)} threats found"
            )
            return threat_matches

        except Exception as e:
            logger.error(f"Session-aware analysis failed: {e}")
            raise
        finally:
            # Always cleanup session if it was created
            if session:
                self.session_manager.close_session(session.session_id)

    async def analyze_file_with_context(
        self,
        file_path: Path,
        project_root: Path | None = None,
        context_hint: str | None = None,
    ) -> list[ThreatMatch]:
        """
        Analyze a specific file with project context.

        Args:
            file_path: File to analyze
            project_root: Project root for context (defaults to file's parent)
            context_hint: Hint about what to focus on

        Returns:
            List of threat matches
        """
        if not self.session_manager:
            return []

        # Determine project root
        if project_root is None:
            project_root = file_path.parent
            # Try to find actual project root by looking for common indicators
            current = file_path.parent
            while current.parent != current:
                if any(
                    (current / indicator).exists()
                    for indicator in [
                        ".git",
                        "package.json",
                        "pyproject.toml",
                        "requirements.txt",
                    ]
                ):
                    project_root = current
                    break
                current = current.parent

        logger.info(f"Analyzing {file_path} with project context from {project_root}")

        try:
            # Create session focused on this file
            session = await self.session_manager.create_session(
                project_root=project_root,
                target_files=[file_path],
                session_metadata={
                    "analysis_type": "focused_file",
                    "target_file": str(file_path),
                },
            )

            # Analyze the specific file
            query = f"Analyze {file_path.name} for security vulnerabilities"
            if context_hint:
                query += f". {context_hint}"

            findings = await self.session_manager.analyze_with_session(
                session_id=session.session_id,
                analysis_query=query,
                context_hint=context_hint,
            )

            # Convert to ThreatMatch objects
            threat_matches = []
            for finding in findings:
                threat_match = finding.to_threat_match()
                threat_matches.append(threat_match)

            # Cleanup session
            self.session_manager.close_session(session.session_id)

            return threat_matches

        except Exception as e:
            logger.error(f"File analysis with context failed: {e}")
            raise

    async def analyze_code_with_context(
        self,
        code_content: str,
        language: str,
        file_name: str = "code_snippet",
        context_hint: str | None = None,
    ) -> list[ThreatMatch]:
        """
        Analyze code content with minimal context.

        This is a lighter version that creates a temporary context
        just for the code snippet being analyzed.

        Args:
            code_content: Code to analyze
            language: Programming language
            file_name: Name for the code snippet
            context_hint: Analysis focus hint

        Returns:
            List of threat matches
        """
        if not self.session_manager:
            return []

        logger.info(f"Analyzing {language} code snippet with context")

        try:
            # Create a temporary project context just for this code
            temp_session = await self.session_manager.create_session(
                project_root=Path.cwd(),  # Use current directory as fallback
                target_files=[],  # No specific files
                session_metadata={
                    "analysis_type": "code_snippet",
                    "language": language,
                    "file_name": file_name,
                },
            )

            # Add the code content to the conversation
            code_analysis_query = f"""
Analyze this {language} code for security vulnerabilities:

File: {file_name}
```{language}
{code_content}
```

{context_hint if context_hint else "Focus on common security vulnerabilities for this language."}
"""

            findings = await self.session_manager.analyze_with_session(
                session_id=temp_session.session_id,
                analysis_query=code_analysis_query,
                context_hint=context_hint,
            )

            # Convert to ThreatMatch objects
            threat_matches = []
            for finding in findings:
                # Update file path to reflect the code snippet
                finding.file_path = file_name
                threat_match = finding.to_threat_match()
                threat_matches.append(threat_match)

            # Cleanup session
            self.session_manager.close_session(temp_session.session_id)

            return threat_matches

        except Exception as e:
            logger.error(f"Code analysis with context failed: {e}")
            raise

    async def _perform_comprehensive_analysis(self, session_id: str) -> list:
        """Perform comprehensive security analysis using the session."""
        all_findings = []

        # Phase 1: General security analysis
        findings = await self.session_manager.analyze_with_session(
            session_id=session_id,
            analysis_query="""
Perform a comprehensive security analysis of this codebase. Look for:

1. Authentication and authorization vulnerabilities
2. Input validation issues and injection flaws
3. Cross-site scripting (XSS) vulnerabilities
4. Cross-site request forgery (CSRF) issues
5. SQL injection and database security
6. File upload and path traversal vulnerabilities
7. Session management issues
8. Cryptographic implementation problems
9. Information disclosure risks
10. Business logic flaws

Focus on real, exploitable vulnerabilities with high confidence.
""",
        )
        all_findings.extend(findings)

        # Phase 2: Architectural security analysis
        arch_findings = await self.session_manager.continue_analysis(
            session_id=session_id,
            follow_up_query="""
Now analyze the overall architecture for security issues:

1. Are there any trust boundary violations?
2. How does data flow between components - any risks?
3. Are authentication/authorization consistently applied?
4. Any privilege escalation opportunities?
5. Configuration and deployment security issues?
6. Third-party dependency risks?

Focus on systemic and architectural vulnerabilities.
""",
        )
        all_findings.extend(arch_findings)

        # Phase 3: Cross-file interaction analysis
        if len(all_findings) > 0:
            interaction_findings = await self.session_manager.continue_analysis(
                session_id=session_id,
                follow_up_query="""
Based on the vulnerabilities found, analyze cross-file interactions:

1. Do validation failures in one component affect others?
2. Are there any attack chains across multiple files?
3. Can an attacker pivot from one vulnerability to exploit others?
4. Are there any missing security controls in the interaction between components?

Focus on vulnerabilities that require understanding of multiple files working together.
""",
            )
            all_findings.extend(interaction_findings)

        logger.info(f"Comprehensive analysis found {len(all_findings)} total findings")
        return all_findings

    # Compatibility methods for legacy interface

    def analyze_code(
        self,
        source_code: str,
        file_path: str,
        language: str,
        max_findings: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Legacy compatibility method - runs session analysis synchronously."""
        if not self.session_manager:
            return []

        try:
            # Run async analysis in sync context
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        threat_matches = loop.run_until_complete(
            self.analyze_code_with_context(
                code_content=source_code,
                language=language,
                file_name=file_path,
            )
        )

        # Convert ThreatMatch back to LLMSecurityFinding for compatibility
        findings = []
        for threat in threat_matches:
            finding = LLMSecurityFinding(
                finding_type=threat.rule_id,
                severity=threat.severity.value,
                description=threat.description,
                line_number=threat.line_number,
                code_snippet=threat.code_snippet,
                explanation=threat.description,
                recommendation="See architectural context for remediation",
                confidence=threat.confidence,
                file_path=threat.file_path,
            )
            findings.append(finding)

        return findings

    async def analyze_file(
        self,
        file_path: Path,
        language: str,
        max_findings: int | None = None,
    ) -> list[LLMSecurityFinding]:
        """Legacy compatibility method for file analysis."""
        threat_matches = await self.analyze_file_with_context(file_path)

        # Convert to LLMSecurityFinding
        findings = []
        for threat in threat_matches:
            finding = LLMSecurityFinding(
                finding_type=threat.rule_id,
                severity=threat.severity.value,
                description=threat.description,
                line_number=threat.line_number,
                code_snippet=threat.code_snippet,
                explanation=threat.description,
                recommendation="See session context for detailed remediation",
                confidence=threat.confidence,
                file_path=threat.file_path,
            )
            findings.append(finding)

        return findings

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        if self.session_manager:
            return self.session_manager.cleanup_expired_sessions()
        return 0
