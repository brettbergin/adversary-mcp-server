"""Demo script for session-aware LLM scanning."""

import asyncio
import sys
from pathlib import Path

from ..credentials import get_credential_manager
from ..logger import get_logger
from ..scanner.session_aware_llm_scanner import SessionAwareLLMScanner

logger = get_logger("session_demo")


async def demo_session_scanning():
    """Demonstrate session-aware LLM scanning capabilities."""

    print("🔬 Session-Aware LLM Security Analysis Demo")
    print("=" * 50)

    # Initialize scanner
    try:
        credential_manager = get_credential_manager()
        scanner = SessionAwareLLMScanner(credential_manager)

        if not scanner.is_available():
            print("❌ LLM scanner not available. Please configure your API keys.")
            return

        print("✅ LLM scanner initialized successfully")

    except Exception as e:
        print(f"❌ Failed to initialize scanner: {e}")
        return

    # Get project root (current directory or examples)
    project_root = Path.cwd()
    examples_dir = project_root / "examples"

    if examples_dir.exists():
        project_root = examples_dir
        print(f"📁 Using examples directory: {project_root}")
    else:
        print(f"📁 Using current directory: {project_root}")

    try:
        print("\\n🧠 Starting session-aware analysis...")
        print("This will:")
        print("  1. Load the entire project context into the LLM")
        print("  2. Perform comprehensive security analysis")
        print("  3. Look for cross-file vulnerabilities")
        print("  4. Provide architectural security insights")

        # Run session-aware analysis
        threat_matches = await scanner.analyze_project_with_session(
            project_root=project_root,
            analysis_focus="comprehensive security analysis with architectural review",
        )

        print(f"\\n🎯 Analysis Results: {len(threat_matches)} findings")
        print("-" * 30)

        if not threat_matches:
            print("✅ No security vulnerabilities detected!")
        else:
            for i, threat in enumerate(threat_matches, 1):
                print(f"\\n{i}. {threat.rule_name}")
                print(f"   Severity: {threat.severity.value.upper()}")
                print(f"   File: {threat.file_path}")
                if threat.line_number > 1:
                    print(f"   Line: {threat.line_number}")
                print(f"   Description: {threat.description}")
                if threat.code_snippet:
                    print(f"   Code: {threat.code_snippet[:100]}...")
                print(f"   Confidence: {threat.confidence:.1%}")

                # Show session-specific context if available
                if hasattr(threat, "metadata") and threat.metadata:
                    session_context = threat.metadata.get("session_context", {})
                    if "architectural_context" in session_context:
                        print(
                            f"   Architectural Context: {session_context['architectural_context'][:100]}..."
                        )

        print("\\n📊 Analysis Summary:")
        print(f"   • Total findings: {len(threat_matches)}")

        # Count by severity
        severity_counts = {}
        for threat in threat_matches:
            severity = threat.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity, count in severity_counts.items():
            print(f"   • {severity.title()}: {count}")

        print("\\n🎉 Session-aware analysis complete!")
        print("\\nKey advantages of session-aware analysis:")
        print("  ✓ Full project context understanding")
        print("  ✓ Cross-file vulnerability detection")
        print("  ✓ Architectural security insights")
        print("  ✓ Reduced false positives through context")
        print("  ✓ More intelligent threat analysis")

    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        logger.error(f"Demo analysis failed: {e}", exc_info=True)

    finally:
        # Cleanup any sessions
        scanner.cleanup_expired_sessions()


async def demo_file_analysis():
    """Demonstrate file analysis with project context."""

    print("\\n" + "=" * 50)
    print("🔬 File Analysis with Project Context Demo")
    print("=" * 50)

    try:
        credential_manager = get_credential_manager()
        scanner = SessionAwareLLMScanner(credential_manager)

        if not scanner.is_available():
            print("❌ LLM scanner not available")
            return

        # Find a Python file to analyze
        project_root = Path.cwd()
        examples_dir = project_root / "examples"

        target_file = None
        if examples_dir.exists():
            # Look for Python files in examples
            python_files = list(examples_dir.glob("**/*.py"))
            if python_files:
                target_file = python_files[0]

        if not target_file:
            # Look in current project
            python_files = list(project_root.glob("src/**/*.py"))
            if python_files:
                target_file = python_files[0]

        if not target_file:
            print("❌ No Python files found to analyze")
            return

        print(f"📄 Analyzing file with context: {target_file}")

        threat_matches = await scanner.analyze_file_with_context(
            file_path=target_file,
            context_hint="Focus on input validation and injection vulnerabilities",
        )

        print(f"\\n🎯 File Analysis Results: {len(threat_matches)} findings")

        for i, threat in enumerate(threat_matches, 1):
            print(f"\\n{i}. {threat.rule_name}")
            print(f"   Severity: {threat.severity.value.upper()}")
            print(f"   Line: {threat.line_number}")
            print(f"   Description: {threat.description}")
            print(f"   Confidence: {threat.confidence:.1%}")

        if not threat_matches:
            print("✅ No vulnerabilities found in this file!")

    except Exception as e:
        print(f"❌ File analysis failed: {e}")


def main():
    """Main demo function."""
    if len(sys.argv) > 1 and sys.argv[1] == "file":
        asyncio.run(demo_file_analysis())
    else:
        asyncio.run(demo_session_scanning())


if __name__ == "__main__":
    main()
