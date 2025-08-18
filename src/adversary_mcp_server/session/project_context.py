"""Project context building and management for LLM sessions."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..logger import get_logger
from ..scanner.file_filter import FileFilter
from ..scanner.language_mapping import LanguageMapper

logger = get_logger("project_context")


@dataclass
class ProjectFile:
    """Represents a file in the project context."""

    path: Path
    language: str
    size_bytes: int
    priority_score: float = 0.0
    security_relevance: float = 0.0
    content_preview: str = ""
    is_entry_point: bool = False
    is_config: bool = False
    is_security_critical: bool = False


@dataclass
class ProjectContext:
    """Comprehensive project context for LLM analysis."""

    project_root: Path
    project_type: str = "unknown"
    structure_overview: str = ""
    key_files: list[ProjectFile] = field(default_factory=list)
    security_modules: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    architecture_summary: str = ""
    total_files: int = 0
    total_size_bytes: int = 0
    languages_used: set[str] = field(default_factory=set)
    estimated_tokens: int = 0

    def to_context_prompt(self) -> str:
        """Generate context prompt for LLM initialization."""
        return f"""
# Project Analysis Context

**Project Type**: {self.project_type}
**Project Root**: {self.project_root}
**Total Files**: {self.total_files} ({self.total_size_bytes:,} bytes)
**Languages**: {', '.join(sorted(self.languages_used))}

## Project Structure
{self.structure_overview}

## Key Security-Relevant Files
{self._format_key_files()}

## Security Modules
{chr(10).join(f"- {sm}" for sm in self.security_modules)}

## Entry Points
{chr(10).join(f"- {ep}" for ep in self.entry_points)}

## Dependencies
{chr(10).join(f"- {dep}" for dep in self.dependencies[:10])}
{f"... and {len(self.dependencies) - 10} more" if len(self.dependencies) > 10 else ""}

## Architecture Summary
{self.architecture_summary}

---

I'll be analyzing this codebase for security vulnerabilities. I'll reference these components by name in my queries.
"""

    def _format_key_files(self) -> str:
        """Format key files for display."""
        formatted = []
        for file in self.key_files[:15]:  # Limit to top 15 files
            markers = []
            if file.is_entry_point:
                markers.append("🚪 Entry Point")
            if file.is_config:
                markers.append("⚙️ Config")
            if file.is_security_critical:
                markers.append("🔒 Security Critical")

            marker_str = f" ({', '.join(markers)})" if markers else ""
            formatted.append(f"- {file.path}{marker_str} - {file.language}")
            if file.content_preview:
                formatted.append(f"  Preview: {file.content_preview[:100]}...")

        return "\n".join(formatted)


class ProjectContextBuilder:
    """Builds intelligent project context for LLM analysis."""

    def __init__(self, max_context_tokens: int = 50000):
        """Initialize with token budget for context."""
        self.max_context_tokens = max_context_tokens
        self.security_keywords = {
            "auth",
            "login",
            "password",
            "token",
            "jwt",
            "session",
            "permission",
            "role",
            "admin",
            "user",
            "security",
            "crypto",
            "hash",
            "encrypt",
            "decrypt",
            "validate",
            "sanitize",
            "escape",
            "sql",
            "query",
            "database",
            "db",
            "api",
            "endpoint",
            "route",
            "controller",
            "middleware",
            "filter",
            "cors",
            "csrf",
            "xss",
            "injection",
        }

        self.entry_point_patterns = {
            "main.py",
            "app.py",
            "server.py",
            "index.js",
            "index.ts",
            "main.js",
            "main.ts",
            "app.js",
            "server.js",
            "wsgi.py",
            "asgi.py",
            "manage.py",
            "run.py",
            "__main__.py",
        }

        self.config_patterns = {
            "config",
            "settings",
            "env",
            "docker",
            "requirements",
            "package.json",
            "pyproject.toml",
            "setup.py",
            "Cargo.toml",
            "pom.xml",
            "build.gradle",
            "Dockerfile",
            "compose",
        }

    def build_context(
        self, project_root: Path, target_files: list[Path] | None = None
    ) -> ProjectContext:
        """Build comprehensive project context."""
        logger.info(f"Building project context for {project_root}")

        context = ProjectContext(project_root=project_root)

        # Discover files
        all_files = self._discover_files(project_root)
        context.total_files = len(all_files)
        context.total_size_bytes = sum(
            f.stat().st_size for f in all_files if f.exists()
        )

        # Focus on target files if specified, otherwise analyze all
        files_to_analyze = target_files if target_files else all_files

        # Create project files with metadata
        project_files = []
        for file_path in files_to_analyze:
            if file_path.exists() and file_path.is_file():
                project_file = self._create_project_file(file_path, project_root)
                project_files.append(project_file)
                context.languages_used.add(project_file.language)

        # Sort by priority and security relevance
        project_files.sort(
            key=lambda f: (f.security_relevance, f.priority_score), reverse=True
        )

        # Select key files within token budget
        context.key_files = self._select_key_files(project_files, context)

        # Analyze project structure
        context.project_type = self._detect_project_type(project_root, project_files)
        context.structure_overview = self._build_structure_overview(
            project_root, all_files
        )
        context.security_modules = self._identify_security_modules(project_files)
        context.entry_points = self._identify_entry_points(project_files)
        context.dependencies = self._extract_dependencies(project_root)
        context.architecture_summary = self._analyze_architecture(context)

        # Estimate token usage
        context.estimated_tokens = self._estimate_tokens(context)

        logger.info(
            f"Built context: {len(context.key_files)} key files, "
            f"{len(context.security_modules)} security modules, "
            f"~{context.estimated_tokens} tokens"
        )

        return context

    def _discover_files(self, project_root: Path) -> list[Path]:
        """Discover all relevant files in the project."""
        try:
            # Use existing file filter for consistent logic
            file_filter = FileFilter(
                root_path=project_root,
                max_file_size_mb=10,  # Reasonable limit for context
                respect_gitignore=True,
            )

            # Get all files recursively
            all_files = []
            for file_path in project_root.rglob("*"):
                if file_path.is_file():
                    all_files.append(file_path)

            # Apply filtering
            filtered_files = file_filter.filter_files(all_files)

            # Further filter to analyzable source files
            source_files = []
            for file_path in filtered_files:
                if self._is_analyzable_file(file_path):
                    source_files.append(file_path)

            logger.debug(
                f"Discovered {len(source_files)} analyzable files from {len(all_files)} total"
            )
            return source_files

        except Exception as e:
            logger.warning(f"Error discovering files: {e}")
            return []

    def _is_analyzable_file(self, file_path: Path) -> bool:
        """Check if file should be included in analysis."""
        # Use language mapper to check if it's a source file
        language = LanguageMapper.detect_language_from_extension(file_path)
        if language == "generic":
            # Check if it's a config file we care about
            return any(
                pattern in file_path.name.lower() for pattern in self.config_patterns
            )
        return True

    def _create_project_file(self, file_path: Path, project_root: Path) -> ProjectFile:
        """Create ProjectFile with metadata."""
        relative_path = file_path.relative_to(project_root)
        language = LanguageMapper.detect_language_from_extension(file_path)

        try:
            size_bytes = file_path.stat().st_size

            # Read content preview
            content_preview = ""
            if size_bytes < 10000:  # Only preview small files
                try:
                    content_preview = file_path.read_text(
                        encoding="utf-8", errors="ignore"
                    )[:200]
                except Exception:
                    pass

            # Calculate priority and security scores
            priority_score = self._calculate_priority_score(file_path, relative_path)
            security_relevance = self._calculate_security_relevance(
                file_path, content_preview
            )

            # Identify file characteristics
            is_entry_point = file_path.name in self.entry_point_patterns
            is_config = any(
                pattern in file_path.name.lower() for pattern in self.config_patterns
            )
            is_security_critical = security_relevance > 0.7

            return ProjectFile(
                path=relative_path,
                language=language,
                size_bytes=size_bytes,
                priority_score=priority_score,
                security_relevance=security_relevance,
                content_preview=content_preview,
                is_entry_point=is_entry_point,
                is_config=is_config,
                is_security_critical=is_security_critical,
            )

        except Exception as e:
            logger.warning(f"Error processing {file_path}: {e}")
            return ProjectFile(
                path=relative_path,
                language=language,
                size_bytes=0,
            )

    def _calculate_priority_score(self, file_path: Path, relative_path: Path) -> float:
        """Calculate priority score for a file."""
        score = 0.0

        # Entry points get high priority
        if file_path.name in self.entry_point_patterns:
            score += 1.0

        # Files in root or important directories
        if len(relative_path.parts) == 1:
            score += 0.8
        elif any(part in ["src", "app", "lib", "core"] for part in relative_path.parts):
            score += 0.6

        # Shorter paths often more important
        path_depth_penalty = len(relative_path.parts) * 0.1
        score = max(0.0, score - path_depth_penalty)

        return score

    def _calculate_security_relevance(
        self, file_path: Path, content_preview: str
    ) -> float:
        """Calculate security relevance score."""
        score = 0.0

        # Check filename for security keywords
        filename_lower = file_path.name.lower()
        for keyword in self.security_keywords:
            if keyword in filename_lower:
                score += 0.3

        # Check content for security patterns
        if content_preview:
            content_lower = content_preview.lower()
            keyword_count = sum(
                1 for keyword in self.security_keywords if keyword in content_lower
            )
            score += min(1.0, keyword_count * 0.2)

        return min(1.0, score)

    def _select_key_files(
        self, project_files: list[ProjectFile], context: ProjectContext
    ) -> list[ProjectFile]:
        """Select key files within token budget."""
        selected = []
        estimated_tokens = 0

        # Always include top security-critical files
        for file in project_files:
            if file.is_security_critical or file.is_entry_point:
                file_tokens = len(file.content_preview) // 4  # Rough token estimate
                if estimated_tokens + file_tokens < self.max_context_tokens:
                    selected.append(file)
                    estimated_tokens += file_tokens

        # Fill remaining budget with high-priority files
        for file in project_files:
            if file not in selected and file.priority_score > 0.5:
                file_tokens = len(file.content_preview) // 4
                if estimated_tokens + file_tokens < self.max_context_tokens:
                    selected.append(file)
                    estimated_tokens += file_tokens
                else:
                    break

        return selected

    def _detect_project_type(
        self, project_root: Path, project_files: list[ProjectFile]
    ) -> str:
        """Detect the type of project."""
        # Check for common project indicators
        languages = {f.language for f in project_files}

        if (project_root / "package.json").exists():
            return "Node.js/JavaScript Application"
        elif (project_root / "requirements.txt").exists() or (
            project_root / "pyproject.toml"
        ).exists():
            if any(
                "django" in f.content_preview.lower()
                for f in project_files
                if f.content_preview
            ):
                return "Django Web Application"
            elif any(
                "flask" in f.content_preview.lower()
                for f in project_files
                if f.content_preview
            ):
                return "Flask Web Application"
            elif any(
                "fastapi" in f.content_preview.lower()
                for f in project_files
                if f.content_preview
            ):
                return "FastAPI Application"
            else:
                return "Python Application"
        elif (project_root / "Cargo.toml").exists():
            return "Rust Application"
        elif (project_root / "pom.xml").exists() or (
            project_root / "build.gradle"
        ).exists():
            return "Java Application"
        elif "javascript" in languages or "typescript" in languages:
            return "JavaScript/TypeScript Application"
        elif "python" in languages:
            return "Python Application"
        else:
            return "Multi-language Application"

    def _build_structure_overview(
        self, project_root: Path, all_files: list[Path]
    ) -> str:
        """Build a high-level structure overview."""
        # Group files by directory
        dir_structure = {}
        for file_path in all_files[:50]:  # Limit for overview
            try:
                relative = file_path.relative_to(project_root)
                dir_name = (
                    str(relative.parent) if relative.parent != Path(".") else "root"
                )
                if dir_name not in dir_structure:
                    dir_structure[dir_name] = []
                dir_structure[dir_name].append(relative.name)
            except ValueError:
                continue

        # Format structure
        lines = []
        for dir_name in sorted(dir_structure.keys()):
            files = dir_structure[dir_name][:5]  # Limit files per directory
            lines.append(f"📁 {dir_name}/ ({len(dir_structure[dir_name])} files)")
            for file_name in files:
                lines.append(f"   📄 {file_name}")
            if len(dir_structure[dir_name]) > 5:
                lines.append(f"   ... and {len(dir_structure[dir_name]) - 5} more")

        return "\n".join(lines)

    def _identify_security_modules(self, project_files: list[ProjectFile]) -> list[str]:
        """Identify security-related modules."""
        modules = []
        for file in project_files:
            if file.is_security_critical:
                modules.append(str(file.path))
        return modules[:10]  # Limit list size

    def _identify_entry_points(self, project_files: list[ProjectFile]) -> list[str]:
        """Identify application entry points."""
        entry_points = []
        for file in project_files:
            if file.is_entry_point:
                entry_points.append(str(file.path))
        return entry_points

    def _extract_dependencies(self, project_root: Path) -> list[str]:
        """Extract project dependencies."""
        dependencies = []

        # Python dependencies
        requirements_files = ["requirements.txt", "requirements.in", "pyproject.toml"]
        for req_file in requirements_files:
            req_path = project_root / req_file
            if req_path.exists():
                try:
                    content = req_path.read_text()
                    # Simple extraction - could be enhanced
                    for line in content.split("\n")[:20]:  # Limit for context
                        if line.strip() and not line.startswith("#"):
                            dep = (
                                line.split("==")[0]
                                .split(">=")[0]
                                .split("~=")[0]
                                .strip()
                            )
                            if dep:
                                dependencies.append(dep)
                except Exception:
                    pass
                break

        # Node.js dependencies
        package_json = project_root / "package.json"
        if package_json.exists():
            try:
                content = json.loads(package_json.read_text())
                deps = content.get("dependencies", {})
                dependencies.extend(list(deps.keys())[:20])  # Limit for context
            except Exception:
                pass

        return dependencies

    def _analyze_architecture(self, context: ProjectContext) -> str:
        """Analyze and summarize the architecture."""
        summary_parts = []

        # Based on project type
        if "Django" in context.project_type:
            summary_parts.append(
                "Django MVC architecture with models, views, and templates"
            )
        elif "Flask" in context.project_type:
            summary_parts.append("Flask microframework with route-based architecture")
        elif "FastAPI" in context.project_type:
            summary_parts.append(
                "FastAPI with async endpoints and automatic API documentation"
            )
        elif "Node.js" in context.project_type:
            summary_parts.append("Node.js application with JavaScript/TypeScript")

        # Based on file structure
        if any("api" in str(f.path).lower() for f in context.key_files):
            summary_parts.append("RESTful API architecture")

        if any("auth" in str(f.path).lower() for f in context.key_files):
            summary_parts.append("Authentication/authorization layer present")

        if any(
            "db" in str(f.path).lower() or "model" in str(f.path).lower()
            for f in context.key_files
        ):
            summary_parts.append("Database/data layer architecture")

        return (
            "; ".join(summary_parts)
            if summary_parts
            else "Standard application architecture"
        )

    def _estimate_tokens(self, context: ProjectContext) -> int:
        """Estimate token usage for the context."""
        # Rough estimation: 4 characters per token
        total_chars = len(context.to_context_prompt())
        for file in context.key_files:
            total_chars += len(file.content_preview)

        return total_chars // 4
