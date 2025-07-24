"""AST-based static code scanner for security vulnerability detection."""

import ast
import re
from pathlib import Path
from typing import Any

import esprima

from .logging_config import get_logger
from .threat_engine import Language as LangEnum
from .threat_engine import MatchCondition, ThreatEngine, ThreatMatch, ThreatRule

logger = get_logger("ast_scanner")


class CodeContext:
    """Context information for code analysis."""

    def __init__(self, file_path: str, source_code: str, language: LangEnum):
        """Initialize code context.

        Args:
            file_path: Path to the source file
            source_code: The source code content
            language: Programming language
        """
        logger.debug(f"Initializing CodeContext for {file_path} ({language.value})")
        self.file_path = file_path
        self.source_code = source_code
        self.language = language
        self.lines = source_code.split("\n")
        logger.debug(f"Source code split into {len(self.lines)} lines")

        # Parse the code based on language
        self.ast_tree = self._parse_code()
        logger.debug(
            f"AST parsing completed, tree: {type(self.ast_tree) if self.ast_tree else 'None'}"
        )

    def _parse_code(self) -> Any:
        """Parse the source code into an AST.

        Returns:
            AST representation of the code
        """
        logger.debug(f"Parsing {self.language.value} code into AST")

        if self.language == LangEnum.PYTHON:
            try:
                ast_tree = ast.parse(self.source_code)
                logger.debug("Successfully parsed Python code into AST")
                return ast_tree
            except SyntaxError as e:
                logger.debug(f"Python syntax error during parsing: {e}")
                # Return None for syntax errors, scanner will handle gracefully
                return None

        elif self.language in [LangEnum.JAVASCRIPT, LangEnum.TYPESCRIPT]:
            try:
                # Use esprima for JavaScript/TypeScript parsing
                ast_tree = esprima.parseScript(self.source_code, tolerant=True)
                logger.debug(f"Successfully parsed {self.language.value} code into AST")
                return ast_tree
            except Exception as e:
                logger.debug(f"{self.language.value} parsing error: {e}")
                # Return None for parsing errors
                return None

        logger.debug(f"No parser available for language {self.language.value}")
        return None

    def get_line_content(self, line_number: int) -> str:
        """Get the content of a specific line.

        Args:
            line_number: Line number (1-based)

        Returns:
            Line content
        """
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]
        return ""

    def get_code_snippet(self, line_number: int, context_lines: int = 3) -> str:
        """Get a code snippet around a line.

        Args:
            line_number: Center line number (1-based)
            context_lines: Number of context lines around the center

        Returns:
            Code snippet with line numbers
        """
        start_line = max(1, line_number - context_lines)
        end_line = min(len(self.lines), line_number + context_lines)

        snippet_lines = []
        for i in range(start_line, end_line + 1):
            prefix = ">>> " if i == line_number else "    "
            snippet_lines.append(f"{prefix}{i}: {self.lines[i - 1]}")

        return "\n".join(snippet_lines)


class PythonAnalyzer:
    """Analyzer for Python code using AST."""

    def __init__(self):
        """Initialize the Python analyzer."""
        logger.debug("Initializing PythonAnalyzer")
        self.function_calls: set[str] = set()
        self.imports: set[str] = set()
        self.variables: set[str] = set()

    def analyze(self, context: CodeContext) -> dict[str, Any]:
        """Analyze Python code and extract relevant information.

        Args:
            context: Code context with parsed AST

        Returns:
            Dictionary containing analysis results
        """
        logger.debug(f"Starting Python analysis for {context.file_path}")

        if context.ast_tree is None:
            logger.debug("No AST tree available, returning empty analysis")
            return {}

        # Reset analysis state
        self.function_calls.clear()
        self.imports.clear()
        self.variables.clear()
        logger.debug("Cleared analysis state")

        # Walk the AST
        self._walk_ast(context.ast_tree)

        result = {
            "function_calls": list(self.function_calls),
            "imports": list(self.imports),
            "variables": list(self.variables),
        }

        logger.debug(
            f"Python analysis completed: {len(result['function_calls'])} function calls, "
            f"{len(result['imports'])} imports, {len(result['variables'])} variables"
        )
        return result

    def _walk_ast(self, node: ast.AST) -> None:
        """Walk the AST and collect information."""
        if isinstance(node, ast.Call):
            # Function calls
            func_name = self._get_function_name(node.func)
            if func_name:
                self.function_calls.add(func_name)

        elif isinstance(node, ast.Import):
            # Import statements
            for alias in node.names:
                self.imports.add(alias.name)

        elif isinstance(node, ast.ImportFrom):
            # From imports
            if node.module:
                for alias in node.names:
                    self.imports.add(f"{node.module}.{alias.name}")

        elif isinstance(node, ast.Name):
            # Variable names
            self.variables.add(node.id)

        # Recursively walk child nodes
        for child in ast.iter_child_nodes(node):
            self._walk_ast(child)

    def _get_function_name(self, func_node: ast.AST) -> str | None:
        """Extract function name from a function call node."""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            # Handle module.function calls
            value_name = self._get_function_name(func_node.value)
            if value_name:
                return f"{value_name}.{func_node.attr}"
            return func_node.attr
        return None


class JavaScriptAnalyzer:
    """Analyzer for JavaScript/TypeScript code using esprima."""

    def __init__(self):
        """Initialize the JavaScript analyzer."""
        logger.debug("Initializing JavaScriptAnalyzer")
        self.function_calls: set[str] = set()
        self.variables: set[str] = set()
        self.properties: set[str] = set()

    def analyze(self, context: CodeContext) -> dict[str, Any]:
        """Analyze JavaScript/TypeScript code.

        Args:
            context: Code context with parsed AST

        Returns:
            Dictionary containing analysis results
        """
        logger.debug(f"Starting JavaScript/TypeScript analysis for {context.file_path}")

        if context.ast_tree is None:
            logger.debug("No AST tree available, returning empty analysis")
            return {}

        # Reset analysis state
        self.function_calls.clear()
        self.variables.clear()
        self.properties.clear()
        logger.debug("Cleared analysis state")

        # Walk the AST
        self._walk_ast(context.ast_tree)

        result = {
            "function_calls": list(self.function_calls),
            "variables": list(self.variables),
            "properties": list(self.properties),
        }

        logger.debug(
            f"JavaScript/TypeScript analysis completed: {len(result['function_calls'])} function calls, "
            f"{len(result['variables'])} variables, {len(result['properties'])} properties"
        )
        return result

    def _walk_ast(self, node: Any) -> None:
        """Walk the JavaScript AST and collect information."""
        if node is None:
            return

        # Handle esprima nodes (they have attributes, not dict keys)
        node_type = getattr(node, "type", None)

        if node_type == "CallExpression":
            # Function calls
            callee = getattr(node, "callee", None)
            if callee:
                func_name = self._get_function_name(callee)
                if func_name:
                    self.function_calls.add(func_name)

        elif node_type == "Identifier":
            # Variable names
            name = getattr(node, "name", None)
            if name:
                self.variables.add(name)

        elif node_type == "MemberExpression":
            # Property access
            property_node = getattr(node, "property", None)
            if property_node and getattr(property_node, "type", None) == "Identifier":
                prop_name = getattr(property_node, "name", None)
                if prop_name:
                    self.properties.add(prop_name)

        # Recursively walk child nodes
        if hasattr(node, "__dict__"):
            for attr_name, attr_value in node.__dict__.items():
                if hasattr(attr_value, "type"):
                    # Single node
                    self._walk_ast(attr_value)
                elif isinstance(attr_value, list):
                    # List of nodes
                    for item in attr_value:
                        if hasattr(item, "type"):
                            self._walk_ast(item)

    def _get_function_name(self, callee: Any) -> str | None:
        """Extract function name from a callee node."""
        if not callee:
            return None

        callee_type = getattr(callee, "type", None)

        if callee_type == "Identifier":
            return getattr(callee, "name", None)
        elif callee_type == "MemberExpression":
            # Handle object.method calls
            obj = getattr(callee, "object", None)
            prop = getattr(callee, "property", None)
            if obj and prop:
                obj_name = self._get_function_name(obj)
                prop_name = (
                    getattr(prop, "name", None)
                    if getattr(prop, "type", None) == "Identifier"
                    else None
                )
                if obj_name and prop_name:
                    return f"{obj_name}.{prop_name}"
                elif prop_name:
                    return prop_name
        return None


class ASTScanner:
    """Main AST-based scanner for detecting security vulnerabilities."""

    def __init__(self, threat_engine: ThreatEngine):
        """Initialize the AST scanner.

        Args:
            threat_engine: Threat detection engine with rules
        """
        logger.info("Initializing ASTScanner")
        self.threat_engine = threat_engine
        self.python_analyzer = PythonAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
        logger.debug("ASTScanner initialization completed")

    def scan_file(
        self, file_path: Path, language: LangEnum | None = None
    ) -> list[ThreatMatch]:
        """Scan a single file for security vulnerabilities.

        Args:
            file_path: Path to the file to scan
            language: Programming language (auto-detected if not provided)

        Returns:
            List of detected threats
        """
        logger.info(f"Starting AST scan of file: {file_path}")

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read file content
        try:
            with open(file_path, encoding="utf-8") as f:
                source_code = f.read()
            logger.debug(
                f"Successfully read file content: {len(source_code)} characters"
            )
        except UnicodeDecodeError as e:
            logger.debug(f"Skipping binary file {file_path}: {e}")
            # Skip binary files
            return []

        # Detect language if not provided
        if language is None:
            language = self._detect_language(file_path)
            logger.debug(f"Auto-detected language: {language.value}")
        else:
            logger.debug(f"Using provided language: {language.value}")

        return self.scan_code(source_code, str(file_path), language)

    def scan_code(
        self, source_code: str, file_path: str, language: LangEnum
    ) -> list[ThreatMatch]:
        """Scan source code for security vulnerabilities.

        Args:
            source_code: Source code to scan
            file_path: Path to the source file
            language: Programming language

        Returns:
            List of detected threats
        """
        # Create code context
        context = CodeContext(file_path, source_code, language)

        # Get applicable rules
        rules = self.threat_engine.get_rules_for_language(language)

        # Analyze code
        analysis_results = self._analyze_code(context)

        # Apply rules
        threats = []
        for rule in rules:
            matches = self._apply_rule(rule, context, analysis_results)
            threats.extend(matches)

        return threats

    def scan_directory(
        self, directory: Path, recursive: bool = True
    ) -> list[ThreatMatch]:
        """Scan a directory for security vulnerabilities.

        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories

        Returns:
            List of detected threats
        """
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        threats = []

        # Use centralized language support for file extensions
        from .threat_engine import LanguageSupport

        extension_to_lang_map = LanguageSupport.get_extension_to_language_map()

        # Filter to only supported languages that we can analyze with AST
        ast_supported_languages = {
            LangEnum.PYTHON,
            LangEnum.JAVASCRIPT,
            LangEnum.TYPESCRIPT,
        }
        extensions = {
            ext: lang
            for ext, lang in extension_to_lang_map.items()
            if lang in ast_supported_languages
        }

        # Scan files
        pattern = "**/*" if recursive else "*"
        for file_path in directory.glob(pattern):
            if file_path.is_file() and file_path.suffix in extensions:
                language = extensions[file_path.suffix]
                try:
                    file_threats = self.scan_file(file_path, language)
                    threats.extend(file_threats)
                except Exception as e:
                    # Log error but continue scanning
                    print(f"Error scanning {file_path}: {e}")

        return threats

    def _detect_language(self, file_path: Path) -> LangEnum:
        """Detect programming language from file extension.

        Args:
            file_path: Path to the file

        Returns:
            Detected language
        """
        suffix = file_path.suffix.lower()

        if suffix == ".py":
            return LangEnum.PYTHON
        elif suffix in [".js", ".jsx"]:
            return LangEnum.JAVASCRIPT
        elif suffix in [".ts", ".tsx"]:
            return LangEnum.TYPESCRIPT

        # Default to Python
        return LangEnum.PYTHON

    def _analyze_code(self, context: CodeContext) -> dict[str, Any]:
        """Analyze code based on language.

        Args:
            context: Code context

        Returns:
            Analysis results
        """
        if context.language == LangEnum.PYTHON:
            return self.python_analyzer.analyze(context)
        elif context.language in [LangEnum.JAVASCRIPT, LangEnum.TYPESCRIPT]:
            return self.js_analyzer.analyze(context)

        return {}

    def _apply_rule(
        self, rule: ThreatRule, context: CodeContext, analysis: dict[str, Any]
    ) -> list[ThreatMatch]:
        """Apply a single rule to the code.

        Args:
            rule: Threat detection rule
            context: Code context
            analysis: Analysis results

        Returns:
            List of threat matches
        """
        matches = []

        for condition in rule.conditions:
            condition_matches = self._check_condition(condition, context, analysis)

            for line_number, code_snippet, func_name in condition_matches:
                # Generate exploit examples
                exploit_examples = []
                for template in rule.exploit_templates:
                    exploit_examples.append(template.template)

                # Create threat match
                threat_match = ThreatMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=rule.description,
                    category=rule.category,
                    severity=rule.severity,
                    file_path=context.file_path,
                    line_number=line_number,
                    code_snippet=code_snippet,
                    function_name=func_name,
                    exploit_examples=exploit_examples,
                    remediation=rule.remediation,
                    references=rule.references,
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    confidence=0.8,  # Default confidence
                    source="rules",  # Rules engine
                )

                matches.append(threat_match)

        return matches

    def _check_condition(
        self, condition: MatchCondition, context: CodeContext, analysis: dict[str, Any]
    ) -> list[tuple]:
        """Check if a condition matches the code.

        Args:
            condition: Match condition
            context: Code context
            analysis: Analysis results

        Returns:
            List of (line_number, code_snippet, function_name) tuples
        """
        matches = []

        if condition.type == "pattern" or condition.type == "regex":
            # Pattern matching
            pattern = condition.value
            flags = 0 if condition.case_sensitive else re.IGNORECASE
            if condition.multiline:
                flags |= re.MULTILINE

            try:
                regex = re.compile(pattern, flags)
                for i, line in enumerate(context.lines, 1):
                    if regex.search(line):
                        code_snippet = context.get_code_snippet(i)
                        matches.append((i, code_snippet, None))
            except re.error:
                # Invalid regex, skip
                pass

        elif condition.type == "function_call":
            # Function call matching
            target_functions = condition.value
            if isinstance(target_functions, str):
                target_functions = [target_functions]

            function_calls = analysis.get("function_calls", [])

            # Find lines with matching function calls
            for func_name in function_calls:
                if func_name in target_functions:
                    # Find the line where this function is called
                    for i, line in enumerate(context.lines, 1):
                        if func_name in line:
                            code_snippet = context.get_code_snippet(i)
                            matches.append((i, code_snippet, func_name))

        elif condition.type == "import":
            # Import matching
            target_imports = condition.value
            if isinstance(target_imports, str):
                target_imports = [target_imports]

            imports = analysis.get("imports", [])

            for import_name in imports:
                if import_name in target_imports:
                    # Find the line with this import
                    for i, line in enumerate(context.lines, 1):
                        if import_name in line and ("import" in line or "from" in line):
                            code_snippet = context.get_code_snippet(i)
                            matches.append((i, code_snippet, None))

        elif condition.type == "variable":
            # Variable matching
            target_variables = condition.value
            if isinstance(target_variables, str):
                target_variables = [target_variables]

            variables = analysis.get("variables", [])

            for var_name in variables:
                if var_name in target_variables:
                    # Find lines with this variable
                    for i, line in enumerate(context.lines, 1):
                        if var_name in line:
                            code_snippet = context.get_code_snippet(i)
                            matches.append((i, code_snippet, None))

        return matches
