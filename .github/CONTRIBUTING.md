# Contributing to Adversary MCP Server

Thank you for your interest in contributing to the Adversary MCP Server! This guide will help you get started with contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful**: Treat all contributors with respect and professionalism
- **Be collaborative**: Work together to improve the project
- **Be inclusive**: Welcome contributors of all backgrounds and experience levels
- **Be constructive**: Provide helpful feedback and suggestions

## Development Setup

### Prerequisites

- **Python 3.10+** (3.11+ recommended)
- **Git**
- **uv** (recommended) or **pip**

### Quick Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/your-username/adversary-mcp-server.git
   cd adversary-mcp-server
   ```

2. **Set up development environment**:
   ```bash
   # Using uv (recommended - faster)
   pip install uv
   uv venv
   source .venv/bin/activate  # Linux/Mac
   # or .venv\Scripts\activate  # Windows
   uv pip install -e ".[dev]"

   # OR using traditional pip
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Verify installation**:
   ```bash
   adversary-mcp-cli --version
   make test-fast
   ```

### Development Tools

The project uses several development tools:

- **uv**: Fast Python package installer and resolver
- **pytest**: Testing framework
- **ruff**: Fast Python linter
- **mypy**: Static type checker
- **black**: Code formatter
- **bandit**: Security linter
- **semgrep**: Security scanner

All tools are configured in `pyproject.toml` and can be run via Makefile targets.

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-new-scanner` - New features
- `fix/memory-leak-in-scanner` - Bug fixes
- `docs/update-installation-guide` - Documentation
- `refactor/improve-error-handling` - Code improvements
- `security/fix-cve-2024-xxxx` - Security fixes

### Commit Messages

Write clear, descriptive commit messages:

```
type(scope): brief description

Detailed explanation if needed.

- Include bullet points for multiple changes
- Reference issues with #123
- Use present tense ("add" not "added")
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `security`: Security-related changes

**Examples:**
```
feat(scanner): add Semgrep integration for static analysis

Add SemgrepScanner class that integrates with Semgrep CLI tool
to provide additional static analysis capabilities alongside
existing rule-based and LLM analysis.

- Supports both free and pro Semgrep tiers
- Automatic detection of SEMGREP_APP_TOKEN
- Intelligent result merging with existing engines
- Configurable timeouts and error handling

Fixes #123
```

## Testing

### Running Tests

```bash
# Quick test run (no coverage)
make test-fast

# Full test suite with coverage
make test

# HTML coverage report
make test-html

# Specific test categories
make test-unit        # Unit tests only
make test-integration # Integration tests only
make test-security    # Security-related tests
```

### Writing Tests

1. **Test Organization**:
   - Place tests in `tests/` directory
   - Name test files `test_<module>.py`
   - Use descriptive test method names

2. **Test Structure**:
   ```python
   import pytest
   from unittest.mock import Mock, patch

   from adversary_mcp_server.module import ClassToTest

   class TestClassToTest:
       """Test cases for ClassToTest."""

       def setup_method(self):
           """Setup test fixtures."""
           self.instance = ClassToTest()

       def test_method_should_return_expected_value(self):
           """Test that method returns expected value."""
           # Arrange
           expected = "expected_value"

           # Act
           result = self.instance.method()

           # Assert
           assert result == expected
   ```

3. **Test Coverage**:
   - Aim for 75%+ code coverage
   - Test both happy path and error cases
   - Mock external dependencies
   - Use fixtures for complex test data

4. **Test Categories** (use pytest markers):
   ```python
   @pytest.mark.unit
   def test_unit_functionality():
       """Unit test."""
       pass

   @pytest.mark.integration
   def test_integration_functionality():
       """Integration test."""
       pass

   @pytest.mark.security
   def test_security_feature():
       """Security-related test."""
       pass
   ```

### Testing Guidelines

- **Mock external services**: Don't make real network calls
- **Use temporary files**: For file system tests
- **Test error conditions**: Not just happy paths
- **Keep tests fast**: Unit tests should run in milliseconds
- **Make tests deterministic**: No random values or time dependencies

## Code Quality

### Linting and Formatting

Run all quality checks:
```bash
make lint          # Run all linting tools
make format        # Format code with black
make format-check  # Check formatting without changing files
```

Individual tools:
```bash
make ruff          # Python linting with ruff
make mypy          # Type checking with mypy
make security-scan # Security scanning with bandit and semgrep
```

### Code Style Guidelines

1. **Follow PEP 8**: Use black for automatic formatting
2. **Type hints**: Add type hints to all functions and methods
3. **Docstrings**: Use Google-style docstrings
4. **Error handling**: Use specific exception types
5. **Security**: Follow secure coding practices

Example function:
```python
def scan_code(
    self,
    source_code: str,
    file_path: str,
    language: Language,
    use_llm: bool = False,
) -> EnhancedScanResult:
    """Scan source code for security vulnerabilities.

    Args:
        source_code: The source code to scan
        file_path: Path to the source file
        language: Programming language of the code
        use_llm: Whether to enable LLM analysis

    Returns:
        Enhanced scan result with threat information

    Raises:
        ScanEngineError: If scanning fails
        ValueError: If invalid parameters provided
    """
    # Implementation here
```

### Security Guidelines

- **Input validation**: Validate all user inputs
- **Output sanitization**: Sanitize outputs to prevent injection
- **Secure defaults**: Use secure default configurations
- **Principle of least privilege**: Minimize required permissions
- **Dependency management**: Keep dependencies updated

## Pull Request Process

### Before Submitting

1. **Update from main**:
   ```bash
   git checkout main
   git pull upstream main
   git checkout your-feature-branch
   git rebase main
   ```

2. **Run full test suite**:
   ```bash
   make check-all  # Runs linting, tests, and security scans
   ```

3. **Update documentation**: If your changes affect user-facing functionality

4. **Add tests**: Ensure new code is properly tested

### PR Requirements

✅ **Required Checks:**
- [ ] All tests pass
- [ ] Code coverage ≥ 75%
- [ ] Linting passes (ruff, mypy, black)
- [ ] Security scans pass (bandit, semgrep)
- [ ] Documentation updated if needed
- [ ] CHANGELOG.md updated for user-facing changes

### PR Template

When creating a PR, include:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Documentation update

## Testing
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] I have tested the changes manually

## Checklist
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] Any dependent changes have been merged and published
```

### Review Process

1. **Automated checks**: CI pipeline must pass
2. **Code review**: At least one maintainer review required
3. **Testing**: Reviewers may test changes locally
4. **Approval**: All feedback addressed and approved
5. **Merge**: Squash and merge to main branch

## Release Process

### Version Management

The project uses semantic versioning (semver):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Steps

1. **Update version** in `pyproject.toml`:
   ```toml
   [project]
   version = "0.8.0"
   ```

2. **Update CHANGELOG.md** with release notes

3. **Create release tag**:
   ```bash
   git tag -a v0.8.0 -m "Release v0.8.0"
   git push origin v0.8.0
   ```

4. **GitHub Actions** will automatically:
   - Run full test suite
   - Build package
   - Publish to PyPI
   - Create GitHub release
   - Build Docker image

## Contributing Areas

### High-Priority Areas

1. **Security Rules**: Add new detection rules
2. **Language Support**: Extend support for more programming languages
3. **Performance**: Optimize scanning performance
4. **Documentation**: Improve user guides and API docs
5. **Testing**: Increase test coverage and add integration tests

### Rule Contributions

1. **Create new rule**:
   ```bash
   cp rules/templates/rule-template.yaml rules/custom/my-rule.yaml
   ```

2. **Edit rule definition**:
   ```yaml
   rules:
     - id: my_security_rule
       name: My Security Rule
       description: Detects security issue X
       category: injection
       severity: high
       languages: [python, javascript]

       conditions:
         - type: pattern
           value: "dangerous_pattern.*"

       remediation: |
         Fix the issue by doing Y instead of X.

       references:
         - https://owasp.org/...
   ```

3. **Add tests**:
   ```python
   def test_my_security_rule():
       """Test that my rule detects the vulnerability."""
       vulnerable_code = "dangerous_pattern(user_input)"
       threats = scanner.scan_code(vulnerable_code, "test.py", Language.PYTHON)
       assert any(t.rule_id == "my_security_rule" for t in threats)
   ```

4. **Test rule**:
   ```bash
   adversary-mcp-cli rules validate
   adversary-mcp-cli scan test-file.py
   ```

## Getting Help

- **GitHub Issues**: Report bugs or request features
- **GitHub Discussions**: Ask questions or discuss ideas
- **Documentation**: Check the README and wiki
- **Code**: Look at existing implementations for examples

## Recognition

Contributors are recognized in:
- `CONTRIBUTORS.md` file
- GitHub releases
- Project documentation

Thank you for contributing to making software security analysis more accessible and effective! 🚀
