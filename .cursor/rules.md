# Adversary MCP Server - Development Rules

## Code Quality Standards

### Python Code Style
- **Formatting**: Use Black formatter with 88-character line length (`make format`)
- **Linting**: Use Ruff for fast Python linting (`make ruff`)
- **Type Checking**: Use MyPy with strict type checking enabled (`make mypy`)
- **Import Organization**: Use isort for consistent import ordering (included in `make format`)
- **Docstrings**: All public functions, classes, and modules must have docstrings
- **Type Hints**: All function parameters and return types must be annotated

### Security-First Development
- **Input Validation**: Always validate and sanitize user inputs
- **Error Handling**: Never expose sensitive information in error messages
- **Logging**: Use structured logging with appropriate log levels
- **Secrets Management**: Never hardcode secrets; use environment variables or secure stores
- **Dependency Security**: Regularly audit dependencies (`make security-scan`)

### Testing Requirements
- **Coverage**: Maintain >75% test coverage (`make test`)
- **Test Types**: Write unit (`make test-unit`), integration (`make test-integration`), and security tests (`make test-security`)
- **Quick Testing**: Use fast tests during development (`make test-fast`)
- **Coverage Reports**: Generate HTML coverage reports (`make test-html`)
- **Test Naming**: Use descriptive test names that explain the scenario
- **Mocking**: Use pytest fixtures and mocks for external dependencies
- **Security Tests**: Include tests for security vulnerabilities and edge cases

## Architecture Principles

### MCP Server Design
- **Tool Independence**: Each MCP tool should be self-contained
- **Async Operations**: Use async/await for I/O operations
- **Error Propagation**: Proper error handling with meaningful messages
- **Resource Management**: Clean up resources (files, connections) properly

### Security Engine Design
- **Modular Scanners**: Keep scanner implementations separate and pluggable
- **Rule Management**: Support for built-in, custom, and organization rules
- **Performance**: Optimize for large codebases with caching strategies
- **Extensibility**: Design for easy addition of new security rules and scanners

### Data Handling
- **Immutable Data**: Prefer immutable data structures where possible
- **Schema Validation**: Use Pydantic for data validation and serialization
- **File Operations**: Use pathlib for cross-platform file operations
- **JSON Handling**: Standardize JSON schemas for scan results

## Development Workflow

### Daily Development Commands
```bash
# Initial setup (one time)
make dev-setup-uv

# Before starting work
make sync                    # Sync dependencies

# During development
make test-fast              # Quick test feedback
make format                 # Format code
make ruff-fix              # Auto-fix linting issues

# Before committing
make check-all             # Run all checks
make pre-commit            # Run pre-commit hooks

# Build and deploy
make build                 # Build package
make demo                  # Test demo functionality
```

### Git Practices
- **Branch Naming**: Use descriptive branch names (feature/, fix/, security/)
- **Commit Messages**: Write clear, concise commit messages
- **Pull Requests**: Include description, testing notes, and security considerations
- **Code Review**: All code must be reviewed before merging

### Development Environment
- **Setup**: Initialize development environment (`make dev-setup-uv`)
- **Dependencies**: Install and sync dependencies (`make install-uv`, `make sync`)
- **Virtual Environment**: Always develop in a virtual environment (`.venv`)
- **Hot Reload**: Use hot reload for faster development iterations
- **Local Testing**: Run full test suite before committing (`make test`)
- **Pre-commit**: Use pre-commit hooks (`make install-pre-commit`, `make pre-commit`)

### Security Development Lifecycle
- **Threat Modeling**: Consider security implications of new features
- **Secure Defaults**: Choose secure defaults for all configurations
- **Vulnerability Assessment**: Regular security scanning of the codebase
- **Incident Response**: Have procedures for handling security issues

## Code Review Checklist

### Functionality
- [ ] Code accomplishes its intended purpose
- [ ] Edge cases are handled appropriately
- [ ] Error conditions are properly managed
- [ ] Performance considerations are addressed

### Security
- [ ] No hardcoded secrets or credentials
- [ ] Input validation is comprehensive
- [ ] Output sanitization is applied
- [ ] Authentication and authorization are correct
- [ ] SQL injection and XSS protections are in place
- [ ] Security scan passes (`make security-scan`)

### Quality
- [ ] Code follows established patterns (`make lint`)
- [ ] Code is properly formatted (`make format-check`)
- [ ] Type checking passes (`make mypy`)
- [ ] Documentation is complete and accurate
- [ ] Tests cover the new functionality (`make test`)
- [ ] No code duplication or unnecessary complexity

### MCP Specific
- [ ] Tool definitions are complete and accurate
- [ ] Resource cleanup is handled properly
- [ ] Error messages are user-friendly
- [ ] Tool interactions are well-documented

## Performance Guidelines

### Scanning Performance
- **Caching**: Implement intelligent caching for repeated operations
- **Parallel Processing**: Use asyncio for concurrent operations
- **Memory Management**: Monitor and optimize memory usage for large files
- **File I/O**: Minimize file system operations

### Database/Storage
- **False Positive Management**: Optimize false positive lookups
- **Result Storage**: Efficient JSON serialization/deserialization
- **Indexing**: Use appropriate data structures for fast lookups

## Documentation Standards

### Code Documentation
- **Module Docstrings**: Explain the purpose and usage of each module
- **Class Docstrings**: Document class purpose, attributes, and usage patterns
- **Function Docstrings**: Include parameters, return values, and examples
- **Inline Comments**: Explain complex logic and security considerations

### User Documentation
- **CLI Help**: Comprehensive help text for all commands
- **Examples**: Provide working examples for common use cases
- **Configuration**: Document all configuration options
- **Troubleshooting**: Include common issues and solutions

## Anti-Patterns to Avoid

### Security Anti-Patterns
- ❌ Trusting user input without validation
- ❌ Exposing sensitive data in logs or error messages
- ❌ Using weak cryptographic practices
- ❌ Ignoring security warnings from tools

### Code Anti-Patterns
- ❌ Deep nesting (prefer early returns)
- ❌ Large functions (keep functions focused and small)
- ❌ Global state (prefer dependency injection)
- ❌ Magic numbers/strings (use constants or configuration)
- ❌ Bypassing make targets (use `make lint` instead of direct `ruff` calls)
- ❌ Skipping code formatting (`make format` before committing)

### MCP Anti-Patterns
- ❌ Blocking operations in async functions
- ❌ Poor error propagation to client
- ❌ Inconsistent tool interfaces
- ❌ Resource leaks in long-running operations

## Build and Deployment

### Package Management
- **Dependencies**: Use `make sync` to ensure consistent dependency versions
- **Lock Files**: Update lock files with `make lock` when adding dependencies
- **Clean Builds**: Use `make clean` before building releases

### Quality Assurance
- **Pre-deployment**: Always run `make check-all` before releases
- **CI/CD Integration**: Use CI-specific targets (`make ci-test`, `make ci-lint`, `make ci-security`)
- **Distribution**: Build packages with `make build` and deploy with `make deploy`

### Documentation
- **Help**: Use `make help` to see all available targets
- **Examples**: Test examples with `make scan-example` and `make demo`

## Vulnerable Test Code Management

### Examples Directory Standards
- **Purpose**: Contains intentionally vulnerable code for testing security scanners
- **Safety**: Never deploy or run vulnerable example code in production environments
- **Documentation**: Each vulnerability should be clearly commented for educational purposes
- **Coverage**: Maintain examples for all major vulnerability categories we detect
- **Validation**: Regularly test that our scanners detect all known vulnerabilities in examples

### Adding New Vulnerable Examples
- **Realistic Code**: Create examples that resemble real-world vulnerable patterns
- **Multiple Languages**: Include examples in Python, JavaScript, and other supported languages
- **Clear Comments**: Explain why each code pattern is vulnerable
- **Test Integration**: Ensure `make scan-example` detects the new vulnerabilities
- **Educational Value**: Examples should help developers understand security issues

### Scanner Validation Workflow
```bash
# Test scanners against examples
make scan-example              # Run security scan on vulnerable examples
make test-security            # Run security-focused tests

# Validate detection accuracy
# - Check that all known vulnerabilities are detected
# - Verify no false positives on safe code patterns
# - Test scanner effectiveness across different languages
```

### Vulnerable Code Anti-Patterns
- ❌ Adding vulnerable code outside the examples/ directory
- ❌ Running vulnerable example code in production contexts
- ❌ Creating examples without educational comments
- ❌ Failing to test that scanners detect new vulnerable examples
- ❌ Including sensitive or real credentials in example code
