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

## Claude Code Specific Guidelines

### MCP Tool Development
- **Parameter Validation**: Use Pydantic models for all tool parameters
- **Error Handling**: Return structured error messages using AdversaryToolError
- **Async Support**: All tools should support async operations where appropriate
- **Resource Management**: Properly clean up temporary files and connections
- **Logging**: Use structured logging with appropriate context

### Integration Patterns
- **File System**: Use pathlib for all file operations
- **Configuration**: Support both environment variables and configuration files
- **Credentials**: Integrate with OS keyring for secure credential storage
- **Caching**: Implement intelligent caching for performance optimization

### Testing for MCP Integration
- **Mock MCP Client**: Test tools with simulated MCP client interactions
- **Parameter Validation**: Test all parameter combinations and edge cases
- **Error Scenarios**: Test tool behavior under various error conditions
- **Performance**: Test with large inputs and verify timeout handling

### Documentation for Claude Code
- **Tool Descriptions**: Provide clear, comprehensive tool descriptions
- **Usage Examples**: Include realistic usage examples in documentation
- **Error Handling**: Document all possible error conditions and responses
- **Configuration**: Document all configuration options and their effects

## Defensive Security Focus

### Vulnerability Detection
- **Rule Quality**: Ensure security rules have high accuracy and low false positive rates
- **Coverage**: Maintain comprehensive coverage of OWASP Top 10 and CWE categories
- **Language Support**: Support multiple programming languages and frameworks
- **Business Logic**: Include rules for application-specific vulnerabilities

### Educational Approach
- **Remediation Guidance**: Provide clear, actionable remediation advice
- **Learning Resources**: Include references to security best practices
- **Safe Examples**: Use safe, educational examples in documentation
- **Context Awareness**: Explain why vulnerabilities are dangerous

### Ethical Considerations
- **Defensive Only**: Focus exclusively on defensive security measures
- **Educational Value**: Prioritize learning and improvement over demonstration
- **Responsible Disclosure**: Follow responsible disclosure practices
- **Privacy Respect**: Never log or expose sensitive user data

## Development Environment Best Practices

### Virtual Environment Management
```bash
# Always activate virtual environment before development
source .venv/bin/activate

# Use uv for fast dependency management
make dev-setup-uv
make sync
```

### IDE Configuration
- **Type Checking**: Enable MyPy in your IDE for real-time type checking
- **Formatting**: Configure auto-formatting with Black on save
- **Linting**: Enable Ruff linting with real-time feedback
- **Testing**: Configure test runner integration for quick feedback

### Debugging and Profiling
- **Structured Logging**: Use the configured logging system for debugging
- **Performance Profiling**: Profile security scanning operations
- **Memory Monitoring**: Monitor memory usage during large scans
- **Error Tracking**: Implement comprehensive error tracking and reporting
