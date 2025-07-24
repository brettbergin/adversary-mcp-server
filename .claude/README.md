# Claude Code Configuration

This directory contains configuration files for Claude Code to enhance the development experience for the Adversary MCP Server project.

## Files Overview

### `settings.local.json`
Local Claude Code settings that define:
- Bash command permissions for development workflows
- Test execution permissions with coverage reporting
- Virtual environment activation permissions
- Project-specific command allowlists

### `context.md`
Comprehensive project context for AI assistance:
- Architecture overview and component descriptions
- Data models and JSON schemas
- Security features and vulnerability categories
- Integration points and external dependencies
- Common development workflows
- Virtual environment and development commands

### `prompts.md`
Specialized AI prompts for security-focused development:
- Security analysis and vulnerability detection
- Code generation for scanners and rules
- Testing strategies for security tools
- Documentation generation
- Debugging and performance optimization
- Advanced analysis for business logic, cryptography, and infrastructure

### `architecture.md`
Detailed system architecture documentation:
- High-level system design diagrams
- Component relationships and data flow
- Performance and security architecture
- Extensibility points and deployment patterns
- Monitoring and observability strategies

### `rules.md`
Development guidelines and coding standards including:
- Python code quality standards
- Security-first development practices
- Testing requirements and patterns
- MCP server design principles
- Performance optimization guidelines
- Code review checklists
- Claude Code specific integration patterns

## Usage

These files are automatically used by Claude Code to:
- Provide better code completion and suggestions
- Understand project structure and patterns
- Apply security-focused analysis
- Generate appropriate tests and documentation
- Follow established coding standards
- Execute development commands safely

## Benefits

- **Enhanced AI Assistance**: AI understands the security domain and project patterns
- **Consistent Development**: Standardized practices across the team
- **Better Code Quality**: Automated adherence to security and quality standards
- **Faster Onboarding**: New developers get immediate context about the project
- **Security Focus**: AI assistance tuned for security analysis and vulnerability detection
- **Safe Command Execution**: Controlled permissions for development commands

## Development Workflow Integration

### Permitted Commands
The configuration allows safe execution of key development commands:
- Virtual environment activation (`source .venv/bin/activate`)
- Test execution with coverage reporting
- Specific test module execution
- Test collection and discovery

### Security Considerations
- Commands are explicitly allowlisted for security
- No arbitrary command execution
- Focus on defensive security development only
- Safe development environment practices

## Maintenance

Update these files when:
- Adding new components or architectural changes
- Modifying development workflows or standards
- Introducing new security patterns or rules
- Changing tool configurations or dependencies
- Adding new development commands that need permission

## Comparison with .cursor Directory

The .claude directory provides similar but enhanced documentation compared to .cursor:
- More detailed security-focused prompts
- Enhanced architecture documentation with monitoring
- Specific Claude Code integration patterns
- Defensive security emphasis throughout
- Virtual environment integration guidance

The configuration is designed to evolve with the project while maintaining consistency in development practices and security focus.
