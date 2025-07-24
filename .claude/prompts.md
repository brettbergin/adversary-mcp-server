# Adversary MCP Server - AI Prompts

## Security Analysis Prompts

### Vulnerability Detection
```
Analyze this code for security vulnerabilities with a focus on:
1. Injection attacks (SQL, command, LDAP, XSS)
2. Authentication and authorization flaws
3. Cryptographic weaknesses
4. Information disclosure
5. Business logic vulnerabilities

For each vulnerability found, provide:
- Severity level (critical/high/medium/low)
- CWE classification
- OWASP category
- Specific line numbers
- Proof of concept exploit
- Remediation guidance

Code to analyze:
{code}
```

### Security Rule Development
```
Create a security rule for detecting {vulnerability_type} in {language} code.

The rule should:
1. Use YAML format following our ThreatRule schema
2. Include accurate pattern matching (regex or AST)
3. Provide clear description and remediation
4. Include test cases (vulnerable and safe code)
5. Reference relevant CWE and OWASP categories

Focus on minimizing false positives while maintaining high detection accuracy.
```

### Code Review Security
```
Perform a security-focused code review on this change:

{code_diff}

Check for:
- New security vulnerabilities introduced
- Removal of existing security controls
- Proper input validation and sanitization
- Secure error handling
- Authentication/authorization impacts
- Data exposure risks

Provide specific line-by-line feedback with security recommendations.
```

## Development Prompts

### MCP Tool Implementation
```
Implement a new MCP tool for the Adversary MCP Server with the following requirements:

Tool Name: {tool_name}
Purpose: {tool_purpose}
Parameters: {tool_parameters}

The implementation should:
1. Follow the existing MCP tool pattern in server.py
2. Include proper error handling with AdversaryToolError
3. Use structured logging with appropriate log levels
4. Validate all input parameters using Pydantic
5. Return results in the standard TextContent format
6. Include comprehensive docstring with examples

Ensure thread safety and proper resource cleanup.
```

### Scanner Integration
```
Create a new security scanner for the Adversary MCP Server that integrates with {scanner_name}.

Requirements:
1. Implement the scanner interface pattern used by existing scanners
2. Support async operations for large codebases
3. Return standardized ThreatMatch objects
4. Include error handling and timeout management
5. Add configuration options in security_config.py
6. Write comprehensive unit tests
7. Document usage and configuration

Focus on performance optimization and proper error propagation.
```

### Performance Optimization
```
Analyze and optimize the performance of this code for large-scale security scanning:

{code}

Consider:
1. Caching strategies for repeated operations
2. Async/await patterns for I/O operations
3. Memory usage optimization
4. File system operation minimization
5. Database/storage access patterns
6. Parallel processing opportunities

Provide specific recommendations with code examples.
```

## Testing Prompts

### Security Test Creation
```
Create comprehensive security tests for this vulnerability detection function:

{function_code}

The tests should include:
1. Positive cases: Code that should trigger the vulnerability detection
2. Negative cases: Similar but safe code that should not trigger
3. Edge cases: Boundary conditions and unusual inputs
4. False positive tests: Code that might trigger but shouldn't
5. Performance tests: Large inputs and stress testing

Use pytest framework with appropriate fixtures and mocks.
```

### Integration Test Design
```
Design integration tests for the complete security scanning pipeline from {input_type} to {output_type}.

Test scenarios should cover:
1. Multiple scanner combinations (rules + LLM + Semgrep)
2. Different programming languages
3. Various vulnerability types
4. Error conditions and recovery
5. Performance with large codebases
6. False positive handling

Include setup/teardown for test data and external service mocking.
```

## Documentation Prompts

### API Documentation
```
Generate comprehensive API documentation for this MCP tool:

{tool_implementation}

Include:
1. Tool description and purpose
2. Parameter specifications with types and validation
3. Return value format and schema
4. Usage examples with different scenarios
5. Error conditions and handling
6. Performance considerations
7. Security implications

Format as markdown with clear examples.
```

### Security Rule Documentation
```
Document this security rule for the user guide:

{rule_yaml}

Include:
1. Rule purpose and vulnerability description
2. Affected languages and frameworks
3. Example vulnerable code patterns
4. Remediation best practices
5. False positive scenarios and how to avoid them
6. Related CWE/OWASP references
7. Testing and validation approaches
```

## Debugging Prompts

### Log Analysis
```
Analyze these log entries to diagnose the security scanning performance issue:

{log_entries}

Focus on:
1. Performance bottlenecks and timing issues
2. Error patterns and failure modes
3. Resource usage anomalies
4. Scanner-specific issues
5. Configuration problems

Provide specific recommendations for resolution.
```

### Error Investigation
```
Investigate this error occurring during security scanning:

Error: {error_message}
Stack trace: {stack_trace}
Context: {context_info}

Analyze:
1. Root cause of the error
2. Impact on scan accuracy and completeness
3. Potential security implications
4. Recommended fixes with code examples
5. Prevention strategies for similar issues
```

## Code Generation Prompts

### Rule Template Generation
```
Generate a security rule template for detecting {vulnerability_pattern} vulnerabilities.

The template should:
1. Follow the YAML schema in rules/templates/
2. Include placeholder patterns for common cases
3. Provide guidance comments for customization
4. Include example test cases
5. Reference relevant security standards
6. Support multiple programming languages where applicable
```

### Exploit Generation
```
Generate a proof-of-concept exploit for this vulnerability:

Vulnerability: {vulnerability_description}
Location: {file_path}:{line_number}
Code snippet: {vulnerable_code}

The exploit should:
1. Demonstrate the vulnerability impact
2. Be safe for testing environments
3. Include clear explanation of the attack vector
4. Provide step-by-step reproduction instructions
5. Suggest defensive measures

Focus on educational value while being responsible about disclosure.
```

## Configuration Prompts

### Rule Configuration
```
Create a configuration setup for managing security rules across these scenarios:

1. Built-in rules for common vulnerabilities
2. Custom rules for organization-specific patterns
3. Language-specific rule sets
4. Severity-based rule filtering
5. False positive rule exclusions

Include examples for each configuration type and validation logic.
```

### Scanner Configuration
```
Design a configuration system for managing multiple security scanners with these requirements:

1. Enable/disable individual scanners
2. Scanner-specific settings and timeouts
3. Result aggregation and deduplication
4. Performance tuning parameters
5. External service integration settings

Provide YAML configuration examples and validation schemas.
```

## Refactoring Prompts

### Architecture Improvement
```
Refactor this code to improve the security scanning architecture:

{existing_code}

Goals:
1. Better separation of concerns
2. Improved testability and mocking
3. Enhanced error handling and logging
4. Performance optimization
5. Easier extensibility for new scanners

Maintain backward compatibility and existing API contracts.
```

### Security Hardening
```
Review and harden this code against security vulnerabilities:

{code_to_harden}

Focus on:
1. Input validation and sanitization
2. Output encoding and escaping
3. Authentication and authorization
4. Secure error handling
5. Logging without sensitive data exposure
6. Resource cleanup and DoS prevention

Provide specific code improvements with security justification.
```

## Advanced Analysis Prompts

### Business Logic Analysis
```
Analyze this application code for business logic vulnerabilities:

{application_code}

Focus on:
1. Authorization bypass opportunities
2. Race condition vulnerabilities
3. State manipulation attacks
4. Privilege escalation paths
5. Data validation bypass
6. Workflow sequence violations

Consider the business context and provide realistic attack scenarios.
```

### Cryptographic Analysis
```
Review this cryptographic implementation for security weaknesses:

{crypto_code}

Evaluate:
1. Algorithm selection and strength
2. Key generation and management
3. Random number generation
4. Initialization vectors and salts
5. Padding and mode selection
6. Side-channel vulnerability potential

Reference current cryptographic best practices and standards.
```

### Infrastructure Security
```
Analyze this deployment/configuration code for security issues:

{infrastructure_code}

Check for:
1. Insecure default configurations
2. Missing security headers
3. Improper access controls
4. Credential exposure
5. Network security misconfigurations
6. Container/orchestration security issues

Provide hardening recommendations aligned with security benchmarks.
```

## Specialized Domain Prompts

### Web Application Security
```
Perform a comprehensive security analysis of this web application component:

{web_app_code}

Focus on OWASP Top 10 vulnerabilities:
1. Injection flaws (SQL, NoSQL, LDAP, OS command)
2. Broken authentication and session management
3. Sensitive data exposure
4. XML external entities (XXE)
5. Broken access control
6. Security misconfiguration
7. Cross-site scripting (XSS)
8. Insecure deserialization
9. Using components with known vulnerabilities
10. Insufficient logging and monitoring

Provide specific remediation for each finding.
```

### API Security Analysis
```
Analyze this API implementation for security vulnerabilities:

{api_code}

Evaluate:
1. Authentication and authorization mechanisms
2. Input validation and sanitization
3. Rate limiting and DoS protection
4. Data exposure and information leakage
5. CORS configuration
6. API versioning security implications
7. Error handling and information disclosure
8. Logging and monitoring coverage

Consider REST, GraphQL, and other API paradigms as applicable.
```

### Mobile Application Security
```
Review this mobile application code for platform-specific security issues:

{mobile_code}

Platform: {ios|android|react_native|flutter}

Focus on:
1. Data storage security (keychain, preferences, databases)
2. Network communication security
3. Authentication and biometric integration
4. Deep linking and URL scheme security
5. Inter-app communication vulnerabilities
6. Runtime application self-protection (RASP)
7. Code obfuscation and anti-tampering
8. Platform-specific permission models

Consider mobile-specific attack vectors and mitigation strategies.
```
