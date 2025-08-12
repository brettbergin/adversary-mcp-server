# SDLC Agent Fleet

A comprehensive collection of specialized agents for each stage of the Software Development Lifecycle, designed to assist Claude Code with domain-specific expertise.

## Agent Overview

### 🔍 [Requirements Analysis Agent](./requirements_agent.md)
**Stage**: Requirements Gathering & Analysis
**Expertise**: Business requirements, user stories, acceptance criteria, stakeholder analysis
**Use When**: Starting new features, clarifying unclear requirements, writing specifications

### 🏗️ [Architecture & Design Agent](./architecture_agent.md)
**Stage**: Design & Architecture Planning
**Expertise**: System architecture, design patterns, technology selection, scalability planning
**Use When**: Designing systems, evaluating technologies, architecture reviews, integration planning

### 💻 [Development & Coding Agent](./development_agent.md)
**Stage**: Development & Implementation
**Expertise**: Multi-language programming, code quality, design patterns, refactoring
**Use When**: Writing code, code reviews, debugging, performance optimization, establishing standards

### 🔒 [Application Security Agent](./security_agent.md)
**Stage**: Security Analysis & Threat Modeling
**Expertise**: OWASP Top 10, vulnerability assessment, secure coding, threat modeling
**Use When**: Security reviews, vulnerability analysis, implementing auth/crypto, incident response

### 🧪 [Testing & QA Agent](./testing_agent.md)
**Stage**: Testing, Validation & Quality Assurance
**Expertise**: Test automation, quality metrics, TDD/BDD, performance testing
**Use When**: Test strategy design, automation setup, quality gates, test troubleshooting

### 🚀 [Deployment & DevOps Agent](./deployment_agent.md)
**Stage**: Deployment, Release Management & Infrastructure
**Expertise**: CI/CD pipelines, Infrastructure as Code, container orchestration, cloud platforms
**Use When**: Pipeline setup, infrastructure design, deployment strategies, environment management

### 🔧 [Operations & Maintenance Agent](./operations_agent.md)
**Stage**: Operations, Maintenance & Continuous Improvement
**Expertise**: SRE practices, monitoring, incident response, capacity planning
**Use When**: Production issues, monitoring setup, maintenance planning, performance optimization

## Usage Guidelines

### Agent Selection
Choose agents based on the current phase of your project or the specific domain expertise needed:

- **Early Project Phases**: Requirements → Architecture → Development
- **Implementation Phase**: Development → Security → Testing
- **Deployment Phase**: Testing → Deployment → Operations
- **Maintenance Phase**: Operations → Security → Development (for fixes)

### Multi-Agent Collaboration
Many tasks benefit from multiple agent perspectives:

- **New Feature Development**: Requirements + Architecture + Development + Security
- **Performance Issues**: Operations + Development + Testing + Architecture
- **Security Incidents**: Security + Operations + Development
- **Release Planning**: Testing + Deployment + Operations

### Integration with Claude Code
These agents are designed to work seamlessly with Claude Code's capabilities:

- **Code Analysis**: Security Agent + Development Agent for comprehensive code review
- **System Design**: Architecture Agent + Security Agent for secure system design
- **Quality Assurance**: Testing Agent + Development Agent for comprehensive testing strategy
- **Production Support**: Operations Agent + Security Agent for incident response

## Agent Specializations

### Security Agent Deep Dive
The Security Agent has specialized knowledge in application security defects including:

- **Injection Vulnerabilities**: SQL, NoSQL, Command, LDAP, XPath injection
- **Authentication Flaws**: Broken auth, session management, credential stuffing
- **Access Control**: RBAC/ABAC, IDOR, missing function-level access control
- **Data Exposure**: Sensitive data exposure, XXE, insecure deserialization
- **Input/Output Issues**: XSS, SSRF, path traversal, buffer overflows
- **Cryptographic Failures**: Weak crypto, insecure RNG, key management

### Development Workflow Integration
Each agent is designed to integrate with common development workflows:

- **Git Integration**: All agents understand branching strategies and code review processes
- **CI/CD Awareness**: Deployment and Testing agents specialize in pipeline integration
- **Monitoring Integration**: Operations agent connects with observability platforms
- **Security Integration**: Security agent works with SAST/DAST tools and vulnerability scanners

## Best Practices

1. **Start with Requirements**: Always begin complex projects with the Requirements Agent
2. **Security by Design**: Involve the Security Agent early in architecture and design phases
3. **Test-Driven Approach**: Engage the Testing Agent alongside Development for TDD practices
4. **Operations Readiness**: Include the Operations Agent in deployment planning
5. **Continuous Improvement**: Use agent expertise for retrospectives and process improvements

## Future Enhancements

This agent fleet is designed to be extensible. Future additions may include:

- **Data Engineering Agent**: For data pipeline and analytics projects
- **Mobile Development Agent**: Specialized mobile app development expertise
- **AI/ML Agent**: Machine learning and AI system development
- **Compliance Agent**: Regulatory compliance and governance expertise
- **UX/UI Agent**: User experience and interface design specialization
