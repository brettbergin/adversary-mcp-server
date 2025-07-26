"""STRIDE-based threat catalog for threat modeling."""

from .models import ComponentType, Severity, Threat, ThreatType


class ThreatCatalog:
    """Catalog of STRIDE threats mapped to component types."""

    def __init__(self):
        """Initialize the threat catalog."""
        self.threats = self._build_threat_catalog()

    def _build_threat_catalog(self) -> dict[str, dict[str, dict]]:
        """Build the complete STRIDE threat catalog."""
        return {
            # SPOOFING THREATS
            ThreatType.SPOOFING.value: {
                "weak_authentication": {
                    "title": "Weak Authentication Mechanism",
                    "description": "Authentication mechanism can be bypassed or is insufficient",
                    "severity": Severity.HIGH,
                    "applies_to": [
                        ComponentType.PROCESS,
                        ComponentType.EXTERNAL_ENTITY,
                    ],
                    "indicators": [
                        "no authentication",
                        "basic auth",
                        "hardcoded credentials",
                    ],
                    "mitigation": "Implement strong authentication (OAuth2, JWT, MFA)",
                    "cwe_id": "CWE-287",
                },
                "session_fixation": {
                    "title": "Session Fixation",
                    "description": "Session identifiers are not regenerated after authentication",
                    "severity": Severity.MEDIUM,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["session management", "login", "authentication"],
                    "mitigation": "Regenerate session IDs after login and implement secure session management",
                    "cwe_id": "CWE-384",
                },
                "identity_spoofing": {
                    "title": "Identity Spoofing",
                    "description": "External entities can impersonate legitimate users or systems",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.EXTERNAL_ENTITY],
                    "indicators": ["external api", "third party", "webhook"],
                    "mitigation": "Implement mutual authentication and certificate validation",
                    "cwe_id": "CWE-290",
                },
            },
            # TAMPERING THREATS
            ThreatType.TAMPERING.value: {
                "data_tampering": {
                    "title": "Data Tampering in Transit",
                    "description": "Data can be modified during transmission",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.PROCESS, ComponentType.DATA_STORE],
                    "indicators": ["http", "unencrypted", "plain text"],
                    "mitigation": "Use HTTPS/TLS for all communications and implement data integrity checks",
                    "cwe_id": "CWE-319",
                },
                "sql_injection": {
                    "title": "SQL Injection",
                    "description": "Malicious SQL code can be injected through user input",
                    "severity": Severity.CRITICAL,
                    "applies_to": [ComponentType.DATA_STORE],
                    "indicators": ["sql", "database", "user input", "query"],
                    "mitigation": "Use parameterized queries and input validation",
                    "cwe_id": "CWE-89",
                },
                "input_validation": {
                    "title": "Insufficient Input Validation",
                    "description": "User input is not properly validated before processing",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["user input", "form", "api endpoint", "request"],
                    "mitigation": "Implement comprehensive input validation and sanitization",
                    "cwe_id": "CWE-20",
                },
                "file_upload": {
                    "title": "Malicious File Upload",
                    "description": "Uploaded files can contain malicious content",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.PROCESS, ComponentType.DATA_STORE],
                    "indicators": ["file upload", "attachment", "media"],
                    "mitigation": "Validate file types, scan for malware, and store in isolated location",
                    "cwe_id": "CWE-434",
                },
            },
            # REPUDIATION THREATS
            ThreatType.REPUDIATION.value: {
                "insufficient_logging": {
                    "title": "Insufficient Logging",
                    "description": "Critical actions are not logged, enabling repudiation",
                    "severity": Severity.MEDIUM,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": [
                        "authentication",
                        "authorization",
                        "sensitive operation",
                    ],
                    "mitigation": "Implement comprehensive audit logging for all critical operations",
                    "cwe_id": "CWE-778",
                },
                "log_tampering": {
                    "title": "Log Tampering",
                    "description": "Audit logs can be modified or deleted by unauthorized users",
                    "severity": Severity.MEDIUM,
                    "applies_to": [ComponentType.DATA_STORE],
                    "indicators": ["logs", "audit", "file system"],
                    "mitigation": "Implement tamper-proof logging and log integrity verification",
                    "cwe_id": "CWE-117",
                },
                "non_repudiation": {
                    "title": "Lack of Non-Repudiation",
                    "description": "Users can deny performing actions due to insufficient evidence",
                    "severity": Severity.LOW,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["transaction", "sensitive operation", "user action"],
                    "mitigation": "Implement digital signatures and comprehensive audit trails",
                    "cwe_id": "CWE-807",
                },
            },
            # INFORMATION DISCLOSURE THREATS
            ThreatType.INFORMATION_DISCLOSURE.value: {
                "data_exposure": {
                    "title": "Sensitive Data Exposure",
                    "description": "Sensitive information is exposed to unauthorized parties",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.DATA_STORE, ComponentType.PROCESS],
                    "indicators": [
                        "database",
                        "personal data",
                        "credentials",
                        "api response",
                    ],
                    "mitigation": "Implement encryption at rest and in transit, minimize data exposure",
                    "cwe_id": "CWE-200",
                },
                "information_leakage": {
                    "title": "Information Leakage",
                    "description": "System information is leaked through error messages or responses",
                    "severity": Severity.MEDIUM,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["error handling", "debug", "stack trace"],
                    "mitigation": "Implement generic error messages and proper error handling",
                    "cwe_id": "CWE-209",
                },
                "inadequate_encryption": {
                    "title": "Inadequate Encryption",
                    "description": "Data is stored or transmitted with weak or no encryption",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.DATA_STORE],
                    "indicators": ["storage", "transmission", "sensitive data"],
                    "mitigation": "Use strong encryption algorithms and proper key management",
                    "cwe_id": "CWE-327",
                },
                "directory_traversal": {
                    "title": "Directory Traversal",
                    "description": "Attackers can access files outside intended directories",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["file access", "path parameter", "user input"],
                    "mitigation": "Validate and sanitize file paths, use chroot jails",
                    "cwe_id": "CWE-22",
                },
            },
            # DENIAL OF SERVICE THREATS
            ThreatType.DENIAL_OF_SERVICE.value: {
                "resource_exhaustion": {
                    "title": "Resource Exhaustion",
                    "description": "System resources can be exhausted by malicious requests",
                    "severity": Severity.MEDIUM,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["api endpoint", "computation", "memory", "cpu"],
                    "mitigation": "Implement rate limiting, resource quotas, and proper scaling",
                    "cwe_id": "CWE-400",
                },
                "algorithmic_complexity": {
                    "title": "Algorithmic Complexity Attack",
                    "description": "Expensive operations can be triggered to cause DoS",
                    "severity": Severity.MEDIUM,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["algorithm", "computation", "user input"],
                    "mitigation": "Use efficient algorithms and implement input size limits",
                    "cwe_id": "CWE-407",
                },
                "database_dos": {
                    "title": "Database Denial of Service",
                    "description": "Database can be overwhelmed by expensive queries",
                    "severity": Severity.MEDIUM,
                    "applies_to": [ComponentType.DATA_STORE],
                    "indicators": ["database", "query", "search"],
                    "mitigation": "Implement query optimization, connection pooling, and query timeouts",
                    "cwe_id": "CWE-405",
                },
            },
            # ELEVATION OF PRIVILEGE THREATS
            ThreatType.ELEVATION_OF_PRIVILEGE.value: {
                "privilege_escalation": {
                    "title": "Privilege Escalation",
                    "description": "Users can gain unauthorized elevated privileges",
                    "severity": Severity.CRITICAL,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["authorization", "admin", "elevated access"],
                    "mitigation": "Implement proper authorization checks and principle of least privilege",
                    "cwe_id": "CWE-269",
                },
                "insecure_direct_object_reference": {
                    "title": "Insecure Direct Object Reference",
                    "description": "Direct object references can be manipulated to access unauthorized data",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["object id", "parameter", "authorization"],
                    "mitigation": "Implement proper authorization checks for all object access",
                    "cwe_id": "CWE-639",
                },
                "broken_access_control": {
                    "title": "Broken Access Control",
                    "description": "Access control mechanisms can be bypassed",
                    "severity": Severity.HIGH,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["access control", "authorization", "permission"],
                    "mitigation": "Implement robust access control mechanisms and regular audits",
                    "cwe_id": "CWE-284",
                },
                "command_injection": {
                    "title": "Command Injection",
                    "description": "System commands can be injected through user input",
                    "severity": Severity.CRITICAL,
                    "applies_to": [ComponentType.PROCESS],
                    "indicators": ["system command", "shell", "execution"],
                    "mitigation": "Avoid system calls with user input, use parameterized commands",
                    "cwe_id": "CWE-78",
                },
            },
        }

    def get_threats_for_component(
        self,
        component_name: str,
        component_type: ComponentType,
        context: str | None = None,
    ) -> list[Threat]:
        """Get applicable threats for a component.

        Args:
            component_name: Name of the component
            component_type: Type of the component
            context: Additional context about the component (optional)

        Returns:
            List of applicable Threat objects
        """
        applicable_threats = []
        context_lower = (context or "").lower()
        component_lower = component_name.lower()

        for threat_category, category_threats in self.threats.items():
            for threat_id, threat_data in category_threats.items():
                # Check if threat applies to this component type
                if component_type not in threat_data["applies_to"]:
                    continue

                # Check if indicators match the component or context
                indicators = threat_data.get("indicators", [])
                if self._matches_indicators(component_lower, context_lower, indicators):
                    threat = Threat(
                        threat_type=ThreatType(threat_category),
                        component=component_name,
                        title=threat_data["title"],
                        description=threat_data["description"],
                        severity=threat_data["severity"],
                        mitigation=threat_data.get("mitigation"),
                        cwe_id=threat_data.get("cwe_id"),
                    )
                    applicable_threats.append(threat)

        return applicable_threats

    def _matches_indicators(
        self, component_name: str, context: str, indicators: list[str]
    ) -> bool:
        """Check if component/context matches threat indicators."""
        if not indicators:
            return True  # If no specific indicators, threat applies generally

        search_text = f"{component_name} {context}"
        return any(indicator in search_text for indicator in indicators)

    def get_all_threats_by_type(self, threat_type: ThreatType) -> dict[str, dict]:
        """Get all threats of a specific STRIDE type."""
        return self.threats.get(threat_type.value, {})

    def get_threat_by_id(self, threat_category: str, threat_id: str) -> dict | None:
        """Get a specific threat by category and ID."""
        return self.threats.get(threat_category, {}).get(threat_id)


# Global instance of the threat catalog
STRIDE_THREATS = ThreatCatalog()
