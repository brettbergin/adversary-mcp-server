"""Base extractor interface for analyzing source code and extracting architectural components."""

import re
from abc import ABC, abstractmethod
from pathlib import Path

from ..models import ComponentType, ThreatModelComponents


class BaseExtractor(ABC):
    """Abstract base class for language-specific code extractors."""

    def __init__(self):
        """Initialize the extractor."""
        self.reset()

    def reset(self):
        """Reset the extractor state."""
        self.components = ThreatModelComponents()
        self._seen_flows = set()  # Track flows to avoid duplicates

    @abstractmethod
    def extract_components(self, code: str, file_path: str) -> ThreatModelComponents:
        """Extract architectural components from source code.

        Args:
            code: Source code content
            file_path: Path to the source file

        Returns:
            ThreatModelComponents containing extracted architecture
        """
        pass

    @abstractmethod
    def get_supported_extensions(self) -> set[str]:
        """Get file extensions supported by this extractor.

        Returns:
            Set of supported file extensions (e.g., {'.py', '.pyw'})
        """
        pass

    def can_extract(self, file_path: str) -> bool:
        """Check if this extractor can handle the given file.

        Args:
            file_path: Path to the source file

        Returns:
            True if this extractor supports the file
        """
        path = Path(file_path)
        return path.suffix.lower() in self.get_supported_extensions()

    def extract_from_directory(self, directory_path: str) -> ThreatModelComponents:
        """Extract components from all supported files in a directory.

        Args:
            directory_path: Path to directory to analyze

        Returns:
            Combined ThreatModelComponents from all files
        """
        self.reset()
        directory = Path(directory_path)

        if not directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory_path}")

        # Find all supported files
        supported_files = []
        for ext in self.get_supported_extensions():
            supported_files.extend(directory.rglob(f"*{ext}"))

        # Process each file
        for file_path in supported_files:
            try:
                with open(file_path, encoding="utf-8") as f:
                    code = f.read()
                file_components = self.extract_components(code, str(file_path))
                self._merge_components(file_components)
            except (OSError, UnicodeDecodeError) as e:
                # Skip files that can't be read
                continue

        return self.components

    def _merge_components(self, other: ThreatModelComponents):
        """Merge components from another ThreatModelComponents instance."""
        # Merge lists, avoiding duplicates
        for boundary in other.boundaries:
            if boundary not in self.components.boundaries:
                self.components.boundaries.append(boundary)

        for entity in other.external_entities:
            if entity not in self.components.external_entities:
                self.components.external_entities.append(entity)

        for process in other.processes:
            if process not in self.components.processes:
                self.components.processes.append(process)

        for store in other.data_stores:
            if store not in self.components.data_stores:
                self.components.data_stores.append(store)

        # Merge data flows, avoiding duplicates
        for flow in other.data_flows:
            flow_key = (flow.source, flow.target, flow.protocol)
            if flow_key not in self._seen_flows:
                self.components.data_flows.append(flow)
                self._seen_flows.add(flow_key)

        # Merge components
        for component in other.components:
            # Check if component already exists
            existing = next(
                (c for c in self.components.components if c.name == component.name),
                None,
            )
            if not existing:
                self.components.components.append(component)

    def _add_data_flow_if_new(self, source: str, target: str, protocol: str, **kwargs):
        """Add a data flow if it doesn't already exist."""
        flow_key = (source, target, protocol)
        if flow_key not in self._seen_flows:
            self.components.add_data_flow(source, target, protocol, **kwargs)
            self._seen_flows.add(flow_key)

    def _infer_protocol_from_context(self, context: str) -> str:
        """Infer protocol from code context."""
        context_lower = context.lower()

        # HTTP/HTTPS patterns
        if any(
            pattern in context_lower
            for pattern in [
                "http://",
                "https://",
                "fetch(",
                "requests.",
                "urllib",
                "axios",
            ]
        ):
            if "https://" in context_lower or "ssl" in context_lower:
                return "HTTPS"
            return "HTTP"

        # Database patterns
        if any(
            pattern in context_lower
            for pattern in ["select ", "insert ", "update ", "delete ", "sql"]
        ):
            return "SQL"

        # MongoDB patterns
        if any(
            pattern in context_lower
            for pattern in ["mongodb://", "find(", "insert_one", "collection"]
        ):
            return "MongoDB Protocol"

        # Redis patterns
        if any(
            pattern in context_lower
            for pattern in ["redis://", "hget", "hset", "lpush"]
        ):
            return "Redis Protocol"

        # gRPC patterns
        if any(pattern in context_lower for pattern in ["grpc", ".proto", "stub"]):
            return "gRPC"

        # WebSocket patterns
        if any(
            pattern in context_lower for pattern in ["websocket", "ws://", "wss://"]
        ):
            return "WebSocket"

        # File system
        if any(
            pattern in context_lower for pattern in ["open(", "file", "read", "write"]
        ):
            return "File System"

        return "Unknown"

    def _extract_external_entity_from_url(self, url: str) -> str | None:
        """Extract external entity name from URL."""
        # Remove protocol
        url_clean = re.sub(r"^https?://", "", url)

        # Extract domain
        domain_match = re.match(r"^([^/]+)", url_clean)
        if domain_match:
            domain = domain_match.group(1)

            # Convert to friendly name
            if "api.stripe.com" in domain:
                return "Stripe API"
            elif "api.github.com" in domain:
                return "GitHub API"
            elif "api.sendgrid.com" in domain:
                return "SendGrid API"
            elif "api.twilio.com" in domain:
                return "Twilio API"
            elif "googleapis.com" in domain:
                return "Google APIs"
            elif "amazonaws.com" in domain:
                return "AWS Services"
            else:
                # Generic external API - sanitize domain name
                clean_domain = domain.replace("api.", "").replace("www.", "")
                # Replace dots and special chars with spaces, then title case
                clean_name = re.sub(r"[^a-zA-Z0-9]", " ", clean_domain).title()
                # Normalize whitespace
                clean_name = re.sub(r"\s+", " ", clean_name.strip())
                return f"{clean_name} API"

        return None

    def _identify_trust_boundaries(self) -> list[str]:
        """Identify trust boundaries based on extracted components."""
        boundaries = set()

        # Standard boundaries
        if self.components.external_entities:
            boundaries.add("Internet")

        if self.components.processes:
            boundaries.add("Application")

        if self.components.data_stores:
            boundaries.add("Data Layer")

        # Infer additional boundaries based on component names
        for component_name in (
            self.components.processes
            + self.components.data_stores
            + self.components.external_entities
        ):
            name_lower = component_name.lower()

            if any(keyword in name_lower for keyword in ["api", "gateway", "proxy"]):
                boundaries.add("DMZ")

            if any(
                keyword in name_lower for keyword in ["admin", "internal", "private"]
            ):
                boundaries.add("Internal")

            if any(keyword in name_lower for keyword in ["public", "cdn", "static"]):
                boundaries.add("Public")

        return sorted(boundaries)

    def _post_process_components(self):
        """Post-process extracted components to add inferred data."""
        # Add trust boundaries
        self.components.boundaries = self._identify_trust_boundaries()

        # Consolidate similar external entities to reduce over-extraction
        self._consolidate_external_entities()

        # Add missing essential data flows for web applications
        self._add_essential_web_flows()

        # Add bidirectional flows where appropriate
        self._add_bidirectional_flows()

        # Sort all lists for consistent output
        self.components.boundaries.sort()
        self.components.external_entities.sort()
        self.components.processes.sort()
        self.components.data_stores.sort()

        # Sort data flows by source, then target
        self.components.data_flows.sort(key=lambda f: (f.source, f.target))

    def _consolidate_external_entities(self):
        """Consolidate similar external entities to reduce over-extraction."""
        # Group similar API entities
        consolidated_entities = []
        consolidated_flows = []
        entity_groups = {}

        # Group entities by type
        for entity in self.components.external_entities:
            # Determine entity group
            group_key = self._get_entity_group(entity)
            if group_key not in entity_groups:
                entity_groups[group_key] = []
            entity_groups[group_key].append(entity)

        # Keep only one representative per group (unless group has special handling)
        for group_key, entities in entity_groups.items():
            if group_key == "Generic API" and len(entities) > 5:
                # For generic APIs, keep only the first few and group the rest
                consolidated_entities.extend(entities[:3])
                if len(entities) > 3:
                    consolidated_entities.append("External APIs")
                    # Update flows to point to consolidated entity
                    self._update_flows_for_consolidated_entity(
                        entities[3:], "External APIs"
                    )
            else:
                # Keep all entities in specialized groups
                consolidated_entities.extend(entities)

        self.components.external_entities = consolidated_entities

    def _get_entity_group(self, entity: str) -> str:
        """Get the group classification for an external entity."""
        entity_lower = entity.lower()

        # Payment and financial services
        if any(
            term in entity_lower for term in ["stripe", "paypal", "square", "payment"]
        ):
            return "Payment Services"

        # Communication services
        if any(term in entity_lower for term in ["twilio", "sendgrid", "mail", "sms"]):
            return "Communication Services"

        # Cloud services
        if any(term in entity_lower for term in ["aws", "google", "azure", "cloud"]):
            return "Cloud Services"

        # Authentication services
        if any(term in entity_lower for term in ["auth", "oauth", "sso", "login"]):
            return "Authentication Services"

        # Development services
        if any(
            term in entity_lower for term in ["github", "gitlab", "bitbucket", "git"]
        ):
            return "Development Services"

        # Generic or unknown APIs
        return "Generic API"

    def _update_flows_for_consolidated_entity(
        self, old_entities: list[str], new_entity: str
    ):
        """Update data flows to point to consolidated entity."""
        for flow in self.components.data_flows:
            if flow.target in old_entities:
                flow.target = new_entity
            elif flow.source in old_entities:
                flow.source = new_entity

    def _add_essential_web_flows(self):
        """Add essential data flows for web applications that are often missing."""
        # Check if this is a web application
        web_processes = []
        for process in self.components.processes:
            if any(
                term in process.lower()
                for term in [
                    "app",
                    "web",
                    "server",
                    "django",
                    "flask",
                    "fastapi",
                    "express",
                ]
            ):
                web_processes.append(process)

        if not web_processes:
            return

        # Add Web User entity if not present
        if "Web User" not in self.components.external_entities:
            self.components.add_component(
                "Web User",
                ComponentType.EXTERNAL_ENTITY,
                description="End users accessing the web application",
            )

        # Add flows from Web User to web processes
        for process in web_processes:
            self._add_data_flow_if_new(
                "Web User",
                process,
                "HTTPS",
                data_type="user_requests",
                authentication="session_based",
            )

        # Add flows between processes and databases if missing
        databases = [
            store
            for store in self.components.data_stores
            if any(
                term in store.lower()
                for term in ["database", "db", "mysql", "postgres", "sqlite"]
            )
        ]

        for process in web_processes:
            for database in databases:
                # Check if flow already exists
                existing_flow = any(
                    flow.source == process and flow.target == database
                    for flow in self.components.data_flows
                )
                if not existing_flow:
                    self._add_data_flow_if_new(
                        process,
                        database,
                        "SQL",
                        data_type="queries",
                        authentication="connection_pool",
                    )

    def _add_bidirectional_flows(self):
        """Add bidirectional flows where appropriate (e.g., API responses)."""
        current_flows = list(self.components.data_flows)

        for flow in current_flows:
            # Add return flows for HTTP/HTTPS requests
            if flow.protocol in ["HTTP", "HTTPS"]:
                # Check if reverse flow already exists
                reverse_exists = any(
                    existing_flow.source == flow.target
                    and existing_flow.target == flow.source
                    for existing_flow in self.components.data_flows
                )

                if not reverse_exists:
                    self._add_data_flow_if_new(
                        flow.target,
                        flow.source,
                        flow.protocol,
                        data_type="responses",
                        authentication=flow.authentication,
                        encryption=flow.encryption,
                    )

            # Add return flows for database queries (result sets)
            elif flow.protocol == "SQL":
                reverse_exists = any(
                    existing_flow.source == flow.target
                    and existing_flow.target == flow.source
                    for existing_flow in self.components.data_flows
                )

                if not reverse_exists:
                    self._add_data_flow_if_new(
                        flow.target,
                        flow.source,
                        "SQL",
                        data_type="result_sets",
                        authentication=flow.authentication,
                        encryption=flow.encryption,
                    )
