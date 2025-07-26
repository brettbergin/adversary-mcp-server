"""Python AST-based extractor for architectural components."""

import ast

from ..models import ComponentType, ThreatModelComponents
from .base_extractor import BaseExtractor


class PythonExtractor(BaseExtractor):
    """Extractor for Python source code using AST analysis."""

    def __init__(self):
        """Initialize the Python extractor."""
        super().__init__()
        self.current_file = ""
        self.imports = set()
        self.functions = {}
        self.classes = {}

        # Patterns for identifying different types of components
        self.external_api_patterns = {
            "stripe": "Stripe API",
            "requests": "HTTP Client",
            "urllib": "HTTP Client",
            "httpx": "HTTP Client",
            "aiohttp": "HTTP Client",
            "github": "GitHub API",
            "sendgrid": "SendGrid API",
            "twilio": "Twilio API",
            "boto3": "AWS Services",
            "botocore": "AWS Services",
            "google.cloud": "Google Cloud",
            "google-cloud": "Google Cloud",
            "azure": "Azure Services",
            "slack_sdk": "Slack API",
            "slack_bolt": "Slack API",
            "paypalrestsdk": "PayPal API",
            "twitter": "Twitter API",
            "tweepy": "Twitter API",
            "openai": "OpenAI API",
            "anthropic": "Anthropic API",
        }

        # AWS-specific service patterns
        self.aws_service_patterns = {
            "boto3.client('s3')": "AWS S3",
            "boto3.resource('s3')": "AWS S3",
            "boto3.client('dynamodb')": "AWS DynamoDB",
            "boto3.resource('dynamodb')": "AWS DynamoDB",
            "boto3.client('lambda')": "AWS Lambda",
            "boto3.client('sqs')": "AWS SQS",
            "boto3.client('sns')": "AWS SNS",
            "boto3.client('ses')": "AWS SES",
            "boto3.client('secretsmanager')": "AWS Secrets Manager",
            "boto3.client('cognito-idp')": "AWS Cognito",
            "boto3.client('rds')": "AWS RDS",
            "boto3.client('ec2')": "AWS EC2",
            "boto3.client('cloudwatch')": "AWS CloudWatch",
            "boto3.client('kinesis')": "AWS Kinesis",
        }

        self.database_patterns = {
            "sqlalchemy": "SQL Database",
            "django.db": "Django Database",
            "psycopg2": "PostgreSQL",
            "asyncpg": "PostgreSQL",
            "mysql": "MySQL",
            "pymysql": "MySQL",
            "aiomysql": "MySQL",
            "sqlite3": "SQLite",
            "aiosqlite": "SQLite",
            "pymongo": "MongoDB",
            "motor": "MongoDB",
            "redis": "Redis",
            "aioredis": "Redis",
            "cassandra": "Cassandra",
            "elasticsearch": "Elasticsearch",
            "influxdb": "InfluxDB",
            "neo4j": "Neo4j",
            "pyarango": "ArangoDB",
            "peewee": "SQL Database",
            "tortoise": "SQL Database",
            "dynamodb": "DynamoDB",
            "boto3.dynamodb": "DynamoDB",
        }

        self.web_framework_patterns = {
            "flask": "Flask App",
            "django": "Django App",
            "fastapi": "FastAPI App",
            "tornado": "Tornado App",
            "bottle": "Bottle App",
            "pyramid": "Pyramid App",
            "aiohttp": "AIOHTTP App",
            "sanic": "Sanic App",
            "starlette": "Starlette App",
            "quart": "Quart App",
            "falcon": "Falcon App",
            "cherrypy": "CherryPy App",
        }

        # HTTP client patterns
        self.http_client_patterns = {
            "requests": "Requests HTTP Client",
            "httpx": "HTTPX HTTP Client",
            "aiohttp": "AIOHTTP Client",
            "urllib": "URLLib HTTP Client",
            "urllib3": "URLLib3 HTTP Client",
        }

    def get_supported_extensions(self) -> set[str]:
        """Get Python file extensions."""
        return {".py", ".pyw", ".pyx"}

    def extract_components(self, code: str, file_path: str) -> ThreatModelComponents:
        """Extract components from Python source code."""
        self.reset()
        self.current_file = file_path

        try:
            tree = ast.parse(code)
            self._analyze_ast(tree)

            # Also analyze AWS service usage from code patterns
            self._extract_aws_services(code)

            self._post_process_components()
            return self.components
        except SyntaxError:
            # Return empty components for invalid Python
            return self.components

    def _analyze_ast(self, tree: ast.AST):
        """Analyze the AST to extract components."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._handle_import(node)
            elif isinstance(node, ast.ImportFrom):
                self._handle_import_from(node)
            elif isinstance(node, ast.FunctionDef):
                self._handle_function_def(node)
            elif isinstance(node, ast.ClassDef):
                self._handle_class_def(node)
            elif isinstance(node, ast.Call):
                self._handle_function_call(node)
            elif isinstance(node, ast.Assign):
                self._handle_assignment(node)

    def _handle_import(self, node: ast.Import):
        """Handle import statements."""
        for alias in node.names:
            self.imports.add(alias.name)
            self._check_external_dependency(alias.name)

    def _handle_import_from(self, node: ast.ImportFrom):
        """Handle from...import statements."""
        if node.module:
            self.imports.add(node.module)
            self._check_external_dependency(node.module)

            # Check for web framework decorators
            if node.module in ["flask", "django.http", "fastapi"]:
                for alias in node.names:
                    if alias.name in ["app", "route", "api_view", "APIRouter"]:
                        self._add_web_process()

    def _handle_function_def(self, node: ast.FunctionDef):
        """Handle function definitions."""
        self.functions[node.name] = node

        # Check for web framework decorators
        for decorator in node.decorator_list:
            self._check_web_decorator(decorator, node.name)

        # Analyze function body for data flows
        self._analyze_function_body(node)

    def _handle_class_def(self, node: ast.ClassDef):
        """Handle class definitions."""
        self.classes[node.name] = node

        # Check for database models
        if self._is_database_model(node):
            model_name = f"{node.name} Model"
            self.components.add_component(
                model_name,
                ComponentType.DATA_STORE,
                description=f"Database model for {node.name}",
            )

    def _handle_function_call(self, node: ast.Call):
        """Handle function calls to identify data flows."""
        if isinstance(node.func, ast.Attribute):
            self._handle_method_call(node)
        elif isinstance(node.func, ast.Name):
            self._handle_function_call_by_name(node)

        # Also check all function calls for URLs to extract external entities
        self._extract_external_entities_from_call(node)

    def _handle_assignment(self, node: ast.Assign):
        """Handle variable assignments."""
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id

            # Check for database connections
            if isinstance(node.value, ast.Call):
                self._check_database_connection(node.value, var_name)

    def _check_external_dependency(self, module_name: str):
        """Check if module represents an external dependency."""
        # Check for external API patterns
        for pattern, entity_name in self.external_api_patterns.items():
            if pattern in module_name.lower():
                if entity_name not in self.components.external_entities:
                    self.components.add_component(
                        entity_name,
                        ComponentType.EXTERNAL_ENTITY,
                        description=f"External service: {module_name}",
                    )
                    self._add_process_to_external_flow(entity_name)
                return

        # Check for database dependencies
        for pattern, db_name in self.database_patterns.items():
            if pattern in module_name.lower():
                # Special handling for DynamoDB - could be data store
                if "dynamodb" in pattern.lower():
                    if db_name not in self.components.data_stores:
                        self.components.add_component(
                            db_name,
                            ComponentType.DATA_STORE,
                            description=f"NoSQL Database: {module_name}",
                        )
                else:
                    if db_name not in self.components.data_stores:
                        self.components.add_component(
                            db_name,
                            ComponentType.DATA_STORE,
                            description=f"Database: {module_name}",
                        )
                return

        # Check for web frameworks
        for pattern, framework_name in self.web_framework_patterns.items():
            if pattern in module_name.lower():
                if framework_name not in self.components.processes:
                    self.components.add_component(
                        framework_name,
                        ComponentType.PROCESS,
                        description=f"Web framework: {module_name}",
                        exposed=True,
                    )
                return

    def _check_web_decorator(self, decorator, function_name: str):
        """Check if decorator indicates a web endpoint."""
        decorator_name = ""

        if isinstance(decorator, ast.Name):
            decorator_name = decorator.id
        elif isinstance(decorator, ast.Attribute):
            if isinstance(decorator.value, ast.Name):
                decorator_name = f"{decorator.value.id}.{decorator.attr}"
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                if isinstance(decorator.func.value, ast.Name):
                    decorator_name = f"{decorator.func.value.id}.{decorator.func.attr}"

        # Check for web framework decorators
        web_decorators = [
            "app.route",
            "route",
            "api_view",
            "post",
            "get",
            "put",
            "delete",
        ]
        if any(wd in decorator_name.lower() for wd in web_decorators):
            process_name = self._get_web_process_name()
            if process_name not in self.components.processes:
                self.components.add_component(
                    process_name,
                    ComponentType.PROCESS,
                    description="Web application endpoint",
                    exposed=True,
                )

            # Add data flow from external user
            self._add_data_flow_if_new("Web User", process_name, "HTTPS")

    def _analyze_function_body(self, node: ast.FunctionDef):
        """Analyze function body for data flows and operations."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                self._analyze_function_call_in_context(stmt, node.name)

    def _analyze_function_call_in_context(self, call: ast.Call, function_name: str):
        """Analyze function calls within a specific function context."""
        if isinstance(call.func, ast.Attribute):
            attr_name = call.func.attr

            # Database operations
            if attr_name in [
                "query",
                "filter",
                "get",
                "create",
                "save",
                "delete",
                "execute",
            ]:
                db_name = self._infer_database_from_context(call)
                if db_name:
                    process_name = self._get_process_name_from_function(function_name)
                    self._add_data_flow_if_new(process_name, db_name, "SQL")

            # HTTP requests
            elif attr_name in ["get", "post", "put", "delete", "request"]:
                if self._is_http_call(call):
                    external_entity = self._extract_external_entity_from_call(call)
                    if external_entity:
                        process_name = self._get_process_name_from_function(
                            function_name
                        )
                        protocol = "HTTPS" if self._is_secure_call(call) else "HTTP"
                        self._add_data_flow_if_new(
                            process_name, external_entity, protocol
                        )

        # Also check for function calls by name (like urlopen)
        elif isinstance(call.func, ast.Name):
            func_name = call.func.id
            if func_name == "urlopen":
                external_entity = self._extract_external_entity_from_call(call)
                if external_entity:
                    process_name = self._get_process_name_from_function(function_name)
                    protocol = "HTTPS" if self._is_secure_call(call) else "HTTP"
                    self._add_data_flow_if_new(process_name, external_entity, protocol)

    def _handle_method_call(self, node: ast.Call):
        """Handle method calls on objects."""
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr

            # Database method calls
            if method_name in ["query", "filter", "get", "create", "save", "delete"]:
                db_name = self._infer_database_from_context(node)
                if db_name and db_name not in self.components.data_stores:
                    self.components.add_component(
                        db_name,
                        ComponentType.DATA_STORE,
                        description="Database accessed via ORM",
                    )

    def _handle_function_call_by_name(self, node: ast.Call):
        """Handle function calls by name."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Built-in functions that indicate file operations
            if func_name == "open":
                self._handle_file_operation(node)

    def _handle_file_operation(self, node: ast.Call):
        """Handle file operations."""
        file_store_name = "File System"
        if file_store_name not in self.components.data_stores:
            self.components.add_component(
                file_store_name,
                ComponentType.DATA_STORE,
                description="Local file system storage",
            )

    def _check_database_connection(self, call_node: ast.Call, var_name: str):
        """Check if call creates a database connection."""
        if isinstance(call_node.func, ast.Attribute):
            if call_node.func.attr in ["connect", "create_engine", "MongoClient"]:
                # Extract database type from the call
                db_type = self._infer_database_type_from_call(call_node)
                if db_type and db_type not in self.components.data_stores:
                    self.components.add_component(
                        db_type,
                        ComponentType.DATA_STORE,
                        description=f"Database connection via {var_name}",
                    )

    def _is_database_model(self, class_node: ast.ClassDef) -> bool:
        """Check if class is a database model."""
        for base in class_node.bases:
            if isinstance(base, ast.Attribute):
                if base.attr in ["Model", "Document", "Base"]:
                    return True
            elif isinstance(base, ast.Name):
                if base.id in ["Model", "Document", "Base"]:
                    return True
        return False

    def _add_web_process(self):
        """Add a web application process."""
        process_name = self._get_web_process_name()
        if process_name not in self.components.processes:
            self.components.add_component(
                process_name,
                ComponentType.PROCESS,
                description="Web application server",
                exposed=True,
            )

    def _get_web_process_name(self) -> str:
        """Get the name for the web process based on imports."""
        for framework, name in self.web_framework_patterns.items():
            if any(framework in imp for imp in self.imports):
                return name
        return "Web Application"

    def _get_process_name_from_function(self, function_name: str) -> str:
        """Get process name based on function context."""
        # If it's a web function, return web process name
        if any(
            framework in imp
            for imp in self.imports
            for framework in self.web_framework_patterns.keys()
        ):
            return self._get_web_process_name()

        # Otherwise, create a generic process name
        return "Application Process"

    def _infer_database_from_context(self, call: ast.Call) -> str | None:
        """Infer database name from call context."""
        # Check imports for database type
        for imp in self.imports:
            for pattern, db_name in self.database_patterns.items():
                if pattern in imp:
                    return db_name

        # Default database name
        return "Database"

    def _infer_database_type_from_call(self, call: ast.Call) -> str | None:
        """Infer database type from connection call."""
        if isinstance(call.func, ast.Attribute):
            attr_name = call.func.attr

            if attr_name == "create_engine":
                return "SQL Database"
            elif attr_name == "MongoClient":
                return "MongoDB"
            elif attr_name == "Redis":
                return "Redis"
            elif attr_name == "connect":
                # Check the module
                if isinstance(call.func.value, ast.Name):
                    module = call.func.value.id
                    if "psycopg2" in module:
                        return "PostgreSQL"
                    elif "mysql" in module:
                        return "MySQL"
                    elif "sqlite" in module:
                        return "SQLite"

        return None

    def _is_http_call(self, call: ast.Call) -> bool:
        """Check if call is an HTTP request."""
        if isinstance(call.func, ast.Attribute):
            obj_name = ""
            if isinstance(call.func.value, ast.Name):
                obj_name = call.func.value.id

            # Check for common HTTP libraries
            return obj_name in ["requests", "httpx", "urllib", "aiohttp"] or any(
                lib in imp
                for lib in ["requests", "httpx", "aiohttp", "urllib"]
                for imp in self.imports
            )
        return False

    def _is_secure_call(self, call: ast.Call) -> bool:
        """Check if HTTP call uses HTTPS."""
        # Check arguments for URL
        for arg in call.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.startswith("https://"):
                    return True
        return False

    def _extract_external_entity_from_call(self, call: ast.Call) -> str | None:
        """Extract external entity from HTTP call."""
        # Check arguments for URL
        for arg in call.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                url = arg.value
                entity = self._extract_external_entity_from_url(url)
                if entity:
                    # Add the entity to components if not already present
                    if entity not in self.components.external_entities:
                        self.components.add_component(
                            entity,
                            ComponentType.EXTERNAL_ENTITY,
                            description=f"External API service from URL: {url}",
                        )
                    return entity

        # Check for known API patterns in imports
        for imp in self.imports:
            for pattern, entity_name in self.external_api_patterns.items():
                if pattern in imp:
                    return entity_name

        return "External API"

    def _extract_external_entities_from_call(self, call: ast.Call):
        """Extract external entities from any function call that contains URLs."""
        # Check arguments for URL strings
        for arg in call.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                url = arg.value
                if url.startswith(("http://", "https://")):
                    entity = self._extract_external_entity_from_url(url)
                    if entity and entity not in self.components.external_entities:
                        self.components.add_component(
                            entity,
                            ComponentType.EXTERNAL_ENTITY,
                            description=f"External API service from URL: {url}",
                        )

                        # Also add data flow if in function context
                        process_name = self._get_main_process_name()
                        if process_name not in self.components.processes:
                            self.components.add_component(
                                process_name,
                                ComponentType.PROCESS,
                                description="Application process",
                            )
                        protocol = "HTTPS" if url.startswith("https://") else "HTTP"
                        self._add_data_flow_if_new(process_name, entity, protocol)

    def _extract_aws_services(self, code: str):
        """Extract AWS service usage from code patterns."""
        import re

        # AWS service client patterns
        aws_client_patterns = [
            (r"boto3\.client\s*\(\s*['\"]s3['\"]\)", "AWS S3"),
            (r"boto3\.resource\s*\(\s*['\"]s3['\"]\)", "AWS S3"),
            (r"boto3\.client\s*\(\s*['\"]dynamodb['\"]\)", "AWS DynamoDB"),
            (r"boto3\.resource\s*\(\s*['\"]dynamodb['\"]\)", "AWS DynamoDB"),
            (r"boto3\.client\s*\(\s*['\"]lambda['\"]\)", "AWS Lambda"),
            (r"boto3\.client\s*\(\s*['\"]sqs['\"]\)", "AWS SQS"),
            (r"boto3\.client\s*\(\s*['\"]sns['\"]\)", "AWS SNS"),
            (r"boto3\.client\s*\(\s*['\"]ses['\"]\)", "AWS SES"),
            (r"boto3\.client\s*\(\s*['\"]secretsmanager['\"]\)", "AWS Secrets Manager"),
            (r"boto3\.client\s*\(\s*['\"]cognito-idp['\"]\)", "AWS Cognito"),
            (r"boto3\.client\s*\(\s*['\"]rds['\"]\)", "AWS RDS"),
            (r"boto3\.client\s*\(\s*['\"]ec2['\"]\)", "AWS EC2"),
            (r"boto3\.client\s*\(\s*['\"]cloudwatch['\"]\)", "AWS CloudWatch"),
            (r"boto3\.client\s*\(\s*['\"]kinesis['\"]\)", "AWS Kinesis"),
        ]

        for pattern, service_name in aws_client_patterns:
            if re.search(pattern, code):
                if service_name == "AWS DynamoDB":
                    # DynamoDB can be a data store
                    if service_name not in self.components.data_stores:
                        self.components.add_component(
                            service_name,
                            ComponentType.DATA_STORE,
                            description=f"{service_name} NoSQL database",
                        )
                        self._add_process_to_database_flow(service_name)
                else:
                    # Other AWS services are external entities
                    if service_name not in self.components.external_entities:
                        self.components.add_component(
                            service_name,
                            ComponentType.EXTERNAL_ENTITY,
                            description=f"{service_name} cloud service",
                        )
                        self._add_process_to_external_flow(service_name)

    def _add_process_to_database_flow(self, db_name: str):
        """Add data flow from process to database."""
        process_name = self._get_main_process_name()
        if process_name not in self.components.processes:
            self.components.add_component(
                process_name,
                ComponentType.PROCESS,
                description="Application process",
            )
        protocol = "HTTPS" if "AWS" in db_name else "SQL"
        self._add_data_flow_if_new(process_name, db_name, protocol)

    def _add_process_to_external_flow(self, external_entity: str):
        """Add data flow from process to external entity."""
        process_name = self._get_main_process_name()
        if process_name not in self.components.processes:
            self.components.add_component(
                process_name,
                ComponentType.PROCESS,
                description="Application process",
            )
        self._add_data_flow_if_new(process_name, external_entity, "HTTPS")

    def _get_main_process_name(self) -> str:
        """Get the main process name."""
        # Check if it's a web application
        for framework in self.web_framework_patterns.keys():
            if any(framework in imp for imp in self.imports):
                return self._get_web_process_name()

        # Otherwise return generic Python app
        return "Python Application"
