"""JavaScript/TypeScript AST-based extractor for architectural components."""

import re
from typing import Any

try:
    import tree_sitter_typescript as ts_typescript
    from tree_sitter import Language, Node, Parser

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    raise ImportError(
        "tree-sitter-typescript is required for JavaScript/TypeScript extraction"
    )

from ..models import ComponentType, ThreatModelComponents
from .base_extractor import BaseExtractor


class JavaScriptExtractor(BaseExtractor):
    """AST-based extractor for JavaScript and TypeScript source code using tree-sitter."""

    def __init__(self):
        """Initialize the JavaScript/TypeScript extractor."""
        self.current_file = ""
        self.parser = None
        self.language = None

        # AST node storage for analysis
        self.imports: set[str] = set()
        self.classes: list[dict[str, Any]] = []
        self.decorators: list[dict[str, Any]] = []
        self.methods: list[dict[str, Any]] = []
        self.functions: set[str] = set()
        self.exports: set[str] = set()

        # NestJS-specific storage (for compatibility with tests)
        self.controllers: list[dict[str, Any]] = []
        self.routes: list[dict[str, Any]] = []
        self.guards: list[dict[str, Any]] = []
        self.interceptors: list[dict[str, Any]] = []
        self.dtos: list[dict[str, Any]] = []

        # Legacy compatibility
        self.nestjs_routes = []
        self.nestjs_controllers = []
        self.nestjs_guards = []
        self.nestjs_interceptors = []

        # Call super().__init__() after attributes are initialized
        super().__init__()

        # Initialize tree-sitter parser
        if TREE_SITTER_AVAILABLE:
            try:
                self.language = Language(ts_typescript.language_typescript())
                self.parser = Parser(self.language)
            except Exception as e:
                raise RuntimeError(f"Failed to initialize TypeScript parser: {e}")

        # Patterns for identifying different types of components
        self.external_api_patterns = {
            "stripe": "Stripe API",
            "twilio": "Twilio API",
            "sendgrid": "SendGrid API",
            "aws-sdk": "AWS Services",
            "@aws-sdk": "AWS Services",
            "@google-cloud": "Google Cloud",
            "@azure": "Azure Services",
            "github": "GitHub API",
            "octokit": "GitHub API",
            "mailgun": "Mailgun API",
            "paypal": "PayPal API",
            "slack": "Slack API",
            "twitter": "Twitter API",
            # Fintech and Financial Services APIs
            "fiserv": "Fiserv API",
            "@fiserv": "Fiserv API",
            "vgs": "VGS (Very Good Security)",
            "@vgs": "VGS (Very Good Security)",
            "vgs-api": "VGS (Very Good Security)",
            "plaid": "Plaid API",
            "@plaid": "Plaid API",
            "dwolla": "Dwolla API",
            "@dwolla": "Dwolla API",
            "adyen": "Adyen API",
            "@adyen": "Adyen API",
            "square": "Square API",
            "@square": "Square API",
            "braintree": "Braintree API",
            "@braintree": "Braintree API",
            "marqeta": "Marqeta API",
            "@marqeta": "Marqeta API",
            "circle": "Circle API",
            "@circle-fin": "Circle API",
            "circle-api": "Circle API",
            "coinbase": "Coinbase API",
            "@coinbase": "Coinbase API",
            "klarna": "Klarna API",
            "@klarna": "Klarna API",
            "affirm": "Affirm API",
            "@affirm": "Affirm API",
            "afterpay": "Afterpay API",
            "@afterpay": "Afterpay API",
            "alpaca": "Alpaca Trading API",
            "@alpacahq": "Alpaca Trading API",
            "yodlee": "Yodlee API",
            "@yodlee": "Yodlee API",
            "mx": "MX API",
            "@mx-platform": "MX API",
            "finicity": "Finicity API",
            "@finicity": "Finicity API",
            "truelayer": "TrueLayer API",
            "@truelayer": "TrueLayer API",
            "tink": "Tink API",
            "@tink": "Tink API",
            "zelle": "Zelle API",
            "@zelle": "Zelle API",
            "wise": "Wise API",
            "@wise": "Wise API",
            "transferwise": "Wise API",
            "railsbank": "Railsbank API",
            "@railsbank": "Railsbank API",
            "solarisbank": "Solarisbank API",
            "@solarisbank": "Solarisbank API",
            "unit": "Unit API",
            "@unit-finance": "Unit API",
            "treasury-prime": "Treasury Prime API",
            "@treasury-prime": "Treasury Prime API",
        }

        # AWS-specific service patterns
        self.aws_service_patterns = {
            "@aws-sdk/client-s3": "AWS S3",
            "@aws-sdk/client-lambda": "AWS Lambda",
            "@aws-sdk/client-sqs": "AWS SQS",
            "@aws-sdk/client-sns": "AWS SNS",
            "@aws-sdk/client-rds": "AWS RDS",
            "@aws-sdk/client-ec2": "AWS EC2",
            "@aws-sdk/client-secrets-manager": "AWS Secrets Manager",
            "@aws-sdk/client-cloudwatch": "AWS CloudWatch",
            "@aws-sdk/client-cognito": "AWS Cognito",
            "@aws-sdk/client-kinesis": "AWS Kinesis",
            "@aws-sdk/client-ses": "AWS SES",
            "@aws-sdk/client-cloudformation": "AWS CloudFormation",
            "@aws-sdk/client-apigateway": "AWS API Gateway",
        }

        self.database_patterns = {
            "sequelize": "SQL Database",
            "typeorm": "SQL Database",
            "knex": "SQL Database",
            "mongodb": "MongoDB",
            "mongoose": "MongoDB",
            "redis": "Redis",
            "ioredis": "Redis",
            "elasticsearch": "Elasticsearch",
            "@elastic/elasticsearch": "Elasticsearch",
            "cassandra-driver": "Cassandra",
            "pg": "PostgreSQL",
            "mysql": "MySQL",
            "mysql2": "MySQL",
            "sqlite3": "SQLite",
            "better-sqlite3": "SQLite",
            "prisma": "Prisma ORM",
            "@prisma/client": "Prisma ORM",
            "electrodb": "DynamoDB",
            "dynamodb": "DynamoDB",
            "@aws-sdk/client-dynamodb": "DynamoDB",
            "@aws-sdk/lib-dynamodb": "DynamoDB",
        }

        self.web_framework_patterns = {
            "express": "Express App",
            "fastify": "Fastify App",
            "koa": "Koa App",
            "@nestjs": "NestJS App",
            "hapi": "Hapi App",
            "restify": "Restify App",
            "next": "Next.js App",
            "nuxt": "Nuxt.js App",
            "gatsby": "Gatsby App",
        }

        # HTTP client patterns
        self.http_client_patterns = {
            "axios": "Axios HTTP Client",
            "node-fetch": "Fetch HTTP Client",
            "got": "Got HTTP Client",
            "request": "Request HTTP Client",
            "superagent": "SuperAgent HTTP Client",
        }

    def reset(self):
        """Reset the extractor state."""
        super().reset()
        self.imports.clear()
        self.classes.clear()
        self.decorators.clear()
        self.methods.clear()
        self.functions.clear()
        self.exports.clear()
        self.controllers.clear()
        self.routes.clear()
        self.guards.clear()
        self.interceptors.clear()
        self.dtos.clear()

        # Legacy compatibility
        self.nestjs_routes = []
        self.nestjs_controllers = []
        self.nestjs_guards = []
        self.nestjs_interceptors = []

    def get_supported_extensions(self) -> set[str]:
        """Get JavaScript/TypeScript file extensions."""
        return {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}

    def extract_components(self, code: str, file_path: str) -> ThreatModelComponents:
        """Extract components from JavaScript/TypeScript source code using AST analysis."""
        self.reset()
        self.current_file = file_path

        if not self.parser:
            raise RuntimeError("TypeScript parser not initialized")

        # Parse code to AST
        tree = self.parser.parse(code.encode("utf-8"))
        root_node = tree.root_node

        # Extract components from AST
        self._traverse_ast(root_node, code)

        # Classify all extracted classes (after all decorators are collected)
        for class_info in self.classes:
            self._classify_class(class_info)

        # Process extracted data into threat model components
        self._process_components(code)

        # Update legacy attributes for compatibility
        self._update_legacy_attributes()

        return self.components

    def _traverse_ast(self, node: Node, code: str):
        """Recursively traverse the AST to extract relevant information."""
        # Extract imports
        if node.type == "import_statement":
            self._extract_import_from_node(node, code)

        # Extract requires (CommonJS)
        elif node.type == "lexical_declaration" or node.type == "variable_declaration":
            self._extract_require_from_node(node, code)

        # Extract class declarations
        elif node.type == "class_declaration":
            self._extract_class_from_node(node, code)

        # Extract method definitions
        elif node.type == "method_definition":
            self._extract_method_from_node(node, code)

        # Extract property declarations (for validation decorators)
        elif (
            node.type == "property_signature" or node.type == "public_field_definition"
        ):
            self._extract_property_decorators(node, code)

        # Extract function declarations
        elif node.type == "function_declaration":
            self._extract_function_from_node(node, code)

        # Extract exports
        elif node.type == "export_statement":
            self._extract_export_from_node(node, code)

        # Extract call expressions (for database connections, HTTP calls, etc.)
        elif node.type == "call_expression":
            self._extract_call_expression(node, code)

        # Recursively process child nodes
        for child in node.children:
            self._traverse_ast(child, code)

    def _extract_import_from_node(self, node: Node, code: str):
        """Extract import information from import statement node."""
        try:
            # Find the source (module name) in the import statement
            for child in node.children:
                if (
                    child.type == "string"
                    and child.start_point[0] == child.end_point[0]
                ):
                    # Extract module name from string literal
                    module_text = code[child.start_byte : child.end_byte]
                    module_name = module_text.strip("\"'")
                    self.imports.add(module_name)
                    self._check_external_dependency(module_name)
                    break
        except Exception:
            pass  # Skip malformed imports

    def _extract_require_from_node(self, node: Node, code: str):
        """Extract CommonJS require statements."""
        try:
            # Look for require() patterns
            node_text = code[node.start_byte : node.end_byte]
            if "require(" in node_text:
                # Recursively find all call expressions in this node
                self._find_require_calls_recursive(node, code)
        except Exception:
            pass

    def _find_require_calls_recursive(self, node: Node, code: str):
        """Recursively find require() calls in a node."""
        try:
            if node.type == "call_expression":
                self._extract_require_call(node, code)

            # Recursively search child nodes
            for child in node.children:
                self._find_require_calls_recursive(child, code)
        except Exception:
            pass

    def _extract_require_call(self, node: Node, code: str):
        """Extract module name from require() call."""
        try:
            # Check if this is a require call
            for child in node.children:
                if (
                    child.type == "identifier"
                    and code[child.start_byte : child.end_byte] == "require"
                ):
                    # Find the argument (module name)
                    for sibling in node.children:
                        if sibling.type == "arguments":
                            for arg_child in sibling.children:
                                if arg_child.type == "string":
                                    module_text = code[
                                        arg_child.start_byte : arg_child.end_byte
                                    ]
                                    module_name = module_text.strip("\"'")
                                    self.imports.add(module_name)
                                    self._check_external_dependency(module_name)
                                    break
                    break
        except Exception:
            pass

    def _extract_property_decorators(self, node: Node, code: str):
        """Extract decorators from property declarations."""
        try:
            # For public_field_definition nodes, decorators are direct children
            for child in node.children:
                if child.type == "decorator":
                    decorator_info = self._parse_decorator_node(child, code)
                    if decorator_info:
                        self.decorators.append(decorator_info)
        except Exception:
            pass  # Skip malformed properties

    def _extract_class_from_node(self, node: Node, code: str):
        """Extract class information including decorators."""
        try:
            class_info = {
                "name": "",
                "decorators": [],
                "implements": [],
                "extends": [],
                "start_byte": node.start_byte,
                "end_byte": node.end_byte,
            }

            # Extract class name
            for child in node.children:
                if child.type == "type_identifier":
                    class_info["name"] = code[child.start_byte : child.end_byte]
                    break

            # Look for decorators before the class
            self._extract_decorators_for_node(node, code, class_info)

            # Extract implements/extends clauses
            for child in node.children:
                if child.type == "class_heritage":
                    self._extract_heritage_clause(child, code, class_info)

            if class_info["name"]:
                self.classes.append(class_info)

        except Exception:
            pass  # Skip malformed classes

    def _extract_method_from_node(self, node: Node, code: str):
        """Extract method information including decorators and parameters."""
        try:
            method_info = {
                "name": "",
                "decorators": [],
                "parameters": [],
                "is_async": False,
                "start_byte": node.start_byte,
                "end_byte": node.end_byte,
            }

            # Extract method name
            for child in node.children:
                if child.type == "property_identifier":
                    method_info["name"] = code[child.start_byte : child.end_byte]
                    break

            # Check for async modifier
            method_text = code[node.start_byte : node.end_byte]
            method_info["is_async"] = (
                "async" in method_text[:50]
            )  # Check first 50 chars

            # Extract decorators
            self._extract_decorators_for_node(node, code, method_info)

            # Extract parameters
            for child in node.children:
                if child.type == "formal_parameters":
                    self._extract_parameters_from_node(child, code, method_info)
                    break

            if method_info["name"]:
                self.methods.append(method_info)

                # Classify if it's a route method
                self._classify_method(method_info)

        except Exception:
            pass  # Skip malformed methods

    def _extract_function_from_node(self, node: Node, code: str):
        """Extract function declarations."""
        try:
            # Extract function name
            for child in node.children:
                if child.type == "identifier":
                    func_name = code[child.start_byte : child.end_byte]
                    self.functions.add(func_name)
                    break
        except Exception:
            pass

    def _extract_export_from_node(self, node: Node, code: str):
        """Extract export statements."""
        try:
            # Check what's being exported
            for child in node.children:
                if child.type in ["class_declaration", "function_declaration"]:
                    # Extract the name of what's being exported
                    for grandchild in child.children:
                        if grandchild.type in ["identifier", "type_identifier"]:
                            export_name = code[
                                grandchild.start_byte : grandchild.end_byte
                            ]
                            self.exports.add(export_name)
                            break
                elif child.type == "export_clause":
                    # Handle named exports
                    for grandchild in child.children:
                        if grandchild.type == "export_specifier":
                            for ggchild in grandchild.children:
                                if ggchild.type == "identifier":
                                    export_name = code[
                                        ggchild.start_byte : ggchild.end_byte
                                    ]
                                    self.exports.add(export_name)
                                    break
        except Exception:
            pass

    def _extract_call_expression(self, node: Node, code: str):
        """Extract information from call expressions (database connections, HTTP calls, etc.)."""
        try:
            call_text = code[node.start_byte : node.end_byte]

            # Database connections
            self._check_database_connection(call_text)

            # HTTP calls
            self._check_http_call(node, code)

            # AWS service instantiation
            self._check_aws_service(call_text)

            # File operations
            self._check_file_operation(call_text)

        except Exception:
            pass

    def _extract_decorators_for_node(
        self, node: Node, code: str, target_info: dict[str, Any]
    ):
        """Extract decorators that precede a node."""
        try:
            # Look for decorator nodes before this node
            parent = node.parent
            if not parent:
                return

            # Find the index of the current node
            node_index = -1
            for i, child in enumerate(parent.children):
                if child == node:
                    node_index = i
                    break

            if node_index == -1:
                return

            # Look backwards for decorators
            for i in range(node_index - 1, -1, -1):
                child = parent.children[i]
                if child.type == "decorator":
                    decorator_info = self._parse_decorator_node(child, code)
                    if decorator_info:
                        target_info["decorators"].insert(0, decorator_info)
                elif child.type not in [
                    "comment",
                    "export_statement",
                ] and not self._is_whitespace_node(child, code):
                    # Stop if we hit non-decorator, non-whitespace content
                    break

            # Also check if the parent is an export_statement, look at its decorators
            if parent.type == "export_statement":
                for child in parent.children:
                    if child.type == "decorator":
                        decorator_info = self._parse_decorator_node(child, code)
                        if decorator_info:
                            target_info["decorators"].append(decorator_info)

        except Exception:
            pass  # Skip decorator extraction errors

    def _parse_decorator_node(self, node: Node, code: str) -> dict[str, Any] | None:
        """Parse a decorator node to extract its information."""
        try:
            decorator_text = code[node.start_byte : node.end_byte]

            # Extract decorator name and arguments
            # Pattern: @DecoratorName(args) or @DecoratorName
            match = re.match(r"@(\w+)(?:\((.*?)\))?", decorator_text, re.DOTALL)
            if match:
                name = match.group(1)
                args_text = match.group(2) if match.group(2) else ""

                return {
                    "name": name,
                    "arguments": self._parse_decorator_arguments(args_text),
                    "raw_text": decorator_text,
                }
        except Exception:
            pass

        return None

    def _parse_decorator_arguments(self, args_text: str) -> list[str]:
        """Parse decorator arguments from text."""
        if not args_text.strip():
            return []

        # Simple argument parsing - can be enhanced for complex cases
        args = []
        current_arg = ""
        paren_depth = 0
        quote_char = None

        for char in args_text:
            if quote_char:
                current_arg += char
                if char == quote_char and (not current_arg.endswith("\\" + quote_char)):
                    quote_char = None
            elif char in "\"'":
                quote_char = char
                current_arg += char
            elif char == "(":
                paren_depth += 1
                current_arg += char
            elif char == ")":
                paren_depth -= 1
                current_arg += char
            elif char == "," and paren_depth == 0:
                if current_arg.strip():
                    args.append(current_arg.strip())
                current_arg = ""
            else:
                current_arg += char

        if current_arg.strip():
            args.append(current_arg.strip())

        return args

    def _extract_heritage_clause(
        self, node: Node, code: str, class_info: dict[str, Any]
    ):
        """Extract implements/extends information from heritage clause."""
        try:
            for child in node.children:
                if child.type == "implements_clause":
                    for grandchild in child.children:
                        if grandchild.type == "type_identifier":
                            interface_name = code[
                                grandchild.start_byte : grandchild.end_byte
                            ]
                            class_info["implements"].append(interface_name)
                elif child.type == "extends_clause":
                    for grandchild in child.children:
                        if grandchild.type == "type_identifier":
                            parent_class = code[
                                grandchild.start_byte : grandchild.end_byte
                            ]
                            class_info["extends"].append(parent_class)
        except Exception:
            pass

    def _extract_parameters_from_node(
        self, node: Node, code: str, method_info: dict[str, Any]
    ):
        """Extract parameter information from formal parameters node."""
        try:
            for child in node.children:
                if (
                    child.type == "required_parameter"
                    or child.type == "optional_parameter"
                ):
                    param_info = self._parse_parameter_node(child, code)
                    if param_info:
                        method_info["parameters"].append(param_info)
        except Exception:
            pass

    def _parse_parameter_node(self, node: Node, code: str) -> dict[str, Any] | None:
        """Parse a parameter node to extract parameter information."""
        try:
            param_info = {
                "name": "",
                "type": "",
                "decorators": [],
                "optional": node.type == "optional_parameter",
            }

            # Extract decorators from child nodes
            for child in node.children:
                if child.type == "decorator":
                    decorator_info = self._parse_decorator_node(child, code)
                    if decorator_info:
                        # Convert decorator name to parameter type for compatibility
                        decorator_type = self._decorator_to_param_type(
                            decorator_info["name"]
                        )
                        if decorator_type:
                            param_decorator = {
                                "type": decorator_type,
                                "name": (
                                    decorator_info["arguments"][0].strip("'\"")
                                    if decorator_info["arguments"]
                                    else None
                                ),
                            }
                            param_info["decorators"].append(param_decorator)

            # Extract parameter name and type
            for child in node.children:
                if child.type == "identifier":
                    param_info["name"] = code[child.start_byte : child.end_byte]
                elif child.type == "type_annotation":
                    # Extract type from type annotation
                    for grandchild in child.children:
                        if grandchild.type != ":":
                            param_info["type"] = code[
                                grandchild.start_byte : grandchild.end_byte
                            ]
                            break

            return param_info if param_info["name"] else None

        except Exception:
            return None

    def _decorator_to_param_type(self, decorator_name: str) -> str | None:
        """Convert decorator name to parameter type for compatibility."""
        mapping = {
            "Param": "path_param",
            "Query": "query_param",
            "Body": "body_param",
            "Headers": "header_param",
            "Header": "header_param",
            "Req": "request_object",
            "Res": "response_object",
            "Session": "session_object",
            "UploadedFile": "file_upload",
            "UploadedFiles": "file_upload",
            "Ip": "client_ip",
            "HostParam": "host_param",
        }
        return mapping.get(decorator_name)

    def _is_whitespace_node(self, node: Node, code: str) -> bool:
        """Check if a node contains only whitespace."""
        try:
            text = code[node.start_byte : node.end_byte]
            return text.isspace()
        except Exception:
            return False

    def _classify_class(self, class_info: dict[str, Any]):
        """Classify a class based on its decorators and interfaces."""
        decorators = {d["name"] for d in class_info["decorators"]}
        implements = set(class_info["implements"])

        # NestJS Controller
        if "Controller" in decorators:
            controller_info = {
                "name": class_info["name"],
                "base_path": self._extract_controller_path(class_info["decorators"]),
                "decorators": class_info["decorators"],
                "file": self.current_file,
            }
            self.controllers.append(controller_info)

        # NestJS Guard
        elif "Injectable" in decorators and "CanActivate" in implements:
            guard_info = {
                "name": class_info["name"],
                "type": (
                    "authentication"
                    if "auth" in class_info["name"].lower()
                    else "authorization"
                ),
                "decorators": class_info["decorators"],
                "file": self.current_file,
            }
            self.guards.append(guard_info)

        # NestJS Interceptor
        elif "Injectable" in decorators and "NestInterceptor" in implements:
            interceptor_info = {
                "name": class_info["name"],
                "decorators": class_info["decorators"],
                "file": self.current_file,
            }
            self.interceptors.append(interceptor_info)

        # DTO class (check for validation decorators in methods/properties)
        elif class_info["name"].endswith(("Dto", "DTO", "Request", "Response")):
            # For now, mark as potential DTO - full validation check would require method analysis
            dto_info = {
                "name": class_info["name"],
                "has_validation": self._has_validation_decorators(class_info),
                "file": self.current_file,
            }
            self.dtos.append(dto_info)

    def _classify_method(self, method_info: dict[str, Any]):
        """Classify a method based on its decorators."""
        decorators = {d["name"] for d in method_info["decorators"]}
        http_methods = {
            "Get",
            "Post",
            "Put",
            "Delete",
            "Patch",
            "Options",
            "Head",
            "All",
        }

        # Check if it's a route method
        route_decorator = decorators.intersection(http_methods)
        if route_decorator:
            route_info = {
                "method": list(route_decorator)[0].upper(),
                "function_name": method_info["name"],
                "path": self._extract_route_path(method_info["decorators"]),
                "decorators": method_info["decorators"],
                "parameters": method_info["parameters"],
                "status_code": self._extract_status_code(method_info["decorators"]),
                "file": self.current_file,
            }
            self.routes.append(route_info)

    def _extract_controller_path(self, decorators: list[dict[str, Any]]) -> str:
        """Extract base path from @Controller decorator."""
        for decorator in decorators:
            if decorator["name"] == "Controller" and decorator["arguments"]:
                # First argument is usually the path
                path_arg = decorator["arguments"][0]
                # Remove quotes
                return path_arg.strip("\"'")
        return ""

    def _extract_route_path(self, decorators: list[dict[str, Any]]) -> str:
        """Extract route path from HTTP method decorator."""
        http_methods = {
            "Get",
            "Post",
            "Put",
            "Delete",
            "Patch",
            "Options",
            "Head",
            "All",
        }
        for decorator in decorators:
            if decorator["name"] in http_methods and decorator["arguments"]:
                # First argument is usually the path
                path_arg = decorator["arguments"][0]
                # Remove quotes
                return path_arg.strip("\"'")
        return ""

    def _extract_status_code(self, decorators: list[dict[str, Any]]) -> int | None:
        """Extract status code from @HttpCode decorator."""
        for decorator in decorators:
            if decorator["name"] == "HttpCode" and decorator["arguments"]:
                try:
                    return int(decorator["arguments"][0])
                except (ValueError, IndexError):
                    pass
        return None

    def _has_validation_decorators(self, class_info: dict[str, Any]) -> bool:
        """Check if a class has validation decorators by analyzing the class properties."""
        validation_decorators = {
            "IsString",
            "IsNumber",
            "IsBoolean",
            "IsEmail",
            "IsUrl",
            "IsUUID",
            "IsOptional",
            "IsNotEmpty",
            "MinLength",
            "MaxLength",
            "Min",
            "Max",
            "IsArray",
            "ValidateNested",
            "IsEnum",
            "Matches",
            "IsDateString",
        }

        # Check class-level decorators
        decorators = {d["name"] for d in class_info["decorators"]}
        if decorators.intersection(validation_decorators):
            return True

        # For DTO-like classes, check if they contain validation decorators by examining
        # decorators that occur near their definition in the AST
        class_name = class_info["name"]
        if not class_name.endswith(("Dto", "DTO", "Request", "Response")):
            return False

        # Check if class-validator is imported
        if "class-validator" not in self.imports:
            return False

        # For now, use a simple heuristic: if there are validation decorators anywhere
        # in the file and this is a DTO-like input class, assume it has validation
        has_validation_decorators_in_file = any(
            decorator["name"] in validation_decorators for decorator in self.decorators
        )

        if has_validation_decorators_in_file and class_name.endswith(
            ("Dto", "DTO", "Request")
        ):
            # Input DTOs like "CreateUserDto" should have validation, not output like "UserResponse"
            return not class_name.endswith(("Response", "Result", "Output"))

        return False

    def _check_database_connection(self, call_text: str):
        """Check if call expression is a database connection."""
        # MongoDB connections
        mongodb_patterns = [
            "mongoose.connect",
            "new MongoClient",
            "mongodb.connect",
        ]

        for pattern in mongodb_patterns:
            if pattern in call_text:
                if "MongoDB" not in self.components.data_stores:
                    self.components.add_component(
                        "MongoDB",
                        ComponentType.DATA_STORE,
                        description="MongoDB database",
                    )
                    self._add_process_to_database_flow("MongoDB", "MongoDB Protocol")
                break

        # SQL database connections
        sql_patterns = [
            ("createConnection", "SQL Database"),
            ("new Sequelize", "SQL Database"),
            ("knex(", "SQL Database"),
            ("new Pool", "PostgreSQL"),
            ("mysql.createConnection", "MySQL"),
            ("new Database", "SQLite"),
        ]

        for pattern, db_type in sql_patterns:
            if pattern in call_text:
                if db_type not in self.components.data_stores:
                    self.components.add_component(
                        db_type,
                        ComponentType.DATA_STORE,
                        description=f"{db_type} database",
                    )
                    self._add_process_to_database_flow(db_type, "SQL")
                break

        # Redis connections
        redis_patterns = [
            "redis.createClient",
            "new Redis",
            "new IORedis",
        ]

        for pattern in redis_patterns:
            if pattern in call_text:
                if "Redis" not in self.components.data_stores:
                    self.components.add_component(
                        "Redis",
                        ComponentType.DATA_STORE,
                        description="Redis cache/database",
                    )
                    self._add_process_to_database_flow("Redis", "Redis Protocol")
                break

        # Elasticsearch
        if "new Client" in call_text and any(
            imp for imp in self.imports if "elasticsearch" in imp
        ):
            if "Elasticsearch" not in self.components.data_stores:
                self.components.add_component(
                    "Elasticsearch",
                    ComponentType.DATA_STORE,
                    description="Elasticsearch search engine",
                )
                self._add_process_to_database_flow("Elasticsearch", "HTTP/HTTPS")

        # DynamoDB connections
        dynamodb_patterns = [
            "new DynamoDBClient",
            "new DynamoDB",
            "DynamoDBDocumentClient.from",
            "new DocumentClient",
        ]

        for pattern in dynamodb_patterns:
            if pattern in call_text:
                if "DynamoDB" not in self.components.data_stores:
                    self.components.add_component(
                        "DynamoDB",
                        ComponentType.DATA_STORE,
                        description="AWS DynamoDB NoSQL database",
                    )
                    self._add_process_to_database_flow("DynamoDB", "HTTPS")
                break

        # ElectroDB usage (DynamoDB ORM)
        if "new Entity" in call_text and any(
            "electrodb" in imp.lower() for imp in self.imports
        ):
            if "DynamoDB" not in self.components.data_stores:
                self.components.add_component(
                    "DynamoDB",
                    ComponentType.DATA_STORE,
                    description="AWS DynamoDB (via ElectroDB)",
                )
                self._add_process_to_database_flow("DynamoDB", "HTTPS")

    def _check_http_call(self, node: Node, code: str):
        """Check if call expression is an HTTP call."""
        try:
            call_text = code[node.start_byte : node.end_byte]

            # Check for axios, fetch, etc.
            http_patterns = [
                "axios.",
                "fetch(",
                "node-fetch(",
                "got(",
                "request(",
                "superagent.",
            ]

            for pattern in http_patterns:
                if pattern in call_text:
                    # Try to extract URL from arguments
                    for child in node.children:
                        if child.type == "arguments":
                            for arg_child in child.children:
                                if arg_child.type == "string":
                                    url_text = code[
                                        arg_child.start_byte : arg_child.end_byte
                                    ]
                                    url = url_text.strip("\"'")
                                    if url.startswith(("http://", "https://")):
                                        self._process_http_url(url)
                                elif arg_child.type == "template_string":
                                    # Handle template literals
                                    url_text = code[
                                        arg_child.start_byte : arg_child.end_byte
                                    ]
                                    # Extract base URL if possible
                                    base_url_match = re.match(
                                        r"`(https?://[^/\$]+)", url_text
                                    )
                                    if base_url_match:
                                        self._process_http_url(base_url_match.group(1))
                                elif arg_child.type == "binary_expression":
                                    # Handle string concatenation like "https://api.example.com" + path
                                    self._extract_url_from_binary_expression(
                                        arg_child, code
                                    )

                            # Also check if the entire call text contains URLs
                            self._extract_urls_from_text(call_text)
                    break
        except Exception:
            pass

    def _extract_url_from_binary_expression(self, node: Node, code: str):
        """Extract URLs from binary expressions (string concatenation)."""
        try:
            # Look for string literals in the binary expression
            for child in node.children:
                if child.type == "string":
                    url_text = code[child.start_byte : child.end_byte]
                    url = url_text.strip("\"'")
                    if url.startswith(("http://", "https://")):
                        self._process_http_url(url)
                elif child.type == "binary_expression":
                    # Recursively check nested binary expressions
                    self._extract_url_from_binary_expression(child, code)
        except Exception:
            pass

    def _extract_urls_from_text(self, text: str):
        """Extract URLs from text using regex."""
        try:
            # Look for HTTP/HTTPS URLs in the text
            url_pattern = r'["\']*(https?://[^"\'\\s]+)["\']*'
            matches = re.findall(url_pattern, text)
            for url in matches:
                # Clean up the URL
                clean_url = url.strip("\"'")
                if clean_url.startswith(("http://", "https://")):
                    self._process_http_url(clean_url)
        except Exception:
            pass

    def _check_aws_service(self, call_text: str):
        """Check if call expression instantiates an AWS service."""
        # AWS SDK v3 client patterns
        aws_client_patterns = [
            ("new S3Client", "AWS S3"),
            ("new LambdaClient", "AWS Lambda"),
            ("new SQSClient", "AWS SQS"),
            ("new SNSClient", "AWS SNS"),
            ("new SecretsManagerClient", "AWS Secrets Manager"),
            ("new CognitoIdentityProviderClient", "AWS Cognito"),
            ("new CloudWatchClient", "AWS CloudWatch"),
            ("new KinesisClient", "AWS Kinesis"),
            ("new SESClient", "AWS SES"),
            ("new RDSClient", "AWS RDS"),
            ("new EC2Client", "AWS EC2"),
        ]

        for pattern, service_name in aws_client_patterns:
            if pattern in call_text:
                if service_name not in self.components.external_entities:
                    self.components.add_component(
                        service_name,
                        ComponentType.EXTERNAL_ENTITY,
                        description=f"{service_name} cloud service",
                    )
                    self._add_process_to_external_flow(service_name)

        # AWS SDK v2 patterns
        aws_v2_patterns = [
            ("new AWS.S3", "AWS S3"),
            ("new AWS.Lambda", "AWS Lambda"),
            ("new AWS.SQS", "AWS SQS"),
            ("new AWS.SNS", "AWS SNS"),
            ("new AWS.SecretsManager", "AWS Secrets Manager"),
            ("new AWS.CognitoIdentityServiceProvider", "AWS Cognito"),
        ]

        for pattern, service_name in aws_v2_patterns:
            if pattern in call_text:
                if service_name not in self.components.external_entities:
                    self.components.add_component(
                        service_name,
                        ComponentType.EXTERNAL_ENTITY,
                        description=f"{service_name} cloud service",
                    )
                    self._add_process_to_external_flow(service_name)

    def _check_file_operation(self, call_text: str):
        """Check if call expression is a file operation."""
        file_patterns = [
            "fs.readFile",
            "fs.writeFile",
            "fs.readFileSync",
            "fs.writeFileSync",
            "fs.createReadStream",
            "fs.createWriteStream",
            "readFile",
            "writeFile",
            "createReadStream",
            "createWriteStream",
        ]

        for pattern in file_patterns:
            if pattern in call_text:
                if "File System" not in self.components.data_stores:
                    self.components.add_component(
                        "File System",
                        ComponentType.DATA_STORE,
                        description="Local file system storage",
                    )
                    self._add_process_to_database_flow("File System", "File System")
                break

    def _check_external_dependency(self, module: str):
        """Check if module represents an external dependency."""
        # Skip relative imports
        if module.startswith("."):
            return

        # Check for specific AWS service patterns first
        for pattern, service_name in self.aws_service_patterns.items():
            if pattern in module:
                if service_name not in self.components.external_entities:
                    self.components.add_component(
                        service_name,
                        ComponentType.EXTERNAL_ENTITY,
                        description=f"AWS service: {module}",
                    )
                    self._add_process_to_external_flow(service_name)
                return

        # Check for external API patterns
        for pattern, entity_name in self.external_api_patterns.items():
            if pattern in module.lower():
                if entity_name not in self.components.external_entities:
                    self.components.add_component(
                        entity_name,
                        ComponentType.EXTERNAL_ENTITY,
                        description=f"External service: {module}",
                    )
                    self._add_process_to_external_flow(entity_name)
                return

        # Check for database dependencies
        for pattern, db_name in self.database_patterns.items():
            if pattern in module.lower():
                # Special handling for DynamoDB - could be data store or external service
                if "dynamodb" in pattern.lower():
                    if (
                        db_name not in self.components.data_stores
                        and db_name not in self.components.external_entities
                    ):
                        self.components.add_component(
                            db_name,
                            ComponentType.DATA_STORE,
                            description=f"NoSQL Database: {module}",
                        )
                else:
                    if db_name not in self.components.data_stores:
                        self.components.add_component(
                            db_name,
                            ComponentType.DATA_STORE,
                            description=f"Database: {module}",
                        )
                return

        # Check for web frameworks
        for pattern, framework_name in self.web_framework_patterns.items():
            if pattern in module.lower():
                if framework_name not in self.components.processes:
                    self.components.add_component(
                        framework_name,
                        ComponentType.PROCESS,
                        description=f"Web framework: {module}",
                        exposed=True,
                    )
                return

    def _process_http_url(self, url: str):
        """Process an HTTP URL and add external entity if needed."""
        external_entity = self._extract_external_entity_from_url(url)
        if external_entity and external_entity not in self.components.external_entities:
            self.components.add_component(
                external_entity,
                ComponentType.EXTERNAL_ENTITY,
                description=f"External API: {url}",
            )
            protocol = "HTTPS" if url.startswith("https") else "HTTP"
            process_name = self._get_main_process_name()
            self._add_data_flow_if_new(process_name, external_entity, protocol)

    def _process_components(self, code: str):
        """Process extracted AST data into threat model components."""
        # Check if this is a NestJS application
        is_nestjs = any("@nestjs" in imp.lower() for imp in self.imports)

        if is_nestjs:
            self._process_nestjs_components()
        else:
            self._process_generic_components()

        # Check for Express/Fastify routes
        self._check_express_routes(code)

        # Check for Swagger documentation
        self._check_for_swagger_documentation()

    def _process_nestjs_components(self):
        """Process NestJS-specific components."""
        # Add NestJS application as main process
        app_name = "NestJS Application"
        if app_name not in self.components.processes:
            self.components.add_component(
                app_name,
                ComponentType.PROCESS,
                description="NestJS web application server",
                exposed=True,
            )

        # Add Web User as external entity
        if "Web User" not in self.components.external_entities:
            self.components.add_component(
                "Web User",
                ComponentType.EXTERNAL_ENTITY,
                description="External web application user",
            )

        # Process controllers
        for controller in self.controllers:
            controller_name = f"{controller['name']} Controller"
            if controller_name not in self.components.processes:
                self.components.add_component(
                    controller_name,
                    ComponentType.PROCESS,
                    description=f"NestJS controller handling {controller['base_path']} routes",
                    exposed=True,
                )

            # Add data flow from main app to controller
            self._add_data_flow_if_new(app_name, controller_name, "Internal")

            # Add data flows for routes
            for route in self.routes:
                base_path = controller["base_path"]
                route_path = self._build_route_path(base_path, route["path"])
                route_description = f"{route['method']} {route_path}"

                self.components.add_data_flow(
                    "Web User", controller_name, "HTTPS", data_type=route_description
                )

        # Process guards
        for guard in self.guards:
            guard_name = f"{guard['name']} Security Guard"
            if guard_name not in self.components.processes:
                self.components.add_component(
                    guard_name,
                    ComponentType.PROCESS,
                    description=f"Security guard for {guard['type']}",
                )

            # Add data flows from controllers to guards
            for controller in self.controllers:
                controller_name = f"{controller['name']} Controller"
                # Check if this guard is used by this controller
                # For now, create flow for all guards (can be refined later)
                self._add_data_flow_if_new(
                    controller_name,
                    guard_name,
                    "Internal",
                    data_type="Authorization Check",
                )

        # Process interceptors
        for interceptor in self.interceptors:
            interceptor_name = f"{interceptor['name']} Middleware"
            if interceptor_name not in self.components.processes:
                self.components.add_component(
                    interceptor_name,
                    ComponentType.PROCESS,
                    description="Request/response processing middleware",
                )

        # Process DTOs with validation
        for dto in self.dtos:
            if dto["has_validation"]:
                validator_name = f"{dto['name']} Validator"
                if validator_name not in self.components.processes:
                    self.components.add_component(
                        validator_name,
                        ComponentType.PROCESS,
                        description=f"Input validation process for {dto['name']}",
                    )

    def _process_generic_components(self):
        """Process generic JavaScript/TypeScript components."""
        # Determine main process name based on imports
        process_name = self._get_main_process_name()

        # Add main process if we have meaningful code
        if (
            self.imports or self.classes or self.functions
        ) and process_name not in self.components.processes:
            self.components.add_component(
                process_name,
                ComponentType.PROCESS,
                description="JavaScript/TypeScript application",
                exposed=True,
            )

    def _check_express_routes(self, code: str):
        """Check for Express/Fastify style routes using AST."""
        # This is a simplified check - in a full implementation,
        # we would traverse the AST looking for specific patterns
        route_patterns = [
            "app.get",
            "app.post",
            "router.get",
            "router.post",
            "fastify.get",
        ]

        for pattern in route_patterns:
            if pattern in code:
                # Add web process
                process_name = self._get_web_process_name()
                if process_name not in self.components.processes:
                    self.components.add_component(
                        process_name,
                        ComponentType.PROCESS,
                        description="Web application server",
                        exposed=True,
                    )

                # Add web user as external entity
                if "Web User" not in self.components.external_entities:
                    self.components.add_component(
                        "Web User",
                        ComponentType.EXTERNAL_ENTITY,
                        description="External web application user",
                    )

                # Add data flow
                self._add_data_flow_if_new("Web User", process_name, "HTTPS")
                break

    def _check_for_swagger_documentation(self):
        """Check for Swagger/OpenAPI documentation and add as external entity."""
        # Check if Swagger is imported
        if any("swagger" in imp.lower() for imp in self.imports):
            app_name = self._get_main_process_name()
            if "API Documentation" not in self.components.external_entities:
                self.components.add_component(
                    "API Documentation",
                    ComponentType.EXTERNAL_ENTITY,
                    description="Swagger/OpenAPI documentation interface",
                )
                self._add_data_flow_if_new(
                    app_name, "API Documentation", "HTTPS", data_type="API Schema"
                )

    def _build_route_path(self, base_path: str, route_path: str) -> str:
        """Build full route path from controller base path and route path."""
        if base_path and route_path:
            return f"{base_path}/{route_path}"
        elif base_path:
            return f"{base_path}/"
        elif route_path:
            return route_path
        else:
            return ""

    def _get_web_process_name(self) -> str:
        """Get the name for the web process based on imports."""
        for framework, name in self.web_framework_patterns.items():
            if any(framework in imp for imp in self.imports):
                return name
        return "Node.js Web Application"

    def _get_main_process_name(self) -> str:
        """Get the main process name."""
        # Check if it's a web application
        for framework in self.web_framework_patterns.keys():
            if any(framework in imp for imp in self.imports):
                return self._get_web_process_name()

        # Otherwise return generic Node.js app
        return "Node.js Application"

    def _add_process_to_database_flow(self, db_name: str, protocol: str):
        """Add data flow from process to database."""
        process_name = self._get_main_process_name()
        if process_name not in self.components.processes:
            self.components.add_component(
                process_name,
                ComponentType.PROCESS,
                description="Application process",
            )
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

    def _update_legacy_attributes(self):
        """Update legacy attributes for backward compatibility with tests."""
        self.nestjs_routes = self.routes
        self.nestjs_controllers = self.controllers
        self.nestjs_guards = self.guards
        self.nestjs_interceptors = self.interceptors
