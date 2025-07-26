"""Unit tests for specific NestJS route extraction edge cases discovered during debugging."""

import os
import sys

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.threat_modeling.extractors.js_extractor import (
    JavaScriptExtractor,
)


class TestNestJSRouteExtractionUnit:
    """Unit tests for specific NestJS route extraction behaviors."""

    def test_function_name_extraction_with_multiple_decorators(self):
        """Test that function names are correctly extracted when multiple decorators are present."""
        code = """
        import { Controller, Post, HttpCode, Header, UsePipes, ValidationPipe } from '@nestjs/common';

        @Controller('api')
        export class TestController {
            @Post()
            @HttpCode(201)
            @Header('X-Custom-Header', 'UserCreated')
            @UsePipes(new ValidationPipe({ transform: true }))
            async create(@Body() data: any): Promise<any> {
                return data;
            }
        }
        """
        extractor = JavaScriptExtractor()
        extractor.extract_components(code, "test.controller.ts")

        assert len(extractor.nestjs_routes) == 1
        route = extractor.nestjs_routes[0]

        # Should extract correct function name, not decorator names
        assert route["function_name"] == "create"
        assert route["method"] == "POST"
        assert route["path"] == ""

    def test_http_status_code_extraction(self):
        """Test that @HttpCode decorators are correctly parsed."""
        code = """
        import { Controller, Post, Delete, HttpCode } from '@nestjs/common';

        @Controller('api')
        export class TestController {
            @Post()
            @HttpCode(201)
            async create(): Promise<any> {
                return {};
            }

            @Delete(':id')
            @HttpCode(204)
            async remove(): Promise<void> {
                // delete logic
            }

            @Get()
            async findAll(): Promise<any[]> {
                return [];
            }
        }
        """
        extractor = JavaScriptExtractor()
        extractor.extract_components(code, "test.controller.ts")

        routes_by_method = {r["method"]: r for r in extractor.nestjs_routes}

        # POST should have status 201
        assert "POST" in routes_by_method
        assert routes_by_method["POST"]["status_code"] == 201

        # DELETE should have status 204
        assert "DELETE" in routes_by_method
        assert routes_by_method["DELETE"]["status_code"] == 204

        # GET should have no status code (None)
        assert "GET" in routes_by_method
        assert routes_by_method["GET"]["status_code"] is None

    def test_parameter_extraction_multiline_signatures(self):
        """Test parameter extraction from multi-line method signatures."""
        code = """
        import { Controller, Get, Query, Headers, Req } from '@nestjs/common';

        @Controller('api')
        export class TestController {
            @Get('search')
            async search(
                @Query('term') searchTerm: string,
                @Query('limit') limit?: number,
                @Headers('authorization') auth: string,
                @Req() request: Request
            ): Promise<any> {
                return {};
            }
        }
        """
        extractor = JavaScriptExtractor()
        extractor.extract_components(code, "test.controller.ts")

        assert len(extractor.nestjs_routes) == 1
        route = extractor.nestjs_routes[0]

        # Should extract all 4 parameters
        assert len(route["parameters"]) == 4

        # Check parameter details
        params_by_name = {p["name"]: p for p in route["parameters"]}

        assert "searchTerm" in params_by_name
        assert params_by_name["searchTerm"]["type"] == "string"
        assert params_by_name["searchTerm"]["optional"] is False
        assert len(params_by_name["searchTerm"]["decorators"]) == 1
        assert params_by_name["searchTerm"]["decorators"][0]["type"] == "query_param"
        assert params_by_name["searchTerm"]["decorators"][0]["name"] == "term"

        assert "limit" in params_by_name
        assert params_by_name["limit"]["optional"] is True

        assert "auth" in params_by_name
        assert params_by_name["auth"]["decorators"][0]["type"] == "header_param"

        assert "request" in params_by_name
        assert params_by_name["request"]["decorators"][0]["type"] == "request_object"

    def test_data_flow_creation_for_multiple_routes(self):
        """Test that unique data flows are created for each route."""
        code = """
        import { Controller, Get, Post, Put, Delete } from '@nestjs/common';

        @Controller('api/users')
        export class UsersController {
            @Get()
            async findAll(): Promise<any[]> {
                return [];
            }

            @Get(':id')
            async findOne(): Promise<any> {
                return {};
            }

            @Post()
            async create(): Promise<any> {
                return {};
            }

            @Put(':id')
            async update(): Promise<any> {
                return {};
            }

            @Delete(':id')
            async remove(): Promise<void> {
                // delete
            }
        }
        """
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "users.controller.ts")

        # Should create 5 routes
        assert len(extractor.nestjs_routes) == 5

        # Should create data flows for each route
        route_flows = [
            flow
            for flow in components.data_flows
            if flow.source == "Web User" and flow.target == "UsersController Controller"
        ]

        # Should have 5 unique data flows (one per route)
        assert len(route_flows) == 5

        # Each flow should have unique data_type
        data_types = {flow.data_type for flow in route_flows}
        assert len(data_types) == 5

        # Check specific route flows
        expected_data_types = {
            "GET api/users/",
            "GET api/users/:id",
            "POST api/users/",
            "PUT api/users/:id",
            "DELETE api/users/:id",
        }
        assert data_types == expected_data_types

    def test_controller_and_route_path_combination(self):
        """Test proper combination of controller base path and route paths."""
        code = """
        import { Controller, Get, Post } from '@nestjs/common';

        @Controller('api/v1/users')
        export class UsersController {
            @Get()
            async findAll(): Promise<any[]> {
                return [];
            }

            @Get('profile')
            async getProfile(): Promise<any> {
                return {};
            }

            @Post('avatar')
            async uploadAvatar(): Promise<any> {
                return {};
            }
        }

        @Controller()
        export class DefaultController {
            @Get('health')
            async health(): Promise<any> {
                return { status: 'ok' };
            }
        }
        """
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "controllers.ts")

        # Should detect both controllers
        assert len(extractor.nestjs_controllers) == 2

        # Should extract 4 routes total
        assert len(extractor.nestjs_routes) == 4

        # Check controller information
        controllers_by_name = {c["name"]: c for c in extractor.nestjs_controllers}

        assert "UsersController" in controllers_by_name
        assert controllers_by_name["UsersController"]["base_path"] == "api/v1/users"

        assert "DefaultController" in controllers_by_name
        assert controllers_by_name["DefaultController"]["base_path"] == ""

        # Check data flow paths include base path
        route_flows = [
            flow
            for flow in components.data_flows
            if flow.source == "Web User" and "Controller" in flow.target
        ]

        data_types = {flow.data_type for flow in route_flows}

        # Should include base paths in flow descriptions
        assert "GET api/v1/users/" in data_types
        assert "GET api/v1/users/profile" in data_types
        assert "POST api/v1/users/avatar" in data_types
        assert "GET health" in data_types

    def test_decorator_filtering_edge_cases(self):
        """Test that decorator names are properly filtered from function name extraction."""
        code = """
        import { Controller, Get, UseGuards, UseInterceptors, Injectable } from '@nestjs/common';

        @Injectable()
        export class SomeGuard {}

        @Injectable()
        export class SomeInterceptor {}

        @Controller('api')
        export class TestController {
            @Get()
            @UseGuards(SomeGuard)
            @UseInterceptors(SomeInterceptor)
            async findAll(): Promise<any[]> {
                return [];
            }
        }
        """
        extractor = JavaScriptExtractor()
        extractor.extract_components(code, "test.controller.ts")

        assert len(extractor.nestjs_routes) == 1
        route = extractor.nestjs_routes[0]

        # Should extract correct function name despite multiple decorators
        assert route["function_name"] == "findAll"

        # Should not be confused by class names that match decorator patterns
        assert route["function_name"] != "UseGuards"
        assert route["function_name"] != "UseInterceptors"
        assert route["function_name"] != "Injectable"

    def test_route_without_path_parameter(self):
        """Test routes that don't specify a path parameter."""
        code = """
        import { Controller, Get, Post } from '@nestjs/common';

        @Controller('api')
        export class TestController {
            @Get()
            async getDefault(): Promise<any> {
                return {};
            }

            @Post()
            async postDefault(): Promise<any> {
                return {};
            }
        }
        """
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "test.controller.ts")

        assert len(extractor.nestjs_routes) == 2

        # Routes without path should have empty string path
        for route in extractor.nestjs_routes:
            assert route["path"] == ""

        # Should still create proper data flows
        route_flows = [
            flow
            for flow in components.data_flows
            if flow.source == "Web User" and "TestController Controller" in flow.target
        ]
        assert len(route_flows) == 2

    def test_all_http_methods_detected(self):
        """Test that all standard HTTP methods are properly detected."""
        code = """
        import { Controller, Get, Post, Put, Delete, Patch, Options, Head, All } from '@nestjs/common';

        @Controller('api')
        export class TestController {
            @Get()
            async get(): Promise<any> { return {}; }

            @Post()
            async post(): Promise<any> { return {}; }

            @Put()
            async put(): Promise<any> { return {}; }

            @Delete()
            async delete(): Promise<any> { return {}; }

            @Patch()
            async patch(): Promise<any> { return {}; }

            @Options()
            async options(): Promise<any> { return {}; }

            @Head()
            async head(): Promise<any> { return {}; }

            @All()
            async all(): Promise<any> { return {}; }
        }
        """
        extractor = JavaScriptExtractor()
        extractor.extract_components(code, "test.controller.ts")

        assert len(extractor.nestjs_routes) == 8

        methods = {route["method"] for route in extractor.nestjs_routes}
        expected_methods = {
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "HEAD",
            "ALL",
        }

        assert methods == expected_methods

    def test_guards_and_interceptors_extraction(self):
        """Test that guards and interceptors are properly extracted and linked."""
        code = """
        import { Controller, Get, UseGuards, UseInterceptors, Injectable } from '@nestjs/common';

        @Injectable()
        export class JwtAuthGuard implements CanActivate {
            canActivate(): boolean { return true; }
        }

        @Injectable()
        export class LoggingInterceptor implements NestInterceptor {
            intercept(): any { return null; }
        }

        @Controller('api')
        @UseGuards(JwtAuthGuard)
        @UseInterceptors(LoggingInterceptor)
        export class TestController {
            @Get()
            async findAll(): Promise<any[]> {
                return [];
            }
        }
        """
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "test.controller.ts")

        # Should detect guard and interceptor as processes
        assert "JwtAuthGuard Security Guard" in components.processes
        assert "LoggingInterceptor Middleware" in components.processes

        # Should detect controller
        assert "TestController Controller" in components.processes

        # Should create data flow from controller to guard
        guard_flows = [
            flow
            for flow in components.data_flows
            if flow.source == "TestController Controller"
            and flow.target == "JwtAuthGuard Security Guard"
        ]
        assert len(guard_flows) > 0
        assert guard_flows[0].data_type == "Authorization Check"

    def test_dto_validation_detection(self):
        """Test that DTO classes with validation decorators are detected."""
        code = """
        import { IsString, IsEmail, IsOptional, MinLength } from 'class-validator';
        import { Controller, Post, Body } from '@nestjs/common';

        export class CreateUserDto {
            @IsString()
            @MinLength(2)
            name: string;

            @IsEmail()
            email: string;

            @IsOptional()
            @IsString()
            bio?: string;
        }

        export class UserResponse {
            id: string;
            name: string;
            email: string;
        }

        @Controller('users')
        export class UsersController {
            @Post()
            async create(@Body() createUserDto: CreateUserDto): Promise<UserResponse> {
                return {} as UserResponse;
            }
        }
        """
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "users.controller.ts")

        # Should detect DTO validator for class with validation decorators
        assert "CreateUserDto Validator" in components.processes

        # Should not create validator for response DTOs without validation
        assert "UserResponse Validator" not in components.processes
