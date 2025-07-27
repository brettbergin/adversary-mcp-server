"""Tests for comprehensive NestJS extraction in JavaScript extractor."""

import os
import sys

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.threat_modeling.extractors.js_extractor import (
    JavaScriptExtractor,
)


class TestNestJSExtractor:
    """Test comprehensive NestJS code extraction."""

    def test_basic_nestjs_controller_extraction(self):
        """Test extraction of basic NestJS controller with routes."""
        code = """
import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import { CreateUserDto, UserDto } from './dto/user.dto';

@Controller('users')
export class UsersController {
    @Get()
    async findAll(): Promise<UserDto[]> {
        return this.userService.findAll();
    }

    @Get(':id')
    async findOne(@Param('id') id: string): Promise<UserDto> {
        return this.userService.findOne(id);
    }

    @Post()
    async create(@Body() createUserDto: CreateUserDto): Promise<UserDto> {
        return this.userService.create(createUserDto);
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "users.controller.ts")

        # Should detect NestJS application
        assert "NestJS Application" in components.processes

        # Should detect controller as a process
        assert "UsersController Controller" in components.processes

        # Should detect Web User as external entity
        assert "Web User" in components.external_entities

        # Should have data flows
        assert len(components.data_flows) > 0

        # Should have data flow from Web User to controller
        user_to_controller_flows = [
            flow
            for flow in components.data_flows
            if flow.source == "Web User" and "UsersController Controller" in flow.target
        ]
        assert len(user_to_controller_flows) > 0

    def test_nestjs_guards_and_interceptors(self):
        """Test extraction of NestJS guards and interceptors."""
        code = """
import { Controller, Get, UseGuards, UseInterceptors } from '@nestjs/common';
import { JwtAuthGuard, RolesGuard } from './guards';
import { LoggingInterceptor, TransformInterceptor } from './interceptors';

@Injectable()
export class JwtAuthGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        return this.validateJwt(context);
    }
}

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        console.log('Before...');
        return next.handle();
    }
}

@Controller('protected')
@UseGuards(JwtAuthGuard)
@UseInterceptors(LoggingInterceptor)
export class ProtectedController {
    @Get('admin')
    @UseGuards(RolesGuard)
    @UseInterceptors(TransformInterceptor)
    async getAdminData(): Promise<any> {
        return { sensitive: 'data' };
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "protected.controller.ts")

        # Should detect guard as security component
        assert "JwtAuthGuard Security Guard" in components.processes

        # Should detect interceptor as middleware
        assert "LoggingInterceptor Middleware" in components.processes

        # Should detect controller
        assert "ProtectedController Controller" in components.processes

        # Should have internal data flows between components
        internal_flows = [
            flow for flow in components.data_flows if flow.protocol == "Internal"
        ]
        assert len(internal_flows) > 0

    def test_nestjs_parameter_decorators(self):
        """Test extraction of various NestJS parameter decorators."""
        code = """
import { Controller, Get, Post, Param, Query, Body, Headers, Req, Res, UploadedFile } from '@nestjs/common';

@Controller('api')
export class ApiController {
    @Get('search')
    async search(
        @Query('term') searchTerm: string,
        @Query('limit') limit?: number,
        @Headers('authorization') auth: string,
        @Req() request: Request
    ): Promise<any> {
        return this.searchService.search(searchTerm, limit);
    }

    @Post('users/:id/avatar')
    async uploadAvatar(
        @Param('id') userId: string,
        @UploadedFile() file: Express.Multer.File,
        @Body() metadata: any,
        @Res() response: Response
    ): Promise<void> {
        await this.userService.updateAvatar(userId, file);
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "api.controller.ts")

        # Should detect controller
        assert "ApiController Controller" in components.processes

        # Should extract route information (stored internally)
        assert len(extractor.nestjs_routes) == 2

        # Check that routes have parameter information
        search_route = next(
            (r for r in extractor.nestjs_routes if r["path"] == "search"), None
        )
        assert search_route is not None
        assert len(search_route["parameters"]) == 4

        # Check parameter types
        param_types = [
            p["decorators"][0]["type"]
            for p in search_route["parameters"]
            if p["decorators"]
        ]
        assert "query_param" in param_types
        assert "header_param" in param_types
        assert "request_object" in param_types

    def test_nestjs_dto_validation(self):
        """Test extraction of DTO classes with validation decorators."""
        code = """
import { IsString, IsEmail, IsOptional, MinLength, MaxLength } from 'class-validator';
import { Controller, Post, Body } from '@nestjs/common';

export class CreateUserDto {
    @IsString()
    @MinLength(2)
    @MaxLength(50)
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
        return this.userService.create(createUserDto);
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "users.controller.ts")

        # Should detect DTO validator as a process
        assert "CreateUserDto Validator" in components.processes

        # Should not create validator for response DTOs without validation
        assert "UserResponse Validator" not in components.processes

        # Should detect controller
        assert "UsersController Controller" in components.processes

    def test_nestjs_with_database_and_external_apis(self):
        """Test NestJS application with database and external API integrations."""
        code = """
import { Controller, Get, Post, Body, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import axios from 'axios';
import { User } from './entities/user.entity';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>
    ) {}

    async findAll(): Promise<User[]> {
        return this.userRepository.find();
    }

    async sendNotification(userId: string): Promise<void> {
        const user = await this.userRepository.findOne(userId);
        await axios.post('https://api.sendgrid.com/v3/mail/send', {
            to: user.email,
            subject: 'Welcome!'
        });
    }
}

@Controller('users')
export class UsersController {
    constructor(private userService: UserService) {}

    @Get()
    async findAll(): Promise<User[]> {
        return this.userService.findAll();
    }

    @Post(':id/notify')
    async notify(@Param('id') id: string): Promise<void> {
        await this.userService.sendNotification(id);
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "users.module.ts")

        # Should detect NestJS application
        assert "NestJS Application" in components.processes

        # Should detect controller
        assert "UsersController Controller" in components.processes

        # Should detect database (TypeORM)
        assert "SQL Database" in components.data_stores

        # Should detect external API
        assert "SendGrid API" in components.external_entities

        # Should have data flows
        flows = components.data_flows
        assert len(flows) > 0

        # Should have flow to external API
        external_flows = [flow for flow in flows if flow.target == "SendGrid API"]
        assert len(external_flows) > 0

    def test_nestjs_with_swagger_documentation(self):
        """Test NestJS application with Swagger/OpenAPI documentation."""
        code = """
import { Controller, Get, Post } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

@ApiTags('users')
@Controller('users')
export class UsersController {
    @Get()
    @ApiOperation({ summary: 'Get all users' })
    @ApiResponse({ status: 200, description: 'Return all users.' })
    async findAll(): Promise<any[]> {
        return [];
    }

    @Post()
    @ApiOperation({ summary: 'Create user' })
    @ApiResponse({ status: 201, description: 'User created successfully.' })
    async create(@Body() userData: any): Promise<any> {
        return userData;
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "users.controller.ts")

        # Should detect API documentation as external entity
        assert "API Documentation" in components.external_entities

        # Should have data flow to API documentation
        doc_flows = [
            flow for flow in components.data_flows if flow.target == "API Documentation"
        ]
        assert len(doc_flows) > 0
        assert doc_flows[0].data_type == "API Schema"

    def test_nestjs_microservice_pattern(self):
        """Test NestJS microservice with message patterns."""
        code = """
import { Controller, Get } from '@nestjs/common';
import { MessagePattern, ClientProxy, Inject } from '@nestjs/microservices';

@Controller()
export class UserController {
    constructor(
        @Inject('USER_SERVICE') private client: ClientProxy
    ) {}

    @MessagePattern('get_user')
    async getUser(data: { id: string }): Promise<any> {
        return this.userService.findOne(data.id);
    }

    @Get('external-user/:id')
    async getExternalUser(@Param('id') id: string): Promise<any> {
        return this.client.send('get_user', { id }).toPromise();
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "user.controller.ts")

        # Should detect NestJS application
        assert "NestJS Application" in components.processes

        # Should detect controller
        assert "UserController Controller" in components.processes

        # Should have basic web flows
        assert len(components.data_flows) > 0

    def test_complex_nestjs_enterprise_application(self):
        """Test complex enterprise NestJS application with multiple security layers."""
        code = """
import {
    Controller, Get, Post, Put, Delete, Body, Param, Query, UseGuards, UseInterceptors,
    UsePipes, ValidationPipe, HttpCode, Header, Req, Res, Session
} from '@nestjs/common';
import { JwtAuthGuard, RolesGuard, ThrottlerGuard } from './guards';
import { LoggingInterceptor, CacheInterceptor, TransformInterceptor } from './interceptors';
import { IsUUID, IsString, IsEmail, MinLength, IsOptional } from 'class-validator';

export class CreateUserDto {
    @IsString()
    @MinLength(2)
    name: string;

    @IsEmail()
    email: string;

    @IsOptional()
    @IsString()
    department?: string;
}

export class UpdateUserDto {
    @IsOptional()
    @IsString()
    name?: string;

    @IsOptional()
    @IsString()
    department?: string;
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        return this.jwtService.verify(context);
    }
}

@Injectable()
export class RolesGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        return this.roleService.hasPermission(context);
    }
}

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        this.logger.log('Request received');
        return next.handle();
    }
}

@Controller('api/v1/users')
@UseGuards(JwtAuthGuard, ThrottlerGuard)
@UseInterceptors(LoggingInterceptor, CacheInterceptor)
export class UsersController {
    @Get()
    @UseInterceptors(TransformInterceptor)
    async findAll(
        @Query('page') page: number = 1,
        @Query('limit') limit: number = 10,
        @Query('search') search?: string,
        @Headers('authorization') token: string,
        @Req() request: Request
    ): Promise<any[]> {
        return this.userService.findAll({ page, limit, search });
    }

    @Get(':id')
    @UseGuards(RolesGuard)
    async findOne(
        @Param('id') @IsUUID() id: string,
        @Headers('x-request-id') requestId: string
    ): Promise<any> {
        return this.userService.findOne(id);
    }

    @Post()
    @HttpCode(201)
    @Header('X-Custom-Header', 'UserCreated')
    @UsePipes(new ValidationPipe({ transform: true }))
    async create(
        @Body() createUserDto: CreateUserDto,
        @Session() session: any,
        @Res() response: Response
    ): Promise<any> {
        const user = await this.userService.create(createUserDto);
        return response.status(201).json(user);
    }

    @Put(':id')
    @UseGuards(RolesGuard)
    async update(
        @Param('id') id: string,
        @Body() updateUserDto: UpdateUserDto,
        @Headers('if-match') etag: string
    ): Promise<any> {
        return this.userService.update(id, updateUserDto, etag);
    }

    @Delete(':id')
    @HttpCode(204)
    @UseGuards(RolesGuard)
    async remove(
        @Param('id') id: string,
        @Headers('authorization') token: string
    ): Promise<void> {
        await this.userService.remove(id);
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "users.controller.ts")

        # Should detect NestJS application
        assert "NestJS Application" in components.processes

        # Should detect controller
        assert "UsersController Controller" in components.processes

        # Should detect multiple guards
        assert "JwtAuthGuard Security Guard" in components.processes
        assert "RolesGuard Security Guard" in components.processes

        # Should detect interceptor
        assert "LoggingInterceptor Middleware" in components.processes

        # Should detect DTO validators
        assert "CreateUserDto Validator" in components.processes
        assert "UpdateUserDto Validator" in components.processes

        # Should have multiple data flows
        assert len(components.data_flows) >= 5

        # Should have flows from controller to guards
        guard_flows = [
            flow
            for flow in components.data_flows
            if "Security Guard" in flow.target
            and flow.data_type == "Authorization Check"
        ]
        assert len(guard_flows) > 0

        # Should extract route information
        assert len(extractor.nestjs_routes) == 5  # GET, GET :id, POST, PUT, DELETE

        # Check specific route parameters
        get_all_route = next(
            (
                r
                for r in extractor.nestjs_routes
                if r["method"] == "GET" and not r["path"]
            ),
            None,
        )
        assert get_all_route is not None
        assert (
            len(get_all_route["parameters"]) == 5
        )  # page, limit, search, token, request

        # Check parameter decorators
        query_params = [
            p
            for p in get_all_route["parameters"]
            if p["decorators"] and p["decorators"][0]["type"] == "query_param"
        ]
        assert len(query_params) >= 3  # page, limit, search

    def test_nestjs_route_extraction_accuracy(self):
        """Test accuracy of NestJS route extraction with various HTTP methods."""
        code = """
import { Controller, Get, Post, Put, Delete, Patch, Options, HttpCode } from '@nestjs/common';

@Controller('api/resources')
export class ResourceController {
    @Get()
    async findAll(): Promise<any[]> {
        return [];
    }

    @Get('search')
    async search(): Promise<any[]> {
        return [];
    }

    @Get(':id')
    async findOne(@Param('id') id: string): Promise<any> {
        return {};
    }

    @Post()
    @HttpCode(201)
    async create(@Body() data: any): Promise<any> {
        return data;
    }

    @Put(':id')
    async update(@Param('id') id: string, @Body() data: any): Promise<any> {
        return data;
    }

    @Patch(':id')
    async partialUpdate(@Param('id') id: string, @Body() data: any): Promise<any> {
        return data;
    }

    @Delete(':id')
    @HttpCode(204)
    async remove(@Param('id') id: string): Promise<void> {
        // delete logic
    }

    @Options()
    async options(): Promise<void> {
        // options logic
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "resource.controller.ts")

        # Should extract all routes
        assert len(extractor.nestjs_routes) == 8

        # Check all HTTP methods are detected
        methods = [route["method"] for route in extractor.nestjs_routes]
        assert "GET" in methods
        assert "POST" in methods
        assert "PUT" in methods
        assert "PATCH" in methods
        assert "DELETE" in methods
        assert "OPTIONS" in methods

        # Check paths are correctly extracted
        paths = [route["path"] for route in extractor.nestjs_routes]
        assert "" in paths  # GET /
        assert "search" in paths  # GET /search
        assert ":id" in paths  # GET /:id

        # Check HTTP status codes
        post_route = next(
            (r for r in extractor.nestjs_routes if r["method"] == "POST"), None
        )
        assert post_route["status_code"] == 201

        delete_route = next(
            (r for r in extractor.nestjs_routes if r["method"] == "DELETE"), None
        )
        assert delete_route["status_code"] == 204

    def test_nestjs_imports_detection(self):
        """Test that NestJS extraction only triggers when NestJS imports are present."""
        # Code without NestJS imports
        non_nestjs_code = """
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    res.json([]);
});

module.exports = app;
"""

        extractor = JavaScriptExtractor()
        components = extractor.extract_components(non_nestjs_code, "express-app.js")

        # Should not create NestJS-specific components
        assert "NestJS Application" not in components.processes
        assert len(extractor.nestjs_controllers) == 0
        assert len(extractor.nestjs_routes) == 0

        # Should detect Express instead
        assert "Express App" in components.processes

    def test_nestjs_controller_base_path_handling(self):
        """Test proper handling of controller base paths."""
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

@Controller()  // No base path
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
        assert "UsersController Controller" in components.processes
        assert "DefaultController Controller" in components.processes

        # Should extract controller information
        assert len(extractor.nestjs_controllers) == 2

        users_controller = next(
            (c for c in extractor.nestjs_controllers if c["name"] == "UsersController"),
            None,
        )
        assert users_controller is not None
        assert users_controller["base_path"] == "api/v1/users"

        default_controller = next(
            (
                c
                for c in extractor.nestjs_controllers
                if c["name"] == "DefaultController"
            ),
            None,
        )
        assert default_controller is not None
        assert default_controller["base_path"] == ""

        # Should extract routes
        assert len(extractor.nestjs_routes) == 4
