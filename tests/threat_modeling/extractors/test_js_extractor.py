"""Tests for JavaScript/TypeScript code extractor."""

import os
import sys

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.threat_modeling.extractors.js_extractor import (
    JavaScriptExtractor,
)


class TestJavaScriptExtractor:
    """Test JavaScript/TypeScript code extractor."""

    def test_basic_express_app_extraction(self):
        """Test extraction from a basic Express application."""
        code = """
const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');

const app = express();

mongoose.connect('mongodb://localhost:27017/myapp');

app.get('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    const stripeData = await axios.get(`https://api.stripe.com/v1/customers/${user.stripeId}`);
    res.json({ user, payment: stripeData.data });
});

app.post('/api/orders', async (req, res) => {
    const order = new Order(req.body);
    await order.save();
    res.json(order);
});

app.listen(3000);
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "app.js")

        # Should detect Express app as a process
        assert len(components.processes) > 0
        assert any("Express" in process for process in components.processes)

        # Should detect MongoDB
        assert len(components.data_stores) > 0
        assert any("MongoDB" in store for store in components.data_stores)

        # Should detect Stripe API as external entity
        assert len(components.external_entities) > 0
        assert any("Stripe" in entity for entity in components.external_entities)

        # Should have data flows
        assert len(components.data_flows) > 0

    def test_typescript_nestjs_extraction(self):
        """Test extraction from a TypeScript NestJS application."""
        code = """
import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as AWS from 'aws-sdk';

@Injectable()
export class UserService {
    private s3 = new AWS.S3();

    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>
    ) {}

    async findOne(id: string): Promise<User> {
        return this.userRepository.findOne(id);
    }
}

@Controller('users')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @Get(':id')
    async getUser(@Param('id') id: string) {
        return this.userService.findOne(id);
    }

    @Post()
    async createUser(@Body() userData: any) {
        return this.userService.create(userData);
    }
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "user.controller.ts")

        # Should detect NestJS app as a process
        assert len(components.processes) > 0
        assert any(
            "NestJS" in process or "Node.js" in process
            for process in components.processes
        )

        # Should detect SQL database (TypeORM)
        assert len(components.data_stores) > 0
        assert any("SQL" in store for store in components.data_stores)

        # Should detect AWS Services
        assert len(components.external_entities) > 0
        assert any("AWS" in entity for entity in components.external_entities)

        # Should detect web user
        assert any("Web User" in entity for entity in components.external_entities)

    def test_database_operations_detection(self):
        """Test detection of various database operations."""
        code = """
import { createConnection } from 'mysql2';
import Redis from 'ioredis';
import { Client } from '@elastic/elasticsearch';
import knex from 'knex';

// MySQL connection
const mysql = createConnection({
    host: 'localhost',
    user: 'root',
    database: 'test'
});

// Redis connection
const redis = new Redis({
    host: 'localhost',
    port: 6379
});

// Elasticsearch client
const elastic = new Client({
    node: 'http://localhost:9200'
});

// Knex SQL query builder
const db = knex({
    client: 'pg',
    connection: {
        host: '127.0.0.1',
        user: 'admin',
        database: 'myapp'
    }
});
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "db.ts")

        # Should detect multiple databases
        assert len(components.data_stores) >= 3
        data_stores = set(components.data_stores)

        # Check for specific databases
        assert any("MySQL" in store for store in data_stores)
        assert any("Redis" in store for store in data_stores)
        assert any("Elasticsearch" in store for store in data_stores)
        assert any("SQL" in store or "PostgreSQL" in store for store in data_stores)

    def test_external_api_detection(self):
        """Test detection of external API calls."""
        code = """
const stripe = require('stripe')('sk_test_...');
const twilio = require('twilio')(accountSid, authToken);
const sgMail = require('@sendgrid/mail');
const { Octokit } = require("@octokit/rest");

async function processPayment(amount) {
    const charge = await stripe.charges.create({
        amount: amount,
        currency: 'usd',
        source: 'tok_visa'
    });

    // Also make direct HTTP calls
    const response = await fetch('https://api.github.com/user/repos');
    const paypalResponse = await axios.post('https://api.paypal.com/v1/payments/payment');

    return charge;
}

async function sendSMS(phone, message) {
    return twilio.messages.create({
        body: message,
        to: phone,
        from: '+1234567890'
    });
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "external.js")

        # Should detect multiple external APIs
        external_entities = set(components.external_entities)

        assert any("Stripe" in entity for entity in external_entities)
        assert any("Twilio" in entity for entity in external_entities)
        assert any("SendGrid" in entity for entity in external_entities)
        assert any("GitHub" in entity for entity in external_entities)
        assert any(
            "PayPal" in entity or "Paypal" in entity for entity in external_entities
        )

    def test_file_operations_detection(self):
        """Test detection of file system operations."""
        code = """
const fs = require('fs');
const path = require('path');
import { promises as fsPromises } from 'fs';

async function readConfig() {
    const data = await fsPromises.readFile('config.json', 'utf8');
    return JSON.parse(data);
}

function writeLog(message) {
    fs.appendFileSync('app.log', message + '\\n');
}

const stream = fs.createReadStream('large-file.csv');
stream.on('data', (chunk) => {
    process(chunk);
});
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "files.js")

        # Should detect file system as data store
        assert "File System" in components.data_stores

        # Should have data flow to file system
        assert any(flow.target == "File System" for flow in components.data_flows)

    def test_mixed_import_styles(self):
        """Test handling of mixed ES6 and CommonJS imports."""
        code = """
// ES6 imports
import express from 'express';
import { MongoClient } from 'mongodb';
import type { Request, Response } from 'express';

// CommonJS requires
const redis = require('redis');
const { Pool } = require('pg');

// Dynamic imports
async function loadStripe() {
    const stripe = await import('stripe');
    return stripe;
}

// Mixed usage
const app = express();
const client = redis.createClient();
const pool = new Pool();
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "mixed.ts")

        # Should handle all import styles
        assert any("Express" in process for process in components.processes)
        assert any("MongoDB" in store for store in components.data_stores)
        assert any("Redis" in store for store in components.data_stores)
        assert any(
            "PostgreSQL" in store or "SQL" in store for store in components.data_stores
        )

    def test_web_framework_detection(self):
        """Test detection of various web frameworks."""
        frameworks_code = {
            "fastify": """
const fastify = require('fastify')();
fastify.get('/hello', async (request, reply) => {
    return { hello: 'world' };
});
""",
            "koa": """
const Koa = require('koa');
const Router = require('@koa/router');
const app = new Koa();
const router = new Router();
router.get('/users', ctx => {
    ctx.body = 'Users';
});
""",
            "hapi": """
const Hapi = require('@hapi/hapi');
const server = Hapi.server({ port: 3000 });
server.route({
    method: 'GET',
    path: '/',
    handler: (request, h) => 'Hello World!'
});
""",
        }

        for framework, code in frameworks_code.items():
            extractor = JavaScriptExtractor()
            components = extractor.extract_components(code, f"{framework}.js")

            # Should detect the framework
            assert len(components.processes) > 0
            assert any(
                framework.title() in process or "Node.js" in process
                for process in components.processes
            )

    def test_data_flow_creation(self):
        """Test that appropriate data flows are created."""
        code = """
const express = require('express');
const mongoose = require('mongoose');
const redis = require('redis');
const axios = require('axios');

const app = express();
const cache = redis.createClient();

mongoose.connect('mongodb://localhost/myapp');

app.get('/api/data/:id', async (req, res) => {
    // Check cache first
    const cached = await cache.get(req.params.id);
    if (cached) return res.json(JSON.parse(cached));

    // Get from database
    const data = await DataModel.findById(req.params.id);

    // Get additional info from external API
    const extra = await axios.get('https://api.external.com/info/' + req.params.id);

    // Cache the result
    await cache.set(req.params.id, JSON.stringify(data));

    res.json({ data, extra: extra.data });
});
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "dataflow.js")

        # Check data flows exist
        flows = components.data_flows
        assert len(flows) > 0

        # Should have flows between components
        flow_pairs = {(flow.source, flow.target) for flow in flows}

        # Web User -> Express App
        assert any(
            "Web User" in pair[0] and ("Express" in pair[1] or "Node.js" in pair[1])
            for pair in flow_pairs
        )

        # Process -> External API
        assert any(
            ("Express" in pair[0] or "Node.js" in pair[0]) and "API" in pair[1]
            for pair in flow_pairs
        )

        # Verify data stores were detected
        assert "MongoDB" in components.data_stores
        assert "Redis" in components.data_stores

    def test_empty_file_handling(self):
        """Test handling of empty or minimal files."""
        empty_cases = [
            "",  # Empty file
            "// Just comments",  # Only comments
            "console.log('Hello');",  # No imports or components
        ]

        for code in empty_cases:
            extractor = JavaScriptExtractor()
            components = extractor.extract_components(code, "empty.js")

            # Should return valid but minimal components
            assert components is not None
            assert isinstance(components.processes, list)
            assert isinstance(components.data_stores, list)
            assert isinstance(components.external_entities, list)

    def test_supported_extensions(self):
        """Test that all JavaScript/TypeScript extensions are supported."""
        extractor = JavaScriptExtractor()
        extensions = extractor.get_supported_extensions()

        # Should support common JS/TS extensions
        expected = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
        assert extensions == expected

    def test_can_extract(self):
        """Test file extension checking."""
        extractor = JavaScriptExtractor()

        # Should accept JS/TS files
        assert extractor.can_extract("app.js")
        assert extractor.can_extract("component.tsx")
        assert extractor.can_extract("module.mjs")
        assert extractor.can_extract("test.ts")

        # Should reject non-JS/TS files
        assert not extractor.can_extract("app.py")
        assert not extractor.can_extract("styles.css")
        assert not extractor.can_extract("data.json")

    def test_aws_and_dynamodb_extraction(self):
        """Test extraction of AWS services and DynamoDB with ElectroDB."""
        code = """
import { Entity } from 'electrodb';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';

// DynamoDB setup
const ddbClient = new DynamoDBClient({ region: 'us-east-1' });
const docClient = DynamoDBDocumentClient.from(ddbClient);

// S3 setup
const s3Client = new S3Client({ region: 'us-east-1' });

// ElectroDB entity
const UserEntity = new Entity({
    model: {
        entity: "User",
        service: "UserService",
        version: "1"
    },
    attributes: {
        userId: { type: "string" },
        email: { type: "string" },
        createdAt: { type: "string" }
    },
    indexes: {
        primary: {
            pk: { field: "pk", composite: ["userId"] },
            sk: { field: "sk", composite: [] }
        }
    }
});

async function createUser(userData) {
    // Store in DynamoDB via ElectroDB
    const user = await UserEntity.put(userData).go();

    // Upload profile picture to S3
    if (userData.profilePicture) {
        await s3Client.send(new PutObjectCommand({
            Bucket: 'user-profiles',
            Key: `${userData.userId}/profile.jpg`,
            Body: userData.profilePicture
        }));
    }

    // Trigger Lambda function
    const lambda = new LambdaClient({ region: 'us-east-1' });
    await lambda.send(new InvokeCommand({
        FunctionName: 'ProcessNewUser',
        Payload: JSON.stringify({ userId: userData.userId })
    }));

    return user;
}
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "aws-app.ts")

        # Should detect DynamoDB
        assert "DynamoDB" in components.data_stores

        # Should detect AWS services
        assert any("S3" in entity for entity in components.external_entities)
        assert any("Lambda" in entity for entity in components.external_entities)
        assert any(
            "Secrets Manager" in entity for entity in components.external_entities
        )

        # Should have data flows
        assert len(components.data_flows) > 0

        # Should detect process
        assert len(components.processes) > 0

    def test_fp_ts_io_ts_extraction(self):
        """Test extraction of fp-ts and io-ts functional programming libraries."""
        code = """
import * as E from 'fp-ts/Either';
import * as TE from 'fp-ts/TaskEither';
import * as O from 'fp-ts/Option';
import { pipe } from 'fp-ts/function';
import * as t from 'io-ts';
import { PathReporter } from 'io-ts/PathReporter';
import axios from 'axios';
import { MongoClient } from 'mongodb';

// io-ts schema validation
const UserSchema = t.type({
    id: t.string,
    email: t.string,
    age: t.number,
    roles: t.array(t.string)
});

type User = t.TypeOf<typeof UserSchema>;

// MongoDB connection wrapped in TaskEither
const connectDB = (): TE.TaskEither<Error, MongoClient> =>
    TE.tryCatch(
        () => new MongoClient('mongodb://localhost:27017').connect(),
        (reason) => new Error(String(reason))
    );

// Fetch user from external API with validation
const fetchUser = (userId: string): TE.TaskEither<Error, User> =>
    pipe(
        TE.tryCatch(
            () => axios.get(`https://api.example.com/users/${userId}`),
            (e) => new Error(String(e))
        ),
        TE.map((response) => response.data),
        TE.chain((data) =>
            pipe(
                UserSchema.decode(data),
                E.mapLeft((errors) => new Error(PathReporter.report(E.left(errors)).join('\\n'))),
                TE.fromEither
            )
        )
    );

// Store user in database
const storeUser = (client: MongoClient) => (user: User): TE.TaskEither<Error, void> =>
    TE.tryCatch(
        async () => {
            const db = client.db('myapp');
            await db.collection('users').insertOne(user);
        },
        (e) => new Error(String(e))
    );

// Main pipeline
const processUser = (userId: string) =>
    pipe(
        TE.Do,
        TE.bind('client', () => connectDB()),
        TE.bind('user', () => fetchUser(userId)),
        TE.chain(({ client, user }) => storeUser(client)(user))
    );
"""
        extractor = JavaScriptExtractor()
        components = extractor.extract_components(code, "fp-app.ts")

        # Should detect MongoDB
        assert "MongoDB" in components.data_stores

        # Should detect external API
        assert any("API" in entity for entity in components.external_entities)

        # Should have processes implied by data flows (data flows indicate a process exists)
        assert len(components.data_flows) > 0
        process_names_in_flows = {flow.source for flow in components.data_flows}
        assert len(process_names_in_flows) > 0

        # Should have data flows
        assert len(components.data_flows) > 0

        # Should not misinterpret fp-ts/io-ts imports as external services
        assert not any("Fp-Ts" in entity for entity in components.external_entities)
        assert not any("Io-Ts" in entity for entity in components.external_entities)
