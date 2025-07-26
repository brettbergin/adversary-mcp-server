"""Tests for enhanced Python code extractor."""

import os
import sys

# Add the src directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from adversary_mcp_server.threat_modeling.extractors.python_extractor import (
    PythonExtractor,
)


class TestEnhancedPythonExtractor:
    """Test enhanced Python code extractor with AWS and modern patterns."""

    def test_aws_services_extraction(self):
        """Test extraction of AWS services using boto3."""
        code = """
import boto3
from botocore.exceptions import ClientError

# Create AWS service clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
lambda_client = boto3.client('lambda')
sqs = boto3.client('sqs')
sns = boto3.client('sns')
secrets_manager = boto3.client('secretsmanager')

def upload_file_to_s3(filename, bucket):
    try:
        s3_client.upload_file(filename, bucket, filename)
        return True
    except ClientError as e:
        print(f"Error uploading to S3: {e}")
        return False

def get_item_from_dynamodb(table_name, key):
    table = dynamodb.Table(table_name)
    response = table.get_item(Key=key)
    return response.get('Item')

def invoke_lambda(function_name, payload):
    response = lambda_client.invoke(
        FunctionName=function_name,
        Payload=payload
    )
    return response

def send_sqs_message(queue_url, message):
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=message
    )
"""
        extractor = PythonExtractor()
        components = extractor.extract_components(code, "aws_services.py")

        # Should detect multiple AWS services
        external_entities = set(components.external_entities)
        data_stores = set(components.data_stores)

        # S3 should be external entity
        assert any("S3" in entity for entity in external_entities)

        # DynamoDB should be data store
        assert any("DynamoDB" in store for store in data_stores)

        # Lambda, SQS, SNS, Secrets Manager should be external entities
        assert any("Lambda" in entity for entity in external_entities)
        assert any("SQS" in entity for entity in external_entities)
        assert any("SNS" in entity for entity in external_entities)
        assert any("Secrets Manager" in entity for entity in external_entities)

        # Should have data flows
        assert len(components.data_flows) > 0

    def test_modern_web_frameworks(self):
        """Test detection of modern Python web frameworks."""
        frameworks_code = {
            "fastapi": """
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    name: str
    email: str

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"user_id": user_id}

@app.post("/users")
async def create_user(user: User):
    return user
""",
            "sanic": """
from sanic import Sanic, response
from sanic.request import Request

app = Sanic("MyApp")

@app.route("/")
async def hello(request: Request):
    return response.json({"message": "Hello world"})

@app.route("/users/<user_id>", methods=["GET"])
async def get_user(request: Request, user_id: str):
    return response.json({"user_id": user_id})
""",
            "aiohttp": """
from aiohttp import web, ClientSession
import asyncio

async def hello(request):
    return web.json_response({"message": "Hello"})

async def fetch_data(request):
    async with ClientSession() as session:
        async with session.get('https://api.example.com/data') as resp:
            data = await resp.json()
            return web.json_response(data)

app = web.Application()
app.router.add_get('/', hello)
app.router.add_get('/data', fetch_data)
""",
        }

        for framework, code in frameworks_code.items():
            extractor = PythonExtractor()
            components = extractor.extract_components(code, f"{framework}_app.py")

            # Should detect the framework as a process
            # The process names follow the pattern "{Framework} App"
            expected_names = {
                "fastapi": "FastAPI App",
                "sanic": "Sanic App",
                "aiohttp": "AIOHTTP App",
            }
            expected_name = expected_names[framework]
            assert (
                expected_name in components.processes
            ), f"Failed to detect {framework}. Found processes: {components.processes}"

    def test_async_database_libraries(self):
        """Test detection of async database libraries."""
        code = """
import asyncpg
import aiomysql
import aiosqlite
import aioredis
from motor.motor_asyncio import AsyncIOMotorClient

async def setup_databases():
    # PostgreSQL with asyncpg
    pg_conn = await asyncpg.connect('postgresql://user:pass@localhost/db')

    # MySQL with aiomysql
    mysql_conn = await aiomysql.connect(
        host='localhost', port=3306,
        user='root', password='', db='mysql'
    )

    # SQLite with aiosqlite
    sqlite_conn = await aiosqlite.connect('database.db')

    # Redis with aioredis
    redis = await aioredis.create_redis_pool('redis://localhost')

    # MongoDB with motor
    mongo_client = AsyncIOMotorClient('mongodb://localhost:27017')

    return pg_conn, mysql_conn, sqlite_conn, redis, mongo_client

async def query_data():
    pg_conn, mysql_conn, sqlite_conn, redis, mongo_client = await setup_databases()

    # PostgreSQL query
    rows = await pg_conn.fetch('SELECT * FROM users')

    # MySQL query
    async with mysql_conn.cursor() as cursor:
        await cursor.execute('SELECT * FROM products')
        result = await cursor.fetchall()

    # SQLite query
    async with sqlite_conn.execute('SELECT * FROM orders') as cursor:
        data = await cursor.fetchall()

    # Redis operations
    await redis.set('key', 'value')
    value = await redis.get('key')

    # MongoDB operations
    db = mongo_client.mydatabase
    collection = db.mycollection
    document = await collection.find_one({'_id': 'test'})

    return rows, result, data, value, document
"""
        extractor = PythonExtractor()
        components = extractor.extract_components(code, "async_db.py")

        # Should detect multiple database types
        data_stores = set(components.data_stores)

        assert any("PostgreSQL" in store for store in data_stores)
        assert any("MySQL" in store for store in data_stores)
        assert any("SQLite" in store for store in data_stores)
        assert any("Redis" in store for store in data_stores)
        assert any("MongoDB" in store for store in data_stores)

    def test_modern_http_clients(self):
        """Test detection of modern HTTP client libraries."""
        code = """
import httpx
import aiohttp
import requests
from urllib.request import urlopen

async def fetch_with_httpx():
    async with httpx.AsyncClient() as client:
        response = await client.get('https://api.github.com/users/octocat')
        return response.json()

async def fetch_with_aiohttp():
    async with aiohttp.ClientSession() as session:
        async with session.get('https://api.stripe.com/v1/customers') as resp:
            return await resp.json()

def fetch_with_requests():
    response = requests.get('https://api.twilio.com/2010-04-01/Accounts')
    return response.json()

def fetch_with_urllib():
    with urlopen('https://api.sendgrid.com/v3/mail') as response:
        return response.read()
"""
        extractor = PythonExtractor()
        components = extractor.extract_components(code, "http_clients.py")

        # Should detect external APIs based on URL patterns
        external_entities = set(components.external_entities)
        assert any(
            "GitHub" in entity for entity in external_entities
        ), f"GitHub not found in {external_entities}"
        assert any(
            "Stripe" in entity for entity in external_entities
        ), f"Stripe not found in {external_entities}"
        assert any(
            "Twilio" in entity for entity in external_entities
        ), f"Twilio not found in {external_entities}"
        assert any(
            "SendGrid" in entity for entity in external_entities
        ), f"SendGrid not found in {external_entities}"

        # Should have data flows
        assert len(components.data_flows) > 0

    def test_ai_and_modern_apis(self):
        """Test detection of AI and modern API services."""
        code = """
import openai
import anthropic
from slack_sdk import WebClient
from slack_bolt import App
import tweepy

# OpenAI API
openai.api_key = "your-api-key"

def generate_text(prompt):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

# Anthropic Claude API
client = anthropic.Anthropic(api_key="your-api-key")

def claude_completion(prompt):
    message = client.messages.create(
        model="claude-3-sonnet-20240229",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content

# Slack API
slack_client = WebClient(token="your-token")
slack_app = App(token="your-token")

def send_slack_message(channel, text):
    result = slack_client.chat_postMessage(
        channel=channel,
        text=text
    )
    return result

# Twitter API
auth = tweepy.OAuth1UserHandler(
    consumer_key="key",
    consumer_secret="secret",
    access_token="token",
    access_token_secret="secret"
)
twitter_api = tweepy.API(auth)

def post_tweet(text):
    tweet = twitter_api.update_status(text)
    return tweet
"""
        extractor = PythonExtractor()
        components = extractor.extract_components(code, "ai_apis.py")

        # Should detect AI and social media APIs
        external_entities = set(components.external_entities)

        assert any("OpenAI" in entity for entity in external_entities)
        assert any("Anthropic" in entity for entity in external_entities)
        assert any("Slack" in entity for entity in external_entities)
        assert any("Twitter" in entity for entity in external_entities)

    def test_comprehensive_django_app(self):
        """Test comprehensive Django application with multiple components."""
        code = """
from django.db import models
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import boto3
import redis
import requests
from celery import shared_task

# Models
class User(models.Model):
    username = models.CharField(max_length=100)
    email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)

class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    total = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

# AWS services
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

# Redis cache
cache = redis.Redis(host='localhost', port=6379, db=0)

# Views
@require_http_methods(["GET"])
def get_user(request, user_id):
    try:
        user = User.objects.get(id=user_id)

        # Cache user data
        cache.set(f"user:{user_id}", user.username, ex=3600)

        # Log to DynamoDB
        table = dynamodb.Table('user_logs')
        table.put_item(Item={
            'user_id': str(user_id),
            'action': 'get_user',
            'timestamp': str(user.created_at)
        })

        return JsonResponse({
            'id': user.id,
            'username': user.username,
            'email': user.email
        })
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

@csrf_exempt
@require_http_methods(["POST"])
def process_payment(request):
    # Process payment with Stripe
    stripe_response = requests.post(
        'https://api.stripe.com/v1/charges',
        headers={'Authorization': 'Bearer sk_test_...'},
        data={'amount': 2000, 'currency': 'usd'}
    )

    if stripe_response.status_code == 200:
        # Upload receipt to S3
        s3_client.put_object(
            Bucket='receipts',
            Key=f'receipt_{request.user.id}.pdf',
            Body=b'receipt data'
        )

        # Send confirmation email via Celery task
        send_confirmation_email.delay(request.user.email)

        return JsonResponse({'status': 'success'})

    return JsonResponse({'status': 'failed'}, status=400)

@shared_task
def send_confirmation_email(email):
    # Send email via SendGrid
    response = requests.post(
        'https://api.sendgrid.com/v3/mail/send',
        headers={'Authorization': 'Bearer SG.your-api-key'},
        json={
            'personalizations': [{'to': [{'email': email}]}],
            'from': {'email': 'noreply@example.com'},
            'subject': 'Payment Confirmation',
            'content': [{'type': 'text/plain', 'value': 'Thank you for your payment!'}]
        }
    )
    return response.status_code == 202
"""
        extractor = PythonExtractor()
        components = extractor.extract_components(code, "django_ecommerce.py")

        # Should detect Django app
        assert any(
            "Django" in process for process in components.processes
        ), f"Django not found in processes: {components.processes}"

        # Should detect multiple data stores
        data_stores = set(components.data_stores)
        assert any(
            "Django Database" in store or "SQL" in store for store in data_stores
        )
        assert any("Redis" in store for store in data_stores)
        assert any("DynamoDB" in store for store in data_stores)

        # Should detect external APIs
        external_entities = set(components.external_entities)
        assert any("AWS S3" in entity for entity in external_entities)
        assert any("Stripe" in entity for entity in external_entities)
        assert any("SendGrid" in entity for entity in external_entities)

        # Should have multiple data flows
        assert len(components.data_flows) >= 3

    def test_modern_orm_libraries(self):
        """Test detection of modern ORM libraries."""
        code = """
from peewee import *
from tortoise.models import Model
from tortoise import fields
import asyncio

# Peewee ORM
db = SqliteDatabase('my_app.db')

class User(Model):
    username = CharField()
    email = CharField()

    class Meta:
        database = db

class Order(Model):
    user = ForeignKeyField(User, backref='orders')
    total = DecimalField()

    class Meta:
        database = db

# Tortoise ORM
class TortoiseUser(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50)
    email = fields.CharField(max_length=120)

class TortoiseOrder(Model):
    id = fields.IntField(pk=True)
    user = fields.ForeignKeyField('models.TortoiseUser', related_name='orders')
    total = fields.DecimalField(max_digits=10, decimal_places=2)

async def setup_tortoise():
    from tortoise import Tortoise
    await Tortoise.init(
        db_url='sqlite://db.sqlite3',
        modules={'models': ['myapp.models']}
    )
    await Tortoise.generate_schemas()

def create_user_peewee(username, email):
    user = User.create(username=username, email=email)
    return user

async def create_user_tortoise(username, email):
    user = await TortoiseUser.create(username=username, email=email)
    return user
"""
        extractor = PythonExtractor()
        components = extractor.extract_components(code, "modern_orms.py")

        # Should detect SQL databases through ORM libraries
        data_stores = set(components.data_stores)
        assert any("SQL Database" in store for store in data_stores)

    def test_supported_extensions(self):
        """Test that Python file extensions are supported."""
        extractor = PythonExtractor()
        extensions = extractor.get_supported_extensions()

        # Should support Python file extensions
        expected = {".py", ".pyw", ".pyx"}
        assert extensions == expected

    def test_can_extract(self):
        """Test file extension checking."""
        extractor = PythonExtractor()

        # Should accept Python files
        assert extractor.can_extract("app.py")
        assert extractor.can_extract("module.pyw")
        assert extractor.can_extract("extension.pyx")

        # Should reject non-Python files
        assert not extractor.can_extract("app.js")
        assert not extractor.can_extract("styles.css")
        assert not extractor.can_extract("data.json")
