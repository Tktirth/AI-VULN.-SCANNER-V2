import os
import sys
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database import Base, get_db
import backend.database as database
from backend.main import app

# Mock Redis Client
class MockRedis:
    def __init__(self):
        self.store = {}
        self.ttls = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value
        return True

    def setex(self, key, ttl, value):
        self.store[key] = value
        self.ttls[key] = ttl
        return True

    def ttl(self, key):
        return self.ttls.get(key, 60)

    def incr(self, key):
        val = int(self.store.get(key, 0)) + 1
        self.store[key] = str(val)
        return val

    def expire(self, key, ttl):
        self.ttls[key] = ttl
        return True

    def ping(self):
        return True

    def pipeline(self):
        return self

    def execute(self):
        return []

mock_redis = MockRedis()
database.redis_client = mock_redis

# Set up SQLite engine with StaticPool for in-memory connection sharing
SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Register PostgreSQL functions for SQLite compatibility in tests
@event.listens_for(engine, "connect")
def do_connect(dbapi_connection, connection_record):
    import sqlite3
    if isinstance(dbapi_connection, sqlite3.Connection):
        dbapi_connection.create_function("gen_random_uuid", 0, lambda: str(uuid.uuid4()))
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

@pytest.fixture(name="db_session")
def db_session_fixture():
    """
    Creates tables, yields a session, and drops tables.
    """
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(name="client")
def client_fixture(db_session):
    """
    TestClient that overrides the get_db dependency.
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    # Clear Redis mock state before each test
    mock_redis.store.clear()
    mock_redis.ttls.clear()
    
    with TestClient(app) as test_client:
        yield test_client
        
    app.dependency_overrides.clear()
