# Runs before any test file is loaded. Gives the app harmless fake settings so
# tests never need your real .env, a real Postgres, or a real Redis.
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
