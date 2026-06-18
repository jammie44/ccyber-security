import asyncio
import os
import sys
import uuid
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@localhost:5432/cyberplatform_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("ENVIRONMENT", "test")


def _postgres_available() -> bool:
    try:
        import psycopg

        conn = psycopg.connect(
            os.environ["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://"),
            connect_timeout=2,
        )
        conn.close()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(
    not _postgres_available(),
    reason="PostgreSQL test database not reachable at DATABASE_URL — skipping integration test",
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:10]}@example.com"
