from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

# Celery tasks run synchronously; use the sync psycopg driver variant
_sync_url = settings.DATABASE_URL.replace("postgresql+psycopg://", "postgresql+psycopg://")

sync_engine = create_engine(_sync_url, pool_pre_ping=True, pool_size=5, max_overflow=10)
SyncSessionLocal = sessionmaker(bind=sync_engine, autoflush=False, autocommit=False)


def get_sync_db() -> Session:
    db = SyncSessionLocal()
    try:
        return db
    finally:
        pass
