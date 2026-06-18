from __future__ import annotations

import secrets
from typing import Any, List, Optional
from pydantic import AnyHttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = secrets.token_urlsafe(64)
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "CyberPlatform"

    # ── CORS ──────────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+psycopg://postgres:postgres@localhost:5432/cyberplatform"

    @property
    def async_database_url(self) -> str:
        return self.DATABASE_URL.replace("postgresql+psycopg://", "postgresql+psycopg://", 1)

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT ───────────────────────────────────────────────────────────────────
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # ── Celery ────────────────────────────────────────────────────────────────
    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""

    @model_validator(mode="after")
    def set_celery_urls(self) -> "Settings":
        if not self.CELERY_BROKER_URL:
            self.CELERY_BROKER_URL = self.REDIS_URL
        if not self.CELERY_RESULT_BACKEND:
            self.CELERY_RESULT_BACKEND = self.REDIS_URL
        return self

    # ── Elasticsearch ─────────────────────────────────────────────────────────
    ELASTICSEARCH_URL: Optional[str] = None
    ELASTICSEARCH_API_KEY: Optional[str] = None

    # ── Kafka ─────────────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: Optional[str] = None
    KAFKA_SECURITY_PROTOCOL: str = "PLAINTEXT"

    # ── Anthropic ─────────────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"
    ANTHROPIC_MAX_TOKENS: int = 1000

    # ── Pagination ────────────────────────────────────────────────────────────
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 500

    # ── Risk Scoring Defaults ─────────────────────────────────────────────────
    RISK_VULN_WEIGHT: float = 0.35
    RISK_EXPOSURE_WEIGHT: float = 0.25
    RISK_BUSINESS_WEIGHT: float = 0.20
    RISK_POSTURE_WEIGHT: float = 0.15
    RISK_BLAST_RADIUS_WEIGHT: float = 0.05

    # ── NVD / EPSS / KEV sync ─────────────────────────────────────────────────
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_SYNC_INTERVAL_HOURS: int = 2

    # ── Feature Flags ─────────────────────────────────────────────────────────
    ENABLE_AI_FEATURES: bool = True
    ENABLE_KAFKA: bool = False
    ENABLE_ELASTICSEARCH: bool = False


settings = Settings()
