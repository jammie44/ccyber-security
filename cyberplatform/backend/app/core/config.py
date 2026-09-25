from __future__ import annotations

import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberPlatform API"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    DATABASE_URL: str = ""
    REDIS_URL: str = "redis://localhost:6379/0"

    SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    ENABLE_AI_FEATURES: bool = False
    ENABLE_KAFKA: bool = False
    ENABLE_ELASTICSEARCH: bool = False
    DEBUG: bool = False

    ANTHROPIC_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None

    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM_EMAIL: Optional[str] = None
    PLATFORM_DASHBOARD_URL: str = "https://cyberplatform-web.onrender.com/dashboard"

    @property
    def cors_origins(self) -> list[str]:
        origins = []
        for origin in self.ALLOWED_ORIGINS.split(","):
            cleaned = origin.strip().rstrip("/")
            if cleaned:
                origins.append(cleaned)
        return origins

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
