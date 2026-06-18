from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import ai, alerts, assets, auth, health, risk, vulnerabilities

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(risk.router, prefix="/risk", tags=["risk"])
api_router.include_router(alerts.router, prefix="/monitoring", tags=["monitoring"])
api_router.include_router(ai.router, prefix="/ai", tags=["ai"])
