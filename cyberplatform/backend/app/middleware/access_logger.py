"""
app/middleware/access_logger.py
Writes one AccessAuditLog row per authenticated request.
Never blocks or fails the request — audit logging is best-effort.
"""
from __future__ import annotations

import logging
import uuid as uuid_module
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings

logger = logging.getLogger(__name__)

# Skip logging for these paths to avoid logging noise and self-referential entries
_SKIP_PATHS = {"/api/v1/health", "/", "/api/v1/docs", "/api/v1/redoc", "/api/v1/openapi.json"}


def _decode_token(auth_header: Optional[str]) -> dict:
    """
    Best-effort JWT decode — returns {} on any failure.
    Never raises; middleware must not affect request processing.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        return {}
    token = auth_header.removeprefix("Bearer ").strip()
    if not token:
        return {}
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return {}
    except Exception:
        logger.exception("Unexpected error decoding JWT in access logger")
        return {}


class AccessLoggerMiddleware(BaseHTTPMiddleware):
    """
    Logs every authenticated request to access_audit_log.
    Uses a fresh DB session per request (not the endpoint's session)
    so logging failures never affect the actual endpoint transaction.
    """

    def __init__(self, app: ASGIApp, session_factory):
        super().__init__(app)
        self._session_factory = session_factory

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Skip noisy/unauthenticated paths
        if request.url.path not in _SKIP_PATHS:
            try:
                await self._log_access(request, response)
            except Exception:
                logger.exception(
                    "Access audit logging failed for %s %s",
                    request.method, request.url.path,
                )

        return response

    async def _log_access(self, request: Request, response) -> None:
        from app.models.network_monitor import AccessAuditLog

        payload = _decode_token(request.headers.get("Authorization"))
        tenant_id_str = payload.get("tenant_id")
        user_id_str = payload.get("sub")
        user_role = payload.get("role")

        # Only log authenticated, tenant-scoped requests
        if not tenant_id_str:
            return

        try:
            tenant_id = uuid_module.UUID(tenant_id_str)
            user_id = uuid_module.UUID(user_id_str) if user_id_str else None
        except (ValueError, AttributeError):
            return

        client_host = request.client.host if request.client else None

        try:
            async with self._session_factory() as db:
                log_row = AccessAuditLog(
                    id=uuid_module.uuid4(),
                    tenant_id=tenant_id,
                    user_id=user_id,
                    user_role=user_role,
                    endpoint=str(request.url.path),
                    method=request.method,
                    ip_address=client_host,
                    user_agent=request.headers.get("user-agent", "")[:500],
                    status_code=getattr(response, "status_code", None),
                    accessed_at=datetime.now(timezone.utc),
                )
                db.add(log_row)
                await db.commit()
        except Exception:
            logger.exception("Failed to write access audit log row")
