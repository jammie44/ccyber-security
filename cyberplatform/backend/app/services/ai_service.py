from __future__ import annotations

import re
import uuid
from typing import Optional

import httpx
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"dd\s+if=",
    r"mkfs\.",
    r">\s*/dev/[sh]d",
    r"chmod\s+-R\s+777\s+/",
    r"DROP\s+TABLE",
    r"DROP\s+DATABASE",
    r"wget.*\|.*sh",
    r"curl.*\|.*sh",
]


def validate_output(text: str) -> bool:
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return False
    if len(text) > 10000:
        return False
    return True


def safe_wrap_input(user_text: str, max_length: int = 500) -> str:
    truncated = user_text[:max_length]
    cleaned = truncated.replace("</user_input>", "[TAG_STRIPPED]")
    return f"<user_input>{cleaned}</user_input>"


class AIService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _call_claude(self, prompt: str, max_tokens: int = 300) -> str:
        if not settings.ANTHROPIC_API_KEY:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI features are not configured for this deployment",
            )
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": settings.ANTHROPIC_MODEL,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            response.raise_for_status()
            data = response.json()
            text = "".join(block.get("text", "") for block in data.get("content", []))
            return text.strip()

    async def explain_risk_score(
        self,
        asset_name: str,
        asset_type: str,
        risk_score: float,
        risk_band: str,
        top_drivers: list[str],
        requesting_role: str = "security_manager",
    ) -> str:
        audience_guidance = {
            "executive": "Write for a C-suite executive. Business impact language, no jargon. Max 80 words.",
            "security_manager": "Write for a security manager. Mix business and technical detail with 2 next actions. Max 120 words.",
            "analyst": "Write for a security analyst with technical specifics and 3 next actions. Max 150 words.",
            "asset_owner": "Write for a non-security asset owner. State exactly what they need to do. Max 100 words.",
        }
        drivers_text = "\n".join(f"- {d}" for d in top_drivers) or "No specific drivers recorded."
        prompt = f"""Explain why {asset_name} ({asset_type}) has a risk score of {risk_score:.0f}/100 ({risk_band} risk).

Top risk contributors:
{drivers_text}

{audience_guidance.get(requesting_role, audience_guidance["security_manager"])}
"""
        try:
            text = await self._call_claude(prompt, max_tokens=300)
        except Exception:
            return self._fallback_explanation(asset_name, risk_score, risk_band, top_drivers)

        if not validate_output(text):
            return self._fallback_explanation(asset_name, risk_score, risk_band, top_drivers)
        return text

    def _fallback_explanation(self, asset_name: str, risk_score: float, risk_band: str, top_drivers: list[str]) -> str:
        base = f"{asset_name} has a {risk_band} risk score of {risk_score:.0f}/100."
        if top_drivers:
            base += f" Primary concern: {top_drivers[0]}."
        return base
