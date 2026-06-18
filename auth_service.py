from __future__ import annotations

import uuid
from pydantic import BaseModel, Field


class ExplainRiskRequest(BaseModel):
    asset_id: uuid.UUID
    requesting_role: str = Field(default="security_manager")


class ExplainResponse(BaseModel):
    explanation: str
    cached: bool = False
