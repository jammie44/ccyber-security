from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vulnerability import AssetVulnerability, CVERecord
from app.repositories.base import BaseRepository


class VulnerabilityRepository(BaseRepository[AssetVulnerability]):
    model = AssetVulnerability

    OPEN_STATUSES = ["discovered", "triaged", "assigned", "in_remediation", "pending_verification"]

    async def search(
        self,
        tenant_id: uuid.UUID,
        *,
        status: Optional[list[str]] = None,
        priority: Optional[list[str]] = None,
        asset_id: Optional[uuid.UUID] = None,
        sla_status: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> tuple[Sequence[AssetVulnerability], int]:
        conditions = [AssetVulnerability.tenant_id == tenant_id]
        if status:
            conditions.append(AssetVulnerability.status.in_(status))
        if priority:
            conditions.append(AssetVulnerability.priority.in_(priority))
        if asset_id:
            conditions.append(AssetVulnerability.asset_id == asset_id)
        if sla_status:
            conditions.append(AssetVulnerability.sla_status == sla_status)

        stmt = (
            select(AssetVulnerability)
            .where(and_(*conditions))
            .order_by(AssetVulnerability.created_at.desc())
        )
        count_stmt = select(func.count()).select_from(AssetVulnerability).where(and_(*conditions))

        stmt = stmt.offset((page - 1) * per_page).limit(per_page)

        result = await self.db.execute(stmt)
        items = result.scalars().all()
        total = (await self.db.execute(count_stmt)).scalar_one()
        return items, total

    async def get_summary(self, tenant_id: uuid.UUID) -> dict:
        def count_where(*extra):
            return select(func.count()).select_from(AssetVulnerability).where(
                AssetVulnerability.tenant_id == tenant_id,
                AssetVulnerability.status.in_(self.OPEN_STATUSES),
                *extra,
            )

        open_critical = (await self.db.execute(count_where(AssetVulnerability.priority == "critical"))).scalar_one()
        open_high = (await self.db.execute(count_where(AssetVulnerability.priority == "high"))).scalar_one()
        open_medium = (await self.db.execute(count_where(AssetVulnerability.priority == "medium"))).scalar_one()
        open_low = (await self.db.execute(count_where(AssetVulnerability.priority == "low"))).scalar_one()

        sla_breached_critical = (await self.db.execute(
            count_where(AssetVulnerability.priority == "critical", AssetVulnerability.sla_status == "breached")
        )).scalar_one()
        sla_breached_high = (await self.db.execute(
            count_where(AssetVulnerability.priority == "high", AssetVulnerability.sla_status == "breached")
        )).scalar_one()

        total_open = (await self.db.execute(count_where())).scalar_one()

        # KEV / exploit counts require join to CVE table
        kev_stmt = (
            select(func.count())
            .select_from(AssetVulnerability)
            .join(CVERecord, AssetVulnerability.cve_id_fk == CVERecord.id)
            .where(
                AssetVulnerability.tenant_id == tenant_id,
                AssetVulnerability.status.in_(self.OPEN_STATUSES),
                CVERecord.is_in_kev == True,  # noqa: E712
            )
        )
        kev_count = (await self.db.execute(kev_stmt)).scalar_one()

        exploit_stmt = (
            select(func.count())
            .select_from(AssetVulnerability)
            .join(CVERecord, AssetVulnerability.cve_id_fk == CVERecord.id)
            .where(
                AssetVulnerability.tenant_id == tenant_id,
                AssetVulnerability.status.in_(self.OPEN_STATUSES),
                CVERecord.has_public_exploit == True,  # noqa: E712
            )
        )
        exploit_available = (await self.db.execute(exploit_stmt)).scalar_one()

        seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        delta_stmt = count_where(
            AssetVulnerability.priority == "critical",
            AssetVulnerability.created_at >= seven_days_ago,
        )
        delta_7d_critical = (await self.db.execute(delta_stmt)).scalar_one()

        return {
            "open_critical": open_critical,
            "open_high": open_high,
            "open_medium": open_medium,
            "open_low": open_low,
            "kev_count": kev_count,
            "exploit_available": exploit_available,
            "sla_breached_critical": sla_breached_critical,
            "sla_breached_high": sla_breached_high,
            "delta_7d_critical": delta_7d_critical,
            "total_open": total_open,
        }
