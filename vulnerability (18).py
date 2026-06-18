from __future__ import annotations

import uuid
from typing import Optional, Sequence

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.repositories.base import BaseRepository


class AssetRepository(BaseRepository[Asset]):
    model = Asset

    async def search(
        self,
        tenant_id: uuid.UUID,
        *,
        q: Optional[str] = None,
        asset_type: Optional[list[str]] = None,
        environment: Optional[str] = None,
        status: Optional[str] = None,
        risk_band: Optional[list[str]] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> tuple[Sequence[Asset], int]:
        conditions = [Asset.tenant_id == tenant_id, Asset.is_deleted == False]  # noqa: E712

        if q:
            conditions.append(
                or_(
                    Asset.name.ilike(f"%{q}%"),
                    Asset.fqdn.ilike(f"%{q}%"),
                )
            )
        if asset_type:
            conditions.append(Asset.asset_type.in_(asset_type))
        if environment:
            conditions.append(Asset.environment == environment)
        if status:
            conditions.append(Asset.status == status)
        if risk_band:
            conditions.append(Asset.current_risk_band.in_(risk_band))

        stmt = select(Asset).where(and_(*conditions)).order_by(Asset.created_at.desc())
        count_stmt = select(func.count()).select_from(Asset).where(and_(*conditions))

        stmt = stmt.offset((page - 1) * per_page).limit(per_page)

        result = await self.db.execute(stmt)
        items = result.scalars().all()

        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar_one()

        return items, total

    async def get_summary(self, tenant_id: uuid.UUID) -> dict:
        base = select(Asset).where(Asset.tenant_id == tenant_id, Asset.is_deleted == False)  # noqa: E712

        total = (await self.db.execute(
            select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant_id, Asset.is_deleted == False)  # noqa: E712
        )).scalar_one()

        active = (await self.db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.tenant_id == tenant_id, Asset.is_deleted == False, Asset.status == "active"  # noqa: E712
            )
        )).scalar_one()

        critical_risk = (await self.db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.tenant_id == tenant_id, Asset.is_deleted == False, Asset.current_risk_band == "critical"  # noqa: E712
            )
        )).scalar_one()

        high_risk = (await self.db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.tenant_id == tenant_id, Asset.is_deleted == False, Asset.current_risk_band == "high"  # noqa: E712
            )
        )).scalar_one()

        internet_facing = (await self.db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.tenant_id == tenant_id, Asset.is_deleted == False, Asset.is_internet_facing == True  # noqa: E712
            )
        )).scalar_one()

        never_scanned = (await self.db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.tenant_id == tenant_id, Asset.is_deleted == False, Asset.last_scan_date.is_(None)  # noqa: E712
            )
        )).scalar_one()

        type_rows = (await self.db.execute(
            select(Asset.asset_type, func.count()).where(
                Asset.tenant_id == tenant_id, Asset.is_deleted == False  # noqa: E712
            ).group_by(Asset.asset_type)
        )).all()

        env_rows = (await self.db.execute(
            select(Asset.environment, func.count()).where(
                Asset.tenant_id == tenant_id, Asset.is_deleted == False  # noqa: E712
            ).group_by(Asset.environment)
        )).all()

        return {
            "total": total,
            "active": active,
            "critical_risk": critical_risk,
            "high_risk": high_risk,
            "internet_facing": internet_facing,
            "never_scanned": never_scanned,
            "by_type": {row[0]: row[1] for row in type_rows},
            "by_environment": {row[0]: row[1] for row in env_rows},
        }
