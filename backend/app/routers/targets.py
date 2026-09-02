from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid
from ..database import get_db
from ..models import Target
from ..schemas import TargetCreate, TargetOut
from ..routers.auth import get_current_user

router = APIRouter(prefix="/engagements/{engagement_id}/targets", tags=["targets"])

@router.get("", response_model=list[TargetOut])
async def list_targets(engagement_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Target).where(Target.engagement_id == engagement_id).order_by(Target.created_at))
    return res.scalars().all()

@router.post("", response_model=TargetOut)
async def create_target(engagement_id: uuid.UUID, body: TargetCreate, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    tgt = Target(engagement_id=engagement_id, ip=body.ip, hostname=body.hostname, os_fingerprint=body.os_fingerprint, ports=body.ports, discovered_in_phase=body.discovered_in_phase)
    db.add(tgt)
    await db.commit()
    await db.refresh(tgt)
    return tgt
