from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid
from ..database import get_db
from ..models import Engagement
from ..schemas import EngagementCreate, EngagementOut, EngagementUpdate
from ..killchain_engine import list_phases, get_tools_for_phase
from .auth import get_current_user

router = APIRouter(prefix="/engagements", tags=["engagements"])

@router.get("", response_model=list[EngagementOut])
async def list_engagements(db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Engagement).order_by(Engagement.created_at.desc()))
    return res.scalars().all()

@router.post("", response_model=EngagementOut)
async def create_engagement(body: EngagementCreate, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    eng = Engagement(name=body.name, scope_cidr=body.scope_cidr, authorized_by=body.authorized_by, status="active", current_phase=1)
    db.add(eng)
    await db.commit()
    await db.refresh(eng)
    return eng

@router.get("/{engagement_id}", response_model=EngagementOut)
async def get_engagement(engagement_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    eng = res.scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    return eng

@router.patch("/{engagement_id}", response_model=EngagementOut)
async def update_engagement(engagement_id: uuid.UUID, body: EngagementUpdate, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    eng = res.scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    if body.status is not None:
        eng.status = body.status
    if body.current_phase is not None:
        if not 1 <= body.current_phase <= 18:
            raise HTTPException(400, "phase must be 1..18")
        eng.current_phase = body.current_phase
    await db.commit()
    await db.refresh(eng)
    return eng

@router.delete("/{engagement_id}", status_code=204)
async def delete_engagement(engagement_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    eng = res.scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    await db.delete(eng)
    await db.commit()
    return Response(status_code=204)

@router.delete("", status_code=204)
async def delete_all_engagements(db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    from ..models import Target, Credential, Command, Result, AssetEdge
    await db.execute(AssetEdge.__table__.delete())
    await db.execute(Result.__table__.delete())
    await db.execute(Command.__table__.delete())
    await db.execute(Credential.__table__.delete())
    await db.execute(Target.__table__.delete())
    await db.execute(Engagement.__table__.delete())
    await db.commit()
    return Response(status_code=204)

@router.get("/{engagement_id}/killchain/phases")
async def get_phases(engagement_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    return list_phases()

@router.get("/{engagement_id}/killchain/tools/{phase}")
async def get_tools(engagement_id: uuid.UUID, phase: int, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    if not 1 <= phase <= 18:
        raise HTTPException(400, "phase 1..18")
    tools = get_tools_for_phase(phase)
    return [{"name": t.name, "template": t.template, "description": t.description, "params": [p.__dict__ for p in t.params], "parser": t.parser} for t in tools]

@router.get("/{engagement_id}/graph")
async def get_graph(engagement_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    from ..models import Target, Credential
    t_res = await db.execute(select(Target).where(Target.engagement_id == engagement_id))
    c_res = await db.execute(select(Credential).where(Credential.engagement_id == engagement_id))
    return {"targets": [{"id": str(t.id), "ip": t.ip, "hostname": t.hostname, "ports": t.ports, "discovered_in_phase": t.discovered_in_phase} for t in t_res.scalars().all()],
            "credentials": [{"id": str(c.id), "username": c.username, "hash_type": c.hash_type, "cracked": c.cracked} for c in c_res.scalars().all()]}
