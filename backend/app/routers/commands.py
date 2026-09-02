from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid
import shlex
from ..database import get_db, async_session
from ..models import Command, Result, Engagement
from ..schemas import CommandCreate, CommandOut
from ..killchain_engine import get_tools_for_phase
from ..executor import KaliExecutor, is_command_allowed, assemble_command
from ..orchestrator import Orchestrator
from ..routers.auth import get_current_user
from ..routers.ws import manager

router = APIRouter(prefix="/engagements/{engagement_id}/commands", tags=["commands"])

def build_raw_from_tool(tool_name: str, phase: int, params: dict | None) -> str:
    tools = get_tools_for_phase(phase)
    spec = next((t for t in tools if t.name == tool_name), None)
    if not spec:
        # allow generic if not in mapping but still allow-listed
        if params and "target" in params:
            return f"{tool_name} {shlex.quote(str(params['target']))}"
        return tool_name
    return assemble_command(spec.template, params)

@router.get("", response_model=list[CommandOut])
async def list_commands(engagement_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Command).where(Command.engagement_id == engagement_id).order_by(Command.created_at.desc()))
    return res.scalars().all()

@router.post("", response_model=CommandOut)
async def create_command(engagement_id: uuid.UUID, body: CommandCreate, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    # validate engagement exists
    eng_res = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    if not eng_res.scalars().first():
        raise HTTPException(404, "engagement not found")
    orch = Orchestrator(db)
    ok, msg = await orch.can_execute_phase(engagement_id, body.phase)
    if not ok:
        raise HTTPException(400, msg)
    raw = body.raw_command or build_raw_from_tool(body.tool_name, body.phase, body.params)
    # allow-list check at creation time too
    allowed, reason = is_command_allowed(raw, body.tool_name)
    if not allowed:
        raise HTTPException(400, reason)
    cmd = Command(engagement_id=engagement_id, phase=body.phase, tool_name=body.tool_name, raw_command=raw, params=body.params, status="pending_approval")
    db.add(cmd)
    await db.commit()
    await db.refresh(cmd)
    return cmd

@router.post("/{command_id}/approve", response_model=CommandOut)
async def approve_command(engagement_id: uuid.UUID, command_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Command).where(Command.id == command_id, Command.engagement_id == engagement_id))
    cmd = res.scalars().first()
    if not cmd:
        raise HTTPException(404, "command not found")
    if cmd.status != "pending_approval":
        raise HTTPException(400, f"command not pending_approval, current {cmd.status}")
    cmd.status = "approved"
    cmd.approved_by = user
    await db.commit()
    await db.refresh(cmd)
    await manager.broadcast(engagement_id, {"type": "command_approved", "command_id": str(cmd.id)})
    return cmd

@router.post("/{command_id}/execute", response_model=CommandOut)
async def execute_command(engagement_id: uuid.UUID, command_id: uuid.UUID, background: BackgroundTasks, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Command).where(Command.id == command_id, Command.engagement_id == engagement_id))
    cmd = res.scalars().first()
    if not cmd:
        raise HTTPException(404, "command not found")
    if cmd.status not in ("approved", "failed"):
        raise HTTPException(400, f"command must be approved first, current {cmd.status}")
    # fire background task with new session
    async def _run():
        async with async_session() as sess:
            r = await sess.execute(select(Command).where(Command.id == command_id))
            c = r.scalars().first()
            if not c:
                return
            exe = KaliExecutor()

            async def ws_broadcast(msg: dict):
                await manager.broadcast(engagement_id, msg)

            await exe.execute(c, sess, ws_broadcast=ws_broadcast)
            orch = Orchestrator(sess)
            await orch.on_command_finished(c)

    background.add_task(_run)
    # mark running optimistically
    cmd.status = "running"
    await db.commit()
    await db.refresh(cmd)
    return cmd

@router.get("/{command_id}/result")
async def get_result(engagement_id: uuid.UUID, command_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: str = Depends(get_current_user)):
    res = await db.execute(select(Result).where(Result.command_id == command_id))
    r = res.scalars().first()
    if not r:
        raise HTTPException(404, "result not found - command may not have run yet")
    # ensure command belongs to engagement
    c_res = await db.execute(select(Command).where(Command.id == command_id, Command.engagement_id == engagement_id))
    if not c_res.scalars().first():
        raise HTTPException(404, "command not in engagement")
    return {"id": str(r.id), "command_id": str(r.command_id), "raw_output": r.raw_output, "parsed_data": r.parsed_data, "created_at": r.created_at}
