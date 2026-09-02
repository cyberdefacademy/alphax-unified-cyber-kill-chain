from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db, async_session
from ..models import Engagement, Command
from .. import ai_assist
from ..executor import assemble_command
from ..killchain_engine import TOOL_MAPPING, get_tools_for_phase
from .auth import get_current_user
from .ws import manager
import json

router = APIRouter(prefix="/ai", tags=["ai"])

class RecommendRequest(BaseModel):
    phase: int
    context: Optional[dict] = None

class ChainRequest(BaseModel):
    start_phase: int = 1
    end_phase: int = 18
    context: Optional[dict] = None

class AnalyzeRequest(BaseModel):
    command_id: uuid.UUID

class FailureRequest(BaseModel):
    phase: int
    failed_tool: str
    stderr: Optional[str] = ""
    exit_code: Optional[int] = None

class ExecuteChainRequest(BaseModel):
    start_phase: int = 1
    end_phase: int = 18
    context: Optional[dict] = None
    auto_advance: bool = True

@router.post("/{engagement_id}/recommend")
async def recommend(
    engagement_id: uuid.UUID,
    body: RecommendRequest,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user),
):
    eng = (await db.execute(select(Engagement).where(Engagement.id == engagement_id))).scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    ctx = body.context or {}
    ctx.setdefault("scope_cidr", eng.scope_cidr)
    if "hosts" not in ctx:
        # build live context
        live = await ai_assist.build_context(db, engagement_id)
        ctx["hosts"] = live.get("hosts", [])
        ctx["open_ports"] = live.get("open_ports", [])
    rec = ai_assist.recommend_tool(body.phase, ctx)
    return {
        "phase": body.phase,
        "tool_name": rec.tool_name,
        "template": rec.template,
        "params": rec.params,
        "rationale": rec.rationale,
        "confidence": rec.confidence,
        "cve_hint": rec.cve_hint,
        "requires_approval": rec.requires_approval,
    }

@router.post("/{engagement_id}/chain")
async def chain(
    engagement_id: uuid.UUID,
    body: ChainRequest,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user),
):
    eng = (await db.execute(select(Engagement).where(Engagement.id == engagement_id))).scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    ctx = body.context or {"scope_cidr": eng.scope_cidr}
    if "hosts" not in ctx:
        live = await ai_assist.build_context(db, engagement_id)
        ctx["hosts"] = live.get("hosts", [])
        ctx["open_ports"] = live.get("open_ports", [])
    steps = ai_assist.build_chain(body.start_phase, body.end_phase, ctx)
    return {
        "engagement_id": str(engagement_id),
        "start_phase": body.start_phase,
        "end_phase": body.end_phase,
        "steps": [
            {
                "phase": s.phase,
                "tool_name": s.tool_name,
                "params": s.params,
                "rationale": s.rationale,
            } for s in steps
        ],
        "summary": ai_assist.summarize(ctx),
    }

@router.post("/{engagement_id}/analyze")
async def analyze(
    engagement_id: uuid.UUID,
    body: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user),
):
    cmd = (await db.execute(select(Command).where(Command.id == body.command_id, Command.engagement_id == engagement_id))).scalars().first()
    if not cmd:
        raise HTTPException(404, "command not found")
    from ..models import Result
    res = (await db.execute(select(Result).where(Result.command_id == cmd.id))).scalars().first()
    parsed = res.parsed_data if res else None
    return ai_assist.analyze_result(cmd.phase, cmd, parsed)

@router.post("/{engagement_id}/pivot")
async def pivot(
    engagement_id: uuid.UUID,
    body: FailureRequest,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user),
):
    eng = (await db.execute(select(Engagement).where(Engagement.id == engagement_id))).scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    return ai_assist.suggest_on_failure(body.phase, body.failed_tool, body.stderr or "", body.exit_code)

@router.post("/{engagement_id}/execute-chain")
async def execute_chain(
    engagement_id: uuid.UUID,
    body: ExecuteChainRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user),
):
    eng = (await db.execute(select(Engagement).where(Engagement.id == engagement_id))).scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    ctx = body.context or {"scope_cidr": eng.scope_cidr}
    if "hosts" not in ctx:
        live = await ai_assist.build_context(db, engagement_id)
        ctx["hosts"] = live.get("hosts", [])
        ctx["open_ports"] = live.get("open_ports", [])
    steps = ai_assist.build_chain(body.start_phase, body.end_phase, ctx)

    async def _run():
        async with async_session() as sess:
            for s in steps:
                from ..executor import is_command_allowed
                # Build raw command
                spec = next((t for t in get_tools_for_phase(s.phase) if t.name == s.tool_name), None)
                raw = assemble_command(spec.template, s.params) if spec else s.tool_name
                allowed, reason = is_command_allowed(raw, s.tool_name)
                cmd = Command(
                    engagement_id=engagement_id,
                    phase=s.phase,
                    tool_name=s.tool_name,
                    raw_command=raw,
                    params=s.params,
                    status="blocked" if not allowed else "pending_approval",
                )
                sess.add(cmd)
                await sess.commit()
                await sess.refresh(cmd)
                if not allowed:
                    await manager.broadcast(engagement_id, {
                        "type": "ai_chain_step",
                        "phase": s.phase, "tool": s.tool_name,
                        "status": "blocked", "reason": reason,
                    })
                    continue
                # Auto-approve since the operator explicitly invoked the chain
                cmd.status = "approved"
                cmd.approved_by = user + "+ai-chain"
                await sess.commit()
                await sess.refresh(cmd)
                await manager.broadcast(engagement_id, {
                    "type": "ai_chain_step",
                    "phase": s.phase, "tool": s.tool_name,
                    "command_id": str(cmd.id), "status": "approved",
                    "rationale": s.rationale,
                })
                # Execute
                from ..executor import KaliExecutor
                from ..orchestrator import Orchestrator
                exe = KaliExecutor()
                async def ws_bcast(m):
                    m2 = dict(m)
                    m2["ai_chain"] = True
                    await manager.broadcast(engagement_id, m2)
                await exe.execute(cmd, sess, ws_broadcast=ws_bcast)
                if body.auto_advance:
                    orch = Orchestrator(sess)
                    await orch.on_command_finished(cmd)
                await manager.broadcast(engagement_id, {
                    "type": "ai_chain_step_finished",
                    "phase": s.phase, "tool": s.tool_name,
                    "status": cmd.status, "exit_code": cmd.exit_code,
                })
                # If we are in blocked_needs_input, stop the chain
                eng2 = (await sess.execute(select(Engagement).where(Engagement.id == engagement_id))).scalars().first()
                if eng2 and eng2.status == "blocked_needs_input":
                    await manager.broadcast(engagement_id, {
                        "type": "ai_chain_halted",
                        "reason": "blocked_needs_input",
                        "phase": s.phase,
                    })
                    break

    background.add_task(_run)
    return {
        "queued_steps": len(steps),
        "engagement_id": str(engagement_id),
        "message": f"AI chain queued: {len(steps)} step(s). Will run with HITL auto-approve + auto-advance until blocked.",
        "steps": [
            {"phase": s.phase, "tool_name": s.tool_name, "rationale": s.rationale} for s in steps
        ],
    }

@router.get("/{engagement_id}/status")
async def status(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user),
):
    eng = (await db.execute(select(Engagement).where(Engagement.id == engagement_id))).scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    ctx = await ai_assist.build_context(db, engagement_id)
    # Recommendation for current phase
    rec = ai_assist.recommend_tool(eng.current_phase, ctx)
    return {
        "summary": ai_assist.summarize(ctx),
        "context": ctx,
        "recommendation": {
            "phase": eng.current_phase,
            "tool_name": rec.tool_name,
            "params": rec.params,
            "rationale": rec.rationale,
            "confidence": rec.confidence,
        },
    }
