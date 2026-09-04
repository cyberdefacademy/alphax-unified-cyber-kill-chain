"""Monitoring snapshot — aggregate engagement state for visual dashboard."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import uuid
from datetime import datetime, timezone, timedelta
from collections import Counter
from ..database import get_db
from ..models import Engagement, Target, Command, Result, Credential
from .auth import get_current_user
from .ws import manager

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@router.get("/{engagement_id}/snapshot")
async def snapshot(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user),
):
    eng = (await db.execute(select(Engagement).where(Engagement.id == engagement_id))).scalars().first()
    if not eng:
        raise HTTPException(404, "engagement not found")
    # Commands last 5 min
    cmds_all = (await db.execute(select(Command).where(Command.engagement_id == engagement_id).order_by(Command.created_at))).scalars().all()
    now = datetime.now(timezone.utc)
    recent = [c for c in cmds_all if c.created_at and (now - c.created_at).total_seconds() < 300]
    # Per-phase status
    phase_cmds: dict[int, list[Command]] = {}
    for c in cmds_all:
        phase_cmds.setdefault(c.phase, []).append(c)
    phase_grid = []
    for p in range(1, 19):
        cmds = phase_cmds.get(p, [])
        last = max(cmds, key=lambda c: c.created_at) if cmds else None
        last_status = last.status if last else "pending"
        last_tool = last.tool_name if last else None
        success_n = sum(1 for c in cmds if c.status == "succeeded")
        fail_n = sum(1 for c in cmds if c.status == "failed")
        phase_grid.append({
            "phase": p,
            "status": "completed" if eng.current_phase > p else ("active" if eng.current_phase == p else "pending"),
            "last_status": last_status,
            "last_tool": last_tool,
            "commands": len(cmds),
            "succeeded": success_n,
            "failed": fail_n,
        })
    # Threats
    threats: list[dict] = []
    for c in cmds_all:
        if c.status == "failed" and c.exit_code is not None:
            sev = "high" if c.exit_code in (127, 124) else "medium" if c.exit_code in (1, 255) else "low"
            threats.append({
                "id": str(c.id), "phase": c.phase, "tool": c.tool_name,
                "exit_code": c.exit_code, "severity": sev,
                "ts": c.created_at.isoformat() if c.created_at else None,
                "summary": (c.stderr or "")[:120],
            })
    # Targets
    targets = (await db.execute(select(Target).where(Target.engagement_id == engagement_id))).scalars().all()
    target_nodes = [{
        "id": str(t.id), "ip": t.ip, "hostname": t.hostname,
        "discovered_in_phase": t.discovered_in_phase,
        "open_ports": [p for p in (t.ports or []) if p.get("state") == "open"],
        "services": list({(p.get("service") or "") for p in (t.ports or []) if p.get("service")}),
    } for t in targets]
    # Credentials
    creds = (await db.execute(select(Credential).where(Credential.engagement_id == engagement_id))).scalars().all()
    cred_nodes = [{"id": str(c.id), "user": c.username, "hash_type": c.hash_type, "cracked": c.cracked, "phase": c.source_phase} for c in creds]
    # Counters
    cmds_by_status = Counter(c.status for c in cmds_all)
    tools_top = Counter(c.tool_name for c in cmds_all).most_common(8)
    # Threat score 0..100 (heuristic)
    threat_score = min(100, len(targets) * 8 + len(creds) * 12 + sum(1 for t in threats if t["severity"] == "high") * 6)
    # Recent timeline (last 30 commands)
    timeline = [{
        "id": str(c.id), "ts": c.created_at.isoformat() if c.created_at else None,
        "phase": c.phase, "tool": c.tool_name, "status": c.status,
        "exit_code": c.exit_code, "raw": (c.raw_command or "")[:80],
    } for c in cmds_all[-30:][::-1]]
    return {
        "engagement": {
            "id": str(eng.id), "name": eng.name, "scope_cidr": eng.scope_cidr,
            "status": eng.status, "current_phase": eng.current_phase,
        },
        "phase_grid": phase_grid,
        "targets": target_nodes,
        "credentials": cred_nodes,
        "threats": threats[-50:],
        "timeline": timeline,
        "counters": {
            "by_status": dict(cmds_by_status),
            "tools_top": tools_top,
            "threat_score": threat_score,
            "total_commands": len(cmds_all),
            "recent_5min": len(recent),
        },
        "ts": now.isoformat(),
    }
