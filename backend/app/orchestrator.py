from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from .models import Engagement, Command
from .killchain_engine import UckcPhase, get_next_phase, can_transition, get_tools_for_phase
from . import ai_assist

class Orchestrator:
    """Conditional sequential + HITL orchestrator."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_engagement(self, engagement_id) -> Engagement | None:
        res = await self.db.execute(select(Engagement).where(Engagement.id == engagement_id))
        return res.scalars().first()

    async def on_command_finished(self, command: Command):
        eng = await self.get_engagement(command.engagement_id)
        if not eng:
            return
        if command.status == "succeeded":
            # auto-advance only if this was the current phase and no blocking pending approvals
            if command.phase == eng.current_phase:
                nxt = get_next_phase(eng.current_phase)
                if nxt:
                    # don't auto-advance past human decision if next phase has destructive tool default? v0 always advance
                    eng.current_phase = int(nxt)
                    # if engagement still active, keep active
                    if eng.status == "draft":
                        eng.status = "active"
                    await self.db.commit()
        elif command.status == "failed":
            # flag for operator
            eng.status = "blocked_needs_input"
            await self.db.commit()
            # AI pivot suggestions (lazy import to avoid circular)
            try:
                from .routers.ws import manager
                pivot = ai_assist.suggest_on_failure(
                    command.phase, command.tool_name, command.stderr or "", command.exit_code
                )
                await manager.broadcast(command.engagement_id, {
                    "type": "ai_pivot",
                    "command_id": str(command.id),
                    "phase": command.phase,
                    "failed_tool": command.tool_name,
                    "exit_code": command.exit_code,
                    "suggestions": pivot.get("suggestions", []),
                })
            except Exception:
                pass

    def suggest_next_tool(self, phase: int, failed_tool: str):
        tools = get_tools_for_phase(phase)
        for t in tools:
            if t.name != failed_tool:
                return t
        return None

    async def can_execute_phase(self, engagement_id, phase: int) -> tuple[bool, str]:
        eng = await self.get_engagement(engagement_id)
        if not eng:
            return False, "engagement not found"
        if eng.status == "blocked_needs_input" and phase != eng.current_phase:
            return False, "engagement blocked - resolve current phase first"
        if not can_transition(eng.current_phase, phase):
            return False, f"illegal transition {eng.current_phase} -> {phase}. Complete current phase or go back."
        return True, "ok"
