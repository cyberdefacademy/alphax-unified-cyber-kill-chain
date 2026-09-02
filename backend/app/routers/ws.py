from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from collections import defaultdict
import uuid
import json

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active: dict[str, set[WebSocket]] = defaultdict(set)

    async def connect(self, engagement_id: uuid.UUID | str, ws: WebSocket):
        await ws.accept()
        self.active[str(engagement_id)].add(ws)

    def disconnect(self, engagement_id: uuid.UUID | str, ws: WebSocket):
        self.active[str(engagement_id)].discard(ws)

    async def broadcast(self, engagement_id: uuid.UUID | str, message: dict):
        eid = str(engagement_id)
        dead = []
        for ws in list(self.active[eid]):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for d in dead:
            self.active[eid].discard(d)

manager = ConnectionManager()

@router.websocket("/ws/engagements/{engagement_id}")
async def ws_engagement(websocket: WebSocket, engagement_id: str):
    await manager.connect(engagement_id, websocket)
    try:
        await websocket.send_json({"type": "connected", "engagement_id": engagement_id})
        while True:
            # keep alive, echo pings
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except Exception:
                await websocket.send_json({"type": "echo", "data": data})
    except WebSocketDisconnect:
        manager.disconnect(engagement_id, websocket)
