from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from .config import get_settings
from .database import init_db
from .routers import auth, engagements, commands, targets, ws, ai

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # init tables on startup (for v0 without alembic migration run)
    try:
        await init_db()
    except Exception as e:
        print(f"[AlphaX] init_db failed: {e}")
    yield

app = FastAPI(
    title="AlphaX Cyber Kill-Chain - Director Console",
    description="Monolithic War Room for Unified Cyber Kill Chain (18 phases) - Human-in-the-Loop automation on VulnHub lab.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(ws.router, tags=["ws"])
app.include_router(ai.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(engagements.router, prefix="/api/v1")
app.include_router(commands.router, prefix="/api/v1")
app.include_router(targets.router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "alphax-api", "version": "0.1.0", "executor": settings.executor_mode, "phases": 18}

@app.get("/")
async def root():
    return {"message": "AlphaX Cyber Kill-Chain Director Console", "docs": "/docs", "health": "/health", "banner": "AUTHORIZED ENGAGEMENTS ONLY - HITL gates enforced"}
