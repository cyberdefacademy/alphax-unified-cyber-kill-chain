# AlphaX Cyber Kill-Chain — Director's Console

Monolithic War Room for **18-phase Unified Cyber Kill Chain (UCKC)** — Human-in-the-Loop gates, Kali host executor (`subprocess`), real-time WS console, Attack Knowledge Graph, PostgreSQL, VulnHub lab.

**Live on this Kali (2026-09-02):** API `http://localhost:8001` + UI `http://localhost:3002/` (8000/3000 occupied; Docker Desktop down → host mode verified). Engagement `80e7b1a0-a15b-4013-8aaf-2b99e34f8362` with 1 host auto-discovered via `nmap -sV -oX -`.

See **[DOCUMENTATION.md](./DOCUMENTATION.md)** for **full step-by-step: install → login → usage** (Docker & host paths, 18-phase mapping, API cURL, UI walkthrough, VulnHub setup, troubleshooting).

## 30-Second Quick Start (Host Kali)
```bash
cp .env.example .env          # set POSTGRES_PASSWORD, JWT_SECRET
pip install --break-system-packages -r backend/requirements.txt
pip install --break-system-packages --force-reinstall bcrypt==4.1.3  # passlib fix
nohup python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8001 > /tmp/alphax_api.log 2>&1 &
cd frontend && npm install && nohup npm run dev -- --port 3002 --host 0.0.0.0 > /tmp/alphax_front.log 2>&1 &
curl -s http://localhost:8001/health
# → {"status":"ok","executor":"host","phases":18}
```

## Login & First Engagement
```bash
TOKEN=$(curl -s -X POST http://localhost:8001/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" -d "username=operator&password=AlphaX!2026" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -X POST http://localhost:8001/api/v1/engagements -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"VulnHub Kioptrix","scope_cidr":"192.168.56.0/24"}' | python3 -m json.tool
# paste TOKEN + engagement id into UI header at http://localhost:3002/
```

## HITL Flow
`Create Command (pending_approval)` → `Approve ✓` → `Execute ▶` → live console streams WS → parser feeds Knowledge Graph → auto-advance or `blocked_needs_input`.

## Docs
- **Full guide:** [`DOCUMENTATION.md`](./DOCUMENTATION.md) (§1 Architecture … §22 Dev Notes)
- API Swagger: `http://localhost:8001/docs`  Health: `http://localhost:8001/health`  WS: `ws://localhost:8001/ws/engagements/{id}`
- 18 phases/tools: `backend/app/killchain_engine.py:12`  Executor: `backend/app/executor.py:35`

> **AUTHORIZED ENGAGEMENTS ONLY** — scope `VULNHUB_TARGETS` in `.env`, allow-list `ALLOWED_TOOLS`, deny patterns, JWT. Never auto-runs.
