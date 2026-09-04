# AlphaX Cyber Kill-Chain — Director's Console

Monolithic War Room for **18-phase Unified Cyber Kill Chain (UCKC)** — Human-in-the-Loop gates, Kali host executor (`subprocess`), real-time WS console, Attack Knowledge Graph, **rule-based AI assist**, **834-item script library**, visual monitoring + analytics, **4 dashboard themes**, PostgreSQL. Labs: VulnHub / local OWASP Juice Shop.

**Live on this Kali:** API `http://localhost:8001` (v0.2.0) + UI `http://localhost:3002/` (8000/3000 occupied → host mode). Juice Shop v20.1.1 available at `http://127.0.0.1:3005` (`docker run -d --name juiceshop-test -p 127.0.0.1:3005:3000 bkimminich/juice-shop:latest`).

See **[DOCUMENTATION.md](./DOCUMENTATION.md)** for **full step-by-step: install → login → usage → AI → library → monitoring → themes → Juice Shop test report** (Docker & host paths, 18-phase mapping, API cURL, UI walkthrough, troubleshooting).

## 30-Second Quick Start (Host Kali)
```bash
cp .env.example .env          # set POSTGRES_PASSWORD, JWT_SECRET
pip install --break-system-packages -r backend/requirements.txt
pip install --break-system-packages --force-reinstall bcrypt==4.1.3  # passlib fix
nohup python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8001 > /tmp/alphax_api.log 2>&1 &
cd frontend && npm install && nohup npm run dev -- --port 3002 --host 0.0.0.0 > /tmp/alphax_front.log 2>&1 &
curl -s http://localhost:8001/health
# → {"status":"ok","service":"alphax-api","version":"0.2.0","executor":"host","phases":18}
```

## Login & First Engagement
```bash
TOKEN=$(curl -s -X POST http://localhost:8001/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" -d "username=operator&password=AlphaX!2026" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -X POST http://localhost:8001/api/v1/engagements -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"Juice Shop 20.1.1 Local Test","scope_cidr":"127.0.0.1"}' | python3 -m json.tool
# paste TOKEN + engagement id into UI header at http://localhost:3002/
```

## HITL Flow
`Create Command (pending_approval)` → `Approve ✓` → `Execute ▶` → live console streams WS → parser feeds Knowledge Graph → auto-advance or `blocked_needs_input` (+ auto `ai_pivot` suggestions).

## What's Inside (v0.2.0)
- **AI Assist** (`/api/v1/ai/*`): recommend / chain / analyze / pivot / execute-chain / status — CVE hints, failure pivots, background chains. UI: `AIAssistPanel`.
- **Script Library** (`/api/v1/library/*`): 75 nmap flags + 612 live NSE scripts + 123 Kali tools + 24 presets (sources: nmap.org, kali.org). UI: `PreselectPanel` (5 tabs, click-to-fill + raw override).
- **Monitoring** (`/api/v1/monitoring/{id}/snapshot`): phase grid, host map, threat gauge, timeline. UI: `MonitoringWindow` + `VisualAnalytics` (progress ring, MITRE heatmap, attack graph, sparkline, event ticker).
- **Themes**: Neon Cyan (default), Tactical Green, Cyber Crimson, Midnight Ops + scanline overlay. UI: header `ThemeSwitcher`.
- **Engagement deletion**: per-card `×` + **Clear All** (cascade). API: `DELETE /engagements[/{id}]` → 204.

## Docs
- **Full guide:** [`DOCUMENTATION.md`](./DOCUMENTATION.md) (§1 Architecture … §27 Dev Notes, incl. Juice Shop test report §22)
- API Swagger: `http://localhost:8001/docs`  Health: `http://localhost:8001/health`  WS: `ws://localhost:8001/ws/engagements/{id}`
- 18 phases/tools: `backend/app/killchain_engine.py:64`  Executor: `backend/app/executor.py:35`  AI: `backend/app/ai_assist.py:1`  Library: `backend/app/scripts_library.py:1`

> **AUTHORIZED ENGAGEMENTS ONLY** — scope per engagement, 42-tool allow-list `ALLOWED_TOOLS`, deny patterns, JWT. AI chains auto-approve only after explicit operator launch.
