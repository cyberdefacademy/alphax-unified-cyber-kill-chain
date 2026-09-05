# AlphaX Cyber Kill-Chain — Complete Documentation
### Director's Console | Unified Cyber Kill Chain (18 Phases) | Kali Host Executor

**Codename:** AlphaX Cyber Kill-Chain  •  **Stack:** FastAPI + PostgreSQL + React 18 Vite 5 + Tailwind 3  •  **Executor:** host `subprocess` on Kali  •  **Labs:** VulnHub / OWASP Juice Shop (local)  •  **Version:** 0.2.0

> **AUTHORIZED ENGAGEMENTS ONLY** — Every command requires explicit `pending_approval → approved → running` HITL gate (AI chains auto-approve only after the operator explicitly launches them). Scope is enforced per engagement.

---

## Table of Contents
1. [Architecture](#1-architecture)
2. [Prerequisites](#2-prerequisites)
3. [Repository Layout](#3-repository-layout)
4. [Configuration (.env)](#4-configuration)
5. [Installation — Option A: Docker](#5-installation--option-a-docker-recommended-when-daemon-available)
6. [Installation — Option B: Host Kali (Current Verified Path)](#6-installation--option-b-host-kali-subprocess-verified)
7. [Database Initialization](#7-database-initialization)
8. [Health Checks](#8-health-checks)
9. [Authentication](#9-authentication-single-operator-jwt)
10. [Engagement Lifecycle (incl. Delete)](#10-engagement-lifecycle)
11. [War Room UI (React)](#11-war-room-ui)
12. [Dashboard Themes](#12-dashboard-themes)
13. [AI Assist Layer](#13-ai-assist-layer-backendappai_assistpy1)
14. [Scripts Library & Pre-Select](#14-scripts-library--pre-select-backendappscripts_librarypy1)
15. [Visual Monitoring & Analytics](#15-visual-monitoring--analytics)
16. [API Usage — cURL Step-by-Step](#16-api-usage--curl-step-by-step)
17. [18 Phases & Tool Mapping](#17-18-phases--tool-mapping-backendappkillchain_enginepy12)
18. [Executor & HITL Gates](#18-executor--hitl-gates-backendappexecutorpy1)
19. [Output Parsing & Knowledge Graph](#19-output-parsing--knowledge-graph)
20. [WebSocket Live Console & Events](#20-websocket-live-console--events)
21. [VulnHub Lab Setup](#21-vulnhub-lab-setup)
22. [Juice Shop Lab Setup & Test Report](#22-juice-shop-lab-setup--test-report)
23. [Full Walkthrough — Juice Shop on 127.0.0.1:3005](#23-full-walkthrough--juice-shop-verified)
24. [Troubleshooting](#24-troubleshooting)
25. [Security Considerations](#25-security-considerations)
26. [Stopping / Restarting](#26-stopping--restarting)
27. [Development Notes](#27-development-notes)

---

## 1. Architecture
```
┌─────────────────────────┐      REST + WS :8001            ┌──────────────────────────┐
│  React Vite (3002)      │  ───────────────────────────▶  │  FastAPI (8001)          │
│  KillChainDashboard     │  ◀───────────────────────────  │  routers/engagements     │──▶ asyncpg ──▶ PostgreSQL :5432
│  AttackFlow 18-step     │     JSON + WS broadcast         │  routers/commands (HITL) │    (alphax DB: engagements,
│  PhasePanel ×18 (+raw)  │                                 │  routers/auth (JWT)      │     targets, credentials,
│  PreselectPanel (5 tabs)│                                 │  routers/ai (assist)     │     commands, results,
│  AIAssistPanel          │                                 │  routers/library (834)   │     asset_edges)
│  MonitoringWindow       │                                 │  routers/monitoring      │
│  VisualAnalytics        │                                 │  orchestrator.py         │──▶ host subprocess (nmap,
│  LiveConsole + ticker   │                                 │  ai_assist.py (brain)    │    nuclei, nikto, sqlmap,
│  KnowledgeGraph         │                                 │  killchain_engine.py     │    gobuster, msfvenom,
│  ThemeSwitcher (4)      │                                 │  executor.py ────────────┤    hydra, impacket, etc.)
└─────────────────────────┘                                 │  scripts_library.py      │
                                                            │  parsers/nmap_parser     │
                                                            └──────────────────────────┘
```
- **Monolith** FastAPI serves REST + WS + Executor abstraction. Frontend standalone but proxied in dev (`vite.config.ts:10` → `http://localhost:8001`).
- DB: SQLAlchemy 2.0 async (`backend/app/database.py:1`, `models.py:1`), `init_db()` at `lifespan` in `main.py:1`.
- Executor mode `host` (this Kali) vs `docker` per `config.py:9` `EXECUTOR_MODE`.
- **AI layer** (`ai_assist.py`) is deterministic and rule-based — no external LLM calls. Every AI-built command still passes `is_command_allowed()` + deny patterns.
- **Library layer** (`scripts_library.py`) serves 75 nmap flags + 612 live-scanned NSE scripts + 123 curated Kali tools + 24 ready-to-run presets.

## 2. Prerequisites
On **Kali** verified:

| Component | Version | Check |
|-----------|---------|-------|
| Python | 3.13.x | `python3 --version` |
| Node | 22.x | `node --version` |
| PostgreSQL | 18.x | `psql --version` + `pg_isready -h localhost -p 5432` |
| nmap | 7.99 | `nmap --version` |
| sqlmap | 1.10.x | `sqlmap --version` |
| nikto | 2.6.0 | `nikto -Version` |
| nuclei | v3.11.0 | `nuclei -version` |
| gobuster | v3.8.2 | `gobuster --help` |
| Docker | 29.x | `docker ps` (for Juice Shop target) |

**Port notes (this host):** `8000` taken by NeuroSploit, `3000`/`3001` taken → AlphaX verified on **`8001` (API)** and **`3002` (UI)**.

## 3. Repository Layout
```
.
├── docker-compose.yml               # postgres:5432 + api:8001 + frontend:3002
├── .env / .env.example             # DATABASE_URL, JWT_SECRET, ALLOWED_TOOLS (42), VULNHUB_TARGETS
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt             # fastapi, uvicorn[standard], sqlalchemy[asyncio], asyncpg, pydantic-settings, python-jose, passlib, bcrypt==4.1.3, websockets, lxml, xmltodict
│   └── app/
│       ├── main.py                 # FastAPI lifespan, /health (v0.2.0), CORS, 8 routers
│       ├── config.py               # Settings via .env, allowed_tools_set (42 defaults)
│       ├── database.py             # create_async_engine + async_session + init_db()
│       ├── models.py               # Engagement/Target/Credential/Command/Result/AssetEdge
│       ├── schemas.py              # Pydantic DTOs
│       ├── killchain_engine.py     # UckcPhase 1..18 + TOOL_MAPPING (37 ToolSpec)
│       ├── executor.py             # KaliExecutor + run_via_subprocess + parsers
│       ├── orchestrator.py         # conditional flow + AI pivot broadcast on failure
│       ├── ai_assist.py            # rule-based brain: recommend/analyze/chain/pivot
│       ├── scripts_library.py      # 75 nmap opts + 612 NSE + 123 Kali tools + 24 presets
│       ├── parsers/nmap_parser.py  # parse_nmap_xml + parse_nmap_text (regex fallback)
│       └── routers/auth.py, engagements.py (CRUD + DELETE), commands.py (HITL),
│                  targets.py, ws.py, ai.py (6 endpoints), monitoring.py (snapshot),
│                  library.py (8 endpoints)
└── frontend/
    ├── vite.config.ts              # proxy /api, /ws → 8001
    ├── tailwind.config.js
    └── src/
        ├── App.tsx                 # header + login + engagement selector + delete + ThemeSwitcher
        ├── index.css               # 4 theme token sets + ax-* component classes + ticker
        ├── components/AttackFlow.tsx        # 18-step progress bar
        ├── components/PhasePanel.tsx        # tool dropdown + param form + raw override + HITL gate
        ├── components/PreselectPanel.tsx    # 5-tab script library picker
        ├── components/AIAssistPanel.tsx     # recommend / chain / pivot UI
        ├── components/MonitoringWindow.tsx  # phase grid + host map + gauge + timeline
        ├── components/VisualAnalytics.tsx   # ring + MITRE heatmap + attack graph + sparkline + ticker
        ├── components/LiveConsole.tsx       # WS streaming console (incl. AI events)
        ├── components/KnowledgeGraph.tsx    # hosts + creds cards
        └── components/ThemeSwitcher.tsx     # 4-theme picker + scanline toggle
```

## 4. Configuration
Copy template and **change secrets before any real engagement**:

```bash
cp .env.example .env
# edit .env
```
Key `.env` entries (see `.env.example:1`):

```
POSTGRES_USER=alphax
POSTGRES_PASSWORD=alphax_secret_change_me   # ← change
POSTGRES_DB=alphax
API_PORT=8001        # 8000 occupied → use 8001
FRONTEND_PORT=3002   # 3000 occupied → use 3002
DATABASE_URL=postgresql+asyncpg://alphax:alphax_secret_change_me@localhost:5432/alphax
JWT_SECRET=change_me_in_prod_alphax_2026_32chars_min  # ← 32+ random chars (openssl rand -hex 32)
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=480
EXECUTOR_MODE=host
# 42 tools — must cover every ToolSpec.name in killchain_engine.py + nikto/gobuster/dirb/ffuf/feroxbuster/whatweb/wafw00f
ALLOWED_TOOLS=nmap,masscan,nuclei,msfvenom,msfconsole,msfconsole_handler,curl,setoolkit,gophish,sqlmap,cron,mimikatz,amsi-bypass,sliver,chisel,ssh,ligolo,linpeas,winPEAS,bloodhound,sudo,windows-exploit-suggester,psexec.py,wmiexec.py,secretsdump.py,hashcat,crackmapexec,smbclient,scp,rclone,custom,report,hydra,nikto,winpeas,gobuster,dirb,ffuf,feroxbuster,whatweb,wafw00f
VULNHUB_TARGETS=192.168.56.0/24,10.0.0.0/24
CORS_ORIGINS=http://localhost:3002,http://127.0.0.1:3002,http://localhost:3000,http://127.0.0.1:3000
ALPHAX_OPERATOR_USER=operator
ALPHAX_OPERATOR_PASSWORD=AlphaX!2026
```

`backend/app/config.py:4` loads via `pydantic-settings` (`env_file=".env"`). The code default mirrors the full 42-tool list so fresh clones work even before `.env` is copied.

## 5. Installation — Option A: Docker (recommended when daemon available)

```bash
cp .env.example .env   # set POSTGRES_PASSWORD, JWT_SECRET
docker compose config   # verify (the `version` warning is harmless)
docker compose up --build -d
docker compose ps
curl -s http://localhost:8001/health
docker compose logs -f api
```

`docker-compose.yml:1` defines `postgres` (healthcheck `pg_isready`), `api` (`uvicorn --host 0.0.0.0 --port 8001 --reload`, bind-mount `./backend:/app`), `frontend` (`npm run dev -- --host 0.0.0.0 --port 3002`).

## 6. Installation — Option B: Host Kali Subprocess (Verified)
Current working method on this host (ports shifted, host executor).

### 6.1 System deps & Postgres
```bash
pg_isready -h localhost -p 5432
sudo service postgresql start   # if not running
psql -h localhost -U postgres -c "ALTER USER alphax WITH PASSWORD 'alphax_secret_change_me';"
PGPASSWORD=alphax_secret_change_me psql -h localhost -U alphax -d alphax -c "SELECT 1;"
```

### 6.2 Python backend (host)
```bash
# from repo root
pip install --break-system-packages --no-cache-dir -r backend/requirements.txt
# critical: bcrypt must be 4.1.3 (passlib 1.7.4 incompatible with bcrypt 5)
pip install --break-system-packages --force-reinstall bcrypt==4.1.3
cp .env.example .env   # then edit secrets if needed
nohup python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8001 > /tmp/alphax_api.log 2>&1 &
sleep 3; curl -s http://localhost:8001/health
# → {"status":"ok","service":"alphax-api","version":"0.2.0","executor":"host","phases":18}
```

### 6.3 Frontend
```bash
cd frontend && npm install          # vite 5.4.21, 142 modules
nohup npm run dev -- --port 3002 --host 0.0.0.0 > /tmp/alphax_front.log 2>&1 &
curl -s -I http://localhost:3002/ | head -n 3   # → 200 OK
npm run build   # production check: tsc && vite build → dist/ (≈304kB JS)
```

Keep logs: `tail -f /tmp/alphax_api.log /tmp/alphax_front.log`.

## 7. Database Initialization
`backend/app/main.py:12` lifespan calls `database.py:13` `init_db()` → `Base.metadata.create_all` creates if not exists:

- `engagements` (id UUID, name, scope_cidr, status, current_phase, authorized_by)
- `targets` (ip, hostname, ports JSONB, discovered_in_phase)
- `credentials` (username, password_or_hash, hash_type, cracked)
- `commands` (phase, tool_name, raw_command, params JSONB, status, stdout/stderr, exit_code)
- `results` (command_id unique, raw_output, parsed_data JSONB)
- `asset_edges`

Verify: `psql -h localhost -U alphax -d alphax -c "\dt"`. `alembic.ini:1` is a stub; production should switch to `alembic upgrade head`.

## 8. Health Checks
```bash
curl -s http://localhost:8001/health | python3 -m json.tool
curl -s http://localhost:8001/ | python3 -m json.tool
# Swagger: http://localhost:8001/docs   OpenAPI: http://localhost:8001/openapi.json
curl -s -I http://localhost:3002/ | head -n 3
```

## 9. Authentication (Single-Operator JWT)
`backend/app/routers/auth.py:16` uses `OAuth2PasswordBearer` + `passlib`/`bcrypt` + `python-jose`.

- User: `operator` (`ALPHAX_OPERATOR_USER`), Pass: `AlphaX!2026` (`ALPHAX_OPERATOR_PASSWORD`)
- `POST /api/v1/auth/login` expects `application/x-www-form-urlencoded` (`username`+`password`).

```bash
curl -s -X POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=operator&password=AlphaX!2026" | python3 -m json.tool
# → {"access_token":"eyJ...","token_type":"bearer"}
TOKEN=$(curl -s -X POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=operator&password=AlphaX!2026" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
export TOKEN
```
All `/api/v1/engagements`, `/commands`, `/ai`, `/library`, `/monitoring` routes require `Authorization: Bearer $TOKEN`. JWT: `HS256`, 480 min expiry.

## 10. Engagement Lifecycle
`models.py:52` `Engagement` defaults `status active`, `current_phase 1`. States: `draft → active → blocked_needs_input` (on failure, `orchestrator.py:24`) → `completed/archived`.

```bash
# create
curl -s -X POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Juice Shop 20.1.1 Local Test","scope_cidr":"127.0.0.1"}' | python3 -m json.tool
# list / get / move phase
curl -s http://localhost:8001/api/v1/engagements -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
EID=<uuid>
curl -s http://localhost:8001/api/v1/engagements/$EID -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -s -X PATCH http://localhost:8001/api/v1/engagements/$EID \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"current_phase":2}' | python3 -m json.tool
# delete one (cascades targets/credentials/commands/results/edges) → 204
curl -s -o /dev/null -w "DELETE one: %{http_code}\n" -X DELETE \
  http://localhost:8001/api/v1/engagements/$EID -H "Authorization: Bearer $TOKEN"
# delete ALL → 204
curl -s -o /dev/null -w "DELETE all: %{http_code}\n" -X DELETE \
  http://localhost:8001/api/v1/engagements -H "Authorization: Bearer $TOKEN"
# phases / tools / graph
curl -s http://localhost:8001/api/v1/engagements/$EID/killchain/phases -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 20
curl -s http://localhost:8001/api/v1/engagements/$EID/killchain/tools/1 -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -s http://localhost:8001/api/v1/engagements/$EID/graph -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```
In the UI, each engagement card has a red `×` (delete one, with confirm) and the section header has **Clear All** (bulk, with count confirm). Deleting the selected engagement clears the UUID field.

## 11. War Room UI
Open `http://localhost:3002/` (hard refresh after upgrades: `Ctrl+Shift+R`).

**Header:** gradient `ALPHAX CYBER KILL-CHAIN` title + `AUTHORIZED ENGAGEMENTS ONLY` banner + **ThemeSwitcher** + Logout + operator dot.
**§1 Authenticate:** username/password + Login button (calls `/api/v1/auth/login`, auto-stores JWT).
**§2 Select/Create:** UUID field with validation, clickable engagement cards (name/scope/phase/status), `×` per card, **Clear All**, create-by-name+CIDR form.
**Stats grid** (`KillChainDashboard.tsx:89`): engagement, current phase (+WS state), Knowledge Graph counts, command counts.
**AttackFlow** (`AttackFlow.tsx:1`): 18 buttons, accent = current, success = completed. Click opens that phase's panel.
**PhasePanel** (`PhasePanel.tsx:1`): tool dropdown from `TOOL_MAPPING`, dynamic param form, template preview, **raw-command override** input (bypasses template assembly, still allow-listed), then `1. Create → 2. Approve ✓ → 3. Execute ▶`.
**PreselectPanel** (see §14), **AIAssistPanel** (see §13), **MonitoringWindow** + **VisualAnalytics** (see §15), **LiveConsole** (see §20), **KnowledgeGraph**, **Recent Commands**.

## 12. Dashboard Themes
`ThemeSwitcher.tsx:1` + `index.css:1` CSS-variable engine. Four professional themes, persisted in `localStorage:alphax_theme`, applied as `data-theme` on `<html>`:

| Theme | Feel | Accent | Background |
|-------|------|--------|------------|
| **Neon Cyan** (default) | Director Console | `#22d3ee` cyan | `#060a12` deep navy |
| **Tactical Green** | SOC analyst CRT phosphor | `#4ade80` green | `#04110a` dark green |
| **Cyber Crimson** | Red-team threat intel | `#f43f5e` crimson | `#150407` dark red |
| **Midnight Ops** | Aerospace steel + gold | `#fbbf24` gold | `#05060b` near-black |

All components use semantic `ax-*` classes (`ax-card`, `ax-input`, `ax-btn-primary/secondary/danger`, `ax-accent/success/warn/danger`, `ax-fg*`) so switching re-skins the entire War Room instantly. Optional **scanline overlay** (CRT vibe, `localStorage:alphax_scanlines`) toggles from the theme dropdown.

## 13. AI Assist Layer (`backend/app/ai_assist.py:1`)
Deterministic rule-based brain — **no external LLM calls**. Served by `backend/app/routers/ai.py:1`:

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/ai/{id}/recommend` `{phase}` | Best tool + params + rationale + confidence (0–1) + CVE hint |
| `POST /api/v1/ai/{id}/chain` `{start_phase,end_phase}` | Ordered `ChainStep[]` preview with progressive context |
| `POST /api/v1/ai/{id}/analyze` `{command_id}` | Insights (hosts/ports/CVEs) + next-phase recommendation |
| `POST /api/v1/ai/{id}/pivot` `{phase,failed_tool,stderr,exit_code}` | Failure-specific pivot suggestions |
| `POST /api/v1/ai/{id}/execute-chain` `{start_phase,end_phase,auto_advance}` | Background chain: queue → auto-approve (operator explicitly launched) → execute → auto-advance → halt on `blocked_needs_input` |
| `GET /api/v1/ai/{id}/status` | Live context + current-phase recommendation + one-line summary |

Key logic:
- `recommend_tool()` picks payload by detected OS/services and flags CVE matches (`Apache 2.4.49–51 → CVE-2021-41773`, `vsftpd 2.3.4 → CVE-2011-2523`, `Samba 3.x → CVE-2017-7494`).
- `suggest_on_failure()` pattern-matches: `exit 127` (install hint + same-phase fallback), `connection refused` (re-run Recon), `timeout` (reduce scope), sudo TTY, **gobuster SPA wildcard** (`--exclude-length` guidance), **nikto no-CGI** (normal for SPA), **sqlmap not-injectable** (level/risk/tamper escalation).
- `orchestrator.py:31` broadcasts `ai_pivot` over WS on **every** command failure — no operator action needed.
- `AIAssistPanel.tsx:1`: status summary + current-phase rec, `Recommend for P<n>` (auto-fills PhasePanel), `Simulate Pivot`, chain builder (`Preview` dry-run / `▶ Run Chain` background), AI chat log.

Safety: AI output still passes `is_command_allowed()` + deny patterns + `assemble_command()`; "Run Chain" only removes the manual click after explicit operator launch.

## 14. Scripts Library & Pre-Select (`backend/app/scripts_library.py:1`)
Canonical reference pulled from **`https://nmap.org/book/man.html`** (19kB), **`nmap -h`**, **`/usr/share/nmap/scripts/*.nse`** (612 scripts live-scanned), **`https://www.kali.org/tools/`** (146kB, 725 slugs, 17 MITRE categories). Totals: **75 nmap flags + 612 NSE scripts + 123 curated Kali tools + 24 presets = 834 selectable items.**

`backend/app/routers/library.py:1` (8 endpoints, all JWT-gated):

| Endpoint | Returns |
|----------|---------|
| `GET /library/nmap/options?category=` | 75 flags (13 categories) |
| `GET /library/nmap/option-categories` | category list |
| `GET /library/nmap/scripts?category=&search=&limit=` | live NSE index |
| `GET /library/nse/categories` | 14 NSE categories |
| `GET /library/kali?category=&search=&phase=` | 123 tools (17 categories, UCKC phase tags, kali.org URLs) |
| `GET /library/kali/categories` | 17 categories |
| `GET /library/presets?phase=&tool=` | 24 ready-to-run recipes |
| `GET /library/search?q=` | cross-source one-shot search |

`PreselectPanel.tsx:1` (5 tabs: **Presets / Nmap Opts / NSE / Kali / Search**): click any item → auto-fills PhasePanel tool+params (+ `raw_command` override for presets). NSE rows show categories; Kali rows link to `kali.org/tools/<slug>/`; every flag/script has a `copy` button.

## 15. Visual Monitoring & Analytics
`GET /api/v1/monitoring/{id}/snapshot` (`routers/monitoring.py:1`) aggregates: 18-cell `phase_grid`, target nodes (open ports/services), credentials, severity-classified threats (`127/124→high`, `1/255→medium`), last-30 timeline, counters (`by_status`, `tools_top`, `threat_score = targets×8 + creds×12 + high×6`, `total/recent_5min`). Polled every 4s; React Query key `['monitoring', id]` is **shared** between both visual components (single request).

**MonitoringWindow** (`MonitoringWindow.tsx:1`): 3×6 phase grid (accent pulse = active), Canvas host map (operator → targets radial layout, DPI-scaled), SVG threat-score gauge (green→amber→red), counters, status bars, top tools, threats list, WS-event counter.

**VisualAnalytics** (`VisualAnalytics.tsx:1`): SVG kill-chain progress **ring** (done/active/failed/pending + %), **MITRE tactic heatmap** (13 tactics TA0043–TA0040 with per-tactic bars), layered **attack-graph SVG** (operator → hosts → port chips → dashed cred links), **service distribution bars** (top 8), **commands-per-phase sparkline** (18 mini bars, red = failures), **live event ticker** (last 20 WS events, auto-drift, hover-pause, `prefers-reduced-motion` safe), session card.

## 16. API Usage — cURL Step-by-Step
Full HITL flow for Recon → nmap (verified against Juice Shop `127.0.0.1:3005`):

```bash
TOKEN=...; EID=<uuid>
# tools for phase 1
curl -s http://localhost:8001/api/v1/engagements/$EID/killchain/tools/1 -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# create (template assembly via executor.py:35; flag params unquoted, data params shlex-quoted)
CID=$(curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"phase":1,"tool_name":"nmap","params":{"target":"127.0.0.1","scan_type":"-sV -oX -","ports":"-p 3005,80,22","extra":""}}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
# raw_command direct (bypasses template; still allow-listed) — used by Preselect presets + nikto/gobuster
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"phase":1,"tool_name":"nikto","raw_command":"nikto -h http://127.0.0.1:3005 -Tuning 1","params":{}}' | python3 -m json.tool
# approve → execute (BackgroundTasks, streams WS)
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands/$CID/approve -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands/$CID/execute -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
sleep 8
curl -s http://localhost:8001/api/v1/engagements/$EID/commands -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 40
curl -s http://localhost:8001/api/v1/engagements/$EID/commands/$CID/result -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 40
curl -s http://localhost:8001/api/v1/engagements/$EID/graph -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# AI
curl -s -X POST http://localhost:8001/api/v1/ai/$EID/recommend -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"phase":5}' | python3 -m json.tool
curl -s -X POST http://localhost:8001/api/v1/ai/$EID/chain -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"start_phase":1,"end_phase":6}' | python3 -m json.tool | head -n 40
curl -s http://localhost:8001/api/v1/ai/$EID/status -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 20
# library + monitoring
curl -s "http://localhost:8001/api/v1/library/search?q=smb" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 30
curl -s http://localhost:8001/api/v1/monitoring/$EID/snapshot -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 40
```

## 17. 18 Phases & Tool Mapping (`backend/app/killchain_engine.py:64`)
| # | Phase | MITRE | Example Tools (`TOOL_MAPPING`, 37 ToolSpec) |
|---|-------|-------|----------------------------------------------|
|1|Reconnaissance|TA0043|nmap `-sV -sC`, masscan, nuclei (+ nikto/gobuster via raw) |
|2|Weaponization|—|msfvenom `-p LHOST LPORT -f`|
|3|Delivery|—|curl, msfconsole auxiliary|
|4|Social Engineering|—|setoolkit, gophish|
|5|Exploitation|TA0002|msfconsole exploit, sqlmap|
|6|Persistence|TA0003|cron, mimikatz|
|7|Defense Evasion|TA0005|amsi-bypass placeholder|
|8|Command & Control|TA0011|msfconsole handler, sliver|
|9|Pivoting|—|chisel, ssh -D, ligolo|
|10|Discovery|TA0007|linpeas.sh, winPEAS, bloodhound-python|
|11|Privilege Escalation|TA0004|linpeas, sudo -l, windows-exploit-suggester|
|12|Execution|TA0002|psexec.py, wmiexec.py|
|13|Credential Access|TA0006|secretsdump.py, hashcat, mimikatz|
|14|Lateral Movement|TA0008|psexec.py, crackmapexec, smbclient|
|15|Collection|TA0009|smbclient mget|
|16|Exfiltration|TA0010|scp, rclone|
|17|Impact|TA0040|custom (explicit approval)|
|18|Objectives|—|report|

Each `ToolSpec` has `name, template, description, params: ParamSpec[], parser`. `list_phases()` / `get_tools_for_phase()` back `/killchain/*`. State machine: `can_transition` (forward-1 / back-any / stay), auto-advance on success, `blocked_needs_input` on failure.

## 18. Executor & HITL Gates (`backend/app/executor.py:1`)
- **Allow-list** (42 tools, §4) + **deny patterns** (`rm -rf /`, `mkfs.`, fork bomb, `dd of=/dev/`, `shutdown`…).
- **Assemble** `assemble_command()`: flag params (`scan_type, ports, extra, wordlist, severity`) unquoted + sanitized; data params `shlex.quote`d.
- **Run** `run_via_subprocess()` (`asyncio.create_subprocess_shell`, per-line WS stream, 300s timeout → exit 124).
- **Gates** `routers/commands.py:14` `pending_approval → approved → running → succeeded/failed/blocked`; `execute` uses `BackgroundTasks`; `orchestrator.on_command_finished()` auto-advances or blocks (+ `ai_pivot` broadcast).

## 19. Output Parsing & Knowledge Graph
- `parsers/nmap_parser.py:1`: `parse_nmap_xml()` (ET) → `{hosts:[{ip,hostname,ports}]}`; `parse_nmap_text()` regex fallback (`Nmap scan report for …`, `PORT/STATE` lines) — no more `ip="unknown"` rows.
- `parsers/generic.py:1`: stdout/stderr previews.
- On `hosts`, `executor.py:144` upserts `Target` rows (dedup `engagement_id+ip`, `discovered_in_phase`) + `knowledge_update` broadcast. UI `GET /graph` polls every 6s; next-phase forms can pre-fill from it.

## 20. WebSocket Live Console & Events
- Route `routers/ws.py:11` `GET /ws/engagements/{id}` (`ConnectionManager` broadcast).
- `useEngagementWS.ts:11` streams `console` lines into `LiveConsole`; dashboard's second listener collects non-console events for Monitoring/Analytics.
- Message types: `connected`, `console{line}`, `command_approved`, `command_finished{status,exit_code,parsed}`, `knowledge_update{target}`, **`ai_pivot{suggestions}`** (auto on failure), **`ai_chain_step{phase,tool,status,rationale}`**, **`ai_chain_step_finished`**, **`ai_chain_halted{reason}`**.
- Test: `python3 -c "import asyncio,websockets …"` or `wscat -c ws://localhost:8001/ws/engagements/$EID`.

## 21. VulnHub Lab Setup
AlphaX expects isolated labs (`VULNHUB_TARGETS`, default `192.168.56.0/24,10.0.0.0/24`).
1. Download OVA from vulnhub.com (Kioptrix, Metasploitable2).
2. VirtualBox: import, **Host-only Adapter** (`vboxnet0` 192.168.56.1).
3. `VBoxManage startvm "Kioptrix" --type headless`; find IP via `nmap -sn 192.168.56.0/24`.
4. `ping` + `nmap -sV <ip>` from Kali; create engagement with that CIDR.
5. UI Phase 1 → `nmap` `target=<ip>` `scan_type=-sV -sC` `ports=-p-`.

## 21b. PortSwigger Web Security Academy Labs
Per-user lab instances (`https://<32-hex>.web-security-academy.net`) launched from the operator's Academy account. **Never scan `portswigger.net` itself** (production portal); only the operator's own live instance is in scope.
1. Academy → open a lab → **Access the Lab** → copy the instance URL **while it runs** (instances expire after ~1–2h idle).
2. Verify before locking scope: DNS resolves (wildcard — proves nothing alone) **plus** a single `GET /` returning `200` in <2s. Dead ID pattern: valid TLS + hang/`000` = no lab behind the ID.
3. Create engagement, then `PATCH /engagements/{id}` with `{"scope_cidr":"<instance host>"}` (retargeting supported since v0.2.0 — `EngagementUpdate` accepts `name` + `scope_cidr`).
4. Recon gentle-first: `nmap -Pn -sT -p 443 <host>` (single port; **`-sV` probe battery stalls** against the AWS edge — use connect scan + nuclei/nikto for service intel), `nuclei -severity info,low <url>`, `nikto -Tuning 1 -timeout 8 <url>`.
5. If the lab goes dark mid-engagement (`000`/timeout from direct curl too), it expired — refresh it in the browser, then re-run; do not escalate scan intensity against dead IDs.

**Live-fire notes (2026-09-05, engagement `1c1e71b8`, SQLi WHERE-clause lab):** nmap connect fingerprint `443/tcp open https` (AWS eu-west-1, 1.19s); nuclei `info,low` found `wildcard-dns-detect` only; nikto `exit=0` with `[FAIL] Unable to connect` after expiry (nikto's own exit-code quirk — stdout tells the truth); graph correctly ingested `34.246.129.62` + instance hostname. Bugs fixed during this run: immutable engagement scope (`schemas.py:23` + router now accept `name`/`scope_cidr`), nmap text parser hostname loss + version line-bleed + multi-host mis-attachment (`parsers/nmap_parser.py:43` — `[ \t]+` separators, hostname map, positional sweep).

## 22. Juice Shop Lab Setup & Test Report
Local authorized target (OWASP Juice Shop is purpose-built vulnerable):

```bash
docker pull bkimminich/juice-shop:latest   # 20.1.1 verified
docker run -d --name juiceshop-test -p 127.0.0.1:3005:3000 bkimminich/juice-shop:latest
curl -s http://127.0.0.1:3005/rest/admin/application-version  # → {"version":"20.1.1"}
docker stop juiceshop-test   # tear down when done
```

**Full test (2026-09-04, engagement `94db6f37`, strictly loopback):**

| Phase | Tool | Result |
|-------|------|--------|
| P1 | `nmap -sV -oX - -p 3005,80,22` | ✅ `succeeded` — 3005 open (Juice Shop fingerprint), graph fed, P1→P2 |
| P1 | `nmap --script=http-enum -p 3005` (library NSE) | ✅ `succeeded` |
| P1 | `nuclei -severity info` | ✅ `succeeded` (~90s, 3749 templates: juice-shop-detect, swagger, robots.txt) |
| P1 | `nikto -Tuning 1` (raw) | ✅ `succeeded` (~2min: headers, robots.txt, missing HSTS) |
| P1 | `gobuster dir common.txt` (raw) | ❌→✅ blocked by allow-list → **fixed** (§4), then correct `exit=1` SPA-wildcard handling |
| P2 | `msfvenom linux/x64 reverse_tcp → /tmp/juice_test.elf` | ✅ `succeeded` 250-byte ELF |
| P3 | `curl http://127.0.0.1:3005/` | ✅ `succeeded` |
| P5 | `sqlmap …/rest/products/search?q=test --batch --crawl=1` | ✅ `succeeded` — `q` not injectable at level 1 (correct; needs higher level/tamper), 41× 500s expected |
| P7/P17/P18 | placeholders | ✅ `succeeded` |
| P15 | `smbclient //127.0.0.1/C$` | ✅ correct `failed` (`CONNECTION_REFUSED`) → `blocked_needs_input` |
| Chain | AI `execute-chain` P17→P18 | ✅ 2 steps queued + succeeded |
| AI/library/monitoring/WS/frontend | all endpoints `200`, build 142 modules 0 errors, 4 themes live | ✅ |

**Fixes from this test:** (1) allow-list widened 35→42 tools (`.env`, `config.py`, `.env.example`); (2) AI pivot branches for gobuster-SPA-wildcard, nikto-no-CGI, sqlmap-not-injectable (`ai_assist.py:340`). Target stayed healthy (`200`) throughout.

## 23. Full Walkthrough — Juice Shop (Verified)
```bash
docker run -d --name juiceshop-test -p 127.0.0.1:3005:3000 bkimminich/juice-shop:latest
TOKEN=$(curl -s -X POST http://localhost:8001/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" -d "username=operator&password=AlphaX!2026" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
EID=$(curl -s -X POST http://localhost:8001/api/v1/engagements -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"Juice Shop 20.1.1 Local Test","scope_cidr":"127.0.0.1"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
CID=$(curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"phase":1,"tool_name":"nmap","params":{"target":"127.0.0.1","scan_type":"-sV -oX -","ports":"-p 3005,80,22","extra":""}}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands/$CID/approve -H "Authorization: Bearer $TOKEN" > /dev/null
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands/$CID/execute -H "Authorization: Bearer $TOKEN" > /dev/null
sleep 12
curl -s http://localhost:8001/api/v1/engagements/$EID/graph -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# → 127.0.0.1 localhost, ports 22 closed / 80 open Apache / 3005 open Juice Shop
```
Then open `http://localhost:3002/`, login, select the engagement: Monitoring shows the host, Analytics ring advances, Preselect offers NSE vuln presets, AI recommends P2 msfvenom.

## 24. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `docker compose up` → `Cannot connect to Docker daemon` | Docker Desktop down | Host mode (§6) |
| `POST /auth/login` → `500 … longer than 72 bytes` | `bcrypt 5` + `passlib 1.7.4` | `pip install --break-system-packages --force-reinstall bcrypt==4.1.3` |
| `GET /health` refused on 8000 | Port taken (NeuroSploit) | Use `8001`; update `vite.config.ts:10`, `useEngagementWS.ts:11` |
| Frontend blank / token lost | Wrong proxy port | Match Vite port with `CORS_ORIGINS` + API port; check console WS errors |
| `nmap` → `Scantype not supported` | Old quoting of `scan_type` | Fixed in `executor.py:35` (flags unquoted) |
| `400 Tool 'X' not in ALLOWED_TOOLS` | Missing from `.env:16` | Add to `ALLOWED_TOOLS`, restart API (fixed for gobuster/dirb/ffuf/feroxbuster/whatweb/wafw00f in v0.2.0) |
| `blocked_needs_input` after phase | `orchestrator.py:24` failure gate | Check Live Console + `ai_pivot` suggestions; re-run or PATCH phase |
| nikto/nuclei seem "stuck" (`running`) | Tool-inherent slowness (nikto ~2min, nuclei template load ~90s) | Wait; executor timeout is 300s (exit 124). Reduce scope (`-Tuning 1`, `-severity info`) |
| gobuster `exit=1` wildcard error | SPA target (Juice Shop) returns 200 for all routes | Expected — use AI pivot advice: `--exclude-length <len>` |
| sqlmap "not injectable" | Level 1 too shallow | Expected — escalate per AI pivot (`--level=3 --risk=2 --tamper=…`), still scoped |
| `\dt` shows no engagements | `DATABASE_URL` password mismatch | `ALTER USER alphax ...` to match `.env` |
| WS `disconnected` | API down | `tail -f /tmp/alphax_api.log`, `curl /health`, restart uvicorn |
| 401 flood `/engagements/username%3D…` | Pasted credentials into Engagement-ID field | Logout (clears localStorage), re-login, pick UUID card; UUID guard now blocks polling |

Logs: `tail -f /tmp/alphax_api.log /tmp/alphax_front.log` · DB: `psql -h localhost -U alphax -d alphax -c "SELECT status,current_phase FROM engagements;"` · Ports: `ss -tulpn | grep -E "8001|3002|5432"`.

## 25. Security Considerations
- **Authorization:** single-operator JWT v0; multi-user needs DB users + RBAC (`routers/auth.py:16`).
- **Allow-list:** 42 tools minimal; `bash`/`rm` blocked by deny patterns regardless.
- **Scope:** UI banner + per-engagement `scope_cidr`; add CIDR validation in `can_execute_phase` to hard-reject out-of-scope targets.
- **Audit:** all commands stored with stdout/stderr/exit/`approved_by`; consider `pgcrypto` for creds.
- **Isolation:** host executor runs on Kali; untrusted targets → Docker sidecar (`EXECUTOR_MODE=docker`, `kalilinux/kali-rolling` + `NET_RAW`).
- **Juice Shop:** intentionally vulnerable — keep it on loopback (`127.0.0.1:3005`), never expose; stop container when done.

## 26. Stopping / Restarting
```bash
# host mode (find PIDs via ps aux | grep -E "uvicorn|vite")
kill <api-pid 8001> <vite-pid 3002>
nohup python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8001 > /tmp/alphax_api.log 2>&1 &
nohup npm --prefix frontend run dev -- --port 3002 --host 0.0.0.0 > /tmp/alphax_front.log 2>&1 &
docker stop juiceshop-test   # test target
# docker mode
docker compose down && docker compose up --build -d && docker compose logs -f api
```

## 27. Development Notes
- Verify: `python3 -m py_compile backend/app/*.py backend/app/routers/*.py backend/app/parsers/*.py` • `docker compose config` • `npm --prefix frontend run build` (142 modules, 304kB, 0 errors)
- Docs: `http://localhost:8001/docs` (Swagger) · `http://localhost:8001/redoc` · WS: `ws://localhost:8001/ws/engagements/{id}`
- Add a tool: append `ToolSpec` in `killchain_engine.py:64` **and** its binary name to `ALLOWED_TOOLS` (`.env` + `config.py` default) or creation returns `400`.
- Add a preset: append to `PRESET_TEMPLATES` in `scripts_library.py`; appears instantly in Preselect (no restart needed beyond API reload).
- AI without LLM: replace `recommend_tool()` body with a chat completion fed by `TOOL_MAPPING` + live context; HITL/WS/chain code unchanged.
- **Live (2026-09-04):** API `:8001` v0.2.0 healthy, UI `:3002/` ready, Juice Shop `:3005` v20.1.1 available, engagement `94db6f37` with `127.0.0.1` (3 ports) auto-discovered.

**Quick re-login:**
```bash
export TOKEN=$(curl -s -X POST http://localhost:8001/api/v1/auth/login -d "username=operator&password=AlphaX!2026" -H "Content-Type: application/x-www-form-urlencoded" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
export EID=94db6f37-daea-4f3d-b333-6627bf5a0af1
echo $TOKEN  # paste into UI top bar along with $EID
```
