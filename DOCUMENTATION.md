# AlphaX Cyber Kill-Chain — Complete Documentation
### Director's Console | Unified Cyber Kill Chain (18 Phases) | Kali Host Executor

**Codename:** AlphaX Cyber Kill-Chain  •  **Stack:** FastAPI 0.115 + PostgreSQL 16 + React 18 Vite 5 + Tailwind 3  •  **Executor:** host `subprocess` on Kali  •  **Lab:** VulnHub  •  **Version:** 0.1.0

> **AUTHORIZED ENGAGEMENTS ONLY** — Every command requires explicit `pending_approval → approved → running` HITL gate. No auto-execution. Scope CIDR is enforced per engagement.

---

## Table of Contents
1. [Architecture](#1-architecture)
2. [Prerequisites](#2-prerequisites)
3. [Repository Layout](#3-repository-layout)
4. [Configuration (.env)](#4-configuration)
5. [Installation — Option A: Docker](#5-installation--option-a-docker-recommended-when-daemon-available)
6. [Installation — Option B: Host Kali (Current Verified Path)](#6-installation--option-b-host-kali-subprocess-verified-2026-09-02)
7. [Database Initialization](#7-database-initialization)
8. [Health Checks](#8-health-checks)
9. [Authentication](#9-authentication-single-operator-jwt)
10. [Engagement Lifecycle](#10-engagement-lifecycle)
11. [War Room UI (React)](#11-war-room-ui)
12. [API Usage — cURL Step-by-Step](#12-api-usage--curl-step-by-step)
13. [18 Phases & Tool Mapping](#13-18-phases--tool-mapping-backendappkillchain_enginepy12)
14. [Executor & HITL Gates](#14-executor--hitl-gates-backendappexecutorpy1)
15. [Output Parsing & Knowledge Graph](#15-output-parsing--knowledge-graph)
16. [WebSocket Live Console](#16-websocket-live-console)
17. [VulnHub Lab Setup](#17-vulnhub-lab-setup)
18. [Full Walkthrough — 127.0.0.1](#18-full-walkthrough--verified-against-127001)
19. [Troubleshooting](#19-troubleshooting)
20. [Security Considerations](#20-security-considerations)
21. [Stopping / Restarting](#21-stopping--restarting)
22. [Development Notes](#22-development-notes)

---

## 1. Architecture
```
┌─────────────────────┐      REST + WS :8001       ┌──────────────────────┐
│  React Vite (3002)  │  ───────────────────────▶  │  FastAPI (8001)      │
│  KillChainDashboard │  ◀───────────────────────  │  routers/engagements │
│  AttackFlow 18-step │     JSON + WS broadcast     │  routers/commands    │──▶ asyncpg ──▶ PostgreSQL :5432
│  PhasePanel ×18     │                             │  orchestrator.py     │    (alphax DB: engagements, targets,
│  LiveConsole xterm  │                             │  killchain_engine.py │     credentials, commands, results,
│  KnowledgeGraph     │                             │  executor.py ────────┼──▶ host subprocess (nmap, hydra,
└─────────────────────┘                             │  parsers/nmap_parser │    msfvenom, impacket, etc.)
                                                    └──────────────────────┘
```
- **Monolith** FastAPI serves REST + WS + Executor abstraction. Frontend standalone but proxied in dev (`vite.config.ts:9` → `http://localhost:8001`).
- DB: SQLAlchemy 2.0 async (`backend/app/database.py:1`, `models.py:1`), `init_db()` at `lifespan` in `main.py:1`.
- Executor mode `host` (this Kali) vs `docker` per `config.py:6` `EXECUTOR_MODE`.

## 2. Prerequisites
On **Kali 7.0.12** verified:

| Component | Version | Check |
|-----------|---------|-------|
| Python | 3.13.14 | `python3 --version` |
| Node | 22.23.2 | `node --version` |
| PostgreSQL | 18.4 | `psql --version` + `pg_isready -h localhost -p 5432` |
| nmap | 7.99 | `nmap --version` |
| pip / venv | 26.x | `pip --version` |

If `psql` reports no server: `sudo service postgresql start` (Kali `postgres 18/main` runs via `/var/lib/postgresql/18/main`).

**Port notes (this host):** `8000` taken by NeuroSploit (`1144`), `3000`/`3001` taken → AlphaX verified on **`8001` (API)** and **`3002` (UI)**. Docker Desktop daemon at `~/.docker/desktop/docker.sock` was down on 2026-09-02; host mode is the active method.

## 3. Repository Layout
```
.
├── docker-compose.yml               # postgres:5432 + api:8001 + frontend:3002 (api bind-mounts /usr/bin/nmap)
├── .env / .env.example             # DATABASE_URL, JWT_SECRET, ALLOWED_TOOLS, VULNHUB_TARGETS
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt             # fastapi, uvicorn[standard], sqlalchemy[asyncio], asyncpg, pydantic-settings, python-jose, passlib, bcrypt==4.1.3, websockets, lxml, xmltodict
│   └── app/
│       ├── main.py                 # FastAPI lifespan, /health, CORS, include routers
│       ├── config.py               # Settings via .env, allowed_tools_set
│       ├── database.py             # create_async_engine + async_session + init_db()
│       ├── models.py               # Engagement/Target/Credential/Command/Result/AssetEdge
│       ├── schemas.py              # Pydantic DTOs
│       ├── killchain_engine.py     # UckcPhase 1..18 + TOOL_MAPPING
│       ├── executor.py             # KaliExecutor + run_via_subprocess + parsers
│       ├── orchestrator.py         # conditional flow, can_transition, blocked_needs_input
│       ├── parsers/nmap_parser.py  # XML → {hosts:[{ip,hostname,ports}]}
│       └── routers/auth.py, engagements.py, commands.py, targets.py, ws.py
└── frontend/
    ├── vite.config.ts              # proxy /api, /ws → 8001
    ├── src/App.tsx                 # header + token/engagement inputs
    ├── src/components/KillChainDashboard.tsx # War Room grid, stats, phase tabs
    ├── src/components/AttackFlow.tsx         # 18-step progress bar
    ├── src/components/PhasePanel.tsx         # tool dropdown + param form + Create→Approve→Execute
    ├── src/components/LiveConsole.tsx        # WS streaming pre
    └── src/hooks/useEngagementWS.ts         # ws://host:8001/ws/engagements/{id}
```

## 4. Configuration
Copy template and **change secrets before any real engagement**:

```bash
cp .env.example .env
# edit .env
```
`.env.example:1` keys:

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
ALLOWED_TOOLS=nmap,msfvenom,msfconsole,hydra,hashcat,sqlmap,nikto,smbclient,psexec.py,wmiexec.py,secretsdump.py,crackmapexec,linpeas,winpeas,chisel,ligolo,scp
VULNHUB_TARGETS=192.168.56.0/24,10.0.0.0/24
CORS_ORIGINS=http://localhost:3002,http://localhost:3000
ALPHAX_OPERATOR_USER=operator
ALPHAX_OPERATOR_PASSWORD=AlphaX!2026
```

`backend/app/config.py:3` loads via `pydantic-settings` (`env_file=".env"`).

## 5. Installation — Option A: Docker (recommended when daemon available)
> Requires `Docker Desktop` running. On 2026-09-02 it was down; restart Docker Desktop first.

```bash
cp .env.example .env   # set POSTGRES_PASSWORD, JWT_SECRET, VULNHUB_TARGETS
docker compose config   # verify: warning about version is harmless
docker compose up --build -d
docker compose ps
curl -s http://localhost:8001/health  # or 8000 if you freed it
# logs
docker compose logs -f api
```

`docker-compose.yml:1` defines `postgres` (healthcheck `pg_isready`), `api` (`uvicorn --host 0.0.0.0 --port 8000 --reload` with bind mount `./backend:/app` + `/usr/bin/nmap:ro`), `frontend` (`npm run dev -- --host 0.0.0.0 --port 3000`).

To run on 8001/3002 with Docker, override: `API_PORT=8001 FRONTEND_PORT=3002 docker compose up --build -d`.

## 6. Installation — Option B: Host Kali Subprocess (Verified 2026-09-02)
This is the **current working method** on this Kali host (Docker down, ports shifted).

### 6.1 System deps & Postgres
```bash
# ensure postgres listening
pg_isready -h localhost -p 5432
ss -tulpn | grep 5432
# if not running (Kali uses pg 18/main):
sudo service postgresql start   # or pg_ctl
psql -h localhost -U postgres -c "ALTER USER alphax WITH PASSWORD 'alphax_secret_change_me';"
# verify
PGPASSWORD=alphax_secret_change_me psql -h localhost -U alphax -d alphax -c "SELECT 1;"
```

### 6.2 Python backend (host)
```bash
# from repo root: /home/x3/Desktop/Alphax Projects/Alphax Unified Cyber Kill Chain
pip install --break-system-packages --no-cache-dir -r backend/requirements.txt
# critical: bcrypt must be 4.1.3 (passlib 1.7.4 incompatible with bcrypt 5)
pip install --break-system-packages --force-reinstall bcrypt==4.1.3

# fix stale env: ensure .env DATABASE_URL matches the password you set above
cp .env.example .env   # then edit if you changed password/JWT

# start API (port 8001 because 8000 taken)
nohup python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8001 > /tmp/alphax_api.log 2>&1 &
sleep 3; cat /tmp/alphax_api.log | tail -n 20
curl -s http://localhost:8001/health
# → {"status":"ok","service":"alphax-api","version":"0.1.0","executor":"host","phases":18}
```

If `8001` also busy, pick any free: `--port 8002` and update `frontend/vite.config.ts:10` proxy accordingly.

### 6.3 Frontend
```bash
cd frontend
npm install                 # 211 packages, vite 5.4.21
# patch proxy if API not on 8001 (already done for 8001):
# vite.config.ts:10 '/api' -> http://localhost:8001 , '/ws' -> ws://localhost:8001
# src/hooks/useEngagementWS.ts:11 port 8001
# src/App.tsx:38 hint updated to 8001
nohup npm run dev -- --port 3002 --host 0.0.0.0 > /tmp/alphax_front.log 2>&1 &
sleep 5; cat /tmp/alphax_front.log | tail -n 20
curl -s -I http://localhost:3002/ | head
# → 200 OK, Vite ready
```

Keep both logs: `tail -f /tmp/alphax_api.log /tmp/alphax_front.log`.

## 7. Database Initialization
`backend/app/main.py:12` lifespan calls `database.py:13` `init_db()` → `Base.metadata.create_all` creates if not exists:

- `engagements` (id UUID, name, scope_cidr, status, current_phase, authorized_by)
- `targets` (ip, hostname, ports JSONB, discovered_in_phase)
- `credentials` (username, password_or_hash, hash_type, cracked)
- `commands` (phase, tool_name, raw_command, params JSONB, status, stdout/stderr, exit_code)
- `results` (command_id unique, raw_output, parsed_data JSONB)
- `asset_edges`

Existing tables from prior `alphax_platform` (`agent_logs` etc.) are left untouched; verify with:

```bash
psql -h localhost -U alphax -d alphax -c "\dt"
# should list engagements, targets, credentials, commands, results, asset_edges alongside old tables
```

Migrations: `alembic.ini:1` stub; for production switch to `alembic upgrade head` instead of `create_all`.

## 8. Health Checks
```bash
curl -s http://localhost:8001/health | python3 -m json.tool
curl -s http://localhost:8001/ | python3 -m json.tool
curl -s http://localhost:8001/docs | head   # Swagger UI
curl -s http://localhost:3002/ | head       # Vite HTML
```

## 9. Authentication (Single-Operator JWT)
`backend/app/routers/auth.py:16` uses `OAuth2PasswordBearer` + `passlib`/`bcrypt` + `python-jose`.

- User: `operator` (from `ALPHAX_OPERATOR_USER`)
- Pass: `AlphaX!2026` (from `ALPHAX_OPERATOR_PASSWORD`)
- Endpoint `POST /api/v1/auth/login` expects `application/x-www-form-urlencoded` (`username`+`password`).

```bash
curl -s -X POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=operator&password=AlphaX!2026" | python3 -m json.tool
# → {"access_token":"eyJ...","token_type":"bearer"}

TOKEN=$(curl -s -X POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=operator&password=AlphaX!2026" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
echo $TOKEN
# save
export TOKEN
```

All subsequent `/api/v1/engagements` and `/commands` require `Authorization: Bearer $TOKEN` (`routers/auth.py:44` `get_current_user`).

JWT: `HS256`, `expire 480 min` (`config.py:7`), `exp` in payload.

**Troubleshooting:** `ValueError: password cannot be longer than 72 bytes` → `bcrypt==4.1.3` not `5` (see §19). `Internal Server Error` on login → check `/tmp/alphax_api.log`, ensure `.env` readable (env_file relative to CWD repo root).

## 10. Engagement Lifecycle
Engagement = authorized scope container. `models.py:52` `Engagement` defaults `status active`, `current_phase 1`.

```bash
# create
curl -s -X POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"VulnHub Kioptrix","scope_cidr":"192.168.56.0/24"}' | python3 -m json.tool
# → {"id":"80e7b1a0-a15b-4013-8aaf-2b99e34f8362", ... "current_phase":1}

# list
curl -s http://localhost:8001/api/v1/engagements -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# get one
EID=80e7b1a0-a15b-4013-8aaf-2b99e34f8362
curl -s http://localhost:8001/api/v1/engagements/$EID -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# move phase (manual, normally auto-advances on success via orchestrator.py:18)
curl -s -X PATCH http://localhost:8001/api/v1/engagements/$EID \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"current_phase":2}' | python3 -m json.tool

# phases meta
curl -s http://localhost:8001/api/v1/engagements/$EID/killchain/phases -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 40
# tools for phase 1
curl -s http://localhost:8001/api/v1/engagements/$EID/killchain/tools/1 -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# knowledge graph
curl -s http://localhost:8001/api/v1/engagements/$EID/graph -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**States:** `draft → active → blocked_needs_input` (on failure, `orchestrator.py:24`) → `completed/archived`. `blocked_needs_input` blocks forward phase until operator resolves.

## 11. War Room UI
Open `http://localhost:3002/` (or 3000 if Docker).

**Header:** `ALPHAX CYBER KILL-CHAIN` + `AUTHORIZED ENGAGEMENTS ONLY` banner. Top inputs:

- **API Token (JWT)** — paste token from §9 (stored `localStorage:alphax_token`)
- **Engagement ID (UUID)** — paste `80e7b1a0...` (stored `localStorage:alphax_eid`)

**Stats grid** (`KillChainDashboard.tsx:1`): Engagement name/scope, current phase, `WS connected/disconnected`, Knowledge Graph `hosts • creds`, commands `total • succeeded • pending_approval`.

**AttackFlow** (`AttackFlow.tsx:1`): 18 buttons `1 Recon … 18 Objectives`, cyan  = current, emerald = completed, gray = pending. Click to open `PhasePanel` for that phase.

**PhasePanel** (`PhasePanel.tsx:1`):
1. Tool dropdown (from `TOOL_MAPPING` for that phase)
2. Dynamic param form (examples: `target 192.168.56.101`, `scan_type -sV -sC`, `ports -p-`, `payload linux/x64/meterpreter/reverse_tcp`)
3. **`1. Create Command (Pending Approval)`** → POST `/commands` creates `status pending_approval`
4. Box shows `Command 22031370… — requires HITL gate` with **`2. Approve ✓`** → `POST .../approve` (`approved`) and **`3. Execute ▶`** → `POST .../execute` (`running` → streaming)

**LiveConsole** (`LiveConsole.tsx:1`): WS streaming `stdout/stderr` line-by-line (`parser` sends chunks via `ws.py:19`), plus `[FINISHED succeeded exit=0]`. `Clear` button.

**KnowledgeGraph** (`KnowledgeGraph.tsx:1`): hosts (ip, hostname, open count, `P phase`) and credentials (username, hash_type). Auto-populated after Recon `nmap` parser.

**Recent Commands** box: last 20 commands with `P phase tool raw …` + status badge (`pending_approval` amber, `succeeded` emerald, `failed` red).

## 12. API Usage — cURL Step-by-Step
Complete HITL flow for **Reconnaissance → nmap** (verified against `127.0.0.1`):

```bash
TOKEN=...; EID=80e7b1a0-a15b-4013-8aaf-2b99e34f8362

# 1. Get tools for phase 1
curl -s http://localhost:8001/api/v1/engagements/$EID/killchain/tools/1 -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# 2. Create command (phase 1, tool nmap) — uses assemble_command in executor.py:35
#    template "nmap {scan_type} {ports} {extra} {target}" with flag handling (scan_type/ports not quoted)
CID=$(curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"phase":1,"tool_name":"nmap","params":{"target":"127.0.0.1","scan_type":"-sV -oX -","ports":"-p 22,80","extra":""}}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo $CID  # 65705abf-297a-4ce3-9092-defe3ea501c5 (example)
# raw_command built: "nmap -sV -oX - -p 22,80  127.0.0.1" (check via GET)

# 3. Approve (HITL gate 1)
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands/$CID/approve \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# → status approved

# 4. Execute (HITL gate 2) — background task streams WS, runs via host subprocess
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands/$CID/execute \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# → status running

# 5. Poll
sleep 8
curl -s http://localhost:8001/api/v1/engagements/$EID/commands -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 80
# succeeded, stdout contains <?xml ... <nmaprun ...>

# 6. Result + parsed hosts
curl -s http://localhost:8001/api/v1/engagements/$EID/commands/$CID/result -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -n 80
# parsed_data: {"hosts":[{"ip":"127.0.0.1","hostname":"localhost","ports":[...]}],"parsed":true,"host_count":1}

# 7. Graph (auto-fed)
curl -s http://localhost:8001/api/v1/engagements/$EID/graph -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# {"targets":[{"ip":"127.0.0.1","ports":[...]}]}

# 8. Alternative: raw_command direct (bypass template)
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"phase":1,"tool_name":"nmap","raw_command":"nmap -sV -p 80 192.168.56.101","params":null}' | python3 -m json.tool
```

**Other phases** same pattern: `phase 5` `msfconsole` with `module`, `target`; `phase 13` `secretsdump.py` with `domain/user/password/target`, etc. See `killchain_engine.py:40` `TOOL_MAPPING`.

**List targets added manually:**
```bash
curl -s http://localhost:8001/api/v1/engagements/$EID/targets -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/targets -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"ip":"192.168.56.102","hostname":"win7","ports":[]}' | python3 -m json.tool
```

## 13. 18 Phases & Tool Mapping (`backend/app/killchain_engine.py:12`)
| # | Phase | MITRE | Example Tools (`TOOL_MAPPING`) |
|---|-------|-------|-------------------------------|
|1|Reconnaissance|TA0043|nmap `-sV -sC`, masscan, nuclei|
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

Each `ToolSpec` has `name, template, description, params: ParamSpec[], parser` (`nmap_xml`, `generic`). `list_phases()` and `get_tools_for_phase()` exposed via `/killchain/*`.

## 14. Executor & HITL Gates (`backend/app/executor.py:1`)
- **Allow-list** `config.py:8` `ALLOWED_TOOLS` + **deny patterns** (`rm -rf /`, `mkfs.`, fork bomb, `dd of=/dev/`, `shutdown`).
- **Assemble** `assemble_command()` — flag params (`scan_type, ports, extra`) are NOT `shlex.quote`d as single quoted string; data params (`target, user, password`) ARE quoted. Prevents `nmap '-sV -oX -'` bug fixed 2026-09-02.
- **Run** `run_via_subprocess()` (`asyncio.create_subprocess_shell`, streamed `readline` → `ws_broadcast` `type:console` per line, timeout 300s, kill on timeout exit 124).
- **Gates** `routers/commands.py:14` `create → pending_approval`; `approve → approved` (sets `approved_by`); `execute → running` (BackgroundTasks) → `succeeded/failed` + `Result` row + `orchestrator.on_command_finished()` (auto-advance `current_phase` on success, else `blocked_needs_input`).
- **Host vs Docker:** `EXECUTOR_MODE=host` uses shell directly; Docker would `docker exec kali <cmd>` (not used here, daemon down).

## 15. Output Parsing & Knowledge Graph
- `parsers/nmap_parser.py:1` `parse_nmap_xml()` via `xml.etree` → `{hosts:[{ip,hostname,ports:[{port,protocol,state,service,version}]}]}`. Fallback `parse_nmap_grepable()`.
- `parsers/generic.py:1` preview len.
- On `hosts` found, `executor.py:144` inserts `Target` per host (dedup by `engagement_id+ip`) with `discovered_in_phase`, broadcasts `type:knowledge_update`, committed before `command_finished`.
- Next phases can pre-fill `target` inputs from graph (UI reads `GET /graph` every 6s).

## 16. WebSocket Live Console
- Route `routers/ws.py:11` `GET /ws/engagements/{id}` (`ConnectionManager`).
- UI `useEngagementWS.ts:11` connects to `ws://host:8001/ws/engagements/{EID}` (port auto to 8001). Messages:
  - `{"type":"connected"}`
  - `{"type":"console","command_id":"...","line":"Nmap 7.99 ..."}` per stdout line
  - `{"type":"knowledge_update","target":{...}}`
  - `{"type":"command_finished","command_id":"...","status":"succeeded","exit_code":0,"parsed":{...}}`
  - `{"type":"command_approved"}`
- Test via `wscat`: `wscat -c ws://localhost:8001/ws/engagements/$EID`.

## 17. VulnHub Lab Setup
AlphaX expects isolated lab `VULNHUB_TARGETS` (default `192.168.56.0/24,10.0.0.0/24`).

**Steps:**
1. Download OVA from vulnhub.com (e.g., Kioptrix Level 1, Metasploitable2).
2. VirtualBox: `File → Import Appliance → Kioptrix.ova`, **Network → Host-only Adapter** (`vboxnet0` 192.168.56.1) or `Bridged` + `Host-Only`.
3. Start VM: `VBoxManage startvm "Kioptrix" --type headless`; find IP: `nmap -sn 192.168.56.0/24` or `arp -a`.
4. Verify Kali can reach: `ping 192.168.56.101`, `nmap -sV 192.168.56.101`.
5. Create engagement with that CIDR: `scope_cidr=192.168.56.0/24`.
6. In UI Phase 1 select `nmap` `target=192.168.56.101` `scan_type=-sV -sC` `ports=-p-`.

**Do not** point at non-authorized scopes; scope check is UI banner + future `EXECUTOR` CIDR validation.

## 18. Full Walkthrough — Verified Against 127.0.0.1
On this host `127.0.0.1:80 Apache 2.4.68 (Debian)` served as stand-in target (since VulnHub VM not yet imported). Steps performed 2026-09-02 13:48 UTC:

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" -d "username=operator&password=AlphaX!2026" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
EID=80e7b1a0-a15b-4013-8aaf-2b99e34f8362

CID=$(curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"phase":1,"tool_name":"nmap","params":{"target":"127.0.0.1","scan_type":"-sV -oX -","ports":"-p 22,80","extra":""}}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
# → 65705abf-... raw "nmap -sV -oX - -p 22,80  127.0.0.1"

curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands/$CID/approve -H "Authorization: Bearer $TOKEN"
curl -s -X POST http://localhost:8001/api/v1/engagements/$EID/commands/$CID/execute -H "Authorization: Bearer $TOKEN"
sleep 8
curl -s http://localhost:8001/api/v1/engagements/$EID/commands -H "Authorization: Bearer $TOKEN" | grep -A2 succeeded
curl -s http://localhost:8001/api/v1/engagements/$EID/graph -H "Authorization: Bearer $TOKEN"
# → 1 target 127.0.0.1 ports 22 closed, 80 open Apache
```

Prior buggy attempt `22031370...` failed due to `assemble_command` quoting (`' -sV -oX -'` → `Scantype not supported`); fixed, verified second run succeeded.

Repeat for VulnHub IP replacing `127.0.0.1`, then continue `Phase 5 Exploitation` etc.

## 19. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `docker compose up` → `Cannot connect to Docker daemon at ...desktop/docker.sock` | Docker Desktop not running | `systemctl --user start docker` or host mode (this doc §6). |
| `curl /auth/login` → `500 Internal Server Error` `ValueError: password cannot be longer than 72 bytes` | `bcrypt 5.0.0` with `passlib 1.7.4` | `pip install --break-system-packages --force-reinstall bcrypt==4.1.3` (verified) |
| `bcrypt` `AttributeError: __about__` warning | Same as above | Harmless after downgrade; trapped log shows success. |
| `GET /health` connection refused on 8000 | Port occupied (`1144` NeuroSploit) | Use `8001` (or `lsof -i :8000`, `kill`, or change `API_PORT`). Update `vite.config.ts:10` and `useEngagementWS.ts:11`. |
| Frontend blank, token not persisted | Wrong port for proxy | Ensure `vite --port 3002` matches `CORS_ORIGINS` and API `8001`; check browser console WS error. |
| `nmap` → `Scantype not supported` | Old `executor.py` quoted `scan_type` | Pull fixed `executor.py:35` (flag params not quoted). Use `scan_type="-sV -oX -"` properly. |
| `Failed: Tool not in ALLOWED_TOOLS` | `ALLOWED_TOOLS` missing entry | Add to `.env` `ALLOWED_TOOLS` comma list and restart API. |
| `blocked_needs_input` after phase | `orchestrator.py:24` failure gate | Resolve via UI (re-run or advance with PATCH `/engagements/{id}` `{"current_phase":2}`), or create alternate tool per `suggest_next_tool`. |
| `\dt` shows no engagements | `DATABASE_URL` password mismatch | `psql -U postgres -c "ALTER USER alphax ..."` to match `.env` `DATABASE_URL`. |
| WS `disconnected` | API not running | `cat /tmp/alphax_api.log`, `curl /health`, restart `uvicorn`. |

Logs:
```bash
tail -f /tmp/alphax_api.log /tmp/alphax_front.log
psql -h localhost -U alphax -d alphax -c "SELECT status,current_phase FROM engagements;"
ss -tulpn | grep -E "8001|3002|5432"
```

## 20. Security Considerations
- **Authorization:** JWT single operator v0; for multi-user, replace `routers/auth.py:16` hash with DB table + RBAC.
- **Allow-list:** Edit `ALLOWED_TOOLS` minimally; adding `bash` or `rm` is blocked by deny patterns anyway.
- **Scope:** Currently UI banner only; add CIDR validation in `orchestrator.py:14` `can_execute_phase` to reject `target` outside `VULNHUB_TARGETS`.
- **Audit:** All commands stored with `stdout/stderr/exit_code/approved_by`; consider `pgcrypto` for creds encryption.
- **Isolation:** Host executor runs on Kali host; for untrusted targets prefer Docker sidecar (`EXECUTOR_MODE=docker` with `kalilinux/kali-rolling` + `cap_add NET_RAW`).

## 21. Stopping / Restarting
```bash
# host mode
kill $(cat /tmp/alphax_api.pid 2>/dev/null) 2>/dev/null; pkill -f "uvicorn.*8001"; pkill -f "vite.*3002"
# or
ps aux | grep -E "uvicorn|vite" | awk '{print $2}' | xargs kill

# restart
nohup python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8001 > /tmp/alphax_api.log 2>&1 &
nohup npm --prefix frontend run dev -- --port 3002 --host 0.0.0.0 > /tmp/alphax_front.log 2>&1 &

# docker mode
docker compose down
docker compose up --build -d
docker compose logs -f api
```

## 22. Development Notes
- Verify: `python3 -m py_compile backend/app/*.py backend/app/routers/*.py backend/app/parsers/*.py` • `docker compose config` • `npm --prefix frontend run build` (252kB proven)
- API docs: `http://localhost:8001/docs` (Swagger), `http://localhost:8001/redoc`
- Kill-chain logic: `killchain_engine.py:12` `TOOL_MAPPING` drives param forms; add new tool by appending `ToolSpec`.
- Frontend build: `tsc && vite build` → `dist/` (served by Vite preview or Docker nginx in prod).

---

**Status on this Kali (2026-09-02 13:49 UTC):** API `http://localhost:8001` healthy, 1 engagement `80e7b1a0...` active phase 1, 1 host `127.0.0.1` auto-discovered, frontend `http://localhost:3002/` ready. Import VulnHub OVA → repeat walkthrough with `192.168.56.101`.

**Quick re-login:**
```bash
export TOKEN=$(curl -s -X POST http://localhost:8001/api/v1/auth/login -d "username=operator&password=AlphaX!2026" -H "Content-Type: application/x-www-form-urlencoded" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
export EID=80e7b1a0-a15b-4013-8aaf-2b99e34f8362
echo TOKEN $TOKEN  # paste into UI top bar along with $EID
```
