import asyncio
import shlex
import re
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .models import Command
from .parsers.nmap_parser import parse_nmap_xml, parse_nmap_text
from .parsers.generic import parse_generic

settings = get_settings()

# Deny list for obviously destructive patterns even if tool is allow-listed
DENY_PATTERNS = [
    r"rm\s+-rf\s+/\b",
    r"mkfs\.",
    r":\(\)\{.*\}.*&",  # fork bomb
    r"dd\s+if=.*of=/dev/",
    r"shutdown",
    r"reboot",
    r"init\s+0",
]

def is_command_allowed(raw: str, tool_name: str) -> tuple[bool, str]:
    if tool_name not in settings.allowed_tools_set:
        return False, f"Tool '{tool_name}' not in ALLOWED_TOOLS allow-list"
    for pat in DENY_PATTERNS:
        if re.search(pat, raw):
            return False, f"Blocked by deny pattern: {pat}"
    return True, "ok"

def assemble_command(template: str, params: dict | None) -> str:
    if not params:
        return template
    # For host shell execution we must NOT quote flags as single string.
    # Only quote values that are likely to be data (target, user, password, etc.)
    # Flag-like params (scan_type, ports, extra) are left unquoted but sanitized via allow-list.
    safe = {}
    for k, v in params.items():
        if v is None:
            continue
        sval = str(v)
        # Do NOT quote flag-style params that the ToolSpec templates insert as flags
        if k in ("scan_type", "ports", "extra", "wordlist", "severity"):
            # Basic sanitization: remove ; && || | ` $()
            if re.search(r"[;&|`$()]", sval):
                sval = re.sub(r"[;&|`$()]", "", sval)
            safe[k] = sval
        else:
            safe[k] = shlex.quote(sval)
    try:
        return template.format(**safe)
    except KeyError:
        return template

async def run_via_subprocess(raw_command: str, timeout: int = 300, on_line: Optional[Callable[[str], None]] = None) -> tuple[str, str, int]:
    """Execute raw_command via shell on host Kali, streaming lines to on_line."""
    proc = await asyncio.create_subprocess_shell(
        raw_command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    async def drain(stream, chunks, is_stderr=False):
        while True:
            line = await stream.readline()
            if not line:
                break
            chunks.append(line)
            if on_line:
                try:
                    # best effort ws push
                    await on_line(line.decode(errors="ignore"))
                except Exception:
                    pass
            else:
                # also ignore
                pass

    try:
        await asyncio.wait_for(
            asyncio.gather(drain(proc.stdout, stdout_chunks), drain(proc.stderr, stderr_chunks), proc.wait()),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        stdout = b"".join(stdout_chunks).decode(errors="ignore")
        stderr = b"".join(stderr_chunks).decode(errors="ignore") + "\n[TIMEOUT after {}s]".format(timeout)
        return stdout, stderr, 124

    stdout = b"".join(stdout_chunks).decode(errors="ignore")
    stderr = b"".join(stderr_chunks).decode(errors="ignore")
    return stdout, stderr, proc.returncode if proc.returncode is not None else -1

def parse_output(tool_name: str, stdout: str, stderr: str) -> dict:
    if tool_name == "nmap":
        if "<nmaprun" in stdout:
            return parse_nmap_xml(stdout)
        elif stdout:
            return parse_nmap_text(stdout)
    return parse_generic(stdout, stderr)

class KaliExecutor:
    """Host Kali executor with HITL gates enforced at router layer."""

    async def execute(
        self,
        command: Command,
        db: AsyncSession,
        ws_broadcast: Optional[Callable[[dict], None]] = None,
        timeout: int = 300,
    ) -> Command:
        raw = command.raw_command
        allowed, reason = is_command_allowed(raw, command.tool_name)
        if not allowed:
            command.status = "blocked"
            command.stderr = reason
            command.finished_at = datetime.now(timezone.utc)
            await db.commit()
            return command

        command.status = "running"
        command.started_at = datetime.now(timezone.utc)
        await db.commit()

        async def on_line_cb(line: str):
            if ws_broadcast:
                try:
                    await ws_broadcast({"type": "console", "command_id": str(command.id), "line": line})
                except Exception:
                    pass

        stdout, stderr, exit_code = await run_via_subprocess(raw, timeout=timeout, on_line=on_line_cb)

        command.stdout = stdout[:200000]  # truncate for DB
        command.stderr = stderr[:50000]
        command.exit_code = exit_code
        command.finished_at = datetime.now(timezone.utc)
        command.status = "succeeded" if exit_code == 0 else "failed"

        # parse
        parsed = parse_output(command.tool_name, stdout, stderr)
        # upsert Result
        from .models import Result
        result = Result(command_id=command.id, raw_output=(stdout + stderr)[:200000], parsed_data=parsed)
        db.add(result)

        # Auto-feed Knowledge Graph for nmap hosts
        if parsed.get("hosts"):
            from .models import Target
            from sqlalchemy import select
            for h in parsed["hosts"]:
                ip = h.get("ip")
                if not ip:
                    continue
                # avoid dup
                existing = await db.execute(select(Target).where(Target.engagement_id == command.engagement_id, Target.ip == ip))
                if existing.scalars().first():
                    continue
                tgt = Target(
                    engagement_id=command.engagement_id,
                    ip=ip,
                    hostname=h.get("hostname"),
                    ports=h.get("ports"),
                    discovered_in_phase=command.phase,
                )
                db.add(tgt)
                if ws_broadcast:
                    try:
                        await ws_broadcast({"type": "knowledge_update", "target": {"ip": ip, "ports": h.get("ports")}})
                    except Exception:
                        pass

        await db.commit()
        await db.refresh(command)

        if ws_broadcast:
            try:
                await ws_broadcast({"type": "command_finished", "command_id": str(command.id), "status": command.status, "exit_code": exit_code, "parsed": parsed})
            except Exception:
                pass

        return command
