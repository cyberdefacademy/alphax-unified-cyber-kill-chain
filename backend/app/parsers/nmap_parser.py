import re
import xml.etree.ElementTree as ET
from typing import Any

def parse_nmap_xml(xml_str: str) -> dict[str, Any]:
    """Parse nmap -oX XML to Knowledge Graph friendly dict.
    Returns {hosts: [{ip, hostname, ports: [{port, protocol, state, service, version}]}]}
    Falls back to empty if not XML.
    """
    if not xml_str or "<nmaprun" not in xml_str:
        return {"raw": xml_str[:5000] if xml_str else "", "hosts": [], "parsed": False}
    try:
        root = ET.fromstring(xml_str)
        hosts = []
        for host in root.findall("host"):
            ip = None
            hostname = None
            status = host.find("status")
            if status is not None and status.get("state") == "down":
                continue
            for addr in host.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.get("addr")
            for hn in host.findall("hostnames/hostname"):
                hostname = hn.get("name")
                break
            ports = []
            for port in host.findall("ports/port"):
                portid = port.get("portid")
                protocol = port.get("protocol")
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                svc = port.find("service")
                service = svc.get("name") if svc is not None else ""
                version = " ".join(filter(None, [svc.get("product") if svc is not None else None, svc.get("version") if svc is not None else None]))
                ports.append({"port": int(portid), "protocol": protocol, "state": state, "service": service, "version": version})
            if ip:
                hosts.append({"ip": ip, "hostname": hostname, "ports": ports})
        return {"hosts": hosts, "parsed": True, "host_count": len(hosts)}
    except ET.ParseError as e:
        return {"raw": xml_str[:5000], "hosts": [], "parsed": False, "error": str(e)}

# Match "Nmap scan report for <name> (<ip>)" / "for <ip>" (hostname optional)
_NMAP_REPORT_RE = re.compile(r"Nmap scan report for\s+(?:([\w.\-]+)\s+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?", re.MULTILINE)
# NOTE: service/version separators are [ \t]+ (never \s+) so the version group
# cannot slurp the next line across a blank line (e.g. "Nmap done: ...").
_NMAP_OPEN_RE = re.compile(r"^(\d{1,5})/(tcp|udp)[ \t]+open(?:[ \t]+(\S+))?(?:[ \t]+(.*?))?[ \t]*$", re.MULTILINE)

def parse_nmap_text(text: str) -> dict[str, Any]:
    """Robust nmap plaintext parser: extracts host IP + open ports from
    standard nmap human-readable output. Returns {hosts: [{ip, hostname, ports}], parsed: False, fallback:'text'}
    """
    if not text:
        return {"hosts": [], "parsed": False, "fallback": "text"}
    # Positional sweep: walk report + port matches in text order so each
    # open port attaches to its nearest preceding host report.
    events: list[tuple[int, str, re.Match]] = (
        [(m.start(), "host", m) for m in _NMAP_REPORT_RE.finditer(text)]
        + [(m.start(), "port", m) for m in _NMAP_OPEN_RE.finditer(text)]
    )
    events.sort(key=lambda e: e[0])
    host_ports: dict[str, list[dict]] = {}
    host_names: dict[str, str] = {}
    order: list[str] = []
    current: str | None = None
    for _, kind, m in events:
        if kind == "host":
            name, ip = m.group(1), m.group(2)
            if ip not in host_ports:
                host_ports[ip] = []
                order.append(ip)
            # Don't mistake a bare IP for a hostname
            if name and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", name):
                host_names.setdefault(ip, name)
            current = ip
        else:
            if current is None:
                continue
            port, proto = int(m.group(1)), m.group(2)
            service, version = m.group(3) or "", (m.group(4) or "").strip()
            host_ports[current].append({"port": port, "protocol": proto, "state": "open", "service": service, "version": version})
    hosts = [
        {"ip": ip, "hostname": host_names.get(ip), "ports": host_ports[ip]}
        for ip in order if host_ports[ip]
    ]
    return {"hosts": hosts, "parsed": False, "fallback": "text", "host_count": len(hosts)}
