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

# Match "Nmap scan report for <name|ip>" and "Host is up ... Address: <ip>"
_NMAP_REPORT_RE = re.compile(r"Nmap scan report for\s+(?:([\w.\-]+)\s+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?", re.MULTILINE)
_NMAP_OPEN_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open(?:\s+(\S+))?(?:\s+(.*?))?$", re.MULTILINE)

def parse_nmap_text(text: str) -> dict[str, Any]:
    """Robust nmap plaintext parser: extracts host IP + open ports from
    standard nmap human-readable output. Returns {hosts: [{ip, hostname, ports}], parsed: False, fallback:'text'}
    """
    if not text:
        return {"hosts": [], "parsed": False, "fallback": "text"}
    host_ports: dict[str, list[dict]] = {}
    for m in _NMAP_REPORT_RE.finditer(text):
        name, ip = m.group(1), m.group(2)
        host_ports.setdefault(ip, [])
        if name:
            # attach hostname later as side effect via dict
            host_ports[ip + "::host"] = [name] if ip + "::host" not in host_ports else host_ports[ip + "::host"]
    for m in _NMAP_OPEN_RE.finditer(text):
        port, proto, service, version = int(m.group(1)), m.group(2), m.group(3) or "", m.group(4) or ""
        # attach to most recent host in text
        ips = list(host_ports.keys())
        if not ips:
            continue
        last_ip = next((k for k in reversed(ips) if "::" not in k), None)
        if not last_ip:
            continue
        host_ports[last_ip].append({"port": port, "protocol": proto, "state": "open", "service": service, "version": version.strip()})
    hosts = []
    for key, ports in host_ports.items():
        if "::" in key:
            continue
        if not ports:
            continue
        hosts.append({"ip": key, "hostname": None, "ports": ports})
    return {"hosts": hosts, "parsed": False, "fallback": "text", "host_count": len(hosts)}
