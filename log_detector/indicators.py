'''
Deterministic strong indicators.

Small LLMs recognise attacks but often under-rate them. These rules set a minimum severity for
unambiguous patterns, so known-bad events are never classified as Benign. Patterns are kept
specific to avoid adding false positives; everything else is left to the LLM.
'''
import re
from urllib.parse import unquote_plus

SEVERITY_RANK = {"UNKNOWN": -1, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# (name, minimum severity, MITRE technique, regex) matched against the URL-decoded event text
TEXT_INDICATORS = [
    ("sql_injection", "HIGH", "T1190",
     r"union(\s|/\*.*?\*/)+(all(\s|/\*.*?\*/)+)?select\s|'\s*or\s+'?\d+'?\s*=\s*'?\d+|information_schema\.|\bsleep\(\s*\d+\s*\)|benchmark\(\s*\d+"),
    ("path_traversal", "HIGH", "T1083", r"(\.\./){2,}|(\.\.\\){2,}"),
    ("xss", "HIGH", "T1189", r"<script[\s>]|javascript:\s*\w+\(|\bonerror\s*="),
    ("log4shell", "CRITICAL", "T1190", r"\$\{jndi:"),
    ("web_command_injection", "HIGH", "T1059", r"[;|`]\s*(wget|curl)\s+https?://|\$\((wget|curl)\s"),
    ("reverse_shell", "CRITICAL", "T1059.004",
     r"/dev/tcp/\d|\bnc(at)?\s+(-\w+\s+)*-[ec]\s|bash\s+-i\s+>&|socket\.socket\(.*connect"),
    ("encoded_shell_command", "HIGH", "T1027", r"base64\s+(-d|--decode)[^|\n]*\|\s*(ba|z|da)?sh\b"),
    ("download_and_execute", "HIGH", "T1105", r"(wget|curl)\s[^|\n]*\|\s*(ba|z|da)?sh\b"),
    ("encoded_powershell", "HIGH", "T1059.001",
     r"powershell(\.exe)?\s.*\s-(e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{20,}|\biex\s*\(|downloadstring\(|frombase64string\("),
    ("certutil_download", "HIGH", "T1105", r"certutil(\.exe)?\s.*-urlcache"),
    ("credential_dumping", "CRITICAL", "T1003", r"mimikatz|sekurlsa::|lsass\.dmp|procdump.*lsass"),
    ("attack_tool_user_agent", "MEDIUM", "T1595", r"\b(sqlmap|nikto|nuclei|masscan|wpscan|dirbuster|gobuster)/"),
]
TEXT_INDICATORS = [(n, s, m, re.compile(p, re.IGNORECASE)) for n, s, m, p in TEXT_INDICATORS]

# Windows Security event IDs
WINDOWS_EVENTS = {
    "1102": ("audit_log_cleared", "HIGH", "T1070.001"),
    "4720": ("user_account_created", "MEDIUM", "T1136.001"),
    "4728": ("added_to_privileged_group", "HIGH", "T1098"),
    "4732": ("added_to_privileged_group", "HIGH", "T1098"),
    "4756": ("added_to_privileged_group", "HIGH", "T1098"),
}
PRIVILEGED_GROUPS = re.compile(r"admin|domain admins|enterprise admins|schema admins|backup operators", re.IGNORECASE)

# File integrity monitoring paths
FIM_PATHS = [
    ("sudoers_modified", "HIGH", "T1548.003", re.compile(r"^/etc/sudoers(\.d/.*)?$")),
    ("credential_file_modified", "MEDIUM", "T1098", re.compile(r"^/etc/(shadow|passwd|gshadow)$")),
    ("ssh_authorized_keys_modified", "MEDIUM", "T1098.004", re.compile(r"/\.ssh/authorized_keys2?$")),
    ("cron_modified", "MEDIUM", "T1053.003", re.compile(r"^/(etc/cron|var/spool/cron)")),
]

def _windows_event(alert: dict):
    win = (alert.get("data") or {}).get("win") or {}
    event_id = str((win.get("system") or {}).get("eventID", ""))
    if event_id not in WINDOWS_EVENTS:
        return None
    name, severity, mitre = WINDOWS_EVENTS[event_id]
    if name == "added_to_privileged_group":
        group = str((win.get("eventdata") or {}).get("targetUserName", ""))
        if not PRIVILEGED_GROUPS.search(group):
            return None
        return name, severity, mitre, f"eventID={event_id} targetUserName={group}"
    return name, severity, mitre, f"eventID={event_id}"

def find_indicators(alert: dict, event_text: str):
    '''Return a list of {name, severity, mitre, match} for every strong indicator in the alert.'''
    found = []
    decoded = unquote_plus(event_text)
    for name, severity, mitre, pattern in TEXT_INDICATORS:
        match = pattern.search(decoded)
        if match:
            found.append({"name": name, "severity": severity, "mitre": mitre, "match": match.group(0).strip()[:200]})

    win = _windows_event(alert)
    if win:
        name, severity, mitre, match = win
        found.append({"name": name, "severity": severity, "mitre": mitre, "match": match})

    syscheck = alert.get("syscheck") or {}
    path = str(syscheck.get("path", ""))
    if path and syscheck.get("event") in ("modified", "added", "deleted", None):
        for name, severity, mitre, pattern in FIM_PATHS:
            if pattern.search(path):
                found.append({"name": name, "severity": severity, "mitre": mitre, "match": f"syscheck.path={path}"})
                break

    return found

def max_severity(*severities):
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, -1))
