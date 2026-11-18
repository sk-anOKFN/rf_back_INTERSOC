import json
import logging
import queue
import signal
import threading
import time

import requests
from postgre_store import PostgresStorage
from wazuh_client import WazuhIndexerClient
from indicators import find_indicators, max_severity
import config

logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("detector")

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# JSON schema passed to Ollama's "format" option to enforce the output structure.
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "benign_explanation": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "event_category": {"type": "string"},
        "mitre": {"type": "array", "items": {"type": "string"}},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "confidence": {"type": "number"}
    },
    "required": ["summary", "benign_explanation", "evidence", "event_category",
                 "mitre", "severity", "confidence"]
}

_stop = threading.Event()
_work_q: "queue.Queue[dict]" = queue.Queue(maxsize = config.INDEXER_PAGE_SIZE)

def wait_for_ollama():
    log.info("Waiting for Ollama at %s ...", config.OLLAMA_URL)

    for attempt in range(60):
        try:
            response = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                if any(config.OLLAMA_MODEL in m['name'] for m in models):
                    log.info("Ollama ready with %s", config.OLLAMA_MODEL)
                    return True
        except requests.RequestException:
            pass

        log.info("Attempt %d/60...", attempt + 1)
        time.sleep(2)

    log.error("Ollama timeout")
    return False

# ============================ Alert normalization ============================ #
def _truncate(value, limit: int):
    '''Recursively shorten long strings so one field cannot flood the prompt.'''
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "...[truncated]"
    if isinstance(value, dict):
        return {k: _truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate(v, limit) for v in value[:50]]
    return value

def _leaf_strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaf_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _leaf_strings(v)
    elif value is not None:
        yield str(value)

def _flatten(value, prefix=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _flatten(v, f"{prefix}{k}.")
    elif value not in (None, "", [], {}):
        yield prefix.rstrip("."), value

def get_log_family(alert: dict) -> str:
    '''Coarse source family, used for log_type and to pick the prompt guidance.'''
    rule = alert.get('rule') or {}
    groups = {str(g).lower() for g in rule.get('groups') or []}
    decoder = str((alert.get('decoder') or {}).get('name', '')).lower()
    location = str(alert.get('location', '')).lower()

    if 'windows' in groups or decoder.startswith('windows') or location == 'eventchannel':
        return 'windows'
    if 'syscheck' in groups or 'syscheck' in decoder:
        return 'fim'
    if groups & {'ids', 'suricata'} or 'suricata' in decoder:
        return 'ids'
    if groups & {'web', 'accesslog', 'web_scan', 'attack'} or 'web-accesslog' in decoder:
        return 'web'
    if 'firewall' in groups:
        return 'firewall'
    if 'audit' in groups or decoder.startswith('auditd'):
        return 'audit'
    return 'system'

def get_raw_message(alert: dict) -> str:
    '''Log line used for display and Drain3 templates; synthesized when full_log is missing.'''
    full_log = alert.get('full_log')
    if full_log:
        return full_log

    rule = alert.get('rule') or {}
    data = alert.get('data') or {}
    parts = [str(v) for k, v in _flatten(data) if k.endswith('message')][:1]
    if not parts:
        pairs = [f"{k}={v}" for k, v in _flatten(data) if not isinstance(v, list)]
        parts = pairs[:12]
    description = rule.get('description') or 'Wazuh event'
    return f"{description}: {' '.join(parts)}"[:config.MAX_FIELD_CHARS] if parts else description

# Per-family projection of data.audit-like fields: only the keys an LLM can use for
# reasoning, dropping pid/ppid, syscall register arguments and hex blobs.
AUDIT_DATA_KEYS = ('command', 'exe', 'cwd', 'success', 'key', 'subj', 'uid', 'euid',
                   'execve', 'file')

def _project_data(data: dict, family: str):
    if not isinstance(data, dict):
        return data
    if family == 'audit' and 'audit' in data:
        projected = {k: v for k, v in data['audit'].items() if k in AUDIT_DATA_KEYS}
        return {**{k: v for k, v in data.items() if k != 'audit'}, 'audit': projected}
    return data

def build_event(alert: dict, family: str) -> dict:
    '''Compact LLM input. rule.level is left out on purpose: the partner sets it uniformly.'''
    rule = alert.get('rule') or {}
    agent = alert.get('agent') or {}
    decoder = alert.get('decoder') or {}
    mitre = rule.get('mitre') or {}

    event = {
        'timestamp': alert.get('timestamp'),
        'agent': {'name': agent.get('name'), 'ip': agent.get('ip')},
        'location': alert.get('location'),
        'decoder': decoder.get('name'),
        'program': (alert.get('predecoder') or {}).get('program_name'),
        'rule_description': rule.get('description'),
        'rule_groups': rule.get('groups'),
        'rule_mitre': mitre.get('id'),
        'full_log': alert.get('full_log'),
        'data': _project_data(alert.get('data'), family),
    }
    syscheck = alert.get('syscheck')
    if isinstance(syscheck, dict):
        event['syscheck'] = {
            k: syscheck.get(k)
            for k in ('path', 'event', 'changed_attributes', 'uname_after', 'perm_after', 'size_after')
            if syscheck.get(k) is not None
        }

    event = {k: v for k, v in event.items() if v not in (None, "", [], {})}
    event = _truncate(event, 500)
    if 'full_log' in event and isinstance(alert.get('full_log'), str):
        event['full_log'] = _truncate(alert['full_log'], config.MAX_FIELD_CHARS)
    return event

def extract_context(alert: dict) -> dict:
    '''Fields the dashboard displays, taken from the alert rather than from the LLM.'''
    data = alert.get('data') or {}
    win = (data.get('win') or {}).get('eventdata') or {}
    return {
        'hostname': (alert.get('agent') or {}).get('name') or (alert.get('predecoder') or {}).get('hostname'),
        'service': (alert.get('predecoder') or {}).get('program_name') or (alert.get('decoder') or {}).get('name'),
        'user': data.get('srcuser') or data.get('dstuser') or win.get('targetUserName') or win.get('subjectUserName'),
        'source_ip': data.get('srcip') or data.get('src_ip') or win.get('ipAddress'),
        'rule_id': (alert.get('rule') or {}).get('id'),
        'rule_description': (alert.get('rule') or {}).get('description'),
    }

def should_analyze(alert: dict) -> bool:
    rule = alert.get('rule') or {}
    rule_id = str(rule.get('id', ''))
    if int(rule.get('level') or 0) < config.MIN_RULE_LEVEL:
        return False
    if config.RULE_ID_ALLOWLIST and rule_id not in config.RULE_ID_ALLOWLIST:
        return False
    if rule_id in config.RULE_ID_DENYLIST:
        return False
    return True

# ================================ LLM analysis ================================ #
def call_ollama(prompt: str):
    payload = {
        "model": config.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": config.OLLAMA_TEMPERATURE,
            "num_predict": config.OLLAMA_NUM_PREDICT
        }
    }
    if config.OLLAMA_FORMAT == "schema":
        payload["format"] = OUTPUT_SCHEMA
    elif config.OLLAMA_FORMAT == "json":
        payload["format"] = "json"

    try:
        response = requests.post(f"{config.OLLAMA_URL}/api/generate", json=payload,
                                 timeout=config.OLLAMA_TIMEOUT)
    except requests.RequestException as e:
        log.warning("Ollama error: %s", e)
        return None

    if response.status_code != 200:
        log.warning("Ollama HTTP %s: %s", response.status_code, response.text[:300])
        return None

    llm_output = response.json().get('response', '').strip()
    # Clean markdown code blocks if present (only happens with OLLAMA_FORMAT=none)
    if '```json' in llm_output:
        llm_output = llm_output.split('```json')[1].split('```')[0].strip()
    elif '```' in llm_output:
        llm_output = llm_output.split('```')[1].split('```')[0].strip()

    try:
        parsed = json.loads(llm_output)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError as e:
        log.warning("Invalid JSON from LLM: %s", e)
        return None

def verify_evidence(evidence, event_text: str):
    '''Keep only evidence that quotes something actually present in the event.'''
    verified, dropped = [], 0
    for item in evidence:
        item = str(item).strip()
        candidates = [item, item.split('=', 1)[-1], item.split(':', 1)[-1]]
        candidates = [c.strip().strip('"\'`') for c in candidates]
        if any(len(c) >= 3 and c.lower() in event_text for c in candidates):
            verified.append(item)
        else:
            dropped += 1
    return verified, dropped

def classify(severity: str, confidence: float, evidence: list, has_indicator: bool = False):
    '''The verdict is decided here, not by the model.'''
    if severity in ("CRITICAL", "HIGH"):
        indicator_ok = has_indicator or not config.REQUIRE_INDICATOR_FOR_ANOMALY
        if evidence and confidence >= config.DETECTION_THRESHOLD and indicator_ok:
            return "Anomaly", True
        return "Needs Attention", False
    if severity == "MEDIUM":
        return "Needs Attention", False
    return "Benign", False

def analyze_alert(alert: dict, family: str) -> dict:
    event = build_event(alert, family)
    prompt = config.WAZUH_PROMPT.format(
        family_guidance = config.FAMILY_GUIDANCE.get(family, ""),
        examples = config.FEW_SHOT_EXAMPLES if config.PROMPT_EXAMPLES else "",
        event = json.dumps(event, indent=1, ensure_ascii=False)
    )

    llm_result = call_ollama(prompt)
    if llm_result is None:
        llm_result = call_ollama(prompt)  # one retry

    context = extract_context(alert)
    context['timestamp'] = alert.get('timestamp')
    context['model'] = config.OLLAMA_MODEL

    # Matched against the whole alert, since build_event() truncates long fields
    found = find_indicators(alert, "\n".join(_leaf_strings(alert)))
    context['indicators'] = found

    if llm_result is None:
        if not found:
            return {**context, 'severity': 'UNKNOWN', 'classification': 'Unanalyzed',
                    'is_anomaly': False, 'description': 'LLM analysis failed', 'error': 'llm_failed'}
        llm_result = {'summary': 'LLM analysis failed; verdict based on strong indicators only.',
                      'severity': 'INFO', 'confidence': 0.0, 'error': 'llm_failed'}

    severity = str(llm_result.get('severity', '')).upper()
    if severity not in SEVERITIES:
        severity = 'UNKNOWN'
    try:
        confidence = min(max(float(llm_result.get('confidence', 0)), 0.0), 1.0)
    except (TypeError, ValueError):
        confidence = 0.0

    evidence = llm_result.get('evidence') or []
    if not isinstance(evidence, list):
        evidence = [evidence]
    event_text = "\n".join(_leaf_strings(event)).lower()
    evidence, dropped = verify_evidence(evidence, event_text)

    mitre = llm_result.get('mitre') or []
    if not isinstance(mitre, list):
        mitre = [mitre]
    mitre = [str(m) for m in mitre]

    # Strong indicators set a minimum severity; the model can only raise it further.
    llm_severity = severity
    if found:
        floor = max_severity(*(i['severity'] for i in found))
        severity = max_severity(severity, floor)
        evidence += [f"{i['name']}: {i['match']}" for i in found]
        mitre += [i['mitre'] for i in found if i['mitre'] not in mitre]
        if severity != llm_severity:
            confidence = max(confidence, 0.9)   # deterministic match

    classification, is_anomaly = classify(severity, confidence, evidence, has_indicator = bool(found))
    if severity == 'UNKNOWN':
        classification = 'Unanalyzed'

    summary = str(llm_result.get('summary', ''))
    category = str(llm_result.get('event_category', 'other'))
    return {
        **context,
        'summary': summary,
        'description': summary,           # key used by the dashboard
        'benign_explanation': str(llm_result.get('benign_explanation', '')),
        'evidence': evidence,
        'evidence_unverified': dropped,
        'event_category': category,
        'event_type': category,           # key used by the dashboard
        'mitre': mitre,
        'severity': severity,
        'llm_severity': llm_severity,     # before the indicator floor, for evaluation
        'confidence': confidence,
        'classification': classification,
        'is_anomaly': is_anomaly,
    }

# ============================ Workers & poll loop ============================ #
def worker(idx: int, db: PostgresStorage):
    log.info("worker-%d started", idx)
    while not _stop.is_set():
        try:
            alert = _work_q.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            alert_id = alert.get('id')
            if alert_id and db.alert_exists(alert_id):
                continue

            family = get_log_family(alert)
            analysis = analyze_alert(alert, family)
            source_host = analysis.get('hostname') or 'unknown'
            incident_id = db.store_alert(alert, family, source_host, get_raw_message(alert), analysis)
            if incident_id:
                log.info("Stored incident #%s: [%s] %s / %s", incident_id, family,
                         analysis['severity'], analysis['classification'])

            if config.RATE_LIMIT_DELAY:
                time.sleep(config.RATE_LIMIT_DELAY)
        except Exception:
            log.exception("worker-%d failed on alert %s", idx, alert.get('id'))
        finally:
            _work_q.task_done()
    log.info("worker-%d stopped", idx)

def wait_for_queue_drain() -> bool:
    while _work_q.unfinished_tasks and not _stop.is_set():
        _stop.wait(0.2)
    return not _stop.is_set()

def poll(db: PostgresStorage):
    while not config.indexer_configured() and not _stop.is_set():
        log.warning("Wazuh indexer not configured (INDEXER_URL / INDEXER_USER / INDEXER_PASSWORD). "
                    "Waiting for configuration...")
        _stop.wait(60)
    if _stop.is_set():
        return

    client = WazuhIndexerClient()
    cursor = db.get_cursor()
    log.info("Polling %s index=%s, %s", config.INDEXER_URL, config.INDEXER_INDEX,
             f"resuming from cursor {cursor}" if cursor else
             f"starting {config.INDEXER_LOOKBACK_MIN} min back")
    backoff = config.INDEXER_POLL_INTERVAL

    while not _stop.is_set():
        try:
            alerts, last_sort = client.fetch_page(cursor)
            backoff = config.INDEXER_POLL_INTERVAL
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status in (401, 403):
                log.error("Indexer rejected credentials (HTTP %s). Check INDEXER_USER / INDEXER_PASSWORD.", status)
            else:
                log.warning("Indexer query failed (HTTP %s): %s", status, e)
            _stop.wait(backoff)
            backoff = min(backoff * 2, 300)
            continue
        except requests.RequestException as e:
            log.warning("Indexer unreachable: %s. Retrying in %ss", e, backoff)
            _stop.wait(backoff)
            backoff = min(backoff * 2, 300)
            continue

        if not alerts:
            _stop.wait(config.INDEXER_POLL_INTERVAL)
            continue

        queued = 0
        for alert in alerts:
            if not should_analyze(alert):
                continue
            while not _stop.is_set():
                try:
                    _work_q.put(alert, timeout=1)  # blocks while workers are busy
                    queued += 1
                    break
                except queue.Full:
                    pass

        # Advance the cursor only after the whole page is stored, so a crash re-reads the page
        # (already stored alerts are skipped) instead of losing it.
        if not wait_for_queue_drain():
            break
        cursor = last_sort
        db.save_cursor(cursor)
        log.info("Processed page: %d alerts, %d analyzed", len(alerts), queued)

        if len(alerts) < config.INDEXER_PAGE_SIZE:
            _stop.wait(config.INDEXER_POLL_INTERVAL)

def shutdown(signum, _frame):
    log.info("Signal %s received, shutting down", signum)
    _stop.set()

def main():
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if not wait_for_ollama():
        return

    try:
        db = PostgresStorage(max_conn = config.NUM_WORKERS + 2)
    except Exception as e:
        log.error("Failed to initialize DB: %s", e)
        return

    workers = [
        threading.Thread(target=worker, args=(i, db), daemon=True)
        for i in range(config.NUM_WORKERS)
    ]
    for w in workers:
        w.start()

    try:
        poll(db)
    except Exception:
        log.exception("Fatal error")
    finally:
        _stop.set()
        for w in workers:
            w.join(timeout=config.OLLAMA_TIMEOUT + 5)
        db.close()
        log.info("Shutdown complete")

if __name__ == "__main__":
    main()
