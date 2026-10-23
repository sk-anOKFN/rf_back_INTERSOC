"""
Mock Wazuh Indexer for testing: replays alerts from an NDJSON fixture through the indexer _search API.

Supports what the detector uses: basic auth, the timestamp range filter, sort and search_after.
Alerts are re-timestamped at startup (oldest first, ending FRESHNESS_SEC seconds ago), so the
detector picks them up within its lookback window. Restart the container to replay them again
(use a fresh database, or the detector skips alert IDs it already stored).

Environment:
  FIXTURE                path to the NDJSON file (one Wazuh alert per line)
  MOCK_INDEXER_USER      basic auth user      (default: redflags_ro)
  MOCK_INDEXER_PASSWORD  basic auth password  (default: test-only-password)
"""
import base64
import json
import os
import re
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURE = os.getenv("FIXTURE", "/testing/fixtures/sample_alerts.ndjson")
USER = os.getenv("MOCK_INDEXER_USER", "redflags_ro")
PASSWORD = os.getenv("MOCK_INDEXER_PASSWORD", "test-only-password")
FRESHNESS_SEC = 60      # newest alert is this old, so it is past the detector's INDEXER_SETTLE_SEC
SPACING_SEC = 2

def load_docs():
    with open(FIXTURE, encoding="utf-8") as f:
        alerts = [json.loads(line) for line in f if line.strip()]
    # Captured alerts keep their original order; fixtures without timestamps keep file order.
    alerts.sort(key=lambda a: a.get("timestamp", ""))
    newest = datetime.now(timezone.utc) - timedelta(seconds=FRESHNESS_SEC)
    docs = []
    for i, alert in enumerate(alerts):
        ts = newest - timedelta(seconds=SPACING_SEC * (len(alerts) - 1 - i))
        alert["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}+0000"
        alert.setdefault("id", f"mock.{i}")
        docs.append({"_index": "wazuh-alerts-4.x-mock", "_id": f"os-{alert['id']}", "_source": alert,
                     "sort": [int(ts.timestamp() * 1000), alert["id"]], "_ts": ts})
    return docs

DOCS = load_docs()

def parse_date(value):
    if value.startswith("now-") and value.endswith("s"):
        return datetime.now(timezone.utc) - timedelta(seconds=int(value[4:-1]))
    return datetime.strptime(value.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z")

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        expected = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        return self.headers.get("Authorization") == expected

    def do_GET(self):
        self._send(200, {"name": "mock-wazuh-indexer", "fixture": FIXTURE, "alerts": len(DOCS)})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if not self._authorized():
            return self._send(401, {"error": "Unauthorized"})
        if not re.fullmatch(r"/wazuh-alerts-[^/]*/_search", self.path):
            return self._send(404, {"error": f"no such index {self.path}"})

        rng = body.get("query", {}).get("range", {}).get("timestamp", {})
        lt = parse_date(rng["lt"]) if "lt" in rng else None
        gte = parse_date(rng["gte"]) if "gte" in rng else None
        after = body.get("search_after")

        hits = []
        for doc in DOCS:
            if (lt and doc["_ts"] >= lt) or (gte and doc["_ts"] < gte):
                continue
            if after and doc["sort"] <= after:
                continue
            hits.append({k: v for k, v in doc.items() if k != "_ts"})
        self._send(200, {"hits": {"total": {"value": len(hits)}, "hits": hits[: body.get("size", 10)]}})

    def log_message(self, fmt, *args):
        print("mock-indexer:", fmt % args, flush=True)

if __name__ == "__main__":
    print(f"mock indexer serving {len(DOCS)} alerts from {FIXTURE}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 9200), Handler).serve_forever()
