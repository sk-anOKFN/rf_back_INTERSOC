"""
Capture alerts from a real Wazuh Indexer into an NDJSON fixture, plus a labelling template.

Standard library only, so it runs anywhere with Python 3.9+.

Examples:
  # last 2 hours from a local Wazuh (self-signed certificate)
  python capture_alerts.py --url https://localhost:9200 --user admin --since 120 --insecure \
      --out fixtures/local_alerts.ndjson --labels fixtures/local_labels.csv

  # only one agent, at most 500 alerts
  python capture_alerts.py --url https://localhost:9200 --user admin --insecure \
      --query 'agent.name:"ubuntu-agent"' --max 500 --out fixtures/agent.ndjson

The password is read from --password or the INDEXER_PASSWORD environment variable.
"""
import argparse
import base64
import csv
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

def search(args, body):
    url = f"{args.url.rstrip('/')}/{args.index}/_search"
    request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    token = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    request.add_header("Content-Type", "application/json")

    context = ssl.create_default_context(cafile=args.cacert) if args.cacert else ssl.create_default_context()
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(request, context=context, timeout=60) as response:
        return json.load(response)

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.getenv("INDEXER_URL", "https://localhost:9200"))
    parser.add_argument("--user", default=os.getenv("INDEXER_USER", "admin"))
    parser.add_argument("--password", default=os.getenv("INDEXER_PASSWORD"))
    parser.add_argument("--index", default="wazuh-alerts-4.x-*")
    parser.add_argument("--since", type=int, default=60, help="minutes back (default 60)")
    parser.add_argument("--query", help='optional Lucene filter, e.g. \'agent.name:"web01"\'')
    parser.add_argument("--max", type=int, default=1000, help="maximum alerts to capture")
    parser.add_argument("--out", required=True, help="output NDJSON fixture")
    parser.add_argument("--labels", help="also write a labelling template CSV here")
    parser.add_argument("--cacert", help="CA certificate to verify the indexer")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification (local testing only)")
    args = parser.parse_args()
    if not args.password:
        sys.exit("Password missing: pass --password or set INDEXER_PASSWORD")

    filters = [{"range": {"timestamp": {"gte": f"now-{args.since}m"}}}]
    if args.query:
        filters.append({"query_string": {"query": args.query}})
    body = {
        "size": min(500, args.max),
        "query": {"bool": {"filter": filters}},
        "sort": [{"timestamp": {"order": "asc"}}, {"id": {"order": "asc", "unmapped_type": "keyword"}}],
    }

    alerts = []
    try:
        while len(alerts) < args.max:
            hits = search(args, body).get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                source = hit["_source"]
                source.setdefault("id", hit["_id"])
                alerts.append(source)
            body["search_after"] = hits[-1]["sort"]
    except urllib.error.HTTPError as e:
        sys.exit(f"Indexer returned HTTP {e.code}: {e.read()[:300]!r}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach indexer: {e.reason}")
    alerts = alerts[: args.max]

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    print(f"Wrote {len(alerts)} alerts to {args.out}")

    if args.labels:
        with open(args.labels, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["wazuh_alert_id", "label", "note", "agent", "rule_id", "rule_description", "full_log"])
            for alert in alerts:
                rule = alert.get("rule") or {}
                writer.writerow([alert.get("id"), "", "", (alert.get("agent") or {}).get("name"),
                                 rule.get("id"), rule.get("description"), (alert.get("full_log") or "")[:300]])
        print(f"Wrote labelling template to {args.labels}: fill the 'label' column with malicious or benign")

if __name__ == "__main__":
    main()
