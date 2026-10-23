"""
Compare Red Flags verdicts with your labels.

Reads analyzed alerts from the API export (or a downloaded NDJSON file), joins them with a labels
CSV (columns: wazuh_alert_id, label[, note]; label = malicious or benign) and reports:
  - detected:        malicious alerts classified Anomaly
  - surfaced:        malicious alerts classified Anomaly or Needs Attention
  - false anomalies: benign alerts classified Anomaly
  - review noise:    benign alerts classified Needs Attention
  - the same for the LLM alone (llm_severity HIGH/CRITICAL), to see what the indicator rules add

Standard library only. Examples:
  python evaluate.py --api http://localhost:8000 --labels fixtures/sample_labels.csv
  python evaluate.py --export redflags-analyzed-logs.ndjson --labels fixtures/local_labels.csv --report report.csv
  python evaluate.py --api http://localhost:8000 --labels fixtures/sample_labels.csv --min-detected 1.0 --max-false-anomalies 0

Exits with code 1 when --min-detected or --max-false-anomalies is not met.
"""
import argparse
import csv
import json
import sys
import urllib.request

HIGH = {"HIGH", "CRITICAL"}

def load_results(args):
    if args.export:
        with open(args.export, encoding="utf-8") as f:
            lines = f.read().splitlines()
    else:
        url = f"{args.api.rstrip('/')}/incidents/export?format=ndjson"
        if args.hours:
            url += f"&hours={args.hours}"
        with urllib.request.urlopen(url, timeout=120) as response:
            lines = response.read().decode("utf-8").splitlines()
    results = {}
    for line in lines:
        if line.strip():
            row = json.loads(line)
            if row.get("wazuh_alert_id"):
                results[row["wazuh_alert_id"]] = row
    return results

def load_labels(path):
    with open(path, encoding="utf-8", newline="") as f:
        labels = {}
        for row in csv.DictReader(f):
            label = (row.get("label") or "").strip().lower()
            if label in ("malicious", "benign"):
                labels[row["wazuh_alert_id"].strip()] = (label, row.get("note", ""))
    if not labels:
        sys.exit(f"No labelled rows in {path} (label must be malicious or benign)")
    return labels

def pct(n, d):
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "n/a"

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--api", help="Red Flags API base URL, e.g. http://localhost:8000")
    source.add_argument("--export", help="NDJSON file downloaded from the dashboard")
    parser.add_argument("--labels", required=True)
    parser.add_argument("--hours", type=int, help="only alerts analyzed in the last N hours (with --api)")
    parser.add_argument("--report", help="write a per-alert CSV report here")
    parser.add_argument("--min-detected", type=float, help="fail if detected rate is below this (0-1)")
    parser.add_argument("--max-false-anomalies", type=int, help="fail if false anomalies exceed this")
    args = parser.parse_args()

    results, labels = load_results(args), load_labels(args.labels)

    rows, missing = [], []
    for alert_id, (label, note) in labels.items():
        result = results.get(alert_id)
        if result is None:
            missing.append((alert_id, label, note))
            continue
        analysis = result.get("analysis_result") or {}
        classification = result.get("classification") or "Unknown"
        if label == "malicious":
            outcome = "OK" if classification == "Anomaly" else ("PARTIAL" if classification == "Needs Attention" else "MISSED")
        else:
            outcome = "OK" if classification in ("Benign", "Unanalyzed") else ("NOISE" if classification == "Needs Attention" else "FALSE ALARM")
        rows.append({
            "wazuh_alert_id": alert_id, "label": label, "classification": classification,
            "severity": result.get("severity"), "llm_severity": analysis.get("llm_severity"),
            "indicators": ",".join(i["name"] for i in analysis.get("indicators") or []),
            "outcome": outcome, "note": note, "summary": (analysis.get("summary") or "")[:120],
        })

    malicious = [r for r in rows if r["label"] == "malicious"]
    benign = [r for r in rows if r["label"] == "benign"]
    detected = sum(r["classification"] == "Anomaly" for r in malicious)
    surfaced = sum(r["classification"] in ("Anomaly", "Needs Attention") for r in malicious)
    false_anomalies = sum(r["classification"] == "Anomaly" for r in benign)
    noise = sum(r["classification"] == "Needs Attention" for r in benign)
    llm_detected = sum(r["llm_severity"] in HIGH for r in malicious)
    llm_false = sum(r["llm_severity"] in HIGH for r in benign)

    print(f"\n{'ID':<20} {'LABEL':<10} {'CLASSIFICATION':<16} {'SEV':<9} {'LLM SEV':<9} {'OUTCOME':<12} INDICATORS / NOTE")
    for r in sorted(rows, key=lambda r: r["wazuh_alert_id"]):
        print(f"{r['wazuh_alert_id']:<20} {r['label']:<10} {r['classification']:<16} {str(r['severity']):<9} "
              f"{str(r['llm_severity']):<9} {r['outcome']:<12} {r['indicators'] or '-'} / {r['note']}")
    for alert_id, label, note in missing:
        print(f"{alert_id:<20} {label:<10} {'NOT ANALYZED':<16} {'':<9} {'':<9} {'':<12} - / {note}")

    print(f"\nLabelled: {len(labels)}  analyzed: {len(rows)}  not analyzed (filtered or not reached yet): {len(missing)}")
    print(f"Malicious detected (Anomaly):              {pct(detected, len(malicious))}")
    print(f"Malicious surfaced (Anomaly + Needs Att.): {pct(surfaced, len(malicious))}")
    print(f"Benign false anomalies:                    {pct(false_anomalies, len(benign))}")
    print(f"Benign review noise (Needs Attention):     {pct(noise, len(benign))}")
    print(f"LLM alone, HIGH/CRITICAL on malicious:     {pct(llm_detected, len(malicious))}")
    print(f"LLM alone, HIGH/CRITICAL on benign:        {pct(llm_false, len(benign))}")

    if args.report:
        with open(args.report, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["wazuh_alert_id"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nPer-alert report written to {args.report}")

    failed = False
    if args.min_detected is not None and malicious and detected / len(malicious) < args.min_detected:
        print(f"FAIL: detected rate below {args.min_detected}")
        failed = True
    if args.max_false_anomalies is not None and false_anomalies > args.max_false_anomalies:
        print(f"FAIL: more than {args.max_false_anomalies} false anomalies")
        failed = True
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
