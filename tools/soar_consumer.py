#!/usr/bin/env python3
"""
tools/soar_consumer.py — a minimal SOAR playbook against HydraPoT's API.

Shows the integration contract a real SOAR (Shuffle, Cortex XSOAR, Splunk SOAR)
follows: poll /api/v1/export for OCSF findings since the last run, triage each
one by severity and MITRE technique, and decide an action.

    python tools/soar_consumer.py --since 2019-05-01
    python tools/soar_consumer.py --format cef        # what ArcSight ingests

Reads only. A real playbook would POST the action somewhere; this prints it.
"""
import argparse
import json
import urllib.parse
import urllib.request

# Techniques worth waking someone for. A real playbook keeps this in the SOAR.
ESCALATE = {
    "T1105": "ingress tool transfer — attacker pulled a file in",
    "T1059": "command interpreter — arbitrary execution",
    "T1070": "indicator removal — covering tracks",
    "T1098": "account manipulation — persistence",
}


def fetch(base, cls, fmt, since, limit, key=None):
    q = urllib.parse.urlencode({"class": cls, "format": fmt,
                                "since": since, "limit": limit})
    req = urllib.request.Request(f"{base}/api/v1/export?{q}")
    if key:
        req.add_header("X-API-Key", key)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def triage(item):
    """-> (action, why). The decision a playbook would make."""
    sev = item.get("severity_id", 0)
    techs = [a.get("technique", {}).get("uid", "") for a in item.get("attacks", [])]
    for t in techs:
        for prefix, why in ESCALATE.items():
            if t.startswith(prefix):
                return "ESCALATE", f"{t}: {why}"
    if sev >= 4:
        return "REVIEW", f"severity {sev}, no escalating technique"
    return "LOG", f"severity {sev}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--base", default="http://127.0.0.1:8050")
    ap.add_argument("--since", default="2019-01-01")
    ap.add_argument("--class", dest="cls", default="finding",
                    choices=["finding", "auth", "process"])
    ap.add_argument("--format", default="ocsf", choices=["ocsf", "json", "cef", "ecs"])
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--key", default=None, help="X-API-Key, if the server requires one")
    a = ap.parse_args()

    data = fetch(a.base, a.cls, a.format, a.since, a.limit, a.key)
    items = data.get("items", [])
    print(f"\n  pulled {len(items)} of {data.get('total')} {a.cls} records "
          f"as {data.get('format')} {data.get('ocsf_version') or ''}".rstrip())
    print(f"  more available: {data.get('has_more')}\n")

    if a.format != "ocsf":
        for raw in items[:5]:
            print(f"    {str(raw)[:110]}")
        print("\n  (non-OCSF formats are passed to the SIEM verbatim; no triage here)\n")
        return

    counts = {}
    for it in items:
        action, why = triage(it)
        counts[action] = counts.get(action, 0) + 1
        uid = (it.get("finding_info") or {}).get("uid", "")[:34]
        print(f"    [{action:8}] {uid:36} {why}")
    print("\n  playbook outcome:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())), "\n")


if __name__ == "__main__":
    main()
