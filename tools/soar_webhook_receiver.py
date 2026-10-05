#!/usr/bin/env python3
"""
tools/soar_webhook_receiver.py — stand in for a SOAR's inbound webhook.

A SOAR exposes a URL; HydraPoT POSTs an alert to it; the playbook runs. This
prints what arrives, so the push half of the integration can be demonstrated
without installing a SOAR.

    python tools/soar_webhook_receiver.py --port 9000

Then, in threat_intel/rules/alert_sinks.yml set the `channels` sink
enabled: true, in threat_intel/alerts.yml set webhook enabled: true, and

    export ALERT_WEBHOOK_URL=http://127.0.0.1:9000/hook
"""
import argparse
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(size).decode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"received":true}')

        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n  [{stamp}] alert received on {self.path}", flush=True)
        try:
            data = json.loads(raw)
        except ValueError:
            print(f"    (not JSON) {raw[:200]}", flush=True)
            return
        for k in ("title", "severity", "detection_id", "rule", "technique",
                  "session_id", "src_ip", "message"):
            if k in data:
                print(f"    {k:14} {str(data[k])[:70]}", flush=True)
        extra = [k for k in data if k not in
                 ("title", "severity", "detection_id", "rule", "technique",
                  "session_id", "src_ip", "message")]
        if extra:
            print(f"    other fields   {', '.join(extra[:8])}", flush=True)

    def log_message(self, *a):
        pass          # the prints above are the log


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(f"\n  SOAR webhook receiver on http://{a.host}:{a.port}/hook")
    print("  waiting for HydraPoT to POST an alert ...  (Ctrl+C to stop)\n")
    HTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
