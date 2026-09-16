"""
shell/telemetry.py — writing down what happened.

One command produces two records, and they are NOT the same shape:

    the row      what the attacker did, including the full response.
                 Goes to SQLite (or JSON Lines), and is what the dashboard,
                 the SIEM pipeline and every later analysis read.
    the event    the same facts WITHOUT the response, handed to the SIEM
                 exporters. Smaller on purpose: a forwarded stream does not
                 need every byte a model generated.

LOGGING MUST NEVER KILL A SESSION. Every write here is wrapped. A locked
database or a full disk costs one row; it must not take the honeypot down or
raise into the attacker's connection. SQLite writes retry once, because a
failure there is almost always a transient writer lock from another sensor
sharing the file.

FI IS RECORDED, NOT INTERPRETED. `fi_score` rides along because it is a real
operational fact (which agent answered and why), and it is never a severity.
The SOC severity comes from threat_intel/severity.py, nowhere near here.

NO PER-COMMAND ALERTING. This used to fire a notification for every command
over an FI threshold -- paging on HydraPoT's ROUTING metric, so a loud `rm` of
the attacker's own file (FI 4) woke someone while a multi-session loader whose
commands were each FI 1 did not. Notifications come from the analysis now:
correlation -> detection -> severity -> alert_records.
"""
import json
import os
import time
from datetime import datetime


class Telemetry:
    """One session's record keeping.

        tel = Telemetry(session_id, src_ip, instance="sensor-a",
                        tag=mitre_tag, export=plugins.export_event)
        tel.record("whoami", "cowrie", "root", fi_score=0, latency_ms=12.3)

    `tag` and `export` are injected so this module depends on neither the MITRE
    mapper nor the plugin system, and the tests need no database.
    """

    def __init__(self, session_id, src_ip="?", public_ip="?", instance="default",
                 store="sqlite", store_dir="", session_dir="",
                 tag=None, export=None, writer=None, log=print):
        self.session_id = session_id
        self.src_ip = src_ip
        self.public_ip = public_ip
        self.instance = instance
        self.store = store
        self.store_dir = store_dir
        self.session_dir = session_dir
        self.tag = tag
        self.export = export
        # storage.insert_command by default; injectable so a test never writes
        # to the real hydrapot.db.
        self._writer = writer
        self.log = log

    def _insert(self, row):
        if self._writer is not None:
            return self._writer(row)
        import storage
        return storage.insert_command(row)

    # ── the one entry point ─────────────────────────────────────────────────

    def record(self, cmd, agent, response, fi_score=0, latency_ms=0.0):
        """Write the row and forward the event. Returns the row."""
        # Tagged ONCE and shared. The row and the event carried the same
        # technique and each called the mapper for it; it is cached, so this is
        # tidiness rather than a speedup, but two calls invited two answers.
        mitre = (self.tag(cmd) if self.tag else None) or {}

        row = {
            "session_id": self.session_id, "src_ip": self.src_ip,
            "public_ip": self.public_ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cmd": cmd, "agent": agent, "response": response,
            "fi_score": fi_score, "latency_ms": round(latency_ms, 2),
            # Self-describing origin, so a central SOC can aggregate many
            # sensors without relying on which host or folder collected a file.
            "instance": self.instance,
            **mitre,
        }
        self._write(row)

        # Same facts, no response body.
        event = {
            "session_id": self.session_id, "src_ip": self.src_ip,
            "timestamp": datetime.now().isoformat(),
            "cmd": cmd, "agent": agent, "fi_score": fi_score,
            "latency_ms": round(latency_ms, 2),
            "instance": self.instance,
            **mitre,
        }
        self._export(event)
        return row

    # ── writing ─────────────────────────────────────────────────────────────

    def _write(self, row):
        if self.store == "json":
            self._write_jsonl(row)
            return
        # The only write on the hot path: one indexed INSERT, O(1) in session
        # length, and the dashboard sees the command as soon as it returns.
        try:
            self._insert(row)
        except Exception:
            # Almost always a transient writer lock -- several sensors share
            # one file. Retry once, then give up loudly but harmlessly.
            try:
                time.sleep(0.2)
                self._insert(row)
            except Exception as e:
                self._lost(e)

    def _write_jsonl(self, row):
        """One line appended per command, never a re-dumped array.

        Re-dumping cost O(n^2) bytes over a session -- the exact problem the
        SQLite migration removed. Appending also means a crashed run keeps
        everything written up to that point.
        """
        try:
            target = self.store_dir or self.session_dir
            os.makedirs(target, exist_ok=True)
            with open(os.path.join(target, f"{self.src_ip}.jsonl"), "a",
                      encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception as e:
            self._lost(e)

    def _export(self, event):
        if not self.export:
            return
        try:
            self.export(event)
        except Exception as e:
            if self.log:
                self.log(f"[telemetry] export failed: {type(e).__name__}: {e}")

    def _lost(self, err):
        if self.log:
            self.log(f"[storage] LOST command for {self.session_id}: {err}")
