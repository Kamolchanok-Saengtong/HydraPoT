"""
threat_intel/exporters.py — SIEM export sinks.

Moved here from plugins/plugin_loader.py. These are the OUTBOUND half of the
normalization layer: every exporter takes the canonical OCSF event that
threat_intel/normalize.py produces and translates it into whatever the
destination speaks -- JSON for Splunk, ECS for Elasticsearch, CEF for syslog.

They lived under plugins/ for historical reasons, next to FI scoring rules and
fake-command handlers, which are honeypot-emulation concerns and have nothing
to do with threat intelligence. The split mattered in practice: alert_records
already reached back through plugins.export_finding() to get here, and every
exporter imported threat_intel.normalize from inside a function to dodge the
resulting import cycle. Same package now, so those are plain imports.

plugins/plugin_loader.py still OWNS the exporters at runtime -- PluginManager
discovers configs, builds the objects and dispatches events -- because it also
loads FI rules and static handlers and main.py drives all three through one
object. What moved is the export machinery, not the plugin system.

Configs live in threat_intel/export/*.yml, alongside threat_intel/rules/.

NO FI FILTERING BY DEFAULT. should_export() still supports min_fi and it
defaults to 0. FI is HydraPoT's ROUTING metric: a loud `rm` of the attacker's
own file is FI 4 and harmless, a quiet credential read is FI 1. Gating a
threat-intel export on it drops the quiet dangerous events and keeps the loud
harmless ones -- the severity mistake, one layer further out. The shipped
configs set no min_fi; see the comment in either yml.
"""
import base64
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

from threat_intel.normalize import to_cef, to_ecs, to_json
from threat_intel import normalize as _n


class SIEMExporter:
    """Base class for SIEM export plugins."""

    def __init__(self, config: dict):
        self.name     = config.get("name", "unknown")
        self.enabled  = config.get("enabled", False)
        self.type     = config.get("type", "")
        self.filters  = config.get("filters", {})
        self.settings = config.get("settings", {})
        self.connection = config.get("connection", {})

        self._buffer = []
        self._lock   = threading.Lock()

        self.batch_size     = self.settings.get("batch_size", 10)
        self.flush_interval = self.settings.get("flush_interval_sec", 30)

    def _normalize(self, event: dict) -> dict:
        """Raw HydraPoT event -> canonical OCSF event.

        Auth rows and command rows are different OCSF classes, so the shape of
        the incoming dict decides which normalizer runs. An event that is
        neither is passed through untouched rather than being forced into a
        class it does not belong to.
        """
        if event.get("auth_type") or event.get("event") in (
                "connection", "login.success", "login.failed", "auth"):
            return _n.normalize_auth(event)
        if "cmd" in event or "command" in event:
            return _n.normalize_command(event)
        return event

    def should_export(self, event: dict) -> bool:
        """Operational export filter — NOT a severity judgement.

        min_fi is a legitimate volume control: "do not ship every `ls` to my
        paid SIEM". It is kept, because deciding WHICH events are worth the
        bandwidth is a different question from how dangerous they are. What was
        removed is FI reaching the CEF severity column, where downstream tools
        read it as a security rating (see normalize.to_cef).
        """
        min_fi = self.filters.get("min_fi", 0)
        if event.get("fi", event.get("fi_score", 0)) < min_fi:
            return False

        allowed_agents = self.filters.get("agents")
        if allowed_agents and event.get("agent", "unknown") not in allowed_agents:
            return False

        # auth events
        if event.get("event") == "auth" and not self.filters.get("include_auth", True):
            return False

        return True

    def emit(self, event: dict):
        """Buffer an event and flush when batch is full.

        NORMALIZES HERE, once, for every exporter. Previously each subclass
        received the raw internal dict and decided for itself what to do with
        it: syslog converted to CEF, Splunk and Elasticsearch shipped the raw
        shape. That meant HydraPoT had no canonical representation and every
        new exporter would invent another mapping.

        Filtering still runs against the RAW event, because should_export()
        filters on operational fields (min_fi, agents) that deliberately do not
        exist at the top level of the normalized form.
        """
        if not self.enabled or not self.should_export(event):
            return

        with self._lock:
            self._buffer.append(self._normalize(event))
            if len(self._buffer) >= self.batch_size:
                self._flush()

    def flush(self):
        """Force flush any remaining events."""
        with self._lock:
            if self._buffer:
                self._flush()

    def _flush(self):
        """Override in subclasses to send events to the SIEM."""
        events = self._buffer[:]
        self._buffer.clear()
        self._send(events)

    def _send(self, events: list):
        """Override in subclasses."""
        raise NotImplementedError

    def _resolve_env(self, key: str) -> str:
        """Resolve an environment variable name to its value."""
        return os.environ.get(key, "")

    def __repr__(self):
        status = "enabled" if self.enabled else "disabled"
        return f"<SIEMExporter '{self.name}' type={self.type} {status}>"


class SplunkHECExporter(SIEMExporter):
    """Export events to Splunk via HTTP Event Collector."""

    def _send(self, events: list):

        url   = self.connection.get("url", "")
        token = self._resolve_env(self.connection.get("token_env", ""))

        if not url or not token:
            print(f"[splunk] Missing URL or token for {self.name}")
            return

        index      = self.settings.get("index", "main")
        sourcetype = self.settings.get("sourcetype", "hydrapot:session")
        host       = self.settings.get("host", "honeypot")

        for event in events:
            # Splunk indexes arbitrary JSON and OCSF is a published schema, so
            # the canonical event ships as-is -- no Splunk-specific mapping to
            # maintain. `time` is OCSF epoch MILLISECONDS; HEC wants seconds.
            doc = to_json(event)
            ocsf_ms = doc.get("time")
            payload = json.dumps({
                "index":      index,
                "sourcetype": sourcetype,
                "host":       host,
                "time":       (ocsf_ms / 1000.0) if ocsf_ms else time.time(),
                "event":      doc,
            }, default=str).encode()

            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Authorization", f"Splunk {token}")
            req.add_header("Content-Type", "application/json")

            try:
                verify = self.connection.get("verify_ssl", True)
                if not verify:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    urllib.request.urlopen(req, context=ctx, timeout=5)
                else:
                    urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                print(f"[splunk] Export failed: {e}")

        print(f"[splunk] Exported {len(events)} events to {self.name}")


class ElasticsearchExporter(SIEMExporter):
    """Export events to Elasticsearch."""

    def _send(self, events: list):

        hosts    = self.connection.get("hosts", [])
        username = self._resolve_env(self.connection.get("username_env", ""))
        password = self._resolve_env(self.connection.get("password_env", ""))

        if not hosts:
            print(f"[elastic] No hosts configured for {self.name}")
            return

        host = hosts[0]
        date_str = datetime.now().strftime("%Y.%m.%d")
        index_pattern = self.settings.get("index_pattern", "hydrapot-{date}")
        index = index_pattern.replace("{date}", date_str)

        for event in events:
            # ECS, because Elastic's own dashboards and detection rules are
            # written against it. HydraPoT is NOT internally ECS -- this is a
            # translation at the boundary, the same way syslog gets CEF.
            url = f"{host}/{index}/_doc"
            payload = json.dumps(to_ecs(event), default=str).encode()

            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")

            if username and password:
                creds = base64.b64encode(f"{username}:{password}".encode()).decode()
                req.add_header("Authorization", f"Basic {creds}")

            try:
                verify = self.connection.get("verify_ssl", True)
                if not verify:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    urllib.request.urlopen(req, context=ctx, timeout=5)
                else:
                    urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                print(f"[elastic] Export failed: {e}")

        print(f"[elastic] Exported {len(events)} events to {index}")


class SyslogExporter(SIEMExporter):
    """Export events via syslog (UDP/TCP) in JSON or CEF format."""

    def __init__(self, config: dict):
        super().__init__(config)
        self._socket = None

    def _get_socket(self):
        if self._socket:
            return self._socket

        host     = self.connection.get("host", "127.0.0.1")
        port     = self.connection.get("port", 514)
        protocol = self.connection.get("protocol", "udp")

        if protocol == "tcp":
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((host, port))
        else:
            # No connect() and no stored destination: _send() passes the
            # address to sendto() per datagram. This used to set
            # `self._socket._dest = (host, port)`, which raises AttributeError
            # -- socket objects use __slots__ -- so every UDP send failed
            # inside the try/except and UDP syslog export never worked. The
            # attribute was never read.
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        return self._socket

    def _send(self, events: list):

        host     = self.connection.get("host", "127.0.0.1")
        port     = self.connection.get("port", 514)
        protocol = self.connection.get("protocol", "udp")
        fmt      = self.connection.get("format", "json")

        for event in events:
            if fmt == "cef":
                msg = self._to_cef(event)
            else:
                msg = json.dumps(event, default=str)

            # syslog priority: facility=local0 (16), severity=warning (4)
            priority = (16 * 8) + 4
            syslog_msg = f"<{priority}>{datetime.now().strftime('%b %d %H:%M:%S')} honeypot hydrapot: {msg}"

            try:
                s = self._get_socket()
                data = syslog_msg.encode("utf-8")
                if protocol == "tcp":
                    s.send(data + b"\n")
                else:
                    s.sendto(data, (host, port))
            except Exception as e:
                print(f"[syslog] Export failed: {e}")
                self._socket = None

        print(f"[syslog] Exported {len(events)} events via {protocol}://{host}:{port}")

    def _to_cef(self, event: dict) -> str:
        """Canonical OCSF event -> CEF.

        The mapping itself lives in threat_intel/normalize.to_cef so the CEF
        shape is testable without a socket, and so a second CEF consumer would
        not fork it.

        THE BUG THIS REPLACED: the old implementation did
        `severity = {0:1, 1:3, 2:5, 3:7, 4:10}.get(fi, 1)` and used FI as both
        the CEF signature id and the severity column. FI is HydraPoT's routing
        metric -- it decides which agent answers a command -- so every SIEM
        receiving this read a loud-but-harmless `rm` as severity 10 and a quiet
        credential read as 3. Severity now comes from severity_id (which only
        findings carry) and FI travels as a labelled custom field, cs3.
        """
        return to_cef(event)


# type string in a config yml -> the class that implements it
EXPORTER_TYPES = {
    "splunk_hec":    SplunkHECExporter,
    "elasticsearch": ElasticsearchExporter,
    "syslog":        SyslogExporter,
}
