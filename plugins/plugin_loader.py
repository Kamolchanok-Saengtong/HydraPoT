"""
plugin_loader.py — HydraPoT plugin system.

Loads three types of plugins at startup:
  1. Custom FI rules     (plugins/rules/*.yaml)
  2. Custom static handlers (plugins/static/*.py)
  3. SIEM exporters      (plugins/export/*.yaml)

Usage in main.py:
    from plugins.plugin_loader import PluginManager
    plugins = PluginManager("plugins/")
    plugins.load_all()

    # merge custom FI rules into fi_manager
    plugins.apply_fi_rules(fi_manager)

    # register custom static handlers
    plugins.apply_static_handlers(static_handler_module)

    # after every command, export to SIEM
    plugins.export_event(event_dict)
"""

import os
import re
import json
import yaml
import importlib.util
import threading
from datetime import datetime


# ══════════════════════════════════════════════════════════════════════════════
# 1. CUSTOM FI RULES
# ══════════════════════════════════════════════════════════════════════════════

class FIRulePlugin:
    """A set of custom FI scoring rules loaded from a YAML file."""

    def __init__(self, path: str):
        self.path = path
        self.name = ""
        self.author = ""
        self.version = ""
        self.rules = {}  # {fi_level: [compiled_patterns]}

        self._load(path)

    def _load(self, path: str):
        with open(path) as f:
            data = yaml.safe_load(f)

        self.name    = data.get("name", os.path.basename(path))
        self.author  = data.get("author", "unknown")
        self.version = data.get("version", "1.0")

        for rule in data.get("rules", []):
            fi = int(rule.get("fi", 0))
            patterns = rule.get("patterns", [])
            if fi not in self.rules:
                self.rules[fi] = []
            for p in patterns:
                try:
                    self.rules[fi].append(re.compile(p))
                except re.error as e:
                    print(f"[plugin] Bad regex in {self.name}: '{p}' → {e}")

    def __repr__(self):
        total = sum(len(v) for v in self.rules.values())
        return f"<FIRulePlugin '{self.name}' v{self.version} ({total} patterns)>"


# ══════════════════════════════════════════════════════════════════════════════
# 2. CUSTOM STATIC HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

class StaticHandlerPlugin:
    """A custom static command handler loaded from a Python file."""

    def __init__(self, path: str):
        self.path = path
        self.commands = []
        self.handle_fn = None
        self.name = os.path.basename(path).replace(".py", "")

        self._load(path)

    def _load(self, path: str):
        spec = importlib.util.spec_from_file_location(self.name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.commands = getattr(module, "COMMANDS", [])
        self.handle_fn = getattr(module, "handle", None)

        if not self.commands or not self.handle_fn:
            print(f"[plugin] Warning: {path} missing COMMANDS or handle()")

    def __repr__(self):
        return f"<StaticPlugin '{self.name}' commands={self.commands}>"


# ══════════════════════════════════════════════════════════════════════════════
# 3. SIEM EXPORTERS
# ══════════════════════════════════════════════════════════════════════════════

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

    def should_export(self, event: dict) -> bool:
        """Check if this event passes the export filters."""
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
        """Buffer an event and flush when batch is full."""
        if not self.enabled or not self.should_export(event):
            return

        with self._lock:
            self._buffer.append(event)
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
        import urllib.request
        import urllib.error

        url   = self.connection.get("url", "")
        token = self._resolve_env(self.connection.get("token_env", ""))

        if not url or not token:
            print(f"[splunk] Missing URL or token for {self.name}")
            return

        index      = self.settings.get("index", "main")
        sourcetype = self.settings.get("sourcetype", "hydrapot:session")
        host       = self.settings.get("host", "honeypot")

        for event in events:
            payload = json.dumps({
                "index":      index,
                "sourcetype": sourcetype,
                "host":       host,
                "time":       event.get("timestamp", datetime.now().isoformat()),
                "event":      event,
            }).encode()

            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Authorization", f"Splunk {token}")
            req.add_header("Content-Type", "application/json")

            try:
                verify = self.connection.get("verify_ssl", True)
                if not verify:
                    import ssl
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
        import urllib.request
        import urllib.error

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
            url = f"{host}/{index}/_doc"
            payload = json.dumps(event).encode()

            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")

            if username and password:
                import base64
                creds = base64.b64encode(f"{username}:{password}".encode()).decode()
                req.add_header("Authorization", f"Basic {creds}")

            try:
                verify = self.connection.get("verify_ssl", True)
                if not verify:
                    import ssl
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

        import socket
        host     = self.connection.get("host", "127.0.0.1")
        port     = self.connection.get("port", 514)
        protocol = self.connection.get("protocol", "udp")

        if protocol == "tcp":
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((host, port))
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket._dest = (host, port)

        return self._socket

    def _send(self, events: list):
        import socket as sock_module

        host     = self.connection.get("host", "127.0.0.1")
        port     = self.connection.get("port", 514)
        protocol = self.connection.get("protocol", "udp")
        fmt      = self.connection.get("format", "json")

        for event in events:
            if fmt == "cef":
                msg = self._to_cef(event)
            else:
                msg = json.dumps(event)

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
        """Convert event to CEF (Common Event Format) string."""
        fi = event.get("fi", event.get("fi_score", 0))
        severity = {0: 1, 1: 3, 2: 5, 3: 7, 4: 10}.get(fi, 1)
        cmd = event.get("cmd", event.get("command", "")).replace("=", "\\=").replace("|", "\\|")
        src = event.get("src_ip", "?")
        agent = event.get("agent", "unknown")

        return (
            f"CEF:0|HydraPoT|Honeypot|1.0|{fi}|"
            f"FI-{fi} Command|{severity}|"
            f"src={src} msg={cmd} cs1={agent} cs1Label=Agent"
        )


# ══════════════════════════════════════════════════════════════════════════════
# PLUGIN MANAGER
# ══════════════════════════════════════════════════════════════════════════════

EXPORTER_TYPES = {
    "splunk_hec":    SplunkHECExporter,
    "elasticsearch": ElasticsearchExporter,
    "syslog":        SyslogExporter,
}


class PluginManager:
    """
    Discovers and loads all plugins from the plugins/ directory.

    Usage:
        pm = PluginManager("plugins/")
        pm.load_all()
        pm.apply_fi_rules(fi_manager)
        pm.export_event({"cmd": "whoami", "fi_score": 0, ...})
    """

    def __init__(self, plugin_dir: str = "plugins/"):
        self.plugin_dir = plugin_dir
        self.fi_plugins      = []   # list of FIRulePlugin
        self.static_plugins  = []   # list of StaticHandlerPlugin
        self.exporters       = []   # list of SIEMExporter

    def load_all(self):
        """Scan plugin directories and load everything."""
        self._load_fi_rules()
        self._load_static_handlers()
        self._load_exporters()
        self._print_summary()

    def _load_fi_rules(self):
        rules_dir = os.path.join(self.plugin_dir, "rules")
        if not os.path.isdir(rules_dir):
            return
        for fname in sorted(os.listdir(rules_dir)):
            if fname.endswith((".yaml", ".yml")):
                path = os.path.join(rules_dir, fname)
                try:
                    plugin = FIRulePlugin(path)
                    self.fi_plugins.append(plugin)
                    print(f"[plugin] Loaded FI rules: {plugin}")
                except Exception as e:
                    print(f"[plugin] Failed to load {fname}: {e}")

    def _load_static_handlers(self):
        static_dir = os.path.join(self.plugin_dir, "static")
        if not os.path.isdir(static_dir):
            return
        for fname in sorted(os.listdir(static_dir)):
            if fname.endswith(".py") and not fname.startswith("_"):
                path = os.path.join(static_dir, fname)
                try:
                    plugin = StaticHandlerPlugin(path)
                    self.static_plugins.append(plugin)
                    print(f"[plugin] Loaded static handler: {plugin}")
                except Exception as e:
                    print(f"[plugin] Failed to load {fname}: {e}")

    def _load_exporters(self):
        export_dir = os.path.join(self.plugin_dir, "export")
        if not os.path.isdir(export_dir):
            return
        for fname in sorted(os.listdir(export_dir)):
            if fname.endswith((".yaml", ".yml")):
                path = os.path.join(export_dir, fname)
                try:
                    with open(path) as f:
                        config = yaml.safe_load(f)
                    etype = config.get("type", "")
                    cls   = EXPORTER_TYPES.get(etype)
                    if cls:
                        exporter = cls(config)
                        self.exporters.append(exporter)
                        print(f"[plugin] Loaded exporter: {exporter}")
                    else:
                        print(f"[plugin] Unknown exporter type '{etype}' in {fname}")
                except Exception as e:
                    print(f"[plugin] Failed to load {fname}: {e}")

    def _print_summary(self):
        total_rules = sum(
            sum(len(v) for v in p.rules.values())
            for p in self.fi_plugins
        )
        total_cmds = sum(len(p.commands) for p in self.static_plugins)
        enabled_exp = sum(1 for e in self.exporters if e.enabled)

        print(f"[plugin] Summary: "
              f"{len(self.fi_plugins)} rule files ({total_rules} patterns), "
              f"{len(self.static_plugins)} static handlers ({total_cmds} commands), "
              f"{len(self.exporters)} exporters ({enabled_exp} enabled)")

    # ── Apply to FI Manager ──────────────────────────────────────────────

    def apply_fi_rules(self, fi_scorer):
        """
        Merge custom plugin rules into the FI scorer.
        Plugin rules are checked BEFORE built-in rules (higher priority).
        """
        if not self.fi_plugins:
            return

        # store compiled plugin patterns on the scorer
        if not hasattr(fi_scorer, '_plugin_rules'):
            fi_scorer._plugin_rules = {}

        for plugin in self.fi_plugins:
            for fi, patterns in plugin.rules.items():
                if fi not in fi_scorer._plugin_rules:
                    fi_scorer._plugin_rules[fi] = []
                fi_scorer._plugin_rules[fi].extend(patterns)

        # monkey-patch the score method to check plugin rules first
        original_score = fi_scorer.score

        def patched_score(command: str):
            cmd = command.strip()
            # check cache first
            if cmd in fi_scorer.cache:
                return fi_scorer.cache[cmd], "cached"

            # check plugin rules (highest FI first)
            for fi in [4, 3, 2, 1, 0]:
                for pattern in fi_scorer._plugin_rules.get(fi, []):
                    if pattern.search(cmd):
                        fi_scorer.cache[cmd] = fi
                        return fi, "plugin"

            # fall back to built-in rules
            return original_score(command)

        fi_scorer.score = patched_score

    # ── Apply Static Handlers ────────────────────────────────────────────

    def get_static_handler(self, cmd_base: str):
        """
        Check if any plugin handles this command.
        Returns (plugin, True) if found, (None, False) if not.
        """
        for plugin in self.static_plugins:
            if cmd_base in plugin.commands:
                return plugin, True
        return None, False

    def dispatch_static_plugin(self, cmd: str, write_fn) -> str:
        """Dispatch a command to the matching static plugin."""
        cmd_base = cmd.strip().split()[0] if cmd.strip() else ""
        for plugin in self.static_plugins:
            if cmd_base in plugin.commands and plugin.handle_fn:
                return plugin.handle_fn(cmd, write_fn)
        return ""

    # ── SIEM Export ──────────────────────────────────────────────────────

    def export_event(self, event: dict):
        """Send an event to all enabled SIEM exporters."""
        for exporter in self.exporters:
            try:
                exporter.emit(event)
            except Exception as e:
                print(f"[plugin] Export error ({exporter.name}): {e}")

    def export_auth(self, auth_entry: dict):
        """Send an auth event to all enabled SIEM exporters."""
        event = {**auth_entry, "event": "auth"}
        self.export_event(event)

    def flush_exporters(self):
        """Flush all exporter buffers (call on shutdown)."""
        for exporter in self.exporters:
            try:
                exporter.flush()
            except Exception as e:
                print(f"[plugin] Flush error ({exporter.name}): {e}")