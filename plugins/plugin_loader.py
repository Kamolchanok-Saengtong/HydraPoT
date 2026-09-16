"""
plugin_loader.py — HydraPoT plugin system.

Loads three types of plugins at startup:
  1. Custom FI rules        (plugins/rules/*.yaml)
  2. Custom static handlers (plugins/static/*.py)
  3. SIEM exporters         (threat_intel/export/*.yaml)

The exporters are the odd one out and their CODE lives in
threat_intel/exporters.py — see the note above PluginManager. Their CONFIGS
moved with them, to threat_intel/export/, next to threat_intel/rules/. Only
the first two are discovered under plugins/.

Usage in main.py:
    from plugins.plugin_loader import PluginManager
    plugins = PluginManager()
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
import yaml
import importlib.util

from threat_intel.exporters import EXPORTER_TYPES

# Both directories are anchored to the repo root via THIS FILE, never the cwd.
# A relative "plugins/" only resolves when HydraPoT is started from the repo
# root; under systemd, from an installed entry point, or from a test runner the
# scan silently finds nothing and every plugin is skipped with no error -- the
# worst kind of failure, because the honeypot comes up looking healthy.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PLUGIN_DIR = os.path.join(_ROOT, "plugins")              # FI rules, static handlers
EXPORT_CONFIG_DIR = os.path.join(_ROOT, "threat_intel", "export")   # SIEM exporters


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
# The exporter classes live in threat_intel/exporters.py, because translating a
# canonical event into what Splunk/Elasticsearch/syslog speak is threat-intel
# work, not plugin plumbing. PluginManager below still owns them at runtime --
# it discovers the configs, builds the objects and dispatches events -- because
# it does the same for FI rules and static handlers and main.py drives all three
# through one object.


# ══════════════════════════════════════════════════════════════════════════════
# PLUGIN MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class PluginManager:
    """
    Discovers and loads all plugins from the plugins/ directory.

    Usage:
        pm = PluginManager()
        pm.load_all()
        pm.apply_fi_rules(fi_manager)
        pm.export_event({"cmd": "whoami", "fi_score": 0, ...})
    """

    def __init__(self, plugin_dir: str = None):
        # Defaults to the anchored PLUGIN_DIR. Callers may still pass a path
        # (tests, a custom install) -- what they may not do is rely on the cwd.
        self.plugin_dir = plugin_dir or PLUGIN_DIR
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
        # NOT under self.plugin_dir. Exporter configs live beside the rest of
        # the threat-intel rules, and the path is derived from this file's
        # location rather than the cwd so it resolves however HydraPoT is
        # started (hp, systemd, a test runner).
        export_dir = EXPORT_CONFIG_DIR
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

    def export_finding(self, detection: dict, alert: dict = None):
        """Send an ANALYSED finding to the SIEM exporters.

        The other half of interoperability. export_event() ships raw telemetry
        -- a command, a login -- which is what the honeypot OBSERVED.
        Correlation, detection and severity output previously reached only the
        dashboard and alerts.jsonl, so external SIEMs received raw commands and
        none of the analysis that is HydraPoT's actual contribution.

        Bypasses should_export() deliberately: those filters (min_fi, agents)
        are about raw event volume, and a finding has already passed a
        detection rule AND an alert rule. Re-filtering it on the routing metric
        of one of its member commands would drop findings for the wrong reason.
        """
        from threat_intel.normalize import normalize_finding
        ocsf = normalize_finding(detection, alert)
        for exporter in self.exporters:
            if not exporter.enabled:
                continue
            try:
                with exporter._lock:
                    exporter._buffer.append(ocsf)
                    if len(exporter._buffer) >= exporter.batch_size:
                        exporter._flush()
            except Exception as e:
                print(f"[plugin] Finding export error ({exporter.name}): {e}")

    def flush_exporters(self):
        """Flush all exporter buffers (call on shutdown)."""
        for exporter in self.exporters:
            try:
                exporter.flush()
            except Exception as e:
                print(f"[plugin] Flush error ({exporter.name}): {e}")