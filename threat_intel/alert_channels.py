"""
threat_intel/alert_channels.py — multi-channel push notification.

Reads threat_intel/alerts.yml, and when a high-severity event arrives, pushes a
formatted alert to whichever channels the user enabled (Slack / Discord /
Telegram / generic webhook / email). Standard library only — no extra deps.

Secrets are resolved from ENVIRONMENT VARIABLES named in the config, never
stored in the file. A channel that is misconfigured or unreachable fails
softly (logged, skipped) so alerting never crashes the honeypot.

DELIVERY ONLY. This module decides nothing about whether something is
dangerous -- it formats and pushes whatever it is handed. The alert RECORD
(identity, new/acknowledged/closed lifecycle, durable state) lives in
threat_intel/alert_records.py; the two were briefly merged under one filename
and are deliberately separate again, because "notify someone now" and "track
this until a human closes it" have nothing in common but a word.

main.py wires it into the live event loop (see _get_alert_manager); it also
works standalone:

    from threat_intel.alert_channels import AlertManager
    am = AlertManager()                     # loads alerts.yml
    am.test()                               # send a test alert to enabled channels

WHAT CALLS notify(): threat_intel/alert_records.py, via the `channels` sink in
alert_rules.yml. Nothing here decides WHETHER to notify -- see notify().
"""
import os
import json
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

# FI band labels. NOT security severity, and deliberately not worded as it:
# this said INFO/LOW/MEDIUM/HIGH/CRITICAL keyed on FI, which published
# HydraPoT's routing metric to Slack as though it were a security rating. FI
# measures how much INTERACTION a command drew (which agent had to answer it);
# a loud `rm` of a file the attacker created themselves is FI 4 and harmless,
# while a quiet credential read may be FI 1. Security severity comes from
# threat_intel/severity.py and belongs on findings, not on single commands.
_FI_BAND  = {0: "FI 0 · minimal", 1: "FI 1 · low", 2: "FI 2 · moderate",
             3: "FI 3 · high", 4: "FI 4 · maximum"}
_EMOJI    = {0: "⚪", 1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴"}


def _env(name: str) -> str:
    return os.environ.get(name or "", "").strip()


class AlertManager:
    def __init__(self, config_path: str = DEFAULT_CONFIG):
        self.config = {}
        self.channels = {}
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

    def notify(self, alert: dict) -> dict:
        """Deliver one ALERT RECORD to every enabled channel. No gating.

        THE LIVE ENTRY POINT. threat_intel/alert_records.py already decided
        this finding is worth interrupting someone -- it cleared a detection
        rule, then an alert rule in alert_rules.yml, and `channels` is listed
        among that rule's `notify:` sinks. Re-deciding here would put a second,
        competing policy in a second file, and the two would drift.

        So this formats and sends. It does not consult FI, and it does not
        consult min_fi: the routing metric has nothing to do with whether a
        correlated finding deserves a page. That judgement lives in
        session_severity.yml (how bad) and alert_rules.yml (worth waking
        someone), which is where the rest of the SIEM already looks.

        `alert` is a row from the alerts table: severity, title, the rule that
        raised it, and how far the behaviour spread.
        """
        channels = self._enabled_channels()
        if not channels:
            return {}
        msg = self._format_finding(alert)
        results = {}
        for name in channels:
            cfg = self.channels[name]
            fn = getattr(self, f"_send_{name}", None)
            if fn is None:
                results[name] = "unknown channel"
                continue
            try:
                fn(cfg, msg, alert)
                results[name] = "sent"
            except Exception as e:
                results[name] = f"failed: {e}"
                print(f"[alert] {name} failed: {e}")
        return results

    def _format_finding(self, alert: dict) -> dict:
        """One alert record -> a message.

        Carries what the PIPELINE concluded rather than what a single command
        looked like: the severity threat_intel/severity.py assigned, the rule
        that raised it, and how far the behaviour spread. Someone reading this
        on a phone should be able to decide whether to open a laptop.
        """
        sev = (alert.get("severity") or "unrated").lower()
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                 "low": "🟢", "info": "⚪"}.get(sev, "⚫")
        title = (f"{emoji} HydraPoT — {sev.upper()}: "
                 f"{alert.get('title') or 'correlated finding'}")
        spread = " · ".join(filter(None, [
            f"{alert['member_count']} sessions" if alert.get("member_count") else None,
            f"{alert['distinct_sources']} sources" if alert.get("distinct_sources") else None,
        ]))
        lines = [f"Severity : {sev.upper()}",
                 f"Rule     : {alert.get('alert_rule') or '?'}"]
        if spread:
            lines.append(f"Scope    : {spread}")
        if alert.get("link_type"):
            lines.append(f"Related  : {alert['link_type']}")
        if alert.get("last_seen"):
            lines.append(f"Last seen: {alert['last_seen']}")
        if alert.get("alert_key"):
            lines.append(f"ID       : {alert['alert_key']}")
        return {"title": title, "body": "\n".join(lines),
                "severity": sev, "sev": sev, "fi": None}

    def test(self) -> dict:
        """Send a fake CRITICAL alert to every enabled channel (for setup testing)."""
        enabled = self._enabled_channels()
        if not enabled:
            print("[alert] no channels enabled in alerts.yml — nothing to test.")
            return {}
        print(f"[alert] testing channels: {', '.join(enabled)}")
        msg = self._format_finding({
            "severity": "critical",
            "title": "Critical behaviour observed   (TEST ALERT)",
            "alert_rule": "critical-behaviour", "link_type": "same_sequence",
            "member_count": 22, "distinct_sources": 3,
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert_key": "test-0001",
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
                              "event": event, "text": msg["body"]})

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
