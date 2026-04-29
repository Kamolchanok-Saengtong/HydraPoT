import re
import time
import json
import os
from datetime import datetime

# ── FI Rules (hardcoded) ──────────────────────────────────────────────────────

FI_RULES = {
    0: [
        r'^(cat|head|tail|less|more|strings|xxd|hexdump)',
        r'^(ls|dir|find|locate|stat|file|wc|diff)',
        r'^(whoami|id|who|users|w|last|lastlog|groups|finger)',
        r'^(uname|free|df|du|lscpu|lsblk|hostname|arch|date|uptime)',
        r'^(ps|pstree|top|htop|lsof|pgrep)',
        r'^(netstat|ss|ip|ifconfig|arp|dig|nslookup)',
        r'cat\s+/etc/(passwd|hosts|hostname|os-release|group|fstab|issue|motd)',
        r'^(env|printenv|history|alias)',
        r'^(pwd|cd\s*$)',                          # ← echo removed from here
    ],
    1: [
        r'^(touch|mkdir|cp|ln)',
        r'^(apt|apt-get|yum|dnf|pip|pip3|gem|npm)',
        r'^(wget|curl)(?!.*\|\s*(bash|sh|python))',
        r'^(tar|zip|unzip|gzip|gunzip)',
        r'^(python|python3|perl|ruby|php|node|lua|bash|sh)\s+\w+',
    ],
    2: [
        r'^(mv|rm(?!\s+.*-rf?)|rmdir|truncate|tee|dd)',
        r'^(sed|awk|tr|cut|paste)',
        r'^(chmod|chown|chgrp|umask|setfacl)',
        r'^(cd\s+\S+)',
        r'^(chsh|chfn)',
        r'^export\s+PATH=',
        r'^(vi|vim|nano|emacs)',
        r'echo\s+.*>>',                            # append
        r'echo\s+.*>(?!>)',                        # ← single redirect e.g. echo x > file.py
        r'^echo\s+',                               # plain echo (write intent)
    ],
    3: [
        r'^(systemctl|service|init)',
        r'^(sudo|su\s)',
        r'^(crontab|at|batch)',
        r'^(ssh|scp|sftp|ftp|nc|telnet|socat)',
        r'(curl|wget).*\|\s*(bash|sh|python)',
        r'wget.*&&\s*(bash|sh)',
        r'^(nmap|masscan)',
    ],
    4: [
        r'^(passwd|chpasswd)',
        r'rm\s+.*(-rf?|--recursive)',
        r'^(kill|killall|pkill).*-9',
        r'^(adduser|useradd|userdel|usermod)',
        r'>\s*/etc/(passwd|shadow|hosts)',
        r'^dd\s+if=/dev/zero',
        r'chmod\s+(777|4777|7777)',
        r'echo\s+.*>>\s*/etc/(passwd|crontab|sudoers)',
    ],
}

FI_LABELS = {
    0: "Read/Display",
    1: "Create/Install",
    2: "Modify/Navigate",
    3: "Service/Download/Elevate",
    4: "Impact/Delete/Passwd",
}

# ── FI Scorer ─────────────────────────────────────────────────────────────────

class FIScorer:
    def __init__(self, llm_fn=None):
        self.llm_fn = llm_fn
        self.cache  = {}

    def score(self, command: str) -> tuple[int, str]:
        cmd = command.strip()

        if cmd in self.cache:
            return self.cache[cmd], "cached"

        for fi in [4, 3, 2, 1, 0]:
            for pattern in FI_RULES[fi]:
                if re.search(pattern, cmd):
                    return fi, "hardcoded"

        if self.llm_fn:
            try:
                fi = int(self.llm_fn(cmd))
                fi = max(0, min(4, fi))
                self.cache[cmd] = fi
                return fi, "llm"
            except Exception:
                pass

        self.cache[cmd] = 0
        return 0, "fallback"

# ── Memory Pruner ─────────────────────────────────────────────────────────────

class MemoryPruner:
    def __init__(self, max_events=10, min_fi=2):
        self.max_events = max_events
        self.min_fi     = min_fi
        self.buffer     = []

    def add(self, event: dict):
        if event["fi"] < self.min_fi:
            return

        self.buffer.append(event)

        if len(self.buffer) > self.max_events:
            self._prune()

    def _prune(self):
        now = time.time()

        for e in self.buffer:
            age_min        = (now - e["timestamp"]) / 60
            fi_weight      = e["fi"] / 4
            recency_weight = 1 / (1 + age_min)
            e["retention"] = (0.7 * fi_weight) + (0.3 * recency_weight)

        self.buffer.sort(key=lambda e: e["retention"])

        while len(self.buffer) > self.max_events:
            self.buffer.pop(0)

        self.buffer.sort(key=lambda e: e["timestamp"])
        print(f"[MemoryPruner] Pruned — buffer now {len(self.buffer)} events")

    def get_buffer(self) -> list:
        return self.buffer

    def buffer_stats(self) -> dict:
        return {
            "event_count": len(self.buffer),
            "max_events":  self.max_events,
            "fi_breakdown": {
                str(fi): sum(1 for e in self.buffer if e["fi"] == fi)
                for fi in range(5)
            }
        }

# ── FI Log Manager ────────────────────────────────────────────────────────────

class FILogManager:
    def __init__(
        self,
        impactful_path = "impactful_log.json",
        llm_fn         = None,
        max_events     = 10,
        min_fi         = 2,
    ):
        self.impactful_path = impactful_path
        self.scorer         = FIScorer(llm_fn=llm_fn)
        self.pruner         = MemoryPruner(max_events, min_fi)

        if not os.path.exists(impactful_path):
            with open(impactful_path, "w") as f:
                json.dump([], f)

    def process(self, command: str, output: str, agent: str, session_id: str) -> dict:
        fi, method = self.scorer.score(command)

        event = {
            "session_id":   session_id,
            "timestamp":    time.time(),
            "datetime":     datetime.now().isoformat(),
            "command":      command,
            "output":       output[:300],
            "agent":        agent,
            "fi":           fi,
            "fi_label":     FI_LABELS[fi],
            "score_method": method,
        }

        if fi >= self.pruner.min_fi:
            self._append_log(self.impactful_path, event)
            self.pruner.add(event)

        return event

    def build_llm_prompt(self) -> str:
        stats  = self.pruner.buffer_stats()
        events = self.pruner.get_buffer()
        lines  = [
            f"[{e['datetime']}] FI={e['fi']} ({e['fi_label']}) [{e['agent']}] $ {e['command']}"
            for e in events
        ]
        return (
            f"Session impactful commands ({stats['event_count']}/{stats['max_events']} events):\n\n"
            + "\n".join(lines)
            + "\n\nWhat is the attacker's current intent and next likely action?"
        )

    def build_terminal_history(self) -> str:
        events = self.pruner.get_buffer()
        if not events:
            return ""
        history_text = "Previous impactful interactions:\n"
        for e in events:
            history_text += f"Command: {e['command']}\n"
            if e.get("output", "").strip():
                history_text += f"Response: {e['output']}\n\n"
            else:
                history_text += f"Response: (command executed successfully, no output)\n\n"
        return history_text

    def status(self):
        stats     = self.pruner.buffer_stats()
        imp_count = self._count_log(self.impactful_path)
        print("\n── FI Buffer Status ──────────────────────────────")
        print(f"  Events in buffer : {stats['event_count']} / {stats['max_events']}")
        print(f"  FI breakdown     :")
        for fi, count in stats["fi_breakdown"].items():
            print(f"    FI {fi} ({FI_LABELS[int(fi)]}): {count} events")
        print(f"  Total in impactful_log : {imp_count} commands")
        print("──────────────────────────────────────────────────\n")

    def _append_log(self, path: str, event: dict):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            data.append(event)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[FILogManager] Log write error: {e}")

    def _count_log(self, path: str) -> int:
        try:
            with open(path, "r") as f:
                return len(json.load(f))
        except Exception:
            return 0

    def _print_event(self, event: dict):
        flag = "🔴" if event["fi"] >= 3 else "🟡" if event["fi"] >= 1 else "⚪"
        print(
            f"{flag} FI={event['fi']} [{event['fi_label']}] "
            f"[{event['agent']}|{event['score_method']}] "
            f"$ {event['command']}"
        )