import re
import time
import json
import os
from datetime import datetime

# ── FI Rules (hardcoded) ──────────────────────────────────────────────────────

FI_RULES = {
    0: [
        r'^(cat|head|tail|less|more|strings|xxd|hexdump)',
        r'^(ls|dir|vdir|find|locate|stat|file|wc|diff|du|tree)',
        r'^(whoami|id|who|users|w|last|lastlog|groups|finger)',
        r'^(uname|free|df|lscpu|lsmem|lsblk|lshw|lspci|hostname|hostnamectl|timedatectl|arch|date|cal|uptime|dmesg)',
        r'^(ps|pstree|top|htop|lsof|pgrep|bg|fg|jobs)',
        r'^(netstat|ss|ip|ifconfig|arp|dig|nslookup)',
        r'cat\s+/etc/(passwd|hosts|hostname|os-release|group|fstab|issue|motd)',
        r'^(env|printenv|history|alias)',
        r'^(pwd|cd\s*$)',                          # ← echo removed from here
        # readonly/lookup utilities merged in from router.py's BASIC_PATTERNS —
        # pure read/display, same tier as cat/ls above
        r'^(readlink|basename|dirname)',
        r'^(grep|sort|uniq|tac|rev|od|column|join|nl)',
        r'^(exit|type|which|whereis|whatis|man)(\s|$)',
        r'^export(?!\s+PATH=)\s+',                 # non-PATH export — read/no-op state effect
        r'^tty(\s|$)',
        r'^(lsmod|modinfo)(\s|$)',                  # display loaded kernel modules
        r'^(journalctl|sar)(\s|$)',                 # display logs/activity — FI0 per "display system information"
    ],
    1: [
        r'^(touch|mkdir|cp|ln)',
        r'^(apt|apt-get|yum|dnf|pip|pip3|gem|npm)',
        r'^(wget|curl)(?!.*\|\s*(bash|sh|python))',
        r'^(tar|zip|unzip|gzip|gunzip|bzip2|bunzip2|xz|7z|zcat|zless)',
        r'^echo\s+',
        # merged in from router.py's BASIC_PATTERNS — minor actions, same tier
        # as touch/cp/tar above (create/install-adjacent, not a modify/nav op)
        r'^xargs\b',
        r'^(kill|killall|pkill)\b(?!.*-9)',        # bare kill — the -9 variant is FI4 below
        r'^exec\s+(?!\d+[<>])',                     # exec <cmd> — network-fd redirect handled by _is_cloud()
    ],
    2: [
        r'^(mv|rm(?!\s+.*-rf?)|rmdir|truncate|tee|dd)',
        r'^(sed|awk|tr|cut|paste)(\s|$)',
        r'^(chmod|chown|chgrp|umask|setfacl)',
        r'^(cd\s+\S+)',
        r'^(chsh|chfn|chage)',
        r'^export\s+PATH=',
        r'^(vi|vim|nano|emacs)',
        # echo patterns REMOVED from here
        # merged in from router.py's ONDEVICE_PATTERNS — "modify shell/session
        # environment" tier, same spirit as chsh/chfn above
        r'^(screen|stty)(\s|$)',
        r'^unset\s+\w+',
    ],
    3: [
        r'^(systemctl|service|init)',
        r'^(sudo|su\s)',
        r'^(crontab|at|batch|cron|atd)(\s|$)',
        r'^(ssh|scp|sftp|ftp|nc|telnet|socat)',
        r'(curl|wget).*\|\s*(bash|sh|python)',
        r'wget.*&&\s*(bash|sh)',
        r'^(nmap|masscan)',
        # merged in from router.py's ONDEVICE_PATTERNS — running/building
        # arbitrary code is at least as consequential as starting a service,
        # not a simple "create file" (FI1) or "modify" (FI2) action
        r'^(python|python3|perl|ruby|php|node|lua|bash|sh|source)\s+\S+',
        r'^\./\S+',                                  # direct execution of a local binary/script
        r'^(gcc|g\+\+|gdb|make)(\s|$)',
        r'^(insmod|rmmod)(\s|$)',                    # loads/unloads kernel state — not read-only like lsmod
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
"""
fi_manager.py — Functional Impact (FI) scoring + memory pruning.

FI scale:
  0 = Read/Display
  1 = Create/Install
  2 = Modify/Navigate
  3 = Service/Download/Elevate
  4 = Impact/Delete/Passwd
"""
# ── FI Scorer ─────────────────────────────────────────────────────────────────
class FIScorer:
    def __init__(self, llm_fn=None):
        self.llm_fn = llm_fn
        self.cache  = {}   # per-instance cache, safe for concurrent sessions

    def score(self, command: str) -> tuple[int, str]:
        cmd = command.strip()

        if cmd in self.cache:
            return self.cache[cmd], "cached"

        # check from highest FI down so the most severe match wins
        for fi in [4, 3, 2, 1, 0]:
            for pattern in FI_RULES[fi]:
                if re.search(pattern, cmd):
                    self.cache[cmd] = fi
                    return fi, "hardcoded"

        # optional LLM fallback for unusual commands
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
    def __init__(self, max_events=20, min_fi=1):
        self.max_events = max_events
        self.min_fi     = min_fi
        self.buffer     = []   # per-instance buffer, isolated per session

    def add(self, event: dict):
        if event["fi"] < self.min_fi:
            return
        # Keep only the FIRST-seen output for a given exact command, not the
        # most recent. Otherwise, if the model ever mis-generates on a repeat
        # of a command it previously got right (sampling variance, however
        # rare), that wrong output gets recorded into Hi as if confirmed —
        # and the model then imitates its own wrong precedent on every later
        # repeat of that command for the rest of the session. Locking to the
        # first observation prevents one slip from permanently poisoning Hi.
        for existing in self.buffer:
            if existing["command"] == event["command"]:
                existing["repeat_count"] = existing.get("repeat_count", 1) + 1
                return
        event["repeat_count"] = 1
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

        # drop the lowest-retention event(s) until we're back at max
        self.buffer.sort(key=lambda e: e["retention"])
        while len(self.buffer) > self.max_events:
            self.buffer.pop(0)
        # restore chronological order for downstream consumers
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
            },
        }


# ── FI Log Manager ────────────────────────────────────────────────────────────
class FILogManager:
    def __init__(
        self,
        impactful_path = "data/logs/impactful/default.json",
        llm_fn         = None,
        max_events     = 10,
        min_fi         = 2,
        store          = "json",
        instance       = "default",
    ):
        """store: where impactful events are recorded.

          "json"   — one file per session (the original behaviour). This is the
                     DEFAULT on purpose: the NSC experiment harness builds its
                     own FILogManager and must keep writing its own JSON, so
                     production opting in explicitly is what keeps the two
                     apart.
          "sqlite" — the shared DB, used by the live honeypot (main.py).

        Either way this is an audit log only. The H_i the model sees is built
        from MemoryPruner's in-memory buffer, so the choice cannot change
        model behaviour or experiment results."""
        self.impactful_path = impactful_path
        self.store          = store
        self.instance       = instance
        self.scorer         = FIScorer(llm_fn=llm_fn)
        self.pruner         = MemoryPruner(max_events, min_fi)

        if store == "json":
            # main.py used to pass per-session paths like:
            #   data/logs/impactful/20260503_142201.json
            # ensure the parent directory exists.
            parent = os.path.dirname(impactful_path)
            if parent:
                os.makedirs(parent, exist_ok=True)

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
            "output":       (output or "")[:300],
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

        # MemoryPruner.add() already guarantees at most one buffered entry
        # per unique command (first-seen output wins), so no further
        # collapsing is needed here — just render the repeat_count it kept.
        history_text = "Previous impactful interactions:\n"
        for e in events:
            count  = e.get("repeat_count", 1)
            suffix = f"  (x{count})" if count > 1 else ""
            output = e.get("output", "")
            if output.strip():
                history_text += f"Command: {e['command']}{suffix}\nResponse: {output}\n\n"
            else:
                # No "Response:" field at all for silent commands — a
                # "Response: (...)" placeholder here reads as a stylistic
                # template the model can imitate onto its OWN next output
                # (e.g. echoing "(chmod 777 file)" instead of staying truly
                # silent). This note is metadata about a past turn, never
                # something to reproduce.
                history_text += (
                    f"Command: {e['command']}{suffix}  "
                    f"[historical note: produced no output — do not repeat "
                    f"this annotation style in your own response]\n\n"
                )
        return history_text

    def status(self):
        stats     = self.pruner.buffer_stats()
        imp_count = self._count_log(self.impactful_path)
        print("\n── FI Buffer Status ──────────────────────────────")
        print(f"  Events in buffer       : {stats['event_count']} / {stats['max_events']}")
        print(f"  FI breakdown           :")
        for fi, count in stats["fi_breakdown"].items():
            print(f"    FI {fi} ({FI_LABELS[int(fi)]}): {count} events")
        print(f"  Total in impactful_log : {imp_count} commands")
        print("──────────────────────────────────────────────────\n")

    # ── log file helpers ──────────────────────────────────────────────────
    def _append_log(self, path: str, event: dict):
        if self.store == "sqlite":
            try:
                import storage
                storage.insert_impactful({**event, "instance": self.instance})
            except Exception as e:
                print(f"[FILogManager] SQLite write error: {e}")
            return

        # JSON mode (NSC / default). Kept exactly as it was: read the array,
        # append, write it back. That is O(n^2) over a session — one session
        # here rewrote ~118 MB across 844 events — which is precisely why
        # production moved to "sqlite".
        try:
            with open(path, "r") as f:
                data = json.load(f)
            data.append(event)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[FILogManager] Log write error: {e}")

    def _count_log(self, path: str) -> int:
        if self.store == "sqlite":
            try:
                import storage
                return storage.count_impactful()
            except Exception:
                return 0
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