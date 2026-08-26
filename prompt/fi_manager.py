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
fi_manager.py — Functional Impact (FI) scoring.

Memory pruning was removed: SYSTEM_STATE in main.py holds all session memory,
so there is no H_i buffer. What remains is FI scoring (used for routing, the
fi_score column, and the impactful audit log).

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

        Either way this is an audit log only — nothing here reaches the model.
        H_i has been removed: SYSTEM_STATE (the SRi dict in main.py) is now the
        single source of session memory, so there is no history buffer to
        prune and no interaction history in the prompt."""
        self.impactful_path = impactful_path
        self.store          = store
        self.instance       = instance
        self.scorer         = FIScorer(llm_fn=llm_fn)
        # H_i removed: SYSTEM_STATE is the only memory now, so there is no
        # buffer to prune. min_fi is still the "is this impactful" threshold
        # for the audit log.
        self.min_fi         = min_fi
        self.max_events     = max_events

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

        if fi >= self.min_fi:
            self._append_log(self.impactful_path, event)

        return event

    def status(self):
        imp_count = self._count_log(self.impactful_path)
        print("\n── FI Buffer Status ──────────────────────────────")
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